// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Naby Sidime. LogSonar : https://github.com/NabySidime/LogSonar
/*
 * Alarme de nuit : une sirène en boucle quand une attaque sérieuse arrive pendant que personne
 * ne regarde. Elle ne sonne que si l'alarme est activée ET qu'il n'y a eu aucune activité
 * (souris, clavier, toucher) depuis le délai choisi : devant l'écran, l'alerte s'affiche sans son.
 * Une fois déclenchée, elle sonne jusqu'à ce qu'on clique sur « Arrêter ».
 *
 * Déclencheurs (empreintes des alertes envoyées par le serveur) :
 *   attack-ok:  attaque élevée ou critique acceptée par le serveur (code 2xx non expliqué)
 *   targeted:   une même IP essaie plusieurs techniques en 10 min
 *   surge       afflux d'attaques venant de nombreuses IP
 *   hors ligne  LogSonar ne reçoit plus rien du serveur depuis 2 min
 */
"use strict";

const Alarm = (() => {
  const KEY = "logsonar-alarm";
  const OFFLINE_MS = 2 * 60 * 1000;
  const RERING_MS = 30 * 60 * 1000;       // attaque qui continue : nouvelle sonnerie 30 min après la précédente
  const TRIGGERS = [
    ["accepted", "attack-ok:", "Attaque acceptée par le serveur (code 2xx)"],
    ["targeted", "targeted:", "Attaque ciblée (une IP, plusieurs techniques)"],
    ["surge", "surge", "Afflux d'attaques (nombreuses IP)"],
    ["offline", null, "Connexion au serveur perdue (plus de 2 min)"],
  ];
  const DEFAULTS = { armed: false, idleMin: 10, volume: 0.7, sound: "reveil", triggers: { accepted: true, targeted: true, surge: true, offline: true } };

  let cfg = load();
  let lastActivity = Date.now();
  let ctx = null, nodes = null;           // Web Audio : créé au premier geste de l'utilisateur
  let ringing = null;                     // { reason, detail, ts, alertId }
  let snoozeUntil = 0;
  let offlineSince = 0;
  let wakeLock = null;
  let idle = { supported: "IdleDetector" in window, granted: false, systemIdle: false, detector: null };
  const lastRing = new Map();             // empreinte -> heure de la dernière sonnerie
  let titleTimer = null;

  function load() {
    try {
      const s = JSON.parse(localStorage.getItem(KEY) || "{}");
      return { ...DEFAULTS, ...s, triggers: { ...DEFAULTS.triggers, ...(s.triggers || {}) } };
    } catch (e) { return { ...DEFAULTS, triggers: { ...DEFAULTS.triggers } }; }
  }
  function save() { try { localStorage.setItem(KEY, JSON.stringify(cfg)); } catch (e) { /* ignoré */ } }
  const idleMs = () => Math.max(1, Number(cfg.idleMin) || 10) * 60 * 1000;

  // ---------------------------------------------------------------- activité
  function activity() {
    lastActivity = Date.now();
    unlockAudio();
  }
  ["pointerdown", "keydown", "wheel", "touchstart"].forEach((t) =>
    window.addEventListener(t, activity, { passive: true, capture: true }));
  // Le navigateur envoie aussi des « mouvements » quand la page change sous une souris immobile
  // (graphique en direct, logs qui défilent) : seul un vrai déplacement de quelques pixels compte.
  let lastX = null, lastY = null;
  window.addEventListener("pointermove", (e) => {
    if (lastX !== null && Math.abs(e.screenX - lastX) + Math.abs(e.screenY - lastY) < 4) return;
    const first = lastX === null;
    lastX = e.screenX; lastY = e.screenY;
    if (!first) activity();
  }, { passive: true, capture: true });

  // Avec la permission « détection d'inactivité » (Chrome), on sait si la personne utilise
  // l'ordinateur, même dans un autre onglet ou une autre application.
  async function startIdleDetector() {
    if (!idle.supported || idle.detector) return;
    try {
      const d = new IdleDetector();
      d.addEventListener("change", () => {
        idle.systemIdle = d.userState === "idle" || d.screenState === "locked";
        if (!idle.systemIdle) lastActivity = Date.now();
      });
      await d.start({ threshold: Math.max(60000, idleMs()) });
      idle.detector = d; idle.granted = true;
    } catch (e) { idle.granted = false; }
  }
  async function requestIdlePermission() {
    if (!idle.supported) return false;
    try {
      const r = await IdleDetector.requestPermission();
      if (r === "granted") { idle.detector = null; await startIdleDetector(); }
    } catch (e) { /* refusé */ }
    return idle.granted;
  }
  function isIdle() {
    if (idle.granted && idle.detector) return idle.systemIdle;
    return Date.now() - lastActivity >= idleMs();
  }

  // ---------------------------------------------------------------- son
  function unlockAudio() {
    if (ctx) { if (ctx.state === "suspended") ctx.resume().catch(() => {}); return; }
    const AC = window.AudioContext || window.webkitAudioContext;
    if (!AC) return;
    try { ctx = new AC(); } catch (e) { ctx = null; return; }
    ctx.onstatechange = renderButton;
    if (ctx.state === "suspended") ctx.resume().catch(() => {});
    renderButton();
  }
  const audioReady = () => !!ctx && ctx.state === "running";

  // Sons : chaque motif est calculé une fois dans un tampon audio, puis joué en boucle par la
  // carte son. Aucun minuteur : le navigateur ne peut pas le ralentir dans un onglet en arrière-plan.
  function buildSound(kind) {
    const rate = ctx.sampleRate;
    const spec = SOUNDS[kind] || SOUNDS.reveil;
    const data = new Float32Array(Math.ceil(spec.length * rate));
    // Note : fondamentale + harmoniques, attaque courte, puis tenue (bip) ou extinction (cloche)
    const note = (t0, freq, { dur = 0.12, decay = 0, partials = [[1, 1], [2, 0.25]], amp = 1 } = {}) => {
      const start = Math.floor(t0 * rate), n = Math.floor((decay ? decay * 5 : dur) * rate);
      for (let i = 0; i < n && start + i < data.length; i++) {
        const t = i / rate;
        let env = Math.min(1, t / 0.004);
        env *= decay ? Math.exp(-t / decay) : Math.min(1, (dur - t) / 0.012);
        let v = 0;
        for (const [mult, a] of partials) v += a * Math.sin(2 * Math.PI * freq * mult * t);
        data[start + i] += v * env * amp;
      }
    };
    spec.play(note);
    let peak = 0;
    for (const v of data) peak = Math.max(peak, Math.abs(v));
    if (peak) for (let i = 0; i < data.length; i++) data[i] /= peak;
    const buf = ctx.createBuffer(1, data.length, rate);
    buf.copyToChannel(data, 0);
    return buf;
  }
  const BELL = [[1, 1], [2, 0.45], [3, 0.2], [4.2, 0.1]];
  const SOUNDS = {
    reveil: { label: "Réveil (bips)", length: 1.4, play: (note) => [0, 0.2, 0.4, 0.6].forEach((t) => note(t, 1046, { dur: 0.12 })) },
    carillon: { label: "Carillon (ding-dong)", length: 2.4, play: (note) => { note(0, 659, { decay: 0.35, partials: BELL }); note(0.55, 523, { decay: 0.45, partials: BELL }); } },
    sonar: { label: "Sonar (ping et écho)", length: 2.2, play: (note) => { note(0, 1318, { decay: 0.18, partials: [[1, 1]] }); note(0.32, 1318, { decay: 0.18, partials: [[1, 1]], amp: 0.35 }); note(0.64, 1318, { decay: 0.18, partials: [[1, 1]], amp: 0.12 }); } },
    sirene: { label: "Sirène (très forte)", length: 1.6, play: null },
  };
  // Sirène : balayage de fréquence continu, calculé directement
  function sirenBuffer() {
    const rate = ctx.sampleRate, len = Math.ceil(1.6 * rate), data = new Float32Array(len);
    let phase = 0;
    for (let i = 0; i < len; i++) {
      const t = i / rate, f = 700 + 400 * (0.5 - 0.5 * Math.cos(2 * Math.PI * t / 1.6));
      phase += 2 * Math.PI * f / rate;
      data[i] = 0.8 * Math.sin(phase) + 0.2 * Math.sin(2 * phase);
    }
    const buf = ctx.createBuffer(1, len, rate);
    buf.copyToChannel(data, 0);
    return buf;
  }

  function startSiren(volume = cfg.volume, kind = cfg.sound) {
    if (!ctx || nodes) return;
    if (ctx.state === "suspended") ctx.resume().catch(() => {});
    const src = ctx.createBufferSource(), gain = ctx.createGain();
    src.buffer = kind === "sirene" ? sirenBuffer() : buildSound(kind);
    src.loop = true;
    gain.gain.value = Math.max(0.05, Math.min(1, volume)) * 0.6;
    src.connect(gain).connect(ctx.destination);
    src.start();
    nodes = { src, gain };
  }
  function stopSiren() {
    if (!nodes) return;
    try { nodes.src.stop(); } catch (e) { /* déjà arrêté */ }
    nodes = null;
  }

  // ---------------------------------------------------------------- écran allumé
  async function keepAwake() {
    if (!cfg.armed || !("wakeLock" in navigator) || document.visibilityState !== "visible" || wakeLock) return;
    try {
      wakeLock = await navigator.wakeLock.request("screen");
      wakeLock.addEventListener("release", () => { wakeLock = null; });
    } catch (e) { wakeLock = null; }
  }
  function releaseAwake() { if (wakeLock) { wakeLock.release().catch(() => {}); wakeLock = null; } }
  document.addEventListener("visibilitychange", keepAwake);

  // ---------------------------------------------------------------- déclenchement
  function trigger(reason, detail, alertId = null, fingerprint = "") {
    if (!cfg.armed || ringing || Date.now() < snoozeUntil) return false;
    if (!isIdle()) return false;           // quelqu'un est devant l'écran : le toast suffit
    if (fingerprint) lastRing.set(fingerprint, Date.now());
    ringing = { reason, detail, ts: Date.now() / 1000, alertId };
    startSiren();
    renderRinging();
    flashTitle(true);
    return true;
  }
  function stop() {
    stopSiren();
    ringing = null;
    flashTitle(false);
    setHTML($("#alarm-root"), "");
    lastActivity = Date.now();
  }
  function flashTitle(on) {
    clearInterval(titleTimer); titleTimer = null;
    if (!on) { if (document.title.startsWith("🚨")) document.title = document.title.replace(/^🚨 ALARME · /, ""); return; }
    const base = document.title.replace(/^🚨 ALARME · /, "");
    titleTimer = setInterval(() => { document.title = document.title.startsWith("🚨") ? base : `🚨 ALARME · ${base}`; }, 1000);
  }

  function triggerFor(fp) {
    const t = TRIGGERS.find(([, prefix]) => prefix && (prefix.endsWith(":") ? fp.startsWith(prefix) : fp === prefix));
    return t && cfg.triggers[t[0]] ? t : null;
  }

  // Alerte reçue en temps réel
  function onAlert(a) {
    if (!a || a.status === "resolved" || !a.fingerprint) return;
    if (!triggerFor(a.fingerprint)) return;
    const prev = lastRing.get(a.fingerprint);
    const fresh = a.count === 1;
    // Attaque qui continue : on ne sonne à nouveau qu'après RERING_MS
    if (!fresh && (prev === undefined || Date.now() - prev < RERING_MS)) {
      if (prev === undefined) lastRing.set(a.fingerprint, Date.now());   // déjà en cours à l'ouverture de la page
      return;
    }
    trigger(a.title, a.message, a.id, a.fingerprint);
  }

  // Connexion temps réel perdue / retrouvée
  function onConnection(up) {
    if (up) { offlineSince = 0; return; }
    if (!offlineSince) offlineSince = Date.now();
  }
  setInterval(() => {
    if (offlineSince && cfg.triggers.offline && Date.now() - offlineSince >= OFFLINE_MS && !lastRing.has("offline:" + offlineSince)) {
      if (trigger("LogSonar ne reçoit plus rien du serveur",
        `Plus de connexion temps réel depuis ${fmtTime(offlineSince / 1000)}. Le serveur, LogSonar ou la connexion Internet de cet ordinateur est peut-être coupé : la surveillance ne fonctionne plus.`,
        null, "offline:" + offlineSince)) { /* sonnerie lancée */ }
    }
    renderButton();
  }, 15000);

  // ---------------------------------------------------------------- affichage
  function renderButton() {
    const b = $("#alarm-btn");
    if (!b) return;
    const state = !cfg.armed ? "off" : !audioReady() ? "locked" : "on";
    b.className = `btn sm alarm-btn ${state}`;
    b.title = { off: "Alarme de nuit désactivée", locked: "Alarme activée : cliquez sur la page pour autoriser le son", on: `Alarme activée : sonne après ${cfg.idleMin} min sans activité` }[state];
    setHTML(b, html`${icon(state === "off" ? "bell-off" : "siren")}<span class="txt">${state === "locked" ? "Activer le son" : "Alarme"}</span>`);
  }

  function renderRinging() {
    const r = ringing;
    setHTML($("#alarm-root"), html`<div class="alarm-screen" role="alertdialog" aria-modal="true" aria-label="Alarme">
      <div class="alarm-box">
        <div class="alarm-icon">${icon("siren")}</div>
        <div class="alarm-kicker">Alarme LogSonar · ${fmtTime(r.ts, true)}</div>
        <h2>${r.reason}</h2>
        ${r.detail ? html`<pre class="alarm-detail">${String(r.detail).slice(0, 900)}</pre>` : ""}
        <div class="alarm-actions">
          <button class="btn primary alarm-stop" data-action="alarm-stop">${icon("bell-off")}Arrêter l'alarme</button>
          ${r.alertId ? html`<button class="btn" data-action="alarm-open">${icon("bell")}Voir les alertes</button>` : ""}
          <button class="btn ghost" data-action="alarm-snooze">${icon("moon")}Silence 30 min</button>
        </div>
      </div></div>`);
  }

  function openSettings() {
    unlockAudio();
    const t = cfg.triggers;
    const idleInfo = idle.granted ? "Inactivité détectée sur tout l'ordinateur (permission accordée)."
      : idle.supported ? "Inactivité détectée sur cette page seulement. Autorisez la détection sur tout l'ordinateur pour que l'alarme ne sonne pas pendant que vous travaillez dans un autre onglet."
      : "Inactivité détectée sur cette page seulement (ce navigateur ne permet pas de mieux).";
    openOverlay({
      kind: "modal", title: "Alarme de nuit", sub: "Réglage propre à ce navigateur",
      body: html`<label class="switch"><input type="checkbox" id="al-armed" ${cfg.armed ? raw("checked") : ""}>Alarme activée</label>
        <div class="field"><label for="al-idle">Sonner seulement après</label>
          <select class="input" id="al-idle">${[2, 5, 10, 15, 30, 60].map((m) => html`<option value="${m}" ${Number(cfg.idleMin) === m ? raw("selected") : ""}>${m} min sans activité sur l'ordinateur</option>`)}</select>
          <span class="hint">Devant l'écran, l'alerte s'affiche sans son.</span></div>
        <div class="field"><label>Ce qui déclenche l'alarme</label>
          <div class="stack" style="gap:6px">${TRIGGERS.map(([k, , label]) => html`<label class="switch"><input type="checkbox" data-trig="${k}" ${t[k] ? raw("checked") : ""}>${label}</label>`)}</div></div>
        <div class="field"><label for="al-sound">Son</label>
          <select class="input" id="al-sound">${Object.entries(SOUNDS).map(([k, v]) => html`<option value="${k}" ${cfg.sound === k ? raw("selected") : ""}>${v.label}</option>`)}</select></div>
        <div class="field"><label for="al-vol">Volume</label><input type="range" id="al-vol" min="0.1" max="1" step="0.1" value="${cfg.volume}"></div>
        <div class="tiny muted">${idleInfo}</div>
        <div class="tiny muted">Pour la nuit : laissez cet onglet ouvert, l'ordinateur branché, sans mise en veille, et le son allumé. L'écran reste allumé tant que l'onglet est affiché.</div>`,
      foot: html`${idle.supported && !idle.granted ? html`<button class="btn" id="al-perm">${icon("monitor-check")}Détecter sur tout l'ordinateur</button>` : ""}
        <button class="btn" id="al-test">${icon("volume-2")}Écouter</button>
        <button class="btn primary" id="al-save">${icon("check")}Enregistrer</button>`,
    });
    const perm = $("#al-perm");
    if (perm) perm.addEventListener("click", async () => {
      const ok = await requestIdlePermission();
      toast(ok ? "Détection d'inactivité sur tout l'ordinateur activée." : "Permission refusée : seule l'activité sur cette page sera prise en compte.", ok ? "" : "error");
      if (ok) openSettings();
    });
    $("#al-test").addEventListener("click", () => {
      unlockAudio();
      if (!ctx) { toast("Ce navigateur ne peut pas jouer l'alarme.", "error"); return; }
      stopSiren();
      startSiren(Number($("#al-vol").value), $("#al-sound").value);
      setTimeout(() => { if (!ringing) stopSiren(); }, 4000);
    });
    $("#al-save").addEventListener("click", () => {
      cfg.armed = $("#al-armed").checked;
      cfg.idleMin = Number($("#al-idle").value);
      cfg.volume = Number($("#al-vol").value);
      cfg.sound = $("#al-sound").value;
      $$("[data-trig]").forEach((el) => { cfg.triggers[el.dataset.trig] = el.checked; });
      save();
      if (idle.detector) { idle.detector = null; startIdleDetector(); }
      if (cfg.armed) keepAwake(); else { releaseAwake(); stop(); }
      closeOverlay();
      renderButton();
      toast(cfg.armed ? `Alarme activée : elle sonnera après ${cfg.idleMin} min sans activité.` : "Alarme désactivée.");
    });
  }

  Object.assign(App.actions, {
    "alarm-settings": openSettings,
    "alarm-stop": stop,
    "alarm-snooze": () => { snoozeUntil = Date.now() + 30 * 60 * 1000; stop(); toast("Alarme en silence pendant 30 min."); },
    "alarm-open": () => { stop(); location.hash = "#/alerts"; },
  });

  async function init() {
    renderButton();
    if (idle.supported && navigator.permissions) {
      try {
        const p = await navigator.permissions.query({ name: "idle-detection" });
        if (p.state === "granted") await startIdleDetector();
      } catch (e) { /* permission inconnue de ce navigateur */ }
    }
    if (cfg.armed) keepAwake();
  }

  return {
    init, onAlert, onConnection, stop, isRinging: () => !!ringing,
    // Diagnostic (console) : Alarm.state()
    state: () => ({ armed: cfg.armed, idle: isIdle(), idleFor: Math.round((Date.now() - lastActivity) / 1000), idleDetector: idle.granted,
      audio: ctx ? ctx.state : "absent", snoozed: Date.now() < snoozeUntil, ringing: !!ringing }),
  };
})();
