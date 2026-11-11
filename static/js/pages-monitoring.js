// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Naby Sidime. LogSonar : https://github.com/NabySidime/LogSonar
/* LogSonar — pages de surveillance : vue d'ensemble, serveur, conteneurs, trafic, logs */
"use strict";

const minuteLabels = (series) => series.map((p) => fmtTime(p.ts));

function hostGauges(h) {
  if (!h) return html`<div class="card gauge"><div class="skeleton"></div></div>`;
  const disk = (h.disks || []).reduce((a, d) => (!a || d.percent > a.percent ? d : a), null);
  const cpuLvl = levelOf(h.cpu, 85, 95), memLvl = levelOf(h.mem.percent, 85, 95), diskLvl = levelOf(disk && disk.percent, 80, 90);
  const lvlText = { critical: "Critique", warning: "Élevé", good: "Normal", "": "" };
  const g = (ic, label, value, pct, lvl, foot) => html`<div class="card gauge">
    <div class="top"><span class="label">${icon(ic)}${label}</span>${lvl && lvl !== "good" ? sevBadge(lvl === "critical" ? "critical" : "warning") : html`<span class="tiny muted">${lvlText[lvl]}</span>`}</div>
    <div class="value">${value}</div>${pct != null ? meter(pct, lvl) : ""}<div class="foot">${foot}</div></div>`;
  return html`
    ${g("cpu", "Processeur", fmtPct(h.cpu), h.cpu, cpuLvl, `Charge ${h.load[0]} · ${h.cpu_count} cœurs`)}
    ${g("memory-stick", "Mémoire", fmtPct(h.mem.percent), h.mem.percent, memLvl, `${fmtBytes(h.mem.used)} / ${fmtBytes(h.mem.total)}`)}
    ${g("hard-drive", disk ? `Disque ${disk.mount}` : "Disque", disk ? fmtPct(disk.percent) : "—", disk && disk.percent, diskLvl, disk ? `${fmtBytes(disk.free)} libres sur ${fmtBytes(disk.total)}` : "Montez /hostfs pour voir les disques")}
    ${g("network", "Réseau", fmtRate(h.net.rx_rate + h.net.tx_rate), null, "", `↓ ${fmtRate(h.net.rx_rate)} · ↑ ${fmtRate(h.net.tx_rate)}`)}`;
}

function alertItem(a) {
  const sevCls = a.severity === "warning" ? "warning" : a.severity;
  return html`<div class="list-item clickable" data-action="alert-open" data-id="${a.id}">
    <span class="sev-dot ${sevCls}"></span>
    <div class="grow"><div class="title">${a.title}</div>
      <div class="meta">${a.source || a.category} · ${fmtAgo(a.last_ts)}${a.count > 1 ? ` · ${fmtNum(a.count)} occurrences` : ""}${a.status === "acknowledged" ? " · prise en compte" : ""}</div></div>
    ${sevBadge(a.severity)}</div>`;
}

// ===========================================================================
// VUE D'ENSEMBLE
// ===========================================================================
App.pages.overview = async (view) => {
  setHeader("Vue d'ensemble", "État du serveur, des conteneurs et de la sécurité");
  const d = await GET("/api/overview");
  const sc = d.score;
  const v = (d.scan.last && d.scan.last.vulns_by_severity) || {};
  const t = d.traffic;
  const rpmNow = t.series.length > 1 ? t.series[t.series.length - 2].requests : 0;

  setHTML(view, html`
    ${!d.docker.connected ? html`<div class="callout danger" style="margin-bottom:16px">${icon("plug-zap")}<div><b>Docker inaccessible.</b> La surveillance des conteneurs est interrompue. <span class="muted">${d.docker.error}</span></div></div>` : ""}
    ${d.notifications && d.notifications.unreadable.length ? html`<div class="callout danger" style="margin-bottom:16px">${icon("key-round")}<div><b>Secret(s) illisible(s) : ${d.notifications.unreadable.join(", ")}.</b> Ils sont enregistrés mais chiffrés avec une autre clé : LogSonar ne peut plus les utiliser. ${App.isAdmin() ? html`<a href="#/settings">Ressaisissez-les dans Paramètres</a>.` : "Prévenez un administrateur."}</div></div>` : ""}
    ${d.notifications && !d.notifications.channels.length ? html`<div class="callout warn" style="margin-bottom:16px">${icon("bell-off")}<div><b>Aucune notification ne part.</b> Aucun canal (email, Discord, Slack, Telegram, webhook) n'est configuré : les alertes restent visibles ici uniquement. ${App.isAdmin() ? html`<a href="#/settings">Configurer un canal</a>.` : ""}</div></div>` : ""}
    ${d.host_info && !d.host_info.host_mode ? html`<div class="callout warn" style="margin-bottom:16px">${icon("info")}<div>Les métriques affichées sont celles du conteneur LogSonar : montez <code>/proc:/host/proc:ro</code> et <code>/:/hostfs:ro</code> pour voir le serveur entier (voir docker-compose.yml).</div></div>` : ""}
    <div class="grid g-4" id="gauges">${hostGauges(d.host)}</div>

    <div class="grid g-main mt">
      <div class="card">
        <div class="card-head"><h3>Trafic HTTP</h3><span class="sub">requêtes par minute, 60 dernières minutes</span>
          <div class="actions"><a class="btn sm ghost" href="#/traffic">Détails ${icon("arrow-right")}</a></div></div>
        <div class="card-body">
          <div class="row" style="gap:28px;margin-bottom:8px">
            <div><div class="tiny muted">Dernière minute</div><div class="strong" style="font-size:20px">${fmtNum(rpmNow)} <span class="small muted">req/min</span></div></div>
            <div><div class="tiny muted">Normale (moyenne 1 h)</div><div class="strong" style="font-size:20px">${fmtNum(t.baseline_rpm)} <span class="small muted">req/min</span></div></div>
            <div><div class="tiny muted">Erreurs 5xx (1 h)</div><div class="strong" style="font-size:20px">${fmtNum(t.series.reduce((s, p) => s + p.errors, 0))}</div></div>
          </div>
          <div class="chart"><canvas id="ch-traffic" aria-label="Requêtes par minute"></canvas></div>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><h3>Score de sécurité</h3><div class="actions"><a class="btn sm ghost" href="#/vulns">Améliorer ${icon("arrow-right")}</a></div></div>
        <div class="card-body">
          <div class="score">${scoreRing(sc.score, sc.grade)}
            <div class="penalties">${sc.penalties.length ? sc.penalties.slice(0, 6).map((p) => html`<div class="p" title="${p.hint}"><span>${p.label}</span><span>−${p.points}</span></div>`) : html`<div class="text-2">Aucun point faible détecté. Bravo !</div>`}</div>
          </div>
        </div>
      </div>
    </div>

    <div class="grid g-3 mt">
      <div class="card">
        <div class="card-head"><h3>Alertes en cours</h3><span class="sub">${fmtNum(d.alerts_count)}</span><div class="actions"><a class="btn sm ghost" href="#/alerts">Toutes ${icon("arrow-right")}</a></div></div>
        <div class="card-body flush"><div class="list">${d.alerts.length ? d.alerts.slice(0, 6).map(alertItem) : empty("Aucune alerte en cours", "Tout fonctionne normalement.", "circle-check")}</div></div>
      </div>
      <div class="card">
        <div class="card-head"><h3>Menaces aujourd'hui</h3><div class="actions"><a class="btn sm ghost" href="#/threats">Détails ${icon("arrow-right")}</a></div></div>
        <div class="card-body">
          <div class="row" style="gap:28px;margin-bottom:14px">
            <div><div class="tiny muted">Attaques détectées</div><div class="strong" style="font-size:24px">${fmtNum(d.attacks_today)}</div></div>
            <div><div class="tiny muted">IP attaquantes</div><div class="strong" style="font-size:24px">${fmtNum(d.attacker_ips_today)}</div></div>
          </div>
          ${hbars(d.top_attack_types, { label: (x) => x.attack_type, value: (x) => x.n, color: "--series-2" })}
        </div>
      </div>
      <div class="stack">
        <div class="card">
          <div class="card-head"><h3>Conteneurs</h3><div class="actions"><a class="btn sm ghost" href="#/containers">Voir ${icon("arrow-right")}</a></div></div>
          <div class="card-body"><div class="grid g-3" style="gap:8px">
            <div><div class="tiny muted">En marche</div><div class="strong" style="font-size:22px">${d.containers.running}<span class="small muted"> / ${d.containers.total}</span></div></div>
            <div><div class="tiny muted">Arrêtés</div><div class="strong" style="font-size:22px">${d.containers.stopped}</div></div>
            <div><div class="tiny muted">En échec</div><div class="strong" style="font-size:22px">${d.containers.unhealthy}</div></div>
          </div></div>
        </div>
        <div class="card">
          <div class="card-head"><h3>Vulnérabilités</h3><span class="sub">${d.scan.last ? "scan " + fmtAgo(d.scan.last.finished) : "aucun scan"}</span><div class="actions"><a class="btn sm ghost" href="#/vulns">Voir ${icon("arrow-right")}</a></div></div>
          <div class="card-body">
            ${d.scan.state.running ? html`<div class="small text-2">${d.scan.state.stage}</div><div class="progress mt"><i style="width:${d.scan.state.progress}%"></i></div>` :
              d.scan.last ? html`<div class="row">${sevBadge("critical")}<b>${v.critical || 0}</b>${sevBadge("high")}<b>${v.high || 0}</b>${sevBadge("medium")}<b>${v.medium || 0}</b></div>
              <div class="small muted mt">${fmtNum(d.scan.last.packages_total)} paquets analysés · ${fmtNum(d.scan.last.fixable)} corrigeables · ${fmtNum(d.scan.last.config_total)} problèmes de configuration</div>` :
              html`<div class="small muted">Le premier scan démarre automatiquement après l'installation.</div>`}
          </div>
        </div>
      </div>
    </div>

    <div class="card mt">
      <div class="card-head"><h3>Dernières attaques</h3></div>
      <div class="card-body flush">${d.recent_attacks.length ? html`<div class="table-wrap"><table class="table"><thead><tr><th>Heure</th><th>Type</th><th>IP</th><th>Conteneur</th><th>Requête</th><th>Code</th></tr></thead>
        <tbody>${d.recent_attacks.map((e) => html`<tr><td class="nowrap mono">${fmtDate(e.ts)}</td><td>${sevBadge(e.severity)} ${e.attack_type}</td><td class="mono">${e.ip || "—"}</td><td class="mono">${e.container}</td><td class="path" title="${e.path}">${e.method} ${e.path}</td><td class="mono">${e.status || "—"}</td></tr>`)}</tbody></table></div>` : empty("Aucune attaque enregistrée", "", "shield-check")}</div>
    </div>`);

  lineChart($("#ch-traffic"), minuteLabels(t.series), [{ label: "Requêtes", data: t.series.map((p) => p.requests), color: "--series-1", fill: true }]);
  on("host", (h) => patchHTML($("#gauges"), hostGauges(h)));
  every(60000, refresh);
};

// ===========================================================================
// SERVEUR
// ===========================================================================
App.pages.server = async (view) => {
  const range = hashParams().get("range") || "1h";
  const custom = customPeriod();
  setHeader("Serveur", "Ressources de la machine hôte",
    periodPicker("range", ["1h", "6h", "24h", "7d", "14d"].map((r) => [r, r.replace("d", " j").replace("h", " h")]), range, 14));
  const d = await GET(`/api/host?${qs(custom ? { since: custom.from, until: custom.to } : { range })}`);
  const info = d.info, h = d.now;
  const hist = d.history;
  // Au-delà d'une journée, l'heure seule ne suffit plus : on affiche aussi la date
  const longSpan = hist.length > 1 && hist[hist.length - 1].ts - hist[0].ts > 86400;
  const labels = hist.map((p) => (longSpan ? fmtDate(p.ts) : fmtTime(p.ts)));
  const df = d.docker_df || {};

  setHTML(view, html`
    <div class="grid g-4" id="gauges">${hostGauges(h)}</div>
    <div class="grid g-2 mt">
      <div class="card"><div class="card-head"><h3>Processeur et mémoire</h3><div class="actions">${legend([["CPU", "--series-1"], ["Mémoire", "--series-2"]])}</div></div>
        <div class="card-body"><div class="chart"><canvas id="ch-cpu"></canvas></div></div></div>
      <div class="card"><div class="card-head"><h3>Réseau</h3><div class="actions">${legend([["Réception", "--series-3"], ["Émission", "--series-4"]])}</div></div>
        <div class="card-body"><div class="chart"><canvas id="ch-net"></canvas></div></div></div>
      <div class="card"><div class="card-head"><h3>Occupation disque (max)</h3></div>
        <div class="card-body"><div class="chart"><canvas id="ch-disk"></canvas></div></div></div>
      <div class="card"><div class="card-head"><h3>Charge système (1 min)</h3><span class="sub">${info.cpu_count} cœurs</span></div>
        <div class="card-body"><div class="chart"><canvas id="ch-load"></canvas></div></div></div>
    </div>

    <div class="grid g-main mt">
      <div class="card"><div class="card-head"><h3>Disques</h3></div>
        <div class="card-body flush"><div class="table-wrap"><table class="table"><thead><tr><th>Point de montage</th><th>Type</th><th>Utilisé</th><th style="width:32%">Occupation</th><th class="right">Libre</th></tr></thead>
        <tbody>${(h && h.disks || []).map((x) => html`<tr><td class="mono">${x.mount}<div class="tiny muted">${x.device}</div></td><td class="mono">${x.fstype || "—"}</td><td class="num">${fmtBytes(x.used)} / ${fmtBytes(x.total)}</td><td><div class="row" style="flex-wrap:nowrap"><div style="flex:1">${meter(x.percent, levelOf(x.percent, 80, 90))}</div><span class="num small">${fmtPct(x.percent)}</span></div></td><td class="right num">${fmtBytes(x.free)}</td></tr>`)}</tbody></table></div></div></div>
      <div class="card"><div class="card-head"><h3>Machine</h3></div>
        <div class="card-body"><dl class="kv">
          <dt>Nom</dt><dd class="strong">${info.hostname}</dd>
          <dt>Système</dt><dd>${info.os}</dd>
          <dt>Noyau</dt><dd class="mono">${info.kernel}</dd>
          <dt>Processeur</dt><dd>${info.cpu_model || "—"} · ${info.cpu_count} cœurs</dd>
          <dt>Mémoire</dt><dd>${fmtBytes(info.mem_total)}${h ? ` · swap ${fmtBytes(h.swap.total)} (${fmtPct(h.swap.percent)})` : ""}</dd>
          <dt>Allumé depuis</dt><dd>${fmtDur(h && h.uptime)}</dd>
          <dt>Docker</dt><dd>${d.docker_info.version ? `${d.docker_info.version} · ${d.docker_info.storage_driver}` : "—"}</dd>
        </dl></div></div>
    </div>

    <div class="grid g-main mt">
      <div class="card"><div class="card-head"><h3>Processus les plus gourmands</h3>
        <div class="actions"><div class="seg" id="proc-seg"><button class="active" data-action="proc-sort" data-sort="by_cpu">CPU</button><button data-action="proc-sort" data-sort="by_mem">Mémoire</button></div></div></div>
        <div class="card-body flush" id="procs"><div class="empty"><span class="spinner"></span></div></div></div>
      <div class="card"><div class="card-head"><h3>Espace utilisé par Docker</h3></div>
        <div class="card-body">${df.total != null ? html`
          <div class="row between"><span class="text-2">Total</span><b>${fmtBytes(df.total)}</b></div>
          <div class="mt">${hbars([
            { label: `Images (${df.images.count})`, value: df.images.size },
            { label: `Volumes (${df.volumes.count})`, value: df.volumes.size },
            { label: "Cache de build", value: df.build_cache.size },
            { label: `Conteneurs (${df.containers.count})`, value: df.containers.size },
          ], { fmt: fmtBytes })}</div>
          ${df.reclaimable > 512 * 1024 * 1024 ? html`<div class="callout info mt">${icon("sparkles")}<div><b>${fmtBytes(df.reclaimable)} récupérables.</b><br><span class="small">Images inutilisées et cache de build : <code>docker system prune -a</code> (vérifiez avant : les images non utilisées seront supprimées).</span></div></div>` : ""}` :
          html`<div class="small muted">Mesure en cours (toutes les 10 minutes).</div>`}</div></div>
    </div>`);

  const pctFmt = (x) => `${Math.round(x)} %`;
  lineChart($("#ch-cpu"), labels, [
    { label: "CPU", data: hist.map((p) => p.cpu), color: "--series-1" },
    { label: "Mémoire", data: hist.map((p) => p.mem), color: "--series-2" },
  ], { yMax: 100, yFmt: pctFmt });
  lineChart($("#ch-net"), labels, [
    { label: "Réception", data: hist.map((p) => p.net_rx), color: "--series-3" },
    { label: "Émission", data: hist.map((p) => p.net_tx), color: "--series-4" },
  ], { yFmt: fmtRate });
  lineChart($("#ch-disk"), labels, [{ label: "Disque", data: hist.map((p) => p.disk), color: "--series-1", fill: true }], { yMax: 100, yFmt: pctFmt });
  lineChart($("#ch-load"), labels, [{ label: "Charge", data: hist.map((p) => p.load1), color: "--series-1" }], { yFmt: (x) => Number(x).toFixed(1).replace(".", ",") });

  let procs = null, sort = "by_cpu";
  const renderProcs = () => {
    if (!procs) return;
    const rows = procs[sort];
    setHTML($("#procs"), rows.length ? html`<div class="table-wrap"><table class="table"><thead><tr><th>Processus</th><th>Utilisateur</th><th class="right">CPU</th><th class="right">Mémoire</th></tr></thead>
      <tbody>${rows.map((p) => html`<tr><td><div class="strong">${p.name}</div><div class="tiny muted mono" style="max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${p.cmd}">${p.cmd}</div></td><td class="mono small">${p.user}</td><td class="right num">${fmtPct(p.cpu, 1)}</td><td class="right num">${fmtBytes(p.mem)}</td></tr>`)}</tbody></table></div>` : empty("Liste des processus indisponible", "Montez /proc de l'hôte pour la voir."));
  };
  const loadProcs = async () => { try { procs = await GET("/api/host/processes"); renderProcs(); } catch (e) { /* ignoré */ } };
  App.actions["proc-sort"] = (el) => { sort = el.dataset.sort; $$("#proc-seg button").forEach((b) => b.classList.toggle("active", b === el)); renderProcs(); };
  // Le % CPU d'un processus se calcule entre deux mesures : on en prend deux
  await loadProcs(); setTimeout(loadProcs, 2500);
  every(15000, loadProcs);
  on("host", (x) => patchHTML($("#gauges"), hostGauges(x)));
};

// ===========================================================================
// CONTENEURS
// ===========================================================================
function containerState(c) {
  if (c.status && c.status.includes("unhealthy")) return ["unhealthy", "En échec (healthcheck)"];
  const map = { running: "En marche", exited: "Arrêté", restarting: "Redémarre", paused: "En pause", created: "Créé", dead: "Mort" };
  return [c.state, map[c.state] || c.state];
}
function containerCard(c, traffic) {
  const st = c.stats || {};
  const [cls, label] = containerState(c);
  const tr = traffic[c.name];
  return html`<div class="card container-card clickable" data-action="container-open" data-name="${c.name}" style="cursor:pointer">
    <div class="row between" style="flex-wrap:nowrap"><div style="min-width:0"><div class="name" title="${c.name}">${c.name}</div><div class="img" title="${c.image}">${c.image}</div></div>
      ${c.muted ? html`<span class="badge sev-info" title="Logs non analysés">${icon("volume-x")}Sourdine</span>` : ""}</div>
    <div class="row between"><span class="state ${cls}">${label}</span><span class="tiny muted">${c.status}</span></div>
    ${c.state === "running" ? html`
      <div class="mini"><span>CPU</span>${meter(Math.min(st.cpu || 0, 100), levelOf(st.cpu, 80, 95))}<span class="v">${fmtPct(st.cpu, 1)}</span></div>
      <div class="mini"><span>Mémoire</span>${meter(st.mem_pct || 0, levelOf(st.mem_pct, 80, 90))}<span class="v">${fmtBytes(st.mem_bytes)}</span></div>` : ""}
    ${tr && tr.requests ? html`<div class="tiny muted">${fmtNum(tr.requests)} requêtes / h${tr.errors ? ` · ${fmtNum(tr.errors)} erreurs 5xx` : ""}${tr.attacks ? ` · ${fmtNum(tr.attacks)} attaques` : ""}</div>` : ""}
  </div>`;
}
App.pages.containers = async (view) => {
  setHeader("Conteneurs", "Tous les conteneurs Docker du serveur");
  let d = await GET("/api/containers");
  const render = () => {
    App.live.containers = d.containers;
    const list = [...d.containers].sort((a, b) => (b.state === "running") - (a.state === "running") || a.name.localeCompare(b.name));
    const groups = {};
    list.forEach((c) => { (groups[c.compose_project || "Autres"] = groups[c.compose_project || "Autres"] || []).push(c); });
    setHTML(view, html`
      ${!d.connected ? html`<div class="callout danger" style="margin-bottom:16px">${icon("plug-zap")}<div><b>Docker inaccessible.</b> ${d.error}</div></div>` : ""}
      ${list.length ? Object.entries(groups).sort().map(([g, items]) => html`
        <div class="row" style="margin:6px 0 10px"><h3 style="font-size:13px" class="text-2">${icon("layers")} ${g}</h3><span class="tiny muted">${items.length}</span></div>
        <div class="grid g-4" style="margin-bottom:20px">${items.map((c) => containerCard(c, d.traffic))}</div>`) :
        html`<div class="card">${empty("Aucun conteneur", "LogSonar n'a trouvé aucun conteneur à surveiller.", "box")}</div>`}`);
  };
  render();
  on("containers", (cs) => { d = { ...d, containers: cs, connected: true }; softly(render); });
};
App.actions["container-open"] = async (el) => {
  const name = el.dataset.name;
  const c = (App.live.containers.length ? App.live.containers : []).find((x) => x.name === name) || { name };
  const [cls, label] = containerState(c);
  const st = c.stats || {};
  openOverlay({
    title: name, sub: c.image,
    body: html`<div class="row"><span class="state ${cls}">${label}</span><span class="small muted">${c.status || ""}</span></div>
      <dl class="kv">
        <dt>CPU</dt><dd>${fmtPct(st.cpu, 1)}</dd>
        <dt>Mémoire</dt><dd>${fmtBytes(st.mem_bytes)}${st.mem_limit ? ` / ${fmtBytes(st.mem_limit)} (${fmtPct(st.mem_pct)})` : ""}</dd>
        <dt>Processus</dt><dd>${st.pids ?? "—"}</dd>
        <dt>Réseau</dt><dd>↓ ${fmtBytes(st.net_rx)} · ↑ ${fmtBytes(st.net_tx)} (cumul)</dd>
        <dt>Ports</dt><dd>${(c.ports || []).filter((p) => p.public).map((p) => html`<span class="tag">${p.ip || "0.0.0.0"}:${p.public}→${p.private}</span> `)}${!(c.ports || []).some((p) => p.public) ? "aucun port publié" : ""}</dd>
        <dt>Projet</dt><dd>${c.compose_project || "—"}</dd>
        <dt>Logs analysés</dt><dd>${c.muted ? "Non (sourdine)" : c.watched ? "Oui" : "Non (arrêté)"}</dd>
      </dl>
      <div><div class="row between"><b class="small">CPU et mémoire (6 h)</b>${legend([["CPU %", "--series-1"], ["Mémoire %", "--series-2"]])}</div><div class="chart sm mt"><canvas id="ch-ct"></canvas></div></div>
      <div class="row"><a class="btn sm" href="#/logs?container=${encodeURIComponent(name)}">${icon("square-terminal")}Logs en direct</a>
        <a class="btn sm" href="#/threats?container=${encodeURIComponent(name)}">${icon("shield-alert")}Menaces</a></div>`,
    foot: App.isAdmin() ? html`<button class="btn" data-action="container-mute" data-name="${name}" data-muted="${c.muted ? "0" : "1"}">${icon(c.muted ? "volume-2" : "volume-x")}${c.muted ? "Réactiver l'analyse" : "Mettre en sourdine"}</button>` : "",
  });
  const hist = await GET(`/api/containers/${encodeURIComponent(name)}/history?range=6h`);
  lineChart($("#ch-ct"), hist.map((p) => fmtTime(p.ts)), [
    { label: "CPU", data: hist.map((p) => p.cpu), color: "--series-1" },
    { label: "Mémoire", data: hist.map((p) => p.mem_pct), color: "--series-2" },
  ], { yFmt: (x) => `${Math.round(x)} %` });
};
App.actions["container-mute"] = async (el) => {
  const muted = el.dataset.muted === "1";
  await POST("/api/containers/mute", { name: el.dataset.name, muted });
  toast(muted ? "Logs de ce conteneur ignorés." : "Analyse des logs réactivée.");
  closeOverlay();
};

// ===========================================================================
// TRAFIC
// ===========================================================================
App.pages.traffic = async (view) => {
  setHeader("Trafic", "Requêtes HTTP vues dans les logs, 60 dernières minutes");
  const draw = async () => {
    const t = await GET("/api/traffic?minutes=60");
    const total = t.series.reduce((s, p) => s + p.requests, 0);
    const errors = t.series.reduce((s, p) => s + p.errors, 0);
    const attacks = t.series.reduce((s, p) => s + p.attacks, 0);
    const peak = Math.max(0, ...t.series.map((p) => p.requests));
    const statuses = Object.entries(t.statuses).sort();
    setHTML(view, html`
      <div class="grid g-4">
        <div class="card kpi"><div class="label">${icon("arrow-down-up")}Requêtes (1 h)</div><div class="value">${fmtNum(total)}</div><div class="foot">${fmtNum(total / 60)} / min en moyenne</div></div>
        <div class="card kpi"><div class="label">${icon("trending-up")}Pic</div><div class="value">${fmtNum(peak)}<small>req/min</small></div><div class="foot">normale : ${fmtNum(t.baseline_rpm)} req/min</div></div>
        <div class="card kpi"><div class="label">${icon("server-crash")}Erreurs serveur (5xx)</div><div class="value">${fmtNum(errors)}</div><div class="foot">${total ? fmtPct(errors / total * 100, 1) : "—"} des requêtes</div></div>
        <div class="card kpi"><div class="label">${icon("shield-alert")}Attaques</div><div class="value">${fmtNum(attacks)}</div><div class="foot">détectées dans le trafic</div></div>
      </div>
      <div class="card mt"><div class="card-head"><h3>Requêtes par minute</h3></div><div class="card-body"><div class="chart lg"><canvas id="ch-req"></canvas></div></div></div>
      <div class="grid g-2 mt">
        <div class="card"><div class="card-head"><h3>Erreurs 5xx par minute</h3></div><div class="card-body"><div class="chart sm"><canvas id="ch-err"></canvas></div></div></div>
        <div class="card"><div class="card-head"><h3>Attaques par minute</h3></div><div class="card-body"><div class="chart sm"><canvas id="ch-att"></canvas></div></div></div>
      </div>
      <div class="grid g-3 mt">
        <div class="card"><div class="card-head"><h3>IP les plus actives</h3></div><div class="card-body">${hbars(t.top_ips, { label: (x) => x.ip, value: (x) => x.count })}</div></div>
        <div class="card"><div class="card-head"><h3>URL les plus demandées</h3></div><div class="card-body">${hbars(t.top_paths, { label: (x) => x.path, value: (x) => x.count })}</div></div>
        <div class="card"><div class="card-head"><h3>Codes de réponse</h3></div><div class="card-body">${hbars(statuses.map(([k, n]) => ({ label: k, value: n })))}</div></div>
      </div>
      <div class="card mt"><div class="card-head"><h3>Par conteneur</h3><span class="sub">les conteneurs « bordure » reçoivent le trafic public ; les autres sont derrière eux</span></div>
        <div class="card-body flush"><div class="table-wrap"><table class="table"><thead><tr><th>Conteneur</th><th>Rôle</th><th class="right">Requêtes</th><th class="right">Erreurs 5xx</th><th class="right">Attaques</th></tr></thead>
        <tbody>${t.containers.length ? t.containers.map((c) => html`<tr><td class="mono">${c.container}</td><td>${c.edge ? html`<span class="badge sev-info">${icon("globe")}Bordure</span>` : html`<span class="tiny muted">interne</span>`}</td><td class="right num">${fmtNum(c.requests)}</td><td class="right num">${fmtNum(c.errors)}</td><td class="right num">${fmtNum(c.attacks)}</td></tr>`) : html`<tr><td colspan="5">${empty("Aucun log HTTP reconnu", "Formats pris en charge : Nginx, Apache, Traefik, Caddy, Uvicorn, Gunicorn, Django.")}</td></tr>`}</tbody></table></div></div></div>`);
    const labels = minuteLabels(t.series);
    lineChart($("#ch-req"), labels, [{ label: "Requêtes", data: t.series.map((p) => p.requests), color: "--series-1", fill: true }]);
    barChart($("#ch-err"), labels, [{ label: "Erreurs 5xx", data: t.series.map((p) => p.errors), color: "--series-2" }]);
    barChart($("#ch-att"), labels, [{ label: "Attaques", data: t.series.map((p) => p.attacks), color: "--series-2" }]);
  };
  await draw();
  every(30000, refresh);
};

// ===========================================================================
// LOGS EN DIRECT
// ===========================================================================
App.pages.logs = async (view) => {
  const params = new URLSearchParams(location.hash.split("?")[1] || "");
  const state = { paused: false, attacksOnly: false, container: params.get("container") || "", q: "", count: 0, attacks: 0 };
  const containers = (App.live.containers.length ? App.live.containers : (await GET("/api/containers")).containers).filter((c) => c.state === "running");
  setHeader("Logs en direct", "Toutes les lignes des conteneurs surveillés, analysées en temps réel");
  setHTML(view, html`
    <div class="row" style="margin-bottom:12px">
      <select class="input" id="lg-container" aria-label="Conteneur"><option value="">Tous les conteneurs</option>${containers.map((c) => html`<option value="${c.name}" ${c.name === state.container ? raw("selected") : ""}>${c.name}</option>`)}</select>
      <input class="input" id="lg-q" placeholder="Filtrer (texte, IP…)" style="width:220px">
      <label class="switch"><input type="checkbox" id="lg-att"> Attaques uniquement</label>
      <span class="muted small" id="lg-stats" style="margin-left:auto">0 ligne</span>
      <button class="btn sm" id="lg-pause">${icon("pause")}Pause</button>
      <button class="btn sm ghost" id="lg-clear">${icon("eraser")}Effacer</button>
    </div>
    <div class="terminal" id="term" role="log" aria-live="off"><div class="ln t">En attente de logs…</div></div>`);
  const term = $("#term");
  const MAX = 1500;
  let first = true;
  const statusCls = (s) => (s ? "s" + s[0] : "");
  const add = (e) => {
    state.count++;
    if (e.attack_type) state.attacks++;
    if (state.paused) return;
    if (state.attacksOnly && !e.attack_type) return;
    if (state.container && e.container !== state.container) return;
    if (state.q && !(e.raw + " " + e.ip).toLowerCase().includes(state.q)) return;
    if (first) { term.innerHTML = ""; first = false; }
    const el = document.createElement("div");
    el.className = "ln" + (e.attack_type ? " attack" : "");
    el.innerHTML = html`<span class="t">${fmtTime(e.ts, true)}</span> <span class="c">[${e.container}]</span> ${e.kind === "web"
      ? html`<span class="ip">${e.ip || "-"}</span> ${e.method} ${e.path} <span class="${statusCls(e.status)}">${e.status}</span>`
      : e.raw}${e.attack_type ? html` <span class="a">⚠ ${e.attack_type}</span>` : ""}`.s;
    const stick = term.scrollTop + term.clientHeight >= term.scrollHeight - 30;
    term.appendChild(el);
    while (term.childElementCount > MAX) term.firstElementChild.remove();
    if (stick) term.scrollTop = term.scrollHeight;
  };
  let pending = [];
  on("log", (e) => pending.push(e));
  every(250, () => {
    if (!pending.length) return;
    const batch = pending.splice(0, pending.length);
    batch.forEach(add);
    $("#lg-stats").textContent = `${fmtNum(state.count)} lignes · ${fmtNum(state.attacks)} attaques`;
  });
  bind($("#lg-container"), "change", (e) => { state.container = e.target.value; });
  bind($("#lg-q"), "input", (e) => { state.q = e.target.value.toLowerCase(); });
  bind($("#lg-att"), "change", (e) => { state.attacksOnly = e.target.checked; });
  bind($("#lg-clear"), "click", () => { term.innerHTML = ""; });
  bind($("#lg-pause"), "click", (e) => {
    state.paused = !state.paused;
    setHTML(e.currentTarget, html`${icon(state.paused ? "play" : "pause")}${state.paused ? "Reprendre" : "Pause"}`);
  });
};
