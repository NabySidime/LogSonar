/* LogSonar — pages sécurité : menaces, vulnérabilités, alertes, rapports */
"use strict";

let EXPLAIN = {};

// ===========================================================================
// MENACES
// ===========================================================================
// Filtre par code de réponse : familles (2xx…) puis codes vus sur la période
const STATUS_FAMILY = { 2: "acceptées", 3: "redirigées", 4: "refusées", 5: "erreur serveur", 1: "information" };
function statusOptions(byStatus, current) {
  const fam = {};
  byStatus.forEach((x) => { if (x.status) fam[x.status[0]] = (fam[x.status[0]] || 0) + x.n; });
  const none = byStatus.find((x) => !x.status);
  const opts = [["", "Tous les codes"]];
  if (fam[2] && fam[3]) opts.push(["2xx,3xx", `2xx et 3xx — acceptées ou redirigées (${fmtNum(fam[2] + fam[3])})`]);
  Object.keys(fam).sort().forEach((k) => opts.push([`${k}xx`, `${k}xx — ${STATUS_FAMILY[k] || ""} (${fmtNum(fam[k])})`]));
  byStatus.filter((x) => x.status).forEach((x) => opts.push([x.status, `${x.status} (${fmtNum(x.n)})`]));
  if (none) opts.push(["none", `Sans code (${fmtNum(none.n)})`]);
  if (current && !opts.some(([v]) => v === current)) opts.push([current, `${current} (0)`]);
  return opts.map(([v, l]) => html`<option value="${v}" ${v === current ? raw("selected") : ""}>${l}</option>`);
}

App.pages.threats = async (view) => {
  const params = hashParams();
  const custom = customPeriod();
  const f = { days: Number(params.get("days")) || 7, q: params.get("q") || "", attack_type: params.get("type") || "",
              ip: params.get("ip") || "", severity: params.get("severity") || "", status: params.get("status") || "",
              container: params.get("container") || "", offset: 0 };
  setHeader("Menaces", "Attaques détectées dans les logs de vos applications",
    periodPicker("days", [[1, "Aujourd'hui"], [7, "7 j"], [30, "30 j"], [90, "90 j"]].map(([d, l]) => [String(d), l]), String(f.days), 90));
  const stats = await GET(`/api/security/stats?${qs(custom ? { since: custom.from, until: custom.to } : { days: f.days })}`);
  EXPLAIN = stats.explanations;
  const total = stats.by_type.reduce((s, x) => s + x.n, 0);
  const hourly = stats.timeline.length && stats.timeline[0].hour != null;
  const severalDays = hourly && stats.timeline[0].day !== stats.timeline[stats.timeline.length - 1].day;
  const tlLabel = (x) => (hourly ? `${severalDays ? x.day.slice(8, 10) + "/" + x.day.slice(5, 7) + " " : ""}${pad(x.hour)}h` : x.day.slice(8, 10) + "/" + x.day.slice(5, 7));

  setHTML(view, html`
    <div class="grid g-main">
      <div class="card"><div class="card-head"><h3>Attaques par ${hourly ? "heure" : "jour"}</h3><span class="sub">${fmtNum(total)} au total</span></div>
        <div class="card-body"><div class="chart"><canvas id="ch-days"></canvas></div></div></div>
      <div class="card"><div class="card-head"><h3>Par type</h3></div>
        <div class="card-body">${stats.by_type.length ? html`<div class="hbar">${stats.by_type.slice(0, 8).map((x) => html`
          <a href="#" class="text-2" data-action="threats-filter" data-key="attack_type" data-value="${x.attack_type}" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${x.attack_type}</a>
          <span class="num strong">${fmtNum(x.n)}</span>
          <div class="bar"><i style="width:${(x.n / stats.by_type[0].n * 100).toFixed(1)}%;background:var(--series-2)"></i></div>`)}</div>` : empty("Aucune attaque sur la période", "", "shield-check")}</div></div>
    </div>
    <div class="card mt"><div class="card-head"><h3>IP les plus actives</h3><span class="sub">bannissez les récidivistes (pare-feu, Fail2Ban, CrowdSec)</span></div>
      <div class="card-body flush">${stats.top_ips.length ? html`<div class="table-wrap"><table class="table"><thead><tr><th>IP</th><th class="right">Tentatives</th><th class="right">Types</th><th class="right">Acceptées (2xx)</th><th>Dernière</th><th></th></tr></thead>
        <tbody>${stats.top_ips.map((x) => html`<tr><td class="mono strong">${x.ip}</td><td class="right num">${fmtNum(x.n)}</td><td class="right num">${x.types}</td>
          <td class="right num">${x.success ? html`<a href="#" class="badge sev-high" data-action="threats-ip-ok" data-ip="${x.ip}" title="Voir les requêtes acceptées">${x.success}</a>` : "0"}</td><td class="small muted">${fmtAgo(x.last_ts)}</td>
          <td class="right"><button class="btn sm ghost" data-action="threats-filter" data-key="ip" data-value="${x.ip}">${icon("filter")}Filtrer</button></td></tr>`)}</tbody></table></div>` : empty("Aucune IP", "", "globe")}</div></div>
    <div class="card mt">
      <div class="card-head"><h3>Événements</h3><span class="sub" id="ev-count"></span></div>
      <div class="card-body" style="padding-bottom:10px"><div class="row">
        <input class="input" id="ev-q" placeholder="Rechercher (URL, IP, User-Agent…)" value="${f.q}" style="flex:1;min-width:200px">
        <select class="input" id="ev-type"><option value="">Tous les types</option>${stats.by_type.map((x) => html`<option ${x.attack_type === f.attack_type ? raw("selected") : ""}>${x.attack_type}</option>`)}</select>
        <select class="input" id="ev-sev"><option value="">Toutes gravités</option>${["critical", "high", "medium", "low"].map((s) => html`<option value="${s}" ${s === f.severity ? raw("selected") : ""}>${SEV[s].label}</option>`)}</select>
        <select class="input" id="ev-status" title="Code de réponse du serveur">${statusOptions(stats.by_status, f.status)}</select>
        <input class="input" id="ev-ip" placeholder="IP" value="${f.ip}" style="width:150px">
        <button class="btn sm ghost" id="ev-reset">${icon("x")}Réinitialiser</button>
      </div>${f.container ? html`<div class="small muted mt">Conteneur : <span class="tag">${f.container}</span></div>` : ""}</div>
      <div id="ev-table"></div>
    </div>`);

  barChart($("#ch-days"), stats.timeline.map(tlLabel), [{ label: "Attaques", data: stats.timeline.map((x) => x.count), color: "--series-2" }], { xTicks: 15 });

  // Même période que les statistiques ci-dessus
  const since = stats.since, until = custom && custom.to ? stats.until : "";
  let rows = [];
  const load = async () => {
    const r = await GET(`/api/security/events?${qs({ q: f.q, attack_type: f.attack_type, ip: f.ip, severity: f.severity, status: f.status, container: f.container, since, until, limit: 50, offset: f.offset })}`);
    rows = r.items;
    $("#ev-count").textContent = `${fmtNum(r.total)} résultat(s)`;
    setHTML($("#ev-table"), r.items.length ? html`<div class="table-wrap"><table class="table"><thead><tr><th>Date</th><th>Gravité</th><th>Type</th><th>IP</th><th>Requête</th><th>Code</th><th>Conteneur</th></tr></thead>
      <tbody>${r.items.map((e, i) => html`<tr class="clickable" data-action="event-open" data-i="${i}"><td class="nowrap mono small">${fmtDate(e.ts)}</td><td>${sevBadge(e.severity)}</td><td>${e.attack_type}</td><td class="mono">${e.ip || "—"}</td>
        <td class="path" title="${e.path}">${e.method} ${e.path || e.raw}</td><td class="mono">${e.status || "—"}</td><td class="mono small">${e.container}</td></tr>`)}</tbody></table></div>
      <div class="pager"><span>${f.offset + 1}–${f.offset + r.items.length} sur ${fmtNum(r.total)}</span><div class="row">
        <button class="btn sm" data-action="ev-page" data-d="-50" ${f.offset ? "" : raw("disabled")}>${icon("chevron-left")}Précédent</button>
        <button class="btn sm" data-action="ev-page" data-d="50" ${f.offset + 50 < r.total ? "" : raw("disabled")}>Suivant${icon("chevron-right")}</button></div></div>` :
      empty("Aucun événement", "Aucune attaque ne correspond à ces filtres.", "search-x"));
  };
  let debounce;
  const changed = () => { clearTimeout(debounce); debounce = setTimeout(() => { f.offset = 0; load(); }, 300); };
  bind($("#ev-q"), "input", (e) => { f.q = e.target.value; changed(); });
  bind($("#ev-ip"), "input", (e) => { f.ip = e.target.value.trim(); changed(); });
  bind($("#ev-type"), "change", (e) => { f.attack_type = e.target.value; changed(); });
  bind($("#ev-sev"), "change", (e) => { f.severity = e.target.value; changed(); });
  bind($("#ev-status"), "change", (e) => { f.status = e.target.value; changed(); });
  bind($("#ev-reset"), "click", () => { location.hash = `#/threats?${qs(custom ? { from: custom.from, to: custom.to } : { days: f.days })}`; });
  App.actions["ev-page"] = (el) => { f.offset = Math.max(0, f.offset + Number(el.dataset.d)); load(); };
  App.actions["event-open"] = (el) => openEvent(rows[Number(el.dataset.i)]);
  App.actions["threats-filter"] = (el) => {
    if (el.dataset.key === "ip") { f.ip = el.dataset.value; $("#ev-ip").value = f.ip; }
    else { f.attack_type = el.dataset.value; $("#ev-type").value = f.attack_type; }
    f.offset = 0; load(); $("#ev-table").scrollIntoView({ behavior: "smooth", block: "start" });
  };
  App.actions["threats-ip-ok"] = (el) => {
    f.ip = el.dataset.ip; $("#ev-ip").value = f.ip;
    f.status = "2xx"; $("#ev-status").value = "2xx";
    f.offset = 0; load(); $("#ev-table").scrollIntoView({ behavior: "smooth", block: "start" });
  };
  await load();
};

function openEvent(e) {
  const ex = EXPLAIN[e.attack_type] || EXPLAIN[(e.attack_type || "").split(" (")[0]];
  openOverlay({
    title: e.attack_type, sub: fmtDate(e.ts),
    body: html`<div class="row">${sevBadge(e.severity)}${e.status && e.status.startsWith("2") && ["high", "critical"].includes(e.severity) ? (e.neutral
      ? html`<span class="badge sev-info">${icon("shield-check")}Page servie normalement</span>`
      : html`<span class="badge sev-critical">${icon("triangle-alert")}Requête acceptée par le serveur</span>`) : ""}</div>
    ${e.neutral ? html`<p class="small muted" style="margin:8px 0 0">${e.neutral}</p>` : ""}
      ${ex ? html`<div class="callout info">${icon("lightbulb")}<div><b>De quoi s'agit-il ?</b><br>${ex.what}<br><br><b>Que faire ?</b><br>${ex.fix}</div></div>` : ""}
      <dl class="kv"><dt>IP source</dt><dd class="mono">${e.ip || "—"}</dd><dt>Conteneur</dt><dd class="mono">${e.container}</dd>
        <dt>Requête</dt><dd class="mono break">${e.method} ${e.path || "—"}</dd><dt>Réponse</dt><dd class="mono">${e.status || "—"}</dd>
        <dt>User-Agent</dt><dd class="mono small break">${e.ua || "—"}</dd></dl>
      <div><div class="small strong" style="margin-bottom:6px">Log brut</div><pre class="raw">${e.raw}</pre></div>`,
    foot: e.ip ? html`<a class="btn" href="#/threats?days=30&ip=${encodeURIComponent(e.ip)}">${icon("filter")}Toutes les attaques de cette IP</a>` : "",
  });
}

// ===========================================================================
// VULNÉRABILITÉS
// ===========================================================================
const SEV_KEYS = ["critical", "high", "medium", "low", "unknown"];
App.pages.vulns = async (view) => {
  const tab = new URLSearchParams(location.hash.split("?")[1] || "").get("tab") || "vulns";
  const d = await GET("/api/vulns/summary");
  const scan = d.scan, s = scan ? scan.summary : null, state = d.state;
  setHeader("Vulnérabilités", "Failles connues des paquets installés et audit de configuration",
    App.isAdmin() ? html`<button class="btn primary" data-action="scan-start" ${state.running ? raw("disabled") : ""}>${icon("scan-search")}Lancer un scan</button>` : "");
  const v = (s && s.vulns_by_severity) || {};
  const tabs = [["vulns", "Vulnérabilités", s ? s.vulns_total : 0], ["config", "Configuration", s ? s.config_total : 0], ["targets", "Cibles analysées", s ? s.targets.length : 0], ["tls", "Certificats TLS", null]];

  setHTML(view, html`
    <div id="scan-progress" class="${state.running ? "" : "hidden"}"><div class="card card-body" style="margin-bottom:16px"><div class="row between"><b class="small" id="scan-stage">${state.stage || "Scan en cours…"}</b><span class="spinner"></span></div><div class="progress mt"><i id="scan-bar" style="width:${state.progress}%"></i></div></div></div>
    ${!scan ? html`<div class="card">${empty("Aucun scan pour l'instant", "Le premier scan démarre automatiquement peu après l'installation, puis chaque nuit.", "scan-search")}</div>` : html`
    <div class="grid g-4">
      <div class="card kpi"><div class="label">${icon("octagon-alert")}Critiques</div><div class="value" style="color:var(--critical)">${fmtNum(v.critical)}</div><div class="foot">à corriger en priorité</div></div>
      <div class="card kpi"><div class="label">${icon("triangle-alert")}Élevées</div><div class="value">${fmtNum(v.high)}</div><div class="foot">${fmtNum(v.medium)} moyennes · ${fmtNum(v.low)} faibles</div></div>
      <div class="card kpi"><div class="label">${icon("wrench")}Corrigeables</div><div class="value">${fmtNum(s.fixable)}</div><div class="foot">une version corrigée existe</div></div>
      <div class="card kpi"><div class="label">${icon("package")}Paquets analysés</div><div class="value">${fmtNum(s.packages_total)}</div><div class="foot">scan ${fmtAgo(scan.finished_ts)} · ${s.duration} s</div></div>
    </div>
    ${s.errors && s.errors.length ? html`<div class="callout warn mt">${icon("triangle-alert")}<div>${s.errors.join(" · ")}</div></div>` : ""}
    <div class="tabs mt-lg">${tabs.map(([k, l, n]) => html`<button class="${k === tab ? "active" : ""}" data-action="vulns-tab" data-tab="${k}">${l}${n != null ? html`<span class="count">${fmtNum(n)}</span>` : ""}</button>`)}</div>
    <div id="vtab"></div>`}`);

  on("scan", (st) => {
    $("#scan-progress").classList.toggle("hidden", !st.running);
    if (st.running) { $("#scan-stage").textContent = st.stage; $("#scan-bar").style.width = st.progress + "%"; }
    else { toast("Scan de sécurité terminé."); refresh(); }
  });
  if (!scan) return;
  const el = $("#vtab");
  if (tab === "vulns") await vulnsTab(el, s, d.top_packages);
  else if (tab === "config") await configTab(el);
  else if (tab === "targets") targetsTab(el, s);
  else await tlsTab(el);
};
App.actions["vulns-tab"] = (el) => { location.hash = `#/vulns?tab=${el.dataset.tab}`; };
App.actions["scan-start"] = async () => {
  try { await POST("/api/vulns/scan"); toast("Scan lancé : cela prend en général une à trois minutes."); refresh(); }
  catch (e) { toast(e.message, "error"); }
};

const SEV_RANK = ["critical", "high", "medium", "low", "info", "unknown"];
async function vulnsTab(el, s, top) {
  const f = { target: "", severity: "", q: "", fixable: true, offset: 0 };
  let rows = [];
  setHTML(el, html`
    ${top.length ? html`<div class="card" style="margin-bottom:16px"><div class="card-head"><h3>Paquets à mettre à jour en priorité</h3></div>
      <div class="card-body flush"><div class="table-wrap"><table class="table"><thead><tr><th>Paquet</th><th>Version installée</th><th>Pire gravité</th><th class="right">Failles</th><th>Corrigé en</th><th>Où</th></tr></thead>
      <tbody>${top.slice(0, 8).map((p) => html`<tr><td class="mono strong">${p.package} <span class="tag">${p.ecosystem.split(":")[0]}</span></td><td class="mono small">${p.version}</td><td>${sevBadge(SEV_RANK[p.sev_rank])}</td><td class="right num">${p.n}</td><td class="mono small">${p.fixed_version || html`<span class="muted">pas encore</span>`}</td><td class="small muted" style="max-width:260px">${(p.targets || "").split(",").slice(0, 3).join(", ")}</td></tr>`)}</tbody></table></div></div></div>` : ""}
    <div class="card">
      <div class="card-body" style="padding-bottom:10px"><div class="row">
        <input class="input" id="vf-q" placeholder="Paquet, CVE…" style="flex:1;min-width:180px">
        <select class="input" id="vf-target"><option value="">Toutes les cibles</option>${s.targets.map((t) => html`<option value="${t.name}">${t.name}</option>`)}</select>
        <select class="input" id="vf-sev"><option value="">Toutes gravités</option>${SEV_KEYS.map((k) => html`<option value="${k}">${SEV[k].label}</option>`)}</select>
        <label class="switch"><input type="checkbox" id="vf-fix" checked> Avec correctif uniquement</label>
        <span class="small muted" id="vf-count" style="margin-left:auto"></span>
      </div></div>
      <div id="vf-table"></div>
    </div>`);
  const load = async () => {
    const r = await GET(`/api/vulns/findings?${qs({ ...f, limit: 50 })}`);
    rows = r.items;
    $("#vf-count").textContent = `${fmtNum(r.total)} résultat(s)`;
    setHTML($("#vf-table"), r.items.length ? html`<div class="table-wrap"><table class="table"><thead><tr><th>Gravité</th><th>Vulnérabilité</th><th>Paquet</th><th>Installé</th><th>Corrigé en</th><th>Cible</th></tr></thead>
      <tbody>${r.items.map((x, i) => html`<tr class="clickable" data-action="vuln-open" data-i="${i}"><td>${sevBadge(x.severity)}${x.score ? html` <span class="tiny muted num">${x.score}</span>` : ""}</td>
        <td><div class="mono small strong">${(x.aliases.split(",").find((a) => a.startsWith("CVE-")) || x.vuln_id)}</div><div class="tiny muted" style="max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${x.summary}</div></td>
        <td class="mono small">${x.package}</td><td class="mono small">${x.version}</td><td class="mono small">${x.fixed_version || html`<span class="muted">—</span>`}</td><td class="small">${x.target}</td></tr>`)}</tbody></table></div>
      <div class="pager"><span>${f.offset + 1}–${f.offset + r.items.length} sur ${fmtNum(r.total)}</span><div class="row">
        <button class="btn sm" data-action="vf-page" data-d="-50" ${f.offset ? "" : raw("disabled")}>${icon("chevron-left")}Précédent</button>
        <button class="btn sm" data-action="vf-page" data-d="50" ${f.offset + 50 < r.total ? "" : raw("disabled")}>Suivant${icon("chevron-right")}</button></div></div>` :
      empty("Aucune vulnérabilité", f.fixable ? "Aucune faille avec correctif disponible pour ces filtres. Décochez « avec correctif » pour tout voir." : "Rien ne correspond à ces filtres.", "shield-check"));
  };
  let deb;
  const changed = () => { clearTimeout(deb); deb = setTimeout(() => { f.offset = 0; load(); }, 300); };
  bind($("#vf-q"), "input", (e) => { f.q = e.target.value; changed(); });
  bind($("#vf-target"), "change", (e) => { f.target = e.target.value; changed(); });
  bind($("#vf-sev"), "change", (e) => { f.severity = e.target.value; changed(); });
  bind($("#vf-fix"), "change", (e) => { f.fixable = e.target.checked; changed(); });
  App.actions["vf-page"] = (b) => { f.offset = Math.max(0, f.offset + Number(b.dataset.d)); load(); };
  App.actions["vuln-open"] = (b) => {
    const x = rows[Number(b.dataset.i)];
    const ids = [x.vuln_id, ...x.aliases.split(",").filter(Boolean)];
    openOverlay({
      title: ids.find((a) => a.startsWith("CVE-")) || x.vuln_id, sub: `${x.package} ${x.version}`,
      body: html`<div class="row">${sevBadge(x.severity)}${x.score ? html`<span class="tag">CVSS ${x.score}</span>` : ""}<span class="tag">${x.ecosystem}</span></div>
        <p style="margin:0">${x.summary || "Pas de description fournie."}</p>
        <dl class="kv"><dt>Paquet</dt><dd class="mono">${x.package}</dd><dt>Version installée</dt><dd class="mono">${x.version}</dd>
          <dt>Version corrigée</dt><dd class="mono">${x.fixed_version || "Aucune pour l'instant"}</dd><dt>Cible</dt><dd>${x.target}${x.image ? html` <span class="tag">${x.image}</span>` : ""}</dd>
          <dt>Références</dt><dd>${ids.map((id) => html`<a class="tag" href="https://osv.dev/vulnerability/${encodeURIComponent(id)}" target="_blank" rel="noopener noreferrer">${id}</a> `)}</dd></dl>
        <div class="callout info">${icon("wrench")}<div>${fixAdvice(x)}</div></div>`,
    });
  };
  await load();
}
function fixAdvice(x) {
  const eco = x.ecosystem.split(":")[0];
  if (!x.fixed_version) return html`Aucune version corrigée n'est encore publiée. Surveillez les mises à jour, et vérifiez si la fonctionnalité concernée est réellement utilisée.`;
  if (x.target_kind === "host") {
    if (eco === "Alpine") return html`Sur le serveur : <code>apk upgrade</code>.`;
    return html`Sur le serveur : <code>sudo apt update &amp;&amp; sudo apt upgrade</code>.`;
  }
  if (eco === "PyPI") return html`Dans le projet : passez <code>${x.package}</code> en version <code>${x.fixed_version}</code> ou plus dans requirements.txt, puis reconstruisez l'image.`;
  if (eco === "npm") return html`Dans le projet : <code>npm install ${x.package}@${x.fixed_version}</code> (ou <code>npm audit fix</code>), puis reconstruisez l'image.`;
  return html`Paquet système de l'image : reconstruisez l'image avec une version récente de l'image de base (<code>docker compose build --pull</code>), ou ajoutez <code>apt-get upgrade</code> / <code>apk upgrade</code> dans le Dockerfile.`;
}

async function configTab(el) {
  const items = await GET("/api/vulns/config");
  if (!items.length) { setHTML(el, html`<div class="card">${empty("Aucun problème de configuration", "", "shield-check")}</div>`); return; }
  const groups = {};
  items.forEach((x) => (groups[x.target] = groups[x.target] || []).push(x));
  const nAccepted = items.filter((x) => x.accepted).length;
  setHTML(el, html`${nAccepted ? html`<p class="small muted" style="margin:0 0 12px">${icon("shield-check")} ${nAccepted} risque(s) accepté(s) : ils ne comptent plus dans le score ni dans les alertes.</p>` : ""}
    ${Object.entries(groups).map(([target, list]) => html`
    <div class="card" style="margin-bottom:12px"><div class="card-head"><h3 class="mono">${target}</h3><span class="sub">${list.length} constat(s)</span></div>
      <div class="card-body flush"><div class="list">${list.map((x) => html`<div class="list-item" style="${x.accepted ? "opacity:.6" : ""}">
        <span class="sev-dot ${x.severity === "medium" ? "warning" : x.severity}"></span>
        <div class="grow"><div class="title">${x.title}</div><div class="small text-2" style="margin-top:2px">${x.detail}</div>
          <div class="small" style="margin-top:6px">${icon("wrench")} ${x.fix}</div>
          ${App.isAdmin() && ["critical", "high", "medium"].includes(x.severity) ? html`<div style="margin-top:8px"><button class="btn sm" data-action="config-accept" data-target="${x.target}" data-check="${x.check_id}" data-accepted="${x.accepted ? "0" : "1"}">${icon(x.accepted ? "rotate-ccw" : "check")}${x.accepted ? "Ne plus accepter" : "Accepter le risque"}</button></div>` : ""}</div>
        ${x.accepted ? html`<span class="badge sev-good">${icon("check")}Risque accepté</span>` : sevBadge(x.severity)}</div>`)}</div></div></div>`)}`);
}
App.actions["config-accept"] = async (el) => {
  const accepted = el.dataset.accepted === "1";
  if (accepted && !(await confirmDialog("Accepter ce risque ?",
    "À faire seulement si ce réglage est voulu (ex. mailcow a besoin d'un conteneur privilégié pour son pare-feu). Il ne comptera plus dans le score ni dans les alertes.", "Accepter"))) return;
  try {
    await POST("/api/vulns/config/accept", { target: el.dataset.target, check_id: el.dataset.check, accepted });
    toast(accepted ? "Risque accepté." : "Le risque compte de nouveau dans le score.");
    refresh();
  } catch (e) { toast(e.message, "error"); }
};

function targetsTab(el, s) {
  setHTML(el, html`<div class="card"><div class="card-body flush"><div class="table-wrap"><table class="table"><thead><tr><th>Cible</th><th>Système</th><th>Sources</th><th class="right">Paquets</th><th>Vulnérabilités</th></tr></thead>
    <tbody>${s.targets.map((t) => html`<tr><td><div class="strong mono">${t.name}</div>${t.image ? html`<div class="tiny muted mono">${t.image}</div>` : ""}</td><td class="small">${t.os || "—"}</td>
      <td class="small text-2">${t.sources.length ? t.sources.join(" · ") : html`<span class="muted">aucun gestionnaire de paquets reconnu</span>`}</td><td class="right num">${fmtNum(t.packages)}</td>
      <td><div class="row">${["critical", "high", "medium"].map((k) => (t.vulns[k] ? html`<span class="badge sev-${k}">${t.vulns[k]} ${SEV[k].label.toLowerCase()}</span>` : ""))}${!Object.keys(t.vulns).length ? html`<span class="badge sev-good">${icon("check")}Aucune</span>` : ""}</div></td></tr>`)}</tbody></table></div></div></div>
    <p class="small muted mt">Formats lus : paquets Debian/Ubuntu (dpkg), Alpine (apk), Python (site-packages), Node.js (package-lock.json). Les binaires Go/Java et les images Red Hat ne sont pas encore analysés.</p>`);
}

async function tlsTab(el) {
  const items = await GET("/api/vulns/tls");
  setHTML(el, html`<div class="card"><div class="card-head"><h3>Certificats surveillés</h3>
    <div class="actions">${App.isAdmin() ? html`<a class="btn sm" href="#/settings">${icon("settings")}Domaines</a><button class="btn sm" data-action="tls-check">${icon("refresh-cw")}Vérifier</button>` : ""}</div></div>
    <div class="card-body flush">${items.length ? html`<div class="table-wrap"><table class="table"><thead><tr><th>Domaine</th><th>État</th><th>Expiration</th><th>Émetteur</th><th>Vérifié</th></tr></thead>
    <tbody>${items.map((t) => html`<tr><td class="mono strong">${t.domain}${t.port !== 443 ? ":" + t.port : ""}</td>
      <td>${!t.ok ? html`<span class="badge sev-critical">${icon("x")}${t.error}</span>` : t.days_left <= 14 ? html`<span class="badge sev-warning">${icon("clock")}${t.days_left} jours</span>` : html`<span class="badge sev-good">${icon("check")}${t.days_left} jours</span>`}</td>
      <td class="small">${t.expires ? fmtDate(t.expires, false) : "—"}</td><td class="small">${t.issuer || "—"}</td><td class="small muted">${fmtAgo(t.checked_ts)}</td></tr>`)}</tbody></table></div>` :
    empty("Aucun domaine surveillé", "Ajoutez vos domaines dans Paramètres pour être prévenu avant l'expiration de leurs certificats.", "lock")}</div></div>`);
}
App.actions["tls-check"] = async () => { await POST("/api/vulns/tls/check"); toast("Certificats vérifiés."); refresh(); };

// ===========================================================================
// ALERTES
// ===========================================================================
let alertRows = {};
const ALERT_PERIODS = { all: 0, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400 };
App.pages.alerts = async (view) => {
  const params = hashParams();
  const status = params.get("status") || "active";
  const period = ALERT_PERIODS[params.get("period")] != null ? params.get("period") : "all";
  const custom = customPeriod();
  setHeader("Alertes", "Problèmes détectés sur le serveur, les conteneurs et la sécurité",
    periodPicker("period", [["all", "Tout"], ["24h", "24 h"], ["7d", "7 j"], ["30d", "30 j"]], period, 90));
  const range = custom ? { since: custom.from, until: custom.to } : { since: ALERT_PERIODS[period] ? Math.floor(Date.now() / 1000 - ALERT_PERIODS[period]) : "" };
  const r = await GET(`/api/alerts?${qs({ status, limit: 200, ...range })}`);
  alertRows = {};
  r.items.forEach((a) => (alertRows[a.id] = a));
  const CAT = { security: "Sécurité", host: "Serveur", container: "Conteneur", traffic: "Trafic", vulnerability: "Vulnérabilités", config: "Configuration", tls: "TLS", system: "Système" };
  setHTML(view, html`
    <div class="tabs">${[["active", "En cours"], ["resolved", "Résolues"], ["all", "Toutes"]].map(([k, l]) => html`<button class="${k === status ? "active" : ""}" data-action="alerts-tab" data-status="${k}">${l}${k === status ? html`<span class="count">${fmtNum(r.total)}</span>` : ""}</button>`)}</div>
    <div class="card">${r.items.length ? html`<div class="table-wrap"><table class="table"><thead><tr><th>Gravité</th><th>Alerte</th><th>Catégorie</th><th class="right">Occurrences</th><th>Dernière</th><th>État</th></tr></thead>
      <tbody>${r.items.map((a) => html`<tr class="clickable" data-action="alert-open" data-id="${a.id}"><td>${sevBadge(a.severity)}</td><td><div class="strong">${a.title}</div><div class="tiny muted">${a.source}</div></td>
        <td class="small">${CAT[a.category] || a.category}</td><td class="right num">${fmtNum(a.count)}</td><td class="small muted nowrap">${fmtAgo(a.last_ts)}</td>
        <td class="small">${STATUS_LABEL[a.status]}</td></tr>`)}</tbody></table></div>` :
      empty(status === "active" ? "Aucune alerte en cours" : "Aucune alerte", status === "active" ? "Tout fonctionne normalement." : "", "circle-check")}</div>`);
  on("alert", () => refresh());
};
App.actions["alerts-tab"] = (el) => setHashParams({ status: el.dataset.status });
App.actions["alert-open"] = async (el) => {
  let a = alertRows[el.dataset.id];
  if (!a) {
    const r = await GET("/api/alerts?status=all&limit=500");
    r.items.forEach((x) => (alertRows[x.id] = x));
    a = alertRows[el.dataset.id];
    if (!a) return;
  }
  openOverlay({
    title: a.title, sub: `${a.source} · ${STATUS_LABEL[a.status]}`,
    body: html`<div class="row">${sevBadge(a.severity)}<span class="small muted">${fmtNum(a.count)} occurrence(s)</span></div>
      <dl class="kv"><dt>Première fois</dt><dd>${fmtDate(a.first_ts)}</dd><dt>Dernière fois</dt><dd>${fmtDate(a.last_ts)} (${fmtAgo(a.last_ts)})</dd>
        ${a.resolved_ts ? html`<dt>Résolue</dt><dd>${fmtDate(a.resolved_ts)}</dd>` : ""}<dt>Notifiée</dt><dd>${a.notified ? "Oui" : "Non"}</dd></dl>
      <pre class="msg">${a.message}</pre>`,
    foot: a.status !== "resolved" ? html`${a.status === "open" ? html`<button class="btn" data-action="alert-set" data-id="${a.id}" data-status="acknowledged">${icon("eye")}Prendre en compte</button>` : ""}
      <button class="btn primary" data-action="alert-set" data-id="${a.id}" data-status="resolved">${icon("check")}Marquer résolue</button>` : "",
  });
};
App.actions["alert-set"] = async (el) => {
  await POST(`/api/alerts/${el.dataset.id}/status`, { status: el.dataset.status });
  closeOverlay();
  toast(el.dataset.status === "resolved" ? "Alerte résolue." : "Alerte prise en compte.");
  refreshAlertCount();
  refresh();
};

// ===========================================================================
// RAPPORTS
// ===========================================================================
App.pages.reports = async (view) => {
  setHeader("Rapports", "Un rapport quotidien est généré automatiquement chaque nuit");
  const list = await GET("/api/reports");
  const today = new Date();
  const iso = `${today.getFullYear()}-${pad(today.getMonth() + 1)}-${pad(today.getDate())}`;
  setHTML(view, html`
    ${App.isAdmin() ? html`<div class="card card-body" style="margin-bottom:16px"><div class="row">
      <b class="small">Générer un rapport</b><input type="date" class="input" id="rp-date" value="${iso}" max="${iso}">
      <button class="btn primary" data-action="report-gen">${icon("file-plus")}Générer</button>
      <button class="btn" data-action="report-gen" data-send="1" title="Envoie aussi le résumé sur les canaux de notification">${icon("send")}Générer et envoyer</button></div></div>` : ""}
    <div class="card">${list.length ? html`<div class="list">${list.map((r) => html`<div class="list-item">
      ${icon("file-text")}<div class="grow"><div class="title">Rapport du ${r.date.slice(8, 10)}/${r.date.slice(5, 7)}/${r.date.slice(0, 4)}
        ${r.verdict ? html` <span class="badge ${{ bad: "sev-critical", warn: "sev-warning", good: "sev-good" }[r.verdict]}">${r.verdict_label}</span>` : ""}</div>
        <div class="meta">${r.headline ? html`${r.headline} · score ${r.score}/100` : fmtBytes(r.size)}</div></div>
      <a class="btn sm" href="/api/reports/${encodeURIComponent(r.filename)}" target="_blank" rel="noopener">${icon("external-link")}Ouvrir</a>
      <a class="btn sm ghost" href="/api/reports/${encodeURIComponent(r.filename)}?download=true">${icon("download")}</a>
      ${App.isAdmin() ? html`<button class="btn sm ghost danger" data-action="report-del" data-f="${r.filename}" aria-label="Supprimer">${icon("trash-2")}</button>` : ""}</div>`)}</div>` :
      empty("Aucun rapport", "Le premier sera généré cette nuit, ou générez-en un maintenant.", "file-text")}</div>`);
};
App.actions["report-gen"] = async (el) => {
  const send = el.dataset.send === "1";
  el.disabled = true;
  try { const r = await POST(`/api/reports/generate?date=${$("#rp-date").value}${send ? "&send=true" : ""}`); toast(send ? "Rapport généré et envoyé." : "Rapport généré."); refresh(); window.open(`/api/reports/${r.filename}`, "_blank", "noopener"); }
  catch (e) { toast(e.message, "error"); el.disabled = false; }
};
App.actions["report-del"] = async (el) => {
  if (!(await confirmDialog("Supprimer ce rapport ?", "Cette action est définitive.", "Supprimer"))) return;
  await DEL(`/api/reports/${encodeURIComponent(el.dataset.f)}`);
  toast("Rapport supprimé."); refresh();
};
