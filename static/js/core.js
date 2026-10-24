/* LogSonar — socle de l'interface : utilitaires, API, graphiques, routeur, temps réel */
"use strict";

// ---------------------------------------------------------------------------
// HTML sûr : toute valeur interpolée est échappée, sauf si elle vient de html``
// ---------------------------------------------------------------------------
class Raw { constructor(s) { this.s = s; } toString() { return this.s; } }
const raw = (s) => new Raw(s);
const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const esc = (v) => String(v == null ? "" : v).replace(/[&<>"']/g, (c) => ESC[c]);
function html(strings, ...vals) {
  let out = strings[0];
  vals.forEach((v, i) => {
    if (v instanceof Raw) out += v.s;
    else if (Array.isArray(v)) out += v.map((x) => (x instanceof Raw ? x.s : esc(x))).join("");
    else if (v !== false && v != null) out += esc(v);
    out += strings[i + 1];
  });
  return raw(out);
}
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
function setHTML(el, content) {
  if (App.soft && el.firstChild) { patchHTML(el, content); return; }
  el.innerHTML = content instanceof Raw ? content.s : esc(content); icons(el);
}

// ---------------------------------------------------------------------------
// Mise à jour sur place : on compare le nouveau rendu à la page affichée et on
// ne modifie que ce qui a changé. Pas de clignotement, le défilement, la saisie
// en cours et les graphiques (canvas) sont conservés.
// ---------------------------------------------------------------------------
function patchHTML(el, content) {
  const tmp = document.createElement("div");
  tmp.innerHTML = content instanceof Raw ? content.s : esc(content);
  icons(tmp);
  patchChildren(el, tmp);
}
function patchChildren(a, b) {
  const an = Array.from(a.childNodes), bn = Array.from(b.childNodes);
  bn.forEach((y, i) => { if (an[i]) patchNode(an[i], y); else a.appendChild(y); });
  for (let i = an.length - 1; i >= bn.length; i--) an[i].remove();
}
function patchNode(x, y) {
  if (x.nodeType !== y.nodeType || x.nodeName !== y.nodeName || (x.nodeType === 1 && x.id !== y.id)) { x.replaceWith(y); return; }
  if (x.nodeType !== 1) { if (x.nodeValue !== y.nodeValue) x.nodeValue = y.nodeValue; return; }
  if (x.nodeName === "CANVAS") return;              // graphique : mis à jour par Chart.js
  const keepOpen = x.nodeName === "DETAILS";        // un bloc déplié par l'utilisateur le reste
  for (const { name } of Array.from(x.attributes)) if (!y.hasAttribute(name) && !(keepOpen && name === "open")) x.removeAttribute(name);
  for (const { name, value } of Array.from(y.attributes)) if (x.getAttribute(name) !== value) x.setAttribute(name, value);
  patchChildren(x, y);
  if (x !== document.activeElement) {                // jamais pendant que l'utilisateur tape
    if (x.nodeName === "INPUT") { if (x.type === "checkbox" || x.type === "radio") x.checked = y.checked; else x.value = y.value; }
    else if (x.nodeName === "SELECT" || x.nodeName === "TEXTAREA") x.value = y.value;
  }
}
// Exécute un rendu synchrone en mode « mise à jour sur place »
function softly(fn) { const prev = App.soft; App.soft = true; try { return fn(); } finally { App.soft = prev; } }
// Gestionnaire d'événement unique : rebrancher après une mise à jour ne le double pas
function bind(el, type, fn) {
  if (!el) return;
  const key = "__ls_" + type;
  if (el[key]) el.removeEventListener(type, el[key]);
  el[key] = fn;
  el.addEventListener(type, fn);
}
function icons(root) { if (window.lucide) lucide.createIcons({ root: root || document }); }
const icon = (name, cls = "") => raw(`<i data-lucide="${esc(name)}" class="${esc(cls)}"></i>`);

// ---------------------------------------------------------------------------
// Formats
// ---------------------------------------------------------------------------
const nf = new Intl.NumberFormat("fr-FR");
const fmtNum = (n) => (n == null ? "—" : nf.format(Math.round(n)));
function fmtBytes(n, dec = 1) {
  if (n == null || isNaN(n)) return "—";
  const u = ["o", "Ko", "Mo", "Go", "To", "Po"];
  let i = 0;
  while (Math.abs(n) >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i === 0 ? 0 : dec).replace(".", ",")} ${u[i]}`;
}
const fmtRate = (n) => (n == null ? "—" : fmtBytes(n) + "/s");
const fmtPct = (n, d = 0) => (n == null ? "—" : `${Number(n).toFixed(d).replace(".", ",")} %`);
function fmtDur(sec) {
  if (sec == null) return "—";
  sec = Math.max(0, Math.round(sec));
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d) return `${d} j ${h} h`;
  if (h) return `${h} h ${m} min`;
  if (m) return `${m} min`;
  return `${sec} s`;
}
const pad = (n) => String(n).padStart(2, "0");
function fmtTime(ts, withSec = false) {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}${withSec ? ":" + pad(d.getSeconds()) : ""}`;
}
function fmtDate(ts, withTime = true) {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  const s = `${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()}`;
  return withTime ? `${s} ${fmtTime(ts)}` : s;
}
function fmtAgo(ts) {
  if (!ts) return "—";
  const s = Date.now() / 1000 - ts;
  if (s < 60) return "à l'instant";
  if (s < 3600) return `il y a ${Math.floor(s / 60)} min`;
  if (s < 86400) return `il y a ${Math.floor(s / 3600)} h`;
  return `il y a ${Math.floor(s / 86400)} j`;
}

const SEV = {
  critical: { label: "Critique", icon: "octagon-alert" },
  high: { label: "Élevée", icon: "triangle-alert" },
  warning: { label: "Avertissement", icon: "triangle-alert" },
  medium: { label: "Moyenne", icon: "circle-alert" },
  low: { label: "Faible", icon: "info" },
  info: { label: "Info", icon: "info" },
  unknown: { label: "Non évaluée", icon: "circle-help" },
};
const sevBadge = (s) => html`<span class="badge sev-${s || "unknown"}">${icon((SEV[s] || SEV.unknown).icon)}${(SEV[s] || SEV.unknown).label}</span>`;
const levelOf = (pct, warn, crit) => (pct == null ? "" : pct >= crit ? "critical" : pct >= warn ? "warning" : "good");
const meter = (pct, level) => html`<div class="meter ${level || ""}" role="meter" aria-valuenow="${Math.round(pct || 0)}" aria-valuemin="0" aria-valuemax="100"><i style="width:${Math.min(100, Math.max(0, pct || 0)).toFixed(1)}%"></i></div>`;
const empty = (title, text = "", ic = "inbox") => html`<div class="empty">${icon(ic)}<div class="title">${title}</div>${text ? html`<div class="small">${text}</div>` : ""}</div>`;
const STATUS_LABEL = { open: "Ouverte", acknowledged: "Prise en compte", resolved: "Résolue" };

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------
async function api(method, url, body) {
  const opts = { method, credentials: "same-origin", headers: { "X-LogSonar": "1" } };
  if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  const res = await fetch(url, opts);
  if (res.status === 401) { window.location.replace("/login"); throw new Error("Session expirée"); }
  let data = null;
  try { data = await res.json(); } catch (e) { /* pas de corps */ }
  if (!res.ok) {
    let msg = data && data.detail;
    if (Array.isArray(msg)) msg = "Champ invalide : " + msg.map((d) => (d.loc || []).slice(-1)[0]).join(", ");
    throw new Error(msg || `Erreur ${res.status}`);
  }
  return data;
}
const GET = (u) => api("GET", u);
const POST = (u, b = {}) => api("POST", u, b);
const PUT = (u, b) => api("PUT", u, b);
const PATCH = (u, b) => api("PATCH", u, b);
const DEL = (u) => api("DELETE", u);
const qs = (o) => Object.entries(o).filter(([, v]) => v !== "" && v != null && v !== false).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&");

// ---------------------------------------------------------------------------
// Notifications et fenêtres
// ---------------------------------------------------------------------------
function toast(msg, type = "") {
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  setHTML(el, html`${icon(type === "error" ? "circle-x" : "check")}<div>${msg}</div>`);
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), type === "error" ? 6000 : 3500);
}
function closeOverlay() { setHTML($("#overlay-root"), ""); document.body.style.overflow = ""; }
function openOverlay({ title, body, foot = "", kind = "drawer", sub = "" }) {
  const root = $("#overlay-root");
  setHTML(root, html`<div class="overlay ${kind === "modal" ? "center" : ""}" data-overlay>
    <div class="${kind}" role="dialog" aria-modal="true" aria-label="${title}">
      <div class="overlay-head"><h3>${title}${sub ? html`<div class="tiny muted">${sub}</div>` : ""}</h3>
        <button class="btn icon ghost" data-action="close" aria-label="Fermer">${icon("x")}</button></div>
      <div class="overlay-body">${body}</div>
      ${foot ? html`<div class="overlay-foot">${foot}</div>` : ""}
    </div></div>`);
  document.body.style.overflow = "hidden";
  const first = $("input, select, textarea", root);
  if (first) first.focus();
  return root;
}
function confirmDialog(title, text, okLabel = "Confirmer", danger = true) {
  return new Promise((resolve) => {
    openOverlay({
      kind: "modal", title, body: html`<p class="text-2" style="margin:0">${text}</p>`,
      foot: html`<button class="btn" data-action="close">Annuler</button><button class="btn ${danger ? "primary" : "primary"}" id="confirm-ok">${okLabel}</button>`,
    });
    $("#confirm-ok").addEventListener("click", () => { closeOverlay(); resolve(true); });
    $("[data-overlay]").addEventListener("click", (e) => { if (e.target.closest('[data-action="close"]') || e.target.matches("[data-overlay]")) resolve(false); });
  });
}

// ---------------------------------------------------------------------------
// Graphiques (Chart.js) — couleurs lues dans les variables CSS du thème
// ---------------------------------------------------------------------------
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const charts = new Set();
function destroyCharts() { charts.forEach((c) => c.destroy()); charts.clear(); }

function baseOptions({ yMax, yFmt, stacked = false, xTicks = 8 } = {}) {
  return {
    responsive: true, maintainAspectRatio: false, animation: false,
    interaction: { mode: "index", intersect: false },
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: css("--surface"), titleColor: css("--text"), bodyColor: css("--text-2"),
        borderColor: css("--border-strong"), borderWidth: 1, padding: 10, boxPadding: 4, usePointStyle: true,
        callbacks: { label: (ctx) => ` ${ctx.dataset.label} : ${yFmt ? yFmt(ctx.parsed.y) : fmtNum(ctx.parsed.y)}` },
      },
    },
    scales: {
      x: { stacked, grid: { display: false }, border: { color: css("--axis") }, ticks: { color: css("--muted"), maxTicksLimit: xTicks, maxRotation: 0, autoSkip: true, font: { size: 11 } } },
      y: {
        stacked, beginAtZero: true, max: yMax, suggestedMax: yMax ? undefined : (yFmt ? undefined : 4),
        grid: { color: css("--grid") }, border: { display: false },
        ticks: { color: css("--muted"), maxTicksLimit: 5, font: { size: 11 }, precision: yFmt ? undefined : 0, callback: (v) => (yFmt ? yFmt(v) : fmtNum(v)) },
      },
    },
  };
}
// Graphique déjà affiché (mise à jour sur place) : on remplace ses données, sans le recréer
function updateChart(canvas, labels, series) {
  const chart = window.Chart && Chart.getChart(canvas);
  if (!chart || chart.data.datasets.length !== series.length) { if (chart) { chart.destroy(); charts.delete(chart); } return null; }
  chart.data.labels = labels;
  series.forEach((s, i) => { chart.data.datasets[i].data = s.data; });
  chart.update("none");
  return chart;
}
function lineChart(canvas, labels, series, opts = {}) {
  if (!canvas || !window.Chart) return null;
  const existing = updateChart(canvas, labels, series);
  if (existing) return existing;
  const chart = new Chart(canvas, {
    type: "line",
    data: {
      labels,
      datasets: series.map((s) => ({
        label: s.label, data: s.data, borderColor: css(s.color), backgroundColor: css(s.color) + (s.fill ? "22" : ""),
        fill: !!s.fill, borderWidth: 2, pointRadius: 0, pointHoverRadius: 4, pointHoverBorderWidth: 2,
        pointHoverBorderColor: css("--surface"), tension: 0.25, spanGaps: true,
      })),
    },
    options: baseOptions(opts),
  });
  charts.add(chart);
  return chart;
}
function barChart(canvas, labels, series, opts = {}) {
  if (!canvas || !window.Chart) return null;
  const existing = updateChart(canvas, labels, series);
  if (existing) return existing;
  const chart = new Chart(canvas, {
    type: "bar",
    data: {
      labels,
      datasets: series.map((s) => ({
        label: s.label, data: s.data, backgroundColor: css(s.color), borderRadius: 4, borderSkipped: "start",
        borderColor: css("--surface"), borderWidth: opts.stacked ? { top: 2 } : 0, maxBarThickness: 28,
      })),
    },
    options: baseOptions(opts),
  });
  charts.add(chart);
  return chart;
}
const legend = (items) => html`<div class="legend">${items.map(([label, color]) => html`<span><i style="background:var(${color})"></i>${label}</span>`)}</div>`;
function hbars(items, { label = (x) => x.label, value = (x) => x.value, fmt = fmtNum, color = "--series-1" } = {}) {
  if (!items.length) return empty("Aucune donnée", "", "chart-no-axes-column");
  const mx = Math.max(...items.map(value), 1);
  return html`<div class="hbar">${items.map((x) => html`
    <span class="text-2" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${label(x)}">${label(x)}</span>
    <span class="num strong">${fmt(value(x))}</span>
    <div class="bar"><i style="width:${(value(x) / mx * 100).toFixed(1)}%;background:var(${color})"></i></div>`)}</div>`;
}

// Anneau de score
function scoreRing(score, grade) {
  const r = 48, c = 2 * Math.PI * r, pct = Math.max(0, Math.min(100, score)) / 100;
  const color = score >= 75 ? "--good" : score >= 50 ? "--warning" : "--critical";
  return html`<div class="score-ring" role="img" aria-label="Score de sécurité ${score} sur 100">
    <svg viewBox="0 0 112 112"><circle cx="56" cy="56" r="${r}" fill="none" stroke="var(--surface-3)" stroke-width="10"/>
    <circle cx="56" cy="56" r="${r}" fill="none" stroke="var(${color})" stroke-width="10" stroke-linecap="round" stroke-dasharray="${(c * pct).toFixed(1)} ${c.toFixed(1)}"/></svg>
    <div class="center"><div><div class="big">${score}</div><div class="grade">Note ${grade}</div></div></div></div>`;
}

// ---------------------------------------------------------------------------
// État global, temps réel, routeur
// ---------------------------------------------------------------------------
const App = {
  me: null,
  live: { host: null, containers: [] },
  page: null,
  listeners: {},          // type de message WS -> fonction de la page courante
  ws: null,
  wsRetry: 1,
  alertsOpen: 0,
  soft: false,            // vrai pendant une mise à jour sur place (refresh)
  actions: {},            // data-action -> gestionnaire
  pages: {},
  isAdmin() { return this.me && this.me.role === "admin"; },
};

function on(type, fn) { App.listeners[type] = fn; }

function connectWS() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  App.ws = ws;
  const live = $("#live");
  ws.onopen = () => {
    App.wsRetry = 1;
    live.className = "live on"; $(".txt", live).textContent = "En direct";
    ws.send(JSON.stringify({ type: "logs", enabled: App.page === "logs" }));
  };
  ws.onclose = (e) => {
    live.className = "live off"; $(".txt", live).textContent = "Hors ligne";
    if (e.code === 4401) { window.location.replace("/login"); return; }
    setTimeout(connectWS, Math.min(App.wsRetry *= 2, 30) * 1000);
  };
  ws.onmessage = (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch (e) { return; }
    if (msg.type === "host") App.live.host = msg.data;
    if (msg.type === "containers") App.live.containers = msg.data;
    if (msg.type === "alert") onAlertMessage(msg.data);
    const fn = App.listeners[msg.type];
    if (fn) { try { fn(msg.data); } catch (e) { console.error(e); } }
  };
}
function wsLogs(enabled) {
  if (App.ws && App.ws.readyState === 1) App.ws.send(JSON.stringify({ type: "logs", enabled }));
}

const seenAlerts = new Set();
function onAlertMessage(a) {
  if (a.status !== "resolved" && a.count === 1 && !seenAlerts.has(a.id) && ["critical", "high"].includes(a.severity)) {
    seenAlerts.add(a.id);
    toast(`${(SEV[a.severity] || {}).label} : ${a.title}`, a.severity === "critical" ? "error" : "");
  }
  refreshAlertCount();
}
let alertCountTimer = null;
function refreshAlertCount() {
  clearTimeout(alertCountTimer);
  alertCountTimer = setTimeout(async () => {
    try {
      const r = await GET("/api/alerts?status=active&limit=1");
      App.alertsOpen = r.total;
      const el = $("#nav-alerts");
      el.textContent = r.total;
      el.classList.toggle("hidden", !r.total);
    } catch (e) { /* ignoré */ }
  }, 400);
}

function setHeader(title, sub = "", actions = "") {
  $("#page-title").textContent = title;
  document.title = `${title} · LogSonar`;
  $("#page-sub").textContent = sub;
  setHTML($("#page-actions"), actions);
}

let pageTimers = [];
function every(ms, fn) { pageTimers.push(setInterval(fn, ms)); }

// Recharge les données de la page affichée et met à jour uniquement ce qui a changé
let refreshing = null;
function refresh() {
  if (refreshing) return refreshing;
  const page = App.page;
  const oldTimers = pageTimers;
  pageTimers = []; App.listeners = {};
  App.soft = true;
  refreshing = (async () => {
    try { await App.pages[page]($("#view")); }
    catch (e) { console.error(e); }
    finally {
      App.soft = false; refreshing = null;
      oldTimers.forEach(clearInterval);
    }
  })();
  return refreshing;
}

async function route() {
  if (refreshing) { try { await refreshing; } catch (e) { /* ignoré */ } }
  const name = (location.hash.replace(/^#\/?/, "").split("?")[0] || "overview");
  const page = App.pages[name] ? name : "overview";
  pageTimers.forEach(clearInterval); pageTimers = [];
  App.listeners = {};
  destroyCharts();
  closeOverlay();
  App.page = page;
  wsLogs(page === "logs");
  $$("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.page === page));
  $("#sidebar").classList.remove("open");
  const view = $("#view");
  setHTML(view, html`<div class="grid g-4">${[1, 2, 3, 4].map(() => html`<div class="card kpi"><div class="skeleton" style="width:50%"></div><div class="skeleton" style="height:28px;width:70%"></div></div>`)}</div>`);
  window.scrollTo(0, 0);
  try {
    await App.pages[page](view);
  } catch (e) {
    console.error(e);
    setHTML(view, html`<div class="card">${empty("Impossible de charger cette page", e.message, "cloud-off")}</div>`);
  }
}

// Délégation des clics : aucun gestionnaire inline (CSP stricte)
document.addEventListener("click", (e) => {
  const el = e.target.closest("[data-action]");
  if (el) {
    const fn = App.actions[el.dataset.action];
    if (fn) { if (!el.matches("input, select")) e.preventDefault(); fn(el, e); }
    return;
  }
  if (e.target.matches("[data-overlay]")) closeOverlay();
});
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeOverlay(); });

Object.assign(App.actions, {
  close: closeOverlay,
  menu: () => $("#sidebar").classList.toggle("open"),
  theme: () => {
    const cur = document.documentElement.getAttribute("data-theme") ||
      (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    const next = cur === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("logsonar-theme", next); } catch (e) { /* ignoré */ }
    route(); // redessine les graphiques avec les couleurs du thème
  },
  logout: async () => {
    try { await POST("/api/auth/logout"); } catch (e) { /* déjà déconnecté */ }
    window.location.replace("/login");
  },
});

async function boot() {
  try {
    App.me = await GET("/api/auth/me");
  } catch (e) { return; }
  $("#me-name").textContent = App.me.username;
  $("#me-role").textContent = App.me.role === "admin" ? "Administrateur" : "Lecture seule";
  $("#me-avatar").textContent = App.me.username.charAt(0).toUpperCase();
  if (!App.isAdmin()) $$(".admin-only").forEach((el) => el.classList.add("hidden"));
  icons();
  connectWS();
  refreshAlertCount();
  window.addEventListener("hashchange", route);
  route();
  GET("/api/host").then((h) => { $("#instance-host").textContent = h.info.hostname; }).catch(() => {});
}
document.addEventListener("DOMContentLoaded", boot);
