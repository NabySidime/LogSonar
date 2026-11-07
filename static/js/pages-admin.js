/* LogSonar — administration : paramètres, utilisateurs, compte */
"use strict";

const CHANNELS = [
  { key: "email", label: "Email (Brevo)", icon: "mail", fields: [
    ["email_enabled", "Activer l'envoi d'emails", "bool"],
    ["email_to", "Destinataires", "text", "admin@exemple.com, autre@exemple.com"],
    ["brevo_sender", "Expéditeur vérifié chez Brevo", "text", "alertes@exemple.com"],
    ["brevo_api_key", "Clé API Brevo", "secret", "xkeysib-…"]] },
  { key: "discord", label: "Discord", icon: "message-square", fields: [["discord_webhook", "URL du webhook", "secret", "https://discord.com/api/webhooks/…"]] },
  { key: "slack", label: "Slack", icon: "hash", fields: [["slack_webhook", "URL du webhook", "secret", "https://hooks.slack.com/services/…"]] },
  { key: "telegram", label: "Telegram", icon: "send", fields: [
    ["telegram_bot_token", "Token du bot (@BotFather)", "secret", "123456:ABC…"], ["telegram_chat_id", "ID de la conversation", "text", "-1001234567890"]] },
  { key: "webhook", label: "Webhook JSON", icon: "webhook", fields: [["webhook_url", "URL (ntfy, n8n, Zapier…)", "secret", "https://…"]] },
];

function fieldHTML([key, label, type, ph], s) {
  if (type === "bool") return html`<label class="switch"><input type="checkbox" data-k="${key}" ${s[key] ? raw("checked") : ""}> ${label}</label>`;
  if (type === "secret") {
    const set = s[key + "_set"], unreadable = s[key + "_unreadable"], hint = s[key + "_hint"];
    return html`<div class="field"><label>${label}</label><div class="row" style="flex-wrap:nowrap">
      <input class="input" type="password" autocomplete="new-password" data-lpignore="true" data-1p-ignore="true" data-bwignore="true" data-k="${key}" data-secret="1" placeholder="${set ? `Enregistrée${hint ? ` (se termine par ${hint})` : ""} - laissez vide pour la conserver` : unreadable ? "Illisible — ressaisissez la valeur" : ph || ""}" style="flex:1${unreadable ? ";border-color:var(--critical)" : ""}">
      ${set ? html`<button class="btn sm ghost" data-action="secret-clear" data-k="${key}" title="Supprimer">${icon("trash-2")}</button>` : ""}</div>
      ${unreadable ? html`<span class="hint" style="color:var(--critical)">${icon("triangle-alert")} Enregistré, mais chiffré avec une autre clé que celle de ce serveur : LogSonar ne peut plus le lire. Saisissez-le de nouveau puis enregistrez.</span>` : ""}</div>`;
  }
  return html`<div class="field"><label>${label}</label><input class="input" data-k="${key}" value="${s[key] ?? ""}" placeholder="${ph || ""}"></div>`;
}
const numField = (key, label, s, hint = "", suffix = "") => html`<div class="field"><label>${label}</label>
  <div class="row" style="flex-wrap:nowrap"><input class="input" type="number" data-k="${key}" data-num="1" value="${s[key]}" style="flex:1">${suffix ? html`<span class="small muted">${suffix}</span>` : ""}</div>${hint ? html`<span class="hint">${hint}</span>` : ""}</div>`;

App.pages.settings = async (view) => {
  setHeader("Paramètres", App.isAdmin() ? "Notifications, seuils d'alerte et surveillance" : "Votre compte");
  if (!App.isAdmin()) { setHTML(view, accountCard()); bindAccount(); return; }
  const [s, containers, ingest, tokens] = await Promise.all([GET("/api/settings"), GET("/api/containers"), GET("/api/settings/ingest"), GET("/api/tokens")]);
  const muted = new Set(s.muted_containers);

  setHTML(view, html`<div class="stack" style="max-width:980px">
    <div class="card"><div class="card-head"><h3>Notifications</h3><span class="sub">${s.channels.length ? `actives : ${s.channels.join(", ")}` : "aucun canal configuré — les alertes ne sont visibles que dans le tableau de bord"}</span></div>
      <div class="card-body">
        <div class="form-grid">
          <div class="field"><label>Gravité minimale notifiée</label><select class="input" data-k="notify_min_severity">
            ${[["info", "Tout (info et plus)"], ["warning", "Avertissement et plus"], ["high", "Élevée et critique (recommandé)"], ["critical", "Critique uniquement"]].map(([v, l]) => html`<option value="${v}" ${s.notify_min_severity === v ? raw("selected") : ""}>${l}</option>`)}</select></div>
          <div class="field"><label>&nbsp;</label>${fieldHTML(["notify_resolved", "Prévenir aussi quand une alerte est résolue", "bool"], s)}</div>
          <div class="field"><label>&nbsp;</label>${fieldHTML(["report_notify", "Envoyer le rapport quotidien (résumé + rapport complet par email)", "bool"], s)}</div>
        </div>
        <div class="stack mt">${CHANNELS.map((c) => html`<details class="card" style="box-shadow:none" ${s.channels.includes(c.key) ? raw("open") : ""}>
          <summary class="card-head" style="cursor:pointer;padding-bottom:14px">${icon(c.icon)}<h3>${c.label}</h3>${s.channels.includes(c.key) ? html`<span class="badge sev-good">${icon("check")}Configuré</span>` : ""}
            <div class="actions"><button class="btn sm" data-action="test-channel" data-ch="${c.key}">${icon("send")}Tester</button></div></summary>
          <div class="card-body" style="padding-top:0"><div class="form-grid">${c.fields.map((fd) => fieldHTML(fd, s))}</div></div></details>`)}</div>
      </div></div>

    <div class="card"><div class="card-head"><h3>Seuils du serveur</h3></div><div class="card-body"><div class="form-grid">
      ${numField("cpu_warn", "CPU — avertissement", s, "", "%")}${numField("cpu_crit", "CPU — critique", s, "", "%")}
      ${numField("mem_warn", "Mémoire — avertissement", s, "", "%")}${numField("mem_crit", "Mémoire — critique", s, "", "%")}
      ${numField("disk_warn", "Disque — avertissement", s, "", "%")}${numField("disk_crit", "Disque — critique", s, "", "%")}
      ${numField("metric_duration_min", "Durée avant alerte CPU/mémoire", s, "Évite les alertes sur un pic passager.", "min")}
    </div></div></div>

    <div class="card"><div class="card-head"><h3>Trafic et attaques</h3></div><div class="card-body"><div class="form-grid">
      ${numField("traffic_rpm_threshold", "Seuil de trafic fixe", s, "0 = automatique : alerte si le trafic dépasse N fois la normale.", "req/min")}
      ${numField("traffic_spike_factor", "Facteur de pic (mode auto)", s, "Ex. 4 = quatre fois le trafic habituel.", "×")}
      ${numField("traffic_min_rpm", "Trafic minimum pour alerter", s, "Ignore les pics sur un site peu visité.", "req/min")}
      ${numField("error_rate_threshold", "Taux d'erreurs 5xx", s, "", "%")}
      ${numField("attack_campaign_threshold", "Campagne d'attaque", s, "Tentatives d'une même IP en 10 min.", "tentatives")}
    </div></div></div>

    <div class="card"><div class="card-head"><h3>Certificats TLS</h3></div><div class="card-body"><div class="form-grid">
      <div class="field" style="grid-column:1/-1"><label>Domaines à surveiller</label><input class="input" data-k="tls_domains" value="${s.tls_domains}" placeholder="exemple.com, api.exemple.com, admin.exemple.com:8443"><span class="hint">Séparés par des virgules. Vérifiés toutes les 6 heures.</span></div>
      ${numField("tls_warn_days", "Prévenir avant expiration", s, "", "jours")}
    </div></div></div>

    <div class="row" style="position:sticky;bottom:12px;justify-content:flex-end"><button class="btn primary" data-action="settings-save" style="box-shadow:var(--shadow-lg)">${icon("save")}Enregistrer les paramètres</button></div>

    <div class="card"><div class="card-head"><h3>Conteneurs surveillés</h3><span class="sub">un conteneur en sourdine n'est plus analysé (ses ressources restent mesurées)</span></div>
      <div class="card-body flush"><div class="list">${containers.containers.map((c) => html`<div class="list-item"><div class="grow"><div class="title mono">${c.name}</div><div class="meta mono">${c.image}</div></div>
        <label class="switch"><input type="checkbox" data-action="mute-toggle" data-name="${c.name}" ${muted.has(c.name) ? "" : raw("checked")}> Analyser les logs</label></div>`)}</div>
        <div class="small muted" style="padding:12px 18px">Astuce : ajoutez le label <code>logsonar.enable=false</code> à un conteneur pour l'exclure totalement.</div></div></div>

    ${ingestCard(ingest)}

    ${tokensCard(tokens)}

    ${accountCard()}
  </div>`);
  bindAccount();
};

function ingestCard(ing) {
  const sources = Object.entries(ing.sources || {});
  return html`<div class="card"><div class="card-head"><h3>Analyse des requêtes POST</h3>
      <span class="sub">${ing.token_set ? (sources.length ? `${sources.length} application(s) connectée(s)` : "jeton créé — en attente de la première requête") : "désactivée"}</span>
      <div class="actions">${ing.token_set ? html`<button class="btn sm ghost" data-action="ingest-revoke">${icon("trash-2")}Révoquer</button>` : ""}
        <button class="btn sm" data-action="ingest-token">${icon("key-round")}${ing.token_set ? "Nouveau jeton" : "Activer"}</button></div></div>
    <div class="card-body">
      <p class="small" style="margin:0 0 10px">Les logs ne contiennent pas le <b>contenu</b> des formulaires et des appels API : une injection SQL envoyée dans un champ de connexion y est invisible.
        Un petit middleware ajouté à votre application transmet ces requêtes à LogSonar, qui les analyse sans conserver leur contenu (seul un court extrait de l'attaque est gardé, jamais un mot de passe ; les données bancaires ne sont jamais transmises).</p>
      ${sources.length ? html`<div class="list">${sources.map(([name, st]) => html`<div class="list-item"><div class="grow"><div class="title mono">${name}</div>
          <div class="meta">${st.received} requête(s) analysée(s) · ${st.attacks} attaque(s) · dernière ${fmtAgo(st.last_ts)}</div></div>
          <span class="badge ${Date.now() / 1000 - st.last_ts < 3600 ? "sev-good" : "sev-warning"}">${Date.now() / 1000 - st.last_ts < 3600 ? "active" : "silencieuse"}</span></div>`)}</div>`
        : html`<p class="small muted" style="margin:0">Django : fichier <code>integrations/django/logsonar_middleware.py</code> du dépôt (instructions en tête du fichier). Autres langages : voir le README.</p>`}
    </div></div>`;
}
function tokensCard(t) {
  const active = t.items.filter((x) => x.active);
  return html`<div class="card"><div class="card-head"><h3>Accès en lecture seule</h3>
      <span class="sub">${active.length ? `${active.length} jeton(s) actif(s)` : "aucun jeton actif"}</span>
      <div class="actions"><button class="btn sm" data-action="token-new" ${active.length >= t.max_active ? raw("disabled") : ""}>${icon("key-round")}Créer un jeton</button></div></div>
    <div class="card-body">
      <p class="small" style="margin:0 0 10px">Un jeton permet à un outil externe (un script, un assistant) de <b>consulter</b> les données : vue d'ensemble, alertes, menaces, vulnérabilités, rapports.
        Il ne peut <b>rien modifier</b> (lecture uniquement) et n'a jamais accès aux paramètres, aux secrets ni aux comptes. Révocable à tout moment.</p>
      ${t.items.length ? html`<div class="list">${t.items.map((x) => html`<div class="list-item"><div class="grow">
          <div class="title">${x.name} <span class="mono tiny muted">${x.prefix}…</span>
            ${x.active ? html`<span class="badge sev-good">actif</span>` : html`<span class="badge sev-info">${x.revoked_at ? "révoqué" : "expiré"}</span>`}</div>
          <div class="meta">créé par ${x.created_by} ${fmtAgo(x.created_at)} · expire le ${fmtDate(x.expires_at, false)} ·
            ${x.last_used_at ? `dernière utilisation ${fmtAgo(x.last_used_at)} depuis ${x.last_used_ip} (${x.use_count} min. d'activité)` : "jamais utilisé"}</div></div>
          ${x.active ? html`<button class="btn sm ghost danger" data-action="token-revoke" data-id="${x.id}" data-name="${x.name}">${icon("ban")}Révoquer</button>` : ""}</div>`)}</div>` : ""}
    </div></div>`;
}
App.actions["token-new"] = () => {
  openOverlay({
    kind: "modal", title: "Nouveau jeton de lecture",
    body: html`<div class="field"><label>Nom</label><input class="input" id="tk-name" placeholder="Claude, script de supervision…" maxlength="40"></div>
      <div class="field"><label>Durée de validité</label><select class="input" id="tk-days">
        <option value="7">7 jours</option><option value="30" selected>30 jours</option><option value="90">90 jours</option><option value="365">1 an</option></select></div>
      <p class="small muted">Lecture seule : il ne pourra ni modifier un paramètre, ni traiter une alerte, ni lancer un scan.</p>`,
    foot: html`<button class="btn" data-action="close">Annuler</button><button class="btn primary" data-action="token-create">Créer</button>`,
  });
};
App.actions["token-create"] = async () => {
  try {
    const r = await POST("/api/tokens", { name: $("#tk-name").value.trim(), days: Number($("#tk-days").value) });
    openOverlay({
      kind: "modal", title: "Jeton créé",
      body: html`<div class="callout warn">${icon("triangle-alert")}<div>Copiez-le maintenant : il ne sera plus jamais affiché. Ne le collez pas dans une conversation : placez-le dans une variable d'environnement.</div></div>
        <div class="field mt"><label>Jeton</label><textarea class="input mono" rows="2" readonly id="ingest-env" style="resize:none">${r.token}</textarea>
          <span class="hint">Utilisation : en-tête <code>Authorization: Bearer &lt;jeton&gt;</code> sur les routes GET de l'API.</span></div>`,
      foot: html`<button class="btn" data-action="ingest-copy">${icon("copy")}Copier</button><button class="btn primary" data-action="close-reload">Terminé</button>`,
    });
  } catch (e) { toast(e.message, "error"); }
};
App.actions["token-revoke"] = async (el) => {
  if (!(await confirmDialog(`Révoquer « ${el.dataset.name} » ?`, "L'outil qui l'utilise perdra immédiatement l'accès.", "Révoquer"))) return;
  try { await DEL(`/api/tokens/${el.dataset.id}`); toast("Jeton révoqué."); refresh(); } catch (e) { toast(e.message, "error"); }
};
App.actions["ingest-token"] = async (el) => {
  if (el.textContent.includes("Nouveau") && !(await confirmDialog("Générer un nouveau jeton ?", "L'ancien cessera immédiatement de fonctionner : il faudra mettre à jour vos applications.", "Générer"))) return;
  try {
    const { token } = await POST("/api/settings/ingest/token");
    openOverlay({
      kind: "modal", title: "Jeton du middleware",
      body: html`<div class="callout warn">${icon("triangle-alert")}<div>Copiez ce jeton maintenant : il ne sera plus jamais affiché.</div></div>
        <div class="field mt"><label>Variables d'environnement de votre application</label>
          <textarea class="input mono" rows="3" readonly id="ingest-env" style="resize:none">LOGSONAR_URL=http://logsonar:8000
LOGSONAR_TOKEN=${token}
LOGSONAR_SOURCE=mon-application</textarea>
          <span class="hint">L'application doit être sur le même réseau Docker que LogSonar (voir README).</span></div>`,
      foot: html`<button class="btn" data-action="ingest-copy">${icon("copy")}Copier</button><button class="btn primary" data-action="close-reload">Terminé</button>`,
    });
  } catch (e) { toast(e.message, "error"); }
};
App.actions["ingest-copy"] = async () => {
  const ta = $("#ingest-env");
  try { await navigator.clipboard.writeText(ta.value); toast("Copié."); } catch { ta.select(); toast("Sélectionné : copiez avec Ctrl+C."); }
};
App.actions["close-reload"] = () => { closeOverlay(); refresh(); };
App.actions["ingest-revoke"] = async () => {
  if (!(await confirmDialog("Révoquer le jeton ?", "Les applications connectées ne pourront plus envoyer de requêtes à analyser.", "Révoquer"))) return;
  try { await DEL("/api/settings/ingest/token"); toast("Jeton révoqué."); refresh(); } catch (e) { toast(e.message, "error"); }
};

// Champs secrets : le navigateur (ou un gestionnaire de mots de passe) peut y injecter
// le mot de passe de connexion à LogSonar, même avec autocomplete="off". Envoyé tel quel,
// il remplaçait la clé Brevo à chaque enregistrement. Un secret n'est donc envoyé que
// s'il a été réellement saisi au clavier, collé ou déposé (un remplissage automatique
// ne déclenche aucun de ces événements).
const SECRET_EDIT_KEYS = new Set(["Backspace", "Delete"]);
const markSecretTyped = (ev) => {
  const el = ev.target;
  if (!el || !el.dataset || !el.dataset.secret) return;
  if (ev.type === "keydown" && ev.key.length !== 1 && !SECRET_EDIT_KEYS.has(ev.key)) return; // Tab, flèches, Entrée...
  if (ev.type === "keydown" && (ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() !== "v") return; // Ctrl+A, Ctrl+C...
  el.dataset.typed = "1";
};
["keydown", "paste", "drop", "cut"].forEach((t) => document.addEventListener(t, markSecretTyped, true));

App.actions["settings-save"] = async () => {
  const out = {};
  $$("[data-k]").forEach((el) => {
    const k = el.dataset.k;
    if (el.closest("#account")) return;
    if (el.type === "checkbox") out[k] = el.checked;
    else if (el.dataset.secret) { if (el.dataset.typed && el.value.trim()) out[k] = el.value.trim(); }
    else if (el.dataset.num) out[k] = Number(el.value);
    else out[k] = el.value.trim();
  });
  try { await PUT("/api/settings", out); toast("Paramètres enregistrés."); refresh(); }
  catch (e) { toast(e.message, "error"); }
};
App.actions["secret-clear"] = async (el) => {
  if (!(await confirmDialog("Supprimer ce secret ?", "Le canal correspondant sera désactivé.", "Supprimer"))) return;
  await PUT("/api/settings", { [el.dataset.k]: "" });
  toast("Secret supprimé."); refresh();
};
App.actions["test-channel"] = async (el, ev) => {
  ev.stopPropagation();
  el.disabled = true;
  try { await POST(`/api/settings/test/${el.dataset.ch}`); toast("Notification de test envoyée."); }
  catch (e) { toast(e.message + " Enregistrez d'abord les paramètres.", "error"); }
  el.disabled = false;
};
// Les cases à cocher déclenchent aussi le clic délégué : on laisse le navigateur cocher puis on envoie
App.actions["mute-toggle"] = (el, ev) => {
  setTimeout(async () => {
    try { await POST("/api/containers/mute", { name: el.dataset.name, muted: !el.checked }); toast(el.checked ? `Logs de ${el.dataset.name} analysés.` : `${el.dataset.name} en sourdine.`); }
    catch (e) { toast(e.message, "error"); el.checked = !el.checked; }
  }, 0);
};

function accountCard() {
  const me = App.me;
  return html`<div class="card" id="account"><div class="card-head"><h3>Mon compte</h3><span class="sub">${me.username} · ${me.role === "admin" ? "administrateur" : "lecture seule"} · 2FA ${me.totp_enabled ? "activée" : "inactive"}</span></div>
    <div class="card-body"><form id="pw-form" class="form-grid" autocomplete="off">
      <div class="field"><label>Mot de passe actuel</label><input class="input" type="password" id="pw-cur" required autocomplete="current-password"></div>
      <div class="field"><label>Nouveau mot de passe</label><input class="input" type="password" id="pw-new" required minlength="10" autocomplete="new-password"><span class="hint">10 caractères, une majuscule, un chiffre.</span></div>
      <div class="field"><label>&nbsp;</label><button class="btn" type="submit">${icon("key-round")}Changer le mot de passe</button></div>
    </form><p class="small muted" style="margin:10px 0 0">Changer de mot de passe déconnecte vos autres sessions.</p></div></div>`;
}
function bindAccount() {
  const form = $("#pw-form");
  if (!form) return;
  bind(form, "submit", async (e) => {
    e.preventDefault();
    try { await POST("/api/auth/password", { current_password: $("#pw-cur").value, new_password: $("#pw-new").value }); toast("Mot de passe modifié."); form.reset(); }
    catch (err) { toast(err.message, "error"); }
  });
}

// ===========================================================================
// UTILISATEURS
// ===========================================================================
let usersCache = [];
App.pages.users = async (view) => {
  if (!App.isAdmin()) { setHeader("Utilisateurs", "Comptes ayant accès à LogSonar"); setHTML(view, html`<div class="card">${empty("Accès réservé aux administrateurs", "", "lock")}</div>`); return; }
  const res = await GET("/api/users");
  usersCache = res.items;
  const full = usersCache.length >= res.max;
  setHeader("Utilisateurs", `${usersCache.length} / ${res.max} comptes`,
    html`<button class="btn primary" data-action="user-new" ${full ? raw("disabled") : ""} title="${full ? `Limite de ${res.max} comptes atteinte` : ""}">${icon("user-plus")}Nouvel utilisateur</button>`);
  setHTML(view, html`${full ? html`<div class="callout warn" style="margin-bottom:14px">${icon("info")}<div>Limite de ${res.max} comptes atteinte. Supprimez un compte pour en créer un nouveau.</div></div>` : ""}<div class="card"><div class="table-wrap"><table class="table"><thead><tr><th>Utilisateur</th><th>Rôle</th><th>2FA</th><th>Dernière connexion</th><th>Créé le</th><th></th></tr></thead>
    <tbody>${usersCache.map((u) => html`<tr><td><div class="row" style="flex-wrap:nowrap"><div class="avatar">${u.username.charAt(0).toUpperCase()}</div><div><div class="strong">${u.username}${u.id === App.me.id ? html` <span class="tiny muted">(vous)</span>` : ""}</div><div class="tiny muted">${u.email || "—"}</div></div></div></td>
      <td>${u.role === "admin" ? html`<span class="badge sev-warning">${icon("crown")}Administrateur</span>` : html`<span class="badge sev-info">${icon("eye")}Lecture seule</span>`}</td>
      <td>${u.totp_enabled ? html`<span class="badge sev-good">${icon("shield-check")}Active</span>` : html`<span class="badge sev-info">À configurer</span>`}</td>
      <td class="small muted">${u.last_login ? fmtAgo(u.last_login) : "jamais"}</td><td class="small muted">${fmtDate(u.created_at, false)}</td>
      <td class="right"><button class="btn sm ghost" data-action="user-edit" data-id="${u.id}">${icon("pencil")}Modifier</button></td></tr>`)}</tbody></table></div></div>
    <p class="small muted mt">« Lecture seule » : consultation du tableau de bord et des alertes, sans accès aux paramètres ni aux scans.</p>`);
};
App.actions["user-new"] = () => {
  openOverlay({
    kind: "modal", title: "Nouvel utilisateur",
    body: html`<div class="field"><label>Nom d'utilisateur</label><input class="input" id="u-name" required></div>
      <div class="field"><label>Email</label><input class="input" id="u-email" type="email"></div>
      <div class="field"><label>Mot de passe initial</label><input class="input" id="u-pass" type="password" autocomplete="new-password"><span class="hint">La 2FA sera configurée à sa première connexion.</span></div>
      <div class="field"><label>Rôle</label><select class="input" id="u-role"><option value="viewer">Lecture seule</option><option value="admin">Administrateur</option></select></div>`,
    foot: html`<button class="btn" data-action="close">Annuler</button><button class="btn primary" data-action="user-create">Créer</button>`,
  });
};
App.actions["user-create"] = async () => {
  try {
    await POST("/api/users", { username: $("#u-name").value.trim(), email: $("#u-email").value.trim(), password: $("#u-pass").value, role: $("#u-role").value });
    closeOverlay(); toast("Utilisateur créé."); refresh();
  } catch (e) { toast(e.message, "error"); }
};
App.actions["user-edit"] = (el) => {
  const u = usersCache.find((x) => x.id === Number(el.dataset.id));
  const self = u.id === App.me.id;
  openOverlay({
    kind: "modal", title: `Modifier ${u.username}`,
    body: html`<div class="field"><label>Email</label><input class="input" id="ue-email" value="${u.email}"></div>
      <div class="field"><label>Rôle</label><select class="input" id="ue-role" ${self ? raw("disabled") : ""}><option value="viewer" ${u.role === "viewer" ? raw("selected") : ""}>Lecture seule</option><option value="admin" ${u.role === "admin" ? raw("selected") : ""}>Administrateur</option></select></div>
      <div class="field"><label>Nouveau mot de passe</label><input class="input" id="ue-pass" type="password" autocomplete="new-password" placeholder="laisser vide pour ne pas changer"></div>
      <label class="switch"><input type="checkbox" id="ue-2fa"> Réinitialiser la 2FA (nouveau QR code à la prochaine connexion)</label>`,
    foot: html`${!self ? html`<button class="btn danger" data-action="user-delete" data-id="${u.id}" style="margin-right:auto">${icon("trash-2")}Supprimer</button>` : ""}
      <button class="btn" data-action="close">Annuler</button><button class="btn primary" data-action="user-save" data-id="${u.id}">Enregistrer</button>`,
  });
};
App.actions["user-save"] = async (el) => {
  const body = { email: $("#ue-email").value.trim(), reset_2fa: $("#ue-2fa").checked };
  if (!$("#ue-role").disabled) body.role = $("#ue-role").value;
  if ($("#ue-pass").value) body.password = $("#ue-pass").value;
  try { await PATCH(`/api/users/${el.dataset.id}`, body); closeOverlay(); toast("Utilisateur modifié."); refresh(); }
  catch (e) { toast(e.message, "error"); }
};
App.actions["user-delete"] = async (el) => {
  if (!(await confirmDialog("Supprimer cet utilisateur ?", "Ses sessions seront immédiatement coupées.", "Supprimer"))) return;
  try { await DEL(`/api/users/${el.dataset.id}`); toast("Utilisateur supprimé."); refresh(); }
  catch (e) { toast(e.message, "error"); }
};
