"""
reporter.py — Générateur de rapports HTML LogSonar
Style : rapport professionnel type DSI/RSSI, inspiré du rapport TikiPay.
Structure : Table des matières · Synthèse exécutive · Incidents critiques (2xx) ·
            Tentatives bloquées · Inventaire attaquants · Graphiques Chart.js ·
            Sections pédagogiques · Recommandations priorisées · Pied de page confidentiel.
"""
import json
import os
from collections import Counter, defaultdict
from datetime import datetime

from db import get_events_for_date

REPORT_DIR = "data/reports"

# ---------------------------------------------------------------------------
# DICTIONNAIRE PÉDAGOGIQUE
# ---------------------------------------------------------------------------
EXPLANATIONS: dict[str, dict] = {
    "Tentative d'Injection SQL": {
        "icon": "🗄️", "color": "#dc2626", "priority": "Critique",
        "what": "L'attaquant insère des commandes SQL dans l'URL ou des champs de formulaire pour manipuler directement la base de données — vol de données, contournement d'authentification, destruction de tables.",
        "impact": "Compromission totale de la base de données, fuite des données utilisateurs et financières, contournement d'authentification.",
        "fix": "Utilisez exclusivement l'ORM de votre framework (Django Models) ou des requêtes paramétrées. Ne concaténez <strong>jamais</strong> de variables utilisateur dans une requête SQL brute.",
    },
    "Tentative de Cross-Site Scripting (XSS)": {
        "icon": "💉", "color": "#d97706", "priority": "Haute",
        "what": "Injection de code JavaScript malveillant dans les pages du site. Si exécuté dans le navigateur d'un visiteur, ce code peut voler des cookies de session ou rediriger vers un site frauduleux.",
        "impact": "Vol de sessions administrateur, redirections malveillantes, défacement, propagation de malware.",
        "fix": "Échappez toutes les données utilisateur avant affichage HTML (<code>|escape</code> dans Django). Activez le header <code>Content-Security-Policy</code>.",
    },
    "Tentative de Path Traversal": {
        "icon": "📂", "color": "#7c3aed", "priority": "Haute",
        "what": "Les séquences <code>../</code> permettent de remonter l'arborescence du serveur pour accéder à des fichiers hors du répertoire web autorisé.",
        "impact": "Lecture de fichiers sensibles : clés API, mots de passe, configuration serveur, code source.",
        "fix": "Validez tout chemin de fichier avec <code>Path.resolve()</code> + vérification que le chemin reste dans le dossier autorisé.",
    },
    "Tentative d'Injection de Commande": {
        "icon": "⚡", "color": "#dc2626", "priority": "Critique",
        "what": "L'attaquant tente d'exécuter des commandes système arbitraires sur le serveur via des caractères spéciaux (<code>; | & ` $(...)</code>) injectés dans des paramètres.",
        "impact": "Exécution de code arbitraire (RCE), installation de backdoor, pivotement vers d'autres systèmes, extraction de données.",
        "fix": "Ne passez jamais de données utilisateur dans <code>subprocess</code>, <code>os.system()</code> ou des commandes shell. Utilisez des API Python natives.",
    },
    "Tentative Log4Shell (Log4J)": {
        "icon": "☢️", "color": "#dc2626", "priority": "Critique",
        "what": "Exploitation de la CVE-2021-44228 (Log4Shell). L'attaquant injecte une chaîne JNDI pour forcer le serveur à charger du code depuis un serveur distant contrôlé par l'attaquant.",
        "impact": "Exécution de code à distance (RCE) complète, compromission totale du serveur.",
        "fix": "Mettez à jour Log4j vers 2.17.1+. Désactivez les lookups JNDI (<code>log4j2.formatMsgNoLookups=true</code>). Filtrez les patterns <code>${jndi:</code> au niveau WAF.",
    },
    "Tentative de SSRF (Falsification de Requête Côté Serveur)": {
        "icon": "🔄", "color": "#0891b2", "priority": "Haute",
        "what": "L'attaquant force le serveur à effectuer des requêtes HTTP vers des ressources internes — notamment les endpoints de métadonnées cloud (169.254.169.254) ou des services internes non exposés.",
        "impact": "Accès aux métadonnées cloud (clés AWS/GCP), pivot vers des services internes, contournement de firewalls.",
        "fix": "Validez et filtrez toutes les URLs soumises par l'utilisateur. Bloquez les plages d'IP privées (10.x, 192.168.x, 172.16-31.x, 169.254.x) dans les requêtes sortantes.",
    },
    "Tentative XXE (Injection d'Entité XML)": {
        "icon": "📄", "color": "#6d28d9", "priority": "Haute",
        "what": "Exploitation du parseur XML pour lire des fichiers locaux ou effectuer des requêtes réseau internes via des entités XML malveillantes (<code><!DOCTYPE ... SYSTEM 'file:///etc/passwd'></code>).",
        "impact": "Lecture de fichiers sensibles, SSRF, déni de service (billion laughs attack).",
        "fix": "Désactivez le traitement des entités externes dans votre parseur XML (<code>defusedxml</code> en Python). Validez les schémas XML avant parsing.",
    },
    "Tentative de Redirection Ouverte": {
        "icon": "↗️", "color": "#059669", "priority": "Moyenne",
        "what": "Le paramètre de redirection accepte des URLs vers des domaines externes, permettant des attaques de phishing sous l'apparence de votre domaine.",
        "impact": "Phishing, vol de credentials, atteinte à la réputation.",
        "fix": "Validez que les redirections restent sur votre domaine. Utilisez une liste blanche de destinations autorisées.",
    },
    "Scan de vulnérabilités (Bot)": {
        "icon": "🤖", "color": "#0891b2", "priority": "Moyenne",
        "what": "Un outil automatisé (Sqlmap, Nikto, Nmap, ffuf, nuclei…) cartographie votre serveur à la recherche de failles connues, de pages d'administration exposées ou de versions logicielles vulnérables.",
        "impact": "Reconnaissance préalable à une attaque ciblée. L'attaquant dispose d'une carte de vos points faibles.",
        "fix": "Configurez <strong>Fail2Ban</strong> pour bannir les IPs après N erreurs. Masquez les headers de version (<code>Server</code>, <code>X-Powered-By</code>).",
    },
    "Recherche de fichiers sensibles": {
        "icon": "🔑", "color": "#059669", "priority": "Haute",
        "what": "Recherche de fichiers oubliés en production : <code>.env</code> (secrets), <code>.git/</code> (code source), <code>backup.sql</code> (données), fichiers de configuration…",
        "impact": "Exposition de clés API, mots de passe BDD, code source, données sensibles.",
        "fix": "Bloquez ces chemins dans Nginx (<code>return 444;</code>). Ajoutez <code>.env</code>, <code>*.sql</code>, <code>*.bak</code> au <code>.gitignore</code>.",
    },
    "Alerte interne de l'application": {
        "icon": "⚙️", "color": "#6b7280", "priority": "Moyenne",
        "what": "Votre application a levé une exception de sécurité interne (SuspiciousOperation Django, BadRequest, PermissionDenied ou signal LOGSONAR_POST_ATTACK).",
        "impact": "Variable selon le contexte. Peut indiquer une manipulation de cookies, tokens ou paramètres POST suspects.",
        "fix": "Consultez les logs applicatifs complets pour identifier la requête déclenchante.",
    },
    "Tentative de falsification (CSRF)": {
        "icon": "🎭", "color": "#be185d", "priority": "Haute",
        "what": "Tentatives de soumission de formulaires sans token CSRF valide. Un attaquant peut forcer un utilisateur connecté à effectuer des actions à son insu.",
        "impact": "Transactions frauduleuses, modification de données au nom d'un utilisateur authentifié.",
        "fix": "Vérifiez que le middleware CSRF est activé sur toutes vos vues POST (<code>@csrf_protect</code> ou middleware global).",
    },
    "Tentative d'Injection de Template (SSTI)": {
        "icon": "📝", "color": "#dc2626", "priority": "Critique",
        "what": "L'attaquant injecte des expressions de template (<code>{{7*7}}</code>, <code>${7*7}</code>) pour exécuter du code arbitraire via le moteur de rendu côté serveur.",
        "impact": "Exécution de code arbitraire (RCE), lecture de fichiers, compromission totale.",
        "fix": "Ne rendez jamais de templates construits à partir d'entrées utilisateur. Utilisez <code>autoescape=True</code> dans Jinja2.",
    },
    "Tentative de Désérialisation Malveillante": {
        "icon": "💣", "color": "#dc2626", "priority": "Critique",
        "what": "L'attaquant envoie des données sérialisées malveillantes (Java, PHP, Python pickle) qui, lors de la désérialisation, exécutent du code arbitraire.",
        "impact": "Exécution de code à distance (RCE), escalade de privilèges, accès complet au serveur.",
        "fix": "N'utilisez jamais <code>pickle.loads()</code> sur des données non fiables. Préférez JSON. Validez la signature des données sérialisées.",
    },
}

GENERIC_EXPLANATION = {
    "icon": "⚠️", "color": "#6b7280", "priority": "Inconnue",
    "what": "Une activité suspecte non classifiée a été détectée.",
    "impact": "À déterminer selon le contexte.",
    "fix": "Analysez le log brut pour comprendre l'intention de l'attaquant.",
}

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------
def _esc(s: str) -> str:
    return (str(s)
            .replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))

def _short(t: str) -> str:
    M = {
        "Tentative d'Injection SQL": "Injection SQL",
        "Tentative de Cross-Site Scripting (XSS)": "XSS",
        "Tentative de Path Traversal": "Path Traversal",
        "Tentative d'Injection de Commande": "Cmd Injection",
        "Tentative Log4Shell (Log4J)": "Log4Shell",
        "Tentative de SSRF (Falsification de Requête Côté Serveur)": "SSRF",
        "Tentative XXE (Injection d'Entité XML)": "XXE",
        "Tentative de Redirection Ouverte": "Open Redirect",
        "Scan de vulnérabilités (Bot)": "Scan Bot",
        "Recherche de fichiers sensibles": "Fichiers sensibles",
        "Alerte interne de l'application": "Alerte interne",
        "Tentative de falsification (CSRF)": "CSRF",
        "Tentative d'Injection de Template (SSTI)": "SSTI",
        "Tentative de Désérialisation Malveillante": "Désérialisation",
    }
    return M.get(t, t)

def _status_class(status: str) -> str:
    try:
        code = int(status)
        if 200 <= code <= 299: return "status-success"
        if 300 <= code <= 399: return "status-redirect"
        if 400 <= code <= 499: return "status-client"
        if 500 <= code <= 599: return "status-server"
    except Exception:
        pass
    return ""

def _priority_badge(priority: str) -> str:
    colors = {
        "Critique": ("bg-red", "#dc2626"),
        "Haute":    ("bg-orange", "#d97706"),
        "Moyenne":  ("bg-yellow", "#ca8a04"),
        "Basse":    ("bg-blue", "#2563eb"),
    }
    c = colors.get(priority, ("bg-gray", "#6b7280"))
    return f'<span class="badge" style="background:{c[1]}18;color:{c[1]};border:1px solid {c[1]}40">{priority}</span>'


# ---------------------------------------------------------------------------
# GÉNÉRATEUR PRINCIPAL
# ---------------------------------------------------------------------------
async def generate_daily_report(date_str: str | None = None) -> str | None:
    today    = date_str or datetime.now().strftime("%Y-%m-%d")
    events   = await get_events_for_date(today)
    if not events:
        print(f"LogSonar: Aucune attaque pour le {today}.")
        return None

    rows = [dict(e) for e in events]

    # -- Séparation attaques réussies vs bloquées --
    def _is_success(r: dict) -> bool:
        try: return 200 <= int(r.get("status", "0")) <= 299
        except: return False

    critical = [r for r in rows if _is_success(r)]   # 2xx
    blocked  = [r for r in rows if not _is_success(r)]

    # -- Agrégations --
    type_counts      = Counter(r["attack_type"] for r in rows)
    ip_counts        = Counter(r["ip"] for r in rows)
    container_counts = Counter(r["container"] for r in rows)
    hour_counts: dict[int,int] = defaultdict(int)
    for r in rows:
        try: hour_counts[int(r["timestamp"][11:13])] += 1
        except: pass

    top_ips       = ip_counts.most_common(10)
    unique_ips    = len(ip_counts)
    unique_types  = len(type_counts)
    top_container = container_counts.most_common(1)[0][0] if container_counts else "—"
    detected_types= list(type_counts.keys())

    # -- Chart.js data --
    pie_labels = json.dumps([_short(t) for t in type_counts])
    pie_data   = json.dumps(list(type_counts.values()))
    pie_colors = json.dumps([EXPLANATIONS.get(t, GENERIC_EXPLANATION)["color"] for t in type_counts])
    bar_labels = json.dumps([f"{h:02d}h" for h in range(24)])
    bar_data   = json.dumps([hour_counts.get(h, 0) for h in range(24)])

    gen_time   = datetime.now().strftime("%d/%m/%Y à %H:%M")

    # Recommandations par priorité basées sur les types détectés
    reco_critical = [t for t in detected_types if EXPLANATIONS.get(t, {}).get("priority") == "Critique"]
    reco_high     = [t for t in detected_types if EXPLANATIONS.get(t, {}).get("priority") == "Haute"]

    # Pré-calculer les fragments HTML pour éviter les f-strings imbriqués avec backslash
    alert_banner = ""
    if critical:
        alert_banner = f'<div class="alert-crit">⚠ {len(critical)} attaque(s) réussie(s) (code 2xx) — intervention immédiate requise</div>'
    else:
        alert_banner = f"<div class=\"alert-ok\">✓ Aucune attaque n'a abouti — {len(blocked)} tentative(s) bloquée(s) détectée(s)</div>"

    blocked_more = ""
    if len(blocked) > 50:
        blocked_more = f"<p style=\"font-size:12px;color:var(--gray-3);margin-top:8px\">... et {len(blocked)-50} autre(s) tentative(s) non affichée(s). Consultez la base de données pour l'inventaire complet.</p>"

    critical_table = _render_events_table(critical, highlight="danger") if critical else '<div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:10px;padding:20px 24px;color:#15803d;font-size:13px">✓ Aucune attaque n\'a abouti sur la période. Tous les événements ont été bloqués ou redirigés.</div>'

    kpi_danger = "danger" if critical else ""

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Rapport LogSonar — {today}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root {{
  --black:#111827;--gray-1:#374151;--gray-2:#6b7280;--gray-3:#9ca3af;
  --gray-4:#d1d5db;--gray-5:#f3f4f6;--gray-6:#f9fafb;--white:#ffffff;
  --red:#dc2626;--orange:#d97706;--green:#059669;--blue:#2563eb;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
      background:var(--gray-6);color:var(--black);line-height:1.6;font-size:14px}}
a{{color:var(--blue);text-decoration:none}}
a:hover{{text-decoration:underline}}
code{{background:var(--gray-5);padding:1px 5px;border-radius:3px;font-size:12px;font-family:monospace}}
strong{{font-weight:600}}

/* HEADER */
.rh{{background:var(--black);color:var(--white);padding:48px}}
.rh-brand{{font-size:11px;letter-spacing:3px;text-transform:uppercase;
           color:var(--gray-3);margin-bottom:16px;display:flex;align-items:center;gap:8px}}
.rh-brand::before{{content:'⬡';font-size:16px;color:#4b5563}}
.rh h1{{font-size:32px;font-weight:800;margin-bottom:8px;letter-spacing:-.5px}}
.rh-meta{{display:flex;gap:24px;flex-wrap:wrap;margin-top:20px}}
.rh-meta-item{{font-size:12px;color:var(--gray-3)}}
.rh-meta-item strong{{color:var(--white);display:block;font-size:13px;margin-bottom:2px}}

/* CONFIDENTIAL BANNER */
.conf-banner{{background:#1f2937;color:#9ca3af;
              padding:10px 48px;font-size:11px;letter-spacing:2px;
              text-transform:uppercase;display:flex;justify-content:space-between}}

/* ALERT */
.alert-crit{{background:var(--red);color:var(--white);
             padding:14px 48px;font-size:14px;font-weight:600;
             display:flex;align-items:center;gap:10px}}
.alert-ok{{background:#059669;color:var(--white);
           padding:14px 48px;font-size:14px;font-weight:600;
           display:flex;align-items:center;gap:10px}}

/* LAYOUT */
.wrap{{max-width:980px;margin:0 auto;padding:48px 24px}}

/* TOC */
.toc{{background:var(--white);border:1px solid var(--gray-4);
      border-radius:10px;padding:24px 28px;margin-bottom:40px}}
.toc h2{{font-size:13px;font-weight:700;color:var(--gray-2);
         text-transform:uppercase;letter-spacing:1.5px;margin-bottom:14px}}
.toc ol{{list-style:none;counter-reset:toc;padding:0}}
.toc ol li{{counter-increment:toc;padding:5px 0;
            border-bottom:1px solid var(--gray-5);font-size:13px}}
.toc ol li:last-child{{border-bottom:none}}
.toc ol li::before{{content:counter(toc)".";
                    color:var(--gray-3);margin-right:10px;font-weight:600}}

/* SECTIONS */
.section{{margin-bottom:48px}}
.section-anchor{{display:block;position:relative;top:-80px;visibility:hidden}}
.section-title{{font-size:11px;font-weight:700;letter-spacing:2px;
                text-transform:uppercase;color:var(--gray-2);
                margin-bottom:20px;padding-bottom:10px;
                border-bottom:2px solid var(--gray-4);
                display:flex;align-items:center;gap:8px}}
.section-num{{color:var(--gray-4);font-size:13px}}

/* KPI GRID */
.kpi-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}}
.kpi-card{{background:var(--white);border:1px solid var(--gray-4);
           border-radius:10px;padding:20px}}
.kpi-card .k-label{{font-size:10px;font-weight:700;letter-spacing:1.5px;
                    text-transform:uppercase;color:var(--gray-2);margin-bottom:10px}}
.kpi-card .k-value{{font-size:36px;font-weight:800;line-height:1;color:var(--black)}}
.kpi-card .k-sub{{font-size:12px;color:var(--gray-3);margin-top:4px}}
.kpi-card.danger .k-value{{color:var(--red)}}
.kpi-card.success .k-value{{color:var(--green)}}

/* INDICATOR ROW */
.ind-table{{width:100%;border-collapse:collapse;
            background:var(--white);border:1px solid var(--gray-4);
            border-radius:10px;overflow:hidden;margin-bottom:24px}}
.ind-table th{{background:var(--gray-5);padding:10px 16px;text-align:left;
               font-size:10px;font-weight:700;letter-spacing:1.5px;
               text-transform:uppercase;color:var(--gray-2);
               border-bottom:1px solid var(--gray-4)}}
.ind-table td{{padding:12px 16px;border-bottom:1px solid var(--gray-5);
               font-size:13px}}
.ind-table tr:last-child td{{border-bottom:none}}
.ind-table tr:hover td{{background:var(--gray-6)}}
.mono{{font-family:monospace;font-size:12px}}
.badge{{display:inline-flex;align-items:center;padding:2px 8px;
        border-radius:9999px;font-size:11px;font-weight:600}}
.status-success{{color:var(--green);font-weight:700}}
.status-redirect{{color:#ca8a04;font-weight:700}}
.status-client{{color:#d97706}}
.status-server{{color:var(--red);font-weight:700}}

/* CHARTS */
.charts-grid{{display:grid;grid-template-columns:1fr 2fr;gap:16px}}
.chart-card{{background:var(--white);border:1px solid var(--gray-4);
             border-radius:10px;padding:24px}}
.chart-card h3{{font-size:13px;font-weight:600;margin-bottom:4px}}
.chart-card .chart-sub{{font-size:11px;color:var(--gray-3);margin-bottom:16px}}

/* IP TABLE */
.bar-wrap{{display:flex;align-items:center;gap:8px}}
.bar-bg{{flex:1;background:var(--gray-5);border-radius:4px;height:6px}}
.bar-fill{{height:6px;border-radius:4px;background:var(--black)}}

/* PÉDAGOGIE */
.edu-card{{background:var(--white);border:1px solid var(--gray-4);
           border-radius:10px;overflow:hidden;margin-bottom:16px}}
.edu-header{{display:flex;align-items:center;gap:14px;
             padding:16px 24px;border-bottom:1px solid var(--gray-5)}}
.edu-icon{{width:40px;height:40px;border-radius:8px;display:flex;
           align-items:center;justify-content:center;font-size:20px;flex-shrink:0}}
.edu-header h3{{font-size:15px;font-weight:700}}
.edu-cnt{{font-size:12px;color:var(--gray-3);margin-top:2px}}
.edu-body{{padding:20px 24px;display:grid;grid-template-columns:1fr 1fr;gap:16px}}
.edu-block h4{{font-size:10px;font-weight:700;letter-spacing:1.5px;
               text-transform:uppercase;color:var(--gray-2);margin-bottom:6px}}
.edu-block p{{font-size:13px;color:var(--gray-1);line-height:1.65}}
.edu-fix{{grid-column:1/-1;background:#eff6ff;
          border:1px solid #bfdbfe;border-radius:8px;padding:14px 18px}}
.edu-fix h4{{color:var(--blue)}}

/* RECO */
.reco-card{{background:var(--white);border:1px solid var(--gray-4);
            border-radius:10px;padding:20px 24px;margin-bottom:12px;
            display:flex;gap:16px;align-items:flex-start}}
.reco-num{{font-size:28px;font-weight:800;color:var(--gray-4);
           flex-shrink:0;line-height:1;margin-top:2px}}
.reco-content h4{{font-size:14px;font-weight:600;margin-bottom:4px}}
.reco-content p{{font-size:13px;color:var(--gray-1)}}

/* FOOTER */
.report-footer{{background:var(--black);color:var(--gray-3);
                padding:32px 48px;margin-top:0}}
.reco-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:20px;margin-top:20px}}
.reco-item{{border-left:2px solid #374151;padding-left:14px}}
.reco-item strong{{color:var(--white);display:block;margin-bottom:4px;font-size:13px}}
.footer-legal{{margin-top:24px;padding-top:20px;
               border-top:1px solid #374151;
               font-size:11px;color:#4b5563;
               display:flex;justify-content:space-between}}

@media(max-width:700px){{
  .kpi-grid{{grid-template-columns:repeat(2,1fr)}}
  .charts-grid{{grid-template-columns:1fr}}
  .edu-body{{grid-template-columns:1fr}}
  .reco-grid{{grid-template-columns:1fr}}
  .rh,.report-footer,.conf-banner{{padding:24px}}
  .wrap{{padding:24px 16px}}
}}
</style>
</head>
<body>

<!-- HEADER -->
<div class="rh">
  <div class="rh-brand">LogSonar — Rapport de Sécurité Automatisé</div>
  <h1>Analyse des Journaux Serveur</h1>
  <div class="rh-meta">
    <div class="rh-meta-item"><strong>Période</strong>{today}</div>
    <div class="rh-meta-item"><strong>Événements analysés</strong>{len(rows)} attaque(s) détectée(s)</div>
    <div class="rh-meta-item"><strong>Généré le</strong>{gen_time}</div>
    <div class="rh-meta-item"><strong>Classification</strong>Confidentiel — Interne</div>
  </div>
</div>
<div class="conf-banner">
  <span>Direction des Systèmes d'Information</span>
  <span>Document Confidentiel</span>
</div>
{alert_banner}

<div class="wrap">

  <!-- TABLE DES MATIÈRES -->
  <a class="section-anchor" id="toc"></a>
  <div class="toc">
    <h2>Table des matières</h2>
    <ol>
      <li><a href="#synthese">Synthèse exécutive</a></li>
      <li><a href="#critiques">Incidents critiques (attaques réussies)</a></li>
      <li><a href="#bloquees">Tentatives bloquées</a></li>
      <li><a href="#attaquants">Inventaire des attaquants</a></li>
      <li><a href="#graphiques">Analyse graphique</a></li>
      <li><a href="#pedagogie">Explications & Remédiation par type</a></li>
      <li><a href="#recommandations">Recommandations priorisées</a></li>
    </ol>
  </div>

  <!-- 1. SYNTHÈSE EXÉCUTIVE -->
  <div class="section">
    <a class="section-anchor" id="synthese"></a>
    <div class="section-title"><span class="section-num">1.</span> Synthèse exécutive</div>

    <table class="ind-table" style="margin-bottom:24px">
      <thead><tr>
        <th>Indicateur</th><th>Valeur</th><th>Statut</th>
      </tr></thead>
      <tbody>
        <tr><td>Événements analysés</td><td><strong>{len(rows)}</strong></td>
            <td><span class="badge" style="background:#fee2e2;color:#dc2626">Critique</span></td></tr>
        <tr><td>Attaques réussies (2xx)</td>
            <td><strong style="color:{'var(--red)' if critical else 'var(--green)'}">
              {len(critical)}</strong></td>
            <td>{"⚠ Intervention requise" if critical else "✓ Aucune"}</td></tr>
        <tr><td>Tentatives bloquées</td><td><strong>{len(blocked)}</strong></td>
            <td>✓ Rejetées</td></tr>
        <tr><td>Adresses IP uniques</td><td><strong>{unique_ips}</strong></td><td>—</td></tr>
        <tr><td>Types d'attaque distincts</td><td><strong>{unique_types}</strong></td><td>—</td></tr>
        <tr><td>Conteneur le plus ciblé</td>
            <td><span class="mono">{_esc(top_container)}</span></td><td>—</td></tr>
      </tbody>
    </table>

    <div class="kpi-grid">
      <div class="kpi-card {kpi_danger}">
        <div class="k-label">Attaques réussies</div>
        <div class="k-value">{len(critical)}</div>
        <div class="k-sub">codes 2xx</div>
      </div>
      <div class="kpi-card">
        <div class="k-label">Tentatives bloquées</div>
        <div class="k-value">{len(blocked)}</div>
        <div class="k-sub">rejetées</div>
      </div>
      <div class="kpi-card">
        <div class="k-label">IPs attaquantes</div>
        <div class="k-value">{unique_ips}</div>
        <div class="k-sub">sources distinctes</div>
      </div>
      <div class="kpi-card">
        <div class="k-label">Types menaces</div>
        <div class="k-value">{unique_types}</div>
        <div class="k-sub">catégories</div>
      </div>
    </div>
  </div>

  <!-- 2. INCIDENTS CRITIQUES -->
  <div class="section">
    <a class="section-anchor" id="critiques"></a>
    <div class="section-title"><span class="section-num">2.</span> Incidents critiques — Attaques réussies (2xx)</div>
    {critical_table}
  </div>

  <!-- 3. TENTATIVES BLOQUÉES -->
  <div class="section">
    <a class="section-anchor" id="bloquees"></a>
    <div class="section-title"><span class="section-num">3.</span> Tentatives bloquées</div>
    <p style="font-size:13px;color:var(--gray-2);margin-bottom:16px">
      Les événements ci-dessous ont été <strong>rejetés</strong> par le serveur (codes 3xx, 4xx, 5xx).
      Ils sont enregistrés à titre de surveillance mais ne nécessitent pas d'intervention immédiate.
    </p>
    {_render_events_table(blocked[:50], highlight="normal")}
    {blocked_more}
  </div>

  <!-- 4. INVENTAIRE ATTAQUANTS -->
  <div class="section">
    <a class="section-anchor" id="attaquants"></a>
    <div class="section-title"><span class="section-num">4.</span> Inventaire des attaquants</div>
    <table class="ind-table">
      <thead><tr>
        <th>#</th><th>Adresse IP</th><th>Nb requêtes</th><th>Types détectés</th>
        <th>Succès</th><th>Volume</th>
      </tr></thead>
      <tbody>
        {''.join(_render_ip_row(i, ip, cnt, rows, ip_counts[top_ips[0][1]] if top_ips else 1)
                 for i, (ip, cnt) in enumerate(top_ips))}
      </tbody>
    </table>
  </div>

  <!-- 5. GRAPHIQUES -->
  <div class="section">
    <a class="section-anchor" id="graphiques"></a>
    <div class="section-title"><span class="section-num">5.</span> Analyse graphique</div>
    <div class="charts-grid">
      <div class="chart-card">
        <h3>Répartition par type</h3>
        <div class="chart-sub">Tous événements confondus</div>
        <div style="position:relative;height:220px"><canvas id="chartPie"></canvas></div>
      </div>
      <div class="chart-card">
        <h3>Volume par heure</h3>
        <div class="chart-sub">Distribution sur 24h</div>
        <div style="position:relative;height:220px"><canvas id="chartHours"></canvas></div>
      </div>
    </div>
  </div>

  <!-- 6. PÉDAGOGIE -->
  <div class="section">
    <a class="section-anchor" id="pedagogie"></a>
    <div class="section-title"><span class="section-num">6.</span> Explications & Remédiation par type détecté</div>
    {''.join(_render_edu(t, type_counts[t]) for t in detected_types)}
  </div>

  <!-- 7. RECOMMANDATIONS -->
  <div class="section">
    <a class="section-anchor" id="recommandations"></a>
    <div class="section-title"><span class="section-num">7.</span> Recommandations priorisées</div>

    {_render_recos(reco_critical, reco_high, bool(critical))}
  </div>

</div><!-- /wrap -->

<!-- FOOTER -->
<div class="report-footer">
  <strong style="color:white">Recommandations générales de sécurité</strong>
  <div class="reco-grid">
    <div class="reco-item">
      <strong>🔒 Fail2Ban</strong>
      Bannissez automatiquement les IPs après 5 tentatives échouées en 10 minutes.
    </div>
    <div class="reco-item">
      <strong>📋 Logs POST</strong>
      Ajoutez un middleware <code>LOGSONAR_POST_ATTACK</code> dans Django pour couvrir les corps de requêtes POST.
    </div>
    <div class="reco-item">
      <strong>🔄 Dépendances</strong>
      Maintenez vos paquets à jour. La plupart des scans ciblent des CVE connues sur des versions spécifiques.
    </div>
  </div>
  <div class="footer-legal">
    <span>Rapport généré par <strong>LogSonar</strong> — {gen_time}</span>
    <span>CONFIDENTIEL — Diffusion restreinte — DSI</span>
    <span>Aucune donnée n'a quitté vos serveurs</span>
  </div>
</div>

<script>
new Chart(document.getElementById('chartPie'),{{
  type:'doughnut',
  data:{{labels:{pie_labels},datasets:[{{data:{pie_data},backgroundColor:{pie_colors},borderWidth:2,borderColor:'#fff'}}]}},
  options:{{responsive:true,maintainAspectRatio:false,
            plugins:{{legend:{{position:'bottom',labels:{{font:{{size:11}},padding:12,boxWidth:12}}}}}}}}
}});
new Chart(document.getElementById('chartHours'),{{
  type:'bar',
  data:{{labels:{bar_labels},datasets:[{{
    data:{bar_data},
    backgroundColor:{bar_data}.map(v=>v>0?'rgba(220,38,38,0.75)':'rgba(209,213,219,0.4)'),
    borderRadius:3
  }}]}},
  options:{{responsive:true,maintainAspectRatio:false,
            plugins:{{legend:{{display:false}}}},
            scales:{{
              x:{{ticks:{{font:{{size:9}},maxRotation:0}},grid:{{display:false}}}},
              y:{{ticks:{{font:{{size:10}},stepSize:1}},beginAtZero:true,grid:{{color:'#f3f4f6'}}}}
            }}}}
}});
</script>
</body>
</html>"""

    os.makedirs(REPORT_DIR, exist_ok=True)
    filename = f"rapport_{today}.html"
    with open(os.path.join(REPORT_DIR, filename), "w", encoding="utf-8") as f:
        f.write(html)

    print(f"LogSonar: Rapport {filename} — {len(rows)} events, {len(critical)} critiques, {unique_ips} IPs, {unique_types} types.")
    return filename


# ---------------------------------------------------------------------------
# FONCTIONS DE RENDU HELPER
# ---------------------------------------------------------------------------
def _render_events_table(events: list, highlight: str = "normal") -> str:
    if not events:
        return '<p style="color:var(--gray-3);font-size:13px;padding:12px 0">Aucun événement.</p>'
    bg = "background:#fef2f2;" if highlight == "danger" else ""
    rows_html = ""
    for r in sorted(events, key=lambda x: x["timestamp"]):
        sc = _status_class(r.get("status", ""))
        rows_html += f"""
        <tr style="{bg}">
          <td class="mono">{_esc(r["timestamp"][11:19])}</td>
          <td class="mono">{_esc(r["ip"])}</td>
          <td>{_esc(_short(r["attack_type"]))}</td>
          <td class="mono" style="color:var(--gray-2)">[{_esc(r["container"])}]</td>
          <td class="mono" style="max-width:200px;overflow:hidden;text-overflow:ellipsis;
              white-space:nowrap">{_esc(r["path"])}</td>
          <td class="{sc}">{_esc(r.get("status","?"))}</td>
        </tr>"""
    return f"""
    <table class="ind-table">
      <thead><tr>
        <th>Heure</th><th>IP source</th><th>Type</th>
        <th>Conteneur</th><th>Chemin</th><th>Code</th>
      </tr></thead>
      <tbody>{rows_html}</tbody>
    </table>"""


def _render_ip_row(i: int, ip: str, cnt: int, all_rows: list, max_cnt: int) -> str:
    ip_events   = [r for r in all_rows if r["ip"] == ip]
    types       = list({r["attack_type"] for r in ip_events})
    successes   = sum(1 for r in ip_events if _esc(r.get("status","")).startswith("2"))
    pct         = round(cnt / max_cnt * 100) if max_cnt else 0
    types_html  = ", ".join(_esc(_short(t)) for t in types[:3])
    badge_style = "background:#fee2e2;color:#dc2626" if i == 0 else "background:var(--gray-5);color:var(--gray-1)"
    return f"""
    <tr>
      <td style="color:var(--gray-3);font-size:12px">{i+1}</td>
      <td class="mono"><strong>{_esc(ip)}</strong></td>
      <td><span class="badge" style="{badge_style}">{cnt}</span></td>
      <td style="font-size:12px;color:var(--gray-2)">{types_html}</td>
      <td>{"<span style='color:var(--red);font-weight:700'>⚠ "+str(successes)+"</span>" if successes else "✓ 0"}</td>
      <td>
        <div class="bar-wrap">
          <div class="bar-bg"><div class="bar-fill" style="width:{pct}%;opacity:{max(0.2, 1-i*0.1):.1f}"></div></div>
          <span style="font-size:11px;color:var(--gray-3);width:32px;text-align:right">{pct}%</span>
        </div>
      </td>
    </tr>"""


def _render_edu(attack_type: str, count: int) -> str:
    info  = EXPLANATIONS.get(attack_type, GENERIC_EXPLANATION)
    icon  = info["icon"]
    color = info["color"]
    prio  = _priority_badge(info["priority"])
    bg    = color + "14"
    return f"""
    <div class="edu-card">
      <div class="edu-header">
        <div class="edu-icon" style="background:{bg}">{icon}</div>
        <div>
          <h3>{_esc(attack_type)}</h3>
          <div class="edu-cnt">{count} occurrence(s) · {prio}</div>
        </div>
      </div>
      <div class="edu-body">
        <div class="edu-block">
          <h4>Qu'est-ce que c'est ?</h4>
          <p>{info["what"]}</p>
        </div>
        <div class="edu-block">
          <h4>Quel est le risque ?</h4>
          <p>{info["impact"]}</p>
        </div>
        <div class="edu-block edu-fix">
          <h4>🔧 Recommandation de remédiation</h4>
          <p>{info["fix"]}</p>
        </div>
      </div>
    </div>"""


def _render_recos(critical_types: list, high_types: list, has_successful: bool) -> str:
    recos = []
    if has_successful:
        recos.append(("🔴 Critique", "Attaques réussies détectées",
            "Des requêtes malveillantes ont reçu un code 2xx. Analysez immédiatement les logs bruts "
            "et vérifiez les données affectées. Une compromission potentielle est à investiguer."))
    if critical_types:
        recos.append(("🔴 Critique", f"Remédiation urgente : {', '.join(_short(t) for t in critical_types[:3])}",
            "Ces types d'attaque représentent un risque d'exécution de code à distance (RCE) ou de "
            "compromission totale. Appliquez les corrections décrites dans la section 6 immédiatement."))
    if high_types:
        recos.append(("🟠 Haute", "Durcissement de la configuration serveur",
            "Ajoutez dans Nginx : blocage des chemins sensibles (<code>return 444</code> pour "
            "<code>/.env</code>, <code>/.git</code>, <code>/wp-admin</code>…) et augmentation "
            "des buffers proxy (<code>proxy_buffer_size 128k</code>)."))
    recos.append(("🟡 Moyenne", "Mise en place de Fail2Ban",
        "Bannissez automatiquement les IPs après 5 tentatives échouées en 10 minutes. "
        "Configurez UFW pour n'ouvrir que les ports 80, 443 et 22."))
    recos.append(("🔵 Basse", "Monitoring continu et gouvernance",
        "Planifiez une revue mensuelle de ces rapports. Ajoutez un fichier <code>robots.txt</code> "
        "et <code>favicon.ico</code> pour réduire les 404 dans les logs."))

    html = ""
    for i, (priority, title, desc) in enumerate(recos):
        html += f"""
        <div class="reco-card">
          <div class="reco-num">{i+1:02d}</div>
          <div class="reco-content">
            <h4>{priority} — {title}</h4>
            <p>{desc}</p>
          </div>
        </div>"""
    return html