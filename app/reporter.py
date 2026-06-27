"""
reporter.py — Générateur de rapports HTML enrichis LogSonar
Contenu : KPIs, graphiques Chart.js (camembert + barres), top IPs,
          timeline des événements, sections pédagogiques, recommandations.
"""
import os
from collections import Counter, defaultdict
from datetime import datetime

from db import get_events_for_date

DB_PATH    = "data/logsonar.db"
REPORT_DIR = "data/reports"

# ---------------------------------------------------------------------------
# DICTIONNAIRE PÉDAGOGIQUE
# ---------------------------------------------------------------------------
EXPLANATIONS = {
    "Tentative d'Injection SQL": {
        "icon":   "🗄️",
        "color":  "#dc2626",
        "what":   "L'attaquant insère des commandes SQL dans un champ de saisie ou l'URL pour manipuler votre base de données — voler des mots de passe, contourner une connexion, ou supprimer des données.",
        "impact": "Compromise totale de la base de données, fuite des données utilisateurs, contournement d'authentification.",
        "fix":    "Utilisez exclusivement l'ORM de votre framework (Django Models, SQLAlchemy) ou des requêtes paramétrées. Ne concaténez <strong>jamais</strong> de variables utilisateur dans une requête SQL.",
    },
    "Tentative de Cross-Site Scripting (XSS)": {
        "icon":   "💉",
        "color":  "#d97706",
        "what":   "L'attaquant tente d'injecter du code JavaScript malveillant dans votre site. Si ce code s'exécute dans le navigateur d'un visiteur, il peut voler ses cookies, ses sessions ou agir en son nom.",
        "impact": "Vol de sessions administrateur, redirections malveillantes, défacement de page.",
        "fix":    "Échappez systématiquement toutes les données utilisateur avant affichage HTML (<code>|escape</code> dans Django). Activez le header <code>Content-Security-Policy</code> pour restreindre les scripts autorisés.",
    },
    "Tentative de Path Traversal": {
        "icon":   "📂",
        "color":  "#7c3aed",
        "what":   "Les séquences <code>../</code> permettent de remonter l'arborescence du serveur pour accéder à des fichiers hors du répertoire web — comme <code>/etc/passwd</code> ou vos fichiers de configuration.",
        "impact": "Lecture de fichiers sensibles (clés API, mots de passe, configuration serveur).",
        "fix":    "Validez tout chemin de fichier avec <code>os.path.basename()</code> ou <code>Path.resolve()</code> + vérification que le chemin reste dans le dossier autorisé.",
    },
    "Scan de vulnérabilités (Bot)": {
        "icon":   "🤖",
        "color":  "#0891b2",
        "what":   "Un outil automatisé (Sqlmap, Nikto, Nmap, ffuf…) cartographie votre serveur à la recherche de failles connues, de pages d'administration exposées ou de versions logicielles vulnérables.",
        "impact": "Reconnaissance préalable à une attaque ciblée. L'attaquant dispose d'une carte de vos points faibles.",
        "fix":    "Configurez <strong>Fail2Ban</strong> pour bloquer les IPs après N erreurs. Censurez les headers de version (<code>Server</code>, <code>X-Powered-By</code>) dans Nginx/Apache.",
    },
    "Recherche de fichiers sensibles": {
        "icon":   "🔑",
        "color":  "#059669",
        "what":   "L'attaquant cherche des fichiers couramment oubliés en production : <code>.env</code> (clés API, mots de passe BDD), <code>.git/</code> (code source), <code>wp-admin</code>, <code>backup.sql</code>…",
        "impact": "Exposition des secrets d'application, accès au code source, compromission des credentials.",
        "fix":    "Bloquez l'accès à ces chemins dans Nginx (<code>deny all</code>). Ajoutez <code>.env</code>, <code>*.sql</code>, <code>*.bak</code> à votre <code>.gitignore</code>. N'exposez jamais le dossier <code>.git/</code>.",
    },
    "Alerte interne de l'application": {
        "icon":   "⚙️",
        "color":  "#6b7280",
        "what":   "Votre application a levé une exception de sécurité interne (SuspiciousOperation Django, BadRequest, ou signal LOGSONAR_POST_ATTACK de votre middleware).",
        "impact": "Variable selon le contexte. Peut indiquer une manipulation de cookies, de tokens CSRF ou de paramètres POST suspects.",
        "fix":    "Consultez les logs applicatifs complets pour identifier la requête déclenchante. Vérifiez la configuration du middleware de sécurité de votre framework.",
    },
    "Tentative de falsification (CSRF)": {
        "icon":   "🎭",
        "color":  "#be185d",
        "what":   "Des tentatives de soumission de formulaires sans token CSRF valide ont été détectées. Un attaquant peut tenter de forcer un utilisateur connecté à effectuer des actions à son insu.",
        "impact": "Transactions frauduleuses, modification de données, actions non désirées au nom de l'utilisateur.",
        "fix":    "Assurez-vous que la protection CSRF est activée sur toutes vos vues POST (<code>@csrf_protect</code> ou middleware global dans Django).",
    },
}

GENERIC_EXPLANATION = {
    "icon":   "⚠️",
    "color":  "#6b7280",
    "what":   "Une activité suspecte non classifiée a été détectée dans vos logs.",
    "impact": "À déterminer selon le contexte.",
    "fix":    "Analysez le log brut ci-dessous pour comprendre l'intention de l'attaquant.",
}

# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------
def _esc(s: str) -> str:
    """Échappe le HTML pour éviter les XSS dans le rapport lui-même."""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _short_type(t: str) -> str:
    mapping = {
        "Tentative d'Injection SQL":               "Injection SQL",
        "Tentative de Cross-Site Scripting (XSS)": "XSS",
        "Tentative de Path Traversal":             "Path Traversal",
        "Scan de vulnérabilités (Bot)":            "Scan Bot",
        "Recherche de fichiers sensibles":         "Fichiers sensibles",
        "Alerte interne de l'application":         "Alerte interne",
        "Tentative de falsification (CSRF)":       "CSRF",
    }
    return mapping.get(t, t)


# ---------------------------------------------------------------------------
# GÉNÉRATEUR PRINCIPAL
# ---------------------------------------------------------------------------
async def generate_daily_report(date_str: str | None = None) -> str | None:
    """
    Génère le rapport HTML du jour (ou de la date fournie).
    Retourne le nom de fichier créé, ou None si aucun événement.
    """
    today = date_str or datetime.now().strftime("%Y-%m-%d")
    events = await get_events_for_date(today)

    if not events:
        print(f"LogSonar: Aucune attaque à rapporter pour le {today}.")
        return None

    rows = [dict(e) for e in events]

    # --- Agrégations ---
    type_counts     = Counter(r["attack_type"] for r in rows)
    ip_counts       = Counter(r["ip"] for r in rows)
    container_counts= Counter(r["container"] for r in rows)
    hour_counts: dict[int, int] = defaultdict(int)
    for r in rows:
        try:
            h = int(r["timestamp"][11:13])
            hour_counts[h] += 1
        except Exception:
            pass

    top_ips        = ip_counts.most_common(5)
    unique_ips     = len(ip_counts)
    unique_types   = len(type_counts)
    top_container  = container_counts.most_common(1)[0][0] if container_counts else "—"
    detected_types = list(type_counts.keys())

    # --- Données JSON pour Chart.js ---
    import json
    # Camembert types
    pie_labels  = json.dumps([_short_type(t) for t in type_counts])
    pie_data    = json.dumps(list(type_counts.values()))
    pie_colors  = json.dumps([
        EXPLANATIONS.get(t, GENERIC_EXPLANATION)["color"]
        for t in type_counts
    ])
    # Barres heures (0-23 complets)
    bar_labels  = json.dumps([f"{h:02d}h" for h in range(24)])
    bar_data    = json.dumps([hour_counts.get(h, 0) for h in range(24)])

    # ---------------------------------------------------------------------------
    # TEMPLATE HTML
    # ---------------------------------------------------------------------------
    gen_time = datetime.now().strftime("%d/%m/%Y à %H:%M")

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Rapport LogSonar — {today}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root {{
    --black:   #111827;
    --gray-1:  #374151;
    --gray-2:  #6b7280;
    --gray-3:  #9ca3af;
    --gray-4:  #d1d5db;
    --gray-5:  #f3f4f6;
    --gray-6:  #f9fafb;
    --white:   #ffffff;
    --red:     #dc2626;
    --red-bg:  #fef2f2;
    --green:   #059669;
    --green-bg:#f0fdf4;
    --blue:    #2563eb;
    --blue-bg: #eff6ff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--gray-6);
    color: var(--black);
    line-height: 1.6;
    font-size: 14px;
  }}

  /* HEADER */
  .report-header {{
    background: var(--black);
    color: var(--white);
    padding: 40px 48px;
  }}
  .report-header .brand {{
    font-size: 13px;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: var(--gray-4);
    margin-bottom: 12px;
  }}
  .report-header h1 {{
    font-size: 28px;
    font-weight: 700;
    margin-bottom: 6px;
  }}
  .report-header .meta {{
    font-size: 13px;
    color: var(--gray-3);
  }}

  /* ALERTE CRITIQUE */
  .alert-critical {{
    background: var(--red);
    color: var(--white);
    padding: 14px 48px;
    font-size: 14px;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 10px;
  }}

  /* CONTAINER */
  .container {{ max-width: 960px; margin: 0 auto; padding: 40px 24px; }}

  /* SECTION */
  .section {{ margin-bottom: 40px; }}
  .section-title {{
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: var(--gray-2);
    margin-bottom: 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--gray-4);
  }}

  /* KPI GRID */
  .kpi-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
  }}
  .kpi-card {{
    background: var(--white);
    border: 1px solid var(--gray-4);
    border-radius: 10px;
    padding: 20px;
  }}
  .kpi-card .label {{
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: var(--gray-2);
    margin-bottom: 8px;
  }}
  .kpi-card .value {{
    font-size: 32px;
    font-weight: 800;
    line-height: 1;
    color: var(--black);
  }}
  .kpi-card .sub {{
    font-size: 12px;
    color: var(--gray-3);
    margin-top: 4px;
  }}
  .kpi-card.danger .value {{ color: var(--red); }}

  /* CHARTS */
  .charts-grid {{
    display: grid;
    grid-template-columns: 1fr 2fr;
    gap: 16px;
  }}
  .chart-card {{
    background: var(--white);
    border: 1px solid var(--gray-4);
    border-radius: 10px;
    padding: 24px;
  }}
  .chart-card h3 {{
    font-size: 13px;
    font-weight: 600;
    color: var(--black);
    margin-bottom: 4px;
  }}
  .chart-card .chart-sub {{
    font-size: 11px;
    color: var(--gray-3);
    margin-bottom: 20px;
  }}
  .chart-wrap {{ position: relative; }}

  /* TOP IPs */
  .ip-table {{
    width: 100%;
    border-collapse: collapse;
    background: var(--white);
    border: 1px solid var(--gray-4);
    border-radius: 10px;
    overflow: hidden;
  }}
  .ip-table th {{
    background: var(--gray-5);
    text-align: left;
    padding: 10px 16px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: var(--gray-2);
    border-bottom: 1px solid var(--gray-4);
  }}
  .ip-table td {{
    padding: 12px 16px;
    border-bottom: 1px solid var(--gray-5);
    font-size: 13px;
  }}
  .ip-table tr:last-child td {{ border-bottom: none; }}
  .ip-table .ip-addr {{ font-family: monospace; font-weight: 600; }}
  .bar-cell {{ display: flex; align-items: center; gap: 10px; }}
  .bar-bg {{
    flex: 1;
    background: var(--gray-5);
    border-radius: 4px;
    height: 8px;
    overflow: hidden;
  }}
  .bar-fill {{
    height: 8px;
    background: var(--black);
    border-radius: 4px;
  }}
  .badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 9999px;
    font-size: 11px;
    font-weight: 600;
  }}

  /* TIMELINE */
  .timeline-table {{
    width: 100%;
    border-collapse: collapse;
    background: var(--white);
    border: 1px solid var(--gray-4);
    border-radius: 10px;
    overflow: hidden;
    font-family: monospace;
    font-size: 12px;
  }}
  .timeline-table th {{
    background: var(--gray-5);
    padding: 10px 14px;
    text-align: left;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: var(--gray-2);
    border-bottom: 1px solid var(--gray-4);
    font-family: -apple-system, sans-serif;
  }}
  .timeline-table td {{
    padding: 9px 14px;
    border-bottom: 1px solid var(--gray-5);
    color: var(--gray-1);
    vertical-align: top;
  }}
  .timeline-table tr:last-child td {{ border-bottom: none; }}
  .timeline-table tr:hover td {{ background: var(--gray-6); }}
  .time-cell {{ color: var(--gray-3); white-space: nowrap; }}
  .status-2 {{ color: var(--green); font-weight: 700; }}
  .status-4 {{ color: #d97706; font-weight: 700; }}
  .status-5 {{ color: var(--red); font-weight: 700; }}

  /* PÉDAGOGIE */
  .edu-section {{
    background: var(--white);
    border: 1px solid var(--gray-4);
    border-radius: 10px;
    overflow: hidden;
    margin-bottom: 16px;
  }}
  .edu-header {{
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 18px 24px;
    border-bottom: 1px solid var(--gray-5);
  }}
  .edu-icon {{
    width: 40px;
    height: 40px;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
    flex-shrink: 0;
  }}
  .edu-header h3 {{ font-size: 15px; font-weight: 700; }}
  .edu-header .count {{ font-size: 12px; color: var(--gray-3); margin-top: 2px; }}
  .edu-body {{ padding: 20px 24px; display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
  .edu-block h4 {{
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: var(--gray-2);
    margin-bottom: 6px;
  }}
  .edu-block p {{ font-size: 13px; color: var(--gray-1); line-height: 1.6; }}
  .edu-block code {{
    background: var(--gray-5);
    padding: 1px 5px;
    border-radius: 3px;
    font-size: 12px;
  }}
  .edu-fix {{
    grid-column: 1 / -1;
    background: var(--blue-bg);
    border: 1px solid #bfdbfe;
    border-radius: 8px;
    padding: 14px 18px;
  }}
  .edu-fix h4 {{ color: var(--blue); }}

  /* FOOTER */
  .report-footer {{
    background: var(--black);
    color: var(--gray-3);
    padding: 32px 48px;
    font-size: 12px;
    margin-top: 48px;
  }}
  .report-footer strong {{ color: var(--white); }}
  .reco-grid {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 24px;
    margin-top: 20px;
  }}
  .reco-item {{ border-left: 2px solid var(--gray-1); padding-left: 14px; }}
  .reco-item .reco-title {{ color: var(--white); font-weight: 600; margin-bottom: 4px; font-size: 13px; }}

  @media (max-width: 700px) {{
    .kpi-grid {{ grid-template-columns: repeat(2, 1fr); }}
    .charts-grid {{ grid-template-columns: 1fr; }}
    .edu-body {{ grid-template-columns: 1fr; }}
    .reco-grid {{ grid-template-columns: 1fr; }}
    .report-header, .report-footer {{ padding: 24px; }}
    .container {{ padding: 24px 16px; }}
  }}
</style>
</head>
<body>

<!-- HEADER -->
<div class="report-header">
  <div class="brand">⬡ LogSonar — Rapport de sécurité</div>
  <h1>Rapport du {today}</h1>
  <div class="meta">Généré le {gen_time} &nbsp;·&nbsp; {len(rows)} événement(s) critique(s) détecté(s)</div>
</div>

<!-- ALERTE -->
<div class="alert-critical">
  ⚠ {len(rows)} attaque(s) détectée(s) sur vos conteneurs Docker aujourd'hui
</div>

<div class="container">

  <!-- KPIs -->
  <div class="section">
    <div class="section-title">Résumé de la journée</div>
    <div class="kpi-grid">
      <div class="kpi-card danger">
        <div class="label">Attaques totales</div>
        <div class="value">{len(rows)}</div>
        <div class="sub">événements critiques</div>
      </div>
      <div class="kpi-card">
        <div class="label">IPs uniques</div>
        <div class="value">{unique_ips}</div>
        <div class="sub">sources distinctes</div>
      </div>
      <div class="kpi-card">
        <div class="label">Types d'attaque</div>
        <div class="value">{unique_types}</div>
        <div class="sub">catégories détectées</div>
      </div>
      <div class="kpi-card">
        <div class="label">Conteneur ciblé</div>
        <div class="value" style="font-size:18px;margin-top:6px">{_esc(top_container)}</div>
        <div class="sub">le plus attaqué</div>
      </div>
    </div>
  </div>

  <!-- GRAPHIQUES -->
  <div class="section">
    <div class="section-title">Analyse graphique</div>
    <div class="charts-grid">

      <!-- Camembert types -->
      <div class="chart-card">
        <h3>Répartition par type</h3>
        <div class="chart-sub">Tous événements</div>
        <div class="chart-wrap" style="height:200px">
          <canvas id="chartPie"></canvas>
        </div>
      </div>

      <!-- Barres heures -->
      <div class="chart-card">
        <h3>Volume par heure</h3>
        <div class="chart-sub">Distribution sur 24h</div>
        <div class="chart-wrap" style="height:200px">
          <canvas id="chartHours"></canvas>
        </div>
      </div>

    </div>
  </div>

  <!-- TOP IPs -->
  <div class="section">
    <div class="section-title">Top 5 IP attaquantes</div>
    <table class="ip-table">
      <thead>
        <tr>
          <th>#</th>
          <th>Adresse IP</th>
          <th>Attaques</th>
          <th>Volume</th>
        </tr>
      </thead>
      <tbody>
        {"".join(f'''
        <tr>
          <td style="color:var(--gray-3);font-size:12px">{i+1}</td>
          <td><span class="ip-addr">{_esc(ip)}</span></td>
          <td><span class="badge" style="background:{"#fee2e2" if i==0 else "var(--gray-5)"};color:{"var(--red)" if i==0 else "var(--gray-1)"}">{cnt}</span></td>
          <td>
            <div class="bar-cell">
              <div class="bar-bg"><div class="bar-fill" style="width:{round(cnt/top_ips[0][1]*100)}%;opacity:{1-i*0.15:.2f}"></div></div>
              <span style="font-size:11px;color:var(--gray-3);width:32px;text-align:right">{round(cnt/len(rows)*100)}%</span>
            </div>
          </td>
        </tr>''' for i, (ip, cnt) in enumerate(top_ips))}
      </tbody>
    </table>
  </div>

  <!-- TIMELINE -->
  <div class="section">
    <div class="section-title">Timeline des événements ({len(rows)} au total)</div>
    <table class="timeline-table">
      <thead>
        <tr>
          <th>Heure</th>
          <th>IP source</th>
          <th>Type d'attaque</th>
          <th>Conteneur</th>
          <th>Chemin</th>
          <th>Code</th>
        </tr>
      </thead>
      <tbody>
        {"".join(f'''
        <tr>
          <td class="time-cell">{_esc(r["timestamp"][11:19])}</td>
          <td>{_esc(r["ip"])}</td>
          <td>{_esc(_short_type(r["attack_type"]))}</td>
          <td style="color:var(--gray-3)">[{_esc(r["container"])}]</td>
          <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{_esc(r["path"])}</td>
          <td class="status-{r["status"][0] if r["status"] else "0"}">{_esc(r["status"])}</td>
        </tr>''' for r in sorted(rows, key=lambda x: x["timestamp"]))}
      </tbody>
    </table>
  </div>

  <!-- PÉDAGOGIE -->
  <div class="section">
    <div class="section-title">Explications & recommandations par type détecté</div>
    {"".join(_render_edu_section(t, type_counts[t]) for t in detected_types)}
  </div>

</div><!-- /container -->

<!-- FOOTER -->
<div class="report-footer">
  <strong>Recommandations générales de sécurité</strong>
  <div class="reco-grid">
    <div class="reco-item">
      <div class="reco-title">🔒 Fail2Ban</div>
      Configurez Fail2Ban pour bannir automatiquement les IPs après 5 tentatives échouées en 10 minutes.
    </div>
    <div class="reco-item">
      <div class="reco-title">📋 Logs structurés</div>
      Activez les logs applicatifs POST dans TikiPay/Django via un middleware LOGSONAR_POST_ATTACK pour couvrir le point aveugle des corps de requête.
    </div>
    <div class="reco-item">
      <div class="reco-title">🔄 Mises à jour</div>
      Maintenez vos dépendances à jour. La plupart des scans automatiques ciblent des CVE connues sur des versions spécifiques.
    </div>
  </div>
  <div style="margin-top:24px;padding-top:20px;border-top:1px solid #374151;color:var(--gray-3)">
    Rapport généré par <strong>LogSonar</strong> — {gen_time} &nbsp;·&nbsp;
    Aucune donnée n'a quitté vos serveurs.
  </div>
</div>

<script>
// ── CAMEMBERT TYPES ──────────────────────────────────────────────────────────
new Chart(document.getElementById('chartPie'), {{
  type: 'doughnut',
  data: {{
    labels: {pie_labels},
    datasets: [{{ data: {pie_data}, backgroundColor: {pie_colors}, borderWidth: 2, borderColor: '#fff' }}]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    plugins: {{
      legend: {{ position: 'bottom', labels: {{ font: {{ size: 11 }}, padding: 12, boxWidth: 12 }} }}
    }}
  }}
}});

// ── BARRES HEURES ─────────────────────────────────────────────────────────────
new Chart(document.getElementById('chartHours'), {{
  type: 'bar',
  data: {{
    labels: {bar_labels},
    datasets: [{{
      data: {bar_data},
      backgroundColor: {bar_data}.map(v => v > 0 ? 'rgba(220,38,38,0.75)' : 'rgba(209,213,219,0.4)'),
      borderRadius: 3,
    }}]
  }},
  options: {{
    responsive: true, maintainAspectRatio: false,
    plugins: {{ legend: {{ display: false }} }},
    scales: {{
      x: {{ ticks: {{ font: {{ size: 9 }}, maxRotation: 0 }}, grid: {{ display: false }} }},
      y: {{ ticks: {{ font: {{ size: 10 }}, stepSize: 1 }}, beginAtZero: true,
            grid: {{ color: '#f3f4f6' }} }}
    }}
  }}
}});
</script>
</body>
</html>"""

    os.makedirs(REPORT_DIR, exist_ok=True)
    filename = f"rapport_{today}.html"
    filepath = os.path.join(REPORT_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"LogSonar: Rapport {filename} généré ({len(rows)} attaques, {unique_types} types, {unique_ips} IPs uniques).")
    return filename


# ---------------------------------------------------------------------------
# RENDU D'UNE SECTION PÉDAGOGIQUE
# ---------------------------------------------------------------------------
def _render_edu_section(attack_type: str, count: int) -> str:
    info = EXPLANATIONS.get(attack_type, GENERIC_EXPLANATION)
    icon  = info["icon"]
    color = info["color"]
    bg    = color + "18"   # couleur avec opacité ~10 %

    return f"""
    <div class="edu-section">
      <div class="edu-header">
        <div class="edu-icon" style="background:{bg}">{icon}</div>
        <div>
          <h3>{_esc(attack_type)}</h3>
          <div class="count">{count} occurrence(s) aujourd'hui</div>
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
          <h4>🔧 Recommandation</h4>
          <p>{info["fix"]}</p>
        </div>
      </div>
    </div>"""