import aiosqlite
import os
from datetime import datetime

DB_PATH = "data/logsonar.db"
REPORT_DIR = "data/reports"

# Dictionnaire pédagogique : on traduit le jargon technique en français clair
EXPLANATIONS = {
    "Tentative d'Injection SQL": {
        "what": "L'attaquant a essayé d'insérer des commandes SQL (le langage des bases de données) dans un champ de saisie. Le but est souvent de voler des mots de passe, de supprimer des données ou de contourner une page de connexion.",
        "impact": "Si l'attaque réussit, l'attaquant peut prendre le contrôle total de votre base de données.",
        "fix": "Assurez-vous d'utiliser l'ORM de votre framework (ex: Django Models) ou des requêtes paramétrées. Ne concaténez JAMAIS des variables utilisateur directement dans une requête SQL."
    },
    "Tentative de Cross-Site Scripting (XSS)": {
        "what": "L'attaquant a tenté d'injecter du code JavaScript malveillant dans votre site. Si ce code s'exécute, il peut voler les cookies ou les sessions de vos utilisateurs.",
        "impact": "Un XSS réussi permet à l'attaquant d'agir au nom de vos utilisateurs (compte admin, etc.).",
        "fix": "Échappez systématiquement toutes les données saisies par l'utilisateur avant de les afficher dans le HTML (ex: avec le filtre |escape dans vos templates)."
    },
    "Tentative de Path Traversal": {
        "what": "L'attaquant a utilisé des caractères spéciaux (../) pour essayer de sortir du dossier prévu et accéder à des fichiers sensibles du serveur (comme /etc/passwd sous Linux).",
        "impact": "Cela peut permettre de lire des fichiers de configuration contenant des mots de passe ou des clés secrètes.",
        "fix": "Validez strictement les chemins de fichiers demandés. Utilisez la fonction `os.path.basename()` pour vous assurer que l'utilisateur ne remonte pas l'arborescence."
    },
    "Scan de vulnérabilités (Bot)": {
        "what": "Un robot automatisé (comme Nmap ou Nikto) scanne votre serveur à la recherche de failles connues ou de pages d'administration ouvertes.",
        "impact": "C'est souvent le prélude à une attaque ciblée. Le robot dresse une carte de vos points faibles.",
        "fix": "Censurez les messages d'erreur détaillés en production. Utilisez un pare-feu (Fail2Ban) pour bloquer les IP qui font trop de requêtes erronées."
    },
    "Recherche de fichiers sensibles": {
        "what": "Quelqu'un cherche des fichiers classiques qui ne devraient pas être publics (comme .env, wp-admin, ou .git).",
        "impact": "Le fichier .env contient souvent vos clés API et mots de passe de base de données.",
        "fix": "Assurez-vous que le fichier .env est strictement interdit d'accès via votre serveur web (Nginx/Apache) et ne jamais le commiter sur Git."
    }
}

async def generate_daily_report():
    today = datetime.now().strftime("%Y-%m-%d")
    yesterday = (datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
    
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        # On récupère toutes les attaques de la journée
        cursor = await db.execute("SELECT * FROM critical_events WHERE timestamp LIKE ? ORDER BY timestamp DESC", (f"{today}%",))
        events = await cursor.fetchall()

    if not events:
        print(f"LogSonar: Aucune attaque à rapporter pour le {today}.")
        return None

    # Génération du HTML du rapport
    html_content = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f9fafb; color: #111827; padding: 40px; line-height: 1.6; }}
            .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }}
            h1 {{ color: #111827; border-bottom: 2px solid #e5e7eb; padding-bottom: 10px; }}
            .alert-box {{ background: #fef2f2; border-left: 4px solid #ef4444; padding: 15px; margin-bottom: 20px; border-radius: 4px; }}
            .explanation-box {{ background: #f0fdf4; border-left: 4px solid #22c55e; padding: 15px; margin: 20px 0; border-radius: 4px; }}
            .fix-box {{ background: #eff6ff; border-left: 4px solid #3b82f6; padding: 15px; margin: 20px 0; border-radius: 4px; }}
            .raw-log {{ background: #1f2937; color: #d1d5db; padding: 10px; border-radius: 6px; font-family: monospace; font-size: 13px; margin-top: 10px; word-break: break-all; }}
            .meta {{ color: #6b7280; font-size: 14px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Rapport de Sécurité LogSonar</h1>
            <p class="meta">Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')}<br>Événements analysés pour la journée du {today}</p>
            
            <div class="alert-box">
                <strong>Résumé :</strong> {len(events)} événement(s) critique(s) détecté(s) sur vos serveurs aujourd'hui.
            </div>
    """

    for event in events:
        attack_type = event["attack_type"]
        infos = EXPLANATIONS.get(attack_type, {
            "what": "Une activité suspecte non classifiée a été détectée.",
            "impact": "À déterminer.",
            "fix": "Analysez les logs bruts ci-dessous pour comprendre l'intention de l'attaquant."
        })

        html_content += f"""
            <hr style="border: 0; border-top: 1px solid #e5e7eb; margin: 30px 0;">
            <h2>{attack_type}</h2>
            <p><strong>IP source :</strong> {event['ip']} | <strong>Cible :</strong> {event['container']} | <strong>Heure :</strong> {event['timestamp']}</p>
            
            <div class="explanation-box">
                <strong>Qu'est-ce que c'est ?</strong><br>
                {infos['what']}<br><br>
                <strong>Quel est le risque ?</strong><br>
                {infos['impact']}
            </div>

            <div class="fix-box">
                <strong>🔧 Recommandation de remédiation :</strong><br>
                {infos['fix']}
            </div>

            <p class="meta"><strong>Log brut pour analyse technique :</strong></p>
            <div class="raw-log">{event['raw_log'][:500]}</div>
        """

    html_content += "</div></body></html>"

    # Sauvegarde du fichier
    os.makedirs(REPORT_DIR, exist_ok=True)
    filename = f"rapport_{today}.html"
    filepath = os.path.join(REPORT_DIR, filename)
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)
        
    print(f"LogSonar: Rapport {filename} généré avec succès ({len(events)} attaques).")
    return filename