import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import asyncio
from db import get_setting

async def send_critical_alert(event_data):
    """Récupère les paramètres et envoie l'email de manière asynchrone"""
    alert_email = await get_setting('alert_email')
    
    # Si l'email n'est pas configuré, on abandonne silencieusement
    if not alert_email or alert_email == 'votre_email@example.com':
        return 

    smtp_host = await get_setting('smtp_host')
    smtp_port = int(await get_setting('smtp_port') or 587)
    smtp_user = await get_setting('smtp_user')
    smtp_password = await get_setting('smtp_password')

    # Création du message
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"LogSonar Alert : {event_data.get('attack_type')}"
    msg["From"] = f"LogSonar <{smtp_user}>"
    msg["To"] = alert_email

    # Le texte brut du mail (propre et lisible)
    text = f"""
    Une attaque critique a été détectée par LogSonar.

    - Type d'attaque : {event_data.get('attack_type')}
    - Adresse IP     : {event_data.get('ip')}
    - Conteneur      : {event_data.get('container')}
    - Méthode        : {event_data.get('method')}
    - Chemin visé    : {event_data.get('path')}
    - Heure          : {event_data.get('timestamp')}

    Log brut :
    {event_data.get('raw')}
    """
    
    msg.attach(MIMEText(text, "plain"))

    # Fonction bloquante pour l'envoi SMTP (exécutée dans un thread pour ne pas figer LogSonar)
    def send_mail_sync():
        try:
            server = smtplib.SMTP(smtp_host, smtp_port)
            server.starttls() # Sécurisation de la connexion
            server.login(smtp_user, smtp_password)
            server.sendmail(smtp_user, alert_email, msg.as_string())
            server.quit()
            print(f"LogSonar: Alerte envoyée à {alert_email}")
        except Exception as e:
            print(f"LogSonar: Erreur d'envoi d'email -> {e}")

    # On lance l'envoi en arrière-plan
    await asyncio.to_thread(send_mail_sync)