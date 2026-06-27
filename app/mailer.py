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

    # ← AJOUT : Si SMTP non configuré, on abandonne silencieusement
    if not smtp_user or not smtp_password:
        print(f"LogSonar: SMTP non configuré — alerte email ignorée")
        return

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
            raise

    # On lance l'envoi en arrière-plan
    await asyncio.to_thread(send_mail_sync)


async def send_otp_email(to_email: str, otp_code: str, username: str) -> None:
    """Envoie un email avec le code OTP de confirmation."""
    smtp_host = await get_setting('smtp_host')
    smtp_port = int(await get_setting('smtp_port') or 587)
    smtp_user = await get_setting('smtp_user')
    smtp_password = await get_setting('smtp_password')

    if not smtp_host or not smtp_user or not smtp_password:
        print(f"LogSonar: SMTP non configuré — OTP non envoyé à {username}")
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "LogSonar — Code de confirmation"
    msg["From"] = f"LogSonar <{smtp_user}>"
    msg["To"] = to_email

    text = f"""
Bonjour {username},

Votre code de confirmation LogSonar est :

    {otp_code}

Ce code est valable pendant 5 minutes.
Si vous n'avez pas demandé cette connexion, ignorez cet email.

— LogSonar Security
"""
    
    html = f"""
<!DOCTYPE html>
<html>
<body style="font-family: system-ui, sans-serif; background: #f5f5f5; padding: 40px;">
<div style="max-width: 400px; margin: 0 auto; background: white; border-radius: 12px; padding: 32px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
    <h2 style="margin-top: 0; color: #111;">LogSonar</h2>
    <p style="color: #666;">Bonjour <strong>{username}</strong>,</p>
    <p style="color: #666;">Voici votre code de confirmation :</p>
    <div style="background: #f5f5f5; border-radius: 8px; padding: 20px; text-align: center; margin: 24px 0;">
        <span style="font-family: monospace; font-size: 32px; font-weight: bold; color: #111; letter-spacing: 8px;">{otp_code}</span>
    </div>
    <p style="color: #999; font-size: 13px;">Ce code est valable 5 minutes. Ne le partagez avec personne.</p>
</div>
</body>
</html>
"""
    
    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))

    def send_sync():
        try:
            server = smtplib.SMTP(smtp_host, smtp_port)
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(smtp_user, to_email, msg.as_string())
            server.quit()
            print(f"LogSonar: OTP envoyé à {to_email}")
        except Exception as e:
            print(f"LogSonar: Erreur envoi OTP -> {e}")
            raise

    await asyncio.to_thread(send_sync)