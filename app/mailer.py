import asyncio
import aiohttp
from db import get_setting

BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"

async def send_brevo_email(
    to_email: str,
    subject: str,
    html_content: str,
    text_content: str = None,
) -> bool:
    """
    Envoie un email via l'API Brevo (Sendinblue).
    Retourne True si l'envoi a réussi.
    """
    api_key = await get_setting("brevo_api_key")
    sender = await get_setting("brevo_sender_email")

    if not api_key or not sender:
        print("LogSonar: Brevo non configuré (clé API ou expéditeur manquant).")
        return False

    if not to_email:
        return False

    payload = {
        "sender": {"email": sender},
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": html_content,
    }
    if text_content:
        payload["textContent"] = text_content

    headers = {
        "api-key": api_key,
        "Content-Type": "application/json",
    }

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(BREVO_API_URL, json=payload, headers=headers, timeout=10) as resp:
                if resp.status in (200, 201):
                    print(f"LogSonar: Email Brevo envoyé à {to_email}")
                    return True
                else:
                    error_text = await resp.text()
                    print(f"LogSonar: Erreur Brevo {resp.status}: {error_text}")
                    return False
        except Exception as e:
            print(f"LogSonar: Exception Brevo: {e}")
            return False


async def send_critical_alert(event_data):
    """Envoie une alerte critique via Brevo."""
    alert_email = await get_setting("alert_email")
    if not alert_email or alert_email == "votre_email@example.com":
        return

    subject = f"LogSonar Alert : {event_data.get('attack_type')}"
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
    html = f"""
<!DOCTYPE html>
<html>
<body style="font-family: system-ui, sans-serif; background: #f5f5f5; padding: 40px;">
<div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 12px; padding: 32px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
    <h2 style="margin-top: 0; color: #d32f2f;">⚠️ Alerte LogSonar</h2>
    <p><strong>Type :</strong> {event_data.get('attack_type')}</p>
    <p><strong>IP :</strong> {event_data.get('ip')}</p>
    <p><strong>Conteneur :</strong> {event_data.get('container')}</p>
    <p><strong>Méthode :</strong> {event_data.get('method')}</p>
    <p><strong>Chemin :</strong> {event_data.get('path')}</p>
    <p><strong>Heure :</strong> {event_data.get('timestamp')}</p>
    <hr>
    <pre style="background:#f0f0f0; padding:12px; border-radius:6px; overflow:auto; font-size:13px;">{event_data.get('raw')}</pre>
</div>
</body>
</html>
"""
    await send_brevo_email(alert_email, subject, html, text)


async def send_otp_email(to_email: str, otp_code: str, username: str) -> None:
    """Envoie un OTP via Brevo."""
    subject = "LogSonar — Code de confirmation"
    text = f"""
Bonjour {username},

Votre code de confirmation LogSonar est :

    {otp_code}

Ce code est valable pendant 5 minutes.
— LogSonar Security
"""
    html = f"""
<!DOCTYPE html>
<html>
<body style="font-family: system-ui, sans-serif; background: #f5f5f5; padding: 40px;">
<div style="max-width: 400px; margin: 0 auto; background: white; border-radius: 12px; padding: 32px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
    <h2 style="margin-top: 0; color: #111;">LogSonar</h2>
    <p>Bonjour <strong>{username}</strong>,</p>
    <p>Voici votre code de confirmation :</p>
    <div style="background: #f5f5f5; border-radius: 8px; padding: 20px; text-align: center; margin: 24px 0;">
        <span style="font-family: monospace; font-size: 32px; font-weight: bold; color: #111; letter-spacing: 8px;">{otp_code}</span>
    </div>
    <p style="color: #999; font-size: 13px;">Ce code est valable 5 minutes. Ne le partagez avec personne.</p>
</div>
</body>
</html>
"""
    await send_brevo_email(to_email, subject, html, text)