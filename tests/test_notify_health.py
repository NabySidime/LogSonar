"""
Secrets illisibles et absence de canal de notification : signalés, plus jamais silencieux.
"""
import asyncio

from cryptography.fernet import Fernet

from app import db
from app import settings_store as S
from app.alerts import alerts, check_notification_setup

EMAIL = {"email_enabled": True, "brevo_sender": "alertes@exemple.com", "email_to": "moi@exemple.com"}


async def _reset():
    await db.init_db()
    await db.execute("DELETE FROM settings")
    await db.execute("DELETE FROM alerts")
    await S.load()
    await alerts.load()


def test_secret_encrypted_with_another_key_is_reported():
    async def run():
        await _reset()
        await S.set_many(EMAIL)
        # Comme en production : clé Brevo chiffrée avec une ancienne clé
        other = Fernet(Fernet.generate_key()).encrypt(b"xkeysib-ancienne").decode()
        await db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('brevo_api_key', ?)", (other,))
        await S.load()

        assert S.unreadable_secrets() == ["brevo_api_key"]
        view = S.public_view()
        assert view["brevo_api_key_set"] is False and view["brevo_api_key_unreadable"] is True

        await check_notification_setup()
        assert alerts.is_open("settings:unreadable-secrets")
        assert alerts.is_open("settings:no-notification")   # sans clé lisible, l'email ne part pas

        # Ressaisie : tout redevient normal, y compris après rechargement
        await S.set_many({"brevo_api_key": "xkeysib-nouvelle"})
        await check_notification_setup()
        assert S.unreadable_secrets() == []
        assert not alerts.is_open("settings:unreadable-secrets")
        assert not alerts.is_open("settings:no-notification")
        await S.load()
        assert S.get("brevo_api_key") == "xkeysib-nouvelle"
        await db.close_db()
    asyncio.run(run())


def test_empty_secret_is_not_unreadable():
    async def run():
        await _reset()
        await S.set_many({"brevo_api_key": ""})   # bouton « Supprimer »
        await S.load()
        assert S.unreadable_secrets() == []
        await db.close_db()
    asyncio.run(run())
