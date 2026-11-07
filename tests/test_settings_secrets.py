"""
Paramètres : la clé API Brevo n'est jamais effacée ni remplacée par un enregistrement
qui ne la modifie pas, et une valeur qui n'est pas une clé Brevo est refusée.
"""
from contextlib import asynccontextmanager

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import config, db
from app import settings_store as S
from app.api import admin
from app.security import require_admin

KEY = "xkeysib-" + "0123456789abcdef" * 4 + "-AbCdEfGh12345678"
FORM = {"email_enabled": True, "email_to": "admin@exemple.com", "brevo_sender": "alertes@exemple.com",
        "notify_min_severity": "high", "cpu_warn": 80, "cpu_crit": 95}


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(db, "_db", None)
    monkeypatch.setattr(S, "_fernet", None)
    monkeypatch.setattr(S, "_cache", {})

    async def no_check():
        return None
    monkeypatch.setattr(admin, "check_notification_setup", no_check)

    @asynccontextmanager
    async def lifespan(_app):
        await db.init_db()
        await S.load()
        yield
        await db.close_db()

    app = FastAPI(lifespan=lifespan)
    app.include_router(admin.router)
    app.dependency_overrides[require_admin] = lambda: {"id": 1, "role": "admin"}
    with TestClient(app) as c:
        yield c


def stored_key():
    return S.get("brevo_api_key")


def test_save_without_key_keeps_it(client):
    assert client.put("/api/settings", json={**FORM, "brevo_api_key": KEY}).status_code == 200
    r = client.put("/api/settings", json={**FORM, "cpu_warn": 70})  # champ secret laissé vide : non envoyé
    assert r.status_code == 200
    assert stored_key() == KEY
    assert r.json()["brevo_api_key_set"] is True


def test_keep_marker_and_null_keep_it(client):
    client.put("/api/settings", json={**FORM, "brevo_api_key": KEY})
    for value in ("__keep__", None):
        assert client.put("/api/settings", json={**FORM, "brevo_api_key": value}).status_code == 200
        assert stored_key() == KEY


def test_browser_autofilled_password_is_refused_and_key_kept(client):
    client.put("/api/settings", json={**FORM, "brevo_api_key": KEY})
    r = client.put("/api/settings", json={**FORM, "cpu_warn": 70, "brevo_api_key": "MonMotDePasse2026!"})
    assert r.status_code == 422
    assert "xkeysib-" in r.json()["detail"]
    assert stored_key() == KEY
    assert S.get("cpu_warn") != 70  # rien n'est enregistré quand une valeur est refusée


def test_explicit_clear_still_works(client):
    client.put("/api/settings", json={**FORM, "brevo_api_key": KEY})
    assert client.put("/api/settings", json={"brevo_api_key": ""}).status_code == 200  # bouton « Supprimer »
    assert stored_key() == ""


def test_settings_show_key_ending_only(client):
    client.put("/api/settings", json={**FORM, "brevo_api_key": KEY})
    data = client.get("/api/settings").json()
    assert data["brevo_api_key_hint"] == KEY[-4:]
    assert KEY not in str(data)
    assert "brevo_api_key" not in data


def test_webhook_urls_get_no_hint(client):
    url = "https://discord.com/api/webhooks/123/abcdefghijklmnop"
    client.put("/api/settings", json={"discord_webhook": url})
    assert client.get("/api/settings").json()["discord_webhook_hint"] == ""


def test_telegram_token_format(client):
    assert client.put("/api/settings", json={"telegram_bot_token": "motdepasse"}).status_code == 422
    assert client.put("/api/settings", json={"telegram_bot_token": "123456789:ABCdefGHIjklMNOpqrSTUvwxYZ012"}).status_code == 200


def test_static_js_is_revalidated():
    from app.main import app
    with TestClient(app) as c:
        r = c.get("/static/js/pages-admin.js")
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-cache"
