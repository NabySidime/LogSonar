"""
Jetons de lecture : ils doivent pouvoir CONSULTER, et rien d'autre.
"""
import time
from contextlib import asynccontextmanager

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import db, security as sec
from app import settings_store as S
from app.api import admin, auth, ingest, monitoring, tokens, users, vulns

VALID, REVOKED, EXPIRED = "lsr_valide_123", "lsr_revoque_456", "lsr_expire_789"


@asynccontextmanager
async def lifespan(_app):
    await db.init_db()
    await S.load()
    await db.execute("DELETE FROM api_tokens")
    now = time.time()
    for tok, expires, revoked in ((VALID, now + 3600, None), (REVOKED, now + 3600, now), (EXPIRED, now - 1, None)):
        await db.execute(
            "INSERT INTO api_tokens (name, token_hash, prefix, created_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?)",
            (tok, sec.hash_api_token(tok), tok[:10], now, expires, revoked))
    yield
    await db.close_db()


@pytest.fixture(scope="module")
def client():
    app = FastAPI(lifespan=lifespan)
    for r in (auth.router, users.router, monitoring.router, vulns.router, admin.router, ingest.router, tokens.router):
        app.include_router(r)
    sec.ip_limiter.success("readtoken:testclient")
    with TestClient(app) as c:
        yield c


def h(token=VALID):
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize("path", ["/api/alerts", "/api/vulns/summary", "/api/vulns/findings", "/api/reports",
                                  "/api/security/events"])
def test_reading_is_allowed(client, path):
    assert client.get(path, headers=h()).status_code == 200


@pytest.mark.parametrize("method,path", [
    ("POST", "/api/alerts/1/status"),       # traiter une alerte
    ("POST", "/api/vulns/scan"),            # lancer un scan
    ("POST", "/api/vulns/config/accept"),   # accepter un risque de configuration
    ("POST", "/api/containers/mute"),       # mettre un conteneur en sourdine
    ("PUT", "/api/settings"),               # modifier les paramètres
    ("POST", "/api/settings/test/email"),   # envoyer une notification
    ("POST", "/api/reports/generate"),
    ("DELETE", "/api/reports/rapport_2026-01-01.html"),
    ("POST", "/api/users"),
    ("DELETE", "/api/users/1"),
    ("POST", "/api/auth/password"),
    ("POST", "/api/auth/logout"),
    ("POST", "/api/tokens"),                # un jeton ne crée pas d'autres jetons
    ("DELETE", "/api/tokens/1"),
])
def test_writing_is_refused(client, method, path):
    r = client.request(method, path, headers=h(), json={})
    assert r.status_code == 403
    assert "lecture seule" in r.json()["detail"]


@pytest.mark.parametrize("path", ["/api/settings", "/api/users", "/api/tokens", "/api/auth/me", "/api/settings/ingest"])
def test_sensitive_pages_are_refused(client, path):
    assert client.get(path, headers=h()).status_code == 403


@pytest.mark.parametrize("token", [REVOKED, EXPIRED, "lsr_inconnu", "lsr_"])
def test_invalid_tokens_are_refused(client, token):
    assert client.get("/api/alerts", headers=h(token)).status_code == 401


def test_no_token_no_access(client):
    assert client.get("/api/alerts").status_code == 401


def test_read_token_cannot_feed_the_ingest_endpoint(client):
    # Le point d'entrée du middleware a son propre jeton : un jeton de lecture n'y écrit rien
    assert client.post("/api/ingest", headers=h(), json={"events": []}).status_code == 401
