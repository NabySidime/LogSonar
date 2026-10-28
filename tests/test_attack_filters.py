"""
Attaques critiques : email seulement si le serveur les a acceptées (2xx).
Menaces : filtre par code de réponse et par période personnalisée.
"""
import asyncio
import time
from contextlib import asynccontextmanager

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import db
from app import monitor as M
from app import settings_store as S
from app.alerts import AlertManager
from app.api import monitoring
from app.security import current_user

SQLI = "Tentative d'Injection SQL"


# ---------------------------------------------------------------------------
# Notifications des attaques critiques
# ---------------------------------------------------------------------------
def attack(status, severity="critical", ip="203.0.113.9"):
    return {
        "ts": time.time(), "container": "nginx", "kind": "web", "ip": ip, "method": "GET",
        "path": "/?id=1' UNION SELECT", "status": status, "attack_type": SQLI, "severity": severity,
        "ua": "sqlmap", "raw": "...", "detail": "",
    }


def raised_for(monkeypatch, ev):
    raised = []

    async def fake_raise(fingerprint, category, severity, title, message="", source="", notify=True):
        raised.append((fingerprint, severity, notify))

    monkeypatch.setattr(M.alerts, "raise_alert", fake_raise)
    monkeypatch.setattr(M.S, "get", lambda key: 1000)
    asyncio.run(M.Monitor()._security_alerts(ev))
    return raised


@pytest.mark.parametrize("status", ["200", "204"])
def test_critical_attack_accepted_is_emailed(monkeypatch, status):
    assert raised_for(monkeypatch, attack(status)) == [(f"attack-ok:{SQLI}:203.0.113.9", "critical", True)]


@pytest.mark.parametrize("status", ["301", "403", "404", "503", ""])
def test_critical_attack_refused_stays_in_dashboard(monkeypatch, status):
    assert raised_for(monkeypatch, attack(status)) == [(f"attack:{SQLI}:203.0.113.9", "critical", False)]


def test_high_attack_accepted_still_alerts(monkeypatch):
    assert raised_for(monkeypatch, attack("200", "high")) == [(f"attack-ok:{SQLI}:203.0.113.9", "high", True)]


def test_raise_alert_without_notify_never_sends(monkeypatch):
    sent = []

    async def run():
        await db.init_db()
        await db.execute("DELETE FROM alerts WHERE fingerprint LIKE 'test-notify:%'")
        mgr = AlertManager()
        monkeypatch.setattr(mgr, "_notify", lambda alert: sent.append(alert["fingerprint"]))
        await mgr.raise_alert("test-notify:a", "security", "critical", "A", notify=False)
        await mgr.raise_alert("test-notify:a", "security", "critical", "A", notify=False)
        await mgr.raise_alert("test-notify:b", "security", "critical", "B")
        await db.execute("DELETE FROM alerts WHERE fingerprint LIKE 'test-notify:%'")

    asyncio.run(run())
    assert sent == ["test-notify:b"]


# ---------------------------------------------------------------------------
# API des menaces
# ---------------------------------------------------------------------------
NOW = time.time()
EVENTS = [  # (il y a combien de secondes, code)
    (60, "200"), (120, "200"), (180, "301"), (240, "403"), (300, "503"), (360, ""),
    (3 * 86400, "200"),  # hors de la période « 24 h »
]
MARK = "test-filtres"


@asynccontextmanager
async def lifespan(_app):
    await db.init_db()
    await S.load()
    await db.execute("DELETE FROM security_events WHERE container = ?", (MARK,))
    for ago, status in EVENTS:
        await db.execute(
            "INSERT INTO security_events (ts, container, ip, method, path, status, attack_type, severity)"
            " VALUES (?, ?, '203.0.113.9', 'GET', '/', ?, ?, 'critical')", (NOW - ago, MARK, status, SQLI))
    yield
    await db.execute("DELETE FROM security_events WHERE container = ?", (MARK,))
    await db.close_db()


@pytest.fixture(scope="module")
def client():
    app = FastAPI(lifespan=lifespan)
    app.include_router(monitoring.router)
    app.dependency_overrides[current_user] = lambda: {"id": 1, "role": "admin"}
    with TestClient(app) as c:
        yield c


def codes(client, **params):
    r = client.get("/api/security/events", params={"container": MARK, "limit": 500, **params})
    assert r.status_code == 200, r.text
    return sorted(e["status"] for e in r.json()["items"])


def test_filter_by_exact_code(client):
    assert codes(client, status="200") == ["200", "200", "200"]
    assert codes(client, status="200,301") == ["200", "200", "200", "301"]


def test_filter_by_family_and_without_code(client):
    assert codes(client, status="5xx") == ["503"]
    assert codes(client, status="2xx,3xx") == ["200", "200", "200", "301"]
    assert codes(client, status="none") == [""]


def test_invalid_code_is_refused(client):
    assert client.get("/api/security/events", params={"status": "2' OR 1=1"}).status_code == 400


def test_custom_period(client):
    since, until = NOW - 4 * 86400, NOW - 2 * 86400
    assert codes(client, since=since, until=until) == ["200"]
    assert len(codes(client, since=NOW - 86400)) == 6


def test_stats_on_custom_period(client):
    r = client.get("/api/security/stats", params={"since": NOW - 3600}).json()
    mine = {x["status"]: x["n"] for x in r["by_status"]}
    assert mine["200"] >= 2 and mine["503"] >= 1
    assert r["timeline"][0]["hour"] is not None   # courbe par heure sur une courte période
    r = client.get("/api/security/stats", params={"since": NOW - 10 * 86400}).json()
    assert r["timeline"][0]["hour"] is None and len(r["timeline"]) in (10, 11)


def test_period_must_be_ordered(client):
    assert client.get("/api/security/stats", params={"since": NOW, "until": NOW - 60}).status_code == 400


def test_alerts_and_host_accept_a_period(client):
    assert client.get("/api/alerts", params={"status": "all", "since": NOW - 86400, "until": NOW}).status_code == 200
    r = client.get("/api/host", params={"since": NOW - 2 * 86400, "until": NOW - 86400})
    assert r.status_code == 200
    assert all(NOW - 2 * 86400 - 3600 <= p["ts"] <= NOW - 86400 for p in r.json()["history"])
