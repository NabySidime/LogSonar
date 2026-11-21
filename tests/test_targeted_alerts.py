"""
Alertes « attaque ciblée » et « afflux » : elles font sonner l'alarme de nuit, donc elles doivent
viser une vraie attaque (une IP qui essaie plusieurs techniques, ou beaucoup d'IP à la fois) et
ignorer un scanner automatique qui envoie des centaines de requêtes d'un seul type.
"""
import asyncio
import time

from app import monitor as M

SETTINGS = {
    "attack_campaign_threshold": 100000, "attack_targeted_types": 3,
    "attack_surge_threshold": 100, "attack_surge_min_ips": 10,
}
FILES = "Recherche de fichiers sensibles"


def event(ip, typ, path="/x", status="404", severity="high"):
    return {
        "ts": time.time(), "container": "web_nginx", "kind": "web", "ip": ip, "method": "GET",
        "path": path, "status": status, "attack_type": typ, "severity": severity, "ua": "curl",
        "raw": f'{ip} - - "GET {path} HTTP/1.1" {status} 10', "detail": "",
    }


def run(monkeypatch, events, settings=None):
    raised = []

    async def fake_raise(fingerprint, *args, **kw):
        raised.append(fingerprint)

    values = {**SETTINGS, **(settings or {})}
    monkeypatch.setattr(M.alerts, "raise_alert", fake_raise)
    monkeypatch.setattr(M.S, "get", lambda key: values[key])

    async def scenario():
        mon = M.Monitor()
        for ev in events:
            mon._on_attack(ev)
        await asyncio.gather(*mon._bg)

    asyncio.run(scenario())
    return raised


def test_one_ip_trying_three_techniques_is_targeted(monkeypatch):
    evs = [event("45.148.10.5", t, path=f"/{i}") for i, t in enumerate(
        ["Tentative d'Injection SQL", "Tentative de Path Traversal", FILES])]
    raised = run(monkeypatch, evs)
    assert "targeted:45.148.10.5" in raised


def test_scanner_with_one_technique_is_not_targeted(monkeypatch):
    evs = [event("34.140.184.76", FILES, path=f"/.env{i}") for i in range(130)]
    raised = run(monkeypatch, evs)
    assert not [f for f in raised if f.startswith("targeted:") or f == "surge"]


def test_bots_and_login_failures_do_not_count(monkeypatch):
    evs = [event("45.148.10.9", t, path=f"/{i}", severity="low") for i, t in enumerate(
        ["Scan de vulnérabilités (Bot)", "Échec d'authentification", "Flood", FILES])]
    raised = run(monkeypatch, evs)
    assert "targeted:45.148.10.9" not in raised


def test_surge_needs_many_ips(monkeypatch):
    many = [event(f"45.148.10.{i % 12 + 1}", FILES, path=f"/a{i}") for i in range(100)]
    assert "surge" in run(monkeypatch, many)
    few = [event(f"45.148.10.{i % 3 + 1}", FILES, path=f"/b{i}") for i in range(150)]
    assert "surge" not in run(monkeypatch, few)


def test_zero_disables(monkeypatch):
    evs = [event(f"45.148.10.{i % 12 + 1}", t, path=f"/c{i}") for i in range(120)
           for t in ["Tentative d'Injection SQL"]] + [
        event("45.148.10.1", t, path=f"/d{j}") for j, t in enumerate(["Tentative de Path Traversal", FILES])]
    raised = run(monkeypatch, evs, {"attack_targeted_types": 0, "attack_surge_threshold": 0})
    assert not [f for f in raised if f.startswith("targeted:") or f == "surge"]


def test_private_ips_are_ignored(monkeypatch):
    monkeypatch.setattr(M, "PROXY_WAIT", 0)
    evs = [event("172.18.0.7", t, path=f"/{i}") for i, t in enumerate(
        ["Tentative d'Injection SQL", "Tentative de Path Traversal", FILES])]
    assert "targeted:172.18.0.7" not in run(monkeypatch, evs)
