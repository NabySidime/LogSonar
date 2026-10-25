"""
Une attaque vue par l'application (IP interne du proxy) puis par le proxy (IP réelle)
ne doit produire qu'une alerte, avec l'IP réelle, même si l'application écrit en premier.
"""
import asyncio
import time

from app import monitor as M

PATH = "/?website=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2Fiam%2Fsecurity-credentials%2F"
SSRF = "Tentative de SSRF (Falsification de Requête Côté Serveur)"


def event(container, ip):
    return {
        "ts": time.time(), "container": container, "kind": "web", "ip": ip, "method": "GET",
        "path": PATH, "status": "200", "attack_type": SSRF, "severity": "high", "ua": "Mozilla/5.0",
        "raw": f'{ip} - - "GET {PATH} HTTP/1.1" 200 96759', "detail": "",
    }


def run(monkeypatch, events, gap):
    raised = []

    async def fake_raise(fingerprint, *args, **kw):
        raised.append(fingerprint)

    monkeypatch.setattr(M, "PROXY_WAIT", 0.3)
    monkeypatch.setattr(M.alerts, "raise_alert", fake_raise)
    monkeypatch.setattr(M.S, "get", lambda key: 1000)

    async def scenario():
        mon = M.Monitor()
        for ev in events:
            mon._on_attack(ev)
            await asyncio.sleep(gap)  # la ligne suivante arrive plus tard
        await asyncio.gather(*mon._bg)
        return mon

    mon = asyncio.run(scenario())
    return raised, mon


def test_app_line_first_alerts_with_real_ip(monkeypatch):
    raised, mon = run(monkeypatch, [event("tikipay_web", "172.18.0.7"), event("tikipay_nginx", "93.123.109.101")], 0.1)
    assert raised == [f"attack-ok:{SSRF}:93.123.109.101"]
    assert [e["ip"] for e in mon._pending_events] == ["93.123.109.101"]


def test_proxy_line_first(monkeypatch):
    raised, _ = run(monkeypatch, [event("tikipay_nginx", "93.123.109.101"), event("tikipay_web", "172.18.0.7")], 0.1)
    assert raised == [f"attack-ok:{SSRF}:93.123.109.101"]


def test_internal_attack_without_proxy_still_alerts(monkeypatch):
    raised, _ = run(monkeypatch, [event("tikipay_web", "172.18.0.7")], 0)
    assert raised == [f"attack-ok:{SSRF}:172.18.0.7"]
