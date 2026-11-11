"""
Un scanner ne doit pas déclencher d'email « panne » ou « pic de trafic » :
- 5xx renvoyées à une IP qui attaque ou est bloquée (nginx qui freine) : dashboard seulement ;
- pic expliqué par une ou deux IP : dashboard, email seulement s'il dure 3 min.
Une vraie panne ou un vrai afflux (beaucoup d'IP) reste notifié.
"""
import asyncio
import time
from collections import Counter

from app import monitor as M
from app.traffic import Traffic, spike_sources

SCANNER = "207.175.202.245"
SETTINGS = {"traffic_rpm_threshold": 120, "traffic_spike_factor": 4, "traffic_min_rpm": 120,
            "error_rate_threshold": 10}


def add(tr, n, ip, status, attack=None):
    ts = (int(time.time() // 60) - 1) * 60 + 5   # dernière minute complète
    for _ in range(n):
        tr.record({"ts": ts, "container": "tikipay_nginx", "kind": "web", "ip": ip,
                   "path": "/x", "status": status, "attack_type": attack})


def legit(tr, n, status="200"):
    for i in range(n):
        add(tr, 1, f"41.223.{i // 250}.{i % 250 + 1}", status)


def evaluate(monkeypatch, tr, minutes=1):
    calls, opened = [], set()

    async def raise_alert(fp, category, severity, title, message="", source="", notify=True):
        calls.append((fp, severity, notify))
        opened.add(fp)

    async def resolve(fp, note=""):
        opened.discard(fp)

    monkeypatch.setattr(M, "traffic", tr)
    monkeypatch.setattr(M.alerts, "raise_alert", raise_alert)
    monkeypatch.setattr(M.alerts, "resolve", resolve)
    monkeypatch.setattr(M.alerts, "is_open", lambda fp: fp in opened)
    monkeypatch.setattr(M.S, "get", SETTINGS.get)

    async def scenario():
        mon = M.Monitor()
        for _ in range(minutes):
            await mon._evaluate_traffic(tr.last_minute())

    asyncio.run(scenario())
    return calls


def test_scan_rate_limited_by_nginx_is_not_an_outage(monkeypatch):
    # Alerte du 11/11 02:08 : 52 erreurs 5xx sur 165 requêtes, toutes pour le scanner
    tr = Traffic()
    add(tr, 74, SCANNER, "444", "Recherche de fichiers sensibles")
    add(tr, 9, SCANNER, "503", "Recherche de fichiers sensibles")
    add(tr, 43, SCANNER, "503")
    legit(tr, 39)
    assert tr.last_minute()["errors"] == 52 and tr.last_minute()["requests"] == 165
    calls = evaluate(monkeypatch, tr)
    assert ("traffic:errors:scan", "warning", False) in calls
    assert not [c for c in calls if c[0] == "traffic:errors"]


def test_real_outage_still_notified(monkeypatch):
    tr = Traffic()
    legit(tr, 30, "502")
    legit(tr, 10)
    calls = evaluate(monkeypatch, tr)
    assert ("traffic:errors", "high", True) in calls


def test_outage_during_a_scan_still_notified(monkeypatch):
    tr = Traffic()
    add(tr, 100, SCANNER, "503", "Recherche de fichiers sensibles")
    legit(tr, 40, "500")
    legit(tr, 10)
    calls = evaluate(monkeypatch, tr)
    assert ("traffic:errors", "high", True) in calls
    assert not [c for c in calls if c[0] == "traffic:errors:scan"]


def test_errors_of_unflagged_single_ip_still_count(monkeypatch):
    # Une IP qui n'attaque pas et n'est pas bloquée : on ne l'excuse pas
    tr = Traffic()
    add(tr, 40, "41.223.51.165", "500")
    calls = evaluate(monkeypatch, tr)
    assert ("traffic:errors", "high", True) in calls


def test_single_ip_spike_is_a_scan_emailed_only_if_it_lasts(monkeypatch):
    tr = Traffic()
    add(tr, 320, "34.22.196.121", "404")
    legit(tr, 5)
    calls = evaluate(monkeypatch, tr)
    assert calls == [("traffic:scan", "warning", False)]

    calls = evaluate(monkeypatch, tr, minutes=3)
    assert [c for c in calls if c[0] == "traffic:scan"][-1] == ("traffic:scan", "high", True)
    assert not [c for c in calls if c[0] == "traffic:spike"]


def test_two_scanners_spike(monkeypatch):
    tr = Traffic()
    add(tr, 175, "82.47.1.106", "404")
    add(tr, 170, "82.47.1.148", "404")
    legit(tr, 12)
    calls = evaluate(monkeypatch, tr)
    assert calls == [("traffic:scan", "warning", False)]


def test_distributed_spike_still_notified(monkeypatch):
    tr = Traffic()
    legit(tr, 300)
    calls = evaluate(monkeypatch, tr)
    assert ("traffic:spike", "high", True) in calls


def test_spike_sources():
    assert spike_sources(Counter({"a": 320, "b": 5}), 325, 120) == ["a"]
    # Un scanner, mais le reste du trafic dépasse lui aussi le seuil : vrai pic
    assert spike_sources(Counter({"a": 300, **{f"u{i}": 1 for i in range(200)}}), 500, 120) == []
    # Trois scanners égaux : on n'en retient que deux, ça ne suffit pas
    assert spike_sources(Counter({"a": 150, "b": 150, "c": 150}), 450, 120) == []
