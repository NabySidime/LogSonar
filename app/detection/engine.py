"""
Analyse d'une ligne de log : parsing HTTP, signatures, comportement.
"""
from __future__ import annotations

import ipaddress
import re
import time
import unicodedata
from collections import defaultdict, deque
from typing import Optional
from urllib.parse import unquote_plus, urlsplit

from .. import config
from .parsers import is_private_ip, parse_http
from .signatures import RULES, SEVERITY_ORDER

_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
_SQL_COMMENT_RE = re.compile(r"/\*.*?\*/")
MAX_LINE = 8192


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def normalize(raw: str) -> str:
    """Décodage URL répété (double encodage), normalisation Unicode, retrait des commentaires SQL."""
    # Nginx échappe les guillemets en \x22, Apache en \"
    s = raw.replace("\\x22", '"').replace('\\"', '"')
    for _ in range(4):
        try:
            decoded = unquote_plus(s)
        except Exception:
            break
        if decoded == s:
            break
        s = decoded
    s = unicodedata.normalize("NFKC", s).replace("\x00", "")
    return _SQL_COMMENT_RE.sub(" ", s)


def _whitelisted(ip: str) -> bool:
    if not ip or not config.WHITELIST:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in config.WHITELIST)


_REDIRECT_RE = re.compile(
    r"(?:^|[?&])(?:redirect|redirect_uri|redirect_url|return|returnTo|return_url|next|url|goto|dest|"
    r"destination|continue|target|redir)=((?:https?:)?//[^&\s]+)",
    re.IGNORECASE,
)


def _open_redirect(path_qs: str) -> bool:
    for m in _REDIRECT_RE.finditer(path_qs):
        try:
            host = (urlsplit(m.group(1)).hostname or "").lower()
        except ValueError:
            continue
        if not host:
            continue
        allowed = config.ALLOWED_REDIRECT_DOMAINS
        if not any(host == d or host.endswith("." + d) for d in allowed):
            return True
    return False


def find_rule(surfaces: dict[str, str]) -> Optional[tuple[str, str, str, re.Match]]:
    """Règle la plus grave qui correspond : (nom, sévérité, surface, correspondance)."""
    best: Optional[tuple[str, str, str, re.Match]] = None
    for rule in RULES:
        for surface in rule.surfaces:
            text = surfaces.get(surface)
            m = rule.regex.search(text) if text else None
            if m:
                if best is None or SEVERITY_ORDER[rule.severity] > SEVERITY_ORDER[best[1]]:
                    best = (rule.name, rule.severity, surface, m)
                break
        if best and best[1] == "critical":
            break
    return best


def match_rules(surfaces: dict[str, str]) -> Optional[tuple[str, str]]:
    """Retourne (nom, sévérité) de la règle la plus grave qui correspond."""
    hit = find_rule(surfaces)
    return hit[:2] if hit else None


# ---------------------------------------------------------------------------
# Détection comportementale (fenêtres glissantes, mémoire bornée)
# ---------------------------------------------------------------------------
class Behavior:
    BRUTE_LIMIT, BRUTE_WINDOW = 60, 60     # même IP + même URL sensible (POST, login)
    FLOOD_LIMIT, FLOOD_WINDOW = 600, 60    # même IP, toutes URLs
    AUTH_FAIL_LIMIT, AUTH_FAIL_WINDOW = 10, 300  # réponses 401/403 sur la même IP

    def __init__(self) -> None:
        self._hits: dict[str, deque] = defaultdict(deque)
        self._flagged: dict[str, float] = {}
        self._last_cleanup = time.monotonic()

    def _count(self, key: str, window: int, now: float) -> int:
        q = self._hits[key]
        q.append(now)
        while q and now - q[0] > window:
            q.popleft()
        return len(q)

    def _once(self, key: str, now: float, cooldown: float = 300) -> bool:
        """Évite de signaler la même rafale à chaque requête suivante."""
        last = self._flagged.get(key)
        if last and now - last < cooldown:
            return False
        self._flagged[key] = now
        return True

    def observe(self, ip: str, method: str, path: str, status: str) -> Optional[tuple[str, str, str]]:
        # Les IP internes (proxy, autres conteneurs) ne sont pas évaluées : sinon le
        # reverse proxy serait lui-même pris pour un attaquant.
        if not ip or is_private_ip(ip):
            return None
        now = time.monotonic()
        self._maybe_cleanup(now)
        base = path.split("?")[0]

        if status in ("401", "403"):
            n = self._count(f"a:{ip}", self.AUTH_FAIL_WINDOW, now)
            if n >= self.AUTH_FAIL_LIMIT and self._once(f"a:{ip}", now):
                return ("Force brute", "high", f"{n} refus d'accès (401/403) en {self.AUTH_FAIL_WINDOW // 60} min")

        if method == "POST":
            n = self._count(f"b:{ip}:{base}", self.BRUTE_WINDOW, now)
            if n >= self.BRUTE_LIMIT and self._once(f"b:{ip}:{base}", now):
                return ("Force brute", "high", f"{n} POST en 1 min sur {base[:80]}")

        n = self._count(f"f:{ip}", self.FLOOD_WINDOW, now)
        if n >= self.FLOOD_LIMIT and self._once(f"f:{ip}", now):
            return ("Flood", "medium", f"{n} requêtes en 1 min")
        return None

    def _maybe_cleanup(self, now: float) -> None:
        if now - self._last_cleanup < 60:
            return
        self._last_cleanup = now
        horizon = max(self.BRUTE_WINDOW, self.FLOOD_WINDOW, self.AUTH_FAIL_WINDOW)
        for key in [k for k, q in self._hits.items() if not q or now - q[-1] > horizon]:
            del self._hits[key]
        for key in [k for k, t in self._flagged.items() if now - t > 600]:
            del self._flagged[key]


behavior = Behavior()


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------
def analyze(raw_line: str, container: str, replay: bool = False) -> dict:
    """
    Analyse une ligne. `replay=True` pour des lignes rattrapées après une coupure :
    elles sont analysées par signatures mais pas par comportement (un rattrapage
    en rafale ressemblerait à un flood).
    """
    line = strip_ansi(raw_line)[:MAX_LINE]
    event = {
        "ts": time.time(),
        "container": container,
        "kind": "app",
        "ip": "", "method": "", "path": "", "status": "", "size": "",
        "ua": "", "referer": "",
        "attack_type": None, "severity": None, "detail": "",
        "raw": line,
    }

    http = parse_http(line)
    if http is None:
        if any(s in line for s in config.IGNORE_APP_LOG_SUBSTRINGS):
            return event
        hit = match_rules({"app": normalize(line)})
        if hit:
            event["attack_type"], event["severity"] = hit
            ip = re.search(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])", line)
            if ip:
                event["ip"] = ip.group(1)
            if _whitelisted(event["ip"]):
                event["attack_type"] = event["severity"] = None
        return event

    event.update(http)
    event["kind"] = "web"
    if _whitelisted(http["ip"]):
        return event

    url = normalize(http["path"])
    hit = match_rules({
        "url": url,
        "ua": normalize(http["ua"]) if http["ua"] else "",
        "referer": normalize(http["referer"]) if http["referer"] else "",
    })
    if hit is None and _open_redirect(url):
        hit = ("Tentative de Redirection Ouverte", "low")
    if hit is None and not replay:
        found = behavior.observe(http["ip"], http["method"], http["path"], http["status"])
        if found:
            hit = found[:2]
            event["detail"] = found[2]

    if hit:
        event["attack_type"], event["severity"] = hit
        # Fichier sensible effectivement servi : c'est une fuite, pas une tentative.
        if hit[0] == "Recherche de fichiers sensibles" and http["status"] == "200" and http["size"] not in ("", "0", "-"):
            event["severity"] = "critical"
            event["attack_type"] = "Fichier sensible exposé"
    return event


def is_success(status: str) -> bool:
    return status.isdigit() and 200 <= int(status) < 300


# ---------------------------------------------------------------------------
# Requêtes transmises par le middleware applicatif (corps POST/PUT/PATCH)
# ---------------------------------------------------------------------------
# Champs dont la valeur n'est jamais conservée : seule la présence d'une attaque est notée.
SENSITIVE_FIELD_RE = re.compile(
    r"pass|pwd|secret|token|api[_-]?key|auth|session|csrf|card|cvv|cvc|iban|ccnum|(?<![a-z])(?:otp|pin|pan)(?![a-z])",
    re.IGNORECASE)
MAX_BODY_FIELDS = 500
MAX_BODY_CHARS = 32768


def flatten_body(body) -> list[tuple[str, str]]:
    """Transforme un corps (objet JSON, formulaire, texte) en paires (champ, valeur)."""
    pairs: list[tuple[str, str]] = []

    def walk(value, key: str) -> None:
        if len(pairs) >= MAX_BODY_FIELDS:
            return
        if isinstance(value, dict):
            for k, v in value.items():
                walk(v, f"{key}.{k}" if key else str(k))
        elif isinstance(value, list):
            for i, v in enumerate(value):
                walk(v, f"{key}[{i}]")
        elif value is not None:
            pairs.append((key, str(value)))

    walk(body, "")
    return pairs


def _pick_client_ip(remote: str, xff: str) -> str:
    """Derrière un proxy, l'IP du client est la plus à droite des IP publiques de X-Forwarded-For."""
    if xff and (not remote or is_private_ip(remote)):
        for part in reversed([p.strip() for p in xff.split(",")]):
            if part and not is_private_ip(part):
                return part
    return remote


def analyze_request(req: dict, source: str) -> dict:
    """Analyse une requête complète (URL, en-têtes et corps) envoyée par le middleware."""
    method = str(req.get("method") or "").upper()[:10]
    path = str(req.get("path") or "")[:MAX_LINE]
    status = str(req.get("status") or "")[:3]
    ua = str(req.get("ua") or "")[:1000]
    referer = str(req.get("referer") or "")[:2000]
    ip = _pick_client_ip(str(req.get("ip") or "")[:64], str(req.get("xff") or "")[:500])
    event = {
        "ts": time.time(), "container": source, "kind": "web",
        "ip": ip, "method": method, "path": path, "status": status, "size": "",
        "ua": ua, "referer": referer, "attack_type": None, "severity": None, "detail": "",
        "raw": f"{method} {path} -> {status or '?'}",
    }
    if _whitelisted(ip):
        return event

    # Corps : chaque champ est normalisé séparément, une ligne par champ
    body = req.get("body")
    if isinstance(body, str):
        body = body[:MAX_BODY_CHARS]
    pairs = flatten_body(body)
    lines, spans, offset = [], [], 0
    for key, value in pairs:
        line = f"{key}={normalize(value[:MAX_BODY_CHARS])}" if key else normalize(value)
        lines.append(line)
        spans.append((offset, offset + len(line), key))
        offset += len(line) + 1
    body_text = "\n".join(lines)

    hit = find_rule({
        "url": normalize(path),
        "ua": normalize(ua) if ua else "",
        "referer": normalize(referer) if referer else "",
        "body": body_text,
    })
    if hit is None:
        return event
    name, severity, surface, m = hit
    event["attack_type"], event["severity"] = name, severity
    if surface == "body":
        # L'extrait ne déborde jamais sur les champs voisins (un mot de passe, par exemple)
        start, end, key = next((s for s in spans if s[0] <= m.start() < s[1]), (0, len(body_text), ""))
        if key and SENSITIVE_FIELD_RE.search(key):
            excerpt = f"{key}=[valeur masquée : champ sensible]"
        else:
            excerpt = body_text[max(start, m.start() - 80):min(end, m.end() + 80)]
        event["detail"] = f"Attaque dans le corps de la requête (champ « {key or 'corps'} »)"
        event["raw"] += f"\nCorps : {excerpt}"
    return event
