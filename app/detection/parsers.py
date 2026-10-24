"""
Lecture des lignes de log HTTP, quel que soit le serveur.

Formats reconnus :
  - Nginx / Apache (common et combined), y compris derrière X-Forwarded-For
  - Uvicorn / Gunicorn / Django runserver / Werkzeug
  - Logs JSON : Traefik, Caddy, et JSON générique (ip, method, path, status...)
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Optional

_IP = r"(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]*:[0-9a-fA-F:]+)"

_REQUEST_RE = re.compile(
    r'"(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE|PROPFIND|[A-Z]{3,10}) '
    r'(?P<path>(?:[^"\\]|\\.)+?) HTTP/[\d.]+"\s+(?P<status>\d{3})'
    r'(?:\s+(?P<size>\d+|-))?'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)
_LEADING_IP_RE = re.compile(r'^\s*(?:\S+\s+)?\[?(?P<ip>' + _IP + r')\]?(?::\d+)?\s')
_ANY_IP_RE = re.compile(r'(?<![\d.:])(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(?![\d.])')
_TRAILING_XFF_RE = re.compile(r'"(?P<xff>' + _IP + r'(?:\s*,\s*' + _IP + r')*)"\s*$')


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_private_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def _pick(d: dict, *keys: str) -> str:
    for key in keys:
        cur = d
        ok = True
        for part in key.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                ok = False
                break
        if ok and cur not in (None, ""):
            if isinstance(cur, list):
                cur = cur[0] if cur else ""
            return str(cur)
    return ""


def _parse_json(line: str) -> Optional[dict]:
    try:
        data = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    method = _pick(data, "RequestMethod", "request.method", "method", "http_method", "request_method")
    path = _pick(data, "RequestPath", "request.uri", "uri", "path", "url", "request_uri")
    status = _pick(data, "DownstreamStatus", "OriginStatus", "status", "status_code", "response.status")
    if not (method and path and status.isdigit()):
        return None
    ip = _pick(data, "ClientHost", "request.client_ip", "request.remote_ip", "client_ip", "remote_ip",
               "remote_addr", "ip", "x_forwarded_for")
    ip = ip.split(",")[0].strip()
    if ip.count(":") == 1:  # "1.2.3.4:5678"
        ip = ip.split(":")[0]
    return {
        "ip": ip if _valid_ip(ip) else "",
        "method": method.upper(),
        "path": path,
        "status": status,
        "size": _pick(data, "DownstreamContentSize", "size", "bytes_sent", "body_bytes_sent"),
        "referer": _pick(data, "request_Referer", "request.headers.Referer", "referer", "http_referer"),
        "ua": _pick(data, "request_User-Agent", "request.headers.User-Agent", "user_agent", "http_user_agent", "ua"),
    }


def parse_http(line: str) -> Optional[dict]:
    """Retourne les champs d'une requête HTTP, ou None si la ligne n'en est pas une."""
    stripped = line.strip()
    if stripped.startswith("{"):
        return _parse_json(stripped)

    m = _REQUEST_RE.search(stripped)
    if not m:
        return None

    prefix = stripped[: m.start()]
    ip = ""
    lead = _LEADING_IP_RE.match(prefix)
    if lead and _valid_ip(lead.group("ip")):
        ip = lead.group("ip")
    else:
        anyip = _ANY_IP_RE.search(prefix)
        if anyip and _valid_ip(anyip.group("ip")):
            ip = anyip.group("ip")

    # Format Nginx courant avec "$http_x_forwarded_for" en fin de ligne :
    # si l'IP de connexion est privée (proxy), on prend l'IP client d'origine.
    if ip and is_private_ip(ip):
        xff = _TRAILING_XFF_RE.search(stripped[m.end():])
        if xff:
            first = xff.group("xff").split(",")[0].strip()
            if _valid_ip(first):
                ip = first

    return {
        "ip": ip,
        "method": m.group("method"),
        "path": m.group("path"),
        "status": m.group("status"),
        "size": m.group("size") or "",
        "referer": m.group("referer") or "",
        "ua": m.group("ua") or "",
    }
