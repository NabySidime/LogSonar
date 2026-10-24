"""
Paramètres modifiables depuis l'interface, avec valeurs par défaut typées.

Les secrets (clés API, tokens, URLs de webhook) sont chiffrés au repos avec
Fernet et ne sont JAMAIS renvoyés au navigateur : l'API indique seulement
s'ils sont configurés.
"""
from __future__ import annotations

import json
import os
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from . import config, db

# clé -> (valeur par défaut, type)
DEFAULTS: dict[str, tuple[Any, type]] = {
    # Notifications
    "notify_min_severity": ("high", str),         # info | warning | high | critical
    "notify_resolved": (False, bool),
    "email_enabled": (False, bool),
    "email_to": ("", str),
    "brevo_sender": ("", str),
    "brevo_api_key": ("", str),                   # secret
    "discord_webhook": ("", str),                 # secret
    "slack_webhook": ("", str),                   # secret
    "telegram_bot_token": ("", str),              # secret
    "telegram_chat_id": ("", str),
    "webhook_url": ("", str),                     # secret (JSON générique : ntfy, n8n, ...)
    # Seuils serveur
    "cpu_warn": (85, int), "cpu_crit": (95, int),
    "mem_warn": (85, int), "mem_crit": (95, int),
    "disk_warn": (80, int), "disk_crit": (90, int),
    "metric_duration_min": (5, int),              # durée avant de lever une alerte CPU/RAM
    # Trafic
    "traffic_rpm_threshold": (0, int),            # 0 = automatique (comparé à la normale)
    "traffic_spike_factor": (4, int),
    "traffic_min_rpm": (120, int),
    "error_rate_threshold": (10, int),            # % de réponses 5xx
    # Détection
    "attack_campaign_threshold": (30, int),       # attaques d'une même IP en 10 min
    # TLS
    "tls_domains": ("", str),                     # "exemple.com, api.exemple.com:8443"
    "tls_warn_days": (14, int),
    # Rapport quotidien
    "report_notify": (True, bool),                # envoie le résumé du rapport sur les canaux configurés
    # Analyse du corps des requêtes (middleware applicatif)
    "ingest_token": ("", str),                    # secret, généré par LogSonar
    # Conteneurs mis en sourdine (liste JSON)
    "muted_containers": ([], list),
    # Problèmes de configuration acceptés en connaissance de cause ("cible|check_id")
    "accepted_config": ([], list),
}

SECRET_KEYS = {"brevo_api_key", "discord_webhook", "slack_webhook", "telegram_bot_token", "webhook_url", "ingest_token"}

_cache: dict[str, Any] = {}
_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        key_path = config.DATA_DIR / ".secret_key"
        if key_path.exists():
            key = key_path.read_bytes().strip()
        else:
            key = Fernet.generate_key()
            key_path.write_bytes(key)
            try:
                os.chmod(key_path, 0o600)
            except OSError:
                pass
        _fernet = Fernet(key)
    return _fernet


def encrypt(value: str) -> str:
    return _get_fernet().encrypt(value.encode()).decode() if value else ""


def decrypt(value: str) -> str:
    if not value:
        return ""
    try:
        return _get_fernet().decrypt(value.encode()).decode()
    except InvalidToken:
        return ""


def _coerce(key: str, raw: Any) -> Any:
    default, typ = DEFAULTS[key]
    try:
        if typ is bool:
            if isinstance(raw, str):
                return raw.lower() in ("1", "true", "yes", "on")
            return bool(raw)
        if typ is int:
            return int(raw)
        if typ is list:
            return list(raw) if isinstance(raw, (list, tuple)) else json.loads(raw)
        return str(raw)
    except (ValueError, TypeError, json.JSONDecodeError):
        return default


async def load() -> None:
    _cache.clear()
    for row in await db.fetchall("SELECT key, value FROM settings"):
        key = row["key"]
        if key not in DEFAULTS:
            continue
        raw = decrypt(row["value"]) if key in SECRET_KEYS else row["value"]
        _cache[key] = _coerce(key, raw)


def get(key: str) -> Any:
    if key in _cache:
        return _cache[key]
    return DEFAULTS[key][0]


async def set_many(values: dict[str, Any]) -> None:
    for key, value in values.items():
        if key not in DEFAULTS:
            continue
        value = _coerce(key, value)
        if key in SECRET_KEYS:
            stored = encrypt(value)
        elif isinstance(value, list):
            stored = json.dumps(value)
        else:
            stored = str(value)
        await db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, stored))
        _cache[key] = value


def public_view() -> dict[str, Any]:
    """Paramètres pour l'interface : les secrets sont remplacés par un booléen."""
    out: dict[str, Any] = {}
    for key in DEFAULTS:
        if key in SECRET_KEYS:
            out[key + "_set"] = bool(get(key))
        else:
            out[key] = get(key)
    return out
