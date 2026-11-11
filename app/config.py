# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Naby Sidime. LogSonar : https://github.com/NabySidime/LogSonar
"""
Configuration lue depuis les variables d'environnement.

Tout ce qui dépend du déploiement passe par ici : aucune valeur propre à un
projet n'est écrite en dur dans le code. Voir `.env.example`.
"""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path


def _csv(name: str, default: str = "") -> list[str]:
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


def _bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _networks(values: list[str]) -> list[ipaddress._BaseNetwork]:
    nets = []
    for v in values:
        try:
            nets.append(ipaddress.ip_network(v, strict=False))
        except ValueError:
            print(f"LogSonar: valeur réseau ignorée (invalide) : {v}")
    return nets


BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = Path(os.environ.get("LOGSONAR_DATA_DIR", BASE_DIR / "data"))
REPORT_DIR = DATA_DIR / "reports"
DB_PATH = DATA_DIR / "logsonar.db"

# --- Serveur hôte -----------------------------------------------------------
# Le /proc et la racine de l'hôte sont montés en lecture seule dans le conteneur
# (voir docker-compose.yml). Sans ces montages, LogSonar mesure son propre conteneur.
HOST_PROC = Path(os.environ.get("LOGSONAR_HOST_PROC", "/host/proc"))
HOST_ROOT = Path(os.environ.get("LOGSONAR_HOST_ROOT", "/hostfs"))

# --- Docker -------------------------------------------------------------------
DOCKER_URL = os.environ.get("LOGSONAR_DOCKER_URL", os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock"))

# --- Sécurité -----------------------------------------------------------------
JWT_SECRET_ENV = os.environ.get("LOGSONAR_JWT_SECRET", "")
SESSION_HOURS = _int("LOGSONAR_SESSION_HOURS", 12)
# Nombre maximum de comptes : un outil d'administration doit rester à quelques personnes de confiance.
MAX_USERS = 3
# "auto" : cookie Secure si la requête arrive en HTTPS (directement ou via un proxy de confiance)
SECURE_COOKIES = os.environ.get("LOGSONAR_SECURE_COOKIES", "auto").lower()
# X-Forwarded-For n'est lu QUE si la requête vient d'un de ces réseaux (votre reverse proxy).
TRUSTED_PROXIES = _networks(_csv("LOGSONAR_TRUSTED_PROXIES"))

# --- Détection ----------------------------------------------------------------
WHITELIST = _networks(_csv("LOGSONAR_WHITELIST_IPS"))
ALLOWED_REDIRECT_DOMAINS = [d.lower() for d in _csv("LOGSONAR_ALLOWED_REDIRECT_DOMAINS")]
# Lignes NON-web contenant ces sous-chaînes ignorées (bruit de BDD, etc.).
# Jamais appliqué aux requêtes HTTP : leur contenu est contrôlé par l'attaquant.
IGNORE_APP_LOG_SUBSTRINGS = _csv("LOGSONAR_IGNORE_LOG_SUBSTRINGS")

# --- Rétention ----------------------------------------------------------------
RETENTION_EVENTS_DAYS = _int("LOGSONAR_RETENTION_DAYS", 90)
RETENTION_METRICS_DAYS = _int("LOGSONAR_METRICS_RETENTION_DAYS", 14)

# --- Scan de vulnérabilités ----------------------------------------------------
OSV_API = os.environ.get("LOGSONAR_OSV_API", "https://api.osv.dev")
VULN_SCAN_HOUR = _int("LOGSONAR_VULN_SCAN_HOUR", 3)  # scan automatique quotidien, heure locale
SCAN_HOST_PACKAGES = _bool("LOGSONAR_SCAN_HOST", True)

# Nom affiché dans l'interface et les emails
INSTANCE_NAME = os.environ.get("LOGSONAR_INSTANCE_NAME", "LogSonar")


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
