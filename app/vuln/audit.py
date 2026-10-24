"""
Audit de configuration : conteneurs Docker, serveur hôte (SSH, mises à jour,
pare-feu, démon Docker) et certificats TLS.

Chaque constat explique le risque et la correction, en langage clair.
"""
from __future__ import annotations

import asyncio
import json
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .. import config

DB_PORTS = {
    5432: "PostgreSQL", 3306: "MySQL/MariaDB", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
    11211: "Memcached", 5672: "RabbitMQ", 2375: "API Docker", 2376: "API Docker", 9000: "MinIO/Portainer",
    8086: "InfluxDB", 5984: "CouchDB", 1433: "SQL Server", 15672: "RabbitMQ (admin)",
}
SAFE_PUBLIC_PORTS = {80, 443}
DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH"}
SECRET_ENV_RE = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_KEY|ACCESS_KEY)", re.I)


def _f(target: str, check_id: str, severity: str, title: str, detail: str, fix: str) -> dict:
    return {"target": target, "check_id": check_id, "severity": severity, "title": title, "detail": detail, "fix": fix}


def audit_container(name: str, attrs: dict) -> list[dict]:
    out = []
    cfg = attrs.get("Config") or {}
    host = attrs.get("HostConfig") or {}
    image = cfg.get("Image", "")

    if host.get("Privileged"):
        out.append(_f(name, "privileged", "critical", "Conteneur en mode privilégié",
                      "Un conteneur privilégié a un accès quasi total au noyau : s'il est compromis, le serveur l'est aussi.",
                      "Retirez `privileged: true` et n'ajoutez que les capacités strictement nécessaires (cap_add)."))

    for m in attrs.get("Mounts") or []:
        if m.get("Source") in ("/var/run/docker.sock", "/run/docker.sock"):
            out.append(_f(name, "docker_socket", "high", "Socket Docker monté dans le conteneur",
                          "Accéder au socket Docker revient à être root sur le serveur.",
                          "Si l'accès est nécessaire, passez par un proxy en lecture seule (docker-socket-proxy)."))
        if m.get("Source") == "/" and m.get("RW"):
            out.append(_f(name, "host_root_rw", "critical", "Racine du serveur montée en écriture",
                          "Le conteneur peut modifier n'importe quel fichier du serveur.",
                          "Montez seulement les dossiers utiles, en lecture seule (:ro)."))

    if host.get("PidMode") == "host":
        out.append(_f(name, "pid_host", "high", "Espace de processus de l'hôte partagé",
                      "Le conteneur voit et peut signaler tous les processus du serveur.",
                      "Retirez `pid: host` sauf besoin réel de supervision."))
    if host.get("NetworkMode") == "host":
        out.append(_f(name, "net_host", "medium", "Réseau de l'hôte partagé",
                      "Le conteneur écoute directement sur les interfaces du serveur, sans isolation réseau.",
                      "Utilisez un réseau Docker et publiez seulement les ports nécessaires."))

    caps = set(host.get("CapAdd") or [])
    bad = caps & DANGEROUS_CAPS
    if bad:
        out.append(_f(name, "caps", "high", f"Capacités sensibles ajoutées : {', '.join(sorted(bad))}",
                      "Ces capacités permettent souvent de sortir du conteneur.",
                      "Retirez-les de cap_add si elles ne sont pas indispensables."))

    user = (cfg.get("User") or "").split(":")[0]
    if user in ("", "0", "root"):
        out.append(_f(name, "root_user", "low", "Processus lancé en root",
                      "Une faille dans l'application donnerait les droits root dans le conteneur.",
                      "Ajoutez un utilisateur dédié dans le Dockerfile (`USER app`)."))

    for port_key, bindings in ((host.get("PortBindings") or {}).items()):
        try:
            port = int(port_key.split("/")[0])
        except ValueError:
            continue
        for b in bindings or []:
            ip = b.get("HostIp") or "0.0.0.0"
            if ip not in ("0.0.0.0", "::", ""):
                continue
            hport = b.get("HostPort") or port
            if port in DB_PORTS:
                out.append(_f(name, f"exposed_db_{port}", "critical", f"{DB_PORTS[port]} exposé sur Internet (port {hport})",
                              "Ce service est joignable depuis l'extérieur : il est la cible permanente de robots qui testent les mots de passe et les failles connues.",
                              f"Supprimez la publication du port ou liez-le à 127.0.0.1 (`127.0.0.1:{hport}:{port}`)."))
            elif port not in SAFE_PUBLIC_PORTS and int(hport) not in SAFE_PUBLIC_PORTS:
                out.append(_f(name, f"exposed_{port}", "low", f"Port {hport} ouvert sur toutes les interfaces",
                              "Ce port est accessible depuis Internet si le pare-feu ne le bloque pas. Attention : Docker contourne UFW.",
                              f"Si l'accès doit rester interne, publiez `127.0.0.1:{hport}:{port}` ou passez par le reverse proxy."))

    if not host.get("Memory"):
        out.append(_f(name, "no_mem_limit", "low", "Aucune limite de mémoire",
                      "Une fuite mémoire dans ce conteneur peut saturer tout le serveur.",
                      "Ajoutez `mem_limit` (ou `deploy.resources.limits.memory`)."))
    restart = (host.get("RestartPolicy") or {}).get("Name", "")
    if restart in ("", "no"):
        out.append(_f(name, "no_restart", "low", "Pas de redémarrage automatique",
                      "Après un crash ou un redémarrage du serveur, ce service restera arrêté.",
                      "Ajoutez `restart: unless-stopped`."))
    if not cfg.get("Healthcheck"):
        out.append(_f(name, "no_healthcheck", "info", "Pas de healthcheck",
                      "Docker ne peut pas savoir si l'application répond vraiment.",
                      "Ajoutez un `healthcheck` qui interroge l'application."))
    if image.endswith(":latest") or (":" not in image.split("/")[-1] and "@" not in image):
        out.append(_f(name, "latest_tag", "info", "Image sans version précise (latest)",
                      "La version déployée peut changer à chaque pull, sans contrôle.",
                      "Fixez une version (ex. `postgres:16.4`)."))

    secret_vars = [e.split("=", 1)[0] for e in cfg.get("Env") or [] if "=" in e and SECRET_ENV_RE.search(e.split("=", 1)[0]) and e.split("=", 1)[1]]
    if secret_vars:
        out.append(_f(name, "env_secrets", "info", f"Secrets en variables d'environnement ({len(secret_vars)})",
                      "Visibles par quiconque peut inspecter le conteneur : " + ", ".join(secret_vars[:6]),
                      "Préférez les secrets Docker ou un fichier monté en lecture seule."))
    return out


# ---------------------------------------------------------------------------
# Hôte
# ---------------------------------------------------------------------------
def _read(rel: str) -> Optional[str]:
    try:
        return (config.HOST_ROOT / rel.lstrip("/")).read_text(errors="replace")
    except OSError:
        return None


def _sshd_options() -> tuple[Optional[dict], bool]:
    """Options effectives de sshd, et un booléen « lecture complète »."""
    main = _read("/etc/ssh/sshd_config")
    if main is None:
        return None, False
    complete = True
    # Les fichiers inclus sont lus à la position de leur directive Include
    lines: list[str] = []
    for line in main.splitlines():
        s = line.strip()
        if s.lower().startswith("include") and len(s.split(None, 1)) > 1:
            base = config.HOST_ROOT / s.split(None, 1)[1].lstrip("/")
            if base.parent.is_dir():
                for p in sorted(base.parent.glob(base.name)):
                    try:
                        lines.extend(p.read_text(errors="replace").splitlines())
                    except OSError:
                        complete = False  # ex. 50-cloud-init.conf en 600 sur Ubuntu
            continue
        lines.append(line)
    # sshd retient la PREMIÈRE valeur rencontrée ; les blocs Match ne s'appliquent qu'à certains cas
    opts: dict[str, str] = {}
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.lower().startswith("match "):
            break
        parts = s.split(None, 1)
        if len(parts) == 2:
            opts.setdefault(parts[0].lower(), parts[1].strip().lower())
    return opts, complete


def audit_host() -> list[dict]:
    if not (config.HOST_ROOT / "etc").is_dir():
        return []
    out = []
    target = "serveur"

    ssh, complete = _sshd_options()
    if ssh is not None and not complete:
        out.append(_f(target, "ssh_unreadable", "info", "Configuration SSH partiellement lisible",
                      "Certains fichiers de /etc/ssh/sshd_config.d ne sont lisibles que par root : l'audit SSH ne porte que sur le reste.",
                      "Vérifiez manuellement : `sudo sshd -T | grep -Ei 'permitrootlogin|passwordauthentication'`."))
    if ssh is not None and complete:
        if ssh.get("permitrootlogin", "prohibit-password") == "yes":
            out.append(_f(target, "ssh_root", "high", "Connexion SSH root autorisée par mot de passe",
                          "Les robots testent en permanence le compte root sur SSH.",
                          "Dans /etc/ssh/sshd_config : `PermitRootLogin no` (ou prohibit-password), puis `systemctl reload ssh`."))
        if ssh.get("passwordauthentication", "yes") == "yes":
            out.append(_f(target, "ssh_password", "medium", "Authentification SSH par mot de passe activée",
                          "Un mot de passe peut être deviné par force brute ; une clé SSH, non.",
                          "Installez votre clé (`ssh-copy-id`), puis `PasswordAuthentication no`."))
        if not (config.HOST_ROOT / "etc/fail2ban").is_dir() and not (config.HOST_ROOT / "etc/crowdsec").is_dir():
            out.append(_f(target, "no_fail2ban", "low", "Aucune protection anti-bruteforce (Fail2Ban / CrowdSec)",
                          "Les IP qui échouent en boucle à se connecter ne sont jamais bannies.",
                          "Installez Fail2Ban (`apt install fail2ban`) ou CrowdSec."))

    if (config.HOST_ROOT / "var/run/reboot-required").exists() or (config.HOST_ROOT / "run/reboot-required").exists():
        out.append(_f(target, "reboot_required", "medium", "Redémarrage requis",
                      "Des mises à jour (souvent du noyau) ne sont pas actives tant que le serveur n'a pas redémarré.",
                      "Planifiez un redémarrage (`sudo reboot`)."))

    if (config.HOST_ROOT / "etc/apt").is_dir():
        auto = _read("/etc/apt/apt.conf.d/20auto-upgrades") or ""
        if 'Unattended-Upgrade "1"' not in auto:
            out.append(_f(target, "no_auto_updates", "low", "Mises à jour de sécurité automatiques désactivées",
                          "Les correctifs de sécurité du système ne s'installent pas tout seuls.",
                          "`sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades`."))

    ufw = _read("/etc/ufw/ufw.conf")
    if ufw is not None and "ENABLED=yes" not in ufw:
        out.append(_f(target, "ufw_disabled", "medium", "Pare-feu UFW installé mais désactivé",
                      "Tous les ports en écoute sur le serveur sont accessibles.",
                      "`sudo ufw allow OpenSSH && sudo ufw allow 80,443/tcp && sudo ufw enable`."))

    daemon = _read("/etc/docker/daemon.json")
    if daemon:
        try:
            hosts = json.loads(daemon).get("hosts") or []
        except ValueError:
            hosts = []
        for h in hosts:
            if h.startswith("tcp://") and not h.startswith(("tcp://127.", "tcp://localhost")):
                tls = '"tlsverify": true' in daemon.replace(" ", "").replace('":true', '": true')
                if not tls:
                    out.append(_f(target, "docker_tcp", "critical", f"API Docker exposée sans TLS ({h})",
                                  "N'importe qui pouvant joindre ce port contrôle entièrement le serveur.",
                                  "Retirez l'écoute TCP de /etc/docker/daemon.json ou activez tlsverify."))
    return out


# ---------------------------------------------------------------------------
# Certificats TLS
# ---------------------------------------------------------------------------
def _check_cert(host: str, port: int) -> dict:
    ctx = ssl.create_default_context()
    result = {"domain": host, "port": port, "ok": False, "error": "", "days_left": None,
              "expires": None, "issuer": "", "checked_ts": time.time()}
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        result.update(
            ok=True, expires=expires.timestamp(),
            days_left=int((expires - datetime.now(timezone.utc)).total_seconds() // 86400),
            issuer=issuer.get("organizationName") or issuer.get("commonName", ""),
        )
    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Certificat invalide : {e.verify_message}"
    except (OSError, ssl.SSLError, ValueError, KeyError) as e:
        result["error"] = f"Connexion impossible : {type(e).__name__}"
    return result


def parse_domains(raw: str) -> list[tuple[str, int]]:
    out = []
    for item in re.split(r"[,\s]+", raw or ""):
        item = item.strip().removeprefix("https://").split("/")[0]
        if not item:
            continue
        host, _, port = item.partition(":")
        out.append((host.lower(), int(port) if port.isdigit() else 443))
    return out


async def check_tls(domains: list[tuple[str, int]]) -> list[dict]:
    return list(await asyncio.gather(*(asyncio.to_thread(_check_cert, h, p) for h, p in domains)))
