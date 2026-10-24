"""
Inventaire des logiciels installés, dans chaque conteneur et sur l'hôte.

Sources lues (sans rien exécuter dans les conteneurs) :
  - Debian / Ubuntu : /var/lib/dpkg/status (+ status.d pour les images distroless)
  - Alpine          : /lib/apk/db/installed
  - Python          : dossiers *.dist-info / *.egg-info des site-packages
  - Node.js         : package-lock.json du dossier de travail
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable, Optional

from .. import config
from ..collectors import docker_watch as D

PY_VERSIONS = [f"3.{m}" for m in range(14, 6, -1)]
KERNEL_SOURCES = {"linux", "linux-signed-amd64", "linux-signed-arm64", "linux-lts"}


def _parse_os_release(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"')
    return out


def os_ecosystem(osr: dict) -> Optional[str]:
    """Nom d'écosystème OSV correspondant à la distribution."""
    distro = osr.get("ID", "").lower()
    version = osr.get("VERSION_ID", "")
    if distro == "debian" and version:
        return f"Debian:{version.split('.')[0]}"
    if distro == "ubuntu" and version:
        lts = "LTS" in osr.get("VERSION", "")
        return f"Ubuntu:{version}:LTS" if lts else f"Ubuntu:{version}"
    if distro == "alpine" and version:
        major_minor = ".".join(version.split(".")[:2])
        return f"Alpine:v{major_minor}"
    return None


def parse_dpkg_status(text: str) -> list[dict]:
    pkgs = []
    for block in text.split("\n\n"):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if line and not line[0].isspace() and ":" in line:
                k, v = line.split(":", 1)
                fields[k] = v.strip()
        if not fields.get("Package") or "installed" not in fields.get("Status", "install ok installed"):
            continue
        version = fields.get("Version", "")
        source = fields.get("Source", "") or fields["Package"]
        src_version = version
        m = re.match(r"(\S+)\s+\((.+)\)", source)
        if m:
            source, src_version = m.group(1), m.group(2)
        pkgs.append({"name": source, "version": src_version, "binary": fields["Package"]})
    return pkgs


def parse_apk_installed(text: str) -> list[dict]:
    pkgs = []
    for block in text.split("\n\n"):
        fields = {}
        for line in block.splitlines():
            if len(line) > 2 and line[1] == ":":
                fields[line[0]] = line[2:]
        if "P" in fields and "V" in fields:
            pkgs.append({"name": fields.get("o") or fields["P"], "version": fields["V"], "binary": fields["P"]})
    return pkgs


_DIST_RE = re.compile(r"^(?P<name>.+?)-(?P<version>\d[^-]*?)(?:-py[\d.]+)?\.(?:dist-info|egg-info)$")


def parse_python_dirs(names: list[str]) -> list[dict]:
    pkgs = []
    for n in names:
        m = _DIST_RE.match(n)
        if m:
            name = re.sub(r"[-_.]+", "-", m.group("name")).lower()
            pkgs.append({"name": name, "version": m.group("version")})
    return pkgs


def parse_package_lock(text: str) -> list[dict]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    pkgs = []
    if isinstance(data.get("packages"), dict):  # lockfile v2 / v3
        for path, info in data["packages"].items():
            if not path or not isinstance(info, dict) or "version" not in info:
                continue
            name = info.get("name") or path.split("node_modules/")[-1]
            pkgs.append({"name": name, "version": info["version"]})
    elif isinstance(data.get("dependencies"), dict):  # lockfile v1
        def walk(deps: dict):
            for name, info in deps.items():
                if isinstance(info, dict) and "version" in info:
                    pkgs.append({"name": name, "version": info["version"]})
                    walk(info.get("dependencies") or {})
        walk(data["dependencies"])
    return pkgs


def _dedupe(pkgs: list[dict]) -> list[dict]:
    seen, out = set(), []
    for p in pkgs:
        key = (p["ecosystem"], p["name"], p["version"])
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


# ---------------------------------------------------------------------------
# Lecteurs génériques : conteneur (API d'archive) ou hôte (fichiers montés)
# ---------------------------------------------------------------------------
def _collect(read_text: Callable[[str], Optional[str]], list_dir: Callable[[str], Optional[list[str]]],
             workdirs: list[str], env: dict, host: bool = False) -> dict:
    result = {"os": {}, "packages": [], "sources": []}
    osr_text = read_text("/etc/os-release") or read_text("/usr/lib/os-release") or ""
    osr = _parse_os_release(osr_text)
    result["os"] = {"id": osr.get("ID", ""), "name": osr.get("PRETTY_NAME", ""), "version": osr.get("VERSION_ID", "")}
    eco = os_ecosystem(osr)

    if eco:
        if eco.startswith(("Debian", "Ubuntu")):
            status = read_text("/var/lib/dpkg/status")
            os_pkgs = parse_dpkg_status(status) if status else []
            if not os_pkgs:  # images distroless
                for fname in list_dir("/var/lib/dpkg/status.d") or []:
                    content = read_text(f"/var/lib/dpkg/status.d/{fname}")
                    if content:
                        os_pkgs.extend(parse_dpkg_status(content))
        else:
            installed = read_text("/lib/apk/db/installed")
            os_pkgs = parse_apk_installed(installed) if installed else []
        for p in os_pkgs:
            # Les sources du noyau (linux-libc-dev...) n'ont pas de sens dans une image :
            # un conteneur tourne sur le noyau de l'hôte, qui est scanné à part.
            if p["name"] in KERNEL_SOURCES and not host:
                continue
            result["packages"].append({"ecosystem": eco, "name": p["name"], "version": p["version"]})
        if os_pkgs:
            result["sources"].append(f"{len(os_pkgs)} paquets système ({eco})")

    # Python : site-packages des emplacements habituels (+ virtualenv déclaré)
    py_dirs = []
    venv = env.get("VIRTUAL_ENV")
    roots = ["/usr/local/lib", "/usr/lib", "/opt/venv/lib", "/venv/lib", "/root/.local/lib"]
    if venv:
        roots.insert(0, f"{venv}/lib")
    for wd in workdirs:
        roots.append(f"{wd.rstrip('/')}/.venv/lib")
        roots.append(f"{wd.rstrip('/')}/venv/lib")
    for root in roots:
        for v in PY_VERSIONS:
            py_dirs.append(f"{root}/python{v}/site-packages")
    # /usr/lib/python3/dist-packages est géré par dpkg (déjà couvert, avec les correctifs Debian)

    py_count = 0
    seen_dirs = set()
    for d in py_dirs:
        if d in seen_dirs:
            continue
        seen_dirs.add(d)
        names = list_dir(d)
        if not names:
            continue
        found = parse_python_dirs(names)
        for p in found:
            result["packages"].append({"ecosystem": "PyPI", "name": p["name"], "version": p["version"]})
        py_count += len(found)
    if py_count:
        result["sources"].append(f"{py_count} paquets Python")

    # Node.js : lockfile du projet
    for wd in dict.fromkeys(workdirs + ["/app", "/usr/src/app", "/srv", "/var/www", "/home/node/app"]):
        text = read_text(f"{wd.rstrip('/')}/package-lock.json")
        if text:
            found = parse_package_lock(text)
            for p in found:
                result["packages"].append({"ecosystem": "npm", "name": p["name"], "version": p["version"]})
            if found:
                result["sources"].append(f"{len(found)} paquets npm ({wd})")
            break

    result["packages"] = _dedupe(result["packages"])
    return result


def container_inventory(cid: str, attrs: dict) -> dict:
    cfg = attrs.get("Config") or {}
    env = dict(e.split("=", 1) for e in (cfg.get("Env") or []) if "=" in e)
    workdirs = [cfg["WorkingDir"]] if cfg.get("WorkingDir") and cfg["WorkingDir"] != "/" else []
    return _collect(
        lambda p: D.read_text(cid, p),
        lambda p: D.list_names(cid, p),
        workdirs, env,
    )


def host_inventory() -> Optional[dict]:
    root = config.HOST_ROOT
    if not (root / "etc").is_dir():
        return None

    def read_text(p: str) -> Optional[str]:
        try:
            return (root / p.lstrip("/")).read_text(errors="replace")
        except OSError:
            return None

    def list_dir(p: str) -> Optional[list[str]]:
        path = root / p.lstrip("/")
        try:
            return sorted(x.name for x in Path(path).iterdir())
        except OSError:
            return None

    inv = _collect(read_text, list_dir, [], {}, host=True)
    # Sur l'hôte, seuls les paquets système nous intéressent (Python système = paquets dpkg)
    inv["packages"] = [p for p in inv["packages"] if p["ecosystem"] not in ("PyPI", "npm")]
    inv["sources"] = [s for s in inv["sources"] if "Python" not in s and "npm" not in s]
    return inv
