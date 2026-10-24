"""
Diagnostic : mémoire consommée par chaque étape du scan de sécurité.

Lance un scan complet dans un conteneur SÉPARÉ et jetable (base temporaire),
sans toucher à l'instance LogSonar en service :

  docker run --rm --network logsonar_logsonar-internal \
    -e LOGSONAR_DOCKER_URL=tcp://socket-proxy:2375 -e LOGSONAR_DATA_DIR=/tmp/diag \
    -v /:/hostfs:ro -v "$PWD/scripts:/diag:ro" --memory 2g \
    logsonar:2 python /diag/diag_scan_memoire.py
"""
import asyncio
import resource
import sys
import time

sys.path.insert(0, "/app")

from app import db, settings_store as S  # noqa: E402
from app.collectors import docker_watch as D  # noqa: E402
from app.vuln import inventory, scanner  # noqa: E402

T0 = time.time()


def rss() -> int:
    with open("/proc/self/status") as f:
        return int(f.read().split("VmRSS:")[1].split()[0]) // 1024


def peak() -> int:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024


def log(msg: str) -> None:
    print(f"[{time.time() - T0:6.0f}s] RSS {rss():5d} Mo | pic {peak():5d} Mo | {msg}", flush=True)


# Étapes du scan
_update = scanner.ScanState.update
scanner.ScanState.update = lambda self, stage, progress: (log(f"{progress:3d} % {stage}"), _update(self, stage, progress))[1]

# Inventaire : mémoire avant/après chaque conteneur
_inv = inventory.container_inventory


def inv_mesure(cid, attrs):
    before = peak()
    t = time.time()
    out = _inv(cid, attrs)
    name = (attrs.get("Name") or "?").lstrip("/")
    log(f"    inventaire {name}: {len(out['packages'])} paquets, {time.time() - t:.0f}s, pic +{peak() - before} Mo")
    return out


inventory.container_inventory = inv_mesure


async def main() -> None:
    await db.init_db()
    await S.load()
    log("début")
    await scanner.run_scan()
    row = await db.fetchone("SELECT status, error FROM vuln_scans ORDER BY id DESC LIMIT 1")
    log(f"fin : {row['status']} {row['error']}")
    await db.close_db()


asyncio.run(main())
