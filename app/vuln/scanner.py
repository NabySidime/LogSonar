"""
Orchestration d'un scan de sécurité complet :
inventaire -> recherche des vulnérabilités (OSV) -> audit de configuration -> stockage.
"""
from __future__ import annotations

import asyncio
import json
import time
from collections import Counter, defaultdict

from .. import config, db
from .. import settings_store as S
from ..alerts import alerts
from ..collectors import docker_watch as D
from ..hub import hub
from . import audit, inventory
from .osv import SEV_ORDER, OSVClient, fixed_version, only_packages, severity_of, slim_vuln


class ScanState:
    def __init__(self) -> None:
        self.running = False
        self.stage = ""
        self.progress = 0
        self.scan_id: int | None = None
        self.started: float | None = None

    def as_dict(self) -> dict:
        return {"running": self.running, "stage": self.stage, "progress": self.progress,
                "scan_id": self.scan_id, "started": self.started}

    def update(self, stage: str, progress: int) -> None:
        self.stage, self.progress = stage, progress
        hub.publish("scan", self.as_dict())


scan_state = ScanState()
_scan_lock = asyncio.Lock()


async def start_scan() -> bool:
    if scan_state.running:
        return False
    asyncio.create_task(run_scan())
    return True


async def run_scan() -> None:
    if _scan_lock.locked():
        return
    async with _scan_lock:
        scan_state.running = True
        scan_state.started = time.time()
        scan_id = await db.execute("INSERT INTO vuln_scans (started_ts, status) VALUES (?, 'running')", (time.time(),))
        scan_state.scan_id = scan_id
        osv = OSVClient()
        try:
            summary = await _scan(scan_id, osv)
            await db.execute(
                "UPDATE vuln_scans SET finished_ts = ?, status = 'done', summary = ? WHERE id = ?",
                (time.time(), json.dumps(summary), scan_id),
            )
            await _raise_alerts(summary)
            print(f"LogSonar: scan de sécurité terminé — {summary['vulns_total']} vulnérabilité(s), "
                  f"{summary['config_total']} problème(s) de configuration.")
        except Exception as e:
            print(f"LogSonar: échec du scan de sécurité : {type(e).__name__}: {e}")
            await db.execute(
                "UPDATE vuln_scans SET finished_ts = ?, status = 'error', error = ? WHERE id = ?",
                (time.time(), f"{type(e).__name__}: {e}"[:500], scan_id),
            )
        finally:
            await osv.close()
            scan_state.running = False
            scan_state.update("", 100)


async def _scan(scan_id: int, osv: OSVClient) -> dict:
    t0 = time.time()
    targets: list[dict] = []        # {name, kind, image, packages, os, sources}
    config_findings: list[dict] = []
    errors: list[str] = []

    # 1. Inventaire des conteneurs (une seule lecture par image)
    scan_state.update("Inventaire des conteneurs", 5)
    try:
        containers = await D.state.run(D.list_containers, False)
    except Exception as e:
        containers = []
        errors.append(f"Docker inaccessible : {type(e).__name__}")

    by_image: dict[str, dict] = {}
    for i, c in enumerate(containers):
        scan_state.update(f"Inventaire : {c['name']}", 5 + int(35 * i / max(len(containers), 1)))
        try:
            attrs = await D.state.run(D.inspect, c["id"])
        except Exception:
            continue
        config_findings.extend(audit.audit_container(c["name"], attrs))
        image_id = attrs.get("Image", c["image"])
        if image_id not in by_image:
            try:
                by_image[image_id] = await D.state.run(inventory.container_inventory, c["id"], attrs)
            except Exception as e:
                errors.append(f"{c['name']} : inventaire impossible ({type(e).__name__})")
                by_image[image_id] = {"os": {}, "packages": [], "sources": []}
        inv = by_image[image_id]
        targets.append({"name": c["name"], "kind": "container", "image": c["image"], **inv})

    # 2. Serveur hôte
    if config.SCAN_HOST_PACKAGES:
        scan_state.update("Inventaire du serveur", 42)
        host_inv = await asyncio.to_thread(inventory.host_inventory)
        if host_inv:
            targets.append({"name": "serveur", "kind": "host", "image": "", **host_inv})
        config_findings.extend(await asyncio.to_thread(audit.audit_host))

    # 3. Vulnérabilités connues (OSV)
    unique = {}
    for t in targets:
        for p in t["packages"]:
            unique[(p["ecosystem"], p["name"], p["version"])] = p
    pkgs = list(unique.values())
    scan_state.update(f"Recherche de vulnérabilités ({len(pkgs)} paquets)", 50)
    ids_per_pkg = await osv.query_batch(pkgs) if pkgs else []
    vulns_by_key = {
        (p["ecosystem"], p["name"], p["version"]): ids for p, ids in zip(pkgs, ids_per_pkg)
    }

    all_ids = sorted({vid for ids in ids_per_pkg for vid in ids})
    # Paquets concernés par chaque faille : on ne garde en mémoire que leurs entrées
    names_by_vid: dict[str, set[str]] = defaultdict(set)
    for p, ids in zip(pkgs, ids_per_pkg):
        for vid in ids:
            names_by_vid[vid].add(p["name"].lower())
    details: dict[str, dict] = {}
    done = 0

    async def fetch(vid: str) -> None:
        nonlocal done
        details[vid] = only_packages(await osv.get_vuln(vid), names_by_vid[vid])
        done += 1
        if done % 25 == 0:
            scan_state.update(f"Détails des vulnérabilités ({done}/{len(all_ids)})", 55 + int(40 * done / max(len(all_ids), 1)))

    await asyncio.gather(*(fetch(v) for v in all_ids))

    # 4. Constats par cible
    scan_state.update("Enregistrement des résultats", 96)
    rows = []
    sev_total: Counter = Counter()
    per_target: dict[str, Counter] = defaultdict(Counter)
    fix_sev: Counter = Counter()
    fixable = 0
    for t in targets:
        for p in t["packages"]:
            # Une même faille est souvent publiée sous plusieurs identifiants
            # (GHSA, PYSEC, CVE) : on la compte une seule fois, en préférant l'avis GHSA.
            ids = sorted(vulns_by_key.get((p["ecosystem"], p["name"], p["version"]), []),
                         key=lambda x: (not x.startswith("GHSA"), x))
            seen_ids: set[str] = set()
            for vid in ids:
                v = details.get(vid) or {}
                aliases = [a for a in (v.get("aliases") or []) + (v.get("upstream") or []) if a != vid]
                if v.get("withdrawn") or vid in seen_ids or any(a in seen_ids for a in aliases):
                    continue
                seen_ids.add(vid)
                seen_ids.update(aliases)
                sev, score = severity_of(v, p["name"], p["ecosystem"])
                fix = fixed_version(v, p["name"], p["version"], p["ecosystem"])
                summary = v.get("summary") or (v.get("details") or "").split("\n")[0][:300]
                rows.append((scan_id, t["name"], t["kind"], t["image"], p["ecosystem"], p["name"], p["version"],
                             vid, ",".join(dict.fromkeys(aliases)), sev, score, summary, fix))
                sev_total[sev] += 1
                per_target[t["name"]][sev] += 1
                if fix:
                    fixable += 1
                    fix_sev[sev] += 1
    await db.executemany(
        "INSERT INTO vuln_findings (scan_id, target, target_kind, image, ecosystem, package, version, vuln_id,"
        " aliases, severity, score, summary, fixed_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows,
    )
    await db.executemany(
        "INSERT INTO config_findings (scan_id, target, check_id, severity, title, detail, fix) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(scan_id, f["target"], f["check_id"], f["severity"], f["title"], f["detail"], f["fix"]) for f in config_findings],
    )

    cfg_sev = Counter(f["severity"] for f in config_findings)
    return {
        "duration": round(time.time() - t0, 1),
        "targets": [
            {"name": t["name"], "kind": t["kind"], "image": t["image"], "os": t["os"].get("name", ""),
             "packages": len(t["packages"]), "sources": t["sources"], "vulns": dict(per_target.get(t["name"], {}))}
            for t in targets
        ],
        "packages_total": len(pkgs),
        "vulns_total": sum(sev_total.values()),
        "vulns_by_severity": {k: sev_total.get(k, 0) for k in SEV_ORDER},
        "fixable": fixable,
        "fixable_by_severity": {k: fix_sev.get(k, 0) for k in SEV_ORDER},
        "config_total": len(config_findings),
        "config_by_severity": dict(cfg_sev),
        "errors": errors,
    }


async def _raise_alerts(summary: dict) -> None:
    crit = summary["vulns_by_severity"].get("critical", 0)
    if crit:
        await alerts.raise_alert(
            "vuln:critical", "vulnerability", "high",
            f"{crit} vulnérabilité(s) critique(s) détectée(s)",
            "Le dernier scan a trouvé des paquets avec des failles critiques connues. "
            "Ouvrez l'onglet Vulnérabilités pour voir les versions corrigées.",
            "Scan de sécurité",
        )
    else:
        await alerts.resolve("vuln:critical")

    await sync_config_alerts()


# ---------------------------------------------------------------------------
# Problèmes de configuration acceptés (ex. conteneur privilégié voulu par mailcow)
# ---------------------------------------------------------------------------
def config_key(target: str, check_id: str) -> str:
    return f"{target}|{check_id}"


def accepted_config() -> set[str]:
    return set(S.get("accepted_config"))


async def config_counts(scan_id: int) -> dict:
    """Constats par gravité, hors risques acceptés (pour le score)."""
    accepted = accepted_config()
    out: Counter = Counter()
    for r in await db.fetchall("SELECT target, check_id, severity FROM config_findings WHERE scan_id = ?", (scan_id,)):
        if config_key(r["target"], r["check_id"]) not in accepted:
            out[r["severity"]] += 1
    return dict(out)


async def sync_config_alerts() -> None:
    """Une alerte par problème critique du dernier scan, sauf ceux acceptés."""
    rows = await db.fetchall(
        "SELECT target, check_id, title, detail FROM config_findings WHERE scan_id = (SELECT MAX(id) FROM vuln_scans WHERE status = 'done') AND severity = 'critical'"
    )
    accepted = accepted_config()
    keep = set()
    for r in rows:
        if config_key(r["target"], r["check_id"]) in accepted:
            continue
        fp = f"config:{r['target']}:{r['check_id']}"
        keep.add(fp)
        await alerts.raise_alert(fp, "config", "critical", f"{r['title']} — {r['target']}", r["detail"], "Audit de configuration")
    await alerts.resolve_prefix("config:", keep)


async def mark_interrupted_scans() -> None:
    """Au démarrage : un scan resté « en cours » a été coupé (redémarrage, manque de mémoire)."""
    await db.execute(
        "UPDATE vuln_scans SET status = 'interrupted', finished_ts = ?, error = ? WHERE status = 'running'",
        (time.time(), "Interrompu : LogSonar a redémarré pendant le scan"))


async def latest_scan() -> dict | None:
    row = await db.fetchone("SELECT * FROM vuln_scans WHERE status = 'done' ORDER BY id DESC LIMIT 1")
    if row:
        row["summary"] = json.loads(row["summary"] or "{}")
    return row


async def slim_osv_cache(min_bytes: int = 20_000, batch: int = 50) -> int:
    """
    Réduit les fiches OSV mises en cache en entier par les versions d'avant
    slim_vuln (fiches Ubuntu du noyau jusqu'à ~220 Ko chacune). Ne touche que
    les grosses fiches, par lots (jamais tout en mémoire) ; sans effet une fois
    le cache propre.
    """
    ids = [r["vuln_id"] for r in await db.fetchall(
        "SELECT vuln_id FROM osv_cache WHERE length(data) > ?", (min_bytes,))]
    done = 0
    for start in range(0, len(ids), batch):
        chunk = ids[start:start + batch]
        marks = ",".join("?" * len(chunk))
        updates = []
        for r in await db.fetchall(f"SELECT vuln_id, data FROM osv_cache WHERE vuln_id IN ({marks})", chunk):
            try:
                slim = json.dumps(slim_vuln(json.loads(r["data"])))
            except (ValueError, TypeError):
                continue
            if len(slim) < len(r["data"]):
                updates.append((slim, r["vuln_id"]))
        if updates:
            await db.executemany("UPDATE osv_cache SET data = ? WHERE vuln_id = ?", updates)
            done += len(updates)
    if done:
        print(f"LogSonar: {done} fiche(s) de vulnérabilité réduite(s) dans le cache.")
    return done
