"""
Client OSV.dev (base de vulnérabilités ouverte de Google : Debian, Ubuntu,
Alpine, PyPI, npm, GitHub Advisories...) et calcul des scores CVSS v3.
"""
from __future__ import annotations

import asyncio
import json
import math
import re
import time
from typing import Optional

import httpx

from .. import config, db

SEV_ORDER = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CACHE_TTL = 3 * 86400


# ---------------------------------------------------------------------------
# CVSS v3.x
# ---------------------------------------------------------------------------
_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> Optional[float]:
    if not vector.startswith("CVSS:3"):
        return None
    try:
        m = dict(part.split(":", 1) for part in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _W["CIA"][m["C"]]) * (1 - _W["CIA"][m["I"]]) * (1 - _W["CIA"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    return _roundup(min((1.08 if changed else 1) * (impact + expl), 10))


def score_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


_LABELS = {
    "critical": "critical", "high": "high", "important": "high", "moderate": "medium", "medium": "medium",
    "low": "low", "negligible": "low", "unimportant": "low", "low*": "low", "minor": "low",
}


def _matching_affected(vuln: dict, package: str, ecosystem: Optional[str]) -> list[dict]:
    """Entrées « affected » propres à CE paquet dans CETTE distribution (ex. Debian:13, pas Debian:14)."""
    out = []
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if package and pkg.get("name", "").lower() != package.lower():
            continue
        if ecosystem and pkg.get("ecosystem") and pkg["ecosystem"] != ecosystem:
            continue
        out.append(aff)
    return out


def severity_of(vuln: dict, package: str = "", ecosystem: Optional[str] = None) -> tuple[str, Optional[float]]:
    affected = _matching_affected(vuln, package, ecosystem) if (package or ecosystem) else (vuln.get("affected") or [])
    # L'avis de la distribution prime : Debian classe « unimportant » les failles
    # sans impact réel sur ses paquets (fonction non compilée, CVE contestée...).
    distro_labels = []
    for aff in affected:
        for key in ("ecosystem_specific", "database_specific"):
            spec = aff.get(key) or {}
            for field in ("severity", "urgency"):
                if spec.get(field):
                    distro_labels.append(str(spec[field]).lower())
    if "unimportant" in distro_labels:
        return "low", None

    best_score = None
    for s in vuln.get("severity") or []:
        if s.get("type") == "CVSS_V3":
            sc = cvss3_score(s.get("score", ""))
            if sc is not None and (best_score is None or sc > best_score):
                best_score = sc
    if best_score is not None:
        return score_to_severity(best_score), best_score

    labels = list(distro_labels)
    for s in vuln.get("severity") or []:
        if s.get("type") == "Ubuntu":
            labels.append(str(s.get("score", "")).lower())
    labels.append(str((vuln.get("database_specific") or {}).get("severity", "")).lower())
    found = [_LABELS[x] for x in labels if x in _LABELS]
    if found:
        return max(found, key=lambda x: SEV_ORDER[x]), None
    return "unknown", None


def _natural_key(v: str) -> list:
    return [(0, int(x)) if x.isdigit() else (1, x) for x in re.split(r"[.\-+:~_]", v) if x != ""]


def fixed_version(vuln: dict, package: str, current: str, ecosystem: Optional[str] = None) -> str:
    """Plus petite version corrigée supérieure à la version installée, dans la même distribution."""
    fixes = []
    for aff in _matching_affected(vuln, package, ecosystem):
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    fixes.append(ev["fixed"])
    if not fixes:
        return ""
    cur = _natural_key(current)
    newer = sorted((f for f in fixes if _natural_key(f) > cur), key=_natural_key)
    return newer[0] if newer else ""


def _severity_fields(spec: Optional[dict]) -> dict:
    return {k: v for k, v in (spec or {}).items() if k in ("severity", "urgency")}


def slim_vuln(data: dict) -> dict:
    """
    Ne garde que ce que LogSonar utilise. Une fiche Ubuntu sur le noyau pèse
    ~340 Ko (136 variantes linux-*, avec la liste de leurs binaires) : sans ce
    tri, quelques milliers de fiches dépassent la mémoire du conteneur.
    """
    slim = {
        k: data.get(k) for k in
        ("id", "summary", "details", "aliases", "upstream", "severity", "database_specific", "withdrawn", "published")
        if data.get(k) is not None
    }
    slim["affected"] = [
        {
            "package": a.get("package"),
            "ranges": a.get("ranges"),
            "ecosystem_specific": _severity_fields(a.get("ecosystem_specific")),
            "database_specific": _severity_fields(a.get("database_specific")),
        }
        for a in data.get("affected") or []
    ]
    if "details" in slim:
        slim["details"] = slim["details"][:600]
    return slim


def only_packages(vuln: dict, names: set[str]) -> dict:
    """Copie de la fiche réduite aux paquets donnés (noms en minuscules)."""
    out = dict(vuln)
    out["affected"] = [a for a in vuln.get("affected") or []
                       if ((a.get("package") or {}).get("name") or "").lower() in names]
    return out


# ---------------------------------------------------------------------------
# Requêtes
# ---------------------------------------------------------------------------
class OSVClient:
    def __init__(self) -> None:
        self.client = httpx.AsyncClient(
            base_url=config.OSV_API, timeout=httpx.Timeout(30.0),
            headers={"User-Agent": "LogSonar/2 (+https://github.com/NabySidime/LogSonar)"},
        )
        self._sem = asyncio.Semaphore(8)

    async def close(self) -> None:
        await self.client.aclose()

    async def query_batch(self, packages: list[dict]) -> list[list[str]]:
        """Pour chaque paquet, la liste des identifiants de vulnérabilités connues."""
        results: list[list[str]] = [[] for _ in packages]
        for start in range(0, len(packages), 500):
            chunk = packages[start:start + 500]
            queries = [
                {"package": {"name": p["name"], "ecosystem": p["ecosystem"]}, "version": p["version"]}
                for p in chunk
            ]
            pending = list(range(len(chunk)))
            tokens: dict[int, str] = {}
            for _page in range(10):
                if not pending:
                    break
                body = {"queries": [{**queries[i], **({"page_token": tokens[i]} if i in tokens else {})} for i in pending]}
                resp = await self._post_retry("/v1/querybatch", body)
                answers = resp.get("results") or []
                next_pending = []
                for i, ans in zip(pending, answers):
                    results[start + i].extend(v["id"] for v in ans.get("vulns") or [])
                    if ans.get("next_page_token"):
                        tokens[i] = ans["next_page_token"]
                        next_pending.append(i)
                pending = next_pending
        return results

    async def _post_retry(self, url: str, body: dict) -> dict:
        for attempt in range(3):
            try:
                resp = await self.client.post(url, json=body)
                if resp.status_code == 200:
                    return resp.json()
                if resp.status_code < 500 and resp.status_code != 429:
                    raise RuntimeError(f"OSV a répondu {resp.status_code}")
            except httpx.HTTPError:
                if attempt == 2:
                    raise
            await asyncio.sleep(2 ** attempt)
        raise RuntimeError("OSV indisponible")

    async def get_vuln(self, vuln_id: str) -> dict:
        row = await db.fetchone("SELECT data, fetched_ts FROM osv_cache WHERE vuln_id = ?", (vuln_id,))
        if row and time.time() - row["fetched_ts"] < CACHE_TTL:
            return json.loads(row["data"])
        async with self._sem:
            data: dict = {}
            for attempt in range(3):
                try:
                    resp = await self.client.get(f"/v1/vulns/{vuln_id}")
                    if resp.status_code == 200:
                        data = resp.json()
                        break
                    if resp.status_code == 404:
                        break
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(1 + attempt)
        slim = slim_vuln(data)
        await db.execute(
            "INSERT OR REPLACE INTO osv_cache (vuln_id, data, fetched_ts) VALUES (?, ?, ?)",
            (vuln_id, json.dumps(slim), time.time()),
        )
        return slim
