"""
Compteurs de trafic HTTP par conteneur, à la minute, sur la dernière heure.

Derrière un reverse proxy, la même requête apparaît dans les logs du proxy ET
de l'application. Pour ne pas la compter deux fois, le trafic global ne
somme que les conteneurs « de bordure » : ceux qui voient des IP publiques.
"""
from __future__ import annotations

import time
from collections import Counter, deque
from dataclasses import dataclass, field

from .detection.parsers import is_private_ip

WINDOW_MINUTES = 60
MAX_KEYS_PER_BUCKET = 2000
# Codes par lesquels le proxy refuse un client : 444 (connexion coupée), 429 (trop de requêtes)
BLOCKED_STATUSES = {"444", "429"}
# Part minimale du trafic qu'une IP doit faire pour être tenue responsable d'un pic
SOURCE_MIN_SHARE = 0.2


@dataclass
class Bucket:
    minute: int
    requests: int = 0
    errors: int = 0          # 5xx
    client_errors: int = 0   # 4xx
    attacks: int = 0
    public: int = 0
    ips: Counter = field(default_factory=Counter)
    paths: Counter = field(default_factory=Counter)
    statuses: Counter = field(default_factory=Counter)
    error_ips: Counter = field(default_factory=Counter)   # 5xx par IP
    suspects: set = field(default_factory=set)            # IP qui attaquent ou sont bloquées


class Traffic:
    def __init__(self) -> None:
        self._buckets: dict[str, deque[Bucket]] = {}

    def _bucket(self, container: str, now: float) -> Bucket:
        minute = int(now // 60)
        dq = self._buckets.setdefault(container, deque(maxlen=WINDOW_MINUTES + 1))
        if not dq or dq[-1].minute != minute:
            dq.append(Bucket(minute))
        return dq[-1]

    def record(self, event: dict) -> None:
        if event.get("kind") != "web":
            if event.get("attack_type"):
                self._bucket(event["container"], event["ts"]).attacks += 1
            return
        b = self._bucket(event["container"], event["ts"])
        b.requests += 1
        status = event.get("status", "")
        if status.startswith("5"):
            b.errors += 1
        elif status.startswith("4"):
            b.client_errors += 1
        if event.get("attack_type"):
            b.attacks += 1
        ip = event.get("ip", "")
        if ip and not is_private_ip(ip):
            b.public += 1
        if len(b.ips) < MAX_KEYS_PER_BUCKET or ip in b.ips:
            b.ips[ip] += 1
        if ip and status.startswith("5") and (len(b.error_ips) < MAX_KEYS_PER_BUCKET or ip in b.error_ips):
            b.error_ips[ip] += 1
        if ip and (event.get("attack_type") or status in BLOCKED_STATUSES) and len(b.suspects) < MAX_KEYS_PER_BUCKET:
            b.suspects.add(ip)
        path = event.get("path", "").split("?")[0][:200]
        if len(b.paths) < MAX_KEYS_PER_BUCKET or path in b.paths:
            b.paths[path] += 1
        b.statuses[status[:1] + "xx" if status else "?"] += 1

    def forget(self, container: str) -> None:
        self._buckets.pop(container, None)

    def _recent(self, dq: deque[Bucket], minutes: int, include_current: bool) -> list[Bucket]:
        now_min = int(time.time() // 60)
        lo = now_min - minutes
        hi = now_min if include_current else now_min - 1
        return [b for b in dq if lo <= b.minute <= hi]

    def edge_containers(self) -> list[str]:
        edges = []
        for name, dq in self._buckets.items():
            recent = self._recent(dq, 15, True)
            req = sum(b.requests for b in recent)
            pub = sum(b.public for b in recent)
            if req and pub / req >= 0.5:
                edges.append(name)
        if not edges:  # aucun trafic public (dev local) : on prend tout
            edges = list(self._buckets.keys())
        return edges

    def last_minute(self) -> dict:
        """Trafic de la dernière minute complète (requêtes, 5xx, attaques)."""
        out = {"requests": 0, "errors": 0, "attacks": 0}
        edges = set(self.edge_containers())
        for name, dq in self._buckets.items():
            for b in self._recent(dq, 1, False):
                if name in edges:
                    out["requests"] += b.requests
                    out["errors"] += b.errors
                out["attacks"] += b.attacks
        return out

    def last_minute_sources(self) -> dict:
        """Détail par IP de la dernière minute complète (conteneurs de bordure) :
        requêtes, erreurs 5xx, et IP qui ont attaqué ou été bloquées."""
        ips, error_ips, suspects = Counter(), Counter(), set()
        for name in self.edge_containers():
            for b in self._recent(self._buckets.get(name, deque()), 1, False):
                ips.update(b.ips)
                error_ips.update(b.error_ips)
                suspects |= b.suspects
        return {"ips": ips, "error_ips": error_ips, "suspects": suspects}

    def baseline_rpm(self) -> float:
        """Moyenne des requêtes/minute sur l'heure écoulée (hors dernière minute)."""
        edges = set(self.edge_containers())
        per_minute: Counter = Counter()
        for name in edges:
            for b in self._recent(self._buckets.get(name, deque()), WINDOW_MINUTES, False)[:-1]:
                per_minute[b.minute] += b.requests
        if len(per_minute) < 10:
            return 0.0
        return sum(per_minute.values()) / len(per_minute)

    def summary(self, minutes: int = 60) -> dict:
        edges = set(self.edge_containers())
        timeline: dict[int, dict] = {}
        ips, paths, statuses = Counter(), Counter(), Counter()
        per_container = []
        for name, dq in self._buckets.items():
            recent = self._recent(dq, minutes, True)
            req = sum(b.requests for b in recent)
            per_container.append({
                "container": name,
                "requests": req,
                "errors": sum(b.errors for b in recent),
                "attacks": sum(b.attacks for b in recent),
                "edge": name in edges,
            })
            if name not in edges:
                continue
            for b in recent:
                t = timeline.setdefault(b.minute, {"requests": 0, "errors": 0, "attacks": 0})
                t["requests"] += b.requests
                t["errors"] += b.errors
                t["attacks"] += b.attacks
                ips.update(b.ips)
                paths.update(b.paths)
                statuses.update(b.statuses)
        now_min = int(time.time() // 60)
        series = [
            {"ts": m * 60, **timeline.get(m, {"requests": 0, "errors": 0, "attacks": 0})}
            for m in range(now_min - minutes + 1, now_min + 1)
        ]
        return {
            "series": series,
            "top_ips": [{"ip": ip, "count": c} for ip, c in ips.most_common(10) if ip],
            "top_paths": [{"path": p, "count": c} for p, c in paths.most_common(10)],
            "statuses": dict(statuses),
            "containers": sorted(per_container, key=lambda c: -c["requests"]),
            "baseline_rpm": round(self.baseline_rpm(), 1),
        }


def spike_sources(ips: Counter, rpm: int, limit: float, max_ips: int = 2) -> list[str]:
    """IP (au plus `max_ips`) qui expliquent à elles seules un pic : sans elles,
    le trafic resterait sous le seuil. Liste vide si le pic est réparti (vrai pic)."""
    chosen, rest = [], rpm
    for ip, count in ips.most_common(max_ips):
        if rest <= limit:
            break
        if not ip or count < rpm * SOURCE_MIN_SHARE:
            break
        chosen.append(ip)
        rest -= count
    return chosen if chosen and rest <= limit else []


def errors_without_suspects(src: dict, requests: int, errors: int) -> tuple[int, int, list[str]]:
    """Requêtes et erreurs 5xx une fois retirées les IP qui attaquent ou sont bloquées
    (le proxy qui freine un scanner n'est pas une panne). Renvoie aussi ces IP, les plus actives d'abord."""
    blamed = [ip for ip, _ in src["error_ips"].most_common() if ip in src["suspects"]]
    err = sum(src["error_ips"][ip] for ip in blamed)
    req = sum(src["ips"][ip] for ip in blamed)
    return max(requests - req, 0), max(errors - err, 0), blamed


traffic = Traffic()
