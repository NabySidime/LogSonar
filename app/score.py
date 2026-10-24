"""
Score de sécurité global (0-100) et sa justification, point par point.
Le but n'est pas la précision scientifique mais de montrer où agir en premier.
"""
from __future__ import annotations

from typing import Optional


def _pen(count: int, per: float, cap: float) -> float:
    return min(count * per, cap)


def compute(scan_summary: Optional[dict], open_alerts: list[dict], host: dict, tls: list[dict],
            config_counts: Optional[dict] = None) -> dict:
    items: list[dict] = []

    def add(label: str, points: float, hint: str) -> None:
        if points > 0:
            items.append({"label": label, "points": round(points, 1), "hint": hint})

    if scan_summary:
        v = scan_summary.get("vulns_by_severity") or {}
        add(f"{v.get('critical', 0)} vulnérabilité(s) critique(s)", _pen(v.get("critical", 0), 2.5, 25),
            "Mettez à jour les paquets concernés (onglet Vulnérabilités).")
        add(f"{v.get('high', 0)} vulnérabilité(s) élevée(s)", _pen(v.get("high", 0), 0.5, 15),
            "Reconstruisez les images avec des versions de base récentes.")
        add(f"{v.get('medium', 0)} vulnérabilité(s) moyenne(s)", _pen(v.get("medium", 0), 0.1, 5), "")
        c = config_counts or scan_summary.get("config_by_severity") or {}
        add(f"{c.get('critical', 0)} problème(s) de configuration critique(s)", _pen(c.get("critical", 0), 10, 20),
            "Ex. base de données exposée sur Internet, conteneur privilégié.")
        add(f"{c.get('high', 0)} problème(s) de configuration élevé(s)", _pen(c.get("high", 0), 4, 12), "")
        add(f"{c.get('medium', 0)} problème(s) de configuration moyen(s)", _pen(c.get("medium", 0), 2, 6), "")
        add(f"{c.get('low', 0)} recommandation(s) de configuration", _pen(c.get("low", 0), 0.5, 4), "")
    else:
        add("Aucun scan de sécurité effectué", 10, "Lancez un scan depuis l'onglet Vulnérabilités.")

    # Les alertes issues du scan ou de l'audit sont déjà comptées plus haut
    live = [a for a in open_alerts if a["category"] not in ("vulnerability", "config")]
    crit_alerts = [a for a in live if a["severity"] == "critical"]
    high_alerts = [a for a in live if a["severity"] == "high"]
    add(f"{len(crit_alerts)} alerte(s) critique(s) en cours", _pen(len(crit_alerts), 8, 20), "Traitez-les dans l'onglet Alertes.")
    add(f"{len(high_alerts)} alerte(s) élevée(s) en cours", _pen(len(high_alerts), 3, 9), "")

    full = [d for d in host.get("disks") or [] if d["percent"] >= 90]
    add(f"{len(full)} disque(s) presque plein(s)", _pen(len(full), 5, 10), "Un disque plein bloque les bases de données et les logs.")

    bad_tls = [t for t in tls if not t["ok"] or (t["days_left"] is not None and t["days_left"] <= 7)]
    add(f"{len(bad_tls)} certificat(s) TLS à traiter", _pen(len(bad_tls), 5, 10), "")

    total = sum(i["points"] for i in items)
    score = max(0, round(100 - total))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "E"
    return {"score": score, "grade": grade, "penalties": sorted(items, key=lambda i: -i["points"])}
