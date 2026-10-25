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
        # Les failles corrigeables pèsent lourd : une mise à jour suffit. Celles
        # sans correctif publié (fréquentes dans le noyau) pèsent peu : on ne
        # peut qu'attendre, et elles empêcheraient le score de remonter.
        f = scan_summary.get("fixable_by_severity")
        if f is None:  # scan d'une version précédente : tout compte comme corrigeable
            f = v
        # Par gravité : (poids corrigeable, plafond, poids sans correctif, plafond sans correctif).
        # Les failles sans correctif partagent le plafond de la gravité et ne
        # prennent que la place laissée : le score n'est jamais plus bas qu'avant.
        rules = {"critical": (2.5, 25, 0.25, 5), "high": (0.5, 15, 0.02, 3), "medium": (0.1, 5, 0, 0)}
        labels = {"critical": "critique(s)", "high": "élevée(s)", "medium": "moyenne(s)"}
        hints = {"critical": "Mettez à jour les paquets concernés (onglet Vulnérabilités).",
                 "high": "Reconstruisez les images avec des versions de base récentes.", "medium": ""}
        for sev, (w_fix, cap, w_nofix, cap_nofix) in rules.items():
            n_fix = f.get(sev, 0)
            n_nofix = max(v.get(sev, 0) - n_fix, 0)
            p_fix = _pen(n_fix, w_fix, cap)
            add(f"{n_fix} vulnérabilité(s) {labels[sev]} corrigeable(s)", p_fix, hints[sev])
            add(f"{n_nofix} vulnérabilité(s) {labels[sev]} sans correctif publié",
                min(_pen(n_nofix, w_nofix, cap_nofix), cap - p_fix),
                "Aucune version corrigée n'existe encore : refaites les mises à jour régulièrement.")
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
