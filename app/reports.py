"""
Rapport quotidien HTML autonome (aucune ressource externe, aucun script).

Il répond d'abord à « faut-il faire quelque chose ? » (verdict + actions
prioritaires), puis détaille serveur, trafic, conteneurs, vulnérabilités et attaques.
Un résumé est envoyé sur les canaux de notification, avec le rapport complet par email.
"""
from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timedelta
from typing import Optional

from . import config, db, score
from . import settings_store as S
from .detection.signatures import EXPLANATIONS
from .vuln.osv import _natural_key

SEV_LABEL = {"critical": "Critique", "high": "Élevée", "medium": "Moyenne", "low": "Faible", "info": "Info",
             "warning": "Avertissement", "unknown": "Non évaluée"}
# Couleurs d'état (toujours accompagnées d'un libellé)
SEV_COLOR = {"critical": "#d03b3b", "high": "#ec835a", "medium": "#fab219", "warning": "#fab219",
             "low": "#2a78d6", "info": "#8a94a6", "unknown": "#8a94a6"}
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "warning": 2, "low": 3, "info": 4, "unknown": 5}
BLUE, ORANGE = "#2a78d6", "#eb6834"
CATEGORY_LABEL = {"security": "Sécurité", "host": "Serveur", "container": "Conteneur", "traffic": "Trafic",
                  "tls": "Certificat", "config": "Configuration", "vulnerability": "Vulnérabilité"}
VERDICT = {
    "bad": ("Incident à examiner", "#d03b3b", "#fdecec"),
    "warn": ("À surveiller", "#b77d00", "#fff6dd"),
    "good": ("Journée calme", "#0a8a0a", "#e8f6e8"),
}


def _e(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _num(n) -> str:
    return f"{int(n):,}".replace(",", " ")


def _bytes(n: float) -> str:
    for unit in ("o", "Ko", "Mo", "Go", "To"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} Po"


def _day_bounds(date_str: str) -> tuple[float, float]:
    start = datetime.strptime(date_str, "%Y-%m-%d")
    return start.timestamp(), (start + timedelta(days=1)).timestamp()


def _sev(sev: str) -> str:
    return (f'<span class="sev"><i style="background:{SEV_COLOR.get(sev, "#8a94a6")}"></i>'
            f'{_e(SEV_LABEL.get(sev, sev))}</span>')


def _delta(cur: float, prev: float, higher_is_bad: bool = True) -> str:
    if prev == 0 and cur == 0:
        return '<span class="d">= hier</span>'
    if prev == 0:
        return '<span class="d">nouveau</span>'
    pct = (cur - prev) / prev * 100
    if abs(pct) < 5:
        return '<span class="d">≈ hier</span>'
    bad = (pct > 0) == higher_is_bad
    arrow = "▲" if pct > 0 else "▼"
    return f'<span class="d {"up" if bad else "down"}">{arrow} {abs(pct):.0f} % vs hier</span>'


# ---------------------------------------------------------------------------
# Graphiques SVG (statiques : l'info-bulle native <title> tient lieu de survol)
# ---------------------------------------------------------------------------
W, H, PAD_L, PAD_B, PAD_T = 720, 170, 34, 20, 10


def _axes(ymax: float, fmt) -> str:
    out = []
    for frac in (0, 0.5, 1):
        y = PAD_T + (H - PAD_T - PAD_B) * (1 - frac)
        out.append(f'<line x1="{PAD_L}" x2="{W}" y1="{y:.1f}" y2="{y:.1f}" class="grid"/>'
                   f'<text x="{PAD_L - 6}" y="{y + 3:.1f}" class="ax" text-anchor="end">{_e(fmt(ymax * frac))}</text>')
    for h in range(0, 24, 3):
        x = PAD_L + (W - PAD_L) * (h + 0.5) / 24
        out.append(f'<text x="{x:.1f}" y="{H - 5}" class="ax" text-anchor="middle">{h}h</text>')
    return "".join(out)


def _bars(values: list[float], color: str, label: str) -> str:
    vmax = max(values) if values and max(values) > 0 else 1
    ymax = vmax if vmax > 4 else 4
    plot_h = H - PAD_T - PAD_B
    slot = (W - PAD_L) / 24
    bars = []
    for h, v in enumerate(values):
        bh = v / ymax * plot_h
        x = PAD_L + h * slot + slot * 0.18
        bars.append(f'<rect x="{x:.1f}" y="{PAD_T + plot_h - bh:.1f}" width="{slot * 0.64:.1f}" height="{max(bh, 0):.1f}" '
                    f'rx="3" fill="{color}"><title>{h}h–{h + 1}h : {_num(v)} {label}</title></rect>')
        # zone de survol plus large que la barre
        bars.append(f'<rect x="{PAD_L + h * slot:.1f}" y="{PAD_T}" width="{slot:.1f}" height="{plot_h}" fill="transparent">'
                    f'<title>{h}h–{h + 1}h : {_num(v)} {label}</title></rect>')
    return (f'<svg viewBox="0 0 {W} {H}" width="100%" role="img" aria-label="{_e(label)} par heure">'
            f'{_axes(ymax, lambda v: _num(round(v)))}{"".join(bars)}</svg>')


def _lines(series: list[tuple[str, str, list[Optional[float]]]], suffix: str = " %") -> str:
    ymax = 100
    plot_h = H - PAD_T - PAD_B
    slot = (W - PAD_L) / 24
    out = []
    label_ys: list[float] = []
    for name, color, vals in series:
        pts = [(PAD_L + (h + 0.5) * slot, PAD_T + plot_h * (1 - v / ymax), v) for h, v in enumerate(vals) if v is not None]
        if not pts:
            continue
        out.append(f'<polyline fill="none" stroke="{color}" stroke-width="2" stroke-linejoin="round" '
                   f'points="{" ".join(f"{x:.1f},{y:.1f}" for x, y, _ in pts)}"/>')
        for (x, y, v), h in zip(pts, [h for h, v in enumerate(vals) if v is not None]):
            out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="{color}" stroke="#fff" stroke-width="1.5">'
                       f'<title>{_e(name)} à {h}h : {v:.0f}{suffix}</title></circle>')
        x, y, v = pts[-1]
        # étiquettes directes : on écarte celles qui se chevaucheraient
        for other in label_ys:
            if abs(y - other) < 13:
                y = other + 13 if y >= other else other - 13
        label_ys.append(y)
        out.append(f'<text x="{min(x + 6, W - 2):.1f}" y="{y + 3:.1f}" class="dl" text-anchor="{"start" if x + 60 < W else "end"}">{_e(name)}</text>')
    legend = "".join(f'<span class="lg"><i style="background:{c}"></i>{_e(n)}</span>' for n, c, _ in series)
    return (f'<div class="legend">{legend}</div><svg viewBox="0 0 {W} {H}" width="100%" role="img" aria-label="Utilisation par heure">'
            f'{_axes(ymax, lambda v: f"{v:.0f}{suffix}")}{"".join(out)}</svg>')


# ---------------------------------------------------------------------------
# Collecte des données
# ---------------------------------------------------------------------------
async def _day_counts(t0: float, t1: float) -> dict:
    return {
        "attacks": await db.scalar("SELECT COUNT(*) FROM security_events WHERE ts >= ? AND ts < ?", (t0, t1)) or 0,
        "alerts": await db.scalar("SELECT COUNT(*) FROM alerts WHERE first_ts >= ? AND first_ts < ?", (t0, t1)) or 0,
        "requests": await db.scalar("SELECT COALESCE(SUM(req_rate), 0) FROM host_metrics WHERE ts >= ? AND ts < ?", (t0, t1)) or 0,
        "errors": await db.scalar("SELECT COALESCE(SUM(err_rate), 0) FROM host_metrics WHERE ts >= ? AND ts < ?", (t0, t1)) or 0,
    }


async def _vuln_data(t1: float) -> dict:
    scans = await db.fetchall(
        "SELECT * FROM vuln_scans WHERE status = 'done' AND started_ts < ? ORDER BY id DESC LIMIT 2", (t1,))
    if not scans:
        return {}
    cur = scans[0]
    out = {"scan": cur, "summary": json.loads(cur["summary"] or "{}")}
    sev_case = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
    top = await db.fetchall(
        f"SELECT package, ecosystem, version, MIN({sev_case}) AS rank, COUNT(*) AS n, GROUP_CONCAT(DISTINCT fixed_version) AS fixes,"
        " GROUP_CONCAT(DISTINCT target) AS targets FROM vuln_findings WHERE scan_id = ? AND severity IN ('critical', 'high')"
        " GROUP BY ecosystem, package, version ORDER BY rank, n DESC LIMIT 10", (cur["id"],))
    for r in top:
        fixes = [f for f in (r.pop("fixes") or "").split(",") if f]
        r["fix"] = max(fixes, key=_natural_key) if fixes else ""
    out["top"] = top
    out["config"] = await db.fetchall(
        f"SELECT target, severity, title, fix FROM config_findings WHERE scan_id = ? AND severity IN ('critical', 'high')"
        f" ORDER BY {sev_case}, target LIMIT 10", (cur["id"],))
    out["config_counts"] = {r["severity"]: r["n"] for r in await db.fetchall(
        "SELECT severity, COUNT(*) AS n FROM config_findings WHERE scan_id = ? GROUP BY severity", (cur["id"],))}
    out["new"] = []
    if len(scans) == 2:
        out["new"] = await db.fetchall(
            f"SELECT target, package, version, vuln_id, severity, fixed_version, summary FROM vuln_findings v"
            f" WHERE scan_id = ? AND severity IN ('critical', 'high', 'medium') AND NOT EXISTS ("
            f"  SELECT 1 FROM vuln_findings p WHERE p.scan_id = ? AND p.target = v.target AND p.package = v.package AND p.vuln_id = v.vuln_id)"
            f" ORDER BY {sev_case} LIMIT 15", (cur["id"], scans[1]["id"]))
    return out


def _live_state() -> tuple[dict, list[dict], list[dict]]:
    """État courant (score, TLS) ; import tardif pour éviter une dépendance circulaire."""
    try:
        from .alerts import alerts
        from .monitor import monitor
        return monitor.host_now or {}, monitor.tls or [], alerts.open_alerts()
    except Exception:
        return {}, [], []


# ---------------------------------------------------------------------------
# Génération
# ---------------------------------------------------------------------------
async def build(date_str: str) -> Optional[tuple[str, dict]]:
    t0, t1 = _day_bounds(date_str)
    events = await db.fetchall("SELECT * FROM security_events WHERE ts >= ? AND ts < ? ORDER BY ts", (t0, t1))
    day_alerts = await db.fetchall("SELECT * FROM alerts WHERE first_ts >= ? AND first_ts < ? ORDER BY first_ts", (t0, t1))
    metrics = await db.fetchall("SELECT * FROM host_metrics WHERE ts >= ? AND ts < ? ORDER BY ts", (t0, t1))
    if not events and not day_alerts and not metrics:
        return None

    prev = await _day_counts(t0 - 86400, t0)
    vuln = await _vuln_data(t1)
    vsum = vuln.get("summary") or {}
    vsev = vsum.get("vulns_by_severity") or {}
    host_now, tls, open_alerts = _live_state()
    sc = score.compute(vsum or None, open_alerts, host_now, tls, vuln.get("config_counts"))

    # --- Attaques
    by_type = Counter(e["attack_type"] for e in events)
    by_ip = Counter(e["ip"] for e in events if e["ip"])
    by_url = Counter(e["path"].split("?")[0][:120] for e in events if e["path"])
    by_hour_att = Counter(datetime.fromtimestamp(e["ts"]).hour for e in events)
    successes = [e for e in events if e["status"].startswith("2") and e["severity"] in ("high", "critical")]
    body_attacks = sum(1 for e in events if "\nCorps :" in (e["raw"] or ""))

    # --- Serveur et trafic, par heure
    hourly: dict[int, list[dict]] = {h: [] for h in range(24)}
    for m in metrics:
        hourly[datetime.fromtimestamp(m["ts"]).hour].append(m)

    def hour_avg(key: str) -> list[Optional[float]]:
        out = []
        for h in range(24):
            vals = [m[key] for m in hourly[h] if m[key] is not None]
            out.append(sum(vals) / len(vals) if vals else None)
        return out

    def stat(key: str) -> tuple[float, float]:
        vals = [m[key] for m in metrics if m[key] is not None]
        return (sum(vals) / len(vals), max(vals)) if vals else (0.0, 0.0)

    cpu_avg, cpu_max = stat("cpu")
    mem_avg, mem_max = stat("mem")
    _, disk_max = stat("disk")
    req_hour = [sum(m["req_rate"] or 0 for m in hourly[h]) for h in range(24)]
    requests = int(sum(req_hour))
    errors = int(sum(m["err_rate"] or 0 for m in metrics))
    peak_rpm = int(max((m["req_rate"] or 0 for m in metrics), default=0))
    coverage = len(metrics) / 1440 * 100

    # --- Conteneurs
    ctn = await db.fetchall(
        "SELECT name, AVG(cpu) AS cpu, MAX(cpu) AS cpu_max, MAX(mem_bytes) AS mem FROM container_metrics"
        " WHERE ts >= ? AND ts < ? GROUP BY name ORDER BY cpu DESC LIMIT 10", (t0, t1))
    ctn_incidents = [a for a in day_alerts if a["category"] == "container"]

    # --- Verdict et actions prioritaires
    crit_alerts = [a for a in day_alerts if a["severity"] == "critical"]
    high_alerts = [a for a in day_alerts if a["severity"] == "high"]
    disk_warn = S.get("disk_warn")
    actions: list[tuple[str, str, str]] = []   # (sévérité, action, détail)
    for e in successes[:3]:
        actions.append(("critical", f"Vérifier la requête {e['method']} {e['path'][:90]}",
                        f"{e['attack_type']} depuis {e['ip']} a reçu une réponse {e['status']} : assurez-vous qu'elle n'a rien exposé."))
    for c in [c for c in vuln.get("config", []) if c["severity"] == "critical"][:3]:
        actions.append(("critical", f"{c['title']} ({c['target']})", c["fix"]))
    for a in crit_alerts[:3]:
        if a["category"] != "security":
            actions.append(("critical", a["title"], CATEGORY_LABEL.get(a["category"], a["category"]) + " — voir l'onglet Alertes."))
    if disk_max >= disk_warn:
        actions.append(("high" if disk_max < S.get("disk_crit") else "critical", f"Libérer de l'espace disque ({disk_max:.0f} % utilisé)",
                        "docker system prune, rotation des logs, purge des sauvegardes anciennes."))
    for r in vuln.get("top", [])[:4]:
        if r["fix"]:
            actions.append(("critical" if r["rank"] == 0 else "high", f"Mettre à jour {r['package']} {r['version']} → {r['fix']}",
                            f"{r['n']} faille(s) — {r['targets'].replace(',', ', ')}"))
    for t in [t for t in tls if not t.get("ok") or (t.get("days_left") is not None and t["days_left"] <= S.get("tls_warn_days"))][:2]:
        actions.append(("high", f"Renouveler le certificat de {t['domain']}",
                        f"expire dans {t['days_left']} jour(s)" if t.get("days_left") is not None else (t.get("error") or "certificat invalide")))
    actions.sort(key=lambda a: SEV_RANK.get(a[0], 9))

    if successes or crit_alerts:
        verdict = "bad"
    elif high_alerts or disk_max >= disk_warn or vsev.get("critical") or vuln.get("new"):
        verdict = "warn"
    else:
        verdict = "good"
    sentences = []
    sentences.append(f"{_num(len(events))} attaque(s) détectée(s) depuis {len(by_ip)} IP" if events else "Aucune attaque détectée")
    if successes:
        sentences.append(f"dont {len(successes)} grave(s) ayant reçu une réponse positive")
    if requests:
        sentences.append(f"{_num(requests)} requêtes HTTP servies" + (f", {_num(errors)} erreurs serveur" if errors else ""))
    grave = [f"{n} {label}" for n, label in ((len(crit_alerts), "critique(s)"), (len(high_alerts), "élevée(s)")) if n]
    if grave:
        sentences.append("alertes : " + " et ".join(grave))
    if vuln.get("new"):
        sentences.append(f"{len(vuln['new'])} nouvelle(s) vulnérabilité(s) depuis le scan précédent")
    headline = " · ".join(sentences) + "."

    cur = {"attacks": len(events), "alerts": len(day_alerts), "requests": requests, "errors": errors}
    summary = {
        "date": date_str, "verdict": verdict, "verdict_label": VERDICT[verdict][0], "headline": headline,
        "score": sc["score"], "grade": sc["grade"], "actions": actions[:6], **cur,
        "cpu_max": cpu_max, "mem_max": mem_max, "disk_max": disk_max,
        "vulns_critical": vsev.get("critical", 0), "vulns_high": vsev.get("high", 0),
    }

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------
    def kpi(label: str, value, sub: str = "") -> str:
        return f'<div class="kpi"><div class="kl">{_e(label)}</div><div class="kv">{value}</div><div class="ks">{sub}</div></div>'

    vlabel, vcolor, vbg = VERDICT[verdict]
    kpis = "".join([
        kpi("Score de sécurité", f'{sc["score"]}<small>/100 · {sc["grade"]}</small>', "au moment du rapport"),
        kpi("Attaques détectées", _num(len(events)), _delta(len(events), prev["attacks"])),
        kpi("Requêtes HTTP", _num(requests), _delta(requests, prev["requests"], higher_is_bad=False) + f" · pic {peak_rpm}/min"),
        kpi("Erreurs 5xx", _num(errors), _delta(errors, prev["errors"])),
        kpi("Nouvelles alertes", _num(len(day_alerts)), _delta(len(day_alerts), prev["alerts"])),
        kpi("Vulnérabilités", _num(vsum.get("vulns_total", 0)) if vuln else "—",
            f"{vsev.get('critical', 0)} critiques · {vsev.get('high', 0)} élevées" if vuln else "aucun scan"),
    ])

    if actions:
        action_html = "<ol class='actions'>" + "".join(
            f"<li>{_sev(s)}<div><b>{_e(a)}</b><div class='muted'>{_e(d)}</div></div></li>" for s, a, d in actions[:8]) + "</ol>"
    else:
        action_html = "<p class='ok'>✓ Rien d'urgent : aucune action prioritaire aujourd'hui.</p>"

    def table(head: list[str], rows: list[str], empty: str, cls: str = "") -> str:
        th = "".join(f"<th{' class=n' if h.startswith('#') else ''}>{_e(h.lstrip('#'))}</th>" for h in head)
        body = "".join(rows) or f'<tr><td colspan="{len(head)}" class="muted">{_e(empty)}</td></tr>'
        return f'<div class="tw"><table class="{cls}"><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table></div>'

    def hm(ts: float, sec: bool = False) -> str:
        return datetime.fromtimestamp(ts).strftime("%H:%M:%S" if sec else "%H:%M")

    server_html = (
        f'<div class="box">{_lines([("CPU", BLUE, hour_avg("cpu")), ("Mémoire", ORANGE, hour_avg("mem"))])}'
        f'<div class="facts"><span>CPU moyen <b>{cpu_avg:.0f} %</b> · max <b>{cpu_max:.0f} %</b></span>'
        f'<span>Mémoire moyenne <b>{mem_avg:.0f} %</b> · max <b>{mem_max:.0f} %</b></span>'
        f'<span>Disque max <b>{disk_max:.0f} %</b></span><span>Données sur {min(coverage, 100):.0f} % de la journée</span></div></div>'
    ) if metrics else '<p class="muted">Pas de mesures pour cette journée.</p>'

    traffic_html = (
        f'<div class="box">{_bars(req_hour, BLUE, "requêtes")}</div>' if requests else '<p class="muted">Aucun trafic HTTP mesuré.</p>')

    ctn_rows = [f'<tr><td class="mono">{_e(c["name"])}</td><td class="n">{(c["cpu"] or 0):.1f} %</td>'
                f'<td class="n">{(c["cpu_max"] or 0):.0f} %</td><td class="n">{_bytes(c["mem"] or 0)}</td></tr>' for c in ctn]
    inc_rows = [f'<tr><td class="mono">{hm(a["first_ts"])}</td><td>{_sev(a["severity"])}</td><td>{_e(a["title"])}</td></tr>'
                for a in ctn_incidents]

    vuln_html = ""
    if vuln:
        top_rows = [f'<tr><td>{_sev("critical" if r["rank"] == 0 else "high")}</td><td class="mono">{_e(r["package"])}</td>'
                    f'<td class="mono">{_e(r["version"])}</td><td class="mono">{_e(r["fix"] or "pas encore de correctif")}</td>'
                    f'<td class="n">{r["n"]}</td><td class="muted">{_e(r["targets"].replace(",", ", "))}</td></tr>' for r in vuln["top"]]
        new_rows = [f'<tr><td>{_sev(v["severity"])}</td><td class="mono">{_e(v["vuln_id"])}</td><td class="mono">{_e(v["package"])} {_e(v["version"])}</td>'
                    f'<td>{_e(v["target"])}</td><td class="muted">{_e((v["summary"] or "")[:140])}</td></tr>' for v in vuln["new"]]
        cfg_rows = [f'<tr><td>{_sev(c["severity"])}</td><td>{_e(c["title"])}</td><td class="mono">{_e(c["target"])}</td><td class="muted">{_e(c["fix"])}</td></tr>'
                    for c in vuln["config"]]
        when = datetime.fromtimestamp(vuln["scan"]["started_ts"]).strftime("%d/%m à %H:%M")
        vuln_html = (
            f'<p class="muted">Dernier scan : {when} · {_num(vsum.get("packages_total", 0))} paquets analysés · '
            f'{_num(vsum.get("fixable", 0))} faille(s) corrigeable(s) par une mise à jour.</p>'
            + (f"<h3>Nouvelles depuis le scan précédent</h3>{table(['Gravité', 'Identifiant', 'Paquet', 'Cible', 'Résumé'], new_rows, '')}" if new_rows else "")
            + f"<h3>Paquets à mettre à jour en priorité</h3>{table(['Gravité', 'Paquet', 'Version', 'Corrigé en', '#Failles', 'Où'], top_rows, 'Aucune faille critique ou élevée.')}"
            + f"<h3>Configuration</h3>{table(['Gravité', 'Problème', 'Cible', 'Correction'], cfg_rows, 'Aucun problème critique ou élevé.')}"
        )
    else:
        vuln_html = '<p class="muted">Aucun scan de vulnérabilités disponible.</p>'

    type_rows = [f'<tr><td>{_e(t)}</td><td class="n">{c}</td><td class="muted">{_e(EXPLANATIONS.get(t, {}).get("fix", ""))}</td></tr>'
                 for t, c in by_type.most_common()]
    ip_rows = [f'<tr><td class="mono">{_e(ip)}</td><td class="n">{c}</td><td>{_e(", ".join(sorted({e["attack_type"] for e in events if e["ip"] == ip})[:3]))}</td></tr>'
               for ip, c in by_ip.most_common(10)]
    url_rows = [f'<tr><td class="mono path">{_e(u)}</td><td class="n">{c}</td></tr>' for u, c in by_url.most_common(10)]
    success_rows = [f'<tr><td class="mono">{hm(e["ts"], True)}</td><td class="mono">{_e(e["ip"])}</td><td>{_e(e["attack_type"])}</td>'
                    f'<td class="mono path">{_e(e["method"])} {_e(e["path"][:160])}</td><td class="n">{_e(e["status"])}</td></tr>' for e in successes[:30]]
    alert_rows = [f'<tr><td class="mono">{hm(a["first_ts"])}</td><td>{_sev(a["severity"])}</td><td>{_e(CATEGORY_LABEL.get(a["category"], a["category"]))}</td>'
                  f'<td>{_e(a["title"])}</td><td class="muted">{_e({"open": "ouverte", "acknowledged": "prise en compte", "resolved": "résolue"}.get(a["status"], a["status"]))}</td></tr>'
                  for a in day_alerts[:60]]
    explain = "".join(
        f'<div class="card"><h4>{_e(t)}</h4><p>{_e(EXPLANATIONS[t]["what"])}</p><p><b>Que faire :</b> {_e(EXPLANATIONS[t]["fix"])}</p></div>'
        for t, _ in by_type.most_common(6) if t in EXPLANATIONS)
    attacks_hour = [by_hour_att.get(h, 0) for h in range(24)]
    day_label = datetime.strptime(date_str, "%Y-%m-%d").strftime("%A %d/%m/%Y")
    day_label = day_label.replace(day_label.split()[0], {"Monday": "lundi", "Tuesday": "mardi", "Wednesday": "mercredi", "Thursday": "jeudi",
                                                         "Friday": "vendredi", "Saturday": "samedi", "Sunday": "dimanche"}.get(day_label.split()[0], day_label.split()[0]))

    doc = f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Rapport {_e(config.INSTANCE_NAME)} — {date_str}</title>
<style>
*{{box-sizing:border-box}}
body{{margin:0;background:#f5f6f8;color:#1b2230;font:14px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}}
.wrap{{max-width:1040px;margin:0 auto;padding:32px 20px}}
h1{{font-size:24px;margin:0}} h2{{font-size:17px;margin:36px 0 12px;padding-bottom:6px;border-bottom:1px solid #e3e6eb}}
h3{{font-size:14px;margin:20px 0 8px}} h4{{font-size:14px;margin:0 0 6px}}
.sub{{color:#5d6675;margin:4px 0 20px}}
.verdict{{border-radius:12px;padding:16px 20px;margin-bottom:16px;border-left:6px solid}}
.verdict b{{font-size:18px}} .verdict p{{margin:4px 0 0}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}}
.kpi,.card,.box{{background:#fff;border:1px solid #e3e6eb;border-radius:10px;padding:12px 14px}}
.kl{{font-size:12px;color:#5d6675}} .kv{{font-size:22px;font-weight:700;margin-top:2px;font-variant-numeric:tabular-nums}}
.kv small{{font-size:12px;font-weight:500;color:#5d6675}} .ks{{font-size:12px;color:#5d6675}}
.d{{color:#5d6675}} .d.up{{color:#b42d2d}} .d.down{{color:#0a7a0a}}
.actions{{list-style:none;padding:0;margin:0;display:grid;gap:8px}}
.actions li{{display:flex;gap:12px;align-items:flex-start;background:#fff;border:1px solid #e3e6eb;border-radius:10px;padding:10px 14px}}
.actions li .sev{{flex:none;min-width:96px;margin-top:1px}}
.ok{{background:#e8f6e8;color:#0a6a0a;border-radius:10px;padding:12px 16px;margin:0}}
.tw{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e3e6eb;border-radius:10px;overflow:hidden}}
th,td{{text-align:left;padding:7px 12px;border-bottom:1px solid #eef0f3;vertical-align:top}}
th{{font-size:12px;color:#5d6675;background:#fafbfc;font-weight:600}} tr:last-child td{{border-bottom:0}}
.n{{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}} .mono{{font-family:ui-monospace,Consolas,monospace;font-size:12.5px}}
.path{{word-break:break-all}} .muted{{color:#5d6675}}
.sev{{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;white-space:nowrap}}
.sev i{{width:9px;height:9px;border-radius:50%;display:inline-block}}
.grid2{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px}} .card p{{margin:4px 0;color:#3a4352}}
.danger{{border-left:4px solid #d03b3b}}
svg .grid{{stroke:#e3e6eb;stroke-width:1}} svg .ax{{font-size:10px;fill:#5d6675}} svg .dl{{font-size:11px;fill:#1b2230;font-weight:600}}
.legend{{display:flex;gap:16px;font-size:12px;color:#3a4352;margin-bottom:4px}} .lg{{display:inline-flex;align-items:center;gap:6px}}
.lg i{{width:12px;height:3px;border-radius:2px;display:inline-block}}
.facts{{display:flex;flex-wrap:wrap;gap:6px 22px;font-size:12.5px;color:#3a4352;margin-top:6px}}
footer{{margin-top:40px;color:#8a94a6;font-size:12px;text-align:center}}
@media print{{body{{background:#fff}} .wrap{{padding:0}} h2{{break-after:avoid}} table,.box,.actions li{{break-inside:avoid}}}}
</style></head><body><div class="wrap">
<h1>Rapport quotidien</h1>
<p class="sub">{_e(config.INSTANCE_NAME)} · {_e(day_label)} · généré le {datetime.now().strftime("%d/%m/%Y à %H:%M")}</p>

<div class="verdict" style="background:{vbg};border-color:{vcolor}"><b style="color:{vcolor}">{_e(vlabel)}</b><p>{_e(headline)}</p></div>
<div class="kpis">{kpis}</div>

<h2>Actions prioritaires</h2>{action_html}

<h2>Serveur</h2>{server_html}

<h2>Trafic HTTP</h2>{traffic_html}

<h2>Conteneurs</h2>
<div class="grid2"><div><h3>Consommation</h3>{table(["Conteneur", "#CPU moyen", "#CPU max", "#Mémoire max"], ctn_rows, "Aucune mesure.")}</div>
<div><h3>Incidents</h3>{table(["Heure", "Gravité", "Événement"], inc_rows, "Aucun crash, redémarrage ou manque de mémoire.")}</div></div>

<h2>Vulnérabilités</h2>{vuln_html}

<h2>Attaques</h2>
<p class="muted">{_num(len(events))} tentative(s){f" dont {body_attacks} dans le corps de requêtes POST" if body_attacks else ""}. Survolez une barre pour le détail.</p>
{f'<div class="box">{_bars(attacks_hour, ORANGE, "attaques")}</div>' if events else ""}
{("<h3>⚠️ Attaques graves ayant reçu une réponse positive</h3><p class='muted'>Le serveur a répondu 2xx : vérifiez que ces requêtes ont bien été neutralisées.</p>" + table(["Heure", "IP", "Type", "Requête", "#Code"], success_rows, "", "danger")) if success_rows else ""}
<h3>Types d'attaques</h3>{table(["Type", "#Nombre", "Recommandation"], type_rows, "Aucune attaque détectée.")}
<div class="grid2"><div><h3>IP les plus actives</h3>{table(["IP", "#Tentatives", "Types"], ip_rows, "—")}</div>
<div><h3>URL les plus visées</h3>{table(["URL", "#Tentatives"], url_rows, "—")}</div></div>
{("<h3>Comprendre ces attaques</h3><div class='grid'>" + explain + "</div>") if explain else ""}

<h2>Toutes les alertes du jour</h2>{table(["Heure", "Gravité", "Catégorie", "Alerte", "État"], alert_rows, "Aucune alerte.")}
<footer>Généré par LogSonar · document confidentiel</footer>
</div></body></html>"""
    return doc, summary


async def generate(date_str: Optional[str] = None, send: bool = False) -> Optional[str]:
    date_str = date_str or datetime.now().strftime("%Y-%m-%d")
    built = await build(date_str)
    if not built:
        return None
    doc, summary = built
    config.REPORT_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"rapport_{date_str}.html"
    (config.REPORT_DIR / filename).write_text(doc, encoding="utf-8")
    meta = {k: summary[k] for k in ("verdict", "verdict_label", "headline", "score", "grade", "attacks", "alerts")}
    (config.REPORT_DIR / f"rapport_{date_str}.json").write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    if send:
        from . import notify
        try:
            await notify.send_report(summary, filename, doc)
        except Exception as e:
            print(f"LogSonar: envoi du rapport impossible : {type(e).__name__}: {e}")
    return filename
