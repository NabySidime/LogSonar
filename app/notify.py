# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Naby Sidime. LogSonar : https://github.com/NabySidime/LogSonar
"""
Canaux de notification : email (Brevo), Discord, Slack, Telegram, webhook JSON.
Chaque canal est indépendant : l'échec de l'un n'empêche pas les autres.
"""
from __future__ import annotations

import asyncio
import html
from datetime import datetime

import httpx

from . import config
from . import settings_store as S

SEVERITY_LABEL = {"info": "Info", "warning": "Avertissement", "high": "Élevée", "critical": "Critique"}
SEVERITY_COLOR = {"info": 0x3B82F6, "warning": 0xF59E0B, "high": 0xF97316, "critical": 0xEF4444}
SEVERITY_EMOJI = {"info": "ℹ️", "warning": "⚠️", "high": "🟠", "critical": "🔴"}

_TIMEOUT = httpx.Timeout(10.0)


def _when(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%d/%m/%Y %H:%M:%S")


async def _post(client: httpx.AsyncClient, url: str, **kwargs) -> bool:
    try:
        resp = await client.post(url, **kwargs)
        if resp.status_code >= 300:
            print(f"LogSonar: notification refusée ({resp.status_code}) : {resp.text[:200]}")
            return False
        return True
    except httpx.HTTPError as e:
        print(f"LogSonar: notification impossible : {type(e).__name__}")
        return False


async def _email(client: httpx.AsyncClient, alert: dict, resolved: bool) -> bool:
    key, sender, to = S.get("brevo_api_key"), S.get("brevo_sender"), S.get("email_to")
    if not (S.get("email_enabled") and key and sender and to):
        return False
    e = html.escape
    state = "Résolue" if resolved else SEVERITY_LABEL.get(alert["severity"], alert["severity"])
    color = "#16a34a" if resolved else "#%06x" % SEVERITY_COLOR.get(alert["severity"], 0x6B7280)
    body = f"""<!DOCTYPE html><html><body style="margin:0;background:#f4f4f5;font-family:system-ui,sans-serif">
<div style="max-width:560px;margin:32px auto;background:#fff;border-radius:12px;overflow:hidden;border:1px solid #e4e4e7">
  <div style="background:{color};color:#fff;padding:16px 24px;font-weight:600">{e(config.INSTANCE_NAME)} · {e(state)}</div>
  <div style="padding:24px">
    <h2 style="margin:0 0 8px;font-size:18px;color:#18181b">{e(alert['title'])}</h2>
    <p style="margin:0 0 16px;color:#52525b;font-size:14px">{_when(alert['last_ts'])} · {e(alert['source'])}</p>
    <pre style="white-space:pre-wrap;word-break:break-word;background:#f4f4f5;padding:12px;border-radius:8px;font-size:13px;color:#27272a">{e(alert['message'])}</pre>
  </div>
</div></body></html>"""
    prefix = "[Résolu] " if resolved else f"[{state}] "
    return await _post(
        client, "https://api.brevo.com/v3/smtp/email",
        headers={"api-key": key},
        json={
            "sender": {"email": sender, "name": config.INSTANCE_NAME},
            "to": [{"email": addr.strip()} for addr in to.split(",") if addr.strip()],
            "subject": prefix + alert["title"][:150],
            "htmlContent": body,
            "textContent": f"{alert['title']}\n\n{alert['message']}",
        },
    )


async def _discord(client: httpx.AsyncClient, alert: dict, resolved: bool) -> bool:
    url = S.get("discord_webhook")
    if not url:
        return False
    return await _post(client, url, json={
        "username": config.INSTANCE_NAME,
        "allowed_mentions": {"parse": []},
        "embeds": [{
            "title": ("✅ Résolu : " if resolved else SEVERITY_EMOJI.get(alert["severity"], "") + " ") + alert["title"][:240],
            "description": alert["message"][:3500],
            "color": 0x16A34A if resolved else SEVERITY_COLOR.get(alert["severity"], 0x6B7280),
            "footer": {"text": f"{alert['source']} · {_when(alert['last_ts'])}"},
        }],
    })


async def _slack(client: httpx.AsyncClient, alert: dict, resolved: bool) -> bool:
    url = S.get("slack_webhook")
    if not url:
        return False
    head = "✅ Résolu" if resolved else SEVERITY_EMOJI.get(alert["severity"], "") + " " + SEVERITY_LABEL.get(alert["severity"], "")
    return await _post(client, url, json={
        "text": f"*{head} : {alert['title']}*\n{alert['message'][:2500]}\n_{alert['source']} · {_when(alert['last_ts'])}_",
    })


async def _telegram(client: httpx.AsyncClient, alert: dict, resolved: bool) -> bool:
    token, chat = S.get("telegram_bot_token"), S.get("telegram_chat_id")
    if not (token and chat):
        return False
    e = html.escape
    head = "✅ Résolu" if resolved else SEVERITY_EMOJI.get(alert["severity"], "") + " " + SEVERITY_LABEL.get(alert["severity"], "")
    text = f"<b>{e(head)} : {e(alert['title'])}</b>\n{e(alert['message'][:3000])}\n<i>{e(alert['source'])}</i>"
    return await _post(client, f"https://api.telegram.org/bot{token}/sendMessage",
                       json={"chat_id": chat, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True})


async def _webhook(client: httpx.AsyncClient, alert: dict, resolved: bool) -> bool:
    url = S.get("webhook_url")
    if not url:
        return False
    return await _post(client, url, json={
        "instance": config.INSTANCE_NAME,
        "event": "alert.resolved" if resolved else "alert.opened",
        "alert": {k: alert.get(k) for k in ("id", "category", "severity", "title", "message", "source", "first_ts", "last_ts", "count")},
    })


CHANNELS = {"email": _email, "discord": _discord, "slack": _slack, "telegram": _telegram, "webhook": _webhook}


async def send(alert: dict, resolved: bool = False, only: str | None = None) -> dict[str, bool]:
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        names = [only] if only else list(CHANNELS)
        results = await asyncio.gather(*(CHANNELS[n](client, alert, resolved) for n in names), return_exceptions=True)
    return {n: (r is True) for n, r in zip(names, results)}


# ---------------------------------------------------------------------------
# Rapport quotidien : résumé sur chaque canal, rapport complet en pièce jointe par email
# ---------------------------------------------------------------------------
REPORT_EMOJI = {"bad": "🔴", "warn": "🟠", "good": "🟢"}
REPORT_COLOR = {"bad": 0xD03B3B, "warn": 0xFAB219, "good": 0x0CA30C}
_ACTION_SEV = {"critical": "Critique", "high": "Élevée"}


def _report_text(r: dict) -> tuple[str, str]:
    day = datetime.strptime(r["date"], "%Y-%m-%d").strftime("%d/%m/%Y")
    title = f"{REPORT_EMOJI[r['verdict']]} Rapport du {day} — {r['verdict_label']}"
    lines = [
        r["headline"],
        f"Score de sécurité : {r['score']}/100 ({r['grade']})",
        f"Serveur : CPU max {r['cpu_max']:.0f} % · mémoire max {r['mem_max']:.0f} % · disque {r['disk_max']:.0f} %",
    ]
    if r["actions"]:
        lines.append("")
        lines.append("À faire :")
        lines += [f"• [{_ACTION_SEV.get(s, s)}] {a}" for s, a, _ in r["actions"]]
    return title, "\n".join(lines)


async def send_report(r: dict, filename: str, doc: str) -> dict[str, bool]:
    import base64
    title, text = _report_text(r)
    e = html.escape
    results: dict[str, bool] = {}
    async with httpx.AsyncClient(timeout=httpx.Timeout(20.0)) as client:
        key, sender, to = S.get("brevo_api_key"), S.get("brevo_sender"), S.get("email_to")
        if S.get("email_enabled") and key and sender and to:
            color = "#%06x" % REPORT_COLOR[r["verdict"]]
            requests = f"{r['requests']:,}".replace(",", " ")
            actions = "".join(
                f'<tr><td style="padding:6px 0;vertical-align:top;width:90px;font-size:12px;font-weight:600;color:{"#b42d2d" if s == "critical" else "#a05a00"}">{e(_ACTION_SEV.get(s, s))}</td>'
                f'<td style="padding:6px 0;font-size:14px;color:#1b2230"><b>{e(a)}</b><br><span style="color:#5d6675;font-size:13px">{e(d)}</span></td></tr>'
                for s, a, d in r["actions"])
            body = f"""<!DOCTYPE html><html><body style="margin:0;background:#f5f6f8;font-family:system-ui,-apple-system,Segoe UI,sans-serif">
<div style="max-width:600px;margin:24px auto;background:#fff;border-radius:12px;overflow:hidden;border:1px solid #e3e6eb">
  <div style="border-left:6px solid {color};padding:18px 24px;background:#fafbfc">
    <div style="font-size:12px;color:#5d6675">{e(config.INSTANCE_NAME)} · rapport du {e(datetime.strptime(r['date'], '%Y-%m-%d').strftime('%d/%m/%Y'))}</div>
    <div style="font-size:20px;font-weight:700;color:{color};margin-top:2px">{e(r['verdict_label'])}</div>
    <div style="font-size:14px;color:#1b2230;margin-top:6px">{e(r['headline'])}</div>
  </div>
  <table style="width:100%;border-collapse:collapse;font-size:13px;color:#3a4352"><tr>
    <td style="padding:14px 24px"><div style="color:#5d6675">Score</div><b style="font-size:18px">{r['score']}/100</b></td>
    <td style="padding:14px 8px"><div style="color:#5d6675">Attaques</div><b style="font-size:18px">{r['attacks']}</b></td>
    <td style="padding:14px 8px"><div style="color:#5d6675">Requêtes</div><b style="font-size:18px">{requests}</b></td>
    <td style="padding:14px 8px"><div style="color:#5d6675">Disque</div><b style="font-size:18px">{r['disk_max']:.0f} %</b></td>
  </tr></table>
  <div style="padding:0 24px 20px">
    <div style="font-weight:700;font-size:15px;margin:6px 0 4px;color:#1b2230">Actions prioritaires</div>
    {f'<table style="width:100%;border-collapse:collapse">{actions}</table>' if actions else '<p style="color:#0a6a0a;margin:4px 0">✓ Rien d&#39;urgent aujourd&#39;hui.</p>'}
    <p style="font-size:12px;color:#5d6675;margin:16px 0 0">Rapport complet en pièce jointe (graphiques, conteneurs, vulnérabilités, attaques).</p>
  </div>
</div></body></html>"""
            results["email"] = await _post(client, "https://api.brevo.com/v3/smtp/email", headers={"api-key": key}, json={
                "sender": {"email": sender, "name": config.INSTANCE_NAME},
                "to": [{"email": a.strip()} for a in to.split(",") if a.strip()],
                "subject": title[2:] if title[:1] in REPORT_EMOJI.values() else title,
                "htmlContent": body, "textContent": text,
                "attachment": [{"name": filename, "content": base64.b64encode(doc.encode()).decode()}],
            })
        if S.get("discord_webhook"):
            results["discord"] = await _post(client, S.get("discord_webhook"), json={
                "username": config.INSTANCE_NAME, "allowed_mentions": {"parse": []},
                "embeds": [{"title": title[:240], "description": text[:3800], "color": REPORT_COLOR[r["verdict"]]}]})
        if S.get("slack_webhook"):
            results["slack"] = await _post(client, S.get("slack_webhook"), json={"text": f"*{title}*\n{text[:3500]}"})
        token, chat = S.get("telegram_bot_token"), S.get("telegram_chat_id")
        if token and chat:
            results["telegram"] = await _post(client, f"https://api.telegram.org/bot{token}/sendMessage", json={
                "chat_id": chat, "text": f"<b>{e(title)}</b>\n{e(text[:3500])}", "parse_mode": "HTML", "disable_web_page_preview": True})
        if S.get("webhook_url"):
            results["webhook"] = await _post(client, S.get("webhook_url"), json={
                "instance": config.INSTANCE_NAME, "event": "report.daily",
                "report": {k: r[k] for k in ("date", "verdict", "headline", "score", "grade", "attacks", "requests",
                                             "errors", "alerts", "disk_max", "vulns_critical", "vulns_high")},
                "actions": [{"severity": s, "title": a, "detail": d} for s, a, d in r["actions"]]})
    return results


def configured_channels() -> list[str]:
    out = []
    if S.get("email_enabled") and S.get("brevo_api_key") and S.get("brevo_sender") and S.get("email_to"):
        out.append("email")
    if S.get("discord_webhook"):
        out.append("discord")
    if S.get("slack_webhook"):
        out.append("slack")
    if S.get("telegram_bot_token") and S.get("telegram_chat_id"):
        out.append("telegram")
    if S.get("webhook_url"):
        out.append("webhook")
    return out
