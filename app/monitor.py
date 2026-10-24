"""
Orchestrateur : relie logs, métriques, événements Docker, alertes et tâches planifiées.
"""
from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Optional

from . import config, db, reports
from . import settings_store as S
from .alerts import FROM_DETECTION, alerts
from .collectors import docker_watch as D
from .collectors.host import get_sampler
from .detection.engine import analyze, analyze_request, is_success
from .detection.parsers import is_private_ip
from .hub import hub
from .security import account_limiter, ip_limiter
from .traffic import traffic
from .vuln import audit, scanner


def _fmt_bytes(n: float) -> str:
    for unit in ("o", "Ko", "Mo", "Go", "To"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} Po"


class Monitor:
    def __init__(self) -> None:
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.watcher = D.LogWatcher(self._on_lines_thread)
        self.events: Optional[D.EventWatcher] = None
        self.tasks: list[asyncio.Task] = []

        self.host_now: dict = {}
        self.host_minute: deque = deque(maxlen=60)   # moyennes par minute (cpu, mem)
        self._host_acc: list[dict] = []
        self.containers: list[dict] = []
        self.container_stats: dict[str, dict] = {}
        self.docker_df: dict = {}
        self.docker_info: dict = {}
        self.tls: list[dict] = []

        self._pending_events: list[dict] = []
        self._recent_keys: dict[tuple, tuple[float, dict]] = {}
        self._ip_attacks: dict[str, deque] = defaultdict(deque)
        self._kills: dict[str, float] = {}
        self._starts: dict[str, deque] = defaultdict(lambda: deque(maxlen=20))
        self.lines_total = 0
        self.ingest_sources: dict[str, dict] = {}    # source -> {last_ts, received, attacks}
        self.started = time.time()
        self._sync_now = asyncio.Event()
        self._bg: set[asyncio.Task] = set()

    def _spawn(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._bg.add(task)
        task.add_done_callback(self._bg.discard)

    # ------------------------------------------------------------------
    async def start(self) -> None:
        self.loop = asyncio.get_running_loop()
        self.events = D.EventWatcher(self._on_docker_event_thread)
        self.events.start()
        for coro in (self._containers_loop(), self._host_loop(), self._flush_loop(),
                     self._slow_loop(), self._daily_loop()):
            self.tasks.append(asyncio.create_task(self._guard(coro)))

    async def stop(self) -> None:
        for t in self.tasks:
            t.cancel()
        if self.events:
            self.events.stop()
        self.watcher.stop_all()
        await self._flush()

    async def _guard(self, coro) -> None:
        """Une erreur inattendue ne doit jamais arrêter une boucle de surveillance."""
        name = coro.__name__
        while True:
            try:
                await coro
                return
            except asyncio.CancelledError:
                raise
            except Exception as e:
                print(f"LogSonar: erreur dans {name} : {type(e).__name__}: {e} — redémarrage dans 10 s")
                await asyncio.sleep(10)
                coro = getattr(self, name)()

    # ------------------------------------------------------------------
    # Logs
    # ------------------------------------------------------------------
    def _on_lines_thread(self, container: str, lines: list[str], replay: bool) -> None:
        if self.loop and not self.loop.is_closed():
            self.loop.call_soon_threadsafe(self._ingest, container, lines, replay)

    def _ingest(self, container: str, lines: list[str], replay: bool) -> None:
        live = hub.listeners > 0
        for line in lines:
            self.lines_total += 1
            event = analyze(line, container, replay=replay)
            traffic.record(event)
            if live:
                hub.publish("log", {k: event[k] for k in (
                    "ts", "container", "kind", "ip", "method", "path", "status", "attack_type", "severity", "raw")})
            if event["attack_type"]:
                self._on_attack(event)

    def ingest_requests(self, source: str, requests: list[dict]) -> int:
        """Requêtes complètes (avec leur corps) envoyées par le middleware d'une application."""
        stats = self.ingest_sources.setdefault(source, {"last_ts": 0.0, "received": 0, "attacks": 0})
        if len(self.ingest_sources) > 50:  # borne mémoire
            oldest = min(self.ingest_sources, key=lambda k: self.ingest_sources[k]["last_ts"])
            self.ingest_sources.pop(oldest, None)
        live = hub.listeners > 0
        attacks = 0
        for req in requests:
            if not isinstance(req, dict):
                continue
            event = analyze_request(req, source)
            stats["received"] += 1
            if event["attack_type"]:
                attacks += 1
                if live:
                    hub.publish("log", {k: event[k] for k in (
                        "ts", "container", "kind", "ip", "method", "path", "status", "attack_type", "severity", "raw")})
                self._on_attack(event)
        stats["last_ts"] = time.time()
        stats["attacks"] += attacks
        return attacks

    def _is_duplicate(self, ev: dict) -> bool:
        """
        Derrière un reverse proxy, une même attaque apparaît dans les logs du proxy
        (IP réelle) et de l'application (IP interne). On n'en garde qu'une, avec l'IP réelle.
        """
        now = ev["ts"]
        if len(self._recent_keys) > 5000:
            self._recent_keys = {k: v for k, v in self._recent_keys.items() if now - v[0] < 5}
        key = (ev["method"], ev["path"], ev["attack_type"])
        prev = self._recent_keys.get(key)
        if prev and now - prev[0] < 5:
            first = prev[1]
            if first["ip"] == ev["ip"]:
                return True
            if is_private_ip(first["ip"]) and ev["ip"] and not is_private_ip(ev["ip"]):
                first["ip"], first["ua"] = ev["ip"], ev["ua"] or first["ua"]
                return True
            if is_private_ip(ev["ip"]) and first["ip"] and not is_private_ip(first["ip"]):
                return True
        self._recent_keys[key] = (now, ev)
        return False

    def _on_attack(self, ev: dict) -> None:
        if ev["kind"] == "web" and self._is_duplicate(ev):
            return
        self._pending_events.append(ev)
        self._spawn(self._security_alerts(ev))

    async def _security_alerts(self, ev: dict) -> None:
        ip = ev["ip"] or "IP inconnue"
        typ, sev = ev["attack_type"], ev["severity"]
        where = f"{ev['container']}"
        target = f"{ev['method']} {ev['path'][:200]}".strip()
        msg = f"Source : {ip}\nConteneur : {where}\nRequête : {target}\nRéponse : {ev['status'] or '—'}"
        if ev.get("detail"):
            msg += f"\nDétail : {ev['detail']}"
        msg += f"\n\nLog :\n{ev['raw'][:800]}"

        if typ == "Force brute":
            await alerts.raise_alert(f"brute:{ip}", "security", "high", f"Force brute depuis {ip}", msg, where)
        elif typ == "Flood":
            await alerts.raise_alert(f"flood:{ip}", "security", "warning", f"Volume de requêtes anormal depuis {ip}", msg, where)
        elif sev == "critical":
            await alerts.raise_alert(f"attack:{typ}:{ip}", "security", "critical", f"{typ} — {ip}", msg, where)
        elif sev == "high" and is_success(ev["status"]):
            await alerts.raise_alert(
                f"attack-ok:{typ}:{ip}", "security", "high", f"{typ} acceptée par le serveur (HTTP {ev['status']}) — {ip}",
                msg + "\n\nLe serveur a répondu avec succès : vérifiez que la requête a bien été neutralisée.", where,
            )

        # Campagne : beaucoup d'attaques depuis la même IP
        if ev["ip"] and not is_private_ip(ev["ip"]):
            q = self._ip_attacks[ev["ip"]]
            now = time.time()
            q.append(now)
            while q and now - q[0] > 600:
                q.popleft()
            threshold = S.get("attack_campaign_threshold")
            if len(q) >= threshold:
                await alerts.raise_alert(
                    f"campaign:{ev['ip']}", "security", "warning",
                    f"Campagne d'attaque depuis {ev['ip']} ({len(q)} tentatives en 10 min)",
                    f"Dernière tentative : {typ} sur {where}\n{target}\n\nEnvisagez de bannir cette IP (pare-feu, Fail2Ban, CrowdSec).",
                    where,
                )
            if len(self._ip_attacks) > 20000:
                for k in [k for k, v in self._ip_attacks.items() if not v or now - v[-1] > 600]:
                    del self._ip_attacks[k]

    async def _flush(self) -> None:
        if not self._pending_events:
            return
        batch, self._pending_events = self._pending_events, []
        await db.executemany(
            "INSERT INTO security_events (ts, container, ip, method, path, status, attack_type, severity, ua, raw)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(e["ts"], e["container"], e["ip"], e["method"], e["path"][:2000], e["status"], e["attack_type"],
              e["severity"], e["ua"][:500], e["raw"][:4000]) for e in batch],
        )

    async def _flush_loop(self) -> None:
        while True:
            await asyncio.sleep(2)
            await self._flush()

    # ------------------------------------------------------------------
    # Docker : conteneurs, événements, statistiques
    # ------------------------------------------------------------------
    def _on_docker_event_thread(self, ev: dict) -> None:
        if self.loop and not self.loop.is_closed():
            self.loop.call_soon_threadsafe(lambda: self._spawn(self._on_docker_event(ev)))

    async def _on_docker_event(self, ev: dict) -> None:
        action = ev.get("Action") or ev.get("status") or ""
        actor = ev.get("Actor") or {}
        attrs = actor.get("Attributes") or {}
        name = attrs.get("name", "")
        if not name or attrs.get("logsonar.role") or str(attrs.get("logsonar.enable", "true")).lower() == "false":
            return
        if D.OWN_ID and (actor.get("ID", "").startswith(D.OWN_ID)):
            return
        now = time.time()

        if action == "kill":
            self._kills[name] = now
        elif action == "die":
            code = attrs.get("exitCode", "0")
            intentional = now - self._kills.get(name, 0) < 30
            if code not in ("0", "") and not intentional:
                hint = " (mémoire insuffisante probable)" if code == "137" else ""
                await alerts.raise_alert(
                    f"container:{name}:down", "container", "high",
                    f"Le conteneur {name} s'est arrêté (code {code}){hint}",
                    f"Le conteneur s'est arrêté de lui-même avec le code de sortie {code}.\n"
                    f"Consultez ses derniers logs : docker logs --tail 100 {name}", name,
                )
        elif action == "oom":
            await alerts.raise_alert(
                f"container:{name}:oom", "container", "high", f"Mémoire saturée dans {name} (OOM)",
                "Le noyau a tué un processus du conteneur faute de mémoire. Augmentez sa limite ou cherchez une fuite mémoire.", name,
            )
        elif action == "start":
            await alerts.resolve(f"container:{name}:down")
            q = self._starts[name]
            q.append(now)
            recent = [t for t in q if now - t < 600]
            if len(recent) >= 4:
                await alerts.raise_alert(
                    f"container:{name}:loop", "container", "critical", f"{name} redémarre en boucle",
                    f"{len(recent)} démarrages en 10 minutes : l'application plante au lancement.\n"
                    f"docker logs --tail 100 {name}", name,
                )
            self._sync_now.set()
        elif action.startswith("health_status"):
            status = action.split(":", 1)[-1].strip()
            if status == "unhealthy":
                await alerts.raise_alert(
                    f"container:{name}:health", "container", "warning", f"{name} ne répond plus (healthcheck en échec)",
                    "Le healthcheck Docker échoue : le service est démarré mais ne fonctionne pas correctement.", name,
                )
            elif status == "healthy":
                await alerts.resolve(f"container:{name}:health")
        elif action in ("destroy",):
            traffic.forget(name)
            for suffix in ("down", "health", "loop", "mem", "oom"):
                await alerts.resolve(f"container:{name}:{suffix}")
        if action in ("start", "die", "destroy", "pause", "unpause"):
            self._sync_now.set()

    async def _containers_loop(self) -> None:
        last_store = 0.0
        while True:
            try:
                containers = await D.state.run(D.list_containers, True)
                if not D.state.connected:
                    D.state.connected = True
                    await alerts.resolve("docker:down")
                    try:
                        self.docker_info = await D.state.run(D.docker_info)
                    except Exception:
                        pass
            except Exception as e:
                D.state.connected = False
                D.state.last_error = f"{type(e).__name__}: {e}"[:300]
                D.state.reset()
                await alerts.raise_alert(
                    "docker:down", "system", "critical", "Docker inaccessible",
                    f"LogSonar ne parvient plus à joindre l'API Docker : la surveillance des conteneurs est interrompue.\n{D.state.last_error}",
                    "Docker",
                )
                await self._wait_sync(10)
                continue

            self.watcher.sync(containers)
            running = [c for c in containers if c["state"] == "running"]

            async def one(c):
                try:
                    return c["name"], await D.state.run(D.container_stats, c["id"])
                except Exception:
                    return c["name"], None

            results = await asyncio.gather(*(one(c) for c in running))
            self.container_stats = {n: s for n, s in results if s}
            D.forget_stats({c["id"] for c in running})
            for c in containers:
                c["stats"] = self.container_stats.get(c["name"])
                c["watched"] = c["name"] in self.watcher.watched_names()
                c["muted"] = c["name"] in S.get("muted_containers")
            self.containers = containers
            hub.publish("containers", containers)

            now = time.time()
            for c in running:
                st = c.get("stats") or {}
                fp = f"container:{c['name']}:mem"
                if st.get("mem_pct") is not None and st["mem_pct"] >= 90:
                    await alerts.raise_alert(
                        fp, "container", "warning", f"{c['name']} utilise {st['mem_pct']:.0f} % de sa limite mémoire",
                        f"{_fmt_bytes(st['mem_bytes'])} / {_fmt_bytes(st['mem_limit'])}. Le conteneur risque d'être tué (OOM).", c["name"],
                    )
                elif alerts.is_open(fp) and (st.get("mem_pct") or 0) < 85:
                    await alerts.resolve(fp)
                loop_fp = f"container:{c['name']}:loop"
                if alerts.is_open(loop_fp) and all(now - t > 900 for t in self._starts.get(c["name"], [])):
                    await alerts.resolve(loop_fp)

            if now - last_store >= 60:
                last_store = now
                await db.executemany(
                    "INSERT OR REPLACE INTO container_metrics (ts, name, cpu, mem_bytes, mem_pct) VALUES (?, ?, ?, ?, ?)",
                    [(int(now), n, s.get("cpu"), s.get("mem_bytes"), s.get("mem_pct")) for n, s in self.container_stats.items()],
                )
            await self._wait_sync(15)

    async def _wait_sync(self, timeout: float) -> None:
        try:
            await asyncio.wait_for(self._sync_now.wait(), timeout)
            await asyncio.sleep(1)  # regroupe les événements rapprochés
        except asyncio.TimeoutError:
            pass
        self._sync_now.clear()

    # ------------------------------------------------------------------
    # Serveur : métriques et seuils
    # ------------------------------------------------------------------
    async def _host_loop(self) -> None:
        sampler = await asyncio.to_thread(get_sampler)
        last_minute = int(time.time() // 60)
        while True:
            sample = await asyncio.to_thread(sampler.sample)
            sample["traffic"] = traffic.last_minute()
            self.host_now = sample
            self._host_acc.append(sample)
            hub.publish("host", sample)

            minute = int(time.time() // 60)
            if minute != last_minute:
                last_minute = minute
                await self._store_minute()
            await asyncio.sleep(10)

    async def _store_minute(self) -> None:
        acc, self._host_acc = self._host_acc, []
        if not acc:
            return
        avg = lambda key: sum(s[key] for s in acc if s.get(key) is not None) / max(len([s for s in acc if s.get(key) is not None]), 1)
        cpu = avg("cpu")
        mem = sum(s["mem"]["percent"] for s in acc) / len(acc)
        swap = sum(s["swap"]["percent"] for s in acc) / len(acc)
        last = acc[-1]
        t = traffic.last_minute()
        self.host_minute.append({"cpu": cpu, "mem": mem})
        await db.execute(
            "INSERT OR REPLACE INTO host_metrics (ts, cpu, mem, swap, disk, load1, net_rx, net_tx, req_rate, err_rate, attack_rate)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (int(time.time() // 60 * 60), round(cpu, 1), round(mem, 1), round(swap, 1), last.get("disk_max"),
             last["load"][0], sum(s["net"]["rx_rate"] for s in acc) / len(acc),
             sum(s["net"]["tx_rate"] for s in acc) / len(acc), t["requests"], t["errors"], t["attacks"]),
        )
        await self._evaluate(last, t)

    async def _evaluate(self, sample: dict, t: dict) -> None:
        n = max(S.get("metric_duration_min"), 1)
        window = list(self.host_minute)[-n:]
        if len(window) >= n:
            for key, label in (("cpu", "Processeur"), ("mem", "Mémoire")):
                lowest = min(w[key] for w in window)
                warn, crit = S.get(f"{key}_warn"), S.get(f"{key}_crit")
                fp = f"host:{key}"
                if lowest >= crit:
                    await alerts.raise_alert(fp, "host", "critical", f"{label} saturé : {lowest:.0f} % depuis {n} min",
                                             self._host_context(sample), "Serveur")
                elif lowest >= warn:
                    await alerts.raise_alert(fp, "host", "warning", f"{label} élevé : {lowest:.0f} % depuis {n} min",
                                             self._host_context(sample), "Serveur")
                elif window[-1][key] < warn - 5:
                    await alerts.resolve(fp)

        keep = set()
        for d in sample.get("disks") or []:
            fp = f"host:disk:{d['mount']}"
            warn, crit = S.get("disk_warn"), S.get("disk_crit")
            msg = (f"{d['mount']} : {_fmt_bytes(d['used'])} utilisés sur {_fmt_bytes(d['total'])} "
                   f"({_fmt_bytes(d['free'])} libres).")
            if self.docker_df.get("reclaimable", 0) > 1024 ** 3:
                msg += f"\nDocker peut libérer {_fmt_bytes(self.docker_df['reclaimable'])} : docker system prune (images inutilisées, cache de build)."
            if d["percent"] >= crit:
                keep.add(fp)
                await alerts.raise_alert(fp, "host", "critical", f"Disque {d['mount']} presque plein ({d['percent']:.0f} %)", msg, "Serveur")
            elif d["percent"] >= warn:
                keep.add(fp)
                await alerts.raise_alert(fp, "host", "warning", f"Disque {d['mount']} rempli à {d['percent']:.0f} %", msg, "Serveur")
            elif alerts.is_open(fp) and d["percent"] >= warn - 2:
                keep.add(fp)  # hystérésis : évite l'alternance ouverte/résolue
        await alerts.resolve_prefix("host:disk:", keep)

        # Trafic
        rpm = t["requests"]
        fixed = S.get("traffic_rpm_threshold")
        baseline = traffic.baseline_rpm()
        limit = fixed if fixed > 0 else (max(baseline * S.get("traffic_spike_factor"), S.get("traffic_min_rpm")) if baseline else 0)
        if limit and rpm > limit:
            sev = "high" if rpm > limit * 2 else "warning"
            top = traffic.summary(5)
            tops = ", ".join(f"{x['ip']} ({x['count']})" for x in top["top_ips"][:5])
            await alerts.raise_alert(
                "traffic:spike", "traffic", sev, f"Trafic élevé : {rpm} requêtes/min",
                f"Seuil : {limit:.0f} req/min" + (f" (normale : {baseline:.0f})" if not fixed else "") +
                f"\nIP les plus actives : {tops or '—'}", "Trafic",
            )
        elif alerts.is_open("traffic:spike") and (not limit or rpm < limit * 0.8):
            await alerts.resolve("traffic:spike")

        if rpm >= 30 and t["errors"] / rpm * 100 >= S.get("error_rate_threshold"):
            pct = t["errors"] / rpm * 100
            await alerts.raise_alert(
                "traffic:errors", "traffic", "high", f"{pct:.0f} % de réponses en erreur serveur (5xx)",
                f"{t['errors']} erreurs 5xx sur {rpm} requêtes la dernière minute. L'application ou sa base de données a probablement un problème.",
                "Trafic",
            )
        elif alerts.is_open("traffic:errors") and (rpm == 0 or t["errors"] / max(rpm, 1) * 100 < S.get("error_rate_threshold") / 2):
            await alerts.resolve("traffic:errors")

    def _host_context(self, sample: dict) -> str:
        lines = [
            f"CPU : {sample['cpu']:.0f} % · charge {sample['load'][0]} ({sample['cpu_count']} cœurs)",
            f"Mémoire : {_fmt_bytes(sample['mem']['used'])} / {_fmt_bytes(sample['mem']['total'])} ({sample['mem']['percent']:.0f} %)",
        ]
        top = sorted(self.container_stats.items(), key=lambda kv: -(kv[1].get("cpu") or 0))[:3]
        if top:
            lines.append("Conteneurs les plus actifs : " + ", ".join(
                f"{n} ({s.get('cpu') or 0:.0f} % CPU, {_fmt_bytes(s.get('mem_bytes') or 0)})" for n, s in top))
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Tâches lentes et quotidiennes
    # ------------------------------------------------------------------
    async def _slow_loop(self) -> None:
        last_df = last_tls = 0.0
        while True:
            now = time.time()
            if D.state.connected and now - last_df > 600:
                last_df = now
                try:
                    self.docker_df = await D.state.run(D.disk_usage)
                except Exception as e:
                    print(f"LogSonar: occupation disque Docker indisponible ({type(e).__name__})")
            if now - last_tls > 6 * 3600:
                last_tls = now
                await self.check_tls()
            await alerts.resolve_stale("security", 3600)
            account_limiter.cleanup()
            ip_limiter.cleanup()
            await asyncio.sleep(60)

    async def check_tls(self) -> list[dict]:
        domains = audit.parse_domains(S.get("tls_domains"))
        self.tls = await audit.check_tls(domains) if domains else []
        warn_days = S.get("tls_warn_days")
        keep = set()
        for r in self.tls:
            fp = f"tls:{r['domain']}:{r['port']}"
            if not r["ok"]:
                keep.add(fp)
                await alerts.raise_alert(fp, "tls", "high", f"Certificat TLS en erreur : {r['domain']}", r["error"], "TLS")
            elif r["days_left"] is not None and r["days_left"] <= warn_days:
                keep.add(fp)
                sev = "critical" if r["days_left"] <= 3 else "warning"
                await alerts.raise_alert(fp, "tls", sev, f"Le certificat de {r['domain']} expire dans {r['days_left']} jour(s)",
                                         f"Émetteur : {r['issuer']}. Vérifiez le renouvellement automatique (certbot, Traefik, Caddy).", "TLS")
        await alerts.resolve_prefix("tls:", keep)
        return self.tls

    async def _get_meta(self, key: str) -> str:
        return await db.scalar("SELECT value FROM meta WHERE key = ?", (key,)) or ""

    async def _set_meta(self, key: str, value: str) -> None:
        await db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))

    async def _daily_loop(self) -> None:
        await asyncio.sleep(20)
        # Premier scan de sécurité peu après le tout premier démarrage
        if not await db.scalar("SELECT COUNT(*) FROM vuln_scans"):
            await scanner.start_scan()
        while True:
            now = datetime.now()
            today = now.strftime("%Y-%m-%d")
            yesterday = (now - timedelta(days=1)).strftime("%Y-%m-%d")

            if await self._get_meta("last_report_for") != yesterday:
                if not (config.REPORT_DIR / f"rapport_{yesterday}.html").exists():
                    await reports.generate(yesterday, send=S.get("report_notify"))
                await db.purge_old_data()
                await self._set_meta("last_report_for", yesterday)

            if now.hour >= config.VULN_SCAN_HOUR and await self._get_meta("last_scan_day") != today:
                await self._set_meta("last_scan_day", today)
                await scanner.start_scan()
            await asyncio.sleep(300)


monitor = Monitor()
