"""
Surveillance Docker : lecture des logs, événements (crash, OOM, santé),
statistiques de ressources et occupation disque.

Chaque flux de logs a son propre thread (les flux sont bloquants et durent
indéfiniment) ; les appels ponctuels passent par un petit pool dédié. Ainsi,
même avec 50 conteneurs, l'API Docker reste disponible pour le reste.

LogSonar n'a besoin que d'un accès en LECTURE à l'API Docker (voir le proxy
de socket dans docker-compose.yml) : il n'exécute rien dans les conteneurs.
"""
from __future__ import annotations

import asyncio
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

import docker
from docker.errors import DockerException, NotFound

from .. import config
from .. import settings_store as S

executor = ThreadPoolExecutor(max_workers=6, thread_name_prefix="docker-api")


def _own_container_id() -> str:
    """Identifiant du conteneur LogSonar lui-même (pour ne pas s'auto-surveiller)."""
    try:
        with open("/proc/self/mountinfo") as f:
            for line in f:
                if "/docker/containers/" in line:
                    return line.split("/docker/containers/")[1].split("/")[0]
    except OSError:
        pass
    return os.environ.get("HOSTNAME", "")


OWN_ID = _own_container_id()


class DockerState:
    """Client Docker partagé et accès asynchrone via le pool dédié."""

    def __init__(self) -> None:
        self._client: Optional[docker.DockerClient] = None
        self._lock = threading.Lock()
        self.connected = False
        self.last_error = ""
        self.info: dict = {}

    def client(self) -> docker.DockerClient:
        with self._lock:
            if self._client is None:
                self._client = docker.DockerClient(base_url=config.DOCKER_URL, timeout=30, max_pool_size=128)
            return self._client

    def reset(self) -> None:
        with self._lock:
            if self._client is not None:
                try:
                    self._client.close()
                except Exception:
                    pass
            self._client = None

    async def run(self, fn: Callable, *args):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(executor, fn, *args)


state = DockerState()


def is_ignored(attrs: dict) -> bool:
    cid = attrs.get("Id", "")
    if OWN_ID and (cid.startswith(OWN_ID) or OWN_ID.startswith(cid[:12])):
        return True
    labels = (attrs.get("Config") or {}).get("Labels") or attrs.get("Labels") or {}
    if str(labels.get("logsonar.enable", "true")).lower() == "false":
        return True
    if labels.get("logsonar.role"):  # composants de LogSonar (proxy de socket)
        return True
    return False


def container_name(attrs: dict) -> str:
    name = attrs.get("Name") or (attrs.get("Names") or ["?"])[0]
    return name.lstrip("/")


def list_containers(all_: bool = False) -> list[dict]:
    """Résumé des conteneurs (appel bloquant)."""
    raw = state.client().api.containers(all=all_)
    out = []
    for c in raw:
        if is_ignored(c):
            continue
        out.append({
            "id": c["Id"],
            "name": container_name(c),
            "image": c.get("Image", ""),
            "state": c.get("State", ""),
            "status": c.get("Status", ""),
            "created": c.get("Created", 0),
            "ports": [
                {"ip": p.get("IP", ""), "public": p.get("PublicPort"), "private": p.get("PrivatePort"), "type": p.get("Type")}
                for p in c.get("Ports", [])
            ],
            "labels": c.get("Labels") or {},
            "compose_project": (c.get("Labels") or {}).get("com.docker.compose.project", ""),
        })
    return out


def inspect(cid: str) -> dict:
    return state.client().api.inspect_container(cid)


# ---------------------------------------------------------------------------
# Lecture des logs
# ---------------------------------------------------------------------------
LineHandler = Callable[[str, list[str], bool], None]  # (nom, lignes, rattrapage)


class LogReader(threading.Thread):
    def __init__(self, cid: str, name: str, since: Optional[float], on_lines: LineHandler) -> None:
        super().__init__(name=f"logs-{name}", daemon=True)
        self.cid = cid
        self.cname = name
        self.since = since
        self.on_lines = on_lines
        self._stream = None
        self._stop = threading.Event()
        self.last_seen = time.time()

    def stop(self) -> None:
        self._stop.set()
        stream = self._stream
        if stream is not None:
            try:
                stream.close()
            except Exception:
                pass

    def run(self) -> None:
        replay = self.since is not None
        since = int(self.since) if self.since else int(time.time())
        buffer = ""
        try:
            self._stream = state.client().api.logs(
                self.cid, stream=True, follow=True, stdout=True, stderr=True, since=since, timestamps=False,
            )
            replay_until = time.time() + 2 if replay else 0
            for chunk in self._stream:
                if self._stop.is_set():
                    break
                self.last_seen = time.time()
                buffer += chunk.decode("utf-8", errors="replace")
                if "\n" not in buffer:
                    if len(buffer) > 65536:  # ligne interminable : on coupe
                        self.on_lines(self.cname, [buffer], False)
                        buffer = ""
                    continue
                *lines, buffer = buffer.split("\n")
                lines = [ln.rstrip("\r") for ln in lines if ln.strip()]
                if lines:
                    self.on_lines(self.cname, lines, time.time() < replay_until)
        except NotFound:
            pass
        except Exception as e:
            if not self._stop.is_set():
                print(f"LogSonar: flux de logs interrompu pour {self.cname} ({type(e).__name__})")
        finally:
            if buffer.strip():
                self.on_lines(self.cname, [buffer], False)


class LogWatcher:
    """Garde un lecteur actif par conteneur en marche, et le relance si besoin."""

    def __init__(self, on_lines: LineHandler) -> None:
        self.on_lines = on_lines
        self.readers: dict[str, LogReader] = {}   # par id de conteneur
        self.last_seen: dict[str, float] = {}     # par id : pour reprendre sans trou

    def sync(self, containers: list[dict]) -> None:
        muted = set(S.get("muted_containers"))
        running = {c["id"]: c for c in containers if c["state"] == "running" and c["name"] not in muted}

        for cid in list(self.readers):
            reader = self.readers[cid]
            if cid not in running or not reader.is_alive():
                self.last_seen[cid] = reader.last_seen
                reader.stop()
                del self.readers[cid]

        for cid, c in running.items():
            if cid not in self.readers:
                since = self.last_seen.get(cid)
                # Reprise après coupure récente : on rattrape les lignes manquées.
                if since and time.time() - since > 3600:
                    since = None
                reader = LogReader(cid, c["name"], since, self.on_lines)
                self.readers[cid] = reader
                reader.start()

        for cid in [cid for cid in self.last_seen if cid not in running and cid not in self.readers]:
            if time.time() - self.last_seen[cid] > 7200:
                del self.last_seen[cid]

    def stop_all(self) -> None:
        for reader in self.readers.values():
            reader.stop()
        self.readers.clear()

    def watched_names(self) -> list[str]:
        return sorted(r.cname for r in self.readers.values())


# ---------------------------------------------------------------------------
# Événements Docker (crash, OOM, santé)
# ---------------------------------------------------------------------------
class EventWatcher(threading.Thread):
    def __init__(self, on_event: Callable[[dict], None]) -> None:
        super().__init__(name="docker-events", daemon=True)
        self.on_event = on_event
        self._stop = threading.Event()
        self._stream = None

    def stop(self) -> None:
        self._stop.set()
        if self._stream is not None:
            try:
                self._stream.close()
            except Exception:
                pass

    def run(self) -> None:
        delay = 1
        while not self._stop.is_set():
            try:
                self._stream = state.client().api.events(
                    decode=True, filters={"type": "container"}, since=int(time.time()),
                )
                delay = 1
                for ev in self._stream:
                    if self._stop.is_set():
                        break
                    self.on_event(ev)
            except Exception as e:
                if self._stop.is_set():
                    break
                print(f"LogSonar: flux d'événements Docker interrompu ({type(e).__name__}), reprise dans {delay}s")
            self._stop.wait(delay)
            delay = min(delay * 2, 30)


# ---------------------------------------------------------------------------
# Statistiques de ressources
# ---------------------------------------------------------------------------
_prev_cpu: dict[str, tuple[int, int]] = {}


def container_stats(cid: str) -> dict:
    """Une mesure ponctuelle ; le % CPU est calculé avec la mesure précédente."""
    api = state.client().api
    try:
        raw = api.stats(cid, stream=False, one_shot=True)
    except TypeError:
        raw = api.stats(cid, stream=False)
    cpu = raw.get("cpu_stats") or {}
    total = (cpu.get("cpu_usage") or {}).get("total_usage", 0)
    system = cpu.get("system_cpu_usage", 0)
    ncpu = cpu.get("online_cpus") or len((cpu.get("cpu_usage") or {}).get("percpu_usage") or []) or 1
    cpu_pct = None
    prev = _prev_cpu.get(cid)
    if prev and system > prev[1] and total >= prev[0]:
        cpu_pct = round((total - prev[0]) / (system - prev[1]) * ncpu * 100, 1)
    _prev_cpu[cid] = (total, system)

    mem = raw.get("memory_stats") or {}
    mstats = mem.get("stats") or {}
    usage = mem.get("usage", 0) - mstats.get("inactive_file", mstats.get("total_inactive_file", mstats.get("cache", 0)))
    limit = mem.get("limit", 0)
    rx = tx = 0
    for net in (raw.get("networks") or {}).values():
        rx += net.get("rx_bytes", 0)
        tx += net.get("tx_bytes", 0)
    return {
        "cpu": cpu_pct,
        "mem_bytes": max(usage, 0),
        "mem_limit": limit,
        "mem_pct": round(usage / limit * 100, 1) if limit else None,
        "net_rx": rx, "net_tx": tx,
        "pids": (raw.get("pids_stats") or {}).get("current"),
    }


def forget_stats(active_ids: set[str]) -> None:
    for cid in [c for c in _prev_cpu if c not in active_ids]:
        del _prev_cpu[cid]


def disk_usage() -> dict:
    """Espace occupé par Docker (images, volumes, cache de build) et part récupérable."""
    df = state.client().api.df()
    images = df.get("Images") or []
    volumes = df.get("Volumes") or []
    cache = df.get("BuildCache") or []
    containers = df.get("Containers") or []
    img_total = df.get("LayersSize") or sum(i.get("Size", 0) for i in images)
    img_unused = sum(i.get("Size", 0) - max(i.get("SharedSize", 0), 0) for i in images if i.get("Containers", 0) == 0)
    vol_total = sum(max((v.get("UsageData") or {}).get("Size", 0), 0) for v in volumes)
    vol_unused = sum(max((v.get("UsageData") or {}).get("Size", 0), 0) for v in volumes if (v.get("UsageData") or {}).get("RefCount", 1) == 0)
    cache_total = sum(c.get("Size", 0) for c in cache)
    cache_unused = sum(c.get("Size", 0) for c in cache if not c.get("InUse"))
    ctr_total = sum(c.get("SizeRw", 0) or 0 for c in containers)
    return {
        "images": {"count": len(images), "size": img_total, "reclaimable": max(img_unused, 0)},
        "volumes": {"count": len(volumes), "size": vol_total, "reclaimable": vol_unused},
        "build_cache": {"count": len(cache), "size": cache_total, "reclaimable": cache_unused},
        "containers": {"count": len(containers), "size": ctr_total},
        "total": img_total + vol_total + cache_total + ctr_total,
        "reclaimable": max(img_unused, 0) + vol_unused + cache_unused,
    }


def docker_info() -> dict:
    info = state.client().api.info()
    version = state.client().api.version()
    return {
        "version": version.get("Version", ""),
        "api_version": version.get("ApiVersion", ""),
        "os": info.get("OperatingSystem", ""),
        "kernel": info.get("KernelVersion", ""),
        "cpus": info.get("NCPU"),
        "memory": info.get("MemTotal"),
        "containers": info.get("Containers"),
        "running": info.get("ContainersRunning"),
        "images": info.get("Images"),
        "storage_driver": info.get("Driver", ""),
        "docker_root": info.get("DockerRootDir", ""),
    }


def read_files(cid: str, path: str, max_bytes: int = 64 * 1024 * 1024):
    """
    Lit un fichier ou un dossier d'un conteneur via l'API d'archive (lecture seule,
    rien n'est exécuté dans le conteneur). Retourne un tarfile en flux ou None.
    """
    import io
    import tarfile

    try:
        stream, _stat = state.client().api.get_archive(cid, path)
    except NotFound:
        return None
    except DockerException:
        return None
    buf = io.BytesIO()
    size = 0
    for chunk in stream:
        size += len(chunk)
        if size > max_bytes:
            try:
                stream.close()
            except Exception:
                pass
            return None
        buf.write(chunk)
    buf.seek(0)
    try:
        return tarfile.open(fileobj=buf, mode="r:")
    except tarfile.TarError:
        return None


def read_text(cid: str, path: str, max_bytes: int = 32 * 1024 * 1024) -> Optional[str]:
    tar = read_files(cid, path, max_bytes)
    if tar is None:
        return None
    try:
        for member in tar:
            if member.isfile():
                f = tar.extractfile(member)
                if f:
                    return f.read().decode("utf-8", errors="replace")
            elif member.issym() or member.islnk():
                # Lien symbolique : on suit la cible une fois (ex. /etc/os-release)
                target = member.linkname
                if not target.startswith("/"):
                    target = os.path.normpath(os.path.join(os.path.dirname(path), target))
                if target != path:
                    return read_text(cid, target, max_bytes)
        return None
    finally:
        tar.close()


def list_names(cid: str, path: str, max_bytes: int = 512 * 1024 * 1024) -> Optional[list[str]]:
    """Noms des entrées d'un dossier (premier niveau) sans tout garder en mémoire."""
    import tarfile

    try:
        stream, _ = state.client().api.get_archive(cid, path)
    except (NotFound, DockerException):
        return None

    class _Reader:
        def __init__(self, it):
            self.it = iter(it)
            self.buf = b""
            self.total = 0

        def read(self, n=-1):
            while n < 0 or len(self.buf) < n:
                try:
                    chunk = next(self.it)
                except StopIteration:
                    break
                self.total += len(chunk)
                if self.total > max_bytes:
                    raise IOError("archive trop volumineuse")
                self.buf += chunk
            if n < 0:
                out, self.buf = self.buf, b""
            else:
                out, self.buf = self.buf[:n], self.buf[n:]
            return out

    names = set()
    try:
        with tarfile.open(fileobj=_Reader(stream), mode="r|") as tar:
            for member in tar:
                parts = member.name.split("/")
                if len(parts) >= 2 and parts[1]:
                    names.add(parts[1])
    except (tarfile.TarError, IOError):
        pass
    finally:
        try:
            stream.close()
        except Exception:
            pass
    return sorted(names)
