"""
Métriques du serveur hôte : CPU, mémoire, swap, disques, réseau, processus.

Dans Docker, on lit le /proc et la racine de l'HÔTE, montés en lecture seule
(/host/proc et /hostfs). Sans ces montages, les valeurs sont celles vues
depuis le conteneur (mémoire et CPU restent globaux, mais pas les disques).
"""
from __future__ import annotations

import os
import platform
import socket
import time
from pathlib import Path
from typing import Optional

import psutil

from .. import config

HOST_MODE = config.HOST_PROC.is_dir() and (config.HOST_PROC / "stat").exists()
if HOST_MODE and hasattr(psutil, "PROCFS_PATH"):
    psutil.PROCFS_PATH = str(config.HOST_PROC)
ROOTFS_MODE = config.HOST_ROOT.is_dir() and (config.HOST_ROOT / "etc").is_dir()

REAL_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "reiserfs", "jfs", "vfat", "ntfs", "ntfs3", "exfat"}
SKIP_IFACES = ("lo", "veth", "br-", "docker", "virbr", "cni", "flannel", "cali", "tun", "tap", "vxlan")


def _host_path(p: str) -> str:
    if ROOTFS_MODE:
        return str(config.HOST_ROOT) + (p if p != "/" else "")
    return p


def _read(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return ""


def host_info() -> dict:
    os_name = ""
    release = _read(config.HOST_ROOT / "etc/os-release") if ROOTFS_MODE else _read(Path("/etc/os-release"))
    for line in release.splitlines():
        if line.startswith("PRETTY_NAME="):
            os_name = line.split("=", 1)[1].strip().strip('"')
    if not os_name:
        os_name = f"{platform.system()} {platform.release()}"
    hostname = (_read(config.HOST_ROOT / "etc/hostname").strip() if ROOTFS_MODE else "") or socket.gethostname()
    kernel = _read(config.HOST_PROC / "sys/kernel/osrelease").strip() if HOST_MODE else platform.release()
    try:
        boot = psutil.boot_time()
    except Exception:
        boot = None
    return {
        "hostname": hostname,
        "os": os_name,
        "kernel": kernel,
        "arch": platform.machine(),
        "cpu_count": psutil.cpu_count() or 1,
        "cpu_model": _cpu_model(),
        "mem_total": psutil.virtual_memory().total,
        "boot_time": boot,
        "host_mode": HOST_MODE,
        "rootfs_mode": ROOTFS_MODE,
    }


def _cpu_model() -> str:
    cpuinfo = _read((config.HOST_PROC if HOST_MODE else Path("/proc")) / "cpuinfo")
    for line in cpuinfo.splitlines():
        if line.lower().startswith("model name"):
            return line.split(":", 1)[1].strip()
    return platform.processor()


def disks() -> list[dict]:
    """Systèmes de fichiers réels de l'hôte (hors overlay Docker, tmpfs...)."""
    entries: list[tuple[str, str, str]] = []
    mounts_file = config.HOST_PROC / "1/mounts" if HOST_MODE else Path("/proc/mounts")
    content = _read(mounts_file)
    seen_dev = set()
    for line in content.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        dev, mnt, fstype = parts[0], parts[1].replace("\\040", " "), parts[2]
        if fstype not in REAL_FS or dev in seen_dev or mnt.startswith(("/snap", "/var/lib/docker", "/boot/efi")):
            continue
        seen_dev.add(dev)
        entries.append((dev, mnt, fstype))
    if not entries:
        entries = [("", "/", "")]

    out = []
    for dev, mnt, fstype in entries:
        path = _host_path(mnt)
        try:
            u = psutil.disk_usage(path)
        except (OSError, PermissionError):
            continue
        if u.total == 0:
            continue
        out.append({
            "mount": mnt, "device": dev, "fstype": fstype,
            "total": u.total, "used": u.used, "free": u.free, "percent": round(u.percent, 1),
        })
    out.sort(key=lambda d: d["mount"])
    return out


def _net_counters() -> tuple[int, int]:
    """Octets reçus/envoyés sur les interfaces physiques de l'hôte."""
    netdev = config.HOST_PROC / "1/net/dev" if HOST_MODE else None
    if netdev and netdev.exists():
        rx = tx = 0
        for line in _read(netdev).splitlines()[2:]:
            if ":" not in line:
                continue
            iface, data = line.split(":", 1)
            iface = iface.strip()
            if iface.startswith(SKIP_IFACES):
                continue
            cols = data.split()
            rx += int(cols[0])
            tx += int(cols[8])
        return rx, tx
    per = psutil.net_io_counters(pernic=True)
    rx = sum(v.bytes_recv for k, v in per.items() if not k.startswith(SKIP_IFACES))
    tx = sum(v.bytes_sent for k, v in per.items() if not k.startswith(SKIP_IFACES))
    return rx, tx


class HostSampler:
    def __init__(self) -> None:
        self._prev_net: Optional[tuple[float, int, int]] = None
        self._procs: dict[int, psutil.Process] = {}
        psutil.cpu_percent(interval=None)  # amorce la mesure CPU
        self.info = host_info()

    def sample(self) -> dict:
        now = time.time()
        vm = psutil.virtual_memory()
        sw = psutil.swap_memory()
        try:
            load = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)
            if HOST_MODE:
                parts = _read(config.HOST_PROC / "loadavg").split()
                if len(parts) >= 3:
                    load = tuple(float(x) for x in parts[:3])
        except (OSError, ValueError):
            load = (0.0, 0.0, 0.0)

        rx, tx = _net_counters()
        rx_rate = tx_rate = 0.0
        if self._prev_net:
            dt = now - self._prev_net[0]
            if dt > 0:
                rx_rate = max(rx - self._prev_net[1], 0) / dt
                tx_rate = max(tx - self._prev_net[2], 0) / dt
        self._prev_net = (now, rx, tx)

        disk_list = disks()
        root = next((d for d in disk_list if d["mount"] == "/"), disk_list[0] if disk_list else None)
        return {
            "ts": now,
            "cpu": psutil.cpu_percent(interval=None),
            "cpu_count": self.info["cpu_count"],
            "load": [round(x, 2) for x in load],
            "mem": {"total": vm.total, "used": vm.total - vm.available, "available": vm.available, "percent": round(vm.percent, 1)},
            "swap": {"total": sw.total, "used": sw.used, "percent": round(sw.percent, 1)},
            "disk_root": root["percent"] if root else None,
            "disk_max": max((d["percent"] for d in disk_list), default=None),
            "disks": disk_list,
            "net": {"rx_rate": rx_rate, "tx_rate": tx_rate, "rx_total": rx, "tx_total": tx},
            "uptime": now - self.info["boot_time"] if self.info.get("boot_time") else None,
        }

    def top_processes(self, limit: int = 10) -> list[dict]:
        """Processus les plus gourmands de l'hôte (nécessite le /proc de l'hôte)."""
        current: dict[int, psutil.Process] = {}
        rows = []
        for proc in psutil.process_iter(["pid", "name", "username", "memory_info", "cmdline"]):
            pid = proc.info["pid"]
            p = self._procs.get(pid, proc)
            current[pid] = p
            try:
                cpu = p.cpu_percent(interval=None)
                mem = proc.info["memory_info"].rss if proc.info["memory_info"] else 0
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            cmd = " ".join(proc.info.get("cmdline") or [])[:160] or proc.info["name"]
            rows.append({"pid": pid, "name": proc.info["name"], "user": proc.info.get("username") or "",
                         "cpu": round(cpu, 1), "mem": mem, "cmd": cmd})
        self._procs = current
        total = psutil.virtual_memory().total or 1
        for r in rows:
            r["mem_pct"] = round(r["mem"] / total * 100, 1)
        by_cpu = sorted(rows, key=lambda r: -r["cpu"])[:limit]
        by_mem = sorted(rows, key=lambda r: -r["mem"])[:limit]
        return {"by_cpu": by_cpu, "by_mem": by_mem, "count": len(rows)}


sampler: Optional[HostSampler] = None


def get_sampler() -> HostSampler:
    global sampler
    if sampler is None:
        sampler = HostSampler()
    return sampler
