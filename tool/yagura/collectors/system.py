"""Distro / kernel / uptime / load / memory / disk / top processes."""

from __future__ import annotations

import os
import platform
import socket
import time
from pathlib import Path

import psutil


def collect() -> dict:
    return {
        "hostname": socket.gethostname(),
        "fqdn": _safe_fqdn(),
        "kernel": platform.release(),
        "kernel_full": platform.version(),
        "arch": platform.machine(),
        "distro": _distro(),
        "boot_time": int(psutil.boot_time()),
        "uptime_seconds": int(time.time() - psutil.boot_time()),
        "load": list(_loadavg()),
        "cpu_count": psutil.cpu_count(logical=True) or 1,
        "cpu_percent": psutil.cpu_percent(interval=0.3),
        "memory": _memory(),
        "disk": _disk(),
        "top_processes": _top_processes(n=5),
    }


def _safe_fqdn() -> str:
    try:
        return socket.getfqdn()
    except OSError:
        return socket.gethostname()


def _distro() -> dict:
    info = {"id": "unknown", "name": "unknown", "version": ""}
    p = Path("/etc/os-release")
    if not p.exists():
        return info
    try:
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            v = v.strip().strip('"')
            if k == "ID":
                info["id"] = v
            elif k == "PRETTY_NAME":
                info["name"] = v
            elif k == "VERSION_ID":
                info["version"] = v
    except OSError:
        pass
    return info


def _loadavg() -> tuple[float, float, float]:
    try:
        return os.getloadavg()
    except (AttributeError, OSError):
        return (0.0, 0.0, 0.0)


def _memory() -> dict:
    m = psutil.virtual_memory()
    return {
        "total": m.total,
        "available": m.available,
        "used": m.used,
        "percent": m.percent,
    }


def _disk() -> list[dict]:
    out: list[dict] = []
    for part in psutil.disk_partitions(all=False):
        if part.fstype in {"squashfs", "tmpfs", "devtmpfs"}:
            continue
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except (OSError, PermissionError):
            continue
        out.append(
            {
                "mount": part.mountpoint,
                "device": part.device,
                "fstype": part.fstype,
                "total": usage.total,
                "used": usage.used,
                "percent": usage.percent,
            }
        )
    return out


def _top_processes(n: int = 5) -> list[dict]:
    procs: list[dict] = []
    for p in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_info"]):
        try:
            info = p.info
            procs.append(
                {
                    "pid": info["pid"],
                    "name": info["name"] or "",
                    "user": info.get("username") or "",
                    "cpu": info.get("cpu_percent") or 0.0,
                    "rss": (info.get("memory_info").rss if info.get("memory_info") else 0),
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    procs.sort(key=lambda x: x["cpu"], reverse=True)
    return procs[:n]
