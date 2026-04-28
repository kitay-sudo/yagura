"""Listening sockets, established TCP, interfaces."""

from __future__ import annotations

import psutil

SUSPICIOUS_PROCESS_PATHS = ("/tmp/", "/dev/shm/", "/var/tmp/")


def collect() -> dict:
    return {
        "listeners": _listeners(),
        "established": _established(),
        "interfaces": _interfaces(),
    }


def _listeners() -> list[dict]:
    out: list[dict] = []
    seen: set[tuple] = set()
    for c in psutil.net_connections(kind="inet"):
        if c.status != psutil.CONN_LISTEN:
            continue
        if not c.laddr:
            continue
        proto = "tcp" if c.type == 1 else "udp"  # SOCK_STREAM=1
        ip = c.laddr.ip
        port = c.laddr.port
        key = (proto, ip, port, c.pid)
        if key in seen:
            continue
        seen.add(key)
        proc = _process_info(c.pid)
        out.append(
            {
                "proto": proto,
                "ip": ip,
                "port": port,
                "pid": c.pid,
                "process": proc["name"],
                "exe": proc["exe"],
                "user": proc["user"],
                "cmdline": proc["cmdline"],
                "suspicious_path": _is_suspicious_path(proc["exe"]),
            }
        )
    out.sort(key=lambda x: (x["proto"], x["port"]))
    return out


def _established() -> list[dict]:
    out: list[dict] = []
    for c in psutil.net_connections(kind="inet"):
        if c.status != psutil.CONN_ESTABLISHED:
            continue
        if not c.raddr:
            continue
        proc = _process_info(c.pid)
        out.append(
            {
                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                "raddr": f"{c.raddr.ip}:{c.raddr.port}",
                "pid": c.pid,
                # name() обрезается ядром до 15 символов (TASK_COMM_LEN), поэтому
                # пути вроде /var/www/balifornia/... превращаются в /var/www/b.
                # cmdline даёт полную команду — нужно для адекватных алертов.
                "process": proc["name"],
                "exe": proc["exe"],
                "cmdline": proc["cmdline"],
                "user": proc["user"],
            }
        )
    return out


def _interfaces() -> list[dict]:
    out: list[dict] = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    counters = psutil.net_io_counters(pernic=True)
    for name, addr_list in addrs.items():
        ipv4 = [a.address for a in addr_list if a.family.name == "AF_INET"]
        st = stats.get(name)
        cn = counters.get(name)
        out.append(
            {
                "name": name,
                "ipv4": ipv4,
                "is_up": bool(st and st.isup),
                "speed_mbps": (st.speed if st else 0),
                "bytes_sent": (cn.bytes_sent if cn else 0),
                "bytes_recv": (cn.bytes_recv if cn else 0),
            }
        )
    return out


def _process_info(pid: int | None) -> dict:
    if not pid:
        return {"name": "", "exe": "", "user": "", "cmdline": ""}
    try:
        p = psutil.Process(pid)
        return {
            "name": p.name(),
            "exe": p.exe(),
            "user": p.username(),
            "cmdline": " ".join(p.cmdline()),
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
        return {"name": "", "exe": "", "user": "", "cmdline": ""}


def _is_suspicious_path(exe: str) -> bool:
    if not exe:
        return False
    return any(exe.startswith(p) for p in SUSPICIOUS_PROCESS_PATHS)
