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
                "cwd": proc["cwd"],
                "ppid": proc["ppid"],
                "parent_name": proc["parent_name"],
                "parent_cmdline": proc["parent_cmdline"],
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


_EMPTY_PROC_INFO = {
    "name": "",
    "exe": "",
    "user": "",
    "cmdline": "",
    "cwd": "",
    "ppid": 0,
    "parent_name": "",
    "parent_cmdline": "",
}


def _process_info(pid: int | None) -> dict:
    if not pid:
        return dict(_EMPTY_PROC_INFO)
    try:
        p = psutil.Process(pid)
        info = {
            "name": p.name(),
            "exe": p.exe(),
            "user": p.username(),
            "cmdline": " ".join(p.cmdline()),
            "cwd": _safe(p.cwd),
            "ppid": p.ppid(),
            "parent_name": "",
            "parent_cmdline": "",
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
        return dict(_EMPTY_PROC_INFO)
    if info["ppid"]:
        try:
            parent = psutil.Process(info["ppid"])
            info["parent_name"] = parent.name()
            info["parent_cmdline"] = " ".join(parent.cmdline())
        except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
            pass
    return info


def _safe(fn) -> str:
    try:
        return fn() or ""
    except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError, OSError):
        return ""


def _is_suspicious_path(exe: str) -> bool:
    if not exe:
        return False
    return any(exe.startswith(p) for p in SUSPICIOUS_PROCESS_PATHS)
