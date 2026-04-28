"""Security-relevant sysctl values."""

from __future__ import annotations

from pathlib import Path

# These are the keys we actually care about. Defaults match a hardened modern kernel.
TRACKED = [
    "net.ipv4.tcp_syncookies",
    "net.ipv4.conf.all.rp_filter",
    "net.ipv4.conf.default.rp_filter",
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.all.send_redirects",
    "net.ipv4.icmp_echo_ignore_broadcasts",
    "net.ipv4.conf.all.accept_source_route",
    "net.ipv4.conf.all.log_martians",
    "kernel.randomize_va_space",
    "kernel.kptr_restrict",
    "kernel.dmesg_restrict",
    "fs.protected_hardlinks",
    "fs.protected_symlinks",
]


def collect() -> dict:
    return {"sysctl": _read_all()}


def _read_all() -> dict[str, str]:
    out: dict[str, str] = {}
    for key in TRACKED:
        out[key] = _read_one(key)
    return out


def _read_one(key: str) -> str:
    path = Path("/proc/sys") / key.replace(".", "/")
    if not path.exists():
        return ""
    try:
        return path.read_text(encoding="utf-8").strip()
    except (OSError, PermissionError):
        return ""
