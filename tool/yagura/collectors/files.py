"""SHA-256 of critical files for baseline comparison."""

from __future__ import annotations

import hashlib
from pathlib import Path

CRITICAL_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/hosts",
    "/etc/crontab",
    "/etc/resolv.conf",
]


def collect() -> dict:
    hashes: dict[str, str] = {}
    for path in CRITICAL_FILES:
        h = sha256(path)
        if h:
            hashes[path] = h
    # Per-user authorized_keys files: discover via /etc/passwd home dirs.
    hashes.update(_authorized_keys_hashes())
    return {"hashes": hashes}


def sha256(path: str | Path) -> str:
    p = Path(path)
    if not p.is_file():
        return ""
    try:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return f"sha256:{h.hexdigest()}"
    except (OSError, PermissionError):
        return ""


def _authorized_keys_hashes() -> dict[str, str]:
    out: dict[str, str] = {}
    passwd = Path("/etc/passwd")
    if not passwd.exists():
        return out
    try:
        for line in passwd.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            home = parts[5]
            if not home or home == "/":
                continue
            ak = Path(home) / ".ssh" / "authorized_keys"
            if ak.is_file():
                h = sha256(ak)
                if h:
                    out[str(ak)] = h
    except OSError:
        pass
    return out
