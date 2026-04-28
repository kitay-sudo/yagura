"""/etc/passwd, /etc/shadow, sudoers."""

from __future__ import annotations

from pathlib import Path

PASSWD = Path("/etc/passwd")
SHADOW = Path("/etc/shadow")
SUDOERS = Path("/etc/sudoers")
SUDOERS_D = Path("/etc/sudoers.d")


def collect() -> dict:
    users = _parse_passwd()
    return {
        "users": users,
        "uid_zero": [u["name"] for u in users if u["uid"] == 0],
        "empty_password_users": _empty_password_users(),
        "sudoers": _parse_sudoers(),
    }


def _parse_passwd() -> list[dict]:
    out: list[dict] = []
    if not PASSWD.exists():
        return out
    try:
        for line in PASSWD.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 7:
                continue
            try:
                uid = int(parts[2])
                gid = int(parts[3])
            except ValueError:
                continue
            out.append(
                {
                    "name": parts[0],
                    "uid": uid,
                    "gid": gid,
                    "home": parts[5],
                    "shell": parts[6],
                }
            )
    except OSError:
        pass
    return out


def _empty_password_users() -> list[str]:
    out: list[str] = []
    if not SHADOW.exists():
        return out
    try:
        for line in SHADOW.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 2:
                continue
            name, hash_field = parts[0], parts[1]
            # Empty password = literal empty string. "*" / "!" / "!!" mean *locked*, not empty.
            if hash_field == "":
                out.append(name)
    except (OSError, PermissionError):
        pass
    return out


def _parse_sudoers() -> dict:
    """Returns lines + flags: NOPASSWD users, group ALL grants. Best-effort textual parse."""
    nopasswd_entries: list[str] = []
    raw_lines: list[str] = []
    files = []
    if SUDOERS.exists():
        files.append(SUDOERS)
    if SUDOERS_D.is_dir():
        files.extend(sorted(SUDOERS_D.iterdir()))
    for f in files:
        if not f.is_file():
            continue
        try:
            for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                raw_lines.append(stripped)
                if "NOPASSWD" in stripped:
                    parts = stripped.split()
                    if parts:
                        nopasswd_entries.append(parts[0])
        except (OSError, PermissionError):
            continue
    return {"lines": raw_lines, "nopasswd": nopasswd_entries}
