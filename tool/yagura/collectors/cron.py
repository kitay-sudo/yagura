"""System and user crontabs + suspicious-pattern detection."""

from __future__ import annotations

import re
from pathlib import Path

from yagura.collectors._shell import has, run

SYSTEM_CRON_FILES = [Path("/etc/crontab")]
SYSTEM_CRON_DIRS = [
    Path("/etc/cron.d"),
    Path("/etc/cron.hourly"),
    Path("/etc/cron.daily"),
    Path("/etc/cron.weekly"),
    Path("/etc/cron.monthly"),
]

DOWNLOADER_RE = re.compile(r"(curl|wget|fetch)\b.*?\|\s*(bash|sh|python|perl|zsh)\b", re.IGNORECASE)
SUSPICIOUS_DIR_RE = re.compile(r"\b/(tmp|dev/shm|var/tmp)\b|/home/[^/]+/")
BASE64_RE = re.compile(r"\b(base64\s+-d|echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64\s+-d)")


def collect() -> dict:
    jobs = _system_jobs() + _user_jobs()
    return {
        "jobs": jobs,
        "downloader_jobs": [j for j in jobs if _is_downloader(j["cmd"])],
        "suspicious_dir_jobs": [j for j in jobs if _is_suspicious_dir(j["cmd"])],
        "base64_jobs": [j for j in jobs if _is_base64(j["cmd"])],
    }


def _system_jobs() -> list[dict]:
    out: list[dict] = []
    for f in SYSTEM_CRON_FILES:
        out.extend(_parse_file(f, source=str(f)))
    for d in SYSTEM_CRON_DIRS:
        if not d.is_dir():
            continue
        for entry in sorted(d.iterdir()):
            if entry.is_file():
                out.extend(_parse_file(entry, source=str(entry)))
    return out


def _user_jobs() -> list[dict]:
    """Read every user's crontab via crontab -l (requires root, fails silently otherwise)."""
    out: list[dict] = []
    spool = Path("/var/spool/cron/crontabs")
    spool_alt = Path("/var/spool/cron")
    candidates: list[Path] = []
    for s in (spool, spool_alt):
        if s.is_dir():
            candidates.extend(p for p in s.iterdir() if p.is_file())
    for path in candidates:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split(None, 5)
            if len(parts) >= 6:
                out.append(
                    {
                        "user": path.name,
                        "schedule": " ".join(parts[:5]),
                        "cmd": parts[5],
                        "source": f"crontab:{path.name}",
                    }
                )

    # Fallback: also try `crontab -u <user> -l` for users with shells, in case spool is unreadable
    if has("crontab"):
        try:
            with open("/etc/passwd", encoding="utf-8", errors="replace") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) < 7:
                        continue
                    name, _, _uid, _gid, _, _home, shell = parts[:7]
                    shell = shell.strip()
                    if shell.endswith(("nologin", "false")):
                        continue
                    rc, cron_out, _ = run(["crontab", "-u", name, "-l"], timeout=5)
                    if rc != 0 or not cron_out.strip():
                        continue
                    for ln in cron_out.splitlines():
                        ln = ln.strip()
                        if not ln or ln.startswith("#"):
                            continue
                        sp = ln.split(None, 5)
                        if len(sp) >= 6 and not any(
                            j["user"] == name and j["cmd"] == sp[5] for j in out
                        ):
                            out.append(
                                {
                                    "user": name,
                                    "schedule": " ".join(sp[:5]),
                                    "cmd": sp[5],
                                    "source": f"crontab:{name}",
                                }
                            )
        except OSError:
            pass

    return out


def _parse_file(path: Path, source: str) -> list[dict]:
    out: list[dict] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return out
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # /etc/crontab and /etc/cron.d entries have user as 6th column,
        # cron.daily/hourly/etc are plain shell scripts — skip those.
        parts = stripped.split(None, 6)
        if len(parts) >= 7 and parts[0].startswith(
            ("*", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "@")
        ):
            out.append(
                {
                    "user": parts[5],
                    "schedule": " ".join(parts[:5]),
                    "cmd": parts[6],
                    "source": source,
                }
            )
    return out


def _is_downloader(cmd: str) -> bool:
    return bool(DOWNLOADER_RE.search(cmd))


def _is_suspicious_dir(cmd: str) -> bool:
    return bool(SUSPICIOUS_DIR_RE.search(cmd))


def _is_base64(cmd: str) -> bool:
    return bool(BASE64_RE.search(cmd))
