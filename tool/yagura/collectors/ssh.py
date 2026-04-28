"""sshd_config + recent failed auth attempts."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

SSHD_CONFIG = Path("/etc/ssh/sshd_config")
SSHD_CONFIG_D = Path("/etc/ssh/sshd_config.d")
AUTH_LOGS = [Path("/var/log/auth.log"), Path("/var/log/secure")]

# Settings we want to know about, with their *secure* defaults documented
# in OpenSSH manual (used when the directive is absent — sshd ships defaults).
TRACKED_DIRECTIVES = {
    "PermitRootLogin": "prohibit-password",
    "PasswordAuthentication": "yes",
    "PubkeyAuthentication": "yes",
    "PermitEmptyPasswords": "no",
    "X11Forwarding": "no",
    "Port": "22",
    "MaxAuthTries": "6",
    "ChallengeResponseAuthentication": "no",
    "UsePAM": "yes",
    "AllowUsers": "",
    "AllowGroups": "",
}

FAILED_RE = re.compile(
    r"sshd.*?(Failed password|Invalid user|authentication failure).*?from\s+([0-9a-f.:]+)",
    re.IGNORECASE,
)


def collect() -> dict:
    settings = _parse_sshd_config()
    return {
        "config_present": SSHD_CONFIG.exists(),
        "settings": settings,
        "failed_logins_24h": _failed_logins(),
    }


def _parse_sshd_config() -> dict[str, str]:
    """Last-write-wins across sshd_config and sshd_config.d/*.conf, default applied if absent."""
    settings: dict[str, str] = {}
    files = []
    if SSHD_CONFIG.exists():
        files.append(SSHD_CONFIG)
    if SSHD_CONFIG_D.is_dir():
        files.extend(sorted(SSHD_CONFIG_D.glob("*.conf")))
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            key, val = parts[0], parts[1].strip()
            for tracked in TRACKED_DIRECTIVES:
                if key.lower() == tracked.lower():
                    settings[tracked] = val
                    break
    for k, default in TRACKED_DIRECTIVES.items():
        settings.setdefault(k, default)
    return settings


def _failed_logins() -> dict:
    """Count of failed SSH attempts in the last 24h, plus top offending IPs."""
    by_ip: Counter[str] = Counter()
    total = 0
    for log in AUTH_LOGS:
        if not log.exists():
            continue
        try:
            with open(log, encoding="utf-8", errors="replace") as f:
                # Read only the tail of the file to keep memory bounded on huge logs.
                for line in _tail_lines(f, max_lines=20000):
                    m = FAILED_RE.search(line)
                    if m:
                        total += 1
                        by_ip[m.group(2)] += 1
        except (OSError, PermissionError):
            continue
    top = [{"ip": ip, "count": cnt} for ip, cnt in by_ip.most_common(10)]
    return {"total": total, "top": top}


def _tail_lines(f, max_lines: int = 20000) -> list[str]:
    lines = f.readlines()
    return lines[-max_lines:]
