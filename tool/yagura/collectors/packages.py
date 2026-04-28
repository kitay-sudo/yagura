"""dpkg / rpm / pacman — installed count, security packages presence, available updates."""

from __future__ import annotations

from yagura.collectors._shell import has, lines, run

CHECKED_PACKAGES = [
    "fail2ban",
    "unattended-upgrades",
    "dnf-automatic",
    "ufw",
    "firewalld",
    "auditd",
    "rkhunter",
    "chkrootkit",
    "aide",
]


def collect() -> dict:
    family = _detect_family()
    return {
        "manager": family,
        "installed_count": _installed_count(family),
        "security_packages": _security_packages_status(family),
        "updates_available": _updates_available(family),
    }


def _detect_family() -> str:
    if has("dpkg"):
        return "deb"
    if has("rpm"):
        return "rpm"
    if has("pacman"):
        return "arch"
    return "unknown"


def _installed_count(family: str) -> int:
    if family == "deb":
        rc, out, _ = run(["dpkg", "-l"])
        if rc == 0:
            return sum(1 for ln in lines(out) if ln.startswith("ii"))
    elif family == "rpm":
        rc, out, _ = run(["rpm", "-qa"])
        if rc == 0:
            return len(lines(out))
    elif family == "arch":
        rc, out, _ = run(["pacman", "-Q"])
        if rc == 0:
            return len(lines(out))
    return 0


def _security_packages_status(family: str) -> dict[str, bool]:
    status: dict[str, bool] = {}
    for pkg in CHECKED_PACKAGES:
        status[pkg] = _is_installed(family, pkg)
    return status


def _is_installed(family: str, pkg: str) -> bool:
    if family == "deb":
        rc, out, _ = run(["dpkg-query", "-W", "-f=${Status}", pkg])
        return rc == 0 and "install ok installed" in out
    if family == "rpm":
        rc, _, _ = run(["rpm", "-q", pkg])
        return rc == 0
    if family == "arch":
        rc, _, _ = run(["pacman", "-Qi", pkg])
        return rc == 0
    return False


def _updates_available(family: str) -> int:
    """Best-effort count without forcing a refresh (no network calls beyond what's already cached)."""
    if family == "deb":
        rc, out, _ = run(["apt-get", "-s", "upgrade"], timeout=30)
        if rc == 0:
            for ln in out.splitlines():
                if "upgraded" in ln and "newly installed" in ln:
                    parts = ln.split()
                    try:
                        return int(parts[0])
                    except (ValueError, IndexError):
                        continue
        return 0
    if family == "rpm":
        rc, out, _ = run(["dnf", "check-update", "--quiet"], timeout=30)
        # dnf check-update returns 100 if updates are available
        if rc in (0, 100):
            return sum(
                1 for ln in lines(out) if ln and not ln.startswith(("Last metadata", "Obsoleting"))
            )
        return 0
    if family == "arch":
        rc, out, _ = run(["pacman", "-Qu"], timeout=30)
        if rc == 0:
            return len(lines(out))
        return 0
    return 0
