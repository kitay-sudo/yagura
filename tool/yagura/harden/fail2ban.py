"""Install + enable fail2ban (sshd jail comes by default)."""

from __future__ import annotations

from yagura.collectors.packages import _detect_family
from yagura.harden.base import ApplyResult, HardenAction


def _install_cmd(family: str) -> list[str] | None:
    if family == "deb":
        return ["apt-get", "install", "-y", "fail2ban"]
    if family == "rpm":
        return ["dnf", "install", "-y", "fail2ban"]
    if family == "arch":
        return ["pacman", "-S", "--noconfirm", "fail2ban"]
    return None


class InstallFail2ban(HardenAction):
    id = "pkg.fail2ban"
    title = "Install + enable fail2ban (default sshd jail)"
    severity = "MEDIUM"

    def preview(self) -> list[str]:
        family = _detect_family()
        cmds = []
        install = _install_cmd(family)
        if install:
            cmds.append(" ".join(install))
        cmds.extend(
            [
                "systemctl enable fail2ban",
                "systemctl start fail2ban",
            ]
        )
        return cmds

    def apply(self) -> ApplyResult:
        family = _detect_family()
        if not self._has("fail2ban-client"):
            install = _install_cmd(family)
            if install is None:
                return ApplyResult(False, "Unsupported package manager")
            rc, _, err = self._run(install, timeout=180)
            if rc != 0:
                return ApplyResult(False, f"fail2ban install failed: {err}")
        for cmd in [
            ["systemctl", "enable", "fail2ban"],
            ["systemctl", "start", "fail2ban"],
        ]:
            self._run(cmd)
        rollback = "systemctl stop fail2ban && systemctl disable fail2ban"
        return ApplyResult(True, "fail2ban installed and started", rollback_cmd=rollback)
