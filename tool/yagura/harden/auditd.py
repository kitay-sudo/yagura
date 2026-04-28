"""Install + enable auditd."""

from __future__ import annotations

from yagura.collectors.packages import _detect_family
from yagura.harden.base import ApplyResult, HardenAction


def _install_cmd(family: str) -> list[str] | None:
    if family == "deb":
        return ["apt-get", "install", "-y", "auditd"]
    if family == "rpm":
        return ["dnf", "install", "-y", "audit"]
    if family == "arch":
        return ["pacman", "-S", "--noconfirm", "audit"]
    return None


class InstallAuditd(HardenAction):
    id = "pkg.auditd"
    title = "Install + enable auditd"
    severity = "LOW"

    def preview(self) -> list[str]:
        family = _detect_family()
        cmds = []
        install = _install_cmd(family)
        if install:
            cmds.append(" ".join(install))
        cmds.extend(["systemctl enable --now auditd"])
        return cmds

    def apply(self) -> ApplyResult:
        family = _detect_family()
        if not self._has("auditctl"):
            install = _install_cmd(family)
            if install is None:
                return ApplyResult(False, f"unsupported family: {family}")
            rc, _, err = self._run(install, timeout=180)
            if rc != 0:
                return ApplyResult(False, f"install failed: {err}")
        self._run(["systemctl", "enable", "--now", "auditd"])
        rollback = "systemctl disable --now auditd"
        return ApplyResult(True, "auditd enabled", rollback_cmd=rollback)
