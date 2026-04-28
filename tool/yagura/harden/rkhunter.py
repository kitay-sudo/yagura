"""Install rkhunter (rootkit scanner)."""

from __future__ import annotations

from yagura.collectors.packages import _detect_family
from yagura.harden.base import ApplyResult, HardenAction


def _install_cmd(family: str) -> list[str] | None:
    if family == "deb":
        return ["apt-get", "install", "-y", "rkhunter"]
    if family == "rpm":
        return ["dnf", "install", "-y", "rkhunter"]
    if family == "arch":
        return ["pacman", "-S", "--noconfirm", "rkhunter"]
    return None


class InstallRkhunter(HardenAction):
    id = "pkg.rkhunter"
    title = "Install rkhunter (rootkit scanner)"
    severity = "LOW"

    def preview(self) -> list[str]:
        family = _detect_family()
        cmds = []
        install = _install_cmd(family)
        if install:
            cmds.append(" ".join(install))
        cmds.append("rkhunter --propupd")
        return cmds

    def apply(self) -> ApplyResult:
        family = _detect_family()
        if not self._has("rkhunter"):
            install = _install_cmd(family)
            if install is None:
                return ApplyResult(False, f"unsupported family: {family}")
            rc, _, err = self._run(install, timeout=180)
            if rc != 0:
                return ApplyResult(False, f"install failed: {err}")
        self._run(["rkhunter", "--propupd"], timeout=120)
        rollback = ""  # rkhunter is just a scanner; nothing to undo
        return ApplyResult(True, "rkhunter installed and baseline created", rollback_cmd=rollback)
