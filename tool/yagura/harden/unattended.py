"""Install + enable unattended-upgrades (deb) or dnf-automatic (rpm)."""

from __future__ import annotations

from yagura.collectors.packages import _detect_family
from yagura.harden.base import ApplyResult, HardenAction


class InstallUnattendedUpgrades(HardenAction):
    id = "pkg.unattended_upgrades"
    title = "Auto security updates (unattended-upgrades / dnf-automatic)"
    severity = "MEDIUM"

    def preview(self) -> list[str]:
        family = _detect_family()
        if family == "deb":
            return [
                "apt-get install -y unattended-upgrades",
                "dpkg-reconfigure -p low unattended-upgrades",
                "systemctl enable --now unattended-upgrades.service",
            ]
        if family == "rpm":
            return [
                "dnf install -y dnf-automatic",
                "systemctl enable --now dnf-automatic.timer",
            ]
        if family == "arch":
            return ["echo 'Arch: enable systemd timer for pacman-key + pacman-Syu manually'"]
        return ["echo 'unsupported package manager'"]

    def apply(self) -> ApplyResult:
        family = _detect_family()
        if family == "deb":
            rc, _, err = self._run(["apt-get", "install", "-y", "unattended-upgrades"], timeout=180)
            if rc != 0:
                return ApplyResult(False, f"install failed: {err}")
            self._run(["systemctl", "enable", "--now", "unattended-upgrades.service"])
            rollback = "systemctl disable --now unattended-upgrades.service"
            return ApplyResult(True, "unattended-upgrades enabled", rollback_cmd=rollback)
        if family == "rpm":
            rc, _, err = self._run(["dnf", "install", "-y", "dnf-automatic"], timeout=180)
            if rc != 0:
                return ApplyResult(False, f"install failed: {err}")
            self._run(["systemctl", "enable", "--now", "dnf-automatic.timer"])
            rollback = "systemctl disable --now dnf-automatic.timer"
            return ApplyResult(True, "dnf-automatic enabled", rollback_cmd=rollback)
        return ApplyResult(False, f"Auto-updates not implemented for {family}")
