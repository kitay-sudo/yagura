"""Install + enable ufw with sane defaults."""

from __future__ import annotations

from yagura.collectors.packages import _detect_family
from yagura.harden.base import ApplyResult, HardenAction


def _install_cmd(family: str) -> list[str] | None:
    if family == "deb":
        return ["apt-get", "install", "-y", "ufw"]
    if family == "rpm":
        return ["dnf", "install", "-y", "ufw"]
    if family == "arch":
        return ["pacman", "-S", "--noconfirm", "ufw"]
    return None


class UFWEnable(HardenAction):
    id = "fw.ufw_enable"
    title = "Firewall: install + enable ufw (allow 22, 80, 443)"
    severity = "HIGH"

    def preview(self) -> list[str]:
        family = _detect_family()
        steps = []
        install = _install_cmd(family)
        if install:
            steps.append(" ".join(install))
        steps.extend(
            [
                "ufw default deny incoming",
                "ufw default allow outgoing",
                "ufw allow 22/tcp",
                "ufw allow 80/tcp",
                "ufw allow 443/tcp",
                "ufw --force enable",
            ]
        )
        return steps

    def apply(self) -> ApplyResult:
        if not self._has("ufw"):
            install = _install_cmd(_detect_family())
            if install is None:
                return ApplyResult(False, "Unsupported package manager for ufw install")
            rc, _, err = self._run(install, timeout=120)
            if rc != 0:
                return ApplyResult(False, f"ufw install failed: {err}")
        for cmd in [
            ["ufw", "default", "deny", "incoming"],
            ["ufw", "default", "allow", "outgoing"],
            ["ufw", "allow", "22/tcp"],
            ["ufw", "allow", "80/tcp"],
            ["ufw", "allow", "443/tcp"],
        ]:
            self._run(cmd)
        rc, _, err = self._run(["ufw", "--force", "enable"])
        if rc != 0:
            return ApplyResult(False, f"ufw enable failed: {err}")
        rollback = "ufw --force disable"
        return ApplyResult(True, "ufw enabled with defaults", rollback_cmd=rollback)


class IptablesDefaultDrop(HardenAction):
    id = "fw.iptables_default_drop"
    title = "iptables: set default INPUT policy to DROP (after explicit ACCEPT for 22/lo)"
    severity = "HIGH"

    def preview(self) -> list[str]:
        return [
            "iptables -A INPUT -i lo -j ACCEPT",
            "iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
            "iptables -P INPUT DROP",
        ]

    def apply(self) -> ApplyResult:
        if not self._has("iptables"):
            return ApplyResult(False, "iptables not installed")
        steps = [
            ["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
            [
                "iptables",
                "-A",
                "INPUT",
                "-m",
                "conntrack",
                "--ctstate",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ],
            ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"],
            ["iptables", "-P", "INPUT", "DROP"],
        ]
        for cmd in steps:
            rc, _, err = self._run(cmd)
            if rc != 0:
                return ApplyResult(False, f"failed at: {' '.join(cmd)} -- {err}")
        rollback = "iptables -P INPUT ACCEPT && iptables -F INPUT"
        return ApplyResult(True, "iptables INPUT default policy = DROP", rollback_cmd=rollback)
