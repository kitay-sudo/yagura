"""Persistent sysctl tweaks via /etc/sysctl.d/99-yagura.conf."""

from __future__ import annotations

from pathlib import Path

from yagura.harden.base import ApplyResult, HardenAction

SYSCTL_FILE = Path("/etc/sysctl.d/99-yagura.conf")


def _write_sysctl(settings: dict[str, str], header: str) -> bool:
    """Idempotent write of /etc/sysctl.d/99-yagura.conf merging with existing settings."""
    SYSCTL_FILE.parent.mkdir(parents=True, exist_ok=True)
    existing: dict[str, str] = {}
    if SYSCTL_FILE.exists():
        for line in SYSCTL_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            k, v = stripped.split("=", 1)
            existing[k.strip()] = v.strip()
    existing.update(settings)
    body = [f"# {header}", "# Managed by Yagura — edit with care", ""]
    for k, v in sorted(existing.items()):
        body.append(f"{k} = {v}")
    SYSCTL_FILE.write_text("\n".join(body) + "\n", encoding="utf-8")
    return True


class HardenNetwork(HardenAction):
    id = "sysctl.harden_network"
    title = "sysctl: enable syncookies + rp_filter, drop ICMP redirects"
    severity = "MEDIUM"

    settings = {
        "net.ipv4.tcp_syncookies": "1",
        "net.ipv4.conf.all.rp_filter": "1",
        "net.ipv4.conf.default.rp_filter": "1",
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.all.send_redirects": "0",
        "net.ipv4.icmp_echo_ignore_broadcasts": "1",
        "net.ipv4.conf.all.accept_source_route": "0",
        "net.ipv4.conf.all.log_martians": "1",
    }

    def preview(self) -> list[str]:
        return [
            f"echo '<settings>' >> {SYSCTL_FILE}",
            "sysctl --system",
        ] + [f"sysctl -w {k}={v}" for k, v in self.settings.items()]

    def apply(self) -> ApplyResult:
        try:
            _write_sysctl(self.settings, header="Network hardening")
        except (OSError, PermissionError) as e:
            return ApplyResult(False, f"failed to write {SYSCTL_FILE}: {e}")
        rc, _, err = self._run(["sysctl", "--system"])
        for k, v in self.settings.items():
            self._run(["sysctl", "-w", f"{k}={v}"])
        rollback = f"rm -f {SYSCTL_FILE} && sysctl --system"
        if rc != 0:
            return ApplyResult(False, f"sysctl reload failed: {err}", rollback_cmd=rollback)
        return ApplyResult(True, "Network sysctl hardened", rollback_cmd=rollback)


class EnableASLR(HardenAction):
    id = "sysctl.enable_aslr"
    title = "sysctl: enable ASLR (kernel.randomize_va_space=2)"
    severity = "HIGH"

    settings = {"kernel.randomize_va_space": "2"}

    def preview(self) -> list[str]:
        return [
            f"echo 'kernel.randomize_va_space = 2' >> {SYSCTL_FILE}",
            "sysctl -w kernel.randomize_va_space=2",
        ]

    def apply(self) -> ApplyResult:
        try:
            _write_sysctl(self.settings, header="ASLR")
        except (OSError, PermissionError) as e:
            return ApplyResult(False, f"failed to write {SYSCTL_FILE}: {e}")
        self._run(["sysctl", "-w", "kernel.randomize_va_space=2"])
        rollback = "sysctl -w kernel.randomize_va_space=0"
        return ApplyResult(True, "ASLR enabled", rollback_cmd=rollback)
