"""Stop + disable a list of named systemd services."""

from __future__ import annotations

from yagura.harden.base import ApplyResult, HardenAction


class DisableService(HardenAction):
    """Generic action: parameterised on a unit name. Use via DisableService('telnet.service')."""

    id = "svc.disable"
    title = "Disable a systemd service"
    severity = "LOW"

    def __init__(self, unit: str):
        self.unit = unit
        self.id = f"svc.disable.{unit}"
        self.title = f"Disable + stop {unit}"

    def preview(self) -> list[str]:
        return [
            f"systemctl stop {self.unit}",
            f"systemctl disable {self.unit}",
            f"systemctl mask {self.unit}",
        ]

    def apply(self) -> ApplyResult:
        if not self._has("systemctl"):
            return ApplyResult(False, "systemctl not available")
        self._run(["systemctl", "stop", self.unit])
        self._run(["systemctl", "disable", self.unit])
        rc, _, err = self._run(["systemctl", "mask", self.unit])
        if rc != 0:
            return ApplyResult(False, f"mask failed: {err}")
        rollback = f"systemctl unmask {self.unit} && systemctl enable {self.unit} && systemctl start {self.unit}"
        return ApplyResult(True, f"{self.unit} stopped + disabled + masked", rollback_cmd=rollback)
