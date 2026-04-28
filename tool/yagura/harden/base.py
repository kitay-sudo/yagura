"""HardenAction base class. Each action implements preview / apply / rollback."""

from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ApplyResult:
    success: bool
    message: str
    rollback_cmd: str = ""  # shell command (or sequence) to undo this action


class HardenAction(ABC):
    id: str = ""
    title: str = ""
    severity: str = "MEDIUM"

    @abstractmethod
    def preview(self) -> list[str]:
        """List of shell commands (strings) that *would* be run on apply()."""

    @abstractmethod
    def apply(self) -> ApplyResult:
        """Run the change. Must return rollback_cmd for harden_history."""

    # ---- helpers shared by all actions ----

    @staticmethod
    def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
            return p.returncode, p.stdout, p.stderr
        except (subprocess.TimeoutExpired, OSError) as e:
            return 1, "", str(e)

    @staticmethod
    def _has(binary: str) -> bool:
        return shutil.which(binary) is not None

    @staticmethod
    def _backup_path(path: str) -> str:
        return f"{path}.yagura.bak"
