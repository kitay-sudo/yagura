"""Tiny wrapper around subprocess for collectors. Always non-fatal."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Sequence


def run(cmd: Sequence[str], timeout: int = 10) -> tuple[int, str, str]:
    """Run a command, never raise. Returns (returncode, stdout, stderr)."""
    if not cmd:
        return 1, "", "empty command"
    if not has(cmd[0]):
        return 127, "", f"{cmd[0]}: not found"
    try:
        proc = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except OSError as e:
        return 1, "", str(e)


def has(binary: str) -> bool:
    return shutil.which(binary) is not None


def lines(out: str) -> list[str]:
    return [ln for ln in out.splitlines() if ln.strip()]
