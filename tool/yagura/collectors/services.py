"""systemd units — list-unit-files + ExecStart inspection for suspicious paths."""

from __future__ import annotations

from yagura.collectors._shell import has, lines, run

SUSPICIOUS_EXEC_PATHS = ("/tmp/", "/dev/shm/", "/var/tmp/")


def collect() -> dict:
    if not has("systemctl"):
        return {"present": False, "enabled_units": [], "suspicious_units": []}
    return {
        "present": True,
        "enabled_units": _enabled_units(),
        "suspicious_units": _suspicious_units(),
    }


def _enabled_units() -> list[str]:
    rc, out, _ = run(
        [
            "systemctl",
            "list-unit-files",
            "--type=service",
            "--state=enabled",
            "--no-legend",
            "--no-pager",
        ]
    )
    if rc != 0:
        return []
    units: list[str] = []
    for ln in lines(out):
        parts = ln.split()
        if parts:
            units.append(parts[0])
    return units


def _suspicious_units() -> list[dict]:
    """Return units whose ExecStart points at /tmp, /dev/shm, /var/tmp."""
    suspicious: list[dict] = []
    rc, out, _ = run(
        ["systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"]
    )
    if rc != 0:
        return suspicious
    unit_names = [ln.split()[0] for ln in lines(out) if ln.split()]
    for unit in unit_names:
        rc2, out2, _ = run(["systemctl", "cat", unit])
        if rc2 != 0:
            continue
        for line in lines(out2):
            stripped = line.strip()
            if not stripped.startswith("ExecStart"):
                continue
            for path in SUSPICIOUS_EXEC_PATHS:
                if path in stripped:
                    suspicious.append({"unit": unit, "exec": stripped})
                    break
    return suspicious
