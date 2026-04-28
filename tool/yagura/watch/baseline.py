"""Baseline = the snapshot we treat as 'normal'. New listeners/cron/units are diff'd against this."""

from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from pathlib import Path

from yagura.collectors import (
    cron,
    files,
    network,
    services,
    system,
    users,
)
from yagura.config import BASELINE_PATH, ensure_dirs


def build() -> dict:
    sysinfo = system.collect()
    net = network.collect()
    crons = cron.collect()
    svc = services.collect()
    usr = users.collect()
    fls = files.collect()
    return {
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "hostname": socket.gethostname(),
        "kernel": sysinfo.get("kernel", ""),
        "listeners": [
            {
                "port": lst["port"],
                "proto": lst["proto"],
                "ip": lst["ip"],
                "process": lst["process"],
                "exe": lst["exe"],
                "user": lst["user"],
            }
            for lst in net.get("listeners", [])
        ],
        "processes": [],  # filled in monitor only when needed (heavy)
        "cron_jobs": [
            {"user": j["user"], "schedule": j["schedule"], "cmd": j["cmd"]}
            for j in crons.get("jobs", [])
        ],
        "systemd_units": svc.get("enabled_units", []),
        "uid_zero_users": usr.get("uid_zero", []),
        "sudo_users": usr.get("sudoers", {}).get("nopasswd", []),
        "file_hashes": fls.get("hashes", {}),
        "ssh_known_ips": [],  # populated as users log in successfully
    }


def save(baseline: dict, path: Path = BASELINE_PATH) -> None:
    ensure_dirs()
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(baseline, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def load(path: Path = BASELINE_PATH) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
