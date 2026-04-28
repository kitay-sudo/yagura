"""Behavioral rules — diff current state against baseline + heuristics. Returns Alerts."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Literal

from yagura.collectors import cron, files, network, services, system, users
from yagura.watch import whitelist

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

REVERSE_SHELL_PROCESSES = {
    "bash",
    "sh",
    "dash",
    "zsh",
    "ash",
    "ksh",
    "python",
    "python3",
    "perl",
    "nc",
    "ncat",
    "socat",
}
SUSPICIOUS_PROCESS_PATHS = ("/tmp/", "/dev/shm/", "/var/tmp/")
CRYPTOMINER_CPU_THRESHOLD = 80.0

# Yagura никогда не должна алертить на саму себя.
# Имя процесса или префикс exe-пути — любое совпадение глушит W-NET-001.
SELF_PROCESS_NAMES = {"yagura", "yagura-watch"}
SELF_EXE_PREFIXES = ("/opt/yagura/", "/usr/local/bin/yagura", "/usr/bin/yagura")

# Порты выше этого считаем эфемерными (Linux ip_local_port_range по умолчанию 32768–60999).
# Для процессов из whitelist.processes такие порты не алертим — они почти всегда
# клиентские/рандомные и спамят без пользы.
EPHEMERAL_PORT_MIN = 32768


@dataclass
class Alert:
    rule_id: str
    severity: Severity
    title: str
    detail: str
    context: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "context": self.context,
        }


def evaluate(baseline: dict, cfg: dict) -> list[Alert]:
    """Run every rule and return all triggered alerts."""
    alerts: list[Alert] = []
    disabled = set(cfg.get("watch", {}).get("rules_disabled", []) or [])

    def add(a: Alert) -> None:
        if a.rule_id not in disabled:
            alerts.append(a)

    net_now = network.collect()
    cron_now = cron.collect()
    svc_now = services.collect()
    usr_now = users.collect()
    fls_now = files.collect()
    sys_now = system.collect()

    # W-NET-001: new listener
    base_listeners = {(b["proto"], b["port"]) for b in baseline.get("listeners", [])}
    # Процессы (по exe), у которых хоть один listener уже был в baseline —
    # известные нам сервисы. На их эфемерных портах не шумим.
    base_known_exes = {b.get("exe") for b in baseline.get("listeners", []) if b.get("exe")}
    for lst in net_now.get("listeners", []):
        key = (lst["proto"], lst["port"])
        if key in base_listeners:
            continue
        if _is_self(lst):
            continue
        if whitelist.is_port_whitelisted(cfg, lst["port"]):
            continue
        if whitelist.is_process_whitelisted(cfg, lst["exe"]):
            continue
        # Известный процесс на эфемерном порту — почти наверняка клиентский
        # сокет, который psutil показал как LISTEN. Молчим.
        if (
            lst["port"] >= EPHEMERAL_PORT_MIN
            and lst.get("exe")
            and lst["exe"] in base_known_exes
        ):
            continue
        add(
            Alert(
                rule_id="W-NET-001",
                severity="HIGH",
                title="New listener",
                detail=f"{lst['proto']}/{lst['port']} → {lst['process']} (PID {lst['pid']}, user {lst['user']})",
                context={"listener": lst},
            )
        )

    # W-PROC-001: new process from suspicious path
    for lst in net_now.get("listeners", []):
        if lst.get("suspicious_path") and not whitelist.is_process_whitelisted(cfg, lst["exe"]):
            add(
                Alert(
                    rule_id="W-PROC-001",
                    severity="HIGH",
                    title="Process from suspicious path",
                    detail=f"{lst['exe']} (PID {lst['pid']})",
                    context={"listener": lst},
                )
            )

    # W-PROC-002: cryptominer heuristic — high CPU + has network connections.
    # We approximate: any process in top_processes with cpu>80 + has an established connection.
    high_cpu = [
        p for p in sys_now.get("top_processes", []) if p["cpu"] >= CRYPTOMINER_CPU_THRESHOLD
    ]
    pids_with_conns = {c["pid"] for c in net_now.get("established", []) if c["pid"]}
    for p in high_cpu:
        if p["pid"] in pids_with_conns:
            add(
                Alert(
                    rule_id="W-PROC-002",
                    severity="MEDIUM",
                    title="Cryptominer heuristic",
                    detail=f"{p['name']} (PID {p['pid']}, CPU {p['cpu']:.0f}%, user {p['user']}) has network connections",
                    context={"process": p},
                )
            )

    # W-PROC-003: reverse shell heuristic — shell-ish process has external ESTABLISHED outbound
    for c in net_now.get("established", []):
        proc = c.get("process", "")
        raddr = c.get("raddr", "")
        if not raddr or ":" not in raddr:
            continue
        ip_str = raddr.rsplit(":", 1)[0]
        if not _is_external(ip_str):
            continue
        if proc in REVERSE_SHELL_PROCESSES:
            add(
                Alert(
                    rule_id="W-PROC-003",
                    severity="CRITICAL",
                    title="Reverse-shell heuristic",
                    detail=f"{proc} (PID {c['pid']}, user {c['user']}) → ESTABLISHED {raddr}",
                    context={"connection": c},
                )
            )

    # W-FILE-001: critical file hash changed
    base_hashes = baseline.get("file_hashes", {}) or {}
    now_hashes = fls_now.get("hashes", {}) or {}
    for path, h in base_hashes.items():
        new = now_hashes.get(path)
        if new and new != h:
            add(
                Alert(
                    rule_id="W-FILE-001",
                    severity="CRITICAL",
                    title="Critical file changed",
                    detail=f"{path} hash differs from baseline",
                    context={"path": path, "old": h, "new": new},
                )
            )

    # W-CRON-001: new cron job
    base_crons = {(j["user"], j["schedule"], j["cmd"]) for j in baseline.get("cron_jobs", [])}
    for j in cron_now.get("jobs", []):
        key = (j["user"], j["schedule"], j["cmd"])
        if key not in base_crons:
            add(
                Alert(
                    rule_id="W-CRON-001",
                    severity="HIGH",
                    title="New cron job",
                    detail=f"{j['user']} @ {j['schedule']}: {j['cmd'][:160]}",
                    context={"job": j},
                )
            )

    # W-CRON-002: new cron with downloader pattern
    for j in cron_now.get("downloader_jobs", []) + cron_now.get("base64_jobs", []):
        key = (j["user"], j["schedule"], j["cmd"])
        if key not in base_crons:
            add(
                Alert(
                    rule_id="W-CRON-002",
                    severity="CRITICAL",
                    title="Cron with downloader / base64",
                    detail=f"{j['user']} @ {j['schedule']}: {j['cmd'][:160]}",
                    context={"job": j},
                )
            )

    # W-SVC-001: new enabled systemd unit
    # yagura-* юниты — это сам watchdog, не надо алертить на собственный сервис.
    base_units = set(baseline.get("systemd_units", []))
    for u in svc_now.get("enabled_units", []):
        if u in base_units or u.startswith("yagura-"):
            continue
        add(
            Alert(
                rule_id="W-SVC-001",
                severity="HIGH",
                title="New enabled systemd unit",
                detail=u,
                context={"unit": u},
            )
        )

    # W-USR-001: new UID 0
    base_uid_zero = set(baseline.get("uid_zero_users", []))
    for u in usr_now.get("uid_zero", []):
        if u not in base_uid_zero:
            add(
                Alert(
                    rule_id="W-USR-001",
                    severity="CRITICAL",
                    title="New UID 0 account",
                    detail=u,
                    context={"user": u},
                )
            )

    # W-USR-002: new sudo (NOPASSWD) user
    base_sudo = set(baseline.get("sudo_users", []))
    for u in usr_now.get("sudoers", {}).get("nopasswd", []):
        if u not in base_sudo:
            add(
                Alert(
                    rule_id="W-USR-002",
                    severity="HIGH",
                    title="New sudo (NOPASSWD) user",
                    detail=u,
                    context={"user": u},
                )
            )

    return alerts


def _is_external(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)


def _is_self(listener: dict) -> bool:
    name = (listener.get("process") or "").lower()
    exe = listener.get("exe") or ""
    if name in SELF_PROCESS_NAMES:
        return True
    return any(exe.startswith(p) for p in SELF_EXE_PREFIXES)
