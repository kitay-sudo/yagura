"""Behavioral rules — diff current state against baseline + heuristics. Returns Alerts."""

from __future__ import annotations

import functools
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

# Локальные порты популярных БД/брокеров. Если процесс держит соединения сюда —
# почти наверняка это легитимное приложение, а не майнер. Мы НЕ глушим W-PROC-002
# полностью (атакующий мог бы открыть фейковый коннект), а понижаем severity до LOW
# и логируем — оператор увидит в логе, но не разбудит алертом ночью.
LOCAL_DB_PORTS = {5432, 3306, 6379, 27017, 11211, 9200, 5672, 4222}

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
    # Усиленная версия: учитывает whitelist по cmdline/exe и понижает severity,
    # если процесс держит соединения с локальной БД (не похоже на майнер).
    high_cpu = [
        p for p in sys_now.get("top_processes", []) if p["cpu"] >= CRYPTOMINER_CPU_THRESHOLD
    ]
    # Группируем established по PID — нужны пути соединений, не только факт наличия.
    conns_by_pid: dict[int, list[dict]] = {}
    for c in net_now.get("established", []):
        if c.get("pid"):
            conns_by_pid.setdefault(c["pid"], []).append(c)
    # cmdline/exe из network коллектора — берём из любого соединения процесса.
    cmdline_by_pid = {pid: cs[0].get("cmdline", "") for pid, cs in conns_by_pid.items()}
    exe_by_pid = {pid: cs[0].get("exe", "") for pid, cs in conns_by_pid.items()}
    for p in high_cpu:
        pid = p["pid"]
        if pid not in conns_by_pid:
            continue
        cmdline = cmdline_by_pid.get(pid, "") or p.get("name", "")
        exe = exe_by_pid.get(pid, "")
        # Whitelist по exe или по подстроке в cmdline (например, "balifornia-crm").
        if whitelist.is_process_whitelisted(cfg, exe):
            continue
        if _cmdline_whitelisted(cfg, cmdline):
            continue
        # Если процесс держит соединения на localhost к известному порту БД —
        # понижаем до LOW. Реальный майнер так не делает.
        has_db = any(
            _is_local_db_conn(c) for c in conns_by_pid[pid]
        )
        severity: Severity = "LOW" if has_db else "MEDIUM"
        # Полный cmdline в детали — иначе пользователь видит обрезанный `node /var/www/b`.
        display = cmdline or p["name"]
        detail = (
            f"{display} (PID {pid}, CPU {p['cpu']:.0f}%, user {p['user']}) has network connections"
        )
        if has_db:
            detail += " [holds localhost DB sockets — likely legit app]"
        add(
            Alert(
                rule_id="W-PROC-002",
                severity=severity,
                title="Cryptominer heuristic",
                detail=detail,
                context={
                    "process": p,
                    "cmdline": cmdline,
                    "exe": exe,
                    "connections": conns_by_pid[pid],
                    "has_local_db": has_db,
                },
            )
        )

    # W-PROC-003: reverse shell heuristic — shell-ish process has external ESTABLISHED outbound.
    # Whitelist пар (cmdline_pattern, dest_pattern) подавляет известные легитимные
    # клиенты к API (например, fm-agent → *.googleusercontent.com). Срабатывание
    # supresison требует совпадения ОБОИХ паттернов — атакующий не пройдёт мимо
    # whitelist, просто запустив свой бинарь под тем же именем.
    for c in net_now.get("established", []):
        proc = c.get("process", "")
        raddr = c.get("raddr", "")
        if not raddr or ":" not in raddr:
            continue
        ip_str = raddr.rsplit(":", 1)[0]
        if not _is_external(ip_str):
            continue
        if proc not in REVERSE_SHELL_PROCESSES:
            continue
        cmdline = c.get("cmdline", "") or proc
        if _proc_dest_whitelisted(cfg, cmdline, ip_str):
            continue
        add(
            Alert(
                rule_id="W-PROC-003",
                severity="CRITICAL",
                title="Reverse-shell heuristic",
                # Полный cmdline вместо обрезанного `python3` — если был запущен
                # /opt/foo/agent.py, оператор увидит этот путь сразу.
                detail=(
                    f"{cmdline} (PID {c['pid']}, user {c['user']}) → ESTABLISHED {raddr}"
                ),
                context={"connection": c, "cmdline": cmdline, "dest_ip": ip_str},
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


def _is_local_db_conn(conn: dict) -> bool:
    """True if the established connection points to localhost on a known DB port."""
    raddr = conn.get("raddr", "") or ""
    if ":" not in raddr:
        return False
    ip, _, port_s = raddr.rpartition(":")
    try:
        port = int(port_s)
    except ValueError:
        return False
    if port not in LOCAL_DB_PORTS:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_loopback


def _cmdline_whitelisted(cfg: dict, cmdline: str) -> bool:
    """True if any whitelist.cmdline_substrings entry occurs in cmdline.

    Accepts entries as plain strings ("balifornia-crm") or dicts from bundled
    packs ({value: "balifornia-crm", source: "bundled:..."}). Both work.
    """
    if not cmdline:
        return False
    items = cfg.get("whitelist", {}).get("cmdline_substrings", []) or []
    for it in items:
        if isinstance(it, str) and it and it in cmdline:
            return True
        if isinstance(it, dict):
            v = it.get("value", "")
            if isinstance(v, str) and v and v in cmdline:
                return True
    return False


def _proc_dest_whitelisted(cfg: dict, cmdline: str, dest_ip: str) -> bool:
    """Match against whitelist.process_dest pairs.

    Each entry is a dict like:
        {cmdline: "fm-agent", dest_hostname: "*.googleusercontent.com"}
        {cmdline: "fm-agent", dest_ip: "34.102.0.0/16"}

    BOTH the cmdline substring AND the destination must match. This is intentional —
    a stand-alone cmdline match would let an attacker bypass by naming their binary
    `fm-agent`, and a stand-alone IP match would let any process talk to that IP.
    """
    if not cmdline or not dest_ip:
        return False
    pairs = cfg.get("whitelist", {}).get("process_dest", []) or []
    if not pairs:
        return False
    hostname = _ptr_lookup(dest_ip)
    for pair in pairs:
        if not isinstance(pair, dict):
            continue
        cmd_sub = pair.get("cmdline") or ""
        if not cmd_sub or cmd_sub not in cmdline:
            continue
        # IP/CIDR match
        cidr = pair.get("dest_ip") or ""
        if cidr and _ip_in_cidr(dest_ip, cidr):
            return True
        # Hostname pattern match (PTR-resolved)
        host_pat = pair.get("dest_hostname") or ""
        if host_pat and hostname and _host_matches(hostname, host_pat):
            return True
    return False


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def _host_matches(host: str, pattern: str) -> bool:
    """Glob-style suffix match: `*.googleusercontent.com` matches `foo.googleusercontent.com`."""
    host = host.rstrip(".").lower()
    pattern = pattern.rstrip(".").lower()
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".googleusercontent.com"
        return host.endswith(suffix)
    return host == pattern


def _ptr_lookup(ip: str) -> str:
    """Reverse-DNS lookup with a short timeout; returns "" on failure.

    Имеет лимит — социалкэшируется в LRU, чтобы не дёргать DNS на каждом тике.
    """
    return _ptr_lookup_cached(ip)


# functools.lru_cache не имеет TTL, но для in-memory daemon
# (перезапускается systemd) этого хватит. maxsize ограничивает рост.
@functools.lru_cache(maxsize=1024)
def _ptr_lookup_cached(ip: str) -> str:
    import socket as _s

    try:
        host, _, _ = _s.gethostbyaddr(ip)
    except (OSError, _s.herror):
        return ""
    return host
