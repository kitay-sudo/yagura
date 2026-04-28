"""Auto-triage: gather forensic evidence about an alert before sending.

Triage NEVER suppresses HIGH/CRITICAL alerts — it only enriches them with the
data an operator would otherwise gather by hand (ps, ss, /proc/<pid>/cmdline,
reverse DNS). The dossier lands in alert.context['triage'] and is rendered by
telegram._format_triage(), so the Telegram message arrives with evidence
attached and the AI prompt has more grounding.

Design rule: triage may only ADD information and may only LOWER severity. It
must never delete the alert or claim something is "safe" without explicit
classifier evidence.
"""

from __future__ import annotations

import socket
import subprocess
from pathlib import Path

from yagura.watch.rules import Alert


def investigate(alert: Alert) -> Alert:
    """Run the right collector for this rule, attach dossier to alert.context."""
    rid = alert.rule_id
    if rid == "W-PROC-003":
        dossier = _triage_proc_conn(alert.context.get("connection", {}))
    elif rid == "W-PROC-002":
        dossier = _triage_proc_cpu(alert.context)
    elif rid == "W-NET-001":
        dossier = _triage_listener(alert.context.get("listener", {}))
    elif rid == "W-FILE-001":
        dossier = _triage_file(alert.context.get("path", ""))
    else:
        dossier = {}
    if dossier:
        alert.context["triage"] = dossier
    return alert


def _triage_proc_conn(conn: dict) -> dict:
    """W-PROC-003: enrich a connection-based alert."""
    pid = conn.get("pid")
    raddr = conn.get("raddr", "")
    out: dict = {}
    if pid:
        out["ps"] = _safe_run(["ps", "-fp", str(pid)])
        out["ss"] = _safe_run(["ss", "-tnp"], grep=str(pid))
        cmdline = _read_cmdline(pid)
        if cmdline:
            out["cmdline_full"] = cmdline
        exe = _read_exe(pid)
        if exe:
            out["exe_link"] = exe
        parent = _read_parent(pid)
        if parent:
            out["parent"] = parent
        unit = _systemd_unit_for(pid)
        if unit:
            out["systemd_unit"] = unit
    if raddr and ":" in raddr:
        ip = raddr.rsplit(":", 1)[0]
        ptr = _ptr(ip)
        if ptr:
            out["ptr"] = f"{ip} → {ptr}"
    out["verdict"] = _classify_proc_conn(out, conn)
    return out


def _triage_proc_cpu(ctx: dict) -> dict:
    """W-PROC-002: enrich a high-CPU alert."""
    proc = ctx.get("process", {}) or {}
    pid = proc.get("pid")
    out: dict = {}
    if pid:
        out["ps"] = _safe_run(["ps", "-fp", str(pid)])
        cmdline = _read_cmdline(pid)
        if cmdline:
            out["cmdline_full"] = cmdline
        exe = _read_exe(pid)
        if exe:
            out["exe_link"] = exe
        unit = _systemd_unit_for(pid)
        if unit:
            out["systemd_unit"] = unit
    if ctx.get("has_local_db"):
        out["verdict"] = "likely legit (holds localhost DB sockets)"
    return out


def _triage_listener(lst: dict) -> dict:
    pid = lst.get("pid")
    out: dict = {}
    if pid:
        out["ps"] = _safe_run(["ps", "-fp", str(pid)])
        unit = _systemd_unit_for(pid)
        if unit:
            out["systemd_unit"] = unit
    return out


def _triage_file(path: str) -> dict:
    if not path:
        return {}
    out: dict = {}
    out["ps"] = _safe_run(["ls", "-la", path])
    out["ss"] = _safe_run(["stat", path])
    return out


def _classify_proc_conn(triage: dict, conn: dict) -> str:
    """Heuristic verdict — informational only, never overrides severity at this layer.

    The actual severity is decided in rules.py via the strict whitelist match;
    here we just give the operator a one-line read of "what does this look like".
    """
    if conn.get("pid") and not triage.get("ps"):
        return "process already exited (transient — likely false positive on short-lived agent)"
    ptr = triage.get("ptr") or ""
    if "googleusercontent.com" in ptr or "googleapis.com" in ptr:
        return "destination is Google Cloud — verify it's an expected API endpoint"
    if "amazonaws.com" in ptr:
        return "destination is AWS — verify endpoint"
    if triage.get("systemd_unit"):
        return f"managed by systemd ({triage['systemd_unit']}) — likely a known service"
    return "needs manual review"


# ---------- low-level helpers ----------


def _safe_run(cmd: list[str], grep: str | None = None, timeout: float = 3.0) -> str:
    """Run a command, return stdout (optionally grepped). Empty string on failure."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""
    out = r.stdout or ""
    if grep:
        out = "\n".join(line for line in out.splitlines() if grep in line)
    return out.strip()


def _read_cmdline(pid: int) -> str:
    p = Path(f"/proc/{pid}/cmdline")
    try:
        raw = p.read_bytes()
    except OSError:
        return ""
    return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()


def _read_exe(pid: int) -> str:
    p = Path(f"/proc/{pid}/exe")
    try:
        return str(p.resolve())
    except OSError:
        return ""


def _read_parent(pid: int) -> str:
    """Returns 'PPID name' or '' on failure."""
    p = Path(f"/proc/{pid}/status")
    try:
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("PPid:"):
                ppid = line.split(":", 1)[1].strip()
                pname = _read_comm(int(ppid)) if ppid.isdigit() else ""
                return f"PID {ppid} ({pname})" if pname else f"PID {ppid}"
    except OSError:
        pass
    return ""


def _read_comm(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/comm").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _systemd_unit_for(pid: int) -> str:
    """Returns the systemd unit name owning this PID, or '' if not under systemd."""
    out = _safe_run(["systemctl", "status", str(pid), "--no-pager", "-n", "0"])
    if not out:
        return ""
    # Первая строка обычно: "● unit-name.service - description"
    first = out.splitlines()[0] if out else ""
    parts = first.split()
    for p in parts:
        if p.endswith(".service") or p.endswith(".socket") or p.endswith(".timer"):
            return p
    return ""


def _ptr(ip: str) -> str:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (OSError, socket.herror):
        return ""
