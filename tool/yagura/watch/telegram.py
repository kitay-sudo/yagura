"""Telegram alerts. One-way only — no command handling."""

from __future__ import annotations

import socket
from datetime import datetime, timezone

import requests

from yagura.ai.verdict import AlertVerdict
from yagura.watch.rules import Alert

API_BASE = "https://api.telegram.org"


def _now_msk() -> str:
    """Format 'DD.MM.YYYY HH:MM:SS MSK' (Europe/Moscow), UTC fallback."""
    try:
        from zoneinfo import ZoneInfo

        tz = ZoneInfo("Europe/Moscow")
        return datetime.now(tz).strftime("%d.%m.%Y %H:%M:%S MSK")
    except Exception:
        return datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M:%S UTC")


def _fmt_uptime(seconds: int) -> str:
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def validate(bot_token: str) -> tuple[bool, str]:
    """getMe smoke-test. Returns (ok, message)."""
    if not bot_token:
        return False, "empty token"
    try:
        r = requests.get(f"{API_BASE}/bot{bot_token}/getMe", timeout=10)
    except requests.RequestException as e:
        return False, str(e)
    if r.status_code != 200:
        return False, f"HTTP {r.status_code}"
    data = r.json()
    if not data.get("ok"):
        return False, data.get("description", "unknown error")
    name = data.get("result", {}).get("username", "?")
    return True, f"@{name}"


def send_test(bot_token: str, chat_id: str) -> tuple[bool, str]:
    text = (
        f"🍵 YAGURA test message\n"
        f"Host: {socket.gethostname()}\n"
        f"Time: {_now_msk()}\n"
        f"\n"
        f"Если ты это видишь — связь работает. Дальше в этот чат будут приходить алерты watchdog."
    )
    return send_message(bot_token, chat_id, text)


def send_startup(
    bot_token: str,
    chat_id: str,
    *,
    version: str,
    interval_min: int,
    ai_provider: str,
    baseline_listeners: int,
    baseline_units: int,
) -> tuple[bool, str]:
    """One-shot message when yagura-watch.service starts."""
    host = socket.gethostname()
    ai_label = ai_provider if ai_provider and ai_provider != "none" else "off"
    lines = [
        f"🪴 YAGURA запущен — {host}",
        f"├ Версия: v{version}",
        f"├ Watch interval: {interval_min} мин",
        f"├ AI: {ai_label}",
        f"├ Baseline: {baseline_listeners} listeners · {baseline_units} systemd units",
        f"└ Время: {_now_msk()}",
    ]
    return send_message(bot_token, chat_id, "\n".join(lines))


def send_whitelist_applied(
    bot_token: str,
    chat_id: str,
    *,
    applied_packs: list,
) -> tuple[bool, str]:
    """Notify operator that auto-whitelist rules were merged on watch startup.

    `applied_packs` is a list of known_legit.Match objects. We report what was
    silenced, why it's safe, and how to remove it — so the operator never
    finds a "silently disabled" rule weeks later.
    """
    if not applied_packs:
        return False, "no packs to report"
    host = socket.gethostname()
    lines = [
        f"🪺 YAGURA whitelist обновлён — {host}",
        f"├ При старте обнаружено {len(applied_packs)} легитимных процессов,",
        f"├ для которых добавлены правила тихого подавления:",
        "",
    ]
    for m in applied_packs:
        lines.append(f"● {m.pack_id}")
        if m.description:
            lines.append(f"   Что: {m.description}")
        if m.captured.get("user"):
            lines.append(f"   Под пользователем: {m.captured['user']}")
        if m.why:
            # Берём первую содержательную строку, чтобы не раздуть Telegram.
            short_why = _first_paragraph(m.why)
            lines.append(f"   Почему: {short_why}")
        if m.risk_assessment:
            risk_short = _first_paragraph(m.risk_assessment)
            lines.append(f"   Риск: {risk_short}")
        lines.append(f"   Откатить: sudo yagura whitelist remove-pack {m.pack_id}")
        lines.append("")
    lines.append("Подробнее: sudo yagura whitelist explain <pack_id>")
    lines.append("История: sudo yagura whitelist audit-log")
    return send_message(bot_token, chat_id, "\n".join(lines))


def _first_paragraph(text: str, max_len: int = 240) -> str:
    """Take the first meaningful paragraph and trim to max_len for Telegram."""
    if not text:
        return ""
    paragraph = text.strip().split("\n\n", 1)[0]
    paragraph = " ".join(line.strip() for line in paragraph.splitlines() if line.strip())
    if len(paragraph) > max_len:
        paragraph = paragraph[: max_len - 1].rstrip() + "…"
    return paragraph


def send_heartbeat(
    bot_token: str,
    chat_id: str,
    *,
    uptime_seconds: int,
    ticks: int,
    alerts_sent: int,
) -> tuple[bool, str]:
    """Periodic 'I'm alive' signal. Frequency controlled by watch.heartbeat_hours."""
    host = socket.gethostname()
    lines = [
        f"🌿 YAGURA жив — {host}",
        f"├ Uptime watch: {_fmt_uptime(uptime_seconds)}",
        f"├ Тиков: {ticks} · Алертов: {alerts_sent}",
        f"└ Время: {_now_msk()}",
    ]
    return send_message(bot_token, chat_id, "\n".join(lines))


def send_message(bot_token: str, chat_id: str, text: str) -> tuple[bool, str]:
    if not bot_token or not chat_id:
        return False, "telegram not configured"
    try:
        r = requests.post(
            f"{API_BASE}/bot{bot_token}/sendMessage",
            json={"chat_id": chat_id, "text": text, "disable_web_page_preview": True},
            timeout=15,
        )
    except requests.RequestException as e:
        return False, str(e)
    if r.status_code == 200 and r.json().get("ok"):
        return True, "sent"
    return False, f"HTTP {r.status_code}: {r.text[:200]}"


def send_alert(
    bot_token: str,
    chat_id: str,
    alert: Alert,
    verdict: AlertVerdict | None = None,
    persistent_ticks: int | None = None,
) -> tuple[bool, str]:
    """Send a compact alert to Telegram.

    Format (Variant 1 from operator UX brief):
        🍑 W-NET-001 · HIGH
        host: <hostname>
        tcp/10001 → goronin (root, PID 2100527)
        unit: goronin.service

        🤖 verdict: похоже на легитимный сервис
        → sudo yagura whitelist add process /usr/local/bin/goronin
        → если чужое: sudo systemctl stop goronin.service && kill -9 2100527

    The full AI explanation (`verdict.full`) is intentionally NOT included in
    Telegram — it goes to alerts.log. Telegram stays compact and scannable.
    """
    icon = {"CRITICAL": "🥊", "HIGH": "🍑", "MEDIUM": "🍔", "LOW": "🥝"}.get(alert.severity, "🍔")
    host = socket.gethostname()

    # Header line: rule id + severity. Persistent escalation gets its own marker.
    if persistent_ticks:
        header = f"{icon} {alert.rule_id} · {alert.severity} · [PERSISTENT × {persistent_ticks}]"
    else:
        header = f"{icon} {alert.rule_id} · {alert.severity}"

    lines = [header, f"host: {host}"]
    lines.extend(_compact_body(alert))

    # Verdict block — comes from AI (or static fallback). One short line + one action.
    if verdict is not None:
        lines.append("")
        lines.append(f"🤖 {verdict.one_line}")
        if verdict.action:
            lines.append(f"→ {verdict.action}")

    # Whitelist / block hints — independent of AI, derived from rule + alert context.
    # Always shown when applicable so the operator has a one-line "what to do".
    hints = _action_hints(alert, verdict)
    if hints:
        lines.append("")
        lines.extend(hints)

    return send_message(bot_token, chat_id, "\n".join(lines))


def _compact_body(alert: Alert) -> list[str]:
    """Two-to-three line compact summary of the alert subject. No tree drawings."""
    rid = alert.rule_id
    out: list[str] = []
    if rid in ("W-NET-001", "W-PROC-001"):
        lst = alert.context.get("listener", {}) or {}
        proto = lst.get("proto", "?")
        port = lst.get("port", "?")
        proc = lst.get("process", "?")
        user = lst.get("user", "?")
        pid = lst.get("pid", "?")
        out.append(f"{proto}/{port} → {proc} ({user}, PID {pid})")
        exe = lst.get("exe")
        if exe:
            out.append(f"exe: {exe}")
        unit = (alert.context.get("triage") or {}).get("systemd_unit")
        if unit:
            out.append(f"unit: {unit}")
        return out
    if rid == "W-PROC-002":
        proc = alert.context.get("process", {}) or {}
        pid = proc.get("pid", "?")
        user = proc.get("user", "?")
        cpu = proc.get("cpu", 0)
        cmdline = alert.context.get("cmdline") or proc.get("name", "?")
        out.append(f"{cmdline} (PID {pid}, {user}, CPU {cpu:.0f}%)")
        if alert.context.get("has_local_db"):
            out.append("hint: держит localhost DB-сокеты — похоже на легитимное приложение")
        return out
    if rid == "W-PROC-003":
        c = alert.context.get("connection", {}) or {}
        pid = c.get("pid", "?")
        user = c.get("user", "?")
        raddr = c.get("raddr", "?")
        cmdline = alert.context.get("cmdline") or c.get("process", "?")
        out.append(f"{cmdline} (PID {pid}, {user})")
        out.append(f"→ ESTABLISHED {raddr}")
        ptr = (alert.context.get("triage") or {}).get("ptr")
        if ptr:
            out.append(f"ptr: {ptr}")
        return out
    if rid == "W-FILE-001":
        path = alert.context.get("path", "?")
        out.append(f"file: {path}")
        out.append("hash отличается от baseline")
        return out
    if rid in ("W-CRON-001", "W-CRON-002"):
        j = alert.context.get("job", {}) or {}
        out.append(f"user: {j.get('user', '?')} @ {j.get('schedule', '?')}")
        cmd = j.get("cmd", "")
        if cmd:
            out.append(f"cmd: {cmd[:160]}")
        return out
    if rid == "W-SVC-001":
        out.append(f"unit: {alert.context.get('unit', '?')}")
        return out
    if rid in ("W-USR-001", "W-USR-002"):
        out.append(f"user: {alert.context.get('user', '?')}")
        return out
    # Fallback for unknown rules — just show detail.
    out.append(alert.detail)
    return out


def _action_hints(alert: Alert, verdict: AlertVerdict | None) -> list[str]:
    """One-line whitelist/block suggestions tailored to the alert.

    Design: Yagura NEVER auto-blocks — these are reminders for the operator.
    Both options shown for ambiguous cases ("legit → whitelist", "alien → stop"),
    so the operator always sees the two paths without scrolling docs.
    """
    rid = alert.rule_id
    is_self = bool(verdict and verdict.verdict == "legit_self")

    # Self-detect (deterministic in monitor.py + AI confirmation) — only one action makes sense.
    if is_self:
        return ["→ sudo yagura baseline reset"]

    if rid in ("W-NET-001", "W-PROC-001"):
        lst = alert.context.get("listener", {}) or {}
        pid = lst.get("pid")
        port = lst.get("port")
        exe = lst.get("exe")
        unit = (alert.context.get("triage") or {}).get("systemd_unit")
        out = ["Если знакомое приложение:"]
        if exe:
            out.append(f"→ sudo yagura whitelist add process {exe}")
        if port is not None:
            out.append(f"→ sudo yagura whitelist add port {port}")
        out.append("Если чужое:")
        if unit:
            out.append(f"→ sudo systemctl stop {unit}")
        if pid:
            out.append(f"→ sudo kill -9 {pid}")
        return out
    if rid == "W-PROC-002":
        cmdline = alert.context.get("cmdline") or ""
        exe = alert.context.get("exe") or ""
        proc = alert.context.get("process", {}) or {}
        pid = proc.get("pid")
        out = ["Если знакомое приложение:"]
        # cmdline_substrings — самый точный whitelist для CPU-heavy кастомных приложений.
        token = _shortest_unique_token(cmdline) or exe
        if token:
            out.append(f"→ sudo yagura whitelist add process {token}")
        out.append("Если чужое (возможный майнер):")
        if pid:
            out.append(f"→ sudo kill -9 {pid}")
        return out
    if rid == "W-PROC-003":
        c = alert.context.get("connection", {}) or {}
        pid = c.get("pid")
        cmdline = alert.context.get("cmdline") or ""
        out = ["Расследование (CRITICAL — действуй с осторожностью):"]
        if pid:
            out.append(f"→ ps -fp {pid} && ss -tnp | grep {pid}")
            out.append(f"→ если подтверждён reverse-shell: sudo kill -9 {pid}")
        if cmdline:
            out.append("Если ложная тревога (legit-агент):")
            out.append("→ см. yagura whitelist (нужна пара cmdline+dest, не только cmdline)")
        return out
    if rid == "W-FILE-001":
        path = alert.context.get("path", "")
        return [
            "Расследование:",
            f"→ sudo diff <(cat {path}) <(yagura baseline show | jq -r '.file_hashes.\"{path}\"')",
            "→ проверь cron, новых пользователей и недавно установленные пакеты",
        ]
    if rid in ("W-USR-001", "W-USR-002"):
        user = alert.context.get("user", "?")
        return [
            "Расследование:",
            f"→ getent passwd {user} && sudo grep -r {user} /etc/sudoers /etc/sudoers.d/",
            f"→ если несанкционированно: sudo userdel -r {user}",
        ]
    if rid in ("W-CRON-001", "W-CRON-002"):
        return [
            "Расследование:",
            "→ sudo crontab -u <user> -l && ls -la /etc/cron.* /etc/cron.d/",
            "→ если не твой: sudo crontab -u <user> -e (удали строку)",
        ]
    return []


def _shortest_unique_token(cmdline: str) -> str:
    """Pick a stable substring from a cmdline for whitelist suggestions.

    For `node /var/www/balifornia/balifornia-crm/server/dist/index.js` we want
    `balifornia-crm` (stable, project-specific) — not `node` (too generic) and
    not the full path (breaks if the file moves).
    """
    if not cmdline:
        return ""
    parts = cmdline.split()
    # First non-interpreter token that has a meaningful path component.
    interpreters = {"node", "python", "python3", "python2", "ruby", "perl", "java", "bash", "sh"}
    for p in parts:
        base = p.rsplit("/", 1)[-1]
        if base in interpreters:
            continue
        # `/var/www/balifornia/balifornia-crm/server/dist/index.js` →
        # take the deepest non-generic dir name as a substring.
        if "/" in p:
            segments = [s for s in p.split("/") if s and s not in {"var", "www", "opt", "usr", "local", "bin", "lib", "etc", "tmp", "home", "srv", "dist", "src", "app"}]
            if segments:
                return segments[0]
        return base
    return parts[0] if parts else ""
