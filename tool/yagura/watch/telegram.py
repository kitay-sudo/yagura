"""Telegram alerts. One-way only — no command handling."""

from __future__ import annotations

import socket
from datetime import datetime, timezone

import requests

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
    ai_text: str | None = None,
    persistent_ticks: int | None = None,
) -> tuple[bool, str]:
    # Иконки по severity — единый стиль с goronin (парный проект).
    icon = {"CRITICAL": "🥊", "HIGH": "🍑", "MEDIUM": "🍔", "LOW": "🥝"}.get(alert.severity, "🍔")
    host = socket.gethostname()
    header = f"{icon} YAGURA ALERT — {host}"
    if persistent_ticks:
        header = f"{icon} YAGURA ALERT [PERSISTENT × {persistent_ticks}] — {host}"
    lines = [
        header,
        f"Severity: {alert.severity}",
        f"Rule: {alert.rule_id} ({alert.title})",
        "",
        alert.detail,
    ]
    triage_block = _format_triage(alert)
    if triage_block:
        lines.append("")
        lines.append("Авто-триаж:")
        lines.extend(triage_block)
    fix_hint = _fix_hint(alert)
    if fix_hint:
        lines.append("")
        lines.append("Что делать:")
        lines.extend(fix_hint)
    if ai_text:
        lines.append("")
        lines.append("AI:")
        lines.append(ai_text.strip())
    return send_message(bot_token, chat_id, "\n".join(lines))


def _format_triage(alert: Alert) -> list[str]:
    """Render the triage dossier (if any) as compact lines."""
    triage = alert.context.get("triage")
    if not isinstance(triage, dict) or not triage:
        return []
    out: list[str] = []
    verdict = triage.get("verdict")
    if verdict:
        out.append(f"├ Вердикт: {verdict}")
    for key in ("ps", "ss", "cmdline_full", "exe_link", "ptr", "parent", "systemd_unit"):
        val = triage.get(key)
        if not val:
            continue
        # Многострочные значения сокращаем до первых 2-3 строк, чтобы не раздуть Telegram.
        if isinstance(val, str) and "\n" in val:
            head = "\n  ".join(val.strip().splitlines()[:3])
            out.append(f"├ {key}:")
            out.append(f"  {head}")
        else:
            out.append(f"├ {key}: {val}")
    if out:
        # Превращаем последний `├` в `└` для аккуратности.
        out[-1] = out[-1].replace("├", "└", 1)
    return out


def _fix_hint(alert: Alert) -> list[str]:
    rid = alert.rule_id
    if rid == "W-NET-001":
        lst = alert.context.get("listener", {})
        pid = lst.get("pid", "?")
        return [
            f"- ps -fp {pid}",
            f"- if alien: kill -9 {pid}",
            "- crontab -l && cat /etc/crontab",
            "- yagura scan",
        ]
    if rid == "W-PROC-003":
        c = alert.context.get("connection", {})
        pid = c.get("pid", "?")
        return [
            f"- ps -fp {pid}",
            f"- ss -tnp | grep {pid}",
            f"- kill -9 {pid}",
        ]
    if rid == "W-FILE-001":
        path = alert.context.get("path", "")
        return [
            f"- diff against backup of {path}",
            "- inspect recent users / cron / new packages",
        ]
    if rid in ("W-USR-001", "W-USR-002"):
        return [
            "- cat /etc/passwd | awk -F: '$3==0'",
            "- cat /etc/sudoers /etc/sudoers.d/*",
        ]
    if rid in ("W-CRON-001", "W-CRON-002"):
        return [
            "- crontab -l",
            "- ls -la /etc/cron.* /etc/cron.d/",
            "- grep -r '' /var/spool/cron/",
        ]
    return []
