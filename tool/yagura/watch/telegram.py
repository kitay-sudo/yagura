"""Telegram alerts. One-way only — no command handling."""

from __future__ import annotations

import socket
from datetime import datetime

import requests

from yagura.watch.rules import Alert

API_BASE = "https://api.telegram.org"


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
        f"Time: {datetime.now().isoformat(timespec='seconds')}\n"
        f"\n"
        f"Если ты это видишь — связь работает. Дальше в этот чат будут приходить алерты watchdog."
    )
    return send_message(bot_token, chat_id, text)


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
    bot_token: str, chat_id: str, alert: Alert, ai_text: str | None = None
) -> tuple[bool, str]:
    # Иконки по severity — единый стиль с goronin (парный проект).
    icon = {"CRITICAL": "🥊", "HIGH": "🍑", "MEDIUM": "🍔", "LOW": "🥝"}.get(alert.severity, "🍔")
    host = socket.gethostname()
    lines = [
        f"{icon} YAGURA ALERT — {host}",
        f"Severity: {alert.severity}",
        f"Rule: {alert.rule_id} ({alert.title})",
        "",
        alert.detail,
    ]
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
