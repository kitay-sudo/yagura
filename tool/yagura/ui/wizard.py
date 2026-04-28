"""Interactive prompts (questionary). All wizard funcs degrade gracefully when no TTY."""

from __future__ import annotations

import sys

import questionary
from questionary import Choice
from rich.console import Console

from yagura.analyzers.redflags import Finding


def has_tty() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def ask_ai_provider() -> tuple[str, str]:
    """Returns (provider, api_key). Provider is 'none' if user skipped."""
    if not has_tty():
        return ("none", "")

    provider = questionary.select(
        "AI-провайдер для анализа отчёта (опционально):",
        choices=[
            Choice("Claude (Anthropic)", "claude"),
            Choice("OpenAI (ChatGPT)", "openai"),
            Choice("Gemini (Google)", "gemini"),
            Choice("Пропустить", "none"),
        ],
    ).ask()
    if provider in (None, "none"):
        return ("none", "")

    api_key = questionary.password(f"Введи API-ключ для {provider}:").ask()
    if not api_key:
        return ("none", "")
    return (provider, api_key.strip())


def ask_apply_recommended() -> bool:
    if not has_tty():
        return False
    answer = questionary.confirm(
        "Применить рекомендованный hardening?",
        default=True,
    ).ask()
    return bool(answer)


def ask_harden_actions(recommendations: list[dict], findings: list[Finding]) -> list[str]:
    """Returns selected action_ids. Empty list = user skipped."""
    if not has_tty() or not recommendations:
        return []

    rule_titles = {f.rule_id: f.title for f in findings}
    choices = []
    for rec in recommendations:
        related = ", ".join(rec["related_rules"])
        title_hint = rule_titles.get(rec["related_rules"][0], "") if rec["related_rules"] else ""
        label = f"[{rec['severity']}] {rec['action_id']}  — {title_hint}  ({related})"
        choices.append(
            Choice(label, rec["action_id"], checked=rec["severity"] in ("HIGH", "CRITICAL"))
        )

    selected = questionary.checkbox(
        "Выбери что применить (пробел — отметить, enter — подтвердить):",
        choices=choices,
    ).ask()
    return selected or []


def confirm_apply(action_id: str, preview_lines: list[str]) -> bool:
    if not has_tty():
        return False
    console = Console()
    console.print()
    console.print(f"[accent]→[/accent] [bold]{action_id}[/bold] — preview:")
    for line in preview_lines:
        console.print(f"  [muted]$[/muted] {line}")
    return bool(questionary.confirm("Применить?", default=True).ask())


def ask_enable_watch() -> bool:
    if not has_tty():
        return False
    return bool(
        questionary.confirm(
            "Поставить yagura-watch для постоянного мониторинга? (Telegram-алерты)",
            default=False,
        ).ask()
    )


def ask_telegram() -> tuple[str, str, int]:
    """Returns (bot_token, chat_id, interval_minutes)."""
    if not has_tty():
        return ("", "", 5)
    bot_token = questionary.password("Telegram bot token:").ask() or ""
    chat_id = questionary.text("Telegram chat_id:").ask() or ""
    interval_str = questionary.text("Интервал проверки в минутах:", default="5").ask() or "5"
    try:
        interval = max(1, int(interval_str))
    except ValueError:
        interval = 5
    return (bot_token.strip(), chat_id.strip(), interval)
