"""Color palette for Rich. Sky-blue accent, matches the landing."""

from rich.theme import Theme

ACCENT = "bright_cyan"
ACCENT_DIM = "cyan"

YAGURA_THEME = Theme(
    {
        "accent": ACCENT,
        "accent.dim": ACCENT_DIM,
        "ok": "green",
        "warn": "yellow",
        "danger": "bright_red",
        "muted": "grey50",
        "tower": "bright_cyan bold",
        "kanji": "grey39",
        "header": "bold bright_cyan",
        "score.good": "bright_green",
        "score.mid": "yellow",
        "score.bad": "bright_red",
        "rule.id": "bold cyan",
        "sev.critical": "bright_red bold",
        "sev.high": "red",
        "sev.medium": "yellow",
        "sev.low": "blue",
    }
)


def severity_style(severity: str) -> str:
    return {
        "CRITICAL": "sev.critical",
        "HIGH": "sev.high",
        "MEDIUM": "sev.medium",
        "LOW": "sev.low",
    }.get(severity, "muted")


def score_style(score: int) -> str:
    if score >= 75:
        return "score.good"
    if score >= 50:
        return "score.mid"
    return "score.bad"
