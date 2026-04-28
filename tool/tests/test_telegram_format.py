"""Tests for the compact Telegram alert format.

We don't call the actual Telegram API — we patch send_message to capture the
text and then assert on its structure.
"""

from yagura.ai.verdict import AlertVerdict
from yagura.watch import telegram
from yagura.watch.rules import Alert


class CapturingSender:
    def __init__(self):
        self.last_text: str | None = None

    def __call__(self, bot_token, chat_id, text):
        self.last_text = text
        return True, "sent"


def _patch(monkeypatch):
    cap = CapturingSender()
    monkeypatch.setattr(telegram, "send_message", cap)
    return cap


def _net_alert() -> Alert:
    return Alert(
        rule_id="W-NET-001",
        severity="HIGH",
        title="New listener",
        detail="tcp/10001 → goronin (PID 2100527, user root)",
        context={
            "listener": {
                "proto": "tcp",
                "port": 10001,
                "process": "goronin",
                "exe": "/usr/local/bin/goronin",
                "user": "root",
                "pid": 2100527,
            },
            "triage": {"systemd_unit": "goronin.service", "ps": "..."},
        },
    )


def test_format_is_compact_no_tree(monkeypatch):
    cap = _patch(monkeypatch)
    telegram.send_alert("tok", "chat", _net_alert(), verdict=None)
    text = cap.last_text
    assert text is not None
    # Compact header
    assert "W-NET-001 · HIGH" in text
    # No tree-drawing characters (the old format used these heavily)
    assert "├" not in text
    assert "└" not in text
    # No old "Auto-triage:" section
    assert "Авто-триаж" not in text


def test_format_shows_listener_body(monkeypatch):
    cap = _patch(monkeypatch)
    telegram.send_alert("tok", "chat", _net_alert(), verdict=None)
    text = cap.last_text
    assert "tcp/10001 → goronin (root, PID 2100527)" in text
    assert "exe: /usr/local/bin/goronin" in text
    assert "unit: goronin.service" in text


def test_format_shows_whitelist_and_block_hints_when_not_self(monkeypatch):
    cap = _patch(monkeypatch)
    telegram.send_alert("tok", "chat", _net_alert(), verdict=None)
    text = cap.last_text
    # Both paths offered — operator picks based on familiarity.
    assert "Если знакомое приложение" in text
    assert "sudo yagura whitelist add process /usr/local/bin/goronin" in text
    assert "sudo yagura whitelist add port 10001" in text
    assert "Если чужое" in text
    assert "sudo systemctl stop goronin.service" in text
    assert "sudo kill -9 2100527" in text


def test_format_self_verdict_only_shows_baseline_reset(monkeypatch):
    cap = _patch(monkeypatch)
    self_verdict = AlertVerdict(
        verdict="legit_self",
        one_line="это сам Yagura",
        action="sudo yagura baseline reset",
        full="...",
        source="static_fallback",
    )
    telegram.send_alert("tok", "chat", _net_alert(), verdict=self_verdict)
    text = cap.last_text
    assert "🤖 это сам Yagura" in text
    assert "sudo yagura baseline reset" in text
    # When self, we don't dump whitelist/block hints — only the reset action.
    assert "sudo kill -9" not in text
    assert "Если знакомое" not in text


def test_format_legit_known_app_verdict_with_whitelist_hints(monkeypatch):
    cap = _patch(monkeypatch)
    v = AlertVerdict(
        verdict="legit_known_app",
        one_line="похоже на легитимный сервис",
        action="sudo yagura whitelist add process /usr/local/bin/goronin",
        full="полное объяснение для лога",
        source="ai",
    )
    telegram.send_alert("tok", "chat", _net_alert(), verdict=v)
    text = cap.last_text
    # AI verdict line
    assert "🤖 похоже на легитимный сервис" in text
    # AI action line
    assert "→ sudo yagura whitelist add process /usr/local/bin/goronin" in text
    # And the heuristic whitelist/block hints are STILL shown — operator gets
    # both AI's suggestion and the standard menu.
    assert "Если знакомое приложение" in text
    # Full explanation must NOT appear in Telegram (logs only).
    assert "полное объяснение для лога" not in text


def test_format_persistent_marker(monkeypatch):
    cap = _patch(monkeypatch)
    telegram.send_alert("tok", "chat", _net_alert(), verdict=None, persistent_ticks=5)
    text = cap.last_text
    assert "PERSISTENT × 5" in text


def test_format_proc003_critical_uses_investigation_hints(monkeypatch):
    cap = _patch(monkeypatch)
    a = Alert(
        rule_id="W-PROC-003",
        severity="CRITICAL",
        title="Reverse-shell heuristic",
        detail="python3 (PID 999, user www) → ESTABLISHED 8.8.8.8:443",
        context={
            "connection": {
                "pid": 999,
                "user": "www",
                "raddr": "8.8.8.8:443",
                "process": "python3",
            },
            "cmdline": "python3 /opt/foo/agent.py",
        },
    )
    telegram.send_alert("tok", "chat", a, verdict=None)
    text = cap.last_text
    assert "W-PROC-003 · CRITICAL" in text
    assert "Расследование" in text
    assert "ps -fp 999" in text
    assert "kill -9 999" in text
