"""Tests for the AI verdict parser + retry/fallback flow.

We never call the real AI here. A FakeAI returns the responses we hand it,
in order, so we can assert on each step (parse, retry, fallback).
"""

from yagura.ai import verdict


class FakeAI:
    """Deterministic stand-in for AIClient. Pops responses off a list per call."""

    name = "fake"

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def complete(self, prompt: str, max_tokens: int = 500) -> str:
        self.calls += 1
        if not self.responses:
            return ""
        return self.responses.pop(0)


def test_parse_clean_json():
    raw = '{"verdict":"legit_known_app","one_line":"nginx","action":"sudo yagura whitelist add process /usr/sbin/nginx","full":"стандартный веб-сервер"}'
    v = verdict.parse_verdict(raw)
    assert v is not None
    assert v.verdict == "legit_known_app"
    assert v.one_line == "nginx"
    assert v.action.startswith("sudo yagura whitelist add")
    assert v.source == "ai"


def test_parse_strips_markdown_fence():
    raw = '```json\n{"verdict":"legit_self","one_line":"yagura","action":null,"full":"."}\n```'
    v = verdict.parse_verdict(raw)
    assert v is not None
    assert v.verdict == "legit_self"
    assert v.action is None


def test_parse_tolerates_trailing_prose():
    raw = '{"verdict":"suspicious","one_line":"новый бинарь в /tmp","action":"ps -fp 123","full":"."}\n\nHope this helps!'
    v = verdict.parse_verdict(raw)
    assert v is not None
    assert v.verdict == "suspicious"


def test_parse_rejects_invalid_enum():
    raw = '{"verdict":"definitely_bad","one_line":"x","action":null,"full":"."}'
    assert verdict.parse_verdict(raw) is None


def test_parse_rejects_missing_one_line():
    raw = '{"verdict":"unknown","one_line":"","action":null,"full":"."}'
    assert verdict.parse_verdict(raw) is None


def test_parse_returns_none_for_empty():
    assert verdict.parse_verdict("") is None
    assert verdict.parse_verdict("   ") is None


def test_parse_returns_none_for_garbage():
    assert verdict.parse_verdict("Это серьёзно, надо проверить") is None


def test_get_verdict_with_retry_succeeds_first_try():
    ai = FakeAI([
        '{"verdict":"legit_known_app","one_line":"nginx","action":null,"full":"."}',
    ])
    v = verdict.get_verdict_with_retry(ai, "prompt")
    assert v is not None
    assert v.verdict == "legit_known_app"
    assert ai.calls == 1


def test_get_verdict_with_retry_succeeds_on_retry():
    """First response is garbage; second is valid JSON. Should accept the retry."""
    ai = FakeAI([
        "Это серьёзно, надо проверить",  # not JSON
        '{"verdict":"suspicious","one_line":"подозрительно","action":"ps -fp 1","full":"."}',
    ])
    v = verdict.get_verdict_with_retry(ai, "prompt")
    assert v is not None
    assert v.verdict == "suspicious"
    assert ai.calls == 2


def test_get_verdict_with_retry_fails_twice_returns_none():
    """Both responses are garbage. Caller should fall back to static."""
    ai = FakeAI([
        "garbage 1",
        "garbage 2",
    ])
    v = verdict.get_verdict_with_retry(ai, "prompt")
    assert v is None
    assert ai.calls == 2  # we tried exactly twice, no recursion


def test_get_verdict_with_retry_handles_transport_error():
    class BoomAI:
        def complete(self, prompt, max_tokens=500):
            raise ConnectionError("network down")
    v = verdict.get_verdict_with_retry(BoomAI(), "prompt")
    assert v is None  # no crash, just None — caller falls back


def test_static_fallback_self():
    v = verdict.static_fallback("W-NET-001", "HIGH", is_self=True)
    assert v.verdict == "legit_self"
    assert "yagura baseline reset" in (v.action or "")
    assert v.source == "static_fallback"


def test_static_fallback_critical_non_self():
    v = verdict.static_fallback("W-PROC-003", "CRITICAL", is_self=False)
    assert v.verdict == "suspicious"
    assert v.action is None  # don't suggest a destructive action without AI confirmation


def test_static_fallback_high_non_self():
    v = verdict.static_fallback("W-NET-001", "HIGH", is_self=False)
    assert v.verdict == "unknown"


def test_format_alert_context_emits_process_tree():
    ctx = {
        "listener": {
            "pid": 2775254,
            "user": "admingod",
            "exe": "/home/admingod/.cache/puppeteer/chrome/linux-120/chrome",
            "cwd": "/var/www/app",
            "cmdline": "chrome --headless",
            "ppid": 2766166,
            "parent_name": "node",
            "parent_cmdline": "node /var/www/app/server/index.js",
        }
    }
    out = verdict.format_alert_context(ctx)
    assert "process tree:" in out
    assert "ppid=2766166" in out
    assert "node" in out
    assert "cwd: /var/www/app" in out


def test_format_alert_context_skips_block_when_no_tree_data():
    ctx = {"listener": {"pid": 1, "user": "root", "exe": "/usr/sbin/sshd"}}
    out = verdict.format_alert_context(ctx)
    assert "process tree:" not in out


def test_format_alert_context_handles_empty():
    assert verdict.format_alert_context({}) == ""
    assert verdict.format_alert_context(None) == ""  # type: ignore[arg-type]
