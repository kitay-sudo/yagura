"""Tests for the install-time triage wizard.

We mock both collectors (network/services) and the AI client so the wizard
runs in-memory with deterministic input.
"""

import json

from yagura.watch import triage_install


def _patch_collectors(monkeypatch, listeners=None, units=None):
    """Replace network.collect / services.collect with fakes."""
    monkeypatch.setattr(
        triage_install.network,
        "collect",
        lambda: {"listeners": listeners or [], "established": []},
    )
    monkeypatch.setattr(
        triage_install.services,
        "collect",
        lambda: {"present": True, "enabled_units": units or [], "suspicious_units": []},
    )


def _patch_save(monkeypatch):
    """Don't actually write /etc/yagura/config.yml in tests."""
    monkeypatch.setattr(triage_install, "save_config", lambda cfg: None)
    # The known_legit audit log writer touches the filesystem too — silence it.
    from yagura.watch import known_legit
    monkeypatch.setattr(known_legit, "_audit_write", lambda rec: None)


class FakeAI:
    """Returns canned JSON responses in order."""
    name = "fake"

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def complete(self, prompt: str, max_tokens: int = 1500) -> str:
        self.calls += 1
        return self.responses.pop(0)


def test_collect_items_dedupes_listener_and_unit(monkeypatch):
    _patch_collectors(
        monkeypatch,
        listeners=[
            {
                "proto": "tcp", "port": 22, "ip": "0.0.0.0", "pid": 1,
                "process": "sshd", "exe": "/usr/sbin/sshd", "user": "root",
                "cmdline": "/usr/sbin/sshd", "suspicious_path": False,
            },
        ],
        units=["sshd.service", "nginx.service", "yagura-watch.service"],
    )
    items = triage_install.collect_items()
    # sshd appears once (listener entry, unit dedup'd)
    sshd = [it for it in items if it.process == "sshd" or it.unit == "sshd.service"]
    assert len(sshd) == 1
    # yagura-watch.service is auto-classified as self
    yag = [it for it in items if it.unit == "yagura-watch.service"]
    assert len(yag) == 1
    assert yag[0].source == "self-detect"
    assert yag[0].chosen == "whitelist"


def test_heuristics_classify_known_processes(monkeypatch):
    _patch_collectors(
        monkeypatch,
        listeners=[
            {"proto": "tcp", "port": 22, "ip": "0.0.0.0", "pid": 1, "process": "sshd",
             "exe": "/usr/sbin/sshd", "user": "root", "cmdline": "", "suspicious_path": False},
            {"proto": "tcp", "port": 80, "ip": "0.0.0.0", "pid": 2, "process": "nginx",
             "exe": "/usr/sbin/nginx", "user": "www-data", "cmdline": "", "suspicious_path": False},
            {"proto": "tcp", "port": 4444, "ip": "0.0.0.0", "pid": 99, "process": "miner",
             "exe": "/tmp/.x/miner", "user": "root", "cmdline": "", "suspicious_path": True},
            {"proto": "tcp", "port": 10001, "ip": "0.0.0.0", "pid": 100, "process": "goronin",
             "exe": "/usr/local/bin/goronin", "user": "root", "cmdline": "", "suspicious_path": False},
        ],
    )
    items = triage_install.collect_items()
    triage_install.classify_with_heuristics(items)
    by_proc = {it.process: it for it in items}
    assert by_proc["sshd"].verdict == "system"
    assert by_proc["sshd"].chosen == "whitelist"
    assert by_proc["nginx"].verdict == "known_app"
    assert by_proc["nginx"].chosen == "whitelist"
    assert by_proc["miner"].verdict == "suspicious"
    assert by_proc["miner"].chosen == "block"
    # Unknown custom service: heuristic punts to operator (skip), not auto-whitelisted.
    assert by_proc["goronin"].verdict == "custom"
    assert by_proc["goronin"].chosen == "skip"


def test_ai_classification_overrides_heuristics(monkeypatch):
    _patch_collectors(
        monkeypatch,
        listeners=[
            {"proto": "tcp", "port": 10001, "ip": "0.0.0.0", "pid": 100, "process": "goronin",
             "exe": "/usr/local/bin/goronin", "user": "root", "cmdline": "", "suspicious_path": False},
        ],
    )
    ai = FakeAI([
        json.dumps([
            {"index": 0, "verdict": "custom", "one_line": "пользовательский сервис под systemd",
             "recommend": "whitelist"},
        ]),
    ])
    items = triage_install.collect_items()
    ok = triage_install.classify_with_ai(items, ai)
    assert ok
    assert items[0].verdict == "custom"
    assert items[0].recommend == "whitelist"
    assert items[0].source == "ai"


def test_ai_retry_on_garbage(monkeypatch):
    _patch_collectors(
        monkeypatch,
        listeners=[
            {"proto": "tcp", "port": 10001, "ip": "0.0.0.0", "pid": 100, "process": "goronin",
             "exe": "/usr/local/bin/goronin", "user": "root", "cmdline": "", "suspicious_path": False},
        ],
    )
    ai = FakeAI([
        "это не json",
        json.dumps([{"index": 0, "verdict": "custom", "one_line": "x", "recommend": "skip"}]),
    ])
    items = triage_install.collect_items()
    ok = triage_install.classify_with_ai(items, ai)
    assert ok
    assert ai.calls == 2


def test_ai_garbage_twice_falls_back_to_heuristic(monkeypatch):
    _patch_collectors(
        monkeypatch,
        listeners=[
            {"proto": "tcp", "port": 22, "ip": "0.0.0.0", "pid": 1, "process": "sshd",
             "exe": "/usr/sbin/sshd", "user": "root", "cmdline": "", "suspicious_path": False},
        ],
    )
    ai = FakeAI(["garbage1", "garbage2"])
    items = triage_install.collect_items()
    ok = triage_install.classify_with_ai(items, ai)
    assert ok is False  # AI failed
    triage_install.classify_with_heuristics(items)
    # Heuristic still classified sshd as system → whitelist.
    assert items[0].verdict == "system"
    assert items[0].chosen == "whitelist"


def test_apply_decisions_writes_whitelist_and_blocklist(monkeypatch):
    _patch_save(monkeypatch)
    cfg = {
        "whitelist": {"ports": [22], "processes": []},
        "blocklist": {"processes": [], "units": []},
    }
    items = [
        triage_install.TriageItem(
            kind="listener", label="nginx · tcp/80", process="nginx",
            exe="/usr/sbin/nginx", proto="tcp", port=80, user="www-data",
            verdict="known_app", recommend="whitelist", chosen="whitelist", source="ai",
        ),
        triage_install.TriageItem(
            kind="listener", label="miner · tcp/4444", process="miner",
            exe="/tmp/.x/miner", proto="tcp", port=4444, user="root",
            verdict="suspicious", recommend="block", chosen="block", source="ai",
        ),
        triage_install.TriageItem(
            kind="listener", label="custom · tcp/9999", process="custom",
            exe="/opt/custom/bin", proto="tcp", port=9999, user="root",
            verdict="custom", recommend="skip", chosen="skip", source="ai",
        ),
    ]
    outcome = triage_install.apply_decisions(cfg, items)
    assert outcome.applied_whitelist == 1
    assert outcome.applied_block == 1
    assert outcome.skipped == 1
    assert "/usr/sbin/nginx" in cfg["whitelist"]["processes"]
    assert 80 in cfg["whitelist"]["ports"]
    # blocklist stores dicts with source tag for later audit
    assert any(e.get("value") == "/tmp/.x/miner" for e in cfg["blocklist"]["processes"])


def test_apply_decisions_does_not_kill_processes(monkeypatch):
    """Sanity: blocklist is metadata only — apply_decisions never spawns a kill.

    We patch subprocess.run / os.kill to assert they're not invoked.
    """
    _patch_save(monkeypatch)
    import subprocess as _sp
    import os as _os
    called = {"run": 0, "kill": 0}
    monkeypatch.setattr(_sp, "run", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("subprocess.run called!")))
    monkeypatch.setattr(_sp, "call", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("subprocess.call called!")))
    if hasattr(_os, "kill"):
        original_kill = _os.kill
        def fake_kill(*a, **kw):
            called["kill"] += 1
            return original_kill(*a, **kw)
        monkeypatch.setattr(_os, "kill", fake_kill)
    cfg = {"whitelist": {"ports": [], "processes": []}, "blocklist": {"processes": [], "units": []}}
    items = [
        triage_install.TriageItem(
            kind="listener", label="miner · tcp/4444", process="miner",
            exe="/tmp/.x/miner", proto="tcp", port=4444, user="root",
            verdict="suspicious", recommend="block", chosen="block", source="ai",
        ),
    ]
    triage_install.apply_decisions(cfg, items)
    assert called["kill"] == 0
