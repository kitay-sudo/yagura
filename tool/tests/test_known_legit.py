"""Tests for bundled known-legit auto-whitelist."""

from yagura.watch import known_legit, rules


def _empty_cfg() -> dict:
    return {
        "watch": {"rules_disabled": []},
        "whitelist": {
            "ports": [],
            "processes": [],
            "ssh_ips": [],
            "cmdline_substrings": [],
            "process_dest": [],
        },
    }


def test_known_legit_yml_loads():
    packs = known_legit.load_packs()
    assert isinstance(packs, list)
    # At least the google-api pack is shipped.
    pack_ids = {p.get("id") for p in packs}
    assert "google-api-python-agent" in pack_ids


def test_detect_matches_with_fm_agent_to_google(monkeypatch):
    # Simulate fm-agent python3 → 34.102.x.x with PTR resolving to *.googleusercontent.com
    monkeypatch.setattr(
        known_legit.net_collector,
        "collect",
        lambda: {
            "established": [
                {
                    "laddr": "10.0.0.1:30000",
                    "raddr": "34.102.162.51:443",
                    "pid": 1234,
                    "process": "python3",
                    "exe": "/usr/bin/python3",
                    "cmdline": "/usr/bin/python3 /opt/fm-agent/main.py",
                    "user": "fm-agent",
                }
            ],
            "listeners": [],
        },
    )
    monkeypatch.setattr(known_legit.sys_collector, "collect", lambda: {"distro": {"id": "debian"}})
    monkeypatch.setattr(known_legit.socket, "getfqdn", lambda: "host.example.com")
    # Force PTR to return a Google hostname.
    monkeypatch.setattr(known_legit, "_ptr", lambda ip: "51.162.102.34.bc.googleusercontent.com")
    matches = known_legit.detect_matches()
    pack_ids = {m.pack_id for m in matches}
    assert "google-api-python-agent" in pack_ids
    google = [m for m in matches if m.pack_id == "google-api-python-agent"][0]
    assert google.captured["user"] == "fm-agent"
    assert google.auto_apply is True


def test_apply_matches_writes_to_config(monkeypatch, tmp_path):
    # Avoid touching real /etc/yagura — patch save_config to a no-op.
    saved = {}
    monkeypatch.setattr(known_legit, "save_config", lambda c: saved.update({"called": True, "cfg": c}))
    monkeypatch.setattr(known_legit, "_audit_write", lambda r: None)

    cfg = _empty_cfg()
    fake_match = known_legit.Match(
        pack_id="test-pack",
        description="test",
        auto_apply=True,
        captured={"user": "fm-agent"},
        whitelist_entries=[
            {
                "_target": "process_dest",
                "cmdline": "fm-agent",
                "dest_hostname": "*.googleapis.com",
            }
        ],
    )
    applied = known_legit.apply_matches(cfg, [fake_match], only_auto=True)
    assert len(applied) == 1
    assert applied[0].pack_id == "test-pack"
    assert len(cfg["whitelist"]["process_dest"]) == 1
    entry = cfg["whitelist"]["process_dest"][0]
    assert entry["cmdline"] == "fm-agent"
    assert entry["dest_hostname"] == "*.googleapis.com"
    assert entry["source"] == "bundled:test-pack"
    assert "applied_at" in entry
    assert saved.get("called")


def test_apply_matches_idempotent(monkeypatch):
    monkeypatch.setattr(known_legit, "save_config", lambda c: None)
    monkeypatch.setattr(known_legit, "_audit_write", lambda r: None)
    cfg = _empty_cfg()
    fake_match = known_legit.Match(
        pack_id="dupe-pack",
        description="t",
        auto_apply=True,
        captured={},
        whitelist_entries=[
            {"_target": "process_dest", "cmdline": "x", "dest_hostname": "*.example.com"}
        ],
    )
    a1 = known_legit.apply_matches(cfg, [fake_match])
    a2 = known_legit.apply_matches(cfg, [fake_match])  # second call should be no-op
    assert len(a1) == 1
    assert len(a2) == 0
    assert len(cfg["whitelist"]["process_dest"]) == 1


def test_apply_skips_manual_packs_under_only_auto(monkeypatch):
    monkeypatch.setattr(known_legit, "save_config", lambda c: None)
    monkeypatch.setattr(known_legit, "_audit_write", lambda r: None)
    cfg = _empty_cfg()
    manual = known_legit.Match(
        pack_id="manual-pack",
        description="t",
        auto_apply=False,
        captured={},
        whitelist_entries=[{"_target": "cmdline_substrings", "value": "foo"}],
    )
    a = known_legit.apply_matches(cfg, [manual], only_auto=True)
    assert len(a) == 0
    # but with only_auto=False, it applies
    a2 = known_legit.apply_matches(cfg, [manual], only_auto=False)
    assert len(a2) == 1


def test_audit_log_records_apply_and_remove(monkeypatch, tmp_path):
    """Audit log must capture both apply and remove with actor + timestamp."""
    monkeypatch.setattr(known_legit, "save_config", lambda c: None)
    monkeypatch.setattr(known_legit, "AUDIT_LOG", tmp_path / "audit.log")

    cfg = _empty_cfg()
    fake_match = known_legit.Match(
        pack_id="audited-pack",
        description="t",
        auto_apply=True,
        captured={"user": "fm-agent"},
        whitelist_entries=[
            {"_target": "process_dest", "cmdline": "fm-agent", "dest_hostname": "*.x.com"}
        ],
    )
    known_legit.apply_matches(cfg, [fake_match], actor="cli:test")
    known_legit.remove_pack(cfg, "audited-pack", actor="cli:test-remove")

    entries = known_legit.read_audit_log(limit=10)
    assert len(entries) == 2
    # Newest first.
    assert entries[0]["action"] == "remove"
    assert entries[0]["pack_id"] == "audited-pack"
    assert entries[0]["actor"] == "cli:test-remove"
    assert entries[1]["action"] == "apply"
    assert entries[1]["pack_id"] == "audited-pack"
    assert entries[1]["actor"] == "cli:test"
    assert entries[1]["captured"] == {"user": "fm-agent"}


def test_match_propagates_why_and_risk_fields(monkeypatch):
    # Ensure new metadata fields end up on the Match object so Telegram can render them.
    monkeypatch.setattr(known_legit.sys_collector, "collect", lambda: {"distro": {"id": "debian"}})
    monkeypatch.setattr(known_legit.socket, "getfqdn", lambda: "host.example.com")
    monkeypatch.setattr(
        known_legit.net_collector,
        "collect",
        lambda: {
            "established": [
                {
                    "raddr": "34.102.162.51:443",
                    "pid": 1,
                    "process": "python3",
                    "exe": "/usr/bin/python3",
                    "cmdline": "/usr/bin/python3 /opt/x.py",
                    "user": "fm-agent",
                }
            ],
            "listeners": [],
        },
    )
    monkeypatch.setattr(known_legit, "_ptr", lambda ip: "x.googleusercontent.com")
    matches = known_legit.detect_matches()
    google = next((m for m in matches if m.pack_id == "google-api-python-agent"), None)
    assert google is not None
    assert google.why  # non-empty
    assert google.risk_assessment
    assert google.how_to_audit


def test_find_pack_lookup():
    pack = known_legit.find_pack("google-api-python-agent")
    assert pack is not None
    assert pack["id"] == "google-api-python-agent"
    assert pack.get("why")
    assert known_legit.find_pack("nonexistent-pack") is None


def test_bundled_dict_cmdline_substring_matches(monkeypatch):
    # Whitelist entries from bundled packs are dicts {value, source}.
    # rules._cmdline_whitelisted must accept BOTH plain strings AND dicts.
    cfg = _empty_cfg()
    cfg["whitelist"]["cmdline_substrings"] = [
        {"value": "balifornia-crm", "source": "bundled:nodejs-localhost-db-app"}
    ]
    assert rules._cmdline_whitelisted(cfg, "node /var/www/balifornia-crm/index.js")
    assert not rules._cmdline_whitelisted(cfg, "node /opt/other/app.js")


def test_remove_pack_strips_tagged_entries(monkeypatch):
    monkeypatch.setattr(known_legit, "save_config", lambda c: None)
    cfg = _empty_cfg()
    cfg["whitelist"]["process_dest"] = [
        {"cmdline": "x", "dest_ip": "1.0.0.0/8", "source": "bundled:p1"},
        {"cmdline": "y", "dest_ip": "2.0.0.0/8", "source": "manual"},
    ]
    removed = known_legit.remove_pack(cfg, "p1")
    assert removed == 1
    assert len(cfg["whitelist"]["process_dest"]) == 1
    assert cfg["whitelist"]["process_dest"][0]["source"] == "manual"
