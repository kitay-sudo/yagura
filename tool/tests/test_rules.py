"""Watch-rule tests using fake baseline + monkey-patched collectors."""

from yagura.watch import rules


def _baseline() -> dict:
    return {
        "listeners": [{"port": 22, "proto": "tcp"}],
        "cron_jobs": [],
        "systemd_units": ["sshd.service"],
        "uid_zero_users": ["root"],
        "sudo_users": [],
        "file_hashes": {"/etc/passwd": "sha256:abc"},
    }


def _empty_cfg() -> dict:
    return {
        "watch": {"rules_disabled": []},
        "whitelist": {"ports": [], "processes": [], "ssh_ips": []},
    }


def test_new_listener_triggers_alert(monkeypatch):
    base = _baseline()
    monkeypatch.setattr(
        rules.network,
        "collect",
        lambda: {
            "listeners": [
                {
                    "port": 22,
                    "proto": "tcp",
                    "ip": "0.0.0.0",
                    "pid": 1,
                    "process": "sshd",
                    "exe": "/usr/sbin/sshd",
                    "user": "root",
                    "suspicious_path": False,
                },
                {
                    "port": 4444,
                    "proto": "tcp",
                    "ip": "0.0.0.0",
                    "pid": 99,
                    "process": "miner",
                    "exe": "/tmp/.x/miner",
                    "user": "root",
                    "suspicious_path": True,
                },
            ],
            "established": [],
            "interfaces": [],
        },
    )
    monkeypatch.setattr(
        rules.cron,
        "collect",
        lambda: {"jobs": [], "downloader_jobs": [], "suspicious_dir_jobs": [], "base64_jobs": []},
    )
    monkeypatch.setattr(
        rules.services,
        "collect",
        lambda: {"present": True, "enabled_units": ["sshd.service"], "suspicious_units": []},
    )
    monkeypatch.setattr(
        rules.users,
        "collect",
        lambda: {
            "users": [],
            "uid_zero": ["root"],
            "empty_password_users": [],
            "sudoers": {"lines": [], "nopasswd": []},
        },
    )
    monkeypatch.setattr(rules.files, "collect", lambda: {"hashes": {"/etc/passwd": "sha256:abc"}})
    monkeypatch.setattr(
        rules.system, "collect", lambda: {"top_processes": [], "memory": {}, "disk": []}
    )

    alerts = rules.evaluate(base, _empty_cfg())
    rule_ids = [a.rule_id for a in alerts]
    assert "W-NET-001" in rule_ids
    assert "W-PROC-001" in rule_ids


def test_file_hash_change_is_critical(monkeypatch):
    base = _baseline()
    monkeypatch.setattr(
        rules.network,
        "collect",
        lambda: {
            "listeners": [
                {
                    "port": 22,
                    "proto": "tcp",
                    "ip": "0.0.0.0",
                    "pid": 1,
                    "process": "sshd",
                    "exe": "/usr/sbin/sshd",
                    "user": "root",
                    "suspicious_path": False,
                }
            ],
            "established": [],
            "interfaces": [],
        },
    )
    monkeypatch.setattr(
        rules.cron,
        "collect",
        lambda: {"jobs": [], "downloader_jobs": [], "suspicious_dir_jobs": [], "base64_jobs": []},
    )
    monkeypatch.setattr(
        rules.services,
        "collect",
        lambda: {"present": True, "enabled_units": ["sshd.service"], "suspicious_units": []},
    )
    monkeypatch.setattr(
        rules.users,
        "collect",
        lambda: {
            "users": [],
            "uid_zero": ["root"],
            "empty_password_users": [],
            "sudoers": {"lines": [], "nopasswd": []},
        },
    )
    monkeypatch.setattr(
        rules.files, "collect", lambda: {"hashes": {"/etc/passwd": "sha256:NEW_HASH"}}
    )
    monkeypatch.setattr(
        rules.system, "collect", lambda: {"top_processes": [], "memory": {}, "disk": []}
    )

    alerts = rules.evaluate(base, _empty_cfg())
    crit = [a for a in alerts if a.rule_id == "W-FILE-001"]
    assert crit
    assert crit[0].severity == "CRITICAL"


def test_whitelisted_port_does_not_alert(monkeypatch):
    base = _baseline()
    cfg = _empty_cfg()
    cfg["whitelist"]["ports"] = [4444]
    monkeypatch.setattr(
        rules.network,
        "collect",
        lambda: {
            "listeners": [
                {
                    "port": 4444,
                    "proto": "tcp",
                    "ip": "0.0.0.0",
                    "pid": 99,
                    "process": "myapp",
                    "exe": "/opt/myapp/bin",
                    "user": "app",
                    "suspicious_path": False,
                }
            ],
            "established": [],
            "interfaces": [],
        },
    )
    monkeypatch.setattr(
        rules.cron,
        "collect",
        lambda: {"jobs": [], "downloader_jobs": [], "suspicious_dir_jobs": [], "base64_jobs": []},
    )
    monkeypatch.setattr(
        rules.services,
        "collect",
        lambda: {"present": True, "enabled_units": ["sshd.service"], "suspicious_units": []},
    )
    monkeypatch.setattr(
        rules.users,
        "collect",
        lambda: {
            "users": [],
            "uid_zero": ["root"],
            "empty_password_users": [],
            "sudoers": {"lines": [], "nopasswd": []},
        },
    )
    monkeypatch.setattr(rules.files, "collect", lambda: {"hashes": {"/etc/passwd": "sha256:abc"}})
    monkeypatch.setattr(
        rules.system, "collect", lambda: {"top_processes": [], "memory": {}, "disk": []}
    )

    alerts = rules.evaluate(base, cfg)
    assert "W-NET-001" not in [a.rule_id for a in alerts]


def test_disabled_rule_is_skipped(monkeypatch):
    base = _baseline()
    cfg = _empty_cfg()
    cfg["watch"]["rules_disabled"] = ["W-NET-001"]
    monkeypatch.setattr(
        rules.network,
        "collect",
        lambda: {
            "listeners": [
                {
                    "port": 4444,
                    "proto": "tcp",
                    "ip": "0.0.0.0",
                    "pid": 99,
                    "process": "x",
                    "exe": "/usr/bin/x",
                    "user": "root",
                    "suspicious_path": False,
                }
            ],
            "established": [],
            "interfaces": [],
        },
    )
    monkeypatch.setattr(
        rules.cron,
        "collect",
        lambda: {"jobs": [], "downloader_jobs": [], "suspicious_dir_jobs": [], "base64_jobs": []},
    )
    monkeypatch.setattr(
        rules.services,
        "collect",
        lambda: {"present": True, "enabled_units": ["sshd.service"], "suspicious_units": []},
    )
    monkeypatch.setattr(
        rules.users,
        "collect",
        lambda: {
            "users": [],
            "uid_zero": ["root"],
            "empty_password_users": [],
            "sudoers": {"lines": [], "nopasswd": []},
        },
    )
    monkeypatch.setattr(rules.files, "collect", lambda: {"hashes": {"/etc/passwd": "sha256:abc"}})
    monkeypatch.setattr(
        rules.system, "collect", lambda: {"top_processes": [], "memory": {}, "disk": []}
    )

    alerts = rules.evaluate(base, cfg)
    assert "W-NET-001" not in [a.rule_id for a in alerts]
