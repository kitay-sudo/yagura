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


def test_self_listener_does_not_alert(monkeypatch):
    base = _baseline()
    monkeypatch.setattr(
        rules.network,
        "collect",
        lambda: {
            "listeners": [
                {
                    "port": 9999,
                    "proto": "tcp",
                    "ip": "0.0.0.0",
                    "pid": 42,
                    "process": "yagura",
                    "exe": "/opt/yagura/bin/yagura",
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

    alerts = rules.evaluate(base, _empty_cfg())
    assert "W-NET-001" not in [a.rule_id for a in alerts]


def test_known_process_on_ephemeral_port_is_silent(monkeypatch):
    # goronin уже был в baseline на одном порту — новый эфемерный порт у того же
    # exe должен молча игнорироваться, не спамить алертами.
    base = _baseline()
    base["listeners"].append(
        {"port": 10001, "proto": "tcp", "exe": "/usr/local/bin/goronin"}
    )
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
                    "port": 42176,
                    "proto": "tcp",
                    "ip": "0.0.0.0",
                    "pid": 2100527,
                    "process": "goronin",
                    "exe": "/usr/local/bin/goronin",
                    "user": "root",
                    "suspicious_path": False,
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
    assert "W-NET-001" not in [a.rule_id for a in alerts]


def test_known_process_on_low_port_still_alerts(monkeypatch):
    # Известный процесс на НЕэфемерном порту (например, вдруг открыл 8080) — алертим.
    base = _baseline()
    base["listeners"].append(
        {"port": 10001, "proto": "tcp", "exe": "/usr/local/bin/goronin"}
    )
    monkeypatch.setattr(
        rules.network,
        "collect",
        lambda: {
            "listeners": [
                {
                    "port": 8080,
                    "proto": "tcp",
                    "ip": "0.0.0.0",
                    "pid": 2100527,
                    "process": "goronin",
                    "exe": "/usr/local/bin/goronin",
                    "user": "root",
                    "suspicious_path": False,
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
    assert "W-NET-001" in [a.rule_id for a in alerts]


def _stub_collectors(
    monkeypatch,
    *,
    listeners=None,
    established=None,
    top_processes=None,
):
    """Helper: monkey-patch all collectors to fixed values."""
    monkeypatch.setattr(
        rules.network,
        "collect",
        lambda: {
            "listeners": listeners or [],
            "established": established or [],
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
        rules.system,
        "collect",
        lambda: {"top_processes": top_processes or [], "memory": {}, "disk": []},
    )


def test_proc003_uses_full_cmdline_in_detail(monkeypatch):
    # Линукс comm обрезается до 15 символов — алерт должен показывать ПОЛНЫЙ cmdline
    # из /proc/<pid>/cmdline, а не урезанное `python3`.
    base = _baseline()
    _stub_collectors(
        monkeypatch,
        established=[
            {
                "laddr": "10.0.0.1:12345",
                "raddr": "8.8.8.8:443",
                "pid": 4242,
                "process": "python3",
                "exe": "/opt/foo/agent.py",
                "cmdline": "/usr/bin/python3 /opt/foo/agent.py --token=xxx",
                "user": "fm-agent",
            }
        ],
    )
    alerts = rules.evaluate(base, _empty_cfg())
    proc003 = [a for a in alerts if a.rule_id == "W-PROC-003"]
    assert proc003
    assert "/opt/foo/agent.py" in proc003[0].detail


def test_proc003_whitelist_pair_suppresses(monkeypatch):
    # Пара (cmdline_substring, dest_ip CIDR) должна заглушить алерт. Проверяем,
    # что НИ ПО cmdline, НИ ПО IP по отдельности глушения нет — только ОБА вместе.
    base = _baseline()
    cfg = _empty_cfg()
    cfg["whitelist"]["process_dest"] = [
        {"cmdline": "fm-agent", "dest_ip": "34.102.0.0/16"},
    ]
    _stub_collectors(
        monkeypatch,
        established=[
            {
                "laddr": "10.0.0.1:12345",
                "raddr": "34.102.162.51:443",
                "pid": 4242,
                "process": "python3",
                "exe": "/usr/bin/python3",
                "cmdline": "/usr/bin/python3 /opt/fm-agent/main.py",
                "user": "fm-agent",
            }
        ],
    )
    alerts = rules.evaluate(base, cfg)
    assert not [a for a in alerts if a.rule_id == "W-PROC-003"]


def test_proc003_whitelist_does_not_match_cmdline_only(monkeypatch):
    # Если cmdline совпадает, но dest_ip — нет, алерт ДОЛЖЕН сработать.
    # Это критично: атакующий не должен обходить whitelist одним лишь именем.
    base = _baseline()
    cfg = _empty_cfg()
    cfg["whitelist"]["process_dest"] = [
        {"cmdline": "fm-agent", "dest_ip": "34.102.0.0/16"},
    ]
    _stub_collectors(
        monkeypatch,
        established=[
            {
                "laddr": "10.0.0.1:12345",
                "raddr": "8.8.8.8:443",  # не в whitelisted CIDR
                "pid": 4242,
                "process": "python3",
                "exe": "/usr/bin/python3",
                "cmdline": "/usr/bin/python3 /opt/fm-agent/main.py",
                "user": "fm-agent",
            }
        ],
    )
    alerts = rules.evaluate(base, cfg)
    assert [a for a in alerts if a.rule_id == "W-PROC-003"]


def test_proc002_localhost_db_lowers_severity(monkeypatch):
    # CRM с PostgreSQL и высокой нагрузкой не должен паниковать оператора —
    # понижаем до LOW. Полный cmdline должен быть в detail.
    base = _baseline()
    _stub_collectors(
        monkeypatch,
        established=[
            {
                "laddr": "127.0.0.1:48194",
                "raddr": "127.0.0.1:5432",
                "pid": 1931844,
                "process": "node /var/www/b",
                "exe": "/usr/bin/node",
                "cmdline": "node /var/www/balifornia/balifornia-crm/server/dist/index.js",
                "user": "admingod",
            }
        ],
        top_processes=[
            {
                "pid": 1931844,
                "name": "node /var/www/b",
                "user": "admingod",
                "cpu": 106.0,
                "rss": 0,
            }
        ],
    )
    alerts = rules.evaluate(base, _empty_cfg())
    proc002 = [a for a in alerts if a.rule_id == "W-PROC-002"]
    assert proc002
    assert proc002[0].severity == "LOW"
    assert "/var/www/balifornia/balifornia-crm" in proc002[0].detail
    assert proc002[0].context.get("has_local_db") is True


def test_proc002_no_db_stays_medium(monkeypatch):
    # Без localhost-DB соединения — остаётся MEDIUM, защита НЕ ослаблена.
    base = _baseline()
    _stub_collectors(
        monkeypatch,
        established=[
            {
                "laddr": "10.0.0.1:30001",
                "raddr": "1.2.3.4:80",  # внешний адрес, не БД
                "pid": 9999,
                "process": "miner",
                "exe": "/tmp/x",
                "cmdline": "/tmp/x --pool foo",
                "user": "nobody",
            }
        ],
        top_processes=[
            {"pid": 9999, "name": "miner", "user": "nobody", "cpu": 99.0, "rss": 0}
        ],
    )
    alerts = rules.evaluate(base, _empty_cfg())
    proc002 = [a for a in alerts if a.rule_id == "W-PROC-002"]
    assert proc002
    assert proc002[0].severity == "MEDIUM"


def test_proc002_cmdline_whitelist_suppresses(monkeypatch):
    # Подстрока cmdline в whitelist — алерт не должен срабатывать.
    base = _baseline()
    cfg = _empty_cfg()
    cfg["whitelist"]["cmdline_substrings"] = ["balifornia-crm"]
    _stub_collectors(
        monkeypatch,
        established=[
            {
                "laddr": "10.0.0.1:30001",
                "raddr": "1.2.3.4:80",
                "pid": 9999,
                "process": "node",
                "exe": "/usr/bin/node",
                "cmdline": "node /var/www/balifornia/balifornia-crm/server/dist/index.js",
                "user": "admingod",
            }
        ],
        top_processes=[
            {"pid": 9999, "name": "node", "user": "admingod", "cpu": 99.0, "rss": 0}
        ],
    )
    alerts = rules.evaluate(base, cfg)
    assert not [a for a in alerts if a.rule_id == "W-PROC-002"]


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
