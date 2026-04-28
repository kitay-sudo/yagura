"""Pure-data tests for analyzers — no system access required."""

from yagura.analyzers import recommendations, redflags, score


def _empty_snapshot() -> dict:
    return {
        "system": {
            "hostname": "test",
            "cpu_percent": 1,
            "cpu_count": 1,
            "memory": {},
            "disk": [],
            "top_processes": [],
        },
        "network": {"listeners": [], "established": [], "interfaces": []},
        "ssh": {"settings": {}, "failed_logins_24h": {"total": 0, "top": []}},
        "firewall": {
            "any_active": True,
            "iptables": {"installed": True, "default_input": "DROP"},
            "ufw": {},
            "firewalld": {},
            "nftables": {},
        },
        "users": {
            "users": [],
            "uid_zero": ["root"],
            "empty_password_users": [],
            "sudoers": {"lines": [], "nopasswd": []},
        },
        "services": {"present": True, "enabled_units": [], "suspicious_units": []},
        "packages": {
            "manager": "deb",
            "installed_count": 100,
            "security_packages": {"fail2ban": True, "unattended-upgrades": True},
            "updates_available": 0,
        },
        "cron": {"jobs": [], "downloader_jobs": [], "suspicious_dir_jobs": [], "base64_jobs": []},
        "kernel": {"sysctl": {"net.ipv4.tcp_syncookies": "1", "kernel.randomize_va_space": "2"}},
        "files": {"hashes": {}},
    }


def test_clean_snapshot_yields_no_critical_findings():
    findings = redflags.analyze(_empty_snapshot())
    assert all(f.severity != "CRITICAL" for f in findings), [f.rule_id for f in findings]


def test_permit_root_login_yes_is_critical():
    snap = _empty_snapshot()
    snap["ssh"]["settings"] = {
        "PermitRootLogin": "yes",
        "Port": "22",
        "PasswordAuthentication": "no",
    }
    findings = redflags.analyze(snap)
    assert any(f.rule_id == "SSH-001" and f.severity == "CRITICAL" for f in findings)


def test_aslr_off_is_high():
    snap = _empty_snapshot()
    snap["kernel"]["sysctl"]["kernel.randomize_va_space"] = "0"
    findings = redflags.analyze(snap)
    assert any(f.rule_id == "KER-002" and f.severity == "HIGH" for f in findings)


def test_score_deducts_for_findings():
    snap = _empty_snapshot()
    snap["ssh"]["settings"] = {
        "PermitRootLogin": "yes",
        "Port": "22",
        "PasswordAuthentication": "no",
    }
    findings = redflags.analyze(snap)
    sc = score.compute(findings, snap)
    assert sc["overall"] < 100
    assert sc["sections"]["SSH"] < 100


def test_recommendations_map_critical_first():
    snap = _empty_snapshot()
    snap["ssh"]["settings"] = {"PermitRootLogin": "yes", "Port": "22"}
    findings = redflags.analyze(snap)
    recs = recommendations.recommend(findings)
    assert recs
    assert recs[0]["severity"] == "CRITICAL"
    assert recs[0]["action_id"] == "ssh.disable_root"
