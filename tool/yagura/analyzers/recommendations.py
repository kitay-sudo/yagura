"""Map findings → harden actions the user can apply."""

from __future__ import annotations

from yagura.analyzers.redflags import Finding

# rule_id → harden action ID (matches IDs registered in yagura.harden.registry)
RULE_TO_ACTION = {
    "SSH-001": ["ssh.disable_root"],
    "SSH-002": ["ssh.disable_password_auth", "ssh.change_port"],
    "SSH-003": ["ssh.lock_empty_users"],
    "SSH-004": ["pkg.fail2ban"],
    "FW-001": ["fw.ufw_enable"],
    "FW-002": ["fw.iptables_default_drop"],
    "NET-001": [],  # manual fix
    "NET-002": [],  # manual fix
    "USR-001": [],
    "USR-002": [],
    "PKG-001": ["pkg.fail2ban"],
    "PKG-002": ["pkg.unattended_upgrades"],
    "PKG-003": [],  # too risky to auto-apt-upgrade
    "KER-001": ["sysctl.harden_network"],
    "KER-002": ["sysctl.enable_aslr"],
    "CRON-001": [],
    "CRON-002": [],
    "SVC-001": [],
}


def recommend(findings: list[Finding]) -> list[dict]:
    """Returns a list of { action_id, related_rules, severity } sorted by severity."""
    by_action: dict[str, dict] = {}
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    for f in findings:
        for action_id in RULE_TO_ACTION.get(f.rule_id, []):
            if action_id not in by_action:
                by_action[action_id] = {
                    "action_id": action_id,
                    "related_rules": [],
                    "severity": "LOW",
                }
            entry = by_action[action_id]
            entry["related_rules"].append(f.rule_id)
            if severity_rank.get(f.severity, 0) > severity_rank.get(entry["severity"], 0):
                entry["severity"] = f.severity

    return sorted(
        by_action.values(),
        key=lambda x: severity_rank.get(x["severity"], 0),
        reverse=True,
    )
