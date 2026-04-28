"""ufw / firewalld / iptables / nftables — what's enabled, what the default policy is."""

from __future__ import annotations

from yagura.collectors._shell import has, lines, run


def collect() -> dict:
    return {
        "ufw": _ufw(),
        "firewalld": _firewalld(),
        "iptables": _iptables(),
        "nftables": _nftables(),
        "any_active": _any_active(),
    }


def _ufw() -> dict:
    if not has("ufw"):
        return {"installed": False, "active": False, "rules": []}
    rc, out, _ = run(["ufw", "status", "verbose"])
    if rc != 0:
        return {"installed": True, "active": False, "rules": []}
    active = "Status: active" in out
    rules = [ln for ln in lines(out) if "ALLOW" in ln or "DENY" in ln or "REJECT" in ln]
    return {"installed": True, "active": active, "rules": rules}


def _firewalld() -> dict:
    if not has("firewall-cmd"):
        return {"installed": False, "active": False, "zones": []}
    rc, out, _ = run(["firewall-cmd", "--state"])
    active = rc == 0 and "running" in out.lower()
    zones: list[str] = []
    if active:
        rc2, out2, _ = run(["firewall-cmd", "--get-active-zones"])
        if rc2 == 0:
            zones = [ln for ln in lines(out2) if not ln.startswith(" ")]
    return {"installed": True, "active": active, "zones": zones}


def _iptables() -> dict:
    if not has("iptables"):
        return {"installed": False, "default_input": "unknown", "rules_count": 0}
    rc, out, _ = run(["iptables", "-S"])
    if rc != 0:
        return {"installed": True, "default_input": "unknown", "rules_count": 0}
    default_input = "ACCEPT"
    rules_count = 0
    for ln in lines(out):
        if ln.startswith("-P INPUT"):
            parts = ln.split()
            if len(parts) >= 3:
                default_input = parts[2]
        elif ln.startswith("-A "):
            rules_count += 1
    return {"installed": True, "default_input": default_input, "rules_count": rules_count}


def _nftables() -> dict:
    if not has("nft"):
        return {"installed": False, "tables": []}
    rc, out, _ = run(["nft", "list", "tables"])
    if rc != 0:
        return {"installed": True, "tables": []}
    tables = [ln.strip() for ln in lines(out)]
    return {"installed": True, "tables": tables}


def _any_active() -> bool:
    """True if any firewall layer is meaningfully active."""
    if has("ufw"):
        rc, out, _ = run(["ufw", "status"])
        if rc == 0 and "Status: active" in out:
            return True
    if has("firewall-cmd"):
        rc, out, _ = run(["firewall-cmd", "--state"])
        if rc == 0 and "running" in out.lower():
            return True
    if has("iptables"):
        rc, out, _ = run(["iptables", "-S"])
        if rc == 0:
            for ln in lines(out):
                if ln.startswith("-P INPUT") and "DROP" in ln:
                    return True
                if ln.startswith("-A "):
                    return True
    if has("nft"):
        rc, out, _ = run(["nft", "list", "ruleset"])
        if rc == 0 and out.strip():
            return True
    return False
