"""Compute Security Score 0-100 from findings + raw snapshot signals."""

from __future__ import annotations

from yagura.analyzers.redflags import Finding

SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 12,
    "MEDIUM": 5,
    "LOW": 2,
}

CATEGORY_LABELS = {
    "ssh": "SSH",
    "firewall": "Firewall",
    "network": "Network",
    "users": "Users",
    "packages": "Updates",
    "kernel": "Kernel",
    "cron": "Cron",
    "services": "Services",
}


def compute(findings: list[Finding], snapshot: dict) -> dict:
    """Returns: { overall, label, sections: { name: 0..100 } }."""
    overall = _overall(findings)
    sections = _sections(findings, snapshot)
    return {
        "overall": overall,
        "label": _label(overall),
        "sections": sections,
    }


def _overall(findings: list[Finding]) -> int:
    score = 100
    for f in findings:
        score -= SEVERITY_WEIGHTS.get(f.severity, 0)
    return max(0, min(100, score))


def _label(score: int) -> str:
    if score >= 90:
        return "EXCELLENT"
    if score >= 75:
        return "GOOD"
    if score >= 55:
        return "NEEDS WORK"
    if score >= 35:
        return "POOR"
    return "CRITICAL"


def _sections(findings: list[Finding], snapshot: dict) -> dict[str, int]:
    out: dict[str, int] = {
        label: 100 for label in {"SSH", "Firewall", "Network", "Updates", "Hardening"}
    }

    by_category: dict[str, list[Finding]] = {}
    for f in findings:
        by_category.setdefault(f.category, []).append(f)

    # SSH
    out["SSH"] = _section_score(by_category.get("ssh", []) + by_category.get("users", []))
    # Firewall
    out["Firewall"] = _section_score(by_category.get("firewall", []))
    if not snapshot.get("firewall", {}).get("any_active", False):
        out["Firewall"] = min(out["Firewall"], 30)
    # Network
    out["Network"] = _section_score(by_category.get("network", []))
    # Updates / packages
    upd_findings = by_category.get("packages", [])
    out["Updates"] = _section_score(upd_findings)
    # Hardening = kernel + cron + services
    out["Hardening"] = _section_score(
        by_category.get("kernel", [])
        + by_category.get("cron", [])
        + by_category.get("services", [])
    )

    return out


def _section_score(findings: list[Finding]) -> int:
    s = 100
    for f in findings:
        s -= SEVERITY_WEIGHTS.get(f.severity, 0)
    return max(0, min(100, s))
