"""Apply scan-rules from spec section 4 to a snapshot, return Finding list."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

DB_LISTEN_PORTS = {3306, 5432, 27017, 6379, 9200, 11211}


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    detail: str
    fix_hint: str = ""
    category: str = ""  # ssh | firewall | network | users | packages | kernel | cron | services
    extras: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "fix_hint": self.fix_hint,
            "category": self.category,
            "extras": self.extras,
        }


def analyze(snapshot: dict) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_ssh(snapshot))
    findings.extend(_firewall(snapshot))
    findings.extend(_network(snapshot))
    findings.extend(_users(snapshot))
    findings.extend(_packages(snapshot))
    findings.extend(_kernel(snapshot))
    findings.extend(_cron(snapshot))
    findings.extend(_services(snapshot))
    return findings


def _ssh(snap: dict) -> list[Finding]:
    out: list[Finding] = []
    ssh = snap.get("ssh", {})
    settings = ssh.get("settings", {})
    fw = snap.get("firewall", {})
    pkgs = snap.get("packages", {}).get("security_packages", {})
    users = snap.get("users", {})

    if settings.get("PermitRootLogin", "").lower() == "yes":
        out.append(
            Finding(
                rule_id="SSH-001",
                severity="CRITICAL",
                title="PermitRootLogin yes",
                detail="root может логиниться по SSH — это первое что брутфорсят атакующие.",
                fix_hint="Set PermitRootLogin to 'no' or 'prohibit-password' in /etc/ssh/sshd_config",
                category="ssh",
            )
        )

    port = settings.get("Port", "22")
    pwauth = settings.get("PasswordAuthentication", "yes").lower() == "yes"
    if pwauth and port == "22" and not pkgs.get("fail2ban", False):
        out.append(
            Finding(
                rule_id="SSH-002",
                severity="HIGH",
                title="PasswordAuthentication yes на порту 22 без fail2ban",
                detail="Открытый SSH с паролем на дефолтном порту без защиты от брутфорса.",
                fix_hint="Set PasswordAuthentication no, switch to keys; or install fail2ban; or change port",
                category="ssh",
            )
        )

    empties = users.get("empty_password_users", [])
    if empties:
        out.append(
            Finding(
                rule_id="SSH-003",
                severity="CRITICAL",
                title="Юзеры с пустым паролем",
                detail=f"Аккаунты с пустым паролем в /etc/shadow: {', '.join(empties)}",
                fix_hint="passwd -l <user> for each, or set strong password",
                category="users",
            )
        )

    failed = ssh.get("failed_logins_24h", {}).get("total", 0)
    if failed > 50:
        top = ssh.get("failed_logins_24h", {}).get("top", [])
        top_str = ", ".join(f"{t['ip']}({t['count']})" for t in top[:3])
        out.append(
            Finding(
                rule_id="SSH-004",
                severity="MEDIUM",
                title=f"{failed} неудачных SSH-попыток за сутки",
                detail=f"Топ источников: {top_str or '-'}",
                fix_hint="Install fail2ban or restrict SSH to keys only",
                category="ssh",
            )
        )

    fw_active = fw.get("any_active", False)
    if not fw_active:
        out.append(
            Finding(
                rule_id="FW-001",
                severity="HIGH",
                title="Firewall не активен",
                detail="Ни ufw, ни firewalld, ни iptables/nftables не настроены.",
                fix_hint="Install and enable ufw / firewalld",
                category="firewall",
            )
        )

    iptables = fw.get("iptables", {})
    if iptables.get("installed") and iptables.get("default_input") == "ACCEPT":
        out.append(
            Finding(
                rule_id="FW-002",
                severity="HIGH",
                title="iptables INPUT default policy = ACCEPT",
                detail="Без default-DROP всё разрешено если правило не сработало.",
                fix_hint="Set default policy: iptables -P INPUT DROP (after adding INPUT rules!)",
                category="firewall",
            )
        )

    return out


def _firewall(_snap: dict) -> list[Finding]:
    return []


def _network(snap: dict) -> list[Finding]:
    out: list[Finding] = []
    listeners = snap.get("network", {}).get("listeners", [])
    for lst in listeners:
        if lst["ip"] in ("0.0.0.0", "::") and lst["port"] in DB_LISTEN_PORTS:
            out.append(
                Finding(
                    rule_id="NET-001",
                    severity="HIGH",
                    title=f"DB listening on 0.0.0.0:{lst['port']}",
                    detail=f"Сервис {lst['process']} (PID {lst['pid']}) слушает БД-порт на всех интерфейсах.",
                    fix_hint="Bind to 127.0.0.1 only, or restrict via firewall",
                    category="network",
                    extras={"listener": lst},
                )
            )
        if lst.get("suspicious_path"):
            out.append(
                Finding(
                    rule_id="NET-002",
                    severity="CRITICAL",
                    title=f"Listener из подозрительного пути: {lst['exe']}",
                    detail=f"Процесс {lst['process']} (PID {lst['pid']}) слушает {lst['proto']}/{lst['port']} и запущен из {lst['exe']}",
                    fix_hint="Inspect the process and the binary — likely malware",
                    category="network",
                    extras={"listener": lst},
                )
            )
    return out


def _users(snap: dict) -> list[Finding]:
    out: list[Finding] = []
    users = snap.get("users", {})
    uid_zero = users.get("uid_zero", [])
    if len(uid_zero) > 1:
        out.append(
            Finding(
                rule_id="USR-001",
                severity="CRITICAL",
                title=f"Несколько UID 0 в /etc/passwd: {', '.join(uid_zero)}",
                detail="Только root должен иметь UID 0. Дополнительные UID-0 аккаунты — backdoor.",
                fix_hint="Change UID for the extra account, or remove it",
                category="users",
            )
        )

    nopasswd = users.get("sudoers", {}).get("nopasswd", [])
    non_system = [
        u for u in nopasswd if u and u.lower() not in {"root", "%root", "ubuntu", "ec2-user"}
    ]
    if non_system:
        out.append(
            Finding(
                rule_id="USR-002",
                severity="MEDIUM",
                title="Sudo NOPASSWD для не-системных юзеров",
                detail=f"NOPASSWD выдан: {', '.join(non_system)}",
                fix_hint="Remove NOPASSWD from /etc/sudoers or sudoers.d/",
                category="users",
            )
        )
    return out


def _packages(snap: dict) -> list[Finding]:
    out: list[Finding] = []
    pkgs = snap.get("packages", {}).get("security_packages", {})
    if not pkgs.get("fail2ban", False):
        out.append(
            Finding(
                rule_id="PKG-001",
                severity="LOW",
                title="fail2ban не установлен",
                detail="Защита от SSH брутфорса отсутствует.",
                fix_hint="apt install fail2ban / dnf install fail2ban",
                category="packages",
            )
        )
    if not (pkgs.get("unattended-upgrades", False) or pkgs.get("dnf-automatic", False)):
        out.append(
            Finding(
                rule_id="PKG-002",
                severity="LOW",
                title="Авто-обновления безопасности не настроены",
                detail="unattended-upgrades / dnf-automatic не установлены.",
                fix_hint="Enable unattended-upgrades (deb) or dnf-automatic (rpm)",
                category="packages",
            )
        )
    updates = snap.get("packages", {}).get("updates_available", 0)
    if updates and updates > 5:
        out.append(
            Finding(
                rule_id="PKG-003",
                severity="MEDIUM",
                title=f"{updates} доступных обновлений",
                detail="Нанесите обновления безопасности.",
                fix_hint="apt upgrade / dnf upgrade / pacman -Syu",
                category="packages",
            )
        )
    return out


def _kernel(snap: dict) -> list[Finding]:
    out: list[Finding] = []
    sysctl = snap.get("kernel", {}).get("sysctl", {})

    if sysctl.get("net.ipv4.tcp_syncookies") == "0":
        out.append(
            Finding(
                rule_id="KER-001",
                severity="MEDIUM",
                title="net.ipv4.tcp_syncookies = 0",
                detail="SYN-flood защита выключена.",
                fix_hint="sysctl -w net.ipv4.tcp_syncookies=1; persist in /etc/sysctl.d/",
                category="kernel",
            )
        )

    if sysctl.get("kernel.randomize_va_space") == "0":
        out.append(
            Finding(
                rule_id="KER-002",
                severity="HIGH",
                title="ASLR отключён",
                detail="kernel.randomize_va_space = 0 — выключен Address Space Layout Randomization.",
                fix_hint="sysctl -w kernel.randomize_va_space=2; persist in /etc/sysctl.d/",
                category="kernel",
            )
        )

    return out


def _cron(snap: dict) -> list[Finding]:
    out: list[Finding] = []
    cron = snap.get("cron", {})
    for j in cron.get("downloader_jobs", []):
        out.append(
            Finding(
                rule_id="CRON-001",
                severity="HIGH",
                title="Cron с curl/wget | bash",
                detail=f"{j['user']} @ {j['schedule']}: {j['cmd'][:120]}",
                fix_hint="Inspect this job — pipe-to-shell from network is malware-ish",
                category="cron",
                extras={"job": j},
            )
        )
    for j in cron.get("base64_jobs", []):
        out.append(
            Finding(
                rule_id="CRON-001",
                severity="HIGH",
                title="Cron с base64-командой",
                detail=f"{j['user']} @ {j['schedule']}: {j['cmd'][:120]}",
                fix_hint="Decode and inspect the base64 payload",
                category="cron",
                extras={"job": j},
            )
        )
    for j in cron.get("suspicious_dir_jobs", []):
        out.append(
            Finding(
                rule_id="CRON-002",
                severity="MEDIUM",
                title="Cron из /tmp или /home/*",
                detail=f"{j['user']} @ {j['schedule']}: {j['cmd'][:120]}",
                fix_hint="Move scripts to /usr/local/bin; verify owner",
                category="cron",
                extras={"job": j},
            )
        )
    return out


def _services(snap: dict) -> list[Finding]:
    out: list[Finding] = []
    for u in snap.get("services", {}).get("suspicious_units", []):
        out.append(
            Finding(
                rule_id="SVC-001",
                severity="CRITICAL",
                title=f"systemd unit с ExecStart из подозрительной директории: {u['unit']}",
                detail=u["exec"],
                fix_hint="Inspect the unit; if not yours, systemctl disable + remove",
                category="services",
                extras={"unit": u},
            )
        )
    return out
