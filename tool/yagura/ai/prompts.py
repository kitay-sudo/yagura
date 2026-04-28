"""Prompts sent to the AI provider. Kept short to bound costs."""

from __future__ import annotations

import json

from yagura.analyzers.redflags import Finding

SCAN_ANALYSIS_PROMPT = """Ты — security-инженер с 10-летним опытом. Тебе дан JSON-снапшот Linux-сервера.

Твоя задача:
1. Найди топ-5 главных рисков (приоритет: компрометация > эскалация > утечка данных > DoS).
2. Объясни каждый риск простым языком — так чтобы понял разработчик-фрилансер без security-бэкграунда.
3. Дай конкретные команды или действия для исправления.
4. Будь краток — макс 300 слов на весь ответ.

НЕ пиши "согласно best practices" и подобный bullshit. Пиши прямо, по делу.
НЕ перечисляй очевидное. Если PermitRootLogin no и firewall настроен — не упоминай их.

Снапшот сервера:
{snapshot_json}

Найденные red flags:
{red_flags}
"""

WATCH_ALERT_ENRICHMENT_PROMPT = """Ты — security-аналитик. Сервер мониторится инструментом Yagura, обнаружено отклонение от baseline.

КОНТЕКСТ: Yagura сама ставит на сервер свои systemd-юниты с префиксом `yagura-` (например `yagura-watch.service`). Если алерт пришёл про юнит, начинающийся на `yagura-` — это собственный сервис мониторинга, ЛОЖНАЯ ТРЕВОГА, надо так и сказать. Файлы в /opt/yagura, /etc/yagura, /var/lib/yagura, /var/log/yagura, бинарь /usr/local/bin/yagura — тоже сама Yagura.

Событие: {rule_id} — {rule_name}
Severity: {severity}
Детали: {details}
Контекст: {context}

Дай 3 строки:
1. Это серьёзно или ложная тревога? (одно предложение; если детали указывают на собственные артефакты Yagura — прямо скажи "ложная тревога, это сам Yagura")
2. Что делать прямо сейчас? (одна команда или одно действие; для ложных тревог — `yagura baseline reset`)
3. Как предотвратить в будущем? (одно предложение)

Без воды, без "могу помочь ещё", без emoji.
"""


def build_scan_prompt(snapshot: dict, findings: list[Finding]) -> str:
    snap_lite = _shrink_snapshot(snapshot)
    flags_text = (
        "\n".join(f"- [{f.severity}] {f.rule_id} {f.title}: {f.detail}" for f in findings)
        or "(none)"
    )
    return SCAN_ANALYSIS_PROMPT.format(
        snapshot_json=json.dumps(snap_lite, ensure_ascii=False, indent=2),
        red_flags=flags_text,
    )


def build_alert_prompt(
    rule_id: str, rule_name: str, severity: str, details: str, context: str
) -> str:
    return WATCH_ALERT_ENRICHMENT_PROMPT.format(
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        details=details,
        context=context,
    )


def _shrink_snapshot(snapshot: dict) -> dict:
    """Drop verbose fields to keep the AI prompt small (cheaper, faster)."""
    out: dict = {}
    sysinfo = snapshot.get("system", {})
    out["host"] = {
        "hostname": sysinfo.get("hostname"),
        "distro": sysinfo.get("distro"),
        "kernel": sysinfo.get("kernel"),
    }
    net = snapshot.get("network", {})
    out["listeners"] = [
        {
            "proto": lst["proto"],
            "port": lst["port"],
            "ip": lst["ip"],
            "process": lst["process"],
            "exe": lst["exe"],
        }
        for lst in net.get("listeners", [])
    ]
    out["ssh"] = snapshot.get("ssh", {}).get("settings", {})
    out["firewall"] = {
        "any_active": snapshot.get("firewall", {}).get("any_active", False),
        "iptables_default": snapshot.get("firewall", {})
        .get("iptables", {})
        .get("default_input", "?"),
    }
    users = snapshot.get("users", {})
    out["users"] = {
        "uid_zero": users.get("uid_zero", []),
        "empty_password": users.get("empty_password_users", []),
        "nopasswd": users.get("sudoers", {}).get("nopasswd", []),
    }
    pkgs = snapshot.get("packages", {})
    out["packages"] = {
        "manager": pkgs.get("manager"),
        "updates_available": pkgs.get("updates_available"),
        "security_packages": pkgs.get("security_packages"),
    }
    out["kernel"] = snapshot.get("kernel", {}).get("sysctl", {})
    cron = snapshot.get("cron", {})
    out["cron_suspicious"] = {
        "downloader": len(cron.get("downloader_jobs", [])),
        "tmp_dir": len(cron.get("suspicious_dir_jobs", [])),
        "base64": len(cron.get("base64_jobs", [])),
    }
    return out
