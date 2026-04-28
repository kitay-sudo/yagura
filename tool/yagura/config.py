"""Reads and writes /etc/yagura/config.yml + manages standard paths."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

CONFIG_DIR = Path("/etc/yagura")
CONFIG_PATH = CONFIG_DIR / "config.yml"
STATE_DIR = Path("/var/lib/yagura")
BASELINE_PATH = STATE_DIR / "baseline.json"
LOG_DIR = Path("/var/log/yagura")
SYSTEMD_UNIT_PATH = Path("/etc/systemd/system/yagura-watch.service")

DEFAULT_CONFIG: dict[str, Any] = {
    "version": 1,
    "ai": {
        "provider": "none",
        "api_key": "",
        "model": "",
    },
    "watch": {
        "enabled": False,
        "interval_minutes": 5,
        "heartbeat_hours": 12,  # 0 = выключено. По умолчанию 2 раза в сутки.
        "telegram": {
            "bot_token": "",
            "chat_id": "",
        },
        "rules_disabled": [],
    },
    "whitelist": {
        "ports": [22, 80, 443],
        "processes": [],
        "ssh_ips": [],
        # Подстроки cmdline. Если найдена в полной команде процесса —
        # W-PROC-002 не алертит. Используется для собственных приложений
        # с высоким CPU (CRM, видеокодеры, дев-серверы).
        "cmdline_substrings": [],
        # Пары (cmdline_substring, dest). Подавляют W-PROC-003, только если
        # СОВПАЛО ОБА условия — иначе атакующий обошёл бы переименованием бинаря
        # или направив трафик на «доверенный» IP.
        # Каждый элемент: {cmdline: "fm-agent", dest_hostname: "*.googleapis.com"}
        # или {cmdline: "fm-agent", dest_ip: "34.102.0.0/16"}
        "process_dest": [],
    },
    # Blocklist: оператор пометил процесс/юнит как «не должен здесь быть».
    # Это НЕ автоблок — Yagura никогда не убивает процессы сама. Вместо этого
    # alert.severity повышается до CRITICAL при следующем срабатывании, чтобы
    # оператор увидел его сразу и в первую очередь.
    "blocklist": {
        "processes": [],  # list of {value: <exe>, source: "install_wizard:..."}
        "units": [],      # list of {value: "foo.service", source: "..."}
    },
    "harden_history": [],
}


def ensure_dirs() -> None:
    """Create the standard /etc and /var directories if missing."""
    for d in (CONFIG_DIR, STATE_DIR, LOG_DIR):
        d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(CONFIG_DIR, 0o750)
    except PermissionError:
        pass


def load_config() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        return _deep_copy(DEFAULT_CONFIG)
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except (yaml.YAMLError, OSError):
        return _deep_copy(DEFAULT_CONFIG)
    return _merge_defaults(data, DEFAULT_CONFIG)


def save_config(cfg: dict[str, Any]) -> None:
    ensure_dirs()
    tmp = CONFIG_PATH.with_suffix(".yml.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, sort_keys=False, allow_unicode=True)
    os.replace(tmp, CONFIG_PATH)
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except PermissionError:
        pass


def get(cfg: dict[str, Any], dotted: str, default: Any = None) -> Any:
    cur: Any = cfg
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def set_value(cfg: dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur = cfg
    for part in parts[:-1]:
        if part not in cur or not isinstance(cur[part], dict):
            cur[part] = {}
        cur = cur[part]
    cur[parts[-1]] = value


def _deep_copy(d: Any) -> Any:
    if isinstance(d, dict):
        return {k: _deep_copy(v) for k, v in d.items()}
    if isinstance(d, list):
        return [_deep_copy(v) for v in d]
    return d


def _merge_defaults(data: dict[str, Any], defaults: dict[str, Any]) -> dict[str, Any]:
    """Recursively backfill missing keys from defaults so older configs keep working."""
    out = _deep_copy(defaults)
    for k, v in data.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge_defaults(v, out[k])
        else:
            out[k] = v
    return out
