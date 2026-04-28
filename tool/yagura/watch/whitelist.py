"""Whitelist accessors over the config dict."""

from __future__ import annotations

from yagura.config import get, save_config, set_value


def list_all(cfg: dict) -> dict:
    return {
        "ports": list(get(cfg, "whitelist.ports", []) or []),
        "processes": list(get(cfg, "whitelist.processes", []) or []),
        "ssh_ips": list(get(cfg, "whitelist.ssh_ips", []) or []),
    }


def add(cfg: dict, kind: str, value: str) -> bool:
    """Returns True if the value was added (False if already present)."""
    key = f"whitelist.{kind}"
    items = list(get(cfg, key, []) or [])
    if kind == "ports":
        try:
            value_typed: int | str = int(value)
        except ValueError:
            return False
    else:
        value_typed = value
    if value_typed in items:
        return False
    items.append(value_typed)
    set_value(cfg, key, items)
    save_config(cfg)
    return True


def remove(cfg: dict, kind: str, value: str) -> bool:
    key = f"whitelist.{kind}"
    items = list(get(cfg, key, []) or [])
    if kind == "ports":
        try:
            value_typed: int | str = int(value)
        except ValueError:
            return False
    else:
        value_typed = value
    if value_typed not in items:
        return False
    items.remove(value_typed)
    set_value(cfg, key, items)
    save_config(cfg)
    return True


def is_port_whitelisted(cfg: dict, port: int) -> bool:
    return port in (get(cfg, "whitelist.ports", []) or [])


def is_process_whitelisted(cfg: dict, exe: str) -> bool:
    if not exe:
        return False
    items = get(cfg, "whitelist.processes", []) or []
    return any(
        exe == w or (isinstance(w, str) and w.endswith("/") and exe.startswith(w)) for w in items
    )


def is_ssh_ip_whitelisted(cfg: dict, ip: str) -> bool:
    return ip in (get(cfg, "whitelist.ssh_ips", []) or [])
