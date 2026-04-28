"""Data collectors — read-only system inspection."""

from yagura.collectors import (
    cron,
    files,
    firewall,
    kernel,
    network,
    packages,
    services,
    ssh,
    system,
    users,
)


def collect_all() -> dict:
    """Run every collector and return a single snapshot dict."""
    return {
        "system": system.collect(),
        "network": network.collect(),
        "ssh": ssh.collect(),
        "firewall": firewall.collect(),
        "users": users.collect(),
        "services": services.collect(),
        "packages": packages.collect(),
        "cron": cron.collect(),
        "kernel": kernel.collect(),
        "files": files.collect(),
    }


__all__ = [
    "system",
    "network",
    "ssh",
    "firewall",
    "users",
    "services",
    "packages",
    "cron",
    "kernel",
    "files",
    "collect_all",
]
