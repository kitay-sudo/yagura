"""Run all collectors with a Rich progress bar."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

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

STEPS: list[tuple[str, Callable[[], Any]]] = [
    ("System info", system.collect),
    ("Network", network.collect),
    ("SSH config", ssh.collect),
    ("Firewall", firewall.collect),
    ("Users", users.collect),
    ("Services", services.collect),
    ("Packages", packages.collect),
    ("Cron jobs", cron.collect),
    ("Kernel params", kernel.collect),
    ("Critical file hashes", files.collect),
]


def collect_with_progress(console: Console | None = None) -> dict:
    console = console or Console()
    snapshot: dict = {}
    keys = [
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
    ]

    with Progress(
        SpinnerColumn(style="accent"),
        TextColumn("[bold]{task.description}"),
        BarColumn(complete_style="accent", finished_style="ok"),
        TextColumn("[muted]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task_id = progress.add_task("[accent]Yagura scan", total=len(STEPS))
        for (label, func), key in zip(STEPS, keys, strict=True):
            progress.update(task_id, description=f"[accent]{label}")
            try:
                snapshot[key] = func()
            except Exception as e:  # collectors must never crash the scan
                snapshot[key] = {"error": str(e)}
            progress.advance(task_id)

    return snapshot
