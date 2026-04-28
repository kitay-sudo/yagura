"""Rich rendering of scan results + markdown export."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from yagura.analyzers.redflags import Finding
from yagura.config import LOG_DIR, ensure_dirs
from yagura.ui.theme import score_style, severity_style


def render(console: Console, snapshot: dict, findings: list[Finding], score: dict) -> None:
    console.print()
    console.print(_score_panel(score))
    console.print()

    redflags = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
    warnings = [f for f in findings if f.severity == "MEDIUM"]
    notices = [f for f in findings if f.severity == "LOW"]

    if redflags:
        console.print(_findings_panel("RED FLAGS", redflags, border="bright_red"))
        console.print()
    if warnings:
        console.print(_findings_panel("WARNINGS", warnings, border="yellow"))
        console.print()
    if notices:
        console.print(_findings_panel("RECOMMENDATIONS", notices, border="blue"))
        console.print()

    if not (redflags or warnings or notices):
        console.print(
            Panel(
                "[ok]No issues detected. The tower is happy.[/ok]",
                border_style="ok",
                title="ALL CLEAR",
            )
        )
        console.print()

    console.print(_load_panel(snapshot))


def _score_panel(score: dict) -> Panel:
    overall = score["overall"]
    label = score["label"]
    style = score_style(overall)

    bars = []
    for name, val in score["sections"].items():
        bar_len = 20
        filled = round(bar_len * val / 100)
        bar = f"{'█' * filled}{'░' * (bar_len - filled)}"
        bar_style = score_style(val)
        bars.append(
            Text.assemble(
                (f"  {name:<10}", "muted"),
                (f" {bar} ", bar_style),
                (f"{val:>3}/100", bar_style),
            )
        )

    title_text = Text.assemble(
        ("SECURITY SCORE: ", "bold"),
        (f"{overall}/100", f"bold {style}"),
        ("  (", "muted"),
        (label, f"bold {style}"),
        (")", "muted"),
    )
    return Panel(Group(*bars), title=title_text, border_style="accent", padding=(1, 2))


def _findings_panel(title: str, findings: list[Finding], border: str) -> Panel:
    icon = {"RED FLAGS": "⛔", "WARNINGS": "⚠ ", "RECOMMENDATIONS": "ℹ "}.get(title, "•")
    title_text = Text.assemble((f"{title} ({len(findings)})", f"bold {border}"))
    rows = []
    for f in findings:
        sev_style = severity_style(f.severity)
        line = Text.assemble(
            (f"{icon} ", f"bold {border}"),
            (f"{f.rule_id}", "rule.id"),
            ("  ", ""),
            (f"[{f.severity}] ", sev_style),
            (f.title, "bold"),
        )
        detail = Text.assemble(("    ", ""), (f.detail, "muted"))
        rows.append(line)
        rows.append(detail)
        if f.fix_hint:
            hint = Text.assemble(("    fix: ", "accent.dim"), (f.fix_hint, ""))
            rows.append(hint)
        rows.append(Text(""))
    return Panel(Group(*rows), title=title_text, border_style=border, padding=(1, 2))


def _load_panel(snapshot: dict) -> Panel:
    sysinfo = snapshot.get("system", {})
    mem = sysinfo.get("memory", {})
    disk_list = sysinfo.get("disk", [])
    top = sysinfo.get("top_processes", [])

    table = Table.grid(padding=(0, 2))
    table.add_column(style="muted", no_wrap=True)
    table.add_column()

    cpu = sysinfo.get("cpu_percent", 0)
    cores = sysinfo.get("cpu_count", 1)
    table.add_row("CPU", f"[bold]{cpu:.0f}%[/bold]  ([muted]{cores} cores[/muted])")

    if mem:
        used_gb = mem.get("used", 0) / 1024**3
        total_gb = mem.get("total", 0) / 1024**3
        table.add_row(
            "RAM",
            f"[bold]{used_gb:.1f} GB[/bold] / {total_gb:.1f} GB  ({mem.get('percent', 0):.0f}%)",
        )

    if disk_list:
        d = disk_list[0]
        used_gb = d.get("used", 0) / 1024**3
        total_gb = d.get("total", 0) / 1024**3
        table.add_row(
            "Disk",
            f"[bold]{used_gb:.0f} GB[/bold] / {total_gb:.0f} GB  ({d.get('percent', 0):.0f}%) {d.get('mount', '')}",
        )

    if top:
        tops = ", ".join(f"{p['name']} {p['cpu']:.0f}%" for p in top[:3] if p["name"])
        if tops:
            table.add_row("Top", tops)

    return Panel(table, title="CURRENT LOAD", border_style="muted", padding=(1, 2))


# ---------- Markdown export ----------


def write_markdown_report(
    snapshot: dict,
    findings: list[Finding],
    score: dict,
    ai_text: str | None = None,
) -> Path:
    ensure_dirs()
    ts = datetime.now().strftime("%Y-%m-%d-%H%M")
    path = LOG_DIR / f"report-{ts}.md"
    md = _build_markdown(snapshot, findings, score, ai_text)
    path.write_text(md, encoding="utf-8")
    return path


def _build_markdown(
    snapshot: dict, findings: list[Finding], score: dict, ai_text: str | None
) -> str:
    sysinfo = snapshot.get("system", {})
    lines: list[str] = []
    lines.append(f"# YAGURA report — {sysinfo.get('hostname', '?')}")
    lines.append("")
    lines.append(f"_{datetime.now().isoformat(timespec='seconds')}_")
    lines.append("")
    distro = sysinfo.get("distro", {})
    lines.append(f"- Host: `{sysinfo.get('hostname', '?')}` ({sysinfo.get('fqdn', '?')})")
    lines.append(f"- Distro: {distro.get('name', '?')}  ·  Kernel: {sysinfo.get('kernel', '?')}")
    lines.append(f"- Uptime: {sysinfo.get('uptime_seconds', 0) // 3600}h")
    lines.append("")

    lines.append("## Security Score")
    lines.append("")
    lines.append(f"**{score['overall']}/100** — _{score['label']}_")
    lines.append("")
    for name, val in score["sections"].items():
        lines.append(f"- {name}: {val}/100")
    lines.append("")

    by_sev = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for f in findings:
        by_sev[f.severity].append(f)
    for sev, label in [
        ("CRITICAL", "Critical"),
        ("HIGH", "High"),
        ("MEDIUM", "Medium"),
        ("LOW", "Low"),
    ]:
        if not by_sev[sev]:
            continue
        lines.append(f"## {label} findings")
        lines.append("")
        for f in by_sev[sev]:
            lines.append(f"### `{f.rule_id}` — {f.title}")
            lines.append("")
            lines.append(f.detail)
            if f.fix_hint:
                lines.append("")
                lines.append(f"**Fix:** {f.fix_hint}")
            lines.append("")

    if ai_text:
        lines.append("## AI analysis")
        lines.append("")
        lines.append(ai_text.strip())
        lines.append("")

    lines.append("## Snapshot summary")
    lines.append("")
    net = snapshot.get("network", {})
    lines.append(f"- Listeners: {len(net.get('listeners', []))}")
    lines.append(f"- Established: {len(net.get('established', []))}")
    lines.append(
        f"- Enabled services: {len(snapshot.get('services', {}).get('enabled_units', []))}"
    )
    lines.append(f"- Cron jobs: {len(snapshot.get('cron', {}).get('jobs', []))}")
    pkgs = snapshot.get("packages", {})
    lines.append(
        f"- Installed packages: {pkgs.get('installed_count', '?')}  ·  Updates available: {pkgs.get('updates_available', '?')}"
    )
    lines.append("")
    lines.append("_Generated by [Yagura](https://github.com/kitay-sudo/yagura)._")
    lines.append("")
    return "\n".join(lines)
