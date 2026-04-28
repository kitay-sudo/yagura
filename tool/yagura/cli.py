"""Yagura CLI entry point. Subcommand dispatcher."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

from rich.console import Console
from rich.table import Table

from yagura import __version__
from yagura.ai.factory import build_client
from yagura.ai.prompts import build_scan_prompt
from yagura.analyzers import recommendations, redflags, score
from yagura.config import (
    BASELINE_PATH,
    CONFIG_PATH,
    LOG_DIR,
    SYSTEMD_UNIT_PATH,
    ensure_dirs,
    get,
    load_config,
    save_config,
    set_value,
)
from yagura.harden import get_action
from yagura.ui import ascii_art, progress, report, wizard
from yagura.ui.theme import YAGURA_THEME
from yagura.watch import baseline as baseline_mod
from yagura.watch import monitor, telegram, whitelist

console = Console(theme=YAGURA_THEME)


# ---------- main entry ----------


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()

    # Allow `yagura help` as a friendly alias for `--help`.
    raw = sys.argv[1:] if argv is None else argv
    if raw and raw[0] == "help":
        parser.print_help()
        return 0

    args = parser.parse_args(argv)

    if args.command is None:
        return cmd_wizard(args)

    handler = COMMANDS.get(args.command)
    if handler is None:
        parser.print_help()
        return 2
    try:
        return handler(args) or 0
    except KeyboardInterrupt:
        console.print("\n[muted]aborted[/muted]")
        return 130


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="yagura", description="YAGURA — security audit + watchdog for Linux"
    )
    sub = p.add_subparsers(dest="command")

    sub.add_parser("version", help="Print version and exit")

    p_scan = sub.add_parser("scan", help="Run audit only")
    p_scan.add_argument("--json", action="store_true", help="Print snapshot+findings as JSON")
    p_scan.add_argument(
        "--report-only",
        action="store_true",
        help="Save markdown report only, no interactive output",
    )

    p_h = sub.add_parser("harden", help="Apply hardening actions")
    p_h.add_argument(
        "--apply-all", action="store_true", help="Apply all recommended without prompts (dangerous)"
    )
    p_h_sub = p_h.add_subparsers(dest="harden_command")
    p_h_rb = p_h_sub.add_parser("rollback", help="Rollback a previously applied harden action")
    p_h_rb.add_argument("action_id")

    p_w = sub.add_parser("watch", help="Manage the watchdog daemon")
    p_w_sub = p_w.add_subparsers(dest="watch_command", required=True)
    p_w_sub.add_parser("start", help="Install and start yagura-watch.service")
    p_w_sub.add_parser("stop", help="Stop and disable yagura-watch.service")
    p_w_sub.add_parser("status", help="Show daemon status + recent alerts")
    p_w_sub.add_parser("logs", help="Tail journalctl -u yagura-watch")
    p_w_sub.add_parser("run", help="Run the monitor loop in foreground (used by systemd)")

    p_b = sub.add_parser("baseline", help="Manage baseline")
    p_b_sub = p_b.add_subparsers(dest="baseline_command", required=True)
    p_b_sub.add_parser("show", help="Print baseline as JSON")
    p_b_sub.add_parser("reset", help="Re-collect baseline from current state")
    p_b_sub.add_parser("diff", help="Show diff between current state and baseline")

    p_wl = sub.add_parser("whitelist", help="Manage whitelist")
    p_wl_sub = p_wl.add_subparsers(dest="whitelist_command", required=True)
    p_wl_sub.add_parser("list")
    p_wl_add = p_wl_sub.add_parser("add")
    p_wl_add.add_argument("kind", choices=["port", "process", "ssh-ip"])
    p_wl_add.add_argument("value")
    p_wl_rm = p_wl_sub.add_parser("remove")
    p_wl_rm.add_argument("kind", choices=["port", "process", "ssh-ip"])
    p_wl_rm.add_argument("value")

    p_r = sub.add_parser("report", help="Reports stored in /var/log/yagura")
    p_r_sub = p_r.add_subparsers(dest="report_command")
    p_r_sub.add_parser("list")
    p_r_show = p_r_sub.add_parser("show")
    p_r_show.add_argument("date", nargs="?")

    p_c = sub.add_parser("config", help="Show / edit config")
    p_c_sub = p_c.add_subparsers(dest="config_command", required=True)
    p_c_sub.add_parser("show")
    p_c_sub.add_parser("edit")
    p_c_set = p_c_sub.add_parser("set")
    p_c_set.add_argument("key")
    p_c_set.add_argument("value")

    sub.add_parser("uninstall", help="Roll back all changes and remove Yagura")

    sub.add_parser("health", help="Quick status: watchdog, uptime, last alerts, last scan")

    return p


def _require_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        console.print("[danger]This command must be run as root.[/danger]")
        console.print("Try: [accent]sudo yagura ...[/accent]")
        sys.exit(1)


# ---------- commands ----------


def cmd_version(_args) -> int:
    print(f"yagura {__version__}")
    return 0


def cmd_wizard(args) -> int:
    """Full interactive flow: splash → AI ask → scan → report → AI analysis → harden → watch offer."""
    _require_root()
    ensure_dirs()
    cfg = load_config()

    console.print(f"[tower]{ascii_art.splash(__version__)}[/tower]")

    # 1. AI provider
    cfg = _wizard_ai(cfg)

    # 2. Scan
    snapshot = progress.collect_with_progress(console)
    findings = redflags.analyze(snapshot)
    sc = score.compute(findings, snapshot)
    report.render(console, snapshot, findings, sc)

    # 3. AI analysis (if configured)
    ai_text = _maybe_ai_analysis(cfg, snapshot, findings)

    # 4. Save markdown report
    md_path = report.write_markdown_report(snapshot, findings, sc, ai_text=ai_text)
    console.print(f"\n[muted]Markdown report saved:[/muted] [accent]{md_path}[/accent]")

    # 5. Harden offer
    recs = recommendations.recommend(findings)
    if recs:
        console.print()
        if wizard.ask_apply_recommended():
            _apply_harden_actions(cfg, recs, findings)

    # 6. Watch offer
    cfg = load_config()  # reload after harden writes
    if wizard.ask_enable_watch():
        _enable_watch(cfg)

    console.print("\n[ok]Done.[/ok]")
    return 0


def _wizard_ai(cfg: dict) -> dict:
    provider, key = wizard.ask_ai_provider()
    if provider == "none":
        return cfg
    set_value(cfg, "ai.provider", provider)
    set_value(cfg, "ai.api_key", key)
    set_value(cfg, "ai.model", "")
    save_config(cfg)
    client = build_client(provider, key)
    if client and client.validate():
        console.print(f"[ok]✓[/ok] {provider} key validated")
    else:
        console.print(f"[warn]⚠[/warn] {provider} key validation failed — saved anyway")
    return cfg


def _maybe_ai_analysis(cfg: dict, snapshot, findings) -> str | None:
    provider = get(cfg, "ai.provider", "none")
    key = get(cfg, "ai.api_key", "")
    if provider in (None, "none") or not key:
        return None
    client = build_client(provider, key, get(cfg, "ai.model", ""))
    if client is None:
        return None
    console.print(f"\n[accent]→ AI analysis ({provider})...[/accent]")
    try:
        text = client.complete(build_scan_prompt(snapshot, findings), max_tokens=600)
    except Exception as e:
        console.print(f"[warn]AI analysis failed: {e}[/warn]")
        return None
    if text:
        from rich.panel import Panel

        console.print(
            Panel(text, title=f"AI ANALYSIS ({provider})", border_style="accent", padding=(1, 2))
        )
    return text


def _apply_harden_actions(cfg: dict, recs: list[dict], findings, force: bool = False) -> None:
    selected = (
        [r["action_id"] for r in recs] if force else wizard.ask_harden_actions(recs, findings)
    )
    for action_id in selected:
        action = get_action(action_id)
        if action is None:
            console.print(f"[warn]Unknown action: {action_id}[/warn]")
            continue
        preview_lines = action.preview()
        if not force and not wizard.confirm_apply(action_id, preview_lines):
            console.print(f"[muted]Skipped {action_id}[/muted]")
            continue
        result = action.apply()
        icon = "[ok]✓[/ok]" if result.success else "[danger]✗[/danger]"
        console.print(f"{icon} {action_id}: {result.message}")
        if result.success and result.rollback_cmd:
            history = list(cfg.get("harden_history", []) or [])
            history.append(
                {
                    "id": action_id,
                    "applied_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "rollback_cmd": result.rollback_cmd,
                }
            )
            set_value(cfg, "harden_history", history)
            save_config(cfg)


def cmd_scan(args) -> int:
    _require_root()
    ensure_dirs()
    snapshot = progress.collect_with_progress(console)
    findings = redflags.analyze(snapshot)
    sc = score.compute(findings, snapshot)

    if args.json:
        out = {
            "snapshot": snapshot,
            "findings": [f.to_dict() for f in findings],
            "score": sc,
        }
        sys.stdout.write(json.dumps(out, ensure_ascii=False, indent=2, default=str))
        return 0

    if args.report_only:
        path = report.write_markdown_report(snapshot, findings, sc)
        console.print(f"[ok]✓[/ok] {path}")
        return 0

    report.render(console, snapshot, findings, sc)
    cfg = load_config()
    ai_text = _maybe_ai_analysis(cfg, snapshot, findings)
    path = report.write_markdown_report(snapshot, findings, sc, ai_text=ai_text)
    console.print(f"\n[muted]Markdown report:[/muted] [accent]{path}[/accent]")
    return 0


def cmd_harden(args) -> int:
    _require_root()
    if args.harden_command == "rollback":
        return _harden_rollback(args.action_id)

    cfg = load_config()
    snapshot = progress.collect_with_progress(console)
    findings = redflags.analyze(snapshot)
    recs = recommendations.recommend(findings)
    if not recs:
        console.print("[ok]No hardening recommended — score looks good.[/ok]")
        return 0
    _apply_harden_actions(cfg, recs, findings, force=args.apply_all)
    return 0


def _harden_rollback(action_id: str) -> int:
    cfg = load_config()
    history = list(cfg.get("harden_history", []) or [])
    matches = [h for h in history if h.get("id") == action_id]
    if not matches:
        console.print(f"[warn]No history entry for {action_id}[/warn]")
        return 1
    entry = matches[-1]  # most recent
    cmd = entry.get("rollback_cmd", "")
    if not cmd:
        console.print("[warn]No rollback command stored[/warn]")
        return 1
    console.print(f"[accent]→[/accent] rollback {action_id}: [muted]{cmd}[/muted]")
    rc = subprocess.call(["bash", "-c", cmd])
    if rc != 0:
        console.print(f"[danger]rollback failed (exit {rc})[/danger]")
        return rc
    history.remove(entry)
    set_value(cfg, "harden_history", history)
    save_config(cfg)
    console.print("[ok]✓[/ok] rolled back")
    return 0


# ---------- watch ----------


def cmd_watch(args) -> int:
    if args.watch_command == "start":
        return _watch_start()
    if args.watch_command == "stop":
        return _watch_stop()
    if args.watch_command == "status":
        return _watch_status()
    if args.watch_command == "logs":
        return _watch_logs()
    if args.watch_command == "run":
        monitor.run_forever()
        return 0
    return 2


def _enable_watch(cfg: dict) -> None:
    bot_token, chat_id, interval = wizard.ask_telegram()
    if bot_token:
        ok, msg = telegram.validate(bot_token)
        if not ok:
            console.print(f"[warn]Telegram token invalid: {msg}[/warn]")
            return
        console.print(f"[ok]✓[/ok] bot: {msg}")
        if chat_id:
            ok2, msg2 = telegram.send_test(bot_token, chat_id)
            console.print(f"{'[ok]✓[/ok]' if ok2 else '[warn]⚠[/warn]'} test message: {msg2}")
    set_value(cfg, "watch.enabled", True)
    set_value(cfg, "watch.interval_minutes", interval)
    set_value(cfg, "watch.telegram.bot_token", bot_token)
    set_value(cfg, "watch.telegram.chat_id", chat_id)
    save_config(cfg)
    base = baseline_mod.build()
    baseline_mod.save(base)
    console.print(
        f"[ok]✓[/ok] baseline saved ({len(base['listeners'])} listeners, {len(base['systemd_units'])} units, {len(base['cron_jobs'])} crons)"
    )
    monitor.install_systemd_unit()
    subprocess.call(["systemctl", "daemon-reload"])
    subprocess.call(["systemctl", "enable", "yagura-watch.service"])
    subprocess.call(["systemctl", "start", "yagura-watch.service"])
    console.print("[ok]✓[/ok] yagura-watch.service enabled")


def _watch_start() -> int:
    _require_root()
    cfg = load_config()
    if not get(cfg, "watch.telegram.bot_token"):
        console.print("[muted]Telegram not configured — running enable wizard...[/muted]")
        _enable_watch(cfg)
        return 0
    base = baseline_mod.build()
    baseline_mod.save(base)
    monitor.install_systemd_unit()
    subprocess.call(["systemctl", "daemon-reload"])
    subprocess.call(["systemctl", "enable", "yagura-watch.service"])
    rc = subprocess.call(["systemctl", "start", "yagura-watch.service"])
    if rc == 0:
        console.print("[ok]✓[/ok] yagura-watch started")
    return rc


def _watch_stop() -> int:
    _require_root()
    subprocess.call(["systemctl", "stop", "yagura-watch.service"])
    subprocess.call(["systemctl", "disable", "yagura-watch.service"])
    console.print("[ok]✓[/ok] yagura-watch stopped + disabled")
    return 0


def _watch_status() -> int:
    rc = subprocess.call(["systemctl", "status", "yagura-watch.service", "--no-pager", "-l"])
    log = LOG_DIR / "alerts.log"
    if log.exists():
        console.print("\n[bold]Last 10 alert log lines:[/bold]")
        try:
            tail = log.read_text(encoding="utf-8", errors="replace").splitlines()[-10:]
            for line in tail:
                console.print(f"  {line}")
        except OSError:
            pass
    return rc


def _watch_logs() -> int:
    return subprocess.call(["journalctl", "-u", "yagura-watch.service", "-f"])


# ---------- baseline ----------


def cmd_baseline(args) -> int:
    if args.baseline_command == "show":
        b = baseline_mod.load()
        if b is None:
            console.print("[warn]No baseline yet — run `yagura watch start`[/warn]")
            return 1
        sys.stdout.write(json.dumps(b, ensure_ascii=False, indent=2))
        return 0
    if args.baseline_command == "reset":
        _require_root()
        b = baseline_mod.build()
        baseline_mod.save(b)
        console.print(f"[ok]✓[/ok] baseline rebuilt ({len(b['listeners'])} listeners)")
        return 0
    if args.baseline_command == "diff":
        b = baseline_mod.load()
        if b is None:
            console.print("[warn]No baseline yet[/warn]")
            return 1
        cfg = load_config()
        from yagura.watch import rules

        alerts = rules.evaluate(b, cfg)
        if not alerts:
            console.print("[ok]No drift detected[/ok]")
            return 0
        for a in alerts:
            console.print(f"[{a.severity}] {a.rule_id}: {a.title} — {a.detail}")
        return 0
    return 2


# ---------- whitelist ----------


def cmd_whitelist(args) -> int:
    cfg = load_config()
    if args.whitelist_command == "list":
        wl = whitelist.list_all(cfg)
        for k, items in wl.items():
            console.print(
                f"[bold]{k}[/bold]: {', '.join(str(x) for x in items) if items else '[muted](empty)[/muted]'}"
            )
        return 0
    if args.whitelist_command == "add":
        kind = (
            "ports"
            if args.kind == "port"
            else ("processes" if args.kind == "process" else "ssh_ips")
        )
        ok = whitelist.add(cfg, kind, args.value)
        console.print(
            f"{'[ok]✓ added[/ok]' if ok else '[warn]already present (or invalid)[/warn]'}"
        )
        return 0 if ok else 1
    if args.whitelist_command == "remove":
        kind = (
            "ports"
            if args.kind == "port"
            else ("processes" if args.kind == "process" else "ssh_ips")
        )
        ok = whitelist.remove(cfg, kind, args.value)
        console.print(f"{'[ok]✓ removed[/ok]' if ok else '[warn]not found[/warn]'}")
        return 0 if ok else 1
    return 2


# ---------- report ----------


def cmd_report(args) -> int:
    if args.report_command == "list" or args.report_command is None:
        if not LOG_DIR.exists():
            console.print("[muted]No reports yet[/muted]")
            return 0
        reports = sorted(LOG_DIR.glob("report-*.md"))
        if not reports:
            console.print("[muted]No reports yet[/muted]")
            return 0
        if args.report_command is None:
            # Default: print the latest report
            latest = reports[-1]
            sys.stdout.write(latest.read_text(encoding="utf-8"))
            return 0
        table = Table(title="Reports", show_header=True, header_style="bold accent")
        table.add_column("File")
        table.add_column("Size")
        for p in reports:
            try:
                size = p.stat().st_size
            except OSError:
                size = 0
            table.add_row(p.name, f"{size} B")
        console.print(table)
        return 0
    if args.report_command == "show":
        target = args.date
        if not target:
            reports = sorted(LOG_DIR.glob("report-*.md"))
            if not reports:
                console.print("[muted]No reports yet[/muted]")
                return 1
            sys.stdout.write(reports[-1].read_text(encoding="utf-8"))
            return 0
        matches = sorted(LOG_DIR.glob(f"report-*{target}*.md"))
        if not matches:
            console.print(f"[warn]No report matching {target}[/warn]")
            return 1
        sys.stdout.write(matches[-1].read_text(encoding="utf-8"))
        return 0
    return 2


# ---------- config ----------


def cmd_config(args) -> int:
    cfg = load_config()
    if args.config_command == "show":
        import yaml

        sys.stdout.write(yaml.safe_dump(cfg, sort_keys=False, allow_unicode=True))
        return 0
    if args.config_command == "edit":
        editor = os.environ.get("EDITOR", "vi")
        ensure_dirs()
        if not CONFIG_PATH.exists():
            save_config(cfg)
        return subprocess.call([editor, str(CONFIG_PATH)])
    if args.config_command == "set":
        # Try to coerce common scalar types
        value: object = args.value
        if value.lower() in ("true", "false"):
            value = value.lower() == "true"
        else:
            try:
                value = int(value)
            except ValueError:
                pass
        set_value(cfg, args.key, value)
        save_config(cfg)
        console.print(f"[ok]✓[/ok] {args.key} = {value}")
        return 0
    return 2


# ---------- uninstall ----------


def cmd_uninstall(_args) -> int:
    _require_root()
    cfg = load_config()
    history = list(cfg.get("harden_history", []) or [])

    console.print("[bold]Rolling back applied hardening...[/bold]")
    for entry in reversed(history):
        cmd = entry.get("rollback_cmd", "")
        if not cmd:
            continue
        console.print(f"  [muted]{entry.get('id')}: {cmd}[/muted]")
        subprocess.call(["bash", "-c", cmd])

    console.print("[bold]Stopping yagura-watch...[/bold]")
    subprocess.call(["systemctl", "stop", "yagura-watch.service"])
    subprocess.call(["systemctl", "disable", "yagura-watch.service"])
    if SYSTEMD_UNIT_PATH.exists():
        SYSTEMD_UNIT_PATH.unlink()
    subprocess.call(["systemctl", "daemon-reload"])

    console.print("[bold]Removing state...[/bold]")
    for path in (BASELINE_PATH, CONFIG_PATH):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    # Leave /var/log/yagura with reports — user may want them.

    console.print(
        "[ok]✓[/ok] Yagura uninstalled. To remove the package itself:\n"
        "    [accent]rm -rf /opt/yagura /usr/local/bin/yagura[/accent]"
    )
    return 0


# ---------- health ----------


def _has_systemctl() -> bool:
    from shutil import which

    return which("systemctl") is not None


def _fmt_uptime(seconds: int) -> str:
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def cmd_health(_args) -> int:
    """Compact dashboard: watchdog state, uptime, last alerts, last scan, AI provider."""
    from yagura.collectors import system as sys_collector

    console.print()
    console.print("[bold]YAGURA · health[/bold]")
    console.print()

    # --- system uptime ---
    sysinfo = sys_collector.collect()
    uptime = _fmt_uptime(int(sysinfo.get("uptime_seconds", 0)))
    distro = sysinfo.get("distro", {}).get("name", "?")
    kernel = sysinfo.get("kernel", "?")
    load = sysinfo.get("load", [0.0, 0.0, 0.0])
    mem = sysinfo.get("memory", {})
    mem_pct = mem.get("percent", 0)
    console.print(f"  [muted]host[/muted]      {sysinfo.get('hostname', '?')} · {distro}")
    console.print(f"  [muted]kernel[/muted]    {kernel}")
    console.print(f"  [muted]uptime[/muted]    {uptime}")
    console.print(
        f"  [muted]load[/muted]      {load[0]:.2f} / {load[1]:.2f} / {load[2]:.2f}  "
        f"[muted](1m / 5m / 15m)[/muted]"
    )
    console.print(f"  [muted]memory[/muted]    {mem_pct}% used")
    console.print()

    # --- watchdog status ---
    if not _has_systemctl():
        console.print("  [muted]watch[/muted]     [warn]n/a[/warn] — systemd не найден на этом хосте")
    else:
        rc = subprocess.call(
            ["systemctl", "is-active", "--quiet", "yagura-watch.service"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if rc == 0:
            out = subprocess.run(
                ["systemctl", "show", "yagura-watch.service",
                 "--property=ActiveEnterTimestamp,ActiveState,SubState"],
                capture_output=True, text=True,
            )
            props = dict(
                line.split("=", 1) for line in out.stdout.strip().splitlines() if "=" in line
            )
            active_since = props.get("ActiveEnterTimestamp", "?")
            sub = props.get("SubState", "?")
            console.print(f"  [muted]watch[/muted]     [ok]●[/ok] active ({sub})")
            console.print(f"  [muted]since[/muted]     {active_since}")
        else:
            console.print(
                "  [muted]watch[/muted]     [warn]○[/warn] inactive — start with `yagura watch start`"
            )
    console.print()

    # --- last alerts ---
    log = LOG_DIR / "alerts.log"
    if log.exists():
        try:
            tail = log.read_text(encoding="utf-8", errors="replace").splitlines()[-5:]
        except OSError:
            tail = []
        if tail:
            console.print("  [bold]last alerts[/bold] [muted](newest at bottom)[/muted]")
            for line in tail:
                console.print(f"  {line}")
        else:
            console.print("  [muted]last alerts[/muted]   none")
    else:
        console.print("  [muted]last alerts[/muted]   no alerts.log yet")
    console.print()

    # --- last scan ---
    if LOG_DIR.exists():
        reports = sorted(LOG_DIR.glob("report-*.md"))
        if reports:
            latest = reports[-1]
            mtime = datetime.fromtimestamp(latest.stat().st_mtime, timezone.utc).isoformat(
                timespec="seconds"
            )
            console.print(f"  [muted]last scan[/muted] {latest.name}  [muted]({mtime})[/muted]")
        else:
            console.print("  [muted]last scan[/muted] none — run `yagura scan`")
    else:
        console.print("  [muted]last scan[/muted] none — run `yagura scan`")

    # --- AI provider ---
    cfg = load_config()
    ai_provider = get(cfg, "ai.provider", "none") or "none"
    ai_key = get(cfg, "ai.api_key", "")
    if ai_provider != "none" and ai_key:
        console.print(f"  [muted]ai[/muted]        {ai_provider} · key configured")
    else:
        console.print("  [muted]ai[/muted]        [warn]none[/warn] — alerts go without AI analysis")

    # --- baseline ---
    b = baseline_mod.load()
    if b is None:
        console.print("  [muted]baseline[/muted]  [warn]none[/warn] — run `yagura watch start`")
    else:
        listeners = len(b.get("listeners", []))
        units = len(b.get("systemd_units", []))
        console.print(f"  [muted]baseline[/muted]  {listeners} listeners · {units} units")

    console.print()
    return 0


COMMANDS = {
    "version": cmd_version,
    "scan": cmd_scan,
    "harden": cmd_harden,
    "watch": cmd_watch,
    "baseline": cmd_baseline,
    "whitelist": cmd_whitelist,
    "report": cmd_report,
    "config": cmd_config,
    "uninstall": cmd_uninstall,
    "health": cmd_health,
}


if __name__ == "__main__":
    sys.exit(main())
