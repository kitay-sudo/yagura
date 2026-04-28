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
    p_w_start = p_w_sub.add_parser("start", help="Install and start yagura-watch.service")
    p_w_start.add_argument(
        "--no-triage",
        action="store_true",
        help="Skip the install-time triage wizard (whitelist/block classification)",
    )
    p_w_start.add_argument(
        "--interactive",
        action="store_true",
        help="Force interactive triage even if stdin is not a TTY",
    )
    p_w_sub.add_parser("stop", help="Stop and disable yagura-watch.service")
    p_w_sub.add_parser("status", help="Show daemon status + recent alerts")
    p_w_sub.add_parser("logs", help="Tail journalctl -u yagura-watch")
    p_w_sub.add_parser("run", help="Run the monitor loop in foreground (used by systemd)")
    p_w_wiz = p_w_sub.add_parser(
        "wizard",
        help="Re-run the install-time triage (classify processes, build whitelist/block)",
    )
    p_w_wiz.add_argument(
        "--interactive",
        action="store_true",
        help="Force interactive even if stdin is not a TTY",
    )

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
    p_wl_auto = p_wl_sub.add_parser(
        "auto",
        help="Interactive: scan recent alerts and offer to whitelist repeating ones",
    )
    p_wl_auto.add_argument(
        "--yes", action="store_true", help="Auto-accept all repeating alerts (non-interactive)"
    )
    p_wl_sb = p_wl_sub.add_parser(
        "scan-bundled",
        help="Show which bundled known-legit packs match this host",
    )
    p_wl_sb.add_argument(
        "--apply", action="store_true", help="Apply matched packs (incl. non-auto-apply ones)"
    )
    p_wl_ex = p_wl_sub.add_parser(
        "explain",
        help="Print the full why/risk/audit description of a bundled pack",
    )
    p_wl_ex.add_argument("pack_id")
    p_wl_rp = p_wl_sub.add_parser(
        "remove-pack",
        help="Remove all whitelist entries that came from a specific bundled pack",
    )
    p_wl_rp.add_argument("pack_id")
    p_wl_sub.add_parser(
        "audit-log",
        help="Show the audit log of whitelist changes (who applied/removed what, when)",
    )

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
        return _watch_start(
            skip_triage=getattr(args, "no_triage", False),
            force_interactive=getattr(args, "interactive", False),
        )
    if args.watch_command == "stop":
        return _watch_stop()
    if args.watch_command == "status":
        return _watch_status()
    if args.watch_command == "logs":
        return _watch_logs()
    if args.watch_command == "run":
        monitor.run_forever()
        return 0
    if args.watch_command == "wizard":
        return _watch_wizard(force_interactive=getattr(args, "interactive", False))
    return 2


def _watch_wizard(*, force_interactive: bool) -> int:
    """Re-run install-time triage standalone (post-install adjustments)."""
    _require_root()
    cfg = load_config()
    from yagura.watch import triage_install

    provider = get(cfg, "ai.provider", "none")
    api_key = get(cfg, "ai.api_key", "")
    ai = build_client(provider, api_key, get(cfg, "ai.model", "")) if api_key else None
    outcome = triage_install.run(console, cfg, ai, force_interactive=force_interactive)
    triage_install.render_summary(console, outcome)
    return 0


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

    # Install-time triage: classify listeners + units BEFORE baseline so the
    # operator's known apps go into whitelist on first boot, and we don't bomb
    # them with W-NET/W-PROC alerts on every tick.
    _run_install_triage(cfg)

    cfg = load_config()  # reload — triage may have written whitelist entries
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


def _run_install_triage(cfg: dict, *, force_interactive: bool = False) -> None:
    """Classify processes and persist whitelist/blocklist before baseline.

    Failures are non-fatal — if AI is off and heuristics don't classify
    anything, we just continue without a wizard run.
    """
    from yagura.watch import triage_install

    provider = get(cfg, "ai.provider", "none")
    api_key = get(cfg, "ai.api_key", "")
    ai = build_client(provider, api_key, get(cfg, "ai.model", "")) if api_key else None
    console.print("\n[accent]→[/accent] триаж процессов перед стартом...")
    try:
        outcome = triage_install.run(console, cfg, ai, force_interactive=force_interactive)
    except Exception as e:
        console.print(f"[warn]триаж не выполнен: {e}[/warn]")
        return
    triage_install.render_summary(console, outcome)


def _watch_start(*, skip_triage: bool = False, force_interactive: bool = False) -> int:
    _require_root()
    cfg = load_config()
    if not get(cfg, "watch.telegram.bot_token"):
        console.print("[muted]Telegram not configured — running enable wizard...[/muted]")
        _enable_watch(cfg)
        return 0
    if not skip_triage:
        _run_install_triage(cfg, force_interactive=force_interactive)
        cfg = load_config()
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
        return _whitelist_list(cfg)
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
    if args.whitelist_command == "auto":
        return _whitelist_auto(cfg, accept_all=getattr(args, "yes", False))
    if args.whitelist_command == "scan-bundled":
        return _whitelist_scan_bundled(cfg, apply=getattr(args, "apply", False))
    if args.whitelist_command == "explain":
        return _whitelist_explain(args.pack_id)
    if args.whitelist_command == "remove-pack":
        return _whitelist_remove_pack(cfg, args.pack_id)
    if args.whitelist_command == "audit-log":
        return _whitelist_audit_log()
    return 2


def _whitelist_list(cfg: dict) -> int:
    """Verbose whitelist listing — shows source, capture, and how to remove."""
    from yagura.watch import known_legit

    wl = whitelist.list_all(cfg)
    for k, items in wl.items():
        console.print(
            f"[bold]{k}[/bold]: {', '.join(str(x) for x in items) if items else '[muted](empty)[/muted]'}"
        )

    # Group bundled entries by source pack so the operator sees one block per
    # pack (with description and rollback hint), not a flat dump.
    raw_pd = (cfg.get("whitelist", {}) or {}).get("process_dest", []) or []
    raw_cs = (cfg.get("whitelist", {}) or {}).get("cmdline_substrings", []) or []
    bundled: dict[str, list[tuple[str, dict]]] = {}
    manual: list[tuple[str, dict | str]] = []
    for it in raw_pd:
        src = (it.get("source") if isinstance(it, dict) else None) or "manual"
        if src.startswith("bundled:"):
            bundled.setdefault(src, []).append(("process_dest", it))
        else:
            manual.append(("process_dest", it))
    for it in raw_cs:
        src = (it.get("source") if isinstance(it, dict) else None) or "manual"
        if src.startswith("bundled:"):
            bundled.setdefault(src, []).append(("cmdline_substrings", it))
        else:
            manual.append(("cmdline_substrings", it))

    if bundled:
        console.print("\n[bold]Bundled rules (auto-applied at startup):[/bold]")
        for src_tag, group in sorted(bundled.items()):
            pack_id = src_tag.split(":", 1)[1]
            pack = known_legit.find_pack(pack_id) or {}
            description = pack.get("description", "")
            applied_at = ""
            for _, entry in group:
                if isinstance(entry, dict) and entry.get("applied_at"):
                    applied_at = entry["applied_at"]
                    break
            header = f"  [accent]●[/accent] {pack_id}"
            if description:
                header += f" — {description}"
            console.print(header)
            if applied_at:
                console.print(f"    [muted]applied:[/muted]  {applied_at}")
            for kind, entry in group:
                payload = (
                    {kk: vv for kk, vv in entry.items() if kk not in ("source", "applied_at")}
                    if isinstance(entry, dict)
                    else entry
                )
                console.print(f"    [muted]{kind}:[/muted] {payload}")
            console.print(
                f"    [muted]explain:[/muted] yagura whitelist explain {pack_id}"
            )
            console.print(
                f"    [muted]remove:[/muted]  sudo yagura whitelist remove-pack {pack_id}"
            )
    if manual:
        console.print("\n[bold]Manual rules:[/bold]")
        for kind, entry in manual:
            payload = (
                {kk: vv for kk, vv in entry.items() if kk != "source"}
                if isinstance(entry, dict)
                else entry
            )
            console.print(f"  [muted]{kind}:[/muted] {payload}")
    return 0


def _whitelist_explain(pack_id: str) -> int:
    """Print the full description of a bundled pack: what, why, risk, how-to-audit."""
    from yagura.watch import known_legit

    pack = known_legit.find_pack(pack_id)
    if not pack:
        console.print(f"[warn]No bundled pack with id '{pack_id}'[/warn]")
        # Suggest similar ids to help the operator.
        all_ids = [p.get("id") for p in known_legit.load_packs()]
        if all_ids:
            console.print(f"[muted]Available: {', '.join(all_ids)}[/muted]")
        return 1
    auto = "yes" if pack.get("auto_apply", True) else "no (operator opt-in only)"
    console.print(f"\n[bold accent]{pack['id']}[/bold accent]")
    console.print(f"[bold]Описание:[/bold] {pack.get('description', '')}")
    console.print(f"[bold]Auto-apply:[/bold] {auto}\n")
    if pack.get("why"):
        console.print("[bold]Зачем нужен этот пак:[/bold]")
        for line in pack["why"].strip().splitlines():
            console.print(f"  {line}")
        console.print()
    if pack.get("risk_assessment"):
        console.print("[bold]Оценка риска:[/bold]")
        for line in pack["risk_assessment"].strip().splitlines():
            console.print(f"  {line}")
        console.print()
    if pack.get("how_to_audit"):
        console.print("[bold]Как проверить вручную:[/bold]")
        for line in pack["how_to_audit"].strip().splitlines():
            console.print(f"  {line}")
        console.print()
    detect = pack.get("detect", {})
    if detect:
        console.print("[bold]Детектится по сигнатуре:[/bold]")
        import yaml as _yaml

        for line in _yaml.safe_dump(detect, allow_unicode=True, sort_keys=False).splitlines():
            console.print(f"  [muted]{line}[/muted]")
    return 0


def _whitelist_remove_pack(cfg: dict, pack_id: str) -> int:
    from yagura.watch import known_legit

    _require_root()
    n = known_legit.remove_pack(cfg, pack_id, actor="cli:remove-pack")
    if n == 0:
        console.print(f"[warn]No entries from pack '{pack_id}' found in whitelist[/warn]")
        return 1
    console.print(f"[ok]✓[/ok] removed {n} entries from pack '{pack_id}'")
    console.print("[muted]Restart watchdog to drop these rules: systemctl restart yagura-watch[/muted]")
    return 0


def _whitelist_audit_log() -> int:
    from yagura.watch import known_legit

    entries = known_legit.read_audit_log(limit=200)
    if not entries:
        console.print("[muted]No whitelist changes recorded yet.[/muted]")
        return 0
    console.print("[bold]Whitelist audit log (newest first):[/bold]\n")
    for e in entries:
        ts = e.get("timestamp", "?")
        action = e.get("action", "?")
        pack = e.get("pack_id", "?")
        actor = e.get("actor", "?")
        if action == "apply":
            n = e.get("entries_added", 0)
            cap = e.get("captured", {}) or {}
            cap_str = f" captured={cap}" if cap else ""
            console.print(
                f"  [muted]{ts}[/muted]  [ok]+[/ok] apply  [accent]{pack}[/accent]  "
                f"({n} entries, by {actor}){cap_str}"
            )
        elif action == "remove":
            n = e.get("entries_removed", 0)
            console.print(
                f"  [muted]{ts}[/muted]  [warn]−[/warn] remove [accent]{pack}[/accent]  "
                f"({n} entries, by {actor})"
            )
        else:
            console.print(f"  [muted]{ts}[/muted]  ? {e}")
    return 0


def _whitelist_scan_bundled(cfg: dict, *, apply: bool) -> int:
    """List bundled known-legit packs that match this host. With --apply, merge them."""
    from yagura.watch import known_legit

    matches = known_legit.detect_matches()
    if not matches:
        console.print("[muted]No bundled signatures match the current host state.[/muted]")
        return 0
    console.print(f"[bold]{len(matches)} bundled pack(s) match this host:[/bold]\n")
    for m in matches:
        flag = "[ok]auto-apply[/ok]" if m.auto_apply else "[warn]manual[/warn]"
        console.print(f"  {flag} [accent]{m.pack_id}[/accent] — {m.description}")
        for e in m.whitelist_entries:
            preview = {k: v for k, v in e.items() if not k.startswith("_")}
            console.print(f"      → {e['_target']}: {preview}")
        if m.captured:
            console.print(f"      [muted]captured: {m.captured}[/muted]")
    if not apply:
        console.print(
            "\n[muted]Run with --apply to merge these into config "
            "(auto-apply ones already merged on watch start).[/muted]"
        )
        return 0
    _require_root()
    # Apply ALL packs (including manual ones) — operator explicitly asked.
    applied = known_legit.apply_matches(
        cfg, matches, only_auto=False, actor="cli:scan-bundled"
    )
    if not applied:
        console.print("\n[muted]Nothing new applied (all matched packs already in whitelist).[/muted]")
        return 0
    console.print(f"\n[ok]✓[/ok] applied {len(applied)} pack(s):")
    for m in applied:
        console.print(f"  [accent]●[/accent] {m.pack_id}  [muted]({len(m.whitelist_entries)} entries)[/muted]")
    console.print(
        "\n[muted]Restart watchdog to pick up new rules: "
        "systemctl restart yagura-watch[/muted]"
    )
    return 0


def _whitelist_auto(cfg: dict, *, accept_all: bool) -> int:
    """Scan alerts.log for repeating signatures and offer to whitelist them."""
    from collections import Counter

    log = LOG_DIR / "alerts.log"
    if not log.exists():
        console.print("[muted]No alerts.log yet — let watchdog run for a while first.[/muted]")
        return 0
    try:
        lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        console.print(f"[warn]could not read alerts.log: {e}[/warn]")
        return 1

    # Parse lines like:
    #   2026-04-28 12:07:00 [WARNING] ALERT W-PROC-003 [CRITICAL] Reverse-shell heuristic — <detail>
    counter: Counter[tuple[str, str]] = Counter()
    examples: dict[tuple[str, str], str] = {}
    for line in lines:
        if "ALERT W-PROC-00" not in line:
            continue
        try:
            after = line.split("ALERT ", 1)[1]
            rid = after.split(" ", 1)[0]
            detail = line.rsplit(" — ", 1)[-1]
        except IndexError:
            continue
        # Use a short signature: rule + first 60 chars of detail (process+endpoint)
        sig = (rid, detail[:120])
        counter[sig] += 1
        examples.setdefault(sig, line)

    repeats = [(sig, n) for sig, n in counter.items() if n >= 2]
    if not repeats:
        console.print("[ok]No repeating W-PROC-* alerts found in the log.[/ok]")
        return 0
    repeats.sort(key=lambda x: -x[1])

    console.print(f"[bold]Found {len(repeats)} repeating alert signature(s):[/bold]\n")
    added = 0
    for (rid, detail), n in repeats:
        console.print(f"  [warn]×{n}[/warn] [accent]{rid}[/accent]  {detail}")
        if accept_all:
            choice = "y"
        else:
            try:
                resp = input("    → whitelist this signature? [y/N/q]: ").strip().lower()
            except EOFError:
                resp = "n"
            if resp == "q":
                break
            choice = resp
        if choice != "y":
            continue
        # Heuristic: extract process name + raddr from the detail line.
        added_now = _whitelist_from_alert_line(cfg, rid, detail)
        if added_now:
            added += added_now
            console.print(f"    [ok]✓[/ok] added {added_now} entry/entries")
        else:
            console.print("    [warn]could not parse this alert into a whitelist rule[/warn]")
    if added:
        save_config(cfg)
    console.print(f"\n[bold]Done — added {added} entries to whitelist.[/bold]")
    if added:
        console.print("[muted]Restart watchdog to pick up new rules: systemctl restart yagura-watch[/muted]")
    return 0


def _whitelist_from_alert_line(cfg: dict, rid: str, detail: str) -> int:
    """Parse an alert detail string and add a matching whitelist entry."""
    cfg.setdefault("whitelist", {})
    if rid == "W-PROC-003":
        # Detail format: "<cmdline> (PID N, user U) → ESTABLISHED IP:PORT"
        if "→ ESTABLISHED " not in detail or " (PID " not in detail:
            return 0
        cmdline = detail.split(" (PID ", 1)[0].strip()
        ip_part = detail.rsplit("→ ESTABLISHED ", 1)[1].strip()
        ip = ip_part.rsplit(":", 1)[0]
        # Use the user name (most stable identifier) as the cmdline matcher.
        user_token = ""
        try:
            user_token = detail.split("user ", 1)[1].split(")", 1)[0].strip()
        except IndexError:
            pass
        match_str = user_token or _stable_cmdline_token(cmdline)
        if not match_str:
            return 0
        cfg["whitelist"].setdefault("process_dest", []).append(
            {"cmdline": match_str, "dest_ip": ip + "/32", "source": "manual:auto"}
        )
        return 1
    if rid == "W-PROC-002":
        # Detail format: "<cmdline> (PID N, CPU X%, user U) has network connections [...]"
        if " (PID " not in detail:
            return 0
        cmdline = detail.split(" (PID ", 1)[0].strip()
        token = _stable_cmdline_token(cmdline)
        if not token:
            return 0
        cfg["whitelist"].setdefault("cmdline_substrings", []).append(
            {"value": token, "source": "manual:auto"}
        )
        return 1
    return 0


def _stable_cmdline_token(cmdline: str) -> str:
    """Pick a stable distinctive substring from cmdline for whitelist matching."""
    if not cmdline:
        return ""
    # prefer a path component with hyphens/underscores, length ≥ 6
    parts = [p for p in cmdline.replace("\\", "/").split("/") if p]
    for p in reversed(parts):
        if len(p) >= 6 and ("-" in p or "_" in p) and not p.startswith("-"):
            return p
    # fallback: first non-flag word ≥ 6 chars
    for tok in cmdline.split():
        if len(tok) >= 6 and not tok.startswith("-"):
            return tok
    return ""


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
