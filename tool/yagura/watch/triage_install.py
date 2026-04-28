"""Install-time triage wizard.

Solves the problem: after `yagura watch start` collects baseline, the user's
own services (e.g. `goronin`, `balifornia-crm`) might have only just appeared
or might use ephemeral ports — and they trigger W-NET-001 / W-PROC-* on every
tick because they were never explicitly classified.

Flow:
1. Collect listeners + enabled systemd units.
2. Ask AI to classify each as system / known_app / custom / suspicious.
3. If TTY:  show interactive table → operator picks W/B/S per item.
   If no TTY: auto-apply AI recommendations, write audit log entry, send
              Telegram notice "вот что я авто-доверила, перепройди визард для правок".
4. Persist whitelist/blocklist into config with source="install_wizard:<timestamp>".

Key design choices:
- AI is called ONCE for the whole list (not per item) — saves tokens, gives
  the model cross-item context (e.g. "if sshd is here, system services exist").
- Failure modes: AI off → static heuristic-only classification. AI returns
  garbage → we retry once with stricter instruction, then fall back to
  heuristics. We never block install on AI failure.
- We never auto-execute anything destructive. "block" only marks for alerting,
  it does not kill or stop the process.
- All decisions written to whitelist-audit.log via known_legit._audit_write,
  so an operator can later trace who-decided-what.
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

from yagura.ai.prompts import build_install_triage_prompt
from yagura.collectors import network, services
from yagura.config import save_config

logger = logging.getLogger("yagura.watch.triage_install")

ItemKind = Literal["listener", "unit"]
Verdict = Literal["system", "known_app", "custom", "suspicious", "unknown"]
Action = Literal["whitelist", "block", "skip"]

# Bundled signatures used as the heuristic fallback when AI is unavailable.
# Conservative: these are well-known names that appear unmodified in default
# distro installs. We deliberately don't try to catch everything — anything
# we miss simply gets "custom + skip", which is safe (operator decides).
SYSTEM_PROCESSES = {
    "sshd", "systemd", "systemd-resolved", "systemd-networkd", "systemd-timesyncd",
    "systemd-logind", "systemd-journald", "systemd-udevd", "dbus-daemon",
    "cron", "crond", "rsyslogd", "chronyd", "ntpd", "init",
}
KNOWN_APPS = {
    "nginx", "apache2", "httpd", "haproxy",
    "postgres", "postgresql", "mysqld", "mariadbd", "redis-server",
    "mongod", "memcached", "rabbitmq-server",
    "docker", "dockerd", "containerd", "kubelet",
    "node_exporter", "prometheus", "grafana-server",
}
SUSPICIOUS_PATH_PREFIXES = ("/tmp/", "/dev/shm/", "/var/tmp/")
# Yagura-self markers — same as in rules.py SELF_*.
SELF_PROCESS_NAMES = {"yagura", "yagura-watch"}
SELF_EXE_PREFIXES = ("/opt/yagura/", "/usr/local/bin/yagura", "/usr/bin/yagura")
SELF_UNIT_PREFIX = "yagura-"


@dataclass
class TriageItem:
    """One service/listener under classification."""
    kind: ItemKind
    label: str             # human-readable: "sshd · tcp/22 · /usr/sbin/sshd"
    process: str = ""
    exe: str = ""
    proto: str = ""
    port: int | None = None
    user: str = ""
    unit: str = ""
    verdict: Verdict = "unknown"
    one_line: str = ""     # AI's one-line read or our heuristic fallback
    recommend: Action = "skip"
    chosen: Action = "skip"  # what the operator (or auto-apply) picked
    source: str = "heuristic"  # "ai" | "heuristic" — for audit transparency
    # Stable identity for whitelist payload — set in `apply_decisions`.
    raw: dict = field(default_factory=dict)


@dataclass
class TriageOutcome:
    items: list[TriageItem]
    applied_whitelist: int = 0
    applied_block: int = 0
    skipped: int = 0
    used_ai: bool = False
    ai_failed: bool = False  # True if AI call/parse failed, fell back to heuristic


# ---------- collection ----------


def collect_items() -> list[TriageItem]:
    """Snapshot listeners + enabled systemd units, dedup, return TriageItems."""
    items: list[TriageItem] = []
    seen_keys: set[tuple] = set()

    try:
        net = network.collect()
    except Exception as e:
        logger.warning(f"network collect failed: {e}")
        net = {"listeners": []}

    for lst in net.get("listeners", []) or []:
        proto = lst.get("proto", "?")
        port = lst.get("port")
        proc = lst.get("process", "?")
        exe = lst.get("exe", "")
        key = ("listener", proto, port, exe or proc)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        label_parts = [proc, f"{proto}/{port}"]
        if exe:
            label_parts.append(exe)
        items.append(
            TriageItem(
                kind="listener",
                label=" · ".join(label_parts),
                process=proc,
                exe=exe,
                proto=proto,
                port=port,
                user=lst.get("user", ""),
                raw={"proto": proto, "port": port, "exe": exe, "process": proc},
            )
        )

    # Enabled systemd units — but only those NOT already represented by a listener
    # (sshd appears in both lists — we keep just the listener entry to avoid
    # asking the operator twice about the same thing).
    listener_proc_names = {it.process for it in items}
    try:
        svc = services.collect()
    except Exception as e:
        logger.warning(f"services collect failed: {e}")
        svc = {"enabled_units": []}

    for unit in svc.get("enabled_units", []) or []:
        # `unit` is e.g. "sshd.service"; strip suffix to compare with proc name.
        base = unit.split(".", 1)[0]
        if base in listener_proc_names:
            continue
        if unit.startswith(SELF_UNIT_PREFIX):
            # Yagura's own unit — auto-classified, no need to ask.
            items.append(
                TriageItem(
                    kind="unit",
                    label=f"{unit} (yagura's own)",
                    unit=unit,
                    verdict="system",
                    one_line="собственный сервис мониторинга Yagura",
                    recommend="whitelist",
                    chosen="whitelist",
                    source="self-detect",
                    raw={"unit": unit},
                )
            )
            continue
        items.append(
            TriageItem(
                kind="unit",
                label=f"{unit}",
                unit=unit,
                raw={"unit": unit},
            )
        )

    return items


# ---------- AI classification ----------


def classify_with_ai(items: list[TriageItem], ai) -> bool:
    """Mutate `items` in place with AI verdicts. Returns True if AI succeeded.

    On failure (no AI configured, transport error, or unparseable JSON twice
    in a row), returns False without touching items — caller falls back to
    heuristics. We never raise.
    """
    if ai is None:
        return False
    # Build the input — only items not already classified deterministically.
    pending = [it for it in items if it.source not in ("self-detect",)]
    if not pending:
        return True
    payload = [
        {
            "index": idx,
            "kind": it.kind,
            "label": it.label,
            "process": it.process,
            "exe": it.exe,
            "proto": it.proto,
            "port": it.port,
            "user": it.user,
            "unit": it.unit,
        }
        for idx, it in enumerate(pending)
    ]
    prompt = build_install_triage_prompt(payload)
    try:
        text = ai.complete(prompt, max_tokens=1500)
    except Exception as e:
        logger.warning(f"install-triage AI call failed: {e}")
        return False
    parsed = _parse_install_triage(text, expected_len=len(pending))
    if parsed is None:
        # Retry once with stricter instruction — same trick as alert verdict.
        retry = (
            "Твой предыдущий ответ не распарсился. Верни СТРОГО один JSON-массив "
            "длины " + str(len(pending)) + ", без markdown, без префиксов.\n\n"
            "--- ИСХОДНЫЙ ЗАПРОС ---\n" + prompt
        )
        try:
            text2 = ai.complete(retry, max_tokens=1500)
        except Exception as e:
            logger.warning(f"install-triage AI retry failed: {e}")
            return False
        parsed = _parse_install_triage(text2, expected_len=len(pending))
        if parsed is None:
            logger.warning("install-triage AI returned unparseable JSON twice — falling back")
            return False
    for ai_entry, item in zip(parsed, pending):
        item.verdict = ai_entry.get("verdict") or "unknown"
        item.one_line = (ai_entry.get("one_line") or "")[:200]
        rec = ai_entry.get("recommend")
        if rec in ("whitelist", "block", "skip"):
            item.recommend = rec
        item.source = "ai"
        if not item.chosen or item.chosen == "skip":
            item.chosen = item.recommend
    return True


def _parse_install_triage(text: str, expected_len: int) -> list[dict] | None:
    """Parse the JSON array returned by AI. None on any failure."""
    if not text:
        return None
    raw = text.strip()
    # Strip ```json ... ``` fences if present.
    if raw.startswith("```"):
        # Find first newline after fence opening
        first_nl = raw.find("\n")
        if first_nl == -1:
            return None
        body = raw[first_nl + 1 :]
        end = body.rfind("```")
        if end != -1:
            raw = body[:end].strip()
        else:
            raw = body.strip()
    # Find first '[' and matching ']'.
    start = raw.find("[")
    end = raw.rfind("]")
    if start == -1 or end == -1 or end < start:
        return None
    try:
        data = json.loads(raw[start : end + 1])
    except json.JSONDecodeError:
        return None
    if not isinstance(data, list) or len(data) != expected_len:
        logger.debug(f"install-triage: array len mismatch (got {len(data) if isinstance(data, list) else 'not-list'}, want {expected_len})")
        return None
    out = []
    for entry in data:
        if not isinstance(entry, dict):
            return None
        out.append(entry)
    return out


# ---------- heuristic fallback ----------


def classify_with_heuristics(items: list[TriageItem]) -> None:
    """Conservative classification when AI is unavailable.

    Mutates items in place. Does NOT touch items already classified by
    self-detect or AI.
    """
    for it in items:
        if it.source in ("self-detect", "ai"):
            continue
        # Yagura own — already handled in collect_items, but double-check.
        if _is_self(it):
            it.verdict = "system"
            it.one_line = "собственный сервис мониторинга Yagura"
            it.recommend = "whitelist"
            it.chosen = "whitelist"
            it.source = "self-detect"
            continue
        if it.process in SYSTEM_PROCESSES:
            it.verdict = "system"
            it.one_line = "стандартный системный сервис"
            it.recommend = "whitelist"
        elif it.process in KNOWN_APPS:
            it.verdict = "known_app"
            it.one_line = "известное серверное ПО"
            it.recommend = "whitelist"
        elif it.exe and any(it.exe.startswith(p) for p in SUSPICIOUS_PATH_PREFIXES):
            it.verdict = "suspicious"
            it.one_line = "бинарь в подозрительном пути (/tmp, /dev/shm, /var/tmp)"
            it.recommend = "block"
        else:
            it.verdict = "custom"
            it.one_line = "кастомный/неизвестный процесс — нужна проверка оператора"
            it.recommend = "skip"
        # Default chosen = recommend for non-interactive flow; interactive may override.
        if not it.chosen or it.chosen == "skip":
            it.chosen = it.recommend


def _is_self(it: TriageItem) -> bool:
    if (it.process or "").lower() in SELF_PROCESS_NAMES:
        return True
    if it.exe and any(it.exe.startswith(p) for p in SELF_EXE_PREFIXES):
        return True
    if it.unit and it.unit.startswith(SELF_UNIT_PREFIX):
        return True
    return False


# ---------- interactive UI ----------


def run_interactive(console, items: list[TriageItem]) -> bool:
    """Render table, accept operator commands. Returns True if user accepted (not aborted).

    Commands:
        Enter / "a"   — accept all current `chosen` values (AI/heuristic recs)
        "<n><action>" — set item n's action ("4w 5b 6s")
        "all-w" / "all-b" / "all-s" — bulk set all custom/suspicious
        "q"           — abort, no changes
    """
    while True:
        _render_table(console, items)
        console.print(
            "\n[muted]Команды:[/muted] "
            "Enter=принять, [accent]4w 5w 7b[/accent]=индивидуально, "
            "[accent]all-w[/accent] / [accent]all-b[/accent] / [accent]all-s[/accent], "
            "[accent]q[/accent]=отмена"
        )
        try:
            raw = input("Твой выбор: ").strip()
        except EOFError:
            return False
        if raw.lower() in ("q", "quit"):
            console.print("[muted]отменено — никаких правил не применено[/muted]")
            return False
        if raw == "" or raw.lower() == "a":
            return True
        if raw.lower() in ("all-w", "all-b", "all-s"):
            target = {"all-w": "whitelist", "all-b": "block", "all-s": "skip"}[raw.lower()]
            for it in items:
                if it.source == "self-detect":
                    continue  # don't touch yagura's own
                it.chosen = target
            continue
        # Per-item assignments: "4w 5b 7s"
        ok = _apply_individual_commands(items, raw, console)
        if ok:
            console.print("[ok]✓[/ok] обновил")


def _render_table(console, items: list[TriageItem]) -> None:
    from rich.table import Table

    table = Table(title="Yagura: классификация процессов перед стартом", show_lines=False)
    table.add_column("#", style="muted", width=3)
    table.add_column("Сервис / listener", overflow="fold")
    table.add_column("AI-вердикт", width=14)
    table.add_column("Описание", overflow="fold")
    table.add_column("Действие", width=10)
    icon = {"system": "✓", "known_app": "✓", "custom": "?", "suspicious": "⚠", "unknown": "?"}
    color = {"whitelist": "ok", "block": "danger", "skip": "muted"}
    for idx, it in enumerate(items):
        verdict_str = f"{icon.get(it.verdict, '?')} {it.verdict}"
        action_str = f"[{color.get(it.chosen, 'muted')}]{it.chosen}[/]"
        table.add_row(str(idx), it.label, verdict_str, it.one_line, action_str)
    console.print(table)


def _apply_individual_commands(items: list[TriageItem], raw: str, console) -> bool:
    """Parse `4w 5b 7s` style commands. Returns True if at least one valid command applied."""
    applied = False
    for tok in raw.split():
        tok = tok.lower()
        if len(tok) < 2:
            continue
        idx_part, action_char = tok[:-1], tok[-1]
        try:
            idx = int(idx_part)
        except ValueError:
            console.print(f"[warn]не понял токен: {tok}[/warn]")
            continue
        if idx < 0 or idx >= len(items):
            console.print(f"[warn]индекс вне диапазона: {idx}[/warn]")
            continue
        target = {"w": "whitelist", "b": "block", "s": "skip"}.get(action_char)
        if target is None:
            console.print(f"[warn]неизвестное действие: {action_char} (используй w/b/s)[/warn]")
            continue
        items[idx].chosen = target
        applied = True
    return applied


# ---------- persistence ----------


def apply_decisions(cfg: dict, items: list[TriageItem]) -> TriageOutcome:
    """Write whitelist/block decisions to cfg, save, write audit log.

    Returns counters for the caller (logging / Telegram).

    Why I'm using a fresh source-tag per run: this lets the operator look at
    `yagura whitelist audit-log` later and see "this 12 entries came from the
    install wizard run on <date>". Removing them is one command.
    """
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    source_tag = f"install_wizard:{timestamp}"

    cfg.setdefault("whitelist", {})
    cfg["whitelist"].setdefault("ports", [])
    cfg["whitelist"].setdefault("processes", [])
    cfg.setdefault("blocklist", {})  # NEW section — symmetric to whitelist
    cfg["blocklist"].setdefault("processes", [])
    cfg["blocklist"].setdefault("units", [])

    outcome = TriageOutcome(items=items)
    audit_records: list[dict] = []
    for it in items:
        if it.chosen == "whitelist":
            _add_to_whitelist(cfg, it, source_tag)
            outcome.applied_whitelist += 1
            audit_records.append(
                {
                    "timestamp": timestamp,
                    "action": "whitelist_add",
                    "source": source_tag,
                    "item": it.label,
                    "verdict": it.verdict,
                    "verdict_source": it.source,
                }
            )
        elif it.chosen == "block":
            _add_to_blocklist(cfg, it, source_tag)
            outcome.applied_block += 1
            audit_records.append(
                {
                    "timestamp": timestamp,
                    "action": "blocklist_add",
                    "source": source_tag,
                    "item": it.label,
                    "verdict": it.verdict,
                    "verdict_source": it.source,
                }
            )
        else:
            outcome.skipped += 1

    if outcome.applied_whitelist or outcome.applied_block:
        save_config(cfg)
        # Reuse known_legit's audit log so all whitelist mutations live in one place.
        from yagura.watch import known_legit
        for rec in audit_records:
            known_legit._audit_write(rec)
    return outcome


def _add_to_whitelist(cfg: dict, it: TriageItem, source_tag: str) -> None:
    """Add an item's identifying fields to whitelist.

    Listener → whitelist port + process exe (both, so a future move of the
    binary doesn't immediately re-alert).
    Unit     → unit goes to whitelist.processes only if it has an exe;
               otherwise we skip (the W-SVC-001 rule already ignores yagura-*
               and unit-name alerts are about the SAME binary anyway).
    """
    wl = cfg["whitelist"]
    if it.kind == "listener":
        if it.port is not None and it.port not in wl["ports"]:
            wl["ports"].append(it.port)
        if it.exe and it.exe not in wl["processes"]:
            # Process whitelist accepts plain strings (legacy) — keep it simple.
            # `source` tracking lives in the audit log, not in the value itself,
            # because rules.is_process_whitelisted matches strings as-is.
            wl["processes"].append(it.exe)
    elif it.kind == "unit" and it.exe:
        if it.exe not in wl["processes"]:
            wl["processes"].append(it.exe)


def _add_to_blocklist(cfg: dict, it: TriageItem, source_tag: str) -> None:
    """Block list = bump alert severity, but never auto-kill.

    Implementation: blocklist entries are stored as dicts with `value` and
    `source`. Rules can check this list to escalate severity. No process is
    killed automatically — only the alert severity changes.
    """
    bl = cfg["blocklist"]
    if it.kind == "listener" and it.exe:
        if not any(e.get("value") == it.exe for e in bl["processes"] if isinstance(e, dict)):
            bl["processes"].append({"value": it.exe, "source": source_tag})
    if it.kind == "unit" and it.unit:
        if not any(e.get("value") == it.unit for e in bl["units"] if isinstance(e, dict)):
            bl["units"].append({"value": it.unit, "source": source_tag})


# ---------- top-level orchestration ----------


def run(console, cfg: dict, ai, *, force_interactive: bool = False) -> TriageOutcome:
    """End-to-end triage. Returns TriageOutcome; caller saves config separately if needed.

    Decision tree:
        TTY?       AI?     →  what runs
        yes        yes     →  AI classifies, table shown, operator picks
        yes        no      →  heuristics classify, table shown, operator picks
        no         yes     →  AI classifies, decisions auto-applied
        no         no      →  heuristics classify, decisions auto-applied

    `force_interactive`: from the `--interactive` CLI flag. Forces table even
    if stdin isn't a TTY (e.g. for testing or weird terminal setups).
    """
    items = collect_items()
    outcome = TriageOutcome(items=items)

    if not items:
        return outcome

    if ai is not None:
        ok = classify_with_ai(items, ai)
        outcome.used_ai = ok
        outcome.ai_failed = not ok
    # Heuristic fills any items not classified by AI/self-detect.
    classify_with_heuristics(items)

    interactive = force_interactive or sys.stdin.isatty()
    if interactive:
        accepted = run_interactive(console, items)
        if not accepted:
            outcome.skipped = len(items)
            return outcome

    apply_outcome = apply_decisions(cfg, items)
    # Merge counters — apply_decisions returns its own counters which we adopt.
    outcome.applied_whitelist = apply_outcome.applied_whitelist
    outcome.applied_block = apply_outcome.applied_block
    outcome.skipped = apply_outcome.skipped
    return outcome


def render_summary(console, outcome: TriageOutcome) -> None:
    """Print a one-block summary after `run()` completes."""
    console.print()
    if outcome.applied_whitelist or outcome.applied_block:
        console.print(
            f"[ok]✓[/ok] whitelist: {outcome.applied_whitelist} · "
            f"block: {outcome.applied_block} · skip: {outcome.skipped}"
        )
    else:
        console.print(f"[muted]ничего не добавлено (всё skip)[/muted]")
    if outcome.ai_failed:
        console.print("[warn]⚠[/warn] AI не ответил — использована эвристика по сигнатурам")
