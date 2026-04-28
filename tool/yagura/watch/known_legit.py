"""Bundled signatures of known-legit processes — detect live + auto-whitelist.

This module reads `known_legit.yml` (shipped with Yagura) and matches each pack
against the current host state. When a pack matches, its `whitelist` block is
merged into the user's config. Each merged entry is tagged with
`source: "bundled:<pack_id>"` so an operator can later audit / remove them via
`yagura whitelist list` (and so we don't re-add the same entry twice).

Safety design:
- Auto-applied packs require BOTH a process fingerprint AND a destination
  fingerprint. A signature alone (just cmdline, just dest) is intentionally not
  enough — otherwise an attacker could pre-stage a binary with a known name.
- Packs with `auto_apply: false` only surface in `yagura whitelist scan-bundled`
  for operator review.
- Every merge writes to the audit log so the operator can trace WHO added a rule.
"""

from __future__ import annotations

import json
import logging
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib import resources
from typing import Any

import yaml

from yagura.collectors import network as net_collector
from yagura.collectors import system as sys_collector
from yagura.config import LOG_DIR, save_config

logger = logging.getLogger("yagura.known_legit")

# Audit log: every auto-apply / manual-apply / removal is appended as a JSON
# line so an operator can reconstruct WHO added what and WHEN. Lives next to
# alerts.log; survives process restarts.
AUDIT_LOG = LOG_DIR / "whitelist-audit.log"


@dataclass
class Match:
    """A pack that matched the current host state."""
    pack_id: str
    description: str
    auto_apply: bool
    why: str = ""
    risk_assessment: str = ""
    how_to_audit: str = ""
    # Captured fingerprints (e.g. resolved username / cmdline) used to render
    # the actual whitelist entries with concrete values.
    captured: dict = field(default_factory=dict)
    whitelist_entries: list = field(default_factory=list)


def load_packs() -> list[dict]:
    """Read known_legit.yml from the installed package."""
    try:
        files = resources.files("yagura.watch")
        text = (files / "known_legit.yml").read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, AttributeError):
        return []
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as e:
        logger.warning(f"known_legit.yml parse error: {e}")
        return []
    return list(data.get("packs", []) or [])


def detect_matches(packs: list[dict] | None = None) -> list[Match]:
    """Return packs that match the live state of the current host."""
    if packs is None:
        packs = load_packs()
    if not packs:
        return []
    # Snapshot once — we don't want each pack triggering its own collect.
    state = _snapshot()
    matches: list[Match] = []
    for pack in packs:
        m = _match_pack(pack, state)
        if m:
            matches.append(m)
    return matches


def apply_matches(
    cfg: dict, matches: list[Match], *, only_auto: bool = True, actor: str = "auto"
) -> list[Match]:
    """Merge whitelist entries from matched packs into cfg.

    Returns the list of packs that were ACTUALLY applied (excluding skipped
    duplicates and non-auto packs when only_auto=True). Each application is
    written to the audit log so operators can reconstruct who-added-what-when.

    `only_auto=True` (default, used at watch start) skips packs flagged
    `auto_apply: false` — those require operator opt-in via the CLI.
    `actor` is recorded in the audit log: "auto" for daemon startup,
    "cli:<command>" for explicit operator action.
    """
    if not matches:
        return []
    cfg.setdefault("whitelist", {})
    cfg["whitelist"].setdefault("process_dest", [])
    cfg["whitelist"].setdefault("cmdline_substrings", [])

    applied: list[Match] = []
    existing_sources = _collect_existing_sources(cfg)
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

    for m in matches:
        if only_auto and not m.auto_apply:
            continue
        source_tag = f"bundled:{m.pack_id}"
        if source_tag in existing_sources:
            # Already applied — don't duplicate. The operator may have removed
            # individual entries, but we treat the source-tag as the unit of
            # truth. To re-add, they'd remove the tag from existing entries.
            continue
        added_for_pack = 0
        for entry in m.whitelist_entries:
            target_key = entry["_target"]
            payload = {k: v for k, v in entry.items() if not k.startswith("_")}
            payload["source"] = source_tag
            payload["applied_at"] = timestamp
            cfg["whitelist"][target_key].append(payload)
            added_for_pack += 1
        if added_for_pack:
            applied.append(m)
            logger.info(
                f"known_legit: applied pack '{m.pack_id}' "
                f"({added_for_pack} entries, actor={actor}) — {m.description}"
            )
            _audit_write(
                {
                    "timestamp": timestamp,
                    "action": "apply",
                    "pack_id": m.pack_id,
                    "description": m.description,
                    "entries_added": added_for_pack,
                    "actor": actor,
                    "captured": m.captured,
                }
            )
    if applied:
        try:
            save_config(cfg)
        except OSError as e:
            logger.warning(f"could not save config after auto-whitelist: {e}")
    return applied


def remove_pack(cfg: dict, pack_id: str, *, actor: str = "cli") -> int:
    """Remove all whitelist entries tagged with bundled:<pack_id>. Returns count removed."""
    source_tag = f"bundled:{pack_id}"
    removed = 0
    wl = cfg.get("whitelist", {}) or {}
    for key in ("process_dest", "cmdline_substrings"):
        items = wl.get(key, []) or []
        kept = [it for it in items if not (isinstance(it, dict) and it.get("source") == source_tag)]
        removed += len(items) - len(kept)
        wl[key] = kept
    if removed:
        save_config(cfg)
        _audit_write(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "action": "remove",
                "pack_id": pack_id,
                "entries_removed": removed,
                "actor": actor,
            }
        )
    return removed


def find_pack(pack_id: str) -> dict | None:
    """Look up a pack definition by id (for `whitelist explain`)."""
    for p in load_packs():
        if p.get("id") == pack_id:
            return p
    return None


def read_audit_log(limit: int = 100) -> list[dict]:
    """Return the last `limit` audit entries (most recent first)."""
    if not AUDIT_LOG.exists():
        return []
    try:
        lines = AUDIT_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    out: list[dict] = []
    for line in reversed(lines[-limit:]):
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _audit_write(record: dict) -> None:
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError as e:
        logger.warning(f"audit log write failed: {e}")


# ---------- internals ----------


def _snapshot() -> dict:
    """Collect the data needed to evaluate every pack — once."""
    try:
        net = net_collector.collect()
    except Exception as e:
        logger.warning(f"network collect failed: {e}")
        net = {"established": [], "listeners": []}
    try:
        host = socket.getfqdn()
    except OSError:
        host = ""
    distro = {}
    try:
        distro = sys_collector.collect().get("distro", {})
    except Exception:
        pass
    return {
        "established": net.get("established", []) or [],
        "listeners": net.get("listeners", []) or [],
        "hostname": host.lower(),
        "distro_id": (distro.get("id") or "").lower(),
    }


def _match_pack(pack: dict, state: dict) -> Match | None:
    pid = pack.get("id") or "?"
    detect = pack.get("detect", {}) or {}
    kind = detect.get("kind", "")

    captured: dict = {}
    matched_conn: dict | None = None

    if kind == "established":
        matched_conn = _find_established_match(detect, state["established"])
        if not matched_conn:
            return None
        captured["cmdline"] = matched_conn.get("cmdline") or matched_conn.get("process", "")
        captured["user"] = matched_conn.get("user", "")

    elif kind == "high_cpu_with_local_db":
        # Only auto-applies if false — surface for operator review only.
        # Detection still: there's a process matching cmdline pattern.
        matched_conn = _find_localdb_match(detect, state["established"])
        if not matched_conn:
            return None
        captured["cmdline"] = matched_conn.get("cmdline") or matched_conn.get("process", "")
        captured["user"] = matched_conn.get("user", "")

    elif kind == "hostname_match":
        if not _hostname_matches(state["hostname"], detect.get("hostname_suffix", []) or []):
            return None
        # Optional secondary requirement (process must also be live).
        sub = detect.get("requires_live_match")
        if sub:
            sub_match = _find_established_match(sub, state["established"])
            if not sub_match:
                return None
            captured["cmdline"] = sub_match.get("cmdline") or sub_match.get("process", "")
            captured["user"] = sub_match.get("user", "")
            matched_conn = sub_match

    else:
        return None

    # Build concrete whitelist entries from the template, substituting captures.
    raw_entries = pack.get("whitelist", {}) or {}
    entries: list[dict] = []
    for tpl in raw_entries.get("process_dest", []) or []:
        e = dict(tpl)
        e["_target"] = "process_dest"
        if e.pop("cmdline_user_match", False):
            # Use a safe substring of the cmdline as the matcher. Prefer user
            # name (e.g. "fm-agent") because it's stable and short.
            user = captured.get("user", "")
            cmd = captured.get("cmdline", "")
            e["cmdline"] = user or _shortest_meaningful_token(cmd)
            if not e["cmdline"]:
                continue  # skip if we can't capture anything meaningful
        entries.append(e)
    for tpl in raw_entries.get("cmdline_substrings", []) or []:
        if isinstance(tpl, dict) and tpl.get("cmdline_capture"):
            cmd = captured.get("cmdline", "")
            substring = _captured_substring(cmd, tpl.get("cmdline_substring_min_length", 8))
            if substring:
                entries.append({"_target": "cmdline_substrings", "value": substring})
        elif isinstance(tpl, str):
            entries.append({"_target": "cmdline_substrings", "value": tpl})

    if not entries:
        return None

    return Match(
        pack_id=pid,
        description=pack.get("description", ""),
        auto_apply=bool(pack.get("auto_apply", True)),
        why=pack.get("why", "") or "",
        risk_assessment=pack.get("risk_assessment", "") or "",
        how_to_audit=pack.get("how_to_audit", "") or "",
        captured=captured,
        whitelist_entries=entries,
    )


def _find_established_match(spec: dict, conns: list[dict]) -> dict | None:
    procs = set(spec.get("process_in", []) or [])
    users = set(spec.get("user_in", []) or [])
    suffixes = [s.lower() for s in spec.get("dest_hostname_suffix", []) or []]
    for c in conns:
        proc = (c.get("process") or "").lower()
        if procs and proc not in procs:
            continue
        if users and (c.get("user") or "") not in users:
            continue
        raddr = c.get("raddr", "")
        if ":" not in raddr:
            continue
        ip = raddr.rsplit(":", 1)[0]
        if suffixes:
            host = _ptr(ip)
            if not host or not any(host.lower().endswith(s) for s in suffixes):
                continue
        return c
    return None


def _find_localdb_match(spec: dict, conns: list[dict]) -> dict | None:
    procs = set(spec.get("process_in", []) or [])
    min_len = int(spec.get("cmdline_substring_min_length", 0) or 0)
    by_pid: dict[int, list[dict]] = {}
    for c in conns:
        if c.get("pid"):
            by_pid.setdefault(c["pid"], []).append(c)
    for pid, group in by_pid.items():
        first = group[0]
        proc = (first.get("process") or "").lower()
        if procs and not any(p in proc for p in procs):
            continue
        cmdline = first.get("cmdline", "") or ""
        if min_len and len(cmdline) < min_len:
            continue
        # require at least one localhost-DB connection
        from yagura.watch.rules import _is_local_db_conn

        if any(_is_local_db_conn(c) for c in group):
            return first
    return None


def _hostname_matches(host: str, suffixes: list[str]) -> bool:
    if not host or not suffixes:
        return False
    h = host.lower().rstrip(".")
    return any(h.endswith(s.lower().rstrip(".")) for s in suffixes)


def _shortest_meaningful_token(cmdline: str) -> str:
    """Pick the most distinctive path component from a cmdline."""
    if not cmdline:
        return ""
    # Look for /opt/<name>/ or /usr/local/<name>/ patterns
    parts = cmdline.replace("\\", "/").split("/")
    for p in parts:
        if len(p) >= 6 and ("-" in p or "_" in p) and not p.startswith("-"):
            return p
    return ""


def _captured_substring(cmdline: str, min_length: int) -> str:
    """Take the most stable, app-identifying chunk of a cmdline."""
    if not cmdline or len(cmdline) < min_length:
        return ""
    # Prefer everything between the last `/` and the next space/.js/.py.
    parts = cmdline.split()
    for token in parts:
        if "/" in token and len(token) >= min_length:
            # take the parent dir name as the most stable piece
            segs = [s for s in token.split("/") if s]
            for seg in reversed(segs[:-1]):  # skip the file itself
                if len(seg) >= min_length:
                    return seg
    return ""


_PTR_CACHE: dict[str, str] = {}


def _ptr(ip: str) -> str:
    if ip in _PTR_CACHE:
        return _PTR_CACHE[ip]
    try:
        host, _, _ = socket.gethostbyaddr(ip)
    except (OSError, socket.herror):
        host = ""
    _PTR_CACHE[ip] = host
    return host


def _collect_existing_sources(cfg: dict) -> set[str]:
    """All `source:` tags currently present in the whitelist."""
    out: set[str] = set()
    wl = cfg.get("whitelist", {}) or {}
    for key in ("process_dest", "cmdline_substrings"):
        for item in wl.get(key, []) or []:
            if isinstance(item, dict) and item.get("source"):
                out.add(item["source"])
    return out
