"""Watchdog daemon loop. Runs as systemd service: yagura-watch.service."""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

from yagura import __version__
from yagura.ai.factory import build_client
from yagura.ai.verdict import (
    AlertVerdict,
    build_alert_verdict_prompt,
    format_alert_context,
    get_verdict_with_retry,
    static_fallback,
)
from yagura.config import LOG_DIR, ensure_dirs, get, load_config
from yagura.watch import baseline as baseline_mod
from yagura.watch import known_legit, rules, telegram, triage

ALERT_LOG = LOG_DIR / "alerts.log"
DEFAULT_INTERVAL_MINUTES = 5

# AI is only consulted for HIGH/CRITICAL to keep the bill low.
AI_ENRICH_SEVERITIES = {"HIGH", "CRITICAL"}

# An alert "fires" only once per (rule_id + key) until it stops firing for COOLDOWN_TICKS ticks.
# This stops a single ongoing condition from spamming Telegram every interval.
COOLDOWN_TICKS = 12  # 12 ticks * 5min = 1h with default interval

# После первого алерта мы молчим. Но если условие продолжает выполняться
# ESCALATE_AFTER_TICKS подряд — присылаем повторный алерт с пометкой [PERSISTENT].
# Это защита от противоположной крайности: реальная угроза не должна затухнуть
# в cooldown, потому что оператор мог пропустить первое сообщение.
ESCALATE_AFTER_TICKS = 5  # ~25 минут на дефолтном интервале


def _setup_logging(level: int = logging.INFO) -> logging.Logger:
    ensure_dirs()
    logger = logging.getLogger("yagura.watch")
    logger.setLevel(level)
    if not logger.handlers:
        fh = logging.FileHandler(ALERT_LOG)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(fh)
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(sh)
    return logger


def run_forever() -> None:
    logger = _setup_logging()
    logger.info("yagura-watch starting up")

    cfg = load_config()
    interval_min = int(get(cfg, "watch.interval_minutes", DEFAULT_INTERVAL_MINUTES))
    interval_sec = max(60, interval_min * 60)
    heartbeat_hours = int(get(cfg, "watch.heartbeat_hours", 12))

    # Auto-apply bundled known-legit signatures before evaluating any rules.
    # Safe by design: each pack requires BOTH a process AND a destination match
    # against the live state, and re-applying is idempotent (source-tagged).
    # We collect the applied packs so we can notify the operator via Telegram —
    # silently changing security rules without telling the user is exactly the
    # behavior we don't want.
    auto_applied: list = []
    try:
        matches = known_legit.detect_matches()
        auto_applied = known_legit.apply_matches(cfg, matches, only_auto=True, actor="auto")
        if auto_applied:
            logger.info(
                f"known_legit: auto-applied {len(auto_applied)} packs at startup"
            )
            cfg = load_config()  # reload — apply_matches saved to disk
    except Exception as e:
        logger.warning(f"known_legit auto-apply failed: {e}")

    baseline = baseline_mod.load()
    if baseline is None:
        logger.error("baseline missing — run `yagura watch start` first to create one")
        sys.exit(1)

    bot_token = get(cfg, "watch.telegram.bot_token", "") or ""
    chat_id = get(cfg, "watch.telegram.chat_id", "") or ""
    ai_provider = get(cfg, "ai.provider", "none") or "none"
    ai_key = get(cfg, "ai.api_key", "") or ""
    ai_model = get(cfg, "ai.model", "") or ""
    ai = build_client(ai_provider, ai_key, ai_model)

    # In-memory cooldown:
    #   suppressed[(rule_id, key)] = ticks_until_unsuppress (decays each tick).
    # streak[(rule_id, key)] = сколько тиков ПОДРЯД срабатывала условие (для escalation).
    suppressed: dict[tuple[str, str], int] = {}
    streak: dict[tuple[str, str], int] = {}

    logger.info(
        f"interval: {interval_min}m, telegram: {'on' if bot_token else 'off'}, "
        f"ai: {ai.name if ai else 'off'}, heartbeat: "
        f"{'every ' + str(heartbeat_hours) + 'h' if heartbeat_hours > 0 else 'off'}"
    )

    # Startup notification — лети сразу, чтобы оператор видел что сервис поднялся.
    if bot_token and chat_id:
        ok, msg = telegram.send_startup(
            bot_token,
            chat_id,
            version=__version__,
            interval_min=interval_min,
            ai_provider=ai_provider,
            baseline_listeners=len(baseline.get("listeners", []) or []),
            baseline_units=len(baseline.get("systemd_units", []) or []),
        )
        if not ok:
            logger.error(f"telegram startup failed: {msg}")
        # Уведомление о том, что Yagura САМА добавила правила в whitelist —
        # отдельным сообщением, чтобы оператор увидел и понял, что заглушено.
        if auto_applied:
            ok, msg = telegram.send_whitelist_applied(
                bot_token, chat_id, applied_packs=auto_applied
            )
            if not ok:
                logger.error(f"telegram whitelist-applied notice failed: {msg}")

    # Counters for heartbeat — отражают работу с момента старта сервиса.
    started_at = time.time()
    ticks = 0
    alerts_sent = 0
    last_heartbeat = started_at  # отсчёт интервала

    while True:
        tick_start = time.time()
        try:
            alerts = rules.evaluate(baseline, cfg)
            sent = _handle_alerts(
                alerts, cfg, bot_token, chat_id, ai, suppressed, streak, logger
            )
            alerts_sent += sent
        except Exception as e:  # never let a transient error kill the daemon
            logger.exception(f"tick failed: {e}")

        ticks += 1

        # Heartbeat — раз в N часов; 0 = выключено.
        if heartbeat_hours > 0 and bot_token and chat_id:
            if tick_start - last_heartbeat >= heartbeat_hours * 3600:
                ok, msg = telegram.send_heartbeat(
                    bot_token,
                    chat_id,
                    uptime_seconds=int(tick_start - started_at),
                    ticks=ticks,
                    alerts_sent=alerts_sent,
                )
                if ok:
                    last_heartbeat = tick_start
                else:
                    logger.error(f"telegram heartbeat failed: {msg}")

        # Decay cooldowns
        suppressed = {k: v - 1 for k, v in suppressed.items() if v - 1 > 0}

        elapsed = time.time() - tick_start
        sleep_for = max(5, interval_sec - elapsed)
        time.sleep(sleep_for)


def _handle_alerts(
    alerts,
    cfg,
    bot_token,
    chat_id,
    ai,
    suppressed,
    streak,
    logger,
) -> int:
    """Process alerts; returns count successfully sent to Telegram."""
    sent = 0
    seen_keys: set[tuple[str, str]] = set()
    for a in alerts:
        key = _alert_key(a)
        seen_keys.add(key)
        streak[key] = streak.get(key, 0) + 1

        # Suppressed and not yet at escalation threshold → silent.
        if key in suppressed:
            suppressed[key] = COOLDOWN_TICKS
            # Escalation: если условие держится N тиков подряд — повторный алерт.
            if streak[key] == ESCALATE_AFTER_TICKS:
                logger.warning(
                    f"ESCALATE {a.rule_id} [{a.severity}] persistent for "
                    f"{streak[key]} ticks — {a.detail}"
                )
                if bot_token and chat_id:
                    # Escalation reuses the deterministic verdict (no AI call —
                    # we already paid for one on the original alert).
                    esc_verdict = _make_verdict(a, ai=None)
                    ok, msg = telegram.send_alert(
                        bot_token,
                        chat_id,
                        a,
                        verdict=esc_verdict,
                        persistent_ticks=streak[key],
                    )
                    if ok:
                        sent += 1
                    else:
                        logger.error(f"telegram send failed: {msg}")
            continue

        suppressed[key] = COOLDOWN_TICKS
        # Auto-triage: пишет результаты в a.context['triage'] перед отправкой/AI.
        try:
            triage.investigate(a)
        except Exception as e:
            logger.warning(f"triage failed for {a.rule_id}: {e}")
        logger.warning(f"ALERT {a.rule_id} [{a.severity}] {a.title} — {a.detail}")

        # Verdict pipeline: deterministic self-check first → AI → static fallback.
        # The deterministic check matters because AI was producing contradictory
        # verdicts on the same yagura-self process across consecutive alerts.
        # By short-circuiting here, the operator gets a stable answer.
        verdict = _make_verdict(a, ai)
        # Full AI text → log only (alerts.log). Telegram gets one_line + action.
        if verdict and verdict.full:
            logger.info(
                f"VERDICT {a.rule_id} [{verdict.verdict}/{verdict.source}] {verdict.full}"
            )

        if bot_token and chat_id:
            ok, msg = telegram.send_alert(bot_token, chat_id, a, verdict=verdict)
            if ok:
                sent += 1
            else:
                logger.error(f"telegram send failed: {msg}")

    # Сбрасываем streak для тех ключей, которые в этом тике не сработали —
    # условие исчезло, escalation надо начинать с нуля при следующем срабатывании.
    for k in list(streak.keys()):
        if k not in seen_keys:
            del streak[k]
    return sent


def _make_verdict(a, ai) -> AlertVerdict | None:
    """Build a verdict for an alert.

    Order:
      1. Deterministic self-detect (yagura's own bin/unit). If matched, return
         the static `legit_self` verdict — DON'T call AI for these. We learned
         the hard way that AI gives different answers for the same self-process
         across consecutive ticks; the heuristic is stable.
      2. If AI is configured AND severity is HIGH/CRITICAL, ask AI for a
         structured verdict (with one retry on parse failure).
      3. Otherwise (or if AI fails twice), return the static fallback so the
         alert still ships with SOMETHING actionable.
    """
    is_self = _is_self_alert(a)
    if is_self:
        return static_fallback(a.rule_id, a.severity, is_self=True)
    if ai is None or a.severity not in AI_ENRICH_SEVERITIES:
        # No AI for LOW/MEDIUM by policy (cost). LOW alerts ship without verdict
        # — the alert body itself is enough at that severity.
        if a.severity in AI_ENRICH_SEVERITIES:
            return static_fallback(a.rule_id, a.severity, is_self=False)
        return None
    prompt = build_alert_verdict_prompt(
        rule_id=a.rule_id,
        rule_name=a.title,
        severity=a.severity,
        details=a.detail,
        context=format_alert_context(a.context, max_len=1500),
    )
    v = get_verdict_with_retry(ai, prompt)
    if v is None:
        return static_fallback(a.rule_id, a.severity, is_self=False)
    return v


def _is_self_alert(a) -> bool:
    """Deterministic check: does the alert reference Yagura's own artifacts?"""
    rid = a.rule_id
    if rid in ("W-NET-001", "W-PROC-001"):
        lst = a.context.get("listener", {}) or {}
        return rules._is_self(lst)
    if rid == "W-SVC-001":
        unit = a.context.get("unit", "") or ""
        return unit.startswith("yagura-")
    if rid == "W-PROC-003":
        c = a.context.get("connection", {}) or {}
        return rules._is_self({"process": c.get("process", ""), "exe": c.get("exe", "")})
    return False


def _alert_key(a) -> tuple[str, str]:
    """Stable identity for cooldown.

    Для процессных правил key НЕ включает PID — короткоживущие процессы
    с регулярным перезапуском (новый PID каждый раз) иначе спамят как разные алерты.
    Используем (exe или cmdline) + raddr — стабильную идентичность процесса.
    """
    if a.rule_id in ("W-NET-001", "W-PROC-001"):
        lst = a.context.get("listener", {})
        return (a.rule_id, f"{lst.get('proto')}/{lst.get('port')}/{lst.get('exe', '')}")
    if a.rule_id == "W-PROC-002":
        cmdline = a.context.get("cmdline") or a.context.get("exe") or ""
        return (a.rule_id, cmdline[:120])
    if a.rule_id == "W-PROC-003":
        c = a.context.get("connection", {})
        ident = c.get("exe") or c.get("cmdline") or c.get("process", "")
        return (a.rule_id, f"{ident}->{c.get('raddr', '')}")
    if a.rule_id == "W-FILE-001":
        return (a.rule_id, a.context.get("path", ""))
    if a.rule_id in ("W-CRON-001", "W-CRON-002"):
        j = a.context.get("job", {})
        return (a.rule_id, f"{j.get('user')}@{j.get('cmd', '')[:80]}")
    if a.rule_id == "W-SVC-001":
        return (a.rule_id, a.context.get("unit", ""))
    if a.rule_id in ("W-USR-001", "W-USR-002"):
        return (a.rule_id, a.context.get("user", ""))
    return (a.rule_id, a.detail[:80])


# ---------- systemd unit management ----------

SYSTEMD_UNIT = """[Unit]
Description=Yagura watchdog (behavioral monitor)
After=network.target

[Service]
Type=simple
ExecStart={python} -m yagura.watch.monitor
Restart=on-failure
RestartSec=10s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""


def install_systemd_unit() -> Path:
    """Install yagura-watch.service. Returns the unit file path."""
    from yagura.config import SYSTEMD_UNIT_PATH

    body = SYSTEMD_UNIT.format(python=sys.executable)
    SYSTEMD_UNIT_PATH.write_text(body, encoding="utf-8")
    SYSTEMD_UNIT_PATH.chmod(0o644)
    return SYSTEMD_UNIT_PATH


if __name__ == "__main__":
    run_forever()
