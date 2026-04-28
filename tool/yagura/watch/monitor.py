"""Watchdog daemon loop. Runs as systemd service: yagura-watch.service."""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

from yagura import __version__
from yagura.ai.factory import build_client
from yagura.ai.prompts import build_alert_prompt
from yagura.config import LOG_DIR, ensure_dirs, get, load_config
from yagura.watch import baseline as baseline_mod
from yagura.watch import rules, telegram

ALERT_LOG = LOG_DIR / "alerts.log"
DEFAULT_INTERVAL_MINUTES = 5

# AI is only consulted for HIGH/CRITICAL to keep the bill low.
AI_ENRICH_SEVERITIES = {"HIGH", "CRITICAL"}

# An alert "fires" only once per (rule_id + key) until it stops firing for COOLDOWN_TICKS ticks.
# This stops a single ongoing condition from spamming Telegram every interval.
COOLDOWN_TICKS = 12  # 12 ticks * 5min = 1h with default interval


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

    # In-memory cooldown: { (rule_id, key) -> ticks_since_last_seen }
    suppressed: dict[tuple[str, str], int] = {}

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

    # Counters for heartbeat — отражают работу с момента старта сервиса.
    started_at = time.time()
    ticks = 0
    alerts_sent = 0
    last_heartbeat = started_at  # отсчёт интервала

    while True:
        tick_start = time.time()
        try:
            alerts = rules.evaluate(baseline, cfg)
            sent = _handle_alerts(alerts, cfg, bot_token, chat_id, ai, suppressed, logger)
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
    logger,
) -> int:
    """Process alerts; returns count successfully sent to Telegram."""
    sent = 0
    for a in alerts:
        key = _alert_key(a)
        if key in suppressed:
            suppressed[key] = COOLDOWN_TICKS  # extend
            continue
        suppressed[key] = COOLDOWN_TICKS
        logger.warning(f"ALERT {a.rule_id} [{a.severity}] {a.title} — {a.detail}")
        ai_text = None
        if ai is not None and a.severity in AI_ENRICH_SEVERITIES:
            try:
                prompt = build_alert_prompt(
                    rule_id=a.rule_id,
                    rule_name=a.title,
                    severity=a.severity,
                    details=a.detail,
                    context=str(a.context)[:500],
                )
                ai_text = ai.complete(prompt, max_tokens=300)
            except Exception as e:
                logger.warning(f"AI enrich failed: {e}")
        if bot_token and chat_id:
            ok, msg = telegram.send_alert(bot_token, chat_id, a, ai_text=ai_text)
            if ok:
                sent += 1
            else:
                logger.error(f"telegram send failed: {msg}")
    return sent


def _alert_key(a) -> tuple[str, str]:
    """Stable identity for cooldown — different listener:port → different alert."""
    if a.rule_id in ("W-NET-001", "W-PROC-001"):
        lst = a.context.get("listener", {})
        return (a.rule_id, f"{lst.get('proto')}/{lst.get('port')}/{lst.get('pid')}")
    if a.rule_id == "W-PROC-003":
        c = a.context.get("connection", {})
        return (a.rule_id, f"{c.get('pid')}->{c.get('raddr')}")
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
