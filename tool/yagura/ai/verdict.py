"""Structured AI verdicts for watchdog alerts.

The AI responds in a strict JSON schema so we can render a short, deterministic
Telegram message instead of free-form text that drifted between "ложная тревога"
and "kill процесс" for the same process across consecutive ticks.

Flow:
1. `build_alert_verdict_prompt(...)` produces a prompt that asks the model
   for `{verdict, one_line, action, full}` JSON.
2. `parse_verdict(text)` parses it. On parse failure we retry ONCE with a
   stricter "JSON only, no markdown" instruction. On second failure we return
   `None` and the caller falls back to a deterministic static verdict.

Why this design:
- Free-form AI text was producing contradictory verdicts on consecutive alerts
  for the same process. A small enum (legit_self / legit_known_app / suspicious
  / critical) gives the model far less room to drift.
- Two attempts max — no while-loops, no recursion. If the AI consistently can't
  return JSON, we silently fall back to the static verdict (worse than AI but
  better than a hallucinated one).
- The `full` field can be long and goes only to the alert log, not Telegram.
  Telegram gets `one_line` + `action` + (optional) `whitelist_hint`.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Literal

logger = logging.getLogger("yagura.ai.verdict")

VerdictKind = Literal["legit_self", "legit_known_app", "suspicious", "critical", "unknown"]

VALID_VERDICTS = {"legit_self", "legit_known_app", "suspicious", "critical", "unknown"}

ALERT_VERDICT_PROMPT = """Ты — security-аналитик, мониторишь Linux-сервер через Yagura.

КОНТЕКСТ Yagura: бинарь Yagura живёт в /usr/local/bin/yagura или /opt/yagura.
Юниты systemd с префиксом `yagura-` — это сама Yagura. Если алерт про них,
verdict = "legit_self".

СОБЫТИЕ
rule_id: {rule_id}
title: {rule_name}
severity: {severity}
detail: {details}

context (укорочен):
{context}

ЗАДАЧА
Верни строго ОДИН JSON-объект (без markdown-блоков, без префикса/суффикса). Схема:

{{
  "verdict": "legit_self" | "legit_known_app" | "suspicious" | "critical" | "unknown",
  "one_line": "<до 80 символов, человекочитаемо, без emoji>",
  "action": "<одна shell-команда ИЛИ null>",
  "full": "<развёрнутое объяснение для лога — 2-5 предложений, можно команды>"
}}

ПРАВИЛА выбора verdict:
- legit_self  — это сам Yagura (бинарь yagura, юнит yagura-*).
- legit_known_app — известное системное/инфраструктурное ПО (sshd, nginx, postgres,
  docker, systemd-* и т.п.) ИЛИ пользовательский сервис под systemd с разумным
  exe (/usr/local/bin/, /opt/, /usr/bin/) и без признаков компрометации.
- suspicious — есть подозрительные признаки: бинарь в /tmp,/dev/shm,/var/tmp;
  имя процесса замаскировано; необычные внешние коннекты; новый cron с base64/wget.
- critical — явный indicator-of-compromise: reverse-shell, новый UID 0, изменённый
  /etc/passwd, cron с обфускацией.
- unknown — недостаточно данных для классификации (используй только когда context
  правда не позволяет решить).

action: ОДНА команда. Для legit_* — команда добавления в whitelist (если применимо)
ИЛИ null. Для suspicious/critical — команда расследования или остановки. БЕЗ
автоматических деструктивных действий — kill только если есть прямой IoC.

Не пиши markdown, не пиши ```json, не добавляй текст вне JSON.
"""


RETRY_INSTRUCTION = (
    "Твой предыдущий ответ не распарсился как JSON. "
    "Верни СТРОГО один JSON-объект по той же схеме: "
    'keys = verdict, one_line, action, full. '
    "Никакого markdown, никаких ```json блоков, никакого текста до или после JSON."
)


@dataclass
class AlertVerdict:
    verdict: VerdictKind
    one_line: str
    action: str | None = None
    full: str = ""
    source: str = "ai"  # "ai" | "static_fallback" — для логирования

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "one_line": self.one_line,
            "action": self.action,
            "full": self.full,
            "source": self.source,
        }


def build_alert_verdict_prompt(
    rule_id: str, rule_name: str, severity: str, details: str, context: str
) -> str:
    return ALERT_VERDICT_PROMPT.format(
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        details=details,
        context=context,
    )


def parse_verdict(text: str) -> AlertVerdict | None:
    """Parse the AI response into an AlertVerdict. Returns None on failure.

    Tolerates:
    - Surrounding whitespace.
    - One ```json``` markdown block (we strip the fences).
    - Trailing prose after the JSON (we cut at the matched closing brace).
    """
    if not text:
        return None
    raw = _extract_json_object(text.strip())
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        logger.debug(f"verdict parse failed: {e}; raw={raw[:200]!r}")
        return None
    if not isinstance(data, dict):
        return None
    verdict = data.get("verdict")
    if verdict not in VALID_VERDICTS:
        logger.debug(f"verdict enum invalid: {verdict!r}")
        return None
    one_line = (data.get("one_line") or "").strip()
    if not one_line:
        return None
    if len(one_line) > 200:
        one_line = one_line[:199].rstrip() + "…"
    action = data.get("action")
    if isinstance(action, str):
        action = action.strip() or None
    else:
        action = None
    full = (data.get("full") or "").strip()
    return AlertVerdict(
        verdict=verdict,
        one_line=one_line,
        action=action,
        full=full,
        source="ai",
    )


def get_verdict_with_retry(ai, prompt: str, max_tokens: int = 500) -> AlertVerdict | None:
    """Call AI, parse JSON; on failure retry ONCE with a stricter instruction.

    Returns None if both attempts fail — caller should fall back to a static
    verdict. Never raises; transport errors are caught and logged.
    """
    if ai is None:
        return None
    try:
        text = ai.complete(prompt, max_tokens=max_tokens)
    except Exception as e:
        logger.warning(f"AI call failed: {e}")
        return None
    v = parse_verdict(text)
    if v is not None:
        return v
    # Retry: prepend retry instruction so the model knows what went wrong.
    retry_prompt = RETRY_INSTRUCTION + "\n\n--- ИСХОДНЫЙ ЗАПРОС ---\n" + prompt
    try:
        text2 = ai.complete(retry_prompt, max_tokens=max_tokens)
    except Exception as e:
        logger.warning(f"AI retry call failed: {e}")
        return None
    return parse_verdict(text2)


def static_fallback(rule_id: str, severity: str, is_self: bool) -> AlertVerdict:
    """Deterministic verdict used when AI is off or returns garbage twice.

    Conservative by design: we never claim something is legit unless the
    deterministic self-detect heuristic confirmed it. Otherwise we say
    "unknown" and let the operator decide.
    """
    if is_self:
        return AlertVerdict(
            verdict="legit_self",
            one_line="это сам Yagura — собственный сервис мониторинга",
            action="sudo yagura baseline reset",
            full="Алерт сработал на собственный артефакт Yagura (бинарь или systemd-юнит "
            "с префиксом yagura-). Это ложная тревога: пересобери baseline командой "
            "`sudo yagura baseline reset`, чтобы текущее состояние стало нормой.",
            source="static_fallback",
        )
    if severity == "CRITICAL":
        return AlertVerdict(
            verdict="suspicious",
            one_line="нужна ручная проверка — AI недоступен",
            action=None,
            full="AI-классификатор не смог дать вердикт (нет ключа или неверный JSON). "
            "Severity CRITICAL — рекомендуется проверить вручную: ps -fp <pid>, "
            "ss -tnp, проверить /etc/passwd и cron.",
            source="static_fallback",
        )
    return AlertVerdict(
        verdict="unknown",
        one_line="нужна ручная проверка — AI недоступен",
        action=None,
        full="AI-классификатор не смог дать вердикт. Проверь алерт вручную или "
        "включи AI-провайдер в /etc/yagura/config.yml.",
        source="static_fallback",
    )


# ---------- internals ----------


_JSON_FENCE_RE = re.compile(r"^```(?:json)?\s*\n?(.*?)\n?```\s*$", re.DOTALL)


def _extract_json_object(text: str) -> str:
    """Return the first balanced top-level JSON object substring, or ''.

    Handles a single ```json ... ``` fenced block. Ignores text after the
    closing brace so trailing prose ("Hope this helps!") doesn't break parsing.
    """
    if not text:
        return ""
    m = _JSON_FENCE_RE.match(text)
    if m:
        text = m.group(1).strip()
    start = text.find("{")
    if start == -1:
        return ""
    depth = 0
    in_str = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return ""
