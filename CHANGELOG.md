# Changelog

All notable changes to YAGURA will be documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.0] — 2026-04-28

Первая публичная версия. Парный проект к [GORONIN](https://github.com/kitay-sudo/goronin).

### Added

**Tool (`yagura`):**
- 10 collectors: `system`, `network`, `ssh`, `firewall`, `users`, `services`, `packages`, `cron`, `kernel`, `files`.
- 18 scan-rules (`SSH-001..004`, `FW-001..002`, `NET-001..002`, `USR-001..002`, `PKG-001..003`, `KER-001..002`, `CRON-001..002`, `SVC-001`).
- 10 watch-rules (`W-NET-001`, `W-PROC-001..003`, `W-FILE-001`, `W-CRON-001..002`, `W-SVC-001`, `W-USR-001..002`).
- 13 harden-actions с `preview / apply / rollback`: SSH (disable root, disable password auth, change port, lock empty users), firewall (`ufw enable`, `iptables default DROP`), packages (`fail2ban`, `unattended-upgrades`, `auditd`, `rkhunter`), kernel (`syncookies`, `ASLR`), `ssh-keygen`, generic `systemd disable`.
- 3 AI-провайдера через REST: Anthropic Claude, OpenAI, Google Gemini.
- Telegram-алерты (одно­сторонние) с cooldown 1 ч на повторяющиеся события.
- AI-обогащение HIGH/CRITICAL алертов (LOW/MEDIUM не тратят кредиты).
- Полный CLI: `scan`, `harden`, `watch start|stop|status|logs`, `baseline show|reset|diff`, `whitelist`, `report`, `config`, `uninstall`, `version`.
- systemd-юнит `yagura-watch.service` создаётся автоматически при включении watch.
- Markdown-отчёты в `/var/log/yagura/report-YYYY-MM-DD-HHMM.md`.

**Frontend (лендинг):**
- React 19 + Vite 6 + Tailwind v4, sky-500 акцент.
- Секции: Hero, YaguraStory, TwoModes (Scan vs Watch), Features, BehavioralRules, Versus (vs ClamAV/Wazuh/CrowdStrike), HowItWorks, DemoSection, FAQ, Support, CTA.
- Интерактивный TerminalDemo с реалистичной сессией `yagura scan` → harden → watch.
- Билд: ~120 КБ gz JS, ~6 КБ gz CSS.

**Установка:**
- `install.sh` — single-curl установщик, поддерживает Ubuntu/Debian/CentOS/Rocky/Arch.
- Update-режим (сохраняет конфиг и baseline) и `--reinstall` / `--uninstall` флаги.
- Создаёт venv в `/opt/yagura/venv/`, wrapper `/usr/local/bin/yagura`.

**CI/CD:**
- GitHub Actions: `ci.yml` (lint `ruff`, `pytest`, build), `release.yml` (sdist+wheel на push тега `v*`).

[Unreleased]: https://github.com/kitay-sudo/yagura/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kitay-sudo/yagura/releases/tag/v0.1.0
