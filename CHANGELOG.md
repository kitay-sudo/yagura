# Changelog

All notable changes to YAGURA will be documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.12.0] — 2026-05-07

### Changed

- W-NET-001 больше не алертит на headless Chrome, порождённый легитимным app-рантаймом. Подавление требует одновременного совпадения двух признаков: exe в browser-tooling кеше (`~/.cache/{puppeteer,ms-playwright,Cypress}/`, `*/node_modules/{puppeteer,playwright,cypress,electron}/`) И parent_name в `{node, python, pm2, electron, npm, yarn, pnpm, bun}`. Решает шум на любом Node-проекте с PDF-генерацией или e2e-тестами без ручного whitelist'а.
- Сетевой коллектор ([network.py](tool/yagura/collectors/network.py)) теперь возвращает `ppid`, `parent_name`, `parent_cmdline`, `cwd` для каждого listener и established-соединения. Поля inline в существующих структурах — никаких миграций baseline не требуется.
- AI-вердикт для алертов получает отдельный блок `process tree:` (pid/user/exe/cwd/cmdline/ppid/parent) перед stringified-context'ом. Промпт явно инструктирует модель: путь exe сам по себе не делает процесс подозрительным, смотри parent process. Прекращает ложные вердикты вида «chrome из кеш-папки = компрометация».

### Added

- `AnnouncementBar` и `TimewebCard` на лендинге.

## [0.11.0] — 2026-04-28

### Added

- Лендинг получил секцию "Журнал изменений" перед футером — последние релизы со ссылками на полный CHANGELOG и GitHub releases. В верхнем меню новые ссылки "Изменения" и "Стена чести" (как в [goronin](https://github.com/kitay-sudo/goronin)).
- Фавикон [frontend/public/favicon.svg](frontend/public/favicon.svg) — двухъярусная башня в sky-теме на тёмно-синем фоне со скруглением, парная стилистике goronin.

### Changed

- Логотип башни ([YaguraMark.jsx](frontend/src/components/landing/YaguraMark.jsx)) переделан: вместо плоского треугольника с прямоугольным телом — двухъярусная пагода с подвернутыми карнизами, финиалом-шпилем, конусоидальным телом и арроу-слит бойницами. Читается как башня даже на 22px в шапке.
- Восстановлено отслеживание `frontend/` в Git — раньше папка была в `.gitignore` (commit befe034), что ломало `pages.yml` workflow и не давало деплоиться. Теперь Pages автоматически билдит и деплоит лендинг на каждый push с изменениями в `frontend/**`. Только `node_modules/` и `dist/` остаются игнорируемыми.

## [0.10.0] — 2026-04-28

### Added

- Install-time triage-визард ([yagura/watch/triage_install.py](tool/yagura/watch/triage_install.py)). При `yagura watch start` (и в новой команде `yagura watch wizard`) Yagura собирает listeners + enabled units, отправляет один запрос в AI с просьбой классифицировать каждый как `system / known_app / custom / suspicious`, показывает оператору таблицу с командами `4w 5b 6s` / `all-w` / `q` и сохраняет решения в `whitelist` / `blocklist` ДО построения baseline. Это убирает шквал W-NET-001 на собственные сервисы оператора (типа `goronin`, `balifornia-crm`) сразу на старте.
- Без TTY (CI / unattended deploy) визард сам применяет AI-рекомендации и пишет решения в `whitelist-audit.log` с тегом `install_wizard:<timestamp>`.
- Флаги `yagura watch start --no-triage` / `--interactive` для пропуска или форс-режима визарда.
- Структурированный AI-вердикт ([yagura/ai/verdict.py](tool/yagura/ai/verdict.py)): модель отвечает строгим JSON `{verdict, one_line, action, full}` с enum-вердиктом (`legit_self / legit_known_app / suspicious / critical / unknown`). Парсер толерантен к ` ```json ` fences и трейлинг-прозе.
- Retry-фоллбек: если JSON не распарсился — один retry со строгим напоминанием, ещё один фейл — детерминированный `static_fallback`. Никаких бесконечных циклов.
- Новая секция конфига `blocklist.processes` / `blocklist.units` для процессов, помеченных оператором как "не должно тут быть". Это **только** повышает severity при следующем срабатывании — Yagura никогда не убивает процессы автоматически.

### Changed

- Telegram-формат алертов полностью переписан. Было: длинное полотно с `Авто-триаж: ├ ps: ├ ss: ├ systemd_unit: └`, секцией `Что делать:` с 4 командами вроде `kill -9` (страшно на ложных тревогах) и AI-блоком, который мог давать противоречивые вердикты на одном и том же процессе. Стало: 4-6 строк — `🍑 W-NET-001 · HIGH`, `host:`, `proto/port → proc (user, PID)`, `exe:`, `unit:`, потом одна строка `🤖 <one_line>`, одна команда `→ <action>`, и пара строк "Если знакомое → whitelist add / Если чужое → systemctl stop". Полное объяснение AI идёт в `alerts.log`, не в Telegram.
- Детерминированный self-check ([yagura/watch/monitor.py:_make_verdict](tool/yagura/watch/monitor.py)) выполняется ДО вызова AI. Если алерт про собственный артефакт Yagura (`/usr/local/bin/yagura`, `yagura-*.service`) — сразу возвращается `legit_self` без вызова AI. Это закрывает баг, когда AI давал противоречивые вердикты ("ложная тревога" → "kill процесс") на одном и том же self-процессе через тик.
- Whitelist/block hints в алертах формируются из контекста алерта детерминированно, независимо от AI — оператор всегда видит готовые команды `sudo yagura whitelist add process <exe>` и `sudo yagura whitelist add port <port>` без необходимости их печатать.

### Fixed

- На паре одинаковых W-NET-001 (например, `goronin` PID 2100527 на портах 10001 и 20472) AI больше не выдаёт противоречивые вердикты — JSON-схема и enum убирают почву под "ложная тревога" / "kill процесс" в соседних тиках.

## [0.9.0] — 2026-04-28

### Added

- `yagura whitelist auto` — интерактивно сканирует последние алерты и предлагает добавить часто повторяющиеся в whitelist (флаг `--yes` для non-interactive).
- `yagura whitelist scan-bundled` — показывает, какие bundled-сигнатуры из `known_legit.yml` подходят к текущему хосту.
- `yagura whitelist explain <pack_id>` — печатает полное `why` / `risk` / `audit` описание bundled-пака.
- `yagura whitelist remove-pack <pack_id>` — удаляет все entries, добавленные конкретным bundled-паком (с записью в audit log).
- `yagura whitelist audit-log` — журнал кто-что-когда добавлял в whitelist.
- Bundled-сигнатуры известных легитимных приложений ([known_legit.yml](tool/yagura/watch/known_legit.yml)) — Yagura авто-применяет правила тихого подавления для общеизвестных пар «процесс + назначение» (например, `fm-agent → *.googleusercontent.com`). Безопасность дизайна: каждый pack требует совпадения И процесса И назначения; стенд-элон cmdline-матч не пройдёт.
- Auto-triage dossier ([yagura/watch/triage.py](tool/yagura/watch/triage.py)) — перед отправкой алерта Yagura собирает `ps -fp`, `ss`, `/proc/<pid>/cmdline`, reverse-DNS, родительский PID, systemd-unit. Триаж может только ДОБАВЛЯТЬ информацию и максимум ПОНИЖАТЬ severity — никогда не глушит HIGH/CRITICAL без явных классификаторских доказательств.
- Telegram-уведомление при auto-применении whitelist-правил на старте watch — оператор сразу видит, что было заглушено и почему, плюс команды для отката (`sudo yagura whitelist remove-pack <id>`).

### Changed

- W-PROC-002 для процессов, держащих соединения на localhost к стандартным DB-портам (5432, 3306, 6379, 27017, 11211, 9200, 5672, 4222), понижает severity до LOW — это почти всегда легитимные приложения, не майнеры.
- W-PROC-002 учитывает whitelist по cmdline (например, `balifornia-crm` подавляет высокий-CPU алерт от `node /var/www/balifornia/...`).
- W-PROC-003 использует whitelist пар (cmdline + dest) — атакующий не пройдёт, переименовав бинарь в `fm-agent`, потому что нужно совпасть и cmdline и hostname/IP.

## [0.8.0] — 2026-04-28

### Changed

- W-NET-001 не алертит на эфемерных портах (≥ 32768) для процессов, уже известных в baseline по exe — это были в основном клиентские сокеты, которые psutil показывал как `LISTEN`. Уменьшает шум от postgres/redis/python-сервисов с динамическими портами.
- W-NET-001 / W-PROC-001 / W-PROC-003 распознают собственные артефакты Yagura и не алертят на них — раньше после установки приходил алерт про собственный watchdog-процесс.

### Added

- 172 строки новых тестов в [test_rules.py](tool/tests/test_rules.py) — покрывают сценарии self-detection, ephemeral-port suppression, и комбинации с whitelist.

## [0.7.0] — 2026-04-28

### Added

- Heartbeat-уведомления в Telegram (раз в `watch.heartbeat_hours` часов; `0` = выключено) с uptime, кол-вом тиков и алертов — видно, что watchdog жив и работает.
- Startup-уведомление в Telegram при запуске `yagura-watch.service` — сразу понятно, что сервис поднялся после перезагрузки.

### Changed

- В дефолтный конфиг добавлено поле `watch.heartbeat_hours` (по умолчанию 12 — два раза в сутки).

## [0.6.0] — 2026-04-28

### Added

- GitHub Actions workflow [pages.yml](.github/workflows/pages.yml) — автодеплой лендинга на GitHub Pages при push изменений в `frontend/**`. Использует официальные `actions/upload-pages-artifact` + `actions/deploy-pages` без сторонних `gh-pages` бренчей.
- README обновлён с инструкциями по приватному репо (`GITHUB_TOKEN` для install.sh).

### Changed

- Документация полностью переехала с GitLab на GitHub — все ссылки в README, CHANGELOG, HOW_IT_WORKS, ui/report.py обновлены.
- Иконки severity в Telegram-алертах синхронизированы с goronin: 🥊 (CRITICAL), 🍑 (HIGH), 🍔 (MEDIUM), 🥝 (LOW).

## [0.5.0] — 2026-04-28

### Added

- `yagura health` — компактный дашборд (host, kernel, uptime, load, memory, watchdog status, last alerts, last scan, AI provider, baseline). Работает и на хостах без systemd (`watch: n/a`).
- `yagura help` — алиас для `--help` (раньше `yagura help` падал с `argparse error`).

### Fixed

- W-SVC-001 больше не алертит на собственные юниты с префиксом `yagura-` — раньше после `yagura watch start` приходил ложный HIGH-алерт про `yagura-watch.service`.
- AI-промпт для watch-алертов знает про артефакты Yagura (`/opt/yagura`, `/etc/yagura`, юниты `yagura-*`) и помечает их как ложные срабатывания вместо «срочно проверь».

## [0.4.0] — 2026-04-28

### Fixed

- `install.sh` — venv проверяется по реальному артефакту `bin/python`, а не по существованию директории. Битая `/opt/yagura/venv/` от прошлой неудачной установки больше не блокирует повторный запуск — установщик пересоздаёт venv.

## [0.3.0] — 2026-04-28

Технический релиз (без изменений в коде).

## [0.2.0] — 2026-04-28

### Added

- `install.sh` — структурированный вывод с таймингами `mm:ss` и стилями `→ / ✓ / ⓘ / ⚠ / ✗` (как в goronin). Header с версией + footer со списком команд и контактами.
- Автоматическая установка `pythonX.Y-venv` на Debian/Ubuntu, если `python3` уже есть, но `python3 -m venv` падает с `ensurepip not available`.

### Changed

- Переезд с GitLab на GitHub: `install.sh` теперь использует GitHub API + `archive/refs/tags/...` URL. Поддержка приватного репо через `GITHUB_TOKEN` (PAT с правом `Contents: Read`).
- URL'ы в `pyproject.toml`, `README.md`, `CHANGELOG.md`, `HOW_IT_WORKS.md`, `tool/yagura/ui/report.py` обновлены на `github.com/kitay-sudo/yagura`.

### Added (CI/CD)

- GitHub Actions workflows: `ci.yml` (ruff + pytest + build для `tool/`, `npm ci` + build для `frontend/`), `release.yml` (sdist + wheel + SHA256SUMS на push тега `v*`).
- `scripts/release.bat` — bump SemVer + git tag + push (как в goronin).

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

[Unreleased]: https://github.com/kitay-sudo/yagura/compare/v0.11.0...HEAD
[0.11.0]: https://github.com/kitay-sudo/yagura/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/kitay-sudo/yagura/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/kitay-sudo/yagura/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/kitay-sudo/yagura/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/kitay-sudo/yagura/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/kitay-sudo/yagura/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/kitay-sudo/yagura/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/kitay-sudo/yagura/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/kitay-sudo/yagura/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/kitay-sudo/yagura/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kitay-sudo/yagura/releases/tag/v0.1.0
