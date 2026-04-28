<p align="center">
  <h1 align="center">YAGURA</h1>
  <p align="center"><strong>Аудит безопасности Linux-сервера + опциональный watchdog. Без баз сигнатур.</strong></p>
  <p align="center"><em>櫓 — Сторожевая башня. Видит всё. Молчит до угрозы.</em></p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/tool-Python%203.10%2B-3776AB?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/AI-Claude%20%7C%20OpenAI%20%7C%20Gemini-7C3AED" alt="AI">
  <img src="https://img.shields.io/badge/alerts-Telegram-26A5E4?logo=telegram&logoColor=white" alt="Telegram">
  <img src="https://img.shields.io/badge/runtime-systemd-FCC624?logo=linux&logoColor=black" alt="systemd">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT">
</p>

> **Парный проект к [GORONIN](https://github.com/kitay-sudo/goronin).** Goronin — активный страж-ловушка (浪人 ронин). Yagura — наблюдательная башня (櫓): аудит конфигурации + поведенческий watchdog. Хорошо стоят вместе.

---

## Установка

### Публичный репозиторий

```bash
curl -sSL https://raw.githubusercontent.com/kitay-sudo/yagura/main/install.sh | sudo bash
```

### Приватный репозиторий (нужен `GITHUB_TOKEN`)

Сейчас репо приватный — нужен PAT с правом `Contents: Read` на этот репозиторий:

```bash
export GITHUB_TOKEN=github_pat_xxxxx

curl -sSL -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://raw.githubusercontent.com/kitay-sudo/yagura/main/install.sh \
  | sudo GITHUB_TOKEN="$GITHUB_TOKEN" bash
```

> `sudo GITHUB_TOKEN=...` обязательно — `sudo` по умолчанию сбрасывает env, и токен внутри скрипта пропадёт.

### Что произойдёт

**Свежая установка:**

1. Поставится `python3` + `python3-venv` (если их нет на хосте).
2. Создастся venv в `/opt/yagura/venv/`, скачается архив с GitHub, установятся зависимости.
3. Зарегистрируется wrapper `/usr/local/bin/yagura`.
4. Запустится интерактивный мастер: выбор AI-провайдера (опционально) → scan → меню harden → предложение запустить watchdog с Telegram-алертами.

**Обновление** (если `/etc/yagura/config.yml` уже есть):

1. `tool/` синхронизируется с новой версией.
2. `yagura-watch.service` перезапускается с новым кодом — wizard **не запускается**, конфиг и baseline сохраняются.

### Закрепить версию

```bash
YAGURA_VERSION=v0.5.0 curl -sSL ... | sudo YAGURA_VERSION=v0.5.0 GITHUB_TOKEN=... bash
```

> 📖 **Подробное объяснение для пользователей** — что приходит в Telegram, сколько стоит AI, как удалить — в [HOW_IT_WORKS.md](HOW_IT_WORKS.md).

---

## Что делает Yagura

| Подсистема | Что |
|---|---|
| **Collectors** | `psutil` + парсинг `/etc/passwd`, `/etc/shadow`, `sshd_config`, `iptables -S`, `systemctl`, `dpkg`/`rpm`, cron, sysctl, хеши критичных файлов. ~30–60 секунд на полный сбор. |
| **Analyzers** | 18+ scan-правил: PermitRootLogin, PasswordAuth без fail2ban, default ACCEPT в iptables, ASLR off, NOPASSWD-сюдо, BD-листенеры на 0.0.0.0, cron с `curl ... \| bash`, systemd-юниты из `/tmp` и т.д. → Security Score 0–100. |
| **AI (опционально)** | Claude / GPT-4o / Gemini пишет короткий разбор отчёта простым языком. Твой ключ, твой счёт. |
| **Harden** | Меню исправлений с **preview / apply / rollback**. Каждое применение пишет rollback-команду в `harden_history`. |
| **Watch** | systemd-сервис `yagura-watch` — раз в 5 мин сравнивает состояние с baseline и шлёт алерты в Telegram при отклонениях. ~0.1% CPU. |

---

## Архитектура

Один Python-инструмент в venv. Никакого eBPF, никаких ядерных модулей, никаких баз сигнатур.

**Scan-режим:** `yagura scan` → собрал данные → проанализировал → нарисовал Rich-отчёт + сохранил markdown в `/var/log/yagura/report-YYYY-MM-DD-HHMM.md`. Не висит в памяти после завершения.

**Watch-режим:** `yagura watch start` сохраняет baseline в `/var/lib/yagura/baseline.json` и регистрирует systemd-юнит. Демон раз в N минут (по умолчанию 5) делает легковесную проверку — сравнивает листенеры, cron, systemd-units, UID-0 юзеров, hash критичных файлов с baseline, плюс эвристики (cryptominer, reverse-shell). Найдено отклонение → Telegram-алерт + (опционально) AI-обогащение для HIGH/CRITICAL.

**Состояние:** `/etc/yagura/config.yml` (mode 0600), `/var/lib/yagura/baseline.json`, `/var/log/yagura/`. Системный wrapper в `/usr/local/bin/yagura`.

**Исходящий трафик:** Telegram Bot API (если включён watch) + API выбранного AI-провайдера (если AI настроен). Входящих соединений у Yagura нет — Telegram-связь односторонняя, бот не принимает команды.

---

## CLI

```bash
yagura                       # полный wizard: scan + harden + watch offer
yagura health                # компактный дашборд: watch, uptime, последние алерты, last scan, AI, baseline
yagura help                  # алиас --help
yagura version

yagura scan                  # только аудит
yagura scan --json           # JSON-вывод для скриптов
yagura scan --report-only    # сохранить только markdown без интерактива

yagura harden                # меню harden (использует свежий scan)
yagura harden --apply-all    # все recommended без подтверждений (dangerous)
yagura harden rollback <id>  # откатить применённое изменение

yagura watch start           # baseline + systemd-юнит + старт
yagura watch stop            # остановить + disable
yagura watch status          # systemctl status + последние 10 алертов
yagura watch logs            # journalctl -u yagura-watch -f

yagura baseline show         # текущий baseline (JSON)
yagura baseline reset        # пересобрать baseline (после планового деплоя)
yagura baseline diff         # что изменилось vs baseline

yagura whitelist list
yagura whitelist add port 8080
yagura whitelist add process /opt/myapp/bin/server
yagura whitelist add ssh-ip 1.2.3.4
yagura whitelist remove port 8080

yagura report                # последний markdown-отчёт
yagura report list           # все сохранённые
yagura report show 2026-04-28

yagura config show           # текущий config.yml
yagura config edit           # открыть в $EDITOR
yagura config set ai.model claude-sonnet-4-6
yagura config set watch.interval_minutes 1   # тест/отладка (default: 5)

yagura uninstall             # откатить ВСЕ harden + удалить systemd-юнит + cleanup
```

Все команды требуют root (читают `/etc/shadow`, дёргают `systemctl` и `iptables`).
`yagura health` можно запускать без root — но без root не увидишь статус `yagura-watch.service` через `systemctl`.

---

## Конфиг

`/etc/yagura/config.yml` (создаётся wizard'ом, mode 0600):

```yaml
version: 1

ai:
  provider: claude        # claude | openai | gemini | none
  api_key: sk-ant-...
  model: ""               # пусто = провайдер default

watch:
  enabled: true
  interval_minutes: 5
  telegram:
    bot_token: "123:ABC..."
    chat_id: "987654321"
  rules_disabled: []      # ID правил которые юзер выключил

whitelist:
  ports: [22, 80, 443]
  processes:
    - /usr/sbin/sshd
    - /usr/sbin/nginx
  ssh_ips:
    - 1.2.3.4

harden_history:
  - id: ssh.disable_root
    applied_at: "2026-04-28T14:23:11Z"
    rollback_cmd: "sed -i ... && systemctl restart sshd"
```

Baseline в отдельном файле — `/var/lib/yagura/baseline.json`.

---

## Что детектится

### Scan-правила (18 шт)

| ID | Severity | Правило |
|----|----------|---------|
| SSH-001 | CRITICAL | `PermitRootLogin yes` в sshd_config |
| SSH-002 | HIGH | `PasswordAuthentication yes` + порт 22 + нет fail2ban |
| SSH-003 | CRITICAL | Юзеры с пустым паролем в `/etc/shadow` |
| SSH-004 | MEDIUM | >50 неудачных SSH-попыток за сутки |
| FW-001  | HIGH | Нет активного firewall (ufw/firewalld/iptables/nftables) |
| FW-002  | HIGH | Default policy `iptables INPUT = ACCEPT` |
| NET-001 | HIGH | Сервис слушает 0.0.0.0 на портах БД (3306/5432/27017/6379/...) |
| NET-002 | CRITICAL | Listener из `/tmp`, `/dev/shm`, `/var/tmp` |
| USR-001 | CRITICAL | Несколько UID 0 в `/etc/passwd` |
| USR-002 | MEDIUM | Sudo NOPASSWD для не-системных юзеров |
| PKG-001 | LOW | Не установлен `fail2ban` |
| PKG-002 | LOW | Не установлен `unattended-upgrades` / `dnf-automatic` |
| PKG-003 | MEDIUM | Доступны >5 обновлений |
| KER-001 | MEDIUM | `net.ipv4.tcp_syncookies = 0` |
| KER-002 | HIGH | `kernel.randomize_va_space = 0` (ASLR off) |
| CRON-001 | HIGH | Cron-job содержит `curl ... \| bash` или base64 |
| CRON-002 | MEDIUM | Cron-job из `/tmp` или `/home/*` |
| SVC-001 | CRITICAL | systemd-юнит с `ExecStart` из `/tmp`, `/dev/shm`, `/var/tmp` |

### Watch-правила (поведенческие, без сигнатур)

| ID | Severity | Описание |
|----|----------|---------|
| W-NET-001 | HIGH | Появился listener которого не было в baseline |
| W-PROC-001 | HIGH | Процесс из `/tmp`, `/dev/shm`, `/var/tmp` появился в listener'ах |
| W-PROC-002 | MEDIUM | CPU процесса >80% устойчиво + сетевые соединения (cryptominer) |
| W-PROC-003 | CRITICAL | bash/sh/python/perl/nc имеет ESTABLISHED наружу (reverse-shell) |
| W-FILE-001 | CRITICAL | Хеш `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `sshd_config`, `authorized_keys` изменился |
| W-CRON-001 | HIGH | Появился новый cron-job |
| W-CRON-002 | CRITICAL | Cron с `curl \| bash` / `wget \| sh` / base64 |
| W-SVC-001 | HIGH | Появился новый enabled systemd-юнит |
| W-USR-001 | CRITICAL | Новый аккаунт с UID 0 |
| W-USR-002 | HIGH | В `/etc/sudoers` или `sudoers.d/` добавлен новый юзер |

**Самоисключения:** W-SVC-001 не алертит на собственные юниты с префиксом `yagura-` (напр. `yagura-watch.service`). AI-промпт для алертов знает про артефакты Yagura и помечает их как ложные срабатывания.

**Cooldown:** один и тот же алерт подавляется на 1 час, чтобы не спамить Telegram.

---

## Smoke-test — убедиться что watchdog работает

После `yagura watch start` нужно проверить что детект и Telegram-доставка реально работают. Самый простой тест — открыть «подозрительный» listener:

```bash
# 1. Свежий baseline — на нём НЕТ порта 8888
sudo yagura baseline reset

# 2. Уменьши интервал проверки до 1 минуты (по умолчанию 5)
sudo yagura config set watch.interval_minutes 1
sudo systemctl restart yagura-watch.service

# 3. Открой listener в фоне
nohup python3 -m http.server 8888 > /tmp/test-listener.log 2>&1 &
echo "PID: $!"

# 4. Жди ~1 минуту — в Telegram должен прийти алерт W-NET-001 (HIGH)
sudo yagura watch logs   # увидишь tick в реальном времени

# 5. Убей listener и верни интервал
kill $!
sudo yagura config set watch.interval_minutes 5
sudo systemctl restart yagura-watch.service
```

Если алерт не пришёл за 2 минуты:
- проверь `yagura health` — раздел `watch` должен быть `active (running)`
- проверь `yagura config show` — `watch.telegram.bot_token` и `chat_id` непустые
- проверь логи: `sudo yagura watch logs` — там должна быть строка `[INFO] tick: N alerts`

Аналогично можно протестировать **W-CRON-001** (`(crontab -l; echo "* * * * * echo test") | crontab -`) или **W-USR-002** (новый юзер в sudoers с NOPASSWD).

---

## Безопасность самого Yagura

- Telegram-связь **односторонняя**: бот только шлёт сообщения, не принимает команды. Это не вектор атаки.
- API-ключи хранятся в `/etc/yagura/config.yml` с `chmod 0600`. Никуда не отправляются кроме API провайдера.
- AI вызывается только: 1) во время `scan` (если ключ настроен), 2) на HIGH/CRITICAL алерт в watch. На LOW/MEDIUM не тратим API-кредиты.
- `sudo` нужен потому что: чтение `/etc/shadow`, парсинг sudoers, `iptables -S`, запись в `/etc/ssh/sshd_config` при harden, регистрация systemd-юнита для watch.
- Каждое harden-действие имеет **rollback-команду**. `yagura uninstall` откатит всё и удалит саму Yagura.

---

## Совместимость

- Ubuntu 20.04+ / Debian 11+ / CentOS Stream 9 / Rocky Linux 9 / Arch (с systemd)
- Ядро 3.10+ (используется только polling через `psutil`, без eBPF)
- Python 3.10+ с пакетом `venv` (на Debian/Ubuntu это отдельный `pythonX.Y-venv`, install.sh ставит автоматически)

Без systemd `scan` и `harden` работают, `watch start` выдаст предупреждение и не установит юнит.
Команда `yagura health` на хостах без systemd показывает `watch: n/a` вместо статуса сервиса.

---

## Roadmap

- больше harden-actions: `PasswordPolicy`, `LoginDefs`, AppArmor profiles
- опциональный eBPF-collector для real-time детекций
- web-dashboard (read-only, локальный) для просмотра истории алертов
- multi-server: один CLI собирает отчёты с N серверов через ssh

История изменений по версиям — в [CHANGELOG.md](CHANGELOG.md).

---

## License

MIT — см. [LICENSE](LICENSE).

---

## Поддержать проект

Yagura развивается на энтузиазме. Если оказался полезен:

- USDT (TRC20): `TF9F2FPkreHVfbe8tZtn4V76j3jLo4SeXM`
- TON: `UQBl88kXWJWyHkDPkWNYQwwSCiCAIfA2DiExtZElwJFlIc1o`

После доната напиши `@kitay9` в Telegram свой ник — добавлю в стену чести на лендинге.
