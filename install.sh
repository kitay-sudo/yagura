#!/usr/bin/env bash
# YAGURA — one-command installer / updater / uninstaller.
#
# Usage:
#   # Первая установка ИЛИ обновление:
#   curl -sSL https://raw.githubusercontent.com/kitay-sudo/yagura/main/install.sh | sudo bash
#
#   # Принудительная переустановка с нуля (снесёт конфиг и данные!):
#   curl -sSL .../install.sh | sudo bash -s -- --reinstall
#
#   # Только удаление:
#   curl -sSL .../install.sh | sudo bash -s -- --uninstall
#
# Поведение зависит от того, что уже есть на сервере:
#   - инструмента нет     → установить + запустить wizard
#   - инструмент и конфиг → обновить tool/, сохранить настройки и baseline
#   - --reinstall         → uninstall + fresh install (потеря конфига!)
#   - --uninstall         → откат harden + удаление systemd-юнита + cleanup
#
# Закрепить версию: YAGURA_VERSION=v0.1.0 перед командой.
#
# Приватный репозиторий: задай GITHUB_TOKEN с правом `repo` (PAT classic) или
# `Contents: Read` (fine-grained). Пример:
#   curl -sSL -H "Authorization: Bearer $GITHUB_TOKEN" \
#     https://raw.githubusercontent.com/kitay-sudo/yagura/main/install.sh \
#     | sudo GITHUB_TOKEN="$GITHUB_TOKEN" bash

set -euo pipefail

REPO_HOST="github.com"
REPO_PATH="kitay-sudo/yagura"
INSTALL_DIR="/opt/yagura"
VENV_DIR="$INSTALL_DIR/venv"
TOOL_DIR="$INSTALL_DIR/tool"
WRAPPER="/usr/local/bin/yagura"
CONFIG_PATH="/etc/yagura/config.yml"

MODE="auto" # auto | reinstall | uninstall
for arg in "$@"; do
  case "$arg" in
    --reinstall) MODE="reinstall" ;;
    --uninstall) MODE="uninstall" ;;
    -h|--help)
      sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "Неизвестный флаг: $arg" >&2; exit 1 ;;
  esac
done

# ---------- coloring ----------
if [[ -t 1 ]]; then
  C_OK=$'\e[36m'; C_WARN=$'\e[33m'; C_ERR=$'\e[31m'; C_DIM=$'\e[2m'; C_RESET=$'\e[0m'
else
  C_OK=""; C_WARN=""; C_ERR=""; C_DIM=""; C_RESET=""
fi

say()  { printf "%s\n" "$*"; }
ok()   { printf "%s✓%s %s\n" "$C_OK" "$C_RESET" "$*"; }
warn() { printf "%s⚠%s %s\n" "$C_WARN" "$C_RESET" "$*" >&2; }
err()  { printf "%s✗%s %s\n" "$C_ERR" "$C_RESET" "$*" >&2; }
die()  { err "$*"; exit 1; }

# ---------- preflight ----------
[[ "$EUID" -eq 0 ]] || die "Запусти от root: curl ... | sudo bash"

OS="$(uname -s)"
[[ "$OS" == "Linux" ]] || die "Поддерживается только Linux (сейчас: $OS)"

command -v curl >/dev/null 2>&1 || die "curl не найден (sudo apt install curl / sudo dnf install curl)"

if ! command -v systemctl >/dev/null 2>&1; then
  warn "systemd не найден — режим scan будет работать, но watch установить не получится."
fi

# ---------- distro detection (used by all package-install paths) ----------
DISTRO_ID="unknown"
if [[ -f /etc/os-release ]]; then
  DISTRO_ID="$(. /etc/os-release && echo "${ID:-unknown}")"
fi

pm_install() {
  case "$DISTRO_ID" in
    ubuntu|debian|kali|linuxmint)
      apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
      ;;
    centos|rhel|rocky|almalinux|fedora)
      dnf install -y "$@"
      ;;
    arch|manjaro)
      pacman -Sy --noconfirm "$@"
      ;;
    *)
      die "Неподдерживаемый дистрибутив: $DISTRO_ID"
      ;;
  esac
}

# ---------- uninstall path (no download needed) ----------
if [[ "$MODE" == "uninstall" ]]; then
  if [[ -x "$WRAPPER" ]]; then
    say "${C_DIM}Запускаю yagura uninstall (откат harden + удаление systemd-юнита)…${C_RESET}"
    "$WRAPPER" uninstall || warn "uninstall завершился с ошибками — продолжаю"
  fi
  systemctl stop yagura-watch.service 2>/dev/null || true
  systemctl disable yagura-watch.service 2>/dev/null || true
  rm -f /etc/systemd/system/yagura-watch.service
  systemctl daemon-reload 2>/dev/null || true
  rm -rf "$INSTALL_DIR" /etc/yagura /var/lib/yagura
  rm -f "$WRAPPER"
  ok "Yagura удалён. Логи в /var/log/yagura оставлены."
  exit 0
fi

# ---------- reinstall path ----------
EXISTING_TOOL=""
EXISTING_CONFIG=""
[[ -d "$TOOL_DIR" ]] && EXISTING_TOOL="yes"
[[ -f "$CONFIG_PATH" ]] && EXISTING_CONFIG="yes"

if [[ "$MODE" == "reinstall" && -n "$EXISTING_TOOL" ]]; then
  warn "Режим --reinstall: сношу текущую установку (конфиг и данные будут утеряны)."
  if [[ -x "$WRAPPER" ]]; then
    "$WRAPPER" uninstall || true
  fi
  rm -rf "$INSTALL_DIR" /etc/yagura /var/lib/yagura
  rm -f "$WRAPPER"
  EXISTING_TOOL=""
  EXISTING_CONFIG=""
fi

# ---------- ensure Python 3.10+ ----------
need_python() {
  if command -v python3 >/dev/null 2>&1; then
    local ver
    ver="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
    local major minor
    major="${ver%.*}"; minor="${ver#*.}"
    if (( major > 3 || (major == 3 && minor >= 10) )); then
      return 1
    fi
  fi
  return 0
}

if need_python; then
  say "${C_DIM}Устанавливаю python3 + pip + venv…${C_RESET}"
  case "$DISTRO_ID" in
    ubuntu|debian|kali|linuxmint) pm_install python3 python3-venv python3-pip ;;
    centos|rhel|rocky|almalinux|fedora) pm_install python3 python3-pip ;;
    arch|manjaro) pm_install python python-pip ;;
    *) die "Поставь python3.10+ вручную и перезапусти install.sh" ;;
  esac
  ok "Python: $(python3 --version)"
else
  ok "Python: $(python3 --version) (уже установлен)"
fi

# ---------- determine version + download ----------
VERSION="${YAGURA_VERSION:-}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Для приватного репо нужен GITHUB_TOKEN — добавляем заголовок ко всем curl-запросам.
GH_AUTH=()
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  GH_AUTH=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
fi

if [[ -z "$VERSION" ]]; then
  say "${C_DIM}Определяю последний релиз…${C_RESET}"
  VERSION="$(curl -fsSL "${GH_AUTH[@]}" "https://api.${REPO_HOST}/repos/${REPO_PATH}/releases/latest" \
    | grep -oE '"tag_name":\s*"[^"]+"' | head -n1 | cut -d'"' -f4 || true)"
  if [[ -z "$VERSION" ]]; then
    warn "GitHub API не ответил — клонирую main-ветку (для приватного репо нужен GITHUB_TOKEN)"
    VERSION="main"
  fi
fi
ok "Версия: $VERSION"

# GitHub отдаёт архив исходников по адресу:
#   https://github.com/<owner>/<repo>/archive/refs/tags/<tag>.tar.gz   — для тегов
#   https://github.com/<owner>/<repo>/archive/refs/heads/<branch>.tar.gz — для веток
if [[ "$VERSION" == "main" ]]; then
  ARCHIVE_URL="https://${REPO_HOST}/${REPO_PATH}/archive/refs/heads/main.tar.gz"
else
  ARCHIVE_URL="https://${REPO_HOST}/${REPO_PATH}/archive/refs/tags/${VERSION}.tar.gz"
fi
say "${C_DIM}Скачиваю $ARCHIVE_URL${C_RESET}"
if ! curl -fsSL "${GH_AUTH[@]}" "$ARCHIVE_URL" -o "$TMP/yagura.tar.gz"; then
  die "Не удалось скачать архив. Проверь существование тега $VERSION (и GITHUB_TOKEN, если репо приватный)."
fi
tar -xzf "$TMP/yagura.tar.gz" -C "$TMP"
SRC_DIR="$(find "$TMP" -maxdepth 1 -type d -name "yagura-*" | head -n1)"
[[ -d "$SRC_DIR/tool" ]] || die "Архив не содержит tool/ директории"

# ---------- install ----------
mkdir -p "$INSTALL_DIR" /etc/yagura /var/lib/yagura /var/log/yagura
chmod 0750 /etc/yagura

# Sync new tool/ on top, removing files that disappeared in the new version.
rm -rf "$TOOL_DIR"
cp -r "$SRC_DIR/tool" "$TOOL_DIR"

# venv: create on first install, reuse on update.
if [[ ! -d "$VENV_DIR" ]]; then
  say "${C_DIM}Создаю venv в $VENV_DIR…${C_RESET}"
  python3 -m venv "$VENV_DIR"
fi

say "${C_DIM}Устанавливаю Python-зависимости…${C_RESET}"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet -e "$TOOL_DIR"
ok "Зависимости установлены"

# Wrapper /usr/local/bin/yagura
cat > "$WRAPPER" <<EOF
#!/usr/bin/env bash
exec $VENV_DIR/bin/python -m yagura "\$@"
EOF
chmod +x "$WRAPPER"
ok "yagura → $WRAPPER"

# ---------- branch: update vs fresh install ----------
if [[ -n "$EXISTING_CONFIG" ]]; then
  say
  say "${C_DIM}Обнаружен существующий конфиг ($CONFIG_PATH) — обновление, без перезапроса настроек.${C_RESET}"
  if systemctl list-unit-files yagura-watch.service >/dev/null 2>&1; then
    systemctl restart yagura-watch.service 2>/dev/null && ok "watch перезапущен с новой версией"
  fi
  say
  say "Команды: ${C_OK}yagura scan | harden | watch status | uninstall${C_RESET}"
  exit 0
fi

# Fresh install: launch wizard. Reattach stdin to /dev/tty since stdin is curl's pipe (already EOF).
say
say "${C_DIM}Свежая установка — запускаю интерактивный мастер…${C_RESET}"
say
if [[ -e /dev/tty ]]; then
  exec "$WRAPPER" </dev/tty
else
  warn "Нет доступа к /dev/tty — мастер не сможет считать ввод."
  say  "Заверши настройку вручную: ${C_OK}sudo yagura${C_RESET}"
  exit 0
fi
