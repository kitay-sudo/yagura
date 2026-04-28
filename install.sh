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
      sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "Неизвестный флаг: $arg" >&2; exit 1 ;;
  esac
done

# ---------- coloring ----------
if [[ -t 1 ]]; then
  C_OK=$'\e[32m'; C_WARN=$'\e[33m'; C_ERR=$'\e[31m'; C_DIM=$'\e[2m'
  C_BOLD=$'\e[1m'; C_CYAN=$'\e[36m'; C_RESET=$'\e[0m'
else
  C_OK=""; C_WARN=""; C_ERR=""; C_DIM=""; C_BOLD=""; C_CYAN=""; C_RESET=""
fi

# ---------- structured output (compact + timings) ----------
START_TS=$SECONDS

# mm:ss since script start
_ts() {
  local elapsed=$((SECONDS - START_TS))
  printf "%02d:%02d" $((elapsed / 60)) $((elapsed % 60))
}

say()  { printf "%s\n" "$*"; }

# step → in-progress action (arrow)
step() { printf "  %s%s%s  %s→%s  %s\n" "$C_DIM" "$(_ts)" "$C_RESET" "$C_CYAN" "$C_RESET" "$*"; }

# ok → completed action (check)
ok()   { printf "  %s%s%s  %s✓%s  %s\n" "$C_DIM" "$(_ts)" "$C_RESET" "$C_OK" "$C_RESET" "$*"; }

# info → neutral note (i)
info() { printf "  %s%s%s  %sⓘ%s  %s\n" "$C_DIM" "$(_ts)" "$C_RESET" "$C_DIM" "$C_RESET" "$*"; }

warn() { printf "  %s%s%s  %s⚠%s  %s\n" "$C_DIM" "$(_ts)" "$C_RESET" "$C_WARN" "$C_RESET" "$*" >&2; }
err()  { printf "  %s%s%s  %s✗%s  %s\n" "$C_DIM" "$(_ts)" "$C_RESET" "$C_ERR" "$C_RESET" "$*" >&2; }
die()  { err "$*"; exit 1; }

# header
header() {
  local version="$1"
  printf "\n%s▶ yagura installer%s · %s%s%s · %slinux%s\n\n" \
    "$C_BOLD" "$C_RESET" "$C_CYAN" "$version" "$C_RESET" "$C_CYAN" "$C_RESET"
}

# footer (fresh install / update success)
footer() {
  local elapsed=$((SECONDS - START_TS))
  printf "\n  %sinstalled in %ds%s\n\n" "$C_DIM" "$elapsed" "$C_RESET"
  printf "  %snext:%s  yagura scan          %s# audit конфигурации%s\n" "$C_BOLD" "$C_RESET" "$C_DIM" "$C_RESET"
  printf "         yagura harden        %s# применить рекомендации%s\n" "$C_DIM" "$C_RESET"
  printf "         yagura watch status  %s# статус watchdog%s\n" "$C_DIM" "$C_RESET"
  printf "         yagura --help        %s# все команды%s\n\n" "$C_DIM" "$C_RESET"
  printf "  %s─────────────────────────────────────────%s\n" "$C_DIM" "$C_RESET"
  printf "  %sauthor%s    kitay-sudo\n" "$C_DIM" "$C_RESET"
  printf "  %sgithub%s    github.com/kitay-sudo/yagura\n" "$C_DIM" "$C_RESET"
  printf "  %stelegram%s  t.me/kitay9\n\n" "$C_DIM" "$C_RESET"
}

# ---------- preflight ----------
[[ "$EUID" -eq 0 ]] || die "Запусти от root: curl ... | sudo bash"

OS="$(uname -s)"
[[ "$OS" == "Linux" ]] || die "Поддерживается только Linux (сейчас: $OS)"

command -v curl >/dev/null 2>&1 || die "curl не найден (sudo apt install curl / sudo dnf install curl)"

# ---------- distro detection ----------
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

# ---------- uninstall path ----------
if [[ "$MODE" == "uninstall" ]]; then
  printf "\n%s▶ yagura uninstaller%s\n\n" "$C_BOLD" "$C_RESET"
  if [[ -x "$WRAPPER" ]]; then
    step "yagura uninstall (откат harden + удаление systemd-юнита)"
    "$WRAPPER" uninstall || warn "uninstall завершился с ошибками — продолжаю"
    ok "tool uninstall завершён"
  fi
  step "очистка systemd"
  systemctl stop yagura-watch.service 2>/dev/null || true
  systemctl disable yagura-watch.service 2>/dev/null || true
  rm -f /etc/systemd/system/yagura-watch.service
  systemctl daemon-reload 2>/dev/null || true
  ok "systemd очищен"

  step "удаление файлов"
  rm -rf "$INSTALL_DIR" /etc/yagura /var/lib/yagura
  rm -f "$WRAPPER"
  ok "Yagura удалён (логи в /var/log/yagura оставлены)"

  printf "\n  %s─────────────────────────────────────────%s\n" "$C_DIM" "$C_RESET"
  printf "  %sauthor%s    kitay-sudo\n" "$C_DIM" "$C_RESET"
  printf "  %sgithub%s    github.com/kitay-sudo/yagura\n" "$C_DIM" "$C_RESET"
  printf "  %stelegram%s  t.me/kitay9\n\n" "$C_DIM" "$C_RESET"
  exit 0
fi

# ---------- detect existing install ----------
EXISTING_TOOL=""
EXISTING_CONFIG=""
[[ -d "$TOOL_DIR" ]] && EXISTING_TOOL="yes"
[[ -f "$CONFIG_PATH" ]] && EXISTING_CONFIG="yes"

# ---------- version selection ----------
GH_AUTH=()
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  GH_AUTH=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
fi

VERSION="${YAGURA_VERSION:-}"
if [[ -z "$VERSION" ]]; then
  printf "\n%s▶ yagura installer%s · %slinux%s\n\n" "$C_BOLD" "$C_RESET" "$C_CYAN" "$C_RESET"
  step "определение последней версии"
  VERSION="$(curl -fsSL "${GH_AUTH[@]}" "https://api.${REPO_HOST}/repos/${REPO_PATH}/releases/latest" \
    | grep -oE '"tag_name":\s*"[^"]+"' | head -n1 | cut -d'"' -f4 || true)"
  if [[ -z "$VERSION" ]]; then
    warn "не удалось определить последний релиз — fallback на main (для приватного репо нужен GITHUB_TOKEN)"
    VERSION="main"
  fi
  ok "версия: $VERSION"
else
  header "$VERSION"
  ok "версия (закреплена): $VERSION"
fi

# ---------- reinstall path ----------
if [[ "$MODE" == "reinstall" && -n "$EXISTING_TOOL" ]]; then
  warn "режим --reinstall: сношу текущую установку (конфиг и данные будут утеряны)"
  if [[ -x "$WRAPPER" ]]; then
    "$WRAPPER" uninstall || true
  fi
  rm -rf "$INSTALL_DIR" /etc/yagura /var/lib/yagura
  rm -f "$WRAPPER"
  EXISTING_TOOL=""
  EXISTING_CONFIG=""
fi

# ---------- ensure Python 3.10+ + venv pkg ----------
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

# Detects whether `python3 -m venv` actually works. On Debian/Ubuntu this is a
# separate package (e.g. python3.12-venv) — having `python3` alone is not enough.
ensurepip_ok() {
  python3 -c 'import ensurepip' >/dev/null 2>&1
}

# Returns the right venv package name for the running python version (Debian-family only).
debian_venv_pkg() {
  local ver
  ver="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
  echo "python${ver}-venv"
}

if need_python; then
  step "установка python3 + pip + venv"
  case "$DISTRO_ID" in
    ubuntu|debian|kali|linuxmint) pm_install python3 python3-venv python3-pip ;;
    centos|rhel|rocky|almalinux|fedora) pm_install python3 python3-pip ;;
    arch|manjaro) pm_install python python-pip ;;
    *) die "Поставь python3.10+ вручную и перезапусти install.sh" ;;
  esac
  ok "python: $(python3 --version)"
else
  ok "python: $(python3 --version) (уже установлен)"
fi

# Even if python3 is present, venv-пакет может отсутствовать на Debian/Ubuntu.
if ! ensurepip_ok; then
  case "$DISTRO_ID" in
    ubuntu|debian|kali|linuxmint)
      local_pkg="$(debian_venv_pkg)"
      step "установка $local_pkg (нужен для python -m venv)"
      pm_install "$local_pkg" python3-pip
      ok "$local_pkg установлен"
      ;;
    centos|rhel|rocky|almalinux|fedora)
      step "установка python3-pip"
      pm_install python3-pip
      ok "python3-pip установлен"
      ;;
    *)
      die "python -m venv не работает (нет ensurepip). Установи venv-пакет вручную и перезапусти."
      ;;
  esac
fi

# ---------- download ----------
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if [[ "$VERSION" == "main" ]]; then
  ARCHIVE_URL="https://${REPO_HOST}/${REPO_PATH}/archive/refs/heads/main.tar.gz"
else
  ARCHIVE_URL="https://${REPO_HOST}/${REPO_PATH}/archive/refs/tags/${VERSION}.tar.gz"
fi

step "загрузка yagura-${VERSION}.tar.gz"
if ! curl -fsSL "${GH_AUTH[@]}" "$ARCHIVE_URL" -o "$TMP/yagura.tar.gz"; then
  die "не удалось скачать архив. проверь, что тег $VERSION существует (и GITHUB_TOKEN, если репо приватный)"
fi
tar -xzf "$TMP/yagura.tar.gz" -C "$TMP"
SRC_DIR="$(find "$TMP" -maxdepth 1 -type d -name "yagura-*" | head -n1)"
[[ -d "$SRC_DIR/tool" ]] || die "архив не содержит tool/ директории"
ok "скачано и распаковано"

# ---------- install ----------
step "установка в $INSTALL_DIR"
mkdir -p "$INSTALL_DIR" /etc/yagura /var/lib/yagura /var/log/yagura
chmod 0750 /etc/yagura

# Sync new tool/ on top, removing files that disappeared in the new version.
rm -rf "$TOOL_DIR"
cp -r "$SRC_DIR/tool" "$TOOL_DIR"
ok "tool/ синхронизирован"

# venv: create on first install, reuse on update.
if [[ ! -d "$VENV_DIR" ]]; then
  step "создание venv в $VENV_DIR"
  python3 -m venv "$VENV_DIR"
  ok "venv создан"
fi

step "установка Python-зависимостей"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet -e "$TOOL_DIR"
ok "зависимости установлены"

# Wrapper /usr/local/bin/yagura
cat > "$WRAPPER" <<EOF
#!/usr/bin/env bash
exec $VENV_DIR/bin/python -m yagura "\$@"
EOF
chmod +x "$WRAPPER"
ok "$WRAPPER зарегистрирован"

# ---------- branch: update vs fresh install ----------
if [[ -n "$EXISTING_CONFIG" ]]; then
  info "конфиг найден ($CONFIG_PATH) — wizard пропущен"
  if systemctl list-unit-files yagura-watch.service >/dev/null 2>&1; then
    step "перезапуск yagura-watch.service"
    systemctl restart yagura-watch.service 2>/dev/null && ok "yagura-watch.service active"
  fi
  footer
  exit 0
fi

# Fresh install: launch wizard. Reattach stdin to /dev/tty since stdin is curl's pipe (already EOF).
info "свежая установка — запускаю интерактивный мастер"
say
if [[ -e /dev/tty ]]; then
  exec "$WRAPPER" </dev/tty
else
  warn "нет доступа к /dev/tty — мастер не сможет считать ввод"
  say  "  Заверши настройку вручную:  ${C_BOLD}sudo yagura${C_RESET}"
  exit 0
fi
