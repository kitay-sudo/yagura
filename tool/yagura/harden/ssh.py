"""SSH hardening: PermitRootLogin / PasswordAuthentication / Port."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from yagura.harden.base import ApplyResult, HardenAction

SSHD_CONFIG = Path("/etc/ssh/sshd_config")


def _set_directive(path: Path, key: str, value: str) -> tuple[bool, str]:
    """In-place rewrite of a sshd_config directive. Returns (changed, prev_line_or_empty)."""
    if not path.exists():
        return False, ""
    text = path.read_text(encoding="utf-8", errors="replace")
    pattern = re.compile(rf"^[#\s]*{re.escape(key)}\b.*$", re.MULTILINE | re.IGNORECASE)
    match = pattern.search(text)
    new_line = f"{key} {value}"
    if match:
        prev = match.group(0)
        if prev == new_line:
            return False, prev
        new_text = pattern.sub(new_line, text, count=1)
    else:
        prev = ""
        new_text = text.rstrip() + f"\n{new_line}\n"
    if new_text == text:
        return False, prev
    bak = Path(f"{path}.yagura.bak")
    if not bak.exists():
        shutil.copy2(path, bak)
    path.write_text(new_text, encoding="utf-8")
    return True, prev


def _restart_sshd_cmd() -> str:
    return "systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || service ssh restart"


class DisableRoot(HardenAction):
    id = "ssh.disable_root"
    title = "SSH: PermitRootLogin no"
    severity = "CRITICAL"

    def preview(self) -> list[str]:
        return [
            f"sed -i 's/^[#[:space:]]*PermitRootLogin.*/PermitRootLogin no/i' {SSHD_CONFIG}",
            _restart_sshd_cmd(),
        ]

    def apply(self) -> ApplyResult:
        if not SSHD_CONFIG.exists():
            return ApplyResult(False, f"{SSHD_CONFIG} not found")
        try:
            changed, prev = _set_directive(SSHD_CONFIG, "PermitRootLogin", "no")
        except (OSError, PermissionError) as e:
            return ApplyResult(False, f"write failed: {e}")
        rc, _, err = self._run(["bash", "-c", _restart_sshd_cmd()])
        msg = "PermitRootLogin set to no, sshd restarted"
        if rc != 0:
            msg = f"config changed but restart failed: {err}"
        rollback = f"sed -i 's/^PermitRootLogin no/{prev or 'PermitRootLogin yes'}/' {SSHD_CONFIG} && {_restart_sshd_cmd()}"
        return ApplyResult(rc == 0, msg, rollback_cmd=rollback)


class DisablePasswordAuth(HardenAction):
    id = "ssh.disable_password_auth"
    title = "SSH: PasswordAuthentication no"
    severity = "HIGH"

    def preview(self) -> list[str]:
        return [
            f"sed -i 's/^[#[:space:]]*PasswordAuthentication.*/PasswordAuthentication no/i' {SSHD_CONFIG}",
            _restart_sshd_cmd(),
        ]

    def apply(self) -> ApplyResult:
        if not SSHD_CONFIG.exists():
            return ApplyResult(False, f"{SSHD_CONFIG} not found")
        try:
            _changed, prev = _set_directive(SSHD_CONFIG, "PasswordAuthentication", "no")
        except (OSError, PermissionError) as e:
            return ApplyResult(False, f"write failed: {e}")
        rc, _, err = self._run(["bash", "-c", _restart_sshd_cmd()])
        msg = "PasswordAuthentication set to no, sshd restarted"
        if rc != 0:
            msg = f"config changed but restart failed: {err}"
        rollback = f"sed -i 's/^PasswordAuthentication no/{prev or 'PasswordAuthentication yes'}/' {SSHD_CONFIG} && {_restart_sshd_cmd()}"
        return ApplyResult(rc == 0, msg, rollback_cmd=rollback)


class ChangePort(HardenAction):
    """Switch SSH from 22 to 2222 (a common-but-not-default high port)."""

    id = "ssh.change_port"
    title = "SSH: change port from 22 to 2222"
    severity = "MEDIUM"
    new_port = "2222"

    def preview(self) -> list[str]:
        return [
            f"sed -i 's/^[#[:space:]]*Port.*/Port {self.new_port}/i' {SSHD_CONFIG}",
            f"ufw allow {self.new_port}/tcp 2>/dev/null || true",
            _restart_sshd_cmd(),
        ]

    def apply(self) -> ApplyResult:
        if not SSHD_CONFIG.exists():
            return ApplyResult(False, f"{SSHD_CONFIG} not found")
        try:
            _changed, prev = _set_directive(SSHD_CONFIG, "Port", self.new_port)
        except (OSError, PermissionError) as e:
            return ApplyResult(False, f"write failed: {e}")
        if self._has("ufw"):
            self._run(["ufw", "allow", f"{self.new_port}/tcp"])
        rc, _, err = self._run(["bash", "-c", _restart_sshd_cmd()])
        old_port = "22"
        if prev:
            parts = prev.split()
            if len(parts) >= 2 and parts[0].lower() == "port":
                old_port = parts[1]
        rollback = (
            f"sed -i 's/^Port {self.new_port}/Port {old_port}/' {SSHD_CONFIG} && "
            + _restart_sshd_cmd()
        )
        msg = f"SSH now listens on {self.new_port}"
        if rc != 0:
            msg = f"config changed but restart failed: {err}"
        return ApplyResult(rc == 0, msg, rollback_cmd=rollback)


class LockEmptyPasswordUsers(HardenAction):
    id = "ssh.lock_empty_users"
    title = "Users: lock accounts with empty passwords"
    severity = "CRITICAL"

    def preview(self) -> list[str]:
        return ["for u in $(awk -F: '($2==\"\") {print $1}' /etc/shadow); do passwd -l $u; done"]

    def apply(self) -> ApplyResult:
        from yagura.collectors.users import _empty_password_users  # noqa: WPS437

        empties = _empty_password_users()
        if not empties:
            return ApplyResult(True, "No empty-password users found", rollback_cmd="")
        locked: list[str] = []
        for u in empties:
            rc, _, _ = self._run(["passwd", "-l", u])
            if rc == 0:
                locked.append(u)
        if not locked:
            return ApplyResult(False, "Failed to lock any account")
        rollback = " && ".join(f"passwd -u {u}" for u in locked)
        return ApplyResult(True, f"Locked: {', '.join(locked)}", rollback_cmd=rollback)
