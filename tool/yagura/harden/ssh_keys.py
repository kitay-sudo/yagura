"""Generate ed25519 keypair and append the public key to root's authorized_keys."""

from __future__ import annotations

from pathlib import Path

from yagura.harden.base import ApplyResult, HardenAction


class GenerateSSHKey(HardenAction):
    id = "ssh.generate_key"
    title = "Generate ed25519 SSH key for root + add to authorized_keys"
    severity = "LOW"

    key_path = Path("/root/.ssh/yagura_ed25519")

    def preview(self) -> list[str]:
        return [
            f"ssh-keygen -t ed25519 -N '' -f {self.key_path} -C yagura@$(hostname)",
            f"mkdir -p /root/.ssh && cat {self.key_path}.pub >> /root/.ssh/authorized_keys",
            "chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys",
        ]

    def apply(self) -> ApplyResult:
        if self.key_path.exists():
            return ApplyResult(True, f"key already exists: {self.key_path}", rollback_cmd="")
        self.key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        rc, _, err = self._run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(self.key_path), "-C", "yagura"]
        )
        if rc != 0:
            return ApplyResult(False, f"ssh-keygen failed: {err}")
        pub = self.key_path.with_suffix(".pub").read_text(encoding="utf-8").strip()
        ak = Path("/root/.ssh/authorized_keys")
        ak.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        existing = ak.read_text(encoding="utf-8") if ak.exists() else ""
        if pub not in existing:
            with open(ak, "a", encoding="utf-8") as f:
                f.write(("\n" if existing and not existing.endswith("\n") else "") + pub + "\n")
        ak.chmod(0o600)
        rollback = (
            f"sed -i '/yagura/d' /root/.ssh/authorized_keys && "
            f"rm -f {self.key_path} {self.key_path}.pub"
        )
        return ApplyResult(
            True,
            f"key generated: {self.key_path} (pub appended to authorized_keys)",
            rollback_cmd=rollback,
        )
