"""Map action_id → HardenAction class. The single source of truth."""

from __future__ import annotations

from yagura.harden.auditd import InstallAuditd
from yagura.harden.base import HardenAction
from yagura.harden.fail2ban import InstallFail2ban
from yagura.harden.rkhunter import InstallRkhunter
from yagura.harden.ssh import (
    ChangePort,
    DisablePasswordAuth,
    DisableRoot,
    LockEmptyPasswordUsers,
)
from yagura.harden.ssh_keys import GenerateSSHKey
from yagura.harden.sysctl import EnableASLR, HardenNetwork
from yagura.harden.ufw import IptablesDefaultDrop, UFWEnable
from yagura.harden.unattended import InstallUnattendedUpgrades

REGISTRY: dict[str, type[HardenAction]] = {
    DisableRoot.id: DisableRoot,
    DisablePasswordAuth.id: DisablePasswordAuth,
    ChangePort.id: ChangePort,
    LockEmptyPasswordUsers.id: LockEmptyPasswordUsers,
    GenerateSSHKey.id: GenerateSSHKey,
    UFWEnable.id: UFWEnable,
    IptablesDefaultDrop.id: IptablesDefaultDrop,
    InstallFail2ban.id: InstallFail2ban,
    InstallUnattendedUpgrades.id: InstallUnattendedUpgrades,
    HardenNetwork.id: HardenNetwork,
    EnableASLR.id: EnableASLR,
    InstallAuditd.id: InstallAuditd,
    InstallRkhunter.id: InstallRkhunter,
}


def get_action(action_id: str) -> HardenAction | None:
    cls = REGISTRY.get(action_id)
    if cls is None:
        return None
    return cls()


def list_actions() -> list[HardenAction]:
    return [cls() for cls in REGISTRY.values()]
