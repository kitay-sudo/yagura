"""Splash-screen ASCII tower."""

TOWER = r"""
        /\
       /  \
      /____\
     |  __  |
     | |  | |
     | |__| |     YAGURA
     |  __  |     ───────
     | |  | |     櫓 — watchtower
     | |__| |
     |______|
    /        \
   /__________\
"""


def splash(version: str) -> str:
    return f"{TOWER}\n  v{version} — security audit + behavioral watchdog\n"
