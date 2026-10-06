"""Delete protection for folders via NTFS ACLs.

Keyboard blocking stops the Delete key, but files can still be deleted
from right-click menus, scripts or the command line. A deny ACE for
*Everyone* on DELETE and DELETE_CHILD closes that gap at the file-system
level (it also prevents renaming or moving the files out). Files can still
be opened and edited. Requires an elevated (administrator) prompt.
"""

from __future__ import annotations

import subprocess

EVERYONE_SID = "*S-1-1-0"


def protect_command(path: str) -> list[str]:
    # (OI)(CI): inherit to files and sub-folders; DE: delete; DC: delete child
    return ["icacls", path, "/deny", f"{EVERYONE_SID}:(OI)(CI)(DE,DC)"]


def unprotect_command(path: str) -> list[str]:
    return ["icacls", path, "/remove:d", EVERYONE_SID]


def run(commands: list[list[str]]) -> int:
    failures = 0
    for cmd in commands:
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(" ".join(cmd))
        print((result.stdout or result.stderr).strip())
        failures += result.returncode != 0
    return failures
