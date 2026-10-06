"""JSON-file backed store for identities, groups, roles and policies."""

from __future__ import annotations

import copy
import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any

EMPTY_STATE: dict[str, Any] = {
    "users": {},
    "groups": {},
    "roles": {},
    "policies": {},
    "sod_rules": [],
}


class Store:
    """Holds state in memory and writes it atomically to disk on every change."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.lock = threading.RLock()
        self.data: dict[str, Any] = copy.deepcopy(EMPTY_STATE)
        if self.path and self.path.exists():
            with self.path.open(encoding="utf-8") as fh:
                loaded = json.load(fh)
            for key, default in EMPTY_STATE.items():
                self.data[key] = loaded.get(key, copy.deepcopy(default))

    def save(self) -> None:
        if not self.path:
            return
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".lac-", suffix=".json")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, indent=2, sort_keys=True)
            os.replace(tmp, self.path)

    @property
    def users(self) -> dict[str, Any]:
        return self.data["users"]

    @property
    def groups(self) -> dict[str, Any]:
        return self.data["groups"]

    @property
    def roles(self) -> dict[str, Any]:
        return self.data["roles"]

    @property
    def policies(self) -> dict[str, Any]:
        return self.data["policies"]

    @property
    def sod_rules(self) -> list[dict[str, Any]]:
        return self.data["sod_rules"]
