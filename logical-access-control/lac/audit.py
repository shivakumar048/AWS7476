"""Tamper-evident audit log.

Each entry is a JSON line containing the SHA-256 hash of the previous entry,
forming a hash chain. Editing or deleting any line breaks verification.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(entry: dict[str, Any]) -> str:
    payload = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._memory: list[dict[str, Any]] = []
        self._last_hash = GENESIS
        if self.path and self.path.exists():
            entries = self.entries()
            if entries:
                self._last_hash = entries[-1]["hash"]

    def record(self, event: str, actor: str | None, **details: Any) -> dict[str, Any]:
        with self._lock:
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": event,
                "actor": actor,
                "details": details,
                "prev_hash": self._last_hash,
            }
            entry["hash"] = _digest(entry)
            self._last_hash = entry["hash"]
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, sort_keys=True) + "\n")
            else:
                self._memory.append(entry)
            return entry

    def entries(self, limit: int | None = None, actor: str | None = None, event: str | None = None) -> list[dict[str, Any]]:
        if self.path:
            if not self.path.exists():
                rows = []
            else:
                with self.path.open(encoding="utf-8") as fh:
                    rows = [json.loads(line) for line in fh if line.strip()]
        else:
            rows = list(self._memory)
        if actor:
            rows = [r for r in rows if r.get("actor") == actor]
        if event:
            rows = [r for r in rows if r.get("event") == event]
        return rows[-limit:] if limit else rows

    def verify(self) -> tuple[bool, int | None]:
        """Return (ok, index_of_first_bad_entry)."""
        prev = GENESIS
        for i, entry in enumerate(self.entries()):
            body = {k: v for k, v in entry.items() if k != "hash"}
            if entry.get("prev_hash") != prev or _digest(body) != entry.get("hash"):
                return False, i
            prev = entry["hash"]
        return True, None
