"""Storage for events reported by Endpoint Guard agents (blocked copy/paste, etc.)."""

from __future__ import annotations

import json
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FIELDS = ("timestamp", "event", "user", "host", "control", "trigger", "process")
MAX_MEMORY = 50_000


def _clean(raw: dict[str, Any]) -> dict[str, Any]:
    entry = {k: str(raw[k])[:256] for k in FIELDS if raw.get(k) is not None}
    entry.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    entry["received"] = datetime.now(timezone.utc).isoformat()
    return entry


class EndpointEventStore:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._events: deque[dict[str, Any]] = deque(maxlen=MAX_MEMORY)
        if self.path and self.path.exists():
            with self.path.open(encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        self._events.append(json.loads(line))

    def add(self, events: list[dict[str, Any]]) -> int:
        cleaned = [_clean(e) for e in events if isinstance(e, dict)]
        with self._lock:
            self._events.extend(cleaned)
            if self.path and cleaned:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as fh:
                    for e in cleaned:
                        fh.write(json.dumps(e, sort_keys=True) + "\n")
        return len(cleaned)

    def query(self, limit: int = 200, **filters: str | None) -> list[dict[str, Any]]:
        with self._lock:
            rows = list(self._events)
        for key, value in filters.items():
            if value:
                rows = [r for r in rows if r.get(key) == value]
        return rows[-limit:] if limit else rows
