"""Append-only JSONL log of violations."""

from __future__ import annotations

import json
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .rules import Violation


class EventLog:
    def __init__(self, path: str | Path, user: str, echo: bool = True):
        self.path = Path(path)
        self.user = user
        self.host = socket.gethostname()
        self.echo = echo
        self._lock = threading.Lock()
        self.forward: Callable[[dict], None] | None = None

    def write(self, event: str, **fields) -> dict:
        entry = {"timestamp": datetime.now(timezone.utc).isoformat(), "event": event,
                 "user": self.user, "host": self.host, **fields}
        line = json.dumps(entry)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        if self.echo:
            print(line, flush=True)
        return entry

    def violation(self, v: Violation) -> None:
        entry = self.write("blocked" if v.blocked else "would_block",
                           control=v.control, trigger=v.trigger, process=v.process)
        if self.forward:
            self.forward(entry)
