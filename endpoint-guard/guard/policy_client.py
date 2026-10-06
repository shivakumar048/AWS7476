"""Optional integration with the Logical Access Control server in this repo.

For each control the guard asks the server whether the current user may
perform ``endpoint:<Control>`` (e.g. ``endpoint:Copy``) on
``endpoint:host/<hostname>``. If the answer is Allow, that restriction is
lifted for this user; otherwise it stays in force. If the server can't be
reached, the locally configured restrictions stay as they are (fail closed).
"""

from __future__ import annotations

import json
import os
import queue
import socket
import threading
import urllib.error
import urllib.request
from typing import Callable

from .config import PolicyServer
from .rules import CONTROLS, Guard


def action_name(control: str) -> str:
    return "endpoint:" + "".join(part.capitalize() for part in control.split("_"))


class PolicyClient:
    def __init__(self, server: PolicyServer, principal: str, timeout: float = 5.0):
        self.server = server
        self.principal = principal
        self.timeout = timeout
        self.resource = f"endpoint:host/{socket.gethostname()}"
        self._token: str | None = None

    def _post(self, path: str, body: dict, token: str | None = None) -> dict:
        req = urllib.request.Request(self.server.url.rstrip("/") + path, data=json.dumps(body).encode(), method="POST")
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=self.timeout) as res:
            return json.loads(res.read())

    def _login(self) -> str:
        username = os.environ.get(self.server.username_env)
        password = os.environ.get(self.server.password_env)
        if not username or not password:
            raise RuntimeError(f"set {self.server.username_env} and {self.server.password_env} for the policy server")
        return self._post("/api/login", {"username": username, "password": password})["token"]

    def _post_authed(self, path: str, body: dict) -> dict:
        if self._token is None:
            self._token = self._login()
        try:
            return self._post(path, body, self._token)
        except urllib.error.HTTPError as exc:
            if exc.code != 401:
                raise
            self._token = self._login()  # session expired
            return self._post(path, body, self._token)

    def report_events(self, events: list[dict]) -> int:
        return self._post_authed("/api/endpoint/events", {"events": events})["accepted"]

    def decisions(self) -> dict[str, bool]:
        """Return {control: user_is_allowed} for every control."""
        out = {}
        for control in CONTROLS:
            body = {"principal": self.principal, "action": action_name(control), "resource": self.resource}
            out[control] = bool(self._post_authed("/api/authorize", body).get("allowed"))
        return out


def apply_decisions(guard: Guard, configured: dict[str, bool], allowed: dict[str, bool]) -> dict[str, bool]:
    """A control is enforced if it is configured on and the user is not allowed the action."""
    effective = {c: configured[c] and not allowed.get(c, False) for c in CONTROLS}
    for control, enabled in effective.items():
        guard.set_enabled(control, enabled)
    return effective


def start_refresh(client: PolicyClient, guard: Guard, configured: dict[str, bool],
                  log: Callable[..., None], stop: threading.Event) -> threading.Thread:
    def loop():
        last = None
        while True:
            try:
                effective = apply_decisions(guard, configured, client.decisions())
                if effective != last:
                    log("policy_applied", enforced=sorted(c for c, on in effective.items() if on))
                    last = effective
            except Exception as exc:
                log("policy_error", error=str(exc))
            if stop.wait(client.server.refresh_seconds):
                return

    thread = threading.Thread(target=loop, name="policy-refresh", daemon=True)
    thread.start()
    return thread


class EventForwarder:
    """Sends violation events to the console in batches, from a background thread.

    Events are kept in memory (up to ``max_pending``) while the server is
    unreachable and retried; the local log file is always the source of truth.
    """

    def __init__(self, client: PolicyClient, interval: float = 10.0, max_pending: int = 5000):
        self.client = client
        self.interval = interval
        self._queue: queue.Queue = queue.Queue(maxsize=max_pending)
        self._pending: list[dict] = []

    def submit(self, entry: dict) -> None:
        try:
            self._queue.put_nowait(entry)
        except queue.Full:
            pass  # still in the local log file

    def flush(self) -> int:
        while True:
            try:
                self._pending.append(self._queue.get_nowait())
            except queue.Empty:
                break
        sent = 0
        while self._pending:
            batch = self._pending[:500]
            self.client.report_events(batch)
            del self._pending[:len(batch)]
            sent += len(batch)
        return sent

    def start(self, stop: threading.Event, log: Callable[..., None]) -> threading.Thread:
        def loop():
            while not stop.wait(self.interval):
                try:
                    self.flush()
                except Exception as exc:
                    log("forward_error", error=str(exc), pending=len(self._pending))
            try:
                self.flush()
            except Exception:
                pass

        thread = threading.Thread(target=loop, name="event-forwarder", daemon=True)
        thread.start()
        return thread
