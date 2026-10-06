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

    def decisions(self) -> dict[str, bool]:
        """Return {control: user_is_allowed} for every control."""
        if self._token is None:
            self._token = self._login()
        out = {}
        for control in CONTROLS:
            body = {"principal": self.principal, "action": action_name(control), "resource": self.resource}
            try:
                result = self._post("/api/authorize", body, self._token)
            except urllib.error.HTTPError as exc:
                if exc.code != 401:
                    raise
                self._token = self._login()  # session expired
                result = self._post("/api/authorize", body, self._token)
            out[control] = bool(result.get("allowed"))
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
