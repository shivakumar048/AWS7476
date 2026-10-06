"""Authentication controls: password hashing, password policy, lockout, sessions."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time
from dataclasses import dataclass

PBKDF2_ITERATIONS = 200_000


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, iterations, salt_hex, hash_hex = encoded.split("$")
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations))
    return hmac.compare_digest(dk.hex(), hash_hex)


@dataclass
class PasswordPolicy:
    min_length: int = 12
    require_upper: bool = True
    require_lower: bool = True
    require_digit: bool = True
    require_symbol: bool = True

    def violations(self, password: str) -> list[str]:
        problems = []
        if len(password) < self.min_length:
            problems.append(f"must be at least {self.min_length} characters")
        if self.require_upper and not re.search(r"[A-Z]", password):
            problems.append("must contain an uppercase letter")
        if self.require_lower and not re.search(r"[a-z]", password):
            problems.append("must contain a lowercase letter")
        if self.require_digit and not re.search(r"\d", password):
            problems.append("must contain a digit")
        if self.require_symbol and not re.search(r"[^A-Za-z0-9]", password):
            problems.append("must contain a symbol")
        return problems


@dataclass
class Session:
    token: str
    username: str
    created: float
    expires: float
    source_ip: str | None = None


class SessionManager:
    def __init__(self, ttl_seconds: int = 3600):
        self.ttl = ttl_seconds
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def create(self, username: str, source_ip: str | None = None) -> Session:
        now = time.time()
        session = Session(secrets.token_urlsafe(32), username, now, now + self.ttl, source_ip)
        with self._lock:
            self._sessions[session.token] = session
        return session

    def get(self, token: str) -> Session | None:
        with self._lock:
            session = self._sessions.get(token)
            if session and session.expires < time.time():
                del self._sessions[token]
                return None
            return session

    def revoke(self, token: str) -> bool:
        with self._lock:
            return self._sessions.pop(token, None) is not None

    def revoke_user(self, username: str) -> int:
        with self._lock:
            tokens = [t for t, s in self._sessions.items() if s.username == username]
            for t in tokens:
                del self._sessions[t]
            return len(tokens)
