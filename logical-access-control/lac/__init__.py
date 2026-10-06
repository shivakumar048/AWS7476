"""Logical Access Control (LAC): identity, policy-based authorization and audit."""

from .audit import AuditLog
from .auth import PasswordPolicy
from .policy import Decision, Policy, PolicyError, evaluate
from .service import (
    AccessControlError,
    AccessControlService,
    AccessDenied,
    AuthenticationFailed,
    Conflict,
    NotFound,
)
from .store import Store

__all__ = [
    "AccessControlError",
    "AccessControlService",
    "AccessDenied",
    "AuditLog",
    "AuthenticationFailed",
    "Conflict",
    "Decision",
    "NotFound",
    "PasswordPolicy",
    "Policy",
    "PolicyError",
    "Store",
    "evaluate",
]

__version__ = "1.0.0"
