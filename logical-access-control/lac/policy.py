"""IAM-style policy documents and the evaluation engine.

Evaluation logic (same precedence as AWS IAM):
  1. An explicit Deny in any applicable statement wins.
  2. Otherwise, an explicit Allow grants access.
  3. Otherwise, access is implicitly denied.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, time, timezone
from fnmatch import fnmatchcase
from typing import Any

ALLOW = "Allow"
DENY = "Deny"


class PolicyError(ValueError):
    """Raised when a policy document is malformed."""


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _match(pattern: str, value: str) -> bool:
    return fnmatchcase(value, pattern)


def _glob_escape(value: str) -> str:
    return re.sub(r"([*?\[])", r"[\1]", value)


def _substitute(pattern: str, context: dict[str, Any], escape: bool = False) -> str:
    """Replace ${var} placeholders (e.g. ${user:name}) with context values.

    With ``escape`` the substituted values are made glob-literal, so a value
    such as ``*`` cannot widen a wildcard pattern.
    """
    if "${" not in pattern:
        return pattern
    out = pattern
    for key, val in context.items():
        val = str(val)
        out = out.replace("${" + key + "}", _glob_escape(val) if escape else val)
    return out


# --------------------------------------------------------------------------
# Condition operators
# --------------------------------------------------------------------------

def _to_number(v: Any) -> float:
    return float(v)


def _to_datetime(v: Any) -> datetime:
    if isinstance(v, datetime):
        dt = v
    else:
        dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _to_time(v: Any) -> time:
    if isinstance(v, time):
        return v
    if isinstance(v, datetime):
        return v.time()
    return time.fromisoformat(str(v))


def _ip_in(actual: Any, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _time_between(actual: Any, window: str) -> bool:
    """window like '09:00-17:00'; supports overnight windows ('22:00-06:00')."""
    start_s, end_s = window.split("-", 1)
    start, end, now = _to_time(start_s), _to_time(end_s), _to_time(actual)
    if start <= end:
        return start <= now <= end
    return now >= start or now <= end


_OPERATORS = {
    "StringEquals": lambda a, e: str(a) == str(e),
    "StringNotEquals": lambda a, e: str(a) != str(e),
    "StringEqualsIgnoreCase": lambda a, e: str(a).lower() == str(e).lower(),
    "StringLike": lambda a, e: fnmatchcase(str(a), str(e)),
    "StringNotLike": lambda a, e: not fnmatchcase(str(a), str(e)),
    "NumericEquals": lambda a, e: _to_number(a) == _to_number(e),
    "NumericLessThan": lambda a, e: _to_number(a) < _to_number(e),
    "NumericLessThanEquals": lambda a, e: _to_number(a) <= _to_number(e),
    "NumericGreaterThan": lambda a, e: _to_number(a) > _to_number(e),
    "NumericGreaterThanEquals": lambda a, e: _to_number(a) >= _to_number(e),
    "DateLessThan": lambda a, e: _to_datetime(a) < _to_datetime(e),
    "DateGreaterThan": lambda a, e: _to_datetime(a) > _to_datetime(e),
    "Bool": lambda a, e: str(a).lower() == str(e).lower(),
    "IpAddress": _ip_in,
    "NotIpAddress": lambda a, e: not _ip_in(a, e),
    "TimeOfDayBetween": _time_between,
}

# Operators whose semantics are "none of the values match" rather than "any".
_NEGATED = {"StringNotEquals", "StringNotLike", "NotIpAddress"}


def _evaluate_conditions(conditions: dict[str, dict[str, Any]], context: dict[str, Any]) -> bool:
    """All operators must pass (AND); within a key, any expected value may match (OR)."""
    for op_name, checks in conditions.items():
        if_exists = op_name.endswith("IfExists")
        base_op = op_name[: -len("IfExists")] if if_exists else op_name
        op = _OPERATORS[base_op]
        for key, expected in checks.items():
            if key not in context:
                # As in IAM: a missing key fails positive operators but
                # satisfies negated ones ("not in range" is vacuously true).
                if if_exists or base_op in _NEGATED:
                    continue
                return False
            actual = context[key]
            like = base_op in ("StringLike", "StringNotLike")
            values = [_substitute(v, context, escape=like) if isinstance(v, str) else v for v in _as_list(expected)]
            try:
                if base_op in _NEGATED:
                    ok = all(op(actual, v) for v in values)
                else:
                    ok = any(op(actual, v) for v in values)
            except (TypeError, ValueError):
                ok = False
            if not ok:
                return False
    return True


# --------------------------------------------------------------------------
# Policy model
# --------------------------------------------------------------------------

@dataclass
class Statement:
    effect: str
    actions: list[str]
    resources: list[str]
    sid: str = ""
    not_actions: list[str] = field(default_factory=list)
    conditions: dict[str, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Statement":
        effect = data.get("Effect")
        if effect not in (ALLOW, DENY):
            raise PolicyError(f"Statement Effect must be Allow or Deny, got {effect!r}")
        actions = _as_list(data.get("Action"))
        not_actions = _as_list(data.get("NotAction"))
        if not actions and not not_actions:
            raise PolicyError("Statement needs Action or NotAction")
        resources = _as_list(data.get("Resource", "*"))
        conditions = data.get("Condition", {}) or {}
        for op in conditions:
            base = op[: -len("IfExists")] if op.endswith("IfExists") else op
            if base not in _OPERATORS:
                raise PolicyError(f"Unknown condition operator {op!r}")
        return cls(
            effect=effect,
            actions=[a.lower() for a in actions],
            not_actions=[a.lower() for a in not_actions],
            resources=resources,
            sid=data.get("Sid", ""),
            conditions=conditions,
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"Effect": self.effect, "Resource": self.resources}
        if self.sid:
            out["Sid"] = self.sid
        if self.actions:
            out["Action"] = self.actions
        if self.not_actions:
            out["NotAction"] = self.not_actions
        if self.conditions:
            out["Condition"] = self.conditions
        return out

    def applies(self, action: str, resource: str, context: dict[str, Any]) -> bool:
        action = action.lower()
        if self.actions:
            if not any(_match(p, action) for p in self.actions):
                return False
        elif any(_match(p, action) for p in self.not_actions):
            return False
        if not any(_match(_substitute(r, context, escape=True), resource) for r in self.resources):
            return False
        return _evaluate_conditions(self.conditions, context)


@dataclass
class Policy:
    name: str
    statements: list[Statement]
    description: str = ""

    @classmethod
    def from_dict(cls, name: str, document: dict[str, Any], description: str = "") -> "Policy":
        raw = _as_list(document.get("Statement"))
        if not raw:
            raise PolicyError(f"Policy {name!r} has no statements")
        return cls(name=name, statements=[Statement.from_dict(s) for s in raw], description=description)

    def to_document(self) -> dict[str, Any]:
        return {"Version": "2012-10-17", "Statement": [s.to_dict() for s in self.statements]}


@dataclass
class Decision:
    allowed: bool
    reason: str
    matched_policy: str | None = None
    matched_sid: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "decision": ALLOW if self.allowed else DENY,
            "reason": self.reason,
            "matched_policy": self.matched_policy,
            "matched_sid": self.matched_sid,
        }


def evaluate(policies: list[Policy], action: str, resource: str, context: dict[str, Any] | None = None) -> Decision:
    context = context or {}
    allow_match: tuple[Policy, Statement] | None = None
    for policy in policies:
        for stmt in policy.statements:
            if not stmt.applies(action, resource, context):
                continue
            if stmt.effect == DENY:
                return Decision(False, "explicit deny", policy.name, stmt.sid or None)
            if allow_match is None:
                allow_match = (policy, stmt)
    if allow_match:
        policy, stmt = allow_match
        return Decision(True, "explicit allow", policy.name, stmt.sid or None)
    return Decision(False, "implicit deny (no matching allow)")
