"""AccessControlService: the single entry point for all logical access control.

Features
  * Identities (users) with attributes/tags, groups and roles (RBAC)
  * IAM-style JSON policies with conditions (ABAC: IP, time, MFA, tags...)
  * Explicit-deny precedence, least privilege by default (implicit deny)
  * Password policy, PBKDF2 hashing, account lockout, session tokens with TTL
  * Separation-of-duties (SoD) rules that block conflicting role assignments
  * Access reviews (effective permissions) and a hash-chained audit trail
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from .audit import AuditLog
from .endpoint import EndpointEventStore
from .auth import PasswordPolicy, SessionManager, hash_password, verify_password
from .policy import Decision, Policy, PolicyError, evaluate
from .store import Store


class AccessControlError(Exception):
    """Base error; ``status`` maps onto an HTTP status code."""

    status = 400


class NotFound(AccessControlError):
    status = 404


class Conflict(AccessControlError):
    status = 409


class AuthenticationFailed(AccessControlError):
    status = 401


class AccessDenied(AccessControlError):
    status = 403


class AccessControlService:
    def __init__(
        self,
        store: Store | None = None,
        audit: AuditLog | None = None,
        password_policy: PasswordPolicy | None = None,
        session_ttl: int = 3600,
        max_failed_logins: int = 5,
        lockout_seconds: int = 900,
        endpoint_events: EndpointEventStore | None = None,
    ):
        self.store = store or Store()
        self.audit = audit or AuditLog()
        self.endpoint_events = endpoint_events or EndpointEventStore()
        self.password_policy = password_policy or PasswordPolicy()
        self.sessions = SessionManager(session_ttl)
        self.max_failed_logins = max_failed_logins
        self.lockout_seconds = lockout_seconds

    # ------------------------------------------------------------------ helpers

    def _require(self, collection: str, name: str) -> dict[str, Any]:
        item = self.store.data[collection].get(name)
        if item is None:
            raise NotFound(f"{collection[:-1]} {name!r} not found")
        return item

    def _commit(self, event: str, actor: str | None, **details: Any) -> None:
        self.store.save()
        self.audit.record(event, actor, **details)

    # ---------------------------------------------------------------- policies

    def create_policy(self, name: str, document: dict[str, Any], description: str = "", actor: str | None = None) -> dict[str, Any]:
        with self.store.lock:
            if name in self.store.policies:
                raise Conflict(f"policy {name!r} already exists")
            try:
                policy = Policy.from_dict(name, document, description)
            except (PolicyError, AttributeError, TypeError) as exc:
                raise AccessControlError(f"invalid policy: {exc}") from exc
            self.store.policies[name] = {"description": description, "document": policy.to_document()}
            self._commit("policy.create", actor, policy=name)
            return self.store.policies[name]

    def update_policy(self, name: str, document: dict[str, Any], actor: str | None = None) -> dict[str, Any]:
        with self.store.lock:
            entry = self._require("policies", name)
            try:
                policy = Policy.from_dict(name, document)
            except (PolicyError, AttributeError, TypeError) as exc:
                raise AccessControlError(f"invalid policy: {exc}") from exc
            entry["document"] = policy.to_document()
            self._commit("policy.update", actor, policy=name)
            return entry

    def delete_policy(self, name: str, actor: str | None = None) -> None:
        with self.store.lock:
            self._require("policies", name)
            for collection in ("users", "groups", "roles"):
                for item in self.store.data[collection].values():
                    if name in item.get("policies", []):
                        item["policies"].remove(name)
            del self.store.policies[name]
            self._commit("policy.delete", actor, policy=name)

    def _load_policy(self, name: str) -> Policy | None:
        entry = self.store.policies.get(name)
        if entry is None:
            return None
        return Policy.from_dict(name, entry["document"], entry.get("description", ""))

    # ------------------------------------------------------------------- users

    def create_user(
        self,
        username: str,
        password: str,
        tags: dict[str, str] | None = None,
        groups: list[str] | None = None,
        actor: str | None = None,
    ) -> dict[str, Any]:
        with self.store.lock:
            if not username or not username.replace("-", "").replace("_", "").replace(".", "").isalnum():
                raise AccessControlError("username may contain letters, digits, '.', '-' and '_' only")
            if username in self.store.users:
                raise Conflict(f"user {username!r} already exists")
            problems = self.password_policy.violations(password)
            if problems:
                raise AccessControlError("password " + "; ".join(problems))
            for g in groups or []:
                self._require("groups", g)
            self.store.users[username] = {
                "password_hash": hash_password(password),
                "tags": dict(tags or {}),
                "groups": list(groups or []),
                "roles": [],
                "policies": [],
                "disabled": False,
                "mfa_enabled": False,
                "failed_logins": 0,
                "locked_until": 0,
                "created": datetime.now(timezone.utc).isoformat(),
                "last_login": None,
            }
            self._commit("user.create", actor, user=username, groups=groups or [])
            return self.describe_user(username)

    def describe_user(self, username: str) -> dict[str, Any]:
        user = self._require("users", username)
        info = {k: v for k, v in user.items() if k != "password_hash"}
        info["username"] = username
        info["locked"] = user["locked_until"] > time.time()
        return info

    def list_users(self) -> list[dict[str, Any]]:
        return [self.describe_user(u) for u in sorted(self.store.users)]

    def delete_user(self, username: str, actor: str | None = None) -> None:
        with self.store.lock:
            self._require("users", username)
            del self.store.users[username]
            self.sessions.revoke_user(username)
            self._commit("user.delete", actor, user=username)

    def set_user_disabled(self, username: str, disabled: bool, actor: str | None = None) -> dict[str, Any]:
        with self.store.lock:
            user = self._require("users", username)
            user["disabled"] = disabled
            if disabled:
                self.sessions.revoke_user(username)
            self._commit("user.disable" if disabled else "user.enable", actor, user=username)
            return self.describe_user(username)

    def unlock_user(self, username: str, actor: str | None = None) -> dict[str, Any]:
        with self.store.lock:
            user = self._require("users", username)
            user["failed_logins"] = 0
            user["locked_until"] = 0
            self._commit("user.unlock", actor, user=username)
            return self.describe_user(username)

    def set_password(self, username: str, new_password: str, actor: str | None = None) -> None:
        with self.store.lock:
            user = self._require("users", username)
            problems = self.password_policy.violations(new_password)
            if problems:
                raise AccessControlError("password " + "; ".join(problems))
            user["password_hash"] = hash_password(new_password)
            self.sessions.revoke_user(username)
            self._commit("user.password_change", actor, user=username)

    def set_user_tags(self, username: str, tags: dict[str, str], actor: str | None = None) -> dict[str, Any]:
        with self.store.lock:
            user = self._require("users", username)
            user["tags"].update(tags)
            self._commit("user.tag", actor, user=username, tags=tags)
            return self.describe_user(username)

    def set_mfa(self, username: str, enabled: bool, actor: str | None = None) -> dict[str, Any]:
        with self.store.lock:
            user = self._require("users", username)
            user["mfa_enabled"] = enabled
            self._commit("user.mfa", actor, user=username, enabled=enabled)
            return self.describe_user(username)

    # ------------------------------------------------------------ groups/roles

    def create_group(self, name: str, policies: list[str] | None = None, actor: str | None = None) -> dict[str, Any]:
        return self._create_principal("groups", name, policies, actor)

    def create_role(self, name: str, policies: list[str] | None = None, description: str = "", actor: str | None = None) -> dict[str, Any]:
        return self._create_principal("roles", name, policies, actor, description=description)

    def _create_principal(self, collection: str, name: str, policies: list[str] | None, actor: str | None, **extra: Any) -> dict[str, Any]:
        with self.store.lock:
            if name in self.store.data[collection]:
                raise Conflict(f"{collection[:-1]} {name!r} already exists")
            for p in policies or []:
                self._require("policies", p)
            self.store.data[collection][name] = {"policies": list(policies or []), **extra}
            self._commit(f"{collection[:-1]}.create", actor, name=name, policies=policies or [])
            return self.store.data[collection][name]

    def delete_group(self, name: str, actor: str | None = None) -> None:
        with self.store.lock:
            self._require("groups", name)
            for user in self.store.users.values():
                if name in user["groups"]:
                    user["groups"].remove(name)
            del self.store.groups[name]
            self._commit("group.delete", actor, name=name)

    def delete_role(self, name: str, actor: str | None = None) -> None:
        with self.store.lock:
            self._require("roles", name)
            for user in self.store.users.values():
                if name in user["roles"]:
                    user["roles"].remove(name)
            del self.store.roles[name]
            self._commit("role.delete", actor, name=name)

    def add_user_to_group(self, username: str, group: str, actor: str | None = None) -> None:
        with self.store.lock:
            user = self._require("users", username)
            self._require("groups", group)
            if group not in user["groups"]:
                user["groups"].append(group)
            self._commit("group.add_member", actor, user=username, group=group)

    def remove_user_from_group(self, username: str, group: str, actor: str | None = None) -> None:
        with self.store.lock:
            user = self._require("users", username)
            if group in user["groups"]:
                user["groups"].remove(group)
            self._commit("group.remove_member", actor, user=username, group=group)

    def assign_role(self, username: str, role: str, actor: str | None = None) -> None:
        with self.store.lock:
            user = self._require("users", username)
            self._require("roles", role)
            if role in user["roles"]:
                return
            conflict = self._sod_conflict(user["roles"], role)
            if conflict:
                self.audit.record("role.assign_blocked", actor, user=username, role=role, rule=conflict["name"])
                raise Conflict(f"separation of duties rule {conflict['name']!r} forbids holding {role!r} with {conflict['held']!r}")
            user["roles"].append(role)
            self._commit("role.assign", actor, user=username, role=role)

    def revoke_role(self, username: str, role: str, actor: str | None = None) -> None:
        with self.store.lock:
            user = self._require("users", username)
            if role in user["roles"]:
                user["roles"].remove(role)
            self._commit("role.revoke", actor, user=username, role=role)

    def attach_policy(self, kind: str, name: str, policy: str, actor: str | None = None) -> None:
        collection = self._collection_for(kind)
        with self.store.lock:
            target = self._require(collection, name)
            self._require("policies", policy)
            if policy not in target["policies"]:
                target["policies"].append(policy)
            self._commit("policy.attach", actor, target_type=kind, target=name, policy=policy)

    def detach_policy(self, kind: str, name: str, policy: str, actor: str | None = None) -> None:
        collection = self._collection_for(kind)
        with self.store.lock:
            target = self._require(collection, name)
            if policy in target["policies"]:
                target["policies"].remove(policy)
            self._commit("policy.detach", actor, target_type=kind, target=name, policy=policy)

    @staticmethod
    def _collection_for(kind: str) -> str:
        mapping = {"user": "users", "group": "groups", "role": "roles"}
        if kind not in mapping:
            raise AccessControlError("target type must be user, group or role")
        return mapping[kind]

    # -------------------------------------------------- separation of duties

    def add_sod_rule(self, name: str, roles: list[str], actor: str | None = None) -> dict[str, Any]:
        """Users may hold at most one role from ``roles``."""
        with self.store.lock:
            if len(roles) < 2:
                raise AccessControlError("an SoD rule needs at least two roles")
            if any(r["name"] == name for r in self.store.sod_rules):
                raise Conflict(f"SoD rule {name!r} already exists")
            rule = {"name": name, "roles": list(roles)}
            self.store.sod_rules.append(rule)
            self._commit("sod.create", actor, rule=name, roles=roles)
            return rule

    def _sod_conflict(self, held: list[str], new_role: str) -> dict[str, Any] | None:
        for rule in self.store.sod_rules:
            if new_role in rule["roles"]:
                clash = [r for r in held if r in rule["roles"] and r != new_role]
                if clash:
                    return {"name": rule["name"], "held": clash[0]}
        return None

    def sod_violations(self) -> list[dict[str, Any]]:
        """Report existing users violating SoD rules (e.g. rules added after assignment)."""
        out = []
        for username, user in sorted(self.store.users.items()):
            for rule in self.store.sod_rules:
                held = [r for r in user["roles"] if r in rule["roles"]]
                if len(held) > 1:
                    out.append({"user": username, "rule": rule["name"], "roles": held})
        return out

    # --------------------------------------------------------- authentication

    def authenticate(self, username: str, password: str, source_ip: str | None = None) -> str:
        with self.store.lock:
            user = self.store.users.get(username)
            now = time.time()
            if user is None:
                # Burn comparable CPU time to avoid user enumeration via timing.
                verify_password(password, hash_password("dummy-password"))
                self.audit.record("auth.failure", username, reason="unknown user", ip=source_ip)
                raise AuthenticationFailed("invalid credentials")
            if user["disabled"]:
                self.audit.record("auth.failure", username, reason="disabled", ip=source_ip)
                raise AuthenticationFailed("invalid credentials")
            if user["locked_until"] > now:
                self.audit.record("auth.failure", username, reason="locked", ip=source_ip)
                raise AuthenticationFailed("account locked; try again later")
            if not verify_password(password, user["password_hash"]):
                user["failed_logins"] += 1
                details: dict[str, Any] = {"reason": "bad password", "ip": source_ip, "attempts": user["failed_logins"]}
                if user["failed_logins"] >= self.max_failed_logins:
                    user["locked_until"] = now + self.lockout_seconds
                    details["locked"] = True
                self.store.save()
                self.audit.record("auth.failure", username, **details)
                raise AuthenticationFailed("invalid credentials")
            user["failed_logins"] = 0
            user["locked_until"] = 0
            user["last_login"] = datetime.now(timezone.utc).isoformat()
            session = self.sessions.create(username, source_ip)
            self._commit("auth.success", username, ip=source_ip)
            return session.token

    def resolve_token(self, token: str) -> str:
        session = self.sessions.get(token)
        if session is None:
            raise AuthenticationFailed("invalid or expired session")
        user = self.store.users.get(session.username)
        if user is None or user["disabled"]:
            self.sessions.revoke(token)
            raise AuthenticationFailed("invalid or expired session")
        return session.username

    def logout(self, token: str) -> None:
        session = self.sessions.get(token)
        if session and self.sessions.revoke(token):
            self.audit.record("auth.logout", session.username)

    # ---------------------------------------------------------- authorization

    def effective_policies(self, username: str) -> list[tuple[str, Policy]]:
        """Return (source, policy) pairs, e.g. ('group:admins', <Policy>)."""
        user = self._require("users", username)
        sources: list[tuple[str, str]] = [("user", p) for p in user["policies"]]
        for g in user["groups"]:
            sources += [(f"group:{g}", p) for p in self.store.groups.get(g, {}).get("policies", [])]
        for r in user["roles"]:
            sources += [(f"role:{r}", p) for p in self.store.roles.get(r, {}).get("policies", [])]
        out, seen = [], set()
        for source, name in sources:
            if name in seen:
                continue
            policy = self._load_policy(name)
            if policy:
                seen.add(name)
                out.append((source, policy))
        return out

    def build_context(self, username: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        user = self._require("users", username)
        now = datetime.now(timezone.utc)
        ctx: dict[str, Any] = {
            "user:name": username,
            "user:mfa": str(user["mfa_enabled"]).lower(),
            "request:time": now.isoformat(),
            "request:timeofday": now.strftime("%H:%M:%S"),
            "request:weekday": now.strftime("%a"),
        }
        for g in user["groups"]:
            ctx[f"user:group/{g}"] = "true"
        for k, v in user["tags"].items():
            ctx[f"user:tag/{k}"] = v
        # Caller-supplied request attributes may not spoof identity attributes.
        for k, v in (context or {}).items():
            if not k.startswith("user:"):
                ctx[k] = v
        return ctx

    def authorize(self, username: str, action: str, resource: str, context: dict[str, Any] | None = None, audit: bool = True) -> Decision:
        user = self.store.users.get(username)
        if user is None:
            decision = Decision(False, "unknown principal")
        elif user["disabled"]:
            decision = Decision(False, "principal disabled")
        else:
            ctx = self.build_context(username, context)
            decision = evaluate([p for _, p in self.effective_policies(username)], action, resource, ctx)
        if audit:
            self.audit.record(
                "authz.decision", username,
                action=action, resource=resource, allowed=decision.allowed,
                reason=decision.reason, policy=decision.matched_policy,
            )
        return decision

    def enforce(self, username: str, action: str, resource: str, context: dict[str, Any] | None = None) -> Decision:
        decision = self.authorize(username, action, resource, context)
        if not decision.allowed:
            raise AccessDenied(f"{username} is not authorized to perform {action} on {resource} ({decision.reason})")
        return decision

    # ------------------------------------------------------------ access review

    def access_review(self, username: str) -> dict[str, Any]:
        user = self.describe_user(username)
        return {
            "user": username,
            "disabled": user["disabled"],
            "mfa_enabled": user["mfa_enabled"],
            "last_login": user["last_login"],
            "groups": user["groups"],
            "roles": user["roles"],
            "policies": [
                {"source": source, "policy": p.name, "document": p.to_document()}
                for source, p in self.effective_policies(username)
            ],
            "sod_violations": [v for v in self.sod_violations() if v["user"] == username],
        }
