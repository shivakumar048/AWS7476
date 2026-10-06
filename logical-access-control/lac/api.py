"""REST API built on the standard library's http.server.

Every management operation is itself authorized through the policy engine,
using actions in the ``lac:`` namespace (e.g. ``lac:CreateUser``) against
resources such as ``lac:user/alice``. The ``POST /authorize`` endpoint lets
other systems use this service as their Policy Decision Point.
"""

from __future__ import annotations

import json
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from .service import AccessControlError, AccessControlService, AccessDenied, AuthenticationFailed

STATIC_DIR = Path(__file__).parent / "static"
MAX_BODY = 1 << 20

Route = tuple[str, re.Pattern, Callable[..., Any], bool]


class Router:
    def __init__(self) -> None:
        self.routes: list[Route] = []

    def add(self, method: str, pattern: str, auth: bool = True):
        regex = re.compile("^" + re.sub(r"<(\w+)>", r"(?P<\1>[^/]+)", pattern) + "$")

        def deco(fn):
            self.routes.append((method, regex, fn, auth))
            return fn

        return deco

    def match(self, method: str, path: str):
        path_exists = False
        for m, regex, fn, auth in self.routes:
            found = regex.match(path)
            if found:
                path_exists = True
                if m == method:
                    return fn, found.groupdict(), auth
        return None, None, path_exists


def build_router(svc: AccessControlService) -> Router:
    r = Router()

    def guard(ctx, action: str, resource: str) -> None:
        svc.enforce(ctx["user"], action, resource, ctx["request"])

    # ---------------------------------------------------------------- session
    @r.add("POST", "/api/login", auth=False)
    def login(ctx, body, query):
        token = svc.authenticate(body.get("username", ""), body.get("password", ""), ctx["request"]["request:ip"])
        return {"token": token, "expires_in": svc.sessions.ttl}

    @r.add("POST", "/api/logout")
    def logout(ctx, body, query):
        svc.logout(ctx["token"])
        return {"ok": True}

    @r.add("GET", "/api/me")
    def me(ctx, body, query):
        return svc.access_review(ctx["user"])

    @r.add("GET", "/api/health", auth=False)
    def health(ctx, body, query):
        return {"status": "ok"}

    # ------------------------------------------------------- decision point
    @r.add("POST", "/api/authorize")
    def authorize(ctx, body, query):
        principal = body.get("principal") or ctx["user"]
        if principal != ctx["user"]:
            guard(ctx, "lac:SimulatePrincipalPolicy", f"lac:user/{principal}")
        action, resource = body.get("action"), body.get("resource")
        if not action or not resource:
            raise AccessControlError("action and resource are required")
        context = dict(body.get("context") or {})
        context.setdefault("request:ip", ctx["request"]["request:ip"])
        return svc.authorize(principal, action, resource, context).to_dict()

    # ------------------------------------------------------------------ users
    @r.add("GET", "/api/users")
    def list_users(ctx, body, query):
        guard(ctx, "lac:ListUsers", "lac:user/*")
        return svc.list_users()

    @r.add("POST", "/api/users")
    def create_user(ctx, body, query):
        name = body.get("username", "")
        guard(ctx, "lac:CreateUser", f"lac:user/{name}")
        return svc.create_user(name, body.get("password", ""), body.get("tags"), body.get("groups"), actor=ctx["user"])

    @r.add("GET", "/api/users/<name>")
    def get_user(ctx, body, query, name):
        if name != ctx["user"]:
            guard(ctx, "lac:GetUser", f"lac:user/{name}")
        return svc.describe_user(name)

    @r.add("DELETE", "/api/users/<name>")
    def delete_user(ctx, body, query, name):
        guard(ctx, "lac:DeleteUser", f"lac:user/{name}")
        svc.delete_user(name, actor=ctx["user"])
        return {"ok": True}

    @r.add("POST", "/api/users/<name>/disable")
    def disable_user(ctx, body, query, name):
        guard(ctx, "lac:DisableUser", f"lac:user/{name}")
        return svc.set_user_disabled(name, True, actor=ctx["user"])

    @r.add("POST", "/api/users/<name>/enable")
    def enable_user(ctx, body, query, name):
        guard(ctx, "lac:EnableUser", f"lac:user/{name}")
        return svc.set_user_disabled(name, False, actor=ctx["user"])

    @r.add("POST", "/api/users/<name>/unlock")
    def unlock_user(ctx, body, query, name):
        guard(ctx, "lac:UnlockUser", f"lac:user/{name}")
        return svc.unlock_user(name, actor=ctx["user"])

    @r.add("POST", "/api/users/<name>/password")
    def change_password(ctx, body, query, name):
        guard(ctx, "lac:ChangePassword", f"lac:user/{name}")
        svc.set_password(name, body.get("password", ""), actor=ctx["user"])
        return {"ok": True}

    @r.add("POST", "/api/users/<name>/tags")
    def tag_user(ctx, body, query, name):
        guard(ctx, "lac:TagUser", f"lac:user/{name}")
        return svc.set_user_tags(name, body.get("tags") or {}, actor=ctx["user"])

    @r.add("POST", "/api/users/<name>/mfa")
    def mfa_user(ctx, body, query, name):
        guard(ctx, "lac:SetMFA", f"lac:user/{name}")
        return svc.set_mfa(name, bool(body.get("enabled")), actor=ctx["user"])

    @r.add("POST", "/api/users/<name>/groups")
    def add_to_group(ctx, body, query, name):
        group = body.get("group", "")
        guard(ctx, "lac:AddUserToGroup", f"lac:group/{group}")
        svc.add_user_to_group(name, group, actor=ctx["user"])
        return svc.describe_user(name)

    @r.add("DELETE", "/api/users/<name>/groups/<group>")
    def remove_from_group(ctx, body, query, name, group):
        guard(ctx, "lac:RemoveUserFromGroup", f"lac:group/{group}")
        svc.remove_user_from_group(name, group, actor=ctx["user"])
        return svc.describe_user(name)

    @r.add("POST", "/api/users/<name>/roles")
    def assign_role(ctx, body, query, name):
        role = body.get("role", "")
        guard(ctx, "lac:AssignRole", f"lac:role/{role}")
        svc.assign_role(name, role, actor=ctx["user"])
        return svc.describe_user(name)

    @r.add("DELETE", "/api/users/<name>/roles/<role>")
    def revoke_role(ctx, body, query, name, role):
        guard(ctx, "lac:RevokeRole", f"lac:role/{role}")
        svc.revoke_role(name, role, actor=ctx["user"])
        return svc.describe_user(name)

    @r.add("GET", "/api/users/<name>/access-review")
    def access_review(ctx, body, query, name):
        guard(ctx, "lac:ReviewAccess", f"lac:user/{name}")
        return svc.access_review(name)

    # -------------------------------------------- policy attachments (all)
    for kind in ("user", "group", "role"):
        def make(kind):
            @r.add("POST", f"/api/{kind}s/<name>/policies")
            def attach(ctx, body, query, name):
                policy = body.get("policy", "")
                guard(ctx, "lac:AttachPolicy", f"lac:{kind}/{name}")
                svc.attach_policy(kind, name, policy, actor=ctx["user"])
                return {"ok": True}

            @r.add("DELETE", f"/api/{kind}s/<name>/policies/<policy>")
            def detach(ctx, body, query, name, policy):
                guard(ctx, "lac:DetachPolicy", f"lac:{kind}/{name}")
                svc.detach_policy(kind, name, policy, actor=ctx["user"])
                return {"ok": True}

        make(kind)

    # ------------------------------------------------------- groups & roles
    for kind in ("group", "role"):
        def make_crud(kind):
            cap = kind.capitalize()

            @r.add("GET", f"/api/{kind}s")
            def list_(ctx, body, query):
                guard(ctx, f"lac:List{cap}s", f"lac:{kind}/*")
                return svc.store.data[f"{kind}s"]

            @r.add("POST", f"/api/{kind}s")
            def create(ctx, body, query):
                name = body.get("name", "")
                guard(ctx, f"lac:Create{cap}", f"lac:{kind}/{name}")
                if kind == "role":
                    return svc.create_role(name, body.get("policies"), body.get("description", ""), actor=ctx["user"])
                return svc.create_group(name, body.get("policies"), actor=ctx["user"])

            @r.add("DELETE", f"/api/{kind}s/<name>")
            def delete(ctx, body, query, name):
                guard(ctx, f"lac:Delete{cap}", f"lac:{kind}/{name}")
                getattr(svc, f"delete_{kind}")(name, actor=ctx["user"])
                return {"ok": True}

        make_crud(kind)

    # --------------------------------------------------------------- policies
    @r.add("GET", "/api/policies")
    def list_policies(ctx, body, query):
        guard(ctx, "lac:ListPolicies", "lac:policy/*")
        return svc.store.policies

    @r.add("POST", "/api/policies")
    def create_policy(ctx, body, query):
        name = body.get("name", "")
        guard(ctx, "lac:CreatePolicy", f"lac:policy/{name}")
        return svc.create_policy(name, body.get("document") or {}, body.get("description", ""), actor=ctx["user"])

    @r.add("PUT", "/api/policies/<name>")
    def update_policy(ctx, body, query, name):
        guard(ctx, "lac:UpdatePolicy", f"lac:policy/{name}")
        return svc.update_policy(name, body.get("document") or {}, actor=ctx["user"])

    @r.add("DELETE", "/api/policies/<name>")
    def delete_policy(ctx, body, query, name):
        guard(ctx, "lac:DeletePolicy", f"lac:policy/{name}")
        svc.delete_policy(name, actor=ctx["user"])
        return {"ok": True}

    # ---------------------------------------------------- separation of duty
    @r.add("GET", "/api/sod-rules")
    def list_sod(ctx, body, query):
        guard(ctx, "lac:ListSoDRules", "lac:sod/*")
        return svc.store.sod_rules

    @r.add("POST", "/api/sod-rules")
    def create_sod(ctx, body, query):
        name = body.get("name", "")
        guard(ctx, "lac:CreateSoDRule", f"lac:sod/{name}")
        return svc.add_sod_rule(name, body.get("roles") or [], actor=ctx["user"])

    @r.add("GET", "/api/sod-violations")
    def sod_violations(ctx, body, query):
        guard(ctx, "lac:ListSoDRules", "lac:sod/*")
        return svc.sod_violations()

    # ------------------------------------------------------------------ audit
    @r.add("GET", "/api/audit")
    def audit(ctx, body, query):
        guard(ctx, "lac:ReadAuditLog", "lac:audit")
        limit = int(query.get("limit", ["100"])[0])
        return svc.audit.entries(limit=limit, actor=query.get("actor", [None])[0], event=query.get("event", [None])[0])

    @r.add("GET", "/api/audit/verify")
    def audit_verify(ctx, body, query):
        guard(ctx, "lac:ReadAuditLog", "lac:audit")
        ok, bad = svc.audit.verify()
        return {"intact": ok, "first_bad_entry": bad}

    return r


def make_handler(svc: AccessControlService, router: Router):
    class Handler(BaseHTTPRequestHandler):
        server_version = "LogicalAccessControl/1.0"

        def log_message(self, fmt, *args):  # quieter default logging
            pass

        def _send(self, status: int, payload: Any, content_type: str = "application/json") -> None:
            data = payload if isinstance(payload, bytes) else json.dumps(payload, indent=2, default=str).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _handle(self, method: str) -> None:
            parsed = urlparse(self.path)
            if method == "GET" and parsed.path in ("/", "/index.html"):
                index = STATIC_DIR / "index.html"
                return self._send(200, index.read_bytes(), "text/html; charset=utf-8")
            fn, params, auth = router.match(method, parsed.path)
            if fn is None:
                status = HTTPStatus.METHOD_NOT_ALLOWED if auth else HTTPStatus.NOT_FOUND
                return self._send(status, {"error": status.phrase})
            try:
                length = int(self.headers.get("Content-Length") or 0)
                if length > MAX_BODY:
                    return self._send(413, {"error": "request body too large"})
                raw = self.rfile.read(length) if length else b""
                body = json.loads(raw) if raw else {}
                if not isinstance(body, dict):
                    raise AccessControlError("request body must be a JSON object")
                ctx: dict[str, Any] = {"request": {"request:ip": self.client_address[0], "request:secure": "false"}}
                if auth:
                    header = self.headers.get("Authorization", "")
                    if not header.startswith("Bearer "):
                        raise AuthenticationFailed("missing bearer token")
                    ctx["token"] = header[7:]
                    ctx["user"] = svc.resolve_token(ctx["token"])
                result = fn(ctx, body, parse_qs(parsed.query), **params)
                self._send(200, result)
            except json.JSONDecodeError:
                self._send(400, {"error": "invalid JSON"})
            except AccessDenied as exc:
                self._send(403, {"error": str(exc)})
            except AccessControlError as exc:
                self._send(exc.status, {"error": str(exc)})
            except Exception as exc:  # pragma: no cover - defensive
                self._send(500, {"error": f"internal error: {type(exc).__name__}"})

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

        def do_PUT(self):
            self._handle("PUT")

        def do_DELETE(self):
            self._handle("DELETE")

    return Handler


def create_server(svc: AccessControlService, host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), make_handler(svc, build_router(svc)))
