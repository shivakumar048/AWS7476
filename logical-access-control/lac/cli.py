"""Command line interface: ``python -m lac <command>``."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any

from .api import create_server
from .audit import AuditLog
from .service import AccessControlError, AccessControlService
from .store import Store

ADMIN_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Sid": "FullAccess", "Effect": "Allow", "Action": "*", "Resource": "*"}],
}


def open_service(data_dir: str) -> AccessControlService:
    base = Path(data_dir)
    return AccessControlService(store=Store(base / "state.json"), audit=AuditLog(base / "audit.jsonl"))


def _print(obj: Any) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _read_password(args: argparse.Namespace, prompt: str = "Password: ") -> str:
    if getattr(args, "password", None):
        return args.password
    env = os.environ.get("LAC_PASSWORD")
    if env:
        return env
    first = getpass.getpass(prompt)
    if getpass.getpass("Confirm: ") != first:
        raise AccessControlError("passwords do not match")
    return first


def load_seed(svc: AccessControlService, path: str, actor: str = "cli") -> dict[str, int]:
    """Idempotently load policies, groups, roles and SoD rules from a JSON file."""
    with open(path, encoding="utf-8") as fh:
        seed = json.load(fh)
    counts = {"policies": 0, "groups": 0, "roles": 0, "sod_rules": 0}
    for name, spec in seed.get("policies", {}).items():
        if name not in svc.store.policies:
            svc.create_policy(name, spec["document"], spec.get("description", ""), actor=actor)
            counts["policies"] += 1
    for name, spec in seed.get("groups", {}).items():
        if name not in svc.store.groups:
            svc.create_group(name, spec.get("policies", []), actor=actor)
            counts["groups"] += 1
    for name, spec in seed.get("roles", {}).items():
        if name not in svc.store.roles:
            svc.create_role(name, spec.get("policies", []), spec.get("description", ""), actor=actor)
            counts["roles"] += 1
    existing = {r["name"] for r in svc.store.sod_rules}
    for rule in seed.get("sod_rules", []):
        if rule["name"] not in existing:
            svc.add_sod_rule(rule["name"], rule["roles"], actor=actor)
            counts["sod_rules"] += 1
    return counts


def cmd_init(svc: AccessControlService, args: argparse.Namespace) -> None:
    if "AdministratorAccess" not in svc.store.policies:
        svc.create_policy("AdministratorAccess", ADMIN_POLICY, "Full access to everything", actor="cli")
    if "administrators" not in svc.store.groups:
        svc.create_group("administrators", ["AdministratorAccess"], actor="cli")
    if args.admin not in svc.store.users:
        svc.create_user(args.admin, _read_password(args, f"Password for {args.admin}: "), groups=["administrators"], actor="cli")
        print(f"Created administrator {args.admin!r}")
    if args.seed:
        _print({"seeded": load_seed(svc, args.seed)})
    print(f"Initialised data directory {args.data_dir}")


def cmd_serve(svc: AccessControlService, args: argparse.Namespace) -> None:
    server = create_server(svc, args.host, args.port)
    print(f"Logical Access Control listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def cmd_check(svc: AccessControlService, args: argparse.Namespace) -> None:
    context = dict(kv.split("=", 1) for kv in args.context or [])
    decision = svc.authorize(args.user, args.action, args.resource, context)
    _print(decision.to_dict())
    sys.exit(0 if decision.allowed else 2)


def cmd_user(svc: AccessControlService, args: argparse.Namespace) -> None:
    if args.user_cmd == "add":
        tags = dict(kv.split("=", 1) for kv in args.tag or [])
        _print(svc.create_user(args.username, _read_password(args), tags, args.group, actor="cli"))
    elif args.user_cmd == "list":
        for u in svc.list_users():
            flags = [f for f, on in (("disabled", u["disabled"]), ("locked", u["locked"]), ("mfa", u["mfa_enabled"])) if on]
            print(f"{u['username']:<20} groups={','.join(u['groups']) or '-':<25} roles={','.join(u['roles']) or '-':<25} {' '.join(flags)}")
    elif args.user_cmd == "show":
        _print(svc.describe_user(args.username))
    elif args.user_cmd == "delete":
        svc.delete_user(args.username, actor="cli")
    elif args.user_cmd in ("disable", "enable"):
        _print(svc.set_user_disabled(args.username, args.user_cmd == "disable", actor="cli"))
    elif args.user_cmd == "unlock":
        _print(svc.unlock_user(args.username, actor="cli"))
    elif args.user_cmd == "passwd":
        svc.set_password(args.username, _read_password(args), actor="cli")
    elif args.user_cmd == "mfa":
        _print(svc.set_mfa(args.username, args.state == "on", actor="cli"))
    elif args.user_cmd == "join":
        svc.add_user_to_group(args.username, args.group, actor="cli")
    elif args.user_cmd == "leave":
        svc.remove_user_from_group(args.username, args.group, actor="cli")
    elif args.user_cmd == "grant":
        svc.assign_role(args.username, args.role, actor="cli")
    elif args.user_cmd == "revoke":
        svc.revoke_role(args.username, args.role, actor="cli")
    elif args.user_cmd == "review":
        _print(svc.access_review(args.username))


def cmd_policy(svc: AccessControlService, args: argparse.Namespace) -> None:
    if args.policy_cmd == "add":
        with open(args.file, encoding="utf-8") as fh:
            document = json.load(fh)
        _print(svc.create_policy(args.name, document, args.description or "", actor="cli"))
    elif args.policy_cmd == "list":
        for name, p in sorted(svc.store.policies.items()):
            print(f"{name:<30} {p.get('description', '')}")
    elif args.policy_cmd == "show":
        _print(svc.store.policies.get(args.name) or {"error": "not found"})
    elif args.policy_cmd == "delete":
        svc.delete_policy(args.name, actor="cli")
    elif args.policy_cmd == "attach":
        svc.attach_policy(args.kind, args.target, args.name, actor="cli")
    elif args.policy_cmd == "detach":
        svc.detach_policy(args.kind, args.target, args.name, actor="cli")


def cmd_group(svc: AccessControlService, args: argparse.Namespace) -> None:
    if args.group_cmd == "add":
        _print(svc.create_group(args.name, args.policy, actor="cli"))
    elif args.group_cmd == "list":
        _print(svc.store.groups)
    elif args.group_cmd == "delete":
        svc.delete_group(args.name, actor="cli")


def cmd_role(svc: AccessControlService, args: argparse.Namespace) -> None:
    if args.role_cmd == "add":
        _print(svc.create_role(args.name, args.policy, args.description or "", actor="cli"))
    elif args.role_cmd == "list":
        _print(svc.store.roles)
    elif args.role_cmd == "delete":
        svc.delete_role(args.name, actor="cli")


def cmd_sod(svc: AccessControlService, args: argparse.Namespace) -> None:
    if args.sod_cmd == "add":
        _print(svc.add_sod_rule(args.name, args.roles, actor="cli"))
    elif args.sod_cmd == "list":
        _print(svc.store.sod_rules)
    elif args.sod_cmd == "violations":
        _print(svc.sod_violations())


def cmd_audit(svc: AccessControlService, args: argparse.Namespace) -> None:
    if args.audit_cmd == "list":
        for e in svc.audit.entries(limit=args.limit, actor=args.actor, event=args.event):
            print(f"{e['timestamp']}  {e['event']:<22} {str(e['actor']):<15} {json.dumps(e['details'])}")
    elif args.audit_cmd == "verify":
        ok, bad = svc.audit.verify()
        print("audit log intact" if ok else f"audit log TAMPERED at entry {bad}")
        sys.exit(0 if ok else 1)


def cmd_seed(svc: AccessControlService, args: argparse.Namespace) -> None:
    _print({"seeded": load_seed(svc, args.file)})


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="lac", description="Logical Access Control system")
    p.add_argument("--data-dir", default=os.environ.get("LAC_DATA_DIR", "data"), help="state directory (default: ./data)")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("init", help="bootstrap an administrator and optional seed data")
    s.add_argument("--admin", default="admin")
    s.add_argument("--password", help="admin password (or set LAC_PASSWORD / prompt)")
    s.add_argument("--seed", help="JSON file with policies/groups/roles/sod_rules")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("serve", help="run the REST API and web console")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("check", help="evaluate an access request (exit 0=allow, 2=deny)")
    s.add_argument("user")
    s.add_argument("action")
    s.add_argument("resource")
    s.add_argument("-c", "--context", action="append", metavar="KEY=VALUE", help="request attribute, e.g. request:ip=10.0.0.5")
    s.set_defaults(func=cmd_check)

    s = sub.add_parser("seed", help="load policies/groups/roles/sod rules from JSON")
    s.add_argument("file")
    s.set_defaults(func=cmd_seed)

    user_parser = sub.add_parser("user", help="manage users")
    user_parser.set_defaults(func=cmd_user)
    u = user_parser.add_subparsers(dest="user_cmd", required=True)
    x = u.add_parser("add")
    x.add_argument("username")
    x.add_argument("--password")
    x.add_argument("--group", action="append")
    x.add_argument("--tag", action="append", metavar="KEY=VALUE")
    u.add_parser("list")
    for name in ("show", "delete", "disable", "enable", "unlock", "review"):
        u.add_parser(name).add_argument("username")
    x = u.add_parser("passwd")
    x.add_argument("username")
    x.add_argument("--password")
    x = u.add_parser("mfa")
    x.add_argument("username")
    x.add_argument("state", choices=["on", "off"])
    for name in ("join", "leave"):
        x = u.add_parser(name)
        x.add_argument("username")
        x.add_argument("group")
    for name in ("grant", "revoke"):
        x = u.add_parser(name)
        x.add_argument("username")
        x.add_argument("role")

    policy_parser = sub.add_parser("policy", help="manage policies")
    policy_parser.set_defaults(func=cmd_policy)
    pol = policy_parser.add_subparsers(dest="policy_cmd", required=True)
    x = pol.add_parser("add")
    x.add_argument("name")
    x.add_argument("file", help="JSON policy document")
    x.add_argument("--description")
    pol.add_parser("list")
    pol.add_parser("show").add_argument("name")
    pol.add_parser("delete").add_argument("name")
    for name in ("attach", "detach"):
        x = pol.add_parser(name)
        x.add_argument("name", help="policy name")
        x.add_argument("kind", choices=["user", "group", "role"])
        x.add_argument("target")

    for kind, fn in (("group", cmd_group), ("role", cmd_role)):
        g = sub.add_parser(kind, help=f"manage {kind}s")
        gs = g.add_subparsers(dest=f"{kind}_cmd", required=True)
        x = gs.add_parser("add")
        x.add_argument("name")
        x.add_argument("--policy", action="append")
        if kind == "role":
            x.add_argument("--description")
        gs.add_parser("list")
        gs.add_parser("delete").add_argument("name")
        g.set_defaults(func=fn)

    sod = sub.add_parser("sod", help="separation-of-duties rules")
    ss = sod.add_subparsers(dest="sod_cmd", required=True)
    x = ss.add_parser("add")
    x.add_argument("name")
    x.add_argument("roles", nargs="+")
    ss.add_parser("list")
    ss.add_parser("violations")
    sod.set_defaults(func=cmd_sod)

    a = sub.add_parser("audit", help="inspect the audit trail")
    asub = a.add_subparsers(dest="audit_cmd", required=True)
    x = asub.add_parser("list")
    x.add_argument("--limit", type=int, default=50)
    x.add_argument("--actor")
    x.add_argument("--event")
    asub.add_parser("verify")
    a.set_defaults(func=cmd_audit)
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    svc = open_service(args.data_dir)
    try:
        args.func(svc, args)
    except AccessControlError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
