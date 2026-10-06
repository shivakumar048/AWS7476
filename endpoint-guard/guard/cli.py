"""Command line: ``python -m guard <command>``."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
import threading

from . import config as config_mod
from . import protect
from .eventlog import EventLog
from .policy_client import EventForwarder, PolicyClient, start_refresh
from .rules import CONTROLS, KEY_BINDINGS, Guard


def build_guard(cfg: config_mod.Config, log: EventLog) -> Guard:
    return Guard(
        controls=cfg.controls,
        exempt_processes=cfg.exempt_processes,
        drag_threshold=cfg.drag_threshold,
        dry_run=cfg.dry_run,
        on_violation=log.violation,
    )


def cmd_run(args: argparse.Namespace) -> int:
    cfg = config_mod.load(args.config)
    if args.dry_run:
        cfg.dry_run = True
    user = getpass.getuser()
    log = EventLog(cfg.log_file, user, echo=not args.quiet)
    if user.lower() in cfg.exempt_users:
        log.write("exempt_user", detail="user is exempt; no restrictions applied")
        return 0
    if sys.platform != "win32":
        print("error: enforcement requires Windows (use 'check' or 'status' to test a config elsewhere)", file=sys.stderr)
        return 1
    from .win32 import WindowsEnforcer

    guard = build_guard(cfg, log)
    stop = threading.Event()
    if cfg.policy_server:
        configured = {c: cfg.controls[c].enabled for c in CONTROLS}
        client = PolicyClient(cfg.policy_server, user)
        start_refresh(client, guard, configured, log.write, stop)
        if cfg.policy_server.report_events:
            forwarder = EventForwarder(PolicyClient(cfg.policy_server, user))
            log.forward = forwarder.submit
            forwarder.start(stop, log.write)
    enforced = sorted(c for c in CONTROLS if guard.controls[c].enabled)
    log.write("started", enforced=enforced, dry_run=cfg.dry_run)
    try:
        WindowsEnforcer(guard, log_error=lambda m: log.write("error", detail=m)).run(args.duration)
    finally:
        stop.set()
        log.write("stopped")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    cfg = config_mod.load(args.config)
    print(f"mode: {'monitor only (dry run)' if cfg.dry_run else 'enforce'}")
    for name in CONTROLS:
        c = cfg.controls[name]
        keys = ", ".join(b.label for b in KEY_BINDINGS.get(name, ()))
        extra = {"drag_drop": "mouse drags (left & right button)", "clipboard": "clears clipboard on any copy"}.get(name, "")
        exempt = f"  exempt: {', '.join(sorted(c.exempt_processes))}" if c.exempt_processes else ""
        print(f"  [{'ON ' if c.enabled else 'off'}] {name:<11} {keys or extra}{exempt}")
    if cfg.exempt_processes:
        print(f"exempt processes: {', '.join(sorted(cfg.exempt_processes))}")
    if cfg.exempt_users:
        print(f"exempt users: {', '.join(sorted(cfg.exempt_users))}")
    if cfg.protected_paths:
        print(f"delete-protected paths: {', '.join(cfg.protected_paths)}")
    if cfg.policy_server:
        print(f"policy server: {cfg.policy_server.url} (refresh {cfg.policy_server.refresh_seconds}s)")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Simulate a key combination, e.g. ``check ctrl+c --process notepad.exe``."""
    cfg = config_mod.load(args.config)
    names = {"c": 0x43, "d": 0x44, "s": 0x53, "v": 0x56, "x": 0x58, "insert": 0x2D, "delete": 0x2E,
             "del": 0x2E, "printscreen": 0x2C, "prtsc": 0x2C}
    parts = [p.strip().lower() for p in args.keys.split("+")]
    mods = frozenset(p for p in parts[:-1] if p in ("ctrl", "shift", "alt", "win"))
    key = parts[-1]
    vk = names.get(key) or (ord(key.upper()) if len(key) == 1 else None)
    if vk is None:
        print(f"unknown key {key!r}", file=sys.stderr)
        return 1
    hits = []
    guard = build_guard(cfg, EventLog(cfg.log_file, "check", echo=False))
    guard.on_violation = hits.append
    blocked = guard.handle_key(vk, True, mods, lambda: args.process)
    result = {"keys": args.keys, "process": args.process, "blocked": blocked or bool(hits),
              "control": hits[0].control if hits else None}
    print(json.dumps(result))
    return 0 if result["blocked"] else 2


def _paths(args: argparse.Namespace) -> list[str]:
    paths = args.paths or config_mod.load(args.config).protected_paths
    if not paths:
        raise config_mod.ConfigError("no paths given and none in protected_paths")
    return paths


def cmd_protect(args: argparse.Namespace) -> int:
    return 1 if protect.run([protect.protect_command(p) for p in _paths(args)]) else 0


def cmd_unprotect(args: argparse.Namespace) -> int:
    return 1 if protect.run([protect.unprotect_command(p) for p in _paths(args)]) else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="guard", description="Endpoint Guard: block copy/paste, delete and drag & drop")
    p.add_argument("-c", "--config", help="JSON config file (defaults apply if omitted)")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("run", help="start enforcing (Windows)")
    s.add_argument("--dry-run", action="store_true", help="log violations without blocking")
    s.add_argument("--duration", type=float, help="stop automatically after N seconds (for testing)")
    s.add_argument("--quiet", action="store_true", help="don't echo events to the console")
    s.set_defaults(func=cmd_run)

    sub.add_parser("status", help="show what the config enforces").set_defaults(func=cmd_status)

    s = sub.add_parser("check", help="simulate a key combination, e.g. ctrl+c")
    s.add_argument("keys")
    s.add_argument("--process", help="foreground process name, e.g. notepad.exe")
    s.set_defaults(func=cmd_check)

    for name, fn, text in (("protect", cmd_protect, "deny deletion in folders (admin, Windows)"),
                           ("unprotect", cmd_unprotect, "remove the deletion deny rule")):
        s = sub.add_parser(name, help=text)
        s.add_argument("paths", nargs="*", help="folders (default: protected_paths from config)")
        s.set_defaults(func=fn)
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        sys.exit(args.func(args))
    except config_mod.ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        sys.exit(1)
