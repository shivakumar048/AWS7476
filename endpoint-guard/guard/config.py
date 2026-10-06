"""Configuration loading."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .rules import CONTROLS, ControlSettings

DEFAULT_ENABLED = {
    "copy": True,
    "cut": True,
    "paste": True,
    "delete": True,
    "drag_drop": True,
    "clipboard": True,
    "screenshot": False,
}


class ConfigError(ValueError):
    pass


@dataclass
class PolicyServer:
    url: str
    username_env: str = "LAC_USERNAME"
    password_env: str = "LAC_PASSWORD"
    refresh_seconds: int = 300
    report_events: bool = True


@dataclass
class Config:
    controls: dict[str, ControlSettings]
    exempt_processes: frozenset[str] = frozenset()
    exempt_users: frozenset[str] = frozenset()
    drag_threshold: int = 4
    dry_run: bool = False
    log_file: str = "endpoint-guard.log.jsonl"
    protected_paths: list[str] = field(default_factory=list)
    policy_server: PolicyServer | None = None


def _lower_set(values: Any, where: str) -> frozenset[str]:
    if values is None:
        return frozenset()
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        raise ConfigError(f"{where} must be a list of strings")
    return frozenset(v.lower() for v in values)


def parse(data: dict[str, Any]) -> Config:
    raw_controls = data.get("controls", {})
    unknown = set(raw_controls) - set(CONTROLS)
    if unknown:
        raise ConfigError(f"unknown controls: {', '.join(sorted(unknown))} (valid: {', '.join(CONTROLS)})")
    controls = {}
    for name in CONTROLS:
        spec = raw_controls.get(name, {})
        if isinstance(spec, bool):
            spec = {"enabled": spec}
        controls[name] = ControlSettings(
            enabled=bool(spec.get("enabled", DEFAULT_ENABLED[name])),
            exempt_processes=_lower_set(spec.get("exempt_processes"), f"controls.{name}.exempt_processes"),
        )
    server = None
    if data.get("policy_server"):
        ps = data["policy_server"]
        if "url" not in ps:
            raise ConfigError("policy_server.url is required")
        server = PolicyServer(**{k: ps[k] for k in ("url", "username_env", "password_env", "refresh_seconds", "report_events") if k in ps})
    return Config(
        controls=controls,
        exempt_processes=_lower_set(data.get("exempt_processes"), "exempt_processes"),
        exempt_users=_lower_set(data.get("exempt_users"), "exempt_users"),
        drag_threshold=int(data.get("drag_threshold", 4)),
        dry_run=bool(data.get("dry_run", False)),
        log_file=data.get("log_file", "endpoint-guard.log.jsonl"),
        protected_paths=list(data.get("protected_paths", [])),
        policy_server=server,
    )


def load(path: str | Path | None) -> Config:
    if path is None:
        return parse({})
    try:
        with open(path, encoding="utf-8") as fh:
            return parse(json.load(fh))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path}: invalid JSON: {exc}") from exc
