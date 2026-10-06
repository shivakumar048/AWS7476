"""Platform-independent decision logic.

The Windows layer (win32.py) translates raw hook events into calls on
``Guard``; ``Guard`` decides whether each event is blocked and reports
violations. Keeping this pure makes it testable on any OS.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable

# Windows virtual-key codes
VK_BACK = 0x08
VK_INSERT = 0x2D
VK_DELETE = 0x2E
VK_SNAPSHOT = 0x2C
VK_C, VK_D, VK_S, VK_V, VK_X = 0x43, 0x44, 0x53, 0x56, 0x58

CTRL, SHIFT, ALT, WIN = "ctrl", "shift", "alt", "win"

CONTROLS = ("copy", "cut", "paste", "delete", "drag_drop", "clipboard", "screenshot")


@dataclass(frozen=True)
class Binding:
    vk: int
    modifiers: frozenset[str]
    label: str

    def matches(self, vk: int, pressed: frozenset[str]) -> bool:
        return vk == self.vk and self.modifiers <= pressed


def _b(vk: int, label: str, *mods: str) -> Binding:
    return Binding(vk, frozenset(mods), label)


# Order matters: the first enabled control whose binding matches wins.
KEY_BINDINGS: dict[str, tuple[Binding, ...]] = {
    "copy": (_b(VK_C, "Ctrl+C", CTRL), _b(VK_INSERT, "Ctrl+Insert", CTRL)),
    "cut": (_b(VK_X, "Ctrl+X", CTRL), _b(VK_DELETE, "Shift+Delete", SHIFT)),
    "paste": (_b(VK_V, "Ctrl+V", CTRL), _b(VK_INSERT, "Shift+Insert", SHIFT), _b(VK_V, "Win+V", WIN)),
    # Ctrl+D deletes in Explorer; Shift+Delete is a permanent delete.
    "delete": (_b(VK_DELETE, "Delete"), _b(VK_D, "Ctrl+D", CTRL)),
    "screenshot": (_b(VK_SNAPSHOT, "PrintScreen"), _b(VK_S, "Win+Shift+S", WIN, SHIFT)),
}


@dataclass
class ControlSettings:
    enabled: bool = True
    exempt_processes: frozenset[str] = frozenset()


@dataclass
class Violation:
    control: str
    trigger: str
    process: str | None
    blocked: bool  # False in dry-run (monitor-only) mode


def _norm(process: str | None) -> str | None:
    if not process:
        return None
    return process.replace("\\", "/").rsplit("/", 1)[-1].lower()


class Guard:
    def __init__(
        self,
        controls: dict[str, ControlSettings],
        exempt_processes: frozenset[str] = frozenset(),
        drag_threshold: int = 4,
        dry_run: bool = False,
        on_violation: Callable[[Violation], None] | None = None,
    ):
        self._lock = threading.Lock()
        self.controls = {name: controls.get(name, ControlSettings(enabled=False)) for name in CONTROLS}
        self.exempt_processes = frozenset(p.lower() for p in exempt_processes)
        self.drag_threshold = drag_threshold
        self.dry_run = dry_run
        self.on_violation = on_violation or (lambda v: None)
        self._blocked_keys: set[int] = set()
        self._drag_origin: tuple[int, int] | None = None
        self._drag_state = "idle"  # idle | pressed | allowed | blocked

    # ------------------------------------------------------------ settings

    def set_enabled(self, control: str, enabled: bool) -> None:
        with self._lock:
            self.controls[control].enabled = enabled

    def active(self, control: str, process: str | None) -> bool:
        settings = self.controls.get(control)
        if not settings or not settings.enabled:
            return False
        name = _norm(process)
        return not (name and (name in self.exempt_processes or name in settings.exempt_processes))

    def _report(self, control: str, trigger: str, process: str | None) -> bool:
        """Record a violation; return whether the event should be swallowed."""
        self.on_violation(Violation(control, trigger, _norm(process), blocked=not self.dry_run))
        return not self.dry_run

    # ------------------------------------------------------------ keyboard

    def match_key(self, vk: int, pressed: frozenset[str]) -> tuple[str, Binding] | None:
        for control, bindings in KEY_BINDINGS.items():
            if not self.controls[control].enabled:
                continue
            for binding in bindings:
                if binding.matches(vk, pressed):
                    return control, binding
        return None

    def handle_key(self, vk: int, is_down: bool, pressed: frozenset[str], process: Callable[[], str | None]) -> bool:
        """Return True to swallow the key event."""
        if not is_down:
            # Swallow the key-up of a key whose key-down we swallowed.
            if vk in self._blocked_keys:
                self._blocked_keys.discard(vk)
                return not self.dry_run
            return False
        found = self.match_key(vk, pressed)
        if not found:
            return False
        control, binding = found
        proc = process()
        if not self.active(control, proc):
            return False
        if vk in self._blocked_keys:  # auto-repeat: block silently
            return not self.dry_run
        self._blocked_keys.add(vk)
        return self._report(control, binding.label, proc)

    # --------------------------------------------------------------- mouse

    @property
    def drag_origin(self) -> tuple[int, int] | None:
        return self._drag_origin

    def mouse_down(self, x: int, y: int) -> None:
        self._drag_origin = (x, y)
        self._drag_state = "pressed"

    def mouse_up(self) -> None:
        self._drag_origin = None
        self._drag_state = "idle"

    def mouse_move(self, x: int, y: int, process: Callable[[], str | None]) -> bool:
        """Return True to swallow the move (keeps the cursor pinned so no drag can start)."""
        if self._drag_state in ("idle", "allowed"):
            return False
        if self._drag_state == "blocked":
            return not self.dry_run
        ox, oy = self._drag_origin  # type: ignore[misc]
        if abs(x - ox) <= self.drag_threshold and abs(y - oy) <= self.drag_threshold:
            return False
        proc = process()
        if not self.active("drag_drop", proc):
            self._drag_state = "allowed"
            return False
        self._drag_state = "blocked"
        return self._report("drag_drop", "mouse drag", proc)

    # ----------------------------------------------------------- clipboard

    def clipboard_changed(self, owner_process: str | None) -> bool:
        """Return True if the clipboard contents should be wiped."""
        if not self.active("clipboard", owner_process):
            return False
        return self._report("clipboard", "clipboard write", owner_process)
