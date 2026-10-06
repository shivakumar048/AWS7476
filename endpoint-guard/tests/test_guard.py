import io
import json
import socket
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from guard import cli
from guard.config import ConfigError, PolicyServer, parse
from guard.policy_client import EventForwarder, PolicyClient, action_name, apply_decisions
from guard.protect import protect_command, unprotect_command
from guard.rules import (ALT, CONTROLS, CTRL, SHIFT, VK_C, VK_D, VK_DELETE, VK_INSERT, VK_SNAPSHOT, VK_V, VK_X, WIN,
                         ControlSettings, Guard)

ROOT = Path(__file__).resolve().parent.parent


def make_guard(dry_run=False, **overrides):
    cfg = parse({"controls": overrides, "dry_run": dry_run})
    hits = []
    g = Guard(cfg.controls, cfg.exempt_processes, cfg.drag_threshold, cfg.dry_run, hits.append)
    return g, hits


def key(g, vk, *mods, process="notepad.exe", down=True):
    return g.handle_key(vk, down, frozenset(mods), lambda: process)


class KeyboardTests(unittest.TestCase):
    def test_default_shortcuts_blocked(self):
        g, hits = make_guard()
        cases = [
            ((VK_C, CTRL), "copy"), ((VK_INSERT, CTRL), "copy"),
            ((VK_X, CTRL), "cut"), ((VK_DELETE, SHIFT), "cut"),
            ((VK_V, CTRL), "paste"), ((VK_INSERT, SHIFT), "paste"), ((VK_V, WIN), "paste"),
            ((VK_DELETE,), "delete"), ((VK_D, CTRL), "delete"),
        ]
        for (vk, *mods), control in cases:
            self.assertTrue(key(g, vk, *mods), (vk, mods))
            self.assertEqual(hits[-1].control, control)
            key(g, vk, *mods, down=False)

    def test_extra_modifiers_still_match(self):
        g, _ = make_guard()
        self.assertTrue(key(g, VK_C, CTRL, SHIFT))  # Ctrl+Shift+C copies in terminals
        key(g, VK_C, down=False)
        self.assertTrue(key(g, VK_V, CTRL, ALT))

    def test_normal_typing_allowed(self):
        g, hits = make_guard()
        self.assertFalse(key(g, VK_C))
        self.assertFalse(key(g, VK_V, SHIFT))
        self.assertFalse(key(g, VK_INSERT))
        self.assertEqual(hits, [])

    def test_screenshot_off_by_default(self):
        g, _ = make_guard()
        self.assertFalse(key(g, VK_SNAPSHOT))
        g, _ = make_guard(screenshot=True)
        self.assertTrue(key(g, VK_SNAPSHOT))

    def test_disabled_control(self):
        g, _ = make_guard(copy=False)
        self.assertFalse(key(g, VK_C, CTRL))
        self.assertTrue(key(g, VK_V, CTRL))

    def test_shift_delete_still_blocked_by_delete_when_cut_off(self):
        g, hits = make_guard(cut=False)
        self.assertTrue(key(g, VK_DELETE, SHIFT))
        self.assertEqual(hits[-1].control, "delete")

    def test_autorepeat_logged_once_and_keyup_swallowed(self):
        g, hits = make_guard()
        for _ in range(5):
            self.assertTrue(key(g, VK_C, CTRL))
        self.assertEqual(len(hits), 1)
        self.assertTrue(key(g, VK_C, down=False))
        self.assertFalse(key(g, VK_C, down=False), "only the matching key-up is swallowed")

    def test_exempt_processes(self):
        cfg = parse({"exempt_processes": ["KeePass.exe"],
                     "controls": {"delete": {"exempt_processes": ["code.exe"]}}})
        g = Guard(cfg.controls, cfg.exempt_processes)
        self.assertFalse(key(g, VK_C, CTRL, process=r"C:\Program Files\KeePass\KeePass.exe"))
        self.assertFalse(key(g, VK_DELETE, process=r"C:\VS Code\Code.exe"))
        self.assertTrue(key(g, VK_C, CTRL, process=r"C:\VS Code\Code.exe"), "exempt only for delete")

    def test_dry_run_logs_without_blocking(self):
        g, hits = make_guard(dry_run=True)
        self.assertFalse(key(g, VK_C, CTRL))
        self.assertEqual((hits[0].control, hits[0].blocked), ("copy", False))


class MouseTests(unittest.TestCase):
    def test_drag_blocked_after_threshold(self):
        g, hits = make_guard()
        g.mouse_down(100, 100)
        self.assertFalse(g.mouse_move(102, 103, lambda: "explorer.exe"), "small jitter allowed")
        self.assertTrue(g.mouse_move(120, 100, lambda: "explorer.exe"))
        self.assertTrue(g.mouse_move(200, 100, lambda: "explorer.exe"))
        self.assertEqual(len(hits), 1)
        g.mouse_up()
        self.assertFalse(g.mouse_move(300, 300, lambda: "explorer.exe"), "free movement after release")

    def test_moves_without_button_allowed(self):
        g, _ = make_guard()
        self.assertFalse(g.mouse_move(500, 500, lambda: "explorer.exe"))

    def test_drag_allowed_in_exempt_app(self):
        cfg = parse({"controls": {"drag_drop": {"exempt_processes": ["mspaint.exe"]}}})
        g = Guard(cfg.controls)
        g.mouse_down(0, 0)
        self.assertFalse(g.mouse_move(50, 50, lambda: "mspaint.exe"))
        self.assertFalse(g.mouse_move(90, 90, lambda: "mspaint.exe"))

    def test_drag_control_off(self):
        g, _ = make_guard(drag_drop=False)
        g.mouse_down(0, 0)
        self.assertFalse(g.mouse_move(50, 50, lambda: "explorer.exe"))


class ClipboardTests(unittest.TestCase):
    def test_clipboard_cleared(self):
        g, hits = make_guard()
        self.assertTrue(g.clipboard_changed("winword.exe"))
        self.assertEqual(hits[0].control, "clipboard")

    def test_clipboard_owner_exempt(self):
        cfg = parse({"controls": {"clipboard": {"exempt_processes": ["keepass.exe"]}}})
        self.assertFalse(Guard(cfg.controls).clipboard_changed("KeePass.exe"))


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        cfg = parse({})
        enabled = {c for c in CONTROLS if cfg.controls[c].enabled}
        self.assertEqual(enabled, {"copy", "cut", "paste", "delete", "drag_drop", "clipboard"})

    def test_boolean_shorthand_and_validation(self):
        self.assertFalse(parse({"controls": {"copy": False}}).controls["copy"].enabled)
        with self.assertRaises(ConfigError):
            parse({"controls": {"teleport": True}})
        with self.assertRaises(ConfigError):
            parse({"exempt_processes": "notepad.exe"})

    def test_example_config_is_valid(self):
        with open(ROOT / "config.example.json") as fh:
            cfg = parse(json.load(fh))
        self.assertIn("code.exe", cfg.controls["delete"].exempt_processes)


class CliTests(unittest.TestCase):
    def run_cli(self, *argv):
        out = io.StringIO()
        with redirect_stdout(out), self.assertRaises(SystemExit) as ctx:
            cli.main(list(argv))
        return ctx.exception.code, out.getvalue()

    def test_check_command(self):
        code, out = self.run_cli("check", "ctrl+v", "--process", "notepad.exe")
        self.assertEqual((code, json.loads(out)["control"]), (0, "paste"))
        code, _ = self.run_cli("check", "shift+a")
        self.assertEqual(code, 2)

    def test_status_command(self):
        code, out = self.run_cli("-c", str(ROOT / "config.example.json"), "status")
        self.assertEqual(code, 0)
        self.assertIn("Ctrl+C", out)

    @unittest.skipIf(sys.platform == "win32", "non-Windows behaviour")
    def test_run_refuses_off_windows(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "c.json"
            cfg.write_text(json.dumps({"log_file": str(Path(tmp) / "log.jsonl")}))
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as ctx:
                    cli.main(["-c", str(cfg), "run", "--quiet"])
            self.assertEqual(ctx.exception.code, 1)

    def test_protect_commands(self):
        self.assertEqual(protect_command(r"C:\Data"), ["icacls", r"C:\Data", "/deny", "*S-1-1-0:(OI)(CI)(DE,DC)"])
        self.assertEqual(unprotect_command(r"C:\Data"), ["icacls", r"C:\Data", "/remove:d", "*S-1-1-0"])


class PolicyServerIntegrationTests(unittest.TestCase):
    """Runs the repo's Logical Access Control server and checks per-user decisions."""

    @classmethod
    def setUpClass(cls):
        lac_dir = ROOT.parent / "logical-access-control"
        if not lac_dir.exists():
            raise unittest.SkipTest("logical-access-control not present")
        sys.path.insert(0, str(lac_dir))
        from lac import auth
        from lac.api import create_server
        from lac.cli import ADMIN_POLICY
        from lac.service import AccessControlService

        auth.PBKDF2_ITERATIONS = 1000
        svc = AccessControlService()
        svc.create_policy("Admin", ADMIN_POLICY)
        svc.create_policy("EndpointCopyPaste", {"Statement": [{
            "Effect": "Allow", "Action": ["endpoint:Copy", "endpoint:Paste", "endpoint:Clipboard"],
            "Resource": "endpoint:host/*"}]})
        svc.create_group("svc", ["Admin"])
        svc.create_group("finance", ["EndpointCopyPaste"])
        pw = "Str0ng!Passw0rd"
        svc.create_user("guard-svc", pw, groups=["svc"])
        svc.create_user("alice", pw, groups=["finance"])
        svc.create_user("bob", pw)
        cls.svc = svc
        cls.server = create_server(svc, "127.0.0.1", 0)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.env = {"LAC_USERNAME": "guard-svc", "LAC_PASSWORD": pw}

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def decisions_for(self, user):
        from unittest import mock
        with mock.patch.dict("os.environ", self.env):
            return PolicyClient(PolicyServer(self.url), user).decisions()

    def test_allowed_user_gets_copy_paste_back(self):
        g, _ = make_guard()
        configured = {c: g.controls[c].enabled for c in CONTROLS}
        effective = apply_decisions(g, configured, self.decisions_for("alice"))
        self.assertFalse(effective["copy"])
        self.assertFalse(effective["paste"])
        self.assertTrue(effective["delete"])
        self.assertFalse(key(g, VK_C, CTRL))
        self.assertTrue(key(g, VK_DELETE))

    def test_unprivileged_user_fully_restricted(self):
        self.assertFalse(any(self.decisions_for("bob").values()))

    def test_events_forwarded_to_console(self):
        from unittest import mock
        with mock.patch.dict("os.environ", self.env):
            fwd = EventForwarder(PolicyClient(PolicyServer(self.url), "bob"))
            for i in range(3):
                fwd.submit({"event": "blocked", "user": "bob", "host": "PC-1", "control": "copy", "trigger": "Ctrl+C"})
            self.assertEqual(fwd.flush(), 3)
        stored = self.svc.endpoint_events.query(user="bob")
        self.assertEqual(len(stored), 3)
        self.assertEqual(stored[0]["control"], "copy")

    def test_action_names(self):
        self.assertEqual(action_name("drag_drop"), "endpoint:DragDrop")
        self.assertEqual(socket.gethostname() in PolicyClient(PolicyServer(self.url), "x").resource, True)


if __name__ == "__main__":
    unittest.main()
