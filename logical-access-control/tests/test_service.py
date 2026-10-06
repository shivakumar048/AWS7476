import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from lac import auth
from lac.api import create_server
from lac.audit import AuditLog
from lac.cli import ADMIN_POLICY, load_seed
from lac.service import (
    AccessControlError,
    AccessControlService,
    AccessDenied,
    AuthenticationFailed,
    Conflict,
)
from lac.store import Store

SEED = Path(__file__).resolve().parent.parent / "examples" / "seed.json"
PW = "Str0ng!Passw0rd"

# Keep hashing fast in tests; production uses the default iteration count.
auth.PBKDF2_ITERATIONS = 1000


def make_service(tmp: str | None = None, **kwargs) -> AccessControlService:
    store = Store(Path(tmp) / "state.json") if tmp else Store()
    audit = AuditLog(Path(tmp) / "audit.jsonl") if tmp else AuditLog()
    svc = AccessControlService(store=store, audit=audit, **kwargs)
    svc.create_policy("AdministratorAccess", ADMIN_POLICY)
    svc.create_group("administrators", ["AdministratorAccess"])
    svc.create_user("admin", PW, groups=["administrators"])
    load_seed(svc, str(SEED))
    return svc


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.svc = make_service()

    def test_password_policy_enforced(self):
        with self.assertRaises(AccessControlError):
            self.svc.create_user("weak", "password")

    def test_duplicate_user(self):
        with self.assertRaises(Conflict):
            self.svc.create_user("admin", PW)

    def test_login_and_session(self):
        token = self.svc.authenticate("admin", PW)
        self.assertEqual(self.svc.resolve_token(token), "admin")
        self.svc.logout(token)
        with self.assertRaises(AuthenticationFailed):
            self.svc.resolve_token(token)

    def test_lockout_after_repeated_failures(self):
        self.svc.create_user("bob", PW)
        for _ in range(self.svc.max_failed_logins):
            with self.assertRaises(AuthenticationFailed):
                self.svc.authenticate("bob", "wrong")
        with self.assertRaisesRegex(AuthenticationFailed, "locked"):
            self.svc.authenticate("bob", PW)
        self.svc.unlock_user("bob")
        self.assertTrue(self.svc.authenticate("bob", PW))

    def test_disabling_user_revokes_sessions_and_access(self):
        self.svc.create_user("carol", PW, groups=["auditors"])
        token = self.svc.authenticate("carol", PW)
        self.svc.set_user_disabled("carol", True)
        with self.assertRaises(AuthenticationFailed):
            self.svc.resolve_token(token)
        self.assertFalse(self.svc.authorize("carol", "lac:ListUsers", "lac:user/*").allowed)

    def test_session_expiry(self):
        token = self.svc.authenticate("admin", PW)
        with mock.patch("lac.auth.time.time", return_value=10**12):
            with self.assertRaises(AuthenticationFailed):
                self.svc.resolve_token(token)


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.svc = make_service()
        self.svc.create_user("alice", PW, tags={"team": "platform"}, groups=["employees", "ops"])

    def check(self, action, resource, **ctx):
        ctx.setdefault("request:ip", "10.0.0.5")
        return self.svc.authorize("alice", action, resource, ctx)

    def test_abac_team_tag(self):
        res = "arn:aws:ec2:us-east-1:1:instance/i-1"
        self.assertTrue(self.check("ec2:StopInstances", res, **{"resource:tag/team": "platform"}).allowed)
        self.assertFalse(self.check("ec2:StopInstances", res, **{"resource:tag/team": "payments"}).allowed)

    def test_network_guardrail(self):
        self.assertTrue(self.check("ec2:DescribeInstances", "*").allowed)
        d = self.check("ec2:DescribeInstances", "*", **{"request:ip": "203.0.113.9"})
        self.assertFalse(d.allowed)
        self.assertEqual(d.matched_sid, "CorporateNetworkOnly")

    def test_home_folder(self):
        self.assertTrue(self.check("s3:GetObject", "arn:aws:s3:::company-data/home/alice/notes.txt").allowed)
        self.assertFalse(self.check("s3:GetObject", "arn:aws:s3:::company-data/home/bob/notes.txt").allowed)

    def test_mfa_required_for_destructive(self):
        self.svc.attach_policy("user", "alice", "AdministratorAccess")
        self.assertFalse(self.check("ec2:TerminateInstances", "*").allowed)
        self.svc.set_mfa("alice", True)
        self.assertTrue(self.check("ec2:TerminateInstances", "*").allowed)

    def test_caller_cannot_spoof_identity_attributes(self):
        d = self.check("s3:GetObject", "arn:aws:s3:::company-data/home/bob/x", **{"user:name": "bob"})
        self.assertFalse(d.allowed)

    def test_business_hours_deploy(self):
        self.svc.assign_role("alice", "deployer")
        from datetime import datetime, timezone
        for hour, expected in ((10, True), (23, False)):
            fake = datetime(2026, 1, 5, hour, 0, tzinfo=timezone.utc)
            with mock.patch("lac.service.datetime") as dt:
                dt.now.return_value = fake
                self.assertEqual(self.check("deploy:Release", "app:prod/web").allowed, expected)

    def test_enforce_raises(self):
        with self.assertRaises(AccessDenied):
            self.svc.enforce("alice", "lac:CreateUser", "lac:user/x", {"request:ip": "10.0.0.1"})

    def test_separation_of_duties(self):
        self.svc.assign_role("alice", "payment-requester")
        with self.assertRaises(Conflict):
            self.svc.assign_role("alice", "payment-approver")
        self.assertEqual(self.svc.sod_violations(), [])
        # A rule added after the fact is reported as a violation.
        self.svc.assign_role("alice", "deployer")
        self.svc.add_sod_rule("no-deployer-requester", ["deployer", "payment-requester"])
        self.assertEqual(len(self.svc.sod_violations()), 1)

    def test_access_review(self):
        review = self.svc.access_review("alice")
        sources = {(p["source"], p["policy"]) for p in review["policies"]}
        self.assertIn(("group:ops", "EC2TeamOperator"), sources)
        self.assertIn(("group:employees", "SecurityBaseline"), sources)

    def test_deleting_policy_detaches_it(self):
        self.svc.delete_policy("EC2TeamOperator")
        self.assertNotIn("EC2TeamOperator", self.svc.store.groups["ops"]["policies"])


class PersistenceAndAuditTests(unittest.TestCase):
    def test_state_and_audit_survive_restart_and_detect_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            svc = make_service(tmp)
            svc.create_user("dave", PW)
            svc.authorize("dave", "s3:GetObject", "x")
            svc2 = AccessControlService(store=Store(Path(tmp) / "state.json"), audit=AuditLog(Path(tmp) / "audit.jsonl"))
            self.assertIn("dave", svc2.store.users)
            self.assertEqual(svc2.audit.verify(), (True, None))
            svc2.audit.record("after.restart", "admin")
            self.assertEqual(svc2.audit.verify(), (True, None))

            log = Path(tmp) / "audit.jsonl"
            lines = log.read_text().splitlines()
            entry = json.loads(lines[2])
            entry["actor"] = "mallory"
            lines[2] = json.dumps(entry, sort_keys=True)
            log.write_text("\n".join(lines) + "\n")
            self.assertEqual(svc2.audit.verify(), (False, 2))


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.svc = make_service()
        cls.svc.create_user("auditor1", PW, groups=["auditors"])
        cls.svc.create_user("helper", PW, groups=["helpdesk"])
        cls.server = create_server(cls.svc, "127.0.0.1", 0)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def call(self, method, path, body=None, token=None):
        req = urllib.request.Request(self.base + path, method=method, data=json.dumps(body).encode() if body is not None else None)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req) as res:
                return res.status, json.loads(res.read())
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read())

    def login(self, user):
        status, body = self.call("POST", "/api/login", {"username": user, "password": PW})
        self.assertEqual(status, 200, body)
        return body["token"]

    def test_requires_authentication(self):
        self.assertEqual(self.call("GET", "/api/users")[0], 401)
        self.assertEqual(self.call("POST", "/api/login", {"username": "admin", "password": "nope"})[0], 401)

    def test_admin_can_manage_users(self):
        t = self.login("admin")
        status, body = self.call("POST", "/api/users", {"username": "erin", "password": PW, "groups": ["employees"]}, t)
        self.assertEqual(status, 200, body)
        status, body = self.call("POST", "/api/users/erin/roles", {"role": "payment-approver"}, t)
        self.assertEqual(body["roles"], ["payment-approver"])
        status, body = self.call("POST", "/api/users/erin/roles", {"role": "payment-requester"}, t)
        self.assertEqual(status, 409)

    def test_auditor_is_read_only(self):
        t = self.login("auditor1")
        self.assertEqual(self.call("GET", "/api/users", token=t)[0], 200)
        self.assertEqual(self.call("GET", "/api/audit?limit=5", token=t)[0], 200)
        self.assertEqual(self.call("POST", "/api/users", {"username": "x", "password": PW}, t)[0], 403)

    def test_helpdesk_cannot_touch_admin(self):
        t = self.login("helper")
        self.assertEqual(self.call("POST", "/api/users/auditor1/unlock", {}, t)[0], 200)
        self.assertEqual(self.call("POST", "/api/users/admin/disable", {}, t)[0], 403)

    def test_authorize_endpoint(self):
        t = self.login("auditor1")
        status, body = self.call("POST", "/api/authorize", {"action": "lac:ListUsers", "resource": "lac:user/*"}, t)
        self.assertEqual((status, body["allowed"]), (200, True))
        status, body = self.call("POST", "/api/authorize", {"principal": "helper", "action": "lac:UnlockUser", "resource": "lac:user/bob"}, t)
        self.assertEqual((status, body["allowed"]), (200, True))
        helper = self.login("helper")
        status, _ = self.call("POST", "/api/authorize", {"principal": "admin", "action": "x", "resource": "y"}, helper)
        self.assertEqual(status, 403)

    def test_permissions_probe_is_self_only_and_not_audited(self):
        t = self.login("auditor1")
        before = len(self.svc.audit.entries())
        status, body = self.call("POST", "/api/me/permissions", {"checks": [
            {"action": "lac:ListUsers", "resource": "lac:user/*"},
            {"action": "lac:CreateUser", "resource": "lac:user/*"},
        ]}, t)
        self.assertEqual((status, body), (200, [True, False]))
        self.assertEqual(len(self.svc.audit.entries()), before)
        self.assertEqual(self.call("POST", "/api/me/permissions", {"checks": [{}] * 51}, t)[0], 400)

    def test_endpoint_events(self):
        admin = self.login("admin")
        events = [{"event": "blocked", "user": "bob", "host": "PC-7", "control": "paste", "trigger": "Ctrl+V", "process": "excel.exe"}]
        status, body = self.call("POST", "/api/endpoint/events", {"events": events}, admin)
        self.assertEqual((status, body), (200, {"accepted": 1}))
        auditor = self.login("auditor1")
        status, rows = self.call("GET", "/api/endpoint/events?host=PC-7", token=auditor)
        self.assertEqual((status, rows[-1]["control"]), (200, "paste"))
        # Auditors can read but not report; helpdesk can do neither.
        self.assertEqual(self.call("POST", "/api/endpoint/events", {"events": events}, auditor)[0], 403)
        self.assertEqual(self.call("GET", "/api/endpoint/events", token=self.login("helper"))[0], 403)
        self.assertEqual(self.call("POST", "/api/endpoint/events", {"events": []}, admin)[0], 400)

    def test_static_files_and_security_headers(self):
        with urllib.request.urlopen(self.base + "/") as res:
            self.assertIn("default-src 'self'", res.headers["Content-Security-Policy"])
            self.assertIn(b"/static/js/app.js", res.read())
        with urllib.request.urlopen(self.base + "/static/js/app.js") as res:
            self.assertTrue(res.headers["Content-Type"].startswith("text/javascript"))
        for path in ("/static/../service.py", "/static/%2e%2e/service.py", "/static/missing.js"):
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(self.base + path)
            self.assertEqual(ctx.exception.code, 404, path)

    def test_bad_input(self):
        t = self.login("admin")
        self.assertEqual(self.call("POST", "/api/policies", {"name": "bad", "document": {"Statement": []}}, t)[0], 400)
        self.assertEqual(self.call("GET", "/api/nope", token=t)[0], 404)
        self.assertEqual(self.call("GET", "/api/users/ghost", token=t)[0], 404)


if __name__ == "__main__":
    unittest.main()
