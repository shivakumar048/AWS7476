import unittest

from lac.policy import Policy, PolicyError, evaluate


def policy(name, *statements):
    return Policy.from_dict(name, {"Statement": list(statements)})


class PolicyEvaluationTests(unittest.TestCase):
    def test_implicit_deny_when_nothing_matches(self):
        d = evaluate([policy("p", {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"})], "s3:PutObject", "x")
        self.assertFalse(d.allowed)
        self.assertIn("implicit", d.reason)

    def test_explicit_allow_with_wildcards(self):
        p = policy("p", {"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "arn:aws:ec2:*"})
        self.assertTrue(evaluate([p], "ec2:DescribeInstances", "arn:aws:ec2:us-east-1").allowed)
        self.assertTrue(evaluate([p], "EC2:describeInstances", "arn:aws:ec2:us-east-1").allowed, "actions are case-insensitive")
        self.assertFalse(evaluate([p], "ec2:StartInstances", "arn:aws:ec2:us-east-1").allowed)

    def test_explicit_deny_overrides_allow_regardless_of_order(self):
        allow = policy("allow", {"Effect": "Allow", "Action": "*", "Resource": "*"})
        deny = policy("deny", {"Sid": "NoDelete", "Effect": "Deny", "Action": "s3:Delete*", "Resource": "*"})
        for order in ([allow, deny], [deny, allow]):
            d = evaluate(order, "s3:DeleteObject", "bucket/key")
            self.assertFalse(d.allowed)
            self.assertEqual((d.matched_policy, d.matched_sid), ("deny", "NoDelete"))

    def test_not_action(self):
        p = policy("p", {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})
        self.assertTrue(evaluate([p], "s3:GetObject", "x").allowed)
        self.assertFalse(evaluate([p], "iam:CreateUser", "x").allowed)

    def test_policy_variables_and_escaping(self):
        p = policy("p", {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "home/${user:name}/*"})
        self.assertTrue(evaluate([p], "s3:GetObject", "home/alice/a.txt", {"user:name": "alice"}).allowed)
        self.assertFalse(evaluate([p], "s3:GetObject", "home/bob/a.txt", {"user:name": "alice"}).allowed)
        # A value containing glob characters must not widen the pattern.
        self.assertFalse(evaluate([p], "s3:GetObject", "home/bob/a.txt", {"user:name": "*"}).allowed)

    def test_ip_condition(self):
        p = policy("p", {"Effect": "Allow", "Action": "*", "Resource": "*",
                         "Condition": {"IpAddress": {"request:ip": "10.0.0.0/8"}}})
        self.assertTrue(evaluate([p], "a", "r", {"request:ip": "10.1.2.3"}).allowed)
        self.assertFalse(evaluate([p], "a", "r", {"request:ip": "8.8.8.8"}).allowed)
        self.assertFalse(evaluate([p], "a", "r", {}).allowed, "missing key fails a positive operator")

    def test_negated_operator_with_missing_key_still_denies(self):
        deny = policy("d", {"Effect": "Deny", "Action": "*", "Resource": "*",
                            "Condition": {"NotIpAddress": {"request:ip": "10.0.0.0/8"}}})
        allow = policy("a", {"Effect": "Allow", "Action": "*", "Resource": "*"})
        self.assertFalse(evaluate([allow, deny], "a", "r", {}).allowed)
        self.assertTrue(evaluate([allow, deny], "a", "r", {"request:ip": "10.0.0.1"}).allowed)

    def test_if_exists(self):
        p = policy("p", {"Effect": "Allow", "Action": "*", "Resource": "*",
                         "Condition": {"StringEqualsIfExists": {"env": "dev"}}})
        self.assertTrue(evaluate([p], "a", "r", {}).allowed)
        self.assertTrue(evaluate([p], "a", "r", {"env": "dev"}).allowed)
        self.assertFalse(evaluate([p], "a", "r", {"env": "prod"}).allowed)

    def test_time_of_day_including_overnight(self):
        day = policy("p", {"Effect": "Allow", "Action": "*", "Resource": "*",
                           "Condition": {"TimeOfDayBetween": {"t": "09:00-17:00"}}})
        night = policy("p", {"Effect": "Allow", "Action": "*", "Resource": "*",
                             "Condition": {"TimeOfDayBetween": {"t": "22:00-06:00"}}})
        self.assertTrue(evaluate([day], "a", "r", {"t": "12:00:00"}).allowed)
        self.assertFalse(evaluate([day], "a", "r", {"t": "20:00:00"}).allowed)
        self.assertTrue(evaluate([night], "a", "r", {"t": "23:30:00"}).allowed)
        self.assertTrue(evaluate([night], "a", "r", {"t": "05:00:00"}).allowed)
        self.assertFalse(evaluate([night], "a", "r", {"t": "12:00:00"}).allowed)

    def test_numeric_date_and_bool(self):
        p = policy("p", {"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {
            "NumericLessThanEquals": {"amount": 1000},
            "DateLessThan": {"request:time": "2030-01-01T00:00:00Z"},
            "Bool": {"user:mfa": "true"},
        }})
        ctx = {"amount": "500", "request:time": "2026-06-01T00:00:00+00:00", "user:mfa": "true"}
        self.assertTrue(evaluate([p], "a", "r", ctx).allowed)
        self.assertFalse(evaluate([p], "a", "r", {**ctx, "amount": "5000"}).allowed)
        self.assertFalse(evaluate([p], "a", "r", {**ctx, "user:mfa": "false"}).allowed)
        self.assertFalse(evaluate([p], "a", "r", {**ctx, "amount": "not-a-number"}).allowed)

    def test_condition_variable_substitution(self):
        p = policy("p", {"Effect": "Allow", "Action": "*", "Resource": "*",
                         "Condition": {"StringEquals": {"resource:tag/team": "${user:tag/team}"}}})
        ctx = {"user:tag/team": "platform"}
        self.assertTrue(evaluate([p], "a", "r", {**ctx, "resource:tag/team": "platform"}).allowed)
        self.assertFalse(evaluate([p], "a", "r", {**ctx, "resource:tag/team": "payments"}).allowed)

    def test_invalid_policies_rejected(self):
        with self.assertRaises(PolicyError):
            Policy.from_dict("x", {"Statement": []})
        with self.assertRaises(PolicyError):
            Policy.from_dict("x", {"Statement": [{"Effect": "Maybe", "Action": "*"}]})
        with self.assertRaises(PolicyError):
            Policy.from_dict("x", {"Statement": [{"Effect": "Allow", "Resource": "*"}]})
        with self.assertRaises(PolicyError):
            Policy.from_dict("x", {"Statement": [{"Effect": "Allow", "Action": "*", "Condition": {"Bogus": {}}}]})


if __name__ == "__main__":
    unittest.main()
