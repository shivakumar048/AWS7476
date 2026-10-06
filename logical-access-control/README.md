# Logical Access Control (LAC)

An application for implementing **logical access controls** on systems: deciding
*who* may perform *which action* on *which resource*, under *what conditions*,
and keeping a tamper-evident record of it. The model mirrors AWS IAM, so
policies written here read like the IAM policies used elsewhere in this repo.

Pure Python 3.10+ standard library, so there's nothing to install.

## Controls implemented

| Control | How |
|---|---|
| Identification & authentication | Unique user IDs, PBKDF2-SHA256 password hashing, enforced password complexity |
| Brute-force protection | Account lockout after 5 failed logins (15 min), admin unlock |
| Session management | Random bearer tokens with expiry; revoked on logout, disable, password change |
| Least privilege | Default **implicit deny**; access only via explicit `Allow` |
| Guardrails | Explicit `Deny` always overrides any `Allow` |
| RBAC | Users → groups and roles → policies |
| ABAC / context-aware access | Conditions on source IP, time of day, date, MFA, user tags, resource tags, numeric limits |
| Separation of duties | SoD rules block conflicting role combinations (maker/checker) and report existing violations |
| Access reviews | Effective permissions per user, showing which group/role grants each policy |
| Accountability | Every login, change and authorization decision goes into a SHA-256 **hash-chained** audit log; `audit verify` detects edits |
| Self-protecting admin plane | Every management API call is itself authorized (`lac:CreateUser` on `lac:user/bob`, ...) |
| Policy Decision Point | `POST /api/authorize` lets other systems/apps ask "may X do Y on Z?" |

## Quick start

```bash
cd logical-access-control

# 1. Bootstrap an administrator and load the example policies/groups/roles
python3 -m lac init --admin admin --seed examples/seed.json   # prompts for a password

# 2. Create a user, put them in groups, tag them (ABAC attribute)
python3 -m lac user add alice --group employees --group ops --tag team=platform

# 3. Ask for an access decision (exit code 0 = allow, 2 = deny)
python3 -m lac check alice ec2:StopInstances arn:aws:ec2:us-east-1:1:instance/i-1 \
    -c request:ip=10.0.0.4 -c resource:tag/team=platform

# 4. Run the REST API + web console on http://127.0.0.1:8080
python3 -m lac serve
```

State lives in `./data/` (`state.json`, `audit.jsonl`); override it with `--data-dir` or `LAC_DATA_DIR`.

## Writing policies

```json
{
  "Statement": [
    {
      "Sid": "StartStopOwnTeam",
      "Effect": "Allow",
      "Action": ["ec2:StartInstances", "ec2:StopInstances"],
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": { "StringEquals": { "resource:tag/team": "${user:tag/team}" } }
    },
    {
      "Sid": "CorporateNetworkOnly",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": { "NotIpAddress": { "request:ip": "10.0.0.0/8" } }
    }
  ]
}
```

* `Action` / `NotAction` / `Resource` accept `*` and `?` wildcards (actions are case-insensitive).
* Variables: `${user:name}`, `${user:tag/<key>}` and any other context key.
* Condition operators: `StringEquals`, `StringNotEquals`, `StringEqualsIgnoreCase`, `StringLike`,
  `StringNotLike`, `Numeric{Equals,LessThan,LessThanEquals,GreaterThan,GreaterThanEquals}`,
  `DateLessThan`, `DateGreaterThan`, `Bool`, `IpAddress`, `NotIpAddress`, `TimeOfDayBetween`
  (`"09:00-17:00"`, overnight windows allowed); append `IfExists` to any of them.
* Operators within a condition block are AND-ed; multiple values for a key are OR-ed.

**Context keys** the service supplies automatically (and callers can't override):
`user:name`, `user:mfa`, `user:tag/<key>`, `user:group/<name>`, plus `request:time`,
`request:timeofday`, `request:weekday`, and `request:ip` (from the HTTP connection unless the caller provides one).
Anything else, such as `resource:tag/team`, comes from the calling system in `context`.

## Example seed (`examples/seed.json`)

| Name | Type | What it does |
|---|---|---|
| `SecurityBaseline` | policy → `employees` | Deny destructive/IAM actions without MFA; deny access from outside the corporate network |
| `S3HomeFolder` | policy → `employees` | Read/write only `company-data/home/${user:name}/*` |
| `EC2TeamOperator` | policy → `ops` | Describe everything; start/stop only instances tagged with your team |
| `AuditorReadOnly` | policy → `auditors` | Read identities, policies, audit log; simulate others' access |
| `HelpdeskUserAdmin` | policy → `helpdesk` | Unlock/reset users, with an explicit deny on `admin*` accounts |
| `ProdDeployBusinessHours` | policy → role `deployer` | Deploy to `app:prod/*` only 08:00–18:00 UTC |
| `payments-maker-checker` | SoD rule | Nobody may hold both `payment-requester` and `payment-approver` |

## REST API

Authenticate with `POST /api/login {"username","password"}` → `{"token"}`, then send
`Authorization: Bearer <token>`.

| Method & path | Required permission |
|---|---|
| `POST /api/authorize` `{action, resource, context?, principal?}` | none for yourself; `lac:SimulatePrincipalPolicy` for others |
| `GET /api/me` | — |
| `GET/POST /api/users`, `GET/DELETE /api/users/{u}` | `lac:ListUsers` / `lac:CreateUser` / `lac:GetUser` / `lac:DeleteUser` |
| `POST /api/users/{u}/disable\|enable\|unlock\|password\|tags\|mfa` | `lac:DisableUser`, `lac:EnableUser`, ... |
| `POST /api/users/{u}/groups`, `DELETE .../groups/{g}` | `lac:AddUserToGroup` / `lac:RemoveUserFromGroup` |
| `POST /api/users/{u}/roles`, `DELETE .../roles/{r}` | `lac:AssignRole` / `lac:RevokeRole` |
| `GET /api/users/{u}/access-review` | `lac:ReviewAccess` |
| `GET/POST /api/groups`, `/api/roles`, `DELETE .../{name}` | `lac:List*`, `lac:Create*`, `lac:Delete*` |
| `POST /api/{users\|groups\|roles}/{name}/policies`, `DELETE .../policies/{p}` | `lac:AttachPolicy` / `lac:DetachPolicy` |
| `GET/POST /api/policies`, `PUT/DELETE /api/policies/{p}` | `lac:ListPolicies`, `lac:CreatePolicy`, ... |
| `GET/POST /api/sod-rules`, `GET /api/sod-violations` | `lac:ListSoDRules` / `lac:CreateSoDRule` |
| `GET /api/audit?limit=&actor=&event=`, `GET /api/audit/verify` | `lac:ReadAuditLog` |

Integrating a system is one call per request it wants to guard:

```bash
curl -s -X POST http://127.0.0.1:8080/api/authorize -H "Authorization: Bearer $TOKEN" \
  -d '{"principal":"alice","action":"payments:ApprovePayment","resource":"payments:invoice/42","context":{"amount":900}}'
```

## CLI reference

```
python3 -m lac init | serve | check | seed FILE
python3 -m lac user  add|list|show|delete|disable|enable|unlock|passwd|mfa|join|leave|grant|revoke|review
python3 -m lac policy add NAME FILE | list | show | delete | attach NAME KIND TARGET | detach ...
python3 -m lac group|role add|list|delete
python3 -m lac sod add NAME ROLE ROLE... | list | violations
python3 -m lac audit list [--actor --event --limit] | verify
```

## Tests

```bash
python3 -m unittest discover -s tests -t .
```

## Production notes

* The built-in server speaks plain HTTP. Put it behind TLS (a reverse proxy or load balancer) before exposing it.
* Sessions are kept in memory and reset on restart. The JSON store fits a single node; swap `Store` for a database if you need several.
* The MFA flag is an attribute an administrator sets (`user mfa alice on`); hook it up to your MFA provider to make it authoritative.
