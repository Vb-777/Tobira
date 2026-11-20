# Policy reference

Three files describe the whole deployment. They live in `lab/config/` and are
the only thing an operator edits.

## `users.yaml`

```yaml
users:
  - username: aiko
    display_name: Aiko Tanaka
    groups: [employees, finance]
    mfa: true
    status: active        # active | suspended | revoked
```

In production this is a corporate directory (Entra ID, Okta, LDAP) and Tobira
consumes only group membership and an MFA claim.

`status: revoked` means the IdP refuses to mint anything at all. Revoking a
token that is already in circulation is separate — the broker keeps a `jti` deny
list that takes effect immediately.

## `apps.yaml`

```yaml
apps:
  - name: factory-hmi
    description: Plant floor HMI gateway
    host: 10.20.0.7        # resolved inside the private network
    port: 502
    connector: connector-factory
    sensitivity: critical
```

`connector` is authoritative: it is how the broker knows which App Connector may
publish this application. A connector that registers an application not assigned
to it has its **whole registration refused**, and TOB-002 fires.

`host` and `port` never leave the private network. The broker sends the
connector an application *name*, and the connector resolves it locally.

## `policy.yaml`

### Default

```yaml
default: deny
```

The engine raises `PolicyError` on load if this is anything else. There is no
"permit any" fallback.

### Posture profiles

```yaml
posture_profiles:
  critical:
    require:
      disk_encryption: true
      firewall_enabled: true
      edr_running: true
      screen_lock: true
      secure_boot: true
      os_patch_age_days: { max: 7 }
    min_score: 95
```

`require` supports:

| Form | Meaning |
|---|---|
| `attribute: true` / `false` | exact match |
| `attribute: { max: N }` | numeric upper bound |
| `attribute: { min: N }` | numeric lower bound |
| `attribute: { in: [a, b] }` | membership |

`min_score` is checked against a weighted 0–100 score:

| Attribute | Weight |
|---|---|
| `disk_encryption` | 25 |
| `edr_running` | 20 |
| `firewall_enabled` | 15 |
| `screen_lock` | 10 |
| `secure_boot` | 10 |
| `os_supported` | 10 |
| patched within the profile's window | 10 |

Both gates apply: a device can score 95 and still be refused for a specific
missing control, which is what you want — a score is a summary, not a substitute
for a requirement.

Failures are named individually in the audit event (`tobira.posture_failures`),
so a help desk can tell the user exactly what to fix.

### Rules

```yaml
rules:
  - name: finance-payroll
    users: { groups: [finance] }     # or: users: { names: [aiko] }
    apps: [payroll]                  # "*" matches every application
    posture: high
    mfa_required: true
    time_window:
      days: [mon, tue, wed, thu, fri]
      from: "08:00"
      to:   "20:00"
      tz:   Asia/Tokyo
    action: allow                    # allow | deny
```

### Evaluation order

1. Collect every rule matching **both** the subject and the application.
2. No candidates → `no_matching_rule`.
3. Any candidate with `action: deny` → `explicit_deny`. **Deny always wins**,
   regardless of rule order, which is the safe direction for a conflict.
4. For each remaining candidate, in file order:
   `mfa_required` → `time_window` → posture profile.
   The first rule that passes all three allows the connection.
5. Otherwise the **last** failure reason is returned, so the audit event says
   *why* rather than just "denied".

### Reasons

| Reason | Meaning |
|---|---|
| `no_matching_rule` | no rule covers this subject and application — also returned for applications that do not exist |
| `explicit_deny` | a deny rule matched |
| `mfa_required` | the token has no `mfa` in `amr` |
| `outside_time_window` | outside the rule's window in its own timezone |
| `posture_failed` | one or more required attributes failed, or the score was too low |
| `posture_stale` | no attestation in the last five minutes |
| `token_expired` | the session token expired after login |
| `connector_unavailable` | no connector currently publishes this application |
| `app_unreachable` | the connector could not open a local connection |

### Visibility

`visible_apps()` runs the same decision for every application and returns only
those that would be allowed. The client is told nothing else, so the
reconnaissance step is removed rather than merely logged.

This is why an unknown application name and a forbidden one both return
`no_matching_rule`: the response must not distinguish them.

## Worked examples

| User | Device | App | Result |
|---|---|---|---|
| aiko (finance, MFA) | hardened, 2-day patches | payroll, 14:00 JST Tue | allow — `finance-payroll` |
| aiko | same | payroll, 03:00 JST Tue | deny — `outside_time_window` |
| aiko, token without MFA | same | payroll | deny — `mfa_required` |
| ben (employees) | 21-day patches | wiki | allow — `everyone-wiki` |
| ben | same | payroll | deny — `no_matching_rule`, and not listed |
| chen (ot-engineers) | EDR off | factory-hmi | deny — `posture_failed: edr_running` |
| dinesh (employees + contractors) | hardened | factory-hmi | deny — `explicit_deny` |
