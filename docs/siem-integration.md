# SIEM integration

## The stream

Tobira writes one ECS 8.x JSON object per line. No custom parser is required by
Wazuh, Elastic, Splunk or anything else that understands NDJSON.

```json
{
  "@timestamp": "2026-11-20T09:14:02.481Z",
  "ecs": { "version": "8.11.0" },
  "event": {
    "kind": "event", "module": "tobira", "dataset": "tobira.access",
    "category": ["network", "session"], "type": ["denied"],
    "action": "access_denied", "outcome": "failure",
    "reason": "posture_failed", "severity": 6
  },
  "observer": { "vendor": "Tobira", "product": "zero-trust-broker", "type": "proxy" },
  "user": { "name": "chen", "roles": ["employees", "ot-engineers"] },
  "source": { "ip": "127.0.0.1", "port": 54122 },
  "destination": { "address": "10.20.0.7", "port": 502 },
  "message": "chen -> factory-hmi denied (posture_failed)",
  "tobira": {
    "app": "factory-hmi",
    "device_id": "workstation-chen",
    "session_id": "a1b2c3d4e5f60718",
    "policy_rule": "ot-engineers-hmi",
    "posture_score": 65,
    "posture_failures": ["edr_running", "score<95"]
  }
}
```

### Event actions

| Action | Outcome | Severity | Meaning |
|---|---|---|---|
| `broker_started` | success | 2 | broker came up |
| `connector_registered` | success | 2 | connector published its applications |
| `connector_registration_denied` | failure | 8 | connector claimed applications it does not own |
| `connector_disconnected` | unknown | 5 | tunnel lost; streams dropped |
| `tunnel_rejected` | failure | 7 | peer failed the TLS or certificate-role check |
| `authentication_succeeded` | success | 2 | token + posture accepted |
| `authentication_failed` | failure | 7–9 | see `event.reason` |
| `access_granted` | success | 2 | one connection authorised |
| `access_denied` | failure | 5–6 | one connection refused |
| `access_revoked` | failure | 8 | live stream torn down after re-evaluation |
| `posture_reattested` | success/failure | 3/7 | device re-reported its state |
| `session_terminated` | failure | 9 | whole session ended by the broker |
| `session_ended` | success | 2 | client disconnected normally |
| `session_stream_closed` | success | 2 | one relayed connection finished; carries byte counts |

### Vendor fields

All under `tobira.*`, which is where ECS expects vendor extensions:
`app`, `connector`, `device_id`, `session_id`, `stream_id`, `policy_rule`,
`posture_score`, `posture_failures`, `bytes_sent`, `bytes_received`.

## Detection content

Twelve rules, maintained in two equivalent forms so a finding means the same
thing in the lab and in production:

| Where | Form | Used by |
|---|---|---|
| `src/tobira/siem/rules/tobira-access.yml` | Sigma-style YAML | the in-lab engine, so `tobira attack` proves attacks are *detected* |
| `siem/wazuh/rules/tobira_rules.xml` | Wazuh XML, ids 100100–100199 | a real Wazuh deployment |

Both carry the same `TOB-xxx` identifiers and the same MITRE ATT&CK technique
references.

### Rule shapes

**`match`** — fires on one event. Used where a single occurrence is already an
incident, such as a token presented from the wrong device.

**`threshold`** — fires when N events sharing a key arrive inside a sliding
window. `distinct:` counts unique values instead of raw events, which is what
separates *enumeration* (three different applications denied) from *noise* (the
same application denied five times by a stuck client).

```yaml
- id: TOB-003
  title: Private application enumeration
  type: threshold
  severity: high
  selection:
    event.action: access_denied
  group_by: [user.name]
  distinct: tobira.app
  threshold: 3
  window_seconds: 120
  mitre: [T1046, T1087]
```

### Running them

```bash
tobira detect reports/audit-sample.ecs.json
```

```
12 detection(s) fired:

  CRITICAL      TOB-001  Access token replayed from a different device [aiko]
  CRITICAL      TOB-002  App Connector tried to publish applications it does not own
  HIGH          TOB-003  Private application enumeration [ben]
  HIGH          TOB-005  Device posture attestation forged or replayed [chen]
  ...
```

## Wazuh

```bash
cp siem/wazuh/decoders/tobira_decoders.xml /var/ossec/etc/decoders/
cp siem/wazuh/rules/tobira_rules.xml       /var/ossec/etc/rules/
chown root:wazuh /var/ossec/etc/decoders/tobira_decoders.xml \
                 /var/ossec/etc/rules/tobira_rules.xml
```

Add the `<localfile>` block from `siem/wazuh/ossec.conf.snippet` to
`/var/ossec/etc/ossec.conf`, then restart:

```bash
/var/ossec/bin/wazuh-control restart
```

Verify a rule without waiting for real traffic:

```bash
/var/ossec/bin/wazuh-logtest
# paste one line from reports/audit-sample.ecs.json
```

Wazuh's `frequency` + `same_field` + `different_field` combination expresses the
TOB-003 distinct-count logic natively (rules 100103/100104).

## Elastic

```bash
cp siem/elastic/filebeat-tobira.yml /etc/filebeat/inputs.d/
systemctl restart filebeat
```

No ingest pipeline is needed: the events are already ECS, so Discover, Lens and
the Security app understand them as they arrive. Query examples and suggested
dashboard panels are in `siem/elastic/saved-searches.md`.

## Splunk

```conf
# inputs.conf
[monitor:///var/log/tobira/tobira-ecs.json]
sourcetype = tobira:access
index = security

# props.conf
[tobira:access]
INDEXED_EXTRACTIONS = json
KV_MODE = none
TIME_PREFIX = "@timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%Z
```

The equivalent of TOB-003:

```spl
index=security sourcetype=tobira:access event.action=access_denied
| bucket _time span=2m
| stats dc(tobira.app) AS apps BY _time, user.name
| where apps >= 3
```

## Operational notes

- **Write before answer.** The broker emits the audit event as part of making
  the decision, so a denial cannot be silent even if the client disconnects.
- **Denials name a reason.** `event.reason` is a small closed vocabulary
  (`posture_failed`, `mfa_required`, `outside_time_window`, …), so dashboards can
  group on it without regex.
- **Tune TOB-004 first.** Repeated-denial volume is the rule most likely to be
  noisy in a real estate; a misconfigured client retrying looks like an attacker.
  TOB-003's `distinct` requirement makes it much more specific.
- **TOB-012 is informational by design.** Access *granted* to a crown-jewel
  application is not an alert, but it is something an auditor will ask for.
