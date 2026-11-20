# Useful queries once the stream is in Elastic / OpenSearch

All fields are ECS, so these work unchanged in Kibana Discover, Lens, or the
Security app.

| Question | Query |
|---|---|
| Everything Tobira denied today | `event.module: "tobira" and event.action: "access_denied"` |
| Credentials used off their device | `event.reason: "token_device_mismatch"` |
| Devices failing the posture bar | `event.action: "access_denied" and event.reason: "posture_failed"` |
| Sessions killed while connected | `event.action: ("access_revoked" or "session_terminated")` |
| Who reached the plant HMI | `event.action: "access_granted" and tobira.app: "factory-hmi"` |
| Connectors claiming apps they do not own | `event.action: "connector_registration_denied"` |
| Peers rejected before authentication | `event.action: "tunnel_rejected"` |

### Suggested dashboard panels

1. **Allow vs deny over time** — date histogram, split by `event.action`.
2. **Top denial reasons** — terms on `event.reason`, filtered to `access_denied`.
3. **Posture score distribution** — histogram of `tobira.posture_score`.
4. **Application enumeration** — unique count of `tobira.app` per `user.name`,
   filtered to `access_denied`; anything above three in a short window is the
   TOB-003 signal.
5. **Crown jewels** — table of `access_granted` where
   `tobira.app: "factory-hmi"`, columns `user.name`, `tobira.device_id`,
   `tobira.posture_score`, `tobira.policy_rule`.
