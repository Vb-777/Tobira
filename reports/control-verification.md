# Tobira - zero trust access lab: control verification report

Generated 2026-11-20 15:58 UTC

## Result

- **21/21 adversary scenarios blocked**
- **45 audit events** written in Elastic Common Schema
- **12 detections fired** from 10 distinct rules

## Scenarios

### Attack surface (5/5 blocked)

| Scenario | Attacker goal | Technique | Outcome | Evidence |
|---|---|---|---|---|
| `app_connector_opens_no_port` | Find a service to attack on the App Connector host | Network service discovery (T1046) | Blocked | connector bound 0 listening sockets |
| `anonymous_tls_is_refused` | Reach the broker without any credential | Exploit public-facing application (T1190) | Blocked | refused at the TLS layer (connection closed before hello_ok) |
| `foreign_ca_certificate_is_refused` | Present a certificate from an attacker-controlled CA | Subvert trust controls (T1553) | Blocked | refused at the TLS layer (connection closed before hello_ok) |
| `device_cert_cannot_publish_apps` | Use a valid user device certificate to register as an App Connector | Trusted relationship abuse (T1199) | Blocked | rejected: wrong_certificate_role |
| `rogue_connector_cannot_claim_app` | Register a connector that publishes an application it does not own | Adversary-in-the-middle (T1557) | Blocked | registration refused: unauthorised_app_claim |

### Identity and credentials (6/6 blocked)

| Scenario | Attacker goal | Technique | Outcome | Evidence |
|---|---|---|---|---|
| `forged_token_is_rejected` | Mint our own access token | Forge web credentials (T1606) | Blocked | auth failed: token_bad_signature |
| `expired_token_is_rejected` | Keep using a token after it expires | Valid accounts (T1078) | Blocked | auth failed: token_expired |
| `token_replay_from_other_device` | Steal a valid token and use it from another machine | Application access token theft (T1550.001) | Blocked | auth failed: token_device_mismatch |
| `revoked_credential_is_rejected` | Use the credentials of an offboarded employee | Valid accounts (T1078) | Blocked | idp refused new token (user 'mallory' is revoked); existing token: token_revoked |
| `stale_nonce_is_rejected` | Replay a captured handshake nonce | Replay attack (T1557) | Blocked | auth failed: nonce_mismatch |
| `open_before_auth_is_rejected` | Skip authentication and go straight to opening an application | Exploitation for access (T1212) | Blocked | broker replied: auth_fail (not_authenticated) |

### Device posture (3/3 blocked)

| Scenario | Attacker goal | Technique | Outcome | Evidence |
|---|---|---|---|---|
| `unhealthy_device_is_denied` | Connect from a device that fails the posture bar | Impair defenses (T1562.001) | Blocked | denied: posture_failed; visible apps [] |
| `forged_posture_is_rejected` | Claim a healthy posture the device cannot prove | Masquerading (T1036) | Blocked | auth failed: posture_bad_signature |
| `posture_device_id_mismatch_is_rejected` | Attest as a different, healthier device | Masquerading (T1036) | Blocked | auth failed: posture_device_mismatch |

### Authorisation policy (5/5 blocked)

| Scenario | Attacker goal | Technique | Outcome | Evidence |
|---|---|---|---|---|
| `lateral_movement_is_blocked` | Move sideways from an allowed app to a forbidden one | Lateral movement (T1021) | Blocked | wiki reachable; payroll denied (no_matching_rule); visible ['build-server', 'wiki'] |
| `app_enumeration_is_blocked_and_detected` | Discover which private applications exist | Network service discovery (T1046) | Blocked | 5/5 probes denied with an identical reason |
| `explicit_deny_beats_allow` | Use a group membership to reach a forbidden application | Valid accounts (T1078) | Blocked | denied: explicit_deny |
| `out_of_hours_access_is_denied` | Reach a business-hours application in the middle of the night | Valid accounts (T1078) | Blocked | 03:00 JST -> outside_time_window; 14:00 JST -> allowed |
| `missing_mfa_is_denied` | Reach a high-value application without MFA | Valid accounts (T1078) | Blocked | denied: mfa_required; visible apps ['build-server', 'wiki'] |

### Continuous evaluation (2/2 blocked)

| Scenario | Attacker goal | Technique | Outcome | Evidence |
|---|---|---|---|---|
| `posture_drop_revokes_live_session` | Disable a security control after being let in | Impair defenses (T1562.004) | Blocked | session was live, then revoked: ['factory-hmi']; posture score 65 |
| `stale_posture_blocks_new_connections` | Keep a session alive by never re-attesting | Impair defenses (T1562) | Blocked | denied: posture_stale |

## Why each control holds

**app_connector_opens_no_port** — The connector dials out to the broker and keeps one outbound tunnel; there is nothing inbound for a scanner to find.

**anonymous_tls_is_refused** — The broker requires a client certificate chaining to the lab CA, so an unauthenticated scanner never reaches application logic.

**foreign_ca_certificate_is_refused** — Trust is pinned to one private CA, so minting your own certificate achieves nothing.

**device_cert_cannot_publish_apps** — Certificate role is carried in the subject OU; a device certificate cannot be used to publish applications.

**rogue_connector_cannot_claim_app** — Policy, not the connector, decides which connector serves which application, so traffic cannot be hijacked by a new registration.

**forged_token_is_rejected** — The broker holds only the IdP public key, so tokens it did not sign are rejected before any policy is consulted.

**expired_token_is_rejected** — Tokens are short-lived by design, so stolen credentials have a small window of usefulness.

**token_replay_from_other_device** — The token carries the thumbprint of the device certificate it was issued to; the broker compares it with the live TLS peer.

**revoked_credential_is_rejected** — Revocation takes effect at the enforcement point immediately, not when the token happens to expire.

**stale_nonce_is_rejected** — Each connection gets a fresh broker-chosen nonce, so a recorded handshake cannot be replayed.

**open_before_auth_is_rejected** — The broker keeps per-tunnel state and accepts nothing but AUTH until authentication has succeeded.

**unhealthy_device_is_denied** — Disk encryption was switched off, so the device no longer meets the 'critical' profile the plant HMI requires.

**forged_posture_is_rejected** — A posture report is only accepted if signed by the private key of the device certificate presenting it.

**posture_device_id_mismatch_is_rejected** — The attested device id must match the certificate on the wire.

**lateral_movement_is_blocked** — Reaching one application grants no network position at all, so there is nothing to pivot from. Payroll is not even listed.

**app_enumeration_is_blocked_and_detected** — Real applications and invented names produce the same answer, so the attacker learns nothing; the burst trips detection TOB-003.

**explicit_deny_beats_allow** — Dinesh is in 'employees' and 'contractors'. The contractor deny rule wins, which is the safe direction for a policy conflict.

**out_of_hours_access_is_denied** — The same identity, device and token produce a different answer depending on when the request is made.

**missing_mfa_is_denied** — Password-only authentication is enough for the wiki and not enough for payroll; the bar is per application.

**posture_drop_revokes_live_session** — Access is re-evaluated on every re-attestation, so the open connection is torn down rather than surviving until token expiry.

**stale_posture_blocks_new_connections** — A device that stops proving its state loses access; silence is not treated as health.

## Detections

| Rule | Severity | Title | Entity | Events |
|---|---|---|---|---|
| TOB-007 | high | Tunnel rejected at the TLS or role boundary | `-` | 1 |
| TOB-002 | critical | App Connector tried to publish applications it does not own | `-` | 1 |
| TOB-006 | high | Revoked or invalid credential presented | `aiko` | 1 |
| TOB-001 | critical | Access token replayed from a different device | `aiko` | 1 |
| TOB-006 | high | Revoked or invalid credential presented | `mallory` | 1 |
| TOB-011 | low | Access denied because device posture is below policy | `chen` | 1 |
| TOB-005 | high | Device posture attestation forged or replayed | `chen` | 1 |
| TOB-005 | high | Device posture attestation forged or replayed | `ben` | 1 |
| TOB-003 | high | Private application enumeration | `ben` | 4 |
| TOB-004 | medium | Repeated access denials for one user | `ben` | 5 |
| TOB-012 | informational | Access granted to a critical application | `chen` | 1 |
| TOB-008 | high | Live session revoked after device posture dropped | `chen` | 1 |

## Audit stream

| Event action | Count |
|---|---|
| `access_denied` | 10 |
| `authentication_failed` | 7 |
| `authentication_succeeded` | 7 |
| `session_ended` | 7 |
| `connector_registered` | 3 |
| `access_granted` | 3 |
| `session_stream_closed` | 3 |
| `broker_started` | 1 |
| `tunnel_rejected` | 1 |
| `connector_registration_denied` | 1 |
| `access_revoked` | 1 |
| `posture_reattested` | 1 |

## Notes

- Every scenario runs against the live broker in `tobira attack`; nothing in this table is asserted without being executed.
- `out_of_hours_access_is_denied` is evaluated against the policy engine with a fixed clock rather than by waiting for 03:00 JST.
- Detection rule identifiers match `siem/wazuh/rules/tobira_rules.xml`, so a finding here and a finding in a real Wazuh deployment mean the same thing.
