# Threat model

Scoped with STRIDE, then checked against the control set. Every mitigation
marked **verified** has a scenario in `tobira attack` and a test in `tests/`.

## Assets

| Asset | Why it matters |
|---|---|
| Private applications (payroll, HMI, build server) | the thing being protected |
| User access tokens | bearer credentials for those applications |
| Device certificate private keys | device identity and posture signing |
| The lab CA private key | compromise collapses the whole trust model |
| The audit stream | evidence; also a target for an attacker covering tracks |

## Trust boundaries

1. Internet → broker (the only inbound boundary)
2. Broker → App Connector tunnel
3. Broker → Client Connector tunnel
4. App Connector → private application (plain TCP inside the private network)
5. Endpoint OS → Client Connector (posture is collected here)

## Adversaries

| Adversary | Starting position | Goal |
|---|---|---|
| **A1** External scanner | can route to the broker only | find and exploit anything reachable |
| **A2** Credential thief | holds a valid token exfiltrated from a device | use it from their own machine |
| **A3** Malicious insider | a legitimate low-privilege account and device | reach applications they are not entitled to |
| **A4** Compromised endpoint | code execution on an enrolled device | keep access after disabling security controls |
| **A5** Compromised connector host | code execution next to the applications | hijack other applications' traffic |
| **A6** Offboarded employee | credentials that were valid yesterday | retain access |

## STRIDE

### Spoofing

| Threat | Mitigation | Status |
|---|---|---|
| Impersonate a user | Ed25519 token, broker holds public key only | **verified** `forged_token_is_rejected` |
| Use a stolen token elsewhere | `cnf` thumbprint bound to device certificate | **verified** `token_replay_from_other_device` |
| Impersonate a device | mTLS; private key never leaves the device | **verified** `foreign_ca_certificate_is_refused` |
| Impersonate an App Connector | certificate role in subject OU + policy-owned app list | **verified** `device_cert_cannot_publish_apps`, `rogue_connector_cannot_claim_app` |
| Impersonate the broker | client pins the CA and verifies the broker SAN | partially verified (client-side `check_hostname`) |

### Tampering

| Threat | Mitigation | Status |
|---|---|---|
| Alter posture attributes | attestation signed over canonical JSON | **verified** `test_tampered_attributes_break_the_signature` |
| Alter traffic in flight | TLS 1.3 AEAD on both tunnels | by construction |
| Alter policy | policy loaded from disk at start; file permissions are the control | **not mitigated in-process** |
| Alter the audit log | append-only writes | **weak** — see *Residual risks* |

### Repudiation

| Threat | Mitigation | Status |
|---|---|---|
| "I never accessed that" | every decision carries user, device id, app, rule, posture score | **verified** `test_audit_trail_records_allow_and_deny` |
| Silent denial | a denial is an event with a named reason, not a dropped packet | **verified** |

### Information disclosure

| Threat | Mitigation | Status |
|---|---|---|
| Enumerate private applications | identical deny reason for real and invented names; visibility filtered | **verified** `app_enumeration_is_blocked_and_detected` |
| Discover hosts/ports | broker sends the connector an app *name*; host/port never leave the private network | by construction |
| Fingerprint services | connector binds no listening socket | **verified** `app_connector_opens_no_port` |
| Read another user's traffic | per-stream relay keyed on tunnel identity | **verified** `test_two_users_are_isolated` |

### Denial of service

| Threat | Mitigation | Status |
|---|---|---|
| Memory exhaustion via oversized frames | 1 MiB cap validated before allocation | **verified** `test_announced_oversize_is_refused_before_allocating` |
| Slowloris on the handshake | 15 s handshake timeout | implemented |
| Connection flood | **not mitigated** — no rate limiting or quota | open |
| Connector exhaustion | **not mitigated** — no per-session stream cap | open |

### Elevation of privilege

| Threat | Mitigation | Status |
|---|---|---|
| Lateral movement after reaching one app | no network position is granted at all | **verified** `lateral_movement_is_blocked` |
| Use a second group to bypass a restriction | explicit deny beats allow | **verified** `explicit_deny_beats_allow` |
| Reach a high-value app without MFA | per-application MFA requirement | **verified** `missing_mfa_is_denied` |
| Skip authentication | tunnel accepts nothing but `auth` until authenticated | **verified** `open_before_auth_is_rejected` |
| Keep access after disabling EDR | re-authorisation on re-attestation | **verified** `posture_drop_revokes_live_session` |
| Coast by never re-attesting | stale posture fails closed | **verified** `stale_posture_blocks_new_connections` |

## Adversary walk-through

**A1, external scanner.** Reaches one TCP port. TLS requires a client
certificate chaining to the CA, so the handshake never completes and no
application logic is reached. The private network itself has no Tobira listener
to find.

**A2, credential thief.** Holds a real, unexpired token. It fails on the first
connection from their machine, because the token's `cnf` thumbprint does not
match their TLS certificate. Detection TOB-001 fires at severity *critical* on a
single event — this is not a threshold, one occurrence is an incident.

**A3, malicious insider.** Ben is a real employee with a real device. He reaches
the wiki and the build server. Payroll and the HMI are not merely refused, they
are absent from the list the broker gives him, and probing them returns exactly
the same answer as probing a name that does not exist. His five probes trip
TOB-003.

**A4, compromised endpoint.** The attacker has Chen's laptop and his session. The
moment EDR is switched off and the agent re-attests, the open HMI stream is torn
down and `factory-hmi` disappears from his list. If the attacker suppresses
re-attestation instead, the session goes stale and fails closed. If they forge an
attestation, the signature check fails (TOB-005). What they *can* still do is
leave the controls on and use the session — which is the honest limit of posture
checking, and why this is listed under residual risk.

**A5, compromised connector host.** They can reach the applications that host
can already reach — nothing new. They cannot publish `payroll` through a
different connector, because the broker checks the claimed app list against
policy and refuses the whole registration (TOB-002, *critical*).

**A6, offboarded employee.** The IdP refuses to mint anything for a revoked
user, and a token minted before offboarding is rejected at the enforcement point
as soon as its `jti` is on the deny list — not when it happens to expire.

## Residual risks

Listed deliberately, because a threat model that claims full coverage is not a
threat model.

1. **Fully compromised endpoint.** Posture is attested, not independently
   verified. Malware with sufficient privilege can report healthy attributes and
   sign them with the real device key. *Next step:* TPM quote or platform
   attestation so the claim is rooted in hardware rather than in the agent.
2. **Broker compromise.** The broker terminates both tunnels and sees plaintext.
   *Next step:* split the decision point from the enforcement point; consider
   end-to-end encryption between client and application.
3. **CA key compromise.** Collapses everything. *Next step:* offline root with
   short-lived intermediates; the CA here is a flat, online, single-tier design.
4. **Audit log integrity.** Append-only file writes. An attacker with write
   access to the host can edit history. *Next step:* hash-chain the stream and
   forward off-host in real time.
5. **No rate limiting.** Connection and stream floods are not bounded.
6. **No revocation transport for certificates.** User tokens can be revoked;
   there is no CRL or OCSP path for a compromised *device certificate* yet.
7. **Posture freshness is time-based.** A five-minute window means a device can
   be unhealthy for up to five minutes before a new connection is refused, if it
   never re-attests.
