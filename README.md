# Tobira — a zero trust private access lab

**扉 (tobira)** — *a door.* A door you open for one person, for one room, after
checking who they are and what they are carrying — then close behind them.

Tobira is a working implementation of the private-access model used by
commercial zero trust platforms, built from scratch in Python so that every
control can be inspected, tested and attacked. Private applications expose **no
inbound ports at all**. Every connection is authorised on its own against
identity, device posture and policy, and every decision is written to a
SIEM-ready audit stream.

```
21/21 adversary scenarios blocked     71 tests passing     12 detection rules
```

---

## The problem this solves

A VPN answers one question — *are you allowed onto the network?* — once, at the
door, and then grants a network position. Everything after that is
reachable: an attacker with a stolen password does not need to break anything
else, they just scan. The VPN concentrator itself has to listen on the
internet, so it is also a target in its own right.

Tobira answers a different question, and answers it **every time a connection is
made**: *should this user, on this device, in this state, right now, reach this
one application?*

|  | VPN / firewall | Tobira |
|---|---|---|
| Inbound ports on the private network | VPN gateway listens | **none** |
| Unit of access | a network (subnet, VLAN) | one application |
| When policy is evaluated | at login | every connection + on re-attestation |
| What a user can enumerate | the whole subnet | only what they may already reach |
| Device health | optional, at login | signed attestation, continuously |
| Lateral movement after compromise | scan and pivot | nothing to pivot from |

---

## Architecture

```
          PRIVATE NETWORK                 INTERNET                 USER DEVICE
    ┌───────────────────────────┐                            ┌──────────────────────┐
    │                           │                            │                      │
    │  payroll    :8080         │                            │  curl / browser      │
    │  wiki       :8080         │                            │        │             │
    │  factory-hmi:502          │                            │        ▼             │
    │      ▲                    │                            │  Client Connector    │
    │      │ local TCP          │                            │  ├ device cert       │
    │      │                    │                            │  ├ user token        │
    │  ┌───┴──────────────┐     │                            │  └ signed posture    │
    │  │  App Connector   │     │                            │        │             │
    │  │  NO LISTENING    │     │                            └────────┼─────────────┘
    │  │  SOCKETS         │     │                                     │
    │  └────────┬─────────┘     │                                     │
    └───────────┼───────────────┘                                     │
                │  outbound mTLS                       outbound mTLS  │
                │                                                     │
                └──────────────►  ┌─────────────────────┐  ◄──────────┘
                                  │      BROKER         │
                                  │ ─────────────────── │
                                  │ 1. mTLS + cert role │
                                  │ 2. token + binding  │
                                  │ 3. posture          │
                                  │ 4. policy (default  │
                                  │    deny)            │
                                  │ 5. relay            │
                                  │        │            │
                                  │        ▼            │
                                  │  ECS audit stream ──┼──► SIEM
                                  └─────────────────────┘
```

**Both sides dial out.** The broker is the only process that listens. It never
initiates a connection into the private network, and the App Connector never
accepts one — it keeps a single outbound tunnel and the broker multiplexes
authorised sessions inside it.

That is the whole trick, and it is why `app_connector_opens_no_port` can assert
that the connector binds **zero** listening sockets: there is no port to scan,
no banner to fingerprint, no pre-auth code path to exploit.

---

## Try it

```bash
git clone https://github.com/Vb-777/Tobira && cd Tobira
pip install -e ".[dev]"

tobira demo      # bring the lab up and walk through it
tobira attack    # run 21 adversary scenarios, write a report
pytest           # 71 tests
```

No Docker, no Kubernetes, no cloud account. Everything runs in one process on
loopback, which keeps the security properties easy to verify.

### What `tobira demo` shows

```
== Aiko (finance, MFA, hardened laptop) ==
  broker says she may reach: ['build-server', 'payroll', 'wiki']
  payroll replied: Yamaha-style payroll service | app=payroll | secret=PAYROLL-SECRET-7F31
  wiki is now on 127.0.0.1:41923 for ordinary tools (curl, browser)

== Ben (employee, no MFA, 21-day-old patches) ==
  broker says he may reach: ['build-server', 'wiki']
  payroll: denied (no_matching_rule)
  factory-hmi: denied (no_matching_rule)

== Chen (OT engineer) turns off EDR mid-session ==
  HMI session established
  after re-attestation: score 80, revoked ['factory-hmi']
```

Three things worth noticing:

1. Ben is not told that `payroll` exists. The deny reason for a real application
   and for an invented one is byte-for-byte identical.
2. Aiko's `wiki` appears on a loopback port, so existing tools work unchanged.
3. Chen's **already-open** connection is torn down the moment his device stops
   meeting policy — not when his token expires.

---

## The five controls, and the attacks that test them

`tobira attack` runs each scenario against the live broker and checks both that
the attack failed **and** that the right audit evidence was produced.

### Attack surface

| Scenario | Attacker goal | Result |
|---|---|---|
| `app_connector_opens_no_port` | Find a service to attack on the connector host | connector bound 0 listening sockets |
| `anonymous_tls_is_refused` | Reach the broker with no credential | refused at the TLS layer |
| `foreign_ca_certificate_is_refused` | Present a self-minted certificate | refused at the TLS layer |
| `device_cert_cannot_publish_apps` | Use a user device cert to register as a connector | `wrong_certificate_role` |
| `rogue_connector_cannot_claim_app` | Register a connector that serves `payroll` | `unauthorised_app_claim` |

### Identity and credentials

| Scenario | Attacker goal | Result |
|---|---|---|
| `forged_token_is_rejected` | Mint our own token | `token_bad_signature` |
| `expired_token_is_rejected` | Use a token past its lifetime | `token_expired` |
| `token_replay_from_other_device` | Use a stolen token from another laptop | `token_device_mismatch` |
| `revoked_credential_is_rejected` | Use an offboarded employee's credential | `token_revoked` |
| `stale_nonce_is_rejected` | Replay a captured handshake | `nonce_mismatch` |
| `open_before_auth_is_rejected` | Skip authentication entirely | `not_authenticated` |

### Device posture

| Scenario | Attacker goal | Result |
|---|---|---|
| `unhealthy_device_is_denied` | Connect with disk encryption off | `posture_failed` |
| `forged_posture_is_rejected` | Claim a health state we cannot prove | `posture_bad_signature` |
| `posture_device_id_mismatch_is_rejected` | Attest as someone else's workstation | `posture_device_mismatch` |

### Authorisation policy

| Scenario | Attacker goal | Result |
|---|---|---|
| `lateral_movement_is_blocked` | Pivot from the wiki to payroll | `no_matching_rule`, payroll not even listed |
| `app_enumeration_is_blocked_and_detected` | Discover what exists | 5/5 probes denied identically; trips TOB-003 |
| `explicit_deny_beats_allow` | Use a second group to reach OT | `explicit_deny` |
| `out_of_hours_access_is_denied` | Reach payroll at 03:00 JST | `outside_time_window` |
| `missing_mfa_is_denied` | Reach payroll with a password only | `mfa_required` |

### Continuous evaluation

| Scenario | Attacker goal | Result |
|---|---|---|
| `posture_drop_revokes_live_session` | Disable EDR after being let in | live session revoked in-flight |
| `stale_posture_blocks_new_connections` | Stop re-attesting and coast | `posture_stale` |

---

## How a connection is authorised

Five checks, in order, failing closed at every step:

1. **mTLS.** The peer must present a certificate chaining to the lab CA. The
   subject `OU` carries the role (`broker` / `connector` / `device`), so a user
   device certificate cannot be used to publish an application.
2. **Token.** Ed25519 JWT — signature, issuer, audience, expiry, revocation.
   The broker holds only the IdP's **public** key, so minting and accepting
   credentials are separate concerns.
3. **Device binding.** The token carries a `cnf` claim (RFC 7800 / RFC 8705
   style) holding the SHA-256 thumbprint of the device certificate it was issued
   to. The broker compares it with the live TLS peer, so a token copied off one
   laptop is useless on another.
4. **Posture.** The device signs its health attributes with the private key of
   its certificate, over a nonce the broker chose for *this* connection. That
   defeats both cross-device and replay forgery.
5. **Policy.** Default deny. Group membership, posture profile, MFA and time
   window are evaluated for the **specific application**, on **every**
   connection.

---

## Policy

Policy is YAML, and the engine refuses to load anything that is not default-deny.

```yaml
default: deny

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

rules:
  - name: ot-engineers-hmi
    users: { groups: [ot-engineers] }
    apps: [factory-hmi]
    posture: critical
    mfa_required: true
    action: allow

  # An explicit deny beats any allow — the safe direction for a conflict.
  - name: contractors-no-ot
    users: { groups: [contractors] }
    apps: [factory-hmi, payroll]
    action: deny
```

The same engine decides **visibility**: a client is only told about the
applications it could actually reach right now, which removes the reconnaissance
step entirely. See [`docs/policy-reference.md`](docs/policy-reference.md).

---

## SIEM integration

Every decision is one line of [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html) JSON:

```json
{
  "@timestamp": "2026-11-20T09:14:02.481Z",
  "ecs": { "version": "8.11.0" },
  "event": { "module": "tobira", "dataset": "tobira.access", "category": ["network","session"],
             "action": "access_denied", "outcome": "failure", "reason": "posture_failed",
             "severity": 6 },
  "user": { "name": "chen", "roles": ["employees","ot-engineers"] },
  "tobira": { "app": "factory-hmi", "device_id": "workstation-chen",
              "policy_rule": "ot-engineers-hmi", "posture_score": 65,
              "posture_failures": ["edr_running","score<95"] }
}
```

Shipping logs is not a control on its own, so Tobira ships **detection content**
too — twelve rules, maintained in two equivalent forms:

- `src/tobira/siem/rules/tobira-access.yml` — runs inside the lab, so
  `tobira attack` proves the attacks are *detected*, not just blocked;
- `siem/wazuh/rules/tobira_rules.xml` — drop-in Wazuh rules with the same IDs
  and the same MITRE ATT&CK mappings;
- `siem/elastic/filebeat-tobira.yml` — Filebeat input; no ingest pipeline needed,
  because the events are already ECS.

| Rule | Severity | Fires on |
|---|---|---|
| TOB-001 | critical | token replayed from a different device |
| TOB-002 | critical | connector publishing applications it does not own |
| TOB-003 | high | application enumeration (3 distinct denies / 120s) |
| TOB-005 | high | posture attestation forged, stale or replayed |
| TOB-006 | high | revoked or invalid credential |
| TOB-007 | high | tunnel rejected at the TLS or role boundary |
| TOB-008 | high | live session revoked after posture dropped |

See [`docs/siem-integration.md`](docs/siem-integration.md).

---

## Repository layout

```
src/tobira/
  protocol.py        framed, multiplexed wire protocol over mTLS
  pki.py             private CA, certificate roles, TLS contexts
  identity.py        users, Ed25519 tokens, device binding, revocation
  posture.py         signed attestation, scoring, profile evaluation
  policy.py          default-deny engine, time windows, visibility
  events.py          ECS event emission
  broker/            policy decision + enforcement point, relay
  connector/         App Connector (outbound only, own app allow-list)
  client/            Client Connector (loopback listeners)
  siem/              detection engine + rule content
  attacks.py         21 adversary scenarios
  lab.py             wires the whole environment together
lab/config/          users.yaml, apps.yaml, policy.yaml
siem/                drop-in Wazuh and Elastic configuration
docs/                architecture, threat model, policy reference
tests/               71 tests
```

---

## Honest limits

This is a lab, and the README should say what it is not:

- **Not a product.** No HA, no horizontal scaling, no key rotation, no
  management UI, no persistence beyond the audit log.
- **Posture is attested, not verified.** As on any real endpoint agent, a device
  with full local compromise can sign false attributes. Signing binds the claim
  to the device, which is what makes forgery and replay detectable — it does not
  make a rooted laptop honest. Hardware attestation (TPM quote) is the next step.
- **The broker is a trusted component.** It terminates both tunnels and can see
  plaintext. End-to-end encryption between client and application would remove
  that, at the cost of losing inspection.
- **The IdP is minimal.** Real deployments federate to Entra ID, Okta or an
  LDAP directory; only group membership and an MFA claim are consumed here.
- **The demo applications are stand-ins** — a small keep-alive HTTP responder,
  not real payroll or HMI software.

---

## Why I built it

I spent two conversations with Yamaha Motor's cybersecurity team about zero
trust and their Zscaler rollout, and realised I understood the architecture
diagrams but had never had to make the model actually hold under attack.
Rebuilding it was the way to find out which properties come from the
architecture and which have to be engineered deliberately.

The thing that surprised me: the hard part is not the tunnelling. It is
**continuous evaluation**. Authorising a connection is easy; noticing that a
session which was legitimate thirty seconds ago no longer is, and tearing it
down mid-flight, is where most of the design effort went — and it is the
property that separates zero trust from a VPN with better login.

**Vaibhav Barsaiyan** — M.Tech CSE, IIT Hyderabad
[LinkedIn](https://linkedin.com/in/b7-vaibhav) · [GitHub](https://github.com/Vb-777)

MIT licensed.
