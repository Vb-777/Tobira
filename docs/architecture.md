# Architecture

## Components

| Component | Listens? | Holds | Trust it needs |
|---|---|---|---|
| **Broker** | yes, two ports | policy, IdP public key, live session state | the only internet-facing component; terminates both tunnels |
| **App Connector** | **no** | its own application allow-list, its certificate | must be able to reach the applications it publishes |
| **Client Connector** | loopback only | device certificate, user token | runs on the user's endpoint |
| **Identity provider** | n/a | Ed25519 signing key, user directory | mints tokens; never sees traffic |

The broker is the policy decision point *and* the policy enforcement point. That
is a deliberate simplification for a lab: splitting them is what you would do in
production so that an enforcement node compromise does not leak policy.

## Why both sides dial out

A VPN concentrator must listen, which makes it a permanent internet-facing
target. A reverse-proxy published application must listen, which makes *it* a
target.

Tobira inverts the direction. The App Connector opens one outbound mTLS
connection and keeps it. When a user is authorised, the broker tells the
connector, over that existing tunnel, to open a local TCP connection to the
application and relay it back as a new stream.

Consequences:

- the private network needs **no inbound firewall rule** for Tobira;
- an attacker scanning the private network finds nothing belonging to Tobira,
  which `app_connector_opens_no_port` asserts by diffing `/proc/net/tcp` around
  connector startup;
- the connector's pre-authentication attack surface is a TLS client library and
  a frame parser, not an authentication endpoint.

## Wire protocol

One mTLS connection carries control messages and multiplexed application data.

```
+--------+-----------------+-----------------+============+
| type:1 | stream_id:4     | length:4        | payload    |
+--------+-----------------+-----------------+============+
```

- `CONTROL` — UTF-8 JSON
- `DATA` — opaque application bytes
- `CLOSE` — tear down one stream, leaving the tunnel up

The stream id always travels in the **header**, never in the JSON body, so
control and data can never disagree about which session they belong to.

Frames are capped at 1 MiB and the size is validated *before* allocating, so an
unauthenticated peer cannot ask the broker to reserve arbitrary memory.

`FrameWriter` serialises writes behind a lock. Without it, two concurrently
relayed streams would interleave bytes inside a single frame.

## Connection sequence

```
Connector                    Broker                         Client
    |                          |                              |
    |-- mTLS (OU=connector) -->|                              |
    |-- hello ---------------->|                              |
    |<- hello_ok (nonce) ------|                              |
    |-- register [apps] ------>|  policy check: does this      |
    |<- register_ok -----------|  connector own these apps?    |
    |                          |                              |
    |                          |<------- mTLS (OU=device) ----|
    |                          |<------- hello ---------------|
    |                          |-------- hello_ok (nonce) --->|
    |                          |<------- auth (token,posture)-|
    |                          |  1 token signature/expiry     |
    |                          |  2 cnf thumbprint == peer     |
    |                          |  3 posture sig + nonce        |
    |                          |  4 visible app list           |
    |                          |-------- auth_ok (apps) ----->|
    |                          |                              |
    |                          |<------- open(app) -----------|
    |                          |  policy.decide(subject, app)  |
    |<- dial(stream_id, app) --|                              |
    |  (resolve app locally)   |                              |
    |-- dial_ok -------------->|                              |
    |                          |-------- open_ok ------------>|
    |<===== data ============= | ========= data =============>|
```

Note that the broker sends the connector only an **application name**. The
connector resolves `name -> host:port` from its own configuration. A compromised
broker therefore cannot use a connector as a general-purpose proxy into the
private network — it can only reach applications the connector already
publishes.

## Continuous evaluation

Authorisation is not a login event:

- **every** `open` re-runs the full policy decision, including posture;
- a session whose last attestation is older than five minutes fails closed
  (`posture_stale`);
- when the client re-attests, the broker re-authorises **every open stream** and
  tears down any that would no longer be granted, emitting `access_revoked`;
- the token's own expiry is checked per connection, not just at login.

This is the part that genuinely distinguishes the model from a VPN. A VPN that
checks device health at login hands out a network position that outlives the
check. Here, the check *is* the access.

## Threading and concurrency

Everything is `asyncio` on one event loop:

- each tunnel has one reader coroutine;
- relayed streams are multiplexed, not separate tasks per direction on the
  broker — the broker simply forwards frames, which keeps the hot path short;
- the App Connector runs one pump task per relayed TCP connection, because it
  has a real socket to read;
- `FrameWriter` serialises all writes to a tunnel.

## Failure modes

| Event | Behaviour |
|---|---|
| Connector disconnects | all its streams are closed with `connector_lost`; new opens fail `connector_unavailable` |
| Client tunnel drops | session removed; `session_ended` emitted |
| Application refuses the connection | `dial_fail` → `app_unreachable`, audited |
| Posture drops mid-session | affected streams revoked, `access_revoked` emitted |
| Attestation cannot be verified | whole session terminated, `session_terminated` emitted |
| Broker restarts | all tunnels drop; connectors and clients must re-establish |
