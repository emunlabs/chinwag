# Agent dispatch over iroh v1 — IROH-DISPATCH-1

agent-author: RUST

This candidate adds explicit macOS client/listener commands. It has not been
started against a real identity or live agent. The DAG is a draft only.

## Authority and protocol statement

An authenticated QUIC peer can submit a dispatch only when its endpoint ID equals
the configured pin, its signed genesis room advertisement has been verified by
`RoomSession`, and that room lease remains fresh at request admission. The
existing sovereign endpoint builder also enforces the pin at the TLS handshake
and for outgoing dials. Address lookup supplies addresses and never permission.
There is one remote peer per listener, following the existing two-actor scope.
The coordinator pin and local pin configuration are trusted operator inputs.

The signer attests to the dispatch bytes, intended Studio, issuance, expiry and
nonce. A Studio signature attests to the exact output and exit code for a hash of
that signed request; it does not attest to the quality of the agent's work.
The Studio's existing dispatcher retains its existing authority and side effects.
QUIC supplies confidentiality; application signatures supply explicit binding.
No new scalar/curve arithmetic or general-purpose signing API is introduced.

Primitive: PureEd25519 as specified in RFC 8032 (January 2017), through existing
`iroh =1.4.1` and strict `ed25519-dalek =2.2.0` verification. Request binding uses
SHA-256 (`sha2 =0.10.9` in swarm). See
<https://www.rfc-editor.org/rfc/rfc8032.html>. This is an application protocol
candidate, not an independently reviewed production assurance claim.

## Wire and transcript

ALPN is `chinwag/agent-dispatch/1`. Each connection carries one bidirectional
stream: request JSON then EOF, response JSON then EOF. Unknown ALPN is refused;
extra streams are never dispatched. JSON structs deny unknown/duplicate fields.
JSON ordering/whitespace does not affect signatures. Hex strings must be exact
lowercase: 32-byte endpoint IDs/nonces/digests, 64-byte signatures.

Request JSON fields are `v` (1), `requester`, `studio`, `nonce`, `issued_unix`,
`expiry_unix`, `payload` (`agent`, `sender`, `body`, `itemKey`, `history`,
`customAgent`), `signature`.
The request transcript starts with the literal ASCII domain plus a NUL byte:
`chinwag-agent-dispatch-request/v1\0`. Every following field has an unsigned
64-bit big-endian byte length followed by its bytes, in this order:

1. Requester public key, Studio public key, nonce (decoded bytes).
2. Issuance and expiry (each encoded as eight big-endian bytes).
3. Agent, sender, body, itemKey (UTF-8 bytes).
4. History count (eight big-endian bytes), then each history entry's sender,
   role, body: each optional string is a one-byte presence field (0 or 1),
   followed, when present, by the length-prefixed UTF-8 value.
5. One-byte customAgent presence field, then, when present, role, dept, engine,
   system_prompt, with the same optional-string encoding.

Version 1 is validated and fixed by the domain. Request SHA-256 covers the whole
request transcript followed by the same length-prefixed decoded signature.

Response JSON fields are `v` (1), `studio`, `request_sha256`, `expiry_unix`, `ok`,
`exit_code`, `reply`, `error_code`, `signature`. `reply` is a JSON string holding
the exact dispatcher stdout, including its newline. The response transcript uses
`chinwag-agent-dispatch-response/v1\0` followed by length-prefixed fields:

1. Decoded Studio ID, decoded request SHA-256, eight-byte expiry.
2. Two bytes `[ok_as_0_or_1, exit_code]` as one field.
3. Exact UTF-8 reply; ASCII `none` or `dispatch_failed`.

Success requires exit 0, error `none`, and an object-valued JSON reply. Failure
requires a nonzero exit, error `dispatch_failed`, and an empty reply. Engine
stderr and malformed/oversized stdout never become remote error diagnostics.
Clients print only verified dispatcher JSON and return its exit code; connection,
wire or authentication refusal returns 2, local output failure returns 1.

Limits: 128 KiB request envelope, 1 MiB response envelope, 60,000-byte body,
120,000-byte reply, 128-byte agent, 256-byte sender/itemKey, at most ten history
entries with 30,000 total text bytes, and at most 4,000 bytes per customAgent
field; no blank required
fields or NUL characters. Signed timestamps are positive and at most 2^53-1.
Request expiry is at most 120 seconds after issuance; future issuance and expired
admission are refused. Response validity is a separate 120-second lease from
completion, so a long-running admitted dispatch can complete after admission
expires. Clients verify response freshness and the exact request binding.

Nonces are 32 random bytes, supplied by the client OS-backed RNG. Verification
consumes a `(requester, nonce)` before dispatch. The cache retains all unexpired
entries (maximum 4096), refuses on capacity, and never evicts a live entry. Each
listener rejects requests issued at or before its startup second; this rejects
pre-restart signed requests even though the cache is process-local. A request
signed in the listener's startup second is also refused. The client waits one
second after verifying the Studio advertisement before signing, within its room
lease, so its first request crosses that watermark. Wall-clock rollback during a run fails closed. Restart safety assumes a
trustworthy nondecreasing system clock across listener restarts. No automatic
retry, idempotent completion cache or exactly-once guarantee across new nonces is
claimed. Losing a reply does not prove no work was performed.

## Runtime and operator inputs

Commands require explicit options; no default key, peer or coordinator is read:

```text
chinwag agent-dispatch-listen --key /absolute/operator-key \
  --peer PEER_HEX --coordinator COORDINATOR_HEX \
  --room https://bootstrap.chinwag.sh --local-ipv4 LAN_IPV4 \
  --repo /absolute/studio-repository

chinwag agent-dispatch-remote --stdin --key /absolute/client-key \
  --peer STUDIO_HEX --coordinator COORDINATOR_HEX \
  --room https://bootstrap.chinwag.sh --local-ipv4 LAN_IPV4 \
  --repo /absolute/client-repository < request.json

chinwag agent-dispatch-status --repo /absolute/studio-repository --json
```

The private key loader is the existing owned/private OpenSSH Ed25519 loader.
Do not use a live identity for acceptance tests. The runtime uses the sovereign
builder with `RoomOnly` discovery and `RelayPolicy::Disabled`: no public relay,
LAN discovery, DHT or public address publisher is started. The explicit HTTPS
room coordinator is the existing control plane. Listener and client must overlap
their room rendezvous; opening/receiving has existing bounded room timeouts.

The listener admits at most two connections/dispatches at once. A fixed window
allows six completed request-admission attempts per pinned peer per minute;
bad input also spends that budget. Handshake/read/write deadlines are five
seconds. The client has a 600-second exchange deadline. The blocking dispatcher
keeps its semaphore permit until it exits, even if the client disconnects.
Existing subprocess execution has no new cancellation mechanism. A stuck agent
can therefore occupy a slot and delay shutdown; client timeout does not kill it.

The listener stops admission when its verified room lease expires (at most 120
seconds), or on Ctrl-C, and drains already admitted work. No automatic reattach,
coordinator retry or lease extension is implemented. Start a new listener session
explicitly for another lease. The status file marks admission stopped before
draining. Transport failure details collapse to `dispatch_refused`; only static
outcome messages are logged, never a request body or engine diagnostic.

Remote stdin supports the existing `agent`, optional `sender`, `body`/`message`,
`itemKey`/`item` aliases and defaults, optional `history` (the last ten entries,
matching the local runner), and `customAgent` fields. All effective context is
signed. A supplied `crdb` string is accepted for input compatibility and discarded
before signing: the Studio fixes CRDB to `<repo>/.chinwag/state.crdb`, which cannot
be overridden by remote input. Unknown fields are rejected at every structured
boundary. `run_agent_dispatch` receives the normalized signed JSON via its
existing stdin path and is unchanged. Non-macOS entry points return
`unsupported_os` like the existing CLI modules.

## Read-only planner status

`<repo>/.chinwag/agent-dispatch-status.json` is a typed `DispatchStatus`, schema 1,
with `version`, `listening`, `alpn`, `pinned_peer_count`, `requests_accepted`,
`requests_refused`, `requests_failed`, `last_request_unix`, `started_unix`,
`updated_unix`, `room_valid_until_unix`. Counts are per listener instance and
saturate rather than wrap. Acceptance is recorded before invoking the dispatcher;
refusal counts include rejected connections and malformed input. Failure counts
include dispatcher and post-admission transport failure. There are no bodies,
peer IDs, secret keys, or request IDs in this surface.

The listener requires an existing operator-owned `.chinwag` directory without
group/other write permission. It writes a random create-new 0600 temporary file,
fsyncs it, renames atomically, then syncs the directory. Snapshot writes are
serialized. Persistence failure stops further admission. A 0600 create-new
`agent-dispatch-listener.lock` prevents simultaneous instances for that state
directory. After a crash an operator must verify no listener remains before
removing a stale lock; there is no automatic lock takeover.

The status command only opens/reads the snapshot (no-follow), checks ownership,
0600 mode, schema and a 16 KiB cap, then prints the typed JSON. Missing/bad state
returns `dispatch_status_unavailable` with exit 2 and never creates files.
A heartbeat older than 15 seconds, backwards clock or expired room lease makes
`listening` false in the read result. Snapshots are advisory and local, not
cryptographic remote liveness proofs. They expose no write endpoint.

## Acceptance and handoff

Fake-dispatch tests are in `dispatch_listen.rs`; no test invokes
`LocalDispatcher` or the real `run_agent_dispatch`. Throwaway keys and state are
created only in temp directories. The loopback endpoint pair uses Minimal
endpoints, explicit `127.0.0.1:0`, no relay, no DHT, no external lookup. Membership
in these CLI unit tests is a test-only fixture; production construction requires
a `RoomSession`. Existing swarm tests cover signed room verification separately.
A live coordinator/Studio deployment, Linux execution, independent cryptographic
review (ALISTAIR), and operational lease renewal are outside this acceptance run.

The draft DAG at `docs/dagu-draft/iroh-agent-dispatch.yaml` is copied to the task
backup directory. It is unscheduled and uses placeholder paths/pins. Its `run`,
file-valued `stdin`, and `timeout_sec` follow the current Dagu YAML reference:
<https://docs.dagu.sh/writing-workflows/yaml-specification>. The installed Dagu
version has not been probed, and the draft has not been run or installed.

Exact build/test evidence and blockers are recorded in the task backup
`PROGRESS.md` and command logs. Passing signature tests is not independent
security review or proof that an agent call succeeded in production.
