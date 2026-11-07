# Native bus federation

The native bus can forward an unchanged signed original from one Chinwag daemon to its configured peer. The local publisher, journal, bounded forwarding queue and remote Iroh connection belong to the same daemon. There is no separate walkie-talkie bridge.

This implementation does not by itself establish that a Cloudflare relay is deployed or that two hosts occupy separate networks. Those require actual deployment and transport evidence. A WebSocket signaling service or TURN-credential endpoint is not an Iroh relay.

## Select an ordinary peer and an owned relay

An explicit network-enabled daemon requires all of these selections:

```text
chinwag bus daemon --repo <selected-repository> --port <local-port> --no-governors \
  --network-room-origin <clean-HTTPS-coordinator-origin> \
  --network-coordinator <coordinator-public-endpoint-id> \
  --network-peer <other-daemon-public-endpoint-id> \
  --relay-origin <owned-HTTPS-Iroh-relay-origin> \
  --expected-relay-origin <independently-selected-same-origin> \
  --network-configuration <local-selection-id> --network-generation <positive-generation> \
  --relay-only
```

These values are selected configuration data. Matching relay strings, a generation number or knowledge of an endpoint ID does not authorize a peer. The gate starts closed and requires genuine, current own and peer advertisements with matching coordinator storage receipts. Daemon identity is the actual owned Iroh endpoint identity; it is not relabeled as an SSH identity.

The owned relay policy permits exactly its configured clean HTTPS origin. Public default Iroh relay services, custom peer-supplied transports, incomplete selections and different expected origins are refused. There is no automatic fallback from a requested network route to an unrelated local append.

New daemon keys use OS randomness and private exclusive creation with file and directory synchronization. Existing key bytes are preserved. Wrong-length or unsafe key files are refused without rotation or permission repair. Every structurally acceptable 32-byte file is a valid raw seed: this format cannot detect same-length corruption or prove the entropy or enrollment of an existing key. A recognized old predictable daemon identity cannot start the network-enabled profile; a negative legacy check or remote endpoint pin does not prove how a key was generated.

Diagnostic `daemon.json` is replaced through a retained-directory, no-follow writer using a fresh private file, synchronization and exact readback. Existing symlinks, hardlinks and unsafe files are refused, including a dangling state symlink created before the identity key exists. Startup and later state-write errors stop this daemon's owned runtime. A failure after journal publication may still leave stored bytes and notifications; a negative ACK does not assert rollback.

## Relay-only path

Relay-only mode clears the default IP transports and binds the daemon's sole UDP transport to IPv4 loopback. It advertises no direct peer addresses. A local CLI publisher can still reach this same daemon over loopback; its ephemeral transport identity must also present the existing registered seat signature.

Remote daemon forwarding uses only the configured relay address and the live room gate. Each connection and received federation frame is checked against the current peer. The actual selected QUIC path must be the configured relay in relay-only mode. Cached discovery addresses and home-relay readiness are not path evidence. The room receive loop continues while the single bounded outbound transfer runs.

Ordinary daemons started without network selections retain legacy signed direct-IP publication. Network-enabled daemons accept ordinary publisher frames only over loopback; remote daemon originals use the gated federation frame. The existing seven-field sender-signature transcript, ordinary `Publish` frame and ordinary publication ACK fields are preserved.

## Required coordinator behavior

The ordinary Genesis coordinator contract uses attach/advertise challenges, actor-signed peer advertisements and `chinwag-peer-stored/v1` storage receipts. Initial and updated peer discovery must carry the exact peer advertisement **and its matching receipt**. A legacy advertisement without a receipt remains observational discovery and cannot open the daemon gate.

The daemon-only relay profile additionally requires the backend to verify and receipt a canonical advertisement with zero direct addresses. Legacy nonempty advertisement APIs retain their existing behavior. A backend that does not support this variant remains unsupported for relay-only federation.

The original room owner is revoked by close, drop, receive failure or expiry. Own and peer deadlines retain both their original wall-clock expiry and monotonic deadline, at most 120 seconds. An idle wait cancellation does not extend either deadline. There is no implicit session renewal or reconnect. This is a finite ordinary-room session, not a claim of permanent host continuity. Prompt remote revocation requires an actual backend event or closure; the client cannot infer an event the server never sends.

A peer storage receipt grants ordinary transport membership only. It is not a mesh transfer ticket, license, per-message K2 approval, task lease or processing receipt. The experimental mesh/TURN coordinator draft does not replace this ordinary-room protocol.

## Publication and persistence

The existing `chinwag/bus/1` ALPN carries the original message. Federation re-verifies the original seat signature and its digest/endpoint witnesses before persistence. A single bounded ingress serializes durable journal decisions:

- A new original is appended once and must complete file/directory synchronization, exact bounded readback and retained file/namespace checks before notification.
- An exact replay checks existing history without appending or repeating local notifications or forwarding.
- The same message ID with conflicting immutable content is refused.
- An uncertain or partial write retains its bytes and cannot produce a success ACK or automatic retry.

Once a selected daemon exchange is attempted, a missing or unusable response returns refusal with the original ID/digest available for explicit reconciliation. It never opens a fresh local sink automatically. The local publication path remains available when no daemon exchange was attempted and no explicit remote route was requested.

Inbound federation rechecks its current gate and selected connection path after persistence and diagnostic-state updates, immediately before constructing a positive ACK. If the gate expired or was revoked during storage, the row and any completed effects remain; refusal does not retry or undo them. As with other admission checks, this does not promise atomic authority throughout subsequent asynchronous ACK transmission.

The journal uses retained directory and file descriptors, exclusive cooperative locking and private regular single-link files. Missing or replaced namespaces are refused; an existing unsafe journal/lock is not silently chmodded or repaired. Advisory locks and retained descriptors do not provide containment against an adversarial process with the same OS identity. There is no durable prefix commitment to detect every same-inode historical rewrite or rollback. A fresh sink cannot prove history that was already lost before it opened. Complete valid history may contain non-monotonic sequence values; new allocation uses the maximum observed sequence with checked overflow.

Existing SQLite mirrors remain historical observations. This path does not write an unchecked SQLite filename through an external command. Native history reads the original JSONL journal.

Publication, storage, local receiver count, correlated processing and admitted work start remain separate. Legacy ACKs still have `PUBLISH_ONLY` scope. A native federation ACK reports the peer's journal publication over the authenticated connection; it is not independent remote disk inspection or proof of processing. No peer message starts a worker, renews a task or changes canonical task state.

## Verification boundary

Component tests exercise durable store/reopen/replay/conflict, unsafe-file refusal, actual local WebSocket room events and current binding expiry/revocation. Controlled loopback QUIC tests exercise the actual daemon publication path. These tests do not prove Cloudflare delivery, separate networks or production K2 custody.

The external proof must use two genuinely separate networks, independently establish that direct connectivity is blocked, preserve the exact signed original across both journals, and record the actual selected owned-relay path. A Tailscale address, successful control-plane request, simulator latency, relay readiness or a signed handoff is insufficient.
