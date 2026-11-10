# Native durable bus wait

`CHWG-WAIT-CI-P2-BUS-WAIT` adds a native local receive/handoff path. A durable
handoff, host admission, actual turn start, consumption, and task completion are
separate observations. These commands do not implement a host's turn-admission
API and do not replace an existing conversation monitor automatically.

## Enrollment and local trust

The owner provisions the public trust anchor at
`~/.chinwag/signing/owner_ed25519.pub` and a signed, private
`.chinwag/bus/enrollments/authority-state.json`. No command creates or repairs an
owner key. A peer cannot provision enrollment through a bus message.

`enroll-host` imports an existing owner-signed grant. It requires a fully
qualified actor and an explicit initial watermark:

```text
chinwag bus enroll-host --repo <physical-absolute-repository-path> \
  --for <SEAT#INSTANCE> --grant-file <private-owner-signed-grant.json> \
  --since-seq <sequence> --since-id <original-id>

chinwag bus enroll-host --repo <physical-absolute-repository-path> \
  --for <SEAT#INSTANCE> --grant-file <private-owner-signed-grant.json> \
  --current-tail
```

Explicit genesis uses `--since-seq 0 --since-id GENESIS`. Current-tail enrollment
records its observed tail rather than silently discarding arrivals later.
Enrollment is create-only. Existing or interrupted enrollment fails closed;
rerunning it cannot reset a turn quota or a cursor. Use physical paths, since
the retained directory guard rejects symlink components.

Owner grant fields are the closed `HostGrant` schema in `bus_wait_grant.rs`.
The owner authority schema is `chinwag.host.authority.v1`, with
`min_authority_epoch`, `revoked_grant_ids`, `issuer_pubkey_ed25519` and
`issuer_signature_ed25519`. Both schemas reject unknown fields. Owner signature
bytes are the indicated UTF-8 domain followed by compact JSON with root keys in
lexicographic order, omitting only `issuer_signature_ed25519`:

| Artifact | Signature domain |
| --- | --- |
| Grant, `chinwag.host.enrollment.v3` | `chinwag-host-enrollment-v3\|` |
| Authority, `chinwag.host.authority.v1` | `chinwag-host-authority-v1\|` |
| Reconciliation, `chinwag.bus.wait-reconciliation.v1` | `chinwag-wait-reconciliation-v1\|` |

These closed schemas contain strings, booleans, string arrays and safe unsigned
integers. They do not define canonicalization for arbitrary JSON objects or
floating-point values. The schemas are separate from the unchanged native bus
signature and digest domains.

## Waiting and consumption

```text
chinwag bus wait --repo <physical-absolute-repository-path> \
  --for <SEAT#INSTANCE> --timeout-secs 300 --json
```

The verifier uses compiled seat public keys. It checks the exact original
`chinwag-bus-sig-v2|` textual UTF-8 length-prefixed signature and the unchanged
eight-part `chinwag-bus-v1` digest before parsing signed body metadata. A
`{`-prefixed malformed or unsupported structured body never becomes legacy
chat. Receipts, statuses, self echoes and presence do not wake the host. Body
mentions do not expand the exact recipient or enrolled room/task scope.

Cursor, pending batches and reserved/used quota share one private state file
and one atomic rename. File and parent directory are synced. No cursor lock is
held while waiting, writing stdout, or making a host/network request. A token
orphan preceding the atomic reservation is cleared only after checking that no
committed handoff exists; a committed uncertain handoff is never blindly
re-emitted.

The wait client registers an explicit bounded local-daemon subscription before
opening its catch-up snapshot. Registration is acknowledged only after a
broadcast receiver exists. The subsequent wait consumes that exact receiver;
a journal mark is only an additional hint. Ready delivery, errors and return
cancel unused subscriptions. Registrations are single-use, have an expiry,
and are bounded to 64 entries; expired entries are pruned on registration.
This requires a daemon implementing the subscription frames. An older daemon
fails closed; installing or switching operational binaries is separate work.
No cursor lock spans registration, waiting, output or other IPC.

Each batch has at most 16 messages and a 256 KiB serialized envelope. This
implementation conservatively holds at 64 pending messages. A journal snapshot
is bounded at 64 MiB with 1 MiB record bounds; larger history reports explicit
backpressure. Rotation resolution searches at most eight `messages.jsonl.*` or
`messages.*.jsonl` archives within a cumulative 64 MiB snapshot bound. It drains
the anchored generation before each successor. Every generation edge requires
a verified repeated terminal original as the successor's first row. Names,
timestamps and unsigned sequence order do not prove an edge. Missing,
conflicting or ambiguous evidence fails closed, including legacy rotations
without overlap evidence. Pending-active acknowledgements traverse the same
bounded chain while capacity remains.

| Exit | Meaning |
| --- | --- |
| `0` | Private token and durable reservation committed; one `DATA_ONLY` envelope emitted. |
| `124` | Native wait timed out; no host admission claimed. |
| `75` | Uncertain handoff or offline/unsupported host/daemon; no automatic retry. |
| `2` | Invalid input, unsafe path, invalid signature/scope or another refused operation. |
| `74` | Output failed after the durable handoff; recovery must treat it as uncertain. |

The host adapter uses `wait-ack` with the exact actor, delivery ID, admission
request ID, message ID and original digest. Supply its capability through
`--handoff-token-file <private-0600-path>` or `--handoff-token-stdin`. Raw tokens
in command-line arguments are rejected. The token hash is checked in constant
time, with local UID, regular-file, single-link and permission checks.

```text
chinwag bus wait-ack --repo <physical-absolute-repository-path> \
  --for <SEAT#INSTANCE> --delivery-id <delivery> \
  --admission-request-id <request> --msg-id <original> \
  --digest-sha256 <original-digest> --handoff-token-file <private-token-file> \
  --state HOST_ADMITTED --admission-id <host-admission>
```

Lifecycle order is `HOST_CALL_DISPATCHING`, optionally `PENDING_ACTIVE_TURN`,
`HOST_ADMITTED`, actual `HOST_TURN_STARTED` with a turn ID, then `PROCESSED`.
Admission charges the already reserved slot once; receipt retries do not spend
another slot. A premature turn ID is refused. `PROCESSED` retains deduplication
witnesses and removes the private token. No network ACK can perform these local
transitions.

## Recovery and remaining host gates

This receive path has no supported host idempotency lookup adapter yet. On
restart, a committed pre-ACK handoff therefore holds
`HELD_UNCERTAIN_PRE_ACK_OUTCOME`; queued/admitted/started ambiguity holds
`HELD_UNCERTAIN_HOST_OUTCOME`. Quota and original messages stay retained. A grant
claiming lookup support does not fabricate an actual host lookup capability.

`wait-reconcile --owner-proof-file <private-owner-signed-json>` accepts
`NEVER_RECEIVED` and `ALREADY_PROCESSED`. Each closed proof binds the actor,
delivery, admission request, expected cursor version, expiry, exact ordered
`original_witnesses` (`id`/`digest`) and optional `admission_id`/`turn_id`.
Owner signatures and current enrollment authority are checked independently.
`ALREADY_PROCESSED` requires admission and turn evidence and completes held
work using its actual reservation/charge flags: one reserved slot becomes one
used slot, or an already used slot stays charged once. It records the original
witnesses durably before token unlink. This is an owner assertion, not an
observed host completion. `NEVER_RECEIVED` is restricted to held pre-admission
work; it preserves operation identities and the reserved slot, clears stale
host witnesses, and cannot reset admitted or started work. Stale, altered,
expired, inconsistent or replayed proofs do not change durable accounting.

An owner-signed grant may bind a qualified native actor to a different exact
host conversation ID. Changing that conversation requires a new valid owner
signature; actor, issuer, epoch, expiry, revocation and exact grant checks
remain in force. This binding validation does not prove live same-chat access.

Source/unit fixtures exercise cryptography, local authentication, batching,
durability transitions, rotation, native timeout and notification ordering.
Preserved-real-original tests additionally require the owner-supplied
`CHINWAG_INTEROP_FIXTURE` and run explicitly. They do not establish independent
host reliability, zero provider inference telemetry, user-input overlap,
production logout survival, or an accepted G-01..G-07 host proof. Those gates
remain with the admitted per-host adapter work and its independent acceptors.
Keep operational daemons and existing timers unchanged until that work passes
and the owner explicitly authorizes a switch.
