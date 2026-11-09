# Native inbox wait and conventional CI return: contract decision record

Status as of 2026-11-09: Phase 1 contract baseline frozen with the conditions
below. Phase 2 admission materials have been reviewed; source implementation and
host acceptance are separate execution steps. This checkpoint contains design
decisions, not a claim that the proposed runtime exists.

## Existing accepted alpha and the intended journey

The accepted source baseline is commit
`d326c7129979ca43499547842daac076d80fac35`, tree
`69c3b294b10a74190b894e2be486138c61772d83`. It proved a controlled failed CI run
waking an enrolled idle Codex conversation, reading the scoped failure capture,
and producing the admitted fixture repair. The coordinator separately validated,
integrated, committed and pushed that repair and explicitly dispatched the fresh
green run. That proof did not establish autonomous branch publication or a
general-purpose inbox watcher for every host.

The product journey should follow conventional GitHub/GitLab development:

1. Push the existing feature branch associated with a PR/MR.
2. Run the configured CI pipeline.
3. Report a failed build or test result.
4. Package the scoped failure evidence.
5. Route the signed evidence through Chinwag.
6. Wake the enrolled repair conversation.
7. Prepare the candidate repair in isolation and perform local checks.
8. After the application/publication gate, push the candidate to the same PR/MR
   branch and publish its exact-candidate evidence.
9. In fresh CI, verify candidate identity and trusted policy evidence.
10. Build and test the verified candidate checkout.
11. Report the fresh CI result, leaving the PR/MR ready for normal human review.

Configured platform events trigger the pipeline. A Chinwag relay acknowledgement
does not publish a Git ref, start CI, prove checks passed, or merge the PR/MR.
Local sandbox checks, fresh CI, human review, main merge and deployment remain
distinct gates. The failed runner need not remain alive waiting for the repair.

## Preserved message protocol and wake policy

The proposed wait path preserves the existing native wire formats. For the
message digest:

```text
digest_fields = ["chinwag-bus-v1", String(ts_unix), room, sender,
                 sender_endpoint_id, to || "", task_id || "", body]
digest_sha256 = hex(SHA-256(UTF-8(digest_fields.join("|"))))
```

For the detached signature:

```text
fields = [id, String(ts_unix), sender, to || "", room, task_id || "", body]
signed_utf8 = "chinwag-bus-sig-v2|"
              + fields.map(s => UTF8_BYTE_LENGTH(s) + ":" + s).join("|")
signature_ed25519 = Ed25519.sign(UTF-8(signed_utf8))
```

Lengths are decimal UTF-8 byte counts. This signature domain uses neither a NUL
separator nor binary integer lengths. Verify the exact original field bytes
before parsing or reserializing the signed body.

Wake-driving metadata belongs inside the signed body. A structured body uses a
bounded JSON schema with JCS canonical encoding, closed enums and duplicate-key
rejection. Look up the schema by parsed key; do not require `schema` to be the
first property. Malformed or unsupported structured input must not downgrade
into a waking legacy chat message. Legacy plaintext support is an explicit local
migration policy.

Verify the sender's pinned key and endpoint binding, exact recipient, room and
task scope, and owner-issued enrollment grant before wake. Unsigned outer fields
and body mentions cannot expand authority. Received payloads remain untrusted
data; host tool and task policy enforce the action boundary.

Receipts, status/control events and self echoes do not recursively wake agents.
Ordinary messages receive a useful substantive response when appropriate, without
compulsory model-generated "received" and "working" replies. Task lifecycle
states come from actual task observations and are distinct from chat consumption.

## Durable wait and host admission

The proposed Rust CLI surface is `bus wait`, `bus wait-ack`, `bus enroll-host`
and `bus wait-reconcile`. This record does not assert those commands are already
implemented in the operational binary.

Persist the receive cursor, pending deliveries and mutable quota reservations in
one authoritative atomic store. Use a private sibling temporary file, sync the
file, rename, and sync the parent directory. Enforce ownership, permissions and
safe file handling for state, lock, enrollment and token files.

Register the journal subscription before catch-up scanning. Use an explicit
enrollment watermark, bounded batches, backpressure, rotation anchors and
message-ID/digest deduplication. Do not silently reset the cursor or discard
events when anchors or capacity are unavailable. The contract bounds are 16
messages and 256 KiB per batch, with 64 pending deliveries.

Reserve quota and persist a stable delivery/admission request before emitting a
wake or calling a host. One quota reservation belongs to one coalesced host-turn
delivery batch; retries and lifecycle transitions never charge it twice. Later
messages are retained for the appropriate subsequent batch.

Host admission and actual model-turn start are separate observations:

```text
RECEIVED
  -> WAKE_REQUESTED_QUOTA_RESERVED
  -> HOST_CALL_DISPATCHING
  -> HOST_ADMITTED
  -> HOST_TURN_STARTED
  -> PROCESSED
```

An active conversation queues/coalesces a follow-up batch instead of starting an
overlapping turn. Local acknowledgement requires the caller's authorized UID,
an exact delivery tuple and a 256-bit capability token transferred privately,
never through process arguments. Grants enforce owner trust, expiry, revocation,
authority epoch, scope and quota.

A missing admission acknowledgement does not prove the host was never called.
Recover through a supported durable host idempotency key and correlated lookup.
If the host cannot establish the outcome, retain the delivery and quota and hold
`UNKNOWN`; do not blindly create another turn. The Antigravity prototype does
not establish a supported idempotent-admission lookup API. Declare that capability
unsupported and use conservative recovery until independently proved otherwise.

Release cursor locks before every blocking wait, stdout flush, host lookup or
IPC operation. Recovery snapshots state/version under the lock and applies the
result only after reacquiring and checking the current version. The proposed
10 ms lock-hold bound requires measurement; it is not an observed result.

## Candidate publication and fresh CI

The next CI return path extends the accepted CI crate rather than reviving the
older standalone prototype. The proposed control plane stores signed candidate
evidence and a durable two-slot repair-chain reservation before branch push.

Reservation is atomic and idempotent for the same candidate. CI matrix shards
and retries read the same slot without incrementing counters. An uncertain push
retains its reservation. A moved remote branch causes refusal rather than an
overwrite. Normal branch protections, review and deployment gates still apply.

Fresh CI uses a trusted verifier and policy outside the untrusted candidate
checkout. It binds the signed candidate head/tree and commit chain to the actual
checkout being built. A platform-created merge checkout requires validation of
its base/candidate parents and resulting merge tree. Record both the candidate
head and actual tested commit/tree. Missing, expired or invalid evidence fails
closed before candidate build/test execution.

Do not silently dispatch a replacement workflow after a short timer. Any
explicit-dispatch mode needs its own authorization and deduplication policy.

## Execution and acceptance boundaries

The closed alpha implementation task remains closed. New work uses fresh phase
tasks with a pinned reconciled source base/tree, explicit ownership, bounded
budget/deadline, stop rules and acceptance owners.

The planned order is:

1. Reconcile the accepted CI baseline with the thread-instance CLI baseline in
   an isolated working branch, recording the resulting commit and tree.
2. Implement and verify the Rust wait/durable-state contract.
3. Prove each supported host adapter independently, beginning with Antigravity
   and then the Codex host adapter.
4. Implement the conventional CI return path and prove GitHub and GitLab flows
   with their own observed evidence.

Planned acceptance includes a measured no-inference idle window, actual
same-conversation turn start without concurrent human input, burst/active-turn
handling, native message interoperability, authentication and scope rejection,
crash/replay/rotation recovery, and honest unsupported/offline outcomes. Native
delivery, agent processing, actual task execution and visible UI posting remain
separate evidence classes. Reported shell-watcher completions are feasibility
reports, not acceptance of generic host reliability.

Preserve the existing monitor and operational daemons until the replacement
passes the relevant host gates and the owner explicitly authorizes switching.
Checkpoint each coherent authorized change with a described JJ revision, push
its designated review branch, and read back the remote ref. Remote publication
does not waive review, acceptance, merge or deployment gates.

## Provenance

This is a repository-facing summary of the frozen contract and admission review.
It intentionally excludes private runtime evidence, host addresses, credentials,
conversation identifiers and operational configuration. The exact reviewed
artifacts remain preserved separately:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Phase 1 contract package v4 | 70,769 | `166567a578ff907fdcbcd0512d40e3037fd7feb9a37f59c594448d00895b5dcc` |
| Phase 2 admission packet v2 | 12,667 | `88a4648be3c0dfa9bd2df3c4acb7f27ee91aa60ae796ad07f2bbbe42793066c0` |

The admission review corrected implementation budget/deadline omissions and
portable bundle ref names. It did not perform source reconciliation or start
Phase 2 implementation. This public summary does not replace the exact private
admission packet or claim that its runtime acceptance gates have passed.
