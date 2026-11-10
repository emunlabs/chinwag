# Automatic memory checkpoints for installed Chinwag fleets

Status: proposed next-release product contract. Brian requires this behavior
for every enrolled fleet agent and customer installation. Implementation,
independent review, release gates and execution budgets still need admission.
This work is separate from P2.B.R1 bus-wait corrections and daemon lifecycle.

## Customer behavior

Installing Chinwag and enrolling an agent sets up memory continuity for that
agent's supported host. Before the host discards conversation context through
compaction, Chinwag saves the current structured checkpoint, verifies the
durable record and then permits compaction. Resuming the same agent retrieves
its verified state. This must not depend on the model remembering a rule or
on another polling timer.

Customers see the actual capability and last verified checkpoint for each
enrolled agent. An untested or incompatible host cannot appear protected.
The installer explains any host permission/trust review required and finishes
enrollment only when that host's setup and verification have completed.

## Shared native service and versioned host adapters

Implement the product components in Rust. Use one native checkpoint contract
across Chinwag-managed runners and external host adapters. The memory service
owns durable commits, idempotency, exact readback, retention policy and receipts.
The host adapter owns lifecycle correlation, context freshness, the compaction
gate and recovery injection for its exact supported host/version.

For Chinwag-managed runners, put the verification gate directly in the runtime
path that invokes compaction. For external hosts, use documented lifecycle
interfaces under owner-approved installation. Do not use private bridges,
transcript scraping, UI automation, fabricated aliases or authentication repair
to manufacture support. A Codex hook is one adapter, not fleet-wide enforcement.

Current official Codex documentation describes synchronous `PreCompact` events
for manual and automatic compaction and `continue: false` to stop compaction.
It also requires review/trust of non-managed hooks. Local CLI 0.162.1 public
metadata lists compaction hooks; the running desktop's complete coverage has
not been tested. These facts identify a candidate integration, not acceptance.
See [Codex hooks](https://learn.chatgpt.com/docs/hooks).

The installer must preserve unrelated hooks, host configuration, identities
and services. It must not approve its own trust review or silently bypass host
policy. Customer-approved enterprise management may distribute reviewed
adapters under that customer's policy. Upgrades revalidate adapter hashes,
host compatibility and effective trust; uninstall removes only owned entries.

## Checkpoint content and freshness

Maintain structured state during task work and immediately after ratified
decisions, not only when context is almost full. The checkpoint contains:

- Tenant, agent and host conversation identities; task and parent lineage.
- Objective, accepted decisions and current authority/scope boundaries.
- Exact source commit/tree and artifact pointers with content hashes.
- Completed work with its evidence classification and outstanding gates.
- In-flight operation IDs, uncertainty, remaining budgets and deadlines.
- Next action, blockers, checkpoint revision and last covered host-event mark.

The agent/runtime updates that structured record as work changes. A hook alone
does not supply a correct summary. A checkpoint is fresh only if it covers the
required host-event watermark and current task-state revision; wall-clock age
alone is insufficient. Missing or stale semantic state requests a foreground
checkpoint update and keeps strict compaction blocked. The hook must not start
an unbounded summarization agent or upload the full chat to obtain one.

Store concise decisions and recovery state, not raw transcripts, private
reasoning, credentials, token-like fragments or bulk evidence. Use pointers
for evidence. A new agent/session cannot inherit another private identity.

## Commit and verification protocol

1. Receive an authenticated pre-compaction event with exact tenant, agent,
   conversation, host version, event ID and covered watermark. Serialize
   overlapping checkpoint/compaction work for that enrollment.
2. Validate checkpoint freshness, authorization and task lineage. Derive one
   stable idempotency key from the enrollment/event and checkpoint revision.
   Persist the prepared checkpoint/receipt locally before external effects.
3. Commit the exact record atomically to the configured authoritative native
   memory store using that idempotency key and a canonical content hash.
4. Read the committed record by exact immutable ID and verify tenant/agent,
   revision, hash and required durability. Ranked or semantic recall is not
   commit proof. An unchanged key with different bytes is a conflict.
5. Persist a verified receipt bound to that event and checkpoint. Only then
   release that compaction gate. Duplicate requests return the same result.
6. On startup, resume and post-compaction, retrieve the last verified checkpoint
   and relevant authorized tombstones. Bind recovery to the same enrollment
   and expose pending/unknown operations before any replay or new dispatch.

The authoritative store may be customer-local or customer-hosted according to
an explicit installation policy. Local durable commit and fleet replication
are different facts. A temporary local spool does not satisfy a configured
remote-commit requirement. Offline behavior must follow that policy visibly.

Use bounded timeouts and retry limits, reusing the original idempotency key.
After an uncertain write, perform exact read-only reconciliation before any
repeat write. Persist prepared/stored/verified receipts so a crash or IDE
sign-out cannot erase the distinction. A storage ACK, Git push, semantic search
hit or post-compaction callback cannot substitute for the pre-compaction gate.

## Capability and failure contract

Every enrollment advertises one tested protection level:

| Level | Meaning |
| --- | --- |
| Enforced | Every supported manual and automatic compaction path is gated on fresh, durable, exact verified storage, including tested hook/worker failure behavior. |
| Best effort | Checkpoints run automatically, but one or more compaction paths or failure modes cannot be vetoed. Clearly disclose the gap. |
| Unsupported | No supported adapter or required trust/capability is present. Enrollment cannot claim compaction protection. |

An unhandled command failure must not silently turn an enforced enrollment
into best effort. Test missing hook binaries, crashes and timeouts against the
actual host. If the host proceeds in those cases, a hook configuration alone
cannot provide the enforced level; use a supported runtime gate or report the
weaker capability. Do not claim coverage of server-side compaction that bypasses
the host callback.

Missing/stale checkpoints, failed commits, missing/mismatched exact readback,
revoked authority and unavailable required storage keep an enforced gate closed
with a clear actionable reason. Do not create repeated inference turns to check
the condition. Any customer-approved emergency bypass is explicit, auditable
and removes the enforced claim for that event; it never fabricates success.

Isolation applies to both storage and recall: tenant-scoped keys, least-privilege
per-agent permissions, owner-controlled sharing, retention/deletion policy and
no cross-customer default bank. Internal `spector-fleet` is not a customer bank.
Keep signing keys and provider authentication outside checkpoints and receipts.

## Acceptance before release

Qualify each advertised host/version using synthetic, non-sensitive tasks:

- Fresh install, required trust review, enrollment and an exact verified save.
- Manual and automatic compaction with a correlated save/readback before the
  actual compaction event; recovery in the same agent/conversation afterward.
- A ratified decision followed immediately by compaction; stale/missing state
  must not pass. Exercise event-order races and concurrent compaction requests.
- Storage unavailable, write ACK lost, exact readback missing/hash mismatch,
  search-index lag, duplicate events and expired/revoked credentials.
- Crashes before/after each durable transition; restart/reconciliation must
  preserve one logical checkpoint without duplicate uncertain effects.
- Hook launch failure, killed worker, timeout, untrusted hook, host upgrade and
  a compaction route without a callback; capability reporting stays honest.
- Tenant/agent/conversation mismatch, private-agent and customer isolation,
  malicious checkpoint fields and secret/transcript exclusion.
- Installer repair/uninstall preserves unrelated configuration; zero extra
  polling/inference while idle; bounded latency and local resource use.

Publish an evidence-backed host support matrix. Fleet rollout and customer
installation acceptance require the actual native record and lifecycle traces,
not merely installed files, a live process or a successful memory write response.

An internal observation motivates the exact-read gate: a native retain reported
stored, but two bounded targeted recall attempts did not return the new record.
Its readback is unverified; the cause is not established. The release must
provide and prove an exact record read interface rather than depend on search
ranking. The current CLI's published help lists retain/recall/tombstone/stats;
no exact-ID read command was observed. Any new API is proposed work.
