# P2.B.R1 corrected approval proposal

Status: PROPOSED; requires Brian's explicit approval before execution.

This is a Root-authored correction to GEM's preserved R1 v1, SHA-256
`37be4e1c9da4268a108220b1a07d323a4b507158c1f9a58ae9893da5a392c576`.
GEM's agreement to these corrections has not been observed. The delivered
clarification has a verified remote journal ACK; that receipt does not prove
processing. This proposal preserves the original findings and review outcomes.

TaskRef: `CHWG-WAIT-CI-P2-BUS-WAIT`; new stage: `P2.B.R1`.
Sole writer and integrator: WORKHORSE (Codex).

The starting source candidate is commit
`f060968ce669849edc3d47b4f3388ef05f590e7d`, tree
`2d5f54e37b1c3debead42e1082247511d8bd5832`, on
`workhorse/review-wait-ci-p2-20261109`. Its tested runtime ancestor is
`737ea7d4c2aa66ddd1cd8ff1f44a28743e9247e8`, tree
`f7ff40e80f3571baaaa08d1ff4f957346a2e4b26`.
This document's planning commit is not a replacement source candidate.

## Why rework is needed

Author checks passed on the original candidate. Independent ARCHITECT and QA
returned HOLD, ALISTAIR returned a scoped PASS, and FLINT timed out without a
verdict. The review records preserve token/Cargo budget variances and failed
attempts. Neither a completed process nor this proposal closes those gates.

## Owned changes and required evidence

All source, fixtures, regression tests and implementation documentation stay
within `crates/chinwag-cli/**`. Rust 1.97.1 and existing dependencies remain
pinned. The frozen Phase 1 v4 contract remains the authority except for the
explicit actor/conversation binding correction below.

| Change | Required behavior and acceptance evidence |
| --- | --- |
| R1-01: stable held states | Repeated restart preserves both held classifications, original witnesses and accounting. Include `PENDING_ACTIVE_TURN -> HELD_UNCERTAIN_HOST_OUTCOME` with reserved, uncharged quota. A held no-op does not save or increment the cursor version. |
| R1-02: owner reconciliation and quota | Implement `ALREADY_PROCESSED` using validated reservation/charge flags and original evidence, never the held-state label alone. A reserved, uncharged operation converts one reservation into one used slot, including held-host reached from pending-active. An already charged operation retains its single used charge. Reject inconsistent accounting without mutation. Record exact original witnesses, make the disposition terminal and unlink the token after the durable transition; never free consumed quota. |
| R1-02: never received | Accept `NEVER_RECEIVED` only for a provably applicable pre-admission outcome. Validate owner signature, actor, delivery/admission tuple, cursor version, expiry and original witnesses. Preserve delivery identity, admission request identity and the reserved slot; clear stale admission/turn witnesses. A known admitted or started operation cannot be reset through this disposition. Invalid/stale/replayed proof cannot change accounting or restart host work. |
| R1-02: startup and idle durability | Lock before the initial cursor snapshot. Release the lock before host lookup/IPC, output or blocking wait; reacquire and compare the authoritative version before applying results. Test concurrent version changes and skip writes when scans/recovery change nothing. Preserve the single-store crash-consistency and private-token safeguards. |
| R1-03: archive traversal | Support both declared archive layouts, visit every intermediate generation through `A -> B -> current`, and establish continuity from validated journal evidence. Filename or timestamp order alone is insufficient. Both `wait()` and pending-active ACK draining must deliver the intermediate originals once. Missing anchors/generations, conflicting originals or unprovable ordering fail closed without advancing past the uncertainty. Preserve bounded reads and safe-path protections. |
| R1-04: signed actor/chat binding | Permit the owner-signed enrollment to bind a qualified native actor to a different exact host conversation ID. Keep actor qualification, trusted issuer, epoch, revocation, expiry and exact caller/grant/target matching. Reject altered signatures, wrong actors and wrong conversations. Introduce no implicit alias or identity migration. This proves grant validation, not live desktop access or same-chat wake. |
| R1-05: notification ordering | Explicitly implement the frozen subscription-before-catch-up ordering. A deterministic arrival at that boundary must remain visible once, including rotation and concurrent cursor changes. A mark-recheck alternative requires a separately accepted contract disposition and cannot silently count as closing this finding. |

For successful changes, preserve meaningful pre-fix behavioral failures where
feasible and the corresponding passing results. Fixtures use canonical macOS
temporary paths; production symlink guards remain enforced. Crash cases must
show a durable state from which restart cannot free quota, double-charge,
silently skip an original, or blindly repeat an uncertain host operation.

## Fresh budget and stop rules proposed for approval

The previous P2.B wall budget is exhausted. R1 needs a fresh admission; its work
does not borrow unused capacity or a deadline from the previous stage.

| Limit | Proposed ceiling |
| --- | --- |
| Writer execution turns | 3 |
| Gross LLM input plus output, including cached input | 250,000 tokens |
| Uncached input plus output | 80,000 tokens |
| Cargo invocations, including failures and reruns | 12 |
| Wall time, including verification/checkpoint/handoff | 35 minutes from admitted start |
| Paid subagent dispatches | 0 |
| Absolute deadline | **2026-11-10T04:00:00Z** / Nov 9, 10:00 p.m. CST |

The replacement deadline is a proposal requiring Brian's approval. GEM v1's
03:30Z deadline cannot provide a full 35-minute window to a start after 02:55Z.
Execution stops at the earliest applicable budget limit or absolute deadline.
Use separate cumulative counters for gross and uncached tokens. If actual
usage cannot be accounted for under these caps, hold rather than assume room.

Use the approved private CRSQL input environment without publishing it. Reserve
Cargo capacity for the complete CLI suite, targeted original-verification
checks and strict clippy; failed commands and red-green cycles count. Normal
test-and-fix cycles inside owned files are permitted within this budget. Stop
on an untouched-crate failure, exhausted budget/deadline, an unresolved final
gate, or a scope/authority change. Do not claim completion by skipping a gate.

## Checkpoints, acceptance and operational boundaries

Before feature edits, reconcile and report the exact source base commit/tree
and retire any conflicting writer claim. After each coherent change, create a
described JJ checkpoint, push the designated source review branch and read
back the exact remote ref. Keep the planning branch separate.

Writer completion is done-pending-review. GEM coordinates any freshly admitted
independent review of the exact new candidate with named acceptors, immutable
inputs and explicit per-review budgets/deadlines. The original ARCH/QA holds,
FLINT no-verdict outcome and review variances remain visible until their
proper dispositions. Preparing this proposal does not dispatch a review or
authorize a retry. The author cannot self-accept R1.

Retain original review receipt bytes privately with immutable archive paths
and hashes. A digest alone is not preservation of the original. Quarantine the
unsanitized ARCH receipt; use its sanitized derivative for reviewable packets.
Do not publish raw transcripts, token-like fragments or private runtime state.

Existing operational daemon binaries, profiles, identities, routes and the
single two-minute monitor remain untouched. Session-independent daemon
lifecycle and automatic fleet memory checkpoints are separate release work.
R1 does not authorize P2.C/P2.D host trials, host enrollment, service actions,
authentication changes, merge, release or deployment. Reliable same-chat wake
and zero-inference idle proof remain future acceptance gates.

## Owner decision

Approve or reject this exact Root-authored proposal, including R1-01 through
R1-05, the explicit signed actor/chat binding correction, iterative test rule,
fresh ceilings and proposed 04:00Z deadline. Approval admits only the bounded
R1 writer stage; independent acceptance and later host stages retain their
own gates. Record the approved document hash with the owner decision.
