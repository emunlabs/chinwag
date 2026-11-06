# Shared workspace scheduler

Phase 0 uses one scheduler authority for every enrolled task source in a workspace. Manual, timer and event triggers share the same admission decision and capacity ledger. A trigger requests reconciliation; it grants no execution authority.

## Admission and original identity

An engineering assignment needs an authenticated qualified assignment, the current enrolled source and exact TaskRef, matching controls and dependencies, current grant and verified time, an approved execution binding, available budget and confirmed compatible capacity/write-scope reservations. A bare task ID, Markdown heading, receiver count or PID observation supplies none of these permissions.

Eligibility comes from the current authority lookup. A caller-created completion DTO or boolean cannot establish accepted dependencies. Only the scheduler can mint its private claim capability after the original assignment and reservations have been durably recorded. Executor invocation consumes that capability.

The assignment ID is the replay key. Identical replay returns the original disposition without another invocation; different bindings under the same ID conflict. At most one active assignment exists per full TaskKey across sources and triggers. An ambiguous invocation remains UNKNOWN and retains its original reservations through reopening. Deadline or lease expiry alone does not establish executor retirement or authorize a replacement.

This first profile conservatively refuses another assignment for a completed TaskKey, including a newer task revision. Explicit rework admission is not implemented here. Confirmed retired work still consumes its recorded budget charge; completed work is not a refund.

## Persisted ordinary fairness

Ordinary sources receive round-robin turns in canonical source-ID order. Within each source, the scheduler retains first-seen task order. The cursor advances only with the durable admitted claim. A blocked source does not prevent an eligible source with nonconflicting resources from proceeding. Manual requests have no implicit priority exception.

Selection uses the requested trigger. Timer and event selection skip sources that permit only manual dispatch; manual selection keeps its ordinary shared-ledger fairness. `select_next_for_trigger` exposes that decision, while `select_next` retains manual selection.

`dependency_blocked_reasons` exposes the latest selection's dependency holds by full TaskKey, including unresolved targets, unavailable source states, cycles and missing or mismatched accepted completion evidence. Unaffected eligible tasks can still proceed. These are observations, cleared on source synchronization and refreshed by selection or admission; they confer no grant.

The scheduler's locked local journal is authoritative for its original admissions and cursor; replicas remain observations. Records and total journal size are bounded. Failed or ambiguous persistence cannot return a usable claim or reopen as an empty authority. Protected file/directory identity and sync checks are part of the journal boundary; ordinary path checks are not claims of arbitrary same-user process containment.

## Current CLI boundary

The legacy bus worker/wake/route interface accepts bare IDs and prose. It has no supported production adapter for qualified assignment, execution binding and shared lease evidence, so engineering dispatch returns HELD_QUALIFIED_SCHEDULER_ADMISSION_REQUIRED before publication, worker registration or engine invocation. The timer remains reconciliation-only. Plain signed publication, inbox/history and historical wire bytes retain their transport meaning.

Roster PID observations describe observed processes, not confirmed scheduler admission. New source code does not install a daemon or cut over a live fleet. Positive controlled fixtures exercise the scheduler contract; they do not approve production host/time/storage/custody adapters.
