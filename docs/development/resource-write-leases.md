# Shared write-resource leases

The Phase 0 resource authority is shared by task sources and worktrees in one admitted repository resource domain. A different task-source ID does not create a different lock. The scheduler's assignment journal and the repository's resource journal have separate pinned identities and separate durable phases; they are not one distributed transaction.

## Scope and conflicts

A file reservation includes its canonical parent directory and exact basename, including before the file exists. Existing device/inode identities also participate so physical aliases conflict. Directory ownership conflicts with descendant paths by components. Symbol requests require exclusive ownership of their containing file until a transactional AST writer is supported.

Logical paths targeting the same integration branch conflict across separate worktree directories. Approved isolated branches can avoid that logical conflict, but cannot avoid physical aliases or shared Git resources. Worktree indexes and shared refs, notes, common-directory operations and integration targets need their actual resource identities.

The initial controlled path profile is conservative. Unsupported aliases, traversal, symlinks, missing parents and ambiguous normalization remain held rather than selecting another path. Exact request spelling is retained; conservative case-conflict detection is not a rewrite of a signed TaskRef.

## Assignment and reservation

Requests and public DTOs describe desired resources. They do not grant write authority. The scheduler must first verify the original durable assignment and its exact TaskRef, owner, baseline, operation, epoch and deadline. A usable write capability additionally requires a confirmed durable reservation in the actual admitted resource store.

`qualify_for_lease` verifies the original scheduler claim. `ResourceLeaseStore::prepare` returns either a private preparation capability or `LeasePreparation::Existing` with the recorded disposition. Exact replay does not mint another capability or move the original deadline. Commit returns the sealed capability required by `invoke_with_lease`; the earlier unleased invocation exists only in controlled scheduler tests. `ProtectedWriter::write_file` checks the current assignment binding and persists its observed-time watermark before the file effect.

Acquire the complete scope set deterministically. A conflict cannot leave a partially usable capability or invoke a writer. Persist original preparation and commit identities through recovery. An uncertain commit or invocation retains the original reservation; a new assignment ID is not a recovery mechanism.

The existing `chinwag-claim` maximum TTL remains **120 seconds**. Expiry fences further protected writes; it does not establish that a previous executor or filesystem writer retired. Conflicting work remains held until the admitted retirement protocol proves a safe transfer. A PID observation, cancellation, status change or caller-provided quiescent label supplies no such proof.

Retirement evidence also names the exact current durable lease phase. Invocation and checked-write records advance that phase. A proof made before a later effect cannot release that effect's UNKNOWN reservation, including when the old proof arrives late. The retirement record retains its witnessed predecessor phase for replay validation.

## Protected effects and limits

The supported invocation boundary requires the original scheduler capability and a committed lease capability. Before each protected effect, revalidate current authority, generation, owner, original assignment/deadline and filesystem scope. A protected writer must not expose writable handles that escape those checks. Replacement must retain the pathname reservation and old/new alias evidence through any uncertain outcome.

The initial protected mutation is a bounded in-place write to an existing single-link file covered by a file or promoted symbol reservation. Directory and Git scopes can reserve conflicts, but grant no general filesystem or Git command interface. Missing filenames can be reserved, while creation and atomic replacement are unsupported write operations. A changed target or parent holds further writes and retains the original reservation; it is not permission to adopt the new inode. Shared refs and integration-target reservations serialize conservatively because packed refs and case aliases can share backing resources.

This is a cooperative checked API boundary, not an OS sandbox. It cannot revoke arbitrary foreign descriptors, prevent unrelated same-process filesystem calls, preempt a kernel write already in progress or prove provider cancellation. Production time, host, storage and retirement adapters require their own supported authority; the controlled fixture profile does not approve them. A public boolean, matching pathname, lease ID or serialized row cannot enable an unsupported production adapter.

The trusted caller supplies the root and common-Git directory's binding in the wider namespace. Retained descriptors and checks beneath that root do not independently detect a rename of the root's external pathname. The later execution-binding unit supplies that separate approved-worktree mapping; this lease unit does not manufacture it from a directory handle.

No live daemon, scheduler cutover, networking route or production store migration follows from this source unit. Review and merge evidence must name the exact tested commit and retain these limits.
