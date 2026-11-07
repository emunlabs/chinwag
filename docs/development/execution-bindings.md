# Repository and store execution bindings

P0-09 separates ordinary repository selection from task execution authority.
An explicit `--repo` wins over `CHINWAG_REPO_ROOT`, then discovery from the
current directory. A present invalid selector fails; it never selects a home
directory or a different repository. Discovery stops at the nearest Git
repository. A nested repository is a separate identity. Linked worktrees retain
their own Git directory and their shared common Git directory separately.
Revalidation rejects a newly introduced common-directory mapping and verifies
Git's effective worktree against the retained root, including repo-local
`core.worktree` overrides that leave HEAD and branch unchanged.

`--crdb` is an independent, exact storage selector. Its filename does not select
a repository or establish a workspace identity. A missing or mismatched store
does not create another store, run a migration, or clear retained operation
markers.

`RepositorySelection` retains read-only directory and Git metadata observations.
It permits ordinary inspection and plain publication; it is not a task grant.
`WorkspaceExecutionBinding` is a separate sealed value constructed only after
current trusted enrollment. It binds the workspace, repository and executor
worktree; root identity and generation; Git baseline, branch or approved detached
state, integration target and exact overlay bytes; and the exact store identity,
path, image, site, application and schema. The canonical task-source checkout
and its enrollment remain separate from the executor checkout. A copied task
file grants no source authority.

The public execution authority is currently **Unsupported**. Positive execution
tests use private, controlled enrollment; no CLI switch, environment flag,
request DTO or matching binding ID can enable that profile in the shipped
binary. A successful binding also grants no new scheduler, lease, provider or
human connector permission.

The scheduler checks the binding before consuming a fresh admission, before
qualifying a write lease and immediately before its executor callback. It joins
the current TaskRef and source-root mapping to the same commitment. The lease
store independently checks the executor root, worktree/common Git identities
and integration target. Unbound historical scheduler helpers compile only in
private tests.

All four route adapters carry the selected context:

- The bus preserves ordinary `PUBLISH_ONLY` sends. Legacy worker, wake and route
  requests remain held; combined send-and-wake refuses before publication.
  The admitted-worker seam requires the current scheduler, sealed claim, current
  execution binding and independently committed write capability together.
- Agent dispatch binds before persona, memory, signing, engine construction or
  persistence. Local engines use the approved process directory and any engine
  cwd argument. Worker launch removes inherited and explicitly supplied `GIT_*`
  overrides before installing only the fixed configuration isolation and the
  validated seat-signing configuration. Every engine and permitted fallback
  rechecks the binding.
  An unknown started engine is not replaced by another engine. A local pathname
  cannot authorize a remote checkout, so an unmapped remote route is held. Pool
  dispatch and the hosted executor's `run_command` tool are also held while they
  lack an adapter that carries this workspace binding into their worker and
  persistence operations.
- Feature entry points use retained selection for ordinary OpenSpec, plugin,
  card, bond and public A.509 inspection. Protected mutation/signing effects
  require the separate binding before their first effect. Legacy task exports
  are explicitly unqualified observations.
- Workbench retains the same selection in its server context and propagates it
  to feature and bus requests. Request handling does not rediscover a repository
  from an HTTP worker's ambient directory. Its task preflight precedes ordinary
  publication when a wake is requested.

Native store validation imports only trusted controlled private image bytes
into isolated memory, validates the exact pinned schema/site/bootstrap contract,
and explicitly checked-closes before returning a receipt. It creates no file
lock or store. This receipt is image evidence, not workspace enrollment.

Native persistence uses one original sealed owner and one original operation.
Only that owner's proof can account for its own lock while checks continue
through preparation and commit. Foreign or uncertain markers remain held. A
completed replacement changes the store inode: the route stops afterward and
does not silently adopt a new binding or issue additional retention writes.

Controlled tests link the actual route cores into the library's private test
profile. Owned Rust fake children report the observed process directory and
store/binding context. Binary tests separately exercise public refusal ordering,
retained nondefault HTTP/feature selection and the absence of effects on
refusal. These tests do not prove production host scheduling or provider
execution. They do not authorize a live store migration or fleet cutover.

Descriptor and namespace checks detect observed drift. They do not provide an
atomic pathname-to-exec primitive, preempt an uncooperative process, or remove
same-UID filesystem races. No OS containment, rollback, provider retirement,
production host/time adapter or networking relay proof is claimed here.
