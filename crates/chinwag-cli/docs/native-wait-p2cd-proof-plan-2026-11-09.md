# Independent P2.B review and P2.C/P2.D same-chat proof plan

Status: **proposed execution plan; review coordination requested**. Brian has
authorized GEM to coordinate independent P2.B review and asked for this plan.
This document does not start P2.C/P2.D, install a candidate, replace a running
daemon, or change the existing two-minute monitor.

## 1. Immutable review input and independent responsibilities

Review P2.B commit `f060968ce669849edc3d47b4f3388ef05f590e7d`, tree
`2d5f54e37b1c3debead42e1082247511d8bd5832`, against base
`d326c7129979ca43499547842daac076d80fac35`, tree
`69c3b294b10a74190b894e2be486138c61772d83`. Its runtime implementation is
identical to tested ancestor `737ea7d4c2aa66ddd1cd8ff1f44a28743e9247e8`;
the final child adds only the author verification record. A later planning-only
commit must not silently change that review target.

The normative inputs are Phase 1 v4, SHA-256
`166567a578ff907fdcbcd0512d40e3037fd7feb9a37f59c594448d00895b5dcc`, and
the admitted P2.A/P2.B packet v2, SHA-256
`88a4648be3c0dfa9bd2df3c4acb7f27ee91aa60ae796ad07f2bbbe42793066c0`,
with Brian's direct extensions and corrective continuation. The author results
are in `native-wait-validation-2026-11-09.md`; they are not independent proof.

| Owner | Independent P2.B responsibility | Required output |
| --- | --- | --- |
| GEM | Coordinate fresh bounded review admissions and actual supported reviewer routes | Assignment/operation IDs, exact inputs, budgets/deadlines, dispatch/result evidence, consolidated disposition |
| ARCHITECT | State machine, source/contract scope, lock boundaries, batch/quota invariants and per-host identity binding | Exact-revision technical verdict and blocking contract gaps |
| ALISTAIR | Original signature/digest domains, compiled pins, signed body/grant authority, local token/tuple/UID enforcement | Concrete rejection cases and security verdict |
| FLINT | Lost ACKs, crash cut points, replay/rotation, coalescing, version races and uncertain outcomes | Independent counterexamples or an explicit bounded no-finding verdict |
| QA | Derive and execute independent checks on the exact revision in isolated state | Actual command/tool evidence, results and retained log hashes |
| Root | Supply source/evidence and preserve the canonical writer boundary | No self-acceptance; proposed rework only until separately admitted |

Each review needs its own attributable reviewer/instance, actual engine/route,
input hashes, permitted tools, work/token/resource ceiling, enforced absolute
UTC deadline, original operation ID, output hash and verdict. Text from one
subagent under several reviewer labels is not independent review. ACK,
readiness and a dispatch request do not establish review execution. Preserve
uncertain operations instead of automatically retrying them.

Review/QA uses isolated owned checkouts, build targets and fixtures. It does
not edit product source or use the dirty operational checkout as writable
source. Review budgets are separate from the completed P2.B writer budget.
Missing routes or admissions are reported explicitly. Findings that change
runtime bytes require a new immutable candidate and applicable revalidation;
the reviewers then accept or reject that exact revision.

## 2. Entry gates before either host trial

1. Independent P2.B review is accepted for the exact candidate and any required
   rework is accepted. A source-only acceptance must not be described as a
   host-runtime pass.
2. GEM prepares a fresh stage admission with the operator, source/tree and
   binary hashes, host/API versions, target identity, approved transport,
   fixture ownership, allowed tools/files, work/token/resource budgets,
   runtime wake quota, absolute UTC deadline and independent acceptors.
   The P2.A/P2.B extensions do not supply a new host-execution budget.
3. The owner explicitly enrolls the existing target conversation with signed
   trial authority/grant artifacts, an explicit watermark and a scoped trial
   task. No key creation, auth repair or account/session scanning is implied.
4. Trial state, logs and compatible candidate transport are isolated from the
   operational `:44330` daemons. The older operational binary does not supply
   the new change-hint frame. A distinct compatible trial route therefore
   needs explicit admission: exact endpoint/port/profile, lifetime and owned
   process handles. Do not invent a forwarding route or use another seat's
   signing material. If fresh originals cannot reach that isolated route
   through an approved mechanism, report the dependency and stop.
5. Competing wake sources are attributable. The protected monitor remains
   active. Existing shell prototype watchers are not silently killed or
   adopted; their owner must establish isolation or causal attribution.
6. A single supervisor serializes trial operations. There is at most one
   outstanding ambiguous admission per target chat. No crash injection touches
   a protected daemon, global provider process, other chat or authentication.

No service or monitor switch follows automatically from successful trials.

## 3. Host-specific capability gates

### P2.C — Antigravity on the existing engineering conversation

GEM identifies the supported background-task mechanism available in that
existing conversation, its actual version and how it exposes actual turn start,
completion and active/idle state. A shell process exit is a handoff observation;
it does not prove the conversation woke while genuinely idle.

Use `supports_idempotent_admission_lookup = false` for this profile. A committed
handoff with a missing admission ACK must hold
`HELD_UNCERTAIN_PRE_ACK_OUTCOME`, exit `75`, preserve originals and quota, and
not blindly emit another wake. Queued/admitted/started ambiguity holds the
corresponding host outcome. A prior prototype completion or GEM's report of it
is feasibility context, not independent reliability or zero-inference proof.

### P2.D — Codex on the pre-existing Root chat

Read-only local inspection of installed `codex-cli 0.162.1` produced public
app-server schemas offline, without starting app-server or connecting to a
chat. The help labels that interface experimental. The observed schema
metadata is useful for an adapter design, but supplies no live desktop access
or reliability guarantee:

| Observed public metadata | What it supplies | What remains unproved |
| --- | --- | --- |
| `thread/resume`, required `threadId` | Existing-ID resume/rejoin request shape | Ability to reach the existing desktop-owned Root thread |
| `turn/start`, required `threadId` and `input` | Request/response shape; optional `clientUserMessageId` and `turnTrigger` | Durable admission idempotency or a lookup by Chinwag request ID |
| `turn/started` / `turn/completed`, each carrying thread and turn | Candidate lifecycle observations for correlation | An independently captured actual start/completion in the enrolled Root chat |
| `thread/status/changed` | Idle/active/status observation shape | Atomic reject-or-queue semantics across other admission paths |
| Active-turn start/steer descriptions | Inputs may add to or steer an active turn | P2's required one coalesced follow-up after the active turn closes |
| `thread/read` / `thread/turns/list` | General read/history shapes | Definitive `NEVER_RECEIVED` proof after a lost admission response |

JSON-RPC IDs and `clientUserMessageId` must not be promoted into an idempotency
contract. An unrelated account-operation `idempotencyKey` is not a turn API.
Keep admission lookup capability unknown/false until a supported implementation
and explicit semantics are proved. If the provider has no distinct admission
ID, reviewers must approve an honestly attributed adapter receipt mapping;
do not invent a provider-issued ID or treat a response as a start event.

There is a concrete identity question before a Root-targeted trial: the native
Root actor instance and the Codex app monitor's target chat ID are different
identifier strings, while the current grant verifier requires
`actor.instance == conversation_id`. Their equivalence is not established by
the public schema. ARCHITECT/ALISTAIR must reconcile the host mapping or approve
a narrowly scoped contract/implementation change before P2.D. Do not rename
Root, substitute an app UUID into its native identity, treat a session-tree ID
as an alias, or demonstrate a new/child chat and call that a Root-chat pass.

The active-turn/monitor race is also an entry question. A local adapter mutex
only serializes calls through that adapter; it does not automatically serialize
the unchanged monitor or human input. Establish supported host serialization
or reject/hold safely. A status check followed by an unconstrained `turn/start`
is not evidence of atomic serialization.

## 4. Exact evidence chain and data handling

For every positive trial, independently retain:

`trial ID -> signed original ID/digest -> actor + grant/epoch + existing host chat ID
-> delivery ID -> admission request ID -> admission receipt -> actual host turn ID
-> observed consumption/completion -> authenticated PROCESSED`.

Capture event ordering with monotonic time plus UTC, host/API and binary
versions, state version/hash and quota before/after. Subscribe to host lifecycle
events before admission so a fast start cannot be lost. Check the exact host
chat ID on both response and events, and reject child/new-thread substitution.

`wait-ack` is a local authenticated state claim; independent host events must
substantiate it. A minimal positive payload asks only for its unpredictable
trial nonce to be returned, with no product/tool task. Record the nonce-bearing
input/consumption observation and matching completed turn. Chat consumption is
separate from successful execution of any engineering task.

Keep tokens, owner material, raw private evidence and original message bodies
out of public Git. Public reports carry hashes and compact observations. Raw
handoff tokens never enter argv or reports. Rejected controls use non-waking
typed messages; there are no ACK-of-ACK or obligatory working turns.

## 5. Functional proof matrix, separately on each host

Trial counts below are proposed admission limits, not instructions to run now.

| Gate | Proposed bounded trial set | Required observation / failure behavior |
| --- | --- | --- |
| G-01 | Antigravity: two 10-minute idle windows if competing wakes can be excluded. Root/Codex: two fully observed 45–60-second quiet windows between monitor turns, if feasible | Zero inference requests and zero empty-poll turns in the declared window, with host and provider telemetry, RSS and CPU. Any unrelated wake invalidates the quiet window; missing telemetry is UNKNOWN |
| G-02 | Six sequential signed idle wakes | Existing chat stays the same; complete correlation chain; actual turn start within proposed 60-second observation bound; no concurrent human input |
| G-03 | Single active-turn arrival, a 16-message active-turn burst, and a 65-message pending/backpressure episode | One coalesced follow-up at a time; at most 16 messages/256 KiB; preserved messages and one reservation per batch; no overlapping or silently steered turn |
| G-04 | Preserved-original interop plus signature/digest, JCS receipt, malformed body, unsigned outer mutation, recipient/mention, scope and local ACK rejection families | No rejected input creates host admission; wrong-UID checks use only an explicitly admitted fixture runner |
| G-05 | Seven cuts: before reservation, after reservation, host accepted before ACK, pending-active, admitted, started, after processed | Exact quota preservation and deduplication. Supported lookup only where actually proved; otherwise honest UNKNOWN/held outcome, never blind retry |
| G-06 | Reconnect/replay, exact-anchor rotation, missing anchor, unsafe paths/links/permissions/UID, expiry/revocation/epoch | No duplicate admission; no silent cursor or quota reset; unsafe or stale authority refuses |
| G-07 | Five-second timeout, offline host, unsupported host | Exit/status consistent with observation; cursor intact and lock released; no false admission/start timestamps. Measure bounded lock duration rather than assuming the 10 ms target |

The monitor creates a specific evidence limitation: a ten-minute window in the
same Root chat cannot be called zero-inference while its two-minute inference
monitor remains active. Component-attributed watcher telemetry is still useful
but is not a whole-chat G-01 pass. Short quiet windows must be independently
observed and free of both monitor and human turns. Do not change the schedule
or silently subtract monitor inference from an unqualified claim. If no valid
window exists, report that part unproved while preserving the monitor.

An expected UNKNOWN crash result can satisfy the refusal requirement while
leaving a host operation unresolved. Preserve its state and stop further starts
in that target chat until supported evidence or an explicit owner disposition
retires the operation. Do not open another repository, grant epoch or chat to
evade an uncertain reservation. Perform non-ambiguous/clean trials first and
place disruptive ambiguous cuts last where possible.

## 6. Bounded qualification and proposed resource envelope

After functional acceptance, propose 30 consecutive clean, genuinely idle,
nonce-only wakes per host/profile. Require 30 observed matching-chat start and
consumption chains, zero duplicates/overlaps/wrong-chat starts, and recorded
timeouts plus p50/p95/max observed start latency. Any failed or confounded trial
remains in the denominator and report; do not erase it by restarting the count.
This finite qualification supports only the tested profile and cases, not a
general availability percentage or universal logout/restart guarantee.

Proposed admission ceilings, to be ratified before execution:

| Admission | Proposed limits |
| --- | --- |
| Functional proof per host | 90-minute wall limit; at most 28 reservation-bearing batches, including held outcomes; signed runtime quota no greater than 32; one outstanding operation per chat |
| Qualification per host | Separate 75-minute wall limit; 30 positive trials within one separately owner-approved quota no greater than 32; no unresolved prior operation; no implicit grant renewal/reset |
| Each normal wake | One short nonce-only model response; proposed 60-second start observation limit; no tool/product task |
| Work/resource controls | Fresh work turns, total model/context/token and monetary limits, Cargo/host-call limits, RSS/CPU caps and absolute UTC deadline recorded before dispatch; no silent fallback or automatic extension |

These are separate functional and qualification admissions, not permission to
roll grants or reset counters in order to finish. Existing create-only
enrollment and any renewal/migration limitations must be resolved explicitly.
Model costs include real host-context input, not merely the short output.
Provider limits and inherited quotas are not inferred from an account name.

## 7. Stop conditions, decision and protected operations

Stop and retain original evidence on a wrong/new/child-chat start, duplicate or
overlapping turn, unobserved admission/start claim, lost original, quota reset or
double charge, unsafe ACK/path acceptance, blind uncertain replay, candidate
drift, exhausted admission limit, missing required capability, or any proposed
disturbance of protected services. A missing observation is UNKNOWN, not PASS.
Only the admitted trial supervisor may terminate its own known fixture handles;
never kill a foreign process or repair auth/routes to make a trial pass.

GEM consolidates exact-revision independent results. QA and the named technical
acceptors decide G-01..G-07 for each host separately. Root records acceptance
only from their actual decisions. P2.C acceptance does not imply P2.D support.
The existing daemons and single two-minute monitor remain untouched throughout;
even an accepted host proof requires a separate explicit Brian instruction
before any operational switch.
