# Direction for selected owned work

The explicit `team-work` mode provides one direction composer for up to four owner-local work members. Each member holds an existing Codex, Claude Code or Gemini CLI port in the same process. Opening the Team window, selecting a member or opening its existing work window starts no external task. Initial Start and its provider policy stay in that member's native work window.

A member ID or role label is presentation, not an enrolled agent/account identity. This host cannot adopt another app's windows, private conversations or transports. Existing standalone modes and state stay separate.

## Explicit launch declaration

```sh
/owner/chinwag-desktop-alpha team-work \
  --config /owner/private/team.json \
  --state-root /owner/private/team-state
```

The launch file is an owned private regular file, bounded to16KiB. Its strict schema rejects unknown and duplicate fields. It accepts no commands, argument lists, environment, credentials, session imports, model/provider overrides or remote endpoints.

```json
{
  "schema": "chinwag-team-launch/v1",
  "members": [
    {"id":"codex-ui","label":"UI work","provider":{
      "kind":"codex","owner_socket":"/owner/private/dedicated.sock",
      "workdir":"/owner/work-ui",
      "runtime_policy":"dedicated_runtime_with_explicit_login"
    }},
    {"id":"codex-review","label":"Review","provider":{
      "kind":"codex","owner_socket":"/owner/private/dedicated.sock",
      "workdir":"/owner/work-review",
      "runtime_policy":"dedicated_runtime_with_explicit_login"
    }}
  ]
}
```

Two distinct fresh Codex ports may use the same dedicated listener, with separate owned threads, targets and journals. The Team Host does not start that listener. Each Start retains the existing dedicated-runtime/global explicit-login declaration and first-owned-turn lifetime.

Claude providers declare `kind`, `binary`, exact lowercase `sha256`, `workdir` and `startup_policy: "managed_policy_prose_only"`. Gemini uses the same fixed fields with `startup_policy: "configured_runtime_effects_manual_mode_extensions_disabled"`. Their original policies remain applicable. Claude is not a zero-side-effect sandbox. Gemini's normal settings, hooks, auth refresh, native tools, MCP and helper/model startup can have effects after human Start. Chinwag does not inspect, rewrite or copy environment/provider configuration; the child retains native inherited environment/configuration behavior.

The state root freezes the launch declaration and derives separate `actions/` and `members/<id>/native/` journals. Duplicate held ports, journal aliases, foreign/partial domains and changed files fail closed. Construction is startup-only: on error the fresh entry process exits before app mount, without fallback or retry. An inert native owner thread may already exist; the error does not claim all owners joined or locks were released in a reusable process.

## Explicit native actions

The editor remains available while work runs. The inline plan names recipients, their actual actions and blocked members. A blocked selection sends nothing until the human deselects it or chooses a separately named ready subset. Becoming eligible never sends automatically.

| Member | Direction behavior |
| --- | --- |
| Codex | Steer the captured exact active turn; no new-turn fallback. |
| Claude | Use the visible Now, After tools or After turn choice. Now may interrupt and follow in another turn; no expected-turn comparison is invented. |
| Gemini idle | Send a new prompt after the old response and cancellation window retire. |
| Gemini busy | No team text action. Cancel and a later human Send remain separate actions. |

The click captures one absolute30-second effect deadline and prepares every effective target read-only before persistence. Preparation reserves no flight, increments no sequence, consumes no ID and creates no session. Initial capture failure means zero effects. Opaque tokens cannot be cloned or reconstructed from audit data. Persistence and submission never renew the deadline.

Prepared-to-Admitted handoff checks a local input sequence, obtains a queue permit and mints an owning ticket. Newer direct input can invalidate an older unsubmitted token; it does not revoke an already admitted input merely because the latest counter changed. Final native gates retain original target, deadline, native lifetime and revocation checks. Lookup/status/output cannot release another input's ticket or renew control. Native owner lifetimes remain distinct.

## Durable intent and partial outcomes

The parent action journal saves the original selection, explicit effective subset, exclusions, exact text, target audits and child IDs before any child invocation. A durable once-only member claim precedes each call. Existing child journals remain the source of native evidence; this is not an observer store or identity registry.

There is no cross-member atomic commit, rollback or recall. Later expiry, revocation, local input or storage failure can yield partial results. A claimed member with a missing child receipt is unknown and is never retried. An unclaimed member is never-invoked-by-this-parent only under the enforced claim-before-call invariant. Successfully committed claims stay in the live cache even if a following append fails. Recovery never recreates tokens/leases/IO or resumes fanout.

Queue admission, durable child intent and native evidence stay independent. Codex Core acceptance/harness recording differ; Claude replay/reply/result differ; Gemini has no cancel ACK or reliable per-input update attribution. No aggregate label claims ModelSeen, Applied or that the whole team received a direction.

A short flight plus a consumed human revision rejects repeated clicks without disabling editing. Flight retirement or delayed status cannot rearm unchanged input. Clear only exact matching child intents with full-frame evidence and no known uncertainty/rejection, plus unchanged edit identity/text/selection/options/bindings. Partial/excluded/known-unknown results retain text. Later failures stay in history and cannot overwrite newer drafts. A follow-up or new direction requires another explicit human action.

Local submission-stage results remain keyed to their original parent, including failed saves. Read-only original-record checks retain a separate latest result per known immutable parent. Queue admission orders their serials; a later completed check of that same parent can retire an older pending check, using the later check's actual outcome. The known-parent union includes recovered records and live submission attempts, capped at128 without eviction. Checks request native original lookups without claiming fresh child reads or live connection health.

One retained actor samples native watches; API/Quit callers only signal a bounded publisher. Closing/reopening the Team window retains owners and draft. Show Team focuses the exact owned window. Quit fences team admission and applies existing per-owner Close/EndInput semantics within one bounded local wait, without OS termination or all-work-stopped claims.

## Verification boundary

Rust fixtures cross actual production ports/journals using controlled external IO, including two Codex ports over a synthetic Unix WebSocket listener, Claude/Gemini actors and headless native Start, direction, Cancel and window controls. They exercise deadlines, ordering, claims, recovery, capacity, aliases, revisions and shutdown. They run no real connector CLI or model. A real multi-member revised-reply/artifact trial remains an explicit human acceptance step.

See [Codex work](CODEX_OWNED_WORK.md), [Claude work](CLAUDE_OWNED_WORK.md), [Gemini work](GEMINI_OWNED_WORK.md) and [connector contracts](CONNECTOR_PLUGIN_CONTRACT.md).
