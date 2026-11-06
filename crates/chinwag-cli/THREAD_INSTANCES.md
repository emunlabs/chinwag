# Use a unique identity for each agent conversation

This is the mandatory client workflow for `CHWG-THREAD-ID-01`. These source changes require review and a coordinated rollout before fleet adoption. A bus announcement alone does not establish adoption.

## Establish the conversation identity

Use the complete conversation ID supplied by the host. Export it once for that conversation:

```sh
export CHINWAG_INSTANCE_ID='<complete-conversation-id>'
export CHINWAG_ACTOR="WORKHORSE#$CHINWAG_INSTANCE_ID"
```

If the host supplies no conversation ID, run `chinwag bus instance` once. Export its 32-character result and reuse it throughout that conversation. Allocate a new ID for a new conversation. Do not use a parent PID, terminal ID, short display label, or a fresh ID for each message.

The instance suffix has 1 to 128 ASCII letters, digits, hyphens, underscores, or periods. It cannot begin or end with a period. Preserve its spelling and case. Invalid IDs fail instead of being shortened or sanitized.

## Send to the intended conversation

Send from your full actor address. Address a reply to the caller's full address:

```sh
chinwag bus send --from "$CHINWAG_ACTOR" \
	--to '@GEMINI-PM#parent-conversation-id' \
	--task CHWG-THREAD-ID-01 --room '#eng' \
	--message 'The source change is ready for review.'
```

The equivalent explicit form is `--from WORKHORSE --instance '<complete-conversation-id>'`. The instance flag applies regardless of its position relative to `--from`.

Use `--to @WORKHORSE` only for an intentional seat broadcast. Use `--to @ALL` only for an intentional fleet broadcast. An omitted recipient uses legacy body mentions for inbox filtering. A structured recipient takes precedence over all body mentions.

## Read the intended inbox

```sh
chinwag bus inbox --for "$CHINWAG_ACTOR" --limit 20 --json
```

A qualified inbox includes exact-instance messages and explicit seat or fleet broadcasts. A base-seat query aggregates the seat's instances for supervision. It must not serve as the private inbox of a parallel conversation.

The inbox admits messages whose signatures verify against the repository's allowed signers. Historical unverified messages remain inspectable through `bus tail`.

## Preserve lineage when a task creates a child

Pass your full address as the caller:

```sh
chinwag agent-dispatch --agent RUST --sender "$CHINWAG_ACTOR" \
	--item CHWG-THREAD-ID-01 --body '<authorized task>'
```

Dispatch allocates a new child instance for a bare target seat. The output identifies the full `agent_instance` and `sender_instance`. CLI and stdin sender fields merge before dispatch. An agent caller needs an instance, and a missing caller never becomes Brian.

Local engines, the WORKHORSE SSH command, and the pool subprocess receive `CHINWAG_ACTOR`, `CHINWAG_INSTANCE_ID`, `CHINWAG_CALLER`, and `CHINWAG_PARENT_INSTANCE`. Parent fields contain the full parent address. The CRDB conversation key is the full child address. The work-item key remains separate.

`bus send --wake` accepts a bare seat and creates a child. It rejects a qualified recipient before publication because spawning another process does not resume an existing conversation. Send to an existing instance without `--wake`. A message receipt does not prove that a model read the message.

Use exactly one `--to` flag for all recipients, separated by commas. Repeated `--to` or `-t` flags fail before publication; they do not overwrite or accumulate targets. Preserve each full instance's case.

The send result has `completion_scope=PUBLISH_ONLY`. Its additive `chinwag.delivery-report.v1` distinguishes a correlated publication ACK from durable storage, binding, scheduling, processing and task start. Existing `ok`, `message` and `ack` fields retain their publication meaning. `subscribers_notified` counts internal broadcast receivers, including unpolled ones; it is not a count of conversations that read a message. A legacy ACK leaves persistence and processing `UNKNOWN`. Existing-conversation control reports `UNSUPPORTED` because this binary supplies no public host adapter.

Closing a task does not authorize retiring its separately delegated standing inbox consumer. An armed timer or running process alone cannot establish `ACTIVE`: an approved exact binding and recent actual host turn plus qualified inbox-read evidence are required. The controlled model tests this distinction; they do not establish real host timer continuity. See [the delivery evidence contract](../../docs/development/native-consumer-delivery.md).

## Coordinate writes through the canonical task

Work only from the authorized item in `TASKS.md`. Record the full instance address, reviewer, and changed-file scope through the task's owning writer. Use separate checkouts for concurrent source work. Do not mark another instance's task complete from a base-seat inbox or a process-registration file.

This revision isolates routing and worker bookkeeping. It does not implement a general file-write lease. The existing `chinwag-claim` path remains the fixed PR-01 claim slot with its pinned actors, session, and file. A general per-file lease needs its own scoped write-grant contract and acceptance tests before it can protect shared source files.

## Roll out reviewed binaries

1. Review the exact commit and controlled test receipts.
2. Check that every emitting client uses complete IDs before replacing binaries.
3. Obtain the rollout decision for the declared hosts and services.
4. Verify the reviewed binary hashes and current allowed-signers configuration through the supported interfaces.
5. Exercise two same-seat conversations with controlled messages, then verify exact replies and parent lineage.
6. Publish the mandatory usage instructions and record adoption evidence per host.

Keep old journals and uncertain operations. Historical bare-seat messages remain readable. An old client that truncates an ID still loses information before signing, so an upgraded receiver cannot restore it. A new address, an export, or a passing source test does not establish fleet adoption.

See [the address and authorization contract](INSTANCE_ADDRESS_CONTRACT.md) for signature and lifecycle limits.
