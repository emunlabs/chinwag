# Codex steering core

`chinwag-codex-steer` provides a legacy already-initialized steering controller and a separate human-owned Start/Steer integration. This document describes the legacy controller contract. See [human-owned work](CODEX_OWNED_WORK.md) for the explicit native work window, owner-selected Unix listener, fixed initialization/initial-turn lane and distinct per-action control policy. Validation uses synthetic peers; actual human steering and changed-artifact acceptance remain unproven.

## Owner and target contract

`SteerController::from_established_io` accepts exclusively delegated IO from an already initialized protocol owner. The embedding supplies a serviced Tokio runtime and an `OwnerControlScope` for one exact thread. The constructor starts or adopts no session.

The returned `ConnectionOwner` supplies a separate `HumanSteerGrant` to a trusted human-action handler. Process presence, connectors, bus messages, and MCP `InboxRead` grants confer no control authority. This owner declaration authenticates no account or application. Serialized operation data cannot construct a grant or active-turn handle.

`active_turn()` returns a handle after the same stream reports `turn/started` with `inProgress` for the permitted thread. The handle binds the connection identity, epoch, turn ID, and observation generation. A new turn or matching completion invalidates it. This is an active candidate, without a regular, review, or compact kind. Codex Core decides whether steering is supported.

## Submission and recovery

`submit_human_text` accepts bounded text, an operation ID, a human grant, and the captured target. It validates them and consumes the immutable operation in the private journal. The file and parent directory are synced and verified before the controller creates a committed-attempt token.

The only outbound method is native `turn/steer`, with `threadId`, `expectedTurnId`, the operation ID as `clientUserMessageId`, and one text input with empty `text_elements`. The newline-delimited request omits `jsonrpc`, trace, experimental metadata, and permission changes. It exposes no arbitrary RPC, file input, interrupt, or `turn/start` fallback.

The journal binds each ID to its exact epoch, thread, expected turn, and text. An exact repeat returns its stored receipt without another write to the peer. A different payload conflicts. Codex's `clientUserMessageId` supplies correlation, not peer-side deduplication.

There is no automatic queue, retry, retarget, renewal, or replay. An occupied write slot rejects dispatch. Once it releases, a distinct human operation can proceed despite an earlier uncertain response. A partial or timed-out write blocks further writes because the stream's frame boundary may be unknown.

Caller cancellation cannot retract submitted bytes. Cancellation before transport registration can leave a consumed operation unresolved without sending it. After registration, the owned write task, independent reader, and evidence persistence can continue without the caller. Original receipt lookup never dispatches. Late evidence can update that receipt while the stream remains open.

On restart, a saved-only or write-only operation projects uncertainty without dispatch. Recovery syncs and verifies records before publishing positive evidence. Malformed, partial, special, or orphan records retain their bytes and reserve their IDs. Unrelated IDs remain usable. A persistence failure returns the last durable evidence with `persistence_failed`, without promoting the failed update.

## Evidence contract

Evidence fields are independent and can arrive out of order.

| Evidence | Meaning |
| --- | --- |
| `frame_written` | The complete request frame and flush finished on the supplied writer. |
| `not_dispatched` | This registered attempt did not begin a possible write. |
| `write_uncertain` | The original outcome is unresolved, including a write or response timeout. Later positive evidence does not erase this historical fact. |
| `core_accepted` | A successful response matched the exact string RPC ID and expected turn ID on this connection. |
| `harness_recorded` | A `userMessage` item completed with the exact operation client ID, thread, turn, text, and empty text elements. |
| `peer_error_observed` | A matched peer error arrived. Generic errors remain uncertain; raw peer error text is not retained. |

`core_accepted` and `harness_recorded` prove neither model awareness nor semantic obedience. Neither proves durable Codex rollout storage, an agent acknowledgment, or an applied artifact. The journal makes the bridge's recorded evidence durable, not Codex's conversation. Plan updates and turn completion alone cannot verify a steer result.

## Bounds and lifecycle

| Bound | Contract |
| --- | --- |
| Owner scope | A positive monotonic lease of at most 900 seconds, with no renewal API. |
| Human text | At most 8,192 UTF-8 bytes. |
| Frames | At most 64 KiB outbound and 256 KiB inbound. |
| Retention | At most 128 operations, including reserved journal IDs. No automatic eviction. |
| Journal | At most 64 KiB and 16 lines per operation, with bounded directory enumeration. |
| Write | One frame at a time, with a two-second write budget. |
| Response | Ten seconds without Core acceptance records uncertainty. Late evidence remains correlatable. |

The journal requires an owned `0700` directory, an immutable domain marker, `0600` regular files, and an exclusive lock. No-follow opens, held-file checks, single-link checks, and parent identity checks reject detected path substitution.

Expiry, revocation, owner close, stale targets, malformed frames, and evidence backpressure can deny further dispatch. Unsupported server requests require owner intervention, without automatic approval. `shutdown()` closes delegated IO and joins its tasks. It sends no model-stop or shutdown RPC, grants no tools, and claims no application termination.

## Source and validation boundary

The wire contract follows OpenAI Codex tag `rust-v0.162.1`, commit `092d3acd6bec3e3a14bdc7e7a2810ab628ab759d`: [native envelopes](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/app-server-protocol/src/rpc.rs), [steer parameters](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/app-server-protocol/schema/typescript/v2/TurnSteerParams.ts), and [Core submission mapping](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/app-server/src/request_processors/turn_processor.rs).

The retained receipts are `steer-codex-primary-v1.json` and `steer-codex-wire-primary-v1.json` under the `2026-10-30/chinwag-gpui-bus-integration-v1` artifact directory. Validation in this unit uses synthetic duplex streams and temporary journals. Live ownership delegation, agent acknowledgment, and changed-artifact acceptance remain unproven.
