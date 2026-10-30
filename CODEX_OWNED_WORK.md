# Start work and steer its active turn

The dedicated native Codex work window keeps the editor available while its task runs. Human Start creates one fresh thread and initial turn through an explicitly declared owner listener. Human Steer targets the exact observed active turn. It does not wait for the initial Start response or turn completion.

This source uses the public Codex `rust-v0.162.1` protocol, pinned to `092d3acd6bec3e3a14bdc7e7a2810ab628ab759d`. Validation uses synthetic Unix WebSocket peers, temporary action journals and native headless interactions. It does not establish a live named agent, human acceptance or a changed artifact.

## Declared owner boundary

The host supplies one absolute listener path, work directory and private journal path. It must explicitly declare a dedicated Codex runtime and authorize the runtime-wide explicit-login policy. These declarations are not verified server exclusivity, vendor identity or account authentication.

Chinwag creates no app-server process and changes no daemon enrollment, provider settings or authentication files. The owner starts and configures the external server through its supported interface. A plain local transport does not prove that the server's saved remote-control preference is disabled. The inspected public feature flag for remote control is removed compatibility metadata; this implementation uses no internal disable marker.

Use a canonical, owned `0700` directory for the declared alias and its protected physical parent. Parent symlinks are rejected; for example, use a canonical private path rather than an alias below `/tmp` on macOS. This is stricter than some upstream alias-parent configurations. The supported listener is WebSocket over Unix. Its declared rendezvous path can be a final symlink to the protected physical socket. Chinwag checks the exact alias, target and private parents before and after connecting, and checks the connected peer UID. It performs no default-path search, private configuration read, TCP fallback or reconnect. Socket access establishes local provenance, not a named application or account.

The initial `initialize` declares `explicitGatewayOauth:true`, `experimentalApi:false` and `requestAttestation:false`. The explicit-login choice is sticky for the app-server gateway runtime. It is sent only after the dedicated-runtime declaration and policy consent are durably recorded. A shared or undeclared listener is unsupported. Initialization errors require owner action; no automatic login, approval reply or policy restoration follows.

## Human entry

The source executable has an explicit mode:

```sh
/path/to/chinwag-desktop-alpha codex-work \
  --owner-socket /owner/private/declared.sock \
  --workdir /owner/project \
  --journal /owner/private/one-work-journal \
  --dedicated-runtime \
  --explicit-login-policy
```

The owner independently prepares a compatible dedicated listener with the supported `codex app-server --listen unix:///owner/private/declared.sock` command. The server configuration and sign-in remain the owner's responsibility. This document does not claim that a supplied binary or running server has the pinned version.

Mounting the window starts no connection, thread or model turn. It opens only its own private action history. The normal workbench and existing client profiles stay separate. The task window has one editor, task activity and original receipts. Closing the window leaves the retained owner available through **Chinwag → Show task window**. Explicit **Close control connection** or application Quit releases that connection; work may continue. Neither action claims to stop the server or prove that work survives later failures.

## Operation order

1. A human Start captures bounded initial text and one original 30-second effect deadline. The immutable intent records its operation ID, exact listener, selected work directory and runtime-policy consent before any connection or protocol write.
2. The one retained owner connects once, sends fixed initialization, then `initialized` and one fresh `thread/start`. The matched response must describe an empty thread in the exact committed directory. Other responses, ambiguous envelopes and unsupported server requests cannot mint that proof.
3. The existing buffered reader and ordered notification prefix transfer to the steering core. The core is installed before the first `turn/start`. A durable thread/epoch binding precedes its private once-consumed initial-turn capsule.
4. Only the fixed initial `turn/start` and bounded text `turn/steer` lanes are available. There is no generic RPC, resume, fork, richer input, model override, automatic approval or Start fallback for a failed Steer.
5. Actual `turn/started` activity on that new thread exposes an opaque target. A human can steer it while the initial response remains unconfirmed. Unexpected own-thread activity before our initial write requires owner intervention; the client cannot assume server exclusivity.

A missing bootstrap or Start response never causes another connection, thread or turn to be created. Original lookup is read-only. Restart shows saved receipts without adopting the old connection or minting new control authority. The one work journal cannot be reused for a second task.

## Control and evidence

The original generic steering API keeps its fixed lease of at most 900 seconds. The human-owned work path has a distinct private scope, created only from the committed fresh-thread proof. Every explicit Steer captures a separate 30-second authorization bound to the exact epoch, turn generation, operation ID and text before queueing or persistence. Observations and timers mint no authority. The first owned turn's terminal notification or response permanently ends this scope; late activity cannot reopen it.

The initial operation and each Steer have independent evidence. A completed frame flush is transport evidence. A matched native response proves Core acceptance. A matching user-message lifecycle item proves harness recording. These facts can arrive out of order and do not prove model awareness, an agent acknowledgment, Codex rollout durability or applied work. Agent text is a bounded display of the same owned stream, with no automatic semantic acknowledgment claim.

The bridge records intent before effect and persists evidence before publishing it as saved. Failed writes preserve prior durable facts and expose persistence failure. Caller or view cancellation does not retract bytes or close the owner. A write or response timeout remains uncertain; no automatic replay, retarget or renewal occurs. Original IDs retain their payload binding, and all bounded saved Steer rows remain recoverable.

## Transport and acceptance limits

There is one primary reader and one frame writer. Each WebSocket Text message must contain one bounded envelope. Duplicate keys are rejected before JSON normalization, including pretty-printed messages. Binary protocol input is rejected. Both frame and reassembled-message limits are 256 KiB; outbound frames are at most 64 KiB. A writer flush waits for the actual WebSocket sink. Close cannot flush abandoned staged application data after a canceled write.

Start has a separate original 30-second effect budget; Steer writes retain the two-second budget and ten-second response-uncertainty timer. Blocking filesystem calls are not forcibly interrupted by these deadlines. No latency claim treats a timer as an interruption of synchronous IO.

A full acceptance demonstration still requires a human to start actual owned work, submit a steer while its turn remains active, obtain correlated acknowledgment and verify the revised artifact. A synthetic peer, source build, socket connection, turn completion or plan update cannot substitute for that result.

Primary sources: [app-server protocol](https://learn.chatgpt.com/docs/app-server), [pinned Unix listener](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/app-server-transport/src/transport/unix_socket.rs), and [initialization policy](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/app-server/src/request_processors/initialize_processor.rs). Research and policy corrections are retained under `steer-owned-work-research-v1` and `steer-owned-work-design-review-auth-correction-v1.json` in the task artifacts.
