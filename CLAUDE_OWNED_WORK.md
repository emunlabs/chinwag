# Direct owned Claude work while it runs

The explicit `claude-work` native mode is a separate human control surface for one fresh Claude Code child. Its editor remains available while work runs. It does not discover, resume or adopt an existing Claude Desktop, terminal or editor conversation.

The protocol target is Claude Code **2.1.314**, grounded in the published TypeScript Agent SDK **0.3.314** and Python SDK **0.2.175**. The direct Rust implementation uses the documented JSONL interface rather than a TypeScript or Python runtime. Source fixtures do not establish installed-client compatibility or actual model acceptance.

## Explicit owner entry

```sh
/path/to/chinwag-desktop-alpha claude-work \
  --claude-binary /owner/selected/native/claude \
  --claude-sha256 <exact-lowercase-SHA256> \
  --workdir /owner/selected/work \
  --journal /owner/private/fresh-action-journal \
  --managed-policy-prose-only
```

There are no default binary, session, working directory or journal paths. These arguments are trusted host declarations, never commands extracted from task text. Mounting the view starts no external process. A human **Start** consumes the initial intent and declared policy before child startup, including initialization. The declared native binary is checked against its exact digest and owner metadata before direct shell-free execution. A pinned binary is not vendor, account or cryptographic session identity. The actual initialization response must report the supported version before initial user input; missing or incompatible version information requires owner action.

The fixed child arguments select print mode, streaming JSON input/output, verbose user replay, partial output and a fresh UUID session. The policy selects safe mode, restricted settings, no built-in tools, an MCP tool deny rule, manual/default permissions and no permission prompts. It does not select bare mode, permission bypass, another provider or a login route. This is a prose-only model tool surface, not a zero-side-effect sandbox: enforced managed settings and hooks can remain applicable. Restricted mode excludes user/project settings and can make a setting-derived provider or helper unavailable. The connector reports failure without repairing authentication, changing policy or choosing a fallback. The exact flag combination has source fixtures; actual CLI execution remains a separate human acceptance gate.

## Busy input has explicit delivery semantics

| Human choice | Native priority | Contract |
| --- | --- | --- |
| Send direction now — may interrupt | `now`, genuine human origin | Eligible work can move to the background; other cases interrupt before the new input is processed in a following turn. |
| Send at tool boundary | `next` | May enter the running turn after tools finish, or a following turn. |
| Send after this turn | `later` | Wait for a following turn. |

These requests bind to the held owned session. They have no server-side expected-active-turn comparison field. A busy observation does not turn them into Codex's exact-turn `turn/steer`. Sending now may stop background work through Claude's native interruption behavior; the host does not declare an unimplemented per-task stop affordance. With tools unavailable, a prose-only trial can demonstrate busy interruption and a changed follow-up reply, not backgroundable same-turn preservation.

This first boundary exposes Start, direction timing, original lookup and End input. A separate interrupt or queued-input cancellation control is deferred. A Now request does not generate an interrupt-control acknowledgement, and the UI must not invent one from an echo or result.

Only explicit native human actions create input authority. The fixed user envelope carries a canonical UUID, genuine human origin and `client_composed:true` for literal text. That setting also skips the normal turn-start context-attachment pass; it is not invisible escaping. Model, tool, bus and MCP text cannot become privileged human actions. There is no generic control-request, shell, slash-command, plugin, hook or configuration API.

## Independent receipts and retained ownership

The owner persists immutable Start before spawn and each original input before its one possible write. Original UUID, text, timing, session epoch and action deadline remain bound together. A missing receipt, partial write, disconnected reader or cancelled waiter never causes replay, reconnection, another child or a new operation ID. Read-only original receipt lookup cannot resend input or adopt old IO after restart.

Each explicit Start or direction has one original 30-second effect budget. Human control expires at the original session scope deadline, at most 900 seconds from Start. Reading status, receiving output or checking a receipt never renews either deadline. Human text is bounded to 8192 bytes, and one journal retains at most 128 operations without eviction. Expiry withdraws control; it is not a claim that the child or its work stopped.

The display keeps local intent, frame write, exact input echo, attributed reply, result and lifecycle observations separate. An echo acknowledges input handling. Reply UUID correlation identifies associated output. A successful result can be zero-model when a hook blocks input. None independently proves model awareness, applied direction, changed files or durable remote execution. A changed follow-up can establish prose redirection; changed-file or application claims require corresponding artifact verification.

Status delivery coalesces the latest owned state independently of callers and protocol readers. End input establishes its authority fence synchronously; a displayed snapshot can arrive later, including while a caller retains an older status borrow. Status delivery is not a durable action receipt or a worker-join claim.

The retained owner outlives a view and individual UI waiters. Closing a window does not request interruption or end input. Explicit **End input** fences later writes and releases stdin; application Quit is an explicit lifecycle boundary. Chinwag does not send OS terminate/kill escalation. End input, output EOF, actual child wait and joined workers remain different facts. A local shutdown deadline does not prove the model, background work or external process has stopped.

## Validation boundary

Controlled IO and native headless fixtures exercise the source boundary, durable intent, fixed wire shapes, busy input, draft preservation, independent evidence and failure handling. They are not a real Claude scheduler or a named-client demonstration. A human trial must observe original generation, send the revised direction before the original terminal result, then inspect correlated interruption/result and the follow-up text. Actual backgroundable work, tool effects and changed artifacts need their own evidence.

The existing Codex work entry, inbox bindings, installed client configurations, services and human demo kit remain separate. See [Codex owned work](CODEX_OWNED_WORK.md) and [connector contracts](CONNECTOR_PLUGIN_CONTRACT.md).
