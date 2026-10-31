# Owned Gemini prompts and cancellation

The explicit `gemini-work` native mode keeps a draft editable while one fresh owned Gemini CLI session processes a prompt. It offers **Cancel current response** during that work. A separate human Send starts the next prompt after the original terminal response and after any old cancellation has left the writer. It does not overlap prompts or describe replacement by interruption as same-turn steering.

The public source target is Gemini CLI **0.66.0**, commit `970413207732f5d4d8c50540c7fc359c44fdaaf2`, with ACP SDK **0.16.1** and ACP protocol version **1**. Current ACP v2 draft features and other adapters' steering extensions are not included. Source fixtures do not establish an installed runtime or actual model acceptance.

## Explicit configured runtime

```sh
/path/to/chinwag-desktop-alpha gemini-work \
  --gemini-binary /owner/selected/native/gemini \
  --gemini-sha256 <exact-lowercase-SHA256> \
  --workdir /owner/selected/work \
  --journal /owner/private/fresh-gemini-journal \
  --configured-runtime-effects
```

The host declares an exact native file and digest, selected working directory and private action journal. There is no binary search, default session, profile import or GUI conversation adoption. Opening the window starts no external process. Human Start durably consumes the initial intent and startup declaration before spawning one child.

The declaration authorizes the selected Gemini runtime's normal configured startup effects: loading settings, hooks and context, refreshing its configured authentication, and initializing native tools, MCP servers and helpers, including configured helper/model startup. The fixed arguments are `--acp --approval-mode default --extensions none`. They request default approval mode and disable extensions. They do not establish a restricted, tool-free, authentication-free or helper-free runtime. Native settings and managed policy remain applicable. Chinwag does not call authentication, account-switch, model/mode mutation or provider-repair methods, and it grants no permissions automatically.

The child inherits its environment without inspection or rewriting. No `HOME`, `GEMINI_CLI_HOME`, profile, keychain or settings override is selected. A different Gemini state root would not prove authentication isolation, and local `admin` JSON fields do not enforce the restrictions implied by their names. Empty ACP client capabilities and `mcpServers: []` do not disable the agent's configured native tools or MCP servers.

The native executable pin checks the owned regular executable, host format, permissions, bounded digest and held/named metadata before direct shell-free execution. Pathname execution still has a check-to-exec race; this is not atomic executed-inode, vendor or account attestation. Initialization must report protocol 1 and `gemini-cli` version `0.66.0` before the fixed fresh `session/new` request. That version is self-reported and can be affected by Gemini's `CLI_VERSION` override. It is a compatibility check, separate from the declared file pin. A mismatch requires owner action, without a fallback, another process or a new session.

Session creation is itself effectful. Its matched response must supply a new bounded session ID and default current mode. The request contains the selected cwd, but the inspected response contains no cwd attestation; the host does not invent one. Startup or session creation can have effects even when the initial user prompt is never dispatched.

## One active prompt

Only text is supplied as input. Leading command-shaped text, including JavaScript-trimmed whitespace or a byte-order mark followed by `/` or `$`, is rejected before effects. No slash-command, shell-command, resource or generic RPC entry is exposed. Plain `@file` text is not expanded by the inspected ACP resolver, although the configured runtime can still attach native context and hooks.

Gemini's inspected handler aborts a previous prompt when another arrives. Its callbacks and shared state can overlap before lower-level model sends serialize. The adapter therefore keeps one active prompt and never treats concurrent `session/prompt` calls as a supported append-steer operation. The editor remains available; writing a draft creates no protocol effect.

A human Cancel captures the exact original local prompt RPC ID, connection/session epoch and generation. The wire notification contains only the session ID, so final writer admission must recheck that local target. If natural completion wins first, the old cancel notification is not dispatched. New prompts remain blocked while an older cancellation is queued, writing or uncertain, even if its original prompt has already produced a terminal response. A delayed cancellation must never reach a newer prompt.

Pending permission requests require owner intervention. A human Cancel can resolve only the exact owned prompt's pending permission requests with typed cancelled responses. It cannot choose an allow/always option, deny an unrelated request, implement a file/terminal operation or mint generic control authority. Permission-response writes and the cancel notification are separate effects: a notification not dispatched can coexist with an already written permission cancellation.

The cancel notification has no independent acknowledgement. The original prompt's correlated response and its five distinct stop reasons are terminal facts. A prompt RPC error is not a confirmed stop reason and requires owner intervention before any new prompt; it cannot silently enable replacement. `cancelled` does not prove every process or tool stopped. A mode update away from default requires owner intervention for new prompts; the host never changes the mode back automatically. An unsupported request or protocol failure cannot start a replacement prompt.

## Evidence and lifecycle

Each human effect has one original 30-second admission/write budget. A prompt's RPC response is terminal, so normal work can continue well beyond that budget; there is no short missing-ACK timer that treats a long response as failure. The original human-control scope lasts at most 900 seconds from Start. Status, output and receipt reads do not renew it. Expiry prevents new prompt/cancel control; it does not declare pending work complete or unknown. Explicit End input remains available.

Immutable original intent precedes any possible effect. Exact IDs, text, epoch, RPC target and deadlines do not change after uncertainty. Private original receipt lookup never retries, reconnects, replays, retargets or creates another session. Text and retained history are bounded; history does not evict old unresolved operations to regain capacity.

The display separates local frame writes, notification non-dispatch, permission-cancellation responses, correlated terminal results, RPC errors and session-only output. An unavailable terminal after actual transport loss is distinct from a partial write and from normal pending work. Only registered operations that could have been written receive that historical loss observation; a later exact terminal remains a separate positive fact. Standard session updates contain no stable originating prompt RPC ID. Command output and an `end_turn` result can occur without a model call. No local write, output chunk or terminal result independently proves input echo, model awareness, applied direction or a changed artifact.

The owner retains IO and evidence work independently of views and request waiters. Closing a window keeps its owner available through the application menu. Explicit End input fences new writes and releases stdin; application Quit requests it and waits at most three seconds locally. Chinwag sends no OS terminate/kill escalation. Native runtime cleanup can still follow its own configured policy. EOF, protocol closure, actual child exit, prompt cancellation and actual joined workers remain separate observations, without an all-work-stopped claim.

## Verification boundary

Rust fixtures use controlled IO or a fake child, never a Gemini model. The complete native headless workflow crosses the production port, parser and journal with only child creation replaced: Start, a pending prompt, human Cancel, late output and permission cancellation, the exact original terminal, and a separate human Send. Other cases cover natural completion racing Cancel, stale generations, scope expiry, storage failure, partial writes, restart lookup, EndInput and newer draft retention.

An actual human trial must use a declared compatible runtime, observe the original response, cancel it, send the next prompt through the declared boundary and inspect its changed output. Background tools, authentication, helper lifecycle and changed files need their own evidence. Existing Codex and Claude entries, profiles, clients and live services remain separate. See [Codex work](CODEX_OWNED_WORK.md), [Claude work](CLAUDE_OWNED_WORK.md) and [connector contracts](CONNECTOR_PLUGIN_CONTRACT.md).
