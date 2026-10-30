# MCP connection observations

The Rust inbox server records facts about its own MCP processing. A successful `chinwag_inbox_read` result includes a bounded `connection_observation`. The process owner can inspect the same in-memory observations after shutdown. These observations grant no access and identify no application, account or conversation. They are fixed-field snapshots, not atomic transactions across all concurrent events.

`rmcp` 3.7.0 owns negotiation and framing. Chinwag keeps the existing tool catalogue and fixed read-only native-room grant. No new network route, status file, identity registry or client configuration access is introduced.

## Independent protocol facts

Initialization response preparation, the initialized notification, catalogue preparation and inbox-result preparation are separate facts. The SDK permits tools requests before the initialized notification. The observations therefore do not form a required sequence or a Connected state.

The public `InboxServer::lifecycle_snapshot()` method reads fixed in-process observations without contacting the bus or locking the admission registry.

A prepared result means that the server constructed its response. It does not prove that the peer received, displayed or used that response. An inbox result describes a bounded native-ledger window. It does not establish Grok Bot group delivery.

The observation retains no `clientInfo` name, version, title, URL, icon or other peer-provided identity text. The SDK still owns its normal negotiation metadata. Protocol versions come from the existing SDK negotiation. Counters saturate and the complete structured tool result remains inside the existing 65,536-byte limit, including its observation.

## Serialized fields

The observation schema is `chinwag-mcp-connection-observation/v1`.

| Field | Meaning |
| --- | --- |
| `negotiated_protocol` | Null before successful response preparation, then one supported SDK protocol version. |
| `initialized_notification_seen` | The SDK delivered the initialized notification to this server. |
| `catalogue_outputs_prepared` | Saturating count of prepared tools-list results. |
| `read_windows_prepared` | Saturating count of prepared validated inbox outputs. |
| `lease_expired` | The original monotonic deadline has passed as of this snapshot. |
| `admission_closed` | This process has closed admission to its existing reader. |
| `input_eof_seen`, `input_error_seen` | The owned transport reader observed the specified input end. |
| `protocol_end` | No termination observed, or SDK closure, cancellation or error. |
| `owner_close_requested` | The owner requested cleanup, including last-owner drop. |
| `worker_state` | Drain unobserved, successful owner join or failed owner join. |
| `output_evidence` | Always `prepared_only`. |

The terminal wrapper uses `chinwag-mcp-connection-terminal/v1` and contains the same `connection_observation`. Neither schema carries arbitrary peer text.

## Lease and closure

Lease timing comes from the original monotonic admission deadline. Reading an observation neither renews the lease nor changes the registry. Each inbox read still passes the existing grant, scope, generation, cancellation and deadline checks.

Input EOF, input failure, protocol termination, owner closure and worker drain are distinct observations. The initial worker state is `drain_not_observed`. Only an awaited owner join establishes `drained`; a failed join reports `failed`. EOF can close admission while the original bounded HTTP read is still finishing. A cancelled tool call does not mean that the client application disconnected. An expired lease does not mean that stdio closed.

After an orderly stdio service exit and reader cleanup, the server emits one fixed JSON summary to stderr. The summary contains bounded protocol facts, counters and closure observations. It contains no message bodies, senders, request IDs, endpoints, paths, PIDs, raw errors or client identity text. It never writes protocol diagnostics to stdout.

A process killed before cleanup can produce no terminal summary. Missing output remains unknown. The observations grant no right to stop or restart the launching application.

## Acceptance boundaries

An SDK subprocess fixture can prove negotiation, tool handling and cleanup for that fixture. It is not evidence that Cursor installed the server or read its inbox. Actual Cursor acceptance requires the human-approved client route and its own successful protocol exchange.

The current GPUI preview does not read these in-process observations across processes. Its setup acknowledgment remains an OS handoff receipt. No live Connected indicator follows from a saved observation, a process name or an installation.
