# Runtime-owned MCP HTTP binding

The optional Streamable HTTP inbox runs inside the Rust runtime. Its reader and public observation share the same `InboxServer`, `ConnectorHost` and admission registry. It does not attach to an existing stdio child or identify a particular application, account or conversation.

This source unit is compiled and staged only. Existing runtime services, installed clients, sidecars, installation artifacts and GPUI windows retain their previous behavior. The current GPUI does not request this new observation route.

## Owner opt-in

Only a read-only `serve-shared` runtime on a fixed nonzero `127.0.0.1` port can accept `--mcp-http-capability-file /absolute/new/file.json`. The option is absent by default and cannot accompany signed-send options. Startup reserves the requested listener before issuing authority. It does not stop an existing listener or repair a route.

The declared output must be a new path in an existing owner-controlled directory, without symlink ancestors or group/other write permission on the parent. Publication creates a regular single-link file with mode `0600`, verifies its held and named identity and bounded bytes, then syncs the file and directory. Existing files, symlinks and special nodes are preserved and never adopted. An uncertain new output is retained; it is never automatically deleted or reused.

The private JSON document has schema `chinwag-owner-http-mcp/v1`. It contains the fixed `/api/mcp` URL, an `Authorization: Bearer …` header, `#mgmt`, and `lease_seconds: 900`. This is the sole deliberate capability export. It is not a client configuration file, and creating it installs or opens no application. Keep its bearer private.

The capability and connection nonce come from separate operating-system randomness calls. The registry stores the nonsecret connection identifier and typed `owner_local_http_capability_unattributed` authority. It does not store the bearer or peer identity. The original monotonic grant lasts at most 900 seconds; requests, status reads and reconnects cannot renew it. A later process requires a fresh explicit output path and capability.

If capability or HTTP initialization fails, the runtime reports a fixed redacted diagnostic and continues the healthy bus with HTTP MCP disabled. It does not adopt a previous capability file or change client configuration.

## HTTP and protocol boundary

Every MCP request requires the exact bound Host, no Origin and one valid bearer before the body is read or SDK work begins. Cookie and proxy-authorization headers are rejected, and Authorization is stripped before passing HTTP parts to the SDK. Requests accept only `/api/mcp` without a query. GET, HEAD and standalone SSE/replay are unavailable. POST carries MCP; DELETE closes only the admitted session.

Bodies are streamed under a 16,384-byte cap and a two-second collection deadline. Security and protocol headers must be unique. MIME and Accept validation precede SDK dispatch. Supported stateful protocol versions are `2025-06-18` and `2025-11-25`. Newer stateless lifecycle metadata, `server/discover`, client capability routing overrides and replay identifiers are rejected. A bounded SDK `progressToken` remains valid for supported legacy tool requests.

The wrapper admits one consumed SDK session slot and one active POST response stream. Consuming, deleting or abandoning a session does not restore the slot. The incoming dispatch permit bounds request collection and SDK control dispatch; the separate response permit lasts through actual response-body EOF or drop. An abandoned body retires the transport. It does not prove input EOF or completion of an outstanding inbox read.

Canonical grant checks are nonblocking for requests and session creation. A busy host rejects ordinary requests, initialized notifications and DELETE with 409. An authenticated cancellation received while the original read holds that host can instead withdraw the entire owner transport and return 202. That response acknowledges owner-side closure only: it forwards no unchecked SDK notification and proves neither cancellation of a specific request nor reader drain. Revoked, disconnected or expired authority rejects dispatch.

The tool catalogue remains the fixed read-only `chinwag_inbox_read` tool. Tool arguments cannot choose another room, endpoint, account, sender or command. Reads use canonical authority, scope, generation and deadline checks in the existing host. Initialize and tool listing perform no bus reads. The entire structured result, including observations, remains bounded to 65,536 bytes.

## Observation and shutdown

`GET /api/onboarding/mcp-http/status` exists only when this owner-held transport starts successfully. It requires the exact Host, no Origin or query, and exactly `X-Chinwag-Onboarding-Intent: 1`. The header is a native UI convention, not human or account authentication. The GET projects the same in-memory holder; it performs no scan, bus request, admission lock or file read.

The projection carries independent initialization, initialized-notification, catalogue-output, read-output, expiry and closure facts. It contains no bearer, raw session identifier, arbitrary client information, paths or message text. Prepared output is not proof of client receipt or model consumption. A historical initialized observation remains historical after expiry.

Owner closure and expiry fence new work, cancel the original session and retain cleanup ownership across cancelled awaits. `transport_worker_joined` and `reader_worker_joined` report separate actual joins. The stock SDK protocol-driver task is private and detached; this implementation makes no claim that every SDK task has joined. Scheduled cleanup, response-body drop, map removal and a process name are not drain evidence.

Graceful runtime shutdown requests those MCP joins before waiting for axum's connection drain. A peer that stops reading an already-produced network response can keep that later network drain pending. The MCP join flags establish neither bounded whole-runtime exit nor completion of every HTTP connection.

## Acceptance

Synthetic fixtures use the actual pinned `rmcp` 3.7.0 client and server against temporary loopback endpoints. They exercise negotiation, listing, a fixed-room read, malformed requests, bounded concurrency, original expiry, revocation, body abandonment and cancellation-safe cleanup. Runtime fixtures verify the default-disabled routes, private output publication and a status projection from the same held server.

These fixtures establish the supported transport behavior for their synthetic peer. Cursor, VS Code, Claude Desktop and Antigravity still require their own supported human setup and actual protocol/read evidence. Existing Cursor stdio approval cannot be inferred from this transport, and native inbox reading does not establish Grok group delivery.
