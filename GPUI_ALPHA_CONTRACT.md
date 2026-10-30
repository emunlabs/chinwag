# GPUI bus alpha implementation contract

Brian directly assigned Codex to coordinate UI-to-bus integration and continue until there is an alpha he can drive. GPUI is the UI direction. This isolated checkout starts at 980e71c08b34786bca5af0aeabb4191b6f822545. Existing Studio files and workers are not owned by this checkout.

The existing fleet dispatcher is not used because its audited path reads private target memory/signing material, truncates jobs and silently changes engines. Temporary Codex workers in this chat are separate from registered DEV/QA fleet seats.

## Ownership

- Client worker owns `crates/chinwag-bus-client/src/` and its tests.
- Model worker owns `crates/chinwag-bus-model/src/` and its tests.
- GPUI worker owns `crates/chinwag-desktop-alpha/src/` and its tests.
- Root owns workspace/package manifests, Cargo.lock, launch scripts, backend readiness, integration and delivery.

## Client public interface

Expose the following from the client crate root. All wire types derive Debug and Clone; message types support serde.

- `BusMessage` has public `id: String`, `seq: u64`, `ts_iso: String`, `room: String`, `sender: String`, `body: String`, `to: Option<String>`, `task_id: Option<String>`, `sig_verified: bool`. Extra wire fields may be ignored.
- `BusAck` has public `ok: bool`, `seq: u64`, `message_id: String`, `transport: String`, `room: String`, `sig_verified: bool`, `subscribers_notified: usize`. Extra wire fields may be ignored.
- `SendRequest` has public `sender: String`, `room: String`, `body: String`, `to: Option<String>`, `task_id: Option<String>`. The client serializes `wake: false` internally and never exposes an enable-wake option.
- `SendReceipt` has public `message: BusMessage`, `ack: BusAck`.
- `BusClient::new(base_url: &str) -> Result<BusClient, ClientError>` accepts only HTTP loopback endpoints with no embedded credentials.
- `BusClient::status(&self) -> Result<serde_json::Value, ClientError>`.
- `BusClient::messages(&self, room: &str, limit: usize) -> Result<Vec<BusMessage>, ClientError>`.
- `BusClient::send(&self, request: &SendRequest) -> Result<SendReceipt, ClientError>`.
- ClientError implements Display. All calls have finite timeouts and bounded responses. No automatic send retries. Validate returned message/ack room, ID and sequence before declaring delivery.

HTTP routes are `/api/bus/status`, `/api/bus/messages?room=...&limit=...`, `/api/bus/send`. JSON POST includes Content-Type application/json and X-Chinwag-UI-Intent: 1. Preserve HTTP403 operator restrictions. Do not change authentication or silently impersonate another seat. The UI may expose Brian/Nic as human operator identities for Brian to choose and use himself; Codex automated publication remains CODEX.

## Model public interface

Expose `Conversation` with public `room: String`, `messages: Vec<BusMessage>`, `last_error: Option<String>`, and `send_state: SendState`.

- `Conversation::new(room: &str)`.
- `select_room(&mut self, room: &str) -> u64` changes room and returns a load generation.
- `load_generation(&self) -> u64`.
- `apply_messages(&mut self, generation: u64, messages: Vec<BusMessage>) -> bool` rejects stale generations, wrong rooms, deduplicates and orders bounded history.
- `begin_send(&mut self, body: &str) -> Result<u64, String>` rejects empty/duplicate pending sends and returns a send generation.
- `confirm_send(&mut self, generation: u64, receipt: SendReceipt) -> bool` reconciles the actual message and exposes transport/signature state.
- `fail_send(&mut self, generation: u64, error: String)` retains uncertain send text and never republishes.
- `SendState` variants: `Idle`, `Sending { body: String }`, `Delivered { id: String, seq: u64, transport: String, sig_verified: bool }`, `Uncertain { body: String, error: String }`.

## User-visible alpha

Native GPUI Kit 0.8.1 with gpui-fast. One usable room sidebar, message timeline and composer. Editable loopback endpoint, explicit Connect/Refresh, sender control, accurate disconnected/error/pending/delivered/local-fallback states. Polling may run on a background worker; never block the UI thread. Never automatically wake agents. Preserve drafts on uncertain sends. A demo fixture cannot be labelled a production bus connection.

Acceptance requires build and meaningful client/model tests, a real native window with working text input and room switching, and accurate backend connection results. Live send acceptance must name the actual sender, destination, ID/sequence, transport and signature outcome. No signer/private-key reads, signing commits, push/merge, private-agent memory/persona reads, provider/auth/session/route repairs or broad daemon/governor launch.
