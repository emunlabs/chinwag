# Chinwag native Rust GPUI bus alpha

The product runtime is Rust throughout: the native GPUI Kit0.8.1 workbench, typed HTTP client, conversation model, persistent alpha service, bounded shared-ledger adapter and macOS launcher. The isolated checkout starts at980e71c08b34786bca5af0aeabb4191b6f822545.

## Build and launch

Use Rust1.97.1:

```sh
cargo +1.97.1 build -p chinwag-alpha-runtime -p chinwag-desktop-alpha --locked
./target/debug/chinwag-alpha-runtime launch --state-dir /absolute/alpha-state
```

The launcher opens a native macOS app connected to its persistent unsigned local bus at127.0.0.1:44339. Choose a room, click Connect, type multiline text and use Send or Cmd-Enter. Enter inserts a newline. Rooms refresh every two seconds. Drafts and message history persist in the selected state directory. Sender names in this isolated mode are unsigned labels; local storage does not establish fleet or recipient delivery.

An existing loopback endpoint can be selected with `launch --bus-url http://127.0.0.1:PORT --state-dir /absolute/separate-state`. The launcher does not start or repair that endpoint.

## Shared bus

`serve-shared --ledger /absolute/shared/messages.jsonl --port 44341` exposes a bounded read-only view. It reads at most the last1MiB and returns at most100 messages from one of four fixed rooms. It does not verify stored signatures or publish.

The approved signed mode additionally takes `--signed-cli /absolute/existing/chinwag --repo /absolute/repo --send-journal /absolute/owned/send-journal`. It invokes the existing Rust signer only for an explicit human GPUI Brian post. Select Brian yourself; the application does not choose him automatically. No agent wake is enabled. Each receipt shows the actual transport and signature result. A local fallback is reported as local; no recipient read is inferred.

Each send has a persistent operation ID. An uncertain result remains in the outbox, where Check delivery retrieves its recorded result without another POST. Unrelated messages can continue; no runtime restart is required. The same operation is never automatically published twice. A CLI that exits without a usable receipt may remain uncertain because the existing bus does not accept a caller-provided native message ID.

## Verify

```sh
cargo +1.97.1 test -p chinwag-bus-client -p chinwag-bus-model -p chinwag-desktop-alpha -p chinwag-alpha-runtime --locked
cargo +1.97.1 clippy -p chinwag-bus-client -p chinwag-bus-model -p chinwag-desktop-alpha -p chinwag-alpha-runtime --all-targets --locked -- -D warnings
```

The desktop tests drive actual GPUI headless input and keyboard interactions. Runtime tests use temporary ledgers, bounded loopback fixtures and a compiled Rust mock CLI. No real signer or model is invoked by tests. Native window/Connect were observed earlier; later CUA capture/app-resolution errors limit complete live visual proof. Exact current source/build/service/readback receipts are outside the product checkout in the alpha delivery directory.

Five DEV and five QA DeepSeek4.1 completion jobs previously produced source-bound proposals; CODEX applied/tested accepted changes. All ten slots now have Rust-only shared system instructions, and genuine FLINT acknowledged the rule. Worker completion text is not filesystem execution proof. Output caps remain32768tokens with600s request timeout. Vendor compatibility changes are recorded in vendor/GPUI_PATCHES.md.

No commit, Git signing, push or merge is part of this delivery.
