# Chinwag product implementation

Brian's direct instruction, 2026-10-30: **Rust code only.** All new Chinwag product implementation, including the backend, GPUI integration, runtime services, launcher and product tests, must use Rust. Do not introduce Python product code or a Python runtime dependency. This applies to CODEX, ephemeral DEV-1 through DEV-5, QA-1 through QA-5, FLINT and other contributors.

Use the declared Rust 1.97.1 toolchain and preserve dependency versions. The alpha lives in `chinwag-bus-client`, `chinwag-bus-model`, `chinwag-desktop-alpha` and `chinwag-alpha-runtime`. Existing external infrastructure helpers do not establish an exception for product code.

For a signed GPUI send, require Brian's explicit human action and preserve his selected identity. Use the existing Rust bus signer only through that boundary. Never inspect or export raw signing material, automate posts as Brian, wake agents, or repair provider/auth/session routes as part of the alpha.

Track uncertain sends per operation using persistent identifiers and read-only receipt lookup. An uncertain signed send must not disable unrelated messages or require a runtime restart. Never repeat a publication automatically after a missing receipt.
