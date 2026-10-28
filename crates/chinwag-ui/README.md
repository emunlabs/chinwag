<!--
Copyright 2026 Emun Labs, Inc.
1401 Lavaca St STE 81335, Austin, TX 78701
SPDX-License-Identifier: Apache-2.0
-->
# chinwag-ui

Chinwag Mission Control in pure Rust Dioxus (CHWG-DIOXUS-1). Phase 1 scaffold only: themed shell, router,
and `GET /api/ui/health`. See `docs/chwg-dioxus-1/DESIGN.md` for the plan and parity checklist.

- Dioxus is pinned to `=0.7.10` (current stable; 0.8 is alpha). No Node, npm, or vite anywhere.
- Features: `server` (default, native), `web` (wasm32 client), `desktop` (macOS WKWebView).
- `cargo build -p chinwag-ui`, `cargo clippy -p chinwag-ui --all-targets -- -D warnings`, `cargo test -p chinwag-ui`.
- The server expects a `public/` asset directory next to the binary. A bare `cargo run` panics without it until
  the client bundle is built with the Rust-only `dx` CLI (`dx build --platform web`). Wiring that into
  `chinwag ui` is milestone M1 in the design doc. Dev smoke test: `mkdir -p target/debug/public` then
  `IP=127.0.0.1 PORT=5599 cargo run -p chinwag-ui` (do not use :5487 while the legacy planner is live).
