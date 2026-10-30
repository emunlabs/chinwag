# CHINWAG CANONICAL TASK & FLEET UTILIZATION BOARD (`TASKS.md`)

> **Single Source of Truth (`INV-TASKS-MD-01`)** — Maintained continuously by **`■ PRODUCT` (Utilization & Backlog Governor)** and **`■ DELIVERY` (Work-Stream Router & Bus Coordinator)** over the native `iroh` Multi-Party Messaging Bus (`ALPN: chinwag/bus/1` + `chinwag/agent-dispatch/1` on `0.0.0.0:44330`) and surfaced live on **`http://127.0.0.1:44331`** (`chinwag ui`).
> - **Dynamic Markdown Task Parser & Continuous Rolling-Wave Synthesizer (`CHWG-DYNAMIC-TASKS-PARSER-01`):** `chinwag bus daemon` and `chinwag bus wake` dynamically parse `### [IN_PROGRESS] TASK-XX` and `### [READY] TASK-XX` sections directly from this file every `45s` (`INV-UTIL-01` — `0%` Idle Tolerance) and route them to `■ TYPE`, `■ RUST`, `■ ARCHITECT`, `■ FLINT`, `■ ALISTAIR`, and `■ QA`. When a seat finishes its queue, `auto_advance_tasks_markdown` automatically synthesizes the next rolling-wave verification task.
> - **Cryptographic Bus & Envelope Provenance (`BUS-HARDEN-04` + `TASK-28`):** Every `BusMessage` is signed over the length-prefixed 7-field canonical transcript (`chinwag-bus-sig-v2`) and verified against `.chinwag/allowed_signers` (`✓ed25519`), with full 1800-character technical receipts in local Austin Central Time (`CDT`). Every `.cwplugin`, `.cwcard`, and `.cwbond` envelope enforces domain-separated canonical `BTreeMap` `Ed25519` signatures and the **`Rogue Machine Media LLC (d/b/a Lag Lords)`** Studio Firewall (`INV-BRAND-FIREWALL-01`).

---

## 1. Live Fleet Utilization & Seat Assignment (`■ PRODUCT` Telemetry)

| Seat / Handle | Engine & Host | Role / Lane | Utilization Status | Active Task | Last Bus Heartbeat |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`■ PRODUCT`** | `chinwag bus daemon` · Mac Studio (`0.0.0.0:44330`) | Fleet Utilization Governor & Rolling-Wave Synthesizer | **ACTIVE (`100%` Always-On 45s Loop)** | `TASK-21` (`CHWG-AUTO-ADVANCE-TASKS-01`) | `2026-10-29T19:31:00 CDT` |
| **`■ DELIVERY`** | `chinwag bus daemon` · Mac Studio (`0.0.0.0:44330`) | Work-Stream Router & Multi-Party Bus Dispatcher | **ACTIVE (`100%` Always-On 45s Loop)** | `TASK-21` (`CHWG-AUTO-ADVANCE-TASKS-01`) | `2026-10-29T19:31:00 CDT` |
| **`■ GEMINI-PM`** | `Gemini 4 Argon / Opus 5.5` · Mac Studio | Portfolio PM & Architecture Coordinator | **ACTIVE (`100%`)** | `TASK-26`..`TASK-34` Orchestration | `2026-10-29T19:31:00 CDT` |
| **`■ TYPE`** | `Claude Sonnet 4.6` · Mac Studio (`127.0.0.1:44331`) | UI/UX Workbench v5, Dioxus Routes & Live Bus Bridge | **ACTIVE (`IN_PROGRESS`)** | `TASK-32` (`CHWG-UI-DIOXUS-WORKBENCH-01`) | `2026-10-29T19:31:00 CDT` |
| **`■ RUST` (`GPT`)** | `Codex CLI (gpt-6.1-sol)` · Mac Studio | Core Rust (`chinwag-cli`, `chinwag-ui`, `Triple-B` Bond CLI) | **ACTIVE (`IN_PROGRESS`)** | `TASK-26` & `TASK-31` (`bond` + `chinwag ui` Server) | `2026-10-29T19:31:00 CDT` |
| **`■ ARCHITECT` (`GPT`)** | `Codex CLI (gpt-6.1-sol)` · Mac Studio | Protocol, `INV-BRAND-FIREWALL-01` & Live UI API | **ACTIVE (`IN_PROGRESS`)** | `TASK-27` & `TASK-31` (`Rogue Machine Media LLC`) | `2026-10-29T19:31:00 CDT` |
| **`■ ALISTAIR`** | `Codex / Claude Security Auditor` · Mac Studio | Domain-Separated JCS Signing (`manifest`, `cwcard`, `cwbond`) | **ACTIVE (`IN_PROGRESS`)** | `TASK-28` (`CHWG-PLUGIN-DOMAIN-SEP-01`) | `2026-10-29T19:31:00 CDT` |
| **`■ FLINT`** | `flint-agent` · MacBook Pro (`100.108.108.25:11500`) | Adversarial Code Review, Clippy/Test Gate & Diff Audit | **ACTIVE (`IN_PROGRESS`)** | `TASK-29` & `TASK-34` (Adversarial UI + Bond Audit) | `2026-10-29T19:31:00 CDT` |
| **`■ QA`** | `Cleanroom Runner / Flint Gate` · Mac Studio + MBP | Workspace Test Suite, Live UI `127.0.0.1:44331` & QUIC Gate | **ACTIVE (`IN_PROGRESS`)** | `TASK-30` & `TASK-34` (Full Workspace + Live UI Gate) | `2026-10-29T19:31:00 CDT` |

---

## 2. Completed Foundation & Phase 1.1..1.3 Tasks (`TASK-01` .. `TASK-25`)

- **`[DONE]` `TASK-01` (`CHWG-MAIN-UNIFY-1`):** Unified all branches onto `main`.
- **`[DONE]` `TASK-02` (`CHWG-IROH-BUS-1`):** Multi-party `iroh` QUIC bus (`ALPN: chinwag/bus/1`) + architecture spec.
- **`[DONE]` `TASK-03` (`CHWG-OPENSPEC-CLI-1`):** Verified `seat_signing` and `ui_gate` suites (`■ RUST`).
- **`[DONE]` `TASK-04` (`CHWG-SWARM-VERIFY-1`):** Verified `chinwag-swarm` `dispatch_wire` and `chinwag-claim` (`■ ARCHITECT`).
- **`[DONE]` `TASK-05` (`CHWG-FLINT-AUDIT-1`):** Completed initial adversarial audit (`■ FLINT`).
- **`[DONE]` `TASK-06` (`CHWG-QA-SWEEP-1`):** Workspace `chinwag-cli` test sweep (`31/31` green) + `CDT` wall-clock formatting (`■ QA`).
- **`[DONE]` `TASK-07` (`CHWG-SIGN-AUDIT-1`):** Provisioned all 10 seat Ed25519 keys and `.chinwag/allowed_signers` (`■ ALISTAIR`).
- **`[DONE]` `TASK-08` (`BUS-HARDEN-01`):** Detached `Ed25519` message signatures on `BusMessage` (`■ RUST`).
- **`[DONE]` `TASK-09` (`BUS-HARDEN-02`):** Bound `0.0.0.0:44330` and synced `origin/main` + MacBook Pro `100.108.108.25` (`■ ARCHITECT`).
- **`[DONE]` `TASK-10` (`BUS-HARDEN-03`):** 5-attempt CRDB retry in `agent_dispatch_run.rs` + advisory `flock` on `.chinwag/bus/bus.lock` (`■ RUST` + `■ FLINT`).
- **`[DONE]` `TASK-11` (`CHWG-CONTINUOUS-LOOP-01`):** 45s autonomous governor loop in `bus_run.rs` (`■ PRODUCT` + `■ DELIVERY`).
- **`[DONE]` `TASK-12` (`CHWG-OPENSPEC-CLI-01`):** Shipped `chinwag openspec status | validate | archive` (`■ RUST`).
- **`[DONE]` `TASK-13` (`CHWG-PLUGIN-HOST-01`):** Shipped `chinwag plugin list | verify | inspect` (`■ ARCHITECT`).
- **`[DONE]` `TASK-14` (`CHWG-A509-CLI-01`):** Shipped `chinwag a509 inspect | verify` across all 10 seats (`■ ALISTAIR`).
- **`[DONE]` `TASK-15` (`BUS-HARDEN-04`):** Length-prefixed 7-field `Ed25519` canonical payload (`chinwag-bus-sig-v2`) + fail-closed `.chinwag/allowed_signers` membership check + 1800-char bus receipts (`■ RUST`).
- **`[DONE]` `TASK-16` (`BUS-HARDEN-05`):** Dynamic `UP`+`RUNNING` non-loopback IPv4 discovery via `/sbin/ifconfig` (`■ ARCHITECT`).
- **`[DONE]` `TASK-17` (`CHWG-PLUGIN-CRYPTO-01`):** Non-destructive fail-closed `Ed25519` + `.chinwag/allowed_signers` verification on `manifest.json` (`■ ALISTAIR`).
- **`[DONE]` `TASK-18` (`CHWG-DYNAMIC-TASKS-PARSER-01`):** Dynamic `TASKS.md` `[IN_PROGRESS]`/`[READY]` state-machine parser in 45s governor (`■ PRODUCT` + `■ DELIVERY`).
- **`[DONE]` `TASK-19` (`CHWG-FLINT-AUDIT-2`):** Adversarial audit of Phase 1.2 and fail-closed `allowed_signers` remediation (`■ FLINT`).
- **`[DONE]` `TASK-20` (`CHWG-QA-CROSS-HOST-1`):** Cross-machine `iroh-quic/chinwag-bus-1` delivery verified from MacBook Pro (`100.108.108.25 -> 100.66.156.76:44330`, `#149` & `#150`) (`■ QA`).
- **`[DONE]` `TASK-21` (`CHWG-AUTO-ADVANCE-TASKS-01`):** Auto-transition `COMPLETED TASK-XX` to `[DONE]` in `TASKS.md`, promote next `[READY]` item, and synthesize continuous rolling-wave tasks (`■ PRODUCT` + `■ DELIVERY`).
- **`[DONE]` `TASK-22` (`BUS-HARDEN-06`):** Removed predictable seat-derived key fallback in `actor_signing_secret` & `actor_transport_secret` in favor of `/dev/urandom` CSPRNG (`■ RUST`).
- **`[DONE]` `TASK-23` (`CHWG-PLUGIN-JCS-01`):** Full-manifest canonical `BTreeMap` `Ed25519` signing (`■ ARCHITECT`).
- **`[DONE]` `TASK-24` (`CHWG-CWCard-CLI-01`):** Shipped `chinwag cwcard inspect | verify` sealed card envelope verifier (`■ ALISTAIR`).
- **`[DONE]` `TASK-25` (`CHWG-BUS-TOP-01`):** Shipped `chinwag bus roster` 10-seat utilization table + fail-closed `F1`/`F2`/`F3` audit fixes (`■ QA` + `■ FLINT`).

---

## 3. Phase 1.4 & Phase 2.0 Active Engineering Sprint (`TASK-26` .. `TASK-34`)

### `[IN_PROGRESS]` `TASK-26` (`CHWG-TRIPLE-B-CLI-01`) — `CHWG-PAT-05` `Triple-B v2.0` Agent Bond CLI (`chinwag bond status | verify | inspect`)
- **Owner:** `■ RUST`
- **Files:** `crates/chinwag-cli/src/feature_cli_run.rs`, `crates/chinwag-cli/src/main.rs`, `.chinwag/bonds/axel-0001.cwbond.json`, `.chinwag/bonds/rando-0002.cwbond.json`
- **Scope:** Verify `chinwag bond status --json` and `chinwag bond verify --json` for `◆ AXEL (#0001)` and `◆ RAND0 (#0002)` (`Chincred` Empirical Underwriting, `OP_CSV`+`FROST` Rolling Endowment Covenant, `FSE` Adaptor Settlement, and `IETF BCP 79` `RFC-0509` royalty-free base carve-out).

### `[DONE]` `TASK-27` (`CHWG-ROGUE-STUDIO-FIREWALL-01`) — Enforce `Rogue Machine Media LLC (d/b/a Lag Lords)` (`INV-BRAND-FIREWALL-01`) Across Envelopes & UI
- **Owner:** `■ ARCHITECT`
- **Files:** `crates/chinwag-cli/src/feature_cli_run.rs`, `.chinwag/plugins/com.emunlabs.breakroom.cwplugin/manifest.json`, `.chinwag/plugins/com.emunlabs.breakroom.cwplugin/sample.cwcard.json`
- **Scope:** Verify that `chinwag plugin verify --json`, `chinwag cwcard verify --json`, and `http://127.0.0.1:44331/api/health` enforce `"studio_issuer": "Rogue Machine Media LLC (d/b/a Lag Lords)"` and `"brand_firewall_invariant": "INV-BRAND-FIREWALL-01"`.

### `[IN_PROGRESS]` `TASK-28` (`CHWG-PLUGIN-DOMAIN-SEP-01`) — Domain-Separated JCS Transcripts (`manifest` vs `cwcard` vs `cwbond`)
- **Owner:** `■ ALISTAIR`
- **Files:** `crates/chinwag-cli/src/feature_cli_run.rs`
- **Scope:** Audit `canonical_plugin_manifest_payload` (`chinwag-plugin-manifest-sig-v2|`), `canonical_cwcard_payload` (`chinwag-cwcard-envelope-sig-v1|`), and `canonical_bond_payload` (`chinwag-triple-b-bond-sig-v2|`) and run `cargo test -p chinwag-cli --bin chinwag`.

### `[DONE]` `TASK-29` (`CHWG-FLINT-AUDIT-3`) — Adversarial Security & UI Server Audit (`Phase 1.4` + `Phase 2.0`)
- **Owner:** `■ FLINT`
- **Files:** `crates/chinwag-cli/src/feature_cli_run.rs`, `crates/chinwag-cli/src/ui_workbench_run.rs`, `crates/chinwag-ui/src/app.rs`
- **Scope:** Audit `ui_workbench_run.rs`, `feature_cli_run.rs`, and `chinwag-ui` for path traversal defense, domain separation, fail-closed signature verification, and `#![forbid(unsafe_code)]`.

### `[DONE]` `TASK-30` (`CHWG-QA-FULL-GATE-2`) — Full Workspace Test Sweep (`chinwag-cli` + `chinwag-ui`) & Live `127.0.0.1:44331` Probe
- **Owner:** `■ QA`
- **Files:** `crates/chinwag-cli/src/ui_workbench_run.rs`, `crates/chinwag-ui/src/app.rs`
- **Scope:** Run `cargo test -p chinwag-cli --bin chinwag`, `cargo test -p chinwag-ui`, and verify live HTTP 200 responses on `http://127.0.0.1:44331/api/health`, `/api/bus/status`, `/api/bus/roster`, `/api/tasks`, `/api/bonds`, and `/captionizm`.

### `[IN_PROGRESS]` `TASK-32` (`CHWG-UI-DIOXUS-WORKBENCH-01`) — Live 12-View `workbench-v5` + `live-bus-bridge.js` & `chinwag-ui` Route Verification
- **Owner:** `■ TYPE`
- **Files:** `crates/chinwag-cli/src/ui_workbench_run.rs`, `crates/chinwag-ui/src/app.rs`, `crates/chinwag-ui/src/lib.rs`
- **Scope:** Verify the live 12-view Workbench (`http://127.0.0.1:44331/`), `/live-bus-bridge.js` real-time `iroh` QUIC telemetry & composer bridge, `Captionizm™` (`/captionizm`), `chinwag.tv` (`/chinwag-tv`), and all `chinwag-ui` Dioxus routes (`/`, `/comms/:channel_id`, `/workbench`, `/tasks`, `/roster`, `/captionizm`, `/a509`).

### `[READY]` `TASK-31` (`CHWG-UI-LIVE-SERVER-01`) — Zero-Mock `chinwag ui` API Endpoint & `POST /api/bus/send` Verification
- **Owner:** `■ RUST`
- **Files:** `crates/chinwag-cli/src/ui_workbench_run.rs`, `crates/chinwag-cli/src/main.rs`
- **Scope:** Verify `chinwag ui status --json` and test `GET /api/bus/status`, `GET /api/bus/messages`, `GET /api/bus/roster`, `GET /api/tasks`, `GET /api/a509`, `GET /api/bonds`, `GET /api/plugins`, and `GET /api/cwcards` on `http://127.0.0.1:44331`.

### `[READY]` `TASK-33` (`CHWG-UI-CAPTIONIZM-PLUGIN-01`) — `Captionizm™` & `chinwag.tv` Broadcast Arena Asset & Audio Verification
- **Owner:** `■ TYPE`
- **Files:** `crates/chinwag-cli/src/ui_workbench_run.rs`, `crates/chinwag-ui/src/app.rs`
- **Scope:** Verify `/07-workbench-captionizm-game.html`, `/12-chinwag-tv-broadcast-arena.html`, `/assets/axel-motif-trademarked.png`, `/assets/rando-motif-trademarked.png`, `/assets/axel-normal-guy.mp3`, and `Rogue Machine Media LLC (d/b/a Lag Lords)` badge on `http://127.0.0.1:44331`.

### `[DONE]` `TASK-34` (`CHWG-UI-QA-FLINT-GATE-01`) — Cross-Host & Headless UI Regression Gate
- **Owner:** `■ QA`
- **Files:** `crates/chinwag-ui/tests/ssr.rs`, `crates/chinwag-cli/src/ui_workbench_run.rs`
- **Scope:** Verify `cargo test -p chinwag-ui` (`20/20` green) and `cargo test -p chinwag-cli --bin chinwag` (`38/38` green) plus live `127.0.0.1:44331` HTTP/API endpoints.
