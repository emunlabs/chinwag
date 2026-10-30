# CHINWAG CANONICAL TASK & FLEET UTILIZATION BOARD (`TASKS.md`)

> **Single Source of Truth (`INV-TASKS-MD-01`)** — Maintained continuously by **`■ PRODUCT` (Utilization & Backlog Governor)** and **`■ DELIVERY` (Work-Stream Router & Bus Coordinator)** over the native `iroh` Multi-Party Messaging Bus (`ALPN: chinwag/bus/1` + `chinwag/agent-dispatch/1` on `0.0.0.0:44330`).
> - **Dynamic Markdown Task Parser (`CHWG-DYNAMIC-TASKS-PARSER-01`):** `chinwag bus daemon` and `chinwag bus wake` dynamically parse `### [IN_PROGRESS] TASK-XX` and `### [READY] TASK-XX` sections directly from this file every `45s` (`INV-UTIL-01` — `0%` Idle Tolerance) and route them to `■ RUST`, `■ ARCHITECT`, `■ FLINT`, `■ ALISTAIR`, and `■ QA`.
> - **Cryptographic Bus Provenance (`BUS-HARDEN-04`):** Every `BusMessage` is signed over the 7-field canonical transcript (`id:ts_unix:sender:to:room:task_id:body`) and verified against `.chinwag/allowed_signers` (`✓ed25519`), with full 1800-character technical receipts in local Austin Central Time (`CDT`).

---

## 1. Live Fleet Utilization & Seat Assignment (`■ PRODUCT` Telemetry)

| Seat / Handle | Engine & Host | Role / Lane | Utilization Status | Active Task | Last Bus Heartbeat |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`■ PRODUCT`** | `chinwag bus daemon` · Mac Studio (`0.0.0.0:44330`) | Fleet Utilization Governor & Dynamic `TASKS.md` Parser | **ACTIVE (`100%` Always-On 45s Loop)** | `TASK-18` (`CHWG-DYNAMIC-TASKS-PARSER-01`) | `2026-10-29T18:16:00 CDT` |
| **`■ DELIVERY`** | `chinwag bus daemon` · Mac Studio (`0.0.0.0:44330`) | Work-Stream Router & Multi-Party Bus Dispatcher | **ACTIVE (`100%` Always-On 45s Loop)** | `TASK-18` (`CHWG-DYNAMIC-TASKS-PARSER-01`) | `2026-10-29T18:16:00 CDT` |
| **`■ GEMINI-PM`** | `Gemini 4 Argon / Opus 5.5` · Mac Studio | Portfolio PM & Architecture Coordinator | **ACTIVE (`100%`)** | `TASK-15`..`TASK-20` Orchestration | `2026-10-29T18:16:00 CDT` |
| **`■ RUST` (`GPT`)** | `Codex CLI (gpt-6.1-sol)` · Mac Studio | Core Rust Systems (`chinwag-cli`, `chinwag-swarm`, `chinwag-claim`) | **ACTIVE (`IN_PROGRESS`)** | `TASK-15` (`BUS-HARDEN-04` 7-Field Sig & `allowed_signers`) | `2026-10-29T18:16:00 CDT` |
| **`■ ARCHITECT` (`GPT`)** | `Codex CLI (gpt-6.1-sol)` · Mac Studio | Protocol & Containment (`CHWG-BOX-1`, `CHWG-PLUGIN-1`, `iroh`) | **ACTIVE (`IN_PROGRESS`)** | `TASK-16` & `TASK-17` (`BUS-HARDEN-05` + `.cwplugin` Ed25519) | `2026-10-29T18:16:00 CDT` |
| **`■ FLINT`** | `flint-agent` · MacBook Pro (`100.108.108.25:11500`) | Adversarial Code Review, Clippy/Test Gate & Diff Audit | **ACTIVE (`IN_PROGRESS`)** | `TASK-19` (Adversarial Audit of Phase 1.2 `BUS-HARDEN-04..05`) | `2026-10-29T18:16:00 CDT` |
| **`■ ALISTAIR`** | `Codex / Claude Security Auditor` · Mac Studio | Ed25519 Per-Seat Signing, `.cwplugin` Crypto & `allowed_signers` | **ACTIVE (`IN_PROGRESS`)** | `TASK-17` (`CHWG-PLUGIN-CRYPTO-01` Ed25519 Manifest Audit) | `2026-10-29T18:16:00 CDT` |
| **`■ QA`** | `Cleanroom Runner / Flint Gate` · Mac Studio + MBP | Workspace Test Suite, Cross-Host QUIC Probe & Determinism | **ACTIVE (`IN_PROGRESS`)** | `TASK-20` (Cross-Host MBP `100.108.108.25` QUIC & Test Gate) | `2026-10-29T18:16:00 CDT` |

---

## 2. Completed Foundation & Phase 1.1 Tasks (`TASK-01` .. `TASK-14`)

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

---

## 3. Completed Phase 1.2 Tasks (`TASK-15` .. `TASK-20`)

- **`[DONE]` `TASK-15` (`BUS-HARDEN-04`):** Length-prefixed 7-field `Ed25519` canonical payload (`chinwag-bus-sig-v2`) + fail-closed `.chinwag/allowed_signers` membership check + 1800-char bus receipts + explicit `RUSTUP_TOOLCHAIN=1.97.1` worker injection (`■ RUST`).
- **`[DONE]` `TASK-16` (`BUS-HARDEN-05`):** Dynamic `UP`+`RUNNING` non-loopback IPv4 discovery via `/sbin/ifconfig`, fail-closed nonzero port binding, and remote `DaemonState` synthesis when `CHINWAG_BUS_ADDR` is set (`■ ARCHITECT`).
- **`[DONE]` `TASK-17` (`CHWG-PLUGIN-CRYPTO-01`):** Non-destructive fail-closed `Ed25519` + `.chinwag/allowed_signers` verification on `.chinwag/plugins/com.emunlabs.breakroom.cwplugin/manifest.json` (`■ ALISTAIR`).
- **`[DONE]` `TASK-18` (`CHWG-DYNAMIC-TASKS-PARSER-01`):** Dynamic `TASKS.md` `[IN_PROGRESS]`/`[READY]` state-machine parser in 45s governor (`■ PRODUCT` + `■ DELIVERY`).
- **`[DONE]` `TASK-19` (`CHWG-FLINT-AUDIT-2`):** Adversarial audit of Phase 1.2 and fail-closed `allowed_signers` remediation (`■ FLINT`).
- **`[DONE]` `TASK-20` (`CHWG-QA-CROSS-HOST-1`):** Cross-machine `iroh-quic/chinwag-bus-1` delivery verified from MacBook Pro (`100.108.108.25 -> 100.66.156.76:44330`, `#149` & `#150`) (`■ QA`).

---

## 4. Phase 1.3 Active Engineering Sprint (`TASK-21` .. `TASK-25`)

### `[IN_PROGRESS]` `TASK-21` (`CHWG-AUTO-ADVANCE-TASKS-01`) — Auto-Transition `COMPLETED TASK-XX` to `[DONE]` in `TASKS.md` & Promote Next `[READY]` Item
- **Owner:** `■ PRODUCT` + `■ DELIVERY`
- **Files:** `crates/chinwag-cli/src/bus_run.rs`, `TASKS.md`
- **Scope:** When a worker posts a verified (`sig_verified == true`) `COMPLETED TASK-XX` or `[DONE]` message, automatically transition `### [IN_PROGRESS] TASK-XX` to `### [DONE] TASK-XX` under `.chinwag/bus/bus.lock` and promote the next `[READY]` task for that seat to `[IN_PROGRESS]`.

### `[DONE]` `TASK-22` (`BUS-HARDEN-06`) — Remove Predictable Seat-Derived Key Fallback in `actor_signing_secret` & `actor_transport_secret`
- **Owner:** `■ RUST` (`GPT / Codex`)
- **Files:** `crates/chinwag-cli/src/bus_run.rs`
- **Scope:** Verify that `actor_signing_secret` and `actor_transport_secret` use `/dev/urandom` CSPRNG (`os_csprng_32_bytes`) instead of any predictable SHA-256 seat-name seed, and verify `auto_advance_tasks_markdown` unit test coverage (`cargo test -p chinwag-cli --bin chinwag`).

### `[DONE]` `TASK-23` (`CHWG-PLUGIN-JCS-01`) — Full-Manifest Canonical JSON `Ed25519` Signing & `display_name` Tamper-Rejection
- **Owner:** `■ ARCHITECT` (`GPT / Codex`)
- **Files:** `crates/chinwag-cli/src/feature_cli_run.rs`, `.chinwag/plugins/com.emunlabs.breakroom.cwplugin/manifest.json`
- **Scope:** Verify that `canonical_plugin_manifest_payload` signs the entire canonical JSON `BTreeMap` object (excluding `payload_sha256` and `signature_ed25519`), so mutating `display_name` or any field in `manifest.json` fails verification.

### `[DONE]` `TASK-24` (`CHWG-CWCard-CLI-01`) — Captionizm™ `.cwcard` HPKE+BLAKE3+Ed25519 Sealed Card Envelope Verifier (`chinwag cwcard inspect | verify`)
- **Owner:** `■ ALISTAIR`
- **Files:** `crates/chinwag-cli/src/feature_cli_run.rs`, `.chinwag/plugins/com.emunlabs.breakroom.cwplugin/sample.cwcard.json`
- **Scope:** Audit `verify_cwcard_json` and `chinwag cwcard verify --json` to confirm full-envelope `Ed25519` signature + `.chinwag/allowed_signers` verification on `.cwcard` sealed card envelopes.

### `[DONE]` `TASK-25` (`CHWG-BUS-TOP-01`) — Live 10-Seat Swarm Utilization Roster (`chinwag bus roster`) & Adversarial Gate
- **Owner:** `■ QA`
- **Files:** `crates/chinwag-cli/src/bus_run.rs`, `crates/chinwag-cli/src/feature_cli_run.rs`
- **Scope:** Verify `chinwag bus roster --json`, `chinwag cwcard verify --json`, `chinwag plugin verify --json`, and all `35/35` `chinwag-cli` automated tests.
