# CHINWAG CANONICAL TASK & FLEET UTILIZATION BOARD (`TASKS.md`)

> **Single Source of Truth (`INV-TASKS-MD-01`)** — Maintained continuously by **`■ PRODUCT` (Utilization & Backlog Governor)** and **`■ DELIVERY` (Work-Stream Router & Bus Coordinator)** over the native `iroh` Multi-Party Messaging Bus (`ALPN: chinwag/bus/1` + `chinwag/agent-dispatch/1` on `0.0.0.0:44330`).
> - **Zero Web-UI Dependency:** Any human (`● Brian`, `● Nic`) or agent (`■ GEMINI-PM`, `■ PRODUCT`, `■ DELIVERY`, `■ RUST`, `■ ARCHITECT`, `■ FLINT`, `■ QA`, `■ ALISTAIR`) can inspect tasks here and communicate over `chinwag bus send` / `chinwag bus tail` / `chinwag bus inbox`.
> - **Utilization Mandate (`INV-UTIL-01` — "Always Be Working"):** `■ PRODUCT` enforces `0%` idle tolerance (`45s` autonomous governor loop `CHWG-CONTINUOUS-LOOP-01`) for `GPT (Codex)` (`■ RUST`, `■ ARCHITECT`, `■ ALISTAIR`), `■ FLINT` (`100.108.108.25:11500`), and `■ QA`. Every bus message is signed with the seat's Ed25519 key (`✓ed25519`) and formatted in local Austin Central Time (`CDT`).

---

## 1. Live Fleet Utilization & Seat Assignment (`■ PRODUCT` Telemetry)

| Seat / Handle | Engine & Host | Role / Lane | Utilization Status | Active Task | Last Bus Heartbeat |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`■ PRODUCT`** | `chinwag bus daemon` · Mac Studio (`0.0.0.0:44330`) | Fleet Utilization Governor & Backlog Prioritizer | **ACTIVE (`100%` Always-On 45s Loop)** | `TASK-11` (`CHWG-CONTINUOUS-LOOP-01`) | `2026-10-29T18:07:00 CDT` |
| **`■ DELIVERY`** | `chinwag bus daemon` · Mac Studio (`0.0.0.0:44330`) | Work-Stream Router & Multi-Party Bus Dispatcher | **ACTIVE (`100%` Always-On 45s Loop)** | `TASK-11` (`CHWG-CONTINUOUS-LOOP-01`) | `2026-10-29T18:07:00 CDT` |
| **`■ GEMINI-PM`** | `Gemini 4 Argon / Opus 5.5` · Mac Studio | Portfolio PM & Architecture Coordinator | **ACTIVE (`100%`)** | `TASK-08`..`TASK-14` Orchestration | `2026-10-29T18:07:00 CDT` |
| **`■ RUST` (`GPT`)** | `Codex CLI (gpt-6.1-sol)` · Mac Studio | Core Rust Systems (`chinwag-cli`, `chinwag-swarm`, `chinwag-claim`) | **ACTIVE (`IN_PROGRESS`)** | `TASK-08` & `TASK-12` (`BUS-HARDEN-01` + `openspec`) | `2026-10-29T18:07:00 CDT` |
| **`■ ARCHITECT` (`GPT`)** | `Codex CLI (gpt-6.1-sol)` · Mac Studio | Protocol & Containment (`CHWG-BOX-1`, `CHWG-PLUGIN-1`, `iroh`) | **ACTIVE (`IN_PROGRESS`)** | `TASK-09` & `TASK-13` (`BUS-HARDEN-02` + `plugin`) | `2026-10-29T18:07:00 CDT` |
| **`■ FLINT`** | `flint-agent` · MacBook Pro (`100.108.108.25:11500`) | Adversarial Code Review, Clippy/Test Gate & Diff Audit | **ACTIVE (`IN_PROGRESS`)** | `TASK-10` (`BUS-HARDEN-03` Re-Audit) | `2026-10-29T18:07:00 CDT` |
| **`■ ALISTAIR`** | `Codex / Claude Security Auditor` · Mac Studio | Ed25519 Per-Seat Signing, Seatbelt SBPL & `allowed_signers` | **ACTIVE (`IN_PROGRESS`)** | `TASK-07` & `TASK-14` (`allowed_signers` + `a509`) | `2026-10-29T18:07:00 CDT` |
| **`■ QA`** | `Cleanroom Runner / Flint Gate` · Mac Studio + MBP | Workspace Test Suite, `chinwag ui-gate` & Cleanroom Verification | **ACTIVE (`IN_PROGRESS`)** | `TASK-06` (`ui-gate` & Full CLI Test Sweep) | `2026-10-29T18:07:00 CDT` |

---

## 2. Quick-Reference: Multi-Party `iroh` Bus & Feature CLI Commands

```bash
# 1. Check live iroh QUIC EndpointId, bound UDP sockets (0.0.0.0:44330), Ed25519 verified count & utilization:
chinwag bus status

# 2. Send an Ed25519-signed multi-party message to #mgmt, #eng, or #qa:
chinwag bus send --from Brian --room "#mgmt" "Status check: report progress on TASK-06 through TASK-14"

# 3. Tail multi-party messages in local Central Time (CDT) with ✓ed25519 verification badges:
chinwag bus tail --limit 25
chinwag bus tail -f

# 4. Trigger PRODUCT + DELIVERY to immediately wake all seats on active tasks:
chinwag bus wake

# 5. Run the new OpenSpec, Plugin (.cwplugin), and A.509 Passport CLIs (TASK-12, TASK-13, TASK-14):
chinwag openspec validate --json
chinwag plugin verify --json
chinwag a509 verify --json
```

---

## 3. Completed Foundation Tasks (`TASK-01` .. `TASK-05`)

- **`[DONE]` `TASK-01` (`CHWG-MAIN-UNIFY-1`):** Unified `origin/main`, `chore/chwg-main-hygiene-1`, `feat/per-seat-signing`, `chore/per-agent-signing`, and `feat/iroh-agent-dispatch` onto `main`.
- **`[DONE]` `TASK-02` (`CHWG-IROH-BUS-1`):** Built multi-party `iroh` QUIC bus (`ALPN: chinwag/bus/1`) + `docs/iroh-multiparty-bus-and-tasks-router-v1.md`.
- **`[DONE]` `TASK-03` (`CHWG-OPENSPEC-CLI-1`):** Verified `seat_signing` and `ui_gate` integration suites (`■ RUST`).
- **`[DONE]` `TASK-04` (`CHWG-SWARM-VERIFY-1`):** Verified `chinwag-swarm` `dispatch_wire` and `chinwag-claim` two-horizon lease tests (`■ ARCHITECT`).
- **`[DONE]` `TASK-05` (`CHWG-FLINT-AUDIT-1`):** Completed adversarial audit (`■ FLINT` `#013`), surfacing `BUS-HARDEN-01..03`.

---

## 4. Phase 1.1 Hardening & CLI Feature Sprint (`TASK-06` .. `TASK-14`)

### `[IN_PROGRESS]` `TASK-06` (`CHWG-QA-SWEEP-1`) — Workspace `chinwag ui-gate` & CLI Determinism Sweep
- **Owner:** `■ QA`
- **Scope:** Execute `chinwag ui-gate --json`, `chinwag openspec validate --json`, `chinwag plugin verify --json`, `chinwag a509 verify --json`, and `cargo test -p chinwag-cli`, posting QA gate receipt to `#qa` and `#mgmt`.

### `[IN_PROGRESS]` `TASK-07` (`CHWG-SIGN-AUDIT-1`) — Per-Seat Ed25519 `allowed_signers` & 10-Seat Key Provisioning
- **Owner:** `■ ALISTAIR`
- **Scope:** Provision and verify OpenSSH Ed25519 keys under `~/.chinwag/signing/<seat>_ed25519` and `.chinwag/allowed_signers` for all 10 seats (`rust`, `architect`, `flint`, `qa`, `alistair`, `type`, `gemini-pm`, `product`, `delivery`, `brian`).

### `[IN_PROGRESS]` `TASK-08` (`BUS-HARDEN-01`) — Detached `Ed25519` Message Signatures on `BusMessage`
- **Owner:** `■ RUST` (`GPT / Codex`) + `■ ALISTAIR`
- **Files:** `crates/chinwag-cli/src/bus_run.rs`, `crates/chinwag-swarm/src/identity.rs`
- **Scope:** Sign canonical payload `{id}:{ts_unix}:{sender}:{to}:{room}:{body}` with each seat's Ed25519 key, verify on daemon ingress (`sig_verified = true`), and persist `pubkey_ed25519`, `signature_ed25519`, and `sig_verified` in `messages.jsonl` and `bus.sqlite`.

### `[IN_PROGRESS]` `TASK-09` (`BUS-HARDEN-02`) — Multi-Interface Daemon Binding (`0.0.0.0:44330`) & `origin/main` + MBP (`100.108.108.25`) Sync
- **Owner:** `■ ARCHITECT` (`GPT / Codex`) + `■ DELIVERY`
- **Files:** `crates/chinwag-cli/src/bus_run.rs`
- **Scope:** Bind `chinwag bus daemon` on `0.0.0.0:44330` (serving `127.0.0.1:44330` and Tailscale/LAN `100.66.156.76:44330`), push unified `main` to `origin/main`, and sync MBP (`100.108.108.25`).

### `[IN_PROGRESS]` `TASK-10` (`BUS-HARDEN-03`) — 5-Attempt Retry & Explicit CRDB Error in `agent_dispatch_run.rs` + Advisory `flock` in `bus_run.rs`
- **Owner:** `■ RUST` (`GPT / Codex`) + `■ FLINT` (`100.108.108.25:11500`)
- **Files:** `crates/chinwag-cli/src/agent_dispatch_run.rs`, `crates/chinwag-cli/src/bus_run.rs`
- **Scope:** Replace silent `deferred:` CRDB masking in `agent_dispatch_run.rs` with a 5-attempt backoff loop (`50ms..250ms`) and explicit `error:` status (`crdb_persisted: false`), wrap `messages.jsonl` read-modify-write in `rustix::fs::flock` on `.chinwag/bus/bus.lock`, and set `PRAGMA busy_timeout=5000;` on SQLite writes.

### `[IN_PROGRESS]` `TASK-11` (`CHWG-CONTINUOUS-LOOP-01`) — Autonomous 45s `■ PRODUCT` + `■ DELIVERY` Backlog Governor
- **Owner:** `■ PRODUCT` + `■ DELIVERY`
- **Files:** `crates/chinwag-cli/src/bus_run.rs`
- **Scope:** Run a persistent 45-second governor ticker inside `chinwag bus daemon` (plus immediate `chinwag bus wake`) that checks seat `.pid` liveness and dispatches `■ RUST`, `■ ARCHITECT`, `■ FLINT`, `■ ALISTAIR`, and `■ QA` continuously.

### `[IN_PROGRESS]` `TASK-12` (`CHWG-OPENSPEC-CLI-01`) — `chinwag openspec status | validate | archive` Subcommand
- **Owner:** `■ RUST` (`GPT / Codex`)
- **Files:** `crates/chinwag-cli/src/feature_cli_run.rs`, `crates/chinwag-cli/src/main.rs`
- **Scope:** Implement `chinwag openspec status | validate | archive [--json]` to validate `docs/*.md` specifications and `TASKS.md` invariants (`INV-TASKS-MD-01`, `INV-OPENSPEC-01`).

### `[IN_PROGRESS]` `TASK-13` (`CHWG-PLUGIN-HOST-01`) — `chinwag plugin list | verify | inspect` `.cwplugin` Ed25519 Verifier CLI
- **Owner:** `■ ARCHITECT` (`GPT / Codex`) + `■ ALISTAIR`
- **Files:** `crates/chinwag-cli/src/feature_cli_run.rs`, `crates/chinwag-cli/src/main.rs`
- **Scope:** Implement `chinwag plugin list | verify | inspect [--json]` enforcing `CHWG-PLUGIN-1` invariants (`INV-PLUGIN-SIG-01`, `INV-PLUGIN-SEATBELT-01`, `INV-PLUGIN-CHIP-01`, `INV-PLUGIN-EGRESS-01`, `INV-PLUGIN-ENT-01`).

### `[IN_PROGRESS]` `TASK-14` (`CHWG-A509-CLI-01`) — `chinwag a509 inspect | verify` 10-Seat `RFC-0509` Passport & `allowed_signers` Auditor
- **Owner:** `■ ALISTAIR` + `■ RUST`
- **Files:** `crates/chinwag-cli/src/feature_cli_run.rs`, `crates/chinwag-cli/src/main.rs`
- **Scope:** Implement `chinwag a509 inspect | verify [--json]` auditing all 10 active seats (`rust`, `architect`, `flint`, `qa`, `alistair`, `type`, `gemini-pm`, `product`, `delivery`, `brian`) against `~/.chinwag/signing/<seat>_ed25519`, `iroh::EndpointId`, and `.chinwag/allowed_signers`.
