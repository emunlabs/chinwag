# CHINWAG CANONICAL TASK & FLEET UTILIZATION BOARD (`TASKS.md`)

> **Single Source of Truth (`INV-TASKS-MD-01`)** — Maintained continuously by **`■ PRODUCT` (Utilization & Backlog Governor)** and **`■ DELIVERY` (Work-Stream Router & Bus Coordinator)** over the native `iroh` Multi-Party Messaging Bus (`ALPN: chinwag/bus/1` + `iroh_gossip::ALPN`).
> - **Zero Web-UI Dependency:** Any human (`● Brian`, `● Nic`) or agent (`■ GEMINI-PM`, `■ PRODUCT`, `■ DELIVERY`, `■ RUST`, `■ ARCHITECT`, `■ FLINT`, `■ QA`, `■ ALISTAIR`) can inspect tasks here and communicate over `chinwag bus send` / `chinwag bus tail` / `chinwag bus inbox`.
> - **Utilization Mandate (`INV-UTIL-01`):** `■ PRODUCT` enforces `<60s` idle tolerance for `GPT (Codex)` and `■ FLINT` whenever `READY` engineering or verification tasks exist in this file. `■ DELIVERY` automatically routes work streams, spawns/monitors execution, and posts signed receipts to `.chinwag/bus/messages.jsonl` and `.chinwag/state.crdb`.

---

## 1. Live Fleet Utilization & Seat Assignment (`■ PRODUCT` Telemetry)

| Seat / Handle | Engine & Host | Role / Lane | Utilization Status | Active Task | Last Bus Heartbeat |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`■ PRODUCT`** | `chinwag bus daemon` · Mac Studio | Fleet Utilization Governor & Backlog Prioritizer | **ACTIVE (`100%` Always-On)** | `TASK-00` (Continuous Utilization Watch) | `2026-10-29T14:43:00-05:00` |
| **`■ DELIVERY`** | `chinwag bus daemon` · Mac Studio | Work-Stream Router & Multi-Party Bus Dispatcher | **ACTIVE (`100%` Always-On)** | `TASK-00` (Continuous Work-Stream Routing) | `2026-10-29T14:43:00-05:00` |
| **`■ GEMINI-PM`** | `Gemini 4 Argon / Opus 5.5` · Mac Studio | Portfolio PM & Architecture Coordinator | **ACTIVE (`100%`)** | `TASK-01` & `TASK-02` (`iroh` Bus Unification) | `2026-10-29T14:43:00-05:00` |
| **`■ RUST` (`GPT`)** | `Codex CLI (gpt-6.1-sol)` · Mac Studio | Core Rust Systems (`chinwag-cli`, `chinwag-swarm`, `chinwag-claim`) | **DISPATCHING -> IN_PROGRESS** | `TASK-03` (`chinwag openspec sync` + Bus Tests) | `2026-10-29T14:43:00-05:00` |
| **`■ ARCHITECT` (`GPT`)** | `Codex CLI (gpt-6.1-sol)` · Mac Studio | Protocol & Containment (`CHWG-BOX-1`, `A.509`, `iroh` Wire) | **DISPATCHING -> IN_PROGRESS** | `TASK-04` (`CHWG-BOX-1` Two-Horizon Lease Audit & Tests) | `2026-10-29T14:43:00-05:00` |
| **`■ FLINT`** | `flint-agent` · MacBook Pro (`100.108.108.25:11500`) | Adversarial Code Review, Clippy/Test Gate & Diff Audit | **DISPATCHING -> IN_PROGRESS** | `TASK-05` (Adversarial Audit of `iroh` Bus & `seat_signing`) | `2026-10-29T14:43:00-05:00` |
| **`■ QA`** | `Claude / Cleanroom Runner` · Mac Studio + MBP | Workspace Test Suite, `chinwag ui-gate` & Cleanroom Verification | **READY -> QUEUED** | `TASK-06` (Full Workspace `cargo test` & `ui-gate` Sweep) | `2026-10-29T14:43:00-05:00` |
| **`■ ALISTAIR`** | `Claude / Security Auditor` · Mac Studio | Ed25519 Per-Seat Signing, Seatbelt SBPL & `allowed_signers` | **READY -> QUEUED** | `TASK-07` (`allowed_signers` & `iroh` Replay-Cache Verification) | `2026-10-29T14:43:00-05:00` |

---

## 2. Quick-Reference: Multi-Party `iroh` Bus CLI Commands (`chinwag bus`)

```bash
# 1. Check live iroh QUIC EndpointId, bound UDP ports, room counts & agent utilization:
chinwag bus status

# 2. Send a multi-party message to #mgmt or #eng (auto-signed + broadcast over iroh QUIC):
chinwag bus send --from Brian --room "#mgmt" "Status check: GPT and FLINT report progress on TASK-03 and TASK-05"
chinwag bus send --from PRODUCT --room "#eng" --task TASK-03 "@RUST @FLINT utilization check — post your current commit and test status"

# 3. Tail multi-party messages across all rooms (#mgmt, #eng, #qa) in real time:
chinwag bus tail -f
chinwag bus tail --room "#eng" --limit 25

# 4. Read inbox messages addressed to a specific seat or human:
chinwag bus inbox --for Brian
chinwag bus inbox --for FLINT

# 5. Trigger PRODUCT + DELIVERY to immediately wake idle seats (GPT/Codex & FLINT) on READY tasks:
chinwag bus wake
```

---

## 3. Active Engineering Sprint Queue (`P0` — Core `chinwag` & Multi-Party `iroh` Bus)

### `[DONE]` `TASK-01` — Unify Unmerged Branches onto `main` (`CHWG-MAIN-UNIFY-1`)
- **Owner:** `■ GEMINI-PM` + `■ DELIVERY`
- **Scope:** Merge `origin/main` (`2c83a00` `CHWG-DIOXUS-1`), `chore/chwg-main-hygiene-1` (`ea932e6`), `feat/per-seat-signing` (`9b91f20`), `chore/per-agent-signing` (`0bf1f36`), and `feat/iroh-agent-dispatch` (`e1ce24a`) cleanly onto `main` in `/Users/brianspector/WORKSPACE/chinwag`.
- **Acceptance Gate:** Zero merge conflicts, `cargo check --bin chinwag` passes under `rustc 1.97.1`.

### `[IN_PROGRESS]` `TASK-02` — Zero-Friction Multi-Party `iroh` Messaging Bus & Always-On `PRODUCT`/`DELIVERY` Daemon (`CHWG-IROH-BUS-1`)
- **Owner:** `■ GEMINI-PM` + `■ DELIVERY` + `■ PRODUCT`
- **Files:** `crates/chinwag-cli/src/bus_run.rs`, `crates/chinwag-cli/src/main.rs`, `.chinwag/bus/messages.jsonl`
- **Scope:**
  1. Bind a persistent `iroh::Endpoint` (`ALPN: chinwag/bus/1` + `iroh_gossip::ALPN`) on UDP/QUIC (`127.0.0.1:44330` + LAN interface) so every participant shares a live multi-party message bus without needing 6 manual CLI flags.
  2. Support `chinwag bus daemon`, `chinwag bus send`, `chinwag bus tail`, `chinwag bus inbox`, `chinwag bus status`, and `chinwag bus wake`.
  3. Embed the **`■ PRODUCT` Utilization Governor** + **`■ DELIVERY` Work-Stream Router** loop inside `chinwag bus daemon` so idle `GPT (Codex)` and `■ FLINT` engines are automatically assigned work from `TASKS.md` and post multi-party status updates onto the bus.
- **Acceptance Gate:** `chinwag bus status` shows `ONLINE` with bound `iroh` `EndpointId`; `chinwag bus send` and `chinwag bus tail` exchange multi-party messages across `● Brian`, `■ PRODUCT`, `■ DELIVERY`, `■ GEMINI-PM`, `■ RUST (GPT)`, and `■ FLINT`.

### `[IN_PROGRESS]` `TASK-03` — `GPT (Codex)` Work Stream A: `chinwag bus` Integration Tests & `chinwag openspec` Spec-Sync Scaffolding (`CHWG-OPENSPEC-CLI-1`)
- **Owner:** `■ RUST` (`GPT / Codex CLI`)
- **Routed By:** `■ DELIVERY` (Assigned via `chinwag bus`)
- **Files:** `crates/chinwag-cli/src/bus_run.rs`, `crates/chinwag-cli/tests/`
- **Scope:**
  1. Verify `crates/chinwag-cli` compiles cleanly with zero clippy warnings (`cargo clippy -p chinwag-cli -- -D warnings`).
  2. Run and verify `seat_signing` and `ui_gate` integration tests (`cargo test -p chinwag-cli --test seat_signing --test ui_gate`) and post the test receipt directly to `#eng` via `chinwag bus send --from RUST --room "#eng" --task TASK-03`.

### `[IN_PROGRESS]` `TASK-04` — `GPT (Codex)` Work Stream B: `chinwag-swarm` `iroh` Wire & Two-Horizon Claim Verification (`CHWG-SWARM-VERIFY-1`)
- **Owner:** `■ ARCHITECT` (`GPT / Codex CLI`)
- **Routed By:** `■ DELIVERY` (Assigned via `chinwag bus`)
- **Files:** `crates/chinwag-swarm/src/dispatch_wire.rs`, `crates/chinwag-claim/src/lib.rs`
- **Scope:**
  1. Run `cargo test -p chinwag-swarm -p chinwag-claim` and verify the `iroh` `ALPN chinwag/agent-dispatch/1` wire framing, Ed25519 signature verification, and replay-cache invariants.
  2. Post the architectural verification receipt to `#eng` and `#mgmt` via `chinwag bus send --from ARCHITECT --room "#eng" --task TASK-04`.

### `[IN_PROGRESS]` `TASK-05` — `■ FLINT` Work Stream: Adversarial Security & Code Quality Audit of Unified `main` (`CHWG-FLINT-AUDIT-1`)
- **Owner:** `■ FLINT` (`flint-agent` · `http://100.108.108.25:11500/v1`)
- **Routed By:** `■ PRODUCT` + `■ DELIVERY` (Assigned via `chinwag bus`)
- **Files:** `crates/chinwag-cli/src/seat_signing.rs`, `crates/chinwag-cli/src/dispatch_listen.rs`, `crates/chinwag-cli/src/bus_run.rs`
- **Scope:**
  1. Perform an adversarial review of the newly merged `seat_signing.rs`, `dispatch_listen.rs`, and `bus_run.rs` on `main`.
  2. Post concrete findings/verdict (`PASS` or `BLOCKERS`) to `#eng` and `#mgmt` via `chinwag bus send --from FLINT --room "#eng" --task TASK-05`.

### `[READY]` `TASK-06` — Workspace `chinwag ui-gate` & Cleanroom Determinism Sweep (`CHWG-QA-SWEEP-1`)
- **Owner:** `■ QA`
- **Routed By:** `■ DELIVERY`
- **Scope:** Execute `chinwag ui-gate --repo /Users/brianspector/WORKSPACE/chinwag --json` and verify exit code `0` with all required invariants green.

### `[READY]` `TASK-07` — Per-Seat Ed25519 `allowed_signers` & `A.509` Key Alignment (`CHWG-SIGN-AUDIT-1`)
- **Owner:** `■ ALISTAIR`
- **Routed By:** `■ DELIVERY`
- **Scope:** Audit `.chinwag/allowed_signers` against the 10 active seats (`rust`, `architect`, `flint`, `qa`, `alistair`, `type`, `gemini-pm`, `product`, `delivery`, `brian`) and post verification receipt to `#mgmt`.
