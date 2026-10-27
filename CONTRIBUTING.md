# Contributing to Chinwag & Contributor License Policy

**Corporate Steward:** `Emun Labs, Inc. · 1401 Lavaca St STE 81335, Austin, TX 78701`
**Core Repository License:** `Apache License, Version 2.0` (`SPDX-License-Identifier: Apache-2.0`)
**Legal & IP Review Authority:** `■ EAGLE-EYE` (`[BIZFIN]` · `bizfin@agentmail.to`)

Thank you for your interest in contributing to **Chinwag** (`emunlabs/chinwag`)—the local-first Multi-Agent Swarm Coordination Bus, Atomic Lease Engine, and Cryptographic Flight Recorder built in Rust.

Because Chinwag is an **Open-Core** infrastructure project maintained by **Emun Labs, Inc.**, every contribution must satisfy our **Contributor License Grant**, **Developer Certificate of Origin (DCO 1.1)**, and **Cleanroom Architectural Invariant Gates** described below.

---

## 1. Open-Core Licensing Boundary (`Apache-2.0` Core vs. Commercial Control Plane)

* **Open-Source Core (`Apache-2.0`):** The `chinwag` CLI (`chinwag-cli`), MCP server (`chinwag-mcp`), local `.chinwag/state.crdb` CRDT context & memory bus (`chinwag-claim`, `chinwag-snapshot-session`), `iroh` P2P QUIC swarm crate (`chinwag-swarm`), and RFC 9180 HPKE flight-recorder crate (`chinwag-seed`) in this repository are licensed under the **[Apache License, Version 2.0](./LICENSE)**.
* **Commercial Hosted Relay & Enterprise Control Plane:** Emun Labs, Inc. also develops and operates proprietary hosted services—including the `bootstrap.chinwag.sh` Zero-Knowledge Cloudflare Durable Object Relay, `app.chinwag.sh` Hosted Mission Control, Team Swarm Grid RBAC, and Enterprise KMS Escrow—which are governed by the Emun Labs Commercial Terms of Service.

---

## 2. Contributor License Agreement (CLA) & Developer Certificate of Origin (DCO 1.1)

To keep contribution friction near zero while protecting both the Apache-2.0 commons and Emun Labs' ability to maintain commercial and enterprise distributions, **every Pull Request or patch submitted to `emunlabs/chinwag` is governed by the following two-part Contributor Policy**:

### 2.1 Inbound License Grant to Emun Labs, Inc.
By submitting a Pull Request, commit, issue patch, or documentation change ("Contribution") to any repository owned by `Emun Labs, Inc.` (`emunlabs/*`):

1. **Apache-2.0 Section 5 Grant:** You grant to `Emun Labs, Inc.` and to recipients of software distributed by `Emun Labs, Inc.` a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license and patent license (as defined in Sections 2 and 3 of the Apache License, Version 2.0) to reproduce, prepare derivative works of, publicly display, publicly perform, sublicense, and distribute your Contribution and such derivative works.
2. **Open-Core Commercial & Relicensing Right:** In addition to the Apache-2.0 grant above, you grant **`Emun Labs, Inc.` (`1401 Lavaca St STE 81335, Austin, TX 78701`)**, its successors, and assigns a **perpetual, worldwide, non-exclusive, transferable, no-charge, royalty-free, irrevocable copyright and patent license** to use, modify, distribute, and sublicense your Contribution as part of any open-source, dual-licensed, or commercial/proprietary product or service offered by `Emun Labs, Inc.` (including `chinwag.sh` Hosted Relay, Team Swarm Grid, and Enterprise editions), without any duty of accounting or attribution beyond listing in [`CONTRIBUTORS.md`](./CONTRIBUTORS.md).
3. **AI-Assisted Contributions Permitted With Provenance:** Contributions written with the assistance of AI coding agents (Claude Code, Cursor, Codex, Grok, Gemini) are welcome—and encouraged to be coordinated via `chinwag` itself—provided you have reviewed the generated code, verified that it contains no third-party copyleft (`GPL`/`AGPL`) material, and take full DCO responsibility for the submission.

### 2.2 Mandatory Developer Certificate of Origin (`Signed-off-by:` + SSH Signature)
Every commit in a Pull Request **must** include both:
1. A **`Signed-off-by:`** trailer (`git commit -s`) certifying the [Developer Certificate of Origin v1.1](https://developercertificate.org/):
   ```text
   Signed-off-by: Your Full Name <your.email@example.com>
   ```
2. A **cryptographic Git commit signature** (`git commit -S` using an Ed25519 SSH key; you can initialize local SSH commit signing automatically with `chinwag init --repo <path>`).

---

## 3. Strict Cleanroom & Third-Party Dependency Policy (`INV-LIC-01`)

To preserve a 100% clean IP chain for enterprise and defense/regulated customers:

1. **Forbidden Licenses (`ZERO TOLERANCE`):**
   * Do **NOT** add any Cargo crate, npm package, or copied code snippet licensed under **`GPL-2.0`, `GPL-3.0`, `AGPL-3.0`, `LGPL`, `SSPL`, `BUSL`, `Commons Clause`, or `Fair-Source`**.
   * When referencing external tools (e.g., `Tart` virtualization CLI), invoke them strictly as external user-installed binaries over `std::process::Command`—never link or vendor their source code.
2. **Permitted Dependency Licenses:**
   * Only permissive licenses compatible with Apache-2.0 are allowed: **`Apache-2.0`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Unicode-3.0`, `Zlib`, `CC0-1.0`**.
3. **Mandatory 3-Line SPDX Header:**
   Every new `.rs`, `.ts`, `.tsx`, `.js`, or `.mjs` source file must begin with the canonical Emun Labs header:
   ```rust
   // Copyright 2026 Emun Labs, Inc.
   // 1401 Lavaca St STE 81335, Austin, TX 78701
   // SPDX-License-Identifier: Apache-2.0
   ```

---

## 4. Technical Workflow & Pre-PR Invariant Gates

We dogfood Chinwag to build Chinwag. Before opening a Pull Request:

### Step 1: Check Active Invariants & Tombstones
If you are using an MCP-capable coding agent (`Claude Code`, `Cursor`, `Codex`, `Gemini`), configure Chinwag for your workspace:
```bash
chinwag configure-editor --repo /absolute/path/to/chinwag --editor claude-code
```
Before modifying any crate, query active architectural invariants and negative tombstones (`what was tried, failed, and must never be repeated`):
```bash
chinwag memory recall --query "<crate-or-file-scope>"
```

### Step 2: Run the Offline Locked Workspace Test Suite
All Rust workspace tests must pass 100% in locked mode:
```bash
cargo test --workspace --locked
```

### Step 3: Run `chinwag ui-gate` for Any Mission Control UI Changes (`SOP-QA-02`)
If your PR touches any web UI (`chinwag.sh · Mission Control`), it must pass our deterministic DOM geometry & cross-model visual gate across desktop (`1440×900`), laptop (`1280×800`), and mobile (`390×844`):
```bash
chinwag ui-gate --url http://127.0.0.1:5487
```

### Step 4: Add Yourself to `CONTRIBUTORS.md`
In your PR, add your name and GitHub handle under **Section 3 (Community Contributors)** of [`CONTRIBUTORS.md`](./CONTRIBUTORS.md).

---

## 5. Security Vulnerability Reporting (`INV-SEC-01`)

Please **do not** open public GitHub issues for security vulnerabilities in `chinwag-seed` (RFC 9180 HPKE), `chinwag-signing` (Ed25519), `chinwag-mcp` (path allowlists), or `chinwag-swarm` (`iroh` QUIC). Instead, email our security team directly at **`security@emunlabs.com`** (or `brian@emunlabs.com`).
