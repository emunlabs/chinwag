# Native wait P2.B author verification — 2026-11-09

Task: `CHWG-WAIT-CI-P2-BUS-WAIT`. Author result: **done, pending independent
review**. This is source/test evidence, not acceptance of a host adapter or
authorization to replace a running daemon or timer.

## Source binding

- Admission packet v2 SHA-256:
  `88a4648be3c0dfa9bd2df3c4acb7f27ee91aa60ae796ad07f2bbbe42793066c0`.
- Frozen Phase 1 v4 SHA-256:
  `166567a578ff907fdcbcd0512d40e3037fd7feb9a37f59c594448d00895b5dcc`.
- Reconciled base commit: `d326c7129979ca43499547842daac076d80fac35`.
- Base tree: `69c3b294b10a74190b894e2be486138c61772d83`.
- `c4f8395af729fd7aecf5365f6a4b261a824d83ce` is already an ancestor
  of that base; no CI merge was necessary.
- Tested implementation commit: `737ea7d4c2aa66ddd1cd8ff1f44a28743e9247e8`.
- Tested tree: `f7ff40e80f3571baaaa08d1ff4f957346a2e4b26`.
- Review branch: `workhorse/review-wait-ci-p2-20261109` in `emunlabs/chinwag`.

The base was reported before feature edits. Source changes are confined to
`crates/chinwag-cli/**`. The accepted CI crate, CI workflow, workspace manifest
and lockfile remain unchanged. Native product code and fixtures are Rust, with
the pinned toolchain/dependencies and the existing approved private native
build input. Private inputs, runtime state and original message bodies are not
included in this source checkpoint.

## Executed verification

| Check | Observed result |
| --- | --- |
| `cargo check -p chinwag-cli --all-targets --locked` | PASS |
| `cargo test -p chinwag-cli --all-targets --locked` | PASS: 722 passed, 0 failed, 4 explicitly ignored across 13 result groups |
| `cargo clippy -p chinwag-cli --all-targets --locked -- -D warnings` | PASS |
| Explicit owner-supplied preserved-original tests, `--lib bus_wait_ -- --ignored` | PASS: 2 passed, 0 failed |
| Source whitespace check | PASS |
| Described JJ checkpoints, push and exact remote-ref readback | Verified after each milestone |

The full test run's ignored tests include two separately executed preserved
original tests and two pre-existing child-entry fixtures invoked by controlled
parent tests. The two preserved-original checks verify unchanged signature and
digest bytes, then exercise durable handoff from that same original in an
isolated repository. The expected original is
`bus-1794264873-2b8773b6`, digest
`2b8773b67437fe6174d54b112915bab0cac059846b1c41d034cc5c5904e469c7`.
It was not re-signed. The source fixture file's approved hash was checked again.

An earlier run stopped after two temporary-path fixture failures. Both used
macOS `/var` aliases rejected by the retained no-symlink directory guard. After
the owner explicitly authorized corrective continuation, the fixtures were
changed to physical canonical paths; the production guard was not weakened.
The corrected targeted suite and subsequent complete CLI suite passed. The
original failed logs and the blocked WIP checkpoint remain preserved.

## Gate evidence boundary

| Gate | Source/unit evidence supplied | Still requires independent host acceptance |
| --- | --- | --- |
| G-01 | Native broadcast/timeout wait path has no model/provider call; tested notification ordering and timeout | OS resource trace and provider telemetry for an actual idle host |
| G-02 | Durable token/reservation precedes handoff; authenticated admission and actual-start states remain distinct | Actual same-chat turn-start trace with no simultaneous human input |
| G-03 | Signed burst filtering, 16-message coalescing, one queued admission/quota slot and explicit backpressure | Supported host serialization during real user overlap |
| G-04 | Preserved real signature/digest verification; malformed/JCS receipt rejection; exact recipient; tuple/token checks | Independent adversarial/host review |
| G-05 | Orphan-token recovery, pre-ACK UNKNOWN holds, atomic cursor/quota, authenticated lifecycle, owner reconciliation and stale-proof refusal | Actual host admission-loss/crash cut points and supported idempotent lookup |
| G-06 | Exact archive anchor catch-up, retained deduplication, missing-anchor refusal, private files, grant signature/revocation/expiry | Independent reconnect/rotation and cross-UID runtime proof |
| G-07 | Native timeout hint, no lock across blocking callback, honest offline/unsupported posture | Supported host adapter runtime acceptance |

Enrollment imports owner-signed grant/authority artifacts. It does not
bootstrap an owner key. No host idempotency lookup capability is fabricated:
unknown restart outcomes remain held even when a grant claims such support.
Explicit owner `NEVER_RECEIVED` reconciliation preserves the original reserved
quota slot; unsupported post-admission reconciliation remains held. See
`native-wait.md` for the exact current interface and conservative limits.

## Execution limits and handoff

The corrective continuation used the existing 45-minute wall window and total
20-invocation Cargo ceiling, without reset: 18 Cargo check/test/Clippy
invocations total, including the preserved earlier failures, and 2 of the
6 allowed writer execution turns. Source/test verification finished before
the original `2026-11-10T02:00:16.857Z` wall deadline. No paid subagent dispatch,
host adapter dispatch, candidate daemon installation, merge, release or timer
switch was performed. The existing operational daemon processes and the one
two-minute monitor were preserved.

Independent ARCHITECT/ALISTAIR/FLINT/QA acceptance and later P2.C/P2.D host proof
remain pending. This record does not self-accept those gates.
