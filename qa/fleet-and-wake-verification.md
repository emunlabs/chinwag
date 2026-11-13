# Fleet and message-arrival wake verification

Scope: CHWG-0272–CHWG-0275 / CHWG-0224; issues #83, #84, #85, #86, #50.

Branch: `feat/chwg-0272-fleet-and-wake`.
Base: `03871481a259dd61e0d1fcc09eed651f07bd81b0`.
Actor: `ARCHITECT#caae562efd28ef893f8a6dff2b677a94`.
Observed at: 2026-11-13T09:49:35.330401+00:00

All commands ran inside the assigned worktree with Rust 1.97.1, the assigned Cargo target directory, private native CRSQL input, workspace-local temporary/recovery directories, the built `chinwag-ci` binary, and `RUST_TEST_THREADS=1`.

The native archive was read only. Its SHA-256 remained unchanged:
`13dea052125980dc11a92587d63d8878e49f37554fb9a7acd6939a15ce6654ac`.

## Required commands and exact observed result lines

```text
$ cargo fmt --all -- --check
(no output)
exit_code=0
```

```text
$ cargo check --workspace --all-targets
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2.57s
exit_code=0
```

```text
$ cargo clippy --workspace --all-targets -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.15s
exit_code=0
```

```text
$ cargo test -p chinwag-fleet
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.27s
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.15s
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 39 filtered out; finished in 0.00s
test result: ok. 40 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 4.67s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit_code=0
```

```text
$ cargo test -p chinwag-cli
    Finished `test` profile [unoptimized + debuginfo] target(s) in 16.81s
test bus_wait_cli::tests::preserved_original_drives_durable_handoff_without_resigning ... ignored, owner supplies preserved real native original through CHINWAG_INTEROP_FIXTURE
test bus_wait_message::tests::preserved_original_verifies_without_resigning ... ignored, owner supplies preserved signed original through CHINWAG_INTEROP_FIXTURE
test execution_binding::test_support::p009_git_environment_probe_child ... ignored, Owned child only: inherited Git environment isolation fixture
test execution_route_tests::p009_private_fake_worker_child ... ignored, Owned Rust fake child; invoked only by its controlled parent test
test result: ok. 721 passed; 0 failed; 4 ignored; 0 measured; 0 filtered out; finished in 185.17s
test result: ok. 82 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 52.28s
test result: ok. 18 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.66s
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.14s
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.08s
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.54s
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.47s
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 7.77s
test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.54s
test result: ok. 22 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.87s
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.35s
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.37s
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.64s
exit_code=0
```

```text
$ cargo test -p chinwag-ui
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.12s
test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.41s
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.33s
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
exit_code=0
```

```text
$ rg -n '/opt/homebrew/|gemini-4-argon|DeepSeek V4\.1' crates/chinwag-cli/src/ crates/chinwag-fleet/src/
(no matches; no output)
exit_code=1
```

The scan exits 1 because ripgrep found zero matches. Formatting, workspace check, Clippy, and all package tests exited 0.

| Package | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: |
| fleet | 42 | 0 | 0 |
| cli | 904 | 0 | 4 |
| ui | 39 | 0 | 0 |

Counts sum the unfiltered package harness results emitted by each exact command; the nested child process-group probe is shown above but is not counted twice. Existing explicitly ignored tests remain ignored; no tests were newly ignored.

The hermetic regressions include policy rejection without child execution, OAuth environment scrubbing, key/symlink checks, holds and competing path leases, offline initialization, actual signed arrival/process/receipt correlation, uncertain invocation recovery, restart/replay deduplication, corrupt-recipient rejection, native authority preservation, and utility-environment isolation.

Raw command outputs are retained locally under `.chinwag/private/verification/final-*.log`.

## Changed files

61 changed paths including this report:

```text
.gitignore
Cargo.lock
Cargo.toml
crates/chinwag-claim/src/lib.rs
crates/chinwag-claim/src/path_lease.rs
crates/chinwag-cli/Cargo.toml
crates/chinwag-cli/src/agent_dispatch_route_tests.rs
crates/chinwag-cli/src/agent_dispatch_run.rs
crates/chinwag-cli/src/agent_instance.rs
crates/chinwag-cli/src/bin/p0-task-publish.rs
crates/chinwag-cli/src/board/mod.rs
crates/chinwag-cli/src/board/presentation.rs
crates/chinwag-cli/src/bus_delivery.rs
crates/chinwag-cli/src/bus_network_tests.rs
crates/chinwag-cli/src/bus_run.rs
crates/chinwag-cli/src/bus_wait_cli.rs
crates/chinwag-cli/src/bus_wait_core.rs
crates/chinwag-cli/src/bus_wait_grant.rs
crates/chinwag-cli/src/bus_wait_journal.rs
crates/chinwag-cli/src/bus_wait_message.rs
crates/chinwag-cli/src/bus_wait_store.rs
crates/chinwag-cli/src/canonical_seat_pubkeys.rs
crates/chinwag-cli/src/deepseek_pool.rs
crates/chinwag-cli/src/delivery_operator_readiness.rs
crates/chinwag-cli/src/dispatch_listen.rs
crates/chinwag-cli/src/dispatch_remote.rs
crates/chinwag-cli/src/execution_binding.rs
crates/chinwag-cli/src/feature_cli_run.rs
crates/chinwag-cli/src/fleet_cmd.rs
crates/chinwag-cli/src/hosted_agent.rs
crates/chinwag-cli/src/lib.rs
crates/chinwag-cli/src/main.rs
crates/chinwag-cli/src/memory_run.rs
crates/chinwag-cli/src/relay_run.rs
crates/chinwag-cli/src/release_sync.rs
crates/chinwag-cli/src/seat_signing.rs
crates/chinwag-cli/src/task_scheduler.rs
crates/chinwag-cli/src/task_store_tests.rs
crates/chinwag-cli/src/task_wire.rs
crates/chinwag-cli/src/task_writer.rs
crates/chinwag-cli/src/ui_gate_run.rs
crates/chinwag-cli/src/ui_workbench_run.rs
crates/chinwag-cli/src/workspace_capability_inventory.rs
crates/chinwag-cli/tests/board_ci_sync.rs
crates/chinwag-cli/tests/fleet.rs
crates/chinwag-cli/tests/p0_adversarial.rs
crates/chinwag-cli/tests/ui_v4_zero_jargon.rs
crates/chinwag-fleet/Cargo.toml
crates/chinwag-fleet/src/driver.rs
crates/chinwag-fleet/src/isolation.rs
crates/chinwag-fleet/src/keys.rs
crates/chinwag-fleet/src/lib.rs
crates/chinwag-fleet/src/manifest.rs
crates/chinwag-fleet/src/skills.rs
crates/chinwag-fleet/src/topology.rs
crates/chinwag-fleet/tests/fleet_policy.rs
crates/chinwag-ui/Cargo.toml
crates/chinwag-ui/src/fleet.rs
crates/chinwag-ui/src/lib.rs
docs/development/fleet-and-message-arrival-wake.md
qa/fleet-and-wake-verification.md
```

## Execution limits

The built-in execution driver runs local CLI subprocesses. HTTP/remote target types and container mounts expose explicit host implementation contracts and fail closed when unsupported. Local read-only/write-root policy assumes a trusted process; it is not kernel containment. Uncertain invocation markers remain held for operator inspection rather than retrying possible side effects.
