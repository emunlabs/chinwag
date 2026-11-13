# Declarative fleet and message-arrival wake

CHWG-0272–CHWG-0275 and CHWG-0224 replace compiled organization policy with a
versioned fleet manifest. The implementation has three boundaries:

1. `chinwag-fleet` parses and validates topology, keys, skills, drivers and write
   policy. A dispatch plan is produced only after every applicable policy gate
   succeeds. Driver selection never substitutes an executable or model.
2. CLI dispatch, fleet commands and the Rust UI consume that shared model.
   Unconfigured status remains observational and grants no execution authority.
3. A signed operator binding qualifies the message-arrival coordinator. It
   verifies the original message, durably reserves its exact ID/digest/recipient,
   obtains a workspace lease, invokes the selected driver and records correlated
   evidence from the actual process lifecycle.

Arrivals are persisted before publication acknowledgment. Recovery resumes a
queued arrival only when no invocation marker exists. Completed attempts and
uncertain invocation markers survive daemon restart and are never invoked again.
A crash after the invocation marker is synced can leave work held for operator
inspection, even when no child started; at-most-once execution takes priority
over automatic retries that could duplicate side effects.

Implementation sequence:

- Establish manifest and dispatch contracts, including fail-closed diagnostics.
- Implement durable path leases and isolation receipts around provisioning.
- Replace CLI dispatch and roster policy and add fleet inspection/launch paths.
- Qualify scheduler admission and wire signed arrivals into the daemon.
- Exercise policy rejection, a real local child, restart and replay in isolated
  temporary directories; preserve unsupported-adapter and publication-only tests.
- Run formatting, workspace checks and Clippy, all three required package test
  suites and the forbidden-token scan before the local commit.

All development is confined to the assigned worktree. No deployment, remote
mutation, shared-memory write or fleet bus message is part of this change.

## Configuration and inspection

`chinwag fleet init --profile solo` creates `.chinwag/fleet.toml` without network
access. The other starter profiles are `mesh`, `airgapped` and `cloud-pool`.
Starter seats are paused and contain explicit configuration placeholders. Set a
driver, model, lifecycle and any required policy before launching a seat.

Manifest selection is explicit `--manifest` for fleet commands,
`--fleet-manifest` for dispatch and bus commands, then
`CHINWAG_FLEET_MANIFEST`, then `.chinwag/fleet.toml` in the selected workspace.
JSON manifests use the same schema. Canonical serialization uses JCS; optional
digest and Ed25519 pin metadata cover the manifest with its `pin` field cleared.
The origin directory is runtime metadata excluded from the digest. A signature
inside a manifest proves consistency with its stated signer; trust in that
signer and protection of the configuration file remain operator responsibilities.

Useful local commands:

```sh
chinwag fleet validate --json
chinwag fleet validate --strict-keys --json
chinwag fleet status --json
chinwag fleet explain --seat builder --room '#engineering' --json
chinwag fleet launch --seat builder --cwd . --mode headless
```

`explain` runs policy and availability checks without invoking the driver.
Unknown, paused and retired seats, missing binaries and denied policy produce a
nonzero exit. There is no substitute model, driver or target. HTTP and remote
target specifications are extensible contracts; the built-in process driver
executes only local CLI subprocesses and rejects unsupported configurations.

Skills are selected by name from explicit policy and verified manifest roots.
The process environment starts empty, imports only the configured allowlist and
overrides, and receives dispatch identity, model and target metadata. First-party
OAuth isolation removes alternate Anthropic endpoint/token/key variables even
when supplied by overrides or invocation context.

## Writes, leases and trust

Write patterns are relative exact paths or directories ending in `/**`.
Traversal, protected control directories and ambiguous wildcard syntax are
rejected. Requested roots must be covered by the seat's declared roots. Active
repository holds prevent mutating provisioning. The generic `chinwag-claim`
path-lease store serializes competing acquisitions under a stable filesystem
lock, persists receipts atomically and retains quarantined reservations.

Git worktrees, Jujutsu workspaces, independent directory copies and artifact
subdirectories provide separate working directories. The portable copy backend
copies file contents; it does not promise filesystem reflinks. Read-only mode
grants no write roots. These local process modes assume a trusted executable;
they do not provide kernel containment against arbitrary absolute-path writes or
network access. A container or micro-VM mount requires a host-provided backend.

Trust roots come from the manifest's `pubkey_map` and `allowed_signers` maps.
Strict validation requires both maps to cover every seat exactly once, with
matching unique public keys. Private-key paths reject symlink components and
require mode `0600`. Release privileges additionally require explicit
`policy.release_signers`; the CLI contains no organization public-key table.

## Consumer enrollment and wake recovery

The daemon optionally loads `.chinwag/consumer-bindings.json`, or the path named
by `CHINWAG_CONSUMER_BINDINGS`. This is an array of `SignedConsumerBinding`
records. Construct signing bytes with `ConsumerBindingClaim::signing_bytes` and
sign with `SignedConsumerBinding::sign`. Each claim binds the manifest digest,
full consumer and operator addresses, generation, validity interval, rooms,
skills and write roots. The consumer and operator sign the same claim. The
operator's full address must appear in `policy.operator_signers`.

A registered consumer is a wake capability. An original signed bus message
addressed to its full actor or bare seat can therefore enter its queue without a
caller authorization boolean. Original signatures and digests are reverified;
cached `sig_verified` flags grant nothing. Multiple registrations for the same
bare seat are rejected. Enrollment does not fabricate task completion evidence.
Scheduler task grants additionally bind current task keys, specification and
control digests, capacity and budget, and require the configured scheduler owner
plus a verified live sandbox receipt.

Each wake directory under `.chinwag/bus/wakes` is keyed by the exact original
message ID, digest and recipient. `arrival.json` is synced before publication
acknowledgment. The exclusive `invocation.json` marker is synced before any
child can be spawned. Recovery may resume an arrival with no invocation marker;
it never invokes an arrival that already has one. `started.json` records the
actual child PID. `wake-receipt.json` and `delivery-report.json` correlate the
binding, scheduling, processing acknowledgment, work start and terminal outcome
to the original ID and digest. A partial or uncertain attempt requires operator
inspection; deleting its invocation marker is not a safe retry mechanism.

Unconfigured consumers continue to report publication-only evidence, and
`CurrentAuthority::unsupported` continues to return `UnsupportedAdapters`.

The legacy `chinwag bus send --wake` / `bus wake` / `bus route` task-admission
commands retain their shared-scheduler hold. To use an enrolled message-arrival
consumer, publish an ordinary signed addressed message, for example
`chinwag bus send --from 'operator#session' --to '@RUNNER' --room '#jobs' 'work'`.
The consumer binding supplies the wake authority; publication acknowledgment
alone still proves neither processing nor completion. Inspect the correlated
wake and delivery receipts for actual child start and exit evidence.
