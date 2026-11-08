# Chinwag CI failure loop

`chinwag-ci` captures an admitted build command, seals its complete evidence in
one signed encrypted original, and sends that same object over native Iroh
through an explicitly selected Cloudflare relay to the initiating agent and an
Archive owner. Public runner output contains delivery observations; captured
stdout, stderr and command metadata stay inside the encrypted evidence.

The checked-in demonstration is
[`chinwag-core-ci-and-merge.yml`](../../.github/workflows/chinwag-core-ci-and-merge.yml),
job `Native encrypted CI failure loop`, and the public
[`fixture.rs`](../../ci/chinwag-ci-loop-fixture/fixture.rs). Its manual event is
limited to the designated review branch. The three legacy workflow jobs and
event-only probe are excluded from that controlled payload run.

## Authenticated path

1. The initiating agent signs a typed native intent binding repository, source,
   workflow, recipient, command and delivery commitments, nonce and finite expiry.
   Verification uses the pinned seat key, exact sender, addressee, task and room.
2. The runner creates fresh signing and two distinct transport keys. Admission
   binds their possession to the original intent, an atomic server challenge,
   the exact authenticated dispatch response and GitHub OIDC. RS256 verification
   uses the fixed issuer's public JWKS with normal HTTPS trust and checks the
   expected repository/owner IDs, actor, run/attempt, source, workflow, subject,
   audience and token lifetime. Incoming claims do not select these expectations.
3. The fixed command profile runs the public Rust fixture in an unprivileged,
   networkless container with a pinned image, read-only source/root filesystem,
   dropped capabilities, `no-new-privileges` and CPU/memory/process limits.
   Bounded `/build` scratch explicitly permits the compiled test to execute;
   general `/tmp` remains `noexec`.
4. The parent concurrently drains both output streams and captures the actual
   exit, complete command bytes, stream hashes, EOF status and cleanup evidence.
   Lossless argv and working-directory metadata are sealed too; the process
   environment is not copied. Output remains untrusted data and grants no repair
   authority. The active agent needs separate authorization to change source.
5. The envelope implements customer **ACU AND (Recipient OR Archive)** access.
   The native CI transport uses `chinwag/ci-ciphertext/1`, one pinned destination
   peer and the same selected owned relay. UDP binds only loopback; address
   discovery, direct routing and public-relay fallback are disabled. No remote
   handset publication, journal copying or application message bridge carries
   the CI evidence.
6. Each destination authenticates admission and envelope bindings, persists and
   independently reopens the exact object, and returns signed durable/native
   receipts. The sender verifies the actual selected peer/relay path and receipt
   bindings. Each owner separately requests its current ACU grant and validates
   a complete decrypted capture. A storage ACK is not a qualified read, task
   start or successful repair.

## Owner and runner entry points

```text
chinwag-ci owner-init CONFIG PUBLIC
chinwag-ci owner-verify CONFIG PUBLIC
chinwag-ci policy-sign CONFIG PUBLIC SPEC OUTPUT
chinwag-ci serve-root CONFIG
chinwag-ci serve-studio CONFIG
chinwag-ci runner CONFIG
```

Use typed configuration structures in [`runtime.rs`](src/runtime.rs),
[`runner.rs`](src/runner.rs) and [`owner_cli.rs`](src/owner_cli.rs). Owner files
require compact canonical JSON in exact struct field order, no trailing newline,
regular single-link owner-owned `0600` files and private `0700` directories.
Create the declared output namespace before starting an owner. Symlink,
hardlink, ACL and namespace uncertainty refuses the operation. `owner-init` is
for genuine first enrollment; use `owner-verify` for existing custody. Preserve
uncertain operations and reconcile them instead of reinitializing or replaying.
Private bundles stay opaque to the supported owner API and must not be exported.

Root owns admission and Recipient service; Studio owns Archive and customer ACU
service in the demonstrated topology. Finite owner supervision includes original
bind, receive and first close in one monotonic budget, tracks HTTP connections,
and waits for the original worker's OS exit. Forced/deadline/unconfirmed closure
cannot be reported as clean success. Each original operator controls its own
processes. Public service health and a started PID are preparation observations.

Runner exit `0` means complete successful command capture with both verified
durable destinations. Exit `1` preserves a delivered original that is not
eligible green, including a failed command. Exit `2` holds a refused or uncertain
operation. Neither successful delivery nor exit `0` establishes that an agent
started work. The demonstrated repair was performed by an already active,
explicitly authorized initiating agent; generic agent invocation or automatic
unrestricted remediation is not implemented here.

## Reproducible controlled proof

- [Red run 42450930951](https://github.com/emunlabs/chinwag/actions/runs/42450930951)
  built source `983bf33769dd1a29682dac902430b9cef9885ab0` on hosted Linux. The
  actual command exited `126`: `/build/tests` was denied execution in the tmpfs.
  The planned invoice assertion did **not** run. The full failure reached both
  owners as the same signed encrypted object, and both completed distinct
  ACU-authorized full reads.
- Source `84e00c038e8220b9d54df1ed970f6bfba77f18e8` explicitly enabled execution
  only on bounded `/build`. Source `397497315fc9493786771137c232ec5b2eb9d8ef`
  separately removed the deliberately added invoice `+ 1`, retaining the test
  and all diagnostic output.
- [Fresh green run 42452778661](https://github.com/emunlabs/chinwag/actions/runs/42452778661)
  built and executed source `397497315fc9493786771137c232ec5b2eb9d8ef` using a new
  intent, execution identity, authenticated dispatch and runner keys. The fixture
  passed and the workflow succeeded. Both destinations returned verified selected
  relay receipts for the same 35,359-byte encrypted original. The initiating
  agent's authorized read recovered the complete 29,221-byte capture, including
  10,039 stdout bytes and 8,978 stderr bytes: all 128 diagnostic lines per stream,
  matching stream hashes and EOF, without clipping.

These run links prove their recorded runtime revisions. A later documentation
change does not relabel either run's source, replay its original or turn a failed
startup into success. Full-read and clean-closure receipts remain separate from
the workflow result. Final source/release acceptance is a separate review.

## Tests and limits

```sh
cargo test -p chinwag-ci --locked --offline
cargo clippy -p chinwag-ci --all-targets --locked --offline -- -D warnings
cargo fmt --package chinwag-ci -- --check
cargo build -p chinwag-ci --locked --offline
```

The recorded macOS package checks passed 113 tests: 79 library and 34 integration
tests, with zero failures or ignored tests. Some filesystem cases are macOS-only.
The hosted green run proves a Linux build and the actual isolated fixture; it is
not a claim that all 113 package tests ran on Linux. Tests include public RFC
8032, RFC 7515 and RFC 9180 vectors, tampering/admission/replay cases, hostile
transport/storage inputs, binary/large output, and real owned child/HTTP lifecycle
regressions. See [`tests`](tests) and the module tests in [`src`](src).

Each stream retains at most 4 MiB. Overflow continues draining, counts and hashes
all observed bytes, and explicitly marks the retained prefix incomplete; it
cannot become eligible green evidence. A deadline covers child exit and pipe EOF.
Wall clock and monotonic timings are local software observations, not K2 trusted
time or hardware workload attestation. The demonstrated ACU and Archive share a
customer host/UID; independent compromise resistance is not established.
QuickTunnels are temporary endpoints, not a production availability guarantee.
The fixed-fixture proof does not establish arbitrary build-command admission,
durable outbox/reconnect, reboot continuity, WORM storage or general agent wakeup.
Never print plaintext into public runner logs or upload it as an Actions artifact.
