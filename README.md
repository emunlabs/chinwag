# Chinwag

Chinwag is Emun Labs' local context bus and command-line tooling for agents.
The public client uses the Apache-2.0 license. Hosted coordinator source lives
in the separate private `emunlabs/emun-enterprise-cloud` repository.

This PR-00 candidate contains the seed's capsule library, file inspector,
source-read and opt-in Cargo MCP servers, signed claim contract, and native
iroh identity and transport code.
It is not a complete agent runtime or a Genesis release.

## Current source unit

`crates/chinwag-seed` implements a fixed 256-byte capsule header, compressed
payload encryption, and two independent RFC 9180 recipient wraps. The inspector
opens either recipient slot and rejects a capsule bound to another Git object.
The [capsule format](docs/seed-capsule-v1.md) defines the bytes and size limits.

The current tests cover both recipients, mutations of every capsule byte,
wrong keys and commit targets, truncation, appended bytes, size limits, fresh
random material, and the inspector process. The pinned toolchain is Rust 1.97.1.

`crates/chinwag-swarm` reads the same OpenSSH Ed25519 seed used by Git and
requires its public bytes to match the iroh endpoint identity. It starts from
iroh 1.4's `Minimal` preset, clears address lookups, disables relays, and adds
only the explicit room peerbook, local mDNS, and optional Mainline DHT providers.
LAN discovery selects local IPv4 interfaces inside the application so a VPN
default multicast route cannot redirect its announcements. The `pair_probe`
example requires `CHINWAG_LAN_IPV4` to name those local interface addresses;
it starts no public DHT. `WithMainline` is a separate explicit scope. Ordered
global fallback and public Mainline acceptance remain open. The
Mainline bootstrap list excludes HTTP Pkarr and n0 relay services. In this
version, `clear_address_lookup()` is the API equivalent of the earlier
`clear_discovery()` name in the design.

Gossip and blobs accept the other pinned identity. Blob transfers enforce a
32 MiB bound, declared length, and BLAKE3 verification. Synthetic local tests
exercise gossip, transfer integrity, size refusal, and rejection of a third
identity. Automatic mDNS discovery, gossip, and a 128 KiB blob transfer passed
on both Macs with DHT and relays disabled. A separate room-only test passed
through the deployed Rust/WASM Cloudflare coordinator at `bootstrap.chinwag.sh`.
Both Macs verified signed peer records and coordinator receipts, then used
pinned QUIC for gossip and the matching BLAKE3 blob transfer. That test disabled
mDNS, DHT, and relays. It does not establish a public Mainline fallback, a
particular IP route, or a packet-level proof of zero traffic to n0 services.

The default `serve-read-mcp` mode exposes one tool, `read_file`, through stdio.
The operator supplies an exact path allowlist. The Rig/MCP round-trip and native
stdio tests verify returned bytes and SHA-256, plus refusal of other paths.
Actual native Grok calls read the allowlisted README with its matching SHA-256
and refused `.grok/session` outside that allowlist.

The separate `serve-verify-mcp` mode adds `run_cargo_test`. The operator fixes the
workspace, toolchain, cache, and target paths. The model supplies no arguments;
the tool runs locked offline Cargo check followed by test. Real MCP fixture tests
verify a passing test, a failing test, and refusal of model commands and flags.
The runner bounds output and time and cleans up its owned process group. On
macOS, the separate `chinwag-host-process` crate reads a bounded group snapshot
using SDK-derived layout constants and one read-only native call. A blocking
query retains the unreaped child and the same job permit even after cancellation
or runtime shutdown. Empty, incomplete, or invalid snapshots refuse cleanup
acceptance. The fixture observer is behind a default-off test-support feature.
Cargo build scripts and tests retain local process permissions; this is not an OS
sandbox. Native Grok has invoked the registered mode, but the earlier runner
failed when starting its external process inspector. This native replacement
still requires source review, both-Mac checks, and actual native MCP acceptance.
Task claims, source writes, and bundle review remain unadvertised.

`crates/chinwag-claim` defines signed task requests and coordinator receipts,
strict field and path validation, and exact PR/file policy checks. It compiles
for native and WASM targets. This pure contract does not store reservations or
grant write authority; the durable coordinator and client checks remain required.

The verification commands are:

```sh
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --bin chinwag-seed --locked
```

## Bootstrap provenance

The Genesis participants are the current ChatGPT Conductor on the MacBook and
Grok 4.7 Build Fast with xhigh reasoning on the Mac Studio. No other agent
participates before the verified Genesis gate.

The agents use existing Git, Rust toolchains, and native vendor frontends to
write the first uncommitted seed and coordinator. Temporary Python operator
scripts outside both product repositories launch Grok over SSH, copy and hash
source, and collect test receipts. They are part of the bootstrap record.
The Chinwag seed and Cloudflare coordinator run Rust. Bootstrap orchestration
is not yet self-hosted in the seed. A seed that does not yet exist cannot have
authored itself.

The source and Git history restart from empty workspaces. The ChatGPT
conversation predates that restart. Grok uses a new conversation. Archived
prototype source is excluded from this candidate.

The canonical `~/.chinwag/builder_ed25519` and `~/.chinwag/architect_ed25519`
files already existed when Brian required those exact paths. They are declared
bootstrap infrastructure. Neither key was overwritten, regenerated, or copied
between Macs. Only their public keys enter `.chinwag/allowed_signers`.

SSH copies used to prepare the two Macs are bootstrap transfers. They do not
count as iroh data-plane or hosted Cloudflare room evidence.

## Remaining Genesis requirements

This candidate has no complete Rig tool loop, accepted three-layer discovery,
actual peer commit attestation, or complete flight-record Git-note publisher.
The deployed room coordinator and bounded two-Mac transport test pass.
The Git-note and review-signature code has passed fixture tests, but no source
commit has been created, attested, sealed, or published.
It also has no `chinwag v0.1.0` binary, cross-client context gate, or exec cutover.

Encryption alone establishes neither authorship nor public disclosure approval.
The capsule library does not redact its input. Signing, peer review, transport
proof, and disclosure checks belong to the record publisher before publication.
No organization private key or upstream credential belongs in a public capsule.
Public records exclude unrelated chat history and hidden reasoning. A digest or
redacted record must identify its scope and must not be labeled a full context.

`v0.1.0-genesis` remains reserved for the verified release and actual cutover.
