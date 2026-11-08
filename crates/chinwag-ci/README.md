# Chinwag CI evidence capture

This crate is the first part of the CI failure loop. It runs an explicit argv,
drains stdout and stderr concurrently, preserves binary output and the real exit
status, and returns an in-memory evidence record. It does not print captured
output. Retained output and serialized plaintext use zeroizing buffers.

Each stream has a maximum retained size of 4 MiB. A limit does not stop draining
the child pipes: the record counts and hashes all observed bytes and explicitly
marks the retained prefix incomplete. A deadline covers child exit and pipe EOF;
deadline and I/O failure outcomes cannot become a successful exit. The runner
must also contain process descendants in its owned job sandbox.

Run context is **unverified input**. Capturing a zero exit status does not mint a
trusted workload attestation. Process output remains untrusted data and cannot
authorize execution. Before operational use, the caller must authenticate the
initiating-agent intent and workload identity, seal the full evidence, deliver
the ciphertext through native transport to both intended stores, and verify
separate storage and processing receipts. Those integrations are not implemented
in this capture unit. Never upload `plaintext_for_sealing()` to an Actions
artifact, write it into an inbox, or echo it into a public runner log.

The tests re-execute a Rust fixture as a real child. They exercise a failure with
output larger than a pipe, binary stderr, explicit output overflow, deadline
cleanup, invalid context refusal and a real successful process exit.

The `intent` module verifies an initiating agent's original native bus signature
against a caller-pinned seat key, exact qualified sender, task and room. It also
verifies the native digest, typed dispatch context and finite intent lifetime.
Its tests include the published RFC 8032 section 7.1 Ed25519 known-answer vector
and application tampering cases. The seat key authenticates a signed routing
assertion; it does not establish an independently keyed chat/process identity.
`VerifiedIntent` deliberately does not grant OIDC admission, replay consumption,
K2 attestation, addressed delivery, or permission to execute a repair. Those
checks must bind the actual GitHub run and trusted current instance separately.

The `oidc` module verifies actual RS256 signatures with the issuer's public RSA
keys and matches the repository/owner, run/attempt, actor, source, workflow,
subject and audience against the admitted caller's expected execution. It
rejects duplicate top-level fields, substituted algorithms/key URLs, ambiguous
issuer keys and invalid finite token lifetimes. Its RSA known-answer test uses
the public RFC 7515 Appendix A.2 vector. Expired example claims are never treated
as a GitHub admission.

The caller must fetch the fixed GitHub issuer JWKS with normal HTTPS trust and
bind expected run IDs to the trusted dispatch response. OIDC verifies a GitHub
workflow identity; it does not prove possession of the runner key committed in
the audience, consume a replay record, authenticate an arbitrary job/shard
name, issue K2, or authorize remediation. These remain separate integration
requirements. Nothing here installs an archive/ACU service or performs delivery.

On Unix, `storage` can persist an already authenticated ciphertext claim into
an explicitly owned private directory. It uses private create-new files, refuses
symlink components/hardlinked objects, completes file and directory sync calls,
and independently reopens and verifies exact bytes/hash/length. Existing-object
observation is separate and does not claim comparison against a creation inode
it never witnessed. Partial creation failures leave evidence for reconciliation.
These are byte-storage observations: the caller must authenticate the encrypted
envelope first and sign a receipt that binds the destination role and original
event. They do not establish WORM storage, archive service acceptance, policy
authorization, or initiating-agent processing.

On macOS a small descriptor-bound adapter requests extended security attributes
directly into a fixed buffer and accepts only the exact empty-attribute reply.
Every ACL blob, truncated reply, inspection error and unexpected shape refuses
storage. This follows examined XNU behavior and local filesystem tests and does
not claim universal filesystem support. The adapter is the only
module permitted to use unsafe FFI, with explicit descriptor/opaque-allocation
ownership rationale; cryptography modules continue to deny unsafe code.

`runner_binding` joins the signed intent and verified workflow with the ephemeral
runner signing key's proof of possession. Its custom OIDC audience commits to
the original intent, delivery/command profiles, workflow execution, signing and
two distinct transport public keys, and server challenge. The proof signs a
separate domain containing that audience and the exact JWT hash, so independently
valid intents, tokens and keys cannot be spliced together. Composition rechecks
both issuance bounds, OIDC `nbf`, and the earlier expiry.

The coordinator must issue/consume challenges atomically and supply trusted
dispatch metadata. The two transport keys are still claims until each actual
native handshake proves possession. This layer issues neither K2 nor repair
authority, does not implement replay storage, and does not establish task start.

The native `transport` component uses a dedicated CI ALPN and a single pinned
peer on one explicitly selected owned relay. It binds only loopback UDP sockets,
disables address discovery/public relay fallback, and records the actual
connection's selected peer/relay path around transfer. Frames have bounded
manifest/ciphertext lengths and an independently checked ciphertext checksum.
The receiving application must authenticate and persist the encrypted envelope
and supply its signed receipt. Returned bytes stay unverified until the caller
checks that receipt. The last application-data receiver owns final closure;
a QUIC FIN ACK is not an application-read or processing proof.

Tests cover hostile lengths/routes and a real loopback delayed-reader close
regression. That loopback fixture is not Cloudflare or CI-runner proof. Actual
owned CI profiles, crypto/admission integration, dual destination delivery and
the failing/fixed GitHub workflow remain to be exercised end to end.
