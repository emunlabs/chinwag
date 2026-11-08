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
