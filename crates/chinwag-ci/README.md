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
