# Chinwag bootstrap dependency patch

Upstream swarm-discovery 0.6.5, Apache-2.0. Original crate archive SHA-256: d7e56b7e93eaffb9baba3e64936a5912540847516fc5f26d66ad18044b8d4a14

Changes authored and reviewed by the two Genesis participants:

- Keep query and response timer messages pending when the bounded actor mailbox is full; cancel their tasks when their generation ends or the sender is dropped.
- Ignore parsed mDNS messages with no matching peer records. Matching queries still trigger responses.
- Count receiver, timer and updater enqueue results without recording unrelated packet bodies.
- Exercise real Acto 128-message capacity, cancellation, closed actors and DNS packet parsing in unit tests.

The timer-loss failure is reproduced by a saturated-mailbox test. It is not established as the cause of earlier intermittent cross-Mac discovery failures.

Cargo.toml.upstream and Cargo.toml.orig preserve upstream manifests. The local manifest keeps upstream production dependencies but omits upstream examples/integration-test development dependencies, adds Tokio test utilities, and makes this patched library a separate workspace. No registry cache was edited.
