# Instance addresses and authorization

`ActorAddress` in `src/agent_instance.rs` is the shared parser for bus commands, dispatch, and recipient matching. Seats have canonical spelling. Instance suffixes are opaque and case-sensitive. Full identifiers carry routing authority. A display abbreviation has no routing role.

The inheritance order is `CHINWAG_INSTANCE_ID`, `CHINWAG_THREAD_ID`, `CODEX_THREAD_ID`, `ANTIGRAVITY_CONVERSATION_ID`, then `CONVERSATION_ID`. The first present variable must contain a valid ID. Explicit qualified actors or an explicit instance flag take precedence. Terminal IDs and process IDs are not conversation identities.

The existing seven-field bus signature binds `id`, `ts_unix`, `sender`, `to`, `room`, `task_id`, and `body`. Full sender and recipient instances remain inside that signed payload. The allowed-signers check authorizes the seat's public key. The private signing-key loader uses the seat part and fails if its configured key is unavailable. It does not create a key during a send.

All instances of a seat share that seat key. The signature authenticates the seat and its declared instance context. It cannot distinguish two processes that possess the same key. An instance suffix therefore provides no independent cryptographic principal, delegated grant, or protection against a sibling that can use that key. A signed reply or worker ACK binds its declared child and parent addresses. It does not prove that the parent authorized a spawn.

Dispatcher parent context crosses child-process boundaries in validated environment fields. Usage ledgers contain the child and parent addresses for correlation. Those local ledger fields do not add a signed parent field to the bus protocol. This revision preserves the existing wire signature format.

Room-dispatch requests contain the complete child and caller addresses before the existing request signature is made. The listener refuses a bare agent caller instead of applying its own environment. Existing room-wire field limits remain unchanged, including the 128-byte full-agent field limit. Longer addresses fail that transport's validation even when the address parser accepts them.

Each bare-seat dispatch allocates a fresh 128-bit random child ID. Direct worker registrations use the complete actor address in a SHA-256 filename. A second registration for the same instance fails. Cleanup checks the held file's device and inode before removal and preserves a replacement file observed at that check. Path-based cleanup still has a check-to-remove race against deliberate concurrent replacement.

A worker registration is local bookkeeping. A PID existence check is not proof of process identity, provider completion, cancellation, or a remote lifecycle lease. A restart cannot adopt an uncertain earlier run merely by supplying its instance ID. Explicitly reusing an address does not reconnect an engine. Separate operation IDs distinguish stored exchanges within a conversation.

Existing message-ID deduplication and transport fallback behavior are unchanged. A full instance ID is not an exactly-once delivery guarantee. The local append fallback is local storage evidence, not native remote delivery or model-consumption proof.

No general file-write lease is added. The fixed `chinwag-claim` PR-01 slot retains its existing actor, session, and file authority. Routing isolation, process-registration isolation, filesystem-write authorization, and independent cryptographic identities have separate acceptance boundaries.
