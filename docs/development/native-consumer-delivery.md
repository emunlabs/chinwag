# Native consumer delivery evidence

A successful send acknowledges publication. It does not prove that an addressed conversation was scheduled, read its inbox or began work. The `chinwag.delivery-report.v1` send result adds `completion_scope=PUBLISH_ONLY`, the original message ID/digest and a separate fact set per recipient. Legacy `ok`, `message`, `ack` and the existing seven-field signed bus bytes are preserved. `subscribers_notified` remains a broadcast-receiver diagnostic. Persistence is `UNKNOWN` without supported storage proof.

Use one `--to 'GEMINI-PM#conversation-a,DELIVERY#conversation-b'`. Repeating `--to` or its `-t` alias is an error before publication. Plain publication/fallback behavior remains unchanged. A qualified `--wake` remains refused; it cannot resume a conversation. No new retry, waiting loop, worker, service or deadline renewal is introduced.

## Processing correlation

The pure Rust model registers an immutable per-message, per-recipient `DeliveryExpectation` before accepting processing evidence. Its commitment covers original ID/digest, full sender/recipient, room, optional task/operation, creation time and fixed deadline. Registration, joining and reopening use an explicit trusted outcome-store interface with compare-before-commit and exact durable readback. A receipt cannot register a legacy publication retroactively.

`chinwag.consumer-processing-receipt.v1` is a strict bounded body inside the existing signed envelope. It binds every original expectation field, current binding ID/generation, actual consumer turn and optional attributable scheduler digest. The current approved principal verifies the existing Ed25519 transcript. Exact actor, host/conversation lineage, valid lease, qualified inbox read and verified time are required. The processing timestamp must follow that read. Unknown kinds, substitutions, stale generation, invalid time, wrong principal and conflicts fail closed. Scheduler evidence remains unavailable when absent; a valid processing receipt does not invent it.

An identical recorded receipt returns explicitly historical evidence without another commit or scheduling effect. It is not a current liveness statement. Changed receipts conflict. Failed commit or differing readback cannot return a successful new join. Processing outcomes are `PROCESSING_STARTED` or `PROCESSING_REJECTED`; both keep `WORK_STARTED=UNKNOWN`. Task execution still requires its own admitted original parent/child start proof.

## Standing consumer lifecycle

The cadence snapshot retains exact actor, host/conversation, binding/delegation/generation, lease boundary, observed time, last actual turn/read/cursor and evidence digest. Unknown timer identity/arm time remain null. The finite controlled profile uses a 60-second cadence, 120-second maximum actual-turn gap and 300-second maximum binding lease. These are fixture parameters, not production time or host policy.

`ACTIVE` requires a current exact binding and sufficiently fresh actual turn plus qualified inbox evidence. An armed timer alone is `CADENCE_STALE`. Explicit revocation is `STOPPED`; lease expiry is `EXPIRED`; unavailable verified time is `UNKNOWN`; invalid binding/time is `HELD`. Task closure returns the unchanged snapshot: it has no authority to retire a separate standing consumer. Reopening preserves original identities/deadlines; a changed conversation cannot inherit them.

## Enforced limits and unsupported runtime

The only public binding constructor returns `UNSUPPORTED`. Positive bindings exist solely in controlled in-module tests; a public boolean, provider label or shared seat key cannot enable them. No proprietary Antigravity adapter, hidden API, timer export, continuous watchdog or production outcome-store implementation is supplied. The trusted adapter contract assumes authoritative host/time/storage inputs; it does not authenticate arbitrary files. Shared seat keys do not identify independent processes.

T01–T20 exercise a retained unpolled receiver, exact correlation, real synthetic signatures, wrong actors/keys, revocation, time bounds, replay/conflict, file commit/readback failures, legacy signature compatibility, task-close separation, snapshot reopening, lease expiry, armed-without-turn classification and controlled cadence restoration. File reopening is not a process reboot; snapshot separation is not proof of actual host timer continuity. Deployment and a supported real host adapter require separate admission and observation.
