# Next-release gate: native daemon independent of agent sign-in

Owner requirement, 2026-11-09: Chinwag's native bus must continue operating when
the Codex or Antigravity application signs out, disconnects, updates or restarts.
This is a release requirement separate from the Phase 2 durable-inbox work.

## Incident and immediate recovery

Both operational native daemon processes were absent. Qualified inbox reads
still returned saved journal entries because they read local files; live native
QUIC posture requests timed out. Restoring only one daemon failed closed because
the current verified peer was unavailable. Starting the two unchanged profiles
together restored the route and produced a verified selected-relay journal receipt
for the pending message.

The owner's reported sign-out is consistent with the observed process loss;
the original exit signals were not retained. Do not substitute that report for a
captured process-exit trace. An immediate local per-user launchd configuration
removed the daemon's dependency on the Codex child-process tree. That machine
configuration is not a shipped product installer or a completed logout test.

## Required shipped behavior

- Provide native installation, start, stop and status operations for the supported
  OS process manager. The service must belong to the enrolled OS user rather than
  a chat application's process or authentication session.
- Preserve the selected executable, repository, opaque daemon identity, peer,
  coordinator pin, relay selection and configuration generation. Refuse unsafe
  identity files and conflicting listeners; never silently mint a replacement
  identity or adopt an unrelated service.
- Distinguish a live process, an answering local native endpoint, current room
  authority, selected-path delivery and recipient processing. Cached inbox data
  or a fabricated daemon-shaped status response is not a liveness probe.
- Retain bounded diagnostic logs, the actual supervisor status and terminal exit
  reason. Make startup failures, peer unavailability and expiry visible without
  requiring a model to poll for them.
- Define owner-authorized recovery and backoff explicitly. A process supervisor
  must not bypass finite room authority, extend task grants, blindly reconnect an
  expired session or replay an original with an uncertain publication outcome.
- Scope guarantees precisely: surviving an AI application's sign-out is distinct
  from surviving an OS-user logout, system sleep, network loss or host reboot.
  Each advertised guarantee needs its own supported service domain and proof.

## Acceptance evidence required before release

1. Install an explicitly selected profile through the supported native interface.
   Verify the OS supervisor owns the real daemon PID and bound native socket.
2. Complete a signed end-to-end message exchange with exact original ID/digest,
   selected-relay receipt and correlated recipient processing evidence.
3. Sign out or terminate the relevant AI application in a controlled owner-approved
   test. Show that its service PID/socket remains under the OS supervisor and
   perform another fresh exchange without relaunching the daemon through the app.
4. Separately exercise startup before the peer is available, active-session
   expiry, network loss and uncertain publication. Observe honest held/unknown
   states, bounded recovery and zero duplicate publication or unauthorized grant
   renewal.
5. Verify reinstall/uninstall, profile replacement and listener-conflict behavior
   without changing another service, identity, operational journal or automation.

This document records the next-release gate. It does not mark its installer,
recovery policy or acceptance evidence as implemented or accepted. Preserve the
existing operational daemons and the single two-minute discussion monitor while
the separately admitted Phase 2 source work proceeds.
