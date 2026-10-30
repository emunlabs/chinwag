# Rust connector components

The native GPUI host uses built-in Rust connector components. This implements the host and feature separation from the Captionizm plugin architecture, `CHWG-PRD-PLUGIN-0.2.0` / `CHWG-PLUGIN-1`. The reference document is Studio `docuswiki/wiki/projects/Chinwag/prd/chinwag-plugin-architecture-and-seatbelt-isolation-prd.md` (SHA256 `57289933603cd44a6d91e98a3ea2a2468306aea53f1b63213923e100a9032e86`). GPUI replaces the reference's Dioxus-specific UI layer.

```mermaid
flowchart TD
  UI[GPUI · Your apps] --> HTTP[Runtime · explicit host inventory request]
  HTTP --> H[ConnectorHost · typed capabilities and activation generation]
  MCP[MCP SDK · fixed owner-launched stdio scope] --> H
  H --> C[Native clients component]
  H --> I[Native inbox component]
  C --> OS[One bounded running + public installation observation]
  I --> R[Existing admission registry · grants and leases]
  R --> B[Fixed native ledger endpoint + room]
```

## Ownership

`chinwag-connectors` owns versioned built-in descriptors, enablement, activation generations and typed capability dispatch. It receives the host's existing registry. It does not create a parallel agent identity database. The runtime and an independently owner-launched MCP process are separate authority domains; this is not a distributed admission service.

The native-clients descriptor declares running and installed metadata reads. One explicit invocation collects each shared source once. Application-family matchers consume the observations; they do not each rescan the machine. The native-inbox descriptor declares only inbox read. Enabling a descriptor does not grant a destination, authenticate a client or change a sender.

The host checks capability, enablement, activation generation and monotonic deadline before and after the synchronous service call. Inbox calls additionally require the exact registered connection, binding generation, destination and unexpired grant/lease. Disabling inbox access revokes its grants. Re-enabling the component cannot restore those grants. Inventory and unrelated capabilities remain independent.

The metadata invocation's eight-second deadline rejects a late result. It does not interrupt a synchronous filesystem operation already in progress. Collection has explicit entry and byte caps; interruptible native collection remains separate work.

The MCP SDK owns MCP framing and negotiation. The existing bounded blocking reader retains cancellation, EOF and shutdown ownership. Initialization and tool listing perform no bus reads. Tool arguments cannot select another endpoint, room, account or sender.

## Installed and running applications

The Darwin collector reads current-user process metadata, depth-one public application directories, bounded public `Info.plist` fields and fixed CLI filenames in explicit directories. It does not read process arguments/environments, private chat/session/persona stores or credentials, and does not execute candidates or a login shell. Public metadata is matched conservatively; it is a family hint, not vendor signature verification.

Installations retain canonical location, aliases, public metadata fingerprint and observed executable stat metadata on the host. Physical copies remain separate. Exact bundle/executable relationships associate running instances. A bounded sample that lacks a matching process reports **running not observed**; it does not prove an application is asleep or safe to launch twice.

The HTTP response exposes only opaque host-qualified observation IDs, family/kind, running-instance counts and bounded coverage. Paths, PIDs, UID, boot UUID, bundle IDs and executable metadata stay host-local. Installation observation failure leaves the running inventory usable and visible as partial capability. The configured Studio endpoint returns Studio metadata; no MacBook fallback runs.

Explicitly negotiated discovery details add optional public directory-category and version hints. The directory category contains no path or username, and version text must pass the bounded shared version-shape validator. Earlier clients receive the original response shape; new clients accept an older runtime without the hints. Human opening refreshes the selected exact copy before durable attempt creation. Changed metadata or a superseded UI selection requires reselection rather than substitution.

GPUI groups rows by family for presentation. Original instance and installation identities remain distinct. Installed, running, protocol-capable, authenticated, connected and message-delivered are separate states.

## Implemented boundaries and remaining work

This check-in implements trusted linked components. It does not implement external `.cwplugin` loading, independently updated workers, dynamic libraries, signed archives, TUF, Seatbelt containment or release-key handling. The descriptor schema is `chinwag-builtin-connector/v1`, distinct from the reference's signed archive manifest. No external-package fallback exists.

Human onboarding uses the separate `chinwag-native-launch` component for supported exact-copy opening. The runtime owns its human-action boundary, exact public reobservation, persistent consumed attempts and optional native main queue. This is a host function, not a newly granted native-open capability in the two read-only descriptors above. GPUI offers the action only for eligible IDs from the selected host; neither discovery nor component enablement dispatches it. See [HUMAN_ONBOARDING.md](HUMAN_ONBOARDING.md).

Client-specific bindings, lifecycle invalidation and scoped remote publication remain separate work. Reused applications remain externally owned and must not be terminated on disconnect. Opening an application is separate from connecting its protocol.

The current shared MCP route is owner-local, unattributed and read-only. Its successful SDK fixture/native-ledger read does not establish that a named GPT/Claude/Gemini client enrolled or that Grok Bot received a group message. General remote ingress is not exposed by these loopback-only alpha services.

## Verification

Relevant Rust fixtures cover disabled/undeclared capabilities, stale invocations, post-call expiry, exact inbox scope, revocation, cancellation/EOF, public metadata bounds and aliases, partial installed discovery, redaction, host qualification and family grouping. Runtime and MCP reads migrate through the component host in this change. Product services, tests and launcher remain Rust with the pinned Rust1.97.1 toolchain and existing dependency versions.
