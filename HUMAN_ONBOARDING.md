# Native application opening during onboarding

Chinwag can find running and installed applications, then let a person open one supported application copy on the selected runtime host. Opening uses macOS's supported application interface. It does not connect the application's AI session to the bus.

```mermaid
sequenceDiagram
    actor Person
    participant UI as GPUI on MacBook
    participant Runtime as Selected host runtime
    participant Journal as Durable opening journal
    participant OS as Target host macOS
    Person->>UI: Find apps
    UI->>Runtime: GET bounded inventory
    Runtime->>Runtime: Cache exact public installation observations
    Runtime-->>UI: Redacted families and installation IDs
    UI->>Runtime: GET opening capability
    Person->>UI: Open/reuse selected copy
    UI->>UI: Save attempt ID, endpoint and installation ID
    UI->>Runtime: POST one opaque installation ID
    Runtime->>Journal: Save Pending and sync before dispatch
    Runtime->>Runtime: Reobserve exact selected public target
    Runtime->>OS: Open exact copy; reuse allowed
    OS-->>Runtime: Acknowledgment or uncertainty
    Runtime->>Journal: Save redacted outcome
    Runtime-->>UI: Opening receipt
    Person->>UI: Check opening status if needed
    UI->>Runtime: GET original attempt receipt only
    Note over UI,OS: Protocol binding, sign-in and model readiness remain separate
```

## Runtime setup

Native opening is an explicit runtime option. Run `serve-local` or `serve-shared` with both `--native-main-loop` and `--onboarding-journal /absolute/owned/directory`. The first option services the target host's native main queue. The second enables the opening controller with exclusive durable storage. It does not enable message publication. A read-only bus runtime can offer application opening while its send controls remain disabled.

The existing default startup remains unchanged. A runtime without the opening controller reports the capability as disabled. The options do not launch an AI application at startup, during inventory, on a timer or after reconnect. They do not turn the runtime into a remote agent ingress service.

In GPUI, **Find apps** reads the configured runtime host's inventory. Eligible copies receive an explicit **Open/reuse** action. Opaque ID suffixes distinguish multiple copies without sending private filesystem paths to the UI. An application that is installed but absent from the bounded running sample is described as **running not observed**. That observation does not establish that it is asleep.

## Native loopback interface

All routes use the existing loopback Host and no-Origin boundary and require exactly one `X-Chinwag-Onboarding-Intent: 1` header. The intent header distinguishes the native UI convention; it is not authenticated proof of a person, application or account. The runtime remains bound to loopback. Do not expose these routes as a general remote API.

| Route | Purpose |
| --- | --- |
| `GET /api/onboarding/status` | Read whether opening is enabled and the currently eligible opaque installation IDs. No inventory scan. |
| `POST /api/onboarding/open` | Consume one explicit opening attempt with `X-Chinwag-Request-Id` and JSON `{"installation_id":"<observed ID>"}`. No caller paths, arguments, identity or environment. |
| `GET /api/onboarding/opens/<request ID>` | Read an existing receipt. Never dispatch an application open. |

Unknown fields, invalid identifiers, query parameters, incorrect intent and unsupported methods are rejected. Only the same explicit inventory observation supplies the controller's target cache. Opening rechecks the selected exact public target; it does not rescan other installations or inspect private sessions.

## Outcomes and recovery

| State | Meaning |
| --- | --- |
| `pending` | The attempt was durably consumed. Its final outcome is not yet known. |
| `opened_or_reused` | macOS acknowledged the selected application copy. Connection setup remains separate. |
| `rejected` | This consumed attempt did not obtain an opening acknowledgment. The fixed receipt explains the boundary. |
| `uncertain` | Submission may have occurred without a conclusive acknowledgment. Check the original receipt; do not replay. |

The UI saves the attempt ID, original endpoint and installation ID before the POST. Reconnection and restart do not resend it. A check reads the original endpoint with GET only. A missing record does not prove the application was never opened.

The runtime syncs Pending before native execution. Reusing an ID with the same payload returns the recorded outcome. Reusing it for another installation is a conflict. Pending left by a prior process lifetime becomes uncertain and cannot authorize replay. Busy execution rejects a new attempt before consuming it. Other applications can proceed after the active call ends; there is no global restart-required uncertainty latch. Storage faults protect the opening domain independently of bus messages.

Native execution requests exact-copy opening or reuse, with new-instance creation and running-application substitution disabled. A late callback cannot connect an AI client or change an identity. Reused applications remain externally owned: Chinwag gains no process termination, restart or lifecycle authority. Gatekeeper may still require a person's access decision.

## Delivery limits

This unit wires a human action to the native launch component and durable receipts. Fixture tests exercise the API, UI and crash recovery without opening third-party applications. It does not establish that a real AI application launched, signed in, enrolled, invoked a model or received a message. Deployment and a person's drive of the opening action are separate acceptance steps.

Client-specific protocol attachment, lifecycle invalidation, remote identity enrollment and a supported Grok Bot group publisher remain separate work. The owner-local MCP inbox route reads native ledger messages; its SDK acceptance is not named-client enrollment or Grok group delivery. See [CONNECTOR_PLUGIN_CONTRACT.md](CONNECTOR_PLUGIN_CONTRACT.md).
