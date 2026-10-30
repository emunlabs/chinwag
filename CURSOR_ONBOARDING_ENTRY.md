# Cursor onboarding entry

The dedicated entry opens **Connect Cursor to Chinwag**. It gives the person a focused setup screen with the target host, detected Cursor copies and the existing **Set up Cursor** action. The general alpha workbench remains available separately.

## Human flow

1. Open the dedicated Cursor entry on the MacBook.
2. The Rust launcher checks its Studio connection before opening the window.
3. The setup window collects one bounded target-host inventory. It shows Cursor copies with their public location and version hints.
4. Choose **Set up Cursor** for the intended copy.
5. Review and approve Cursor's own installation dialog on the Mac Studio.

The window performs no automatic installation request. It reuses the existing exact-copy refresh, durable action, single-flight and GET-only recovery contracts. An OS handoff acknowledgment remains separate from Cursor approval, MCP initialization and an actual inbox read.

## Launcher contract

The opt-in `--onboarding cursor` launch option requires an explicit bus URL. It sets the dedicated native presentation mode. An already running application's environment is not replaced, so this entry uses its own profile and bundle identity.

The optional `--studio-forward` mode is restricted to the existing saved `studio` SSH route and the exact local and remote loopback port 44345. It supplies no remote command and changes no SSH configuration, credentials, provider settings or network policy. Other validated loopback bus URLs can be checked as existing endpoints, but cannot select an SSH destination.

The launcher serializes its work, keeps an owned forward receipt and log, and reuses only an original process whose identity matches that receipt and whose exact PID owns the loopback listener. It checks that ownership again after endpoint preflight. A live or uncertain original prevents duplication. A new attempt can start one forward only when the original is absent and the local port is free. An occupied unowned listener is retained. The launcher never kills another process or silently adopts its ownership.

The fixed forward uses noninteractive authentication, a finite connection timeout, forwarding-failure detection and keepalive failure detection. These settings do not repair a dropped network or prove why a previous connection ended.

Before app activation, the launcher checks the configured bus endpoint. Failure returns an actionable launch error and does not open a normal-looking disconnected alpha. A successful check proves endpoint readiness at launch time. It does not authenticate Cursor, establish an MCP session or prove recipient delivery.

## Presentation and access

The dedicated mode has no message composer or general conversation view. It labels the target host and explains where Cursor's approval appears. Existing opening uncertainty remains visible and blocks a second setup attempt for that installation until read-only reconciliation resolves it.

No startup path performs a setup POST, approves permissions, starts a model turn or publishes to the bus. The native runtime continues to use its existing declared MCP executable and fixed read-only native-room grant. Installing this MCP server does not establish delivery into Grok Bot's MGMT group.

See [Cursor MCP setup](CURSOR_MCP_SETUP.md), [Human onboarding](HUMAN_ONBOARDING.md) and [MCP connection observations](MCP_CONNECTION_OBSERVATIONS.md).
