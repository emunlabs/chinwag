# Cursor onboarding entry

The dedicated entry opens **Connect Cursor to Chinwag**. It gives the person a focused setup screen with the target host, detected Cursor copies and the existing **Set up Cursor** action. The general alpha workbench remains available separately.

## Human flow

1. Open the dedicated Cursor entry on the MacBook.
2. The Rust launcher checks its Studio connection before opening the window.
3. The setup window collects one bounded target-host inventory. It shows Cursor copies with their public location and version hints.
4. Choose **Set up Cursor** for the intended copy.
5. Review and approve Cursor's own installation dialog on the Mac Studio.
6. After macOS acknowledges the handoff, the window shows **Setup request sent**. Check **Customize → MCPs** in Cursor on Studio for the Chinwag inbox. For diagnostics, open **Output** (`Cmd+Shift+U`) and select **MCP Logs**.
7. If that exact Cursor entry shows enabled/ready with tools listed, choose **Cursor shows enabled and tools** in Chinwag. The window saves a dated **Enabled with tools in Cursor — confirmed by you** report.

The window performs no automatic installation request. It reuses the existing exact-copy refresh, durable action, single-flight and GET-only recovery contracts. An OS handoff acknowledgment remains separate from Cursor approval, MCP initialization and an actual inbox read.

**Setup request sent** comes from the full bounded opening history for the exact configured endpoint and selected installation, even when that receipt is older than the recent-history display. It disables the main setup action. This window cannot verify installation approval or MCP protocol activity; it does not wait for an approval callback or provide a connection check. The existing **Check setup status** action resolves only an uncertain OS handoff receipt.

The enabled/tools confirmation is an explicit historical human report on the latest acknowledged setup for that exact endpoint and installation. It is saved alongside the unchanged OS receipt and survives reopening the window. Its date uses the client machine's local timezone; the stored timestamp is Unix milliseconds. Repeating the same confirmation preserves its original date. It does not assert a live connection, successful inbox read, active lease, account identity or model activity. Process presence and OS acknowledgement never create this report. A failed save does not publish a confirmation in the current window, and the original OS receipt remains unchanged. If failure occurs after file replacement, recovery may find the report already saved. Changing the selected copy or endpoint cannot attach a stale confirmation to the new target; an unresolved opening or setup must be checked first.

If the person deliberately needs to repeat the handoff, **Show setup options** reveals **Send another setup request** with an explanation. Both steps are explicit. The second step consumes its endpoint/copy-specific UI intent and uses the existing exact-copy preflight and a new durable request. Changing the endpoint or copy, refreshing inventory, or receiving a setup result closes those options. Existing receipts remain unchanged; no request is automatically repeated.

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
