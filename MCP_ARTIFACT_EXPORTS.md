# Native inbox install artifacts

The owner can export a Claude Desktop extension bundle or an Antigravity plugin directory. Both describe the existing read-only native `#mgmt` inbox. Exporting performs local file I/O only. The person installs the artifact through the client's supported interface.

Run the Rust exporter on the computer where the client will run. Supply that computer's owned MCP executable and loopback bus origin:

```text
chinwag-alpha-runtime export-connector \
  --format claude-mcpb \
  --mcp-binary /absolute/owned/chinwag-bus-mcp \
  --bus-url http://127.0.0.1:44346 \
  --output /absolute/owned/exports/chinwag-inbox.mcpb
```

For Antigravity, use `--format antigravity-plugin` and a new output directory path. Choose an output outside client-managed configuration and plugin-load directories so installation remains a separate human action. All four options are explicit and accepted once. The existing output parent must belong to the current user, allow no group or other writes, and contain no symlink components. The exporter does not create missing parents or replace an existing file, directory, link or special node.

The command reuses the fixed stdio configuration and owner-held binary pin from native setup. It checks the regular executable's owner, permissions, native header, identity and SHA256, reads at most 64 MiB from the held inode, and rechecks the source before publication. Staged files are synced and published without replacement. If final publication cannot be confirmed, inspect that exact output before another action; the output may already exist.

Each process receives the fixed native `#mgmt` scope and a 900-second lease from process launch. Export creates no admission or renewal. No caller-selected room, environment, shell, credentials, model or sender is accepted.

## Claude Desktop

The unsigned `.mcpb` is a Stored ZIP with exactly `manifest.json` and `server/chinwag-bus-mcp`. Manifest 0.3 declares a binary server and the `darwin` platform. Its fixed command uses Claude's documented `${__dirname}` substitution. The executable's ZIP metadata retains mode `0755`.

On the target computer, use Claude's **Settings → Desktop app → Extensions → Advanced settings → Install Extension** flow and select the bundle. Claude owns installation and trust decisions. Client policy may restrict unsigned extensions. A native header and platform declaration do not establish architecture compatibility, vendor signing or acceptance by the installed Claude version.

## Antigravity

The new directory contains only `plugin.json` and `mcp.json`. The `mgmt` server uses the exact pinned absolute executable path and fixed arguments. Keep that path available on the target computer. The artifact does not embed the executable; export-time verification cannot guarantee its identity at a later launch.

The person can use Antigravity's supported `/plugin install <local-path>` or `agy plugin install <local-path>` interface. The plugin name namespaces the server key. This plugin format is separate from direct MCP configuration edits. The exporter reads or writes no private client configuration.

## Evidence and portability

The receipt records artifact and executable digests, endpoint and scope, and `client_acceptance: "unverified"`. `host_local: true` describes a local execution requirement; it is not cryptographic host authentication or a health check. Moving a bundle changes where its child and loopback requests run. Generate it for the intended computer.

Artifact creation, installation, enabled tools, a current protocol session and an inbox read need separate evidence. Export invokes no client, installation prompt, model or inbox read. Native `#mgmt` access does not establish delivery into Grok Bot's MGMT group.

The formats follow the official [MCPB schema](https://github.com/modelcontextprotocol/mcpb/blob/70fe3b34cd6dff1b3bba046638edc72a6467a4fb/schemas/mcpb-manifest-v0.3.schema.json), [Claude extension guide](https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop), [Antigravity plugin format](https://antigravity.google/docs/build-plugins) and [plugin installation guide](https://antigravity.google/docs/plugins).
