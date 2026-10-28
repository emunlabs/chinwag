<!-- Copyright 2026 Emun Labs, Inc.
1401 Lavaca St STE 81335, Austin, TX 78701
SPDX-License-Identifier: Apache-2.0 -->
# chinwag-ui

Bare-bones Mission Control in Rust and Dioxus `=0.7.10`: header, channel sidebar,
routed transcripts, loading/empty/error states, and a message composer. No Node,
npm, Vite, or Tailwind. This is a development slice; auth, other views, listeners,
storage, CLI integration, and desktop packaging remain outside this task.

## Toolchain and checks

Use the workspace's Rust **1.97.1**, including its WASM target, rustfmt and clippy.
On this Mac the Homebrew Cargo is older; select the installed toolchain explicitly:

```sh
export PATH="$(dirname "$(rustup which --toolchain 1.97.1 cargo)"):$PATH"
export CARGO_TARGET_DIR=/tmp/chwg-dioxus-1-target
cargo build -p chinwag-ui --locked
cargo test -p chinwag-ui --locked
cargo clippy -p chinwag-ui --all-targets --locked -- -D warnings
cargo fmt -p chinwag-ui --check
cargo deny --manifest-path crates/chinwag-ui/Cargo.toml check licenses
cargo build -p chinwag-ui --no-default-features --features web --target wasm32-unknown-unknown --locked
```

The HTTP integration test binds **127.0.0.1:5598** and stops its own server. Keep
that port free while running tests. It only uses the checked-in synthetic JSON.

## Run against the local fixture planner

In one terminal, start the Rust stub. It keeps messages in memory and contacts no
other service. Restarting it restores the fixture.

```sh
cargo run -p chinwag-ui --example stub_planner --locked
```

In another terminal, use the matching **Dioxus CLI 0.7.10**. On this Mac it is
`~/.local/dioxus/bin/dx`; `/opt/homebrew/bin/dx` is an unrelated Deno tool.
Select the Rust toolchain and target directory above in both terminals.

```sh
cd crates/chinwag-ui
~/.local/dioxus/bin/dx build --platform web --fullstack --no-default-features --locked
CHINWAG_PLANNER_URL=http://127.0.0.1:5598 IP=127.0.0.1 PORT=5599 \
  "$CARGO_TARGET_DIR/dx/chinwag-ui/debug/web/server"
```

Open `http://127.0.0.1:5599`, select a fixture channel, enter text, and send. Use
**Refresh** to fetch changes from the planner. No polling or automatic send retry
is performed. Stop both processes with Ctrl-C. Do not use the live planner or
`:5487` for send tests.

`CHINWAG_PLANNER_URL` is required by the **server**, and must be an HTTP(S) origin
without credentials, a path, query, or fragment. There is no default planner host.
Keep this unauthenticated development UI on loopback with a test planner. A real
planner may reject writes under its authorization policy; the UI shows the failure
and retains the draft. This slice does not read credentials or impersonate an actor.

A plain `cargo run -p chinwag-ui` can serve SSR and server functions for smoke tests
by setting `DIOXUS_PUBLIC_PATH` to an existing empty scratch directory and `IP` /
`PORT` as above. It has no bundled interactive client until `dx build` creates the
server plus `public/` directory. Keep those outputs together. The Cargo WASM build
check verifies compilation only; it does not produce the browser glue or bundle.

## Boundaries and behavior

- `contracts.rs`: serde models preserve channel snake_case and message camelCase;
  unknown fields are accepted. Sessions and summary are retained as uninterpreted
  JSON because this slice only displays channel messages.
- `planner.rs`: native HTTP adapter using `CHINWAG_PLANNER_URL`, GET
  `/api/comms/wiretap` and POST `/api/comms/channel`. Sends use the bare
  `ChannelInput` JSON object. Redirects are rejected, requests time out after 15
  seconds, and responses are capped at 5 MB. Errors omit response bodies and URLs.
- `api.rs`: same-origin Dioxus server functions at GET `/api/ui/comms` and POST
  `/api/ui/comms/send`. The latter's Dioxus transport wraps the payload in
  `{"input":{...}}`; this does not change the planner's plain JSON protocol.
- `view_model.rs`: selection, draft validation, and send lifecycle. Planner order
  is preserved. Validation counts UTF-16 units to match the planner's JS limit.
- `app.rs`: routing, async load/send controller, explicit refresh. Each channel
  page is keyed by ID, isolating drafts and pending responses across navigation.
  Leaving a channel discards its local draft and cancels the UI task; a submitted
  request may already have reached the planner. Check the transcript before retrying.
- `components/`: presentation only; `theme.rs`: all CSS and theme tokens. TYPE can
  replace either without changing contracts or network logic. Default theme is
  midnight; existing daylight/graphite tokens remain available for future controls.

A successful send replaces the snapshot with the planner's canonical response;
the draft clears only after `ok`, channel ID, and returned message membership are
confirmed. An uncertain send keeps the draft and is never retried automatically.
Bodies render as escaped plain text, with whitespace preserved by CSS.

Tests cover JSON casing and unknown fields, required-field failures, validation,
selection, duplicate-send prevention, draft recovery, real HTTP against a stub,
and SSR of the actual shell, channel list, transcript and composer. SSR does not
exercise browser events, CSS geometry, keyboard behavior, or desktop windows.
See `IMPLEMENTATION.md` and `../../docs/chwg-dioxus-1/DESIGN.md` for the task plan
and broader design contract.
