<!-- Copyright 2026 Emun Labs, Inc.
1401 Lavaca St STE 81335, Austin, TX 78701
SPDX-License-Identifier: Apache-2.0 -->

# CHWG-DIOXUS-1 Phase 1 design

**Destination:** `docs/chwg-dioxus-1/DESIGN.md`  
**Status:** Proposed implementation contract  
**Date:** 2026-10-28  
**Owners:** ARCHITECT, RUST, TYPE, QA, ALISTAIR

## 1. Summary and non-goals

Chinwag Mission Control moves into `crates/chinwag-ui`, with a Rust backend, Dioxus components, and embedded frontend assets. `chinwag ui` starts the web application. `chinwag ui --desktop` eventually opens the same components through the macOS desktop renderer.

The existing service on `:5487` remains untouched throughout development. The Rust application uses a separate database and port until cutover. Phase 1 and Phase 2 retain the planner’s SQLite schema. Moving planner records into `.chinwag/state.crdb` is a separate migration milestone.

Pin `dioxus = "=0.7.10"`. The PRD specifies Dioxus 0.6, which conflicts with the supplied stable-version requirement. Enable Dioxus’s `fullstack`, `server`, `web`, and `desktop` features through separate crate features. These features activate `dioxus-fullstack` and `dioxus-desktop`; those are dependency names, not the public Dioxus feature names. [Dioxus feature definitions](https://docs.rs/crate/dioxus/0.7.10/features).

“Pure Rust” means application code and the backend are Rust. Browser delivery still includes generated JavaScript and WebAssembly. SQLite retains its native C implementation, and macOS desktop uses a system WebView. Neither the build nor runtime requires Node, npm, Vite, or a Tailwind executable.

### Evidence and source notation

The inventories below use these roots.

| Prefix | Absolute path |
|---|---|
| `P` | `/Users/brianspector/WORKSPACE/delivery-planner` |
| `W` | `/Users/brianspector/WORKSPACE/chinwag-dioxus` |
| `D` | `/Users/brianspector/WORKSPACE/docuswiki/wiki/projects/Chinwag` |

The source application was inspected at `cbac271`. The target branch is `feat/chwg-dioxus-1`, based on `eafe65e`. Another worker added an uncommitted scaffold during this review. Its observed files are `Cargo.toml`, `README.md`, and `src/{lib,main,app,health,theme}.rs` under `W/crates/chinwag-ui`. This document does not certify that scaffold’s build or tests.

The governing product inputs are the [Dioxus PRD](/Users/brianspector/WORKSPACE/docuswiki/wiki/projects/Chinwag/prd/dioxus-mission-control-zero-node-prd.md) and [CHWG-AUTH-1 PRD](/Users/brianspector/WORKSPACE/docuswiki/wiki/projects/Chinwag/prd/auth-v.0.1.0-prd.md).

### Scope corrections

| PRD statement | Design decision |
|---|---|
| Dioxus 0.6 | Pin Dioxus 0.7.10. Do not use 0.8 alpha. |
| Phase 1 immediately unifies planner tables into CRDB | Preserve SQLite through Phase 2. Perform CRDB unification in M7 after an explicit schema and authority migration. |
| “13 views” | Port the actual 15 navigation entries. `sources` and `onboard` supplement the numbered 13 workflow views. |
| “14-slide deck modal” | The current deck is an inline initiative detail panel. Preserve its behavior first; a modal presentation is optional and requires a product decision. |
| Thirty listeners with unbounded inboxes | Use the enrolled roster with bounded mailboxes and measured readiness. The source contains different canonical and enrolled rosters. |
| `<1ms` persistence and `<2s` replies | Treat these as performance objectives, not established guarantees. The acceptance contract below separates durable send latency, event delivery, and model latency. |

The navigation evidence is `P/src/App.tsx:29–45`. Deck rendering starts around `P/src/App.tsx:2349`.

### Phase mapping

| PRD phase | Implementation milestones | Boundary |
|---|---|---|
| Phase 0, `CHWG-CHAT-RT-1` | Existing hotfix; M0 records its behavior and M3 replaces its mechanism | No modifications to the live Node service in this job |
| Phase 1, `CHWG-DIOXUS-1A` | M0 and M1 | Design, crate scaffold, build proof, embedded assets, shell, and CLI launch wiring |
| Phase 2, `CHWG-DIOXUS-1B` | M2 through M5 | SQLite services, auth, listeners, all views, and API parity |
| Phase 3, `CHWG-DIOXUS-1C` | M6 | Desktop packaging, independent QA, controlled cutover, and Node service retirement |
| Deferred state unification | M7 | Planner-to-CRDB migration and replicated-state semantics |

### Non-goals

Phase 1 does not deliver all views, production auth, functioning agent execution, a planner-to-CRDB migration, a signed application bundle, or Node decommissioning.

The overall port also excludes native iOS and Android packaging, enterprise SSO implementation, billing redesign, a hosted-relay rewrite, new model-routing policy, and changes to imported Paperclip facts. Responsive web behavior at `390×844` remains mandatory.

## 2. Crate layout and integration

### Module tree

The following is the intended completed layout. M1 implements only the subset identified in Section 11.

```text
crates/chinwag-ui/
├── Cargo.toml
├── Dioxus.toml
├── README.md
├── assets/
│   ├── styles.css
│   ├── nessa-theme.css
│   ├── nessa-components.css
│   └── notices/
│       ├── NESSA-LICENSE
│       └── NESSA-UPSTREAM.md
├── src/
│   ├── lib.rs
│   ├── main.rs
│   ├── app.rs
│   ├── routes.rs
│   ├── theme.rs
│   ├── health.rs
│   ├── contracts/
│   │   ├── mod.rs
│   │   ├── planning.rs
│   │   ├── initiatives.rs
│   │   ├── comms.rs
│   │   ├── auth.rs
│   │   └── telemetry.rs
│   ├── domain/
│   │   ├── dates.rs
│   │   ├── dependencies.rs
│   │   ├── markdown.rs
│   │   └── finops.rs
│   ├── components/
│   │   ├── shell.rs
│   │   ├── navigation.rs
│   │   ├── identity.rs
│   │   ├── inspector.rs
│   │   ├── markdown.rs
│   │   ├── gantt.rs
│   │   ├── calendar.rs
│   │   ├── kanban.rs
│   │   └── chat.rs
│   ├── views/
│   │   ├── initiatives.rs
│   │   ├── sops.rs
│   │   ├── rfcs.rs
│   │   ├── kanban.rs
│   │   ├── gantt.rs
│   │   ├── calendar.rs
│   │   ├── work_items.rs
│   │   ├── agents.rs
│   │   ├── comms.rs
│   │   ├── runs.rs
│   │   ├── ship_log.rs
│   │   ├── finops.rs
│   │   ├── wiki.rs
│   │   ├── sources.rs
│   │   └── onboarding.rs
│   └── server/
│       ├── mod.rs
│       ├── state.rs
│       ├── functions.rs
│       ├── http.rs
│       ├── auth.rs
│       ├── assets.rs
│       ├── events.rs
│       ├── store/
│       │   ├── mod.rs
│       │   ├── schema.sql
│       │   ├── migrations.rs
│       │   ├── planning.rs
│       │   ├── initiatives.rs
│       │   ├── comms.rs
│       │   └── telemetry.rs
│       └── services/
│           ├── listeners.rs
│           ├── dispatch.rs
│           ├── relay.rs
│           ├── flint.rs
│           ├── sources.rs
│           ├── wiki.rs
│           └── dagu.rs
└── tests/
    ├── schema_compatibility.rs
    ├── planning.rs
    ├── http_compatibility.rs
    ├── server_functions.rs
    ├── auth.rs
    └── listeners.rs
```

`main.rs` is a development entry point. The distributed executable remains `chinwag`; users do not need a second UI executable.

### Features

Use explicit feature selection and `default-features = false` on the Dioxus dependency.

| Feature | Target and dependencies | Responsibility |
|---|---|---|
| `server`, default | Native; `dioxus/server`, Tokio, Axum, SQLite, server HTTP client | Serve frontend assets, compatibility HTTP, and server functions |
| `web` | `wasm32-unknown-unknown`; `dioxus/web` | Render components and call server functions |
| `desktop` | macOS; `dioxus/desktop` | Native window and lifecycle |
| `server,desktop` | Native macOS | Embedded backend plus desktop window |
| No features | Shared contracts and domain code where practical | Lightweight validation and unit testing |

The common Dioxus feature set includes `fullstack`, `router`, `macro`, `html`, `signals`, `hooks`, and `launch`. Add document and asset support when introducing embedded styles and metadata.

Do not build `web` together with native renderer features. The release pipeline builds the WASM client separately from the native server. Native-only dependencies must be both optional and correctly target-gated; merely putting them behind a module’s `cfg` does not stop Cargo from building them.

Pin direct Dioxus companion dependencies to `=0.7.10` when needed. The lockfile must prevent incompatible framework versions from entering the same feature graph.

### CLI embedding

Add a typed `UiRequest` to `chinwag-cli` dispatch, with mode, bind address, port, and planner path. The names below are proposed CLI additions, not current behavior.

- `chinwag ui` starts the backend and opens the web interface.
- `chinwag ui --desktop` starts the backend and the desktop renderer.
- `chinwag onboard` starts or finds the configured UI and opens its onboarding state.
- Explicit development configuration selects an isolated planner path and an alternate port such as `5497`.
- The eventual default is `127.0.0.1:5487`.
- A bind conflict returns an actionable error. It never stops the existing service or silently attaches to an unidentified process.

The current `onboard` implementation in `W/crates/chinwag-cli/src/main.rs:20` prints and constructs a wizard URL. It does not start a Mission Control backend.

The server owns one `AppState`, one database worker, one listener registry, and one shutdown coordinator. Desktop launch receives that state through native integration. It does not spawn a second `chinwag` process. Keep the macOS event loop on the main thread and run the backend on its own Tokio runtime.

### Existing crate relationships

| Crate | Integration contract |
|---|---|
| `chinwag-cli` | Parses invocation, starts UI runtime, supplies configuration, and owns process exit behavior. Depends on `chinwag-ui`; UI never depends on CLI. |
| `chinwag-swarm` | Supplies authenticated peer transport and relay-related networking. Existing `DataPlane` in `src/transport.rs` is not an HTTP UI beam implementation. |
| `chinwag-seed` | Supplies approved workspace, vault, and agent-service operations through typed library APIs. Extract reusable dispatch logic from CLI wrappers before reuse. |
| `chinwag-signing` | Supplies identity and signature primitives. Private signing material stays native and outside serialized UI state. |
| `chinwag-snapshot-session-private` | Supplies its existing constrained snapshot operations only. Do not treat it as a generic SQLite connection or add planner tables to its validated schema. |
| `chinwag-snapshot-read-owner-private` and confirmed-initial crates | Preserve existing ownership and capability rules. UI roles do not manufacture storage authority. |

The directory `crates/chinwag-snapshot-session` contains package `chinwag-snapshot-session-private`. Its `src/schema.rs` defines eight tables and explicitly identifies the schema as a private fixture experiment. Its `build.rs` supports only `aarch64-apple-darwin` and requires `CHINWAG_PRIVATE_CRSQL_INPUTS`.

Agent dispatch currently exists as command-oriented code in `W/crates/chinwag-cli/src/agent_dispatch_run.rs`. Relay dispatch is a private binary module in `W/crates/chinwag-cli/src/relay_run.rs`. Neither is yet a suitable async service API.

Extract reusable agent execution into a native service module below the CLI, preferably in `chinwag-seed` where workspace and memory dependencies already belong. Put transport-only relay operations in `chinwag-swarm`. UI listener orchestration stays in `chinwag-ui`. Check the dependency graph before each extraction to avoid `seed → swarm → seed` cycles.

### Dependency and build risks

| Concern | Decision or required proof |
|---|---|
| License policy | New Chinwag code is Apache-2.0. `CONTRIBUTING.md` permits specified Apache-compatible licenses, including MIT. It does not require every dependency to be Apache-only. A literal Apache-only interpretation would reject rusqlite and the inherited Nessa code. |
| Dioxus MSRV | Its published manifest declares Rust 1.83.0 and `MIT OR Apache-2.0`. The workspace stays at Rust 1.97.1, edition 2024, resolver 3. Verify every resolved transitive dependency. [Published manifest](https://docs.rs/crate/dioxus/0.7.10/source/Cargo.toml). |
| Desktop dependencies | Audit the selected macOS graph. Do not enable unrelated Linux WebKit dependencies in the supported release build. |
| SQLite linkage | The private snapshot archive exposes ordinary `sqlite3_*` symbols. A second bundled SQLite can collide or interpose unexpectedly. Resolve this before combined CLI/UI release builds. |
| `panic=abort` | Preserve both workspace profiles. No request, transaction, listener, or FFI safety claim may depend on catching a panic. |
| WASM | No SQLite connection, filesystem service, signing secret, Tokio native networking, or private CRSQL dependency enters the client graph. |
| Node-free build | Disable Tailwind integration and frontend package-manager hooks. Build WASM and assets using Rust tooling, then embed the output in the native executable. |
| Single binary | Release startup must succeed after moving the executable away from the checkout and deleting access to the build output directory. |

The selected Boundary Discipline principle places parsing, identity resolution, and error translation in transport adapters. Services accept validated types. The selected Sequence Work into Verifiable Units principle makes native linking and embedded-asset proof prerequisites for feature porting.

## 3. Route and component inventory

The current React application uses component state for navigation. The paths below are proposed Dioxus routes. Preserve existing links such as `/?view=finops`, `/?view=comms`, and `/?onboard=1` through a root-query adapter.

Complexity means S for a small component, M for a form or ordinary view, and L for substantial interaction or service integration.

### Views

All line ranges in this table refer to `P/src/App.tsx`.

| Current view | Source lines | Proposed route and component | Scope | Size | Owner |
|---|---:|---|---|:---:|---|
| Initiatives · Hub | 2174–2824 | `/initiatives`, `InitiativesView` | Initiative selector, creation, founder-note decomposition, linked issues, SOPs, invariants, deck, standup, social radar | L | TYPE + RUST |
| SOPs · Dagu | 2825–3047 | `/sops`, `SopsView` | SOP selector, steps, playbook, YAML, output, trigger, embedded Dagu, social feed | L | TYPE + RUST |
| RFCs · Board | 4144–4269 | `/rfcs`, `RfcsView` | Creation, detail, votes, comments, promotion, invariant status | M | TYPE + RUST |
| Sandbox Kanban | 3079–3086 | `/kanban`, `KanbanView` | Seven status columns, native-card moves, imported-card locks | L | TYPE |
| Critical-Path Gantt | 3048–3059 | `/gantt`, `GanttView` | Bar movement, dependencies, violations, toolbar, selection, unscheduled work | L | TYPE + RUST |
| Release Calendar | 3060–3078 | `/calendar`, `CalendarView` | Month and alternate calendar modes, all-day plans, forecasts, keyboard movement | L | TYPE |
| Work Items & Claims | 3087 | `/work-items`, `WorkItemsView` | Filtered table, selection, source and missing indicators | M | TYPE |
| Agents · Chat | 3831–3896 | `/agents`, `AgentsView` | Roster, custom-agent form, deletion, listener status, direct chat | L | TYPE + RUST |
| Comms · Wiretap | 3410–3830 | `/comms`, `CommsView` | Channels, work-item threads, wiretap sessions, director override, slash bar, Slack preview | L | TYPE + RUST |
| Swarm & Dagu Runs | 3088–3240 | `/runs`, `RunsView` | Runner slots, execution telemetry, workflow evidence, release notes, scale calculator | M | TYPE + RUST |
| Ship Log · Wins | 4270–4431 | `/ship-log`, `ShipLogView` | Daily, weekly, monthly windows, local extra-win entry, summary | M | TYPE |
| FinOps · Cost | 3897–4143 | `/finops`, `FinOpsView` | KPIs, cost entry, per-agent and per-model tables, ledger, exports, calculations | L | TYPE + RUST |
| Docs · Wiki | 3241–3409 | `/wiki`, `WikiView` | Search, category filter, document selection, preview, editing, sandbox metadata | L | TYPE + RUST |
| Vault & Provenance | 4433–4453 | `/sources`, `SourcesView` | Invariants, source freshness, retained captures, revision history | M | TYPE + RUST |
| Setup · Onboard | 4432; 1468–2029 | `/setup`, `OnboardingView` | Reusable seven-step wizard | L | TYPE + RUST |

There is no separate claims mutation API in the inspected Express server. The work-items view’s “Claims” label does not establish a new lease-management endpoint.

### Shell, forms, panels, and shared components

| Current component or interaction | Source lines | Dioxus component | Size | Owner |
|---|---:|---|:---:|---|
| Root startup and error retry | 712 onward; 2031 | `App`, `BootState` | M | RUST + TYPE |
| Rail, project selector, inline project creation, rail collapse | 2082–2095 | `NavigationRail`, `ProjectSelector`, `CreateProjectForm` | M | TYPE |
| Topbar and actions | 2097–2136 | `Topbar` | M | TYPE |
| Brian/Nic badge and switcher | 661–710; 856–907; 2100–2117 | `IdentityBadge`, `IdentitySwitcher` | M | TYPE + ALISTAIR |
| Midnight/Daylight/Graphite switcher | 781–787; 841–854; 2118–2128 | `ThemeSwitcher` | S | TYPE |
| Mobile view tabs | 2137–2143 | `MobileNavigation` | M | TYPE |
| Guided workflow hints and previous/next controls | 2145–2163 | `WorkflowHints` | S | TYPE |
| Error notice and uncertain-save reconciliation | 1395–1410; 2164 | `SaveNotice`, `UncertainChange` | M | RUST + TYPE |
| Source freshness notice | 2165 | `FreshnessNotice` | S | TYPE |
| Search, status, division filters | 1417–1424; 2167–2170 | `PlanningFilters` | M | TYPE |
| Canvas, inspector split, footer | 2172–2173; 4455–4460 | `WorkspaceLayout`, `Statusbar` | M | TYPE |
| Work-item creation/detail inspector | 4462–4530 | `WorkItemInspector` | L | TYPE + RUST |
| Workflow evidence inspector | 4455 | `WorkflowInspector` | M | TYPE |
| Unscheduled queue, including 120-item preview | 4455 | `UnscheduledQueue` | M | TYPE |
| Status badge and human/agent cast formatting | 639–659 | `StatusBadge`, `CastLabel` | S | TYPE |
| WagHead SVG | 628–638 | `WagHeadMark` | S | TYPE |
| Block and inline Markdown | 515–627; `src/markdown.ts` | `MarkdownReader`, `InlineMarkdown` | M | RUST + TYPE |
| Initiative creation and decomposition form | 2234–2265 | `InitiativeForm` | M | TYPE |
| Fourteen-slide deck | 2349–2606 | `InitiativeDeck` | L | TYPE |
| Slide selector and previous/next | 2355–2391 | `SlideSelector` | M | TYPE |
| Slide comment and direct headline/bullet edit | 2430–2520 | `SlideRevisionForm` | M | TYPE + RUST |
| Founder dependencies, signoff, redirect, variance | Deck region, especially after 2520 | `FounderDependencies`, `DeckSignoff` | M | TYPE + RUST |
| Management standup | 2707–2758 | `ManagementStandup` | M | TYPE |
| Social radar reused in Hub and SOPs | 2760–2822; 2992–3046 | `SocialRadar` | M | TYPE + RUST |
| Embedded Dagu frame | 2866–2890 | `DaguFrame` | M | TYPE + ALISTAIR |
| Scale calculator shared by Runs and FinOps | 3135–3168; 3955–3990 | `ScaleCalculator` | M | TYPE |
| Release-note preview shared by Runs and FinOps | 3169–3180; 4002–4013 | `ReleaseNotesPreview` | M | TYPE |
| Wiki resizable sidebar and reset | 3250 onward | `WikiSplitPane` | M | TYPE |
| Wiki editor | Within 3241–3409; save at 1295–1318 | `WikiEditor` | M | TYPE + RUST |
| Wiretap/channel selector and thread lists | 3410–3500 | `CommsNavigation` | M | TYPE |
| Slash output and Block Kit preview | 3500–3685 | `SlashCommandBar`, `SlackPreview` | M | TYPE + RUST |
| Wiretap turns and director override | 3686–3770 | `WiretapPane`, `DirectorOverrideForm` | L | TYPE + RUST |
| Channel transcript and composer | 3771–3830 | `ChannelPane`, `MessageComposer` | L | TYPE + RUST |
| Custom-agent creation/deletion | 3838–3857 | `AgentEditor`, `AgentRoster` | M | TYPE + RUST |
| Direct-chat pane | 3858–3896 | `AgentChatPane` | L | TYPE + RUST |
| FinOps entry form | 4015–4035 | `FinOpsEntryForm` | M | TYPE |
| FinOps resizable tables and reset state | 3897–4143 | `FinOpsTables` | M | TYPE |
| RFC creation and deliberation forms | 4158–4269 | `RfcForm`, `RfcDiscussion` | M | TYPE |
| Ship-log window selector and extra daily wins | 4270–4431 | `ShipLogWindow`, `ExtraWinForm` | M | TYPE |

The deck, release preview, custom-agent editor, RFC form, and scale calculator are inline panels in the inspected source. No `role="dialog"` deck implementation was found. If a deck modal is approved, `InitiativeDeckDialog` wraps `InitiativeDeck` with focus containment, Escape handling, scroll containment, and focus restoration.

### Seven-step setup wizard

| Step | Source lines | Dioxus component |
|---|---:|---|
| Pair Macs and select CI hosts/slot counts | 1525–1735 | `PairMachinesStep` |
| Cloud management layer | 1736–1760 | `ManagementLayerStep` |
| Frontier CLI subscriptions | 1761–1782 | `FrontierClisStep` |
| API accounts | 1783–1805 | `ApiAccountsStep` |
| Local models | 1806–1837 | `LocalModelsStep` |
| FinOps router, four modes, cap, L1–L5 matrix | 1838–1980 | `FinOpsRouterStep` |
| Worker roster and presets | 1981–2029 | `WorkerPresetStep` |
| Fullscreen first-run wrapper | 2033–2080 | `FirstRunSetup` |
| Step rail | 1494–1523 | `SetupProgress` |

The current completion path at `App.tsx:1455–1465` writes `chinwag-coalface-v1` to local storage. It does not prove that machine pairing, model routing, or provisioning occurred. Preserve preferences without presenting preference selection as completed infrastructure work.

### Nessa interaction port

The application directly imports Gantt, calendar, and Kanban from `P/src/nessa`. Port the exercised behavior and its dependencies.

| Source | Rust replacement responsibilities |
|---|---|
| `components/gantt-chart/gantt-chart-scheduling.ts` | Calendar arithmetic, four dependency relations, lag, violations, cycle checks, critical-path calculations |
| `gantt-chart.tsx`, `gantt-chart-grid.tsx`, `gantt-chart-context.ts`, `gantt-chart-shortcuts.ts` | Grid, task list, scale, drag/resize, selection, keyboard controls, dependency connectors |
| `components/event-calendar.tsx` | Calendar navigation, event layout, all-day events, movement, range selection, overflow/popover behavior |
| `components/kanban/*` | Pointer and keyboard movement, insertion calculations, column layout, disabled cards |
| `button.tsx`, `segmented-control.tsx`, `timeline-header.tsx`, `popover-surface.tsx` | Shared controls and accessible state |
| `lib/size-observer.ts` | Resize/content observation, measurement coalescing, and cleanup |
| `lib/compose.ts`, `lib/utils.ts` | Replace React-specific ref/event composition and Tailwind class merging with explicit Dioxus behavior and CSS classes |

## 4. API endpoint inventory

`P/server/server.ts` contains **50 explicit method/path registrations and 49 unique method/path pairs**. `/api/health` is registered twice. The handler at line 655 responds first; the handler at line 1315 is unreachable under normal Express dispatch.

Retain all legacy URLs as plain Axum HTTP routes. Dioxus `#[server]` functions call the same typed services through `AppState`; their transport format does not replace the legacy JSON protocol. This keeps CLI, beam, downloads, imports, and existing integrations compatible.

### Authorization notation

- `R` means the current host-boundary middleware allows the read without a bearer credential.
- `W` means the current mutation middleware requires either a matching Brian/Nic bearer token or an accepted Origin plus `X-Delivery-Client: browser`.
- `I` means `W` plus the import handler’s explicit bearer authorization check.
- In Rust, reads require the appropriate local/private deployment context. Writes require an authenticated capability, normally `Owner` for this two-owner deployment. Import additionally requires an owner API credential.
- Current `W` is not a demonstrated RBAC owner check.

All references in the inventory are to `P/server/server.ts`.

### Core, identity, documents, and planning

| Method | Path | Current auth | Request → response | Rust service / transport | Lines |
|---|---|:---:|---|---|---:|
| GET | `/api/health` | R | None → `{ok:true, storage:"sqlite", upstreamWrites:false}` | Axum `health_legacy` | 655; duplicate 1315 |
| GET | `/api/auth/whoami` | R | Identity headers/query → `{ok, …ResolvedHumanActor, actors}` | Axum + `get_identity` server function | 656–663 |
| GET | `/api/auth/actors` | R | None → `{ok,current,actors,registry}` | Axum + `list_actors` | 664–672 |
| GET | `/api/portfolio` | R | None → `Portfolio` | Axum + `get_portfolio` | 673 |
| GET | `/api/wiki` | R | None → `{anchoredCommit,headCommit,tag,status,docusUrl,docs}` | Axum + `list_wiki_docs` | 674–684 |
| PUT | `/api/wiki` | W | `WikiSave` → `{ok,doc,docs}` | Axum + `save_wiki_doc` | 685–757 |
| POST | `/api/wiki` | W | Same as PUT | Same adapter/service | 758 |
| POST | `/api/changes` | W | Strict `BrowserChange` → `{board:Portfolio,createdIds}` | Axum + `apply_change` | 759–763 |
| POST | `/api/commands` | W | `BrowserChange`, or legacy command/name object → attributed result | Axum + `execute_command` | 764–790 |
| POST | `/api/import` | I | `Snapshot` → `Portfolio` | Plain Axum `import_snapshot` | 791–794 |
| POST | `/api/refresh` | W | No required body → `Portfolio` | Axum + `refresh_sources` | 795–803 |
| GET | `/api/export` | R | None → attached `delivery-portfolio.json`, containing `Portfolio` | Plain Axum download | 804 |
| GET | `/api/wiki/featured` | R | None → `{ok,docs}`, first 12 documents | Axum + `featured_docs` | 1318–1320 |
| GET | `/api/bootstrap/chinwag-darwin-arm64` | R | None → binary or 404; SHA-256, attachment, length headers | Plain Axum bootstrap download | 1331–1345 |
| GET | `/api/bootstrap/nic.sh` | R | Optional `origin` → generated shell script | Plain Axum bootstrap adapter, revised authorization | 1346–1501 |

`BrowserChange` is `Change` without `actor`, with strict top-level validation. Its fields are `requestId`, `expectedRevision`, and `commands`. Preserve the six command variants from `P/shared/contracts.ts:62–74`:

`createProject`, `createItem`, `editLocalItem`, `setPlan`, `setDependency`, and `linkWorkflow`.

`Store.apply()` returns `{board,createdIds}`, not a bare portfolio. `/api/commands` wraps successful changes with `{ok,actor,humanActor,…ApplyResult}`. Its no-op branch spreads a bare portfolio. The legacy name/command fallback attempts project creation, but its generated request ID is not a UUID. Preserve tested responses and explicitly resolve that validation inconsistency before changing the fallback.

`WikiSave` has optional `id`, `path`, `agent`, `doc_type`, `title`, and `description`, plus required `body`. Preserve path confinement, frontmatter behavior, sandbox classification, and the production-wiki test guard. Add canonical-path checks against symlink escape.

### Costs, runs, RFCs, onboarding, and agents

| Method | Path | Current auth | Request → response | Rust service / transport | Lines |
|---|---|:---:|---|---|---:|
| GET | `/api/finops` | R | None → `FinOpsData` | Axum + `get_finops` | 809–811 |
| GET | `/api/ci-runners` | R | None → `CiRunnersData` | Axum + `get_ci_runners` | 812–814 |
| POST | `/api/ci-runners/record` | W | `CiRunInput` → `CiRunnersData` | Axum + `record_ci_run` | 815–832 |
| GET | `/api/release-notes` | R | `version`, default `v0.1.1`; optional `format=markdown|md` → JSON or attached Markdown | Axum + `get_release_notes`; plain HTTP download | 833–843 |
| GET | `/api/finops/export` | R | Optional `format=csv` → CSV; otherwise attached JSON | Plain Axum download | 844–866 |
| POST | `/api/finops` | W | `FinOpsInput` → `FinOpsData` | Axum + `append_finops` | 867–884 |
| GET | `/api/rfcs` | R | None → `RfcsData` | Axum + `get_rfcs` | 901–903 |
| POST | `/api/rfcs` | W | `RfcInput` → `RfcsData` | Axum + `update_rfc` | 904–925 |
| POST | `/api/rfcs/:id/promote` | W | Optional `{actor}` → `{actor,promotedInvariantId,promotedBy,…RfcsData}` | Axum + owner-only `promote_rfc` | 926–936 |
| GET | `/api/custom-agents` | R | None → `{agents}` | Axum + `list_agents` | 937–939 |
| GET | `/api/onboarding` | R | None → seven-step preflight/configuration object | Axum + `get_onboarding` | 940–1089 |
| GET | `/api/models-catalog` | R | None → cached catalog with `ok`, or `{ok,sourceUrl,syncedAt,providers:[]}` | Axum + `get_models_catalog` | 1091–1102 |
| GET | `/api/ship-log` | R | None → `{ok,generatedAt,streakDays,summary,…}` | Axum + `get_ship_log` | 1104–1162 |
| POST | `/api/custom-agents` | W | `CustomAgentInput` → `{agents}` | Axum + `upsert_agent` | 1163–1175 |
| DELETE | `/api/custom-agents/:id` | W | ID or handle → `{agents}` | Axum + `delete_agent` | 1176–1179 |
| GET | `/api/agent-listeners` | R | None → `{ok,ticket,dioxusMigrationTicket,totalListeners,onlineListeners,latencyTargetMs,listeners}` | Axum + `list_listeners` | 1289–1300 |
| GET | `/api/agent-chat/:agent` | R | Handle → `{agent,realtimeReady,listenerStatus,listenerEngine,lastLatencyMs,activeListener,messages}` | Axum + `get_agent_chat` | 1302–1314 |
| POST | `/api/agent-chat/:agent` | W | `ChatInput`; optional `?async=1|true` → queued or completed chat envelope | Axum + `send_agent_message` | 1649–1808 |

`FinOpsInput` requires `agent_handle`, `model`, `item_key`, `commit_sha`, `input_tokens`, `output_tokens`, and `cost_usd`. Optional fields are `id`, `cached_tokens`, `duration_sec`, `cost_tier`, `prevented_collision_savings_usd`, and `created_at`. Tiers remain `reported`, `estimated`, or `billed`.

`CiRunInput` requires `workflow` and nonnegative `duration_sec`. Optional fields are `id`, `slot_id`, `host`, `repo`, `item_key`, `commit_sha`, integer `exit_code`, `source_kind`, `status`, nullable `qa_receipt_id`, and `created_at`.

`RfcInput` supports `action=create|comment|vote`, `id`, `title`, `status`, `killer_feature`, `file_scope`, `proposed_invariant`, `author_cast`, `author_handle`, `comment`, and `vote=approve|request_changes`.

`CustomAgentInput` requires `handle` and `role`. Optional fields are `id`, `dept`, `color`, `description`, `system_prompt`, and `engine`.

`ChatInput` requires a trimmed message of 1–16,000 characters. Optional fields are `sender`, nullable `itemKey`, `async`, and `deepExec`. Handles match `[A-Za-z0-9_-]{1,40}` and normalize to uppercase.

The queued response includes `agent`, `sender`, `queued:true`, `realtimeReady`, listener status/engine, `userMessage`, and `messages`. The synchronous response includes `queued:false`, final listener state/latency, and messages. Preserve explicit synchronous compatibility while making all new UI sends asynchronous.

### Comms, initiatives, SOPs, and social radar

| Method | Path | Current auth | Request → response | Rust service / transport | Lines |
|---|---|:---:|---|---|---:|
| GET | `/api/comms/wiretap` | R | None → `WiretapsData` | Axum + `get_comms` | 1809–1811 |
| POST | `/api/comms/override` | W | `{sessionId,directive,actor?,targetAgents?}` → `{actor,ok,overriddenSessionId,overridePinId,ackPinId,…WiretapsData}` | Axum + owner-only `director_override` | 1812–1824 |
| POST | `/api/comms/channel` | W | `ChannelInput` → `{actor,ok,channelId,message,…WiretapsData}` | Plain Axum + `send_channel_message` | 1825–1840 |
| POST | `/api/comms/channels` | W | Alias of singular path | Same adapter/service | 1825–1840 |
| POST | `/api/comms/slash` | W | JSON command/text, channel, sender → `SlashCommandResponse` plus actor | Axum + `execute_slash` | 1841–1869 |
| POST | `/api/slack/commands` | W | JSON or URL-encoded Slack fields → same slash response | Plain Axum form adapter | 1870 |
| GET | `/api/initiatives` | R | None → `InitiativesData` | Axum + `get_initiatives` | 1873–1875 |
| POST | `/api/initiatives` | W | `InitiativeInput` → `{ok,initiative,…InitiativesData}` | Axum + `upsert_initiative` | 1876–1901 |
| PUT | `/api/initiatives` | W | Same as POST | Same adapter/service | 1902 |
| POST | `/api/initiatives/:id/decompose` | W | Optional title, founder note, owners, actor → initiative result plus `decomposed` | Axum + `decompose_initiative` | 1904–1915 |
| POST | `/api/initiatives/:id/signoff` | W | `SignoffInput` → `InitiativesData`; also synchronizes deck Markdown | Axum + owner-only `update_deck` | 1951–1976 |
| GET | `/api/dagu` | R | None → `DaguData` | Axum + `get_dagu` | 2203–2207 |
| POST | `/api/dagu/:dag/trigger` | W | DAG name or SOP ID; no required body → `DaguData` plus trigger result | Axum + capability-gated `trigger_dagu` | 2209–2265 |
| GET | `/api/social-radar` | R | None → `SocialRadarData` | Axum + `get_social_radar` | 2268–2270 |
| POST | `/api/social-radar/:id/approve` | W | Optional `social_reply_draft`, `status=approved|dispatched` → `{ok,signalId,status,…SocialRadarData}` | Axum + `approve_social_signal` | 2272–2279 |
| POST | `/api/social-radar/crawl` | W | Optional action, ID, draft, query → radar plus `ok,crawledLiveCount`; approve branch returns approval result | Axum + `crawl_social_radar` | 2281–2412 |

`ChannelInput` requires `channelId` and a trimmed body of 1–8,000 characters. Optional fields are `sender`, `senderCast`, `role`, `engine`, and nullable `itemKey`.

`InitiativeInput` requires `title`. Optional fields are `id`, `status`, `owner_divisions`, `owner_agents`, `founder_note`, `summary`, `workstreams`, `issue_keys`, `sop_ids`, `invariant_ids`, `wiretap_ids`, `progress_pct`, `qa_status`, and `qa_receipt`. Workstreams contain `id`, `name`, `lead`, and `status`.

`SignoffInput` supports `action=signoff|redirect|toggle_founder_task|revise_slide`, optional `actor`, `note`, `taskId`, `slideNumber` from 1 through 14, `headline`, `badge`, and `bullets`.

`decomposed` contains `initiativeId`, `workstreamsCreated`, `tasksCreated`, `sopsLinked`, and `invariantsEnforced`.

Slash input accepts `command`, `text`, `channelId` or `channel_name`, and `sender` or `user_name`. The response contains `ok`, `subcommand`, `originalCommand`, `normalizedCommand`, `typoCorrected`, `title`, `markdown`, `data`, `response_type`, `text`, `blocks`, and `wiretaps`.

### Response model sources

`shared/contracts.ts` defines the planning protocol only. Other API models are implemented in `store.ts` and declared locally in `App.tsx`; do not assume a complete shared TypeScript schema exists.

| Response type | Shape and authoritative source |
|---|---|
| `Portfolio` | `revision,projects,items,agents,dags,runs,edges,links,sources,audit`; `P/shared/contracts.ts:33–60` |
| `Snapshot` | `{version:1,sources:Capture[]}` with at most three sources; `shared/contracts.ts:76–93` |
| `FinOpsData` | `summary,byAgent,byModel,entries`; `store.ts:639–760`, `App.tsx:330–387` |
| `CiRunnersData` | `slots,runs,savingsMeter`; `store.ts:1156–1210`, `App.tsx:429–478` |
| `ReleaseNotesData` | `version,anchoredCommit,provenanceReceiptHash,generatedAt,counts,markdown`; `store.ts:1212–1310`, `App.tsx:482–494` |
| `RfcsData` | `rfcs,verifiedInvariants,summary`; RFC votes/comments are decoded JSON arrays; `store.ts:1339–1377`, `App.tsx:389–427` |
| `InitiativesData` | `initiatives,mgmtStandup,summary`; entries include linked evidence and deck state; `store.ts:4330–4579`, `App.tsx:47–162` |
| `WiretapsData` | `sessions,channels,summary`; decoded turn/message arrays retain existing field casing; `store.ts:2310–2397`, `App.tsx:252–328` |
| `DaguData` | `ok,daguOnline,daguUiUrl,daguApiUrl,sopDags,allDags,retiredDags,summary`; `server.ts:2075–2200`, `App.tsx:164–213` |
| `SocialRadarData` | `signals,summary`; signal fields retain snake_case; `store.ts:5158–5200`, `App.tsx:215–250` |
| Chat message | `id,agentName,sender,role,body,itemKey,createdAt`; `store.ts:1643–1651` |
| Listener state | `status,startedAt,lastPrompt,listenerEngine,lastReplyAt?,lastLatencyMs?`; `server.ts:1213–1235` |
| Wiki document | Identity, title/category/description/path, Docus URL, commit/tag/status/stage metadata, invariant, update time, body; `server.ts:51–68` |

### HTTP compatibility details

Keep legacy downloads and CLI-facing endpoints independent of server-function codecs.

`chinwag reply` posts to `/api/comms/channel` and falls back to `/api/comms/channels`. This is explicit in both `P/rust-comms/src/relay_run.rs:1277–1284` and the target CLI source. `/api/export`, FinOps exports, release-note downloads, bootstrap responses, and `/api/slack/commands` also remain ordinary HTTP.

The current beam forwards arbitrary HTTP paths. Preserve status, query, content type, response bytes, identity headers, and download headers. Its implementation shells out to `curl` and buffers responses in `relay_run.rs:559–715`. The `iroh-twine-spoke` label does not establish that this code transports HTTP over QUIC. Streaming needs a native async proxy change, not just a new backend.

Retain the 5 MB request-body ceiling, JSON and URL-encoded form support, structured `{error}` responses, validation status 422, conflict status 409, missing-resource status 404, and authorization status 403. Unknown `/api` routes return 404 JSON rather than frontend HTML.

Express currently accepts case and trailing-slash variants used by the import authorization test. The Rust route normalizer must either support those variants with identical authorization or reject them consistently. No alias may bypass the import credential check.

### Hosted-relay boundary

`P/hosted-relay` is a separate service, not another Express router. Its protocols remain external HTTP integrations.

Observed routes include:

- `GET /v1/health`, `/llms.txt`, and `/llms-full.txt`.
- `POST /v1/enterprise/discovery` and `/v1/telemetry/ingest`.
- `POST /v1/auth/device/code`, `/verify`, and `/token`.
- `POST /v1/billing/checkout`.
- `POST /v1/billing/webhook` and `/webhooks/stripe`.
- `POST /v1/slack/commands`, `/slack/commands`, and `/api/slack/commands`.
- Room dispatch under `/v1/rooms/:org/:room/*` and `/room/genesis/*`, with telemetry, challenge, peer, claim, and relay-usage operations.

Sources are `hosted-relay/src/index.ts` and `room-coordinator.ts:187–235`. Preserve entitlement and signature protocols through Rust clients. Do not bundle this TypeScript code, introduce npm into the UI build, or claim the hosted service is implemented by `chinwag-ui`.

## 5. Data layer

### SQLite choice

Use **rusqlite**, owned by a dedicated database worker.

The source uses synchronous `node:sqlite` calls and explicit transactions. Rusqlite makes that port direct and keeps query ordering, JSON text, and transaction boundaries visible. It is MIT-licensed, which the repository’s explicit permitted-license list allows. Preserve its notice. [Rusqlite manifest and license](https://github.com/rusqlite/rusqlite/blob/master/Cargo.toml).

SQLx is a valid Apache-compatible alternative, but its asynchronous API and pool do not remove SQLite’s single-writer constraint or the native SQLite linkage issue. Its SQLite driver also uses the C library. It adds little value to this schema-preserving port. [SQLx SQLite implementation notes](https://docs.rs/crate/sqlx/0.9.0).

Neither crate makes panics recoverable with `panic=abort`. Choose based on connection ownership and fallible APIs, not panic-catching behavior.

Pin the selected rusqlite version during M0 after checking its native SQLite compatibility. Do not enable `bundled` in the combined CLI build until RUST proves compatibility with the private CRSQL archive. If the combined build needs two engines, namespace the private archive’s SQLite symbols or consolidate linkage through one audited engine. Do not accept accidental linker selection as a solution.

### Complete planner table inventory

The source constructor is `P/server/store.ts:44–219`. It creates **21 tables** and four explicitly named secondary indices.

| Table | Keys, principal columns, and constraints | Source lines |
|---|---|---:|
| `meta` | `id` integer PK constrained to 1; `revision`; initial row `(1,0)` | 49–50 |
| `captures` | `hash` PK; `source_id,captured_at,body`; JSON-valid body | 51 |
| `source_heads` | `id` PK; JSON-valid `attempt`; nullable `good_hash` FK to captures | 52 |
| `entities` | `id` PK; `source_id,kind,body,present`; JSON body and Boolean present check | 53–54 |
| `plans` | `item_id` PK/FK to entities; nullable JSON `body`; `notes` default empty | 55 |
| `dependencies` | Composite PK `(predecessor,successor)`; both entity FKs; `relation,lag_days`; self-edge check | 56–57 |
| `workflow_links` | Composite PK `(item_id,dag_id)`; item FK to entities | 58 |
| `changes` | `revision` integer PK; `at,actor,summary`; JSON `body,source_basis` | 59 |
| `command_receipts` | `request_id` PK; `digest,revision`; JSON `created_ids` | 60 |
| `agent_messages` | `id` PK; `agent_name,sender,role,body,item_key,created_at` | 61–62 |
| `custom_agents` | `id` PK; unique `handle`; role/dept/color/description; `system_prompt`, `engine`, timestamp | 63 |
| `agent_cost_ledger` | `id` PK; agent/model/item/commit; token counts, duration, cost, tier check, prevented-collision savings, timestamp | 64–79 |
| `roadmap_rfcs` | `id` PK; title/status/killer feature/scope/proposed law; author; JSON votes/comments; promoted invariant ID; timestamps | 80–94 |
| `verified_invariants_mirror` | `id` PK; repo/branch/commit/path/symbol/invariant; CI run and receipt hash; verification milliseconds | 95–106 |
| `ci_runner_slots` | `slot_id` PK; host/IP/label/mode/hypervisor/status/trust tier/last job; clone milliseconds; timestamp | 107–119 |
| `ci_runner_runs` | `id` PK; slot/host/repo/workflow/item/commit; duration/exit/source/status/receipt/timestamp; no declared slot FK | 120–134 |
| `wiretap_sessions` | `id` PK; title/item/channel/status/peer; JSON participants/turns; pin count, burn-rate text, timestamp | 135–147 |
| `comms_channels` | `id` PK; name/kind/description; JSON members/messages; nullable item; timestamp | 148–157 |
| `initiatives` | `id` PK; title/status; JSON divisions/agents/workstreams/issues/SOPs/invariants/wiretaps; founder note, summary, progress, QA fields, JSON deck, timestamps | 158–177 |
| `social_signals` | `id` PK; platform/cluster/author/title/URL/snippet; score/rationale/draft/status; initiative/SOP/invariant; published/crawled timestamps | 178–195 |
| `human_actors` | `actor_id` PK; unique handle; name/email/role; JSON machines/IPs; token-file reference; timestamp | 196–206 |

The named indices are:

| Index | Definition |
|---|---|
| `source_entities` | `entities(source_id,kind,present)` |
| `successor_edges` | `dependencies(successor)` |
| `agent_messages_idx` | `agent_messages(agent_name,created_at)` |
| `agent_cost_ledger_idx` | `agent_cost_ledger(created_at DESC,agent_handle)` |

Primary and unique constraints also create SQLite-managed indices where applicable. There is no separate `ship_log`, `rfc_votes`, `sessions`, or listener-queue table in this source.

### Existing migrations and initialization

The constructor applies four additive upgrades at `store.ts:208–211`.

1. `custom_agents.engine TEXT NOT NULL DEFAULT 'claude-code'`.
2. `ci_runner_runs.exit_code INTEGER NOT NULL DEFAULT 0`.
3. `ci_runner_runs.source_kind TEXT NOT NULL DEFAULT 'agent_cost_ledger'`.
4. `initiatives.deck_json TEXT NOT NULL DEFAULT '{}'`.

The current code catches every error from these `ALTER TABLE` statements. Rust must inspect `PRAGMA table_info` and apply only missing columns. It must propagate actual migration errors.

Fresh-table `deck_json` has a JSON-validity check. The historical `ALTER TABLE` does not add that check. Compatibility tests must recognize both forms without rebuilding production tables.

No planner migration-version table or `user_version` mechanism is established by the inspected constructor. Phase 2 uses structural migration checks and keeps the schema unchanged. Do not silently assign CRDB schema versions to the planner.

Initialization also seeds or updates actors, FinOps, RFCs, CI records, comms, initiatives, social signals, and ship-log-related data. Some “read” methods repeat writes. Separate explicit initialization/import from reads in Rust. Production migration must not replay demo fixtures or overwrite imported actor bindings.

### WAL, transactions, and connection ownership

Preserve:

```sql
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=5000;
```

Preserve `BEGIN IMMEDIATE` for planning changes and imports, with explicit commit or rollback on every normal error path. Source transaction logic is `store.ts:5340–5344`.

One dedicated worker owns the writable connection. Tokio tasks submit typed requests through a bounded channel and receive results through oneshot replies. SQLite work never runs on a Tokio executor thread or the desktop event loop.

The first implementation uses one connection to avoid inconsistent multi-query portfolio reads. Add read-only connections only after snapshot-consistency tests justify them.

Do not change `synchronous`, automatic checkpoint policy, or journal mode without a measured requirement. On shutdown, stop admission, complete or reject outstanding work, close connections, and report failure if close does not complete cleanly.

With `panic=abort`, destructors do not provide a recovery plan. A process abort during an uncommitted transaction must recover through SQLite’s transaction/WAL machinery. Verify this using subprocess crash tests.

### Planning semantics

Port `store.ts:5348–5563` and `shared/contracts.ts` precisely.

- `requestId` replay checks the stored digest before revision conflict handling.
- A reused request ID with different content returns 409.
- Stale `expectedRevision` returns 409 without overwriting the draft.
- Successful command batches increment the revision once.
- Self-dependencies and cycles reject the entire batch.
- Imported title, status, project, and owner facts remain read-only.
- Planner notes, dates, dependencies, and explicit workflow links remain local.
- A missing imported item retains its plan.
- Failed imports preserve the last successful capture and expose the failed attempt.
- Older captures do not replace newer source heads.
- Run IDs include source, workflow, and run identity.
- Audit output retains the most recent 80 changes.
- Chat’s compatibility read currently returns the first 200 messages ordered ascending. Do not silently change it to the latest 200.

The command-receipt digest currently uses SHA-256 of JavaScript `JSON.stringify` output. A Rust port must reproduce the normalized field order and escaping for existing receipts. Generic `serde_json` map serialization is not sufficient proof. Add fixed cross-language digest vectors derived from contract fixtures.

Move external dispatch after commit. The source can initiate dispatch from inside a planning transaction. Rust must not send work that a later cycle check rolls back.

### Isolated test data

Create fixtures from the DDL in source and synthetic records. Never open the planner’s live `data/` directory or database for tests.

Use temporary on-disk databases for WAL, reopen, locking, and crash tests. An in-memory database cannot prove WAL behavior. Test fresh schema plus each historical missing-column variant.

Any later operational backup must use SQLite’s backup mechanism or a quiesced database with its WAL handled correctly. Copying only a live `.sqlite` file is not a valid backup procedure.

### Later CRDB unification

M7 needs a separate migration design.

The target private snapshot schema has `threads`, `messages`, `context_pins`, `agent_claims`, `leases`, `flight_checkpoints`, `tombstones`, and `verified_invariants`. It validates a fixed schema and rejects declared foreign keys in CRR table definitions. The planner has foreign keys, JSON aggregate fields, different message tables, and different audit semantics.

M7 must:

1. Define each record’s owner, replication unit, conflict policy, and deletion behavior.
2. Resolve conflicting `context_pins` layouts used by legacy code.
3. Separate authoritative grants from replicated observations.
4. Preserve IDs, actor attribution, timestamps, revisions, and command receipts.
5. Decide how aggregate JSON messages and deck comments become replicated records.
6. Import from a consistent planner snapshot into a new destination.
7. Verify counts, canonical content hashes, referential rules, and replay behavior.
8. Rehearse rollback and recovery before replacing either source of truth.

Do not register fake `crsql_*` functions to bypass CRSQL behavior. The legacy store does this for several best-effort external writes; that technique is not a migration strategy.

## 6. Auth and CHWG-AUTH-1

### Current behavior

`resolveHumanActor()` is implemented at `P/server/server.ts:558–613`.

Its actual precedence is:

1. Matching Nic bearer token selects Nic.
2. `X-Chinwag-Actor`, then `?actor=`, selects an actor.
3. Nic’s recognized peer address selects Nic.
4. Otherwise the resolver defaults to Brian, optionally marking a Brian token match.

This differs from the Auth PRD’s stated precedence. A Brian token does not necessarily override an actor header or Nic-address attribution.

The resolver trusts `X-Forwarded-For` without an explicit trusted-proxy boundary. Actor and machine headers are not cryptographically verified. The registry’s public-key fingerprint strings are metadata, not proof of possession.

Current write authorization is a separate check at `server.ts:640–650`. Either human token or accepted browser Origin/header permits mutation. `human_actors.role` is not used as a role guard.

The current server does not implement browser session cookies, Better-Auth, or WebAuthn verification. UI “TouchID Passkey” text does not establish an authentication ceremony.

The server registry and store seed also disagree on Brian’s Studio address. The source registry uses `100.123.161.18`; the Auth PRD and store seed include `100.66.156.76`. Resolve this through configuration, not another hardcoded inference.

### Rust identity model

Use distinct types for authentication and display attribution.

```text
AuthenticatedPrincipal
    principal_id
    actor_id
    machine_id
    capabilities
    authentication_method
    authenticated_at

HumanActor
    actor_id
    handle
    display_name
    role
    machine_bindings

ActingIdentity
    principal_id
    effective_actor_id
    delegation_reason
```

Brian and Nic both receive owner capabilities in the initial deployment. Display names and role descriptions do not grant authority.

Axum middleware resolves a principal once and stores it in request extensions. Extractors provide `AuthenticatedHuman`, `Owner`, `OwnerApiCredential`, and channel-specific access. Server functions use the same extractors and service checks. A direct server-function call cannot bypass authorization.

Resolution order in Rust is:

1. Valid per-human bearer credential.
2. Valid browser session.
3. Verified device proof using an enrolled public key and an agreed signing protocol.
4. Explicitly configured trusted local or tailnet identity mapping.
5. Otherwise deny privileged operations.

A raw public key header is insufficient device proof. Signed-header payload format, freshness, and replay protection remain a CHWG-AUTH-1 decision.

Use socket peer identity unless the immediate proxy is explicitly trusted to supply an authenticated address. Hostname checks are defense in depth; they do not prove tailnet membership.

### Tokens and cookies

Retain per-human bearer compatibility through a native credential provider. Existing token-file references remain references only. Do not return token values in actor DTOs, HTML, logs, errors, or local storage.

For browsers, introduce opaque sessions with an in-memory server registry initially. Session identifiers are random, stored hashed server-side, expire, and are invalidated on restart or revocation.

Use:

- `HttpOnly`.
- `SameSite=Strict`.
- `Path=/`.
- `Secure` for HTTPS deployments.
- A loopback-only HTTP development policy.
- Origin validation and a session-bound CSRF token for browser mutations.

A verified loopback solo installation or trusted co-founder connection can establish a session through the identity flow. Unknown network clients cannot obtain an owner session merely by calling `whoami`.

The existing identity switcher remains visible, but `?actor=nic` and `chinwag-active-actor` become display preferences. They cannot grant Nic’s authority. Authorized shared-screen delegation must record both the authenticated principal and effective actor. Until that flow is implemented, switching to another identity requires its authentication.

### Owner-only and 403 behavior

| Path or operation | Current enforcement | Rust enforcement |
|---|---|---|
| Any mutation | Bearer or accepted browser Origin/header | Authenticated write capability; 403 when absent |
| `POST /api/import`, including accepted aliases | Explicit API authorization; browser-only requests denied | `OwnerApiCredential`; browser session alone receives 403 |
| `POST /api/rfcs/:id/promote` | Generic mutation gate | `Owner`, with promotion authority checked in service |
| `POST /api/comms/override` | Generic mutation gate | `Owner` plus access to the target session |
| `POST /api/initiatives/:id/signoff` | Generic mutation gate | `Owner` for signoff, redirect, founder task, and slide revision actions |
| Wiki writes | Generic mutation gate; test-process production-root guard | Authenticated write capability, path authorization, and production-root test guard |
| Custom-agent changes, FinOps writes, CI recording | Generic mutation gate | Explicit owner or narrowly scoped service capability |
| Dagu trigger | Generic mutation gate | Explicit execution capability and allowed workflow name |
| Nic bootstrap script | Host-bound GET; embeds the Nic credential | Authenticated enrollment capability; never a host-only credential-bearing GET |
| Private channels | No per-request channel ACL demonstrated | Membership check on reads, writes, exports, and event subscriptions |

The bootstrap script at `server.ts:1366` interpolates the Nic credential into its response. Do not fetch it for golden comparison. Preserve the setup outcome through an authenticated enrollment flow; credential disclosure is an intentional compatibility exception requiring ALISTAIR review.

`#pa-private` must not be returned to every owner or every listener merely because it appears in `readWiretaps()`. Define its membership explicitly. Apply filtering before JSON serialization and before event publication.

Audit actor separation in `changes.actor`, chat senders, RFC votes/comments, wiretap turns, channel messages, and deck revisions. Do not rewrite historic records to infer an identity that was never recorded.

## 7. Chat, relay, and agent listeners

### Current mechanisms

Direct chat is persisted in `agent_messages`.

`POST /api/agent-chat/:agent?async=1` appends the user message, schedules work with `setImmediate`, and returns a queued envelope. Without async mode, the handler waits. The frontend polls direct chat and comms every 1.2 seconds and schedules additional chat refreshes after sending. Sources are `server.ts:1649–1808` and `App.tsx:1320–1383`.

The “listener pool” is currently a state map plus request-launched workflows. It is not thirty persistent conversational worker processes. Canonical defaults report `realtimeReady:true` and a 420 ms latency before measuring a response.

The conversational model request goes to:

- Configured `CHINWAG_FLINT_URL`.
- `http://100.108.108.25:11500/v1/chat/completions`.
- `http://127.0.0.1:11500/v1/chat/completions`.

The source sends model `flint`, recent turns, `max_tokens:240`, `temperature:0.2`, and `enable_thinking:false`. Each attempted endpoint has a 2.2-second timeout. It requests a completed JSON response, not a token stream. Multiple sequential attempts can exceed the stated two-second objective. See `server.ts:1577–1647`.

A deterministic fallback can produce an acknowledgement from local state. It must not be presented as verified agent execution or fresh model reasoning.

`deepExec:true` eventually spawns the `chinwag agent-dispatch` binary. Channel sends also append a synthetic local response and asynchronously execute `chinwag relay send`. See `store.ts:2511–2650`.

Wiretap state is persisted as JSON turns in `wiretap_sessions`. Reads also seed state and synchronize GrokBot replicas. Director override updates the session and chat, then attempts a best-effort external pin write. Existing acknowledgement latencies are partly constructed values.

### Actor design

```text
HTTP or server function
    │ validate principal, channel access, payload, limits
    ▼
Message admission
    │ reserve bounded capacity
    ▼
Database worker
    │ commit user message
    ▼
AgentListenerHandle / RelayDispatcher
    │ process outside request path
    ├── Flint HTTP stream
    ├── typed deep-worker service
    └── native relay client
            │
            ▼
Scoped broadcast events
            │
            ▼
SSE subscriber → Dioxus signals
```

Use one `AgentListenerHandle` per enrolled agent.

```text
AgentListenerHandle
    agent_id
    inbox: bounded mpsc sender
    status: watch receiver
    events: scoped broadcast sender
    shutdown signal

AgentEnvelope
    message_id
    authenticated_principal
    effective_actor
    target_agent
    optional channel_id
    optional item_key
    body
    execution_mode

AgentEvent
    message accepted
    listener status changed
    response started
    token delta
    response completed
    response failed
```

Initial proposed limits are 64 pending envelopes per agent, a process-wide pending-message budget, and a 256-event buffer per scoped subscription stream. These are configuration defaults to validate under load.

A listener processes conversational requests in order. Deep tasks have a separate bounded concurrency budget, so a long tool run does not block rapid conversational admission. Custom-agent creation registers a listener; deletion stops admission and drains or fails pending work explicitly.

Use `mpsc` for commands, `oneshot` for acceptance/results, `watch` for current status, and `broadcast` for transient events. No actor holds a SQLite connection or lock across a network await.

### Non-blocking send contract

For asynchronous agent and channel sends:

1. Parse and authorize the message.
2. Reserve bounded admission capacity without waiting for a model.
3. Commit the user message through the database worker.
4. Enqueue the reserved envelope.
5. Return the accepted message ID and existing compatibility envelope.
6. Run model, relay, and deep execution afterward.

The `<15ms` objective covers server-side admission through durable acknowledgement under the specified healthy local workload. It excludes model inference and network travel. Measure and report p50, p95, p99, storage type, concurrency, and sample count.

A five-second SQLite busy timeout makes an unconditional `<15ms` durability guarantee impossible. When contention or saturation prevents prompt admission, reject before acceptance with a documented retryable overload response. Do not return success for an unpersisted message or claim a universal latency bound.

The UI clears the composer and displays an optimistic row immediately. A response-in-progress indicator does not disable Send. Each submission has independent pending/error state. A failed admission restores or preserves its draft and does not overwrite a newer draft.

The existing schema has no durable listener outbox. Therefore Phase 2 can guarantee durable message acceptance, but not exactly-once downstream execution across a process crash. Do not silently replay every user message after restart. Mark interrupted work and offer an explicit retry. A durable dispatch outbox is a separately versioned extension if Brian requires automatic recovery.

### Streaming and backpressure

Add a **new**, authenticated SSE endpoint under the UI namespace, proposed as `/api/ui/events`. It is not a legacy endpoint.

Use SSE first because messages travel to the server through existing POST routes and events travel back in one direction. WebSocket can be added later if interactive bidirectional transport earns its additional complexity.

- Scope subscriptions by authorized agent or channel.
- Publish durable completion events only after the assistant message commits.
- Coalesce token deltas to avoid one DOM update per token.
- Give streams heartbeat, cancellation, and connection limits.
- Disconnect slow subscribers or send a resynchronization instruction on lag.
- Recover canonical transcripts using existing GET endpoints.
- Do not treat broadcast delivery as durable message storage.
- Do not leak private-channel events through a global event bus.

Token streaming from Flint requires an upstream streaming request and parser; the source does not establish support. If the endpoint lacks streaming, emit status followed by a completed response. Do not simulate token generation.

Retain the 1.2-second polling path as a temporary compatibility fallback through old beam clients. Upgrade beam to stream before making SSE mandatory.

### Native relay and execution

Replace UI-triggered calls to the `chinwag` executable with typed in-process APIs. These APIs accept structured requests and return structured results. They do not parse CLI stdout.

Preserve channel routing:

| Channel | Relay target |
|---|---|
| `#mgmt` | All management seats |
| `#eng-swarm` | ENG |
| `#product-studio` | PRODUCT |
| `#bizfin-legal` | BIZFIN |
| `#s-and-m-growth` | S-AND-M |
| `#infra-cleanroom` | INFRA |
| `#pa-private` | PA, subject to private membership |

Agent-origin replies must not trigger human-message relay fanout. Preserve run/receipt markers and deduplicate retries by stable identifiers where the upstream protocol supports them.

External user-installed agent CLIs and Tart/Dagu processes may remain backend adapters. “No shelling out to chinwag” does not mean every external tool becomes an in-process library. All such execution stays outside HTTP admission and uses argument arrays, bounded output, timeouts, cancellation, and secret-free command lines.

## 8. Styling and assets

### Preserve the existing visual system

Carry over the tokens and selectors from `P/src/styles.css`.

- Midnight uses the existing indigo background, mint, cobalt, and pink palette.
- Daylight retains its light surfaces and adjusted semantic colors.
- Graphite retains the neutral dark palette.
- Apply `data-theme` to the document root.
- Preserve `data-nessa-mode`, dark-class behavior, and `color-scheme`.
- Preserve `chinwag-theme` storage compatibility.
- Initialize the theme before the first visible application frame to avoid a light/dark flash.

The current scaffold puts `data-theme` on `<main>`. That does not satisfy selectors such as `html[data-theme="daylight"]`; fix this during M1.

### Remove Tailwind build dependencies

Embedding the existing CSS verbatim is insufficient.

`src/styles.css:20` imports `tailwindcss`. `src/nessa/styles.css:22–28` imports Tailwind theme/utilities and uses `@source` and `@custom-variant`.

The port must:

1. Preserve a source-provenance record for the original styles.
2. Retain the ordinary CSS rules and theme values.
3. Flatten local CSS imports.
4. Replace Tailwind directives, required reset rules, utilities, and variants with checked-in plain CSS.
5. Assign explicit classes to ported Nessa components.
6. Reject unresolved package imports and Tailwind directives in CI.

Do not use a precompiled Vite stylesheet as the sole source of truth. It would hide the build dependency and make future component changes depend on an unavailable generator.

Use `include_str!` for deterministic embedded CSS in the initial scaffold. An Axum asset route can serve embedded bytes with the correct content type. Use `asset!` where the Rust-only Dioxus asset pipeline is proven to embed and resolve the output correctly.

### Assets and notices

`src/nessa/UPSTREAM.md` pins Nessa to `7a8fe71fe996305a71baba319387df6e81ffbe0e`. Preserve that record and `src/nessa/LICENSE`. Nessa is MIT-licensed; the Chinwag header does not replace its notice.

Port the WagHead SVG directly. Use approved SVG icons with their notices instead of importing `lucide-react`. Do not include restricted Nucleo assets.

The CSS names Onest and Monaspace Neon with system fallbacks. It does not prove that font files are present. Use available system fallbacks until font assets, licenses, and embedding are verified. No font CDN is required.

### Geometry compliance

Run SOP-QA-02 at `1440×900`, `1280×800`, and `390×844`.

Preserve deliberate internal horizontal scrolling for Gantt, calendar, Kanban, and wide tables. Reject document-level horizontal bleed, clipped controls, overlapping topbar actions, inaccessible inspector content, and unbounded setup tables.

Cover all themes and these expanded states:

- Work-item inspector and workflow inspector.
- Fourteen-slide deck with comments, edits, and founder dependencies.
- Setup steps 1 and 6, especially wide tables.
- FinOps forms, previews, calculator, and resized tables.
- Wiki editor and resized split.
- Chat with long Markdown, code, and URLs.
- Wiretap override, slash output, and Slack preview.

Preserve keyboard focus, reduced-motion behavior, drag alternatives, and accessible labels. Geometry success alone does not establish usable keyboard behavior.

## 9. Parity checklist

Every item remains unchecked until supported by a receipt. Approved security corrections are recorded as intentional differences.

### View and interaction parity

- [ ] All 15 navigation entries work through rail, mobile tabs, guided hints, browser history, and legacy query links.
- [ ] Theme selection survives reload and applies the same document-root tokens in web and desktop.
- [ ] Brian and Nic attribution is visible and matches the authenticated identity.
- [ ] Initiative creation and decomposition return linked workstreams, tasks, SOPs, and invariants.
- [ ] All 14 deck slides support selection, previous/next, comments, headline/bullet edits, and retained revision history.
- [ ] Signoff, redirect, and founder-task toggles persist and preserve variance attribution.
- [ ] Management standup and social radar remain reachable from the Hub.
- [ ] SOP selection shows playbook, YAML, steps, and trigger output; offline state is distinguishable.
- [ ] RFC creation, comment, vote replacement, and authorized promotion persist.
- [ ] Native Kanban cards move between the seven statuses; imported cards remain locked.
- [ ] Gantt bars move and resize, dependencies can be added/removed, violations display, and dependents do not automatically move.
- [ ] Calendar month and alternate modes, all-day plans, range selection, and forecasts work.
- [ ] Shift-arrow calendar movement changes plans by one or seven calendar days.
- [ ] Work-item filtering matches project, status, division, text, missing-item, and blocked-first rules.
- [ ] Inspector creation/editing, milestones, inclusive finish, notes, dependencies, workflow links, and source evidence match.
- [ ] Unscheduled work remains undated and the queue exposes its full inventory.
- [ ] Agent roster order, GEMINI-PM prominence, custom-agent creation/deletion, and item-to-chat navigation work.
- [ ] Direct chat supports rapid consecutive sends, retained drafts, listener states, and eventual response display.
- [ ] Channel chat, thread selection, wiretap turns, authorized overrides, and relay replies work.
- [ ] Slash aliases and typo normalization preserve savings, roster, current, wiretap, release, and ask behavior.
- [ ] Slack Block Kit previews match returned structured blocks.
- [ ] Runs show slots, exit codes, source kinds, durations, workflow evidence, release notes, and calculator results.
- [ ] FinOps entries, aggregates, tier labels, exports, resizable tables, and reset behavior match.
- [ ] Ship Log supports daily, weekly, and monthly windows; local extra wins are not falsely presented as server-persisted records.
- [ ] Wiki search/category filters, source metadata, safe Markdown, editing, and sandbox classification work.
- [ ] Sources show capture attempts, last success, missing records, hashes, and revision history.
- [ ] All seven setup steps, preferences, first-run completion, forced `?onboard=1`, and reopen behavior work.
- [ ] Loading, empty, error, stale-data, uncertain-save, and offline states are usable.

### Endpoint parity

- [ ] `GET /api/health` preserves the effective legacy response.
- [ ] `GET /api/auth/whoami` and `GET /api/auth/actors` preserve nonsecret fields and distinct human identities.
- [ ] `GET /api/portfolio` returns the planning contract.
- [ ] `GET /api/wiki` and `GET /api/wiki/featured` return expected document metadata and bodies.
- [ ] `PUT /api/wiki` and `POST /api/wiki` preserve save results and reject invalid or escaped paths.
- [ ] `POST /api/changes` preserves atomic batches, replay, conflict, validation, and created IDs.
- [ ] `POST /api/commands` covers change, legacy command, and no-op branches.
- [ ] `POST /api/import` preserves capture semantics and rejects browser-only credentials through all accepted aliases.
- [ ] `POST /api/refresh` coalesces concurrent refreshes and preserves last-good data.
- [ ] `GET /api/export` preserves attachment name and portfolio JSON.
- [ ] `GET /api/finops`, `POST /api/finops`, and `GET /api/finops/export` preserve aggregates, rounding, JSON, and CSV escaping.
- [ ] `GET /api/ci-runners` and `POST /api/ci-runners/record` preserve duration, exit, source, and slot fields.
- [ ] `GET /api/release-notes` preserves JSON and Markdown download modes.
- [ ] `GET /api/rfcs`, `POST /api/rfcs`, and `POST /api/rfcs/:id/promote` preserve data and enforce promotion authorization.
- [ ] `GET /api/custom-agents`, `POST /api/custom-agents`, and `DELETE /api/custom-agents/:id` preserve normalization and results.
- [ ] `GET /api/onboarding`, `/api/models-catalog`, and `/api/ship-log` preserve tested shapes with approved truthfulness corrections.
- [ ] `GET /api/agent-listeners` reports actual registered and ready listeners.
- [ ] `GET /api/agent-chat/:agent` and synchronous/asynchronous POST variants preserve message envelopes.
- [ ] `GET /api/comms/wiretap` filters authorized channels and preserves session structure.
- [ ] `POST /api/comms/override` preserves persisted directives and rejects unauthorized callers.
- [ ] Both `/api/comms/channel` and `/api/comms/channels` accept CLI replies and preserve attribution.
- [ ] `/api/comms/slash` and `/api/slack/commands` accept their JSON/form variants.
- [ ] `GET /api/initiatives`, POST/PUT upsert, decomposition, and signoff routes preserve expected results.
- [ ] `GET /api/dagu` and authorized trigger requests preserve actual workflow outcomes.
- [ ] Social-radar read, approval, crawl, and crawl-approval branches preserve results.
- [ ] Bootstrap binary headers/checksum and the approved secure Nic enrollment outcome are verified using fixture credentials.
- [ ] Unknown routes, malformed payloads, body limits, content types, and 403/404/409/422 responses match the documented contract.
- [ ] Beam preserves downloads and HTTP errors; its upgraded path supports event streaming.
- [ ] CLI reply and relay receipts do not cause duplicate human-message fanout.

## 10. Testing and QA plan

### Unit tests

Port meaningful behavior from `P/server/store.test.ts`, `server/markdown.test.ts`, `src/dates.ts`, and the exercised Nessa algorithms.

Required cases include revision replay/conflict, full rollback on cycles, failed-import preservation, missing items, duplicate source rejection, host/workflow run identity, DST transitions, half-open plan intervals, zero-length milestones, FinOps rounding, RFC vote replacement, safe links, nested emphasis, wiki links, and raw HTML rendered as text.

Use fixed clock and ID providers for deterministic fixtures. Keep monetary representation compatible with existing JSON and two-decimal rules during the port; a monetary-storage redesign is separate.

### Schema and persistence tests

Use source-built temporary databases.

- Compare table names, columns, defaults, constraints, foreign keys, and named indices.
- Test the four historical additive migrations.
- Reopen after edits and compare results.
- Exercise concurrent connections, busy handling, and WAL readers.
- Kill a release-mode subprocess during an uncommitted transaction and verify recovery.
- Verify that ordinary Rust reads do not seed or rewrite records.
- Verify command digests against fixed JavaScript-compatible vectors.

### HTTP and server-function integration

Start Axum on an ephemeral loopback port with temporary SQLite/wiki roots and fake external services.

Exercise every method/path pair in Section 4. Call server functions through their transport, not only by invoking Rust service methods. Compare authorization and side effects between both adapters.

Test absent, invalid, Brian, and Nic credentials; browser sessions; CSRF; hostile Origin/Host; forged forwarded addresses; actor spoofing; expired sessions; import aliases; private subscriptions; and bootstrap redaction.

The existing source test uses fixture credentials and asserts asynchronous chat under **150 ms**, despite the PRD’s 15 ms target. The Rust suite must not cite that test as proof of a 15 ms bound.

Use a fake Flint endpoint for streaming, timeout, malformed response, disconnect, and overload cases. Use fake relay and Dagu adapters. Tests must never wake real agents, trigger production DAGs, write the production wiki, or access live credentials.

### Golden JSON against `:5487`

Do not assume GET means read-only.

The inspected call graph shows:

| GET family | Hidden behavior |
|---|---|
| Portfolio/export | `read()` calls `readCustomAgents()`, which writes roster state |
| Custom agents/listeners | Roster reconciliation writes |
| CI runners | Synchronizes ledger-backed runs |
| Release notes/ship log | Calls other read methods with writes |
| Wiretap/initiatives | Seeds records and synchronizes GrokBot replicas |
| Agent chat | Reads persisted chat and in-memory status without that roster path |
| FinOps | Reads ledger and computes aggregates |

Live comparison must use an explicit allowlist after a fresh side-effect review. Candidate safe comparisons include effective health, nonsecret identity responses, chat reads, and FinOps JSON/CSV. Do not fetch the bootstrap script.

For mutation-bearing GETs, use a separately authorized legacy reference instance with source-built fixture data, injected roots, and disabled external adapters. If a consistent operational snapshot is later authorized, its acquisition is an operator task separate from this read-only design job.

Normalize only documented volatile fields such as generated timestamps. Preserve arrays whose order is part of the contract. Record source revision, fixture identity, route, normalization rules, and differences.

### Visual and accessibility QA

Run the real application through `chinwag ui-gate` at the isolated Rust URL. Do not execute `chinwag --help`.

At all three required geometries, cover every view, three themes, seven setup steps, expanded forms/previews, inspector, deck, long content, empty states, and failures. Store geometry receipts and screenshots without operational content.

Use browser automation for keyboard navigation, focus restoration, drag alternatives, rapid sends, reconnection, and uncertain-save recovery. WebView testing is additional to browser testing.

### Locked build gates

Run feature-specific checks rather than combining incompatible renderers with `--all-features`.

```text
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo check -p chinwag-ui --locked --no-default-features --features web --target wasm32-unknown-unknown
cargo check -p chinwag-ui --locked --no-default-features --features server
cargo check -p chinwag-ui --locked --no-default-features --features server,desktop
```

Add the corresponding CLI/UI integration checks once CLI features exist. The whole-workspace test gate remains mandatory; existing private native archive prerequisites must be supplied by the approved Cleanroom environment.

Also build release profiles and run them. Standard Rust unit tests alone do not prove `panic=abort` production behavior.

### Cleanroom Tart slots

QA owns independent verification in Slot 1 and Slot 2.

- Slot 1 verifies locked native/WASM builds, HTTP/server-function parity, persistence, and browser geometry.
- Slot 2 verifies desktop launch, signing/notarization workflow, isolated install, shutdown/restart, and beam compatibility.
- Both use synthetic planner state and fixture credentials.
- Prove build and startup without Node, npm, Vite, or Tailwind executables available.
- Prove packaged startup without a checkout, `dist/`, external CSS directory, or a running Node service.
- Keep Tart external to the binary. Do not link or vendor its implementation.

No build, test, live API comparison, or UI gate was executed as part of this read-only design review.

## 11. Milestones, owners, and effort

Estimates are engineering person-days, not elapsed sprint promises. They assume RUST and TYPE can work concurrently after interfaces stabilize, with independent QA and security review. Native-linking uncertainty can extend the critical path.

| Milestone | Scope and exit criteria | Dependencies | Owners | Estimate |
|---|---|---|---|---:|
| M0 | Confirm source baseline, contract inventory, Dioxus pin, feature graph, native SQLite linkage strategy, and Node-free build path. Record all blockers with reproducible evidence. | This design | ARCHITECT + RUST + ALISTAIR | 1–2 days |
| M1 | Complete Phase 1 scaffold. Native server, WASM client, router, shell, theme tokens, embedded assets, health round trip, CLI launch wiring, and isolated port/path configuration work. Desktop feature compiles. Locked checks pass. | M0 | RUST + TYPE + QA | 2–4 days |
| M2 | Port the 21-table schema, migrations, planning/import logic, digest compatibility, auth middleware, cookies, and core HTTP/server functions. Reopen/conflict/rollback/auth tests pass. | M1 | RUST + ALISTAIR + QA | 5–7 days |
| M3 | Implement listener actors, Flint client, native dispatch/relay APIs, SSE, overload behavior, and streaming beam upgrade. Prove non-blocking admission and private event filtering. | M2; extracted library services | RUST + ARCHITECT + QA | 4–6 days |
| M4 | Port shell, inspector, Gantt, calendar, Kanban, and work-item table. Complete interaction and geometry checks. | M2 | TYPE + RUST + QA | 6–9 days |
| M5 | Port initiatives/deck, SOPs, RFCs, agents, comms, runs, FinOps, wiki, Ship Log, provenance, and setup. Complete all endpoint adapters and parity receipts. | M2–M4 | TYPE + RUST + QA + ALISTAIR | 8–12 days |
| M6 | Package desktop, complete Slot 1/2 independent QA, rehearse migration/rollback, approve parity exceptions, then cut over `:5487` and retire only the Node planner service. | M3–M5 | QA + ALISTAIR + RUST + ARCHITECT | 4–6 days |
| M7 | Separately design, implement, and verify planner-to-CRDB unification and replicated authority rules. | Stable port; schema/authority decision | ARCHITECT + RUST + ALISTAIR + QA | 6–10 days |

M4 can overlap M3. Parts of M5 can overlap M4 after contracts stabilize.

The initial parity-critical work totals approximately **30–46 person-days**, excluding M7. After Phase 1 acceptance, remaining effort is approximately **27–40 person-days** for M2–M6. With two primary implementers and available QA/security review, a reasonable planning range is four to six elapsed weeks. These are estimates with medium-to-low confidence until M0 resolves native linking and packaging.

The PRD’s 48-hour scaffold target can fit a narrow M1. Its 72-hour complete-view-port target is not supported by the inspected interaction and backend scope.

### Explicit Phase 1 deliverables

- [ ] This design is accepted as the implementation contract.
- [ ] `crates/chinwag-ui` is a workspace member with exact Dioxus 0.7.10 pinning.
- [ ] `server`, `web`, and `desktop` feature boundaries are proven.
- [ ] The frontend builds without Node or package-manager hooks.
- [ ] A native executable serves embedded frontend bytes away from the checkout.
- [ ] The shell and all three theme token sets render.
- [ ] The observed scaffold’s `/api/ui/health` round trip works.
- [ ] `chinwag ui` launches the isolated scaffold.
- [ ] `chinwag ui --desktop` has dispatch wiring and a compile-checked desktop path; full desktop acceptance remains M6.
- [ ] The development configuration cannot accidentally select the live planner database or take over `:5487`.
- [ ] The lockfile, SPDX headers, dependency notices, and required checks are reviewable.

The observed scaffold already declares `/api/ui/health`, a root route, and a theme enum. It does not yet establish embedded CSS, full theme switching, CLI embedding, SQLite, auth, listeners, or view parity.

### Cutover and rollback

Before cutover, the Node service remains the operational writer. The Rust preview uses separate state and does not dual-write the production planner.

At M6:

1. Complete parity and security receipts.
2. Schedule a bounded write pause.
3. Stop the Node planner writer only at the approved cutover.
4. Take a consistent backup including committed WAL state.
5. Validate the schema and backup.
6. Start Rust against the validated planner state and bind `:5487`.
7. Verify identity, portfolio, a controlled planning edit, reply, relay, exports, and shutdown/restart.
8. Retain the previous service definition and binary until the rollback window closes.

Rollback stops Rust and restores the previous service against a compatible database. Because M2–M6 preserve schema, rollback should not require reverse schema migration. New credential/session handling still needs an explicit rollback procedure.

Decommission `com.roguemachine.delivery-planner` only after acceptance. Do not uninstall Node globally or affect unrelated services.

## 12. Risks, open questions, and decisions

### Risks and mitigations

| Risk | Consequence | Mitigation |
|---|---|---|
| Duplicate native SQLite symbols | Incorrect engine selection, link failures, or CRSQL lifecycle corruption | Resolve and test combined linkage in M0 |
| Fixed private snapshot schema | Adding planner tables invalidates existing snapshot assumptions | Keep planner SQLite separate; use M7 |
| Fullstack assets remain external | “Single binary” fails on a spoke | Run release executable away from build outputs |
| Tailwind imports survive | Missing Nessa layout despite embedded CSS | Replace directives/utilities with checked-in CSS and geometry tests |
| Forged identity metadata | Brian/Nic attribution can be spoofed | Separate principal from display actor; verify credentials and proxy boundary |
| Bootstrap returns a credential | Host-bound read exposes an owner credential | Authenticated enrollment and fixture-only bootstrap tests |
| Broad wiretap responses | Private messages leak through JSON or streams | Per-channel authorization before serialization/publication |
| Hardcoded readiness and execution claims | UI reports work or verification that never happened | Measured state and explicit unavailable/fixture labels |
| SQLite contention | Send acknowledgement exceeds 15 ms | Bounded admission, overload response, measured latency objective |
| No durable dispatch outbox | Accepted message may lack completed execution after crash | Preserve durable transcript, expose interruption, decide on an outbox separately |
| Existing beam buffers responses | SSE appears frozen or times out | Upgrade proxy and retain polling until verified |
| GET handlers mutate live state | Golden “read-only” tests change production | Reviewed allowlist and isolated legacy fixtures |
| Panic abort terminates the process | One panic stops UI and backend | Fallible boundaries, release smoke/crash tests, no unwind-dependent recovery |
| Dagu trigger conflicts with read-only source policy | Port expands upstream write authority unintentionally | Separate snapshot collection from explicit execution capability; resolve policy before enabling |
| Source fixtures masquerade as telemetry | False verified runs, dates, savings, or passkey claims survive the rewrite | Approve explicit truthfulness corrections and record golden exceptions |

The source Dagu fallback can report a simulated successful trigger when execution tools are unavailable. Ship Log and several other summaries contain hardcoded operational claims. Rust must preserve useful structure without manufacturing new successful execution. These changes need explicit acceptance as compatibility exceptions.

### Decisions requested from Brian

| Decision | Recommended default | Needed by |
|---|---|---|
| Does the repository’s explicit compatible-license allowlist govern dependencies? | Yes. New code remains Apache-2.0; preserve MIT and other allowed dependency notices. | M0 |
| SQLite library choice | Rusqlite, with native linkage proven before integration. | M0 |
| Dioxus renderer | Fullstack WASM client plus Axum. Do not introduce LiveView for this port. | M1 |
| Development port | Configurable alternate loopback port, initially `5497`; retain live `:5487`. | M1 |
| Fifteen actual navigation entries | Port all 15; retain the source ordering. | M1 |
| Deck presentation | Preserve inline deck behavior; defer a modal wrapper. | M4 |
| Canonical Brian machine/address mapping | Load an explicit reviewed registry; resolve the source/PRD disagreement. | M2 |
| Shared-screen identity switching | Require authenticated delegation and audit both identities. Query/local-storage values remain display preferences. | M2 |
| Nic enrollment | Preserve one-command setup through authenticated enrollment; do not preserve unauthenticated credential disclosure. | M2 |
| `#pa-private` membership | Brian and explicitly enrolled PA identity only unless Brian grants access. | M2 |
| Crash recovery for listener work | Durable transcript with explicit retry initially; add a versioned outbox if automatic retry is required. | M3 |
| Fifteen-millisecond send target | Healthy-local-load latency objective with explicit overload behavior, not an unconditional durability guarantee. | M3 |
| Explicit Dagu execution | Enable only approved local SOP execution through a capability distinct from read-only snapshot access. | M5 |
| Simulated success and fixed telemetry | Remove false success claims and approve documented parity exceptions. | M5 |
| Mobile scope | Responsive web now; native iOS/Android remain deferred. | M6 |
| Node cutover | Require completed parity, security review, Cleanroom receipts, and rollback rehearsal. | M6 |
| CRDB unification | Separate M7 migration after the application port stabilizes. | M7 |

### Open technical questions

- Which approved native archive and symbol strategy can safely coexist with rusqlite in the distributed CLI?
- Does the deployed Flint endpoint support token streaming, and under what concurrency can it meet the first-response objective?
- Which agent roster is canonical? The server listener catalog and `readCustomAgents()` enrollment list differ.
- What signed device-header protocol replaces the current unsigned actor/machine metadata?
- What authenticated session bootstrap fits both local solo use and Nic’s beamed browser without exposing long-lived credentials?
- Which existing CLI callers depend on synchronous chat or the inconsistent `/api/commands` fallback?
- Which source collectors can be ported directly to Rust without granting the UI upstream credentials?
- Which CRDB pin schema is authoritative? Legacy store writes use layouts that differ from the target snapshot schema.
- Which desktop fullstack configuration provides direct in-process service access while preserving one authorization path?
- Which operational values are authoritative records and which are seed fixtures? Source code alone cannot establish the provenance of live records.
- Which exact SOP-QA-02 receipt format and visual tolerances must the new geometry runner emit?

These questions affect their named milestones. They do not prevent the isolated Phase 1 scaffold from proceeding.
## Appendix A. Phase 1 scaffold status and added constraints (2026-10-28)

Added after the design pass, from Brian's steering and the RUST scaffold run:

- **Scaffold verified** on rustc 1.97.1 (pinned by `rust-toolchain.toml`): `cargo build -p chinwag-ui`, `cargo clippy -p chinwag-ui --all-targets --locked -- -D warnings`, and `cargo test -p chinwag-ui --locked` (8 tests) pass. `cargo check` also passes for `--no-default-features --features web --target wasm32-unknown-unknown` and `--features desktop`. A smoke run on a throwaway port (not `:5487`) served `GET /api/ui/health` and a server-rendered shell. The server panics without a `public/` asset directory until the client bundle exists; closing that gap is part of M1.
- **Existing lock entries unchanged:** adding the crate only added packages (362) and disambiguated dependency references in `Cargo.lock`; no existing package version moved.
- **Pre-existing workspace issue (not caused by this crate):** `cargo build --workspace --locked` fails in a private crate's build script because `CHINWAG_PRIVATE_CRSQL_INPUTS` is unset. Build and test per package until that is resolved.
- **Dioxus tooling:** pin Dioxus `=0.7.10` and the matching `dx` CLI 0.7.10 (Dioxus's own Rust CLI, installed by infra under `~/.local/dioxus/bin`). `/opt/homebrew/bin/dx` is an unrelated tool and must not be used.
- **License gate:** `deny.toml` at the repo root allows Apache-2.0, MIT, BSD-2/3-Clause, ISC, Unicode-3.0, Zlib and CC0-1.0 (the CONTRIBUTING.md list). Run `cargo deny --manifest-path crates/chinwag-ui/Cargo.toml check licenses`. It currently **fails on three transitive crates** that need a decision (not silently allowed):
  - `xxhash-rust 0.8.19` (BSL-1.0, permissive Boost license) via `dioxus-fullstack`.
  - `webpki-roots 1.0.11` (CDLA-Permissive-2.0) via `reqwest`/`hyper-rustls` under `dioxus-fullstack`.
  - `option-ext 0.2.0` (MPL-2.0, file-level copyleft) via the `desktop` feature only.
- **Third-party notices:** any port of the vendored Nessa code keeps its MIT `LICENSE` and `UPSTREAM.md` provenance. No Nucleo assets enter the repository.
- **Known scaffold gaps for M1:** `data-theme` is on `<main>` and must move to the document root; embedded CSS, CLI wiring (`chinwag ui`), and the asset directory are not done.
