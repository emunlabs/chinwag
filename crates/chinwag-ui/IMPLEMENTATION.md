# CHWG-DIOXUS-1 implementation plan

1. Extract the shell (header, sidebar, main) and inline theme CSS. Preserve typed routing.
2. Model the planner's channel JSON separately from components; render typed channel links.
3. Add transcript states and preserve the planner's message-array order.
4. Add a controlled composer and pure validation/state transitions. Keep drafts on failure.
5. Add a server-only HTTP adapter configured by CHINWAG_PLANNER_URL, exposed through
   Dioxus server functions. No implicit planner host, live probes, automatic retries or polling.
6. Verify contracts, view-model behavior, actual components through SSR, and real HTTP
   requests against a synthetic loopback planner. Run native, WASM, lint and license gates.

Data flows from planner JSON -> contracts -> view model -> presentation. Send responses
replace the snapshot, so a successful send shows the server's canonical messages. Channel
views are keyed by route ID to isolate drafts and in-flight state across navigation. Failures
retain drafts and never automatically retry an uncertain mutation. Refresh is explicit.

This development slice has no auth and must run on loopback against a test planner.
No CLI integration, storage, listeners, or desktop packaging is included. TYPE can replace
components and theme.rs without changing the contracts or HTTP adapter.
