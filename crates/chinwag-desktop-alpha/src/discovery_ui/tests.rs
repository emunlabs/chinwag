use super::*;
fn snapshot(host: &str) -> ClientInventory {
    serde_json::from_value(serde_json::json!({
    "schema":"chinwag-client-inventory/v1","observed_at_unix_ms":1793361786000_u64,"host_label":host,
    "coverage":{"pid_capacity":4096,"candidate_capacity":128,"sampled_pid_count":100,"candidate_process_count":75,"omitted_candidate_count":0,"raced_processes":0,"permission_denied_processes":0,"unavailable_processes":0,"invalid_process_metadata":0,"unclassified_interpreters":5,"unresolved_components":0,"pid_capacity_reached":false,"candidate_capacity_reached":false},
    "clients":[{"id":"a".repeat(64),"family":"grok_bot","kind":"application","state":"detected_unverified","component_count":75}]
})).unwrap()
}

#[test]
fn grouped_components_are_not_invented_agents_and_host_comes_from_server_snapshot() {
    let mut panel = DiscoveryPanel::default();
    let generation = panel.begin("http://127.0.0.1:44341".into());
    assert!(panel.complete(generation, "http://127.0.0.1:44341", Ok(snapshot("Studio"))));
    assert_eq!(
        panel.summary(),
        "Studio · 1 app family · 1 running instance"
    );
    assert!(
        panel
            .coverage_lines()
            .iter()
            .any(|line| line.contains("2026-10-30 12:03:06 UTC"))
    );
    assert_eq!(panel.rows().len(), 1);
    assert!(panel.rows()[0].contains("75 components · Detected · not connected"));
    assert!(!panel.rows()[0].contains("agents"));
    assert!(
        panel
            .coverage_lines()
            .iter()
            .any(|line| line.contains("Unclassified interpreters: 5 (not identified as clients)"))
    );
}

#[test]
fn superseded_or_cleared_snapshot_never_attaches_to_another_endpoint_or_room() {
    let mut panel = DiscoveryPanel::default();
    let old = panel.begin("old".into());
    let new = panel.begin("new".into());
    assert!(!panel.complete(old, "old", Ok(snapshot("Old host"))));
    assert!(matches!(panel.state, InventoryState::Loading));
    assert!(panel.complete(new, "new", Ok(snapshot("Studio"))));
    panel.clear();
    assert!(!panel.complete(new, "new", Ok(snapshot("Old room response"))));
    assert!(matches!(panel.state, InventoryState::NotRequested));
}

#[test]
fn capacity_and_missing_metadata_are_visible_without_a_connected_claim() {
    let mut panel = DiscoveryPanel::default();
    let generation = panel.begin("bus".into());
    let mut inventory = snapshot("Studio");
    inventory.coverage.candidate_capacity_reached = true;
    inventory.coverage.omitted_candidate_count = 4;
    panel.complete(generation, "bus", Ok(inventory));
    assert!(
        panel
            .coverage_lines()
            .iter()
            .any(|line| line.contains("coverage is incomplete"))
    );
    let generation = panel.begin("bus".into());
    panel.complete(generation, "bus", Err("HTTP 404".into()));
    assert!(panel.summary().starts_with("Unavailable"));
    assert!(panel.rows().is_empty());
}

#[test]
fn snapshot_time_is_human_utc_and_out_of_range_is_unavailable() {
    assert_eq!(snapshot_time(0), "1970-01-01 00:00:00 UTC");
    assert_eq!(snapshot_time(1793361786000), "2026-10-30 12:03:06 UTC");
    assert_eq!(snapshot_time(u64::MAX), "Unavailable");
    assert_eq!(snapshot_time(i64::MAX as u64), "Unavailable");
    let mut panel = DiscoveryPanel::default();
    let generation = panel.begin("bus".into());
    let mut inventory = snapshot("Studio");
    inventory.observed_at_unix_ms = u64::MAX;
    inventory.clients.clear();
    panel.complete(generation, "bus", Ok(inventory));
    assert_eq!(
        panel.summary(),
        "Studio · 0 app families · 0 running instances"
    );
    assert!(panel.coverage_lines()[0].contains("Unavailable"));
    assert!(!panel.summary().contains("Unix ms"));
}

#[test]
fn rows_use_observed_brand_names_and_natural_component_counts() {
    for (family, label) in [
        ("codex_cli", "Codex CLI"),
        ("codex_desktop", "Codex Desktop"),
        ("chatgpt_desktop", "ChatGPT"),
        ("claude_code", "Claude Code"),
        ("claude_desktop", "Claude Desktop"),
        ("google_antigravity", "Antigravity"),
        ("grok_bot", "Grok Bot"),
        ("gemini_cli", "Gemini CLI"),
        ("gemini_desktop", "Gemini Desktop"),
        ("cursor", "Cursor"),
        ("future_client", "future client"),
    ] {
        let mut inventory = snapshot("Studio");
        inventory.clients[0].family = family.into();
        inventory.clients[0].component_count = 1;
        let mut panel = DiscoveryPanel::default();
        let generation = panel.begin("bus".into());
        panel.complete(generation, "bus", Ok(inventory));
        assert_eq!(
            panel.rows(),
            vec![format!(
                "{label} · application · 1 running instance · 1 component · Detected · not connected"
            )]
        );
    }
}

fn installed_apps(apps: serde_json::Value) -> chinwag_bus_client::InstallationInventory {
    serde_json::from_value(serde_json::json!({
        "observed_at_unix_ms":1793361786000_u64,
        "apps":apps,
        "coverage":{"entry_capacity":512,"entries_examined":12,"installation_capacity":128,
            "capacity_reached":false,"unavailable_roots":0,"invalid_metadata":0}
    }))
    .unwrap()
}

fn ready_panel(inventory: ClientInventory) -> DiscoveryPanel {
    let mut panel = DiscoveryPanel::default();
    let generation = panel.begin("http://127.0.0.1:44341".into());
    panel.complete(generation, "http://127.0.0.1:44341", Ok(inventory));
    panel
}

#[test]
fn family_rows_sum_independent_instances_without_merging_source_identity() {
    let mut inventory = snapshot("Studio");
    inventory.clients[0].component_count = 7;
    let mut second = inventory.clients[0].clone();
    second.id = "b".repeat(64);
    second.component_count = 3;
    inventory.clients.push(second);
    let mut claude = inventory.clients[0].clone();
    claude.id = "c".repeat(64);
    claude.family = "claude_code".into();
    claude.kind = ClientKind::CommandLine;
    claude.component_count = 1;
    inventory.clients.push(claude);
    let original = inventory.clone();
    let panel = ready_panel(inventory);
    assert_eq!(panel.rows().len(), 2);
    assert_eq!(
        panel.rows()[1],
        "Claude Code · command line · 1 running instance · 1 component · Detected · not connected"
    );
    assert!(
        panel.rows()[0].contains("Grok Bot · application · 2 running instances · 10 components")
    );
    assert_eq!(
        panel.summary(),
        "Studio · 2 app families · 3 running instances"
    );
    let InventoryState::Ready(retained) = &panel.state else {
        panic!("ready fixture");
    };
    assert_eq!(retained.as_ref(), &original);
    assert_eq!(retained.clients.len(), 3);
    assert_ne!(retained.clients[0].id, retained.clients[1].id);
}

#[test]
fn installed_families_and_running_groups_share_a_row_without_double_counting() {
    let mut inventory = snapshot("Studio");
    inventory.clients[0].component_count = 7;
    inventory.installations = Some(installed_apps(serde_json::json!([
        {"id":"d".repeat(64),"family":"grok_bot","kind":"application","running_instances":1,"state":"installed_unverified"},
        {"id":"e".repeat(64),"family":"chatgpt_desktop","kind":"application","running_instances":0,"state":"installed_unverified"},
        {"id":"f".repeat(64),"family":"google_antigravity","kind":"application","running_instances":0,"state":"installed_unverified"}
    ])));
    let panel = ready_panel(inventory);
    assert_eq!(panel.rows().len(), 3);
    assert_eq!(
        panel.rows()[1],
        "Antigravity · application · Installed · running not observed · not connected"
    );
    assert_eq!(
        panel.rows()[2],
        "ChatGPT · application · Installed · running not observed · not connected"
    );
    assert!(
        panel.rows()[0]
            .contains("Grok Bot · application · Installed · 1 running instance · 7 components")
    );
    assert!(!panel.rows()[0].contains("2 running instances"));
    assert_eq!(
        panel.summary(),
        "Studio · 3 app families · 1 running instance"
    );
}

#[test]
fn installation_hints_stay_hints_and_caps_are_visible_without_expanding_details() {
    let mut inventory = snapshot("Studio");
    inventory.installations = Some(installed_apps(serde_json::json!([
        {"id":"d".repeat(64),"family":"claude_code","kind":"command_line","running_instances":2,"state":"installed_unverified"}
    ])));
    inventory
        .installations
        .as_mut()
        .unwrap()
        .coverage
        .capacity_reached = true;
    let panel = ready_panel(inventory);
    assert!(!panel.details_expanded);
    assert!(
        panel.rows()[1]
            .contains("Claude Code · command line · Installed · 2 running hints · not connected")
    );
    assert!(panel.coverage_warning().is_some());
    assert!(
        panel
            .coverage_lines()
            .iter()
            .any(|line| line.contains("Installation capacity reached: true"))
    );
}

#[test]
fn legacy_runtime_omits_installation_claims_and_details_start_collapsed() {
    let panel = ready_panel(snapshot("Studio"));
    assert!(!panel.details_expanded);
    assert!(!panel.rows()[0].contains("Installed"));
    assert!(
        panel
            .coverage_lines()
            .iter()
            .any(|line| line.contains("Installed apps were not included"))
    );
    assert_eq!(panel.coverage_warning(), None);
}
