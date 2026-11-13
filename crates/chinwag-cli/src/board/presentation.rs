// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! Shared, status-aware board presentation and live schema reconciliation.
use super::*;

pub(super) const FUNCTIONS: [&str; 7] = [
    "Engineering",
    "Design",
    "Product",
    "Security",
    "QA & Release",
    "Analytics",
    "Docs",
];
const MODES: [&str; 6] = [
    "CI Fix · 50 Cr",
    "Review · 50 Cr",
    "Pair · 100 Cr",
    "Triad · 150 Cr",
    "Quad · 200 Cr",
    "Open bounty",
];
pub(super) const SPEEDUP_OPTIONS: [&str; 7] = [
    "⚡ 100x+ Faster vs. DORA",
    "🚀 50x–99x Faster vs. DORA",
    "🔥 10x–49x Faster vs. DORA",
    "⏱️ Clock Running — In Flight",
    "📐 Baseline Locked — Queued",
    "Shipped · Measurement unavailable",
    "Measured · Below 10x baseline",
];

pub(super) fn primary_function(issue: &AtomicTaskIssue) -> &str {
    issue
        .primary_function
        .as_deref()
        .filter(|v| FUNCTIONS.contains(v))
        .unwrap_or("Engineering")
}

pub(super) fn commercial_execution_mode(issue: &AtomicTaskIssue) -> &'static str {
    if issue.status == BoardStatus::OpenBounty {
        return "Open bounty";
    }
    match issue.assigned_seats.len() {
        0 | 1 if primary_function(issue) == "QA & Release" => MODES[0],
        0 | 1 => MODES[1],
        2 => MODES[2],
        3 => MODES[3],
        _ => MODES[4],
    }
}

pub(super) fn realized_credits(issue: &AtomicTaskIssue) -> u64 {
    if issue.status != BoardStatus::ShippedVerified {
        return 0;
    }
    match commercial_execution_mode(issue) {
        "CI Fix · 50 Cr" | "Review · 50 Cr" => 50,
        "Pair · 100 Cr" => 100,
        "Triad · 150 Cr" => 150,
        "Quad · 200 Cr" => 200,
        _ => 0,
    }
}

fn measured_ship(issue: &AtomicTaskIssue) -> bool {
    issue.status == BoardStatus::ShippedVerified
        && issue.t_claim_ms > 0
        && issue.t_ship_ms > issue.t_claim_ms
        && issue.loc_changed.is_some()
}

pub(super) fn card_metrics(
    issue: &AtomicTaskIssue,
    proof: &VelocityProof,
) -> (String, String, f64) {
    match issue.status {
        BoardStatus::OpenBounty | BoardStatus::ScopedBenchmarked => (
            SPEEDUP_OPTIONS[4].to_string(),
            "Queued · Ready".to_string(),
            0.0,
        ),
        BoardStatus::InFlight | BoardStatus::TribunalGate => (
            SPEEDUP_OPTIONS[3].to_string(),
            "In flight · Clock running".to_string(),
            0.0,
        ),
        BoardStatus::ShippedVerified if measured_ship(issue) => (
            proof.speedup_pill.clone(),
            proof.cycle_time_label.clone(),
            proof.net_hours_saved,
        ),
        BoardStatus::ShippedVerified => (
            SPEEDUP_OPTIONS[5].to_string(),
            "Shipped · Timing unavailable".to_string(),
            0.0,
        ),
    }
}

pub(super) fn verification_receipt(issue: &AtomicTaskIssue) -> String {
    let watch = match issue.surv_status {
        SurvStatus::Pending168h => "7-day watch pending",
        SurvStatus::Survived168h => "7-day watch passed",
        SurvStatus::FailedRegressionClawback => "Regression detected",
        _ => "7-day watch not started",
    };
    match issue.status {
        BoardStatus::OpenBounty | BoardStatus::ScopedBenchmarked => {
            "Scoped · Baseline locked".to_string()
        }
        BoardStatus::InFlight | BoardStatus::TribunalGate => {
            "In progress · Verification pending".to_string()
        }
        BoardStatus::ShippedVerified if !measured_ship(issue) => {
            "Owner confirmed complete · Verification evidence unavailable".to_string()
        }
        BoardStatus::ShippedVerified => {
            let recorded_pass = issue.body.contains("CleanroomCIReceiptV1: status=PASS")
                || issue
                    .last_ci_gate_badge
                    .as_deref()
                    .is_some_and(|b| b.contains("H1+H2"));
            if recorded_pass {
                format!("Recorded cleanroom checks green · Review evidence unverified · {watch}")
            } else {
                format!("Shipped · Review evidence unavailable · {watch}")
            }
        }
    }
}

fn select_options(cfg: &BoardConfigV1, name: &str, labels: &[&str]) -> String {
    let existing = if name == "Status" {
        Some(&cfg.status_option_ids)
    } else {
        cfg.custom_field_option_ids.get(name)
    };
    let colors = [
        "GREEN", "BLUE", "PURPLE", "YELLOW", "GRAY", "ORANGE", "PINK",
    ];
    labels
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let id = existing
                .and_then(|m| m.get(*label))
                .map(|id| format!("id: {}, ", json!(id)))
                .unwrap_or_default();
            format!(
                "{{ {id}name: {}, color: {}, description: {} }}",
                json!(label),
                colors[i % colors.len()],
                json!(label)
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn ensure_project_schema(cfg: &mut BoardConfigV1) -> Result<(), String> {
    refresh_github_project_fields(cfg)?;
    let status: Vec<&str> = [
        BoardStatus::OpenBounty,
        BoardStatus::ScopedBenchmarked,
        BoardStatus::InFlight,
        BoardStatus::TribunalGate,
        BoardStatus::ShippedVerified,
    ]
    .iter()
    .map(|s| s.column_header())
    .collect();
    let tiers: Vec<&str> = [DoraTier::S, DoraTier::M, DoraTier::L, DoraTier::XL]
        .iter()
        .map(|t| t.canonical_option_label())
        .collect();
    for (name, labels) in [
        ("Status", status.as_slice()),
        ("Function / Team", FUNCTIONS.as_slice()),
        ("DORA Baseline", tiers.as_slice()),
        ("Execution Mode", MODES.as_slice()),
        ("Δ Speedup vs. DORA", SPEEDUP_OPTIONS.as_slice()),
    ] {
        let current = if name == "Status" {
            Some(&cfg.status_option_ids)
        } else {
            cfg.custom_field_option_ids.get(name)
        };
        if current
            .is_some_and(|m| m.len() == labels.len() && labels.iter().all(|l| m.contains_key(*l)))
        {
            continue;
        }
        let options = select_options(cfg, name, labels);
        let id = if name == "Status" {
            cfg.status_field_id.as_ref()
        } else {
            cfg.custom_field_ids.get(name)
        };
        let query = if let Some(id) = id {
            format!(
                "mutation {{ updateProjectV2Field(input: {{ fieldId: {}, name: {}, singleSelectOptions: [{options}] }}) {{ clientMutationId }} }}",
                json!(id),
                json!(name)
            )
        } else {
            format!(
                "mutation {{ createProjectV2Field(input: {{ projectId: {}, name: {}, dataType: SINGLE_SELECT, singleSelectOptions: [{options}] }}) {{ clientMutationId }} }}",
                json!(cfg.project_id),
                json!(name)
            )
        };
        execute_gh_graphql(&query, &[])?;
    }
    for (name, data_type) in [
        ("Baseline Hours", "NUMBER"),
        ("Net Hours Saved", "NUMBER"),
        ("Credits Used", "NUMBER"),
        ("Chinwag Cycle Time", "TEXT"),
        ("Verification Receipt", "TEXT"),
    ] {
        if cfg.custom_field_ids.contains_key(name) {
            continue;
        }
        let query = format!(
            "mutation {{ createProjectV2Field(input: {{ projectId: {}, name: {}, dataType: {data_type} }}) {{ clientMutationId }} }}",
            json!(cfg.project_id),
            json!(name)
        );
        execute_gh_graphql(&query, &[])?;
    }
    refresh_github_project_fields(cfg)
}

pub(super) fn project_assignee_id(cfg: &BoardConfigV1) -> Result<String, String> {
    let response = if let Some(login) = &cfg.assignee_login {
        execute_gh_graphql(
            "query($login: String!) { user(login: $login) { id } }",
            &[("login", login)],
        )?
    } else {
        execute_gh_graphql("query { user: viewer { id } }", &[])?
    };
    response
        .pointer("/data/user/id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "configured GitHub assignee is missing".to_string())
}

pub(super) fn populate_project_card(
    cfg: &BoardConfigV1,
    item: &str,
    issue: &AtomicTaskIssue,
    card: &BoardCardEntryV1,
) -> Result<(), String> {
    let status_id = cfg
        .status_field_id
        .as_deref()
        .ok_or("missing Status field")?;
    let status_option = cfg
        .status_option_ids
        .get(issue.status.column_header())
        .ok_or("missing Status option")?;
    let mut writes = vec![(
        status_id.to_string(),
        format!("{{ singleSelectOptionId: {} }}", json!(status_option)),
    )];
    for (name, value) in [
        ("Function / Team", card.primary_function.as_str()),
        ("DORA Baseline", card.dora_baseline.as_str()),
        ("Δ Speedup vs. DORA", card.delta_speedup_vs_dora.as_str()),
        ("Execution Mode", card.execution_mode.as_str()),
    ] {
        let field = cfg
            .custom_field_ids
            .get(name)
            .ok_or_else(|| format!("missing field {name}"))?;
        let option = cfg
            .custom_field_option_ids
            .get(name)
            .and_then(|m| m.get(value))
            .ok_or_else(|| format!("missing option {value} for {name}"))?;
        writes.push((
            field.clone(),
            format!("{{ singleSelectOptionId: {} }}", json!(option)),
        ));
    }
    for (name, value) in [
        ("Baseline Hours", card.baseline_hours),
        ("Net Hours Saved", card.net_hours_saved),
        ("Credits Used", card.credits_used as f64),
    ] {
        let field = cfg
            .custom_field_ids
            .get(name)
            .ok_or_else(|| format!("missing field {name}"))?;
        writes.push((field.clone(), format!("{{ number: {value:.2} }}")));
    }
    for (name, value) in [
        ("Chinwag Cycle Time", card.chinwag_cycle_time.as_str()),
        ("Verification Receipt", card.verification_receipt.as_str()),
        ("Cryptographic Receipt", card.cryptographic_receipt.as_str()),
        ("Active Seats", card.active_seats.as_str()),
    ] {
        if let Some(field) = cfg.custom_field_ids.get(name) {
            writes.push((field.clone(), format!("{{ text: {} }}", json!(value))));
        }
    }
    let mutations = writes.iter().enumerate().map(|(index, (field, value))| {
        format!("f{index}: updateProjectV2ItemFieldValue(input: {{ projectId: {}, itemId: {}, fieldId: {}, value: {value} }}) {{ projectV2Item {{ id }} }}", json!(cfg.project_id), json!(item), json!(field))
    }).collect::<Vec<_>>().join("\n");
    execute_gh_graphql(&format!("mutation {{ {mutations} }}"), &[])?;
    Ok(())
}

pub(super) fn project_readme() -> &'static str {
    r#"## What is “DORA Baseline” (Typical Human Dev Time)?

- **DORA** means **DevOps Research & Assessment**, Google Cloud's annual software-delivery research program. Its 2024 report reflects more than 39,000 professionals across the research program. Paired with LinearB pull-request benchmarks, it informs Chinwag's model of time spent scoping, coding, reviewing, testing and merging a change.
- **The table is Chinwag's planning model**, not a tier table published by Google or LinearB. Active engineering hours exclude calendar waiting; the calendar-day estimates provide a separate comparison.
- **Hours saved are realized only after verification:** `Net Hours Saved = max(0, Baseline Hours − Actual Ship Time)`. Queued and in-flight items stay at **0**. A shipped item without measured timing also stays at **0**.

| Tier | Lines changed | Active human engineering | Calendar estimate |
| :--- | :--- | ---: | ---: |
| S | ≤100 | 8.5h | ~1.1 days |
| M | 101–400 | 27.0h | ~3.4 days |
| L | 401–1,200 | 50.0h | ~6.2 days |
| XL | >1,200 | 112.0h | ~14.0 days |

**Un-gameable by design:** if a merged change touches fewer lines than scoped, Chinwag automatically caps its baseline tier to actual lines changed. Savings are recorded only at **05 · ✓ SHIPPED — Δ VERIFIED**, with measured start/end times and changed-line counts. Fixed credit values use the published function rate for the execution mode.

Sources: [Google Cloud DORA research](https://dora.dev/research/2024/dora-report/), [LinearB engineering benchmarks](https://linearb.io/resources/engineering-benchmarks).

## Views & Insights Guide

- **01 · Kanban Execution Board:** follow work from queued through independently verified delivery.
- **02 · Velocity & DORA Ledger:** compare baseline hours, measured cycle time, realized hours saved and fixed credits.
- **03 · Work by Function:** find Engineering, Design, Product, Security, QA & Release, Analytics and Docs work.
- **04 · Open Bounties (+500 Credits):** find open contributor work and its published reward.
- **View recipes:** GitHub's ProjectV2 GraphQL API provisions view names, layouts, filters, visible columns, and Kanban `Status` lanes; table row grouping and sort order are optional GitHub web UI recipes.
- **/insights:** chart recipes cover verified hours by tier, hours by function, throughput by execution mode, verified credit totals and work by function. Hours and credit sums use the shipped-only filter. Recipes require native GitHub Insights configuration; template recipes alone do not create live charts.

## Privacy & Fixed Credit Pricing

Private repository tasks stay hidden automatically through GitHub repository access controls. Every card is a repository issue; there are zero board-level draft cards. Board sync uses **0 credits**. Execution uses [published fixed function rates](https://chinwag.sh/pricing): CI Fix 50, Review 50, Pair 100, Triad 150 and Quad 200 credits.

Copy this board into your private repository:

```sh
chinwag board init --github --org <your-org> --private-repo <your-org>/<your-repo> --live
```

[See how Chinwag delivery works](https://chinwag.sh/delivery).
"#
}

pub(super) fn update_project_overview(cfg: &BoardConfigV1) -> Result<(), String> {
    let description = "Live Chinwag delivery ledger: shipped work, hours saved vs. typical human dev time (Google DORA), and fixed credits used.";
    execute_gh_graphql(
        r#"mutation($project: ID!, $description: String!, $readme: String!) {
      updateProjectV2(input: {projectId: $project, shortDescription: $description, readme: $readme}) { projectV2 { id } }
    }"#,
        &[
            ("project", &cfg.project_id),
            ("description", description),
            ("readme", project_readme()),
        ],
    )?;
    Ok(())
}

const LEDGER_FIELDS: [&str; 15] = [
    "Title",
    "Status",
    "Assignees",
    "Function / Team",
    "Repository",
    "DORA Baseline",
    "Baseline Hours",
    "Chinwag Cycle Time",
    "Δ Speedup vs. DORA",
    "Net Hours Saved",
    "Credits Used",
    "Execution Mode",
    "Verification Receipt",
    "Created",
    "Updated",
];
const BOARD_FIELDS: [&str; 10] = [
    "Title",
    "Assignees",
    "Function / Team",
    "DORA Baseline",
    "Chinwag Cycle Time",
    "Δ Speedup vs. DORA",
    "Net Hours Saved",
    "Credits Used",
    "Execution Mode",
    "Verification Receipt",
];
const BOUNTY_FIELDS: [&str; 8] = [
    "Title",
    "Status",
    "Assignees",
    "Function / Team",
    "DORA Baseline",
    "Baseline Hours",
    "Execution Mode",
    "Verification Receipt",
];

pub(super) fn configure_project_views(cfg: &BoardConfigV1) -> Result<Value, String> {
    let response = execute_gh_graphql(
        r#"query($project: ID!) { node(id: $project) { ... on ProjectV2 {
      views(first: 100) { nodes { id number name layout filter } pageInfo { hasNextPage } }
    } } }"#,
        &[("project", &cfg.project_id)],
    )?;
    if response
        .pointer("/data/node/views/pageInfo/hasNextPage")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return Err("project views exceed the supported 100-view limit".to_string());
    }
    let existing = response
        .pointer("/data/node/views/nodes")
        .and_then(Value::as_array)
        .ok_or("missing view list")?;
    let specs = [
        (
            1,
            "01 · Kanban Execution Board",
            "BOARD_LAYOUT",
            "",
            BOARD_FIELDS.as_slice(),
        ),
        (
            2,
            "02 · Velocity & DORA Ledger",
            "TABLE_LAYOUT",
            "",
            LEDGER_FIELDS.as_slice(),
        ),
        (
            3,
            "03 · Work by Function",
            "TABLE_LAYOUT",
            "has:status",
            LEDGER_FIELDS.as_slice(),
        ),
        (
            4,
            "04 · 🌱 Open Bounties (+500 Credits)",
            "BOARD_LAYOUT",
            "status:\"01 · 🌱 OPEN BOUNTY (+500 CR)\"",
            BOUNTY_FIELDS.as_slice(),
        ),
    ];
    let mut views = Vec::new();
    for (number, name, layout, filter, fields) in specs {
        let ids: Result<Vec<&str>, String> = fields
            .iter()
            .map(|name| {
                if *name == "Status" {
                    cfg.status_field_id.as_deref()
                } else {
                    cfg.custom_field_ids.get(*name).map(String::as_str)
                }
                .ok_or_else(|| format!("missing visible field {name}"))
            })
            .collect();
        let ids = json!(ids?).to_string();
        let prior = existing
            .iter()
            .find(|v| v["name"] == name)
            .or_else(|| existing.iter().find(|v| v["number"] == number));
        let id = if let Some(prior) = prior {
            prior["id"].as_str().ok_or("view has no id")?.to_string()
        } else {
            let query = format!(
                "mutation {{ createProjectV2View(input: {{ projectId: {}, name: {}, layout: {layout}, configuration: {{ visibleFieldIds: {ids} }} }}) {{ projectV2View {{ id }} }} }}",
                json!(cfg.project_id),
                json!(name)
            );
            execute_gh_graphql(&query, &[])?
                .pointer("/data/createProjectV2View/projectV2View/id")
                .and_then(Value::as_str)
                .ok_or("createProjectV2View returned no id")?
                .to_string()
        };
        let query = format!(
            "mutation {{ updateProjectV2View(input: {{ viewId: {}, name: {}, layout: {layout}, filter: {}, configuration: {{ visibleFieldIds: {ids} }} }}) {{ projectV2View {{ id name layout filter }} }} }}",
            json!(id),
            json!(name),
            json!(filter)
        );
        execute_gh_graphql(&query, &[])?;
        views.push(json!({"id":id, "number":number, "name":name, "layout":layout, "filter":filter, "visible_fields":fields}));
    }
    Ok(json!(views))
}

struct ReadbackViewSpec<'a> {
    number: u64,
    expected_name: &'a str,
    expected_layout: &'a str,
    expected_filter: &'a str,
    wanted_fields: &'a [&'a str],
    allowed_table_group: Option<&'a str>,
    allowed_table_sort: Option<(&'a str, &'a str)>,
}

/// Validate canonical ProjectV2 views on readback, including name, layout, filter, visible
/// columns, BOARD_LAYOUT vertical Status lanes, and absence of stale unexpected grouping/sorting.
fn validate_readback_views(views: &[Value]) -> Result<Value, String> {
    let specs = [
        ReadbackViewSpec {
            number: 1,
            expected_name: "01 · Kanban Execution Board",
            expected_layout: "BOARD_LAYOUT",
            expected_filter: "",
            wanted_fields: BOARD_FIELDS.as_slice(),
            allowed_table_group: None,
            allowed_table_sort: None,
        },
        ReadbackViewSpec {
            number: 2,
            expected_name: "02 · Velocity & DORA Ledger",
            expected_layout: "TABLE_LAYOUT",
            expected_filter: "",
            wanted_fields: LEDGER_FIELDS.as_slice(),
            allowed_table_group: Some("Status"),
            allowed_table_sort: Some(("Updated", "DESC")),
        },
        ReadbackViewSpec {
            number: 3,
            expected_name: "03 · Work by Function",
            expected_layout: "TABLE_LAYOUT",
            expected_filter: "has:status",
            wanted_fields: LEDGER_FIELDS.as_slice(),
            allowed_table_group: Some("Function / Team"),
            allowed_table_sort: None,
        },
        ReadbackViewSpec {
            number: 4,
            expected_name: "04 · 🌱 Open Bounties (+500 Credits)",
            expected_layout: "BOARD_LAYOUT",
            expected_filter: "status:\"01 · 🌱 OPEN BOUNTY (+500 CR)\"",
            wanted_fields: BOUNTY_FIELDS.as_slice(),
            allowed_table_group: None,
            allowed_table_sort: None,
        },
    ];
    let mut recipe_status = Vec::new();
    for spec in specs {
        let ReadbackViewSpec {
            number,
            expected_name,
            expected_layout,
            expected_filter,
            wanted_fields,
            allowed_table_group,
            allowed_table_sort,
        } = spec;
        let view = views
            .iter()
            .find(|v| v["number"].as_u64() == Some(number))
            .ok_or_else(|| format!("missing canonical view {number}"))?;
        if view["name"].as_str() != Some(expected_name) {
            return Err(format!(
                "view {number} persisted name {:?} differs from {expected_name:?}",
                view["name"].as_str()
            ));
        }
        if view["layout"].as_str() != Some(expected_layout) {
            return Err(format!(
                "view {number} persisted layout {:?} differs from {expected_layout:?}",
                view["layout"].as_str()
            ));
        }
        let actual_filter = view["filter"].as_str().unwrap_or("");
        if actual_filter != expected_filter {
            return Err(format!(
                "view {number} persisted filter {actual_filter:?} differs from {expected_filter:?}"
            ));
        }
        let actual_fields: Vec<&str> = view
            .pointer("/configuration/visibleFields/nodes")
            .and_then(Value::as_array)
            .ok_or("missing view fields")?
            .iter()
            .filter_map(|v| v["name"].as_str())
            .collect();
        if actual_fields != wanted_fields {
            return Err(format!(
                "view {number} persisted fields differ: {actual_fields:?}"
            ));
        }
        let group_by: Vec<&str> = view
            .pointer("/groupByFields/nodes")
            .and_then(Value::as_array)
            .ok_or("missing view groupByFields")?
            .iter()
            .filter_map(|v| v["name"].as_str())
            .collect();
        let vertical_group_by: Vec<&str> = view
            .pointer("/verticalGroupByFields/nodes")
            .and_then(Value::as_array)
            .ok_or("missing view verticalGroupByFields")?
            .iter()
            .filter_map(|v| v["name"].as_str())
            .collect();
        let sort_by: Vec<(&str, &str)> = view
            .pointer("/sortByFields/nodes")
            .and_then(Value::as_array)
            .ok_or("missing view sortByFields")?
            .iter()
            .filter_map(|v| {
                Some((
                    v.pointer("/field/name")?.as_str()?,
                    v["direction"].as_str()?,
                ))
            })
            .collect();
        if expected_layout == "BOARD_LAYOUT" {
            if vertical_group_by != ["Status"] {
                return Err(format!(
                    "board view {number} verticalGroupByFields must be [\"Status\"], got {vertical_group_by:?}"
                ));
            }
            if !group_by.is_empty() {
                return Err(format!(
                    "board view {number} has unexpected horizontal groupByFields: {group_by:?}"
                ));
            }
        } else {
            let group_applied = match allowed_table_group {
                Some(expected_group) if group_by == [expected_group] => true,
                _ if group_by.is_empty() => false,
                _ => {
                    return Err(format!(
                        "table view {number} has unexpected stale groupByFields: {group_by:?}"
                    ));
                }
            };
            let sort_applied = match allowed_table_sort {
                Some(expected_sort) if sort_by == [expected_sort] => true,
                None if sort_by.is_empty() => true,
                Some(_) if sort_by.is_empty() => false,
                _ => {
                    return Err(format!(
                        "table view {number} has unexpected stale sortByFields: {sort_by:?}"
                    ));
                }
            };
            recipe_status.push(json!({
                "number": number,
                "name": expected_name,
                "recommended_group_by": allowed_table_group,
                "group_by_applied_in_web_ui": group_applied,
                "recommended_sort_by": allowed_table_sort.map(|(f, d)| json!({"field": f, "direction": d})),
                "sort_by_applied_in_web_ui": sort_applied,
            }));
        }
    }
    Ok(json!(recipe_status))
}

/// Read back persisted values, count zero as populated, and refuse partial/blank data.
pub(super) fn verify_project_population(
    cfg: &BoardConfigV1,
    issues: &[AtomicTaskIssue],
) -> Result<Value, String> {
    let query = r#"query($project: ID!) { node(id: $project) { ... on ProjectV2 {
      items(first: 100) { nodes { id content { ... on Issue { title createdAt updatedAt repository { nameWithOwner isPrivate } assignees(first:100) { nodes { login } } } }
        fieldValues(first: 100) { nodes {
          ... on ProjectV2ItemFieldNumberValue { number field { ... on ProjectV2FieldCommon { name } } }
          ... on ProjectV2ItemFieldTextValue { text field { ... on ProjectV2FieldCommon { name } } }
          ... on ProjectV2ItemFieldSingleSelectValue { name field { ... on ProjectV2FieldCommon { name } } }
        } pageInfo { hasNextPage } }
      } pageInfo { hasNextPage } }
      views(first:100) { nodes {
        id number name layout filter
        groupByFields(first:20) { nodes { ... on ProjectV2FieldCommon { name } } }
        verticalGroupByFields(first:20) { nodes { ... on ProjectV2FieldCommon { name } } }
        sortByFields(first:20) { nodes { direction field { ... on ProjectV2FieldCommon { name } } } }
        configuration { visibleFields(first:100) { nodes { ... on ProjectV2FieldCommon { id name } } } }
      } }
    } } }"#;
    let response = execute_gh_graphql(query, &[("project", &cfg.project_id)])?;
    let project = response
        .pointer("/data/node")
        .ok_or("missing ProjectV2 readback")?;
    if project
        .pointer("/items/pageInfo/hasNextPage")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return Err("readback exceeds 100 project items".to_string());
    }
    let items = project
        .pointer("/items/nodes")
        .and_then(Value::as_array)
        .ok_or("missing project items")?;
    let local_has_private = issues
        .iter()
        .any(|i| !i.visibility.eq_ignore_ascii_case("public"));
    let board_public_count = items
        .iter()
        .filter(|item| {
            item.pointer("/content/repository/isPrivate")
                .and_then(Value::as_bool)
                == Some(false)
        })
        .count();
    let local_public_count = issues
        .iter()
        .filter(|i| i.visibility.eq_ignore_ascii_case("public"))
        .count();
    if local_has_private {
        if items.len() != issues.len() {
            return Err(format!(
                "project has {} items; local scope has {}: reconcile project membership before accepting counts",
                items.len(),
                issues.len()
            ));
        }
    } else if board_public_count != local_public_count {
        return Err(format!(
            "project has {} public items; local public scope has {}: reconcile project membership before accepting counts",
            board_public_count, local_public_count
        ));
    }
    let mut counts: BTreeMap<String, usize> =
        LEDGER_FIELDS.iter().map(|s| (s.to_string(), 0)).collect();
    let mut public_counts = counts.clone();
    let mut public_total = 0;
    let mut shipped_public = 0;
    let mut shipped_total = 0;
    let mut saved = 0.0;
    let mut public_saved = 0.0;
    let mut credits = 0.0;
    let mut public_credits = 0.0;
    let mut measured_total = 0;
    let mut measured_public = 0;
    let mut seen = std::collections::BTreeSet::new();
    for item in items {
        let content = &item["content"];
        let title = content["title"].as_str().ok_or("non-issue project card")?;
        if let Err((inv, leaked)) = super::scan_entity_firewall_text(title) {
            return Err(format!(
                "entity firewall [{inv}] rejected project card `{title}`: {leaked}"
            ));
        }
        let task_id =
            github_task_id_from_title(title).ok_or("project issue missing task prefix")?;
        if !super::is_canonical_chwg_ticket_id(task_id) {
            return Err(format!("non-canonical project task prefix `{task_id}`"));
        }
        if !seen.insert(task_id) {
            return Err(format!("duplicate project task {task_id}"));
        }
        let public = content
            .pointer("/repository/isPrivate")
            .and_then(Value::as_bool)
            == Some(false);
        if public {
            public_total += 1;
        }
        let local_opt = issues.iter().find(|i| i.id == task_id);
        if local_opt.is_none() && (public || local_has_private) {
            return Err(format!("unexpected project task {task_id}"));
        }
        if item
            .pointer("/fieldValues/pageInfo/hasNextPage")
            .and_then(Value::as_bool)
            != Some(false)
        {
            return Err("item fields exceed 100-value limit".to_string());
        }
        let mut values = BTreeMap::<String, Value>::new();
        for field in item
            .pointer("/fieldValues/nodes")
            .and_then(Value::as_array)
            .ok_or("missing item field values")?
        {
            if let Some(name) = field.pointer("/field/name").and_then(Value::as_str)
                && let Some(v) = field
                    .get("number")
                    .or_else(|| field.get("text"))
                    .or_else(|| field.get("name"))
            {
                values.insert(name.to_string(), v.clone());
            }
        }
        for (name, v) in [
            ("Title", content.get("title")),
            ("Created", content.get("createdAt")),
            ("Updated", content.get("updatedAt")),
            ("Repository", content.pointer("/repository/nameWithOwner")),
        ] {
            if let Some(v) = v {
                values.insert(name.to_string(), v.clone());
            }
        }
        let assignees = content
            .pointer("/assignees/nodes")
            .and_then(Value::as_array)
            .ok_or("missing assignees")?;
        if assignees.iter().any(|a| {
            cfg.assignee_login
                .as_deref()
                .is_none_or(|login| a["login"] == login)
        }) {
            values.insert("Assignees".to_string(), json!("assigned"));
        }
        for name in LEDGER_FIELDS {
            let populated = values
                .get(name)
                .is_some_and(|v| !v.is_null() && v.as_str().is_none_or(|s| !s.trim().is_empty()));
            if !populated {
                return Err(format!("blank surfaced field {name} on {task_id}"));
            }
            *counts.get_mut(name).ok_or("missing count")? += 1;
            if public {
                *public_counts.get_mut(name).ok_or("missing public count")? += 1;
            }
        }
        if let Some(local) = local_opt {
            let expected = card_entry_from_issue(local, Some(cfg), None, None);
            for (name, value) in [
                ("Net Hours Saved", expected.net_hours_saved),
                ("Baseline Hours", expected.baseline_hours),
                ("Credits Used", expected.credits_used as f64),
            ] {
                if values
                    .get(name)
                    .and_then(Value::as_f64)
                    .is_none_or(|v| (v - value).abs() > 0.001)
                {
                    return Err(format!("incorrect {name} on {task_id}"));
                }
            }
            for (name, expected_value) in [
                ("Function / Team", expected.primary_function.as_str()),
                ("DORA Baseline", expected.dora_baseline.as_str()),
                ("Chinwag Cycle Time", expected.chinwag_cycle_time.as_str()),
                ("Execution Mode", expected.execution_mode.as_str()),
                (
                    "Δ Speedup vs. DORA",
                    expected.delta_speedup_vs_dora.as_str(),
                ),
                (
                    "Verification Receipt",
                    expected.verification_receipt.as_str(),
                ),
            ] {
                if values.get(name).and_then(Value::as_str) != Some(expected_value) {
                    return Err(format!("incorrect {name} on {task_id}"));
                }
            }
            if values.get("Status").and_then(Value::as_str) != Some(local.status.column_header()) {
                return Err(format!("incorrect Status on {task_id}"));
            }
            if local.status == BoardStatus::ShippedVerified {
                shipped_total += 1;
                saved += expected.net_hours_saved;
                credits += expected.credits_used as f64;
                if measured_ship(local) {
                    measured_total += 1;
                }
                if public {
                    shipped_public += 1;
                    public_saved += expected.net_hours_saved;
                    public_credits += expected.credits_used as f64;
                    if measured_ship(local) {
                        measured_public += 1;
                    }
                }
            }
        } else if values.get("Status").and_then(Value::as_str)
            == Some(BoardStatus::ShippedVerified.column_header())
        {
            shipped_total += 1;
            let item_saved = values
                .get("Net Hours Saved")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let item_credits = values
                .get("Credits Used")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            saved += item_saved;
            credits += item_credits;
            if item_saved > 0.0 {
                measured_total += 1;
            }
        }
    }
    let views = project
        .pointer("/views/nodes")
        .and_then(Value::as_array)
        .ok_or("missing readback views")?;
    let ui_view_recipes = validate_readback_views(views)?;
    if cfg.public_board {
        Ok(json!({
            "public_board": true,
            "public_items": public_total,
            "public_population": public_counts,
            "shipped_public_items": shipped_public,
            "measured_shipped_public_items": measured_public,
            "public_net_hours_saved": (public_saved * 100.0).round() / 100.0,
            "public_credits_used": public_credits,
            "unshipped_hours_saved": 0,
            "ui_view_recipes": ui_view_recipes,
            "views": views,
        }))
    } else {
        Ok(json!({
            "public_board": false,
            "total_items": items.len(),
            "public_items": public_total,
            "population": counts,
            "public_population": public_counts,
            "shipped_items": shipped_total,
            "measured_shipped_items": measured_total,
            "shipped_public_items": shipped_public,
            "measured_shipped_public_items": measured_public,
            "net_hours_saved": (saved * 100.0).round() / 100.0,
            "public_net_hours_saved": (public_saved * 100.0).round() / 100.0,
            "credits_used": credits,
            "public_credits_used": public_credits,
            "unshipped_hours_saved": 0,
            "ui_view_recipes": ui_view_recipes,
            "views": views,
        }))
    }
}

fn format_project_status_body(cfg: &BoardConfigV1, audit: &Value) -> String {
    if cfg.public_board {
        format!(
            "{} public cards shipped; {} measured shipments contribute {:.2} recorded hours saved. Public cards total: {:.0} menu-rated execution credits (not a billing reconciliation). Unshipped items stay at 0 hours saved until verified; unmeasured completions contribute 0. Board sync uses 0 credits.",
            audit["shipped_public_items"].as_u64().unwrap_or(0),
            audit["measured_shipped_public_items"].as_u64().unwrap_or(0),
            audit["public_net_hours_saved"].as_f64().unwrap_or(0.0),
            audit["public_credits_used"].as_f64().unwrap_or(0.0)
        )
    } else {
        format!(
            "{} cards shipped; {} measured shipments contribute {:.2} recorded hours saved. Board total: {:.0} menu-rated execution credits (not a billing reconciliation). Unshipped items stay at 0 hours saved until verified; unmeasured completions contribute 0. Board sync uses 0 credits.",
            audit["shipped_items"].as_u64().unwrap_or(0),
            audit["measured_shipped_items"].as_u64().unwrap_or(0),
            audit["net_hours_saved"].as_f64().unwrap_or(0.0),
            audit["credits_used"].as_f64().unwrap_or(0.0)
        )
    }
}

pub(super) fn post_project_status(cfg: &BoardConfigV1, audit: &Value) -> Result<Value, String> {
    let body = format_project_status_body(cfg, audit);
    let response = execute_gh_graphql(
        r#"mutation($project: ID!, $body: String!) {
      createProjectV2StatusUpdate(input: {projectId: $project, body: $body, status: ON_TRACK}) { statusUpdate { id status body } }
    }"#,
        &[("project", &cfg.project_id), ("body", &body)],
    )?;
    response
        .pointer("/data/createProjectV2StatusUpdate/statusUpdate")
        .cloned()
        .ok_or_else(|| "missing status update".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn pipeline_never_claims_hours_or_credits() {
        let mut issue = AtomicTaskIssue::new_default("CHWG-9999", "Test outcome", DoraTier::XL);
        issue.assigned_seats = vec!["builder".into(), "reviewer".into()];
        issue.loc_changed = Some(80);
        issue.t_ship_ms = issue.t_claim_ms + 1_140_000;
        for status in [
            BoardStatus::OpenBounty,
            BoardStatus::ScopedBenchmarked,
            BoardStatus::InFlight,
            BoardStatus::TribunalGate,
        ] {
            issue.status = status;
            let card = card_entry_from_issue(&issue, None, None, None);
            assert_eq!(card.net_hours_saved, 0.0);
            assert_eq!(card.credits_used, 0);
            assert!(!card.delta_speedup_vs_dora.contains("Faster"));
            assert_eq!(card.baseline_hours, 8.5);
        }
        issue.status = BoardStatus::ShippedVerified;
        let card = card_entry_from_issue(&issue, None, None, None);
        assert_eq!(card.net_hours_saved, 8.18);
        assert_eq!(card.credits_used, 100);
        issue.t_ship_ms = 0;
        let unmeasured = card_entry_from_issue(&issue, None, None, None);
        assert_eq!(unmeasured.net_hours_saved, 0.0);
        assert!(unmeasured.chinwag_cycle_time.contains("unavailable"));
    }

    #[test]
    fn option_updates_preserve_existing_ids() {
        let mut cfg = BoardConfigV1::default();
        cfg.status_option_ids
            .insert("Queued".to_string(), "old-id".to_string());
        assert!(select_options(&cfg, "Status", &["Queued"]).contains("id: \"old-id\""));
    }

    #[test]
    fn overview_contains_no_internal_codes_or_seats() {
        let readme = project_readme();
        assert!(!readme.contains("INV-"));
        assert!(!readme.contains("■"));
        assert!(readme.contains("Chinwag's planning model"));
    }

    #[test]
    fn public_project_status_update_never_leaks_private_totals() {
        let audit = json!({
            "shipped_items": 5,
            "measured_shipped_items": 4,
            "shipped_public_items": 3,
            "measured_shipped_public_items": 2,
            "net_hours_saved": 99.5,
            "public_net_hours_saved": 49.68,
            "credits_used": 350.0,
            "public_credits_used": 200.0,
        });
        let public_cfg = BoardConfigV1 {
            public_board: true,
            ..Default::default()
        };
        let public_body = format_project_status_body(&public_cfg, &audit);
        assert!(public_body.contains("3 public cards shipped"));
        assert!(public_body.contains("2 measured shipments contribute 49.68"));
        assert!(public_body.contains("200 menu-rated execution credits"));
        assert!(!public_body.contains("350"));
        assert!(!public_body.contains("99.50"));
        assert!(!public_body.contains("5 cards"));

        let private_cfg = BoardConfigV1 {
            public_board: false,
            ..Default::default()
        };
        let private_body = format_project_status_body(&private_cfg, &audit);
        assert!(private_body.contains("5 cards shipped"));
        assert!(private_body.contains("350 menu-rated execution credits"));
    }

    #[test]
    fn readback_views_verify_layout_filter_fields_and_reject_stale_grouping() {
        let make_view = |number: u64,
                         name: &str,
                         layout: &str,
                         filter: &str,
                         fields: &[&str],
                         group: &[&str],
                         vgroup: &[&str],
                         sort: &[(&str, &str)]| {
            json!({
                "number": number,
                "name": name,
                "layout": layout,
                "filter": filter,
                "groupByFields": { "nodes": group.iter().map(|n| json!({"name": n})).collect::<Vec<_>>() },
                "verticalGroupByFields": { "nodes": vgroup.iter().map(|n| json!({"name": n})).collect::<Vec<_>>() },
                "sortByFields": { "nodes": sort.iter().map(|(f, d)| json!({"direction": d, "field": {"name": f}})).collect::<Vec<_>>() },
                "configuration": { "visibleFields": { "nodes": fields.iter().map(|n| json!({"name": n})).collect::<Vec<_>>() } }
            })
        };
        let valid = vec![
            make_view(
                1,
                "01 · Kanban Execution Board",
                "BOARD_LAYOUT",
                "",
                &BOARD_FIELDS,
                &[],
                &["Status"],
                &[],
            ),
            make_view(
                2,
                "02 · Velocity & DORA Ledger",
                "TABLE_LAYOUT",
                "",
                &LEDGER_FIELDS,
                &["Status"],
                &[],
                &[("Updated", "DESC")],
            ),
            make_view(
                3,
                "03 · Work by Function",
                "TABLE_LAYOUT",
                "has:status",
                &LEDGER_FIELDS,
                &[],
                &[],
                &[],
            ),
            make_view(
                4,
                "04 · 🌱 Open Bounties (+500 Credits)",
                "BOARD_LAYOUT",
                "status:\"01 · 🌱 OPEN BOUNTY (+500 CR)\"",
                &BOUNTY_FIELDS,
                &[],
                &["Status"],
                &[],
            ),
        ];
        let recipes = validate_readback_views(&valid).expect("valid canonical views");
        assert_eq!(recipes[0]["group_by_applied_in_web_ui"], true);
        assert_eq!(recipes[0]["sort_by_applied_in_web_ui"], true);
        assert_eq!(recipes[1]["group_by_applied_in_web_ui"], false);

        let mut stale_group = valid.clone();
        stale_group[2]["groupByFields"]["nodes"] = json!([{"name": "Repository"}]);
        assert!(validate_readback_views(&stale_group).is_err());

        let mut wrong_filter = valid.clone();
        wrong_filter[3]["filter"] = json!("has:status");
        assert!(validate_readback_views(&wrong_filter).is_err());
    }

    #[test]
    fn committed_public_issues_never_reference_unlisted_or_private_tasks() {
        let issues_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.chinwag/tasks/issues");
        let mut issues = Vec::new();
        for entry in std::fs::read_dir(&issues_dir).expect("read committed issues dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) == Some("md") {
                let raw = std::fs::read_to_string(&path).expect("read issue file");
                issues.push(AtomicTaskIssue::from_markdown(&raw).expect("parse issue markdown"));
            }
        }
        assert!(!issues.is_empty());
        let public_ids: std::collections::BTreeSet<String> =
            issues.iter().map(|i| i.id.clone()).collect();
        for issue in &issues {
            assert_eq!(
                issue.visibility, "public",
                "committed public repo issue {} must have public visibility",
                issue.id
            );
            for hay in [issue.title.as_str(), issue.body.as_str()] {
                let bytes = hay.as_bytes();
                let mut idx = 0;
                while idx + 9 <= bytes.len() {
                    if &bytes[idx..idx + 5] == b"CHWG-"
                        && bytes[idx + 5..idx + 9].iter().all(u8::is_ascii_digit)
                        && (idx + 9 == bytes.len() || !bytes[idx + 9].is_ascii_digit())
                    {
                        let candidate = &hay[idx..idx + 9];
                        assert!(
                            public_ids.contains(candidate),
                            "public issue {} references non-public or unlisted task {}",
                            issue.id,
                            candidate
                        );
                        idx += 9;
                    } else {
                        idx += 1;
                    }
                }
            }
        }
    }
}
