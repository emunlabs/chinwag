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

//! Shared source for generated customer board templates and site downloads.

use super::BoardConfigV1;
use serde_json::{Value, json};

const TEMPLATE_PACK: &str = include_str!("template-pack.json");

fn template(platform: &str, cfg: &BoardConfigV1) -> Value {
    let mut pack: Value =
        serde_json::from_str(TEMPLATE_PACK).expect("compiled-in board template pack is valid JSON");
    let mut schema = pack[platform].take();
    schema["default_visibility"] = json!(if cfg.public_board {
        "public"
    } else {
        "private"
    });
    schema["public"] = json!(cfg.public_board);
    schema["public_board"] = json!(cfg.public_board);
    schema
}

/// Build the customer GitHub Projects v2 template from the same source as site downloads.
#[must_use]
pub fn build_github_project_v2_template_schema(cfg: &BoardConfigV1) -> Value {
    let mut schema = template("github", cfg);
    schema["title"] = json!(cfg.project_title);
    schema["org"] = json!(cfg.org);
    schema["private_repo"] = json!(cfg.private_repo);
    schema["public_repo"] = json!(cfg.public_repo);
    schema
}

/// Build the customer Linear template with identical field and measurement rules.
#[must_use]
pub fn build_linear_template_schema(cfg: &BoardConfigV1) -> Value {
    let mut schema = template("linear", cfg);
    schema["team_name"] = json!(cfg.project_title);
    schema
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::board::DoraTier;
    use std::path::Path;

    const SHIPPED_FILTER: &str = "status:\"05 · ✓ SHIPPED — Δ VERIFIED\"";

    #[test]
    fn customer_templates_are_private_until_explicitly_enabled() {
        let mut cfg = BoardConfigV1::default();
        for build in [
            build_github_project_v2_template_schema,
            build_linear_template_schema,
        ] {
            let private = build(&cfg);
            assert_eq!(private["schema_version"], "CHWG-NATIVE-PM-BOARDS-01.v4");
            assert_eq!(private["public"], false);
            assert_eq!(private["default_visibility"], "private");
            assert_eq!(
                private["visibility_modes"]["private_default"]["default"],
                true
            );
        }
        cfg.public_board = true;
        cfg.project_title = "Example team's board".to_string();
        cfg.org = "example".to_string();
        cfg.private_repo = Some("example/private-tasks".to_string());
        let public = build_github_project_v2_template_schema(&cfg);
        assert_eq!(public["public"], true);
        assert_eq!(public["default_visibility"], "public");
        assert_eq!(public["title"], "Example team's board");
        assert_eq!(public["private_repo"], "example/private-tasks");
        assert_eq!(
            build_linear_template_schema(&cfg)["team_name"],
            "Example team's board"
        );
    }

    #[test]
    fn requested_views_require_populated_assignees_and_hide_optional_metadata() {
        let cfg = BoardConfigV1::default();
        for schema in [
            build_github_project_v2_template_schema(&cfg),
            build_linear_template_schema(&cfg),
        ] {
            assert_eq!(
                schema["zero_empty_column_invariant"]["id"],
                "INV-BOARD-NO-BLANK-COLUMN-01"
            );
            let views = schema["views"].as_array().unwrap();
            assert_eq!(views.len(), 4);
            assert_eq!(views[0]["name"], "01 · Kanban Execution Board");
            assert_eq!(views[1]["name"], "02 · Velocity & DORA Ledger");
            assert_eq!(views[2]["name"], "03 · Work by Function");
            assert_eq!(views[3]["name"], "04 · 🌱 Open Bounties (+500 Credits)");
            assert_eq!(schema["assignee_policy"]["populate_before_surfacing"], true);
            let field_counts: Vec<usize> = views
                .iter()
                .map(|view| view["visible_fields"].as_array().unwrap().len())
                .collect();
            assert_eq!(field_counts, [10, 15, 15, 8]);
            for view in views {
                let fields = view["visible_fields"].as_array().unwrap();
                assert!(!fields.is_empty());
                for required in [
                    "Title",
                    "Assignees",
                    "Function / Team",
                    "DORA Baseline",
                    "Execution Mode",
                    "Verification Receipt",
                ] {
                    assert!(
                        fields.iter().any(|field| field == required),
                        "{required} missing from {}",
                        view["name"]
                    );
                }
                for hidden in [
                    "Linked pull requests",
                    "Sub-issues progress",
                    "Parent issue",
                    "Closed",
                    "Active Seats",
                ] {
                    assert!(
                        !fields.iter().any(|field| field == hidden),
                        "{hidden} surfaced on {}",
                        view["name"]
                    );
                }
            }
            assert!(
                !views[3]["visible_fields"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|field| field == "Net Hours Saved" || field == "Credits Used")
            );
        }
        let linear = build_linear_template_schema(&cfg);
        assert_eq!(linear["views"][0]["layout"], "board");
        assert_eq!(linear["views"][1]["layout"], "list");
        assert!(linear["custom_views"].as_array().unwrap().is_empty());
    }

    #[test]
    fn chart_sums_are_shipped_only_and_tiers_are_chinwag_estimates() {
        let cfg = BoardConfigV1::default();
        for schema in [
            build_github_project_v2_template_schema(&cfg),
            build_linear_template_schema(&cfg),
        ] {
            let charts = schema["insights_charts"].as_array().unwrap();
            assert_eq!(charts.len(), 5);
            for chart in charts {
                assert_eq!(chart["chart_kind"], "current");
                assert_ne!(chart["x_axis"], "Time");
                assert!(
                    ["COLUMN", "BAR", "STACKED_COLUMN", "STACKED_BAR"]
                        .contains(&chart["chart_type"].as_str().unwrap())
                );
                if chart["y_axis"].as_str().unwrap().starts_with("SUM(") {
                    assert_eq!(chart["filter"], SHIPPED_FILTER);
                }
            }
            let explainer = &schema["dora_baseline_explainer"];
            assert_eq!(explainer["model_owner"], "Chinwag");
            let hours: Vec<f64> = explainer["tiers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|tier| tier["active_hours"].as_f64().unwrap())
                .collect();
            assert_eq!(hours, [8.5, 27.0, 50.0, 112.0]);
            let fields = schema["custom_fields"].as_array().unwrap();
            let baseline = fields
                .iter()
                .find(|field| field["name"] == "DORA Baseline")
                .unwrap();
            let labels: Vec<&str> = baseline["options"]
                .as_array()
                .unwrap()
                .iter()
                .map(|option| option["name"].as_str().unwrap())
                .collect();
            assert_eq!(
                labels,
                [DoraTier::S, DoraTier::M, DoraTier::L, DoraTier::XL]
                    .map(DoraTier::canonical_option_label)
            );
            let function = fields
                .iter()
                .find(|field| field["name"] == "Function / Team")
                .unwrap();
            let functions: Vec<&str> = function["options"]
                .as_array()
                .unwrap()
                .iter()
                .map(|option| option["name"].as_str().unwrap())
                .collect();
            assert_eq!(
                functions,
                [
                    "Engineering",
                    "Design",
                    "Product",
                    "Security",
                    "QA & Release",
                    "Analytics",
                    "Docs"
                ]
            );
            let modes = schema["custom_fields"]
                .as_array()
                .unwrap()
                .iter()
                .find(|field| field["name"] == "Execution Mode")
                .unwrap();
            let names: Vec<&str> = modes["options"]
                .as_array()
                .unwrap()
                .iter()
                .map(|option| option["name"].as_str().unwrap())
                .collect();
            assert_eq!(
                names,
                [
                    "CI Fix · 50 Cr",
                    "Review · 50 Cr",
                    "Pair · 100 Cr",
                    "Triad · 150 Cr",
                    "Quad · 200 Cr",
                    "Open bounty"
                ]
            );
            let fanout = schema["subagent_fanout_tiers"]
                .to_string()
                .to_ascii_lowercase();
            for vendor in ["openai", "gpt", "gemini", "claude", "anthropic", "deepseek"] {
                assert!(!fanout.contains(vendor));
            }
            let speedup = schema["custom_fields"]
                .as_array()
                .unwrap()
                .iter()
                .find(|field| field["name"] == "Δ Speedup vs. DORA")
                .unwrap();
            let speedup_names: Vec<&str> = speedup["options"]
                .as_array()
                .unwrap()
                .iter()
                .map(|option| option["name"].as_str().unwrap())
                .collect();
            assert_eq!(speedup_names, crate::board::presentation::SPEEDUP_OPTIONS);
        }
        let gh = build_github_project_v2_template_schema(&cfg);
        let gh_views = gh["views"].as_array().unwrap();
        assert_eq!(gh_views[0]["vertical_group_by"], "Status");
        assert_eq!(
            gh_views[1]["ui_recipe"]["requires_github_web_ui"],
            serde_json::json!(true)
        );
        assert_eq!(
            gh_views[2]["ui_recipe"]["requires_github_web_ui"],
            serde_json::json!(true)
        );
        assert_eq!(gh_views[3]["vertical_group_by"], "Status");

        let linear = build_linear_template_schema(&cfg);
        let linear_speedup_group = linear["label_groups"]
            .as_array()
            .unwrap()
            .iter()
            .find(|group| group["name"] == "Δ Speedup vs. DORA")
            .unwrap();
        let linear_speedup_labels: Vec<&str> = linear_speedup_group["labels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|label| label["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            linear_speedup_labels,
            crate::board::presentation::SPEEDUP_OPTIONS
        );
    }

    #[test]
    fn checked_in_downloads_match_generated_default_templates() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let cfg = BoardConfigV1::default();
        for (file, generated) in [
            (
                "github-project-v2-schema.json",
                build_github_project_v2_template_schema(&cfg),
            ),
            ("linear-template.json", build_linear_template_schema(&cfg)),
        ] {
            let path = root.join(".chinwag/templates").join(file);
            let checked_in: Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            assert_eq!(
                checked_in,
                generated,
                "{} drifted from the compiled template",
                path.display()
            );
        }
    }
}
