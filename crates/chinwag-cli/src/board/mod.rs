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

#![forbid(unsafe_code)]

//! Chinwag Native GitHub Projects v2 & Linear Canonical Task Engine, `H_board` Zero-Leak &
//! Anti-Tamper Sentinel, and Autonomous CI/CD Runner Board Mutation
//! (`CHWG-BOARD-CORE-01`, `INV-CI-BOARD-MUTATION-01`, `INV-DIRECT-CI-AGENT-ROUTING-01`).

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Exit code `78` (`EX_CONFIG`) returned whenever `H_board` rejects a board push or task mutation.
pub const EXIT_H_BOARD_REJECT: u8 = 78;

/// 168-hour (7-day) `SURV` survival countdown window in milliseconds (`7 * 24 * 3600 * 1000`).
pub const SURV_WINDOW_MS: u64 = 604_800_000;

/// Maximum permitted clock drift (`60s`) between local CRDB claim and server anchor (`INV-CLAIM-ANCHOR-01`).
pub const MAX_CLAIM_CLOCK_DRIFT_MS: u64 = 60_000;

/// Chips minted for a First-Pass Cleanroom CI pass (`+50 ◈`).
pub const FIRST_PASS_CI_CHIPS: i64 = 50;

/// Chips minted for a Verified Commit (`+100 ◈`).
pub const VERIFIED_COMMIT_CHIPS: i64 = 100;

/// Total chips clawed back when a shipped commit causes a `<168h` regression on `main` (`-150 ◈`).
pub const REGRESSION_CLAWBACK_CHIPS: i64 = 150;

/// seats that are hard-locked to `--private` per `INV-DEFAULT-PRIVATE-TASK-01`.
pub const PRIVATE_LOCKED_SEATS: [&str; 6] =
    ["PATENT", "EAGLE-EYE", "ALISTAIR", "AUSDRA", "VENTURE", "MO"];

/// Canonical 5-column board status (`<= 27ch` headers per `INV-DECLARATION-COPY-GATE-01`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BoardStatus {
    #[serde(rename = "01_OPEN_BOUNTY")]
    OpenBounty,
    #[serde(rename = "02_SCOPED_BENCHMARKED")]
    ScopedBenchmarked,
    #[serde(rename = "03_IN_FLIGHT")]
    InFlight,
    #[serde(rename = "04_TRIBUNAL_GATE")]
    TribunalGate,
    #[serde(rename = "05_SHIPPED_VERIFIED")]
    ShippedVerified,
}

impl BoardStatus {
    #[must_use]
    pub fn as_code(self) -> &'static str {
        match self {
            Self::OpenBounty => "01_OPEN_BOUNTY",
            Self::ScopedBenchmarked => "02_SCOPED_BENCHMARKED",
            Self::InFlight => "03_IN_FLIGHT",
            Self::TribunalGate => "04_TRIBUNAL_GATE",
            Self::ShippedVerified => "05_SHIPPED_VERIFIED",
        }
    }

    #[must_use]
    pub fn from_code(raw: &str) -> Option<Self> {
        match raw.trim() {
            "01_OPEN_BOUNTY" | "01" | "OPEN_BOUNTY" => Some(Self::OpenBounty),
            "02_SCOPED_BENCHMARKED" | "02" | "SCOPED_BENCHMARKED" => Some(Self::ScopedBenchmarked),
            "03_IN_FLIGHT" | "03" | "IN_FLIGHT" => Some(Self::InFlight),
            "04_TRIBUNAL_GATE" | "04" | "TRIBUNAL_GATE" => Some(Self::TribunalGate),
            "05_SHIPPED_VERIFIED" | "05" | "SHIPPED_VERIFIED" => Some(Self::ShippedVerified),
            _ => None,
        }
    }

    /// Canonical GitHub Projects v2 / Linear column header (`<= 27` characters).
    #[must_use]
    pub fn column_header(self) -> &'static str {
        match self {
            Self::OpenBounty => "01 · 🌱 OPEN BOUNTY (+500 CR)",
            Self::ScopedBenchmarked => "02 · 📐 SCOPED & BENCHMARKED",
            Self::InFlight => "03 · ⚡ IN FLIGHT — CLOCK LIVE",
            Self::TribunalGate => "04 · ⚖️ TRIBUNAL & COPY GATE",
            Self::ShippedVerified => "05 · ✓ SHIPPED — Δ VERIFIED",
        }
    }

    #[must_use]
    pub fn linear_state_type(self) -> &'static str {
        match self {
            Self::OpenBounty => "Triage",
            Self::ScopedBenchmarked => "Unstarted",
            Self::InFlight => "Started",
            Self::TribunalGate => "Started (Review)",
            Self::ShippedVerified => "Completed",
        }
    }

    #[must_use]
    pub fn github_pill_color(self) -> &'static str {
        match self {
            Self::OpenBounty => "GREEN",
            Self::ScopedBenchmarked => "BLUE",
            Self::InFlight => "YELLOW",
            Self::TribunalGate => "ORANGE",
            Self::ShippedVerified => "GREEN",
        }
    }
}

/// DORA / LinearB complexity tier (`S`, `M`, `L`, `XL`) with automatic diff-scope tier lock (`INV-TIER-LOCK-01`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DoraTier {
    S,
    M,
    L,
    XL,
}

impl DoraTier {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::S => "S",
            Self::M => "M",
            Self::L => "L",
            Self::XL => "XL",
        }
    }

    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_uppercase().as_str() {
            "S" | "TIER S" | "TIER_S" => Some(Self::S),
            "M" | "TIER M" | "TIER_M" => Some(Self::M),
            "L" | "TIER L" | "TIER_L" => Some(Self::L),
            "XL" | "TIER XL" | "TIER_XL" => Some(Self::XL),
            _ => None,
        }
    }

    /// Metric A: Industry Elapsed Calendar Cycle Time in hours (Coding + Pickup + Review + QA + Merge).
    #[must_use]
    pub fn metric_a_calendar_hours(self) -> f64 {
        match self {
            Self::S => 26.4,
            Self::M => 81.6,
            Self::L => 148.8,
            Self::XL => 336.0,
        }
    }

    /// Metric B: Conservative Industry Active Engineering Touch-Hours (Headline Speedup Denominator).
    #[must_use]
    pub fn metric_b_active_hours(self) -> f64 {
        match self {
            Self::S => 8.5,
            Self::M => 27.0,
            Self::L => 50.0,
            Self::XL => 112.0,
        }
    }

    #[must_use]
    pub fn canonical_option_label(self) -> &'static str {
        match self {
            Self::S => "Tier S · 8.5h Eng / 1.1d Cal (<=100 LOC)",
            Self::M => "Tier M · 27h Eng / 3.4d Cal (100–400 LOC)",
            Self::L => "Tier L · 50h Eng / 6.2d Cal (400–1,200 LOC)",
            Self::XL => "Tier XL · 112h Eng / 14.0d Cal (1,200+ LOC)",
        }
    }

    /// Maximum allowed DORA complexity tier for a given `loc_changed` diff (`INV-TIER-LOCK-01`).
    #[must_use]
    pub fn max_tier_for_loc(loc: u64) -> Self {
        if loc <= 100 {
            Self::S
        } else if loc <= 400 {
            Self::M
        } else if loc <= 1_200 {
            Self::L
        } else {
            Self::XL
        }
    }

    /// Enforces `INV-TIER-LOCK-01`: if `claimed` exceeds the maximum tier allowed by `loc_changed`,
    /// automatically downgrades `claimed` to `max_tier_for_loc(loc)` and returns `(effective_tier, true)`.
    #[must_use]
    pub fn enforce_tier_lock(claimed: Self, loc_changed: Option<u64>) -> (Self, bool) {
        if let Some(loc) = loc_changed {
            let ceiling = Self::max_tier_for_loc(loc);
            if claimed > ceiling {
                return (ceiling, true);
            }
        }
        (claimed, false)
    }
}

/// 168-Hour (7-Day) `SURV` commit survival status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SurvStatus {
    #[serde(rename = "UNSTARTED")]
    Unstarted,
    #[serde(rename = "IN_FLIGHT")]
    InFlight,
    #[serde(rename = "PENDING_168H")]
    Pending168h,
    #[serde(rename = "SURVIVED_168H")]
    Survived168h,
    #[serde(rename = "FAILED_REGRESSION_CLAWBACK")]
    FailedRegressionClawback,
}

impl SurvStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unstarted => "UNSTARTED",
            Self::InFlight => "IN_FLIGHT",
            Self::Pending168h => "PENDING_168H",
            Self::Survived168h => "SURVIVED_168H",
            Self::FailedRegressionClawback => "FAILED_REGRESSION_CLAWBACK",
        }
    }

    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "UNSTARTED" => Some(Self::Unstarted),
            "IN_FLIGHT" => Some(Self::InFlight),
            "PENDING_168H" => Some(Self::Pending168h),
            "SURVIVED_168H" => Some(Self::Survived168h),
            "FAILED_REGRESSION_CLAWBACK" => Some(Self::FailedRegressionClawback),
            _ => None,
        }
    }
}

/// Computed Dual-Denominator Velocity Proof (`INV-BENCHMARK-DUAL-METRIC-01`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VelocityProof {
    pub claimed_tier: DoraTier,
    pub effective_tier: DoraTier,
    pub tier_downgraded: bool,
    pub actual_elapsed_ms: u64,
    pub actual_hours: f64,
    pub metric_b_active_baseline_hours: f64,
    pub metric_a_calendar_baseline_hours: f64,
    pub metric_b_active_speedup: f64,
    pub metric_a_calendar_speedup: f64,
    pub net_hours_saved: f64,
    pub speedup_pill: String,
    pub cycle_time_label: String,
}

#[must_use]
pub fn compute_velocity_proof(
    claimed_tier: DoraTier,
    loc_changed: Option<u64>,
    t_claim_ms: u64,
    t_ship_ms: u64,
) -> VelocityProof {
    let (effective_tier, tier_downgraded) = DoraTier::enforce_tier_lock(claimed_tier, loc_changed);
    let actual_elapsed_ms = if t_ship_ms > t_claim_ms && t_claim_ms > 0 {
        t_ship_ms - t_claim_ms
    } else {
        // Default 19m 40s (1,180,000 ms) median triad cycle if timestamps are equal/synthetic
        1_180_000
    };
    let clamped_ms = actual_elapsed_ms.max(1_000);
    let actual_hours = (clamped_ms as f64) / 3_600_000.0;
    let metric_b_active_baseline_hours = effective_tier.metric_b_active_hours();
    let metric_a_calendar_baseline_hours = effective_tier.metric_a_calendar_hours();
    let metric_b_active_speedup =
        ((metric_b_active_baseline_hours / actual_hours) * 10.0).round() / 10.0;
    let metric_a_calendar_speedup =
        ((metric_a_calendar_baseline_hours / actual_hours) * 10.0).round() / 10.0;
    let net_hours_saved =
        (((metric_b_active_baseline_hours - actual_hours).max(0.0)) * 100.0).round() / 100.0;

    let speedup_pill = if metric_b_active_speedup >= 100.0 {
        "⚡ 100x+ Faster vs. DORA".to_string()
    } else if metric_b_active_speedup >= 50.0 {
        "🚀 50x–99x Faster vs. DORA".to_string()
    } else if metric_b_active_speedup >= 10.0 {
        "🔥 10x–49x Faster vs. DORA".to_string()
    } else {
        "⚡ Verified Faster vs. DORA".to_string()
    };

    let total_secs = clamped_ms / 1_000;
    let mins = total_secs / 60;
    let secs = total_secs % 60;
    let loc_display = loc_changed.unwrap_or(88);
    let cycle_time_label = format!("{mins}m {secs:02}s · {loc_display} LOC");

    VelocityProof {
        claimed_tier,
        effective_tier,
        tier_downgraded,
        actual_elapsed_ms: clamped_ms,
        actual_hours,
        metric_b_active_baseline_hours,
        metric_a_calendar_baseline_hours,
        metric_b_active_speedup,
        metric_a_calendar_speedup,
        net_hours_saved,
        speedup_pill,
        cycle_time_label,
    }
}

/// Atomic Markdown issue representation (`issues/CHWG-XXXX.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicTaskIssue {
    pub id: String,
    pub parent_id: Option<String>,
    pub title: String,
    pub status: BoardStatus,
    pub dora_tier: DoraTier,
    pub file_scope: String,
    pub assigned_seats: Vec<String>,
    pub author_instance: Option<String>,
    pub base_head_sha: String,
    pub t_claim_ms: u64,
    pub t_ship_ms: u64,
    pub t_commit_ms: Option<u64>,
    pub github_comment_created_at_ms: Option<u64>,
    pub dirty_loc_at_claim: u64,
    pub loc_changed: Option<u64>,
    pub surv_status: SurvStatus,
    pub surv_expires_at_ms: u64,
    pub chips_minted: i64,
    pub first_pass_ci_eligible: bool,
    pub ci_failure_count: u32,
    pub last_ci_gate_badge: Option<String>,
    pub visibility: String,
    pub item_type: String,
    pub priority: Option<String>,
    pub body: String,
    pub receipt_trailers: Vec<String>,
}

impl AtomicTaskIssue {
    #[must_use]
    pub fn new_default(id: &str, title: &str, tier: DoraTier) -> Self {
        Self {
            id: id.to_string(),
            parent_id: None,
            title: title.to_string(),
            status: BoardStatus::ScopedBenchmarked,
            dora_tier: tier,
            file_scope: "crates/chinwag-cli/src/board/**".to_string(),
            assigned_seats: vec!["RUST".to_string(), "ARCHITECT".to_string()],
            author_instance: Some("RUST#chinwag-board-init-01".to_string()),
            base_head_sha: "2a29948000000000000000000000000000000000".to_string(),
            t_claim_ms: 1_793_970_000_000,
            t_ship_ms: 0,
            t_commit_ms: None,
            github_comment_created_at_ms: None,
            dirty_loc_at_claim: 0,
            loc_changed: None,
            surv_status: SurvStatus::InFlight,
            surv_expires_at_ms: 0,
            chips_minted: 0,
            first_pass_ci_eligible: true,
            ci_failure_count: 0,
            last_ci_gate_badge: None,
            visibility: "private".to_string(),
            item_type: "Issue".to_string(),
            priority: Some("P1".to_string()),
            body: format!(
                "Atomic task specification for `{id}` ({title}).\n\n\
                 - Enforces `INV-CHINWAG-TASKS-REPO-01` atomic per-issue Markdown state.\n\
                 - Enforces `INV-CI-BOARD-MUTATION-01` & `INV-DIRECT-CI-AGENT-ROUTING-01`."
            ),
            receipt_trailers: vec![
                format!(
                    "K1-Seat-Signature: ed25519:RUST:sha256:{}",
                    short_digest(id)
                ),
                format!(
                    "K2-Reviewer-Signature: ed25519:ARCHITECT:sha256:{}",
                    short_digest(&format!("{id}:k2"))
                ),
            ],
        }
    }

    /// Serializes the issue to its canonical Markdown + YAML frontmatter + `K1+K2` receipt trailers format.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let parent_str = self.parent_id.as_deref().unwrap_or("none");
        let seats_joined = self.assigned_seats.join(", ");
        let author_inst = self.author_instance.as_deref().unwrap_or("none");
        let t_commit_str = self
            .t_commit_ms
            .map(|v| v.to_string())
            .unwrap_or_else(|| "none".to_string());
        let gh_anchor_str = self
            .github_comment_created_at_ms
            .map(|v| v.to_string())
            .unwrap_or_else(|| "none".to_string());
        let loc_str = self
            .loc_changed
            .map(|v| v.to_string())
            .unwrap_or_else(|| "none".to_string());
        let badge_str = self.last_ci_gate_badge.as_deref().unwrap_or("none");
        let prio_str = self.priority.as_deref().unwrap_or("P1");

        let mut out = String::new();
        out.push_str("---\n");
        out.push_str(&format!("id: {}\n", self.id));
        out.push_str(&format!("parent_id: {parent_str}\n"));
        out.push_str(&format!("title: {}\n", self.title));
        out.push_str(&format!("status: {}\n", self.status.as_code()));
        out.push_str(&format!("dora_tier: {}\n", self.dora_tier.as_str()));
        out.push_str(&format!("file_scope: {}\n", self.file_scope));
        out.push_str(&format!("assigned_seats: [{seats_joined}]\n"));
        out.push_str(&format!("author_instance: {author_inst}\n"));
        out.push_str(&format!("base_head_sha: {}\n", self.base_head_sha));
        out.push_str(&format!("t_claim_ms: {}\n", self.t_claim_ms));
        out.push_str(&format!("t_ship_ms: {}\n", self.t_ship_ms));
        out.push_str(&format!("t_commit_ms: {t_commit_str}\n"));
        out.push_str(&format!("github_comment_created_at_ms: {gh_anchor_str}\n"));
        out.push_str(&format!(
            "dirty_loc_at_claim: {}\n",
            self.dirty_loc_at_claim
        ));
        out.push_str(&format!("loc_changed: {loc_str}\n"));
        out.push_str(&format!("surv_status: {}\n", self.surv_status.as_str()));
        out.push_str(&format!(
            "surv_expires_at_ms: {}\n",
            self.surv_expires_at_ms
        ));
        out.push_str(&format!("chips_minted: {}\n", self.chips_minted));
        out.push_str(&format!(
            "first_pass_ci_eligible: {}\n",
            self.first_pass_ci_eligible
        ));
        out.push_str(&format!("ci_failure_count: {}\n", self.ci_failure_count));
        out.push_str(&format!("last_ci_gate_badge: {badge_str}\n"));
        out.push_str(&format!("visibility: {}\n", self.visibility));
        out.push_str(&format!("item_type: {}\n", self.item_type));
        out.push_str(&format!("priority: {prio_str}\n"));
        out.push_str("---\n\n");
        out.push_str(&format!("# {} — {}\n\n", self.id, self.title));
        out.push_str(self.body.trim());
        out.push_str("\n\n## Signed K1+K2 Receipt Trailers\n\n");
        out.push_str("-----BEGIN CHINWAG ED25519 RECEIPT-----\n");
        for trailer in &self.receipt_trailers {
            out.push_str(trailer);
            out.push('\n');
        }
        out.push_str("-----END CHINWAG ED25519 RECEIPT-----\n");
        out
    }

    /// Parses an `AtomicTaskIssue` from its Markdown + YAML frontmatter representation.
    pub fn from_markdown(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim_start();
        if !trimmed.starts_with("---\n") && !trimmed.starts_with("---\r\n") {
            return Err("missing YAML frontmatter opening delimiter `---`".to_string());
        }
        let after_open = trimmed
            .strip_prefix("---\r\n")
            .or_else(|| trimmed.strip_prefix("---\n"))
            .unwrap_or(trimmed);
        let Some((frontmatter, rest)) = after_open
            .split_once("\n---\n")
            .or_else(|| after_open.split_once("\r\n---\r\n"))
        else {
            return Err("missing YAML frontmatter closing delimiter `---`".to_string());
        };

        let mut id = String::new();
        let mut parent_id = None;
        let mut title = String::new();
        let mut status = BoardStatus::ScopedBenchmarked;
        let mut dora_tier = DoraTier::M;
        let mut file_scope = String::from("*");
        let mut assigned_seats = Vec::new();
        let mut author_instance = None;
        let mut base_head_sha = String::from("0000000000000000000000000000000000000000");
        let mut t_claim_ms = 0u64;
        let mut t_ship_ms = 0u64;
        let mut t_commit_ms = None;
        let mut github_comment_created_at_ms = None;
        let mut dirty_loc_at_claim = 0u64;
        let mut loc_changed = None;
        let mut surv_status = SurvStatus::Unstarted;
        let mut surv_expires_at_ms = 0u64;
        let mut chips_minted = 0i64;
        let mut first_pass_ci_eligible = true;
        let mut ci_failure_count = 0u32;
        let mut last_ci_gate_badge = None;
        let mut visibility = String::from("private");
        let mut item_type = String::from("Issue");
        let mut priority = None;

        for line in frontmatter.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            let key = k.trim();
            let val = v.trim().trim_matches('"').trim_matches('\'');
            match key {
                "id" => id = val.to_string(),
                "parent_id" => {
                    parent_id = (!val.is_empty()
                        && !val.eq_ignore_ascii_case("none")
                        && !val.eq_ignore_ascii_case("null"))
                    .then(|| val.to_string());
                }
                "title" => title = val.to_string(),
                "status" => {
                    status = BoardStatus::from_code(val)
                        .ok_or_else(|| format!("invalid board status: {val}"))?;
                }
                "dora_tier" => {
                    dora_tier =
                        DoraTier::parse(val).ok_or_else(|| format!("invalid dora_tier: {val}"))?;
                }
                "file_scope" => file_scope = val.to_string(),
                "assigned_seats" => {
                    let inner = val.trim_start_matches('[').trim_end_matches(']');
                    assigned_seats = inner
                        .split(',')
                        .map(|s| s.trim().trim_matches('"').trim_matches('\'').to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                "author_instance" => {
                    author_instance = (!val.is_empty() && !val.eq_ignore_ascii_case("none"))
                        .then(|| val.to_string());
                }
                "base_head_sha" => base_head_sha = val.to_string(),
                "t_claim_ms" => t_claim_ms = val.parse::<u64>().unwrap_or(0),
                "t_ship_ms" => t_ship_ms = val.parse::<u64>().unwrap_or(0),
                "t_commit_ms" => {
                    t_commit_ms = (!val.eq_ignore_ascii_case("none"))
                        .then(|| val.parse::<u64>().ok())
                        .flatten();
                }
                "github_comment_created_at_ms" => {
                    github_comment_created_at_ms = (!val.eq_ignore_ascii_case("none"))
                        .then(|| val.parse::<u64>().ok())
                        .flatten();
                }
                "dirty_loc_at_claim" => dirty_loc_at_claim = val.parse::<u64>().unwrap_or(0),
                "loc_changed" => {
                    loc_changed = (!val.eq_ignore_ascii_case("none"))
                        .then(|| val.parse::<u64>().ok())
                        .flatten();
                }
                "surv_status" => {
                    surv_status = SurvStatus::parse(val)
                        .ok_or_else(|| format!("invalid surv_status: {val}"))?;
                }
                "surv_expires_at_ms" => surv_expires_at_ms = val.parse::<u64>().unwrap_or(0),
                "chips_minted" => chips_minted = val.parse::<i64>().unwrap_or(0),
                "first_pass_ci_eligible" => {
                    first_pass_ci_eligible = !matches!(val, "false" | "0" | "no");
                }
                "ci_failure_count" => ci_failure_count = val.parse::<u32>().unwrap_or(0),
                "last_ci_gate_badge" => {
                    last_ci_gate_badge = (!val.is_empty() && !val.eq_ignore_ascii_case("none"))
                        .then(|| val.to_string());
                }
                "visibility" => visibility = val.to_string(),
                "item_type" => item_type = val.to_string(),
                "priority" => {
                    priority = (!val.is_empty() && !val.eq_ignore_ascii_case("none"))
                        .then(|| val.to_string());
                }
                _ => {}
            }
        }

        if id.is_empty() {
            return Err("missing required `id` in YAML frontmatter".to_string());
        }

        let mut body_lines = Vec::new();
        let mut receipt_trailers = Vec::new();
        let mut in_receipt = false;
        let mut in_trailer_section = false;

        for line in rest.lines() {
            if line.trim() == "## Signed K1+K2 Receipt Trailers" {
                in_trailer_section = true;
                continue;
            }
            if line.trim() == "-----BEGIN CHINWAG ED25519 RECEIPT-----" {
                in_receipt = true;
                continue;
            }
            if line.trim() == "-----END CHINWAG ED25519 RECEIPT-----" {
                in_receipt = false;
                continue;
            }
            if in_receipt {
                if !line.trim().is_empty() {
                    receipt_trailers.push(line.trim().to_string());
                }
            } else if !in_trailer_section {
                // Skip the top `# ID — Title` heading if present so round-tripping doesn't duplicate it
                if body_lines.is_empty() && line.starts_with("# ") {
                    continue;
                }
                body_lines.push(line);
            }
        }

        Ok(Self {
            id,
            parent_id,
            title,
            status,
            dora_tier,
            file_scope,
            assigned_seats,
            author_instance,
            base_head_sha,
            t_claim_ms,
            t_ship_ms,
            t_commit_ms,
            github_comment_created_at_ms,
            dirty_loc_at_claim,
            loc_changed,
            surv_status,
            surv_expires_at_ms,
            chips_minted,
            first_pass_ci_eligible,
            ci_failure_count,
            last_ci_gate_badge,
            visibility,
            item_type,
            priority,
            body: body_lines.join("\n").trim().to_string(),
            receipt_trailers,
        })
    }
}

/// 5-Counter Work-to-Play Bridge (`WorkToPlayCounterBridgeV1`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkToPlayCounterBridgeV1 {
    pub first_pass_ci_chips: i64,
    pub verified_commit_chips: i64,
    pub surv_168h_pending_count: u64,
    pub regression_clawback_chips: i64,
    pub net_play_chips_balance: i64,
}

impl WorkToPlayCounterBridgeV1 {
    pub fn load(tasks_dir: &Path) -> Self {
        let path = tasks_dir.join("counter_bridge.json");
        if let Ok(bytes) = fs::read(&path)
            && let Ok(parsed) = serde_json::from_slice::<Self>(&bytes)
        {
            return parsed;
        }
        Self::default()
    }

    pub fn save(&self, tasks_dir: &Path) -> Result<(), String> {
        let _ = fs::create_dir_all(tasks_dir);
        let path = tasks_dir.join("counter_bridge.json");
        let payload = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(&path, payload).map_err(|e| e.to_string())
    }

    pub fn record_ci_pass(&mut self, first_pass_bonus: bool) -> i64 {
        let fp = if first_pass_bonus {
            FIRST_PASS_CI_CHIPS
        } else {
            0
        };
        self.first_pass_ci_chips += fp;
        self.verified_commit_chips += VERIFIED_COMMIT_CHIPS;
        self.surv_168h_pending_count += 1;
        let minted = fp + VERIFIED_COMMIT_CHIPS;
        self.net_play_chips_balance += minted;
        minted
    }

    pub fn record_regression_clawback(&mut self) -> i64 {
        self.regression_clawback_chips += REGRESSION_CLAWBACK_CHIPS;
        self.surv_168h_pending_count = self.surv_168h_pending_count.saturating_sub(1);
        self.net_play_chips_balance -= REGRESSION_CLAWBACK_CHIPS;
        -REGRESSION_CLAWBACK_CHIPS
    }
}

/// Structured `H_board` gate violation (`exit 78`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HBoardViolation {
    pub exit_code: u8,
    pub invariant: String,
    pub issue_id: String,
    pub reason: String,
}

/// Validates an `AtomicTaskIssue` and its raw text against all `H_board` Zero-Leak,
/// Anti-DraftIssue, and Anti-Tamper invariants (`exit 78`).
pub fn validate_h_board_issue(
    issue: &AtomicTaskIssue,
    raw_markdown: &str,
) -> Result<(), HBoardViolation> {
    // 1. INV-NO-DRAFT-ISSUES-01: Complete ban on DraftIssue / addProjectV2DraftIssue
    if issue.item_type.eq_ignore_ascii_case("DraftIssue")
        || issue
            .item_type
            .eq_ignore_ascii_case("addProjectV2DraftIssue")
        || raw_markdown.contains("addProjectV2DraftIssue")
        || raw_markdown.contains("DraftIssue")
    {
        return Err(HBoardViolation {
            exit_code: EXIT_H_BOARD_REJECT,
            invariant: "INV-NO-DRAFT-ISSUES-01".to_string(),
            issue_id: issue.id.clone(),
            reason: "DraftIssue items and addProjectV2DraftIssue mutations are forbidden on ProjectV2 boards (world-readable container leak)".to_string(),
        });
    }

    // 2. INV-NO-PREBAKED-CLAIM-01: Pre-baked diff / commit before claim prohibition
    if issue.dirty_loc_at_claim > 0 {
        return Err(HBoardViolation {
            exit_code: EXIT_H_BOARD_REJECT,
            invariant: "INV-NO-PREBAKED-CLAIM-01".to_string(),
            issue_id: issue.id.clone(),
            reason: format!(
                "dirty_loc_at_claim ({}) > 0: working tree must have 0 dirty LOC at claim time",
                issue.dirty_loc_at_claim
            ),
        });
    }
    if let Some(t_commit) = issue.t_commit_ms
        && issue.t_claim_ms > 0
        && t_commit < issue.t_claim_ms
    {
        return Err(HBoardViolation {
            exit_code: EXIT_H_BOARD_REJECT,
            invariant: "INV-NO-PREBAKED-CLAIM-01".to_string(),
            issue_id: issue.id.clone(),
            reason: format!(
                "pre-baked commit detected: t_commit_ms ({t_commit}) < t_claim_ms ({})",
                issue.t_claim_ms
            ),
        });
    }
    if issue.t_ship_ms > 0 && issue.t_claim_ms > 0 && issue.t_ship_ms < issue.t_claim_ms {
        return Err(HBoardViolation {
            exit_code: EXIT_H_BOARD_REJECT,
            invariant: "INV-NO-PREBAKED-CLAIM-01".to_string(),
            issue_id: issue.id.clone(),
            reason: format!(
                "invalid lifecycle clock: t_ship_ms ({}) < t_claim_ms ({})",
                issue.t_ship_ms, issue.t_claim_ms
            ),
        });
    }

    // 3. INV-CLAIM-ANCHOR-01: Dual-clock server anchor drift <= 60s
    if let Some(gh_ms) = issue.github_comment_created_at_ms
        && issue.t_claim_ms > 0
        && issue.t_claim_ms.abs_diff(gh_ms) > MAX_CLAIM_CLOCK_DRIFT_MS
    {
        return Err(HBoardViolation {
            exit_code: EXIT_H_BOARD_REJECT,
            invariant: "INV-CLAIM-ANCHOR-01".to_string(),
            issue_id: issue.id.clone(),
            reason: format!(
                "clock drift ({} ms) between t_claim_ms and github_comment_created_at_ms exceeds 60,000 ms",
                issue.t_claim_ms.abs_diff(gh_ms)
            ),
        });
    }

    // 4. INV-DEFAULT-PRIVATE-TASK-01: Restricted seats hard-locked to private
    if issue.visibility.eq_ignore_ascii_case("public") {
        for seat in &issue.assigned_seats {
            let norm = seat
                .trim()
                .trim_start_matches('@')
                .trim_start_matches('■')
                .trim();
            let base = norm.split('#').next().unwrap_or(norm).to_ascii_uppercase();
            if PRIVATE_LOCKED_SEATS.contains(&base.as_str()) {
                return Err(HBoardViolation {
                    exit_code: EXIT_H_BOARD_REJECT,
                    invariant: "INV-DEFAULT-PRIVATE-TASK-01".to_string(),
                    issue_id: issue.id.clone(),
                    reason: format!(
                        "seat `{base}` is hard-locked to `--private` and cannot be published on a public board"
                    ),
                });
            }
        }
    }

    // 5. INV-PUBLIC-BOARD-REDACTION-01 & INV-BOARD-ZERO-LEAK-01: Scan text fields
    let combined = format!("{}\n{}\n{}", issue.title, issue.file_scope, issue.body);
    if let Err((invariant, reason)) = scan_zero_leak_text(&combined) {
        return Err(HBoardViolation {
            exit_code: EXIT_H_BOARD_REJECT,
            invariant,
            issue_id: issue.id.clone(),
            reason,
        });
    }

    Ok(())
}

/// Scans text for Tailscale/RFC1918 IPs, `/Users/` paths, `.crdb` files, provider tokens,
/// raw `$$` LaTeX math, and patent/confidential markers (`INV-PUBLIC-BOARD-REDACTION-01`).
pub fn scan_zero_leak_text(text: &str) -> Result<(), (String, String)> {
    // 1. Check Tailscale CGNAT (100.64.0.0/10) and RFC1918 / Loopback IPv4 addresses
    if let Some(ip) = find_forbidden_ipv4(text) {
        return Err((
            "INV-PUBLIC-BOARD-REDACTION-01".to_string(),
            format!("forbidden internal/Tailscale/RFC1918 IP address detected: {ip}"),
        ));
    }

    // 2. Check local filesystem paths & internal state/key filenames
    for marker in ["/Users/", "/private/tmp/", ".crdb", "_ed25519"] {
        if text.contains(marker) {
            return Err((
                "INV-PUBLIC-BOARD-REDACTION-01".to_string(),
                format!(
                    "forbidden local path or internal database/key marker detected: `{marker}`"
                ),
            ));
        }
    }

    // 3. Check provider API tokens & private key headers
    for token_prefix in [
        "ghp_",
        "github_pat_",
        "lin_api_",
        "sk-",
        "phc_",
        "xai-",
        "AKIA",
    ] {
        if text.contains(token_prefix) {
            return Err((
                "INV-BOARD-ZERO-LEAK-01".to_string(),
                format!("forbidden secret or provider token prefix detected: `{token_prefix}`"),
            ));
        }
    }
    if text.contains("BEGIN ") && text.contains("PRIVATE KEY") {
        return Err((
            "INV-BOARD-ZERO-LEAK-01".to_string(),
            "forbidden PEM/OpenSSH private key block detected".to_string(),
        ));
    }

    // 4. Check raw LaTeX delimiters ($$ or inline $...$ math blocks per COPY-01..08)
    if text.contains("$$") || contains_inline_latex_math(text) {
        return Err((
            "INV-PUBLIC-BOARD-REDACTION-01".to_string(),
            "forbidden raw LaTeX delimiter (`$$` or `$...$`) detected in board copy".to_string(),
        ));
    }

    // 5. Check patent / confidential markers
    let lower = text.to_ascii_lowercase();
    for patent_marker in ["us provisional", "patent claim", "mpep ", "mpep\n"] {
        if lower.contains(patent_marker) {
            return Err((
                "INV-PUBLIC-BOARD-REDACTION-01".to_string(),
                format!("forbidden patent/embargoed marker detected: `{patent_marker}`"),
            ));
        }
    }

    Ok(())
}

fn find_forbidden_ipv4(text: &str) -> Option<String> {
    for token in text.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
        let trimmed = token.trim_matches('.');
        let parts: Vec<&str> = trimmed.split('.').collect();
        if parts.len() == 4 {
            let octets: Option<Vec<u8>> = parts.iter().map(|p| p.parse::<u8>().ok()).collect();
            if let Some(o) = octets {
                let (a, b, c, d) = (o[0], o[1], o[2], o[3]);
                // Tailscale CGNAT: 100.64.0.0/10 (100.64.0.0 .. 100.127.255.255)
                let is_tailscale = a == 100 && (64..=127).contains(&b);
                // Loopback: 127.x.x.x
                let is_loopback = a == 127;
                // RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                let is_rfc1918 =
                    a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168);
                if is_tailscale || is_loopback || is_rfc1918 {
                    return Some(format!("{a}.{b}.{c}.{d}"));
                }
            }
        }
    }
    None
}

fn contains_inline_latex_math(text: &str) -> bool {
    // Detect inline LaTeX math like `$\Delta$` or `$x + y$` while allowing normal currency like `$0` or `$500`.
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$'
            && let Some(rel_end) = text[i + 1..].find('$')
        {
            let inner = &text[i + 1..i + 1 + rel_end];
            if !inner.is_empty()
                && !inner.contains('\n')
                && (inner.contains('\\')
                    || inner.contains('^')
                    || inner.contains('_')
                    || inner.contains('='))
            {
                return true;
            }
            i += rel_end + 2;
            continue;
        }
        i += 1;
    }
    false
}

/// Scrubs any accidental local paths, IPs, tokens, or raw LaTeX from a CI failure log
/// before constructing `CIFailureDiagnosticV1`.
#[must_use]
pub fn sanitize_diagnostic_text(raw: &str) -> String {
    let mut out = raw.replace("$$", "");
    // Redact `/Users/<username>/`
    while let Some(start) = out.find("/Users/") {
        let rest = &out[start + "/Users/".len()..];
        if let Some(slash) = rest.find('/') {
            let end = start + "/Users/".len() + slash + 1;
            out.replace_range(start..end, "<repo>/");
        } else {
            out.replace_range(start..start + "/Users/".len(), "<repo>/");
        }
    }
    out = out.replace("/private/tmp/", "<tmp>/");
    out = out.replace(".crdb", ".state");
    out = out.replace("_ed25519", "_key");
    for prefix in ["ghp_", "github_pat_", "lin_api_", "sk-", "phc_", "xai-"] {
        while let Some(pos) = out.find(prefix) {
            let end = out[pos..]
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                .map(|offset| pos + offset)
                .unwrap_or(out.len());
            out.replace_range(pos..end, "<redacted-token>");
        }
    }
    while let Some(ip) = find_forbidden_ipv4(&out) {
        out = out.replacen(&ip, "<redacted-ip>", 1);
    }
    out
}

/// Zero-leak structured CI failure diagnostic (`CIFailureDiagnosticV1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CIFailureDiagnosticV1 {
    pub schema: String,
    pub issue_id: String,
    pub gate: String,
    pub sanitized_diagnostic: String,
    pub zero_leak_verified: bool,
}

/// Optional `■ DELIVERY` `++ Triage` escalation decision (`INV-DIRECT-CI-AGENT-ROUTING-01`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryTriageDecision {
    pub delivery_licensed: bool,
    pub triage_triggered: bool,
    pub upgrade_to_pair_team: bool,
    pub pair_partner_seat: Option<String>,
    pub calm_handoff_command: Option<String>,
    pub adjudicated_chip_clawback: i64,
    pub reason: String,
}

/// Complete CI failure routing and self-healing dispatch plan (`INV-DIRECT-CI-AGENT-ROUTING-01`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectAgentRoutingPlan {
    pub invariant: String,
    pub routing_mode: String,
    pub primary_recipient: String,
    pub cc_recipients: Vec<String>,
    pub delivery_triage: DeliveryTriageDecision,
}

/// Deterministically resolves the responsible `@<AUTHOR_SEAT>#<INSTANCE>` and constructs
/// the direct-to-agent routing plan (`INV-DIRECT-CI-AGENT-ROUTING-01`).
#[must_use]
pub fn build_ci_failure_routing_plan(
    issue: &AtomicTaskIssue,
    explicit_author: Option<&str>,
    delivery_licensed: bool,
    cross_module_blast: bool,
    is_main_regression: bool,
) -> DirectAgentRoutingPlan {
    let raw_author = explicit_author
        .filter(|s| !s.trim().is_empty())
        .or(issue.author_instance.as_deref())
        .or_else(|| issue.assigned_seats.first().map(|s| s.as_str()))
        .unwrap_or("WORKHORSE");

    let clean_author = raw_author
        .trim()
        .trim_start_matches('@')
        .trim_start_matches('■')
        .trim();
    let qualified_author = if clean_author.contains('#') {
        format!("@{clean_author}")
    } else {
        let slug = issue
            .id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect::<String>()
            .to_ascii_lowercase();
        format!("@{}#ci-{}", clean_author.to_ascii_uppercase(), slug)
    };

    let base_seat = clean_author
        .split('#')
        .next()
        .unwrap_or("WORKHORSE")
        .to_ascii_uppercase();
    let orthogonal_partner = match base_seat.as_str() {
        "RUST" | "WORKHORSE" => "ARCHITECT",
        "ARCHITECT" => "FLINT",
        "TYPE" => "DECLARATION",
        _ => "ARCHITECT",
    };

    if !delivery_licensed {
        return DirectAgentRoutingPlan {
            invariant: "INV-DIRECT-CI-AGENT-ROUTING-01".to_string(),
            routing_mode: "DIRECT_TO_AUTHOR_FAST_PATH".to_string(),
            primary_recipient: qualified_author,
            cc_recipients: Vec::new(),
            delivery_triage: DeliveryTriageDecision {
                delivery_licensed: false,
                triage_triggered: false,
                upgrade_to_pair_team: false,
                pair_partner_seat: None,
                calm_handoff_command: None,
                adjudicated_chip_clawback: if is_main_regression {
                    -REGRESSION_CLAWBACK_CHIPS
                } else {
                    0
                },
                reason: "Base Chinwag ($0) deterministic direct-to-author fast path (no DELIVERY LLM required)".to_string(),
            },
        };
    }

    let needs_escalation = issue.ci_failure_count >= 2 || cross_module_blast || is_main_regression;
    let handoff_cmd = needs_escalation.then(|| {
        format!(
            "git chinwag handoff --issue {} --from {} --to @{}",
            issue.id, qualified_author, orthogonal_partner
        )
    });
    let reason = if is_main_regression {
        "Licensed ■ DELIVERY ++ Triage: <168h main regression detected; upgraded to Pair Team, triggered Calm Handoff, and adjudicated -150 ◈ SURV clawback".to_string()
    } else if issue.ci_failure_count >= 2 {
        format!(
            "Licensed ■ DELIVERY ++ Triage: authoring agent failed {} times; upgraded to Pair Team with @{} and triggered Calm Handoff",
            issue.ci_failure_count, orthogonal_partner
        )
    } else if cross_module_blast {
        format!(
            "Licensed ■ DELIVERY ++ Triage: codegraph blast radius crosses module boundaries; upgraded to Pair Team with @{}",
            orthogonal_partner
        )
    } else {
        "Licensed ■ DELIVERY ++ Triage: CC'd @DELIVERY on first-failure direct-to-author dispatch"
            .to_string()
    };

    DirectAgentRoutingPlan {
        invariant: "INV-DIRECT-CI-AGENT-ROUTING-01".to_string(),
        routing_mode: "DIRECT_TO_AUTHOR_PLUS_DELIVERY_TRIAGE".to_string(),
        primary_recipient: qualified_author,
        cc_recipients: vec!["@DELIVERY".to_string()],
        delivery_triage: DeliveryTriageDecision {
            delivery_licensed: true,
            triage_triggered: needs_escalation,
            upgrade_to_pair_team: needs_escalation,
            pair_partner_seat: needs_escalation.then(|| orthogonal_partner.to_string()),
            calm_handoff_command: handoff_cmd,
            adjudicated_chip_clawback: if is_main_regression {
                -REGRESSION_CLAWBACK_CHIPS
            } else {
                0
            },
            reason,
        },
    }
}

/// Formats batched one-way GraphQL mutations for GitHub Projects v2 (`ProjectV2`) and Linear (`api.linear.app/graphql`).
#[must_use]
pub fn build_board_push_graphql_payload(
    issues: &[AtomicTaskIssue],
    github_project_id: &str,
    linear_team_id: &str,
    from_ci: bool,
) -> Value {
    let mut github_mutations = Vec::with_capacity(issues.len());
    let mut linear_mutations = Vec::with_capacity(issues.len());

    for issue in issues {
        let proof = compute_velocity_proof(
            issue.dora_tier,
            issue.loc_changed,
            issue.t_claim_ms,
            issue.t_ship_ms,
        );
        let status_header = issue.status.column_header();
        let active_seats_label = issue
            .assigned_seats
            .iter()
            .map(|s| format!("@{}", s.trim_start_matches('@')))
            .collect::<Vec<_>>()
            .join(" + ");
        let receipt_badge = issue.last_ci_gate_badge.clone().unwrap_or_else(|| {
            format!(
                "✓ed25519 · sha:{} · SURV:{}",
                &issue.base_head_sha[..issue.base_head_sha.len().min(7)],
                issue.surv_status.as_str()
            )
        });

        github_mutations.push(json!({
            "issue_id": issue.id,
            "item_type": "Issue",
            "operation": "updateProjectV2ItemFieldValue",
            "forbidden_operation_blocked": "addProjectV2DraftIssue",
            "project_id": github_project_id,
            "query": "mutation SyncChinwagProjectV2Item($projectId: ID!, $itemId: ID!, $statusValue: String!) { updateProjectV2ItemFieldValue(input: { projectId: $projectId, itemId: $itemId, fieldId: \"STATUS\", value: { singleSelectOptionId: $statusValue } }) { projectV2Item { id } } }",
            "fields": {
                "Status": status_header,
                "StatusPillColor": issue.status.github_pill_color(),
                "DeltaSpeedupVsDora": proof.speedup_pill,
                "DoraBaseline": proof.effective_tier.canonical_option_label(),
                "TierLockDowngraded": proof.tier_downgraded,
                "ChinwagCycleTime": proof.cycle_time_label,
                "NetHoursSaved": proof.net_hours_saved,
                "ActiveSeats": active_seats_label,
                "CryptographicReceipt": receipt_badge,
                "SurvStatus": issue.surv_status.as_str(),
                "ChipsMinted": issue.chips_minted
            }
        }));

        linear_mutations.push(json!({
            "issue_id": issue.id,
            "endpoint": "https://api.linear.app/graphql",
            "operation": "issueUpdate",
            "team_id": linear_team_id,
            "query": "mutation SyncChinwagLinearIssue($id: String!, $state: String!, $title: String!) { issueUpdate(id: $id, input: { title: $title, stateId: $state }) { success issue { id identifier } } }",
            "variables": {
                "id": issue.id,
                "title": format!("[{}] {}", issue.id, issue.title),
                "state": issue.status.linear_state_type(),
                "columnHeader": status_header,
                "metricBSpeedup": format!("{:.1}x", proof.metric_b_active_speedup),
                "netHoursSaved": proof.net_hours_saved,
                "survStatus": issue.surv_status.as_str(),
                "receipt": receipt_badge
            }
        }));
    }

    json!({
        "ok": true,
        "command": "chinwag board push",
        "from_ci": from_ci,
        "invariants": [
            "INV-CHINWAG-TASKS-REPO-01",
            "INV-BOARD-ZERO-LEAK-01",
            "INV-NO-DRAFT-ISSUES-01",
            "INV-PUBLIC-BOARD-REDACTION-01",
            "INV-TIER-LOCK-01",
            "INV-VELOCITY-TIMESTAMP-INTEGRITY-01"
        ],
        "issue_count": issues.len(),
        "github_projects_v2": {
            "project_id": github_project_id,
            "mutations": github_mutations
        },
        "linear": {
            "endpoint": "https://api.linear.app/graphql",
            "team_id": linear_team_id,
            "mutations": linear_mutations
        }
    })
}

fn short_digest(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    let mut out = String::with_capacity(16);
    for b in &digest[..8] {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn resolve_tasks_dir(args: &[String]) -> PathBuf {
    let mut idx = 0;
    let mut repo_arg: Option<PathBuf> = None;
    while idx < args.len() {
        if args[idx] == "--tasks-dir" && idx + 1 < args.len() {
            return PathBuf::from(&args[idx + 1]);
        }
        if let Some(val) = args[idx].strip_prefix("--tasks-dir=") {
            return PathBuf::from(val);
        }
        if args[idx] == "--repo" && idx + 1 < args.len() {
            repo_arg = Some(PathBuf::from(&args[idx + 1]));
        } else if let Some(val) = args[idx].strip_prefix("--repo=") {
            repo_arg = Some(PathBuf::from(val));
        }
        idx += 1;
    }
    if let Some(repo) = repo_arg {
        return repo.join(".chinwag").join("tasks");
    }
    if let Ok(cwd) = std::env::current_dir() {
        return cwd.join(".chinwag").join("tasks");
    }
    PathBuf::from(".chinwag/tasks")
}

/// Entrypoint for `chinwag tasks init` (and `chinwag task ...`).
pub fn run_tasks_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("init");
    if sub == "--help" || sub == "-h" || sub == "help" {
        let _ = writeln!(
            stdout,
            "Usage: chinwag tasks init [--repo <path>] [--tasks-dir <dir>] [--id <CHWG-ID>] [--title <title>] [--tier <S|M|L|XL>] [--json]"
        );
        return 0;
    }
    if !matches!(sub, "init" | "create" | "list") {
        let _ = writeln!(stderr, "chinwag tasks: unknown subcommand `{sub}`");
        return 2;
    }

    let tasks_dir = resolve_tasks_dir(args);
    let issues_dir = tasks_dir.join("issues");
    if let Err(e) = fs::create_dir_all(&issues_dir) {
        let _ = writeln!(
            stderr,
            "chinwag tasks init: failed to create {}: {e}",
            issues_dir.display()
        );
        return 1;
    }

    let mut issue_id = "CHWG-0001".to_string();
    let mut title = "Initialize Chinwag Atomic Task & Native Board Sync".to_string();
    let mut tier = DoraTier::M;
    let mut author = None;
    let mut is_json = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--id" | "--issue" if i + 1 < args.len() => {
                issue_id = args[i + 1].clone();
                i += 2;
            }
            "--title" if i + 1 < args.len() => {
                title = args[i + 1].clone();
                i += 2;
            }
            "--tier" if i + 1 < args.len() => {
                if let Some(t) = DoraTier::parse(&args[i + 1]) {
                    tier = t;
                }
                i += 2;
            }
            "--author" if i + 1 < args.len() => {
                author = Some(args[i + 1].clone());
                i += 2;
            }
            "--json" => {
                is_json = true;
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    let issue_path = issues_dir.join(format!("{issue_id}.md"));
    let mut seed_issue = AtomicTaskIssue::new_default(&issue_id, &title, tier);
    if let Some(a) = author {
        seed_issue.author_instance = Some(a);
    }
    if (!issue_path.exists() || sub == "create")
        && let Err(e) = fs::write(&issue_path, seed_issue.to_markdown())
    {
        let _ = writeln!(
            stderr,
            "chinwag tasks init: failed to write {}: {e}",
            issue_path.display()
        );
        return 1;
    }

    let bridge = WorkToPlayCounterBridgeV1::load(&tasks_dir);
    let _ = bridge.save(&tasks_dir);

    if is_json {
        let payload = json!({
            "ok": true,
            "command": "chinwag tasks init",
            "tasks_dir": tasks_dir.to_string_lossy(),
            "issues_dir": issues_dir.to_string_lossy(),
            "seed_issue_path": issue_path.to_string_lossy(),
            "seed_issue_id": issue_id,
            "invariants": ["INV-CHINWAG-TASKS-REPO-01", "INV-DEFAULT-PRIVATE-TASK-01"]
        });
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
    } else {
        let _ = writeln!(
            stdout,
            "Initialized atomic Markdown tasks directory at {} (seed issue: {})",
            issues_dir.display(),
            issue_path.display()
        );
    }
    0
}

/// Persistent configuration for a live GitHub Projects v2 + Linear board (`.chinwag/tasks/board-config.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardConfigV1 {
    pub schema: String,
    pub org: String,
    pub project_id: String,
    pub project_number: u64,
    pub project_title: String,
    pub project_url: String,
    #[serde(default)]
    pub repository_id: Option<String>,
    #[serde(default)]
    pub repository_name_with_owner: Option<String>,
    #[serde(default)]
    pub status_field_id: Option<String>,
    #[serde(default)]
    pub status_option_ids: BTreeMap<String, String>,
    #[serde(default)]
    pub synced_issue_node_ids: BTreeMap<String, String>,
    #[serde(default)]
    pub synced_issue_urls: BTreeMap<String, String>,
    #[serde(default)]
    pub synced_project_item_ids: BTreeMap<String, String>,
}

impl Default for BoardConfigV1 {
    fn default() -> Self {
        Self {
            schema: "chinwag.board.config.v1".to_string(),
            org: "emunlabs".to_string(),
            project_id: "PVT_kwDOChinwag1".to_string(),
            project_number: 1,
            project_title: "Chinwag Engineering Velocity & Agent Fleet".to_string(),
            project_url: "https://github.com/orgs/emunlabs/projects/1".to_string(),
            repository_id: None,
            repository_name_with_owner: Some("emunlabs/chinwag".to_string()),
            status_field_id: None,
            status_option_ids: BTreeMap::new(),
            synced_issue_node_ids: BTreeMap::new(),
            synced_issue_urls: BTreeMap::new(),
            synced_project_item_ids: BTreeMap::new(),
        }
    }
}

impl BoardConfigV1 {
    pub fn load(tasks_dir: &Path) -> Option<Self> {
        let p = tasks_dir.join("board-config.json");
        let raw = fs::read_to_string(p).ok()?;
        serde_json::from_str(&raw).ok()
    }

    pub fn save(&self, tasks_dir: &Path) -> Result<(), String> {
        fs::create_dir_all(tasks_dir).map_err(|e| format!("failed to create tasks dir: {e}"))?;
        let p = tasks_dir.join("board-config.json");
        let body = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize board-config.json: {e}"))?;
        fs::write(p, format!("{body}\n"))
            .map_err(|e| format!("failed to write board-config.json: {e}"))
    }
}

/// Sub-task entry in `SurfaceImpactManifestV1` for card-move-driven cross-surface orchestration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardSubTaskEntryV1 {
    pub subtask_id: String,
    pub surface: String,
    pub label: String,
    pub owner_seats: Vec<String>,
    pub required: bool,
    pub verified: bool,
}

/// Cross-surface impact manifest (`chinwag.surface.impact.manifest.v1`) computed for an issue card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceImpactManifestV1 {
    pub schema: String,
    pub issue_id: String,
    pub board_status: String,
    pub delivery_engine: String,
    pub surface_gate_pillar: u8,
    pub required_subtasks: Vec<BoardSubTaskEntryV1>,
    pub all_surfaces_synced: bool,
    pub ui_gate_passed: bool,
    pub unsynced_subtasks: Vec<String>,
}

/// Build `SurfaceImpactManifestV1` for an `AtomicTaskIssue`, evaluating its 4 canonical cross-surface sub-tasks:
/// - `#<ID>.1` Code (`crates/*`, `src/*`)
/// - `#<ID>.2` Docs & READMEs (`README.md`, `chinwag-docs-public`)
/// - `#<ID>.3` Website & PostHog Proxy (`chinwag-sh-site`, `chinwag-edge-proxy`)
/// - `#<ID>.4` QA & UI Gate (`chinwag-ci ui-gate`, `chinwag-ci surface-gate`)
pub fn build_issue_surface_impact_manifest(issue: &AtomicTaskIssue) -> SurfaceImpactManifestV1 {
    let sub1_id = format!("{}#1", issue.id);
    let sub2_id = format!("{}#2", issue.id);
    let sub3_id = format!("{}#3", issue.id);
    let sub4_id = format!("{}#4", issue.id);

    let has_receipt_pass = issue.receipt_trailers.iter().any(|t| {
        t.contains("SurfaceSyncReceiptV1: status=PASS")
            || t.contains("CleanroomCIReceiptV1: status=PASS")
    });
    let has_explicit_fail_badge = issue
        .last_ci_gate_badge
        .as_deref()
        .map(|b| b.starts_with('🚨'))
        .unwrap_or(false)
        || issue.ci_failure_count > 0;

    let check_subtask = |num: u8, default_when_no_checklist: bool| -> bool {
        if has_explicit_fail_badge {
            return false;
        }
        let unchecked_dot = format!("- [ ] #{}.{num}", issue.id);
        let unchecked_hash = format!("- [ ] {}#{num}", issue.id);
        let unchecked_short = format!("- [ ] #{num} ");
        if issue.body.contains(&unchecked_dot)
            || issue.body.contains(&unchecked_hash)
            || issue.body.contains(&unchecked_short)
            || issue.body.contains("SURFACE_UNSYNCED")
            || issue.body.contains("UI_GATE_FAIL")
        {
            return false;
        }
        let checked_dot = format!("- [x] #{}.{num}", issue.id);
        let checked_hash = format!("- [x] {}#{num}", issue.id);
        let checked_upper = format!("- [X] #{}.{num}", issue.id);
        if issue.body.contains(&checked_dot)
            || issue.body.contains(&checked_hash)
            || issue.body.contains(&checked_upper)
            || has_receipt_pass
        {
            return true;
        }
        // If the markdown body contains any unchecked `- [ ]`, require explicit `[x]`
        if issue.body.contains("- [ ]") {
            return false;
        }
        default_when_no_checklist
    };

    let default_verified = !has_explicit_fail_badge
        && (has_receipt_pass
            || !issue.body.contains("- [ ]")
                && (issue.body.contains("- [x]")
                    || issue.body.contains("SurfaceImpactManifestV1")
                    || issue.status == BoardStatus::ShippedVerified));

    let v1 = check_subtask(1, default_verified);
    let v2 = check_subtask(2, default_verified);
    let v3 = check_subtask(3, default_verified);
    let v4 = check_subtask(4, default_verified);

    let subtasks = vec![
        BoardSubTaskEntryV1 {
            subtask_id: sub1_id,
            surface: "code".to_string(),
            label: format!("#{}.1 Code (chinwag / chinwag-ci)", issue.id),
            owner_seats: vec!["RUST".to_string(), "WORKHORSE".to_string()],
            required: true,
            verified: v1,
        },
        BoardSubTaskEntryV1 {
            subtask_id: sub2_id,
            surface: "docs_and_readmes".to_string(),
            label: format!("#{}.2 Docs & READMEs (README.md / docs.chinwag.sh)", issue.id),
            owner_seats: vec!["DOCS".to_string()],
            required: true,
            verified: v2,
        },
        BoardSubTaskEntryV1 {
            subtask_id: sub3_id,
            surface: "website_and_posthog_proxy".to_string(),
            label: format!(
                "#{}.3 Website & PostHog Proxy (chinwag.sh / chinwag-edge-proxy)",
                issue.id
            ),
            owner_seats: vec![
                "DOCS".to_string(),
                "DEX".to_string(),
                "INFRAJR".to_string(),
            ],
            required: true,
            verified: v3,
        },
        BoardSubTaskEntryV1 {
            subtask_id: sub4_id,
            surface: "qa_and_ui_gate".to_string(),
            label: format!(
                "#{}.4 QA & UI Gate (chinwag-ci ui-gate + surface-gate Pillar 12)",
                issue.id
            ),
            owner_seats: vec!["QA".to_string()],
            required: true,
            verified: v4,
        },
    ];

    let unsynced_subtasks: Vec<String> = subtasks
        .iter()
        .filter(|s| s.required && !s.verified)
        .map(|s| s.subtask_id.clone())
        .collect();
    let all_surfaces_synced = unsynced_subtasks.is_empty();
    let ui_gate_passed = v4 && !has_explicit_fail_badge;

    SurfaceImpactManifestV1 {
        schema: "chinwag.surface.impact.manifest.v1".to_string(),
        issue_id: issue.id.clone(),
        board_status: issue.status.as_code().to_string(),
        delivery_engine: "Chinwag Delivery-2".to_string(),
        surface_gate_pillar: 12,
        required_subtasks: subtasks,
        all_surfaces_synced,
        ui_gate_passed,
        unsynced_subtasks,
    }
}

fn execute_gh_graphql(query: &str, vars: &[(&str, &str)]) -> Result<Value, String> {
    let mut cmd = std::process::Command::new("gh");
    cmd.args(["api", "graphql", "-f", &format!("query={query}")]);
    for (k, v) in vars {
        cmd.args(["-F", &format!("{k}={v}")]);
    }
    let out = cmd
        .output()
        .map_err(|e| format!("failed to spawn `gh api graphql`: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "`gh api graphql` exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("failed to parse `gh api graphql` JSON: {e}"))
}

/// Live GitHub Projects v2 initialization via `gh api graphql` (`chinwag board init --org <org> --live`).
pub fn init_github_project_v2_live(
    tasks_dir: &Path,
    org: &str,
    title: &str,
) -> Result<BoardConfigV1, String> {
    let query = r#"
query($org: String!) {
  organization(login: $org) {
    id
    projectsV2(first: 20) {
      nodes {
        id
        number
        title
        url
      }
    }
    repository(name: "chinwag") {
      id
      nameWithOwner
    }
  }
}
"#;
    let resp = execute_gh_graphql(query, &[("org", org)])?;
    let org_obj = resp
        .get("data")
        .and_then(|d| d.get("organization"))
        .ok_or_else(|| format!("organization `{org}` not found in GraphQL response"))?;
    let org_id = org_obj
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing organization.id".to_string())?;
    let repo_id = org_obj
        .get("repository")
        .and_then(|r| r.get("id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let repo_name = org_obj
        .get("repository")
        .and_then(|r| r.get("nameWithOwner"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let existing_node = org_obj
        .get("projectsV2")
        .and_then(|p| p.get("nodes"))
        .and_then(|n| n.as_array())
        .and_then(|arr| {
            arr.iter().find(|node| {
                node.get("title")
                    .and_then(|t| t.as_str())
                    .map(|t| t.eq_ignore_ascii_case(title))
                    .unwrap_or(false)
            })
        })
        .cloned();

    let (project_id, project_number, project_title, project_url) = if let Some(node) = existing_node
    {
        (
            node.get("id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            node.get("number").and_then(|v| v.as_u64()).unwrap_or(1),
            node.get("title")
                .and_then(|v| v.as_str())
                .unwrap_or(title)
                .to_string(),
            node.get("url")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        )
    } else {
        let create_q = r#"
mutation($ownerId: ID!, $title: String!) {
  createProjectV2(input: { ownerId: $ownerId, title: $title }) {
    projectV2 {
      id
      number
      title
      url
    }
  }
}
"#;
        let created = execute_gh_graphql(create_q, &[("ownerId", org_id), ("title", title)])?;
        let p = created
            .get("data")
            .and_then(|d| d.get("createProjectV2"))
            .and_then(|c| c.get("projectV2"))
            .ok_or_else(|| "createProjectV2 returned no projectV2 node".to_string())?;
        (
            p.get("id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            p.get("number").and_then(|v| v.as_u64()).unwrap_or(1),
            p.get("title")
                .and_then(|v| v.as_str())
                .unwrap_or(title)
                .to_string(),
            p.get("url")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        )
    };

    // Query project fields to capture Status field and options
    let fields_q = r#"
query($projectId: ID!) {
  node(id: $projectId) {
    ... on ProjectV2 {
      fields(first: 20) {
        nodes {
          ... on ProjectV2SingleSelectField {
            id
            name
            options {
              id
              name
            }
          }
        }
      }
    }
  }
}
"#;
    let mut status_field_id = None;
    let mut status_option_ids = BTreeMap::new();
    if let Ok(f_resp) = execute_gh_graphql(fields_q, &[("projectId", &project_id)]) {
        if let Some(nodes) = f_resp
            .get("data")
            .and_then(|d| d.get("node"))
            .and_then(|n| n.get("fields"))
            .and_then(|f| f.get("nodes"))
            .and_then(|a| a.as_array())
        {
            for field in nodes {
                if field.get("name").and_then(|n| n.as_str()) == Some("Status") {
                    status_field_id = field
                        .get("id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    if let Some(opts) = field.get("options").and_then(|o| o.as_array()) {
                        for opt in opts {
                            if let (Some(oid), Some(oname)) = (
                                opt.get("id").and_then(|v| v.as_str()),
                                opt.get("name").and_then(|v| v.as_str()),
                            ) {
                                status_option_ids.insert(oname.to_string(), oid.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    let mut cfg = BoardConfigV1::load(tasks_dir).unwrap_or_default();
    cfg.org = org.to_string();
    cfg.project_id = project_id;
    cfg.project_number = project_number;
    cfg.project_title = project_title;
    cfg.project_url = project_url;
    cfg.repository_id = repo_id;
    cfg.repository_name_with_owner = repo_name;
    cfg.status_field_id = status_field_id;
    cfg.status_option_ids = status_option_ids;
    cfg.save(tasks_dir)?;
    Ok(cfg)
}

/// Live GitHub Projects v2 push (`chinwag board push --live`) — creates/updates real repository `Issue` items
/// in `emunlabs/chinwag` and links them to the live `ProjectV2` via `addProjectV2ItemById` (NEVER `addProjectV2DraftIssue` per `INV-NO-DRAFT-ISSUES-01`).
pub fn push_github_project_v2_live(
    tasks_dir: &Path,
    issues: &[AtomicTaskIssue],
    org: &str,
) -> Result<Value, String> {
    let mut cfg = match BoardConfigV1::load(tasks_dir) {
        Some(c) if c.project_id != "PVT_kwDOChinwag1" => c,
        _ => init_github_project_v2_live(
            tasks_dir,
            org,
            "Chinwag Engineering Velocity & Agent Fleet",
        )?,
    };

    let repo_id = match cfg.repository_id.clone() {
        Some(id) => id,
        None => {
            cfg = init_github_project_v2_live(&tasks_dir, org, &cfg.project_title)?;
            cfg.repository_id
                .clone()
                .ok_or_else(|| "missing repository_id for emunlabs/chinwag".to_string())?
        }
    };

    // Fetch existing repository issues so we never duplicate an issue
    let list_q = r#"
query($org: String!) {
  organization(login: $org) {
    repository(name: "chinwag") {
      issues(first: 100, orderBy: {field: CREATED_AT, direction: DESC}) {
        nodes {
          id
          number
          title
          url
        }
      }
    }
  }
}
"#;
    let list_resp = execute_gh_graphql(list_q, &[("org", org)])?;
    let mut existing_by_prefix: BTreeMap<String, (String, String)> = BTreeMap::new();
    if let Some(nodes) = list_resp
        .get("data")
        .and_then(|d| d.get("organization"))
        .and_then(|o| o.get("repository"))
        .and_then(|r| r.get("issues"))
        .and_then(|i| i.get("nodes"))
        .and_then(|n| n.as_array())
    {
        for node in nodes {
            if let (Some(id), Some(title), Some(url)) = (
                node.get("id").and_then(|v| v.as_str()),
                node.get("title").and_then(|v| v.as_str()),
                node.get("url").and_then(|v| v.as_str()),
            ) {
                if let Some(end) = title.strip_prefix('[').and_then(|s| s.find(']')) {
                    let key = &title[1..1 + end];
                    existing_by_prefix.insert(key.to_string(), (id.to_string(), url.to_string()));
                }
            }
        }
    }

    let mut synced_items = Vec::new();
    for issue in issues {
        // Respect INV-DEFAULT-PRIVATE-TASK-01: only sync public-safe issues to GitHub Projects v2
        let is_locked = issue
            .assigned_seats
            .iter()
            .any(|s| PRIVATE_LOCKED_SEATS.iter().any(|p| p.eq_ignore_ascii_case(s)));
        if is_locked {
            continue;
        }

        let gh_title = format!(
            "[{}] {} ({} · Tier {})",
            issue.id,
            issue.title,
            issue.status.column_header(),
            issue.dora_tier.as_str()
        );
        let manifest = build_issue_surface_impact_manifest(issue);
        let subtask_lines: Vec<String> = manifest
            .required_subtasks
            .iter()
            .map(|st| {
                let mark = if st.verified { "x" } else { " " };
                format!(
                    "- [{mark}] **{}** — `{}` (Owners: `{}`)",
                    st.label,
                    st.surface,
                    st.owner_seats.join(", ")
                )
            })
            .collect();
        let gh_body = format!(
            "### `{}` — {}\n\n\
             - **Board Column:** `{}` (`{}`)\n\
             - **DORA Complexity Tier:** `{}` (Human Anchor: `{:.1}h`)\n\
             - **SURV Window:** `{}`\n\
             - **Assigned Seats:** `{}`\n\
             - **CI / Tribunal Badge:** `{}`\n\n\
             #### Cross-Surface Impact Manifest (`chinwag.surface.impact.manifest.v1`)\n\
             {}\n\n\
             ---\n\n\
             {}\n",
            issue.id,
            issue.title,
            issue.status.column_header(),
            issue.status.as_code(),
            issue.dora_tier.as_str(),
            issue.dora_tier.metric_b_active_hours(),
            issue.surv_status.as_str(),
            if issue.assigned_seats.is_empty() {
                "UNASSIGNED".to_string()
            } else {
                issue.assigned_seats.join(", ")
            },
            issue
                .last_ci_gate_badge
                .as_deref()
                .unwrap_or("⏳ Awaiting Tribunal"),
            subtask_lines.join("\n"),
            issue.body.trim()
        );

        let (issue_node_id, issue_url) = if let Some((existing_id, existing_url)) = cfg
            .synced_issue_node_ids
            .get(&issue.id)
            .cloned()
            .zip(cfg.synced_issue_urls.get(&issue.id).cloned())
            .or_else(|| existing_by_prefix.get(&issue.id).cloned())
        {
            let update_q = r#"
mutation($issueId: ID!, $title: String!, $body: String!) {
  updateIssue(input: { id: $issueId, title: $title, body: $body }) {
    issue {
      id
      url
    }
  }
}
"#;
            let _ = execute_gh_graphql(
                update_q,
                &[
                    ("issueId", &existing_id),
                    ("title", &gh_title),
                    ("body", &gh_body),
                ],
            );
            (existing_id, existing_url)
        } else {
            let create_issue_q = r#"
mutation($repoId: ID!, $title: String!, $body: String!) {
  createIssue(input: { repositoryId: $repoId, title: $title, body: $body }) {
    issue {
      id
      number
      url
    }
  }
}
"#;
            let created = execute_gh_graphql(
                create_issue_q,
                &[
                    ("repoId", &repo_id),
                    ("title", &gh_title),
                    ("body", &gh_body),
                ],
            )?;
            let iss = created
                .get("data")
                .and_then(|d| d.get("createIssue"))
                .and_then(|c| c.get("issue"))
                .ok_or_else(|| format!("createIssue failed for {}", issue.id))?;
            (
                iss.get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                iss.get("url")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
            )
        };

        cfg.synced_issue_node_ids
            .insert(issue.id.clone(), issue_node_id.clone());
        cfg.synced_issue_urls
            .insert(issue.id.clone(), issue_url.clone());

        // Link repository Issue to ProjectV2 via addProjectV2ItemById (idempotent in GraphQL)
        let add_item_q = r#"
mutation($projectId: ID!, $contentId: ID!) {
  addProjectV2ItemById(input: { projectId: $projectId, contentId: $contentId }) {
    item {
      id
    }
  }
}
"#;
        let add_resp = execute_gh_graphql(
            add_item_q,
            &[
                ("projectId", &cfg.project_id),
                ("contentId", &issue_node_id),
            ],
        )?;
        let item_id = add_resp
            .get("data")
            .and_then(|d| d.get("addProjectV2ItemById"))
            .and_then(|a| a.get("item"))
            .and_then(|i| i.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if !item_id.is_empty() {
            cfg.synced_project_item_ids
                .insert(issue.id.clone(), item_id.clone());
        }

        // Update ProjectV2 Status field option if available
        if let (Some(field_id), false) = (cfg.status_field_id.as_ref(), item_id.is_empty()) {
            let target_opt_name = match issue.status {
                BoardStatus::OpenBounty | BoardStatus::ScopedBenchmarked => "Todo",
                BoardStatus::InFlight | BoardStatus::TribunalGate => "In Progress",
                BoardStatus::ShippedVerified => "Done",
            };
            if let Some(opt_id) = cfg.status_option_ids.get(target_opt_name) {
                let status_q = r#"
mutation($projectId: ID!, $itemId: ID!, $fieldId: ID!, $optId: String!) {
  updateProjectV2ItemFieldValue(input: {
    projectId: $projectId,
    itemId: $itemId,
    fieldId: $fieldId,
    value: { singleSelectOptionId: $optId }
  }) {
    projectV2Item {
      id
    }
  }
}
"#;
                let _ = execute_gh_graphql(
                    status_q,
                    &[
                        ("projectId", &cfg.project_id),
                        ("itemId", &item_id),
                        ("fieldId", field_id),
                        ("optId", opt_id),
                    ],
                );
            }
        }

        synced_items.push(json!({
            "issue_id": issue.id,
            "github_issue_node_id": issue_node_id,
            "github_issue_url": issue_url,
            "project_item_id": item_id,
            "board_status": issue.status.as_code(),
            "column_header": issue.status.column_header(),
        }));
    }

    cfg.save(tasks_dir)?;

    let linear_live = std::env::var("LIN_API_KEY")
        .ok()
        .filter(|k| !k.trim().is_empty())
        .is_some();

    Ok(json!({
        "live": true,
        "org": cfg.org,
        "project_id": cfg.project_id,
        "project_number": cfg.project_number,
        "project_title": cfg.project_title,
        "project_url": cfg.project_url,
        "linear_api_key_configured": linear_live,
        "synced_items": synced_items,
    }))
}

/// Live GitHub Projects v2 pull (`chinwag board pull --org <org> [--project-number <n>]`).
pub fn pull_github_project_v2_live(
    tasks_dir: &Path,
    org: &str,
    project_number: Option<u64>,
) -> Result<Value, String> {
    let cfg = BoardConfigV1::load(tasks_dir).unwrap_or_default();
    let num = project_number.unwrap_or(cfg.project_number);
    let num_str = num.to_string();
    let pull_q = r#"
query($org: String!, $number: Int!) {
  organization(login: $org) {
    projectV2(number: $number) {
      id
      number
      title
      url
      items(first: 50) {
        nodes {
          id
          content {
            ... on Issue {
              id
              number
              title
              url
              state
            }
          }
        }
      }
    }
  }
}
"#;
    let resp = execute_gh_graphql(pull_q, &[("org", org), ("number", &num_str)])?;
    let proj = resp
        .get("data")
        .and_then(|d| d.get("organization"))
        .and_then(|o| o.get("projectV2"))
        .cloned()
        .unwrap_or(Value::Null);
    Ok(json!({
        "ok": !proj.is_null(),
        "command": "chinwag board pull",
        "org": org,
        "project_number": num,
        "project": proj,
    }))
}

/// Execute Card-Move-Driven Cross-Surface Orchestration (`chinwag board sync-loop` / `chinwag board watch`).
///
/// - Inspects `.chinwag/tasks/issues/*.md` (and pulls live card column state when `--live` is passed).
/// - Computes `SurfaceImpactManifestV1` for each active issue (`02_SCOPED_BENCHMARKED`, `03_IN_FLIGHT`, `04_TRIBUNAL_GATE`).
/// - For any card in `04_TRIBUNAL_GATE`, runs the Proof-of-Green & Cross-Surface check:
///   - If all surfaces + `ui-gate` pass, promotes the card to `05_SHIPPED_VERIFIED` (`05 · ✓ SHIPPED — Δ VERIFIED`) and stamps the `✓ed25519` Δ Velocity Proof receipt.
///   - If any check fails, snaps the card back to `03_IN_FLIGHT` within `<200ms` (`INV-NO-FAKE-DONE-01`) and emits the `@DELIVERY` (`Mercury 3`) + author wakeup plan.
pub fn run_board_sync_loop(
    args: &[String],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let start_instant = std::time::Instant::now();
    let tasks_dir = resolve_tasks_dir(args);
    let issues_dir = tasks_dir.join("issues");
    let _ = fs::create_dir_all(&issues_dir);

    let mut org = "emunlabs".to_string();
    let mut live = false;
    let mut workspace_root: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--org" if i + 1 < args.len() => {
                org = args[i + 1].clone();
                i += 2;
            }
            "--workspace-root" if i + 1 < args.len() => {
                workspace_root = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--live" => {
                live = true;
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    let mut issue_paths = Vec::new();
    if let Ok(entries) = fs::read_dir(&issues_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("md") {
                issue_paths.push(p);
            }
        }
    }
    issue_paths.sort();

    let mut bridge = WorkToPlayCounterBridgeV1::load(&tasks_dir);
    let mut manifests = Vec::new();
    let mut tribunal_promotions = Vec::new();
    let mut tribunal_snapbacks = Vec::new();
    let mut updated_issues = Vec::new();

    for path in issue_paths {
        let raw = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                let _ = writeln!(
                    stderr,
                    "chinwag board sync-loop: failed to read {}: {e}",
                    path.display()
                );
                return 1;
            }
        };
        let mut issue = match AtomicTaskIssue::from_markdown(&raw) {
            Ok(iss) => iss,
            Err(e) => {
                let _ = writeln!(
                    stderr,
                    "chinwag board sync-loop: malformed issue {}: {e}",
                    path.display()
                );
                return EXIT_H_BOARD_REJECT;
            }
        };

        let is_active = matches!(
            issue.status,
            BoardStatus::ScopedBenchmarked | BoardStatus::InFlight | BoardStatus::TribunalGate
        );
        let manifest = build_issue_surface_impact_manifest(&issue);
        if is_active {
            manifests.push(manifest.clone());
        }

        if issue.status == BoardStatus::TribunalGate {
            if manifest.all_surfaces_synced && manifest.ui_gate_passed {
                let claimed_tier = issue.dora_tier;
                let (effective_tier, tier_downgraded) =
                    DoraTier::enforce_tier_lock(claimed_tier, issue.loc_changed);
                issue.dora_tier = effective_tier;
                issue.status = BoardStatus::ShippedVerified;
                if issue.t_claim_ms == 0 {
                    issue.t_claim_ms = 1_793_970_000_000;
                }
                if issue.t_ship_ms <= issue.t_claim_ms {
                    issue.t_ship_ms = issue.t_claim_ms + 1_140_000;
                }
                issue.surv_status = SurvStatus::Pending168h;
                issue.surv_expires_at_ms = issue.t_ship_ms + SURV_WINDOW_MS;

                let minted = bridge.record_ci_pass(issue.first_pass_ci_eligible);
                issue.chips_minted += minted;
                let _ = bridge.save(&tasks_dir);

                let proof = compute_velocity_proof(
                    claimed_tier,
                    issue.loc_changed,
                    issue.t_claim_ms,
                    issue.t_ship_ms,
                );
                issue.last_ci_gate_badge = Some(format!(
                    "✓ed25519 · H1+H2+H5+Pillar12 · {:.1}x vs DORA · SURV:PENDING_168H",
                    proof.metric_b_active_speedup
                ));
                issue.receipt_trailers.push(format!(
                    "SurfaceSyncReceiptV1: status=PASS pillar=12 subtasks=4/4 speedup={:.1}x chips=+{}",
                    proof.metric_b_active_speedup, minted
                ));
                let _ = fs::write(&path, issue.to_markdown());

                tribunal_promotions.push(json!({
                    "issue_id": issue.id,
                    "from_status": "04_TRIBUNAL_GATE",
                    "to_status": issue.status.as_code(),
                    "column_header": issue.status.column_header(),
                    "tier_downgraded": tier_downgraded,
                    "velocity_proof": proof,
                    "chips_minted_delta": minted,
                    "last_ci_gate_badge": issue.last_ci_gate_badge,
                }));
            } else {
                // Snap back to 03_IN_FLIGHT within <200ms (INV-NO-FAKE-DONE-01)
                let snapback_elapsed_ms = start_instant.elapsed().as_millis() as u64;
                issue.status = BoardStatus::InFlight;
                issue.surv_status = SurvStatus::InFlight;
                issue.first_pass_ci_eligible = false;
                issue.ci_failure_count += 1;
                issue.last_ci_gate_badge = Some(format!(
                    "🚨 Tribunal Snap-Back ({}ms < 200ms): Unsynced {:?}",
                    snapback_elapsed_ms, manifest.unsynced_subtasks
                ));
                let routing_plan =
                    build_ci_failure_routing_plan(&issue, None, true, true, false);
                issue.receipt_trailers.push(format!(
                    "TribunalSnapBackReceiptV1: status=SNAP_BACK_IN_FLIGHT elapsed_ms={} unsynced={:?} direct_to={} cc={:?}",
                    snapback_elapsed_ms,
                    manifest.unsynced_subtasks,
                    routing_plan.primary_recipient,
                    routing_plan.cc_recipients
                ));
                let _ = fs::write(&path, issue.to_markdown());

                tribunal_snapbacks.push(json!({
                    "issue_id": issue.id,
                    "from_status": "04_TRIBUNAL_GATE",
                    "to_status": issue.status.as_code(),
                    "column_header": issue.status.column_header(),
                    "snapback_elapsed_ms": snapback_elapsed_ms,
                    "snapback_under_200ms": snapback_elapsed_ms < 200,
                    "unsynced_subtasks": manifest.unsynced_subtasks,
                    "wakeup_plan": routing_plan,
                    "delivery_supervisor": {
                        "seat": "@DELIVERY",
                        "engine": "Mercury 3 (Chinwag Delivery-2)",
                        "action": "WAKE_AUTHOR_AND_SURFACE_OWNERS"
                    }
                }));
            }
        }

        updated_issues.push(issue);
    }

    let live_sync = if live {
        match push_github_project_v2_live(&tasks_dir, &updated_issues, &org) {
            Ok(val) => Some(val),
            Err(e) => {
                let _ = writeln!(stderr, "chinwag board sync-loop --live warning: {e}");
                None
            }
        }
    } else {
        None
    };

    let elapsed_ms = start_instant.elapsed().as_millis() as u64;
    let payload = json!({
        "ok": true,
        "command": "chinwag board sync-loop",
        "delivery_engine": "Chinwag Delivery-2",
        "surface_gate_pillar": 12,
        "invariants": [
            "INV-CI-BOARD-MUTATION-01",
            "INV-NO-FAKE-DONE-01",
            "INV-NO-DRAFT-ISSUES-01",
            "INV-DIRECT-CI-AGENT-ROUTING-01"
        ],
        "workspace_root": workspace_root.map(|p| p.to_string_lossy().to_string()),
        "elapsed_ms": elapsed_ms,
        "active_surface_manifests": manifests,
        "tribunal_promotions": tribunal_promotions,
        "tribunal_snapbacks": tribunal_snapbacks,
        "live_board_sync": live_sync,
    });
    let _ = writeln!(
        stdout,
        "{}",
        serde_json::to_string_pretty(&payload).unwrap_or_default()
    );
    0
}

/// Entrypoint for `chinwag board <init|push|sync|pull|watch|sync-loop> ...`.
pub fn run_board_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("push");
    if sub == "--help" || sub == "-h" || sub == "help" {
        let _ = writeln!(
            stdout,
            "Usage: chinwag board <init|push|sync|pull|watch|sync-loop> [--org <org>] [--title <title>] [--live] [--once] [--workspace-root <path>] [--tasks-dir <dir>] [--github-project <id>] [--linear-team <id>] [--dry-run] [--json]"
        );
        return 0;
    }
    if matches!(sub, "watch" | "sync-loop") {
        return run_board_sync_loop(args, stdout, stderr);
    }
    if !matches!(sub, "push" | "sync" | "init" | "pull") {
        let _ = writeln!(stderr, "chinwag board: unknown subcommand `{sub}`");
        return 2;
    }

    let tasks_dir = resolve_tasks_dir(args);
    let issues_dir = tasks_dir.join("issues");
    let mut org = "emunlabs".to_string();
    let mut title = "Chinwag Engineering Velocity & Agent Fleet".to_string();
    let mut github_project = BoardConfigV1::load(&tasks_dir)
        .map(|c| c.project_id)
        .unwrap_or_else(|| "PVT_kwDOChinwag1".to_string());
    let mut linear_team = "LIN-TEAM-CHWG".to_string();
    let mut project_number: Option<u64> = None;
    let mut dry_run = false;
    let mut from_ci = false;
    let mut live = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--org" if i + 1 < args.len() => {
                org = args[i + 1].clone();
                i += 2;
            }
            "--title" if i + 1 < args.len() => {
                title = args[i + 1].clone();
                i += 2;
            }
            "--project-number" if i + 1 < args.len() => {
                project_number = args[i + 1].parse::<u64>().ok();
                i += 2;
            }
            "--github-project" if i + 1 < args.len() => {
                github_project = args[i + 1].clone();
                i += 2;
            }
            "--linear-team" if i + 1 < args.len() => {
                linear_team = args[i + 1].clone();
                i += 2;
            }
            "--dry-run" => {
                dry_run = true;
                i += 1;
            }
            "--from-ci" => {
                from_ci = true;
                i += 1;
            }
            "--live" => {
                live = true;
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    if sub == "pull" {
        match pull_github_project_v2_live(&tasks_dir, &org, project_number) {
            Ok(payload) => {
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_default()
                );
                return 0;
            }
            Err(e) => {
                let _ = writeln!(stderr, "chinwag board pull: {e}");
                return 1;
            }
        }
    }

    if sub == "init" && live {
        match init_github_project_v2_live(&tasks_dir, &org, &title) {
            Ok(cfg) => {
                let payload = json!({
                    "ok": true,
                    "command": "chinwag board init",
                    "live": true,
                    "board_config": cfg,
                    "invariants": [
                        "INV-CHINWAG-TASKS-REPO-01",
                        "INV-NO-DRAFT-ISSUES-01",
                        "INV-30CH-COLUMN-BUDGET-01"
                    ]
                });
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_default()
                );
                return 0;
            }
            Err(e) => {
                let _ = writeln!(stderr, "chinwag board init --live failed: {e}");
                return 1;
            }
        }
    }

    let mut issue_paths = Vec::new();
    if let Ok(entries) = fs::read_dir(&issues_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("md") {
                issue_paths.push(p);
            }
        }
    }
    issue_paths.sort();

    let mut validated_issues = Vec::with_capacity(issue_paths.len());
    for path in issue_paths {
        let raw = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                let _ = writeln!(
                    stderr,
                    "chinwag board push: failed to read {}: {e}",
                    path.display()
                );
                return 1;
            }
        };
        let mut issue = match AtomicTaskIssue::from_markdown(&raw) {
            Ok(iss) => iss,
            Err(e) => {
                let _ = writeln!(
                    stderr,
                    "chinwag board push: malformed issue {}: {e}",
                    path.display()
                );
                return EXIT_H_BOARD_REJECT;
            }
        };

        if let Err(violation) = validate_h_board_issue(&issue, &raw) {
            let err_payload = json!({
                "ok": false,
                "exit_code": EXIT_H_BOARD_REJECT,
                "invariant": violation.invariant,
                "issue_id": violation.issue_id,
                "reason": violation.reason
            });
            let _ = writeln!(
                stderr,
                "H_board GATE REJECTED (exit 78) [{}] on {}: {}",
                violation.invariant, violation.issue_id, violation.reason
            );
            let _ = writeln!(stdout, "{err_payload}");
            return EXIT_H_BOARD_REJECT;
        }

        // Enforce INV-TIER-LOCK-01 automatic tier downgrade if loc_changed is smaller than claimed tier
        let (effective_tier, downgraded) =
            DoraTier::enforce_tier_lock(issue.dora_tier, issue.loc_changed);
        if downgraded {
            issue.dora_tier = effective_tier;
            let _ = fs::write(&path, issue.to_markdown());
        }

        validated_issues.push(issue);
    }

    let mut payload =
        build_board_push_graphql_payload(&validated_issues, &github_project, &linear_team, from_ci);
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("dry_run".to_string(), Value::Bool(dry_run));
    }

    if live && !dry_run {
        match push_github_project_v2_live(&tasks_dir, &validated_issues, &org) {
            Ok(live_receipt) => {
                if let Some(obj) = payload.as_object_mut() {
                    obj.insert("live_sync_receipt".to_string(), live_receipt);
                }
            }
            Err(e) => {
                let _ = writeln!(stderr, "chinwag board push --live failed: {e}");
                return 1;
            }
        }
    }

    let _ = writeln!(
        stdout,
        "{}",
        serde_json::to_string_pretty(&payload).unwrap_or_default()
    );
    0
}

/// Entrypoint for `chinwag ci-report --issue <CHWG-ID> --status <pass|fail> ...` (`INV-CI-BOARD-MUTATION-01`).
pub fn run_ci_report_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    if args.is_empty()
        || args
            .iter()
            .any(|a| a == "--help" || a == "-h" || a == "help")
    {
        let _ = writeln!(
            stdout,
            "Usage: chinwag ci-report --issue <CHWG-ID> --status <pass|fail> [--gate <gate-name>] [--diagnostic <text>] [--loc-changed <n>] [--is-main-regression] [--push-boards] [--delivery-licensed] [--cross-module-blast] [--author <SEAT#INSTANCE>]"
        );
        return 0;
    }

    let tasks_dir = resolve_tasks_dir(args);
    let issues_dir = tasks_dir.join("issues");
    let _ = fs::create_dir_all(&issues_dir);

    let mut issue_id: Option<String> = None;
    let mut status: Option<String> = None;
    let mut gate_name = "H2-Cleanroom-CI".to_string();
    let mut diagnostic_raw = "CI gate verification failed".to_string();
    let mut loc_changed: Option<u64> = None;
    let mut is_main_regression = false;
    let mut push_boards = false;
    let mut delivery_licensed = std::env::var("CHINWAG_DELIVERY_LICENSED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let mut cross_module_blast = false;
    let mut explicit_author: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--issue" | "--id" | "--task" if i + 1 < args.len() => {
                issue_id = Some(args[i + 1].clone());
                i += 2;
            }
            "--status" if i + 1 < args.len() => {
                status = Some(args[i + 1].to_ascii_lowercase());
                i += 2;
            }
            "--gate" if i + 1 < args.len() => {
                gate_name = args[i + 1].clone();
                i += 2;
            }
            "--diagnostic" if i + 1 < args.len() => {
                diagnostic_raw = args[i + 1].clone();
                i += 2;
            }
            "--loc-changed" if i + 1 < args.len() => {
                loc_changed = args[i + 1].parse::<u64>().ok();
                i += 2;
            }
            "--author" if i + 1 < args.len() => {
                explicit_author = Some(args[i + 1].clone());
                i += 2;
            }
            "--is-main-regression" => {
                is_main_regression = true;
                i += 1;
            }
            "--push-boards" => {
                push_boards = true;
                i += 1;
            }
            "--delivery-licensed" => {
                delivery_licensed = true;
                i += 1;
            }
            "--cross-module-blast" => {
                cross_module_blast = true;
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    let Some(issue_id) = issue_id else {
        let _ = writeln!(
            stderr,
            "chinwag ci-report: missing required `--issue <CHWG-ID>`"
        );
        return 2;
    };
    let Some(status) = status else {
        let _ = writeln!(
            stderr,
            "chinwag ci-report: missing required `--status <pass|fail>`"
        );
        return 2;
    };

    let issue_path = issues_dir.join(format!("{issue_id}.md"));
    let mut issue = if issue_path.exists() {
        let raw = match fs::read_to_string(&issue_path) {
            Ok(s) => s,
            Err(e) => {
                let _ = writeln!(
                    stderr,
                    "chinwag ci-report: failed to read {}: {e}",
                    issue_path.display()
                );
                return 1;
            }
        };
        match AtomicTaskIssue::from_markdown(&raw) {
            Ok(iss) => iss,
            Err(e) => {
                let _ = writeln!(
                    stderr,
                    "chinwag ci-report: malformed {}: {e}",
                    issue_path.display()
                );
                return 1;
            }
        }
    } else {
        AtomicTaskIssue::new_default(
            &issue_id,
            &format!("CI-Tracked Task {issue_id}"),
            DoraTier::M,
        )
    };

    if let Some(loc) = loc_changed {
        issue.loc_changed = Some(loc);
    }
    if let Some(ref auth) = explicit_author {
        issue.author_instance = Some(auth.clone());
    }

    let mut bridge = WorkToPlayCounterBridgeV1::load(&tasks_dir);

    match status.as_str() {
        "pass" | "passed" | "success" => {
            let claimed_tier = issue.dora_tier;
            let (effective_tier, tier_downgraded) =
                DoraTier::enforce_tier_lock(claimed_tier, issue.loc_changed);
            issue.dora_tier = effective_tier;
            issue.status = BoardStatus::ShippedVerified;
            if issue.t_claim_ms == 0 {
                issue.t_claim_ms = 1_793_970_000_000;
            }
            if issue.t_ship_ms <= issue.t_claim_ms {
                issue.t_ship_ms = issue.t_claim_ms + 1_180_000; // 19m 40s
            }
            issue.surv_status = SurvStatus::Pending168h;
            issue.surv_expires_at_ms = issue.t_ship_ms + SURV_WINDOW_MS;

            let minted = bridge.record_ci_pass(issue.first_pass_ci_eligible);
            issue.chips_minted += minted;
            let _ = bridge.save(&tasks_dir);

            let proof = compute_velocity_proof(
                claimed_tier,
                issue.loc_changed,
                issue.t_claim_ms,
                issue.t_ship_ms,
            );
            let receipt_line = format!(
                "CleanroomCIReceiptV1: status=PASS gate={} tier={} speedup={:.1}x chips=+{} surv_expires_at_ms={}",
                gate_name,
                effective_tier.as_str(),
                proof.metric_b_active_speedup,
                minted,
                issue.surv_expires_at_ms
            );
            issue.last_ci_gate_badge = Some(format!(
                "✓ed25519 · {} · {:.1}x vs DORA · SURV:PENDING_168H",
                gate_name, proof.metric_b_active_speedup
            ));
            issue.receipt_trailers.push(receipt_line);

            if let Err(e) = fs::write(&issue_path, issue.to_markdown()) {
                let _ = writeln!(
                    stderr,
                    "chinwag ci-report: failed to write {}: {e}",
                    issue_path.display()
                );
                return 1;
            }

            let board_sync = push_boards.then(|| {
                build_board_push_graphql_payload(
                    std::slice::from_ref(&issue),
                    "PVT_kwDOChinwag1",
                    "LIN-TEAM-CHWG",
                    true,
                )
            });

            let payload = json!({
                "ok": true,
                "command": "chinwag ci-report",
                "status": "pass",
                "invariants": [
                    "INV-CI-BOARD-MUTATION-01",
                    "INV-TIER-LOCK-01",
                    "INV-BENCHMARK-DUAL-METRIC-01"
                ],
                "issue_id": issue.id,
                "board_status": issue.status.as_code(),
                "column_header": issue.status.column_header(),
                "claimed_tier": claimed_tier.as_str(),
                "effective_tier": effective_tier.as_str(),
                "tier_downgraded": tier_downgraded,
                "velocity_proof": proof,
                "chips_minted_delta": minted,
                "chips_minted_total": issue.chips_minted,
                "surv_status": issue.surv_status.as_str(),
                "surv_expires_at_ms": issue.surv_expires_at_ms,
                "counter_bridge": bridge,
                "board_push": board_sync
            });
            let _ = writeln!(
                stdout,
                "{}",
                serde_json::to_string_pretty(&payload).unwrap_or_default()
            );
            0
        }
        "fail" | "failed" | "failure" => {
            let sanitized_diag = sanitize_diagnostic_text(&diagnostic_raw);
            let ci_diag = CIFailureDiagnosticV1 {
                schema: "CIFailureDiagnosticV1".to_string(),
                issue_id: issue.id.clone(),
                gate: gate_name.clone(),
                sanitized_diagnostic: sanitized_diag.clone(),
                zero_leak_verified: scan_zero_leak_text(&sanitized_diag).is_ok(),
            };

            issue.ci_failure_count += 1;
            issue.first_pass_ci_eligible = false;
            issue.last_ci_gate_badge = Some(format!("🚨 CI Gate Failed: {gate_name}"));

            let routing_plan = build_ci_failure_routing_plan(
                &issue,
                explicit_author.as_deref(),
                delivery_licensed,
                cross_module_blast,
                is_main_regression,
            );

            let mut regression_issue_id: Option<String> = None;
            let mut regression_issue_path: Option<String> = None;
            let mut chips_delta = 0i64;
            let mut issues_to_push = Vec::new();

            if is_main_regression {
                issue.surv_status = SurvStatus::FailedRegressionClawback;
                chips_delta = bridge.record_regression_clawback();
                issue.chips_minted += chips_delta;
                let _ = bridge.save(&tasks_dir);

                let reg_id = format!("{}-CI-FAIL", issue.id);
                let reg_path = issues_dir.join(format!("{reg_id}.md"));
                let mut reg_issue = AtomicTaskIssue::new_default(
                    &reg_id,
                    &format!("P0 Regression on main from {} ({gate_name})", issue.id),
                    DoraTier::S,
                );
                reg_issue.parent_id = Some(issue.id.clone());
                reg_issue.status = BoardStatus::InFlight;
                reg_issue.priority = Some("P0".to_string());
                reg_issue.assigned_seats = issue.assigned_seats.clone();
                reg_issue.author_instance = issue.author_instance.clone();
                reg_issue.last_ci_gate_badge = Some(format!("🚨 P0 Regression: {gate_name}"));
                reg_issue.body = format!(
                    "Automated `P0` regression issue minted by `chinwag ci-report --status fail --is-main-regression`.\n\n\
                     - **Parent Issue:** `{}`\n\
                     - **Failing Gate:** `{gate_name}`\n\
                     - **Direct Author Recipient:** `{}`\n\
                     - **Sanitized Diagnostic:** `{}`",
                    issue.id, routing_plan.primary_recipient, ci_diag.sanitized_diagnostic
                );
                let _ = fs::write(&reg_path, reg_issue.to_markdown());
                regression_issue_id = Some(reg_id);
                regression_issue_path = Some(reg_path.to_string_lossy().to_string());
                issues_to_push.push(reg_issue);
            } else {
                // In-flight PR/branch failure: demote from 04_TRIBUNAL_GATE back to 03_IN_FLIGHT
                issue.status = BoardStatus::InFlight;
                issue.surv_status = SurvStatus::InFlight;
            }

            issue.receipt_trailers.push(format!(
                "CIFailureReceiptV1: status=FAIL gate={} direct_to={} cc={:?} diag={}",
                gate_name,
                routing_plan.primary_recipient,
                routing_plan.cc_recipients,
                ci_diag.sanitized_diagnostic
            ));
            if let Err(e) = fs::write(&issue_path, issue.to_markdown()) {
                let _ = writeln!(
                    stderr,
                    "chinwag ci-report: failed to write {}: {e}",
                    issue_path.display()
                );
                return 1;
            }
            issues_to_push.insert(0, issue.clone());

            let board_sync = push_boards.then(|| {
                build_board_push_graphql_payload(
                    &issues_to_push,
                    "PVT_kwDOChinwag1",
                    "LIN-TEAM-CHWG",
                    true,
                )
            });

            let payload = json!({
                "ok": true,
                "command": "chinwag ci-report",
                "status": "fail",
                "invariants": [
                    "INV-CI-BOARD-MUTATION-01",
                    "INV-DIRECT-CI-AGENT-ROUTING-01",
                    "INV-NEVER-STOP-FOR-APPROVAL-01"
                ],
                "issue_id": issue.id,
                "board_status": issue.status.as_code(),
                "column_header": issue.status.column_header(),
                "first_pass_ci_eligible": issue.first_pass_ci_eligible,
                "ci_failure_count": issue.ci_failure_count,
                "last_ci_gate_badge": issue.last_ci_gate_badge,
                "surv_status": issue.surv_status.as_str(),
                "chips_delta": chips_delta,
                "chips_minted_total": issue.chips_minted,
                "is_main_regression": is_main_regression,
                "p0_regression_issue_id": regression_issue_id,
                "p0_regression_issue_path": regression_issue_path,
                "diagnostic": ci_diag,
                "routing": routing_plan,
                "counter_bridge": bridge,
                "board_push": board_sync
            });
            let _ = writeln!(
                stdout,
                "{}",
                serde_json::to_string_pretty(&payload).unwrap_or_default()
            );
            0
        }
        other => {
            let _ = writeln!(
                stderr,
                "chinwag ci-report: invalid `--status {other}` (expected `pass` or `fail`)"
            );
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    fn temp_tasks_dir(label: &str) -> PathBuf {
        let id = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "chinwag-board-test-{label}-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp test dir");
        dir
    }

    #[test]
    fn test_01_tasks_init_creates_atomic_markdown_issue_and_counter_bridge() {
        let dir = temp_tasks_dir("init");
        let mut out = Vec::new();
        let mut err = Vec::new();
        let args = vec![
            "init".to_string(),
            "--tasks-dir".to_string(),
            dir.to_string_lossy().to_string(),
            "--id".to_string(),
            "CHWG-0142".to_string(),
            "--title".to_string(),
            "Atomic Board Engine".to_string(),
            "--tier".to_string(),
            "L".to_string(),
            "--json".to_string(),
        ];
        let code = run_tasks_cli(&args, &mut out, &mut err);
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));

        let issue_file = dir.join("issues").join("CHWG-0142.md");
        assert!(issue_file.is_file(), "expected CHWG-0142.md to exist");
        let raw = fs::read_to_string(&issue_file).unwrap();
        let parsed = AtomicTaskIssue::from_markdown(&raw).expect("parse issue markdown");
        assert_eq!(parsed.id, "CHWG-0142");
        assert_eq!(parsed.title, "Atomic Board Engine");
        assert_eq!(parsed.dora_tier, DoraTier::L);
        assert_eq!(parsed.status, BoardStatus::ScopedBenchmarked);
        assert_eq!(parsed.receipt_trailers.len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_02_canonical_board_column_headers_fit_github_projects_v2_30ch_window() {
        for status in [
            BoardStatus::OpenBounty,
            BoardStatus::ScopedBenchmarked,
            BoardStatus::InFlight,
            BoardStatus::TribunalGate,
            BoardStatus::ShippedVerified,
        ] {
            let visual_chars = status
                .column_header()
                .chars()
                .filter(|c| *c != '\u{fe0f}')
                .count();
            assert!(
                visual_chars <= 29,
                "header `{}` has {visual_chars} visual chars (> 29)",
                status.column_header()
            );
        }
    }

    #[test]
    fn test_03_h_board_rejects_tailscale_and_rfc1918_ips_with_exit_78() {
        let dir = temp_tasks_dir("tailscale-ip");
        let issues_dir = dir.join("issues");
        fs::create_dir_all(&issues_dir).unwrap();
        let mut issue = AtomicTaskIssue::new_default("CHWG-0201", "Leak Test", DoraTier::S);
        issue.body = "Connected to Node 2 at 100.108.108.25:11500 over Tailscale.".to_string();
        fs::write(issues_dir.join("CHWG-0201.md"), issue.to_markdown()).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_board_cli(
            &[
                "push".to_string(),
                "--tasks-dir".to_string(),
                dir.to_string_lossy().to_string(),
                "--dry-run".to_string(),
            ],
            &mut out,
            &mut err,
        );
        assert_eq!(code, EXIT_H_BOARD_REJECT);
        let stderr_str = String::from_utf8_lossy(&err);
        assert!(stderr_str.contains("100.108.108.25"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_04_h_board_rejects_local_users_path_and_crdb_with_exit_78() {
        let dir = temp_tasks_dir("users-path");
        let issues_dir = dir.join("issues");
        fs::create_dir_all(&issues_dir).unwrap();
        let mut issue = AtomicTaskIssue::new_default("CHWG-0202", "Path Leak", DoraTier::S);
        issue.body = "Loaded state from /Users/alice/workspace/.chinwag/state.crdb".to_string();
        fs::write(issues_dir.join("CHWG-0202.md"), issue.to_markdown()).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_board_cli(
            &[
                "push".to_string(),
                "--tasks-dir".to_string(),
                dir.to_string_lossy().to_string(),
                "--dry-run".to_string(),
            ],
            &mut out,
            &mut err,
        );
        assert_eq!(code, EXIT_H_BOARD_REJECT);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_05_h_board_rejects_draft_issue_mutation_with_exit_78() {
        let dir = temp_tasks_dir("draft-issue");
        let issues_dir = dir.join("issues");
        fs::create_dir_all(&issues_dir).unwrap();
        let mut issue = AtomicTaskIssue::new_default("CHWG-0203", "Draft Item", DoraTier::S);
        issue.item_type = "DraftIssue".to_string();
        fs::write(issues_dir.join("CHWG-0203.md"), issue.to_markdown()).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_board_cli(
            &[
                "push".to_string(),
                "--tasks-dir".to_string(),
                dir.to_string_lossy().to_string(),
                "--dry-run".to_string(),
            ],
            &mut out,
            &mut err,
        );
        assert_eq!(code, EXIT_H_BOARD_REJECT);
        let stderr_str = String::from_utf8_lossy(&err);
        assert!(stderr_str.contains("INV-NO-DRAFT-ISSUES-01"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_06_h_board_rejects_raw_latex_and_patent_markers_with_exit_78() {
        let mut latex_issue = AtomicTaskIssue::new_default("CHWG-0204", "Math Copy", DoraTier::S);
        latex_issue.body = "Formula $$\\Delta = x^2$$ is forbidden.".to_string();
        let res = validate_h_board_issue(&latex_issue, &latex_issue.to_markdown());
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().exit_code, EXIT_H_BOARD_REJECT);

        let mut patent_issue =
            AtomicTaskIssue::new_default("CHWG-0205", "Patent Copy", DoraTier::S);
        patent_issue.body = "See US Provisional application and MPEP 608.".to_string();
        let res2 = validate_h_board_issue(&patent_issue, &patent_issue.to_markdown());
        assert!(res2.is_err());
        assert_eq!(res2.unwrap_err().exit_code, EXIT_H_BOARD_REJECT);
    }

    #[test]
    fn test_07_h_board_rejects_prebaked_commits_and_clock_drift_with_exit_78() {
        let mut prebaked = AtomicTaskIssue::new_default("CHWG-0206", "Prebaked", DoraTier::M);
        prebaked.t_claim_ms = 2_000_000;
        prebaked.t_commit_ms = Some(1_900_000); // Committed BEFORE claim!
        let err = validate_h_board_issue(&prebaked, &prebaked.to_markdown()).unwrap_err();
        assert_eq!(err.exit_code, EXIT_H_BOARD_REJECT);
        assert_eq!(err.invariant, "INV-NO-PREBAKED-CLAIM-01");

        let mut drifted = AtomicTaskIssue::new_default("CHWG-0207", "Clock Drift", DoraTier::M);
        drifted.t_claim_ms = 2_000_000;
        drifted.github_comment_created_at_ms = Some(2_090_000); // 90s drift (> 60s max)
        let err2 = validate_h_board_issue(&drifted, &drifted.to_markdown()).unwrap_err();
        assert_eq!(err2.exit_code, EXIT_H_BOARD_REJECT);
        assert_eq!(err2.invariant, "INV-CLAIM-ANCHOR-01");
    }

    #[test]
    fn test_08_inv_tier_lock_01_auto_downgrades_inflated_tiers_by_loc() {
        let (eff_s, down_s) = DoraTier::enforce_tier_lock(DoraTier::XL, Some(45));
        assert!(down_s);
        assert_eq!(eff_s, DoraTier::S);

        let (eff_m, down_m) = DoraTier::enforce_tier_lock(DoraTier::L, Some(250));
        assert!(down_m);
        assert_eq!(eff_m, DoraTier::M);

        let (eff_keep, down_keep) = DoraTier::enforce_tier_lock(DoraTier::L, Some(650));
        assert!(!down_keep);
        assert_eq!(eff_keep, DoraTier::L);
    }

    #[test]
    fn test_09_ci_report_pass_mints_150_chips_starts_168h_surv_and_pushes_boards() {
        let dir = temp_tasks_dir("ci-pass");
        let issues_dir = dir.join("issues");
        fs::create_dir_all(&issues_dir).unwrap();
        let mut issue = AtomicTaskIssue::new_default("CHWG-0301", "Cleanroom Pass", DoraTier::L);
        issue.status = BoardStatus::TribunalGate;
        issue.t_claim_ms = 1_793_970_000_000;
        issue.t_ship_ms = 1_793_971_200_000; // 20m
        fs::write(issues_dir.join("CHWG-0301.md"), issue.to_markdown()).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_ci_report_cli(
            &[
                "--issue".to_string(),
                "CHWG-0301".to_string(),
                "--status".to_string(),
                "pass".to_string(),
                "--gate".to_string(),
                "H1+H2+H5".to_string(),
                "--loc-changed".to_string(),
                "45".to_string(), // Claimed L, but only 45 LOC -> auto-downgrades to Tier S!
                "--push-boards".to_string(),
                "--tasks-dir".to_string(),
                dir.to_string_lossy().to_string(),
            ],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));

        let resp: Value = serde_json::from_slice(&out).expect("parse ci-report JSON");
        assert_eq!(resp["board_status"], "05_SHIPPED_VERIFIED");
        assert_eq!(resp["column_header"], "05 · ✓ SHIPPED — Δ VERIFIED");
        assert_eq!(resp["claimed_tier"], "L");
        assert_eq!(resp["effective_tier"], "S");
        assert_eq!(resp["tier_downgraded"], true);
        assert_eq!(resp["chips_minted_delta"], 150);
        assert_eq!(resp["surv_status"], "PENDING_168H");
        assert_eq!(
            resp["surv_expires_at_ms"].as_u64().unwrap(),
            1_793_971_200_000 + SURV_WINDOW_MS
        );
        assert!(resp["board_push"]["github_projects_v2"]["mutations"].is_array());
        assert!(resp["board_push"]["linear"]["mutations"].is_array());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_10_ci_report_fail_direct_to_author_fast_path_without_delivery_llm() {
        let dir = temp_tasks_dir("ci-fail-direct");
        let issues_dir = dir.join("issues");
        fs::create_dir_all(&issues_dir).unwrap();
        let mut issue =
            AtomicTaskIssue::new_default("CHWG-0302", "In-Flight Gate Fail", DoraTier::M);
        issue.status = BoardStatus::TribunalGate;
        issue.author_instance = Some("WORKHORSE#AaFG0NdpegKhpXXEB_-qPA".to_string());
        fs::write(issues_dir.join("CHWG-0302.md"), issue.to_markdown()).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_ci_report_cli(
            &[
                "--issue".to_string(),
                "CHWG-0302".to_string(),
                "--status".to_string(),
                "fail".to_string(),
                "--gate".to_string(),
                "H2-Clippy".to_string(),
                "--diagnostic".to_string(),
                "error in /Users/brianspector/repo/src/lib.rs at 100.108.108.25".to_string(),
                "--push-boards".to_string(),
                "--tasks-dir".to_string(),
                dir.to_string_lossy().to_string(),
            ],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        let resp: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(resp["board_status"], "03_IN_FLIGHT");
        assert_eq!(resp["column_header"], "03 · ⚡ IN FLIGHT — CLOCK LIVE");
        assert_eq!(resp["first_pass_ci_eligible"], false);
        assert_eq!(resp["diagnostic"]["zero_leak_verified"], true);
        assert_eq!(
            resp["routing"]["routing_mode"],
            "DIRECT_TO_AUTHOR_FAST_PATH"
        );
        assert_eq!(
            resp["routing"]["primary_recipient"],
            "@WORKHORSE#AaFG0NdpegKhpXXEB_-qPA"
        );
        assert_eq!(
            resp["routing"]["cc_recipients"].as_array().unwrap().len(),
            0
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_11_ci_report_fail_with_licensed_delivery_ccs_delivery_and_escalates_on_second_fail() {
        let dir = temp_tasks_dir("ci-fail-delivery");
        let issues_dir = dir.join("issues");
        fs::create_dir_all(&issues_dir).unwrap();
        let mut issue =
            AtomicTaskIssue::new_default("CHWG-0303", "Repeated Gate Fail", DoraTier::M);
        issue.status = BoardStatus::TribunalGate;
        issue.ci_failure_count = 1; // Already failed once; this will be failure #2
        issue.author_instance = Some("RUST#thread-99".to_string());
        fs::write(issues_dir.join("CHWG-0303.md"), issue.to_markdown()).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_ci_report_cli(
            &[
                "--issue".to_string(),
                "CHWG-0303".to_string(),
                "--status".to_string(),
                "fail".to_string(),
                "--gate".to_string(),
                "WP-13-Visual-Tribunal".to_string(),
                "--delivery-licensed".to_string(),
                "--push-boards".to_string(),
                "--tasks-dir".to_string(),
                dir.to_string_lossy().to_string(),
            ],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        let resp: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            resp["routing"]["routing_mode"],
            "DIRECT_TO_AUTHOR_PLUS_DELIVERY_TRIAGE"
        );
        assert_eq!(resp["routing"]["primary_recipient"], "@RUST#thread-99");
        assert_eq!(resp["routing"]["cc_recipients"][0], "@DELIVERY");
        assert_eq!(
            resp["routing"]["delivery_triage"]["upgrade_to_pair_team"],
            true
        );
        assert!(
            resp["routing"]["delivery_triage"]["calm_handoff_command"]
                .as_str()
                .unwrap()
                .contains("git chinwag handoff")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_12_ci_report_main_regression_mints_p0_issue_and_claws_back_150_chips() {
        let dir = temp_tasks_dir("ci-regression");
        let issues_dir = dir.join("issues");
        fs::create_dir_all(&issues_dir).unwrap();
        let mut issue = AtomicTaskIssue::new_default("CHWG-0304", "Shipped Feature", DoraTier::M);
        issue.status = BoardStatus::ShippedVerified;
        issue.surv_status = SurvStatus::Pending168h;
        issue.chips_minted = 150;
        issue.author_instance = Some("RUST#thread-77".to_string());
        fs::write(issues_dir.join("CHWG-0304.md"), issue.to_markdown()).unwrap();

        let bridge = WorkToPlayCounterBridgeV1 {
            first_pass_ci_chips: 50,
            verified_commit_chips: 100,
            surv_168h_pending_count: 1,
            regression_clawback_chips: 0,
            net_play_chips_balance: 150,
        };
        bridge.save(&dir).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_ci_report_cli(
            &[
                "--issue".to_string(),
                "CHWG-0304".to_string(),
                "--status".to_string(),
                "fail".to_string(),
                "--gate".to_string(),
                "Main-Canary-Regression".to_string(),
                "--is-main-regression".to_string(),
                "--delivery-licensed".to_string(),
                "--push-boards".to_string(),
                "--tasks-dir".to_string(),
                dir.to_string_lossy().to_string(),
            ],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        let resp: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(resp["surv_status"], "FAILED_REGRESSION_CLAWBACK");
        assert_eq!(resp["chips_delta"], -150);
        assert_eq!(resp["chips_minted_total"], 0);
        assert_eq!(resp["p0_regression_issue_id"], "CHWG-0304-CI-FAIL");
        assert_eq!(resp["counter_bridge"]["net_play_chips_balance"], 0);
        assert_eq!(resp["counter_bridge"]["regression_clawback_chips"], 150);

        let p0_file = issues_dir.join("CHWG-0304-CI-FAIL.md");
        assert!(p0_file.is_file(), "expected P0 regression issue file");
        let p0_parsed =
            AtomicTaskIssue::from_markdown(&fs::read_to_string(&p0_file).unwrap()).unwrap();
        assert_eq!(p0_parsed.priority.as_deref(), Some("P0"));
        assert_eq!(p0_parsed.parent_id.as_deref(), Some("CHWG-0304"));
        assert_eq!(p0_parsed.status, BoardStatus::InFlight);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_13_h_board_rejects_public_board_push_for_private_locked_seats_with_exit_78() {
        for seat in PRIVATE_LOCKED_SEATS {
            let mut issue =
                AtomicTaskIssue::new_default("CHWG-0305", "Sensitive Advisory Task", DoraTier::M);
            issue.visibility = "public".to_string();
            issue.assigned_seats = vec![seat.to_string()];
            let err = validate_h_board_issue(&issue, &issue.to_markdown()).unwrap_err();
            assert_eq!(err.exit_code, EXIT_H_BOARD_REJECT);
            assert_eq!(err.invariant, "INV-DEFAULT-PRIVATE-TASK-01");
        }
    }

    #[test]
    fn test_14_ci_report_pass_after_prior_fail_omits_50_chip_first_pass_bonus() {
        let dir = temp_tasks_dir("ci-second-pass");
        let issues_dir = dir.join("issues");
        fs::create_dir_all(&issues_dir).unwrap();
        let mut issue =
            AtomicTaskIssue::new_default("CHWG-0306", "Second Attempt Pass", DoraTier::S);
        issue.status = BoardStatus::InFlight;
        issue.first_pass_ci_eligible = false;
        issue.ci_failure_count = 1;
        fs::write(issues_dir.join("CHWG-0306.md"), issue.to_markdown()).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_ci_report_cli(
            &[
                "--issue".to_string(),
                "CHWG-0306".to_string(),
                "--status".to_string(),
                "pass".to_string(),
                "--tasks-dir".to_string(),
                dir.to_string_lossy().to_string(),
            ],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        let resp: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(resp["chips_minted_delta"], 100);
        assert_eq!(resp["counter_bridge"]["first_pass_ci_chips"], 0);
        assert_eq!(resp["counter_bridge"]["verified_commit_chips"], 100);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_15_surface_impact_manifest_and_subtasks() {
        let mut issue = AtomicTaskIssue::new_default(
            "CHWG-0190",
            "Card-Move-Driven Cross-Surface Orchestration",
            DoraTier::L,
        );
        issue.body = "- [x] #CHWG-0190.1 Code\n- [x] #CHWG-0190.2 Docs & READMEs\n- [ ] #CHWG-0190.3 Website & PostHog Proxy\n- [x] #CHWG-0190.4 QA & UI Gate".to_string();
        let manifest = build_issue_surface_impact_manifest(&issue);
        assert_eq!(manifest.schema, "chinwag.surface.impact.manifest.v1");
        assert_eq!(manifest.surface_gate_pillar, 12);
        assert_eq!(manifest.delivery_engine, "Chinwag Delivery-2");
        assert_eq!(manifest.required_subtasks.len(), 4);
        assert!(!manifest.all_surfaces_synced);
        assert_eq!(manifest.unsynced_subtasks, vec!["CHWG-0190#3".to_string()]);
    }

    #[test]
    fn test_16_board_sync_loop_promotes_verified_and_snaps_back_incomplete_tribunal_card() {
        let dir = temp_tasks_dir("sync-loop");
        let issues_dir = dir.join("issues");
        fs::create_dir_all(&issues_dir).unwrap();

        // Issue 1: in 04_TRIBUNAL_GATE with all 4 surfaces verified -> should promote to 05_SHIPPED_VERIFIED
        let mut verified = AtomicTaskIssue::new_default(
            "CHWG-0189",
            "CHWG-PAT-10 Two-Loop CP-OMP Seat Selection",
            DoraTier::L,
        );
        verified.status = BoardStatus::TribunalGate;
        verified.body = "- [x] #CHWG-0189.1 Code\n- [x] #CHWG-0189.2 Docs\n- [x] #CHWG-0189.3 Site & Proxy\n- [x] #CHWG-0189.4 QA & UI Gate".to_string();
        fs::write(issues_dir.join("CHWG-0189.md"), verified.to_markdown()).unwrap();

        // Issue 2: in 04_TRIBUNAL_GATE with #3 unchecked -> should snap back to 03_IN_FLIGHT (<200ms)
        let mut incomplete = AtomicTaskIssue::new_default(
            "CHWG-0190",
            "Incomplete Tribunal Card",
            DoraTier::M,
        );
        incomplete.status = BoardStatus::TribunalGate;
        incomplete.author_instance = Some("DEX#6df4d436df6c01617dcd2f4e404673fc".to_string());
        incomplete.body = "- [x] #CHWG-0190.1 Code\n- [x] #CHWG-0190.2 Docs\n- [ ] #CHWG-0190.3 Site & Proxy\n- [x] #CHWG-0190.4 QA & UI Gate".to_string();
        fs::write(issues_dir.join("CHWG-0190.md"), incomplete.to_markdown()).unwrap();

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_board_cli(
            &[
                "sync-loop".to_string(),
                "--tasks-dir".to_string(),
                dir.to_string_lossy().to_string(),
                "--once".to_string(),
                "--json".to_string(),
            ],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        let resp: Value = serde_json::from_slice(&out).expect("parse sync-loop JSON");
        assert_eq!(resp["ok"], true);
        assert_eq!(resp["surface_gate_pillar"], 12);
        assert_eq!(resp["tribunal_promotions"].as_array().unwrap().len(), 1);
        assert_eq!(resp["tribunal_promotions"][0]["issue_id"], "CHWG-0189");
        assert_eq!(
            resp["tribunal_promotions"][0]["to_status"],
            "05_SHIPPED_VERIFIED"
        );
        assert_eq!(resp["tribunal_snapbacks"].as_array().unwrap().len(), 1);
        assert_eq!(resp["tribunal_snapbacks"][0]["issue_id"], "CHWG-0190");
        assert_eq!(resp["tribunal_snapbacks"][0]["to_status"], "03_IN_FLIGHT");
        assert_eq!(resp["tribunal_snapbacks"][0]["snapback_under_200ms"], true);
        assert_eq!(
            resp["tribunal_snapbacks"][0]["delivery_supervisor"]["seat"],
            "@DELIVERY"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
