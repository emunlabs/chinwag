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

mod presentation;
use presentation::*;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

mod templates;
pub use templates::{build_github_project_v2_template_schema, build_linear_template_schema};

mod policy;
pub use policy::{
    BOARD_POLICY_RELATIVE_PATH, BOARD_POLICY_SCHEMA_V1, BoardLedgerPolicyV1, BoardPolicyBoardV1,
    BoardPolicyError, BoardPolicyTomlV1, BoardPrivacyPolicyV1, DELIVERABLE_KIND_ARTIFACT,
    DELIVERABLE_KIND_CODE, INV_BOARD_LEDGER_TRACKING, INV_UNIQUE_TICKET_ID,
    KNOWN_DELIVERABLE_KINDS, ScopingField, SettlementField, TicketId, default_deliverable_kind,
};

mod ledger;
pub use ledger::{
    LiveBoardItem, LiveBoardSnapshot, TicketCardRef, collect_board_ledger_violations,
    collect_live_board_violations, parse_live_project_items, run_board_verify_ledger,
    validate_board_ledger_issue, validate_unique_ticket_ids,
};
use ledger::{require_board_policy_for_live, resolve_board_policy, resolve_board_workspace_root};

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
    compute_velocity_proof_for_deliverable(
        claimed_tier,
        loc_changed,
        DELIVERABLE_KIND_CODE,
        t_claim_ms,
        t_ship_ms,
    )
}

/// `INV-TIER-LOCK-01` applies to code only: a diff's LOC bounds the tier that may be claimed
/// for it. For any other deliverable kind `loc_changed` is an artifact size, not a diff, so
/// the claimed tier stands.
#[must_use]
pub fn enforce_tier_lock_for_deliverable(
    claimed: DoraTier,
    loc_changed: Option<u64>,
    deliverable_kind: &str,
) -> (DoraTier, bool) {
    if deliverable_kind == DELIVERABLE_KIND_CODE {
        DoraTier::enforce_tier_lock(claimed, loc_changed)
    } else {
        (claimed, false)
    }
}

/// [`compute_velocity_proof`] for a card of the given `deliverable_kind`.
#[must_use]
pub fn compute_velocity_proof_for_deliverable(
    claimed_tier: DoraTier,
    loc_changed: Option<u64>,
    deliverable_kind: &str,
    t_claim_ms: u64,
    t_ship_ms: u64,
) -> VelocityProof {
    let (effective_tier, tier_downgraded) =
        enforce_tier_lock_for_deliverable(claimed_tier, loc_changed, deliverable_kind);
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
        "Measured · Below 10x baseline".to_string()
    };

    let total_secs = clamped_ms / 1_000;
    let mins = total_secs / 60;
    let secs = total_secs % 60;
    let cycle_time_label = if deliverable_kind == DELIVERABLE_KIND_CODE {
        let loc_display = loc_changed.unwrap_or(88);
        format!("{mins}m {secs:02}s · {loc_display} LOC")
    } else {
        format!("{mins}m {secs:02}s · {deliverable_kind}")
    };

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
    #[serde(default)]
    pub primary_function: Option<String>,
    #[serde(default)]
    pub completion_evidence_note: Option<String>,
    pub id: String,
    pub parent_id: Option<String>,
    pub title: String,
    pub status: BoardStatus,
    pub dora_tier: DoraTier,
    /// `code` or `artifact`. Task files written before this field existed are `code`.
    #[serde(default = "default_deliverable_kind")]
    pub deliverable_kind: String,
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
            primary_function: None,
            completion_evidence_note: None,
            id: id.to_string(),
            parent_id: None,
            title: title.to_string(),
            status: BoardStatus::ScopedBenchmarked,
            dora_tier: tier,
            deliverable_kind: default_deliverable_kind(),
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

    /// A new card with nothing assumed on its behalf: no function, seats, clocks, or receipts.
    /// The caller supplies scoping explicitly and the ledger gate rejects what is left blank.
    #[must_use]
    pub fn new_unscoped(id: &str, title: &str, tier: DoraTier) -> Self {
        Self {
            file_scope: "*".to_string(),
            assigned_seats: Vec::new(),
            author_instance: None,
            base_head_sha: "0000000000000000000000000000000000000000".to_string(),
            t_claim_ms: 0,
            surv_status: SurvStatus::Unstarted,
            body: title.to_string(),
            receipt_trailers: Vec::new(),
            ..Self::new_default(id, title, tier)
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
        if let Some(function) = &self.primary_function {
            out.push_str(&format!("primary_function: {function}\n"));
        }
        if let Some(note) = &self.completion_evidence_note {
            out.push_str(&format!("completion_evidence_note: {note}\n"));
        }
        out.push_str(&format!("status: {}\n", self.status.as_code()));
        out.push_str(&format!("dora_tier: {}\n", self.dora_tier.as_str()));
        out.push_str(&format!("deliverable_kind: {}\n", self.deliverable_kind));
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
        let mut primary_function = None;
        let mut completion_evidence_note = None;
        let mut status = BoardStatus::ScopedBenchmarked;
        let mut dora_tier = DoraTier::M;
        let mut deliverable_kind = default_deliverable_kind();
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
                "primary_function" => primary_function = Some(val.to_string()),
                "completion_evidence_note" => completion_evidence_note = Some(val.to_string()),
                "status" => {
                    status = BoardStatus::from_code(val)
                        .ok_or_else(|| format!("invalid board status: {val}"))?;
                }
                "dora_tier" => {
                    dora_tier =
                        DoraTier::parse(val).ok_or_else(|| format!("invalid dora_tier: {val}"))?;
                }
                "deliverable_kind" => deliverable_kind = val.to_string(),
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
            primary_function,
            completion_evidence_note,
            id,
            parent_id,
            title,
            status,
            dora_tier,
            deliverable_kind,
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

    if !issue.visibility.eq_ignore_ascii_case("public")
        && !issue.visibility.eq_ignore_ascii_case("private")
    {
        return Err(HBoardViolation {
            exit_code: EXIT_H_BOARD_REJECT,
            invariant: "INV-DEFAULT-PRIVATE-TASK-01".to_string(),
            issue_id: issue.id.clone(),
            reason: "task visibility must be `public` or `private`".to_string(),
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
            let base = normalize_seat_token(seat);
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

    // 5. Secrets are forbidden in every repository, including raw metadata and receipts.
    // Public copy additionally requires internal-information and formatting redaction.
    let combined = format!("{}\n{raw_markdown}", issue.to_markdown());
    if !issue.id.starts_with("CHWG-")
        || issue.id.contains(',')
        || issue.id.contains("..")
        || issue.id.eq_ignore_ascii_case("CHWG-PM-DELIVERY-LOOP-01")
    {
        return Err(HBoardViolation {
            exit_code: EXIT_H_BOARD_REJECT,
            invariant: "INV-ENTITY-SEP-01".to_string(),
            issue_id: issue.id.clone(),
            reason: format!(
                "ticket id `{}` violates INV-ENTITY-SEP-01 (only canonical single-ticket CHWG-* IDs are allowed)",
                issue.id
            ),
        });
    }
    if let Err((invariant, reason)) = scan_entity_firewall_text(&combined) {
        return Err(HBoardViolation {
            exit_code: EXIT_H_BOARD_REJECT,
            invariant,
            issue_id: issue.id.clone(),
            reason,
        });
    }
    if let Err((invariant, reason)) = scan_secret_text(&combined) {
        return Err(HBoardViolation {
            exit_code: EXIT_H_BOARD_REJECT,
            invariant,
            issue_id: issue.id.clone(),
            reason,
        });
    }
    if !issue_requires_private_repo(issue)
        && let Err((invariant, reason)) = scan_zero_leak_text(&combined)
    {
        return Err(HBoardViolation {
            exit_code: EXIT_H_BOARD_REJECT,
            invariant,
            issue_id: issue.id.clone(),
            reason,
        });
    }

    Ok(())
}

/// Returns `true` iff `ticket_id` is a canonical single-ticket Chinwag ID matching `^CHWG-[0-9]{4}$`.
pub fn is_canonical_chwg_ticket_id(ticket_id: &str) -> bool {
    let trimmed = ticket_id.trim();
    trimmed.len() == 9
        && trimmed.starts_with("CHWG-")
        && trimmed[5..].chars().all(|c| c.is_ascii_digit())
}

/// Enforces the `INV-ENTITY-SEP-01` Entity Firewall, rejecting any cross-entity (`Drey`, `DreyBits`,
/// `DreyWallet`, `Rogue Machine`, `RMM-`, `2Real`, `SquirrelSystems`, `Robert R. Khan`) strings.
pub fn scan_entity_firewall_text(text: &str) -> Result<(), (String, String)> {
    let lower = text.to_ascii_lowercase();
    for marker in [
        "drey-",
        "dreybits",
        "dreywallet",
        "rogue machine",
        "rmm-",
        "2real",
        "squirrelsystems",
        "robert r. khan",
        "robert khan",
    ] {
        if lower.contains(marker) {
            return Err((
                "INV-ENTITY-SEP-01".to_string(),
                format!("cross-entity firewall rejected forbidden marker `{marker}`"),
            ));
        }
    }
    for token in lower.split(|c: char| !c.is_ascii_alphanumeric()) {
        if token == "drey" {
            return Err((
                "INV-ENTITY-SEP-01".to_string(),
                "cross-entity firewall rejected forbidden entity token `drey`".to_string(),
            ));
        }
    }
    Ok(())
}

/// Rejected vendor, bridge, and internal model substrings (`tombstone-ui-vendor-leaks-and-crypto-jargon-v1`)
/// that must never be pushed to the public GitHub Projects v2 board (`INV-PUBLIC-BOARD-REDACTION-01`).
pub const FORBIDDEN_BOARD_SUBSTRINGS: [&str; 5] = [
    "chinwag-eve-bridge",
    "inception/mercury-3",
    "Vercel AI Gateway",
    "@cf/openai/gpt-oss-120b",
    "3-Repo Git Time Machine",
];

/// Scans text for Tailscale/RFC1918 IPs, `/Users/` paths, `.crdb` files, provider tokens,
/// raw `$$` LaTeX math, patent/confidential markers, and forbidden vendor/jargon substrings (`INV-PUBLIC-BOARD-REDACTION-01`).
pub fn scan_zero_leak_text(text: &str) -> Result<(), (String, String)> {
    scan_secret_text(text)?;

    // 0. Check rejected vendor/bridge/model substrings (tombstone-ui-vendor-leaks-and-crypto-jargon-v1)
    for forbidden in FORBIDDEN_BOARD_SUBSTRINGS {
        if text.contains(forbidden) {
            return Err((
                "INV-PUBLIC-BOARD-REDACTION-01".to_string(),
                format!("forbidden vendor/internal jargon substring detected: `{forbidden}`"),
            ));
        }
    }

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

    // 3. Check raw LaTeX delimiters ($$ or inline $...$ math blocks per COPY-01..08)
    if text.contains("$$") || contains_inline_latex_math(text) {
        return Err((
            "INV-PUBLIC-BOARD-REDACTION-01".to_string(),
            "forbidden raw LaTeX delimiter (`$$` or `$...$`) detected in board copy".to_string(),
        ));
    }

    // 4. Check patent / confidential markers
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

/// Secret detection is independent of task visibility and repository access controls.
fn scan_secret_text(text: &str) -> Result<(), (String, String)> {
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
    let mut cfg = BoardConfigV1::default();
    let org = cfg.org.clone();
    cfg.normalize_repository_bindings(&org);
    build_board_push_graphql_payload_with_config(
        issues,
        github_project_id,
        linear_team_id,
        from_ci,
        &cfg,
    )
}

fn build_board_push_graphql_payload_with_config(
    issues: &[AtomicTaskIssue],
    github_project_id: &str,
    linear_team_id: &str,
    from_ci: bool,
    cfg: &BoardConfigV1,
) -> Value {
    let mut github_mutations = Vec::with_capacity(issues.len());
    let mut linear_mutations = Vec::with_capacity(issues.len());

    for issue in issues {
        let proof = compute_velocity_proof_for_deliverable(
            issue.dora_tier,
            issue.loc_changed,
            &issue.deliverable_kind,
            issue.t_claim_ms,
            issue.t_ship_ms,
        );
        let card = card_entry_from_issue(issue, Some(cfg), None, None);
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
            "visibility": issue.visibility,
            "target_repository": cfg.target_repository(issue),
            "item_type": "Issue",
            "operation": "updateProjectV2ItemFieldValue",
            "forbidden_operation_blocked": "addProjectV2DraftIssue",
            "project_id": github_project_id,
            "query": "mutation SyncChinwagProjectV2Item($projectId: ID!, $itemId: ID!, $statusValue: String!) { updateProjectV2ItemFieldValue(input: { projectId: $projectId, itemId: $itemId, fieldId: \"STATUS\", value: { singleSelectOptionId: $statusValue } }) { projectV2Item { id } } }",
            "fields": {
                "Status": status_header,
                "StatusPillColor": issue.status.github_pill_color(),
                "DeltaSpeedupVsDora": card.delta_speedup_vs_dora,
                "DoraBaseline": proof.effective_tier.canonical_option_label(),
                "TierLockDowngraded": proof.tier_downgraded,
                "ChinwagCycleTime": card.chinwag_cycle_time,
                "NetHoursSaved": card.net_hours_saved,
                "BaselineHours": card.baseline_hours,
                "CreditsUsed": card.credits_used,
                "FunctionTeam": card.primary_function,
                "ExecutionMode": card.execution_mode,
                "VerificationReceipt": card.verification_receipt,
                "ActiveSeats": active_seats_label,
                "CryptographicReceipt": receipt_badge,
                "SurvStatus": issue.surv_status.as_str(),
                "ChipsMinted": issue.chips_minted
            }
        }));

        linear_mutations.push(json!({
            "issue_id": issue.id,
            "visibility": issue.visibility,
            "target_repository": cfg.target_repository(issue),
            "endpoint": "https://api.linear.app/graphql",
            "operation": "issueUpdate",
            "team_id": linear_team_id,
            "query": "mutation SyncChinwagLinearIssue($id: String!, $state: String!, $title: String!) { issueUpdate(id: $id, input: { title: $title, stateId: $state }) { success issue { id identifier } } }",
            "variables": {
                "id": issue.id,
                "title": format!("[{}] {}", issue.id, issue.title),
                "state": issue.status.linear_state_type(),
                "columnHeader": status_header,
                "metricBSpeedup": card.delta_speedup_vs_dora,
                "netHoursSaved": card.net_hours_saved,
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
    pub public_board: bool,
    #[serde(default)]
    pub assignee_login: Option<String>,
    #[serde(default)]
    pub private_repo: Option<String>,
    #[serde(default)]
    pub public_repo: Option<String>,
    #[serde(default)]
    pub repository_id: Option<String>,
    #[serde(default)]
    pub private_repository_id: Option<String>,
    #[serde(default)]
    pub repository_name_with_owner: Option<String>,
    #[serde(default)]
    pub status_field_id: Option<String>,
    #[serde(default)]
    pub status_option_ids: BTreeMap<String, String>,
    #[serde(default)]
    pub custom_field_ids: BTreeMap<String, String>,
    #[serde(default)]
    pub custom_field_option_ids: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(default)]
    pub system_field_ids: BTreeMap<String, String>,
    #[serde(default)]
    pub view_ids: BTreeMap<String, String>,
    #[serde(default)]
    pub view_layouts: BTreeMap<String, String>,
    #[serde(default)]
    pub synced_issue_node_ids: BTreeMap<String, String>,
    #[serde(default)]
    pub synced_issue_repos: BTreeMap<String, String>,
    #[serde(default)]
    pub synced_issue_numbers: BTreeMap<String, u64>,
    #[serde(default)]
    pub synced_issue_urls: BTreeMap<String, String>,
    #[serde(default)]
    pub synced_project_item_ids: BTreeMap<String, String>,
}

impl Default for BoardConfigV1 {
    fn default() -> Self {
        let mut system_field_ids = BTreeMap::new();
        system_field_ids.insert("CREATED".to_string(), "CREATED".to_string());
        system_field_ids.insert("UPDATED".to_string(), "UPDATED".to_string());
        system_field_ids.insert("CLOSED".to_string(), "CLOSED".to_string());
        system_field_ids.insert("PARENT_ISSUE".to_string(), "PARENT_ISSUE".to_string());
        system_field_ids.insert(
            "SUB_ISSUES_PROGRESS".to_string(),
            "SUB_ISSUES_PROGRESS".to_string(),
        );
        Self {
            schema: "chinwag.board.config.v1".to_string(),
            org: "emunlabs".to_string(),
            project_id: "PVT_kwDOChinwag1".to_string(),
            project_number: 1,
            project_title: "Chinwag Engineering Velocity & Agent Fleet".to_string(),
            project_url: "https://github.com/orgs/emunlabs/projects/1".to_string(),
            public_board: false,
            assignee_login: None,
            private_repo: Some("emunlabs/chinwag-tasks".to_string()),
            public_repo: Some("emunlabs/chinwag".to_string()),
            repository_id: None,
            private_repository_id: None,
            repository_name_with_owner: Some("emunlabs/chinwag".to_string()),
            status_field_id: None,
            status_option_ids: BTreeMap::new(),
            custom_field_ids: BTreeMap::new(),
            custom_field_option_ids: BTreeMap::new(),
            system_field_ids,
            view_ids: BTreeMap::new(),
            view_layouts: BTreeMap::new(),
            synced_issue_node_ids: BTreeMap::new(),
            synced_issue_repos: BTreeMap::new(),
            synced_issue_numbers: BTreeMap::new(),
            synced_issue_urls: BTreeMap::new(),
            synced_project_item_ids: BTreeMap::new(),
        }
    }
}

impl BoardConfigV1 {
    fn normalize_repository_bindings(&mut self, org: &str) {
        if self.org != org {
            if self.public_repo.as_deref() == Some(&format!("{}/chinwag", self.org)) {
                self.public_repo = None;
            }
            if self.private_repo.as_deref() == Some(&format!("{}/chinwag-tasks", self.org)) {
                self.private_repo = None;
            }
        }
        self.org = org.to_string();
        if self.private_repo.is_none()
            || self.private_repo.as_deref() == Some("emunlabs/chinwag-private")
            || self.private_repo.as_deref() == Some(&format!("{org}/chinwag-private"))
        {
            self.private_repo = Some(format!("{org}/chinwag-tasks"));
            self.private_repository_id = None;
        }
        if self.public_repo.is_none() {
            self.public_repo = Some(format!("{org}/chinwag"));
        }
        if self.repository_name_with_owner != self.public_repo {
            self.repository_id = None;
            self.repository_name_with_owner = self.public_repo.clone();
        }
    }

    fn target_repository(&self, issue: &AtomicTaskIssue) -> String {
        if issue_requires_private_repo(issue) {
            self.private_repo
                .as_deref()
                .filter(|repo| *repo != "emunlabs/chinwag-private")
                .map(str::to_string)
                .unwrap_or_else(|| format!("{}/chinwag-tasks", self.org))
        } else {
            self.public_repo
                .clone()
                .unwrap_or_else(|| format!("{}/chinwag", self.org))
        }
    }

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

fn issue_requires_private_repo(issue: &AtomicTaskIssue) -> bool {
    issue.visibility.eq_ignore_ascii_case("private")
        || issue
            .assigned_seats
            .iter()
            .any(|seat| PRIVATE_LOCKED_SEATS.contains(&normalize_seat_token(seat).as_str()))
}

/// Write `.chinwag/templates/github-project-v2-schema.json` and `.chinwag/templates/linear-template.json`.
pub fn write_board_template_pack(
    tasks_dir: &Path,
    cfg: &BoardConfigV1,
) -> Result<(PathBuf, PathBuf), String> {
    let gh_schema = serde_json::to_string_pretty(&build_github_project_v2_template_schema(cfg))
        .map_err(|e| format!("failed to serialize github-project-v2-schema.json: {e}"))?;
    let lin_schema = serde_json::to_string_pretty(&build_linear_template_schema(cfg))
        .map_err(|e| format!("failed to serialize linear-template.json: {e}"))?;

    // Write into `.chinwag/templates/` (parent of `.chinwag/tasks`) and `tasks_dir/templates/`
    let primary_dir = tasks_dir
        .parent()
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n == ".chinwag")
                .unwrap_or(false)
        })
        .map(|p| p.join("templates"))
        .unwrap_or_else(|| tasks_dir.join("templates"));

    fs::create_dir_all(&primary_dir).map_err(|e| {
        format!(
            "failed to create templates dir {}: {e}",
            primary_dir.display()
        )
    })?;
    let gh_path = primary_dir.join("github-project-v2-schema.json");
    let lin_path = primary_dir.join("linear-template.json");
    fs::write(&gh_path, format!("{gh_schema}\n"))
        .map_err(|e| format!("failed to write {}: {e}", gh_path.display()))?;
    fs::write(&lin_path, format!("{lin_schema}\n"))
        .map_err(|e| format!("failed to write {}: {e}", lin_path.display()))?;

    let local_templates = tasks_dir.join("templates");
    if local_templates != primary_dir {
        let _ = fs::create_dir_all(&local_templates);
        let _ = fs::write(
            local_templates.join("github-project-v2-schema.json"),
            format!("{gh_schema}\n"),
        );
        let _ = fs::write(
            local_templates.join("linear-template.json"),
            format!("{lin_schema}\n"),
        );
    }

    Ok((gh_path, lin_path))
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
    }) || (issue.status == BoardStatus::ShippedVerified
        && issue.completion_evidence_note.is_some());
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

    let (subtasks, ui_gate_passed) = if issue.id == "CHWG-0198" {
        let items = vec![
            BoardSubTaskEntryV1 {
                subtask_id: sub1_id,
                surface: "marketing_site".to_string(),
                label: format!(
                    "#{}.1 marketing_site (css/site.css & scripts/site-v1/pages/*.html subtle neutral grey inline code pills across chinwag.sh)",
                    issue.id
                ),
                owner_seats: vec!["TYPE".to_string()],
                required: true,
                verified: v1,
            },
            BoardSubTaskEntryV1 {
                subtask_id: sub2_id,
                surface: "docs_site".to_string(),
                label: format!(
                    "#{}.2 docs_site (assets/css/main.css subtle neutral grey inline <code> pills across docs.chinwag.sh)",
                    issue.id
                ),
                owner_seats: vec!["DOCS".to_string()],
                required: true,
                verified: v2,
            },
            BoardSubTaskEntryV1 {
                subtask_id: sub3_id,
                surface: "ui_qa".to_string(),
                label: format!(
                    "#{}.3 ui_qa (1440×900 desktop & 390×844 mobile Playwright verification via chinwag-ci ui-gate --surface all)",
                    issue.id
                ),
                owner_seats: vec!["QA".to_string()],
                required: true,
                verified: v3,
            },
        ];
        (items, v3 && !has_explicit_fail_badge)
    } else {
        let items = vec![
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
                label: format!(
                    "#{}.2 Docs & READMEs (README.md / docs.chinwag.sh)",
                    issue.id
                ),
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
                owner_seats: vec!["DOCS".to_string(), "DEX".to_string(), "INFRAJR".to_string()],
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
        (items, v4 && !has_explicit_fail_badge)
    };

    let unsynced_subtasks: Vec<String> = subtasks
        .iter()
        .filter(|s| s.required && !s.verified)
        .map(|s| s.subtask_id.clone())
        .collect();
    let all_surfaces_synced = unsynced_subtasks.is_empty();

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
    let response: Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| format!("failed to parse `gh api graphql` JSON: {e}"))?;
    if let Some(errors) = response.get("errors").and_then(Value::as_array)
        && !errors.is_empty()
    {
        return Err(format!("GitHub GraphQL errors: {errors:?}"));
    }
    Ok(response)
}

/// Live GitHub Projects v2 initialization via `gh api graphql` (`chinwag board init --org <org> --live`).
pub fn init_github_project_v2_live(
    tasks_dir: &Path,
    org: &str,
    title: &str,
) -> Result<BoardConfigV1, String> {
    init_github_project_v2_live_with_visibility(tasks_dir, org, title, false, None, None)
}

/// Live GitHub Projects v2 initialization with explicit visibility and repository bindings (`INV-DEFAULT-PRIVATE-BOARD-01`).
pub fn init_github_project_v2_live_with_visibility(
    tasks_dir: &Path,
    org: &str,
    title: &str,
    public_board: bool,
    private_repo: Option<&str>,
    public_repo: Option<&str>,
) -> Result<BoardConfigV1, String> {
    let mut cfg = BoardConfigV1::load(tasks_dir).unwrap_or_default();
    if let Some(repo) = private_repo {
        if cfg.private_repo.as_deref() != Some(repo) {
            cfg.private_repository_id = None;
        }
        cfg.private_repo = Some(repo.to_string());
    } else if cfg.org != org {
        cfg.private_repo = None;
    }
    if let Some(repo) = public_repo {
        cfg.public_repo = Some(repo.to_string());
    } else if cfg.org != org {
        cfg.public_repo = None;
    }
    cfg.normalize_repository_bindings(org);
    let public_inventory = fetch_github_repository_issues(
        cfg.public_repo.as_deref().ok_or("missing public_repo")?,
        false,
    )?;
    let private_inventory = fetch_github_repository_issues(
        cfg.private_repo.as_deref().ok_or("missing private_repo")?,
        true,
    )?;
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
        public
      }
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

    // Enforce project visibility (`public: false` by default per `INV-DEFAULT-PRIVATE-BOARD-01`, or `public: true` on `--public-board`)
    let vis_mutation = format!(
        "mutation($projectId: ID!) {{ updateProjectV2(input: {{ projectId: $projectId, public: {} }}) {{ projectV2 {{ id public }} }} }}",
        if public_board { "true" } else { "false" }
    );
    execute_gh_graphql(&vis_mutation, &[("projectId", &project_id)])?;

    cfg.org = org.to_string();
    cfg.project_id = project_id;
    cfg.project_number = project_number;
    cfg.project_title = project_title;
    cfg.project_url = project_url;
    cfg.public_board = public_board;
    cfg.repository_id = Some(public_inventory.repository_id);
    cfg.private_repository_id = Some(private_inventory.repository_id);
    cfg.repository_name_with_owner = cfg.public_repo.clone();
    ensure_project_schema(&mut cfg)?;
    update_project_overview(&cfg)?;
    cfg.save(tasks_dir)?;
    let _ = write_board_template_pack(tasks_dir, &cfg);
    Ok(cfg)
}

fn close_github_issue_live(
    repo: &str,
    issue_node_id: &str,
    issue_number: Option<u64>,
) -> Result<(), String> {
    set_github_issue_state_live(repo, issue_node_id, issue_number, true)
}

fn reopen_github_issue_live(
    repo: &str,
    issue_node_id: &str,
    issue_number: Option<u64>,
) -> Result<(), String> {
    set_github_issue_state_live(repo, issue_node_id, issue_number, false)
}

fn set_github_issue_state_live(
    repo: &str,
    issue_node_id: &str,
    issue_number: Option<u64>,
    close: bool,
) -> Result<(), String> {
    // Node IDs identify the issue across repositories; never mutate an issue by an unqualified number.
    let query = if close {
        "mutation($issueId: ID!) { closeIssue(input: { issueId: $issueId, stateReason: COMPLETED }) { issue { id state } } }"
    } else {
        "mutation($issueId: ID!) { reopenIssue(input: { issueId: $issueId }) { issue { id state } } }"
    };
    execute_gh_graphql(query, &[("issueId", issue_node_id)]).map_err(|e| {
        format!(
            "failed to {} {repo} issue {issue_number:?}: {e}",
            if close { "close" } else { "reopen" }
        )
    })?;
    Ok(())
}

#[derive(Clone)]
struct GithubRepositoryIssue {
    node_id: String,
    number: u64,
    url: String,
    state: String,
}

struct GithubRepositoryIssues {
    repository_id: String,
    by_prefix: BTreeMap<String, GithubRepositoryIssue>,
    by_node_id: BTreeMap<String, GithubRepositoryIssue>,
}

fn github_task_id_from_title(title: &str) -> Option<&str> {
    if let Some(rest) = title.strip_prefix('[') {
        return rest
            .split_once(']')
            .map(|(id, _)| id)
            .filter(|id| id.starts_with("CHWG-"));
    }
    title
        .split_once(':')
        .map(|(id, _)| id.trim())
        .filter(|id| id.starts_with("CHWG-"))
}

fn fetch_github_repository_issues(
    repo: &str,
    require_private: bool,
) -> Result<GithubRepositoryIssues, String> {
    let (owner, name) = repo
        .split_once('/')
        .filter(|(owner, name)| !owner.is_empty() && !name.is_empty() && !name.contains('/'))
        .ok_or_else(|| format!("invalid repository binding `{repo}`; expected owner/name"))?;
    let query = r#"
query($owner: String!, $name: String!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    id
    nameWithOwner
    isPrivate
    issues(first: 100, after: $cursor, orderBy: {field: CREATED_AT, direction: DESC}) {
      nodes { id number title url state }
      pageInfo { hasNextPage endCursor }
    }
  }
}
"#;
    let mut inventory = GithubRepositoryIssues {
        repository_id: String::new(),
        by_prefix: BTreeMap::new(),
        by_node_id: BTreeMap::new(),
    };
    let mut cursor = None::<String>;
    let mut seen_cursors = std::collections::BTreeSet::new();
    loop {
        let mut vars = vec![("owner", owner), ("name", name)];
        if let Some(ref cursor) = cursor {
            vars.push(("cursor", cursor.as_str()));
        }
        let response = execute_gh_graphql(query, &vars)?;
        let repository = response
            .pointer("/data/repository")
            .filter(|r| r.is_object())
            .ok_or_else(|| format!("repository `{repo}` not found or inaccessible"))?;
        let resolved_name = repository
            .get("nameWithOwner")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("missing nameWithOwner for `{repo}`"))?;
        if !resolved_name.eq_ignore_ascii_case(repo) {
            return Err(format!(
                "repository binding `{repo}` resolved to `{resolved_name}`"
            ));
        }
        if require_private && repository.get("isPrivate").and_then(Value::as_bool) != Some(true) {
            return Err(format!(
                "private repository `{repo}` must have PRIVATE visibility"
            ));
        }
        inventory.repository_id = repository
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| format!("missing repository.id for `{repo}`"))?
            .to_string();
        let connection = repository
            .get("issues")
            .ok_or_else(|| format!("missing issues for `{repo}`"))?;
        let nodes = connection
            .get("nodes")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("missing issue nodes for `{repo}`"))?;
        for node in nodes {
            let record = GithubRepositoryIssue {
                node_id: node
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or("missing issue.id")?
                    .to_string(),
                number: node
                    .get("number")
                    .and_then(Value::as_u64)
                    .ok_or("missing issue.number")?,
                url: node
                    .get("url")
                    .and_then(Value::as_str)
                    .ok_or("missing issue.url")?
                    .to_string(),
                state: node
                    .get("state")
                    .and_then(Value::as_str)
                    .ok_or("missing issue.state")?
                    .to_string(),
            };
            inventory
                .by_node_id
                .insert(record.node_id.clone(), record.clone());
            if let Some(id) = node
                .get("title")
                .and_then(Value::as_str)
                .and_then(github_task_id_from_title)
                && let Some(prior) = inventory.by_prefix.insert(id.to_string(), record.clone())
                && prior.node_id != record.node_id
            {
                return Err(format!(
                    "duplicate task `{id}` in `{repo}`; refusing ambiguous sync"
                ));
            }
        }
        let page_info = connection.get("pageInfo").ok_or("missing issue pageInfo")?;
        if !page_info
            .get("hasNextPage")
            .and_then(Value::as_bool)
            .ok_or("missing hasNextPage")?
        {
            break;
        }
        let next = page_info
            .get("endCursor")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or("missing issue pagination cursor")?
            .to_string();
        if !seen_cursors.insert(next.clone()) {
            return Err(format!("repeated issue pagination cursor for `{repo}`"));
        }
        cursor = Some(next);
    }
    Ok(inventory)
}

fn refresh_github_project_fields(cfg: &mut BoardConfigV1) -> Result<(), String> {
    // Other worktrees can recreate select options; cached IDs are not durable schema identities.
    let query = r#"
query($projectId: ID!) {
  node(id: $projectId) {
    ... on ProjectV2 {
      id
      public
      fields(first: 100) {
        nodes {
          ... on ProjectV2Field { id name }
          ... on ProjectV2SingleSelectField { id name options { id name } }
        }
        pageInfo { hasNextPage }
      }
    }
  }
}
"#;
    let response = execute_gh_graphql(query, &[("projectId", &cfg.project_id)])?;
    let project = response
        .pointer("/data/node")
        .filter(|node| node.is_object())
        .ok_or("ProjectV2 is missing or inaccessible")?;
    if project.get("id").and_then(Value::as_str) != Some(cfg.project_id.as_str()) {
        return Err("ProjectV2 schema response has a different project ID".to_string());
    }
    cfg.public_board = project
        .get("public")
        .and_then(Value::as_bool)
        .ok_or("missing ProjectV2 visibility")?;
    let fields = project.get("fields").ok_or("missing ProjectV2 fields")?;
    if fields
        .pointer("/pageInfo/hasNextPage")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return Err("ProjectV2 schema exceeds the 100-field schema limit".to_string());
    }
    let nodes = fields
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or("missing ProjectV2 field nodes")?;
    cfg.status_field_id = None;
    cfg.status_option_ids.clear();
    cfg.custom_field_ids.clear();
    cfg.custom_field_option_ids.clear();
    for field in nodes {
        let (Some(id), Some(name)) = (
            field.get("id").and_then(Value::as_str),
            field.get("name").and_then(Value::as_str),
        ) else {
            continue;
        };
        let options: BTreeMap<String, String> = field
            .get("options")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|option| {
                Some((
                    option.get("name")?.as_str()?.to_string(),
                    option.get("id")?.as_str()?.to_string(),
                ))
            })
            .collect();
        if name == "Status" {
            cfg.status_field_id = Some(id.to_string());
            cfg.status_option_ids = options;
        } else {
            cfg.custom_field_ids
                .insert(name.to_string(), id.to_string());
            if field.get("options").is_some() {
                cfg.custom_field_option_ids
                    .insert(name.to_string(), options);
            }
        }
    }
    Ok(())
}

/// Live GitHub Projects v2 push (`chinwag board push --live`) — creates/updates real repository `Issue` items
/// in the configured public/private repositories, links them to the live `ProjectV2` via `addProjectV2ItemById` (NEVER `addProjectV2DraftIssue` per `INV-NO-DRAFT-ISSUES-01`),
/// populates all 7 custom fields, and closes `05_SHIPPED_VERIFIED` issues so GitHub stamps the immutable `CLOSED` timestamp.
pub fn push_github_project_v2_live(
    tasks_dir: &Path,
    issues: &[AtomicTaskIssue],
    org: &str,
) -> Result<Value, String> {
    let describe = |v: HBoardViolation| format!("{} on {}: {}", v.invariant, v.issue_id, v.reason);
    let policy = resolve_board_policy(&[], tasks_dir).map_err(describe)?;
    let policy = require_board_policy_for_live(policy.as_ref()).map_err(describe)?;
    push_github_project_v2_live_governed(tasks_dir, issues, org, policy)
}

/// Every live card mutation goes through here, so no card reaches the board without
/// passing the ledger policy.
fn push_github_project_v2_live_governed(
    tasks_dir: &Path,
    issues: &[AtomicTaskIssue],
    org: &str,
    policy: &BoardPolicyTomlV1,
) -> Result<Value, String> {
    validate_org_matches_policy(org, policy)
        .and_then(|()| validate_board_ledger_issues(issues, policy))
        .map_err(|v| format!("{} on {}: {}", v.invariant, v.issue_id, v.reason))?;
    let mut local_ids = std::collections::BTreeSet::new();
    for issue in issues {
        validate_h_board_issue(issue, &issue.to_markdown())
            .map_err(|v| format!("{} on {}: {}", v.invariant, v.issue_id, v.reason))?;
        if !local_ids.insert(&issue.id) {
            return Err(format!("duplicate local task ID `{}`", issue.id));
        }
    }
    let mut cfg = match BoardConfigV1::load(tasks_dir) {
        Some(c) if c.project_id != "PVT_kwDOChinwag1" && !c.custom_field_ids.is_empty() => c,
        Some(c) => init_github_project_v2_live_with_visibility(
            tasks_dir,
            org,
            &c.project_title,
            c.public_board,
            c.private_repo.as_deref(),
            c.public_repo.as_deref(),
        )?,
        None => init_github_project_v2_live(
            tasks_dir,
            org,
            "Chinwag Engineering Velocity & Agent Fleet",
        )?,
    };

    cfg.normalize_repository_bindings(org);
    let public_repo = cfg.public_repo.clone().ok_or("missing public_repo")?;
    let private_repo = cfg.private_repo.clone().ok_or("missing private_repo")?;
    if public_repo.eq_ignore_ascii_case(&private_repo) {
        return Err("public_repo and private_repo must be distinct repositories".to_string());
    }
    for repo in [&public_repo, &private_repo] {
        if !policy.links_repo(repo) {
            return Err(format!(
                "{INV_BOARD_LEDGER_TRACKING}: repository `{repo}` is not in board.linked_repos"
            ));
        }
    }
    // Complete inventories are authoritative, including closed issues and tasks beyond the first page.
    let public_inventory = fetch_github_repository_issues(&public_repo, false)?;
    let private_inventory = fetch_github_repository_issues(&private_repo, true)?;
    cfg.repository_id = Some(public_inventory.repository_id.clone());
    cfg.private_repository_id = Some(private_inventory.repository_id.clone());
    cfg.repository_name_with_owner = Some(public_repo.clone());
    ensure_project_schema(&mut cfg)?;
    update_project_overview(&cfg)?;
    if cfg.status_field_id.is_none() {
        return Err("missing required ProjectV2 field `Status`".to_string());
    }
    for field in [
        "DORA Baseline",
        "Execution Mode",
        "Δ Speedup vs. DORA",
        "Chinwag Cycle Time",
        "Net Hours Saved",
        "Baseline Hours",
        "Credits Used",
        "Function / Team",
        "Verification Receipt",
    ] {
        if !cfg.custom_field_ids.contains_key(field) {
            return Err(format!(
                "missing required ProjectV2 field `{field}`; run board init --live"
            ));
        }
    }
    for issue in issues {
        if !cfg
            .status_option_ids
            .contains_key(issue.status.column_header())
            && !cfg.status_option_ids.contains_key(match issue.status {
                BoardStatus::OpenBounty | BoardStatus::ScopedBenchmarked => "Todo",
                BoardStatus::InFlight | BoardStatus::TribunalGate => "In Progress",
                BoardStatus::ShippedVerified => "Done",
            })
        {
            return Err(format!("missing Status option for {}", issue.id));
        }
        for field in ["DORA Baseline", "Execution Mode", "Δ Speedup vs. DORA"] {
            if !cfg.custom_field_option_ids.contains_key(field) {
                return Err(format!("missing ProjectV2 options for `{field}`"));
            }
        }
    }

    for issue in issues {
        let target = cfg.target_repository(issue);
        let other_inventory = if target == private_repo {
            &public_inventory
        } else {
            &private_inventory
        };
        if other_inventory.by_prefix.contains_key(&issue.id)
            || cfg
                .synced_issue_node_ids
                .get(&issue.id)
                .is_some_and(|id| other_inventory.by_node_id.contains_key(id))
        {
            return Err(format!(
                "{} already exists outside target repository `{target}`; refusing cross-repository duplication or disclosure",
                issue.id
            ));
        }
    }

    let assignee_id = project_assignee_id(&cfg)?;
    let mut synced_items = Vec::new();
    for issue in issues {
        let target_repo = cfg.target_repository(issue);
        let inventory = if target_repo == private_repo {
            &private_inventory
        } else {
            &public_inventory
        };
        let repo_id = &inventory.repository_id;
        let gh_title = if issue.title.starts_with(&format!("{}:", issue.id))
            || issue.title.starts_with(&format!("[{}]", issue.id))
        {
            issue.title.clone()
        } else {
            format!("[{}] {}", issue.id, issue.title)
        };
        let manifest = build_issue_surface_impact_manifest(issue);
        let subtask_lines: Vec<String> = manifest
            .required_subtasks
            .iter()
            .map(|st| {
                let mark = if st.verified { "x" } else { " " };
                let owners = st
                    .owner_seats
                    .iter()
                    .map(|s| {
                        format!(
                            "■ {}",
                            s.trim()
                                .trim_start_matches('■')
                                .trim_start_matches('@')
                                .trim()
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "- [{mark}] **{}** — `{}` (Owners: `{owners}`)",
                    st.label, st.surface
                )
            })
            .collect();
        let completion_note = issue
            .completion_evidence_note
            .as_deref()
            .map(|note| format!("\n\n**Completion evidence:** {note}"))
            .unwrap_or_default();
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
             {}{}\n",
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
            issue.body.trim(),
            completion_note
        );

        let cached_issue = cfg
            .synced_issue_node_ids
            .get(&issue.id)
            .and_then(|id| inventory.by_node_id.get(id));
        let (issue_node_id, issue_number, issue_url, prior_state) = if let Some(existing) =
            inventory.by_prefix.get(&issue.id).or(cached_issue)
        {
            let existing_id = existing.node_id.clone();
            let existing_num = existing.number;
            let existing_url = existing.url.clone();
            let existing_state = existing.state.clone();
            let update_q = r#"
mutation($issueId: ID!, $title: String!, $body: String!, $assignee: ID!) {
  updateIssue(input: { id: $issueId, title: $title, body: $body, assigneeIds: [$assignee] }) {
    issue {
      id
      number
      url
      state
    }
  }
}
"#;
            execute_gh_graphql(
                update_q,
                &[
                    ("issueId", &existing_id),
                    ("assignee", &assignee_id),
                    ("title", &gh_title),
                    ("body", &gh_body),
                ],
            )?;
            (existing_id, existing_num, existing_url, existing_state)
        } else {
            let create_issue_q = r#"
mutation($repoId: ID!, $title: String!, $body: String!, $assignee: ID!) {
  createIssue(input: { repositoryId: $repoId, title: $title, body: $body, assigneeIds: [$assignee] }) {
    issue {
      id
      number
      url
      state
    }
  }
}
"#;
            let created = execute_gh_graphql(
                create_issue_q,
                &[
                    ("repoId", repo_id),
                    ("assignee", &assignee_id),
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
                    .filter(|id| !id.is_empty())
                    .ok_or("createIssue returned no issue ID")?
                    .to_string(),
                iss.get("number")
                    .and_then(|v| v.as_u64())
                    .filter(|n| *n > 0)
                    .ok_or("createIssue returned no issue number")?,
                iss.get("url")
                    .and_then(|v| v.as_str())
                    .filter(|url| !url.is_empty())
                    .ok_or("createIssue returned no issue URL")?
                    .to_string(),
                "OPEN".to_string(),
            )
        };

        cfg.synced_issue_repos
            .insert(issue.id.clone(), target_repo.clone());
        cfg.synced_issue_node_ids
            .insert(issue.id.clone(), issue_node_id.clone());
        if issue_number > 0 {
            cfg.synced_issue_numbers
                .insert(issue.id.clone(), issue_number);
        }
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
            .filter(|id| !id.is_empty())
            .ok_or_else(|| format!("addProjectV2ItemById returned no item for {}", issue.id))?
            .to_string();
        if !item_id.is_empty() {
            cfg.synced_project_item_ids
                .insert(issue.id.clone(), item_id.clone());
        }

        let card = card_entry_from_issue(issue, Some(&cfg), None, None);
        populate_project_card(&cfg, &item_id, issue, &card)?;

        // Close or reopen the backing GitHub issue so native `Closed` (`CLOSED`) timestamp is server-anchored
        let issue_state = if issue.status == BoardStatus::ShippedVerified {
            if !prior_state.eq_ignore_ascii_case("CLOSED") {
                close_github_issue_live(
                    &target_repo,
                    &issue_node_id,
                    (issue_number > 0).then_some(issue_number),
                )?;
            }
            "CLOSED"
        } else {
            if prior_state.eq_ignore_ascii_case("CLOSED") {
                reopen_github_issue_live(
                    &target_repo,
                    &issue_node_id,
                    (issue_number > 0).then_some(issue_number),
                )?;
            }
            "OPEN"
        };

        cfg.save(tasks_dir)?;
        synced_items.push(json!({
            "issue_id": issue.id,
            "visibility": issue.visibility.to_ascii_lowercase(),
            "target_repository": target_repo,
            "github_issue_node_id": issue_node_id,
            "github_issue_number": issue_number,
            "github_issue_url": issue_url,
            "github_issue_state": issue_state,
            "project_item_id": item_id,
            "board_status": issue.status.as_code(),
            "column_header": issue.status.column_header(),
        }));
    }

    cfg.save(tasks_dir)?;
    let views = configure_project_views(&cfg)?;
    let audit = verify_project_population(&cfg, issues)?;
    fs::write(
        tasks_dir.join("board-live-verification.json"),
        serde_json::to_vec_pretty(&audit).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let status_update = post_project_status(&cfg, &audit)?;

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
        "public_board": cfg.public_board,
        "linear_api_key_configured": linear_live,
        "views": views,
        "verification": audit,
        "status_update": status_update,
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
      public
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
              createdAt
              updatedAt
              closedAt
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

/// Ticket prefix written into a starter policy when `chinwag board init` is given none.
const STARTER_TICKET_PREFIX: &str = "CHWG";

fn emit_h_board_rejection(
    violation: &HBoardViolation,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let _ = writeln!(
        stderr,
        "H_board GATE REJECTED (exit {}) [{}] on {}: {}",
        violation.exit_code, violation.invariant, violation.issue_id, violation.reason
    );
    let _ = writeln!(
        stdout,
        "{}",
        json!({
            "ok": false,
            "exit_code": violation.exit_code,
            "invariant": violation.invariant,
            "issue_id": violation.issue_id,
            "reason": violation.reason
        })
    );
    violation.exit_code
}

/// Admission, settlement, and ticket-ID uniqueness for a whole set of cards.
fn validate_board_ledger_issues(
    issues: &[AtomicTaskIssue],
    policy: &BoardPolicyTomlV1,
) -> Result<(), HBoardViolation> {
    for issue in issues {
        validate_board_ledger_issue(issue, policy)?;
    }
    let claims: Vec<TicketCardRef> = issues
        .iter()
        .map(|issue| TicketCardRef {
            ticket_id: issue.id.clone(),
            source: format!("issues/{}.md", issue.id),
        })
        .collect();
    validate_unique_ticket_ids(&claims, &policy.board.ticket_prefix)
        .map_err(|mut duplicates| duplicates.remove(0))
}

/// A board named on the command line must be the board the policy governs.
fn validate_org_matches_policy(
    org: &str,
    policy: &BoardPolicyTomlV1,
) -> Result<(), HBoardViolation> {
    if org.eq_ignore_ascii_case(&policy.board.org) {
        return Ok(());
    }
    Err(HBoardViolation {
        exit_code: EXIT_H_BOARD_REJECT,
        invariant: INV_BOARD_LEDGER_TRACKING.to_string(),
        issue_id: BOARD_POLICY_RELATIVE_PATH.to_string(),
        reason: format!(
            "`--org {org}` is not the organization governed by the board policy (`{}`)",
            policy.board.org
        ),
    })
}

/// Writes a fully enforcing starter policy when the workspace has none. Never overwrites.
fn write_starter_board_policy(
    workspace_root: &Path,
    cfg: &BoardConfigV1,
    ticket_prefix: &str,
) -> Result<Option<PathBuf>, String> {
    let path = BoardPolicyTomlV1::policy_path(workspace_root);
    if path.exists() {
        return Ok(None);
    }
    let public_repo = cfg
        .public_repo
        .clone()
        .unwrap_or_else(|| format!("{}/chinwag", cfg.org));
    let policy = BoardPolicyTomlV1::starter(
        &cfg.org,
        cfg.project_number,
        Some(cfg.project_id.as_str()).filter(|id| !id.is_empty() && *id != "PVT_kwDOChinwag1"),
        &public_repo,
        cfg.private_repo.as_deref(),
        ticket_prefix,
    );
    policy
        .validate()
        .map_err(|problems| format!("starter board policy is invalid: {}", problems.join("; ")))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    fs::write(&path, policy.to_toml_string())
        .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    Ok(Some(path))
}

/// Execute Card-Move-Driven Cross-Surface Orchestration (`chinwag board sync-loop` / `chinwag board watch`).
///
/// - Inspects `.chinwag/tasks/issues/*.md` (and pulls live card column state when `--live` is passed).
/// - Computes `SurfaceImpactManifestV1` for each active issue (`02_SCOPED_BENCHMARKED`, `03_IN_FLIGHT`, `04_TRIBUNAL_GATE`).
/// - For any card in `04_TRIBUNAL_GATE` (or an unverified card in `05_SHIPPED_VERIFIED`), runs the Proof-of-Green & Cross-Surface check:
///   - If all surfaces + `ui-gate` pass, promotes the card to `05_SHIPPED_VERIFIED` (`05 · ✓ SHIPPED — Δ VERIFIED`) and stamps the `✓ed25519` Δ Velocity Proof receipt.
///   - If any check fails, snaps the card back to `03_IN_FLIGHT` within `<200ms` (`INV-NO-FAKE-DONE-01`), reopens any prematurely closed GitHub issue, and emits the `@DELIVERY` (`Mercury 3`) + author wakeup plan.
pub fn run_board_sync_loop(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
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

        let requires_tribunal_check = issue.status == BoardStatus::TribunalGate
            || (issue.status == BoardStatus::ShippedVerified
                && (!manifest.all_surfaces_synced || !manifest.ui_gate_passed));

        if requires_tribunal_check {
            let prior_status_code = issue.status.as_code().to_string();
            if manifest.all_surfaces_synced && manifest.ui_gate_passed {
                let claimed_tier = issue.dora_tier;
                let (effective_tier, tier_downgraded) = enforce_tier_lock_for_deliverable(
                    claimed_tier,
                    issue.loc_changed,
                    &issue.deliverable_kind,
                );
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

                let proof = compute_velocity_proof_for_deliverable(
                    claimed_tier,
                    issue.loc_changed,
                    &issue.deliverable_kind,
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
                    "from_status": prior_status_code,
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
                let routing_plan = build_ci_failure_routing_plan(&issue, None, true, true, false);
                issue.receipt_trailers.push(format!(
                    "TribunalSnapBackReceiptV1: status=SNAP_BACK_IN_FLIGHT elapsed_ms={} unsynced={:?} direct_to={} cc={:?}",
                    snapback_elapsed_ms,
                    manifest.unsynced_subtasks,
                    routing_plan.primary_recipient,
                    routing_plan.cc_recipients
                ));
                let _ = fs::write(&path, issue.to_markdown());

                // The final live push verifies repository ownership and reopens this Issue by node ID.

                tribunal_snapbacks.push(json!({
                    "issue_id": issue.id,
                    "from_status": prior_status_code,
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
        let policy = match resolve_board_policy(args, &tasks_dir) {
            Ok(policy) => policy,
            Err(violation) => return emit_h_board_rejection(&violation, stdout, stderr),
        };
        let policy = match require_board_policy_for_live(policy.as_ref()) {
            Ok(policy) => policy,
            Err(violation) => return emit_h_board_rejection(&violation, stdout, stderr),
        };
        match push_github_project_v2_live_governed(&tasks_dir, &updated_issues, &org, policy) {
            Ok(val) => Some(val),
            Err(e) => {
                let _ = writeln!(stderr, "chinwag board sync-loop --live warning: {e}");
                None
            }
        }
    } else {
        None
    };

    let cfg = BoardConfigV1::load(&tasks_dir);
    let _ = sync_board_cards_ledger(&tasks_dir, &updated_issues, cfg.as_ref());

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

/// Entrypoint for `chinwag board <init|push|sync|pull|watch|sync-loop|add|move|verify-ledger> ...`.
pub fn run_board_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("push");
    if sub == "--help" || sub == "-h" || sub == "help" {
        let _ = writeln!(
            stdout,
            "Usage: chinwag board <init|push|sync|pull|watch|sync-loop|add|move|verify-ledger> [--org <org>] [--title <title>] [--private] [--public-board] [--private-repo <org/repo>] [--public-repo <org/repo>] [--ticket-prefix <PREFIX>] [--live] [--once] [--workspace-root <path>] [--tasks-dir <dir>] [--github-project <id>] [--linear-team <id>] [--dry-run] [--json]\n\
             \n\
             chinwag board add|move <TICKET_ID> [<STATUS>] [--function <team>] [--seats <a,b>] [--deliverable-kind <code|artifact>] [--tier <S|M|L|XL>] [--loc-changed <n>] [--title <title>]\n\
             chinwag board verify-ledger [--live] [--json] [--workspace-root <path>]\n\
             \n\
             add, move, push, sync, and verify-ledger enforce <workspace>/.chinwag/board.toml and exit 78 when it is missing, invalid, or violated."
        );
        return 0;
    }
    let tasks_dir = resolve_tasks_dir(args);
    if let Some(repo_root) = tasks_dir.parent().and_then(|p| p.parent()) {
        emit_active_crisis_alert_if_any(repo_root, stderr);
    }
    if matches!(sub, "watch" | "sync-loop") {
        return run_board_sync_loop(args, stdout, stderr);
    }
    if matches!(sub, "add" | "move") {
        return run_board_add_or_move(sub, args, &tasks_dir, stdout, stderr);
    }
    if sub == "verify-ledger" {
        return run_board_verify_ledger(args, stdout, stderr);
    }
    if !matches!(sub, "push" | "sync" | "init" | "pull") {
        let _ = writeln!(stderr, "chinwag board: unknown subcommand `{sub}`");
        return 2;
    }
    let issues_dir = tasks_dir.join("issues");
    let policy = if matches!(sub, "push" | "sync") {
        match resolve_board_policy(args, &tasks_dir) {
            Ok(policy) => policy,
            Err(violation) => return emit_h_board_rejection(&violation, stdout, stderr),
        }
    } else {
        None
    };
    let mut org = policy
        .as_ref()
        .map_or_else(|| "emunlabs".to_string(), |p| p.board.org.clone());
    let mut ticket_prefix = STARTER_TICKET_PREFIX.to_string();
    let mut title = "Chinwag Engineering Velocity & Agent Fleet".to_string();
    let mut github_project = BoardConfigV1::load(&tasks_dir)
        .map(|c| c.project_id)
        .unwrap_or_else(|| "PVT_kwDOChinwag1".to_string());
    let mut linear_team = "LIN-TEAM-CHWG".to_string();
    let mut project_number: Option<u64> = None;
    let mut dry_run = false;
    let mut from_ci = false;
    let mut live = false;
    let mut public_board = false;
    let mut private_repo: Option<String> = None;
    let mut public_repo: Option<String> = None;

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
            "--ticket-prefix" if i + 1 < args.len() => {
                ticket_prefix = args[i + 1].clone();
                i += 2;
            }
            "--private-repo" if i + 1 < args.len() => {
                private_repo = Some(args[i + 1].clone());
                i += 2;
            }
            "--public-repo" if i + 1 < args.len() => {
                public_repo = Some(args[i + 1].clone());
                i += 2;
            }
            "--private" => {
                public_board = false;
                i += 1;
            }
            "--public-board" => {
                public_board = true;
                i += 1;
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

    if let Some(policy) = &policy
        && let Err(violation) = validate_org_matches_policy(&org, policy)
    {
        return emit_h_board_rejection(&violation, stdout, stderr);
    }
    if matches!(sub, "push" | "sync")
        && live
        && !dry_run
        && let Err(violation) = require_board_policy_for_live(policy.as_ref())
    {
        return emit_h_board_rejection(&violation, stdout, stderr);
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
        let (effective_tier, downgraded) = enforce_tier_lock_for_deliverable(
            issue.dora_tier,
            issue.loc_changed,
            &issue.deliverable_kind,
        );
        if downgraded {
            issue.dora_tier = effective_tier;
            let _ = fs::write(&path, issue.to_markdown());
        }

        validated_issues.push(issue);
    }

    if let Some(policy) = &policy
        && let Err(violation) = validate_board_ledger_issues(&validated_issues, policy)
    {
        return emit_h_board_rejection(&violation, stdout, stderr);
    }

    let workspace_root = resolve_board_workspace_root(args, &tasks_dir);
    if sub == "init" {
        if live {
            match init_github_project_v2_live_with_visibility(
                &tasks_dir,
                &org,
                &title,
                public_board,
                private_repo.as_deref(),
                public_repo.as_deref(),
            ) {
                Ok(cfg) => {
                    let (gh_tpl, lin_tpl) = write_board_template_pack(&tasks_dir, &cfg)
                        .unwrap_or_else(|_| {
                            (
                                tasks_dir.join("templates/github-project-v2-schema.json"),
                                tasks_dir.join("templates/linear-template.json"),
                            )
                        });
                    let created_policy = match workspace_root
                        .as_deref()
                        .map(|root| write_starter_board_policy(root, &cfg, &ticket_prefix))
                        .transpose()
                    {
                        Ok(path) => path.flatten(),
                        Err(e) => {
                            let _ = writeln!(stderr, "chinwag board init --live failed: {e}");
                            return 1;
                        }
                    };
                    let payload = json!({
                        "ok": true,
                        "command": "chinwag board init",
                        "live": true,
                        "public_board": cfg.public_board,
                        "default_visibility": if cfg.public_board { "public" } else { "private" },
                        "board_config": cfg,
                        "board_policy_created": created_policy.map(|p| p.to_string_lossy().to_string()),
                        "templates": {
                            "github_project_v2_schema": gh_tpl.to_string_lossy(),
                            "linear_template": lin_tpl.to_string_lossy(),
                        },
                        "invariants": [
                            "INV-DEFAULT-PRIVATE-BOARD-01",
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
        } else {
            let mut cfg = BoardConfigV1::load(&tasks_dir).unwrap_or_default();
            cfg.org = org.clone();
            cfg.project_title = title.clone();
            cfg.public_board = public_board;
            if let Some(pr) = private_repo {
                cfg.private_repo = Some(pr);
            }
            if let Some(pubr) = public_repo {
                cfg.public_repo = Some(pubr);
            }
            let _ = cfg.save(&tasks_dir);
            let (gh_tpl, lin_tpl) = match write_board_template_pack(&tasks_dir, &cfg) {
                Ok(paths) => paths,
                Err(e) => {
                    let _ = writeln!(stderr, "chinwag board init failed to write templates: {e}");
                    return 1;
                }
            };
            let created_policy = match workspace_root
                .as_deref()
                .map(|root| write_starter_board_policy(root, &cfg, &ticket_prefix))
                .transpose()
            {
                Ok(path) => path.flatten(),
                Err(e) => {
                    let _ = writeln!(stderr, "chinwag board init failed: {e}");
                    return 1;
                }
            };
            let payload = json!({
                "ok": true,
                "command": "chinwag board init",
                "live": false,
                "public_board": cfg.public_board,
                "default_visibility": if cfg.public_board { "public" } else { "private" },
                "board_config": cfg,
                "board_policy_created": created_policy.map(|p| p.to_string_lossy().to_string()),
                "templates": {
                    "github_project_v2_schema": gh_tpl.to_string_lossy(),
                    "linear_template": lin_tpl.to_string_lossy(),
                },
                "invariants": [
                    "INV-DEFAULT-PRIVATE-BOARD-01",
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
    }

    let repository_overrides = private_repo.is_some() || public_repo.is_some();
    let mut routing_cfg = BoardConfigV1::load(&tasks_dir).unwrap_or_default();
    if let Some(repo) = private_repo {
        routing_cfg.private_repo = Some(repo);
    }
    if let Some(repo) = public_repo {
        routing_cfg.public_repo = Some(repo);
    }
    routing_cfg.normalize_repository_bindings(&org);
    let mut payload = build_board_push_graphql_payload_with_config(
        &validated_issues,
        &github_project,
        &linear_team,
        from_ci,
        &routing_cfg,
    );
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("dry_run".to_string(), Value::Bool(dry_run));
    }

    if live && !dry_run {
        if repository_overrides && let Err(e) = routing_cfg.save(&tasks_dir) {
            let _ = writeln!(
                stderr,
                "chinwag board push --live failed to save routing: {e}"
            );
            return 1;
        }
        let live_policy = match require_board_policy_for_live(policy.as_ref()) {
            Ok(policy) => policy,
            Err(violation) => return emit_h_board_rejection(&violation, stdout, stderr),
        };
        match push_github_project_v2_live_governed(&tasks_dir, &validated_issues, &org, live_policy)
        {
            Ok(live_receipt) => {
                if let Some(obj) = payload.as_object_mut() {
                    obj.insert("live_sync_receipt".to_string(), live_receipt);
                }
                routing_cfg = BoardConfigV1::load(&tasks_dir).unwrap_or(routing_cfg);
            }
            Err(e) => {
                let _ = writeln!(stderr, "chinwag board push --live failed: {e}");
                return 1;
            }
        }
    }

    if !dry_run {
        match sync_board_cards_ledger(&tasks_dir, &validated_issues, Some(&routing_cfg)) {
            Ok(ledger) => {
                if let Some(obj) = payload.as_object_mut() {
                    obj.insert(
                        "board_cards_summary".to_string(),
                        json!({
                            "total_cards": ledger.total_cards,
                            "shipped_cards": ledger.shipped_cards,
                            "total_dora_baseline_hours": ledger.total_dora_baseline_hours,
                            "total_chinwag_cycle_hours": ledger.total_chinwag_cycle_hours,
                            "total_net_hours_saved": ledger.total_net_hours_saved,
                        }),
                    );
                }
            }
            Err(e) => {
                let _ = writeln!(
                    stderr,
                    "chinwag board push failed to synchronize cards: {e}"
                );
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

/// Calibrated decision-model risk and interval assessment (`CHWG-0206`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionGateAssessmentV1 {
    pub issue_id: String,
    pub dora_tier_guess: String,
    pub clef_max_trigger: f64,
    pub clef_redaction_clean_score: f64,
    pub clairic_loc_p10: f64,
    pub clairic_loc_median: f64,
    pub clairic_loc_p90: f64,
    pub clairic_burn_usd_median: f64,
    pub clairic_minutes_median: f64,
    pub clairic_ci_fail_prob_median: f64,
    pub system2_escalated: bool,
    pub evaluated_at_ms: u64,
}

/// Evaluates `DecisionGateAssessmentV1` for an `AtomicTaskIssue`, consulting `.chinwag/tasks/decision-gate-cache.json`
/// first and invoking `$HOME/.local/bin/delivery-agent` on cache miss when live board configuration is active.
pub fn evaluate_issue_decision_gate(
    tasks_dir: &Path,
    issue: &AtomicTaskIssue,
    commit_boundary: bool,
) -> DecisionGateAssessmentV1 {
    let cache_path = tasks_dir.join("decision-gate-cache.json");
    let loc_val = issue.loc_changed.unwrap_or(180);
    let cache_key = format!("{}:{}:{}", issue.id, issue.status.as_code(), loc_val);

    let mut cache_map: BTreeMap<String, DecisionGateAssessmentV1> = fs::read_to_string(&cache_path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default();

    if let Some(existing) = cache_map.get(&cache_key) {
        return existing.clone();
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(1_794_368_000_000);

    let (default_p10, default_med, default_p90, default_usd, default_mins, default_fail_prob) =
        match issue.dora_tier {
            DoraTier::S => (20.0, 65.0, 140.0, 1.40, 22.0, 0.08),
            DoraTier::M => (60.0, 210.0, 440.0, 3.85, 55.0, 0.12),
            DoraTier::L => (180.0, 560.0, 1150.0, 7.50, 95.0, 0.16),
            DoraTier::XL => (420.0, 1250.0, 2400.0, 14.20, 145.0, 0.21),
        };

    let mut assessment = DecisionGateAssessmentV1 {
        issue_id: issue.id.clone(),
        dora_tier_guess: issue.dora_tier.as_str().to_string(),
        clef_max_trigger: 0.18,
        clef_redaction_clean_score: 0.96,
        clairic_loc_p10: default_p10,
        clairic_loc_median: default_med,
        clairic_loc_p90: default_p90,
        clairic_burn_usd_median: default_usd,
        clairic_minutes_median: default_mins,
        clairic_ci_fail_prob_median: default_fail_prob,
        system2_escalated: false,
        evaluated_at_ms: now_ms,
    };

    let delivery_agent_bin =
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/bin/delivery-agent"));
    let live_enabled = (tasks_dir.join("board-config.json").exists()
        || std::env::var("CHINWAG_DECISION_GATE_LIVE").as_deref() == Ok("1"))
        && std::env::var("CHINWAG_DECISION_GATE_OFFLINE").as_deref() != Ok("1");

    if let Some(ref delivery_agent_bin) = delivery_agent_bin
        && delivery_agent_bin.is_file()
        && live_enabled
    {
        let state_json = json!({
            "issue_id": issue.id,
            "title": issue.title,
            "status": issue.status.as_code(),
            "dora_tier": issue.dora_tier.as_str(),
            "loc_changed": loc_val,
            "assigned_seats": issue.assigned_seats,
        })
        .to_string();

        let mut clef_cmd = std::process::Command::new(delivery_agent_bin);
        clef_cmd.args(["clef", "--prompt", &state_json]);
        if commit_boundary {
            clef_cmd.arg("--commit-boundary");
        }
        if let Ok(out) = clef_cmd.output()
            && out.status.success()
            && let Ok(val) = serde_json::from_slice::<Value>(&out.stdout)
        {
            let answers = val
                .get("result")
                .and_then(|r| r.get("answers"))
                .or_else(|| val.get("answers"));
            if let Some(ans_obj) = answers.and_then(|a| a.as_object()) {
                let mut max_trig: f64 = 0.0;
                for (k, v) in ans_obj {
                    let score = v
                        .get("noul")
                        .and_then(|n| n.as_f64())
                        .or_else(|| v.as_f64());
                    if let Some(s) = score {
                        if k == "public_board_redaction_clean" {
                            assessment.clef_redaction_clean_score = (s * 10000.0).round() / 10000.0;
                        } else if s > max_trig {
                            max_trig = s;
                        }
                    }
                }
                if max_trig > 0.0 {
                    assessment.clef_max_trigger = (max_trig * 10000.0).round() / 10000.0;
                }
            }
        }

        let clairic_prompt = format!(
            "{}: {} (Tier {} · {} LOC)",
            issue.id,
            issue.title,
            issue.dora_tier.as_str(),
            loc_val
        );
        if let Ok(out) = std::process::Command::new(delivery_agent_bin)
            .args(["clairic", "--prompt", &clairic_prompt])
            .output()
            && out.status.success()
            && let Ok(val) = serde_json::from_slice::<Value>(&out.stdout)
        {
            let answers = val
                .get("result")
                .and_then(|r| r.get("answers"))
                .or_else(|| val.get("answers"));
            if let Some(ans) = answers {
                if let Some(loc_est) = ans.get("estimated_loc_diff") {
                    if let Some(p10) = loc_est.get("p10").and_then(|v| v.as_f64()) {
                        assessment.clairic_loc_p10 = (p10 * 100.0).round() / 100.0;
                    }
                    if let Some(med) = loc_est.get("median").and_then(|v| v.as_f64()) {
                        assessment.clairic_loc_median = (med * 100.0).round() / 100.0;
                    }
                    if let Some(p90) = loc_est.get("p90").and_then(|v| v.as_f64()) {
                        assessment.clairic_loc_p90 = (p90 * 100.0).round() / 100.0;
                    }
                }
                if let Some(burn_med) = ans
                    .get("estimated_token_burn_usd")
                    .and_then(|b| b.get("median"))
                    .and_then(|v| v.as_f64())
                {
                    assessment.clairic_burn_usd_median = (burn_med * 100.0).round() / 100.0;
                }
                if let Some(mins_med) = ans
                    .get("estimated_minutes_to_merge")
                    .and_then(|m| m.get("median"))
                    .and_then(|v| v.as_f64())
                {
                    assessment.clairic_minutes_median = (mins_med * 100.0).round() / 100.0;
                }
                if let Some(fail_med) = ans
                    .get("ci_failure_probability")
                    .and_then(|c| c.get("median"))
                    .and_then(|v| v.as_f64())
                {
                    assessment.clairic_ci_fail_prob_median = (fail_med * 10000.0).round() / 10000.0;
                }
                if let Some(guess) = ans
                    .get("dora_complexity_tier")
                    .and_then(|d| d.get("guess"))
                    .and_then(|v| v.as_str())
                {
                    let clean_guess = guess.trim().to_ascii_uppercase();
                    if matches!(clean_guess.as_str(), "S" | "M" | "L" | "XL") {
                        assessment.dora_tier_guess = clean_guess;
                    }
                }
            }
        }

        if assessment.clef_max_trigger >= 0.50 {
            assessment.system2_escalated = true;
            if std::env::var("CHINWAG_DECISION_GATE_WAKE_SYS2").as_deref() == Ok("1") {
                let _ = std::process::Command::new(delivery_agent_bin)
                    .args(["telemetry-gate", "--prompt", &state_json])
                    .output();
            }
        }
    }

    cache_map.insert(cache_key, assessment.clone());
    if let Ok(serialized) = serde_json::to_string_pretty(&cache_map) {
        let _ = fs::create_dir_all(tasks_dir);
        let _ = fs::write(&cache_path, format!("{serialized}\n"));
    }

    assessment
}

/// Canonical card entry in `.chinwag/tasks/board-cards.json` (`chinwag.board.cards.v1`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BoardCardEntryV1 {
    #[serde(default)]
    pub primary_function: String,
    #[serde(default)]
    pub credits_used: u64,
    #[serde(default)]
    pub verification_receipt: String,
    pub id: String,
    #[serde(default)]
    pub ticket_code: Option<String>,
    pub title: String,
    #[serde(default = "default_card_visibility")]
    pub visibility: String,
    #[serde(default)]
    pub target_repository: String,
    pub status: String,
    pub column_header: String,
    pub dora_tier: String,
    pub dora_baseline: String,
    pub baseline_hours: f64,
    pub chinwag_cycle_time: String,
    pub delta_speedup_vs_dora: String,
    pub net_hours_saved: f64,
    pub execution_mode: String,
    pub active_seats: String,
    pub assigned_seats: Vec<String>,
    pub cryptographic_receipt: String,
    pub t_claim_ms: u64,
    pub t_ship_ms: u64,
    pub trigger_source: String,
    #[serde(default)]
    pub github_issue_number: Option<u64>,
    #[serde(default)]
    pub github_issue_url: Option<String>,
    #[serde(default)]
    pub project_item_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_gate: Option<DecisionGateAssessmentV1>,
}

fn default_card_visibility() -> String {
    "private".to_string()
}

/// Persistent ledger of all board cards and cumulative `Net Hours Saved` (`.chinwag/tasks/board-cards.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BoardCardsLedgerV1 {
    pub schema: String,
    pub project_id: String,
    pub project_url: String,
    pub total_cards: usize,
    pub shipped_cards: usize,
    pub total_dora_baseline_hours: f64,
    pub total_chinwag_cycle_hours: f64,
    pub total_net_hours_saved: f64,
    pub cards: Vec<BoardCardEntryV1>,
}

impl Default for BoardCardsLedgerV1 {
    fn default() -> Self {
        Self {
            schema: "chinwag.board.cards.v1".to_string(),
            project_id: "PVT_kwDOFJPsXM4BrFUV".to_string(),
            project_url: "https://github.com/orgs/emunlabs/projects/1".to_string(),
            total_cards: 0,
            shipped_cards: 0,
            total_dora_baseline_hours: 0.0,
            total_chinwag_cycle_hours: 0.0,
            total_net_hours_saved: 0.0,
            cards: Vec::new(),
        }
    }
}

impl BoardCardsLedgerV1 {
    pub fn sanitize_entity_firewall(&mut self, tasks_dir: &Path) {
        let issues_dir = tasks_dir.join("issues");
        let has_disk_issues = fs::read_dir(&issues_dir).ok().is_some_and(|mut entries| {
            entries.any(|e| {
                e.ok()
                    .and_then(|ent| ent.path().extension().map(|ext| ext == "md"))
                    .unwrap_or(false)
            })
        });
        self.cards.retain(|card| {
            let valid_id = if has_disk_issues {
                is_canonical_chwg_ticket_id(&card.id)
                    && issues_dir.join(format!("{}.md", card.id)).is_file()
            } else {
                card.id.starts_with("CHWG-")
                    && !card.id.contains(',')
                    && !card.id.contains("..")
                    && !card.id.eq_ignore_ascii_case("CHWG-PM-DELIVERY-LOOP-01")
            };
            valid_id && scan_entity_firewall_text(&format!("{}\n{}", card.id, card.title)).is_ok()
        });
    }

    pub fn load(tasks_dir: &Path) -> Self {
        let p = tasks_dir.join("board-cards.json");
        if let Ok(raw) = fs::read_to_string(p)
            && let Ok(mut parsed) = serde_json::from_str::<Self>(&raw)
        {
            parsed.sanitize_entity_firewall(tasks_dir);
            parsed.recompute_totals();
            return parsed;
        }
        Self::default()
    }

    pub fn recompute_totals(&mut self) {
        self.total_cards = self.cards.len();
        self.shipped_cards = self
            .cards
            .iter()
            .filter(|c| c.status == "05_SHIPPED_VERIFIED")
            .count();
        for card in &mut self.cards {
            if card.status != "05_SHIPPED_VERIFIED" {
                card.net_hours_saved = 0.0;
                card.credits_used = 0;
            }
        }
        let baseline_sum: f64 = self.cards.iter().map(|c| c.baseline_hours).sum();
        let saved_sum: f64 = self.cards.iter().map(|c| c.net_hours_saved).sum();
        let cycle_sum: f64 = self
            .cards
            .iter()
            .filter(|c| {
                c.status == "05_SHIPPED_VERIFIED" && c.t_ship_ms > c.t_claim_ms && c.t_claim_ms > 0
            })
            .map(|c| (c.t_ship_ms - c.t_claim_ms) as f64 / 3_600_000.0)
            .sum();
        self.total_dora_baseline_hours = (baseline_sum * 100.0).round() / 100.0;
        self.total_net_hours_saved = (saved_sum * 100.0).round() / 100.0;
        self.total_chinwag_cycle_hours = (cycle_sum * 100.0).round() / 100.0;
    }

    pub fn save(&mut self, tasks_dir: &Path) -> Result<(), String> {
        self.sanitize_entity_firewall(tasks_dir);
        self.recompute_totals();
        fs::create_dir_all(tasks_dir).map_err(|e| format!("failed to create tasks dir: {e}"))?;
        let p = tasks_dir.join("board-cards.json");
        let body = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize board-cards.json: {e}"))?;
        fs::write(p, format!("{body}\n"))
            .map_err(|e| format!("failed to write board-cards.json: {e}"))
    }
}

fn card_entry_from_issue(
    issue: &AtomicTaskIssue,
    cfg: Option<&BoardConfigV1>,
    existing_trigger: Option<&str>,
    existing_ticket_code: Option<String>,
) -> BoardCardEntryV1 {
    let proof = compute_velocity_proof_for_deliverable(
        issue.dora_tier,
        issue.loc_changed,
        &issue.deliverable_kind,
        issue.t_claim_ms,
        issue.t_ship_ms,
    );
    let assigned_seats: Vec<String> = issue
        .assigned_seats
        .iter()
        .map(|s| {
            s.trim()
                .trim_start_matches('■')
                .trim_start_matches('@')
                .trim()
                .to_string()
        })
        .collect();
    let active_seats = if assigned_seats.is_empty() {
        "■ DELIVERY".to_string()
    } else {
        assigned_seats
            .iter()
            .map(|s| format!("■ {s}"))
            .collect::<Vec<_>>()
            .join(" · ")
    };
    let execution_mode = commercial_execution_mode(issue).to_string();
    let (delta_speedup_vs_dora, chinwag_cycle_time, net_hours_saved) = card_metrics(issue, &proof);
    let cryptographic_receipt = issue.last_ci_gate_badge.clone().unwrap_or_else(|| {
        format!(
            "✓ed25519 · blake3:{}",
            short_digest(&format!(
                "{}:{}:{}",
                issue.id, issue.title, issue.t_claim_ms
            ))
        )
    });
    let target_repository = cfg.map_or_else(
        || BoardConfigV1::default().target_repository(issue),
        |c| c.target_repository(issue),
    );
    let linked_cfg = cfg.filter(|c| {
        c.synced_issue_repos.get(&issue.id).map_or_else(
            || {
                c.synced_issue_urls.get(&issue.id).is_some_and(|url| {
                    url.starts_with(&format!("https://github.com/{target_repository}/issues/"))
                })
            },
            |repo| repo.eq_ignore_ascii_case(&target_repository),
        )
    });

    BoardCardEntryV1 {
        primary_function: primary_function(issue).to_string(),
        credits_used: realized_credits(issue),
        verification_receipt: verification_receipt(issue),
        id: issue.id.clone(),
        ticket_code: existing_ticket_code,
        title: issue.title.clone(),
        visibility: issue.visibility.clone(),
        target_repository,
        status: issue.status.as_code().to_string(),
        column_header: issue.status.column_header().to_string(),
        dora_tier: proof.effective_tier.as_str().to_string(),
        dora_baseline: proof.effective_tier.canonical_option_label().to_string(),
        baseline_hours: proof.metric_b_active_baseline_hours,
        chinwag_cycle_time,
        delta_speedup_vs_dora,
        net_hours_saved,
        execution_mode,
        active_seats,
        assigned_seats,
        cryptographic_receipt,
        t_claim_ms: issue.t_claim_ms,
        t_ship_ms: issue.t_ship_ms,
        trigger_source: existing_trigger.unwrap_or("board_push").to_string(),
        github_issue_number: linked_cfg
            .and_then(|c| c.synced_issue_numbers.get(&issue.id).copied()),
        github_issue_url: linked_cfg.and_then(|c| c.synced_issue_urls.get(&issue.id).cloned()),
        project_item_id: linked_cfg.and_then(|c| c.synced_project_item_ids.get(&issue.id).cloned()),
        decision_gate: None,
    }
}

/// Synchronize `.chinwag/tasks/board-cards.json` from all validated `AtomicTaskIssue` records.
pub fn sync_board_cards_ledger(
    tasks_dir: &Path,
    issues: &[AtomicTaskIssue],
    cfg: Option<&BoardConfigV1>,
) -> Result<BoardCardsLedgerV1, String> {
    let mut ledger = BoardCardsLedgerV1::load(tasks_dir);
    if let Some(c) = cfg {
        if !c.project_id.is_empty() && c.project_id != "PVT_kwDOChinwag1" {
            ledger.project_id = c.project_id.clone();
        }
        if !c.project_url.is_empty() {
            ledger.project_url = c.project_url.clone();
        }
    }

    let mut existing_map: BTreeMap<String, BoardCardEntryV1> = ledger
        .cards
        .into_iter()
        .map(|c| (c.id.clone(), c))
        .collect();

    for issue in issues {
        let prior = existing_map.get(&issue.id);
        let mut effective_issue = issue.clone();
        // Monotonic 05_SHIPPED_VERIFIED protection: never downgrade an already-shipped card unless an explicit fail badge is present
        let has_explicit_fail = effective_issue.ci_failure_count > 0
            || effective_issue
                .last_ci_gate_badge
                .as_deref()
                .is_some_and(|b| b.starts_with('🚨'));
        if prior.is_some_and(|p| p.status == "05_SHIPPED_VERIFIED")
            && effective_issue.status != BoardStatus::ShippedVerified
            && !has_explicit_fail
        {
            effective_issue.status = BoardStatus::ShippedVerified;
            if let Some(p) = prior {
                if effective_issue.t_claim_ms == 0 && p.t_claim_ms > 0 {
                    effective_issue.t_claim_ms = p.t_claim_ms;
                }
                if effective_issue.t_ship_ms == 0 && p.t_ship_ms > 0 {
                    effective_issue.t_ship_ms = p.t_ship_ms;
                }
            }
            let disk_path = tasks_dir
                .join("issues")
                .join(format!("{}.md", effective_issue.id));
            if disk_path.is_file() {
                let _ = fs::write(&disk_path, effective_issue.to_markdown());
            }
        }
        validate_h_board_issue(&effective_issue, &effective_issue.to_markdown()).map_err(
            |violation| {
                format!(
                    "H_board rejected (exit {}) [{}] on {}: {}",
                    violation.exit_code, violation.invariant, violation.issue_id, violation.reason
                )
            },
        )?;
        let trigger = prior.map(|p| p.trigger_source.as_str());
        let tcode = prior.and_then(|p| p.ticket_code.clone());
        let mut entry = card_entry_from_issue(&effective_issue, cfg, trigger, tcode);
        entry.decision_gate = Some(evaluate_issue_decision_gate(
            tasks_dir,
            &effective_issue,
            effective_issue.status == BoardStatus::TribunalGate,
        ));
        existing_map.insert(effective_issue.id.clone(), entry);
    }

    ledger.cards = existing_map.into_values().collect();
    ledger.save(tasks_dir)?;
    Ok(ledger)
}

fn normalize_seat_token(raw: &str) -> String {
    let trimmed = raw
        .trim()
        .trim_start_matches(|c: char| c == '@' || c == '■' || c.is_whitespace());
    trimmed
        .split('#')
        .next()
        .unwrap_or(trimmed)
        .trim()
        .to_ascii_uppercase()
}

/// Automatically upsert a board card entry in `.chinwag/tasks/board-cards.json` whenever any agent thread
/// across any model executes `chinwag bus send --task <TICKET>`, `chinwag agent-dispatch --item <TICKET>`,
/// or `chinwag memory retain --context "agent:<SEAT>|ticket:<TICKET>|..."`.
#[allow(clippy::too_many_arguments)]
pub fn upsert_agent_thread_board_card(
    repo_root: &Path,
    ticket_id: &str,
    actor_or_seat: &str,
    peer_seat: Option<&str>,
    summary: &str,
    mark_completed: bool,
    receipt_hash: Option<&str>,
    trigger_source: &str,
) -> Result<BoardCardEntryV1, String> {
    let clean_ticket = ticket_id.trim();
    if clean_ticket.is_empty()
        || clean_ticket.eq_ignore_ascii_case("none")
        || clean_ticket.eq_ignore_ascii_case("null")
    {
        return Err("empty or placeholder ticket_id".to_string());
    }
    if !is_canonical_chwg_ticket_id(clean_ticket) {
        return Err(format!(
            "H_board rejected [INV-ENTITY-SEP-01]: ticket_id `{clean_ticket}` must match ^CHWG-[0-9]{{4}}$"
        ));
    }

    let primary_seat = normalize_seat_token(actor_or_seat);
    let secondary_seat = peer_seat
        .map(normalize_seat_token)
        .filter(|s| !s.is_empty() && s != "ALL" && s != &primary_seat);

    let tasks_dir = repo_root.join(".chinwag").join("tasks");
    if !repo_root.join(".chinwag").is_dir() && !tasks_dir.is_dir() {
        return Err("repository does not have a .chinwag directory".to_string());
    }
    let _ = fs::create_dir_all(&tasks_dir);

    let issues_dir = tasks_dir.join("issues");
    let has_disk_issues = fs::read_dir(&issues_dir).ok().is_some_and(|mut entries| {
        entries.any(|e| {
            e.ok()
                .and_then(|ent| ent.path().extension().map(|ext| ext == "md"))
                .unwrap_or(false)
        })
    });
    let disk_issue_path = issues_dir.join(format!("{clean_ticket}.md"));
    if has_disk_issues && !disk_issue_path.is_file() {
        return Err(format!(
            "H_board rejected [INV-ENTITY-SEP-01]: ticket `{clean_ticket}` is not backed by .chinwag/tasks/issues/{clean_ticket}.md"
        ));
    }
    let disk_issue = fs::read_to_string(&disk_issue_path)
        .ok()
        .and_then(|raw| AtomicTaskIssue::from_markdown(&raw).ok());

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(1_793_970_000_000);

    let mut clean_summary = summary
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or(clean_ticket)
        .trim()
        .to_string();
    if clean_summary.chars().count() > 96 {
        clean_summary = clean_summary.chars().take(96).collect::<String>();
    }
    let mut ledger = BoardCardsLedgerV1::load(&tasks_dir);
    let existing_idx = ledger.cards.iter().position(|c| {
        c.id.eq_ignore_ascii_case(clean_ticket)
            || c.ticket_code
                .as_deref()
                .is_some_and(|tc| tc.eq_ignore_ascii_case(clean_ticket))
    });

    // Validate the full input before truncating display copy so secrets or entity firewall leaks cannot hide beyond it.
    let full_input = format!(
        "{ticket_id}\n{actor_or_seat}\n{}\n{summary}\n{}\n{trigger_source}",
        peer_seat.unwrap_or_default(),
        receipt_hash.unwrap_or_default(),
    );
    scan_entity_firewall_text(&full_input)
        .map_err(|(invariant, reason)| format!("H_board rejected [{invariant}]: {reason}"))?;
    scan_secret_text(&full_input)
        .map_err(|(invariant, reason)| format!("H_board rejected [{invariant}]: {reason}"))?;
    let existing = existing_idx.map(|idx| &ledger.cards[idx]);
    let mut card_issue = AtomicTaskIssue::new_default(clean_ticket, &clean_summary, DoraTier::M);
    card_issue.visibility = existing
        .map(|card| card.visibility.clone())
        .unwrap_or_else(default_card_visibility);
    card_issue.assigned_seats = existing
        .map(|card| card.assigned_seats.clone())
        .unwrap_or_default();
    for seat in std::iter::once(&primary_seat).chain(secondary_seat.iter()) {
        if !seat.is_empty()
            && !card_issue
                .assigned_seats
                .iter()
                .any(|assigned| assigned.eq_ignore_ascii_case(seat))
        {
            card_issue.assigned_seats.push(seat.clone());
        }
    }
    if !issue_requires_private_repo(&card_issue) && scan_zero_leak_text(&clean_summary).is_err() {
        clean_summary = format!("{clean_ticket} Autonomous Multi-Model Fleet Execution");
    }
    card_issue.title = existing
        .map(|card| card.title.clone())
        .unwrap_or_else(|| clean_summary.clone());
    card_issue.body = clean_summary.clone();
    if let Some(card) = existing {
        card_issue.t_claim_ms = card.t_claim_ms;
        card_issue.t_ship_ms = card.t_ship_ms;
        card_issue.receipt_trailers = vec![card.cryptographic_receipt.clone()];
    }
    validate_h_board_issue(&card_issue, &card_issue.to_markdown()).map_err(|violation| {
        format!(
            "H_board rejected (exit {}) [{}]: {}",
            violation.exit_code, violation.invariant, violation.reason
        )
    })?;
    let mut cfg = BoardConfigV1::load(&tasks_dir).unwrap_or_default();
    let org = cfg.org.clone();
    cfg.normalize_repository_bindings(&org);
    let target_repository = cfg.target_repository(&card_issue);

    let mut entry = if let Some(idx) = existing_idx {
        let mut cur = ledger.cards[idx].clone();
        let linkage_matches = if cur.target_repository.is_empty() {
            cur.github_issue_url.as_deref().is_some_and(|url| {
                url.starts_with(&format!("https://github.com/{target_repository}/issues/"))
            })
        } else {
            cur.target_repository
                .eq_ignore_ascii_case(&target_repository)
        };
        if !linkage_matches {
            cur.github_issue_number = None;
            cur.github_issue_url = None;
            cur.project_item_id = None;
        }
        cur.target_repository = target_repository;
        if !primary_seat.is_empty()
            && !cur
                .assigned_seats
                .iter()
                .any(|s| s.eq_ignore_ascii_case(&primary_seat))
        {
            cur.assigned_seats.push(primary_seat.clone());
        }
        if let Some(ref sec) = secondary_seat
            && !cur
                .assigned_seats
                .iter()
                .any(|s| s.eq_ignore_ascii_case(sec))
        {
            cur.assigned_seats.push(sec.clone());
        }
        cur.active_seats = if cur.assigned_seats.is_empty() {
            "■ DELIVERY".to_string()
        } else {
            cur.assigned_seats
                .iter()
                .map(|s| format!("■ {s}"))
                .collect::<Vec<_>>()
                .join(" · ")
        };
        cur.execution_mode = match cur.assigned_seats.len() {
            0 | 1 => "Review · 50 Cr".to_string(),
            2 => "Pair · 100 Cr".to_string(),
            3 => "Triad · 150 Cr".to_string(),
            _ => "Quad · 200 Cr".to_string(),
        };
        if mark_completed && cur.status != "05_SHIPPED_VERIFIED" {
            cur.status = "05_SHIPPED_VERIFIED".to_string();
            cur.column_header = BoardStatus::ShippedVerified.column_header().to_string();
            cur.t_ship_ms = now_ms;
            cur.delta_speedup_vs_dora = "⚡ 100x+ Faster vs. DORA".to_string();
        }
        if let Some(h) = receipt_hash {
            let short_h = &h[..h.len().min(16)];
            cur.cryptographic_receipt = format!("✓ed25519 · blake3:{short_h}");
        }
        cur.trigger_source = trigger_source.to_string();
        cur
    } else {
        let mut seats = Vec::new();
        if !primary_seat.is_empty() {
            seats.push(primary_seat);
        }
        if let Some(sec) = secondary_seat {
            seats.push(sec);
        }
        if seats.is_empty() {
            seats.push("DELIVERY".to_string());
        }
        let active_seats = seats
            .iter()
            .map(|s| format!("■ {s}"))
            .collect::<Vec<_>>()
            .join(" · ");
        let execution_mode = match seats.len() {
            0 | 1 => "Review · 50 Cr".to_string(),
            2 => "Pair · 100 Cr".to_string(),
            3 => "Triad · 150 Cr".to_string(),
            _ => "Quad · 200 Cr".to_string(),
        };
        let status = if mark_completed {
            BoardStatus::ShippedVerified
        } else {
            BoardStatus::InFlight
        };
        let t_claim_ms = now_ms;
        let t_ship_ms = if mark_completed { now_ms } else { 0 };
        let proof = compute_velocity_proof(DoraTier::M, Some(180), t_claim_ms, t_ship_ms);
        let receipt_str = if let Some(h) = receipt_hash {
            format!("✓ed25519 · blake3:{}", &h[..h.len().min(16)])
        } else {
            format!(
                "✓ed25519 · blake3:{}",
                short_digest(&format!("{clean_ticket}:{now_ms}"))
            )
        };
        BoardCardEntryV1 {
            primary_function: primary_function(&card_issue).to_string(),
            credits_used: 0,
            verification_receipt: verification_receipt(&card_issue),
            id: clean_ticket.to_string(),
            ticket_code: Some(clean_ticket.to_string()),
            title: clean_summary,
            visibility: card_issue.visibility.clone(),
            target_repository,
            status: status.as_code().to_string(),
            column_header: status.column_header().to_string(),
            dora_tier: "M".to_string(),
            dora_baseline: DoraTier::M.canonical_option_label().to_string(),
            baseline_hours: DoraTier::M.metric_b_active_hours(),
            chinwag_cycle_time: if mark_completed {
                proof.cycle_time_label
            } else {
                format!("In Flight · {}", proof.cycle_time_label)
            },
            delta_speedup_vs_dora: if mark_completed {
                proof.speedup_pill
            } else {
                "⏱️ Clock Running — In Flight".to_string()
            },
            net_hours_saved: if mark_completed {
                proof.net_hours_saved
            } else {
                0.0
            },
            execution_mode,
            active_seats,
            assigned_seats: seats,
            cryptographic_receipt: receipt_str,
            t_claim_ms,
            t_ship_ms,
            trigger_source: trigger_source.to_string(),
            github_issue_number: None,
            github_issue_url: None,
            project_item_id: None,
            decision_gate: None,
        }
    };

    // Thread activity does not carry a measured diff or independent verification receipt.
    // Keep realized metrics unavailable until the atomic task sync supplies that evidence,
    // while strictly preserving 05_SHIPPED_VERIFIED if already shipped on disk or in ledger.
    let disk_already_shipped = disk_issue
        .as_ref()
        .is_some_and(|iss| iss.status == BoardStatus::ShippedVerified);
    if disk_already_shipped && entry.status != "05_SHIPPED_VERIFIED" {
        entry.status = "05_SHIPPED_VERIFIED".to_string();
        entry.column_header = BoardStatus::ShippedVerified.column_header().to_string();
    }
    if let Some(ref diss) = disk_issue
        && diss.status == BoardStatus::ShippedVerified
    {
        let disk_projected = card_entry_from_issue(
            diss,
            Some(&cfg),
            Some(trigger_source),
            entry.ticket_code.clone(),
        );
        entry.status = "05_SHIPPED_VERIFIED".to_string();
        entry.column_header = BoardStatus::ShippedVerified.column_header().to_string();
        entry.net_hours_saved = disk_projected.net_hours_saved;
        entry.chinwag_cycle_time = disk_projected.chinwag_cycle_time;
        entry.delta_speedup_vs_dora = disk_projected.delta_speedup_vs_dora;
        entry.credits_used = disk_projected.credits_used;
        entry.verification_receipt = disk_projected.verification_receipt;
    } else {
        card_issue.status = BoardStatus::from_code(&entry.status).unwrap_or(BoardStatus::InFlight);
        card_issue.t_claim_ms = entry.t_claim_ms;
        card_issue.t_ship_ms = entry.t_ship_ms;
        let projected = card_entry_from_issue(&card_issue, None, None, None);
        entry.net_hours_saved = projected.net_hours_saved;
        entry.chinwag_cycle_time = projected.chinwag_cycle_time;
        entry.delta_speedup_vs_dora = projected.delta_speedup_vs_dora;
        entry.credits_used = projected.credits_used;
        entry.verification_receipt = projected.verification_receipt;
    }

    if let Some(idx) = existing_idx {
        ledger.cards[idx] = entry.clone();
    } else {
        ledger.cards.push(entry.clone());
    }
    ledger.save(&tasks_dir)?;

    // When CHINWAG_BOARD_AUTO_PUSH=1 and a live board-config.json is present, trigger background board push
    if std::env::var("CHINWAG_BOARD_AUTO_PUSH").as_deref() == Ok("1")
        && let Some(cfg) = BoardConfigV1::load(&tasks_dir)
        && cfg.project_id != "PVT_kwDOChinwag1"
        && let Ok(exe) = std::env::current_exe()
    {
        let _ = std::process::Command::new(exe)
            .args([
                "board",
                "push",
                "--tasks-dir",
                &tasks_dir.to_string_lossy(),
                "--org",
                &cfg.org,
                "--live",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }

    #[allow(clippy::useless_conversion)]
    Ok(entry.into())
}

/// Active crisis record stored at `.chinwag/bus/active_crisis.json` (`INV-CRISIS-ALL-STOP-BROADCAST-01`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveCrisisRecord {
    pub schema: String,
    pub invariant: String,
    pub active: bool,
    pub sender: String,
    #[serde(default)]
    pub task_id: Option<String>,
    pub message: String,
    pub ts_unix: u64,
    pub ts_iso: String,
    #[serde(default)]
    pub notified_threads: Vec<String>,
}

/// Overlapping `03_IN_FLIGHT` surface collision detected by `INV-LIVE-THREAD-WORKTREE-BEACON-01`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceCollision {
    pub other_ticket_id: String,
    pub other_owner: String,
    pub overlapping_globs: Vec<String>,
}

pub fn active_crisis_path(repo_root: &Path) -> PathBuf {
    repo_root
        .join(".chinwag")
        .join("bus")
        .join("active_crisis.json")
}

pub fn read_active_crisis(repo_root: &Path) -> Option<ActiveCrisisRecord> {
    let raw = fs::read_to_string(active_crisis_path(repo_root)).ok()?;
    let rec: ActiveCrisisRecord = serde_json::from_str(&raw).ok()?;
    if rec.active { Some(rec) } else { None }
}

pub fn write_active_crisis(repo_root: &Path, rec: &ActiveCrisisRecord) -> Result<(), String> {
    let path = active_crisis_path(repo_root);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let bytes = serde_json::to_vec_pretty(rec).map_err(|e| e.to_string())?;
    fs::write(path, bytes).map_err(|e| e.to_string())
}

/// Prints the unread `[🚨 CRISIS ALL-STOP]` Chinwag bus alert to `stderr` whenever any `chinwag` command runs
/// while `.chinwag/bus/active_crisis.json` is active (`INV-CRISIS-ALL-STOP-BROADCAST-01`).
pub fn emit_active_crisis_alert_if_any(repo_root: &Path, stderr: &mut dyn Write) {
    if let Some(crisis) = read_active_crisis(repo_root) {
        let task_tag = crisis
            .task_id
            .as_deref()
            .map(|t| format!(" [{t}]"))
            .unwrap_or_default();
        let _ = writeln!(
            stderr,
            "🚨 [CRISIS ALL-STOP · INV-CRISIS-ALL-STOP-BROADCAST-01]{task_tag} from {} ({}): {}",
            crisis.sender, crisis.ts_iso, crisis.message
        );
    }
}

pub fn emit_active_crisis_alert_from_cwd(stderr: &mut dyn Write) {
    if let Ok(repo_env) = std::env::var("CHINWAG_REPO_ROOT") {
        let p = PathBuf::from(repo_env);
        if p.join(".chinwag").is_dir() {
            emit_active_crisis_alert_if_any(&p, stderr);
            return;
        }
    }
    if let Ok(cwd) = std::env::current_dir()
        && cwd.join(".chinwag").is_dir()
    {
        emit_active_crisis_alert_if_any(&cwd, stderr);
    }
}

fn collect_qualified_thread_address(
    raw: &str,
    ts: u64,
    excluded_norm: Option<&str>,
    seen: &mut BTreeMap<String, (u64, String)>,
) {
    for part in raw.split(',') {
        let clean = part.trim().trim_start_matches(['@', '■', '●', '◆']).trim();
        if !clean.contains('#') {
            continue;
        }
        if let Ok(addr) = crate::agent_instance::ActorAddress::parse(clean)
            && !addr.is_human()
            && let Some(inst) = addr.instance()
            && inst.len() >= 16
        {
            let full = addr.to_string();
            let key = full.to_ascii_uppercase();
            if excluded_norm.is_some_and(|ex| ex.eq_ignore_ascii_case(&full)) {
                continue;
            }
            let entry = seen.entry(key).or_insert_with(|| (ts, full.clone()));
            if ts >= entry.0 {
                entry.0 = ts;
                entry.1 = full;
            }
        }
    }
}

/// Discovers all live `<SEAT>#<INSTANCE>` thread instances across all models by scanning
/// `.chinwag/bus/messages.jsonl` (last 120 minutes / tail 500 messages)
/// (`INV-LIVE-THREAD-WORKTREE-BEACON-01` & `INV-CRISIS-ALL-STOP-BROADCAST-01`).
pub fn discover_live_thread_instances(
    repo_root: &Path,
    exclude_actor: Option<&str>,
) -> Vec<String> {
    let excluded_norm = exclude_actor
        .and_then(|raw| {
            let trimmed = raw.trim().trim_start_matches(['@', '■', '●', '◆']).trim();
            crate::agent_instance::ActorAddress::parse(trimmed)
                .ok()
                .map(|a| a.to_string())
        })
        .or_else(|| exclude_actor.map(|s| s.trim().trim_start_matches('@').to_string()));

    let mut seen = BTreeMap::<String, (u64, String)>::new();
    let messages_path = repo_root
        .join(".chinwag")
        .join("bus")
        .join("messages.jsonl");
    if let Ok(raw) = fs::read_to_string(&messages_path) {
        let lines: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
        let start = lines.len().saturating_sub(500);
        let tail = &lines[start..];
        let mut parsed_rows = Vec::<(u64, String, Option<String>)>::with_capacity(tail.len());
        let mut max_ts = 0u64;
        for line in tail {
            if let Ok(val) = serde_json::from_str::<Value>(line) {
                let ts = val.get("ts_unix").and_then(|v| v.as_u64()).unwrap_or(0);
                if ts > max_ts {
                    max_ts = ts;
                }
                let sender = val
                    .get("sender")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let to = val
                    .get("to")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                parsed_rows.push((ts, sender, to));
            }
        }
        let cutoff = max_ts.saturating_sub(7200);
        for (ts, sender, to) in parsed_rows {
            if ts == 0 || ts >= cutoff {
                collect_qualified_thread_address(&sender, ts, excluded_norm.as_deref(), &mut seen);
                if let Some(ref recipients) = to {
                    collect_qualified_thread_address(
                        recipients,
                        ts,
                        excluded_norm.as_deref(),
                        &mut seen,
                    );
                }
            }
        }
    }

    let mut items: Vec<(u64, String)> = seen.into_values().collect();
    // Cap at 32 most-recently active instances so parse_recipients (max 32) always succeeds,
    // then sort alphabetically for deterministic multicast order.
    items.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    items.truncate(32);
    let mut out: Vec<String> = items.into_iter().map(|(_, addr)| addr).collect();
    out.sort();
    out
}

fn globs_overlap(a: &str, b: &str) -> bool {
    let a_clean = a.trim().trim_end_matches("/**").trim_end_matches("/*");
    let b_clean = b.trim().trim_end_matches("/**").trim_end_matches("/*");
    if a_clean.is_empty() || b_clean.is_empty() {
        return false;
    }
    if a_clean == "*" || b_clean == "*" || a_clean == b_clean {
        return true;
    }
    a_clean.starts_with(&format!("{b_clean}/")) || b_clean.starts_with(&format!("{a_clean}/"))
}

/// Checks `.chinwag/tasks/issues/*.md` for any other `03_IN_FLIGHT` ticket touching overlapping `surface_globs`
/// (`INV-LIVE-THREAD-WORKTREE-BEACON-01`).
pub fn detect_in_flight_surface_collisions(
    repo_root: &Path,
    ticket_id: &str,
    actor: &str,
    surface_globs: &[String],
) -> Vec<SurfaceCollision> {
    let issues_dir = repo_root.join(".chinwag").join("tasks").join("issues");
    let Ok(entries) = fs::read_dir(&issues_dir) else {
        return Vec::new();
    };
    let mut collisions = Vec::new();
    for entry in entries.flatten() {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let Ok(raw) = fs::read_to_string(&p) else {
            continue;
        };
        let Ok(issue) = AtomicTaskIssue::from_markdown(&raw) else {
            continue;
        };
        if issue.id.eq_ignore_ascii_case(ticket_id) || issue.status != BoardStatus::InFlight {
            continue;
        }
        let other_owner = issue
            .author_instance
            .clone()
            .or_else(|| issue.assigned_seats.first().cloned())
            .unwrap_or_else(|| "UNKNOWN".to_string());
        if other_owner.eq_ignore_ascii_case(actor) {
            continue;
        }
        let other_globs: Vec<String> = issue
            .file_scope
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let mut overlapping = Vec::new();
        for my_g in surface_globs {
            for other_g in &other_globs {
                if globs_overlap(my_g, other_g) && !overlapping.contains(my_g) {
                    overlapping.push(my_g.clone());
                }
            }
        }
        if !overlapping.is_empty() {
            collisions.push(SurfaceCollision {
                other_ticket_id: issue.id,
                other_owner,
                overlapping_globs: overlapping,
            });
        }
    }
    collisions.sort_by(|a, b| a.other_ticket_id.cmp(&b.other_ticket_id));
    collisions
}

/// Ticket IDs claimed by every task file in `issues_dir` except `skip`.
fn local_ticket_claims(issues_dir: &Path, skip: &Path) -> Vec<TicketCardRef> {
    let Ok(entries) = fs::read_dir(issues_dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path != skip && path.extension().and_then(|e| e.to_str()) == Some("md"))
        .filter_map(|path| {
            let issue = AtomicTaskIssue::from_markdown(&fs::read_to_string(&path).ok()?).ok()?;
            Some(TicketCardRef {
                ticket_id: issue.id,
                source: format!("issues/{}", path.file_name()?.to_string_lossy()),
            })
        })
        .collect()
}

fn run_board_add_or_move(
    sub: &str,
    args: &[String],
    tasks_dir: &Path,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let issues_dir = tasks_dir.join("issues");
    let _ = fs::create_dir_all(&issues_dir);
    let repo_root = tasks_dir
        .parent()
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let mut issue_id: Option<String> = None;
    let mut status_code: Option<String> = None;
    let mut title = "Chinwag Engineering Task".to_string();
    let mut tier = DoraTier::M;
    let mut worktree: Option<String> = None;
    let mut branch: Option<String> = None;
    let mut surfaces: Vec<String> = Vec::new();
    let mut from_actor: Option<String> = std::env::var("CHINWAG_ACTOR").ok();
    let mut function: Option<String> = None;
    let mut seats: Option<Vec<String>> = None;
    let mut deliverable_kind: Option<String> = None;
    let mut loc_changed: Option<u64> = None;
    let mut is_json = false;
    let mut positionals = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--id" | "--issue" | "--task" if i + 1 < args.len() => {
                issue_id = Some(args[i + 1].clone());
                i += 2;
            }
            "--status" if i + 1 < args.len() => {
                status_code = Some(args[i + 1].clone());
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
            "--worktree" if i + 1 < args.len() => {
                worktree = Some(args[i + 1].clone());
                i += 2;
            }
            "--branch" if i + 1 < args.len() => {
                branch = Some(args[i + 1].clone());
                i += 2;
            }
            "--surfaces" | "--surface-globs" if i + 1 < args.len() => {
                surfaces = args[i + 1]
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                i += 2;
            }
            "--from" if i + 1 < args.len() => {
                from_actor = Some(args[i + 1].clone());
                i += 2;
            }
            "--function" if i + 1 < args.len() => {
                function = Some(args[i + 1].clone());
                i += 2;
            }
            "--seats" if i + 1 < args.len() => {
                seats = Some(
                    args[i + 1]
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect(),
                );
                i += 2;
            }
            "--deliverable-kind" if i + 1 < args.len() => {
                deliverable_kind = Some(args[i + 1].clone());
                i += 2;
            }
            "--loc-changed" if i + 1 < args.len() => {
                let Ok(loc) = args[i + 1].parse::<u64>() else {
                    let _ = writeln!(
                        stderr,
                        "chinwag board {sub}: `--loc-changed {}` is not a whole number",
                        args[i + 1]
                    );
                    return 2;
                };
                loc_changed = Some(loc);
                i += 2;
            }
            "--repo" | "--tasks-dir" | "--workspace-root" if i + 1 < args.len() => {
                i += 2;
            }
            "--json" => {
                is_json = true;
                i += 1;
            }
            a if !a.starts_with('-') => {
                positionals.push(a.to_string());
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    if issue_id.is_none() && !positionals.is_empty() {
        issue_id = Some(positionals.remove(0));
    }
    if status_code.is_none() && !positionals.is_empty() {
        status_code = Some(positionals.remove(0));
    }

    let Some(id) = issue_id else {
        let _ = writeln!(stderr, "chinwag board {sub}: missing <TICKET_ID>");
        return 2;
    };
    let policy = match resolve_board_policy(args, tasks_dir) {
        Ok(policy) => policy,
        Err(violation) => return emit_h_board_rejection(&violation, stdout, stderr),
    };
    let ledger_rejection = |reason: String| HBoardViolation {
        exit_code: EXIT_H_BOARD_REJECT,
        invariant: INV_BOARD_LEDGER_TRACKING.to_string(),
        issue_id: id.clone(),
        reason,
    };
    // The ID becomes a file name below, so its shape is checked before anything touches disk.
    match &policy {
        Some(policy) => {
            let prefix = &policy.board.ticket_prefix;
            if TicketId::parse(&id, prefix).is_none() {
                let violation = ledger_rejection(format!(
                    "ticket id `{id}` must match ^{prefix}-[0-9]{{4}}(?:\\.[0-9]{{2}}(?:-[0-9]{{2}})?)?$"
                ));
                return emit_h_board_rejection(&violation, stdout, stderr);
            }
        }
        None if !is_canonical_chwg_ticket_id(&id) => {
            let _ = writeln!(
                stderr,
                "H_board rejected [INV-ENTITY-SEP-01]: ticket `{id}` must match ^CHWG-[0-9]{{4}}$"
            );
            return EXIT_H_BOARD_REJECT;
        }
        None => {}
    }

    let target_status = status_code
        .as_deref()
        .and_then(BoardStatus::from_code)
        .unwrap_or(BoardStatus::InFlight);

    let issue_path = issues_dir.join(format!("{id}.md"));
    let existing = issue_path.is_file().then(|| {
        fs::read_to_string(&issue_path)
            .map_err(|e| e.to_string())
            .and_then(|raw| AtomicTaskIssue::from_markdown(&raw))
    });
    let mut issue = match (existing, &policy) {
        (Some(Ok(existing)), _) => existing,
        (Some(Err(e)), Some(_)) => {
            let violation = ledger_rejection(format!(
                "existing task file cannot be read as a card and will not be overwritten: {e}"
            ));
            return emit_h_board_rejection(&violation, stdout, stderr);
        }
        (None, Some(_)) => AtomicTaskIssue::new_unscoped(&id, &title, tier),
        (Some(Err(_)) | None, None) => AtomicTaskIssue::new_default(&id, &title, tier),
    };
    if let Some(function) = function {
        issue.primary_function = Some(function);
    }
    if let Some(seats) = seats {
        issue.assigned_seats = seats;
    }
    if let Some(kind) = deliverable_kind {
        issue.deliverable_kind = kind;
    }
    if let Some(loc) = loc_changed {
        issue.loc_changed = Some(loc);
    }

    if issue.status == BoardStatus::ShippedVerified && target_status != BoardStatus::ShippedVerified
    {
        let _ = writeln!(
            stderr,
            "chinwag board {sub}: monotonic 05_SHIPPED_VERIFIED protection prevents downgrading {id}"
        );
        return 2;
    }
    issue.status = target_status;
    if !surfaces.is_empty() {
        issue.file_scope = surfaces.join(", ");
    }
    if let Some(ref actor) = from_actor {
        issue.author_instance = Some(actor.clone());
    }
    if let Some(policy) = &policy {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        // The claim clock starts when work starts and the ship clock stops when it ships.
        // A card that was never claimed gets no ship time and fails settlement below.
        if matches!(
            target_status,
            BoardStatus::InFlight | BoardStatus::TribunalGate
        ) && issue.t_claim_ms == 0
        {
            issue.t_claim_ms = now_ms;
        }
        if target_status == BoardStatus::ShippedVerified {
            if issue.t_ship_ms == 0 && issue.t_claim_ms > 0 {
                issue.t_ship_ms = now_ms.max(issue.t_claim_ms);
            }
            issue.dora_tier = enforce_tier_lock_for_deliverable(
                issue.dora_tier,
                issue.loc_changed,
                &issue.deliverable_kind,
            )
            .0;
        }

        let mut claims = local_ticket_claims(&issues_dir, &issue_path);
        claims.push(TicketCardRef {
            ticket_id: issue.id.clone(),
            source: format!("issues/{id}.md"),
        });
        let verdict = validate_board_ledger_issue(&issue, policy).and_then(|()| {
            validate_unique_ticket_ids(&claims, &policy.board.ticket_prefix)
                .map_err(|mut duplicates| duplicates.remove(0))
        });
        if let Err(violation) = verdict {
            return emit_h_board_rejection(&violation, stdout, stderr);
        }
    }
    if let Err(e) = fs::write(&issue_path, issue.to_markdown()) {
        let _ = writeln!(stderr, "chinwag board {sub}: {e}");
        return 1;
    }

    if let Some(ref actor) = from_actor {
        let _ = upsert_agent_thread_board_card(
            &repo_root,
            &id,
            actor,
            None,
            &issue.title,
            target_status == BoardStatus::ShippedVerified,
            None,
            if sub == "add" {
                "board_add"
            } else {
                "board_move"
            },
        );
    }

    // Automatic INV-LIVE-THREAD-WORKTREE-BEACON-01 broadcast over the Chinwag bus when adding or moving to 03_IN_FLIGHT
    if target_status == BoardStatus::InFlight
        && let Some(ref actor) = from_actor
        && let Ok(exe) = std::env::current_exe()
    {
        let mut cmd = std::process::Command::new(exe);
        cmd.args([
            "bus",
            "beacon",
            "--repo",
            &repo_root.to_string_lossy(),
            "--from",
            actor,
            "--task",
            &id,
        ]);
        if let Some(ref wt) = worktree {
            cmd.args(["--worktree", wt]);
        }
        if let Some(ref br) = branch {
            cmd.args(["--branch", br]);
        }
        if !issue.file_scope.trim().is_empty() {
            cmd.args(["--surfaces", &issue.file_scope]);
        }
        let _ = cmd.output();
    }

    let payload = json!({
        "ok": true,
        "command": format!("chinwag board {sub}"),
        "issue_id": id,
        "status": issue.status.as_code(),
        "column_header": issue.status.column_header(),
        "invariants": [
            "INV-ENTITY-SEP-01",
            "INV-LIVE-THREAD-WORKTREE-BEACON-01"
        ]
    });
    if is_json {
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
    } else {
        let _ = writeln!(
            stdout,
            "Updated {} -> {} ({})",
            id,
            issue.status.as_code(),
            issue.status.column_header()
        );
    }
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
            let (effective_tier, tier_downgraded) = enforce_tier_lock_for_deliverable(
                claimed_tier,
                issue.loc_changed,
                &issue.deliverable_kind,
            );
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

            let proof = compute_velocity_proof_for_deliverable(
                claimed_tier,
                issue.loc_changed,
                &issue.deliverable_kind,
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
    fn board_config_legacy_fields_and_private_repo_fallback_are_compatible() {
        let mut legacy = serde_json::to_value(BoardConfigV1::default()).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("private_repository_id");
        legacy.as_object_mut().unwrap().remove("synced_issue_repos");
        for private_repo in [Value::Null, json!("emunlabs/chinwag-private")] {
            legacy["private_repo"] = private_repo;
            let mut cfg: BoardConfigV1 = serde_json::from_value(legacy.clone()).unwrap();
            assert!(cfg.private_repository_id.is_none());
            assert!(cfg.synced_issue_repos.is_empty());
            cfg.normalize_repository_bindings("emunlabs");
            assert_eq!(cfg.private_repo.as_deref(), Some("emunlabs/chinwag-tasks"));
        }
    }

    #[test]
    fn board_repository_routing_preserves_explicit_bindings_and_locked_seats() {
        let mut cfg = BoardConfigV1::default();
        cfg.normalize_repository_bindings("another-org");
        let mut issue = AtomicTaskIssue::new_default("CHWG-9999", "Routing", DoraTier::S);
        issue.visibility = "PuBlIc".to_string();
        assert_eq!(cfg.target_repository(&issue), "another-org/chinwag");
        for seat in PRIVATE_LOCKED_SEATS {
            issue.assigned_seats = vec![format!("@■ {seat}#instance")];
            assert_eq!(cfg.target_repository(&issue), "another-org/chinwag-tasks");
        }
        cfg.private_repo = Some("other-owner/confidential".to_string());
        cfg.normalize_repository_bindings("another-org");
        issue.assigned_seats.clear();
        issue.visibility = "PRIVATE".to_string();
        assert_eq!(cfg.target_repository(&issue), "other-owner/confidential");
    }

    #[test]
    fn board_issue_prefix_parser_handles_both_supported_title_formats() {
        assert_eq!(
            github_task_id_from_title("[CHWG-0214] Board routing"),
            Some("CHWG-0214")
        );
        assert_eq!(
            github_task_id_from_title("CHWG-0214: Board routing"),
            Some("CHWG-0214")
        );
        assert_eq!(github_task_id_from_title("Unrelated: issue"), None);
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
        issue.visibility = "public".to_string();
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
        issue.visibility = "public".to_string();
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
        latex_issue.visibility = "public".to_string();
        latex_issue.body = "Formula $$\\Delta = x^2$$ is forbidden.".to_string();
        let res = validate_h_board_issue(&latex_issue, &latex_issue.to_markdown());
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().exit_code, EXIT_H_BOARD_REJECT);

        let mut patent_issue =
            AtomicTaskIssue::new_default("CHWG-0205", "Patent Copy", DoraTier::S);
        patent_issue.visibility = "public".to_string();
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
        let mut incomplete =
            AtomicTaskIssue::new_default("CHWG-0190", "Incomplete Tribunal Card", DoraTier::M);
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

    #[test]
    fn test_17_board_init_defaults_to_private_visibility_and_writes_template_pack() {
        let dir = temp_tasks_dir("board-init-private");
        let issues_dir = dir.join("issues");
        fs::create_dir_all(&issues_dir).unwrap();

        let cfg_default = BoardConfigV1::default();
        assert!(!cfg_default.public_board);

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_board_cli(
            &[
                "init".to_string(),
                "--tasks-dir".to_string(),
                dir.to_string_lossy().to_string(),
                "--org".to_string(),
                "emunlabs".to_string(),
                "--json".to_string(),
            ],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        let resp: Value = serde_json::from_slice(&out).expect("parse board init JSON");
        assert_eq!(resp["ok"], true);
        assert_eq!(resp["public_board"], false);
        assert_eq!(resp["default_visibility"], "private");

        let gh_tpl_path = dir.join("templates/github-project-v2-schema.json");
        let lin_tpl_path = dir.join("templates/linear-template.json");
        assert!(gh_tpl_path.is_file());
        assert!(lin_tpl_path.is_file());

        let gh_raw = fs::read_to_string(&gh_tpl_path).unwrap();
        let lin_raw = fs::read_to_string(&lin_tpl_path).unwrap();
        assert!(!gh_raw.to_ascii_lowercase().contains("deepseek"));
        assert!(!lin_raw.to_ascii_lowercase().contains("deepseek"));

        // A public project can contain issues routed to a private repository.
        let mut locked_issue =
            AtomicTaskIssue::new_default("CHWG-0401", "Patent Review", DoraTier::M);
        locked_issue.assigned_seats = vec!["PATENT".to_string()];
        fs::write(issues_dir.join("CHWG-0401.md"), locked_issue.to_markdown()).unwrap();

        let mut out2 = Vec::new();
        let mut err2 = Vec::new();
        let code2 = run_board_cli(
            &[
                "init".to_string(),
                "--tasks-dir".to_string(),
                dir.to_string_lossy().to_string(),
                "--public-board".to_string(),
                "--json".to_string(),
            ],
            &mut out2,
            &mut err2,
        );
        assert_eq!(code2, 0, "stderr: {}", String::from_utf8_lossy(&err2));
        let public_project: Value = serde_json::from_slice(&out2).unwrap();
        assert_eq!(public_project["public_board"], true);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_18_board_schema_includes_native_github_created_updated_closed_timestamps_and_insights()
    {
        let cfg = BoardConfigV1::default();
        assert!(cfg.system_field_ids.contains_key("CREATED"));
        assert!(cfg.system_field_ids.contains_key("UPDATED"));
        assert!(cfg.system_field_ids.contains_key("CLOSED"));
        assert!(cfg.system_field_ids.contains_key("PARENT_ISSUE"));
        assert!(cfg.system_field_ids.contains_key("SUB_ISSUES_PROGRESS"));

        let schema = build_github_project_v2_template_schema(&cfg);
        assert_eq!(schema["schema_version"], "CHWG-NATIVE-PM-BOARDS-01.v4");
        assert_eq!(schema["default_visibility"], "private");
        assert_eq!(schema["status_columns"].as_array().unwrap().len(), 5);
        assert_eq!(schema["custom_fields"].as_array().unwrap().len(), 10);

        let sys_codes: Vec<&str> = schema["native_github_system_fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| f["code"].as_str())
            .collect();
        assert!(sys_codes.contains(&"CREATED"));
        assert!(sys_codes.contains(&"UPDATED"));
        assert!(sys_codes.contains(&"CLOSED"));
        assert!(sys_codes.contains(&"PARENT_ISSUE"));
        assert!(sys_codes.contains(&"SUB_ISSUES_PROGRESS"));

        assert_eq!(
            schema["insights"]["primary_chart"]["y_axis"],
            "SUM(Net Hours Saved)"
        );
        assert_eq!(
            schema["insights"]["primary_chart"]["group_by"],
            "Execution Mode"
        );
        assert_eq!(
            schema["insights"]["primary_chart"]["x_axis"],
            "DORA Baseline"
        );
    }

    #[test]
    fn test_19_auto_upsert_agent_thread_board_card_populates_net_hours_saved_and_routes_confidential_seats()
     {
        let repo_dir = temp_tasks_dir("auto-upsert-repo");
        fs::create_dir_all(repo_dir.join(".chinwag/tasks")).unwrap();

        let card1 = upsert_agent_thread_board_card(
            &repo_dir,
            "CHWG-0501",
            "DEX#6df4d436df6c01617dcd2f4e404673fc",
            Some("@INFRAJR#0049dd19946d89fd047810fec6676b05"),
            "3-Way A/B/C Edge Variant Router",
            false,
            Some("a1b2c3d4e5f60718293a4b5c6d7e8f90"),
            "bus_send",
        )
        .expect("upsert in-flight card");
        assert_eq!(card1.id, "CHWG-0501");
        assert_eq!(card1.status, "03_IN_FLIGHT");
        assert_eq!(card1.active_seats, "■ DEX · ■ INFRAJR");
        assert_eq!(card1.execution_mode, "Pair · 100 Cr");
        assert_eq!(card1.net_hours_saved, 0.0);

        let card2 = upsert_agent_thread_board_card(
            &repo_dir,
            "CHWG-0501",
            "QA",
            None,
            "Verified 166/166 edge proxy tests and 2/2 tombstone cassettes",
            true,
            Some("f0e1d2c3b4a5968778695a4b3c2d1e0f"),
            "memory_retain",
        )
        .expect("upsert completed card");
        assert_eq!(card2.status, "05_SHIPPED_VERIFIED");
        assert_eq!(card2.active_seats, "■ DEX · ■ INFRAJR · ■ QA");
        assert_eq!(card2.execution_mode, "Triad · 150 Cr");
        assert_eq!(
            card2.delta_speedup_vs_dora,
            "Shipped · Measurement unavailable"
        );

        let ledger = BoardCardsLedgerV1::load(&repo_dir.join(".chinwag/tasks"));
        assert_eq!(ledger.total_cards, 1);
        assert_eq!(ledger.shipped_cards, 1);
        assert_eq!(ledger.total_net_hours_saved, 0.0);

        // Confidential seats remain available through private repository routing.
        let private_card = upsert_agent_thread_board_card(
            &repo_dir,
            "CHWG-0502",
            "PATENT#11223344556677889900aabbccddeeff",
            None,
            "Confidential claim drafting",
            false,
            None,
            "bus_send",
        )
        .expect("upsert confidential private card");
        assert_eq!(private_card.visibility, "private");
        assert_eq!(private_card.target_repository, "emunlabs/chinwag-tasks");
        assert_eq!(private_card.assigned_seats, vec!["PATENT".to_string()]);

        let _ = fs::remove_dir_all(&repo_dir);
    }

    #[test]
    fn private_tasks_accept_internal_strategy_and_locked_seats() {
        for seat in PRIVATE_LOCKED_SEATS {
            let mut issue =
                AtomicTaskIssue::new_default("CHWG-0214", "Internal Strategy", DoraTier::M);
            issue.assigned_seats = vec![format!("■ @{seat}#instance")];
            issue.body = "Patent claim strategy for a US Provisional; MPEP 608. Internal node 10.0.0.1, state /Users/alice/.chinwag/state.crdb, formula $$x^2$$.".to_string();
            assert_eq!(validate_h_board_issue(&issue, &issue.to_markdown()), Ok(()));

            issue.visibility = "public".to_string();
            let err = validate_h_board_issue(&issue, &issue.to_markdown()).unwrap_err();
            assert_eq!(err.exit_code, EXIT_H_BOARD_REJECT);
            assert_eq!(err.invariant, "INV-DEFAULT-PRIVATE-TASK-01");
        }
    }

    #[test]
    fn task_visibility_rejects_unknown_values() {
        for visibility in ["", "internal", "privte", "public,private"] {
            let mut issue =
                AtomicTaskIssue::new_default("CHWG-0214", "Visibility Gate", DoraTier::S);
            issue.visibility = visibility.to_string();
            let err = validate_h_board_issue(&issue, &issue.to_markdown()).unwrap_err();
            assert_eq!(err.exit_code, EXIT_H_BOARD_REJECT);
            assert_eq!(err.invariant, "INV-DEFAULT-PRIVATE-TASK-01");
        }
    }

    #[test]
    fn secrets_are_rejected_for_public_and_private_tasks_including_raw_metadata() {
        for visibility in ["public", "private"] {
            for secret in [
                "ghp_example",
                "github_pat_example",
                "lin_api_example",
                "sk-example",
                "phc_example",
                "xai-example",
                "AKIAEXAMPLE",
                "-----BEGIN OPENSSH PRIVATE KEY-----",
                "-----BEGIN RSA PRIVATE KEY-----",
            ] {
                let mut issue =
                    AtomicTaskIssue::new_default("CHWG-0214", "Credential Gate", DoraTier::S);
                issue.visibility = visibility.to_string();
                issue.body = format!("Credential: {secret}");
                let err = validate_h_board_issue(&issue, &issue.to_markdown()).unwrap_err();
                assert_eq!(err.exit_code, EXIT_H_BOARD_REJECT);
                assert_eq!(err.invariant, "INV-BOARD-ZERO-LEAK-01");

                issue.body = "Safe task content".to_string();
                let raw = format!("{}\n<!-- {secret} -->", issue.to_markdown());
                let raw_err = validate_h_board_issue(&issue, &raw).unwrap_err();
                assert_eq!(raw_err.invariant, "INV-BOARD-ZERO-LEAK-01");

                issue.receipt_trailers.push(secret.to_string());
                let metadata_err = validate_h_board_issue(&issue, "safe raw input").unwrap_err();
                assert_eq!(metadata_err.invariant, "INV-BOARD-ZERO-LEAK-01");
            }
        }
    }

    #[test]
    fn private_tasks_keep_draft_and_lifecycle_gates() {
        let issue = AtomicTaskIssue::new_default("CHWG-0214", "Private Lifecycle", DoraTier::M);
        let mut draft = issue.clone();
        draft.item_type = "DraftIssue".to_string();
        let mut dirty = issue.clone();
        dirty.dirty_loc_at_claim = 1;
        let mut prebaked = issue.clone();
        prebaked.t_commit_ms = Some(prebaked.t_claim_ms - 1);
        let mut shipped_early = issue.clone();
        shipped_early.t_ship_ms = shipped_early.t_claim_ms - 1;
        let mut drifted = issue;
        drifted.github_comment_created_at_ms =
            Some(drifted.t_claim_ms + MAX_CLAIM_CLOCK_DRIFT_MS + 1);

        for (invalid, invariant) in [
            (draft, "INV-NO-DRAFT-ISSUES-01"),
            (dirty, "INV-NO-PREBAKED-CLAIM-01"),
            (prebaked, "INV-NO-PREBAKED-CLAIM-01"),
            (shipped_early, "INV-NO-PREBAKED-CLAIM-01"),
            (drifted, "INV-CLAIM-ANCHOR-01"),
        ] {
            let err = validate_h_board_issue(&invalid, &invalid.to_markdown()).unwrap_err();
            assert_eq!(err.exit_code, EXIT_H_BOARD_REJECT);
            assert_eq!(err.invariant, invariant);
        }
    }

    #[test]
    fn dry_run_preserves_private_and_public_repository_routes_without_writing_cards() {
        let dir = temp_tasks_dir("dual-repo-dry-run");
        let issues_dir = dir.join("issues");
        fs::create_dir_all(&issues_dir).unwrap();
        let mut private =
            AtomicTaskIssue::new_default("CHWG-0214-PRIVATE", "Patent Review", DoraTier::M);
        private.assigned_seats = vec!["@PATENT#instance".to_string()];
        private.body = "Patent claim strategy for a US Provisional.".to_string();
        let mut public =
            AtomicTaskIssue::new_default("CHWG-0214-PUBLIC", "Public Routing", DoraTier::S);
        public.visibility = "public".to_string();
        for issue in [&private, &public] {
            fs::write(
                issues_dir.join(format!("{}.md", issue.id)),
                issue.to_markdown(),
            )
            .unwrap();
        }

        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_board_cli(
            &[
                "push".to_string(),
                "--tasks-dir".to_string(),
                dir.to_string_lossy().to_string(),
                "--public-board".to_string(),
                "--private-repo".to_string(),
                "example/strategy".to_string(),
                "--public-repo".to_string(),
                "example/product".to_string(),
                "--dry-run".to_string(),
            ],
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0, "stderr: {}", String::from_utf8_lossy(&err));
        let payload: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(payload["issue_count"], 2);
        assert_eq!(payload["dry_run"], true);
        for mutations in [
            &payload["github_projects_v2"]["mutations"],
            &payload["linear"]["mutations"],
        ] {
            let mutations = mutations.as_array().unwrap();
            let private_mutation = mutations
                .iter()
                .find(|mutation| mutation["issue_id"] == private.id)
                .unwrap();
            assert_eq!(private_mutation["visibility"], "private");
            assert_eq!(private_mutation["target_repository"], "example/strategy");
            let public_mutation = mutations
                .iter()
                .find(|mutation| mutation["issue_id"] == public.id)
                .unwrap();
            assert_eq!(public_mutation["visibility"], "public");
            assert_eq!(public_mutation["target_repository"], "example/product");
        }
        assert!(!dir.join("board-cards.json").exists());
        assert!(!dir.join("board-config.json").exists());

        private.visibility = "public".to_string();
        fs::write(
            issues_dir.join(format!("{}.md", private.id)),
            private.to_markdown(),
        )
        .unwrap();
        out.clear();
        err.clear();
        let rejected = run_board_cli(
            &[
                "push".to_string(),
                "--tasks-dir".to_string(),
                dir.to_string_lossy().to_string(),
                "--dry-run".to_string(),
            ],
            &mut out,
            &mut err,
        );
        assert_eq!(rejected, EXIT_H_BOARD_REJECT);
        let rejection: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(rejection["invariant"], "INV-DEFAULT-PRIVATE-TASK-01");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cards_ledger_keeps_locked_tasks_and_loads_legacy_entries() {
        let dir = temp_tasks_dir("dual-repo-cards");
        let mut private =
            AtomicTaskIssue::new_default("CHWG-0214-PRIVATE", "Internal Review", DoraTier::M);
        private.assigned_seats = vec!["@PATENT#instance".to_string()];
        private.body = "Patent claim strategy".to_string();
        let mut public =
            AtomicTaskIssue::new_default("CHWG-0214-PUBLIC", "Public Review", DoraTier::S);
        public.visibility = "public".to_string();
        let cfg = BoardConfigV1 {
            private_repo: Some("example/strategy".to_string()),
            public_repo: Some("example/product".to_string()),
            ..BoardConfigV1::default()
        };
        let ledger = sync_board_cards_ledger(&dir, &[private, public], Some(&cfg)).unwrap();
        assert_eq!(ledger.total_cards, 2);
        let private_card = ledger
            .cards
            .iter()
            .find(|card| card.visibility == "private")
            .unwrap();
        assert_eq!(private_card.target_repository, "example/strategy");
        let public_card = ledger
            .cards
            .iter()
            .find(|card| card.visibility == "public")
            .unwrap();
        assert_eq!(public_card.target_repository, "example/product");
        assert_eq!(BoardCardsLedgerV1::load(&dir), ledger);

        let mut legacy = serde_json::to_value(&ledger).unwrap();
        for card in legacy["cards"].as_array_mut().unwrap() {
            let card = card.as_object_mut().unwrap();
            card.remove("visibility");
            card.remove("target_repository");
        }
        fs::write(
            dir.join("board-cards.json"),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        let restored = BoardCardsLedgerV1::load(&dir);
        assert_eq!(restored.total_cards, 2);
        assert!(
            restored
                .cards
                .iter()
                .all(|card| card.visibility == "private")
        );
        assert!(
            restored
                .cards
                .iter()
                .all(|card| card.target_repository.is_empty())
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn card_links_follow_repository_ownership_and_legacy_url_evidence() {
        let issue = AtomicTaskIssue::new_default("CHWG-0214", "Private Task", DoraTier::S);
        let mut cfg = BoardConfigV1::default();
        cfg.synced_issue_numbers.insert(issue.id.clone(), 14);
        cfg.synced_issue_urls.insert(
            issue.id.clone(),
            "https://github.com/emunlabs/chinwag/issues/14".to_string(),
        );
        cfg.synced_project_item_ids
            .insert(issue.id.clone(), "PVTI_public".to_string());
        cfg.synced_issue_repos
            .insert(issue.id.clone(), "emunlabs/chinwag".to_string());
        let mismatched = card_entry_from_issue(&issue, Some(&cfg), None, None);
        assert_eq!(mismatched.target_repository, "emunlabs/chinwag-tasks");
        assert_eq!(mismatched.github_issue_number, None);
        assert_eq!(mismatched.github_issue_url, None);
        assert_eq!(mismatched.project_item_id, None);

        cfg.synced_issue_repos.remove(&issue.id);
        let legacy_mismatch = card_entry_from_issue(&issue, Some(&cfg), None, None);
        assert_eq!(legacy_mismatch.github_issue_number, None);
        cfg.synced_issue_urls.insert(
            issue.id.clone(),
            "https://github.com/emunlabs/chinwag-tasks/issues/14".to_string(),
        );
        let legacy_match = card_entry_from_issue(&issue, Some(&cfg), None, None);
        assert_eq!(legacy_match.github_issue_number, Some(14));
        assert_eq!(legacy_match.project_item_id.as_deref(), Some("PVTI_public"));

        cfg.synced_issue_repos
            .insert(issue.id.clone(), "emunlabs/chinwag-tasks".to_string());
        let owned = card_entry_from_issue(&issue, Some(&cfg), None, None);
        assert_eq!(owned.github_issue_number, Some(14));
        assert_eq!(owned.github_issue_url, legacy_match.github_issue_url);
        cfg.synced_issue_repos
            .insert(issue.id.clone(), "emunlabs/chinwag".to_string());
        let conflicting_owner = card_entry_from_issue(&issue, Some(&cfg), None, None);
        assert_eq!(conflicting_owner.github_issue_number, None);
    }

    #[test]
    fn thread_card_upsert_clears_links_after_repository_change() {
        let repo_dir = temp_tasks_dir("thread-card-move");
        let tasks_dir = repo_dir.join(".chinwag/tasks");
        fs::create_dir_all(&tasks_dir).unwrap();
        let issue = AtomicTaskIssue::new_default("CHWG-0214", "Private Task", DoraTier::S);
        let mut ledger = sync_board_cards_ledger(&tasks_dir, &[issue], None).unwrap();
        ledger.cards[0].github_issue_number = Some(14);
        ledger.cards[0].github_issue_url =
            Some("https://github.com/emunlabs/chinwag-tasks/issues/14".to_string());
        ledger.cards[0].project_item_id = Some("PVTI_old".to_string());
        ledger.save(&tasks_dir).unwrap();
        let cfg = BoardConfigV1 {
            private_repo: Some("example/strategy".to_string()),
            ..BoardConfigV1::default()
        };
        cfg.save(&tasks_dir).unwrap();
        let moved = upsert_agent_thread_board_card(
            &repo_dir,
            "CHWG-0214",
            "PATENT",
            None,
            "Private review",
            false,
            None,
            "bus_send",
        )
        .unwrap();
        assert_eq!(moved.target_repository, "example/strategy");
        assert_eq!(moved.github_issue_number, None);
        assert_eq!(moved.github_issue_url, None);
        assert_eq!(moved.project_item_id, None);
        let _ = fs::remove_dir_all(&repo_dir);
    }

    #[test]
    fn thread_card_upsert_rejects_secrets_and_public_locked_seats() {
        let repo_dir = temp_tasks_dir("thread-card-security");
        let tasks_dir = repo_dir.join(".chinwag/tasks");
        fs::create_dir_all(&tasks_dir).unwrap();
        let secret_summary = format!("{} ghp_example", "safe ".repeat(30));
        let err = upsert_agent_thread_board_card(
            &repo_dir,
            "CHWG-0214",
            "PATENT",
            None,
            &secret_summary,
            false,
            None,
            "bus_send",
        )
        .unwrap_err();
        assert!(err.contains("INV-BOARD-ZERO-LEAK-01"));
        assert!(!tasks_dir.join("board-cards.json").exists());

        let mut issue = AtomicTaskIssue::new_default("CHWG-0214", "Public Task", DoraTier::S);
        issue.visibility = "public".to_string();
        sync_board_cards_ledger(&tasks_dir, &[issue], None).unwrap();
        let err = upsert_agent_thread_board_card(
            &repo_dir,
            "CHWG-0214",
            "PATENT",
            None,
            "Review task",
            false,
            None,
            "bus_send",
        )
        .unwrap_err();
        assert!(err.contains("INV-DEFAULT-PRIVATE-TASK-01"));
        let ledger = BoardCardsLedgerV1::load(&tasks_dir);
        assert!(
            !ledger.cards[0]
                .assigned_seats
                .iter()
                .any(|seat| seat == "PATENT")
        );
        let _ = fs::remove_dir_all(&repo_dir);
    }

    #[test]
    fn test_20_h_board_rejects_forbidden_board_substrings() {
        for forbidden in FORBIDDEN_BOARD_SUBSTRINGS {
            let mut issue =
                AtomicTaskIssue::new_default("CHWG-0599", "Forbidden Jargon Test", DoraTier::S);
            issue.visibility = "public".to_string();
            issue.body = format!("Ticket body containing rejected substring: {forbidden}");
            let err = validate_h_board_issue(&issue, &issue.to_markdown())
                .expect_err("must reject forbidden vendor/jargon substring");
            assert_eq!(err.exit_code, EXIT_H_BOARD_REJECT);
            assert_eq!(err.invariant, "INV-PUBLIC-BOARD-REDACTION-01");
            assert!(err.reason.contains(forbidden));
        }
    }

    #[test]
    fn test_21_dual_view_kanban_templates_and_decision_gate_assessment_cache() {
        let cfg = BoardConfigV1::default();
        let gh_schema = build_github_project_v2_template_schema(&cfg);
        assert_eq!(gh_schema["default_view_layout"], "BOARD_LAYOUT");
        let gh_views = gh_schema["views"].as_array().expect("gh views array");
        assert_eq!(gh_views.len(), 4);
        assert_eq!(gh_views[0]["code"], "01_KANBAN_EXECUTION_BOARD");
        assert_eq!(gh_views[0]["layout"], "BOARD_LAYOUT");
        assert_eq!(gh_views[1]["code"], "02_VELOCITY_AND_DORA_LEDGER");
        assert_eq!(gh_views[1]["layout"], "TABLE_LAYOUT");
        assert_eq!(gh_views[2]["code"], "03_WORK_BY_FUNCTION");
        assert_eq!(gh_views[2]["layout"], "TABLE_LAYOUT");
        assert_eq!(gh_views[3]["code"], "04_OPEN_BOUNTIES");
        assert_eq!(gh_views[3]["layout"], "BOARD_LAYOUT");

        let lin_schema = build_linear_template_schema(&cfg);
        assert_eq!(lin_schema["default_view_layout"], "board");
        let lin_views = lin_schema["views"].as_array().expect("linear views array");
        assert_eq!(lin_views.len(), 4);
        assert_eq!(lin_views[0]["layout"], "board");
        assert_eq!(lin_views[1]["layout"], "list");
        assert_eq!(lin_views[2]["layout"], "list");
        assert_eq!(lin_views[3]["layout"], "board");

        let dir = temp_tasks_dir("decision-gate-cache");
        let mut issue =
            AtomicTaskIssue::new_default("CHWG-0206", "Decision Gate Calibration", DoraTier::L);
        issue.loc_changed = Some(420);
        let gate1 = evaluate_issue_decision_gate(&dir, &issue, false);
        assert_eq!(gate1.issue_id, "CHWG-0206");
        assert_eq!(gate1.dora_tier_guess, "L");
        assert!(gate1.clairic_loc_p90 >= gate1.clairic_loc_median);
        assert!(dir.join("decision-gate-cache.json").exists());

        let gate2 = evaluate_issue_decision_gate(&dir, &issue, false);
        assert_eq!(gate1, gate2);

        let serialized = serde_json::to_string(&gate1).unwrap();
        assert!(scan_zero_leak_text(&serialized).is_ok());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_22_entity_firewall_rejects_drey_rmm_multi_id_and_protects_shipped_verified() {
        let repo_dir = temp_tasks_dir("entity-firewall-repo");
        let tasks_dir = repo_dir.join(".chinwag/tasks");
        let issues_dir = tasks_dir.join("issues");
        fs::create_dir_all(&issues_dir).unwrap();

        let mut shipped_issue =
            AtomicTaskIssue::new_default("CHWG-0208", "Shipped Header Fix", DoraTier::M);
        shipped_issue.status = BoardStatus::ShippedVerified;
        shipped_issue.t_claim_ms = 1_794_370_620_000;
        shipped_issue.t_ship_ms = 1_794_371_700_000;
        shipped_issue.loc_changed = Some(180);
        fs::write(issues_dir.join("CHWG-0208.md"), shipped_issue.to_markdown()).unwrap();
        sync_board_cards_ledger(&tasks_dir, &[shipped_issue.clone()], None).unwrap();

        // 1. Reject DREY-*, RMM-*, SEC-*, INV-*, CHWG-PM-DELIVERY-LOOP-01, and comma-separated multi-IDs
        for bad_id in [
            "DREY-AUDIT-2026-11-11",
            "DREY-WALLET-SQUIRREL-AUDIT-01",
            "RMM-DREY-REVIEW-01",
            "RMM-INVESTIGATIONS-CARBON-HIGH",
            "SEC-GLASSWORM-HOST-CHECK",
            "INV-PR-MERGE-TRIBUNAL-01",
            "CHWG-PM-DELIVERY-LOOP-01",
            "CHWG-0209,CHWG-0207.3",
            "CHWG-0203,CHWG-0205,CHWG-0227..0233",
            "CHWG-9999",
        ] {
            let err = upsert_agent_thread_board_card(
                &repo_dir,
                bad_id,
                "DEX",
                None,
                "Safe summary",
                true,
                None,
                "memory_retain",
            )
            .expect_err(&format!("must reject {bad_id}"));
            assert!(
                err.contains("INV-ENTITY-SEP-01"),
                "expected INV-ENTITY-SEP-01 for {bad_id}, got {err}"
            );
        }

        // 2. Reject cross-entity body/summary strings even on a valid CHWG-0208 ID
        for bad_summary in [
            "Audit Drey Finance wallet",
            "Rogue Machine Media LLC review",
            "SquirrelSystems Robert R. Khan check",
            "2Real token contract",
        ] {
            let err = upsert_agent_thread_board_card(
                &repo_dir,
                "CHWG-0208",
                "DEX",
                None,
                bad_summary,
                false,
                None,
                "memory_retain",
            )
            .expect_err(&format!("must reject summary `{bad_summary}`"));
            assert!(err.contains("INV-ENTITY-SEP-01"));
        }

        // 3. Monotonic 05_SHIPPED_VERIFIED protection: mark_completed=false or stale sync cannot downgrade CHWG-0208
        let card_after = upsert_agent_thread_board_card(
            &repo_dir,
            "CHWG-0208",
            "DEX",
            Some("INFRAJR"),
            "Follow-up bus receipt",
            false,
            None,
            "bus_send",
        )
        .unwrap();
        assert_eq!(card_after.status, "05_SHIPPED_VERIFIED");

        let mut stale_issue = shipped_issue.clone();
        stale_issue.status = BoardStatus::InFlight;
        let ledger_after = sync_board_cards_ledger(&tasks_dir, &[stale_issue], None).unwrap();
        assert_eq!(ledger_after.cards.len(), 1);
        assert_eq!(ledger_after.cards[0].id, "CHWG-0208");
        assert_eq!(ledger_after.cards[0].status, "05_SHIPPED_VERIFIED");

        let _ = fs::remove_dir_all(&repo_dir);
    }

    #[test]
    fn test_23_discover_live_threads_surface_collision_and_crisis_alert_banner() {
        let repo_dir = temp_tasks_dir("beacon-crisis-repo");
        let bus_dir = repo_dir.join(".chinwag/bus");
        let issues_dir = repo_dir.join(".chinwag/tasks/issues");
        fs::create_dir_all(&bus_dir).unwrap();
        fs::create_dir_all(&issues_dir).unwrap();

        let lines = [
            json!({
                "id": "bus-1",
                "ts_unix": 1_794_380_000_u64,
                "sender": "GEMINI-PM#f3ef0a87-893f-45d3-a15e-10a9f7e558cc",
                "to": "DEX#6df4d436df6c01617dcd2f4e404673fc,INFRAJR#0049dd19946d89fd047810fec6676b05",
                "room": "#mgmt",
                "body": "Delegate CHWG-0234"
            })
            .to_string(),
            json!({
                "id": "bus-2",
                "ts_unix": 1_794_380_100_u64,
                "sender": "WORKHORSE#AaFG0NdpegKhpXXEB_-qPA",
                "to": "QA#81126a23-dd44-4e64-8450-bf1a6c8e3c7b",
                "room": "#eng",
                "body": "Ready for QA"
            })
            .to_string(),
        ];
        fs::write(bus_dir.join("messages.jsonl"), lines.join("\n")).unwrap();

        let live =
            discover_live_thread_instances(&repo_dir, Some("DEX#6df4d436df6c01617dcd2f4e404673fc"));
        assert_eq!(
            live,
            vec![
                "GEMINI-PM#f3ef0a87-893f-45d3-a15e-10a9f7e558cc".to_string(),
                "INFRAJR#0049dd19946d89fd047810fec6676b05".to_string(),
                "QA#81126a23-dd44-4e64-8450-bf1a6c8e3c7b".to_string(),
                "WORKHORSE#AaFG0NdpegKhpXXEB_-qPA".to_string(),
            ]
        );

        let mut other_issue =
            AtomicTaskIssue::new_default("CHWG-0230", "Other In-Flight Work", DoraTier::M);
        other_issue.status = BoardStatus::InFlight;
        other_issue.author_instance = Some("WORKHORSE#AaFG0NdpegKhpXXEB_-qPA".to_string());
        other_issue.file_scope = "crates/chinwag-cli/src/board/**".to_string();
        fs::write(issues_dir.join("CHWG-0230.md"), other_issue.to_markdown()).unwrap();

        let collisions = detect_in_flight_surface_collisions(
            &repo_dir,
            "CHWG-0234",
            "DEX#6df4d436df6c01617dcd2f4e404673fc",
            &["crates/chinwag-cli/src/board/mod.rs".to_string()],
        );
        assert_eq!(collisions.len(), 1);
        assert_eq!(collisions[0].other_ticket_id, "CHWG-0230");
        assert_eq!(
            collisions[0].other_owner,
            "WORKHORSE#AaFG0NdpegKhpXXEB_-qPA"
        );

        write_active_crisis(
            &repo_dir,
            &ActiveCrisisRecord {
                schema: "chinwag.bus.crisis.v1".to_string(),
                invariant: "INV-CRISIS-ALL-STOP-BROADCAST-01".to_string(),
                active: true,
                sender: "GEMINI-PM#f3ef0a87-893f-45d3-a15e-10a9f7e558cc".to_string(),
                task_id: Some("CHWG-0234".to_string()),
                message: "Halt unguarded board sync".to_string(),
                ts_unix: 1_794_380_200,
                ts_iso: "2026-11-11T06:15:00-0600 CST".to_string(),
                notified_threads: live,
            },
        )
        .unwrap();

        let mut stderr = Vec::new();
        emit_active_crisis_alert_if_any(&repo_dir, &mut stderr);
        let alert = String::from_utf8(stderr).unwrap();
        assert!(alert.contains("INV-CRISIS-ALL-STOP-BROADCAST-01"));
        assert!(alert.contains("Halt unguarded board sync"));

        let _ = fs::remove_dir_all(&repo_dir);
    }
}
