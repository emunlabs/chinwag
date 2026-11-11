// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Zero-PII PostHog Telemetry Validator & Background Forwarder (`CHWG-0207.3`).
//!
//! Enforces:
//!   - Closed 56-event allowlist (`UiTelemetryEvent`).
//!   - Closed 127-key client property allowlist (`ALLOWLISTED_PROPERTY_KEYS`).
//!   - Fail-closed whole-event rejection on unknown events, unallowlisted/spoofed keys,
//!     `SampleWalkthroughShipForbidden` violations, or any string matching the 9 PII/jargon
//!     scanners (paths, dotfiles, emails, URLs/git remotes, IPv4/IPv6, secrets/SHAs,
//!     internal/vendor jargon, invalid token charset, or out-of-domain enum/integer bounds).
//!   - Environment opt-out (`CHINWAG_NO_TELEMETRY=1`, `CHINWAG_TELEMETRY_DISABLED=1`,
//!     `DO_NOT_TRACK=1`) and synthetic CI tagging (`CI=true`, `CHINWAG_TELEMETRY_CANARY_RUN`).
//!   - Bounded `256`-slot `mpsc::sync_channel` worker with token-bucket rate limiting (`60/min`,
//!     burst `30`) and `curl --data-binary @-` over `Stdio::piped()` (zero payload bytes in `argv`).

use rand::RngCore;
use rustix::fs::{AtFlags, CWD, Mode, OFlags, fsync, openat, renameat, statat, unlinkat};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAX_TELEMETRY_HTTP_BYTES: usize = 4_096;
pub const MAX_TELEMETRY_PROPS_COUNT: usize = 24;
pub const MAX_TELEMETRY_STR_LEN: usize = 64;
pub const TELEMETRY_QUEUE_CAPACITY: usize = 256;
pub const POSTHOG_EDGE_TRACK_URL: &str = "https://chinwag.sh/ph/track";

/// Exact 56 allowlisted telemetry events for `chinwag ui` (`v4.1`).
pub const ALL_ALLOWLISTED_EVENTS: &[&str] = &[
    // Category A — Session, Navigation & Performance (5)
    "ui_session_started",
    "ui_heartbeat_active",
    "ui_deep_link_bounced",
    "ui_theme_changed",
    "ui_view_navigated",
    // Category B — First-Run 60-Second Onboarding, Tool Discovery & Pairing (10)
    "ui_onboarding_checklist_viewed",
    "ui_onboarding_step_completed",
    "ui_onboarding_dismissed",
    "ui_sample_walkthrough_triggered",
    "ui_sample_walkthrough_finished",
    "ui_cli_tool_detected_summary",
    "ui_cli_setup_command_copied",
    "ui_cursor_import_previewed",
    "ui_cursor_import_completed",
    "ui_cross_tool_pairing_updated",
    // Category C — Core Inbox, Diff & Review & Guardrail Hold Loop (11)
    "ui_inbox_filter_selected",
    "ui_inbox_item_opened",
    "ui_diff_mode_toggled",
    "ui_step_strip_expanded",
    "ui_diff_approved_and_pushed",
    "ui_diff_applied_locally",
    "ui_diff_rejected",
    "ui_hold_approved_once",
    "ui_hold_rule_updated",
    "ui_hold_rejected",
    "ui_pm_prompt_submitted",
    // Category D — Board, Workflow Integrations & Safety Guardrails (12)
    "ui_board_task_modal_opened",
    "ui_board_task_created",
    "ui_board_card_opened",
    "ui_board_sync_triggered",
    "ui_board_sync_clicked",
    "ui_board_sync_completed",
    "ui_board_filter_changed",
    "ui_board_shipped_strip_seen",
    "ui_guardrail_toggled",
    "ui_protected_path_added",
    "ui_protected_path_removed",
    "ui_integration_snippet_copied",
    // Category E — Viral Expansion, Multi-Repo Land-and-Expand & Credits (12)
    "ui_speed_summary_copied",
    "ui_invite_modal_opened",
    "ui_invite_copied",
    "ui_org_pool_joined",
    "ui_repo_connected",
    "ui_credits_tab_viewed",
    "ui_credits_pack_selected",
    "ui_credits_checkout_clicked",
    "ui_low_credit_alert_toggled",
    "ui_founders_talk_clicked",
    "ui_privacy_popover_opened",
    "ui_telemetry_opt_out_changed",
    // Category F — Depletion Holds, Empty-State & Error Observability (6)
    "ui_low_credit_banner_shown",
    "ui_credits_depleted_hold_shown",
    "ui_repo_uninitialized_viewed",
    "ui_action_failed",
    "ui_circuit_breaker_triggered",
    "ui_sse_stream_reconnected",
];

/// Canonical sorted 127 client-allowlisted property keys across all 56 events.
/// Server-attached relational keys (`distinct_id`, `surface`, `ui_version`,
/// `org_anon_id`, `repo_anon_id`, `install_cohort_week`, `os_family`, `arch`,
/// `session_seq`, `is_synthetic_ci`) are intentionally excluded here so client
/// spoofing is rejected fail-closed with `UnallowlistedPropertyKey`.
pub const ALLOWLISTED_PROPERTY_KEYS: &[&str] = &[
    "active_days_last_7d",
    "active_minutes_session",
    "active_tasks_bucket",
    "alert_enabled",
    "all_completed",
    "assigned_tool_kind",
    "attempt_number",
    "board_column",
    "boot_latency_ms_bucket",
    "bounce_source",
    "checkout_attempt_id",
    "chip_slug",
    "copy_surface",
    "credits_remaining_bucket",
    "decision_latency_bucket",
    "deep_link_target",
    "detected_tool_families_mask",
    "detected_tools_count",
    "diff_mode",
    "diff_sheet_open",
    "discovered_rules_bucket",
    "driver_tool_kind",
    "elapsed_since_boot_sec_bucket",
    "entry_route",
    "entry_source",
    "entry_trigger",
    "error_category",
    "expanded",
    "failed_action",
    "failure_stage",
    "files_changed_bucket",
    "filter",
    "function_credits_cost",
    "github_connected",
    "guardrail_enabled",
    "guardrail_id",
    "has_claude_code",
    "has_codex_cli",
    "has_cursor",
    "has_cursor_dir",
    "has_deep_link",
    "has_gemini_cli",
    "has_gh_cli",
    "has_linked_diff",
    "has_target_files",
    "has_time_saved_pill",
    "hold_category",
    "hours_bucket",
    "http_status",
    "import_outcome",
    "imported_agents_bucket",
    "inbox_badge_bucket",
    "includes_open_link",
    "includes_referral_link",
    "input_source",
    "integration_kind",
    "invite_format",
    "invite_kind",
    "is_cross_model_verified",
    "is_git_repo",
    "is_sample_walkthrough",
    "is_under_15s",
    "item_kind",
    "item_status",
    "join_role",
    "learned_rules_count_bucket",
    "linear_connected",
    "lines_changed_bucket",
    "low_credit_alert_enabled",
    "matching_items_bucket",
    "nav_trigger",
    "opt_out_enabled",
    "org_active_repos_bucket",
    "pack_credits",
    "pack_price_usd",
    "pack_slug",
    "path_category",
    "plan_tier",
    "pm_outcome",
    "preference_action",
    "previous_theme",
    "previous_view",
    "prompt_length_bucket",
    "protected_paths_count_bucket",
    "receipt_has_command",
    "receipt_has_duration",
    "receipt_has_revision",
    "recommended_pack_slug",
    "reconnect_attempt_bucket",
    "reject_reason_category",
    "result",
    "reviewer_tool_kind",
    "rule_change_action",
    "runway_days_bucket",
    "safety_checks_passed_count",
    "sandbox_tests_passed",
    "sanitized_warnings_count",
    "shipped_bucket",
    "step_actor",
    "step_index",
    "step_slug",
    "steps_completed_count",
    "summary_surface",
    "surface_readiness",
    "sync_direction",
    "sync_external_tracker",
    "sync_outcome",
    "synced_items_bucket",
    "target",
    "target_found",
    "telemetry_state",
    "theme",
    "threshold_credits",
    "time_saved_baseline_documented",
    "time_saved_minutes_bucket",
    "time_since_install_bucket",
    "tool_kind",
    "tracker_kind",
    "transport_mode",
    "trigger_surface",
    "ui_theme",
    "uninit_action",
    "view",
    "viewport_bucket",
    "walkthrough_mode",
    "workflow_fn",
    "workstream",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UiTelemetryEvent {
    UiSessionStarted,
    UiHeartbeatActive,
    UiDeepLinkBounced,
    UiThemeChanged,
    UiViewNavigated,
    UiOnboardingChecklistViewed,
    UiOnboardingStepCompleted,
    UiOnboardingDismissed,
    UiSampleWalkthroughTriggered,
    UiSampleWalkthroughFinished,
    UiCliToolDetectedSummary,
    UiCliSetupCommandCopied,
    UiCursorImportPreviewed,
    UiCursorImportCompleted,
    UiCrossToolPairingUpdated,
    UiInboxFilterSelected,
    UiInboxItemOpened,
    UiDiffModeToggled,
    UiStepStripExpanded,
    UiDiffApprovedAndPushed,
    UiDiffAppliedLocally,
    UiDiffRejected,
    UiHoldApprovedOnce,
    UiHoldRuleUpdated,
    UiHoldRejected,
    UiPmPromptSubmitted,
    UiBoardTaskModalOpened,
    UiBoardTaskCreated,
    UiBoardCardOpened,
    UiBoardSyncTriggered,
    UiBoardSyncClicked,
    UiBoardSyncCompleted,
    UiBoardFilterChanged,
    UiBoardShippedStripSeen,
    UiGuardrailToggled,
    UiProtectedPathAdded,
    UiProtectedPathRemoved,
    UiIntegrationSnippetCopied,
    UiSpeedSummaryCopied,
    UiInviteModalOpened,
    UiInviteCopied,
    UiOrgPoolJoined,
    UiRepoConnected,
    UiCreditsTabViewed,
    UiCreditsPackSelected,
    UiCreditsCheckoutClicked,
    UiLowCreditAlertToggled,
    UiFoundersTalkClicked,
    UiPrivacyPopoverOpened,
    UiTelemetryOptOutChanged,
    UiLowCreditBannerShown,
    UiCreditsDepletedHoldShown,
    UiRepoUninitializedViewed,
    UiActionFailed,
    UiCircuitBreakerTriggered,
    UiSseStreamReconnected,
}

impl UiTelemetryEvent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UiSessionStarted => "ui_session_started",
            Self::UiHeartbeatActive => "ui_heartbeat_active",
            Self::UiDeepLinkBounced => "ui_deep_link_bounced",
            Self::UiThemeChanged => "ui_theme_changed",
            Self::UiViewNavigated => "ui_view_navigated",
            Self::UiOnboardingChecklistViewed => "ui_onboarding_checklist_viewed",
            Self::UiOnboardingStepCompleted => "ui_onboarding_step_completed",
            Self::UiOnboardingDismissed => "ui_onboarding_dismissed",
            Self::UiSampleWalkthroughTriggered => "ui_sample_walkthrough_triggered",
            Self::UiSampleWalkthroughFinished => "ui_sample_walkthrough_finished",
            Self::UiCliToolDetectedSummary => "ui_cli_tool_detected_summary",
            Self::UiCliSetupCommandCopied => "ui_cli_setup_command_copied",
            Self::UiCursorImportPreviewed => "ui_cursor_import_previewed",
            Self::UiCursorImportCompleted => "ui_cursor_import_completed",
            Self::UiCrossToolPairingUpdated => "ui_cross_tool_pairing_updated",
            Self::UiInboxFilterSelected => "ui_inbox_filter_selected",
            Self::UiInboxItemOpened => "ui_inbox_item_opened",
            Self::UiDiffModeToggled => "ui_diff_mode_toggled",
            Self::UiStepStripExpanded => "ui_step_strip_expanded",
            Self::UiDiffApprovedAndPushed => "ui_diff_approved_and_pushed",
            Self::UiDiffAppliedLocally => "ui_diff_applied_locally",
            Self::UiDiffRejected => "ui_diff_rejected",
            Self::UiHoldApprovedOnce => "ui_hold_approved_once",
            Self::UiHoldRuleUpdated => "ui_hold_rule_updated",
            Self::UiHoldRejected => "ui_hold_rejected",
            Self::UiPmPromptSubmitted => "ui_pm_prompt_submitted",
            Self::UiBoardTaskModalOpened => "ui_board_task_modal_opened",
            Self::UiBoardTaskCreated => "ui_board_task_created",
            Self::UiBoardCardOpened => "ui_board_card_opened",
            Self::UiBoardSyncTriggered => "ui_board_sync_triggered",
            Self::UiBoardSyncClicked => "ui_board_sync_clicked",
            Self::UiBoardSyncCompleted => "ui_board_sync_completed",
            Self::UiBoardFilterChanged => "ui_board_filter_changed",
            Self::UiBoardShippedStripSeen => "ui_board_shipped_strip_seen",
            Self::UiGuardrailToggled => "ui_guardrail_toggled",
            Self::UiProtectedPathAdded => "ui_protected_path_added",
            Self::UiProtectedPathRemoved => "ui_protected_path_removed",
            Self::UiIntegrationSnippetCopied => "ui_integration_snippet_copied",
            Self::UiSpeedSummaryCopied => "ui_speed_summary_copied",
            Self::UiInviteModalOpened => "ui_invite_modal_opened",
            Self::UiInviteCopied => "ui_invite_copied",
            Self::UiOrgPoolJoined => "ui_org_pool_joined",
            Self::UiRepoConnected => "ui_repo_connected",
            Self::UiCreditsTabViewed => "ui_credits_tab_viewed",
            Self::UiCreditsPackSelected => "ui_credits_pack_selected",
            Self::UiCreditsCheckoutClicked => "ui_credits_checkout_clicked",
            Self::UiLowCreditAlertToggled => "ui_low_credit_alert_toggled",
            Self::UiFoundersTalkClicked => "ui_founders_talk_clicked",
            Self::UiPrivacyPopoverOpened => "ui_privacy_popover_opened",
            Self::UiTelemetryOptOutChanged => "ui_telemetry_opt_out_changed",
            Self::UiLowCreditBannerShown => "ui_low_credit_banner_shown",
            Self::UiCreditsDepletedHoldShown => "ui_credits_depleted_hold_shown",
            Self::UiRepoUninitializedViewed => "ui_repo_uninitialized_viewed",
            Self::UiActionFailed => "ui_action_failed",
            Self::UiCircuitBreakerTriggered => "ui_circuit_breaker_triggered",
            Self::UiSseStreamReconnected => "ui_sse_stream_reconnected",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TelemetryScalar {
    Bool(bool),
    Int(i64),
    Str(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryTrackRequest {
    pub event: UiTelemetryEvent,
    #[serde(default)]
    pub props: BTreeMap<String, TelemetryScalar>,
    #[serde(default)]
    pub properties: BTreeMap<String, TelemetryScalar>,
    #[serde(default)]
    pub client_ts_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryRejectReason {
    PayloadTooLarge,
    InvalidJsonOrUnknownEvent,
    TooManyProperties,
    UnallowlistedPropertyKey,
    SampleWalkthroughShipForbidden,
    EmptyOrOversizedString,
    InvalidTokenCharset,
    ForbiddenPathOrDotfile,
    ForbiddenEmailLiteral,
    ForbiddenIpAddressLiteral,
    ForbiddenUrlOrGitRemote,
    ForbiddenSecretOrHighEntropyToken,
    ForbiddenVendorOrInternalJargon,
    InvalidPropertyTypeOrEnumValue,
    IntegerOutOfBounds,
}

impl TelemetryRejectReason {
    pub fn code(&self) -> &'static str {
        match self {
            Self::PayloadTooLarge => "PayloadTooLarge",
            Self::InvalidJsonOrUnknownEvent => "InvalidJsonOrUnknownEvent",
            Self::TooManyProperties => "TooManyProperties",
            Self::UnallowlistedPropertyKey => "UnallowlistedPropertyKey",
            Self::SampleWalkthroughShipForbidden => "SampleWalkthroughShipForbidden",
            Self::EmptyOrOversizedString => "EmptyOrOversizedString",
            Self::InvalidTokenCharset => "InvalidTokenCharset",
            Self::ForbiddenPathOrDotfile => "ForbiddenPathOrDotfile",
            Self::ForbiddenEmailLiteral => "ForbiddenEmailLiteral",
            Self::ForbiddenIpAddressLiteral => "ForbiddenIpAddressLiteral",
            Self::ForbiddenUrlOrGitRemote => "ForbiddenUrlOrGitRemote",
            Self::ForbiddenSecretOrHighEntropyToken => "ForbiddenSecretOrHighEntropyToken",
            Self::ForbiddenVendorOrInternalJargon => "ForbiddenVendorOrInternalJargon",
            Self::InvalidPropertyTypeOrEnumValue => "InvalidPropertyTypeOrEnumValue",
            Self::IntegerOutOfBounds => "IntegerOutOfBounds",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidatedPostHogEvent {
    pub event: String,
    pub distinct_id: String,
    pub properties: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnqueueOutcome {
    Queued,
    DroppedOptedOut,
    DroppedRateLimited,
    DroppedQueueFull,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedTelemetryConfig {
    enabled: bool,
    install_cohort_week: String,
    updated_at_unix: u64,
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    last_heartbeat: Option<Instant>,
}

impl TokenBucket {
    fn new() -> Self {
        Self {
            tokens: 30.0,
            last_refill: Instant::now(),
            last_heartbeat: None,
        }
    }

    fn try_acquire(&mut self, event: UiTelemetryEvent) -> bool {
        let now = Instant::now();
        if event == UiTelemetryEvent::UiHeartbeatActive {
            if let Some(prev) = self.last_heartbeat
                && now.duration_since(prev) < Duration::from_millis(55_000)
            {
                return false;
            }
            self.last_heartbeat = Some(now);
        }
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * 1.0).min(30.0);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct UiTelemetryRuntime {
    sender: SyncSender<ValidatedPostHogEvent>,
    ui_enabled: AtomicBool,
    session_seq: AtomicU64,
    dropped_full_count: AtomicU64,
    preferences_lock: Mutex<()>,
    identity_lock: Mutex<(String, String)>, // (distinct_id, install_cohort_week)
    rate_limiter: Mutex<TokenBucket>,
    config_dir: PathBuf,
    #[cfg_attr(not(test), allow(dead_code))]
    test_sink: Option<Arc<Mutex<Vec<ValidatedPostHogEvent>>>>,
}

static GLOBAL_TELEMETRY_RUNTIME: OnceLock<Arc<UiTelemetryRuntime>> = OnceLock::new();

const FORBIDDEN_TELEMETRY_JARGON: &[&str] = &[
    concat!("mer", "cury"),
    concat!("incep", "tion"),
    concat!("ver", "cel"),
    concat!("ai-", "gateway"),
    concat!("cl", "ef"),
    concat!("clai", "ric"),
    concat!("gpt-", "oss"),
    concat!("eve-", "bridge"),
    concat!("deep", "seek"),
    concat!("gr", "ok"),
    concat!("fa", "ble"),
    concat!("ar", "gon"),
    concat!("fl", "int"),
    concat!("cloud", "flare"),
    concat!("workers-", "ai"),
    concat!("cloudflare", "os"),
    concat!("feather", "less"),
    concat!("fire", "works"),
    concat!("open", "router"),
    "together",
    "baseten",
    "bedrock",
    "vertex",
    concat!("m", "lx"),
    concat!("cf-", "ray"),
    concat!("work", "horse"),
    concat!("alis", "tair"),
    concat!("gemini-", "pm"),
    concat!("emun", "labs"),
    concat!("rogue-", "machine"),
    "laglords",
    "captionize",
];

fn env_is_truthy(name: &str) -> bool {
    std::env::var(name).ok().is_some_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

/// Priority-1 environment hard opt-out check (`CHINWAG_NO_TELEMETRY=1`,
/// `CHINWAG_TELEMETRY_DISABLED=1`, or `DO_NOT_TRACK=1`).
pub fn is_env_telemetry_disabled() -> bool {
    env_is_truthy("CHINWAG_NO_TELEMETRY")
        || env_is_truthy("CHINWAG_TELEMETRY_DISABLED")
        || env_is_truthy("DO_NOT_TRACK")
}

/// Synthetic CI / canary execution check (`CI=true`, `CHINWAG_TELEMETRY_CANARY_RUN`,
/// or `CHINWAG_UI_SYNTHETIC_TEST=1`).
pub fn is_synthetic_ci_env() -> bool {
    env_is_truthy("CI")
        || env_is_truthy("CHINWAG_UI_SYNTHETIC_TEST")
        || std::env::var("CHINWAG_TELEMETRY_CANARY_RUN")
            .ok()
            .is_some_and(|s| !s.trim().is_empty())
}

pub fn is_exact_uuid_v4(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let b = s.as_bytes();
    for (idx, &ch) in b.iter().enumerate() {
        match idx {
            8 | 13 | 18 | 23 => {
                if ch != b'-' {
                    return false;
                }
            }
            14 => {
                if ch != b'4' {
                    return false;
                }
            }
            19 => {
                if !matches!(ch, b'8' | b'9' | b'a' | b'b') {
                    return false;
                }
            }
            _ => {
                if !(ch.is_ascii_digit() || (b'a'..=b'f').contains(&ch)) {
                    return false;
                }
            }
        }
    }
    true
}

fn has_16_contiguous_hex(s: &str) -> bool {
    let mut run = 0usize;
    for b in s.bytes() {
        if b.is_ascii_hexdigit() {
            run += 1;
            if run >= 16 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn looks_like_ipv4_dotted_quad(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts
        .iter()
        .all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
}

const COUNT_BUCKETS: &[&str] = &["0", "1_3", "4_10", "11_25", "26_plus"];
const TOOL_KINDS_4: &[&str] = &["claude_code", "codex_cli", "gemini_cli", "cursor"];
const PACK_SLUGS: &[&str] = &[
    "pack_50",
    "pack_160",
    "pack_560",
    "pack_1000",
    "starter",
    "team",
    "developer_50",
    "growth_160",
    "scale_560",
    "org_volume_1000",
    "developer",
    "growth",
    "scale",
    "volume",
];
const VIEWS_4: &[&str] = &["inbox", "board", "agents", "credits"];
const THEMES: &[&str] = &["stone", "dark", "light"];

fn validate_key_domain(key: &str, value: &TelemetryScalar) -> Result<(), TelemetryRejectReason> {
    match (key, value) {
        ("active_days_last_7d", TelemetryScalar::Int(v)) => check_int(*v, 1, 7),
        ("active_minutes_session", TelemetryScalar::Int(v)) => check_int(*v, 1, 1440),
        ("active_tasks_bucket", TelemetryScalar::Str(s)) => check_enum(s, COUNT_BUCKETS),
        ("alert_enabled", TelemetryScalar::Bool(_)) => Ok(()),
        ("all_completed", TelemetryScalar::Bool(_)) => Ok(()),
        ("assigned_tool_kind", TelemetryScalar::Str(s)) => check_enum(
            s,
            &[
                "unassigned",
                "claude_code",
                "codex_cli",
                "gemini_cli",
                "cursor",
            ],
        ),
        ("attempt_number", TelemetryScalar::Int(v)) => check_int(*v, 1, 2),
        ("board_column", TelemetryScalar::Str(s)) => check_enum(
            s,
            &["all", "queued", "in_progress", "needs_review", "shipped"],
        ),
        ("boot_latency_ms_bucket", TelemetryScalar::Str(s)) => {
            check_enum(s, &["lt_100", "100_249", "250_499", "500_999", "1000_plus"])
        }
        ("bounce_source", TelemetryScalar::Str(s)) => check_enum(
            s,
            &["chinwag_open", "slack", "github", "linear", "direct_hash"],
        ),
        ("checkout_attempt_id", TelemetryScalar::Str(s)) => {
            if is_exact_uuid_v4(s) {
                Ok(())
            } else {
                Err(TelemetryRejectReason::InvalidPropertyTypeOrEnumValue)
            }
        }
        ("chip_slug", TelemetryScalar::Str(s)) => check_enum(
            s,
            &[
                "failing_ci_checks",
                "scope_fix_last_test",
                "summarize_shipped_today",
                "what_needs_me",
                "scope_a_task",
                "what_shipped_this_week",
                "none",
            ],
        ),
        ("copy_surface", TelemetryScalar::Str(s)) => check_enum(s, &["diff_sheet", "shipped_card"]),
        ("credits_remaining_bucket", TelemetryScalar::Str(s)) => check_enum(
            s,
            &["0", "1_49", "50_150", "151_499", "500", "501_5k", "gt_5k"],
        ),
        ("decision_latency_bucket", TelemetryScalar::Str(s)) => {
            check_enum(s, &["lt_10s", "10_30s", "30_120s", "gt_120s"])
        }
        ("deep_link_target", TelemetryScalar::Str(s)) => check_enum(
            s,
            &[
                "inbox",
                "inbox_item",
                "diff_item",
                "board",
                "agents",
                "credits",
                "walkthrough",
            ],
        ),
        ("detected_tool_families_mask", TelemetryScalar::Int(v)) => check_int(*v, 0, 63),
        ("detected_tools_count", TelemetryScalar::Int(v)) => check_int(*v, 0, 7),
        ("diff_mode", TelemetryScalar::Str(s)) => check_enum(s, &["unified", "split"]),
        ("diff_sheet_open", TelemetryScalar::Bool(_)) => Ok(()),
        ("discovered_rules_bucket", TelemetryScalar::Str(s)) => check_enum(s, COUNT_BUCKETS),
        ("driver_tool_kind", TelemetryScalar::Str(s)) => check_enum(s, TOOL_KINDS_4),
        ("elapsed_since_boot_sec_bucket", TelemetryScalar::Str(s)) => {
            check_enum(s, &["0_15", "16_60", "61_180", "181_600", "601_plus"])
        }
        ("entry_route", TelemetryScalar::Str(s)) => check_enum(
            s,
            &["inbox", "diff", "board", "agents", "credits", "walkthrough"],
        ),
        ("entry_source", TelemetryScalar::Str(s)) => check_enum(
            s,
            &[
                "cli_launch",
                "deep_link_open",
                "slack_bounce",
                "github_bounce",
                "linear_bounce",
                "direct_tab",
            ],
        ),
        ("entry_trigger", TelemetryScalar::Str(s)) => check_enum(
            s,
            &[
                "top_tab",
                "header_balance_pill",
                "low_credit_banner",
                "depletion_hold_card",
                "deep_link",
            ],
        ),
        ("error_category", TelemetryScalar::Str(s)) => check_enum(
            s,
            &[
                "git_conflict",
                "auth_missing",
                "protected_branch",
                "timeout",
                "validation_error",
                "io_error",
            ],
        ),
        ("expanded", TelemetryScalar::Bool(_)) => Ok(()),
        ("failed_action", TelemetryScalar::Str(s)) => check_enum(
            s,
            &[
                "approve_and_push",
                "apply_locally",
                "hold_resolve",
                "pm_prompt",
                "cursor_import",
                "guardrail_save",
                "board_task_create",
            ],
        ),
        ("failure_stage", TelemetryScalar::Str(s)) => {
            check_enum(s, &["compile", "unit_test", "sandbox_timeout"])
        }
        ("files_changed_bucket", TelemetryScalar::Str(s)) => {
            check_enum(s, &["0", "1", "2_3", "4_7", "8_15", "16_plus"])
        }
        ("filter", TelemetryScalar::Str(s)) => check_enum(
            s,
            &[
                "all",
                "needs_review",
                "needs_permission",
                "paused_on_hold",
                "in_progress",
                "completed",
                "done",
            ],
        ),
        ("function_credits_cost", TelemetryScalar::Int(v)) => {
            if matches!(*v, 0 | 15 | 50 | 100 | 150 | 200) {
                Ok(())
            } else {
                Err(TelemetryRejectReason::IntegerOutOfBounds)
            }
        }
        ("github_connected", TelemetryScalar::Bool(_)) => Ok(()),
        ("guardrail_enabled", TelemetryScalar::Bool(_)) => Ok(()),
        ("guardrail_id", TelemetryScalar::Str(s)) => check_enum(
            s,
            &[
                "isolated_sandbox",
                "secret_credential_hold",
                "protected_branch_gate",
                "two_attempt_circuit_breaker",
                "independent_review",
                "protect_sensitive_paths",
                "auto_test_before_review",
            ],
        ),
        ("has_claude_code", TelemetryScalar::Bool(_)) => Ok(()),
        ("has_codex_cli", TelemetryScalar::Bool(_)) => Ok(()),
        ("has_cursor", TelemetryScalar::Bool(_)) => Ok(()),
        ("has_cursor_dir", TelemetryScalar::Bool(_)) => Ok(()),
        ("has_deep_link", TelemetryScalar::Bool(_)) => Ok(()),
        ("has_gemini_cli", TelemetryScalar::Bool(_)) => Ok(()),
        ("has_gh_cli", TelemetryScalar::Bool(_)) => Ok(()),
        ("has_linked_diff", TelemetryScalar::Bool(_)) => Ok(()),
        ("has_target_files", TelemetryScalar::Bool(_)) => Ok(()),
        ("has_time_saved_pill", TelemetryScalar::Bool(_)) => Ok(()),
        ("hold_category", TelemetryScalar::Str(s)) => check_enum(
            s,
            &[
                "protected_path",
                "secret_env_access",
                "protected_branch",
                "workflow_yaml",
            ],
        ),
        ("hours_bucket", TelemetryScalar::Str(s)) => {
            check_enum(s, &["0", "under_10", "10_to_100", "over_100"])
        }
        ("http_status", TelemetryScalar::Int(v)) => check_int(*v, 400, 599),
        ("import_outcome", TelemetryScalar::Str(s)) => check_enum(
            s,
            &[
                "imported_clean",
                "imported_with_sanitization",
                "cancelled",
                "failed",
            ],
        ),
        ("imported_agents_bucket", TelemetryScalar::Str(s)) => check_enum(s, COUNT_BUCKETS),
        ("inbox_badge_bucket", TelemetryScalar::Str(s)) => {
            check_enum(s, &["0", "1_3", "4_10", "11_plus"])
        }
        ("includes_open_link", TelemetryScalar::Bool(_)) => Ok(()),
        ("includes_referral_link", TelemetryScalar::Bool(_)) => Ok(()),
        ("input_source", TelemetryScalar::Str(s)) => {
            check_enum(s, &["typed_prompt", "suggestion_chip"])
        }
        ("integration_kind", TelemetryScalar::Str(s)) => check_enum(
            s,
            &[
                "github_actions_yaml",
                "slack_app",
                "github_projects_sync",
                "linear_sync",
            ],
        ),
        ("invite_format", TelemetryScalar::Str(s)) => check_enum(s, &["open_link", "referral_url"]),
        ("invite_kind", TelemetryScalar::Str(s)) => {
            check_enum(s, &["intra_org_seat", "external_org_referral"])
        }
        ("is_cross_model_verified", TelemetryScalar::Bool(_)) => Ok(()),
        ("is_git_repo", TelemetryScalar::Bool(_)) => Ok(()),
        ("is_sample_walkthrough", TelemetryScalar::Bool(_)) => Ok(()),
        ("is_under_15s", TelemetryScalar::Bool(_)) => Ok(()),
        ("item_kind", TelemetryScalar::Str(s)) => check_enum(
            s,
            &[
                "ci_autofix",
                "pair_patch",
                "guardrail_hold",
                "sample_walkthrough",
            ],
        ),
        ("item_status", TelemetryScalar::Str(s)) => check_enum(
            s,
            &[
                "ready_to_review",
                "paused_for_approval",
                "paused_low_credits",
                "fixing_in_sandbox",
                "approved_pushed",
                "needs_permission",
                "in_progress",
                "shipped",
            ],
        ),
        ("join_role", TelemetryScalar::Str(s)) => check_enum(s, &["pool_creator", "coworker_join"]),
        ("learned_rules_count_bucket", TelemetryScalar::Str(s)) => {
            check_enum(s, &["0", "1_5", "6_20", "21_plus"])
        }
        ("linear_connected", TelemetryScalar::Bool(_)) => Ok(()),
        ("lines_changed_bucket", TelemetryScalar::Str(s)) => {
            check_enum(s, &["1_10", "11_50", "51_150", "151_500", "501_plus"])
        }
        ("low_credit_alert_enabled", TelemetryScalar::Bool(_)) => Ok(()),
        ("matching_items_bucket", TelemetryScalar::Str(s)) => check_enum(s, COUNT_BUCKETS),
        ("nav_trigger", TelemetryScalar::Str(s)) => check_enum(
            s,
            &[
                "top_tab",
                "credit_pill",
                "onboarding_cta",
                "keyboard",
                "hash_change",
            ],
        ),
        ("opt_out_enabled", TelemetryScalar::Bool(_)) => Ok(()),
        ("org_active_repos_bucket", TelemetryScalar::Str(s)) => {
            check_enum(s, &["1", "2_3", "4_10", "11_plus"])
        }
        ("pack_credits", TelemetryScalar::Int(v)) => {
            if matches!(*v, 6250 | 25000 | 100000 | 200000) {
                Ok(())
            } else {
                Err(TelemetryRejectReason::IntegerOutOfBounds)
            }
        }
        ("pack_price_usd", TelemetryScalar::Int(v)) => {
            if matches!(*v, 50 | 160 | 560 | 1000) {
                Ok(())
            } else {
                Err(TelemetryRejectReason::IntegerOutOfBounds)
            }
        }
        ("pack_slug", TelemetryScalar::Str(s)) => check_enum(s, PACK_SLUGS),
        ("path_category", TelemetryScalar::Str(s)) => check_enum(
            s,
            &[
                "ci_workflow",
                "billing_payments",
                "infra_deploy",
                "env_secrets",
                "auth_security",
                "custom_glob",
            ],
        ),
        ("plan_tier", TelemetryScalar::Str(s)) => check_enum(
            s,
            &[
                "unenrolled",
                "free_trial",
                "trial",
                "developer",
                "growth",
                "scale",
                "org_volume",
            ],
        ),
        ("pm_outcome", TelemetryScalar::Str(s)) => {
            check_enum(s, &["task_created", "plan_returned", "error"])
        }
        ("preference_action", TelemetryScalar::Str(s)) => {
            check_enum(s, &["opt_out", "opt_in", "rotate_distinct_id"])
        }
        ("previous_theme", TelemetryScalar::Str(s)) => check_enum(s, THEMES),
        ("previous_view", TelemetryScalar::Str(s)) => check_enum(s, VIEWS_4),
        ("prompt_length_bucket", TelemetryScalar::Str(s)) => {
            check_enum(s, &["1_40", "41_120", "121_300", "301_plus"])
        }
        ("protected_paths_count_bucket", TelemetryScalar::Str(s)) => check_enum(s, COUNT_BUCKETS),
        ("receipt_has_command", TelemetryScalar::Bool(_)) => Ok(()),
        ("receipt_has_duration", TelemetryScalar::Bool(_)) => Ok(()),
        ("receipt_has_revision", TelemetryScalar::Bool(_)) => Ok(()),
        ("recommended_pack_slug", TelemetryScalar::Str(s)) => check_enum(s, PACK_SLUGS),
        ("reconnect_attempt_bucket", TelemetryScalar::Str(s)) => {
            check_enum(s, &["1", "2_3", "4_plus"])
        }
        ("reject_reason_category", TelemetryScalar::Str(s)) => check_enum(
            s,
            &[
                "incorrect_fix",
                "wrong_scope",
                "prefer_manual",
                "tests_insufficient",
                "unspecified",
            ],
        ),
        ("result", TelemetryScalar::Str(s)) => check_enum(s, &["created", "synced", "failed"]),
        ("reviewer_tool_kind", TelemetryScalar::Str(s)) => check_enum(s, TOOL_KINDS_4),
        ("rule_change_action", TelemetryScalar::Str(s)) => check_enum(
            s,
            &["allow_pattern", "keep_blocked", "open_guardrails_settings"],
        ),
        ("runway_days_bucket", TelemetryScalar::Str(s)) => {
            check_enum(s, &["lt_3d", "3_7d", "8_30d", "gt_30d"])
        }
        ("safety_checks_passed_count", TelemetryScalar::Int(v)) => check_int(*v, 0, 5),
        ("sandbox_tests_passed", TelemetryScalar::Bool(_)) => Ok(()),
        ("sanitized_warnings_count", TelemetryScalar::Int(v)) => check_int(*v, 0, 10),
        ("shipped_bucket", TelemetryScalar::Str(s)) => {
            check_enum(s, &["0", "1-4", "1_4", "5-14", "5_14", "15_plus"])
        }
        ("step_actor", TelemetryScalar::Str(s)) => check_enum(s, &["user"]),
        ("step_index", TelemetryScalar::Int(v)) => check_int(*v, 1, 12),
        ("step_slug", TelemetryScalar::Str(s)) => check_enum(
            s,
            &[
                "repo_linked",
                "coding_tools_ready",
                "guardrails_active",
                "first_fix_previewed",
            ],
        ),
        ("steps_completed_count", TelemetryScalar::Int(v)) => check_int(*v, 0, 4),
        ("summary_surface", TelemetryScalar::Str(s)) => {
            check_enum(s, &["clipboard", "pr_markdown", "slack"])
        }
        ("surface_readiness", TelemetryScalar::Str(s)) => check_enum(
            s,
            &[
                "all_checked",
                "held_missing_docs",
                "held_missing_tests",
                "in_progress",
            ],
        ),
        ("sync_direction", TelemetryScalar::Str(s)) => {
            check_enum(s, &["pull", "push", "bidirectional"])
        }
        ("sync_external_tracker", TelemetryScalar::Str(s)) => {
            check_enum(s, &["none", "github_projects", "linear"])
        }
        ("sync_outcome", TelemetryScalar::Str(s)) => {
            check_enum(s, &["ok", "auth_missing", "rate_limited", "error"])
        }
        ("synced_items_bucket", TelemetryScalar::Str(s)) => check_enum(s, COUNT_BUCKETS),
        ("target", TelemetryScalar::Str(s)) => check_enum(s, &["github", "linear"]),
        ("target_found", TelemetryScalar::Bool(_)) => Ok(()),
        ("telemetry_state", TelemetryScalar::Str(s)) => {
            check_enum(s, &["enabled", "opted_out_ui", "disabled_env"])
        }
        ("theme", TelemetryScalar::Str(s)) => check_enum(s, THEMES),
        ("threshold_credits", TelemetryScalar::Int(v)) => {
            if matches!(*v, 50 | 150 | 200 | 250 | 500) {
                Ok(())
            } else {
                Err(TelemetryRejectReason::IntegerOutOfBounds)
            }
        }
        ("time_saved_baseline_documented", TelemetryScalar::Bool(_)) => Ok(()),
        ("time_saved_minutes_bucket", TelemetryScalar::Str(s)) => {
            check_enum(s, &["1_15", "16_30", "31_60", "61_180", "181_plus"])
        }
        ("time_since_install_bucket", TelemetryScalar::Str(s)) => {
            check_enum(s, &["lt_10m", "10_60m", "1_24h", "gt_24h"])
        }
        ("tool_kind", TelemetryScalar::Str(s)) => check_enum(
            s,
            &[
                "claude_code",
                "codex_cli",
                "gemini_cli",
                "cursor",
                "windsurf",
                "aider",
                "gh_cli",
            ],
        ),
        ("tracker_kind", TelemetryScalar::Str(s)) => check_enum(s, &["github_projects", "linear"]),
        ("transport_mode", TelemetryScalar::Str(s)) => check_enum(s, &["sse", "poll_fallback"]),
        ("trigger_surface", TelemetryScalar::Str(s)) => check_enum(
            s,
            &[
                "onboarding_banner",
                "inbox_empty_state",
                "agents_tab",
                "board_header",
                "empty_column",
                "keyboard",
                "global_header",
                "credits_tab",
                "low_credit_banner",
                "depletion_hold_card",
                "header_repo_pill",
                "cli_init",
                "invite_modal",
            ],
        ),
        ("ui_theme", TelemetryScalar::Str(s)) => check_enum(s, THEMES),
        ("uninit_action", TelemetryScalar::Str(s)) => {
            check_enum(s, &["viewed", "init_repo_clicked", "docs_clicked"])
        }
        ("view", TelemetryScalar::Str(s)) => check_enum(s, VIEWS_4),
        ("viewport_bucket", TelemetryScalar::Str(s)) => {
            check_enum(s, &["desktop_wide", "desktop_std", "tablet", "mobile"])
        }
        ("walkthrough_mode", TelemetryScalar::Str(s)) => {
            check_enum(s, &["sample_item", "live_item"])
        }
        ("workflow_fn", TelemetryScalar::Str(s)) => check_enum(
            s,
            &[
                "blind_relay_wakeup",
                "ci_remediation",
                "review_handoff",
                "pair_sandbox",
                "triad_sandbox",
                "quad_sandbox",
                "board_sync",
            ],
        ),
        ("workstream", TelemetryScalar::Str(s)) => check_enum(
            s,
            &[
                "all",
                "engineering",
                "design",
                "product",
                "qa",
                "security",
                "analytics",
                "docs",
            ],
        ),
        (_, TelemetryScalar::Int(_)) => Err(TelemetryRejectReason::InvalidPropertyTypeOrEnumValue),
        (_, TelemetryScalar::Bool(_)) => Err(TelemetryRejectReason::InvalidPropertyTypeOrEnumValue),
        (_, TelemetryScalar::Str(_)) => Err(TelemetryRejectReason::InvalidPropertyTypeOrEnumValue),
    }
}

fn check_int(v: i64, min: i64, max: i64) -> Result<(), TelemetryRejectReason> {
    if (min..=max).contains(&v) {
        Ok(())
    } else {
        Err(TelemetryRejectReason::IntegerOutOfBounds)
    }
}

fn check_enum(s: &str, allowed: &[&str]) -> Result<(), TelemetryRejectReason> {
    if allowed.contains(&s) {
        Ok(())
    } else {
        Err(TelemetryRejectReason::InvalidPropertyTypeOrEnumValue)
    }
}

/// Runs all 9 ordered string-scanner rules before per-key enum membership.
pub fn validate_string_scanners(key: &str, s: &str) -> Result<(), TelemetryRejectReason> {
    // 1. Length bounds
    if s.is_empty() || s.len() > MAX_TELEMETRY_STR_LEN {
        return Err(TelemetryRejectReason::EmptyOrOversizedString);
    }

    let lower = s.to_ascii_lowercase();

    // 4. URL & Git remote check BEFORE slash check so `https://...` reports ForbiddenUrlOrGitRemote
    if lower.contains("://")
        || lower.starts_with("http:")
        || lower.starts_with("https:")
        || lower.starts_with("ssh:")
        || lower.starts_with("git:")
        || lower.starts_with("file:")
        || lower.ends_with(".git")
    {
        return Err(TelemetryRejectReason::ForbiddenUrlOrGitRemote);
    }

    // 3. Email & user-at-host rejector
    if s.contains('@') {
        return Err(TelemetryRejectReason::ForbiddenEmailLiteral);
    }

    // 2. Path & dotfile rejector
    if s.contains('/')
        || s.contains('\\')
        || s.contains("..")
        || lower.contains(".env")
        || lower.contains(".git")
        || lower.contains(".ssh")
        || lower.contains(".pem")
        || s.contains('~')
    {
        return Err(TelemetryRejectReason::ForbiddenPathOrDotfile);
    }

    // 5. IPv4 & IPv6 literal rejector
    if s.parse::<IpAddr>().is_ok() || s.contains(':') || looks_like_ipv4_dotted_quad(s) {
        return Err(TelemetryRejectReason::ForbiddenIpAddressLiteral);
    }

    // 6. Secret prefix & high-entropy hex rejector
    for prefix in [
        "ghp_",
        "gho_",
        "ghs_",
        "github_pat_",
        "sk-",
        "phc_",
        "phx_",
        "xoxb-",
        "xoxp-",
        "eyJ",
        "AKIA",
    ] {
        if s.starts_with(prefix) {
            return Err(TelemetryRejectReason::ForbiddenSecretOrHighEntropyToken);
        }
    }
    if key == "checkout_attempt_id" {
        if !is_exact_uuid_v4(s) {
            return Err(TelemetryRejectReason::ForbiddenSecretOrHighEntropyToken);
        }
    } else if has_16_contiguous_hex(s) {
        return Err(TelemetryRejectReason::ForbiddenSecretOrHighEntropyToken);
    }

    // 7. Vendor & internal fleet firewall
    for forbidden in FORBIDDEN_TELEMETRY_JARGON {
        if lower.contains(forbidden) {
            return Err(TelemetryRejectReason::ForbiddenVendorOrInternalJargon);
        }
    }

    // 8. Strict lexical token grammar
    let first = s.as_bytes()[0];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(TelemetryRejectReason::InvalidTokenCharset);
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-'))
    {
        return Err(TelemetryRejectReason::InvalidTokenCharset);
    }

    Ok(())
}

/// Validates raw HTTP request bytes into a normalized `TelemetryTrackRequest`.
pub fn parse_and_validate_track_payload(
    raw_bytes: &[u8],
) -> Result<(UiTelemetryEvent, BTreeMap<String, TelemetryScalar>), TelemetryRejectReason> {
    if raw_bytes.len() > MAX_TELEMETRY_HTTP_BYTES {
        return Err(TelemetryRejectReason::PayloadTooLarge);
    }
    let parsed: TelemetryTrackRequest = serde_json::from_slice(raw_bytes)
        .map_err(|_| TelemetryRejectReason::InvalidJsonOrUnknownEvent)?;

    let mut merged = parsed.props;
    for (k, v) in parsed.properties {
        if let Some(existing) = merged.get(&k)
            && existing != &v
        {
            return Err(TelemetryRejectReason::InvalidPropertyTypeOrEnumValue);
        }
        merged.insert(k, v);
    }

    if merged.len() > MAX_TELEMETRY_PROPS_COUNT {
        return Err(TelemetryRejectReason::TooManyProperties);
    }

    for (key, val) in &merged {
        if ALLOWLISTED_PROPERTY_KEYS
            .binary_search(&key.as_str())
            .is_err()
        {
            return Err(TelemetryRejectReason::UnallowlistedPropertyKey);
        }
        if let TelemetryScalar::Str(s) = val {
            validate_string_scanners(key, s)?;
        }
        validate_key_domain(key, val)?;
    }

    // Enforce SampleWalkthroughShipForbidden
    let is_sample = merged.get("is_sample_walkthrough") == Some(&TelemetryScalar::Bool(true))
        || matches!(
            merged.get("item_kind"),
            Some(TelemetryScalar::Str(s)) if s == "sample_walkthrough"
        );
    if is_sample
        && matches!(
            parsed.event,
            UiTelemetryEvent::UiDiffApprovedAndPushed
                | UiTelemetryEvent::UiDiffAppliedLocally
                | UiTelemetryEvent::UiDiffRejected
        )
    {
        return Err(TelemetryRejectReason::SampleWalkthroughShipForbidden);
    }

    Ok((parsed.event, merged))
}

/// Builds the exact `curl` argv used to post uncompressed JSON over stdin (`--data-binary @-`),
/// ensuring zero payload bytes ever appear in `ps`-visible process arguments (`ROG-580`).
pub fn build_curl_forwarder_args(endpoint_url: &str, canary_run: Option<&str>) -> Vec<String> {
    let user_agent = if canary_run.is_some() {
        "User-Agent: ChinwagSyntheticCanary/4.1.0"
    } else {
        "User-Agent: chinwag-ui/4.1.0"
    };
    let mut args = vec![
        "--silent".to_string(),
        "--show-error".to_string(),
        "--max-time".to_string(),
        "4".to_string(),
        "--connect-timeout".to_string(),
        "2".to_string(),
        "-X".to_string(),
        "POST".to_string(),
        "-H".to_string(),
        "Content-Type: application/json".to_string(),
        "-H".to_string(),
        user_agent.to_string(),
    ];
    if let Some(raw_run_id) = canary_run.map(str::trim).filter(|s| !s.is_empty()) {
        let sanitized: String = raw_run_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            .take(64)
            .collect();
        if !sanitized.is_empty() {
            args.push("-H".to_string());
            args.push(format!("X-Chinwag-Canary-Run: {sanitized}"));
        }
    }
    args.push("--data-binary".to_string());
    args.push("@-".to_string());
    args.push(endpoint_url.to_string());
    args
}

fn send_via_loopback_http(url: &str, payload: &[u8]) -> bool {
    let rest = url
        .strip_prefix("http://127.0.0.1:")
        .or_else(|| url.strip_prefix("http://localhost:"));
    let Some(rest) = rest else {
        return false;
    };
    let (port_str, path) = match rest.split_once('/') {
        Some((p, tail)) => (p, format!("/{tail}")),
        None => (rest, "/ph/track".to_string()),
    };
    let Ok(port) = port_str.parse::<u16>() else {
        return false;
    };
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let req = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Content-Type: application/json\r\n\
         User-Agent: chinwag-ui/4.1.0\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        payload.len()
    );
    if stream.write_all(req.as_bytes()).is_err() || stream.write_all(payload).is_err() {
        return false;
    }
    let _ = stream.flush();
    let mut resp = [0u8; 128];
    let n = stream.read(&mut resp).unwrap_or(0);
    let head = String::from_utf8_lossy(&resp[..n]);
    head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.1 202")
}

fn send_via_curl_stdin(endpoint_url: &str, payload: &[u8]) -> bool {
    let canary = std::env::var("CHINWAG_TELEMETRY_CANARY_RUN").ok();
    let args = build_curl_forwarder_args(endpoint_url, canary.as_deref());
    let mut cmd = Command::new("curl");
    cmd.args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let Ok(mut child) = cmd.spawn() else {
        return false;
    };
    if let Some(mut stdin) = child.stdin.take()
        && stdin.write_all(payload).is_err()
    {
        let _ = child.kill();
        let _ = child.wait();
        return false;
    }
    child.wait().map(|s| s.success()).unwrap_or(false)
}

fn deliver_event_wire(event: &ValidatedPostHogEvent) {
    let Ok(payload) = serde_json::to_vec(event) else {
        return;
    };

    if let Ok(test_ep) = std::env::var("CHINWAG_TELEMETRY_TEST_ENDPOINT") {
        let trimmed = test_ep.trim();
        if (trimmed.starts_with("http://127.0.0.1:") || trimmed.starts_with("http://localhost:"))
            && !send_via_curl_stdin(trimmed, &payload)
            && !send_via_loopback_http(trimmed, &payload)
        {
            std::thread::sleep(Duration::from_millis(50));
            let _ = send_via_loopback_http(trimmed, &payload);
        }
        return;
    }

    // Never send synthetic unit-test traffic to production PostHog when CI=true without explicit canary/endpoint
    if env_is_truthy("CI") && std::env::var("CHINWAG_TELEMETRY_CANARY_RUN").is_err() {
        return;
    }

    if !send_via_curl_stdin(POSTHOG_EDGE_TRACK_URL, &payload) {
        std::thread::sleep(Duration::from_millis(500));
        let _ = send_via_curl_stdin(POSTHOG_EDGE_TRACK_URL, &payload);
    }
}

fn csprng_seed_hex(num_bytes: usize) -> String {
    let mut buf = vec![0u8; num_bytes];
    rand::rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn derive_distinct_id_from_seed(seed_hex: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"chinwag-ui-telemetry-v4:");
    h.update(seed_hex.as_bytes());
    let full: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    format!("ui_{}", &full[..32])
}

/// Computes an anonymous salted 16-hex repository cohort ID (`repo_<16hex>`),
/// omitting outside Git/Jujutsu repositories and never transmitting repo names.
pub fn compute_repo_anon_id(repo_root: &Path, salt: &str) -> Option<String> {
    if !repo_root.join(".git").exists() && !repo_root.join(".jj").exists() {
        return None;
    }
    let mut h = Sha256::new();
    h.update(b"chinwag-repo-cohort-v4:");
    h.update(salt.as_bytes());
    h.update(b":");
    h.update(repo_root.to_string_lossy().as_bytes());
    let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    Some(format!("repo_{}", &hex[..16]))
}

fn current_iso_cohort_week() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1_794_369_000);
    // Approximate UTC year & ISO week deterministically without external chrono crate
    let days_since_epoch = secs / 86_400;
    // 1970-01-01 was Thursday; shift to Monday-anchored week calculation
    let mut year = 1970u64;
    let mut rem_days = days_since_epoch;
    loop {
        let leap =
            (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
        let days_in_year = if leap { 366 } else { 365 };
        if rem_days < days_in_year {
            break;
        }
        rem_days -= days_in_year;
        year += 1;
    }
    let week = ((rem_days / 7) + 1).clamp(1, 53);
    let clamped_year = year.clamp(2020, 2099);
    format!("{clamped_year}-W{week:02}")
}

fn read_config_file_nofollow(config_dir: &Path, leaf_name: &str) -> Option<String> {
    let dir_fd = openat(
        CWD,
        config_dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .ok()?;
    let raw_fd = openat(
        &dir_fd,
        leaf_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .ok()?;
    let mut f = File::from(raw_fd);
    let meta = f.metadata().ok()?;
    if !meta.is_file() || meta.len() > 65_536 {
        return None;
    }
    let mut s = String::new();
    f.read_to_string(&mut s).ok()?;
    Some(s)
}

fn write_config_file_nofollow_atomic(
    config_dir: &Path,
    leaf_name: &str,
    bytes: &[u8],
) -> Result<(), &'static str> {
    fs::create_dir_all(config_dir).map_err(|_| "persistence_failed")?;
    fs::set_permissions(config_dir, fs::Permissions::from_mode(0o700))
        .map_err(|_| "persistence_failed")?;

    let dir_fd = openat(
        CWD,
        config_dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "persistence_failed")?;

    if let Ok(st) = statat(&dir_fd, leaf_name, AtFlags::SYMLINK_NOFOLLOW)
        && ((u32::from(st.st_mode) & 0o170000) != 0o100000 || st.st_nlink != 1)
    {
        return Err("persistence_failed");
    }

    let tmp_name = format!(".{leaf_name}.tmp.{}", csprng_seed_hex(8));
    let tmp_fd = openat(
        &dir_fd,
        tmp_name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| "persistence_failed")?;

    let mut file = File::from(tmp_fd);
    if file.write_all(bytes).is_ok() && file.sync_all().is_ok() {
        if renameat(&dir_fd, tmp_name.as_str(), &dir_fd, leaf_name).is_ok() {
            fsync(&dir_fd).map_err(|_| "persistence_failed")?;
            Ok(())
        } else {
            let _ = unlinkat(&dir_fd, tmp_name.as_str(), AtFlags::empty());
            Err("persistence_failed")
        }
    } else {
        let _ = unlinkat(&dir_fd, tmp_name.as_str(), AtFlags::empty());
        Err("persistence_failed")
    }
}

fn load_or_init_identity_and_config(config_dir: &Path) -> (String, String, bool) {
    if is_env_telemetry_disabled() {
        let ephemeral = derive_distinct_id_from_seed(&csprng_seed_hex(32));
        return (ephemeral, current_iso_cohort_week(), false);
    }

    let _ = fs::create_dir_all(config_dir);
    let _ = fs::set_permissions(config_dir, fs::Permissions::from_mode(0o700));

    let seed = if let Some(existing) = read_config_file_nofollow(config_dir, "telemetry_id")
        && existing.trim().len() >= 32
    {
        existing.trim().to_string()
    } else {
        let fresh = csprng_seed_hex(32);
        let _ = write_config_file_nofollow_atomic(
            config_dir,
            "telemetry_id",
            format!("{fresh}\n").as_bytes(),
        );
        fresh
    };

    let (enabled, cohort_week) = if let Some(raw) =
        read_config_file_nofollow(config_dir, "telemetry_config.json")
        && let Ok(parsed) = serde_json::from_str::<PersistedTelemetryConfig>(&raw)
    {
        (parsed.enabled, parsed.install_cohort_week)
    } else {
        let week = current_iso_cohort_week();
        let cfg = PersistedTelemetryConfig {
            enabled: true,
            install_cohort_week: week.clone(),
            updated_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };
        if let Ok(bytes) = serde_json::to_vec_pretty(&cfg) {
            let _ = write_config_file_nofollow_atomic(config_dir, "telemetry_config.json", &bytes);
        }
        (true, week)
    };

    (derive_distinct_id_from_seed(&seed), cohort_week, enabled)
}

impl UiTelemetryRuntime {
    pub fn new_with_dir(
        config_dir: PathBuf,
        test_sink: Option<Arc<Mutex<Vec<ValidatedPostHogEvent>>>>,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::sync_channel::<ValidatedPostHogEvent>(TELEMETRY_QUEUE_CAPACITY);
        let (distinct_id, cohort_week, enabled) = load_or_init_identity_and_config(&config_dir);
        let sink_clone = test_sink.clone();

        std::thread::Builder::new()
            .name("chinwag-ui-telemetry".to_string())
            .spawn(move || {
                while let Ok(evt) = rx.recv() {
                    if let Some(ref sink) = sink_clone {
                        if let Ok(mut guard) = sink.lock() {
                            guard.push(evt);
                        }
                    } else {
                        deliver_event_wire(&evt);
                    }
                }
            })
            .ok();

        Arc::new(Self {
            sender: tx,
            ui_enabled: AtomicBool::new(enabled),
            session_seq: AtomicU64::new(0),
            dropped_full_count: AtomicU64::new(0),
            preferences_lock: Mutex::new(()),
            identity_lock: Mutex::new((distinct_id, cohort_week)),
            rate_limiter: Mutex::new(TokenBucket::new()),
            config_dir,
            test_sink,
        })
    }

    pub fn global() -> Arc<Self> {
        Arc::clone(GLOBAL_TELEMETRY_RUNTIME.get_or_init(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            let dir = PathBuf::from(home).join(".chinwag");
            Self::new_with_dir(dir, None)
        }))
    }

    pub fn preferences_json(&self) -> Value {
        let env_disabled = is_env_telemetry_disabled();
        let Ok(_pref_tx) = self.preferences_lock.lock() else {
            return json!({
                "ok": false,
                "enabled": false,
                "telemetry_enabled": false,
                "env_disabled": env_disabled,
                "error": "telemetry_state_unavailable",
                "dropped_full_count": self.dropped_full_count.load(Ordering::Relaxed)
            });
        };
        let Ok(identity_guard) = self.identity_lock.lock() else {
            return json!({
                "ok": false,
                "enabled": false,
                "telemetry_enabled": false,
                "env_disabled": env_disabled,
                "error": "telemetry_state_unavailable",
                "dropped_full_count": self.dropped_full_count.load(Ordering::Relaxed)
            });
        };
        let (distinct_id, cohort_week) = identity_guard.clone();
        drop(identity_guard);
        let enabled = !env_disabled && self.ui_enabled.load(Ordering::Acquire);
        let preview = if distinct_id.len() >= 12 {
            format!(
                "{}…{}",
                &distinct_id[..7],
                &distinct_id[distinct_id.len() - 4..]
            )
        } else {
            distinct_id
        };
        json!({
            "ok": true,
            "enabled": enabled,
            "telemetry_enabled": enabled,
            "env_disabled": env_disabled,
            "distinct_id_preview": preview,
            "install_cohort_week": cohort_week,
            "dropped_full_count": self.dropped_full_count.load(Ordering::Relaxed)
        })
    }

    pub fn update_preferences(
        &self,
        raw_body: &[u8],
        repo_root: Option<&Path>,
    ) -> Result<Value, &'static str> {
        let v: Value = serde_json::from_slice(raw_body).map_err(|_| "invalid_json")?;
        let action = v
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or("set_enabled");
        let env_disabled = is_env_telemetry_disabled();
        let _pref_tx = self
            .preferences_lock
            .lock()
            .map_err(|_| "telemetry_lock_poisoned")?;

        match action {
            "rotate_id" => {
                let fresh_seed = csprng_seed_hex(32);
                let fresh_id = derive_distinct_id_from_seed(&fresh_seed);
                let mut g = self
                    .identity_lock
                    .lock()
                    .map_err(|_| "telemetry_lock_poisoned")?;
                if !env_disabled {
                    write_config_file_nofollow_atomic(
                        &self.config_dir,
                        "telemetry_id",
                        format!("{fresh_seed}\n").as_bytes(),
                    )?;
                }
                g.0 = fresh_id;
                drop(g);
                let eff = !env_disabled && self.ui_enabled.load(Ordering::Acquire);
                Ok(json!({
                    "ok": true,
                    "enabled": eff,
                    "telemetry_enabled": eff,
                    "env_disabled": env_disabled,
                    "rotated": true
                }))
            }
            "set_enabled" => {
                let next_enabled = v
                    .get("enabled")
                    .or_else(|| v.get("telemetry_enabled"))
                    .and_then(Value::as_bool)
                    .ok_or("missing_enabled_bool")?;
                let cohort = self
                    .identity_lock
                    .lock()
                    .map_err(|_| "telemetry_lock_poisoned")?
                    .1
                    .clone();
                let was_enabled = self.ui_enabled.load(Ordering::Acquire);
                if was_enabled && !next_enabled && !env_disabled {
                    // Emit one final opt-out audit event before closing the gate
                    let mut final_props = BTreeMap::new();
                    final_props.insert("opt_out_enabled".into(), TelemetryScalar::Bool(true));
                    final_props.insert(
                        "preference_action".into(),
                        TelemetryScalar::Str("opt_out".into()),
                    );
                    let _ = self.enqueue_validated(
                        UiTelemetryEvent::UiTelemetryOptOutChanged,
                        final_props,
                        repo_root,
                    );
                }
                if !next_enabled {
                    // Enforce opt-out immediately in memory even if disk persistence fails below.
                    self.ui_enabled.store(false, Ordering::SeqCst);
                }
                if !env_disabled {
                    let cfg = PersistedTelemetryConfig {
                        enabled: next_enabled,
                        install_cohort_week: cohort,
                        updated_at_unix: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                    };
                    let bytes =
                        serde_json::to_vec_pretty(&cfg).map_err(|_| "persistence_failed")?;
                    write_config_file_nofollow_atomic(
                        &self.config_dir,
                        "telemetry_config.json",
                        &bytes,
                    )?;
                }
                self.ui_enabled.store(next_enabled, Ordering::SeqCst);
                Ok(json!({
                    "ok": true,
                    "enabled": !env_disabled && next_enabled,
                    "telemetry_enabled": !env_disabled && next_enabled,
                    "env_disabled": env_disabled,
                    "rotated": false
                }))
            }
            _ => Err("unknown_preference_action"),
        }
    }

    pub fn enqueue_raw(
        &self,
        raw_bytes: &[u8],
        repo_root: Option<&Path>,
    ) -> Result<EnqueueOutcome, TelemetryRejectReason> {
        let (event, props) = parse_and_validate_track_payload(raw_bytes)?;
        Ok(self.enqueue_validated(event, props, repo_root))
    }

    pub fn enqueue_validated(
        &self,
        event: UiTelemetryEvent,
        props: BTreeMap<String, TelemetryScalar>,
        repo_root: Option<&Path>,
    ) -> EnqueueOutcome {
        if is_env_telemetry_disabled() || !self.ui_enabled.load(Ordering::Acquire) {
            return EnqueueOutcome::DroppedOptedOut;
        }

        let Ok(mut limiter) = self.rate_limiter.lock() else {
            return EnqueueOutcome::DroppedRateLimited;
        };
        if !limiter.try_acquire(event) {
            return EnqueueOutcome::DroppedRateLimited;
        }
        drop(limiter);

        let Ok(identity_guard) = self.identity_lock.lock() else {
            return EnqueueOutcome::DroppedRateLimited;
        };
        let (distinct_id, cohort_week) = identity_guard.clone();
        drop(identity_guard);

        let seq = self.session_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let mut out_props = Map::new();

        let mut active_theme = "stone".to_string();
        for (k, v) in props {
            match v {
                TelemetryScalar::Bool(b) => {
                    out_props.insert(k, Value::Bool(b));
                }
                TelemetryScalar::Int(i) => {
                    out_props.insert(k, Value::Number(i.into()));
                }
                TelemetryScalar::Str(s) => {
                    let normalized =
                        if matches!(k.as_str(), "theme" | "ui_theme" | "previous_theme")
                            && s == "light"
                        {
                            "stone".to_string()
                        } else {
                            s
                        };
                    if k == "ui_theme" || k == "theme" {
                        active_theme = normalized.clone();
                    }
                    out_props.insert(k, Value::String(normalized));
                }
            }
        }

        // Attach the 11 mandatory server-side envelope super-properties
        out_props.insert("surface".into(), Value::String("chinwag_ui".into()));
        out_props.insert("ui_version".into(), Value::String("4.1".into()));
        if let Some(root) = repo_root
            && let Some(repo_anon) = compute_repo_anon_id(root, &distinct_id)
        {
            out_props.insert("repo_anon_id".into(), Value::String(repo_anon));
        }
        out_props.insert("install_cohort_week".into(), Value::String(cohort_week));
        out_props.insert("os_family".into(), Value::String(coarse_os_family().into()));
        out_props.insert("arch".into(), Value::String(coarse_arch().into()));
        out_props.insert("ui_theme".into(), Value::String(active_theme.clone()));
        out_props.insert("theme".into(), Value::String(active_theme));
        out_props.insert(
            "session_seq".into(),
            Value::Number(seq.min(1_000_000).into()),
        );
        out_props.insert("is_synthetic_ci".into(), Value::Bool(is_synthetic_ci_env()));

        let envelope = ValidatedPostHogEvent {
            event: event.as_str().to_string(),
            distinct_id,
            properties: out_props,
        };

        match self.sender.try_send(envelope) {
            Ok(()) => EnqueueOutcome::Queued,
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.dropped_full_count.fetch_add(1, Ordering::Relaxed);
                EnqueueOutcome::DroppedQueueFull
            }
        }
    }

    #[cfg(test)]
    pub fn test_sink_events(&self) -> Vec<ValidatedPostHogEvent> {
        self.test_sink
            .as_ref()
            .and_then(|s| s.lock().ok().map(|g| g.clone()))
            .unwrap_or_default()
    }
}

pub fn enqueue_ui_event(
    raw_bytes: &[u8],
    repo_root: Option<&Path>,
) -> Result<EnqueueOutcome, TelemetryRejectReason> {
    UiTelemetryRuntime::global().enqueue_raw(raw_bytes, repo_root)
}

pub fn get_telemetry_preferences(_repo_root: Option<&Path>) -> Value {
    UiTelemetryRuntime::global().preferences_json()
}

pub fn update_telemetry_preferences(
    raw_body: &[u8],
    repo_root: Option<&Path>,
) -> Result<Value, &'static str> {
    UiTelemetryRuntime::global().update_preferences(raw_body, repo_root)
}

fn coarse_os_family() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macos",
        "linux" => {
            if std::env::var_os("WSL_DISTRO_NAME").is_some() {
                "wsl2"
            } else {
                "linux"
            }
        }
        "windows" => "windows",
        _ => "linux",
    }
}

fn coarse_arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "aarch64",
        "x86_64" => "x86_64",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_counts_and_sorting_match_telemetry_spec_exactly() {
        assert_eq!(ALL_ALLOWLISTED_EVENTS.len(), 56);
        assert_eq!(ALLOWLISTED_PROPERTY_KEYS.len(), 127);
        for pair in ALLOWLISTED_PROPERTY_KEYS.windows(2) {
            assert!(
                pair[0] < pair[1],
                "ALLOWLISTED_PROPERTY_KEYS must be strictly sorted: {} >= {}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn all_14_mandatory_negative_vectors_plus_sample_ship_are_rejected_fail_closed() {
        let sink = Arc::new(Mutex::new(Vec::new()));
        let tmp = tempfile::tempdir().unwrap();
        let runtime =
            UiTelemetryRuntime::new_with_dir(tmp.path().to_path_buf(), Some(sink.clone()));

        let long_a = "a".repeat(65);
        let negative_vectors: Vec<(&str, String, TelemetryRejectReason)> = vec![
            (
                "1_unknown_event",
                r#"{"event":"ui_custom_debug_dump","props":{}}"#.to_string(),
                TelemetryRejectReason::InvalidJsonOrUnknownEvent,
            ),
            (
                "2_spoofed_server_key",
                r#"{"event":"ui_session_started","props":{"org_anon_id":"org_00000000000000000000000000000000"}}"#.to_string(),
                TelemetryRejectReason::UnallowlistedPropertyKey,
            ),
            (
                "3_overlong_string",
                format!(r#"{{"event":"ui_view_navigated","props":{{"view":"{long_a}"}}}}"#),
                TelemetryRejectReason::EmptyOrOversizedString,
            ),
            (
                "4_unix_path_slug",
                r#"{"event":"ui_protected_path_added","props":{"path_category":"acme/payments"}}"#.to_string(),
                TelemetryRejectReason::ForbiddenPathOrDotfile,
            ),
            (
                "5_windows_path",
                r#"{"event":"ui_protected_path_added","props":{"path_category":"src\\billing"}}"#.to_string(),
                TelemetryRejectReason::ForbiddenPathOrDotfile,
            ),
            (
                "6_email_address",
                r#"{"event":"ui_invite_copied","props":{"invite_format":"dev@acme.io"}}"#.to_string(),
                TelemetryRejectReason::ForbiddenEmailLiteral,
            ),
            (
                "7_ipv4_literal",
                r#"{"event":"ui_session_started","props":{"entry_route":"192.168.1.42"}}"#.to_string(),
                TelemetryRejectReason::ForbiddenIpAddressLiteral,
            ),
            (
                "8_ipv6_literal",
                r#"{"event":"ui_session_started","props":{"entry_route":"2001:db8::1"}}"#.to_string(),
                TelemetryRejectReason::ForbiddenIpAddressLiteral,
            ),
            (
                "9_git_https_url",
                r#"{"event":"ui_board_sync_triggered","props":{"tracker_kind":"https://github.com/org/repo.git"}}"#.to_string(),
                TelemetryRejectReason::ForbiddenUrlOrGitRemote,
            ),
            (
                "10_git_commit_sha",
                r#"{"event":"ui_diff_approved_and_pushed","props":{"item_kind":"b1745094d9cb9014361fca30c7de3535c140dd20"}}"#.to_string(),
                TelemetryRejectReason::ForbiddenSecretOrHighEntropyToken,
            ),
            (
                "11_malformed_uuid",
                r#"{"event":"ui_credits_checkout_clicked","props":{"checkout_attempt_id":"not-a-uuid-v4"}}"#.to_string(),
                TelemetryRejectReason::ForbiddenSecretOrHighEntropyToken,
            ),
            (
                "12_vendor_leak",
                format!(
                    r#"{{"event":"ui_pm_prompt_submitted","props":{{"pm_outcome":"{}_3_ok"}}}}"#,
                    concat!("mer", "cury")
                ),
                TelemetryRejectReason::ForbiddenVendorOrInternalJargon,
            ),
            (
                "13_gateway_leak",
                format!(
                    r#"{{"event":"ui_pm_prompt_submitted","props":{{"pm_outcome":"{}"}}}}"#,
                    concat!("workers-", "ai")
                ),
                TelemetryRejectReason::ForbiddenVendorOrInternalJargon,
            ),
            (
                "14_raw_prompt_spaces",
                r#"{"event":"ui_pm_prompt_submitted","props":{"chip_slug":"fix my auth token bug"}}"#.to_string(),
                TelemetryRejectReason::InvalidTokenCharset,
            ),
            (
                "15_sample_walkthrough_ship_forbidden",
                r#"{"event":"ui_diff_approved_and_pushed","props":{"item_kind":"ci_autofix","is_sample_walkthrough":true}}"#.to_string(),
                TelemetryRejectReason::SampleWalkthroughShipForbidden,
            ),
        ];

        for (label, payload, expected_reason) in negative_vectors {
            let res = runtime.enqueue_raw(payload.as_bytes(), None);
            assert_eq!(res, Err(expected_reason), "vector {label} failed");
        }
        assert!(sink.lock().unwrap().is_empty());
    }

    #[test]
    fn valid_events_attach_11_server_properties_and_curl_never_puts_payload_in_argv() {
        let sink = Arc::new(Mutex::new(Vec::new()));
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
        let runtime =
            UiTelemetryRuntime::new_with_dir(tmp.path().to_path_buf(), Some(sink.clone()));

        let valid_payload = r#"{
            "event": "ui_credits_checkout_clicked",
            "properties": {
                "trigger_surface": "credits_tab",
                "pack_slug": "growth_160",
                "pack_price_usd": 160,
                "pack_credits": 25000,
                "checkout_attempt_id": "550e8400-e29b-41d4-a716-446655440000"
            }
        }"#;
        let outcome = runtime
            .enqueue_raw(valid_payload.as_bytes(), Some(tmp.path()))
            .unwrap();
        if !is_env_telemetry_disabled() {
            assert_eq!(outcome, EnqueueOutcome::Queued);
            std::thread::sleep(Duration::from_millis(30));
            let captured = runtime.test_sink_events();
            assert_eq!(captured.len(), 1);
            let evt = &captured[0];
            assert_eq!(evt.event, "ui_credits_checkout_clicked");
            assert!(evt.distinct_id.starts_with("ui_") && evt.distinct_id.len() == 35);
            assert_eq!(evt.properties["surface"], "chinwag_ui");
            assert_eq!(evt.properties["ui_version"], "4.1");
            assert!(
                evt.properties["repo_anon_id"]
                    .as_str()
                    .unwrap()
                    .starts_with("repo_")
            );
        }

        let argv = build_curl_forwarder_args(POSTHOG_EDGE_TRACK_URL, Some("canary-42\r\nEvil: 1"));
        assert!(
            argv.windows(2)
                .any(|w| w[0] == "--data-binary" && w[1] == "@-")
        );
        assert!(
            argv.iter()
                .any(|a| a == "X-Chinwag-Canary-Run: canary-42Evil1")
        );
        assert!(!argv.iter().any(|a| a.contains('\r') || a.contains('\n')));
        assert!(
            !argv
                .iter()
                .any(|a| a.contains("550e8400") || a.contains("distinct_id"))
        );
    }

    #[test]
    fn rate_limiter_fails_closed_after_burst_and_config_refuses_symlink_escape() {
        let sink = Arc::new(Mutex::new(Vec::new()));
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("victim.json");
        std::fs::write(&victim, b"UNCHANGED").unwrap();

        let symlink_cfg = tmp.path().join("telemetry_config.json");
        std::os::unix::fs::symlink(&victim, &symlink_cfg).unwrap();

        let runtime =
            UiTelemetryRuntime::new_with_dir(tmp.path().to_path_buf(), Some(sink.clone()));
        if !is_env_telemetry_disabled() {
            assert_eq!(
                runtime.update_preferences(br#"{"enabled":false}"#, None),
                Err("persistence_failed"),
                "symlinked telemetry_config.json must fail persistence rather than silently succeeding"
            );
            assert!(
                !runtime.ui_enabled.load(Ordering::SeqCst),
                "opt-out must still take effect immediately in memory even when disk persistence fails"
            );
            assert_eq!(
                runtime.update_preferences(br#"{"enabled":true}"#, None),
                Err("persistence_failed"),
                "re-enabling telemetry must refuse while telemetry_config.json is a symlink"
            );
        }
        assert_eq!(std::fs::read(&victim).unwrap(), b"UNCHANGED");

        std::fs::remove_file(&symlink_cfg).unwrap();
        let _ = runtime.update_preferences(br#"{"enabled":true}"#, None);
        if !is_env_telemetry_disabled() {
            let mut dropped = 0usize;
            for _ in 0..40 {
                let mut props = BTreeMap::new();
                props.insert("view".into(), TelemetryScalar::Str("board".into()));
                if runtime.enqueue_validated(UiTelemetryEvent::UiViewNavigated, props, None)
                    == EnqueueOutcome::DroppedRateLimited
                {
                    dropped += 1;
                }
            }
            assert!(
                dropped > 0,
                "token bucket must enforce burst cap fail-closed"
            );
        }
    }

    #[test]
    fn concurrent_telemetry_preference_updates_keep_memory_and_disk_in_sync() {
        let sink = Arc::new(Mutex::new(Vec::new()));
        let tmp = tempfile::tempdir().unwrap();
        let runtime =
            UiTelemetryRuntime::new_with_dir(tmp.path().to_path_buf(), Some(sink.clone()));
        if is_env_telemetry_disabled() {
            return;
        }

        let barrier = Arc::new(std::sync::Barrier::new(8));
        let mut handles = Vec::new();
        for tid in 0..8usize {
            let rt = Arc::clone(&runtime);
            let bar = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                bar.wait();
                for step in 0..16usize {
                    let body: &[u8] = if (tid + step) % 3 == 0 {
                        br#"{"action":"rotate_id"}"#
                    } else if (tid + step) % 2 == 0 {
                        br#"{"enabled":false}"#
                    } else {
                        br#"{"enabled":true}"#
                    };
                    let res = rt.update_preferences(body, None);
                    assert!(res.is_ok(), "concurrent preference update failed: {res:?}");
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let mem_enabled = runtime.ui_enabled.load(Ordering::SeqCst);
        let raw_cfg = std::fs::read_to_string(tmp.path().join("telemetry_config.json")).unwrap();
        let disk_cfg: PersistedTelemetryConfig = serde_json::from_str(&raw_cfg).unwrap();
        assert_eq!(
            mem_enabled, disk_cfg.enabled,
            "live in-memory telemetry gate must strictly match persisted telemetry_config.json after concurrent updates"
        );

        let raw_seed = std::fs::read_to_string(tmp.path().join("telemetry_id")).unwrap();
        let expected_id = derive_distinct_id_from_seed(raw_seed.trim());
        let actual_id = runtime.identity_lock.lock().unwrap().0.clone();
        assert_eq!(
            actual_id, expected_id,
            "live distinct_id must strictly match persisted telemetry_id after concurrent rotations"
        );
    }
}
