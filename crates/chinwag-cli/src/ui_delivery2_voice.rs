// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Duplex Live Voice Engine & Safety Guards for `Delivery-2` (`CHWG-0255` · `:5487` Web Surface).
//!
//! Enforces:
//!   - Pillar 1: 7-State Duplex Voice State Machine (`Idle`, `Connecting`, `Listening`, `Thinking`,
//!     `Speaking`, `SilenceWarning`, `Paused`) + deterministic 9-bar golden-ratio waveform
//!     `voice_frame(t_ms, amp, period_ms, depth)` (`0` random calls; exact parity with `motion.js`).
//!   - Pillar 2: `VoiceDelegate` dual-channel split (`"thinking"` silent status labels with
//!     `>= 3000ms` hold vs `"commentary"` spoken replies truncated cleanly at sentence boundaries
//!     `<= 1500` chars) + fail-closed `spoken_option()` parser stripping polite filler while
//!     rejecting negations, bare `"yes"`/`"ok"`, and ambiguous phrases.
//!   - Pillar 3: Server-owned `600s` `expires_at_unix` TTL, server-enforced `40 Cr` Credits cap,
//!     `75s` silence warning + `90s` auto-pause, `8s` tool/approval hold audio-leg park (`0 Cr`),
//!     `15s` missing-heartbeat anti-orphan park (leaving background runs untouched), durable
//!     transcript persistence across reloads, and mandatory `physical_click_verified == true`
//!     enforcement on danger-class merges/deploys.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::f64::consts::{PI, TAU};

pub const VOICE_SESSION_TTL_SECS: u64 = 600;
pub const VOICE_SESSION_CREDITS_CAP: u64 = 40;
pub const VOICE_DEFAULT_TURN_CREDITS: u64 = 4;
pub const VOICE_CONNECTING_TIMEOUT_MS: u64 = 8_000;
pub const VOICE_SILENCE_WARNING_SECS: u64 = 75;
pub const VOICE_SILENCE_PARK_SECS: u64 = 90;
pub const VOICE_HOLD_PARK_SECS: u64 = 8;
pub const VOICE_HEARTBEAT_INTERVAL_SECS: u64 = 5;
pub const VOICE_HEARTBEAT_ORPHAN_SECS: u64 = 15;
pub const VOICE_THINKING_HOLD_MS: u64 = 3_000;
pub const VOICE_MAX_COMMENTARY_CHARS: usize = 1_500;

pub const DANGER_VOICE_REJECT_COPY: &str =
    "Press Approve to confirm. Voice can't approve this one.";
pub const SILENCE_WARNING_COPY: &str = "Still there? Pausing in 15s";
pub const VOICE_PAUSED_COPY: &str = "Voice paused · 0 Cr while paused";
pub const VOICE_TTL_ENDED_COPY: &str = "Voice ended at the 10-minute limit. Your thread is saved.";
pub const VOICE_CAP_ENDED_COPY: &str =
    "Voice paused at the 40 Cr session cap. Your thread is saved.";

const WAVEFORM_S_MIN: f64 = 0.12;
const GOLDEN_CONJUGATE: f64 = 0.618_033_988_7;

const FILLER_WORDS: &[&str] = &[
    "it", "ok", "okay", "please", "that", "yeah", "yes", "yep", "uh", "um", "now",
];

const NEGATION_WORDS: &[&str] = &[
    "don't", "dont", "not", "never", "no", "can't", "cant", "cannot", "won't", "wont", "neither",
    "unless", "without", "wait", "stop", "hold", "cancel",
];

pub const DANGER_ACTION_VERBS: &[&str] = &["approve", "merge", "deploy", "ship", "push", "apply"];

const IMPERATIVE_LEAD_INS: &[&str] = &[
    "please",
    "ok",
    "okay",
    "yes",
    "yeah",
    "yep",
    "sure",
    "alright",
    "right",
    "now",
    "just",
    "go",
    "ahead",
    "and",
    "then",
    "lets",
    "let's",
    "let",
    "us",
    "can",
    "could",
    "would",
    "will",
    "you",
    "i",
    "we",
    "lgtm",
    "looks",
    "good",
    "uh",
    "um",
    "hey",
    "delivery",
    "delivery-2",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoiceSessionError {
    SessionNotFound,
    SessionMismatch,
    SessionExpired,
    SessionEnded,
    CreditsCapReached,
    SessionParked,
    DangerApprovalForbidden,
    InvalidAction,
}

impl VoiceSessionError {
    pub fn as_code(self) -> &'static str {
        match self {
            Self::SessionNotFound => "voice_session_not_found",
            Self::SessionMismatch => "voice_session_mismatch",
            Self::SessionExpired => "VoiceSessionExpired",
            Self::SessionEnded => "VoiceSessionEnded",
            Self::CreditsCapReached => "VoiceCreditsCapReached",
            Self::SessionParked => "voice_session_parked",
            Self::DangerApprovalForbidden => "VoiceDangerApprovalForbidden",
            Self::InvalidAction => "invalid_voice_action",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VoiceSessionState {
    #[default]
    Idle,
    Connecting,
    Listening,
    Thinking,
    Speaking,
    SilenceWarning,
    Paused,
}

impl VoiceSessionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Connecting => "connecting",
            Self::Listening => "listening",
            Self::Thinking => "thinking",
            Self::Speaking => "speaking",
            Self::SilenceWarning => "silence_warning",
            Self::Paused => "paused",
        }
    }

    pub fn is_live_audio(self) -> bool {
        matches!(
            self,
            Self::Connecting
                | Self::Listening
                | Self::Thinking
                | Self::Speaking
                | Self::SilenceWarning
        )
    }

    pub fn can_transition_to(self, next: Self) -> bool {
        if self == next {
            return true;
        }
        match self {
            Self::Idle => matches!(next, Self::Connecting | Self::Listening | Self::Paused),
            Self::Connecting => matches!(next, Self::Listening | Self::Paused | Self::Idle),
            Self::Listening => matches!(
                next,
                Self::Thinking | Self::Speaking | Self::SilenceWarning | Self::Paused | Self::Idle
            ),
            Self::Thinking => matches!(
                next,
                Self::Speaking | Self::Listening | Self::Paused | Self::Idle
            ),
            Self::Speaking => matches!(
                next,
                Self::Listening | Self::Thinking | Self::SilenceWarning | Self::Paused | Self::Idle
            ),
            Self::SilenceWarning => matches!(
                next,
                Self::Listening | Self::Thinking | Self::Speaking | Self::Paused | Self::Idle
            ),
            Self::Paused => matches!(next, Self::Connecting | Self::Listening | Self::Idle),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoiceContextChannel {
    Thinking,
    Commentary,
}

impl VoiceContextChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Thinking => "thinking",
            Self::Commentary => "commentary",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoiceChannelEvent {
    pub channel: VoiceContextChannel,
    pub spoken: bool,
    pub text: String,
    pub min_hold_ms: u64,
}

#[derive(Debug, Clone, Default)]
pub struct VoiceDelegateTracker {
    thinking_label: Option<String>,
    thinking_hold_until_ms: u64,
    events: Vec<VoiceChannelEvent>,
}

impl VoiceDelegateTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe_thinking(
        &mut self,
        clean_tool_label: &str,
        now_ms: u64,
    ) -> Option<VoiceChannelEvent> {
        let trimmed = clean_tool_label.trim();
        if trimmed.is_empty() {
            return None;
        }
        if self.thinking_label.is_some() && now_ms < self.thinking_hold_until_ms {
            return None;
        }
        let text = truncate_commentary_at_sentence(trimmed, 240);
        self.thinking_label = Some(text.clone());
        self.thinking_hold_until_ms = now_ms.saturating_add(VOICE_THINKING_HOLD_MS);
        let ev = VoiceChannelEvent {
            channel: VoiceContextChannel::Thinking,
            spoken: false,
            text,
            min_hold_ms: VOICE_THINKING_HOLD_MS,
        };
        self.events.push(ev.clone());
        Some(ev)
    }

    pub fn observe_commentary(
        &mut self,
        raw_reply: &str,
        interrupted: bool,
    ) -> Option<VoiceChannelEvent> {
        if interrupted {
            return None;
        }
        let trimmed = raw_reply.trim();
        if trimmed.is_empty() {
            return None;
        }
        let text = truncate_commentary_at_sentence(trimmed, VOICE_MAX_COMMENTARY_CHARS);
        if text.is_empty() {
            return None;
        }
        let ev = VoiceChannelEvent {
            channel: VoiceContextChannel::Commentary,
            spoken: true,
            text,
            min_hold_ms: 0,
        };
        self.events.push(ev.clone());
        Some(ev)
    }

    pub fn active_thinking_label(&self) -> Option<&str> {
        self.thinking_label.as_deref()
    }

    pub fn events(&self) -> &[VoiceChannelEvent] {
        &self.events
    }
}

/// Deterministic 9-bar golden-ratio phase-staggered waveform (`0` random calls).
/// Matches `voiceFrame(t, A, { T, d })` in `assets/ui-v4/motion.js` within `±0.001`.
pub fn voice_frame(t_ms: f64, amp: f64, period_ms: f64, depth: f64) -> [f32; 9] {
    let safe_period = if period_ms.is_finite() && period_ms > 0.0 {
        period_ms
    } else {
        2200.0
    };
    let clamped_amp = if amp.is_finite() {
        amp.clamp(0.0, 1.0)
    } else {
        0.0
    };
    let clamped_depth = if depth.is_finite() {
        depth.clamp(0.0, 1.0)
    } else {
        0.5
    };
    let safe_t = if t_ms.is_finite() { t_ms } else { 0.0 };

    let mut out = [WAVEFORM_S_MIN as f32; 9];
    for (i, slot) in out.iter_mut().enumerate() {
        let idx = i as f64;
        let w = 0.40 + 0.60 * (PI * (idx - 4.0) / 9.0).cos().powi(2);
        let phi = (idx * GOLDEN_CONJUGATE) % 1.0;
        let th = TAU * (safe_t / safe_period + phi);
        let c = 0.5 + 0.30 * th.sin() + 0.20 * (2.0 * th + TAU * phi).sin();
        let inner = (clamped_amp * w * ((1.0 - clamped_depth) + clamped_depth * c)).clamp(0.0, 1.0);
        *slot = (WAVEFORM_S_MIN + (1.0 - WAVEFORM_S_MIN) * inner) as f32;
    }
    out
}

pub fn amp_from_rms(rms: f64) -> f64 {
    let clamped_rms = if rms.is_finite() { rms.max(1e-6) } else { 1e-6 };
    ((20.0 * clamped_rms.log10() + 55.0) / 40.0).clamp(0.0, 1.0)
}

pub fn smooth_amp(current: f64, target: f64, dt_ms: f64) -> f64 {
    let dt = if dt_ms.is_finite() && dt_ms > 0.0 {
        dt_ms
    } else {
        0.0
    };
    let tau_ms = if target > current { 40.0 } else { 180.0 };
    current + (target - current) * (1.0 - (-dt / tau_ms).exp())
}

pub fn format_voice_timer(elapsed_secs: u64, max_secs: u64) -> String {
    let clamped = elapsed_secs.min(max_secs);
    let e_min = clamped / 60;
    let e_sec = clamped % 60;
    let m_min = max_secs / 60;
    let m_sec = max_secs % 60;
    format!("{e_min:02}:{e_sec:02} / {m_min:02}:{m_sec:02}")
}

/// Truncate spoken commentary cleanly at the last sentence boundary (`<= max_chars` chars)
/// so voice replies never cut off mid-sentence (`H7`).
pub fn truncate_commentary_at_sentence(input: &str, max_chars: usize) -> String {
    let trimmed = input.trim();
    if max_chars == 0 || trimmed.is_empty() {
        return String::new();
    }
    let chars: Vec<char> = trimmed.chars().collect();
    if chars.len() <= max_chars {
        return trimmed.to_string();
    }

    let window = &chars[..max_chars];
    let mut last_sentence_end: Option<usize> = None;
    for idx in 0..window.len() {
        let ch = window[idx];
        if matches!(ch, '.' | '!' | '?') {
            let next_ok = idx + 1 == window.len()
                || window[idx + 1].is_whitespace()
                || matches!(window[idx + 1], '"' | '\'' | ')');
            if next_ok {
                let mut end = idx + 1;
                if end < window.len() && matches!(window[end], '"' | '\'' | ')') {
                    end += 1;
                }
                last_sentence_end = Some(end);
            }
        }
    }

    if let Some(cut) = last_sentence_end
        && cut >= 2
    {
        return window[..cut].iter().collect::<String>().trim().to_string();
    }

    // Unpunctuated fallback: cut at last word boundary and close with a period.
    let budget = max_chars.saturating_sub(1);
    if budget == 0 {
        return ".".to_string();
    }
    let sub = &chars[..budget];
    if let Some(last_ws) = sub.iter().rposition(|c| c.is_whitespace())
        && last_ws >= 1
    {
        let mut s: String = sub[..last_ws].iter().collect();
        s = s.trim_end().to_string();
        s.push('.');
        return s;
    }
    let mut s: String = sub.iter().collect();
    s.push('.');
    s
}

fn tokenize_speech_words(raw: &str) -> Vec<String> {
    let normalized = raw.replace(['\u{2018}', '\u{2019}'], "'");
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = normalized.chars().collect();
    for (idx, &ch) in chars.iter().enumerate() {
        let is_inner_apostrophe = ch == '\''
            && !cur.is_empty()
            && idx + 1 < chars.len()
            && chars[idx + 1].is_alphanumeric();
        if ch.is_alphanumeric() || is_inner_apostrophe {
            for lc in ch.to_lowercase() {
                cur.push(lc);
            }
        } else if !cur.is_empty() {
            tokens.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

/// Fail-closed spoken option parser (`CHWG-0255` Pillar 2):
///   - Strips polite speech filler (`"Approve please"` -> `"approve"`).
///   - Rejects ANY negation modifier (`"don't approve"`, `"do not approve"`, `"never approve"`, `"no approve"`).
///   - Rejects bare `"yes"`, `"ok"`, `"okay"`, `"yeah"`, `"please"`, and empty strings.
///   - Rejects ambiguous utterances or duplicate normalized option sets.
pub fn spoken_option(utterance: &str, options: &[&str]) -> Option<String> {
    if options.is_empty() {
        return None;
    }
    let words = tokenize_speech_words(utterance);
    if words.is_empty() {
        return None;
    }

    // Fail closed immediately on any negation word in the utterance.
    if words.iter().any(|w| NEGATION_WORDS.contains(&w.as_str())) {
        return None;
    }

    // Reject conjunctions/disjunctions that indicate hesitation or multi-choice ambiguity.
    if words
        .iter()
        .any(|w| matches!(w.as_str(), "or" | "maybe" | "if" | "whether"))
    {
        return None;
    }

    let filtered: Vec<&str> = words
        .iter()
        .map(String::as_str)
        .filter(|w| !FILLER_WORDS.contains(w))
        .collect();
    if filtered.is_empty() {
        return None;
    }
    let candidate = filtered.join(" ");

    let mut matched: Option<String> = None;
    for &opt in options {
        let opt_words = tokenize_speech_words(opt);
        let opt_filtered: Vec<&str> = opt_words
            .iter()
            .map(String::as_str)
            .filter(|w| !FILLER_WORDS.contains(w))
            .collect();
        if opt_filtered.is_empty() {
            continue;
        }
        let normalized_opt = opt_filtered.join(" ");
        if normalized_opt == candidate {
            if matched.is_some() {
                // Ambiguous duplicate option match -> fail closed.
                return None;
            }
            matched = Some(normalized_opt);
        }
    }

    matched
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoiceSessionRecord {
    pub session_id: String,
    pub thread_id: String,
    pub state: VoiceSessionState,
    pub opened_at_unix: u64,
    pub expires_at_unix: u64,
    pub last_heartbeat_unix: u64,
    pub last_activity_unix: u64,
    #[serde(default)]
    pub hold_started_unix: Option<u64>,
    pub credits_cap: u64,
    pub credits_used: u64,
    #[serde(default)]
    pub muted: bool,
    #[serde(default)]
    pub audio_leg_parked: bool,
    #[serde(default)]
    pub ended: bool,
    #[serde(default)]
    pub park_reason: Option<String>,
    #[serde(default)]
    pub ended_reason: Option<String>,
    #[serde(default)]
    pub thinking_label: Option<String>,
    #[serde(default)]
    pub thinking_hold_until_ms: u64,
    #[serde(default)]
    pub last_spoken_commentary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Delivery2VoiceStore {
    #[serde(default)]
    pub active_session: Option<VoiceSessionRecord>,
    #[serde(default)]
    pub total_voice_credits_used: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct VoiceHeartbeatInput<'a> {
    pub requested_session_id: Option<&'a str>,
    pub client_idle_secs: Option<u64>,
    pub client_hold_secs: Option<u64>,
    pub speech_active: bool,
    pub barge_in: bool,
    pub has_unsettled_hold: bool,
    pub now_unix: u64,
}

impl Delivery2VoiceStore {
    /// Returns true if any non-ended, non-expired voice session is currently open at `now_unix`,
    /// including sessions whose audio leg is temporarily parked (`8s` `hold_park`, `silence_timeout`, etc.).
    pub fn has_open_session(&self, now_unix: u64) -> bool {
        self.active_session
            .as_ref()
            .is_some_and(|s| !s.ended && now_unix < s.expires_at_unix)
    }

    /// Returns true if an unparked, non-ended voice session is currently active at `now_unix`.
    pub fn has_live_unparked_session(&self, now_unix: u64) -> bool {
        let Some(sess) = &self.active_session else {
            return false;
        };
        if sess.ended || sess.audio_leg_parked {
            return false;
        }
        if now_unix >= sess.expires_at_unix || sess.credits_used >= sess.credits_cap {
            return false;
        }
        if now_unix.saturating_sub(sess.last_heartbeat_unix) > VOICE_HEARTBEAT_ORPHAN_SECS {
            return false;
        }
        sess.state.is_live_audio()
    }

    /// Reconcile server-owned TTL (`600s`), `40 Cr` cap, `15s` missing-heartbeat anti-orphan park,
    /// `8s` tool/approval hold park, and `75s`/`90s` silence park deterministically.
    pub fn reconcile_at(
        &mut self,
        now_unix: u64,
        has_unsettled_hold: bool,
        check_orphan_heartbeat: bool,
    ) -> bool {
        let Some(sess) = self.active_session.as_mut() else {
            return false;
        };
        if sess.ended {
            sess.state = VoiceSessionState::Paused;
            sess.audio_leg_parked = true;
            return false;
        }

        let mut changed = false;

        // 1. Hard 600s server-owned TTL check
        if now_unix >= sess.expires_at_unix {
            sess.state = VoiceSessionState::Paused;
            sess.audio_leg_parked = true;
            sess.ended = true;
            sess.ended_reason = Some("ttl_expired".to_string());
            sess.park_reason = Some("ttl_expired".to_string());
            return true;
        }

        // 2. Hard 40 Cr server-enforced session cap check
        if sess.credits_used >= sess.credits_cap {
            sess.state = VoiceSessionState::Paused;
            sess.audio_leg_parked = true;
            sess.ended = true;
            sess.ended_reason = Some("credits_cap_reached".to_string());
            sess.park_reason = Some("credits_cap_reached".to_string());
            return true;
        }

        if sess.audio_leg_parked || sess.state == VoiceSessionState::Paused {
            return false;
        }

        // 3. 15s missing-heartbeat anti-orphan guard (parks voice leg without killing background runs)
        if check_orphan_heartbeat
            && now_unix.saturating_sub(sess.last_heartbeat_unix) > VOICE_HEARTBEAT_ORPHAN_SECS
        {
            sess.state = VoiceSessionState::Paused;
            sess.audio_leg_parked = true;
            sess.park_reason = Some("orphan_heartbeat".to_string());
            return true;
        }

        // 4. 8s tool/approval hold audio-leg park (`Paused · 0 Cr`)
        if has_unsettled_hold {
            let hold_start = *sess.hold_started_unix.get_or_insert(now_unix);
            if now_unix.saturating_sub(hold_start) >= VOICE_HOLD_PARK_SECS {
                sess.state = VoiceSessionState::Paused;
                sess.audio_leg_parked = true;
                sess.park_reason = Some("hold_park".to_string());
                return true;
            }
        } else if sess.hold_started_unix.is_some() {
            sess.hold_started_unix = None;
            changed = true;
        }

        // 5. 75s silence warning + 90s auto-pause
        let idle_secs = now_unix.saturating_sub(sess.last_activity_unix);
        if idle_secs >= VOICE_SILENCE_PARK_SECS {
            sess.state = VoiceSessionState::Paused;
            sess.audio_leg_parked = true;
            sess.park_reason = Some("silence_timeout".to_string());
            return true;
        }
        if idle_secs >= VOICE_SILENCE_WARNING_SECS
            && sess.state != VoiceSessionState::SilenceWarning
        {
            sess.state = VoiceSessionState::SilenceWarning;
            changed = true;
        }

        changed
    }

    pub fn start_or_control_session(
        &mut self,
        action: &str,
        session_id_seed: &str,
        thread_id: &str,
        initial_connecting: bool,
        available_workspace_credits: u64,
        now_unix: u64,
    ) -> Result<Value, (&'static str, Value)> {
        let act = if action.trim().is_empty() {
            "start"
        } else {
            action.trim()
        };

        match act {
            "start" => {
                if available_workspace_credits == 0 {
                    return Err((
                        "402 Payment Required",
                        json!({
                            "ok": false,
                            "error_code": "VoiceCreditsCapReached",
                            "error": "No workspace credits remaining. Voice stays paused at 0 Cr."
                        }),
                    ));
                }
                let effective_cap = VOICE_SESSION_CREDITS_CAP.min(available_workspace_credits);
                let init_state = if initial_connecting {
                    VoiceSessionState::Connecting
                } else {
                    VoiceSessionState::Listening
                };
                let rec = VoiceSessionRecord {
                    session_id: format!("voice-{session_id_seed}"),
                    thread_id: thread_id.to_string(),
                    state: init_state,
                    opened_at_unix: now_unix,
                    expires_at_unix: now_unix.saturating_add(VOICE_SESSION_TTL_SECS),
                    last_heartbeat_unix: now_unix,
                    last_activity_unix: now_unix,
                    hold_started_unix: None,
                    credits_cap: effective_cap,
                    credits_used: 0,
                    muted: false,
                    audio_leg_parked: false,
                    ended: false,
                    park_reason: None,
                    ended_reason: None,
                    thinking_label: None,
                    thinking_hold_until_ms: 0,
                    last_spoken_commentary: None,
                };
                self.active_session = Some(rec);
                Ok(self.to_client_json(now_unix))
            }
            "ready" | "resume" => {
                let Some(sess) = self.active_session.as_mut() else {
                    return Err((
                        "404 Not Found",
                        json!({
                            "ok": false,
                            "error_code": VoiceSessionError::SessionNotFound.as_code(),
                            "error": "Start a voice session first."
                        }),
                    ));
                };
                if sess.ended {
                    sess.state = VoiceSessionState::Paused;
                    sess.audio_leg_parked = true;
                    let msg = match sess.ended_reason.as_deref() {
                        Some("ttl_expired") => VOICE_TTL_ENDED_COPY,
                        Some("credits_cap_reached") => VOICE_CAP_ENDED_COPY,
                        _ => "This voice session has ended. Start a new voice call to continue.",
                    };
                    return Err((
                        "409 Conflict",
                        json!({
                            "ok": false,
                            "error_code": VoiceSessionError::SessionEnded.as_code(),
                            "voice_error": "SessionEnded",
                            "error": msg,
                            "voice": self.to_client_json(now_unix)
                        }),
                    ));
                }
                if now_unix >= sess.expires_at_unix {
                    sess.state = VoiceSessionState::Paused;
                    sess.audio_leg_parked = true;
                    sess.ended = true;
                    sess.ended_reason = Some("ttl_expired".to_string());
                    return Err((
                        "409 Conflict",
                        json!({
                            "ok": false,
                            "error_code": VoiceSessionError::SessionExpired.as_code(),
                            "error": VOICE_TTL_ENDED_COPY,
                            "voice": self.to_client_json(now_unix)
                        }),
                    ));
                }
                if sess.credits_used >= sess.credits_cap || available_workspace_credits == 0 {
                    sess.state = VoiceSessionState::Paused;
                    sess.audio_leg_parked = true;
                    sess.ended = true;
                    sess.ended_reason = Some("credits_cap_reached".to_string());
                    return Err((
                        "402 Payment Required",
                        json!({
                            "ok": false,
                            "error_code": VoiceSessionError::CreditsCapReached.as_code(),
                            "error": VOICE_CAP_ENDED_COPY,
                            "voice": self.to_client_json(now_unix)
                        }),
                    ));
                }
                sess.ended = false;
                sess.ended_reason = None;
                sess.park_reason = None;
                sess.audio_leg_parked = false;
                sess.hold_started_unix = None;
                sess.last_heartbeat_unix = now_unix;
                sess.last_activity_unix = now_unix;
                sess.state = VoiceSessionState::Listening;
                Ok(self.to_client_json(now_unix))
            }
            "mute" | "unmute" => {
                let Some(sess) = self.active_session.as_mut() else {
                    return Err((
                        "404 Not Found",
                        json!({
                            "ok": false,
                            "error_code": "voice_session_not_found",
                            "error": "No active voice session."
                        }),
                    ));
                };
                sess.muted = act == "mute";
                sess.last_heartbeat_unix = now_unix;
                Ok(self.to_client_json(now_unix))
            }
            "end" => {
                if let Some(sess) = self.active_session.as_mut() {
                    sess.state = VoiceSessionState::Paused;
                    sess.audio_leg_parked = true;
                    sess.ended = true;
                    sess.ended_reason = Some("user_ended".to_string());
                    sess.park_reason = Some("user_ended".to_string());
                }
                Ok(self.to_client_json(now_unix))
            }
            "status" => {
                let _ = self.reconcile_at(now_unix, false, true);
                Ok(self.to_client_json(now_unix))
            }
            _ => Err((
                "400 Bad Request",
                json!({
                    "ok": false,
                    "error_code": "invalid_voice_action",
                    "error": "Voice session action must be 'start', 'ready', 'resume', 'mute', 'unmute', 'end', or 'status'."
                }),
            )),
        }
    }

    pub fn heartbeat(
        &mut self,
        input: VoiceHeartbeatInput<'_>,
    ) -> Result<Value, (&'static str, Value)> {
        let VoiceHeartbeatInput {
            requested_session_id,
            client_idle_secs,
            client_hold_secs,
            speech_active,
            barge_in,
            has_unsettled_hold,
            now_unix,
        } = input;
        let Some(sess) = self.active_session.as_mut() else {
            return Err((
                "404 Not Found",
                json!({
                    "ok": false,
                    "error_code": "voice_session_not_found",
                    "error": "No active voice session."
                }),
            ));
        };
        if let Some(req_id) = requested_session_id
            .map(str::trim)
            .filter(|s| !s.is_empty())
            && req_id != sess.session_id
        {
            return Err((
                "409 Conflict",
                json!({
                    "ok": false,
                    "error_code": "voice_session_mismatch",
                    "error": "Voice session ID did not match the active session."
                }),
            ));
        }

        // First check if heartbeat was already orphaned (>15s gap) BEFORE refreshing `last_heartbeat_unix`.
        if !sess.audio_leg_parked
            && !sess.ended
            && now_unix.saturating_sub(sess.last_heartbeat_unix) > VOICE_HEARTBEAT_ORPHAN_SECS
        {
            sess.state = VoiceSessionState::Paused;
            sess.audio_leg_parked = true;
            sess.park_reason = Some("orphan_heartbeat".to_string());
            return Ok(self.to_client_json(now_unix));
        }

        sess.last_heartbeat_unix = now_unix;

        if speech_active || barge_in {
            sess.last_activity_unix = now_unix;
            if !sess.audio_leg_parked && !sess.ended {
                sess.state = VoiceSessionState::Listening;
            }
        } else if let Some(reported_idle) = client_idle_secs {
            // Client VAD can report silence earlier, never postpone server-measured silence.
            let candidate_last = now_unix.saturating_sub(reported_idle);
            if candidate_last < sess.last_activity_unix {
                sess.last_activity_unix = candidate_last;
            }
        }

        if let Some(reported_hold) = client_hold_secs
            && reported_hold > 0
        {
            let candidate_hold_start = now_unix.saturating_sub(reported_hold);
            sess.hold_started_unix = Some(
                sess.hold_started_unix
                    .map_or(candidate_hold_start, |prev| prev.min(candidate_hold_start)),
            );
        }

        let hold_active = has_unsettled_hold || client_hold_secs.is_some_and(|s| s > 0);
        let _ = self.reconcile_at(now_unix, hold_active, false);
        Ok(self.to_client_json(now_unix))
    }

    pub fn park(
        &mut self,
        requested_session_id: Option<&str>,
        reason: &str,
        now_unix: u64,
    ) -> Result<Value, (&'static str, Value)> {
        let Some(sess) = self.active_session.as_mut() else {
            return Ok(self.to_client_json(now_unix));
        };
        if let Some(req_id) = requested_session_id
            .map(str::trim)
            .filter(|s| !s.is_empty())
            && req_id != sess.session_id
        {
            return Err((
                "409 Conflict",
                json!({
                    "ok": false,
                    "error_code": "voice_session_mismatch",
                    "error": "Voice session ID did not match the active session."
                }),
            ));
        }
        let clean_reason = match reason.trim() {
            "silence_timeout" => "silence_timeout",
            "hold_park" => "hold_park",
            "orphan_heartbeat" => "orphan_heartbeat",
            "page_reload" => "page_reload",
            "user_ended" => "user_ended",
            _ => "user_paused",
        };
        sess.state = VoiceSessionState::Paused;
        sess.audio_leg_parked = true;
        sess.park_reason = Some(clean_reason.to_string());
        if clean_reason == "user_ended" {
            sess.ended = true;
            sess.ended_reason = Some("user_ended".to_string());
        }
        sess.last_heartbeat_unix = now_unix;
        Ok(self.to_client_json(now_unix))
    }

    /// Charge voice credits strictly up to the server-owned `40 Cr` session cap.
    pub fn charge_turn_credits(
        &mut self,
        requested_credits: u64,
        now_unix: u64,
    ) -> Result<(u64, bool), (&'static str, Value)> {
        let Some(sess) = self.active_session.as_mut() else {
            return Err((
                "404 Not Found",
                json!({
                    "ok": false,
                    "error_code": "voice_session_not_found",
                    "error": "Start a voice session before sending a voice turn."
                }),
            ));
        };

        if sess.ended && sess.ended_reason.as_deref() == Some("ttl_expired")
            || now_unix >= sess.expires_at_unix
        {
            sess.state = VoiceSessionState::Paused;
            sess.audio_leg_parked = true;
            sess.ended = true;
            sess.ended_reason = Some("ttl_expired".to_string());
            return Err((
                "409 Conflict",
                json!({
                    "ok": false,
                    "error_code": "VoiceSessionExpired",
                    "error": VOICE_TTL_ENDED_COPY,
                    "voice": self.to_client_json(now_unix)
                }),
            ));
        }

        if sess.ended && sess.ended_reason.as_deref() == Some("credits_cap_reached")
            || sess.credits_used >= sess.credits_cap
        {
            sess.state = VoiceSessionState::Paused;
            sess.audio_leg_parked = true;
            sess.ended = true;
            sess.ended_reason = Some("credits_cap_reached".to_string());
            return Err((
                "402 Payment Required",
                json!({
                    "ok": false,
                    "error_code": "VoiceCreditsCapReached",
                    "error": VOICE_CAP_ENDED_COPY,
                    "voice": self.to_client_json(now_unix)
                }),
            ));
        }

        if sess.audio_leg_parked || sess.ended {
            return Err((
                "409 Conflict",
                json!({
                    "ok": false,
                    "error_code": "voice_session_parked",
                    "error": "Voice is paused at 0 Cr. Press Resume to continue speaking.",
                    "voice": self.to_client_json(now_unix)
                }),
            ));
        }

        let remaining = sess.credits_cap.saturating_sub(sess.credits_used);
        let delta = requested_credits.clamp(1, 40).min(remaining);
        sess.credits_used = sess.credits_used.saturating_add(delta);
        self.total_voice_credits_used = self.total_voice_credits_used.saturating_add(delta);
        sess.last_activity_unix = now_unix;
        sess.last_heartbeat_unix = now_unix;

        let hit_cap = sess.credits_used >= sess.credits_cap;
        if hit_cap {
            sess.state = VoiceSessionState::Paused;
            sess.audio_leg_parked = true;
            sess.ended = true;
            sess.ended_reason = Some("credits_cap_reached".to_string());
            sess.park_reason = Some("credits_cap_reached".to_string());
        } else {
            sess.state = VoiceSessionState::Speaking;
        }
        Ok((delta, hit_cap))
    }

    pub fn to_client_json(&self, now_unix: u64) -> Value {
        let Some(sess) = &self.active_session else {
            return json!({
                "session_id": Value::Null,
                "state": VoiceSessionState::Idle.as_str(),
                "status_label": "Idle",
                "timer_label": format_voice_timer(0, VOICE_SESSION_TTL_SECS),
                "elapsed_secs": 0,
                "remaining_secs": VOICE_SESSION_TTL_SECS,
                "max_duration_secs": VOICE_SESSION_TTL_SECS,
                "opened_at_unix": Value::Null,
                "expires_at_unix": Value::Null,
                "credits_used": 0,
                "credits_cap": VOICE_SESSION_CREDITS_CAP,
                "credits_rate_per_min": 0,
                "pause_badge": "Paused · 0 Cr",
                "muted": false,
                "audio_leg_parked": true,
                "ended": false,
                "park_reason": Value::Null,
                "ended_reason": Value::Null,
                "thinking_label": Value::Null,
                "last_spoken_commentary": Value::Null,
                "silence_warning_secs": VOICE_SILENCE_WARNING_SECS,
                "silence_park_secs": VOICE_SILENCE_PARK_SECS,
                "hold_park_secs": VOICE_HOLD_PARK_SECS,
                "heartbeat_interval_secs": VOICE_HEARTBEAT_INTERVAL_SECS,
                "heartbeat_orphan_secs": VOICE_HEARTBEAT_ORPHAN_SECS,
                "danger_reject_copy": DANGER_VOICE_REJECT_COPY
            });
        };

        let raw_elapsed = now_unix.saturating_sub(sess.opened_at_unix);
        let elapsed_secs = raw_elapsed.min(VOICE_SESSION_TTL_SECS);
        let remaining_secs = sess.expires_at_unix.saturating_sub(now_unix);
        let status_label = match sess.state {
            VoiceSessionState::Idle => "Idle",
            VoiceSessionState::Connecting => "Connecting…",
            VoiceSessionState::Listening => {
                if sess.muted {
                    "Muted"
                } else {
                    "Listening"
                }
            }
            VoiceSessionState::Thinking => sess.thinking_label.as_deref().unwrap_or("Thinking"),
            VoiceSessionState::Speaking => "Speaking",
            VoiceSessionState::SilenceWarning => SILENCE_WARNING_COPY,
            VoiceSessionState::Paused => match sess.ended_reason.as_deref() {
                Some("ttl_expired") => VOICE_TTL_ENDED_COPY,
                Some("credits_cap_reached") => VOICE_CAP_ENDED_COPY,
                Some("user_ended") => "Call ended · 0 Cr",
                _ => VOICE_PAUSED_COPY,
            },
        };
        let active_burn_rate =
            if sess.audio_leg_parked || sess.ended || sess.state == VoiceSessionState::Paused {
                0
            } else {
                4
            };

        json!({
            "session_id": sess.session_id,
            "thread_id": sess.thread_id,
            "state": sess.state.as_str(),
            "status_label": status_label,
            "timer_label": format_voice_timer(elapsed_secs, VOICE_SESSION_TTL_SECS),
            "elapsed_secs": elapsed_secs,
            "remaining_secs": remaining_secs,
            "max_duration_secs": VOICE_SESSION_TTL_SECS,
            "opened_at_unix": sess.opened_at_unix,
            "expires_at_unix": sess.expires_at_unix,
            "credits_used": sess.credits_used,
            "credits_cap": sess.credits_cap,
            "credits_rate_per_min": active_burn_rate,
            "pause_badge": "Paused · 0 Cr",
            "muted": sess.muted,
            "audio_leg_parked": sess.audio_leg_parked,
            "ended": sess.ended,
            "park_reason": sess.park_reason,
            "ended_reason": sess.ended_reason,
            "thinking_label": sess.thinking_label,
            "last_spoken_commentary": sess.last_spoken_commentary,
            "silence_warning_secs": VOICE_SILENCE_WARNING_SECS,
            "silence_park_secs": VOICE_SILENCE_PARK_SECS,
            "hold_park_secs": VOICE_HOLD_PARK_SECS,
            "heartbeat_interval_secs": VOICE_HEARTBEAT_INTERVAL_SECS,
            "heartbeat_orphan_secs": VOICE_HEARTBEAT_ORPHAN_SECS,
            "danger_reject_copy": DANGER_VOICE_REJECT_COPY
        })
    }
}

/// Returns true if an option label contains any danger-class action verb (`approve`, `merge`,
/// `deploy`, `ship`, `push`, `apply`), preventing voice option selection from routing around the
/// physical merge button gate.
pub fn option_contains_danger_verb(option: &str) -> bool {
    tokenize_speech_words(option)
        .iter()
        .any(|w| DANGER_ACTION_VERBS.contains(&w.as_str()))
}

/// Filters a slice of option labels down to non-danger options safe for `spoken_option()`.
pub fn filter_safe_voice_options<'a>(options: &'a [&'a str]) -> Vec<&'a str> {
    options
        .iter()
        .copied()
        .filter(|opt| !option_contains_danger_verb(opt))
        .collect()
}

/// Evaluates whether an utterance is attempting to approve or trigger a danger-class merge/deploy/push/apply action.
pub fn is_voice_danger_approval_attempt(utterance: &str, has_unsettled_danger_card: bool) -> bool {
    let words = tokenize_speech_words(utterance);
    if words.is_empty() || words.iter().any(|w| NEGATION_WORDS.contains(&w.as_str())) {
        return false;
    }

    // Check every clause (split on sentence/clause delimiters) for non-negated imperative phrases
    // starting with or targeting `approve`, `merge`, `deploy`, `ship`, `push`, or `apply`.
    for clause in utterance.split([',', ';', '.', '!', '?']) {
        let clause_words = tokenize_speech_words(clause);
        if clause_words.is_empty()
            || clause_words
                .iter()
                .any(|w| NEGATION_WORDS.contains(&w.as_str()))
        {
            continue;
        }
        let core: Vec<&str> = clause_words
            .iter()
            .map(String::as_str)
            .skip_while(|w| IMPERATIVE_LEAD_INS.contains(w))
            .collect();
        if let Some(&first) = core.first()
            && DANGER_ACTION_VERBS.contains(&first)
        {
            return true;
        }
    }

    let has_merge_or_deploy = words
        .iter()
        .any(|w| matches!(w.as_str(), "merge" | "deploy" | "ship" | "push" | "apply"));
    let matched_approve = spoken_option(
        utterance,
        &[
            "approve",
            "approve merge",
            "approve and merge",
            "merge",
            "deploy",
            "ship",
            "push",
            "apply",
            "apply locally",
        ],
    )
    .is_some();
    if matched_approve && (has_unsettled_danger_card || has_merge_or_deploy) {
        return true;
    }
    false
}

/// Enforces `physical_click_verified == true` and `source == "physical_click"` unconditionally
/// on all `decision == "approve"` merge/apply requests (`CHWG-0255` Pillar 3).
/// Client-supplied `"danger": false` booleans are ignored; any open (non-ended, non-expired)
/// voice session — including parked `8s` `hold_park` sessions — counts as voice-active.
pub fn enforce_physical_merge_button_gate(
    parsed_body: &Value,
    decision: &str,
    voice_session_active: bool,
) -> Result<(), (&'static str, Value)> {
    if decision != "approve" {
        return Ok(());
    }

    let source_str = parsed_body
        .get("source")
        .and_then(Value::as_str)
        .map(str::trim);
    let source_is_voice = source_str.is_some_and(|s| s.eq_ignore_ascii_case("voice"));
    let source_is_physical_click = source_str == Some("physical_click");
    let voice_originated = parsed_body
        .get("voice_originated")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let explicit_click_field = parsed_body
        .get("physical_click_verified")
        .and_then(Value::as_bool);

    let rejected = source_is_voice
        || voice_originated
        || !source_is_physical_click
        || explicit_click_field != Some(true);

    if rejected {
        return Err((
            "403 Forbidden",
            json!({
                "ok": false,
                "error_code": VoiceSessionError::DangerApprovalForbidden.as_code(),
                "physical_click_required": true,
                "physical_click_verified": false,
                "voice_active": voice_session_active,
                "error": DANGER_VOICE_REJECT_COPY,
                "message": DANGER_VOICE_REJECT_COPY
            }),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_ratio_9_bar_waveform_matches_ratified_vectors_within_0_001() {
        let listening_floor = voice_frame(0.0, 0.10, 2200.0, 0.50);
        let expected_listening: [f32; 9] = [
            0.148, 0.148, 0.173, 0.169, 0.193, 0.196, 0.165, 0.162, 0.143,
        ];
        for (idx, (got, want)) in listening_floor.iter().zip(expected_listening).enumerate() {
            assert!(
                (got - want).abs() <= 0.001,
                "bar {idx} listening mismatch: got {got:.4}, expected {want:.3}"
            );
        }

        let speaking_t0 = voice_frame(0.0, 0.80, 550.0, 0.45);
        let speaking_t550 = voice_frame(550.0, 0.80, 550.0, 0.45);
        let expected_speaking: [f32; 9] = [
            0.348, 0.357, 0.556, 0.535, 0.714, 0.733, 0.495, 0.462, 0.311,
        ];
        for (idx, ((got0, got_period), want)) in speaking_t0
            .iter()
            .zip(speaking_t550)
            .zip(expected_speaking)
            .enumerate()
        {
            assert!(
                (got0 - want).abs() <= 0.001,
                "bar {idx} speaking t=0 mismatch: got {got0:.4}, expected {want:.3}"
            );
            assert!(
                (got_period - want).abs() <= 0.001,
                "bar {idx} speaking t=T mismatch: got {got_period:.4}, expected {want:.3}"
            );
            assert!(
                (got0 - got_period).abs() <= 1e-5,
                "bar {idx} must close 1-period loop cleanly"
            );
        }

        assert!(amp_from_rms(0.0) <= 0.001);
        assert!(amp_from_rms(0.2) > 0.5);
        let attacked = smooth_amp(0.1, 0.9, 40.0);
        let released = smooth_amp(0.9, 0.1, 40.0);
        assert!(
            (attacked - 0.1) > (0.9 - released),
            "40ms attack must respond faster than 180ms release"
        );
    }

    #[test]
    fn seven_state_machine_covers_all_states_and_transitions() {
        let all_states = [
            VoiceSessionState::Idle,
            VoiceSessionState::Connecting,
            VoiceSessionState::Listening,
            VoiceSessionState::Thinking,
            VoiceSessionState::Speaking,
            VoiceSessionState::SilenceWarning,
            VoiceSessionState::Paused,
        ];
        assert_eq!(all_states.len(), 7);
        assert!(VoiceSessionState::Idle.can_transition_to(VoiceSessionState::Connecting));
        assert!(VoiceSessionState::Connecting.can_transition_to(VoiceSessionState::Listening));
        assert!(VoiceSessionState::Listening.can_transition_to(VoiceSessionState::Thinking));
        assert!(VoiceSessionState::Thinking.can_transition_to(VoiceSessionState::Speaking));
        assert!(VoiceSessionState::Speaking.can_transition_to(VoiceSessionState::Listening));
        assert!(VoiceSessionState::Listening.can_transition_to(VoiceSessionState::SilenceWarning));
        assert!(VoiceSessionState::SilenceWarning.can_transition_to(VoiceSessionState::Paused));
        assert!(VoiceSessionState::Paused.can_transition_to(VoiceSessionState::Listening));
        assert!(!VoiceSessionState::Idle.can_transition_to(VoiceSessionState::Speaking));
        assert_eq!(format_voice_timer(42, 600), "00:42 / 10:00");
        assert_eq!(format_voice_timer(615, 600), "10:00 / 10:00");
    }

    #[test]
    fn spoken_option_strips_filler_and_rejects_negations_bare_yes_and_ambiguity() {
        let opts = &["Approve", "Deny", "Skip"];
        assert_eq!(
            spoken_option("Approve please", opts).as_deref(),
            Some("approve")
        );
        assert_eq!(
            spoken_option("Yes, approve it, please.", opts).as_deref(),
            Some("approve")
        );
        assert_eq!(
            spoken_option("Okay, skip that please!", opts).as_deref(),
            Some("skip")
        );

        // Hard fail-closed negation & bare-affirmation rejections
        for rejected in [
            "don't approve",
            "Don’t approve please",
            "do not approve",
            "never approve",
            "no approve",
            "not approve",
            "wait don't approve",
            "yes",
            "yeah",
            "ok",
            "okay",
            "please",
            "approve or deny",
            "maybe approve",
            "",
        ] {
            assert_eq!(
                spoken_option(rejected, opts),
                None,
                "expected fail-closed None for '{rejected}'"
            );
        }

        // Duplicate normalized options fail closed
        assert_eq!(
            spoken_option("approve", &["Approve", "Approve please"]),
            None
        );
    }

    #[test]
    fn voice_delegate_enforces_3000ms_thinking_hold_and_1500_sentence_truncation() {
        let mut tracker = VoiceDelegateTracker::new();
        let ev1 = tracker
            .observe_thinking("Running workspace unit tests", 1_000)
            .expect("initial thinking label emitted");
        assert_eq!(ev1.channel, VoiceContextChannel::Thinking);
        assert!(!ev1.spoken);
        assert_eq!(ev1.min_hold_ms, 3_000);

        // Rapid update within 3000ms hold window is suppressed so UI status never flickers
        assert!(
            tracker
                .observe_thinking("Reading repository diff", 2_500)
                .is_none()
        );
        // Update at/after 4000ms succeeds
        let ev2 = tracker
            .observe_thinking("Reading repository diff", 4_000)
            .expect("thinking label updates after 3000ms hold");
        assert_eq!(ev2.text, "Reading repository diff");

        // Interrupted replies are never spoken
        assert!(
            tracker
                .observe_commentary("Partial interrupted text.", true)
                .is_none()
        );

        // >1500 char commentary truncates cleanly at the last complete sentence boundary
        let sentence = "Checked three modified files and confirmed every test passed cleanly. ";
        let long_reply = sentence.repeat(30);
        assert!(long_reply.chars().count() > 1_500);
        let comm = tracker
            .observe_commentary(&long_reply, false)
            .expect("spoken commentary emitted");
        assert_eq!(comm.channel, VoiceContextChannel::Commentary);
        assert!(comm.spoken);
        assert!(comm.text.chars().count() <= 1_500);
        assert!(
            comm.text.ends_with('.'),
            "truncated commentary must end cleanly on a sentence boundary: {}",
            comm.text
        );
    }

    #[test]
    fn server_enforces_600s_ttl_40cr_cap_75s_90s_silence_8s_hold_and_15s_orphan_park() {
        let mut store = Delivery2VoiceStore::default();
        let t0 = 1_700_000_000u64;
        let started = store
            .start_or_control_session("start", "abc12345", "thr-main", false, 500, t0)
            .expect("voice session starts");
        assert_eq!(started["state"], "listening");
        assert_eq!(started["expires_at_unix"], t0 + 600);
        assert_eq!(started["credits_cap"], 40);

        // 75s idle -> SilenceWarning ("Still there? Pausing in 15s")
        let warn = store
            .heartbeat(VoiceHeartbeatInput {
                requested_session_id: Some("voice-abc12345"),
                client_idle_secs: Some(75),
                client_hold_secs: None,
                speech_active: false,
                barge_in: false,
                has_unsettled_hold: false,
                now_unix: t0 + 5,
            })
            .expect("75s heartbeat");
        assert_eq!(warn["state"], "silence_warning");
        assert_eq!(warn["status_label"], SILENCE_WARNING_COPY);

        // 90s idle -> Auto-pause ("Paused · 0 Cr")
        let paused = store
            .heartbeat(VoiceHeartbeatInput {
                requested_session_id: Some("voice-abc12345"),
                client_idle_secs: Some(90),
                client_hold_secs: None,
                speech_active: false,
                barge_in: false,
                has_unsettled_hold: false,
                now_unix: t0 + 10,
            })
            .expect("90s heartbeat");
        assert_eq!(paused["state"], "paused");
        assert_eq!(paused["audio_leg_parked"], true);
        assert_eq!(paused["park_reason"], "silence_timeout");
        assert_eq!(paused["credits_rate_per_min"], 0);

        // Resume preserves original 600s expires_at_unix
        let resumed = store
            .start_or_control_session("resume", "ignored", "thr-main", false, 500, t0 + 20)
            .expect("resume session");
        assert_eq!(resumed["state"], "listening");
        assert_eq!(resumed["expires_at_unix"], t0 + 600);

        // 8s approval/tool hold -> parks audio leg at 0 Cr
        let hold_parked = store
            .heartbeat(VoiceHeartbeatInput {
                requested_session_id: Some("voice-abc12345"),
                client_idle_secs: None,
                client_hold_secs: Some(8),
                speech_active: false,
                barge_in: false,
                has_unsettled_hold: true,
                now_unix: t0 + 25,
            })
            .expect("8s hold park");
        assert_eq!(hold_parked["state"], "paused");
        assert_eq!(hold_parked["park_reason"], "hold_park");
        assert_eq!(hold_parked["credits_rate_per_min"], 0);

        // Resume, then miss >15s heartbeat -> anti-orphan park
        store
            .start_or_control_session("resume", "ignored", "thr-main", false, 500, t0 + 30)
            .unwrap();
        let orphan = store
            .heartbeat(VoiceHeartbeatInput {
                requested_session_id: Some("voice-abc12345"),
                client_idle_secs: None,
                client_hold_secs: None,
                speech_active: false,
                barge_in: false,
                has_unsettled_hold: false,
                now_unix: t0 + 46,
            })
            .expect("16s gap parks orphan voice session");
        assert_eq!(orphan["state"], "paused");
        assert_eq!(orphan["park_reason"], "orphan_heartbeat");

        // Resume and hit 40 Cr session cap -> auto-ends at 40 Cr
        store
            .start_or_control_session("resume", "ignored", "thr-main", false, 500, t0 + 50)
            .unwrap();
        let (charged1, capped1) = store.charge_turn_credits(25, t0 + 52).unwrap();
        assert_eq!((charged1, capped1), (25, false));
        let (charged2, capped2) = store.charge_turn_credits(25, t0 + 54).unwrap();
        assert_eq!(
            (charged2, capped2),
            (15, true),
            "must clamp strictly at 40 Cr session ceiling"
        );
        assert!(store.charge_turn_credits(4, t0 + 55).is_err());

        // Start a second session and verify 600s server TTL hard-stop
        store
            .start_or_control_session("start", "ttl99999", "thr-main", false, 500, t0 + 100)
            .unwrap();
        let expired_err = store
            .charge_turn_credits(4, t0 + 700)
            .expect_err("600s TTL must reject turn at t0+700");
        assert_eq!(expired_err.0, "409 Conflict");
        assert_eq!(expired_err.1["error_code"], "VoiceSessionExpired");
    }

    #[test]
    fn danger_merge_button_gate_rejects_voice_and_requires_physical_click() {
        for phrase in [
            "Approve please",
            "Approve this",
            "Approve the PR",
            "Merge PR 96",
            "Merge it",
            "Can you approve this?",
            "Go ahead and deploy it",
            "Let's ship this",
            "Push the branch",
            "Apply locally",
            "Looks good, approve and merge",
        ] {
            assert!(
                is_voice_danger_approval_attempt(phrase, false),
                "expected imperative danger phrase '{phrase}' to be caught even without unsettled card"
            );
            assert!(is_voice_danger_approval_attempt(phrase, true));
        }

        for safe_phrase in [
            "Don't approve",
            "Do not merge PR 96",
            "Never deploy that",
            "Wait hold the merge",
            "What did I miss?",
            "Why did merge checks fail?",
            "Today's Credits check 2",
            "Deny please",
        ] {
            assert!(
                !is_voice_danger_approval_attempt(safe_phrase, true),
                "expected safe/negated phrase '{safe_phrase}' not to trigger danger gate"
            );
        }

        // Danger options are stripped before reaching `spoken_option`
        let raw_opts = &[
            "Approve & merge",
            "Merge now",
            "Deploy",
            "Ship",
            "Push",
            "Apply locally",
            "Deny",
            "Skip",
        ];
        assert_eq!(filter_safe_voice_options(raw_opts), vec!["Deny", "Skip"]);

        // Client `"danger": false` cannot bypass the physical merge button gate
        let err_danger_false = enforce_physical_merge_button_gate(
            &json!({
                "decision": "approve",
                "source": "voice",
                "voice_originated": true,
                "physical_click_verified": false,
                "danger": false
            }),
            "approve",
            false,
        )
        .expect_err("client danger:false must never bypass physical merge button gate");
        assert_eq!(err_danger_false.0, "403 Forbidden");
        assert_eq!(
            err_danger_false.1["error_code"],
            "VoiceDangerApprovalForbidden"
        );
        assert_eq!(err_danger_false.1["error"], DANGER_VOICE_REJECT_COPY);

        // Missing `source == "physical_click"` or missing `physical_click_verified == true` fails unconditionally
        for bad_payload in [
            json!({ "id": "hitl-1", "decision": "approve" }),
            json!({ "id": "hitl-1", "decision": "approve", "danger": false }),
            json!({ "id": "hitl-1", "decision": "approve", "physical_click_verified": true }),
            json!({ "id": "hitl-1", "decision": "approve", "source": "physical_click" }),
            json!({ "id": "hitl-1", "decision": "approve", "source": "physical_click", "physical_click_verified": false }),
            json!({ "id": "hitl-1", "decision": "approve", "source": "physical_click", "physical_click_verified": true, "voice_originated": true }),
        ] {
            let err = enforce_physical_merge_button_gate(&bad_payload, "approve", true)
                .expect_err("unverified approval payload must fail closed");
            assert_eq!(err.0, "403 Forbidden");
            assert_eq!(err.1["error_code"], "VoiceDangerApprovalForbidden");
        }

        // Verified physical click succeeds even while voice session is open or hold-parked
        assert!(
            enforce_physical_merge_button_gate(
                &json!({
                    "id": "hitl-1",
                    "decision": "approve",
                    "source": "physical_click",
                    "physical_click_verified": true
                }),
                "approve",
                true,
            )
            .is_ok()
        );
    }

    #[test]
    fn hold_parked_session_remains_open_and_ended_session_cannot_be_revived() {
        let mut store = Delivery2VoiceStore::default();
        let t0 = 1_700_000_000u64;
        store
            .start_or_control_session("start", "sec00001", "thr-main", false, 500, t0)
            .unwrap();
        assert!(store.has_open_session(t0 + 1));

        // Park via 8s hold_park -> `has_open_session` MUST remain true!
        store
            .heartbeat(VoiceHeartbeatInput {
                requested_session_id: Some("voice-sec00001"),
                client_idle_secs: None,
                client_hold_secs: Some(8),
                speech_active: false,
                barge_in: false,
                has_unsettled_hold: true,
                now_unix: t0 + 9,
            })
            .unwrap();
        assert!(!store.has_live_unparked_session(t0 + 9));
        assert!(
            store.has_open_session(t0 + 9),
            "8s hold_park session must still count as open voice session"
        );

        // User ends call -> `has_open_session` becomes false AND `resume` / `ready` fail 409 SessionEnded!
        store
            .start_or_control_session("end", "ignored", "thr-main", false, 500, t0 + 12)
            .unwrap();
        assert!(!store.has_open_session(t0 + 12));
        for act in ["resume", "ready"] {
            let err = store
                .start_or_control_session(act, "ignored", "thr-main", false, 500, t0 + 15)
                .expect_err("terminated session must never revive via resume/ready");
            assert_eq!(err.0, "409 Conflict");
            assert_eq!(err.1["error_code"], "VoiceSessionEnded");
            assert_eq!(err.1["voice_error"], "SessionEnded");
        }
    }
}
