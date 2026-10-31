use crate::{
    api::{Target, valid_text},
    journal::Stored,
    *,
};
use chinwag_claude_control as claude;
use chinwag_codex_steer as codex;
use chinwag_gemini_control as gemini;
use std::collections::BTreeMap;
pub(crate) fn snapshots(members: &[Member]) -> Vec<MemberSnapshot> {
    members
        .iter()
        .map(|m| MemberSnapshot {
            id: m.id.clone(),
            label: m.label.clone(),
            native: match &m.port {
                HeldWorkPort::Codex(p) => NativeSnapshot::Codex(p.subscribe().borrow().clone()),
                HeldWorkPort::Claude(p) => NativeSnapshot::Claude(p.subscribe().borrow().clone()),
                HeldWorkPort::Gemini(p) => NativeSnapshot::Gemini(p.subscribe().borrow().clone()),
            },
        })
        .collect()
}
pub(crate) fn target(
    native: &NativeSnapshot,
    text: &str,
    timing: ClaudeTiming,
) -> std::result::Result<(Target, ActionLabel), BlockReason> {
    if !valid_text(text) {
        return Err(BlockReason::InvalidText);
    }
    match native {
        NativeSnapshot::Codex(s) => {
            if s.phase == codex::WorkPhase::Ready {
                return Err(BlockReason::NotStarted);
            }
            if matches!(s.phase, codex::WorkPhase::Closed) {
                return Err(BlockReason::InputEnded);
            }
            if matches!(s.phase, codex::WorkPhase::OwnerActionRequired) {
                return Err(BlockReason::OwnerActionRequired);
            }
            if matches!(s.phase, codex::WorkPhase::Unavailable) {
                return Err(BlockReason::Unavailable);
            }
            s.target
                .clone()
                .map(|t| (Target::Codex(t), ActionLabel::CodexSteer))
                .ok_or(BlockReason::NoActiveTurn)
        }
        NativeSnapshot::Claude(s) => {
            if s.phase == claude::WorkPhase::Ready {
                return Err(BlockReason::NotStarted);
            }
            if s.lifecycle.stdin_ended || s.lifecycle.child_exited || s.lifecycle.stdout_eof {
                return Err(BlockReason::InputEnded);
            }
            if s.phase == claude::WorkPhase::OwnerActionRequired {
                return Err(BlockReason::OwnerActionRequired);
            }
            let t = s.session.clone().ok_or(BlockReason::NoSession)?;
            let a = match timing {
                ClaudeTiming::Now => ActionLabel::ClaudeNow,
                ClaudeTiming::AfterTools => ActionLabel::ClaudeAfterTools,
                ClaudeTiming::AfterTurn => ActionLabel::ClaudeAfterTurn,
            };
            Ok((Target::Claude(t, timing), a))
        }
        NativeSnapshot::Gemini(s) => {
            if s.phase == gemini::WorkPhase::Ready {
                return Err(BlockReason::NotStarted);
            }
            if s.control_expired {
                return Err(BlockReason::ControlExpired);
            }
            if s.lifecycle.stdin_ended || s.lifecycle.child_exited || s.lifecycle.stdout_eof {
                return Err(BlockReason::InputEnded);
            }
            if s.cancel_pending {
                return Err(BlockReason::CancellationPending);
            }
            if s.active_prompt.is_some() {
                return Err(BlockReason::ResponsePending);
            }
            if !s.can_prompt || s.pending_permissions > 0 {
                return Err(BlockReason::OwnerActionRequired);
            }
            let t = text.trim_start_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
            if t.starts_with(['/', '$']) {
                return Err(BlockReason::InvalidText);
            }
            s.session
                .clone()
                .map(|t| (Target::Gemini(t), ActionLabel::GeminiPrompt))
                .ok_or(BlockReason::NoSession)
        }
    }
}
fn matching(member: &SavedMember, native: &NativeSnapshot) -> Option<NativeReceipt> {
    match (member.audit.as_ref()?, native) {
        (NativeAudit::Codex { operation, .. }, NativeSnapshot::Codex(s)) => s
            .steers
            .iter()
            .find(|r| r.operation == *operation)
            .cloned()
            .map(NativeReceipt::Codex),
        (NativeAudit::Claude { operation, .. }, NativeSnapshot::Claude(s)) => s
            .inputs
            .iter()
            .find(|r| r.operation == *operation)
            .cloned()
            .map(NativeReceipt::Claude),
        (NativeAudit::Gemini { operation, .. }, NativeSnapshot::Gemini(s)) => s
            .operations
            .iter()
            .find(|r| r.operation == *operation)
            .cloned()
            .map(NativeReceipt::Gemini),
        _ => None,
    }
}
fn clear_safe(r: &NativeReceipt) -> bool {
    match r {
        NativeReceipt::Codex(r) => {
            r.evidence.frame_written
                && !r.evidence.write_uncertain
                && !r.evidence.not_dispatched
                && !r.evidence.peer_error_observed
                && !r.persistence_failed
        }
        NativeReceipt::Claude(r) => {
            r.evidence.frame_written
                && !r.evidence.write_uncertain
                && !r.evidence.not_dispatched
                && !r.evidence.peer_error_observed
                && !r.persistence_failed
        }
        NativeReceipt::Gemini(r) => {
            r.evidence.frame_written
                && !r.evidence.write_uncertain
                && !r.evidence.not_dispatched
                && !r.evidence.terminal_unknown
                && !r.evidence.rpc_error
                && !r.evidence.permission_cancel_responses_uncertain
                && !r.persistence_failed
        }
    }
}
fn native_summary(r: &NativeReceipt) -> String {
    match r {
        NativeReceipt::Codex(r) => {
            let e = r.evidence;
            let mut facts = vec!["Original native intent saved"];
            if e.frame_written {
                facts.push("frame written")
            }
            if e.core_accepted {
                facts.push("Core accepted")
            }
            if e.harness_recorded {
                facts.push("harness recorded")
            }
            if e.write_uncertain {
                facts.push("write outcome uncertain")
            }
            if e.not_dispatched {
                facts.push("not dispatched")
            }
            if e.peer_error_observed {
                facts.push("native error observed")
            }
            if r.persistence_failed {
                facts.push("native persistence failure")
            }
            facts.join(" · ")
        }
        NativeReceipt::Claude(r) => {
            let e = r.evidence;
            let mut facts = vec!["Original native intent saved"];
            if e.frame_written {
                facts.push("frame written")
            }
            if e.user_replayed {
                facts.push("input replayed")
            }
            if e.reply_correlated {
                facts.push("reply attributed")
            }
            if e.result_correlated {
                facts.push("result attributed")
            }
            if e.write_uncertain {
                facts.push("write outcome uncertain")
            }
            if e.not_dispatched {
                facts.push("not dispatched")
            }
            if e.peer_error_observed {
                facts.push("native error observed")
            }
            if r.persistence_failed {
                facts.push("native persistence failure")
            }
            facts.join(" · ")
        }
        NativeReceipt::Gemini(r) => {
            let e = &r.evidence;
            let mut facts = vec!["Original native intent saved"];
            if e.frame_written {
                facts.push("frame written")
            }
            if e.terminal.is_some() {
                facts.push("original prompt terminal observed")
            }
            if e.terminal_unknown {
                facts.push("terminal historically unavailable")
            }
            if e.write_uncertain {
                facts.push("write outcome uncertain")
            }
            if e.not_dispatched {
                facts.push("not dispatched")
            }
            if e.rpc_error {
                facts.push("native RPC error")
            }
            if r.persistence_failed {
                facts.push("native persistence failure")
            }
            facts.join(" · ")
        }
    }
}
pub(crate) fn receipt(
    stored: &Stored,
    natives: &[MemberSnapshot],
    failed: bool,
) -> DirectionReceipt {
    let map: BTreeMap<_, _> = natives.iter().map(|m| (&m.id, &m.native)).collect();
    let members = stored
        .intent
        .members
        .iter()
        .map(|m| {
            let claimed = stored.claims.contains(&m.id);
            let admission = stored.admissions.get(&m.id).copied();
            let native = map.get(&m.id).and_then(|s| matching(m, s));
            let child_saved = native.is_some();
            let safe = admission == Some(LocalAdmission::Queued)
                && native.as_ref().is_some_and(clear_safe)
                && !failed
                && !stored.recovered;
            let summary = if let Some(reason) = m.excluded {
                format!("Not included in this send · {reason}")
            } else if let Some(r) = &native {
                let mut v = native_summary(r);
                if admission == Some(LocalAdmission::Rejected) {
                    v.push_str(
                        " · local rejection conflicts with original record; owner action required",
                    )
                }
                if failed {
                    v.push_str(" · parent storage failed")
                }
                v
            } else if admission == Some(LocalAdmission::Rejected) {
                "Native queue admission rejected; no enqueue".into()
            } else if admission == Some(LocalAdmission::Queued) {
                "Queued locally; original native intent not observed here".into()
            } else if claimed {
                "Dispatch claimed; native outcome unknown".into()
            } else if stored.retired || stored.recovered {
                "Never invoked by this parent".into()
            } else {
                "Waiting for a local dispatch claim".into()
            };
            MemberOutcome {
                id: m.id.clone(),
                label: m.label.clone(),
                claimed,
                admission,
                child_saved,
                clear_safe: safe,
                native,
                summary,
            }
        })
        .collect();
    DirectionReceipt {
        intent: stored.intent.clone(),
        members,
        stage_retired: stored.retired || failed,
        persistence_failed: failed,
        recovered: stored.recovered,
    }
}
