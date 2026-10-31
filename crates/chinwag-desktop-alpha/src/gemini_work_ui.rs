use chinwag_gemini_control::{
    ActionKind, Evidence, GeminiError, HumanWorkPort, MAX_TEXT_BYTES, ObservedActivePrompt,
    ObservedSession, StopReason, WorkPhase, WorkSnapshot, new_operation_id,
};
use gpui_kit::component::{
    ActiveTheme, Disableable,
    button::{Button, ButtonVariants},
    input::{Enter, InputEvent, Textarea, TextareaState},
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    App, AppContext, Context, Div, Entity, FontWeight, InteractiveElement, IntoElement, KeyUpEvent,
    ParentElement, Render, StatefulInteractiveElement, Styled, Subscription, Task, Window, div,
};
use std::sync::Arc;

struct Flight {
    id: String,
    kind: ActionKind,
    text: String,
    session: Option<ObservedSession>,
    active: Option<ObservedActivePrompt>,
    draft_identity: Option<Arc<()>>,
}

pub(crate) struct GeminiWorkView {
    port: Arc<dyn HumanWorkPort>,
    snapshot: WorkSnapshot,
    editor: Entity<TextareaState>,
    draft_identity: Arc<()>,
    flight: Option<Flight>,
    start_admitted: bool,
    input_end_requested: bool,
    lookup_pending: Option<String>,
    shortcut_held: bool,
    notice: Option<&'static str>,
    _watch: Task<()>,
    _editor_subscription: Subscription,
}

impl GeminiWorkView {
    pub(crate) fn new(
        port: Arc<dyn HumanWorkPort>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let mut receiver = port.subscribe();
        let snapshot = receiver.borrow_and_update().clone();
        let editor = cx.new(|cx| {
            TextareaState::new(window, cx)
                .rows(4)
                .placeholder("Describe your task. Keep drafting while the response runs…")
        });
        let subscription = cx.subscribe_in(&editor, window, |this, _, event, _, cx| {
            if matches!(event, InputEvent::Change) {
                this.draft_identity = Arc::new(());
                cx.notify();
            }
        });
        let watch = cx.spawn_in(window, async move |this, cx| {
            while receiver.changed().await.is_ok() {
                let snapshot = receiver.borrow_and_update().clone();
                if this
                    .update_in(cx, |this, window, cx| {
                        this.apply_snapshot(snapshot, window, cx);
                    })
                    .is_err()
                {
                    return;
                }
            }
            let _ = this.update_in(cx, |this, _, cx| {
                this.notice =
                    Some("Owner updates ended. Check original receipts; nothing will be resent.");
                this.input_end_requested = true;
                this.flight = None;
                cx.notify();
            });
        });
        let start_admitted = snapshot.start.is_some() || snapshot.phase != WorkPhase::Ready;
        Self {
            port,
            snapshot,
            editor,
            draft_identity: Arc::new(()),
            flight: None,
            start_admitted,
            input_end_requested: false,
            lookup_pending: None,
            shortcut_held: false,
            notice: None,
            _watch: watch,
            _editor_subscription: subscription,
        }
    }

    fn apply_snapshot(
        &mut self,
        snapshot: WorkSnapshot,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if snapshot.revision < self.snapshot.revision {
            return;
        }
        let completion = self.flight.as_ref().and_then(|flight| {
            let receipt = snapshot
                .start
                .iter()
                .chain(snapshot.operations.iter())
                .find(|receipt| {
                    let operation = &receipt.operation;
                    operation.id == flight.id
                        && operation.kind == flight.kind
                        && operation.text == flight.text
                        && flight.session.as_ref().is_none_or(|session| {
                            operation.session_epoch == session.session_epoch()
                                && operation.session_id.as_deref() == Some(session.session_id())
                        })
                        && flight.active.as_ref().is_none_or(|active| {
                            operation.session_epoch == active.session_epoch()
                                && operation.session_id.as_deref() == Some(active.session_id())
                                && operation.prompt_rpc_id == active.rpc_id()
                                && operation.prompt_generation == active.generation()
                        })
                        && (flight.kind == ActionKind::Cancel
                            || operation.prompt_rpc_id == format!("prompt-{}", flight.id))
                });
            if let Some(receipt) = receipt {
                let error = if receipt.persistence_failed {
                    Some(GeminiError::Storage)
                } else if (receipt.evidence.write_uncertain || receipt.evidence.terminal_unknown)
                    && receipt.evidence.terminal.is_none()
                    && !receipt.evidence.rpc_error
                {
                    Some(GeminiError::Uncertain)
                } else {
                    None
                };
                return Some((!receipt.persistence_failed, error));
            }
            snapshot.last_submission.as_ref().and_then(|report| {
                (report.id == flight.id && report.kind == flight.kind && !report.saved)
                    .then_some((false, report.error))
            })
        });
        if let Some((saved, error)) = completion {
            let flight = self.flight.take().expect("completion requires a flight");
            if saved
                && flight.kind != ActionKind::Cancel
                && flight
                    .draft_identity
                    .as_ref()
                    .is_some_and(|identity| Arc::ptr_eq(identity, &self.draft_identity))
                && self.editor.read(cx).value().as_ref() == flight.text
            {
                self.editor
                    .update(cx, |state, cx| state.set_value("", window, cx));
            }
            self.notice = error.map(error_message);
        }
        if let Some(report) = &snapshot.last_submission
            && report.kind == ActionKind::Lookup
            && self.lookup_pending.as_deref() == Some(report.id.as_str())
        {
            self.lookup_pending = None;
            self.notice = Some(match report.error {
                Some(error) => error_message(error),
                None => "Original receipt checked. No input or cancellation was sent again.",
            });
        }
        self.start_admitted |= snapshot.start.is_some() || snapshot.phase != WorkPhase::Ready;
        self.snapshot = snapshot;
        cx.notify();
    }

    fn action(&self) -> Option<ActionKind> {
        if self.input_end_requested
            || self.flight.is_some()
            || self.snapshot.lifecycle.stdin_ended
            || self.snapshot.control_expired
        {
            return None;
        }
        if self.snapshot.phase == WorkPhase::Ready && !self.start_admitted {
            return Some(ActionKind::Start);
        }
        if self.snapshot.can_prompt
            && !self.snapshot.cancel_pending
            && self.snapshot.active_prompt.is_none()
            && self.snapshot.session.is_some()
        {
            return Some(ActionKind::Prompt);
        }
        None
    }

    fn primary_label(&self) -> &'static str {
        if self.flight.is_some() {
            return "Saving your action…";
        }
        if self.snapshot.control_expired {
            return "Human control expired";
        }
        match self.action() {
            Some(ActionKind::Start) => "Start Gemini task",
            Some(ActionKind::Prompt) => "Send next input",
            _ if self.snapshot.cancel_pending => "Waiting for cancellation to retire",
            _ if self.snapshot.active_prompt.is_some() => "Response pending · keep drafting",
            _ => match self.snapshot.phase {
                WorkPhase::Starting => "Starting declared Gemini",
                WorkPhase::OwnerActionRequired => "Owner action required",
                WorkPhase::InputEnded => "Input ended",
                WorkPhase::Exited => "Gemini process exited",
                WorkPhase::Unavailable => "Owned session unavailable",
                _ => "No current input slot",
            },
        }
    }

    fn valid_draft(&self, cx: &App) -> bool {
        let text = self.editor.read(cx).value();
        let trimmed = text.trim_start_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
        !trimmed.trim().is_empty()
            && !trimmed.starts_with(['/', '$'])
            && text.len() <= MAX_TEXT_BYTES
            && !text
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    }

    fn can_submit(&self, cx: &App) -> bool {
        self.action().is_some() && self.valid_draft(cx)
    }

    fn submit(&mut self, cx: &mut Context<Self>) {
        if !self.can_submit(cx) {
            return;
        }
        let Some(kind) = self.action() else { return };
        let text = self.editor.read(cx).value().to_string();
        let id = match new_operation_id() {
            Ok(id) => id,
            Err(_) => {
                self.notice = Some("Could not create an operation ID. Your draft stays here.");
                cx.notify();
                return;
            }
        };
        let session = self.snapshot.session.clone();
        let result = match kind {
            ActionKind::Start => self.port.start(&id, &text),
            ActionKind::Prompt => {
                let Some(session) = &session else { return };
                self.port.prompt(session, &id, &text)
            }
            _ => return,
        };
        match result {
            Ok(()) => {
                self.start_admitted |= kind == ActionKind::Start;
                self.flight = Some(Flight {
                    id: id.clone(),
                    kind,
                    text,
                    session: (kind == ActionKind::Prompt).then_some(session).flatten(),
                    active: None,
                    draft_identity: None,
                });
                // Flush older Change notifications before capturing the edit
                // identity; any later edit, including same-text restoration,
                // must preserve the new draft when this saved input arrives.
                let view = cx.weak_entity();
                cx.defer(move |cx| {
                    let _ = view.update(cx, |this, _| {
                        if let Some(flight) = &mut this.flight
                            && flight.id == id
                        {
                            flight.draft_identity = Some(this.draft_identity.clone());
                        }
                    });
                });
                self.notice = None;
                self.lookup_pending = None;
            }
            Err(error) => self.notice = Some(error_message(error)),
        }
        cx.notify();
    }

    fn can_cancel(&self) -> bool {
        !self.input_end_requested
            && !self.snapshot.lifecycle.stdin_ended
            && !self.snapshot.control_expired
            && self.flight.is_none()
            && !self.snapshot.cancel_pending
            && self.snapshot.active_prompt.is_some()
    }

    fn cancel(&mut self, captured: &ObservedActivePrompt, cx: &mut Context<Self>) {
        if !self.can_cancel() {
            return;
        }
        if !self
            .snapshot
            .active_prompt
            .as_ref()
            .is_some_and(|current| same_active(current, captured))
        {
            self.notice =
                Some("That response changed. Review the current response before cancelling.");
            cx.notify();
            return;
        }
        let id = match new_operation_id() {
            Ok(id) => id,
            Err(error) => {
                self.notice = Some(error_message(error));
                cx.notify();
                return;
            }
        };
        match self.port.cancel(captured, &id) {
            Ok(()) => {
                self.flight = Some(Flight {
                    id,
                    kind: ActionKind::Cancel,
                    text: String::new(),
                    session: None,
                    active: Some(captured.clone()),
                    draft_identity: None,
                });
                self.notice = Some(
                    "Cancel requested for this response. Wait for its original terminal response before sending new input.",
                );
            }
            Err(error) => self.notice = Some(error_message(error)),
        }
        cx.notify();
    }

    fn lookup(&mut self, id: &str, cx: &mut Context<Self>) {
        if self.flight.is_some() || self.lookup_pending.is_some() {
            return;
        }
        self.notice = Some(match self.port.lookup(id) {
            Ok(()) => {
                self.lookup_pending = Some(id.into());
                "Checking the original receipt; nothing is being resent."
            }
            Err(error) => error_message(error),
        });
        cx.notify();
    }

    fn end_input(&mut self, cx: &mut Context<Self>) {
        if self.input_end_requested || self.snapshot.lifecycle.stdin_ended {
            return;
        }
        match self.port.end_input() {
            Ok(()) => {
                self.input_end_requested = true;
                self.notice =
                    Some("Ending this input stream. Work and native cleanup may continue.");
            }
            Err(error) => self.notice = Some(error_message(error)),
        }
        cx.notify();
    }
}

fn same_active(left: &ObservedActivePrompt, right: &ObservedActivePrompt) -> bool {
    left.session_epoch() == right.session_epoch()
        && left.session_id() == right.session_id()
        && left.generation() == right.generation()
        && left.rpc_id() == right.rpc_id()
        && left.operation_id() == right.operation_id()
}

fn phase_label(snapshot: &WorkSnapshot) -> &'static str {
    if snapshot.lifecycle.child_exited || snapshot.phase == WorkPhase::Exited {
        return "Owned Gemini process exited";
    }
    if snapshot.lifecycle.stdin_ended || snapshot.phase == WorkPhase::InputEnded {
        return "Input ended; work may continue";
    }
    if snapshot.control_expired {
        return "Human control expired; an existing response may still be pending";
    }
    if snapshot.cancel_pending {
        return "Cancellation pending; new input is not queued";
    }
    match snapshot.phase {
        WorkPhase::Ready => "Ready for your task",
        WorkPhase::Starting => "Starting the declared native runtime",
        WorkPhase::Prompting => "Response pending",
        WorkPhase::Idle => "Original response ended; send new input explicitly",
        WorkPhase::Cancelling => "Cancellation pending",
        WorkPhase::OwnerActionRequired => "Owner action required; no approval is granted here",
        WorkPhase::InputEnded => "Input ended; work may continue",
        WorkPhase::Exited => "Owned Gemini process exited",
        WorkPhase::Unavailable => "Owned session unavailable",
    }
}

fn stop_label(reason: StopReason) -> &'static str {
    match reason {
        StopReason::EndTurn => "Original response ended (end_turn).",
        StopReason::MaxTokens => "Original response ended at its token limit (max_tokens).",
        StopReason::MaxTurnRequests => {
            "Original response ended at its request limit (max_turn_requests)."
        }
        StopReason::Refusal => "Original response ended with a refusal.",
        StopReason::Cancelled => "Original response reported cancelled.",
    }
}

fn evidence_lines(kind: ActionKind, evidence: &Evidence, persistence_failed: bool) -> Vec<String> {
    let mut lines = Vec::new();
    if evidence.not_dispatched {
        lines.push(match kind {
        ActionKind::Start => "Initial prompt not dispatched; configured runtime startup may already have run.",
        ActionKind::Cancel => "Cancel notification not dispatched; its original response may already have ended.",
        _ => "Prompt not dispatched.",
    }.into());
    }
    if evidence.frame_written {
        lines.push(
            if kind == ActionKind::Cancel {
                "Cancel notification written. This is not a cancellation acknowledgement."
            } else {
                "Prompt frame written. Its terminal response may still be pending."
            }
            .into(),
        );
    }
    if let Some(reason) = evidence.terminal {
        lines.push(stop_label(reason).into());
    }
    if evidence.rpc_error {
        lines.push("Original RPC returned an error; this does not prove that nothing ran.".into());
    }
    if evidence.permission_cancel_responses_written > 0 {
        lines.push(format!(
            "Cancelled permission replies written: {}. No permission was approved.",
            evidence.permission_cancel_responses_written
        ));
    }
    if evidence.permission_cancel_responses_uncertain {
        lines.push("A cancelled permission reply has an uncertain write outcome. No permission was approved.".into());
    }
    if evidence.write_uncertain {
        lines.push("Original outcome uncertain. Check this receipt; do not repeat the action automatically.".into());
    }
    if evidence.terminal_unknown && evidence.terminal.is_none() && !evidence.rpc_error {
        lines.push("The original terminal response is unavailable after owned transport loss. Work may continue; check this saved receipt without sending again.".into());
    }
    if persistence_failed {
        lines.push("Receipt persistence failed. Only earlier durable evidence is shown.".into());
    }
    if lines.is_empty() {
        lines.push("Human action saved; dispatch evidence has not been observed.".into());
    }
    lines
}

fn error_message(error: GeminiError) -> &'static str {
    match error {
        GeminiError::InvalidInput => {
            "Use nonempty text within the limit. Leading / and $ native commands are not accepted."
        }
        GeminiError::PermissionDenied => {
            "The original human-control scope or action expired. Existing work may continue."
        }
        GeminiError::NoSession => {
            "No current owned session is available. Your draft is not queued."
        }
        GeminiError::StaleTarget => {
            "The captured session or response changed. Review the current target."
        }
        GeminiError::Busy => {
            "The original response or submission is still pending. Your draft stays here; it is not queued."
        }
        GeminiError::Capacity => {
            "Retained operation capacity is full. Original receipts remain available."
        }
        GeminiError::Storage => {
            "Private receipt persistence is unavailable. Original records are retained."
        }
        GeminiError::Conflict => {
            "This operation ID belongs to different content. It will not be sent again."
        }
        GeminiError::Unavailable => {
            "The declared Gemini runtime is unavailable. Your draft stays here."
        }
        GeminiError::Uncertain => {
            "The original outcome is unknown. Check its receipt instead of repeating the action."
        }
        GeminiError::OwnerInterventionRequired => {
            "The runtime requires owner action. Chinwag does not approve, authenticate or repair it automatically."
        }
    }
}

fn text_block(text: impl Into<String>, cx: &App) -> Div {
    div()
        .text_sm()
        .text_color(cx.theme().foreground)
        .child(text.into())
}

impl Render for GeminiWorkView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let history = self
            .snapshot
            .start
            .iter()
            .chain(self.snapshot.operations.iter())
            .enumerate()
            .map(|(index, receipt)| {
                let id = receipt.operation.id.clone();
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .py_3()
                    .child(div().font_weight(FontWeight::SEMIBOLD).child(
                        match receipt.operation.kind {
                            ActionKind::Start => "Your task",
                            ActionKind::Cancel => "Your cancellation",
                            _ => "Your next input",
                        },
                    ))
                    .when(!receipt.operation.text.is_empty(), |this| {
                        this.child(text_block(receipt.operation.text.clone(), cx))
                    })
                    .children(
                        evidence_lines(
                            receipt.operation.kind,
                            &receipt.evidence,
                            receipt.persistence_failed,
                        )
                        .into_iter()
                        .map(|line| {
                            div()
                                .text_xs()
                                .text_color(cx.theme().muted_foreground)
                                .child(line)
                        }),
                    )
                    .when(receipt.recovered_after_restart, |this| {
                        this.child(
                            div()
                                .text_xs()
                                .text_color(cx.theme().muted_foreground)
                                .child("Recovered original receipt. No action was replayed."),
                        )
                    })
                    .child(
                        Button::new(("lookup-gemini-operation", index))
                            .label("Check original receipt")
                            .disabled(self.flight.is_some() || self.lookup_pending.is_some())
                            .on_click(cx.listener(move |this, _, _, cx| this.lookup(&id, cx))),
                    )
            })
            .collect::<Vec<_>>();
        let can_submit = self.can_submit(cx);
        let can_cancel = self.can_cancel();
        let captured = self.snapshot.active_prompt.clone();
        div().flex().flex_col().size_full().bg(cx.theme().background)
            .text_color(cx.theme().foreground).font_family(".AppleSystemUIFont")
            .child(div().flex().flex_col().gap_2().px_6().py_5().border_b_1().border_color(cx.theme().border)
                .child(div().flex().items_center().gap_3()
                    .child(div().flex_1().text_xl().font_weight(FontWeight::SEMIBOLD).child("Gemini work"))
                    .child(Button::new("end-gemini-input").label("End input")
                        .disabled(self.input_end_requested || self.snapshot.lifecycle.stdin_ended || self.snapshot.phase == WorkPhase::Exited)
                        .on_click(cx.listener(|this, _, _, cx| this.end_input(cx)))))
                .child(div().text_sm().child(format!("Work folder: {}", self.snapshot.folder_label)))
                .child(div().text_sm().font_weight(FontWeight::MEDIUM).child(phase_label(&self.snapshot)))
                .when_some(self.snapshot.session.as_ref(), |this, session| this.child(div().text_xs().text_color(cx.theme().muted_foreground)
                    .child(format!("Owned session: {} · generation: {}", session.session_id(), session.generation()))))
                .child(div().text_xs().text_color(cx.theme().muted_foreground)
                    .child("Start launches the declared pinned binary and requires Gemini CLI 0.66.0 compatibility before task input. Its normal settings, context, hooks, authentication refresh, tools, MCP and helper/model startup may run. Extensions are disabled; default approval mode is requested. This is not a restricted or sandboxed runtime."))
                .child(div().text_xs().text_color(cx.theme().muted_foreground)
                    .child("Chinwag grants no tool approval and makes no account or model identity claim. End input closes this stream; work may continue. Closing this window retains its owner.")))
            .child(div().id("gemini-work-timeline").flex_1().min_h_0().overflow_y_scroll().px_6()
                .when(history.is_empty(), |this| this.child(div().flex().flex_col().gap_2().py_8()
                    .child(div().text_lg().font_weight(FontWeight::MEDIUM).child("What would you like Gemini to do?"))
                    .child(div().text_sm().text_color(cx.theme().muted_foreground).child("Start explicitly. While a response runs, keep drafting or cancel that response. Send your next input only after it ends."))))
                .children(history)
                .when_some(self.snapshot.agent_text.clone(), |this, text| this.child(div().flex().flex_col().gap_2().py_3()
                    .child(div().font_weight(FontWeight::SEMIBOLD).child("Session output · not attributed to one input"))
                    .child(text_block(text, cx)))))
            .child(div().flex().flex_col().gap_3().px_6().py_5().border_t_1().border_color(cx.theme().border)
                .child(div().capture_action(cx.listener(|this, action: &Enter, _, cx| {
                    if action.secondary && !action.shift {
                        cx.stop_propagation();
                        if !this.shortcut_held { this.shortcut_held = true; this.submit(cx); }
                    }
                })).on_key_up(cx.listener(|this, event: &KeyUpEvent, _, _| {
                    if event.keystroke.key == "enter" { this.shortcut_held = false; }
                })).child(Textarea::new(&self.editor).aria_label("Gemini task or next input draft")))
                .when(self.snapshot.pending_permissions > 0, |this| this.child(div().text_xs().text_color(cx.theme().muted_foreground)
                    .child("A native permission request needs owner action. Cancel remains available for the exact active response; no permission is approved here.")))
                .child(div().text_xs().text_color(cx.theme().muted_foreground)
                    .child("Your editor stays available. Nothing is queued or sent automatically. Leading / and $ native commands are not accepted."))
                .child(div().flex().items_center().gap_3()
                    .child(Button::new("cancel-gemini-response").label("Cancel current response").disabled(!can_cancel)
                        .on_click(cx.listener(move |this, _, _, cx| { if let Some(active) = &captured { this.cancel(active, cx); } })))
                    .child(div().flex_1())
                    .child(Button::new("submit-gemini-work").primary().label(self.primary_label()).disabled(!can_submit)
                        .on_click(cx.listener(|this, _, _, cx| this.submit(cx)))))
                .when_some(self.notice, |this, notice| this.child(div().text_xs().text_color(cx.theme().muted_foreground).child(notice))))
    }
}

#[cfg(test)]
#[path = "gemini_work_interaction_tests.rs"]
mod tests;
