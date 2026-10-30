use chinwag_claude_control::{
    ActionKind, ClaudeError, HumanWorkPort, InputEvidence, InputTiming, MAX_TEXT_BYTES, WorkPhase,
    WorkSnapshot, new_operation_id,
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
    timing: InputTiming,
    session_binding: Option<(String, String)>,
    draft_identity: Option<Arc<()>>,
}

pub(crate) struct ClaudeWorkView {
    port: Arc<dyn HumanWorkPort>,
    snapshot: WorkSnapshot,
    editor: Entity<TextareaState>,
    draft_identity: Arc<()>,
    timing: InputTiming,
    flight: Option<Flight>,
    start_admitted: bool,
    input_end_requested: bool,
    lookup_pending: Option<String>,
    shortcut_held: bool,
    notice: Option<&'static str>,
    _watch: Task<()>,
    _editor_subscription: Subscription,
}

impl ClaudeWorkView {
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
                .placeholder("Describe your task, or send new direction while Claude works…")
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
                this.notice = Some(
                    "Session updates stopped. Check the original receipt; do not send it again.",
                );
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
            timing: InputTiming::Now,
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
                .chain(snapshot.inputs.iter())
                .find(|receipt| {
                    receipt.operation.id == flight.id
                        && receipt.operation.kind == flight.kind
                        && receipt.operation.text == flight.text
                        && receipt.operation.timing == flight.timing
                        && flight.session_binding.as_ref().is_none_or(|(epoch, id)| {
                            receipt.operation.session_epoch == *epoch
                                && receipt.operation.session_id == *id
                        })
                });
            if let Some(receipt) = receipt {
                let error = if receipt.persistence_failed {
                    Some(ClaudeError::Storage)
                } else if receipt.evidence.write_uncertain
                    && !receipt.evidence.user_replayed
                    && !receipt.evidence.reply_correlated
                    && !receipt.evidence.result_correlated
                {
                    Some(ClaudeError::Uncertain)
                } else {
                    None
                };
                // A saved intent releases the short submission flight. Work
                // and later protocol evidence continue on the retained owner.
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
                None => "Original receipt checked. Nothing was sent again.",
            });
        }
        self.start_admitted |= snapshot.start.is_some() || snapshot.phase != WorkPhase::Ready;
        self.snapshot = snapshot;
        cx.notify();
    }

    fn action(&self) -> Option<ActionKind> {
        if self.input_end_requested || self.flight.is_some() || self.snapshot.lifecycle.stdin_ended
        {
            return None;
        }
        if self.snapshot.phase == WorkPhase::Ready && !self.start_admitted {
            return Some(ActionKind::Start);
        }
        if self.snapshot.session.is_some()
            && matches!(
                self.snapshot.phase,
                WorkPhase::Working | WorkPhase::Idle | WorkPhase::OutcomeUnknown
            )
        {
            return Some(ActionKind::Direction);
        }
        None
    }

    fn primary_label(&self) -> &'static str {
        if self.flight.is_some() {
            return "Saving your input…";
        }
        match self.action() {
            Some(ActionKind::Start) => "Start Claude task",
            Some(ActionKind::Direction) => match self.timing {
                InputTiming::Now => "Send direction now — may interrupt",
                InputTiming::AfterTools => "Send after running tools",
                InputTiming::AfterTurn => "Send after this turn",
            },
            _ => match self.snapshot.phase {
                WorkPhase::Starting => "Starting declared Claude",
                WorkPhase::OwnerActionRequired => "Owner action required",
                WorkPhase::InputEnded => "Input ended",
                WorkPhase::Exited => "Claude process exited",
                WorkPhase::Unavailable => "Session unavailable",
                _ => "No current session",
            },
        }
    }

    fn can_submit(&self, cx: &App) -> bool {
        let text = self.editor.read(cx).value();
        self.action().is_some() && !text.trim().is_empty() && text.len() <= MAX_TEXT_BYTES
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
                self.notice = Some("Could not create an input ID. Your draft is still here.");
                cx.notify();
                return;
            }
        };
        let timing = if kind == ActionKind::Start {
            InputTiming::Now
        } else {
            self.timing
        };
        let session = self.snapshot.session.clone();
        let result = match kind {
            ActionKind::Start => self.port.start(&id, &text),
            ActionKind::Direction => {
                let Some(session) = session.as_ref() else {
                    return;
                };
                self.port.direction(session, &id, &text, timing)
            }
            _ => return,
        };
        match result {
            Ok(()) => {
                self.start_admitted |= kind == ActionKind::Start;
                let baseline_id = id.clone();
                self.flight = Some(Flight {
                    id,
                    kind,
                    text,
                    timing,
                    session_binding: if kind == ActionKind::Direction {
                        session.map(|session| {
                            (session.session_epoch().into(), session.session_id().into())
                        })
                    } else {
                        None
                    },
                    draft_identity: None,
                });
                // Pre-click Change effects precede this FIFO baseline; later
                // edits, including restoring the same text, change identity.
                let view = cx.weak_entity();
                cx.defer(move |cx| {
                    let _ = view.update(cx, |this, _| {
                        let identity = this.draft_identity.clone();
                        if let Some(flight) = &mut this.flight
                            && flight.id == baseline_id
                        {
                            flight.draft_identity = Some(identity);
                        }
                    });
                });
                self.lookup_pending = None;
                self.notice = None;
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
                "Checking the original receipt. This does not send it again."
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
                self.notice = Some("Ending input. This does not guarantee that work has stopped.");
            }
            Err(error) => self.notice = Some(error_message(error)),
        }
        cx.notify();
    }
}

fn phase_label(phase: WorkPhase) -> &'static str {
    match phase {
        WorkPhase::Ready => "Ready for your task",
        WorkPhase::Starting => "Starting the declared Claude process",
        WorkPhase::Working => "Response activity observed",
        WorkPhase::Idle => "Last turn ended; session input is available",
        WorkPhase::OutcomeUnknown => "An input outcome is unknown",
        WorkPhase::OwnerActionRequired => "Owner action required",
        WorkPhase::InputEnded => "Input ended; work may continue",
        WorkPhase::Exited => "Owned Claude process exited",
        WorkPhase::Unavailable => "Owned session unavailable",
    }
}

fn timing_label(timing: InputTiming) -> &'static str {
    match timing {
        InputTiming::Now => "Now · may interrupt",
        InputTiming::AfterTools => "After running tools",
        InputTiming::AfterTurn => "After this turn",
    }
}

fn evidence_lines(evidence: &InputEvidence, persistence_failed: bool) -> Vec<&'static str> {
    let mut lines = Vec::new();
    if evidence.not_dispatched {
        lines.push("User input frame not dispatched; process startup may already have run.");
    }
    if evidence.frame_written {
        lines.push("Input frame written to the owned Claude stream.");
    }
    if evidence.user_replayed {
        lines.push("Input echoed by Claude's harness. Model awareness is unverified.");
    }
    if evidence.reply_correlated {
        lines.push("A reply was attributed to this input UUID. Application is unverified.");
    }
    if evidence.result_correlated {
        lines.push(
            "A result was attributed to this input UUID. This does not prove an artifact changed.",
        );
    }
    if evidence.peer_error_observed {
        lines.push("A peer error was observed; it does not prove that nothing ran.");
    }
    if evidence.write_uncertain {
        lines.push("Outcome uncertain. Check this original receipt instead of sending it again.");
    }
    if persistence_failed {
        lines.push("Receipt persistence failed. Only earlier durable evidence is shown.");
    }
    if lines.is_empty() {
        lines.push("Input saved. A protocol response has not been observed.");
    }
    lines
}

fn error_message(error: ClaudeError) -> &'static str {
    match error {
        ClaudeError::InvalidInput => {
            "Use a nonempty message within the text limit. Your draft stays here."
        }
        ClaudeError::PermissionDenied => {
            "No current human-control permission is available for this action."
        }
        ClaudeError::NoSession => {
            "No current Claude session is available. Your draft is not queued."
        }
        ClaudeError::StaleSession => {
            "The owned session changed. Review the current session before sending."
        }
        ClaudeError::Busy => {
            "Another input is being submitted. Your draft stays here; it is not queued automatically."
        }
        ClaudeError::Capacity => {
            "Retained input capacity is full. Existing receipts remain available."
        }
        ClaudeError::Storage => {
            "Private input persistence is unavailable. Original records are retained."
        }
        ClaudeError::Conflict => {
            "This input ID belongs to different content. It will not be resent."
        }
        ClaudeError::Unavailable => {
            "The owned Claude session is unavailable. Your draft stays here."
        }
        ClaudeError::Uncertain => {
            "The original outcome is unknown. Check its receipt instead of sending it again."
        }
        ClaudeError::OwnerInterventionRequired => {
            "Claude requires owner intervention. Chinwag does not approve or sign in automatically."
        }
    }
}

fn text_block(text: impl Into<String>, cx: &App) -> Div {
    div()
        .text_sm()
        .text_color(cx.theme().foreground)
        .child(text.into())
}

impl Render for ClaudeWorkView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let history = self
            .snapshot
            .start
            .iter()
            .chain(self.snapshot.inputs.iter())
            .enumerate()
            .map(|(index, receipt)| {
                let id = receipt.operation.id.clone();
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .py_3()
                    .child(div().font_weight(FontWeight::SEMIBOLD).child(
                        if receipt.operation.kind == ActionKind::Start {
                            "Your task"
                        } else {
                            "Your direction"
                        },
                    ))
                    .when(receipt.operation.kind == ActionKind::Direction, |this| {
                        this.child(
                            div()
                                .text_xs()
                                .text_color(cx.theme().muted_foreground)
                                .child(timing_label(receipt.operation.timing)),
                        )
                    })
                    .child(text_block(receipt.operation.text.clone(), cx))
                    .children(
                        evidence_lines(&receipt.evidence, receipt.persistence_failed)
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
                                .child("Recovered original receipt. No request was replayed."),
                        )
                    })
                    .child(
                        Button::new(("lookup-claude-input", index))
                            .label("Check original receipt")
                            .disabled(self.flight.is_some() || self.lookup_pending.is_some())
                            .on_click(cx.listener(move |this, _, _, cx| this.lookup(&id, cx))),
                    )
            })
            .collect::<Vec<_>>();
        let can_submit = self.can_submit(cx);
        div().flex().flex_col().size_full().bg(cx.theme().background)
            .text_color(cx.theme().foreground).font_family(".AppleSystemUIFont")
            .child(div().flex().flex_col().gap_2().px_6().py_5().border_b_1().border_color(cx.theme().border)
                .child(div().flex().items_center().gap_3()
                    .child(div().flex_1().text_xl().font_weight(FontWeight::SEMIBOLD).child("Claude work"))
                    .child(Button::new("end-claude-input").label("End input")
                        .disabled(self.input_end_requested || self.snapshot.lifecycle.stdin_ended || self.snapshot.phase == WorkPhase::Exited)
                        .on_click(cx.listener(|this, _, _, cx| this.end_input(cx)))))
                .child(div().text_sm().child(format!("Work folder: {}", self.snapshot.folder_label)))
                .child(div().text_sm().font_weight(FontWeight::MEDIUM).child(phase_label(self.snapshot.phase)))
                .when_some(self.snapshot.session.as_ref(), |this, session| this.child(div().text_xs().text_color(cx.theme().muted_foreground)
                    .child(format!("Owned session: {} · generation: {}", session.session_id(), session.generation()))))
                .child(div().text_xs().text_color(cx.theme().muted_foreground)
                    .child("Start launches the declared pinned binary and requires Claude 2.1.314 before sending task input. This is prose-only work: no built-in or MCP tools, no automatic approvals. User and project customizations are excluded; enforced managed hooks and provider policy may still apply."))
                .child(div().text_xs().text_color(cx.theme().muted_foreground)
                    .child("End input closes this stream; it does not guarantee that all work stops. Closing this window retains its owner. No bus or model message is treated as your direction.")))
            .child(div().id("claude-work-timeline").flex_1().min_h_0().overflow_y_scroll().px_6()
                .when(history.is_empty(), |this| this.child(div().flex().flex_col().gap_2().py_8()
                    .child(div().text_lg().font_weight(FontWeight::MEDIUM).child("What would you like Claude to do?"))
                    .child(div().text_sm().text_color(cx.theme().muted_foreground).child("Start one task explicitly. Keep writing while it runs, then choose when to send your next direction."))))
                .children(history)
                .when_some(self.snapshot.agent_text.clone(), |this, text| this.child(div().flex().flex_col().gap_2().py_3()
                    .child(div().font_weight(FontWeight::SEMIBOLD).child("Claude output"))
                    .child(text_block(text, cx)))))
            .child(div().flex().flex_col().gap_3().px_6().py_5().border_t_1().border_color(cx.theme().border)
                .child(div().capture_action(cx.listener(|this, action: &Enter, _, cx| {
                    if action.secondary && !action.shift {
                        cx.stop_propagation();
                        if !this.shortcut_held { this.shortcut_held = true; this.submit(cx); }
                    }
                })).on_key_up(cx.listener(|this, event: &KeyUpEvent, _, _| {
                    if event.keystroke.key == "enter" { this.shortcut_held = false; }
                })).child(Textarea::new(&self.editor).aria_label("Claude task or direction draft")))
                .child(div().flex().items_center().gap_2()
                    .child(div().text_xs().text_color(cx.theme().muted_foreground).child("Direction timing"))
                    .children([(InputTiming::Now, "claude-timing-now"), (InputTiming::AfterTools, "claude-timing-tools"), (InputTiming::AfterTurn, "claude-timing-turn")].into_iter().map(|(timing, id)| {
                        Button::new(id).label(timing_label(timing))
                            .when(self.timing == timing, |button| button.primary())
                            .on_click(cx.listener(move |this, _, _, cx| { this.timing = timing; cx.notify(); }))
                    })))
                .child(div().text_xs().text_color(cx.theme().muted_foreground).child("Now may interrupt or stop work; it does not promise the same turn. In prose-only work, there are no running tools to move to the background."))
                .child(div().flex().items_center().gap_3()
                    .child(div().flex_1().text_xs().text_color(cx.theme().muted_foreground).child("Your draft stays editable while Claude works. Sending is always your explicit action."))
                    .child(Button::new("submit-claude-work").primary().label(self.primary_label()).disabled(!can_submit)
                        .on_click(cx.listener(|this, _, _, cx| this.submit(cx)))))
                .when_some(self.notice, |this, notice| this.child(div().text_xs().text_color(cx.theme().muted_foreground).child(notice))))
    }
}

#[cfg(test)]
#[path = "claude_work_interaction_tests.rs"]
mod tests;
