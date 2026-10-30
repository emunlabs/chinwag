use chinwag_codex_steer::{
    Evidence, HumanWorkPort, MAX_TEXT_BYTES, SteerError, WorkActionKind, WorkPhase, WorkSnapshot,
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
    kind: WorkActionKind,
    text: String,
    draft_identity: Option<Arc<()>>,
}

pub(crate) struct CodexWorkView {
    port: Arc<dyn HumanWorkPort>,
    snapshot: WorkSnapshot,
    editor: Entity<TextareaState>,
    draft_identity: Arc<()>,
    flight: Option<Flight>,
    start_admitted: bool,
    close_requested: bool,
    lookup_pending: Option<String>,
    shortcut_held: bool,
    notice: Option<&'static str>,
    _watch: Task<()>,
    _editor_subscription: Subscription,
}

impl CodexWorkView {
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
                .placeholder("Describe the work, or steer the active turn…")
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
                if this.update_in(cx, |this, window, cx| {
                    this.apply_snapshot(snapshot, window, cx);
                }).is_err() {
                    return;
                }
            }
            let _ = this.update_in(cx, |this, _, cx| {
                this.notice = Some("Control updates stopped. Check the original receipt; do not resend automatically.");
                this.close_requested = true;
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
            close_requested: false,
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
            if let Some(report) = &snapshot.last_submission
                && report.id == flight.id
                && report.kind == flight.kind
            {
                return Some((report.saved, report.error));
            }
            // A consumed start is durable before the initial acknowledgment.
            // Release the short UI flight so an observed target can be steered.
            if flight.kind == WorkActionKind::Start
                && let Some(start) = &snapshot.start
                && start.id == flight.id
                && start.text == flight.text
            {
                return Some((
                    !start.persistence_failed,
                    start.persistence_failed.then_some(SteerError::Storage),
                ));
            }
            // Watch delivery can coalesce a submission report with later
            // progress. Retained exact receipts also settle the short flight.
            if flight.kind == WorkActionKind::Steer
                && let Some(receipt) = snapshot.steers.iter().find(|receipt| {
                    receipt.operation.id == flight.id && receipt.operation.text == flight.text
                })
                && (receipt.evidence != Evidence::default() || receipt.persistence_failed)
            {
                let error = if receipt.persistence_failed {
                    Some(SteerError::Storage)
                } else if receipt.evidence.write_uncertain
                    && !receipt.evidence.core_accepted
                    && !receipt.evidence.harness_recorded
                {
                    Some(SteerError::Uncertain)
                } else {
                    None
                };
                return Some((!receipt.persistence_failed, error));
            }
            None
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
            && report.kind == WorkActionKind::Lookup
            && self.lookup_pending.as_deref() == Some(report.id.as_str())
        {
            self.lookup_pending = None;
            self.notice = Some(match report.error {
                Some(error) => error_message(error),
                None => "Original receipt checked. No request was sent again.",
            });
        }
        self.start_admitted |= snapshot.start.is_some() || snapshot.phase != WorkPhase::Ready;
        self.snapshot = snapshot;
        cx.notify();
    }

    fn action(&self) -> Option<WorkActionKind> {
        if self.close_requested || self.flight.is_some() {
            return None;
        }
        if self.snapshot.phase == WorkPhase::Ready && !self.start_admitted {
            return Some(WorkActionKind::Start);
        }
        if self.snapshot.target.is_some()
            && !matches!(
                self.snapshot.phase,
                WorkPhase::Finished
                    | WorkPhase::OwnerActionRequired
                    | WorkPhase::Closed
                    | WorkPhase::Unavailable
            )
        {
            return Some(WorkActionKind::Steer);
        }
        None
    }

    fn primary_label(&self) -> &'static str {
        if let Some(flight) = &self.flight {
            return if flight.kind == WorkActionKind::Start {
                "Submitting task…"
            } else {
                "Submitting steer…"
            };
        }
        match self.action() {
            Some(WorkActionKind::Start) => "Start task",
            Some(WorkActionKind::Steer) => "Steer current turn",
            _ => match self.snapshot.phase {
                WorkPhase::Starting => "Waiting for an active turn",
                WorkPhase::OwnerActionRequired => "Owner action required",
                WorkPhase::Finished => "Turn ended",
                WorkPhase::Closed => "Control connection closed",
                WorkPhase::Unavailable => "Control unavailable",
                _ => "No active turn",
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
        let Some(kind) = self.action() else {
            return;
        };
        self.lookup_pending = None;
        let text = self.editor.read(cx).value().to_string();
        let id = match chinwag_bus_client::new_request_id() {
            Ok(id) => id,
            Err(_) => {
                self.notice = Some("Could not create a request ID. Your draft is still here.");
                cx.notify();
                return;
            }
        };
        let result = match kind {
            WorkActionKind::Start => self.port.start(&id, &text),
            WorkActionKind::Steer => {
                let Some(target) = self.snapshot.target.clone() else {
                    return;
                };
                self.port.steer(&target, &id, &text)
            }
            _ => return,
        };
        match result {
            Ok(()) => {
                self.start_admitted |= kind == WorkActionKind::Start;
                let baseline_id = id.clone();
                self.flight = Some(Flight {
                    id,
                    kind,
                    text,
                    draft_identity: None,
                });
                // Input Change notifications are FIFO deferred effects. Capture
                // the edit baseline after pre-click notifications, before later
                // edits, while keeping the exact text/target captured by click.
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
                self.notice = None;
            }
            Err(error) => self.notice = Some(error_message(error)),
        }
        cx.notify();
    }

    fn lookup(&mut self, id: &str, cx: &mut Context<Self>) {
        if self.flight.is_some() {
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

    fn close(&mut self, cx: &mut Context<Self>) {
        if self.close_requested {
            return;
        }
        match self.port.close() {
            Ok(()) => {
                self.close_requested = true;
                self.notice = Some("Control connection closing. Work may continue.");
            }
            Err(error) => self.notice = Some(error_message(error)),
        }
        cx.notify();
    }
}

fn phase_label(phase: WorkPhase) -> &'static str {
    match phase {
        WorkPhase::Ready => "Ready for your task",
        WorkPhase::Starting => "Requesting work",
        WorkPhase::Working => "Active turn observed",
        WorkPhase::Finished => "Turn ended",
        WorkPhase::StartUnknown => "Initial request outcome unknown",
        WorkPhase::OwnerActionRequired => "Owner action required",
        WorkPhase::Closed => "Control connection closed",
        WorkPhase::Unavailable => "Control unavailable",
    }
}

#[derive(Clone, Copy)]
enum EvidenceLane {
    InitialTurn,
    Steer,
}

fn evidence_lines(
    evidence: Evidence,
    persistence_failed: bool,
    lane: EvidenceLane,
) -> Vec<&'static str> {
    let mut lines = Vec::new();
    if evidence.not_dispatched {
        lines.push(match lane {
            EvidenceLane::InitialTurn => {
                "Initial turn request not dispatched; bootstrap may already have run."
            }
            EvidenceLane::Steer => "Steer request not dispatched.",
        });
    }
    if evidence.frame_written {
        lines.push(match lane {
            EvidenceLane::InitialTurn => {
                "Initial turn request frame written to the declared server."
            }
            EvidenceLane::Steer => "Steer request frame written to the declared server.",
        });
    }
    if evidence.core_accepted {
        lines.push("Accepted by Codex Core. Agent awareness and application are unverified.");
    }
    if evidence.harness_recorded {
        lines.push(
            "Harness input recorded. Model awareness and durable Codex storage are unverified.",
        );
    }
    if evidence.peer_error_observed {
        lines.push("A peer error was observed; it does not establish that nothing was submitted.");
    }
    if evidence.write_uncertain {
        lines
            .push("Uncertainty recorded. Check the original receipt; do not resend automatically.");
    }
    if persistence_failed {
        lines.push("Receipt persistence failed. Only earlier durable evidence is shown.");
    }
    if lines.is_empty() {
        lines.push("Request saved. Protocol acceptance is not yet observed.");
    }
    lines
}

fn error_message(error: SteerError) -> &'static str {
    match error {
        SteerError::InvalidInput => {
            "Use a nonempty message within the text limit. Your draft is still here."
        }
        SteerError::PermissionDenied => {
            "This action has no current human-control permission. The owner must authorize it."
        }
        SteerError::NoActiveTurn => "No active turn is available. Your draft will not be queued.",
        SteerError::StaleTarget => {
            "The active turn changed. Review the current target before another explicit action."
        }
        SteerError::Busy => {
            "Another submission is in flight. Your draft stays here and will not be queued."
        }
        SteerError::Capacity => {
            "The retained request capacity is full. Existing receipts remain available."
        }
        SteerError::Storage => {
            "Private request persistence is unavailable. Existing records are retained."
        }
        SteerError::Conflict => {
            "This request ID belongs to different input. No automatic resend is permitted."
        }
        SteerError::Unavailable => {
            "The declared control connection is unavailable. Your draft stays here."
        }
        SteerError::Uncertain => {
            "The original outcome is unknown. Check its receipt instead of sending it again."
        }
        SteerError::OwnerInterventionRequired => {
            "The server requires owner intervention. Chinwag does not approve it automatically."
        }
    }
}

fn text_block(text: impl Into<String>, cx: &App) -> Div {
    div()
        .text_sm()
        .text_color(cx.theme().foreground)
        .child(text.into())
}

impl Render for CodexWorkView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let mut history = Vec::new();
        if let Some(start) = &self.snapshot.start {
            let id = start.id.clone();
            let mut lines = evidence_lines(
                start.evidence,
                start.persistence_failed,
                EvidenceLane::InitialTurn,
            );
            if start.connected {
                lines.push("Transport connected to the owner-declared dedicated server; identity is unverified.");
            }
            if start.initialized {
                lines
                    .push("Initialization acknowledged. This does not verify a vendor or account.");
            }
            if start.bootstrap_uncertain {
                lines.push("An initial runtime or task acknowledgment is uncertain. Check the original receipt; no automatic retry is permitted.");
            }
            history.push(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .py_3()
                    .child(div().font_weight(FontWeight::SEMIBOLD).child("Your task"))
                    .child(text_block(start.text.clone(), cx))
                    .children(lines.into_iter().map(|line| {
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child(line)
                    }))
                    .child(
                        Button::new("lookup-codex-start")
                            .label("Check original receipt")
                            .disabled(self.flight.is_some())
                            .on_click(cx.listener(move |this, _, _, cx| this.lookup(&id, cx))),
                    ),
            );
        }
        for (index, receipt) in self.snapshot.steers.iter().enumerate() {
            let id = receipt.operation.id.clone();
            history.push(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .py_3()
                    .child(div().font_weight(FontWeight::SEMIBOLD).child("Your steer"))
                    .child(text_block(receipt.operation.text.clone(), cx))
                    .children(
                        evidence_lines(
                            receipt.evidence,
                            receipt.persistence_failed,
                            EvidenceLane::Steer,
                        )
                        .into_iter()
                        .map(|line| {
                            div()
                                .text_xs()
                                .text_color(cx.theme().muted_foreground)
                                .child(line)
                        }),
                    )
                    .child(
                        Button::new(("lookup-codex-steer", index))
                            .label("Check original receipt")
                            .disabled(self.flight.is_some())
                            .on_click(cx.listener(move |this, _, _, cx| this.lookup(&id, cx))),
                    ),
            );
        }
        let can_submit = self.can_submit(cx);
        div().flex().flex_col().size_full().bg(cx.theme().background)
            .text_color(cx.theme().foreground).font_family(".AppleSystemUIFont")
            .child(div().flex().flex_col().gap_2().px_6().py_5().border_b_1().border_color(cx.theme().border)
                .child(div().flex().items_center().gap_3()
                    .child(div().flex_1().text_xl().font_weight(FontWeight::SEMIBOLD).child("Codex work"))
                    .child(Button::new("close-codex-control").label("Close control connection")
                        .disabled(self.close_requested || self.snapshot.phase == WorkPhase::Closed)
                        .on_click(cx.listener(|this, _, _, cx| this.close(cx)))))
                .child(div().text_sm().child(format!("Work folder: {}", self.snapshot.folder_label)))
                .child(div().text_sm().font_weight(FontWeight::MEDIUM).child(phase_label(self.snapshot.phase)))
                .when_some(self.snapshot.target.as_ref(), |this, target| this.child(div().text_xs().text_color(cx.theme().muted_foreground)
                    .child(format!("Current task: {} · turn: {}", target.thread_id(), target.turn_id()))))
                .child(div().text_xs().text_color(cx.theme().muted_foreground)
                    .child("Start uses the owner-declared dedicated server and requests explicit sign-in policy for that runtime. Its identity, account and exclusivity are unverified. Chinwag does not sign in for you."))
                .child(div().text_xs().text_color(cx.theme().muted_foreground)
                    .child("Close this control connection; work may continue. This window does not use bus messages or inbox permissions as human input.")))
            .child(div().id("codex-work-timeline").flex_1().min_h_0().overflow_y_scroll().px_6()
                .when(history.is_empty(), |this| this.child(div().flex().flex_col().gap_2().py_8()
                    .child(div().text_lg().font_weight(FontWeight::MEDIUM).child("What would you like Codex to do?"))
                    .child(div().text_sm().text_color(cx.theme().muted_foreground)
                        .child("Start one task explicitly. When an active turn is observed, use the same editor to steer it while work continues."))))
                .children(history)
                .when_some(self.snapshot.agent_text.clone(), |this, text| this.child(div().flex().flex_col().gap_2().py_3()
                    .child(div().font_weight(FontWeight::SEMIBOLD).child("Agent output"))
                    .child(text_block(text, cx)))))
            .child(div().flex().flex_col().gap_3().px_6().py_5().border_t_1().border_color(cx.theme().border)
                .child(div().capture_action(cx.listener(|this, action: &Enter, _, cx| {
                    if action.secondary && !action.shift {
                        cx.stop_propagation();
                        if !this.shortcut_held { this.shortcut_held = true; this.submit(cx); }
                    }
                })).on_key_up(cx.listener(|this, event: &KeyUpEvent, _, _| {
                    if event.keystroke.key == "enter" { this.shortcut_held = false; }
                })).child(Textarea::new(&self.editor).aria_label("Task or steer draft")))
                .child(div().flex().items_center().gap_3()
                    .child(div().flex_1().text_xs().text_color(cx.theme().muted_foreground)
                        .child("Your draft stays editable while work runs. Nothing is queued automatically."))
                    .child(Button::new("submit-codex-work").primary().label(self.primary_label())
                        .disabled(!can_submit).on_click(cx.listener(|this, _, _, cx| this.submit(cx)))))
                .when_some(self.notice, |this, notice| this.child(div().text_xs().text_color(cx.theme().muted_foreground).child(notice))))
    }
}

#[cfg(test)]
#[path = "codex_work_interaction_tests.rs"]
mod tests;
