use chinwag_team_direction::{
    ClaudeTiming, DirectionReceipt, HeldWorkPort, MAX_TEXT_BYTES, NativeSnapshot, RenderedPlan,
    ReportKind, TeamError, TeamHost, TeamSnapshot,
};
use gpui_kit::component::{
    ActiveTheme, Disableable, Sizable,
    button::{Button, ButtonVariants},
    checkbox::Checkbox,
    input::{Enter, InputEvent, Textarea, TextareaState},
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    AnyWindowHandle, App, AppContext, Context, Entity, FontWeight, InteractiveElement, IntoElement,
    KeyUpEvent, ParentElement, Render, StatefulInteractiveElement, Styled, Subscription, Task,
    Window, div, px,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone)]
struct SentRound {
    id: String,
    text: String,
    revision: u64,
    selection_revision: u64,
    options_revision: u64,
    selected: Vec<String>,
    effective: Vec<String>,
}
enum Flight {
    Capture(u64),
    Submitted(String),
}
struct Presentation {
    draft: String,
    revision: u64,
    selection_revision: u64,
    options_revision: u64,
    selected: BTreeSet<String>,
    timings: BTreeMap<String, ClaudeTiming>,
    consumed_revision: Option<u64>,
    flight: Option<Flight>,
    pending_clear: Option<SentRound>,
    lookup_pending: Option<(String, u64)>,
    next_capture: u64,
    exhausted: bool,
    notice: Option<String>,
}
impl Default for Presentation {
    fn default() -> Self {
        Self {
            draft: String::new(),
            revision: 1,
            selection_revision: 1,
            options_revision: 1,
            selected: BTreeSet::new(),
            timings: BTreeMap::new(),
            consumed_revision: None,
            flight: None,
            pending_clear: None,
            lookup_pending: None,
            next_capture: 1,
            exhausted: false,
            notice: None,
        }
    }
}
impl Presentation {
    fn edit(&mut self) {
        if let Some(revision) = self.revision.checked_add(1) {
            self.revision = revision;
        } else {
            self.exhausted = true;
            self.notice = Some(
                "Human revision capacity is exhausted; original receipts remain available.".into(),
            );
        }
    }
    fn consumed(&self) -> bool {
        self.consumed_revision == Some(self.revision)
    }
}

/// App-owned presentation and the exact core owner survive window closure.
/// This is not a second identity/grant registry or an observer file.
pub(crate) struct DesktopTeamHost {
    pub(crate) core: Arc<TeamHost>,
    presentation: Mutex<Presentation>,
    pub(crate) window: Mutex<Option<AnyWindowHandle>>,
}
impl DesktopTeamHost {
    pub(crate) fn new(core: Arc<TeamHost>) -> Arc<Self> {
        Arc::new(Self {
            core,
            presentation: Mutex::new(Presentation::default()),
            window: Mutex::new(None),
        })
    }
    pub(crate) fn close_controls(&self) {
        self.core.close_admission();
        for member in self.core.members() {
            match &member.port {
                HeldWorkPort::Codex(port) => {
                    let _ = port.close();
                }
                HeldWorkPort::Claude(port) => {
                    let _ = port.end_input();
                }
                HeldWorkPort::Gemini(port) => {
                    let _ = port.end_input();
                }
            }
        }
    }
    pub(crate) fn locally_closed(&self) -> bool {
        let snapshot = self.core.subscribe().borrow().clone();
        snapshot.members.len() == self.core.members().len()
            && snapshot.members.iter().all(|member| match &member.native {
                NativeSnapshot::Codex(native) => {
                    native.phase == chinwag_codex_steer::WorkPhase::Closed
                }
                NativeSnapshot::Claude(native) => {
                    native.lifecycle.stdin_ended || native.lifecycle.child_exited
                }
                NativeSnapshot::Gemini(native) => {
                    native.lifecycle.stdin_ended || native.lifecycle.child_exited
                }
            })
    }
}

pub(crate) struct TeamWorkView {
    host: Arc<DesktopTeamHost>,
    snapshot: TeamSnapshot,
    editor: Entity<TextareaState>,
    window: AnyWindowHandle,
    shortcut_held: bool,
    _watch: Task<()>,
    _editor_subscription: Subscription,
}
impl TeamWorkView {
    pub(crate) fn new(
        host: Arc<DesktopTeamHost>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let window_handle = window.window_handle();
        if let Ok(mut current) = host.window.lock() {
            *current = Some(window_handle);
        }
        let mut receiver = host.core.subscribe();
        let snapshot = receiver.borrow_and_update().clone();
        let draft = host
            .presentation
            .lock()
            .map(|state| state.draft.clone())
            .unwrap_or_default();
        let editor = cx.new(|cx| {
            let mut editor = TextareaState::new(window, cx)
                .rows(4)
                .placeholder("Write one direction for your selected work members…");
            editor.set_value(draft, window, cx);
            editor
        });
        let subscription = cx.subscribe_in(&editor, window, |this, _, event, _, cx| {
            if matches!(event, InputEvent::Change) {
                if let Ok(mut state) = this.host.presentation.lock() {
                    state.draft = this.editor.read(cx).value().to_string();
                    state.edit();
                    state.notice = None;
                }
                cx.notify();
            }
        });
        let watch = cx.spawn_in(window, async move |this, cx| {
            while receiver.changed().await.is_ok() {
                let snapshot = receiver.borrow_and_update().clone();
                if this
                    .update_in(cx, |this, window, cx| {
                        this.apply_snapshot(snapshot, window, cx)
                    })
                    .is_err()
                {
                    return;
                }
            }
            let _ = this.update_in(cx, |this, _, cx| {
                if let Ok(mut state) = this.host.presentation.lock() {
                    state.notice = Some(
                        "Team owner updates ended. Check original records; nothing is sent again."
                            .into(),
                    );
                }
                this.snapshot.admission_closed = true;
                cx.notify();
            });
        });
        let mut view = Self {
            host,
            snapshot: snapshot.clone(),
            editor,
            window: window_handle,
            shortcut_held: false,
            _watch: watch,
            _editor_subscription: subscription,
        };
        view.apply_snapshot(snapshot, window, cx);
        view
    }

    fn apply_snapshot(
        &mut self,
        snapshot: TeamSnapshot,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if snapshot.revision < self.snapshot.revision {
            return;
        }
        let mut clear = false;
        if let Ok(mut state) = self.host.presentation.lock() {
            let mut completed_notices = Vec::new();
            let submitted_id = match &state.flight {
                Some(Flight::Submitted(id)) => Some(id.clone()),
                _ => None,
            };
            if let Some(id) = submitted_id {
                let report = snapshot.submissions.get(&id).filter(|report| {
                    report.kind == ReportKind::Submit && report.id == id && report.stage_retired
                });
                let retired = snapshot
                    .directions
                    .iter()
                    .any(|receipt| receipt.intent.id == id && receipt.stage_retired)
                    || report.is_some();
                if retired {
                    state.flight = None;
                    if let Some(error) = report.and_then(|report| report.error) {
                        completed_notices
                            .push(format!("Direction submission: {}", error_message(error)));
                    }
                }
            }
            if let Some(round) = state.pending_clear.clone() {
                let exact = snapshot.directions.iter().find(|receipt| {
                    receipt.intent.id == round.id
                        && receipt.intent.human_revision == round.revision
                        && receipt.intent.text == round.text
                        && receipt.intent.selected == round.selected
                        && receipt.intent.effective == round.effective
                });
                if let Some(receipt) = exact
                    && may_clear(receipt, &round)
                    && state.revision == round.revision
                    && state.selection_revision == round.selection_revision
                    && state.options_revision == round.options_revision
                    && self.editor.read(cx).value().as_ref() == round.text
                {
                    state.draft.clear();
                    state.edit();
                    state.pending_clear = None;
                    clear = true;
                }
            }
            let checked = state.lookup_pending.as_ref().and_then(|(id, serial)| {
                snapshot.lookups.get(id).filter(|report| {
                    report.kind == ReportKind::Lookup
                        && &report.id == id
                        && report
                            .lookup_serial
                            .is_some_and(|observed| observed >= *serial)
                        && report.stage_retired
                })
            });
            if let Some(report) = checked {
                state.lookup_pending = None;
                completed_notices.push(match report.error {
                    Some(error) => format!("Original record check: {}", error_message(error)),
                    None => "Original parent record checked; native receipt lookups requested. No direction was sent again.".into(),
                });
            }
            if !completed_notices.is_empty() {
                state.notice = Some(completed_notices.join(" "));
            }
        }
        if clear {
            self.editor
                .update(cx, |editor, cx| editor.set_value("", window, cx));
        }
        self.snapshot = snapshot;
        cx.notify();
    }

    fn selection(&self) -> (Vec<String>, BTreeMap<String, ClaudeTiming>, u64, u64) {
        self.host
            .presentation
            .lock()
            .map(|state| {
                (
                    state.selected.iter().cloned().collect(),
                    state.timings.clone(),
                    state.selection_revision,
                    state.options_revision,
                )
            })
            .unwrap_or_default()
    }
    fn plan(&self, cx: &App) -> Option<RenderedPlan> {
        let (selected, timings, _, _) = self.selection();
        if selected.is_empty() || !valid_text(self.editor.read(cx).value().as_ref()) {
            return None;
        }
        self.host
            .core
            .plan(&selected, self.editor.read(cx).value().as_ref(), &timings)
            .ok()
    }
    fn interaction_available(&self, cx: &App) -> bool {
        !self.snapshot.admission_closed
            && !self.snapshot.busy
            && valid_text(self.editor.read(cx).value().as_ref())
            && self
                .host
                .presentation
                .lock()
                .is_ok_and(|state| !state.exhausted && state.flight.is_none() && !state.consumed())
    }
    fn select(&mut self, id: &str, checked: bool, cx: &mut Context<Self>) {
        if let Ok(mut state) = self.host.presentation.lock() {
            if checked {
                state.selected.insert(id.into());
            } else {
                state.selected.remove(id);
            }
            if let Some(revision) = state.selection_revision.checked_add(1) {
                state.selection_revision = revision;
                state.edit();
            } else {
                state.exhausted = true;
            }
        }
        cx.notify();
    }
    fn timing(&mut self, id: &str, timing: ClaudeTiming, cx: &mut Context<Self>) {
        if let Ok(mut state) = self.host.presentation.lock() {
            state.timings.insert(id.into(), timing);
            if let Some(revision) = state.options_revision.checked_add(1) {
                state.options_revision = revision;
                state.edit();
            } else {
                state.exhausted = true;
            }
        }
        cx.notify();
    }
    fn new_direction(&mut self, cx: &mut Context<Self>) {
        if let Ok(mut state) = self.host.presentation.lock() {
            // This explicit choice also invalidates older rendered/deferred
            // plans, even when its text and timing values remain identical.
            if let Some(revision) = state.options_revision.checked_add(1) {
                state.options_revision = revision;
            } else {
                state.exhausted = true;
            }
            state.edit();
            state.notice = Some(
                "New direction revision. Review its text and exact recipients before sending."
                    .into(),
            );
        }
        cx.notify();
    }

    fn submit_plan(
        &mut self,
        plan: RenderedPlan,
        effective: Vec<String>,
        selection_revision: u64,
        options_revision: u64,
        cx: &mut Context<Self>,
    ) {
        if self.snapshot.admission_closed || self.snapshot.busy || !valid_text(plan.text()) {
            return;
        }
        let nonce = {
            let Ok(mut state) = self.host.presentation.lock() else {
                return;
            };
            if state.exhausted
                || state.flight.is_some()
                || state.selection_revision != selection_revision
                || state.options_revision != options_revision
                || state.selected.iter().cloned().collect::<Vec<_>>() != plan.selected()
                || self.editor.read(cx).value().as_ref() != plan.text()
            {
                return;
            }
            let nonce = state.next_capture;
            let Some(next) = nonce.checked_add(1) else {
                state.exhausted = true;
                return;
            };
            state.next_capture = next;
            state.draft = plan.text().into();
            state.flight = Some(Flight::Capture(nonce));
            state.notice = None;
            nonce
        };
        let original_deadline = Instant::now() + Duration::from_secs(30);
        let weak = cx.weak_entity();
        let host = self.host.clone();
        // Prior Input Change effects must become the baseline before choosing
        // the backend-consumed human revision. The deadline/plan remain from
        // the original click, and the immediate capture flight blocks repeats.
        cx.defer(move |cx| {
            if weak
                .update(cx, |this, cx| {
                    this.finish_capture(
                        nonce,
                        plan,
                        effective,
                        selection_revision,
                        options_revision,
                        original_deadline,
                        cx,
                    )
                })
                .is_err()
                && let Ok(mut state) = host.presentation.lock()
                && matches!(state.flight, Some(Flight::Capture(current)) if current == nonce)
            {
                state.flight = None;
            }
        });
        cx.notify();
    }

    // Keep the original human click's deadline and revision guards explicit;
    // deferred processing must neither recapture nor renew any of these values.
    #[allow(clippy::too_many_arguments)]
    fn finish_capture(
        &mut self,
        nonce: u64,
        plan: RenderedPlan,
        effective: Vec<String>,
        selection_revision: u64,
        options_revision: u64,
        deadline: Instant,
        cx: &mut Context<Self>,
    ) {
        let revision = {
            let Ok(mut state) = self.host.presentation.lock() else {
                return;
            };
            if !matches!(state.flight, Some(Flight::Capture(current)) if current == nonce) {
                return;
            }
            if state.consumed()
                || state.exhausted
                || state.selection_revision != selection_revision
                || state.options_revision != options_revision
                || state.selected.iter().cloned().collect::<Vec<_>>() != plan.selected()
                || self.editor.read(cx).value().as_ref() != plan.text()
            {
                state.flight = None;
                state.notice = Some("This human revision is consumed or changed; review a new direction before sending.".into());
                cx.notify();
                return;
            }
            state.revision
        };
        let result = self
            .host
            .core
            .capture(&plan, &effective, revision, deadline)
            .and_then(|capture| self.host.core.submit(capture));
        if let Ok(mut state) = self.host.presentation.lock() {
            match result {
                Ok(id) => {
                    state.consumed_revision = Some(revision);
                    state.pending_clear = Some(SentRound {
                        id: id.clone(),
                        text: plan.text().into(),
                        revision,
                        selection_revision,
                        options_revision,
                        selected: plan.selected().to_vec(),
                        effective,
                    });
                    state.flight = Some(Flight::Submitted(id));
                    state.notice = Some("Direction admitted locally. Each member's original saved intent and native outcome remain independent.".into());
                }
                Err(error) => {
                    state.flight = None;
                    state.notice = Some(error_message(error).into());
                }
            }
        }
        cx.notify();
    }

    fn lookup(&mut self, id: &str, cx: &mut Context<Self>) {
        if let Ok(mut state) = self.host.presentation.lock() {
            if state.lookup_pending.is_some() {
                return;
            }
            match self.host.core.lookup(id) {
                Ok(serial) => {
                    state.lookup_pending = Some((id.into(), serial));
                    state.notice =
                        Some("Checking the original parent record; no action is replayed.".into());
                }
                Err(error) => state.notice = Some(error_message(error).into()),
            }
        }
        cx.notify();
    }
}
impl Drop for TeamWorkView {
    fn drop(&mut self) {
        if let Ok(mut current) = self.host.window.lock()
            && *current == Some(self.window)
        {
            *current = None;
        }
    }
}

fn valid_text(text: &str) -> bool {
    !text.trim().is_empty()
        && text.len() <= MAX_TEXT_BYTES
        && !text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
}
fn may_clear(receipt: &DirectionReceipt, round: &SentRound) -> bool {
    !receipt.persistence_failed
        && !receipt.recovered
        && receipt.intent.selected == receipt.intent.effective
        && receipt
            .intent
            .members
            .iter()
            .all(|member| member.excluded.is_none())
        && receipt.members.len() == round.effective.len()
        && round.effective.iter().all(|id| {
            receipt
                .members
                .iter()
                .any(|member| &member.id == id && member.child_saved && member.clear_safe)
        })
}
fn error_message(error: TeamError) -> &'static str {
    match error {
        TeamError::InvalidInput => {
            "Review nonempty text within the limit and the exact selected members."
        }
        TeamError::Storage => {
            "Action persistence is unavailable. Check original records; do not resend an unknown action."
        }
        TeamError::Busy => {
            "A team submission is still in flight. Your editor stays available; another click is not queued."
        }
        TeamError::ConsumedRevision => {
            "This human revision is already admitted. Check its originals or explicitly begin a new direction."
        }
        TeamError::StalePlan => {
            "The selected plan changed. No replacement target is chosen; review it before a new explicit send."
        }
        TeamError::Expired => {
            "The original action deadline expired. No new control window is granted automatically."
        }
        TeamError::Closed => "Team direction input is closed. Existing work may continue.",
        TeamError::Capacity => {
            "Direction history is full. Original unresolved records are retained."
        }
        TeamError::Unavailable => "This team owner is unavailable. No member is woken or adopted.",
    }
}
fn native_label(snapshot: &NativeSnapshot) -> (&'static str, &'static str, String) {
    match snapshot {
        NativeSnapshot::Codex(native) => (
            "Codex",
            match native.phase {
                chinwag_codex_steer::WorkPhase::Ready => "Not started · open work window",
                chinwag_codex_steer::WorkPhase::Finished => "Owned turn ended",
                chinwag_codex_steer::WorkPhase::Closed => "Control closed · work may continue",
                chinwag_codex_steer::WorkPhase::OwnerActionRequired => "Owner action required",
                _ if native.target.is_some() => "Exact active turn observed",
                _ => "No active turn available",
            },
            native.folder_label.clone(),
        ),
        NativeSnapshot::Claude(native) => (
            "Claude",
            match native.phase {
                chinwag_claude_control::WorkPhase::Ready => "Not started · open work window",
                chinwag_claude_control::WorkPhase::InputEnded => "Input ended · work may continue",
                chinwag_claude_control::WorkPhase::Exited => "Owned process exited",
                chinwag_claude_control::WorkPhase::OwnerActionRequired => "Owner action required",
                _ if native.session.is_some() => "Owned session input available",
                _ => "No current owned session",
            },
            native.folder_label.clone(),
        ),
        NativeSnapshot::Gemini(native) => (
            "Gemini",
            if native.lifecycle.child_exited {
                "Owned process exited"
            } else if native.lifecycle.stdin_ended {
                "Input ended · work may continue"
            } else if native.control_expired {
                "Human control expired"
            } else if native.cancel_pending {
                "Original cancellation pending"
            } else if native.active_prompt.is_some() {
                "Response pending · Cancel is separate"
            } else if native.can_prompt {
                "Ready for a new explicit prompt"
            } else if native.phase == chinwag_gemini_control::WorkPhase::Ready {
                "Not started · open work window"
            } else {
                "No current prompt slot"
            },
            native.folder_label.clone(),
        ),
    }
}

impl Render for TeamWorkView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let (selected, timings, selection_revision, options_revision) = self.selection();
        let plan = self.plan(cx);
        let available = self.interaction_available(cx);
        let (notice, consumed, flight) = self
            .host
            .presentation
            .lock()
            .map(|state| {
                (
                    state.notice.clone(),
                    state.consumed(),
                    state.flight.is_some(),
                )
            })
            .unwrap_or_default();
        let rows = self
            .snapshot
            .members
            .iter()
            .enumerate()
            .map(|(index, member)| {
                let id = member.id.clone();
                let open_id = id.clone();
                let (provider, status, folder) = native_label(&member.native);
                let choice = plan
                    .as_ref()
                    .and_then(|plan| plan.rows().iter().find(|row| row.id == member.id));
                let selected_member = selected.contains(&member.id);
                let selected_timing = timings
                    .get(&member.id)
                    .copied()
                    .unwrap_or(ClaudeTiming::Now);
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .py_3()
                    .border_b_1()
                    .border_color(cx.theme().border)
                    .child(
                        Checkbox::new(("team-member", index))
                            .label(format!("{} · {}", member.label, member.id))
                            .checked(selected_member)
                            .on_click(cx.listener(move |this, checked: &bool, _, cx| {
                                this.select(&id, *checked, cx)
                            })),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child(format!("{provider} · {folder}")),
                    )
                    .child(div().text_sm().child(status))
                    .when_some(choice, |this, choice| {
                        this.child(
                            div()
                                .text_xs()
                                .text_color(cx.theme().muted_foreground)
                                .child(
                                    choice
                                        .action
                                        .map(|action| action.to_string())
                                        .or_else(|| choice.blocked.map(|reason| reason.to_string()))
                                        .unwrap_or_default(),
                                ),
                        )
                    })
                    .when(
                        matches!(member.native, NativeSnapshot::Claude(_)) && selected_member,
                        |this| {
                            this.child(
                                div().flex().flex_wrap().gap_1().children(
                                    [
                                        (ClaudeTiming::Now, "Now · may interrupt"),
                                        (ClaudeTiming::AfterTools, "After tools"),
                                        (ClaudeTiming::AfterTurn, "After turn"),
                                    ]
                                    .into_iter()
                                    .enumerate()
                                    .map(
                                        |(choice_index, (timing, label))| {
                                            let id = member.id.clone();
                                            Button::new((
                                                "team-claude-timing",
                                                index * 3 + choice_index,
                                            ))
                                            .small()
                                            .label(label)
                                            .when(selected_timing == timing, |button| {
                                                button.primary()
                                            })
                                            .on_click(
                                                cx.listener(move |this, _, _, cx| {
                                                    this.timing(&id, timing, cx)
                                                }),
                                            )
                                        },
                                    ),
                                ),
                            )
                        },
                    )
                    .child(
                        Button::new(("open-team-member", index))
                            .small()
                            .label("Open work window")
                            .on_click(cx.listener(move |this, _, _, cx| {
                                if let Some(member) = this
                                    .host
                                    .core
                                    .members()
                                    .iter()
                                    .find(|member| member.id == open_id)
                                {
                                    super::open_team_member_window(member, cx);
                                }
                            })),
                    )
            })
            .collect::<Vec<_>>();
        let history = self.snapshot.directions.iter().enumerate().map(|(index, receipt)| {
            let id = receipt.intent.id.clone();
            div().flex().flex_col().gap_2().py_4().border_b_1().border_color(cx.theme().border)
                .child(div().font_weight(FontWeight::SEMIBOLD).child("Your team direction"))
                .child(div().text_sm().child(receipt.intent.text.clone()))
                .when(receipt.recovered, |this| this.child(div().text_xs().text_color(cx.theme().muted_foreground).child("Recovered original action. No fan-out or control was resumed.")))
                .when(receipt.persistence_failed, |this| this.child(div().text_xs().text_color(cx.theme().muted_foreground).child("Parent persistence failed or is uncertain. Check the originals; do not resend all.")))
                .children(receipt.members.iter().map(|member|div().text_xs().text_color(cx.theme().muted_foreground).child(format!("{} ({}): {}",member.label,member.id,member.summary))))
                .children(receipt.intent.members.iter().filter_map(|member|member.excluded.map(|reason|div().text_xs().text_color(cx.theme().muted_foreground).child(format!("{} ({}) — excluded by your chosen subset: {reason}",member.label,member.id)))))
                .child(Button::new(("lookup-team-direction",index)).small().label("Check original records")
                    .on_click(cx.listener(move|this,_,_,cx|this.lookup(&id,cx))))
        }).collect::<Vec<_>>();
        let ready = plan
            .as_ref()
            .map(|plan| plan.ready().to_vec())
            .unwrap_or_default();
        let all_ready = !selected.is_empty() && ready.len() == selected.len();
        let ready_names = plan
            .as_ref()
            .map(|plan| {
                plan.rows()
                    .iter()
                    .filter(|row| ready.contains(&row.id))
                    .map(|row| format!("{} ({})", row.label, row.id))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        let full_plan = plan.clone();
        let subset_plan = plan.clone();
        div().flex().flex_col().size_full().bg(cx.theme().background).text_color(cx.theme().foreground).font_family(".AppleSystemUIFont")
            .child(div().flex().flex_col().gap_2().px_6().py_5().border_b_1().border_color(cx.theme().border)
                .child(div().text_xl().font_weight(FontWeight::SEMIBOLD).child("Team direction"))
                .child(div().text_sm().child("Explicitly owned work on this Chinwag host"))
                .child(div().text_xs().text_color(cx.theme().muted_foreground).child("Open a member's work window to start its task with its native policy. Selecting or opening starts nothing. This composer sends direction only.")))
            .child(div().flex().flex_1().min_h_0()
                .child(div().id("team-members").w(px(310.)).flex_shrink_0().overflow_y_scroll().px_5().border_r_1().border_color(cx.theme().border).children(rows))
                .child(div().flex().flex_col().flex_1().min_w_0()
                    .child(div().id("team-direction-history").flex_1().min_h_0().overflow_y_scroll().px_6()
                        .when(history.is_empty(),|this|this.child(div().flex().flex_col().gap_2().py_8()
                            .child(div().text_lg().font_weight(FontWeight::MEDIUM).child("Give your running work one clear direction"))
                            .child(div().text_sm().text_color(cx.theme().muted_foreground).child("Choose the exact work members, write once, then review each native action. Busy Gemini cancellation stays in its own work window."))))
                        .children(history))
                    .child(div().flex().flex_col().gap_3().px_6().py_5().border_t_1().border_color(cx.theme().border)
                        .child(div().capture_action(cx.listener(|this,action:&Enter,_,cx|{
                            if action.secondary&&!action.shift { cx.stop_propagation(); if !this.shortcut_held { this.shortcut_held=true;
                                if let Some(plan)=this.plan(cx) && plan.ready().len()==plan.selected().len() {
                                    let(_,_,selection,options)=this.selection();let effective=plan.selected().to_vec();this.submit_plan(plan,effective,selection,options,cx);
                                }
                            }}
                        })).on_key_up(cx.listener(|this,event:&KeyUpEvent,_,_|{if event.keystroke.key=="enter"{this.shortcut_held=false;}}))
                            .child(Textarea::new(&self.editor).aria_label("Team direction draft")))
                        .when(!ready.is_empty(),|this|this.child(div().text_xs().text_color(cx.theme().muted_foreground).child(format!("Ready native recipients: {ready_names}"))))
                        .when(!selected.is_empty()&&!all_ready,|this|this.child(div().text_xs().text_color(cx.theme().muted_foreground).child("A selected member is blocked. The normal action sends nothing. Choose the named ready subset explicitly, or change your selection.")))
                        .when(consumed,|this|this.child(div().text_xs().text_color(cx.theme().muted_foreground).child("This human revision is already admitted. Check its originals, edit a new direction or choose New direction; it will not rearm automatically.")))
                        .child(div().flex().flex_wrap().items_center().gap_2()
                            .child(Button::new("new-team-direction").small().label("New direction").on_click(cx.listener(|this,_,_,cx|this.new_direction(cx))))
                            .child(div().flex_1())
                            .child(Button::new("send-team-direction").primary().label(if flight {"Submitting captured direction…".into()}else{format!("Send to selected ({})",selected.len())}).disabled(!available||!all_ready)
                                .on_click(cx.listener(move|this,_,_,cx|{if let Some(plan)=full_plan.clone(){let effective=plan.selected().to_vec();this.submit_plan(plan,effective,selection_revision,options_revision,cx);}}))))
                        .when(!all_ready&&!ready.is_empty(),|this|this.child(Button::new("send-team-ready-subset").label(format!("Send to {} ready members only",ready.len())).disabled(!available)
                            .on_click(cx.listener(move|this,_,_,cx|{if let Some(plan)=subset_plan.clone(){let effective=plan.ready().to_vec();this.submit_plan(plan,effective,selection_revision,options_revision,cx);}}))))
                        .child(div().text_xs().text_color(cx.theme().muted_foreground).child("Saved intent, local admission and native evidence are separate. No aggregate read, applied, retry-all or automatic continuation is inferred."))
                        .when_some(notice,|this,notice|this.child(div().text_xs().text_color(cx.theme().muted_foreground).child(notice))))))
    }
}

#[cfg(test)]
#[path = "team_work_interaction_tests.rs"]
mod tests;
