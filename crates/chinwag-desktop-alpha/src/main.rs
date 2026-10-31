use std::collections::HashMap;
use std::time::Duration;

mod claude_work_launch;
mod claude_work_ui;
mod codex_work_launch;
mod codex_work_ui;
mod discovery_ui;
mod drafts;
mod gemini_work_launch;
mod gemini_work_ui;
#[cfg(test)]
mod interaction_tests;
#[cfg(test)]
mod mcp_http_interaction_tests;
mod mcp_http_ui;
#[cfg(test)]
mod opening_interaction_tests;
mod openings;
mod outbox;
mod team_work_launch;
mod team_work_ui;
use discovery_ui::{DiscoveryPanel, InventoryState};
use drafts::DraftFile;
use mcp_http_ui::{McpHttpPanel, McpHttpRequestKind, McpHttpState};
use openings::{OpeningAction, OpeningAttempt, OpeningStore};
use outbox::{Attempt, AttemptState, Outbox};

use chinwag_bus_client::{
    BusClient, BusMessage, ClientError, ClientInventory, InstalledClient, NativeOpenReceipt,
    OnboardingStatus, SendReceipt, SendRequest,
};
use chinwag_bus_model::{Conversation, SendState};
use gpui_kit::component::{
    ActiveTheme, Disableable, Selectable, Sizable,
    button::{Button, ButtonVariants},
    input::{Enter, Input, InputEvent, InputState, Textarea, TextareaState},
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    App, AppContext, Bounds, ClipboardItem, Context, Div, Entity, FontWeight, InteractiveElement,
    IntoElement, KeyBinding, KeyUpEvent, Menu, MenuItem, ParentElement, Render,
    StatefulInteractiveElement, Styled, Subscription, Task, TitlebarOptions, Window, WindowBounds,
    WindowOptions, application, assets, div, init, open_window, px, size,
};

gpui_kit::actions!(
    chinwag_alpha,
    [
        Quit,
        ShowOwnedWork,
        ShowClaudeWork,
        ShowGeminiWork,
        ShowTeamWork
    ]
);

const ROOMS: [(&str, &str); 4] = [
    ("#alpha", "Try the workbench"),
    ("#mgmt", "Management"),
    ("#eng", "Engineering"),
    ("#qa", "Quality assurance"),
];
const SENDERS: [&str; 3] = ["CODEX", "Brian", "Nic"];

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum AppMode {
    #[default]
    Workbench,
    CursorOnboarding,
}

impl AppMode {
    fn from_setting(value: Option<&str>) -> Self {
        match value {
            Some("cursor") => Self::CursorOnboarding,
            _ => Self::Workbench,
        }
    }

    fn window_title(self) -> &'static str {
        match self {
            Self::Workbench => "Chinwag — Native coordination bus alpha",
            Self::CursorOnboarding => "Connect Cursor to Chinwag",
        }
    }
}

enum Connection {
    Disconnected,
    Connecting,
    Connected {
        endpoint: String,
        detail: String,
        send_available: bool,
        read_only: bool,
        signed_posting: bool,
        allowed_senders: Vec<String>,
    },
    Failed(String),
}

struct OpeningFlight {
    id: String,
    attempt_endpoint: String,
    view_endpoint: String,
    epoch: u64,
    generation: u64,
    action: OpeningAction,
}

#[derive(Clone)]
struct OpeningSelection {
    app: InstalledClient,
    endpoint: String,
    epoch: u64,
    inventory_generation: u64,
    connection_generation: u64,
    generation: u64,
    action: OpeningAction,
}

struct CursorSetupOptions {
    endpoint: String,
    installation_id: String,
}

#[derive(Clone)]
struct CursorConfirmationScope {
    endpoint: String,
    installation_id: String,
    request_id: String,
}

struct AppInventoryRead {
    inventory: Result<ClientInventory, String>,
    opening_status: Option<Result<OnboardingStatus, String>>,
    cursor_mcp_status: Option<Result<OnboardingStatus, String>>,
    vscode_mcp_status: Option<Result<OnboardingStatus, String>>,
}

impl AppInventoryRead {
    fn status_for(&self, action: OpeningAction) -> Option<&Result<OnboardingStatus, String>> {
        match action {
            OpeningAction::OrdinaryOpen => self.opening_status.as_ref(),
            OpeningAction::CursorMcpSetup => self.cursor_mcp_status.as_ref(),
            OpeningAction::VsCodeMcpSetup => self.vscode_mcp_status.as_ref(),
        }
    }
}

fn read_app_inventory(endpoint: &str, action: Option<OpeningAction>) -> AppInventoryRead {
    let inventory = BusClient::new(endpoint)
        .and_then(|client| client.clients())
        .map_err(|error| error.to_string());
    let opening_status = inventory
        .as_ref()
        .ok()
        .filter(|_| action.is_none() || action == Some(OpeningAction::OrdinaryOpen))
        .map(|_| {
            BusClient::new(endpoint)
                .and_then(|client| client.onboarding_status())
                .map_err(|error| error.to_string())
        });
    let cursor_mcp_status = inventory
        .as_ref()
        .ok()
        .filter(|inventory| {
            action == Some(OpeningAction::CursorMcpSetup)
                || (action.is_none()
                    && inventory.installations.as_ref().is_some_and(|installed| {
                        installed.apps.iter().any(|app| {
                            app.kind == chinwag_bus_client::ClientKind::Application
                                && app.family == "cursor"
                        })
                    }))
        })
        .map(|_| {
            BusClient::new(endpoint)
                .and_then(|client| client.cursor_mcp_setup_status())
                .map_err(|error| error.to_string())
        });
    let vscode_mcp_status = inventory
        .as_ref()
        .ok()
        .filter(|inventory| {
            action == Some(OpeningAction::VsCodeMcpSetup)
                || (action.is_none()
                    && inventory.installations.as_ref().is_some_and(|installed| {
                        installed.apps.iter().any(|app| {
                            app.kind == chinwag_bus_client::ClientKind::Application
                                && app.family == "visual_studio_code"
                        })
                    }))
        })
        .map(|_| {
            BusClient::new(endpoint)
                .and_then(|client| client.vscode_mcp_setup_status())
                .map_err(|error| error.to_string())
        });
    AppInventoryRead {
        inventory,
        opening_status,
        cursor_mcp_status,
        vscode_mcp_status,
    }
}

struct Workbench {
    mode: AppMode,
    configured_target_host: Option<String>,
    selected_cursor_copy: Option<String>,
    cursor_setup_options: Option<CursorSetupOptions>,
    conversation: Conversation,
    endpoint: Entity<InputState>,
    composer: Entity<TextareaState>,
    sender: &'static str,
    connection: Connection,
    drafts: HashMap<String, String>,
    draft_file: Option<DraftFile>,
    draft_warning: Option<String>,
    outbox: Option<Outbox>,
    outbox_warning: Option<String>,
    checking_id: Option<String>,
    receipt_origin: Option<(String, String)>,
    rejected_send: Option<String>,
    send_shortcut_held: bool,
    connection_generation: u64,
    client_inventory: DiscoveryPanel,
    inventory_task: Option<Task<()>>,
    mcp_http_panel: McpHttpPanel,
    mcp_http_task: Option<Task<()>>,
    mcp_http_copy_notice: Option<String>,
    mcp_http_details_expanded: bool,
    openings: Option<OpeningStore>,
    opening_warning: Option<String>,
    opening_tasks: HashMap<String, Task<()>>,
    opening_generations: HashMap<String, u64>,
    opening_sequence: u64,
    opening_epoch: u64,
    opening_selection: Option<OpeningSelection>,
    selection_task: Option<Task<()>>,
    load_task: Option<Task<()>>,
    send_task: Option<Task<()>>,
    check_task: Option<Task<()>>,
    _refresh_task: Option<Task<()>>,
    _subscriptions: Vec<Subscription>,
}

impl Workbench {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        Self::with_mode_settings(
            window,
            cx,
            std::env::var("CHINWAG_BUS_URL").unwrap_or_else(|_| "http://127.0.0.1:44331".into()),
            std::env::var_os("CHINWAG_ALPHA_DRAFTS_PATH").map(Into::into),
            AppMode::from_setting(std::env::var("CHINWAG_ALPHA_ONBOARDING").ok().as_deref()),
            std::env::var("CHINWAG_ALPHA_TARGET_HOST")
                .ok()
                .filter(|host| host == "Studio"),
        )
    }

    #[cfg(test)]
    fn with_settings(
        window: &mut Window,
        cx: &mut Context<Self>,
        initial_endpoint: String,
        draft_path: Option<std::path::PathBuf>,
    ) -> Self {
        Self::with_mode_settings(
            window,
            cx,
            initial_endpoint,
            draft_path,
            AppMode::Workbench,
            None,
        )
    }

    fn with_mode_settings(
        window: &mut Window,
        cx: &mut Context<Self>,
        initial_endpoint: String,
        draft_path: Option<std::path::PathBuf>,
        mode: AppMode,
        configured_target_host: Option<String>,
    ) -> Self {
        let (openings, opening_warning) = match draft_path.as_deref() {
            Some(path) => match openings::path_for_drafts(path).and_then(OpeningStore::open) {
                Ok(store) => (Some(store), None),
                Err(error) => (None, Some(format!("Opening history unavailable: {error}. Opening is disabled; existing records are untouched."))),
            },
            None => (None, Some("Opening apps requires persistent opening history. Start with the alpha launcher to configure its storage.".into())),
        };
        let (outbox, outbox_warning) = match draft_path.as_deref() {
            Some(path) => match outbox::path_for_drafts(path).and_then(Outbox::open) {
                Ok(outbox) => (Some(outbox), None),
                Err(error) => (None, Some(format!("Send history unavailable: {error}. New sends are disabled; existing files are untouched."))),
            },
            None => (None, Some("New sends require persistent send history. Start with the alpha launcher to configure its storage.".into())),
        };
        let (draft_file, drafts, draft_warning) = match draft_path {
            Some(path) => match DraftFile::open(path) {
                Ok((file, drafts)) => (Some(file), drafts, None),
                Err(error) => (
                    None,
                    HashMap::new(),
                    Some(format!(
                        "Draft persistence unavailable: {error}. Existing file left untouched."
                    )),
                ),
            },
            None => (None, HashMap::new(), None),
        };
        let initial_draft = drafts.get("#alpha").cloned().unwrap_or_default();
        let endpoint = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("http://127.0.0.1:44331")
                .default_value(initial_endpoint)
        });
        let composer = cx.new(|cx| {
            TextareaState::new(window, cx)
                .rows(3)
                .default_value(initial_draft)
                .placeholder("Write to the selected room…")
        });
        let endpoint_subscription = cx.subscribe_in(&endpoint, window, |this, _, event, _, cx| {
            if matches!(event, InputEvent::Change) {
                this.connection_generation = this.connection_generation.wrapping_add(1);
                this.load_task = None;
                this.inventory_task = None;
                this.client_inventory.clear();
                this.clear_mcp_http();
                this.selected_cursor_copy = None;
                this.cursor_setup_options = None;
                this.opening_epoch = this.opening_epoch.wrapping_add(1);
                this.opening_generations.clear();
                this.connection = Connection::Disconnected;
                this.conversation.messages.clear();
                this.conversation.last_error = None;
                reset_receipt_on_endpoint_change(&mut this.conversation.send_state);
                if !matches!(
                    this.conversation.send_state,
                    SendState::Uncertain { .. } | SendState::Sending { .. }
                ) {
                    this.receipt_origin = None;
                }
                cx.notify();
            } else if matches!(event, InputEvent::PressEnter { .. }) {
                this.load(cx);
            }
        });
        let composer_subscription =
            cx.subscribe_in(&composer, window, |this, input, event, _, cx| {
                if matches!(event, InputEvent::Change) {
                    this.drafts.insert(
                        this.conversation.room.clone(),
                        input.read(cx).value().to_string(),
                    );
                    this.persist_drafts();
                    cx.notify();
                }
            });
        let mut workbench = Self {
            mode,
            configured_target_host,
            selected_cursor_copy: None,
            cursor_setup_options: None,
            conversation: Conversation::new("#alpha"),
            endpoint,
            composer,
            sender: "CODEX",
            connection: Connection::Disconnected,
            drafts,
            draft_file,
            draft_warning,
            outbox,
            outbox_warning,
            checking_id: None,
            receipt_origin: None,
            rejected_send: None,
            send_shortcut_held: false,
            connection_generation: 0,
            client_inventory: DiscoveryPanel::default(),
            inventory_task: None,
            mcp_http_panel: McpHttpPanel::default(),
            mcp_http_task: None,
            mcp_http_copy_notice: None,
            mcp_http_details_expanded: false,
            openings,
            opening_warning,
            opening_tasks: HashMap::new(),
            opening_generations: HashMap::new(),
            opening_sequence: 0,
            opening_epoch: 0,
            opening_selection: None,
            selection_task: None,
            load_task: None,
            send_task: None,
            check_task: None,
            _refresh_task: None,
            _subscriptions: vec![endpoint_subscription, composer_subscription],
        };
        if mode == AppMode::CursorOnboarding {
            let endpoint = workbench.endpoint.read(cx).value().to_string();
            workbench.load_client_inventory(&endpoint, workbench.connection_generation, cx);
        } else {
            workbench.start_read_only_refresh(cx);
        }
        workbench
    }

    fn sending(&self) -> bool {
        matches!(self.conversation.send_state, SendState::Sending { .. })
    }

    fn persist_drafts(&mut self) {
        if let Some(file) = &self.draft_file {
            self.draft_warning = file
                .save(&self.drafts)
                .err()
                .map(|error| format!("Draft not saved: {error}. Text remains in this window."));
        }
    }

    fn can_send(&self) -> bool {
        if self.mode != AppMode::Workbench || self.outbox.is_none() {
            return false;
        }
        match &self.connection {
            Connection::Connected {
                send_available: true,
                allowed_senders,
                ..
            } => allowed_senders.iter().any(|sender| sender == self.sender),
            _ => false,
        }
    }

    fn sender_allowed(&self, sender: &str) -> bool {
        match &self.connection {
            Connection::Connected {
                allowed_senders, ..
            } => allowed_senders.iter().any(|allowed| allowed == sender),
            _ => true,
        }
    }

    fn connected_endpoint(&self) -> Option<String> {
        match &self.connection {
            Connection::Connected { endpoint, .. } => Some(endpoint.clone()),
            _ => None,
        }
    }

    fn start_read_only_refresh(&mut self, cx: &mut Context<Self>) {
        self._refresh_task = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(Duration::from_secs(2)).await;
                let request = this.update(cx, |this, _| {
                    if this.sending() {
                        return None;
                    }
                    this.connected_endpoint().map(|endpoint| {
                        (
                            endpoint,
                            this.conversation.room.clone(),
                            this.connection_generation,
                            this.conversation.load_generation(),
                        )
                    })
                });
                let Ok(request) = request else { break };
                let Some((endpoint, room, connection_generation, load_generation)) = request else {
                    continue;
                };
                let result = cx.background_spawn(async move {
                    BusClient::new(&endpoint)?.messages(&room, 100)
                }).await;
                let updated = this.update(cx, |this, cx| {
                    if this.connection_generation != connection_generation
                        || this.connected_endpoint().is_none()
                        || this.sending()
                    {
                        return;
                    }
                    match result {
                        Ok(messages) => {
                            if !this.conversation.apply_messages(load_generation, messages) {
                                let error = this.conversation.last_error.clone().unwrap_or_else(|| {
                                    "Room history changed while refreshing. Connect again to resume.".into()
                                });
                                this.connection = Connection::Failed(error);
                            }
                        }
                        Err(error) => {
                            let error = format!("Automatic refresh stopped: {error}. Connect again to resume.");
                            this.conversation.last_error = Some(error.clone());
                            this.connection = Connection::Failed(error);
                        }
                    }
                    cx.notify();
                });
                if updated.is_err() { break; }
            }
        }));
    }

    fn load(&mut self, cx: &mut Context<Self>) {
        if self.mode == AppMode::CursorOnboarding {
            let endpoint = self.endpoint.read(cx).value().to_string();
            self.load_client_inventory(&endpoint, self.connection_generation, cx);
        } else {
            self.load_connection(true, cx);
        }
    }

    fn load_connection(&mut self, request_inventory: bool, cx: &mut Context<Self>) {
        if self.sending() {
            return;
        }
        self.clear_mcp_http();
        let endpoint = self.endpoint.read(cx).value().to_string();
        if let Err(error) = BusClient::new(&endpoint) {
            self.inventory_task = None;
            self.client_inventory.clear();
            self.connection = Connection::Failed(error.to_string());
            cx.notify();
            return;
        }
        self.connection_generation = self.connection_generation.wrapping_add(1);
        let request_generation = self.connection_generation;
        let room = self.conversation.room.clone();
        let load_generation = self.conversation.select_room(&room);
        self.connection = Connection::Connecting;
        if request_inventory {
            self.load_client_inventory(&endpoint, request_generation, cx);
        }
        cx.notify();

        self.load_task = Some(cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move {
                    let client = BusClient::new(&endpoint).map_err(|error| error.to_string())?;
                    let status = client.status().map_err(|error| error.to_string())?;
                    let send_available = status_send_available(&status);
                    let allowed_senders = status_allowed_senders(&status);
                    let read_only = status.get("read_only").and_then(|value| value.as_bool()) == Some(true);
                    let signed_posting=status.get("mode").and_then(|value|value.as_str())==Some("fleet-signed-ui");
                    let messages = client
                        .messages(&room, 100)
                        .map_err(|error| error.to_string())?;
                    Ok::<_, String>((endpoint, status_detail(&status), send_available, read_only, signed_posting, allowed_senders, messages))
                })
                .await;
            let _ = this.update(cx, |this, cx| {
                if this.connection_generation != request_generation {
                    return;
                }
                match result {
                    Ok((endpoint, detail, send_available, read_only, signed_posting, allowed_senders, messages)) => {
                        if this.conversation.apply_messages(load_generation, messages) {
                            this.connection = Connection::Connected { endpoint, detail, send_available, read_only, signed_posting, allowed_senders };
                        } else {
                            this.connection = Connection::Failed(
                                this.conversation.last_error.clone().unwrap_or_else(|| {
                                    "The bus history could not be applied. Refresh to try a new read.".into()
                                }),
                            );
                        }
                    }
                    Err(error) => {
                        this.conversation.last_error = Some(error.clone());
                        this.connection = Connection::Failed(error);
                    }
                }
                cx.notify();
            });
        }));
    }

    fn clear_mcp_http(&mut self) {
        self.mcp_http_task = None;
        self.mcp_http_panel.clear();
        self.mcp_http_copy_notice = None;
        self.mcp_http_details_expanded = false;
    }

    fn check_mcp_http(&mut self, kind: McpHttpRequestKind, cx: &mut Context<Self>) {
        if self.mode != AppMode::Workbench
            || matches!(self.mcp_http_panel.state(), McpHttpState::Loading { .. })
            || (kind == McpHttpRequestKind::Copy && !self.mcp_http_panel.copy_eligible())
        {
            return;
        }
        let endpoint = self.endpoint.read(cx).value().to_string();
        let request = self
            .mcp_http_panel
            .begin(kind, endpoint, self.connection_generation);
        self.mcp_http_copy_notice = None;
        let requested_endpoint = request.endpoint().to_owned();
        self.mcp_http_task = Some(cx.spawn(async move |this, cx| {
            // The typed client validates this result against its own canonical
            // endpoint. Both explicit actions perform exactly one fresh GET.
            let result = cx.background_spawn(async move {
                BusClient::new(&requested_endpoint)
                    .and_then(|client| client.mcp_http_status())
                    .map_err(|_| "Runtime inbox observation unavailable".to_owned())
            }).await;
            let checked_at = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0);
            let _ = this.update(cx, |this, cx| {
                let endpoint = this.endpoint.read(cx).value().to_string();
                let configuration = this.mcp_http_panel.complete(
                    &request, &endpoint, this.connection_generation, checked_at, result,
                );
                if let Some(configuration) = configuration {
                    cx.write_to_clipboard(ClipboardItem::new_string(configuration));
                    this.mcp_http_copy_notice = Some(
                        "Configuration copied. In VS Code Local, use MCP: Open User Configuration and merge the new server and input entries. Enter the owner token only in VS Code’s password prompt. Copying does not install or reserve access.".into()
                    );
                }
                cx.notify();
            });
        }));
        cx.notify();
    }

    fn render_mcp_http(&self, cx: &mut Context<Self>) -> Div {
        let loading = matches!(self.mcp_http_panel.state(), McpHttpState::Loading { .. });
        let lines = self.mcp_http_panel.sample_lines();
        let endpoint = self.endpoint.read(cx).value().to_string();
        div()
            .flex()
            .flex_col()
            .gap_2()
            .border_t_1()
            .border_color(cx.theme().border)
            .pt_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        div()
                            .flex_1()
                            .text_sm()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child("Runtime HTTP inbox"),
                    )
                    .child(
                        Button::new("check-mcp-http")
                            .small()
                            .label(if loading {
                                "Checking…"
                            } else {
                                "Check MCP status"
                            })
                            .disabled(loading)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.check_mcp_http(McpHttpRequestKind::Check, cx)
                            })),
                    )
                    .child(
                        Button::new("copy-mcp-http-configuration")
                            .small()
                            .label("Copy VS Code setup")
                            .disabled(loading || !self.mcp_http_panel.copy_eligible())
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.check_mcp_http(McpHttpRequestKind::Copy, cx)
                            })),
                    ),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(cx.theme().muted_foreground)
                    .child(self.mcp_http_panel.message()),
            )
            .when(!lines.is_empty(), |this| {
                this.child(
                    div()
                        .text_xs()
                        .text_color(cx.theme().muted_foreground)
                        .child(lines[0].clone()),
                )
                .child(
                    Button::new("mcp-http-details")
                        .small()
                        .label(if self.mcp_http_details_expanded {
                            "Hide MCP details"
                        } else {
                            "MCP details"
                        })
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.mcp_http_details_expanded = !this.mcp_http_details_expanded;
                            cx.notify();
                        })),
                )
                .when(self.mcp_http_details_expanded, |this| {
                    this.child(
                        div()
                            .id("mcp-http-observation")
                            .max_h(px(145.))
                            .overflow_y_scroll()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(
                                div()
                                    .text_xs()
                                    .child(format!("Checked endpoint: {endpoint}")),
                            )
                            .children(lines.into_iter().skip(1).map(|line| {
                                div()
                                    .text_xs()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(line)
                            })),
                    )
                })
            })
            .when_some(self.mcp_http_copy_notice.clone(), |this, notice| {
                this.child(
                    div()
                        .text_xs()
                        .text_color(cx.theme().muted_foreground)
                        .child(notice),
                )
            })
    }

    fn load_client_inventory(
        &mut self,
        endpoint: &str,
        connection_generation: u64,
        cx: &mut Context<Self>,
    ) {
        if self.mode == AppMode::CursorOnboarding {
            self.cursor_setup_options = None;
        }
        let generation = self.client_inventory.begin(endpoint.into());
        let expected_endpoint = endpoint.to_owned();
        let requested_endpoint = expected_endpoint.clone();
        let action =
            (self.mode == AppMode::CursorOnboarding).then_some(OpeningAction::CursorMcpSetup);
        self.inventory_task = Some(cx.spawn(async move |this, cx| {
            let read = cx
                .background_spawn(async move { read_app_inventory(&requested_endpoint, action) })
                .await;
            let _ = this.update(cx, |this, cx| {
                if this.apply_client_inventory(
                    connection_generation,
                    generation,
                    &expected_endpoint,
                    read.inventory,
                    cx,
                ) {
                    if let Some(status) = read.opening_status {
                        this.client_inventory.complete_opening_status(
                            generation,
                            &expected_endpoint,
                            status,
                        );
                    }
                    if let Some(status) = read.cursor_mcp_status {
                        this.client_inventory.complete_cursor_mcp_status(
                            generation,
                            &expected_endpoint,
                            status,
                        );
                    }
                    if let Some(status) = read.vscode_mcp_status {
                        this.client_inventory.complete_vscode_mcp_status(
                            generation,
                            &expected_endpoint,
                            status,
                        );
                    }
                    this.sync_cursor_copy_selection();
                    cx.notify();
                }
            });
        }));
    }

    fn apply_client_inventory(
        &mut self,
        connection_generation: u64,
        generation: u64,
        endpoint: &str,
        result: Result<chinwag_bus_client::ClientInventory, String>,
        cx: &Context<Self>,
    ) -> bool {
        if self.connection_generation != connection_generation
            || self.endpoint.read(cx).value().as_ref() != endpoint
        {
            return false;
        }
        self.client_inventory.complete(generation, endpoint, result)
    }

    fn can_open_installation(&self, installation_id: &str, cx: &App) -> bool {
        self.can_act_on_installation(OpeningAction::OrdinaryOpen, installation_id, cx)
    }

    fn can_act_on_installation(
        &self,
        action: OpeningAction,
        installation_id: &str,
        cx: &App,
    ) -> bool {
        let endpoint = self.endpoint.read(cx).value().to_string();
        (self.mode == AppMode::Workbench || action == OpeningAction::CursorMcpSetup)
            && self.selection_task.is_none()
            && self.opening_tasks.is_empty()
            && self.client_inventory.endpoint.as_deref() == Some(endpoint.as_str())
            && self
                .client_inventory
                .action_copies(action)
                .iter()
                .any(|(id, _)| id == installation_id)
            && self.openings.as_ref().is_some_and(|store| {
                !store.blocks(&endpoint, installation_id)
                    && (action != OpeningAction::VsCodeMcpSetup
                        || !store.has_acknowledged_vscode_setup(&endpoint, installation_id))
            })
    }

    fn open_installation(&mut self, installation_id: &str, cx: &mut Context<Self>) {
        self.act_on_installation(OpeningAction::OrdinaryOpen, installation_id, cx);
    }

    fn act_on_installation(
        &mut self,
        action: OpeningAction,
        installation_id: &str,
        cx: &mut Context<Self>,
    ) {
        if !self.can_act_on_installation(action, installation_id, cx) {
            return;
        }
        let endpoint = self.endpoint.read(cx).value().to_string();
        let Some(app) = self.client_inventory.installed_copy(installation_id) else {
            return;
        };
        self.opening_sequence = self.opening_sequence.wrapping_add(1);
        let selection = OpeningSelection {
            app,
            endpoint: endpoint.clone(),
            epoch: self.opening_epoch,
            inventory_generation: self.client_inventory.generation(),
            connection_generation: self.connection_generation,
            generation: self.opening_sequence,
            action,
        };
        self.opening_selection = Some(selection.clone());
        self.client_inventory.set_action_notice(action, None);
        self.selection_task = Some(cx.spawn(async move |this, cx| {
            let read = cx
                .background_spawn(async move { read_app_inventory(&endpoint, Some(action)) })
                .await;
            let _ = this.update(cx, |this, cx| {
                this.apply_selection_refresh(&selection, read, cx);
                cx.notify();
            });
        }));
        cx.notify();
    }

    fn apply_selection_refresh(
        &mut self,
        selection: &OpeningSelection,
        read: AppInventoryRead,
        cx: &mut Context<Self>,
    ) -> bool {
        if self.opening_selection.as_ref().is_none_or(|current| {
            current.generation != selection.generation || current.action != selection.action
        }) {
            return false;
        }
        self.selection_task = None;
        self.opening_selection = None;
        if self.opening_epoch != selection.epoch
            || self.connection_generation != selection.connection_generation
            || self.endpoint.read(cx).value().as_ref() != selection.endpoint
            || self.client_inventory.generation() != selection.inventory_generation
            || self.client_inventory.endpoint.as_deref() != Some(selection.endpoint.as_str())
        {
            return false;
        }
        let selected_still_matches = read
            .inventory
            .as_ref()
            .ok()
            .and_then(|inventory| inventory.installations.as_ref())
            .and_then(|installed| installed.apps.iter().find(|app| app.id == selection.app.id))
            .is_some_and(|app| {
                app.family == selection.app.family
                    && app.kind == selection.app.kind
                    && app.location == selection.app.location
                    && app.version == selection.app.version
            });
        let status_valid = read.status_for(selection.action).is_some_and(|status| {
            status.as_ref().is_ok_and(|status| {
                status.validate().is_ok()
                    && status.native_open_allowed
                    && status.openable_installation_ids.contains(&selection.app.id)
            })
        });
        let refreshed =
            read.inventory.is_ok() && read.status_for(selection.action).is_some_and(Result::is_ok);
        self.client_inventory.complete(
            selection.inventory_generation,
            &selection.endpoint,
            read.inventory,
        );
        if let Some(status) = read.opening_status {
            self.client_inventory.complete_opening_status(
                selection.inventory_generation,
                &selection.endpoint,
                status,
            );
        } else if selection.action == OpeningAction::OrdinaryOpen {
            self.client_inventory.opening_status = None;
        }
        if let Some(status) = read.cursor_mcp_status {
            self.client_inventory.complete_cursor_mcp_status(
                selection.inventory_generation,
                &selection.endpoint,
                status,
            );
        } else if selection.action == OpeningAction::CursorMcpSetup {
            self.client_inventory.cursor_mcp_status = None;
        }
        if let Some(status) = read.vscode_mcp_status {
            self.client_inventory.complete_vscode_mcp_status(
                selection.inventory_generation,
                &selection.endpoint,
                status,
            );
        } else if selection.action == OpeningAction::VsCodeMcpSetup {
            self.client_inventory.vscode_mcp_status = None;
        }
        if !selected_still_matches || !status_valid {
            self.client_inventory.set_action_notice(selection.action, Some(if refreshed {
                "The selected app changed or is no longer available. Select an app again. No opening was started."
            } else {
                "The selected app could not be checked. Find apps and select it again. No opening was started."
            }.into()));
            return true;
        }
        if !self.can_act_on_installation(selection.action, &selection.app.id, cx) {
            self.client_inventory.set_action_notice(
                selection.action,
                Some(
                    "This app has an opening or setup to check first. No new action was started."
                        .into(),
                ),
            );
            return true;
        }
        self.prepare_selected_opening(selection.action, &selection.endpoint, &selection.app.id, cx);
        true
    }

    fn prepare_selected_opening(
        &mut self,
        action: OpeningAction,
        endpoint: &str,
        installation_id: &str,
        cx: &mut Context<Self>,
    ) {
        let attempt = match self
            .openings
            .as_mut()
            .expect("eligibility requires storage")
            .prepare(action, endpoint, installation_id)
        {
            Ok(attempt) => attempt,
            Err(error) => {
                self.opening_warning = Some(format!("Opening was not started: {error}"));
                cx.notify();
                return;
            }
        };
        self.opening_warning = None;
        self.start_opening_request(attempt, false, cx);
    }

    fn check_opening(&mut self, id: &str, cx: &mut Context<Self>) {
        if self.opening_tasks.contains_key(id) {
            return;
        }
        let Some(attempt) = self.openings.as_ref().and_then(|store| {
            store
                .attempts
                .iter()
                .find(|attempt| attempt.id == id && attempt.unresolved())
                .cloned()
        }) else {
            return;
        };
        self.start_opening_request(attempt, true, cx);
    }

    fn start_opening_request(
        &mut self,
        attempt: OpeningAttempt,
        check_only: bool,
        cx: &mut Context<Self>,
    ) {
        self.opening_sequence = self.opening_sequence.wrapping_add(1);
        let generation = self.opening_sequence;
        let epoch = self.opening_epoch;
        let view_endpoint = self.endpoint.read(cx).value().to_string();
        let request_id = attempt.id.clone();
        self.opening_generations
            .insert(request_id.clone(), generation);
        let flight = OpeningFlight {
            id: request_id.clone(),
            attempt_endpoint: attempt.endpoint.clone(),
            view_endpoint,
            epoch,
            generation,
            action: attempt.action,
        };
        let task = cx.spawn(async move |this, cx| {
            let result = cx
                .background_spawn(async move {
                    attempt
                        .perform(check_only)
                        .map_err(|error| error.to_string())
                })
                .await;
            let _ = this.update(cx, |this, cx| {
                // Endpoint edits invalidate the receipt, but an HTTP worker may
                // still be running. Retain its flight gate until it returns.
                this.opening_tasks.remove(&flight.id);
                this.apply_opening_result(&flight, result, cx);
                cx.notify();
            });
        });
        self.opening_tasks.insert(request_id, task);
        cx.notify();
    }

    fn apply_opening_result(
        &mut self,
        flight: &OpeningFlight,
        result: Result<Option<NativeOpenReceipt>, String>,
        cx: &Context<Self>,
    ) -> bool {
        if self.opening_epoch != flight.epoch
            || self.endpoint.read(cx).value().as_ref() != flight.view_endpoint
            || self.opening_generations.get(&flight.id) != Some(&flight.generation)
        {
            return false;
        }
        let Some(store) = &mut self.openings else {
            return false;
        };
        if !store.attempts.iter().any(|attempt| {
            attempt.id == flight.id
                && attempt.endpoint == flight.attempt_endpoint
                && attempt.action == flight.action
        }) {
            return false;
        }
        self.opening_tasks.remove(&flight.id);
        self.opening_generations.remove(&flight.id);
        let update = match result {
            Ok(Some(receipt)) => store.apply_receipt(&flight.id, receipt),
            Ok(None) => store.mark_uncertain(&flight.id, "The host has no saved receipt. This does not prove the app stayed closed. It was not opened again."),
            Err(error) => store.mark_uncertain(&flight.id, &error),
        };
        self.opening_warning = update.err().map(|error| format!("Opening status was not accepted or saved: {error}. Original attempt retained; check its status."));
        if flight.action == OpeningAction::CursorMcpSetup {
            self.cursor_setup_options = None;
        }
        true
    }

    fn select_room(&mut self, room: &str, window: &mut Window, cx: &mut Context<Self>) {
        if self.sending() || room == self.conversation.room {
            return;
        }
        self.drafts.insert(
            self.conversation.room.clone(),
            self.composer.read(cx).value().to_string(),
        );
        self.persist_drafts();
        let should_load = self.connected_endpoint().is_some()
            || matches!(self.connection, Connection::Connecting);
        self.clear_mcp_http();
        self.connection_generation = self.connection_generation.wrapping_add(1);
        self.load_task = None;
        self.inventory_task = None;
        self.client_inventory.clear();
        self.conversation.select_room(room);
        let draft = self.drafts.get(room).cloned().unwrap_or_default();
        self.composer.update(cx, |state, cx| {
            state.set_value(draft, window, cx);
        });
        if should_load {
            self.load_connection(false, cx);
        } else {
            self.connection = Connection::Disconnected;
        }
        cx.notify();
    }

    fn send(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.sending() || !self.can_send() {
            return;
        }
        let Some(endpoint) = self.connected_endpoint() else {
            return;
        };
        let body = self.composer.read(cx).value().to_string();
        if body.trim().is_empty() {
            return;
        }
        let room = self.conversation.room.clone();
        let request = SendRequest {
            sender: self.sender.into(),
            room: room.clone(),
            body: body.clone(),
            to: None,
            task_id: None,
        };
        let attempt = match self
            .outbox
            .as_mut()
            .expect("can_send requires outbox")
            .prepare(&endpoint, request.clone())
        {
            Ok(attempt) => attempt,
            Err(error) => {
                self.outbox_warning = Some(error.to_string());
                self.conversation.last_error = Some(error.to_string());
                cx.notify();
                return;
            }
        };
        self.outbox_warning = None;
        let generation = match self.conversation.begin_send(&body) {
            Ok(generation) => generation,
            Err(error) => {
                self.update_attempt(&attempt.id, AttemptState::Rejected(error.clone()));
                self.conversation.last_error = Some(error);
                cx.notify();
                return;
            }
        };
        self.rejected_send = None;
        self.receipt_origin = Some((endpoint.clone(), room.clone()));
        let request_id = attempt.id;
        let id_for_post = request_id.clone();
        cx.notify();
        self.send_task = Some(cx.spawn_in(window, async move |this, cx| {
            let result = cx
                .background_spawn(async move {
                    let client = BusClient::new(&endpoint)?;
                    client.send_with_id(&request, &id_for_post)
                })
                .await;
            let _ = this.update_in(cx, |this, window, cx| {
                match result {
                    Ok(receipt) => {
                        this.update_attempt(
                            &request_id,
                            AttemptState::Delivered(Box::new(receipt.clone())),
                        );
                        if this.conversation.confirm_send(generation, receipt) {
                            // Do not erase a new draft typed while the request was in flight.
                            if this.composer.read(cx).value().as_ref() == body {
                                this.drafts.remove(&room);
                                this.persist_drafts();
                                this.composer.update(cx, |state, cx| {
                                    state.set_value("", window, cx);
                                });
                            }
                            this.composer
                                .update(cx, |state, cx| state.focus(window, cx));
                        }
                    }
                    Err(error) => {
                        this.rejected_send = explicit_rejection(&error);
                        let state = match &this.rejected_send {
                            Some(rejection) => AttemptState::Rejected(rejection.clone()),
                            None => AttemptState::Uncertain(error.to_string()),
                        };
                        this.update_attempt(&request_id, state);
                        this.conversation.fail_send(generation, error.to_string());
                    }
                }
                cx.notify();
            });
        }));
    }

    fn update_attempt(&mut self, id: &str, state: AttemptState) {
        if let Some(outbox) = &mut self.outbox {
            self.outbox_warning = outbox.update(id,state).err().map(|error|
                format!("Send history update could not be saved: {error}. The original pending ID is retained; use Check send receipt."));
        }
    }

    fn check_send_receipt(&mut self, id: &str, window: &mut Window, cx: &mut Context<Self>) {
        if self.checking_id.is_some() {
            return;
        }
        let Some(attempt) = self.outbox.as_ref().and_then(|outbox| {
            outbox
                .attempts
                .iter()
                .find(|attempt| attempt.id == id && attempt.visible_in_send_history())
                .cloned()
        }) else {
            return;
        };
        self.checking_id = Some(attempt.id.clone());
        let endpoint = attempt.endpoint.clone();
        let id = attempt.id.clone();
        cx.notify();
        self.check_task = Some(cx.spawn_in(window, async move |this,cx| {
            let result = cx.background_spawn(async move {
                BusClient::new(&endpoint)?.operation(&id)
            }).await;
            let _ = this.update_in(cx, |this,window,cx| {
                this.checking_id=None;
                match result {
                    Ok(operation) => {
                        let updated = this.outbox.as_mut().expect("attempt came from outbox").apply_status(&attempt.id, operation);
                        match updated {
                            Ok(AttemptState::Delivered(receipt)) => {
                                this.outbox_warning=None;
                                this.observe_reconciled(&attempt,*receipt,window,cx);
                            }
                            Ok(_) => { this.outbox_warning=None; }
                            Err(error) => this.outbox_warning=Some(format!("Send receipt check was not accepted: {error}. Original attempt retained.")),
                        }
                    }
                    Err(error) => this.update_attempt(&attempt.id,AttemptState::Uncertain(format!("Send receipt check could not confirm this attempt: {error}. It was not resent."))),
                }
                cx.notify();
            });
        }));
    }

    fn observe_reconciled(
        &mut self,
        attempt: &Attempt,
        receipt: SendReceipt,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.connected_endpoint().as_deref() != Some(attempt.endpoint.as_str())
            || self.conversation.room != attempt.request.room
        {
            return;
        }
        self.conversation.apply_messages(
            self.conversation.load_generation(),
            vec![receipt.message.clone()],
        );
        if !self.sending() {
            self.conversation.send_state = SendState::Delivered {
                id: receipt.message.id,
                seq: receipt.message.seq,
                transport: receipt.ack.transport,
                sig_verified: receipt.message.sig_verified && receipt.ack.sig_verified,
            };
            self.rejected_send = None;
            self.receipt_origin = Some((attempt.endpoint.clone(), attempt.request.room.clone()));
        }
        if !self.sending() && self.composer.read(cx).value().as_ref() == attempt.request.body {
            self.drafts.remove(&attempt.request.room);
            self.persist_drafts();
            self.composer
                .update(cx, |state, cx| state.set_value("", window, cx));
        }
    }

    fn message_row(message: &BusMessage, cx: &App) -> Div {
        div()
            .flex()
            .gap_3()
            .py_4()
            .border_b_1()
            .border_color(cx.theme().border)
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_center()
                    .size(px(32.))
                    .flex_shrink_0()
                    .rounded_md()
                    .bg(cx.theme().secondary)
                    .text_sm()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(initials(&message.sender)),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .min_w_0()
                    .flex_1()
                    .gap_1()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(
                                div()
                                    .text_sm()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child(message.sender.clone()),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(short_time(&message.ts_iso)),
                            ),
                    )
                    .child(div().text_sm().child(message.body.clone()))
                    .child(
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child(format!(
                                "#{} · {} · {}",
                                message.seq,
                                message.id,
                                signature_label(message.sig_verified),
                            )),
                    ),
            )
    }

    fn receipt_line(&self) -> (String, bool) {
        match &self.conversation.send_state {
            SendState::Idle => match &self.conversation.last_error {
                Some(error) => (error.clone(), true),
                None => (
                    "Cmd-Enter to send · Enter for a new line · Agents are not woken.".into(),
                    false,
                ),
            },
            SendState::Sending { .. } => {
                ("Sending once. Waiting for the bus receipt…".into(), false)
            }
            SendState::Delivered {
                id,
                seq,
                transport,
                sig_verified,
            } => {
                let subscribers = self.outbox.as_ref().and_then(|outbox| {
                    outbox
                        .attempts
                        .iter()
                        .filter(|attempt| {
                            self.receipt_origin
                                .as_ref()
                                .is_some_and(|(endpoint, room)| {
                                    attempt.endpoint == *endpoint && attempt.request.room == *room
                                })
                        })
                        .filter_map(Attempt::receipt)
                        .find(|receipt| {
                            receipt.message.id == *id
                                && receipt.message.seq == *seq
                                && receipt.ack.transport == *transport
                        })
                        .map(|receipt| receipt.ack.subscribers_notified)
                });
                (
                    format!(
                        "{} · #{} · {} · {}{}",
                        outbox::receipt_summary(transport, subscribers),
                        seq,
                        id,
                        signature_label(*sig_verified),
                        self.receipt_origin
                            .as_ref()
                            .map(|(endpoint, room)| format!(" · {room} at {endpoint}"))
                            .unwrap_or_default(),
                    ),
                    !outbox::isolated_transport(transport),
                )
            }
            SendState::Uncertain { error, .. } => (
                if let Some(rejection) = &self.rejected_send {
                    format!(
                        "Send rejected{}. Draft kept. {rejection}",
                        self.receipt_origin
                            .as_ref()
                            .map(|(endpoint, room)| format!(" by {endpoint} for {room}"))
                            .unwrap_or_default()
                    )
                } else {
                    format!(
                        "Delivery unconfirmed{}. Draft kept; do not resend blindly. {error}",
                        self.receipt_origin
                            .as_ref()
                            .map(|(endpoint, room)| format!(" to {room} at {endpoint}"))
                            .unwrap_or_default()
                    )
                },
                true,
            ),
        }
    }

    fn sync_cursor_copy_selection(&mut self) {
        if self.mode != AppMode::CursorOnboarding {
            return;
        }
        let copies = self.client_inventory.cursor_copies();
        if self
            .selected_cursor_copy
            .as_ref()
            .is_some_and(|selected| copies.iter().any(|(id, _)| id == selected))
        {
            return;
        }
        self.selected_cursor_copy = (copies.len() == 1).then(|| copies[0].0.clone());
        self.cursor_setup_options = None;
    }

    fn cursor_setup_was_sent(&self, endpoint: &str, installation_id: &str) -> bool {
        self.openings
            .as_ref()
            .and_then(|store| store.latest_acknowledged_cursor_setup(endpoint, installation_id))
            .is_some()
    }

    fn cursor_confirmation_scope(
        &self,
        endpoint: &str,
        installation_id: &str,
    ) -> Option<CursorConfirmationScope> {
        let attempt = self
            .openings
            .as_ref()?
            .latest_acknowledged_cursor_setup(endpoint, installation_id)?;
        Some(CursorConfirmationScope {
            endpoint: endpoint.into(),
            installation_id: installation_id.into(),
            request_id: attempt.id.clone(),
        })
    }

    fn cursor_human_confirmation(&self, endpoint: &str, installation_id: &str) -> Option<u64> {
        self.openings
            .as_ref()?
            .latest_acknowledged_cursor_setup(endpoint, installation_id)?
            .human_confirmation
            .as_ref()
            .map(|confirmation| confirmation.confirmed_at_unix_ms)
    }

    fn confirm_cursor_tools(&mut self, scope: &CursorConfirmationScope, cx: &mut Context<Self>) {
        if self.mode != AppMode::CursorOnboarding
            || self.endpoint.read(cx).value().as_ref() != scope.endpoint
            || self.selected_cursor_copy.as_deref() != Some(scope.installation_id.as_str())
            || self.client_inventory.endpoint.as_deref() != Some(scope.endpoint.as_str())
            || !self
                .client_inventory
                .installed_copy(&scope.installation_id)
                .is_some_and(|app| app.family == "cursor")
            || self.selection_task.is_some()
            || !self.opening_tasks.is_empty()
        {
            return;
        }
        let Some(store) = &mut self.openings else {
            return;
        };
        if store.blocks(&scope.endpoint, &scope.installation_id)
            || store
                .latest_acknowledged_cursor_setup(&scope.endpoint, &scope.installation_id)
                .is_none_or(|attempt| attempt.id != scope.request_id)
        {
            return;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok());
        self.opening_warning = match now {
            Some(now) => store.confirm_cursor_tools_listed(&scope.endpoint, &scope.installation_id, now)
                .err().map(|error| format!("Your confirmation could not be saved: {error}. The original setup receipt is retained.")),
            None => Some("Your confirmation could not be saved because the date is unavailable. The original setup receipt is retained.".into()),
        };
        self.cursor_setup_options = None;
        cx.notify();
    }

    fn start_cursor_setup(&mut self, cx: &mut Context<Self>) {
        let endpoint = self.endpoint.read(cx).value().to_string();
        let Some(id) = self.selected_cursor_copy.clone() else {
            return;
        };
        if self.cursor_setup_was_sent(&endpoint, &id) {
            return;
        }
        self.act_on_installation(OpeningAction::CursorMcpSetup, &id, cx);
    }

    fn show_cursor_setup_options(&mut self, cx: &mut Context<Self>) {
        let endpoint = self.endpoint.read(cx).value().to_string();
        let Some(id) = self.selected_cursor_copy.clone() else {
            return;
        };
        if self.cursor_setup_was_sent(&endpoint, &id)
            && self.can_act_on_installation(OpeningAction::CursorMcpSetup, &id, cx)
        {
            self.cursor_setup_options = Some(CursorSetupOptions {
                endpoint,
                installation_id: id,
            });
            cx.notify();
        }
    }

    fn send_another_cursor_setup(&mut self, cx: &mut Context<Self>) {
        let Some(scope) = self.cursor_setup_options.take() else {
            return;
        };
        if self.endpoint.read(cx).value().as_ref() == scope.endpoint
            && self.selected_cursor_copy.as_deref() == Some(scope.installation_id.as_str())
            && self.cursor_setup_was_sent(&scope.endpoint, &scope.installation_id)
            && self.can_act_on_installation(
                OpeningAction::CursorMcpSetup,
                &scope.installation_id,
                cx,
            )
        {
            self.act_on_installation(OpeningAction::CursorMcpSetup, &scope.installation_id, cx);
        }
        cx.notify();
    }

    fn cursor_target_host(&self) -> String {
        match &self.client_inventory.state {
            InventoryState::Ready(inventory) => inventory.host_label.clone(),
            _ => self
                .configured_target_host
                .clone()
                .unwrap_or_else(|| "the configured host".into()),
        }
    }

    fn find_cursor(&mut self, cx: &mut Context<Self>) {
        if matches!(self.client_inventory.state, InventoryState::Loading)
            || self.selection_task.is_some()
            || !self.opening_tasks.is_empty()
        {
            return;
        }
        let endpoint = self.endpoint.read(cx).value().to_string();
        self.load_client_inventory(&endpoint, self.connection_generation, cx);
        cx.notify();
    }

    fn render_cursor_onboarding(&self, cx: &mut Context<Self>) -> Div {
        let host = self.cursor_target_host();
        let loading = matches!(self.client_inventory.state, InventoryState::Loading);
        let ready = matches!(self.client_inventory.state, InventoryState::Ready(_));
        let unavailable = matches!(self.client_inventory.state, InventoryState::Unavailable(_));
        let busy = self.selection_task.is_some() || !self.opening_tasks.is_empty();
        let copies = self.client_inventory.cursor_copies();
        let selected = self
            .selected_cursor_copy
            .clone()
            .filter(|id| copies.iter().any(|(copy, _)| copy == id));
        let enabled = selected
            .as_ref()
            .is_some_and(|id| self.can_act_on_installation(OpeningAction::CursorMcpSetup, id, cx));
        let copy_rows = copies
            .iter()
            .enumerate()
            .map(|(index, (id, label))| {
                let chosen = selected.as_ref() == Some(id);
                let id = id.clone();
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        Button::new(("cursor-copy", index))
                            .w_full()
                            .label(label.clone())
                            .selected(chosen)
                            .disabled(loading || busy)
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.selected_cursor_copy = Some(id.clone());
                                this.cursor_setup_options = None;
                                cx.notify();
                            })),
                    )
                    .when_some(
                        self.client_inventory
                            .cursor_copy_disambiguation(&copies[index].0),
                        |this, detail| {
                            this.child(
                                div()
                                    .px_2()
                                    .text_xs()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(detail),
                            )
                        },
                    )
            })
            .collect::<Vec<_>>();
        let endpoint = self.endpoint.read(cx).value().to_string();
        let mut attempts = Vec::new();
        let mut terminal_count = 0;
        if let Some(store) = &self.openings {
            for attempt in store.attempts.iter().rev() {
                let blocking_cursor_open = attempt.unresolved()
                    && copies.iter().any(|(id, _)| id == &attempt.installation_id);
                if attempt.action != OpeningAction::CursorMcpSetup && !blocking_cursor_open {
                    continue;
                }
                if !attempt.unresolved() {
                    if terminal_count >= 4 {
                        continue;
                    }
                    terminal_count += 1;
                }
                attempts.push(attempt.clone());
            }
        }
        attempts.sort_by_key(|attempt| !attempt.unresolved());
        let request_sent = selected
            .as_ref()
            .is_some_and(|id| self.cursor_setup_was_sent(&endpoint, id));
        let confirmation_scope = selected
            .as_ref()
            .and_then(|id| self.cursor_confirmation_scope(&endpoint, id));
        let human_confirmation = selected
            .as_ref()
            .and_then(|id| self.cursor_human_confirmation(&endpoint, id));
        let can_confirm = confirmation_scope.is_some()
            && !loading
            && !busy
            && selected.as_ref().is_some_and(|id| {
                self.openings
                    .as_ref()
                    .is_some_and(|store| !store.blocks(&endpoint, id))
            });
        let show_setup_options = self.cursor_setup_options.as_ref().is_some_and(|scope| {
            scope.endpoint == endpoint
                && selected.as_deref() == Some(scope.installation_id.as_str())
        });
        let history_rows = attempts
            .iter()
            .enumerate()
            .map(|(index, attempt)| {
                let checking = self.opening_tasks.contains_key(&attempt.id);
                let id = attempt.id.clone();
                let copy = copies
                    .iter()
                    .find(|(copy, _)| copy == &attempt.installation_id)
                    .map(|(_, label)| label.clone())
                    .unwrap_or_else(|| {
                        format!(
                            "Cursor · Copy {}",
                            openings::short_installation_id(&attempt.installation_id)
                        )
                    });
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .py_2()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(div().flex_1().text_sm().child(copy))
                            .when(attempt.unresolved(), |this| {
                                this.child(
                                    Button::new(("cursor-setup-status", index))
                                        .small()
                                        .label(if checking {
                                            "Checking…"
                                        } else {
                                            attempt.action.check_label()
                                        })
                                        .disabled(busy || loading)
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.check_opening(&id, cx)
                                        })),
                                )
                            }),
                    )
                    .when(attempt.endpoint != endpoint, |this| {
                        this.child(
                            div()
                                .text_xs()
                                .text_color(cx.theme().muted_foreground)
                                .child("Saved request · status checks use its original host"),
                        )
                    })
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child(if let Some(confirmation) = &attempt.human_confirmation {
                                format!("Enabled with tools in Cursor — confirmed by you · {} · historical report",
                                    confirmation_time(confirmation.confirmed_at_unix_ms))
                            } else if attempt.action == OpeningAction::CursorMcpSetup
                                && matches!(&attempt.state, openings::OpeningState::Receipt(receipt)
                                    if receipt.state == chinwag_bus_client::NativeOpenState::OpenedOrReused)
                            {
                                "Setup request sent · Cursor approval and MCP connection are not verified here".into()
                            } else {
                                attempt.summary()
                            }),
                    )
            })
            .collect::<Vec<_>>();
        let state_text = if loading {
            format!("Looking for Cursor on {host}…")
        } else if unavailable {
            format!(
                "Chinwag could not reach {host}. Check the host connection, then choose Find Cursor again."
            )
        } else if ready && copies.is_empty() {
            format!(
                "No Cursor application was observed on {host}. Check that Cursor is installed there, then find again."
            )
        } else if copies.len() > 1 && selected.is_none() {
            "Choose the Cursor copy you want to set up.".into()
        } else if selected.as_ref().is_some_and(|id| {
            self.openings
                .as_ref()
                .is_some_and(|store| store.blocks(&endpoint, id))
        }) {
            "A saved request for this copy needs a status check. Use its status button below before starting another setup.".into()
        } else if human_confirmation.is_some() {
            "Your dated report is saved for this Cursor copy. It does not establish a live connection or an inbox read.".into()
        } else if request_sent {
            "macOS acknowledged the setup handoff. This window cannot verify Cursor approval or an MCP connection.".into()
        } else if ready && selected.is_some() && !enabled && !busy && self.openings.is_some() {
            "This host has not made the selected Cursor copy available for setup. Check the host setup notice below, then find again.".into()
        } else if ready {
            "This copy will be checked again before setup begins.".into()
        } else {
            "Find Cursor on your target host to get started.".into()
        };
        let setup_notice = self
            .client_inventory
            .cursor_mcp_notice
            .as_ref()
            .map(|notice| notice.replace("Find apps", "Find Cursor"));
        div().size_full().child(div().id("cursor-onboarding").size_full().flex().flex_col()
            .bg(cx.theme().background).text_color(cx.theme().foreground)
            .child(div().id("cursor-onboarding-content").flex_1().min_h_0().overflow_y_scroll()
                .flex().flex_col().gap_6().p_8()
                .child(div().flex().flex_col().gap_2()
                    .child(div().text_2xl().font_weight(FontWeight::BOLD).child("Connect Cursor to Chinwag"))
                    .child(div().text_sm().text_color(cx.theme().muted_foreground)
                        .child("Allow Cursor to use Chinwag’s read-only #mgmt inbox.")))
                .child(div().id("cursor-target-host").flex().flex_col().gap_1()
                    .child(div().text_sm().font_weight(FontWeight::SEMIBOLD).child(format!("Target host: {host}")))
                    .child(div().text_sm().text_color(cx.theme().muted_foreground)
                        .child(if human_confirmation.is_some() {
                            "Your confirmation is saved as a historical report.".into()
                        } else if ready { format!("Approve access in Cursor on {host}.") }
                            else { "Checking the configured target before setup is available.".into() })))
                .child(div().flex().flex_col().gap_3()
                    .child(div().flex().items_center().gap_3()
                        .child(div().flex_1().text_sm().font_weight(FontWeight::SEMIBOLD).child("Cursor application"))
                        .child(Button::new("find-cursor").small()
                            .label(if loading { "Finding Cursor…" } else { "Find Cursor" })
                            .disabled(loading || busy)
                            .on_click(cx.listener(|this, _, _, cx| this.find_cursor(cx)))))
                    .child(div().text_sm().text_color(if unavailable { cx.theme().danger } else { cx.theme().muted_foreground }).child(state_text))
                    .children(copy_rows)
                    .when_some(self.client_inventory.coverage_warning(), |this, _| this.child(
                        div().text_xs().text_color(cx.theme().muted_foreground)
                            .child("This is a bounded snapshot. Some apps may be missing; see Details."))))
                .child(div().flex().flex_col().gap_3()
                    .child(Button::new("cursor-onboarding-setup").primary().w_full().h(px(44.))
                        .label(if self.selection_task.is_some() { "Checking selected Cursor…" }
                            else if !self.opening_tasks.is_empty() { "Checking setup…" }
                            else if request_sent { "Setup request sent" }
                            else { "Set up Cursor" })
                        .disabled(request_sent || !enabled || loading)
                        .on_click(cx.listener(|this, _, _, cx| this.start_cursor_setup(cx))))
                    .child(div().text_sm().text_color(cx.theme().muted_foreground)
                        .child(if human_confirmation.is_some() {
                            "No live connection, account, lease or model activity is inferred from your report.".into()
                        } else if request_sent {
                            format!("In Cursor on {host}, check Customize → MCPs for the Chinwag inbox. For diagnostics, open Output (Cmd+Shift+U) and select MCP Logs.")
                        } else {
                            format!("This adds the existing Chinwag inbox to Cursor on {host}. Approve it there when Cursor asks. An acknowledgement here does not confirm a connection.")
                        }))
                    .when_some(human_confirmation, |this, at_ms| this.child(
                        div().id("cursor-human-confirmation").flex().flex_col().gap_1()
                            .child(div().text_sm().font_weight(FontWeight::SEMIBOLD)
                                .child("Enabled with tools in Cursor — confirmed by you"))
                            .child(div().text_sm().text_color(cx.theme().muted_foreground)
                                .child(format!("Reported {} · historical confirmation", confirmation_time(at_ms))))))
                    .when(human_confirmation.is_none(), |this| this.when_some(confirmation_scope, |this, scope| this.child(
                        Button::new("cursor-confirm-tools").w_full().label("Cursor shows enabled and tools")
                            .disabled(!can_confirm)
                            .on_click(cx.listener(move |this, _, _, cx| this.confirm_cursor_tools(&scope, cx))))))
                    .when(request_sent, |this| this.child(
                        Button::new("cursor-setup-options").small().label("Show setup options")
                            .disabled(!enabled || loading)
                            .on_click(cx.listener(|this, _, _, cx| this.show_cursor_setup_options(cx)))))
                    .when(request_sent && show_setup_options, |this| this.child(
                        div().flex().flex_col().gap_2()
                            .child(div().text_sm().text_color(cx.theme().muted_foreground)
                                .child("Sending another request opens Cursor’s setup approval again. It does not check whether the earlier installation succeeded."))
                            .child(Button::new("cursor-send-another-setup").small().label("Send another setup request")
                                .disabled(!enabled || loading)
                                .on_click(cx.listener(|this, _, _, cx| this.send_another_cursor_setup(cx))))))
                    .when_some(setup_notice, |this, notice| this.child(
                        div().id("cursor-setup-notice").text_sm().text_color(cx.theme().danger).child(notice)))
                    .when_some(self.opening_warning.clone(), |this, warning| this.child(
                        div().id("cursor-setup-storage-warning").text_sm().text_color(cx.theme().danger).child(warning))))
                .when(!history_rows.is_empty(), |this| this.child(div().id("cursor-setup-history")
                    .flex().flex_col().gap_1().border_t_1().border_color(cx.theme().border).pt_4()
                    .child(div().text_sm().font_weight(FontWeight::SEMIBOLD).child("Recent requests"))
                    .children(history_rows)))
                .child(Button::new("cursor-onboarding-details").small()
                    .label(if self.client_inventory.details_expanded { "Hide details" } else { "Details" })
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.client_inventory.details_expanded = !this.client_inventory.details_expanded;
                        cx.notify();
                    })))
                .when(self.client_inventory.details_expanded, |this| this.child(
                    div().id("cursor-onboarding-diagnostics").flex().flex_col().gap_2()
                        .child(div().text_xs().text_color(cx.theme().muted_foreground).child("Configured host endpoint"))
                        .child(Input::new(&self.endpoint).small())
                        .when_some(match &self.client_inventory.state {
                            InventoryState::Unavailable(error) => Some(error.clone()), _ => None
                        }, |this, error| this.child(div().text_xs().text_color(cx.theme().danger).child(error)))
                        .children(self.client_inventory.coverage_lines().into_iter().map(|line| {
                            div().text_xs().text_color(cx.theme().muted_foreground).child(line)
                        })))) ))
    }

    fn render_client_inventory(&self, cx: &mut Context<Self>) -> Div {
        let rows = self.client_inventory.rows();
        let coverage = self.client_inventory.coverage_lines();
        let unavailable = matches!(self.client_inventory.state, InventoryState::Unavailable(_));
        let loading = matches!(self.client_inventory.state, InventoryState::Loading);
        let ready = matches!(self.client_inventory.state, InventoryState::Ready(_));
        let configured_endpoint = self.endpoint.read(cx).value().to_string();
        let exact_copies = self
            .client_inventory
            .actionable_copies()
            .into_iter()
            .enumerate()
            .map(|(index, (id, label))| {
                let enabled = self.can_open_installation(&id, cx);
                let preparing = self.opening_selection.as_ref().is_some_and(|selection| {
                    selection.app.id == id
                        && selection.endpoint == configured_endpoint
                        && selection.action == OpeningAction::OrdinaryOpen
                });
                let setup_preparing = self.opening_selection.as_ref().is_some_and(|selection| {
                    selection.app.id == id
                        && selection.endpoint == configured_endpoint
                        && selection.action == OpeningAction::CursorMcpSetup
                });
                let setup_supported = self
                    .client_inventory
                    .action_copies(OpeningAction::CursorMcpSetup)
                    .iter()
                    .any(|(copy, _)| copy == &id);
                let setup_enabled =
                    self.can_act_on_installation(OpeningAction::CursorMcpSetup, &id, cx);
                let vscode_preparing = self.opening_selection.as_ref().is_some_and(|selection| {
                    selection.app.id == id
                        && selection.endpoint == configured_endpoint
                        && selection.action == OpeningAction::VsCodeMcpSetup
                });
                let vscode_supported = self
                    .client_inventory
                    .action_copies(OpeningAction::VsCodeMcpSetup)
                    .iter()
                    .any(|(copy, _)| copy == &id);
                let vscode_sent = self.openings.as_ref().is_some_and(|store| {
                    store.has_acknowledged_vscode_setup(&configured_endpoint, &id)
                });
                let vscode_enabled =
                    self.can_act_on_installation(OpeningAction::VsCodeMcpSetup, &id, cx);
                let open_id = id.clone();
                let setup_id = id.clone();
                let vscode_id = id.clone();
                let disambiguation = self.client_inventory.copy_disambiguation(&id);
                let latest = self
                    .openings
                    .as_ref()
                    .and_then(|store| {
                        store.attempts.iter().rev().find(|attempt| {
                            attempt.endpoint == configured_endpoint && attempt.installation_id == id
                        })
                    })
                    .map(OpeningAttempt::summary);
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .py_1()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(div().flex_1().text_xs().child(label))
                            .child(
                                Button::new(("open-installation", index))
                                    .small()
                                    .label(if preparing {
                                        "Checking selected app…"
                                    } else {
                                        "Open/reuse"
                                    })
                                    .disabled(!enabled)
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.open_installation(&open_id, cx)
                                    })),
                            )
                            .when(setup_supported, |this| {
                                this.child(
                                    Button::new(("setup-cursor-mcp", index))
                                        .small()
                                        .label(if setup_preparing {
                                            "Checking selected app…"
                                        } else {
                                            "Set up Cursor"
                                        })
                                        .disabled(!setup_enabled)
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.act_on_installation(
                                                OpeningAction::CursorMcpSetup,
                                                &setup_id,
                                                cx,
                                            )
                                        })),
                                )
                            })
                            .when(vscode_supported, |this| {
                                this.child(
                                    Button::new(("setup-vscode-mcp", index))
                                        .small()
                                        .label(if vscode_preparing {
                                            "Checking selected app…"
                                        } else if vscode_sent {
                                            "VS Code setup request sent"
                                        } else {
                                            "Set up VS Code"
                                        })
                                        .disabled(!vscode_enabled)
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.act_on_installation(
                                                OpeningAction::VsCodeMcpSetup,
                                                &vscode_id,
                                                cx,
                                            )
                                        })),
                                )
                            }),
                    )
                    .when_some(disambiguation, |this, detail| {
                        this.child(
                            div()
                                .text_xs()
                                .text_color(cx.theme().muted_foreground)
                                .child(detail),
                        )
                    })
                    .when_some(latest, |this, summary| {
                        this.child(
                            div()
                                .text_xs()
                                .text_color(cx.theme().muted_foreground)
                                .child(summary),
                        )
                    })
            })
            .collect::<Vec<_>>();
        let opening_history = self
            .openings
            .as_ref()
            .map(|store| store.attempts.iter().rev().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
            .into_iter()
            .enumerate()
            .map(|(index, attempt)| {
                let checking = self.opening_tasks.contains_key(&attempt.id);
                let unresolved = attempt.unresolved();
                let summary = attempt.summary();
                let id = attempt.id.clone();
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .py_1()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(div().flex_1().text_xs().child(format!(
                                "{} · Copy {} · {}",
                                attempt.action.label(),
                                openings::short_installation_id(&attempt.installation_id),
                                attempt.endpoint
                            )))
                            .when(unresolved, |this| {
                                this.child(
                                    Button::new(("check-opening-status", index))
                                        .small()
                                        .label(if checking {
                                            "Checking…"
                                        } else {
                                            attempt.action.check_label()
                                        })
                                        .disabled(checking)
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.check_opening(&id, cx)
                                        })),
                                )
                            }),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child(summary),
                    )
            })
            .collect::<Vec<_>>();
        let opening_warning = self.opening_warning.clone().filter(|_| {
            !opening_history.is_empty()
                || self
                    .client_inventory
                    .opening_status
                    .as_ref()
                    .is_some_and(|status| status.native_open_allowed)
                || self
                    .client_inventory
                    .cursor_mcp_status
                    .as_ref()
                    .is_some_and(|status| status.native_open_allowed)
                || self
                    .client_inventory
                    .vscode_mcp_status
                    .as_ref()
                    .is_some_and(|status| status.native_open_allowed)
        });
        div()
                .flex().flex_col().gap_2().border_t_1().border_color(cx.theme().border).pt_3()
                .child(div().flex().items_center().gap_2()
                    .child(div().flex_1().text_sm().font_weight(FontWeight::SEMIBOLD).child("Your apps"))
                    .child(Button::new("find-client-apps").small()
                        .label(if loading { "Finding apps…" } else { "Find apps" })
                        .disabled(loading)
                        .on_click(cx.listener(|this, _, _, cx| {
                            let endpoint = this.endpoint.read(cx).value().to_string();
                            this.client_inventory.expanded = true;
                            this.load_client_inventory(&endpoint, this.connection_generation, cx);
                            cx.notify();
                        })))
                    .child(Button::new("toggle-client-inventory").small()
                        .label(if self.client_inventory.expanded { "Hide apps" } else { "Show apps" })
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.client_inventory.expanded = !this.client_inventory.expanded;
                            cx.notify();
                        }))))
                .child(div().text_xs()
                    .text_color(if unavailable { cx.theme().danger } else { cx.theme().muted_foreground })
                    .child(self.client_inventory.summary()))
                .when_some(self.client_inventory.coverage_warning(), |this, warning| this.child(
                    div().text_xs().text_color(cx.theme().muted_foreground).child(warning)))
                .when(self.client_inventory.expanded, |this| {
                    this.child(div().text_xs().text_color(cx.theme().muted_foreground)
                        .child("Finding apps identifies them; it does not connect them."))
                        .when(ready && rows.is_empty(), |this| this.child(
                            div().text_xs().text_color(cx.theme().muted_foreground)
                                .child("No supported apps were observed in this snapshot. Check details for coverage limits.")))
                        .child(div().id("detected-client-inventory").max_h(px(150.))
                            .overflow_y_scroll().flex().flex_col().gap_2()
                            .children(rows.into_iter().map(|row| div().text_xs().child(row))))
                        .when(!exact_copies.is_empty(), |this| this.child(div().id("openable-installed-copies")
                            .max_h(px(170.)).overflow_y_scroll().flex().flex_col().gap_1().children(exact_copies)))
                        .when(!self.client_inventory.action_copies(OpeningAction::CursorMcpSetup).is_empty(), |this| this.child(
                            div().text_xs().text_color(cx.theme().muted_foreground)
                                .child("Read native #mgmt in Cursor; Cursor will ask for installation approval.")))
                        .when(!self.client_inventory.action_copies(OpeningAction::VsCodeMcpSetup).is_empty(), |this| this.child(
                            div().text_xs().text_color(cx.theme().muted_foreground)
                                .child("Read native #mgmt in VS Code. Review server addition and trust in VS Code; this does not verify an inbox read.")))
                        .when_some(self.client_inventory.opening_notice.clone(), |this, notice| this.child(
                            div().text_xs().text_color(cx.theme().muted_foreground).child(notice)))
                        .when_some(self.client_inventory.cursor_mcp_notice.clone(), |this, notice| this.child(
                            div().text_xs().text_color(cx.theme().muted_foreground).child(notice)))
                        .when_some(self.client_inventory.vscode_mcp_notice.clone(), |this, notice| this.child(
                            div().text_xs().text_color(cx.theme().muted_foreground).child(notice)))
                        .when(!opening_history.is_empty(), |this| this.child(div().id("opening-history")
                            .max_h(px(170.)).overflow_y_scroll().flex().flex_col().gap_1().children(opening_history)))
                        .when_some(opening_warning, |this, warning| this.child(
                            div().text_xs().text_color(cx.theme().danger).child(warning)))
                        .when(ready, |this| this.child(
                            Button::new("toggle-client-discovery-details").small()
                                .label(if self.client_inventory.details_expanded { "Hide details" } else { "Discovery details" })
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.client_inventory.details_expanded = !this.client_inventory.details_expanded;
                                    cx.notify();
                                }))))
                        .when(self.client_inventory.details_expanded, |this| this
                            .child(div().text_xs().text_color(cx.theme().muted_foreground)
                                .child(format!("Configured bus: {configured_endpoint}")))
                            .children(coverage.into_iter().map(|line| div().text_xs()
                                .text_color(cx.theme().muted_foreground).child(line))))
                })
    }
}

impl Render for Workbench {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if self.mode == AppMode::CursorOnboarding {
            return self.render_cursor_onboarding(cx);
        }
        let sending = self.sending();
        let loading = matches!(self.connection, Connection::Connecting);
        let connected = self.connected_endpoint().is_some();
        let can_send = self.can_send();
        let client_inventory = self.render_client_inventory(cx);
        let mcp_http = self.render_mcp_http(cx);
        let (connection_title, connection_detail) = match &self.connection {
            Connection::Disconnected => (
                "Disconnected",
                "Connect to a loopback bus to load messages.".to_string(),
            ),
            Connection::Connecting => (
                "Connecting…",
                "Checking bus status and room history.".into(),
            ),
            Connection::Connected {
                detail,
                send_available,
                read_only,
                ..
            } => (
                if *read_only {
                    "Read only"
                } else if *send_available {
                    "HTTP reachable"
                } else {
                    "Bus unavailable"
                },
                detail.clone(),
            ),
            Connection::Failed(error) => ("Connection failed", error.clone()),
        };
        let (receipt, uncertain) = self.receipt_line();
        let draft_empty = self.composer.read(cx).value().trim().is_empty();
        let attempts = self
            .outbox
            .as_ref()
            .map(|outbox| {
                outbox
                    .attempts
                    .iter()
                    .filter(|attempt| attempt.visible_in_send_history())
                    .rev()
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let attempt_rows = attempts
            .into_iter()
            .enumerate()
            .map(|(index, attempt)| {
                let id = attempt.id.clone();
                let checking = self.checking_id.as_deref() == Some(id.as_str());
                let state = match &attempt.state {
                    AttemptState::Pending => {
                        "Receipt pending; safe to check without resending".to_owned()
                    }
                    AttemptState::Uncertain(error) => error.clone(),
                    AttemptState::Delivered(receipt) => outbox::receipt_summary(
                        &receipt.ack.transport,
                        Some(receipt.ack.subscribers_notified),
                    ),
                    _ => String::new(),
                };
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .py_2()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_3()
                            .child(div().flex_1().text_xs().child(format!(
                                "{} · {} · {}",
                                attempt.request.room, attempt.endpoint, attempt.request.sender
                            )))
                            .child(
                                Button::new(("check-send-receipt", index))
                                    .small()
                                    .label(if checking {
                                        "Checking…"
                                    } else {
                                        "Check send receipt"
                                    })
                                    .disabled(self.checking_id.is_some())
                                    .on_click(cx.listener(move |this, _, window, cx| {
                                        this.check_send_receipt(&id, window, cx)
                                    })),
                            ),
                    )
                    .child(
                        div()
                            .text_xs()
                            .child(attempt.request.body.chars().take(120).collect::<String>()),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child(format!("{} · {state}", attempt.id)),
                    )
            })
            .collect::<Vec<_>>();

        div()
            .flex()
            .size_full()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .font_family(".AppleSystemUIFont")
            .child(
                div()
                    .flex()
                    .flex_col()
                    .w(px(220.))
                    .flex_shrink_0()
                    .p_5()
                    .gap_6()
                    .bg(cx.theme().secondary)
                    .border_r_1()
                    .border_color(cx.theme().border)
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(div().text_xl().font_weight(FontWeight::BOLD).child("Chinwag"))
                            .child(div().text_sm().text_color(cx.theme().muted_foreground).child("Native coordination bus · alpha")),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .children(ROOMS.iter().enumerate().map(|(index, (room, description))| {
                                let room = *room;
                                div()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .child(
                                        Button::new(("room", index))
                                            .label(room)
                                            .selected(self.conversation.room == room)
                                            .w_full()
                                            .disabled(sending)
                                            .on_click(cx.listener(move |this, _, window, cx| {
                                                this.select_room(room, window, cx);
                                            })),
                                    )
                                    .child(div().px_2().text_xs().text_color(cx.theme().muted_foreground).child(*description))
                            })),
                    )
                    .child(div().flex_1())
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_2()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child("Native GPUI")
                            .child("Explicit sends only. No agent wake-ups.")
                            .child("Room labels do not grant access."),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w_0()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_3()
                            .px_6()
                            .py_4()
                            .border_b_1()
                            .border_color(cx.theme().border)
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(div().w(px(90.)).text_sm().font_weight(FontWeight::MEDIUM).child("Bus endpoint"))
                                    .child(div().flex_1().child(Input::new(&self.endpoint).aria_label("Bus endpoint").disabled(sending).small()))
                                    .child(Button::new("connect").label(if connected { "Refresh" } else { "Connect" }).disabled(sending || loading).on_click(cx.listener(|this, _, _, cx| this.load(cx)))),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_start()
                                    .gap_3()
                                    .text_xs()
                                    .child(div().font_weight(FontWeight::SEMIBOLD).child(connection_title))
                                    .child(div().flex_1().text_color(cx.theme().muted_foreground).child(connection_detail)),
                            )
                            .child(client_inventory)
                            .child(mcp_http),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .px_6()
                            .py_4()
                            .child(div().text_xl().font_weight(FontWeight::SEMIBOLD).child(self.conversation.room.clone()))
                            .child(div().text_sm().text_color(cx.theme().muted_foreground).child(format!("{} messages", self.conversation.messages.len()))),
                    )
                    .child(
                        div()
                            .id("message-timeline")
                            .flex_1()
                            .min_h_0()
                            .overflow_y_scroll()
                            .px_6()
                            .when(self.conversation.messages.is_empty(), |this| {
                                this.child(
                                    div()
                                        .flex()
                                        .flex_col()
                                        .gap_2()
                                        .py_8()
                                        .child(div().text_lg().font_weight(FontWeight::MEDIUM).child(if connected { "This room is quiet." } else { "A place for the conversation." }))
                                        .child(div().text_sm().text_color(cx.theme().muted_foreground).child(if can_send { "Write the first message below, or choose another room." } else if connected { "History is available, but sending is disabled. See the bus status above." } else { "Connect above to read the bus. Your draft stays here until you send it." })),
                                )
                            })
                            .children(self.conversation.messages.iter().map(|message| Self::message_row(message, cx))),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_3()
                            .p_5()
                            .border_t_1()
                            .border_color(cx.theme().border)
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(div().text_sm().child("Send as"))
                                    .children(SENDERS.iter().enumerate().map(|(index, sender)| {
                                        let sender = *sender;
                                        Button::new(("sender", index))
                                            .small()
                                            .label(sender)
                                            .selected(self.sender == sender)
                                            .disabled(sending || !self.sender_allowed(sender))
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.sender = sender;
                                                cx.notify();
                                            }))
                                    }))
                                    .child(div().flex_1())
                                    .child(div().text_xs().text_color(cx.theme().muted_foreground).child(posting_hint(&self.connection,self.sender))),
                            )
                            .child(
                                div()
                                    .capture_action(cx.listener(|this, action: &Enter, window, cx| {
                                        if action.secondary && !action.shift {
                                            cx.stop_propagation();
                                            if !this.send_shortcut_held {
                                                this.send_shortcut_held = true;
                                                this.send(window, cx);
                                            }
                                        }
                                    }))
                                    .on_key_up(cx.listener(|this, event: &KeyUpEvent, _, _| {
                                        if event.keystroke.key == "enter" {
                                            this.send_shortcut_held = false;
                                        }
                                    }))
                                    .child(Textarea::new(&self.composer).aria_label("Message draft").disabled(sending)),
                            )
                            .child(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_4()
                                    .child(div().flex_1().text_xs().text_color(if uncertain { cx.theme().danger } else { cx.theme().muted_foreground }).child(receipt))
                                    .child(Button::new("send").primary().label(format!("Send to {}", self.conversation.room)).disabled(!can_send || sending || draft_empty).on_click(cx.listener(|this, _, window, cx| this.send(window, cx)))),
                            )
                            .when(!attempt_rows.is_empty(), |this|this.child(div().id("unconfirmed-outbox").max_h(px(180.)).overflow_y_scroll().flex().flex_col()
                                .child(div().text_sm().font_weight(FontWeight::MEDIUM).child("Send history · receipt checks never publish"))
                                .children(attempt_rows)))
                            .when_some(self.outbox_warning.clone(),|this,warning|this.child(div().text_xs().text_color(cx.theme().danger).child(warning)))
                            .when_some(self.draft_warning.clone(), |this, warning| this.child(div().text_xs().text_color(cx.theme().danger).child(warning))),
                    ),
            )
    }
}

fn posting_hint(connection: &Connection, sender: &str) -> &'static str {
    match connection {
        Connection::Disconnected => "Connect and check posting permissions before sending",
        Connection::Connecting => "Checking connection and posting permissions",
        Connection::Failed(_) => "Connection unavailable; reconnect before sending",
        Connection::Connected {
            read_only: true, ..
        } => "Sending disabled for this read-only connection",
        Connection::Connected {
            send_available: false,
            ..
        } => "Sending disabled for this connection",
        Connection::Connected {
            signed_posting: true,
            allowed_senders,
            ..
        } if sender != "Brian" && allowed_senders.iter().any(|allowed| allowed == "Brian") => {
            "Select Brian to enable signed posting"
        }
        Connection::Connected {
            allowed_senders, ..
        } if !allowed_senders.iter().any(|allowed| allowed == sender) => {
            "Posting permission is required for this sender"
        }
        Connection::Connected { .. } if sender == "CODEX" => "Own sender label · unverified",
        Connection::Connected { .. } => "Explicit human post · see receipt for signature",
    }
}

fn status_detail(status: &serde_json::Value) -> String {
    if status.get("mode").and_then(|value| value.as_str()) == Some("fleet-signed-ui") {
        return if status_send_available(status) {
            "Native coordination bus · Select Brian for signed native posts. This view does not verify Grok Bot receipt.".into()
        } else {
            "Native coordination bus · Signed posting unavailable. Drafts and per-message send history are retained. Grok Bot receipt is unconfirmed."
                .into()
        };
    }
    if status.get("mode").and_then(|value| value.as_str()) == Some("fleet-ledger-read-only") {
        return "Native coordination bus · read only; signing/delivery not invoked. Grok Bot receipt is not checked. Checks for new messages every 2 seconds.".into();
    }
    if status.get("mode").and_then(|value| value.as_str()) == Some("isolated-local-alpha") {
        if status
            .get("storage_healthy")
            .and_then(|value| value.as_bool())
            == Some(false)
        {
            return "Isolated alpha bus · Local storage unavailable; sending disabled. Your draft stays in this window.".into();
        }
        return "Isolated alpha bus · Unsigned local storage; fleet delivery disabled. Checks for new messages every 2 seconds.".into();
    }
    if !status_send_available(status) {
        return "HTTP service reachable, but the bus daemon is stopped or unavailable. History may be local; sending is disabled.".into();
    }
    let transport = status.get("transport").and_then(|value| value.as_str());
    let mode = status.get("mode").and_then(|value| value.as_str());
    match transport.or(mode) {
        Some(value) => format!(
            "HTTP bus reachable · Reported transport: {value}. Checks for new messages every 2 seconds.",
        ),
        None => {
            "HTTP bus reachable. Checks for new messages every 2 seconds; subscriber delivery is not implied."
                .into()
        }
    }
}

fn status_send_available(status: &serde_json::Value) -> bool {
    if status.get("read_only").and_then(|value| value.as_bool()) == Some(true)
        || status.get("send_allowed").and_then(|value| value.as_bool()) == Some(false)
    {
        return false;
    }
    if status.get("ok").and_then(|value| value.as_bool()) != Some(true) {
        return false;
    }
    if status.get("mode").and_then(|value| value.as_str()) == Some("isolated-local-alpha") {
        return status
            .get("storage_healthy")
            .and_then(|value| value.as_bool())
            == Some(true);
    }
    if status.get("mode").and_then(|value| value.as_str()) == Some("fleet-signed-ui") {
        return status.get("send_allowed").and_then(|value| value.as_bool()) == Some(true)
            && status.get("read_only").and_then(|value| value.as_bool()) == Some(false)
            && status
                .get("storage_healthy")
                .and_then(|value| value.as_bool())
                == Some(true)
            && status.get("allowed_senders") == Some(&serde_json::json!(["Brian"]));
    }
    status
        .get("daemon")
        .is_some_and(serde_json::Value::is_object)
        && status
            .get("storage_healthy")
            .and_then(|value| value.as_bool())
            != Some(false)
}

fn status_allowed_senders(status: &serde_json::Value) -> Vec<String> {
    if !status_send_available(status) {
        return Vec::new();
    }
    if let Some(value) = status.get("allowed_senders") {
        return value
            .as_array()
            .map(|senders| {
                senders
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
    }
    Vec::new()
}

fn reset_receipt_on_endpoint_change(state: &mut SendState) {
    if matches!(state, SendState::Delivered { .. }) {
        *state = SendState::Idle;
    }
}

fn explicit_rejection(error: &ClientError) -> Option<String> {
    match error {
        ClientError::HttpStatus {
            status: 400..=499, ..
        } => Some(error.to_string()),
        _ => None,
    }
}

fn signature_label(verified: bool) -> &'static str {
    if verified {
        "signature verified"
    } else {
        "signature unverified"
    }
}

fn initials(sender: &str) -> String {
    sender
        .chars()
        .filter(|character| character.is_alphanumeric())
        .take(2)
        .flat_map(char::to_uppercase)
        .collect()
}

fn short_time(timestamp: &str) -> String {
    timestamp.get(11..19).unwrap_or(timestamp).to_owned()
}

fn confirmation_time(milliseconds: u64) -> String {
    i64::try_from(milliseconds)
        .ok()
        .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
        .map(|date| {
            date.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S %Z")
                .to_string()
        })
        .unwrap_or_else(|| "date unavailable".into())
}

fn main() {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let team_work = match team_work_launch::parse(arguments.clone()) {
        Ok(Some(declaration)) => match chinwag_team_direction::TeamHost::open(
            &declaration.config,
            &declaration.state_root,
        ) {
            Ok(host) => Some(team_work_ui::DesktopTeamHost::new(host)),
            Err(error) => {
                eprintln!("Could not open declared team work: {error}");
                return;
            }
        },
        Ok(None) => None,
        Err(error) => {
            eprintln!("Invalid team-work invocation: {error}");
            return;
        }
    };
    let gemini_work = match gemini_work_launch::parse(arguments.clone()) {
        Ok(Some(config)) => match chinwag_gemini_control::open_work_service(config) {
            Ok(port) => Some(port),
            Err(error) => {
                eprintln!("Could not open owned Gemini work: {error}");
                return;
            }
        },
        Ok(None) => None,
        Err(error) => {
            eprintln!("Invalid owned-Gemini invocation: {error}");
            return;
        }
    };
    let claude_work = match claude_work_launch::parse(arguments.clone()) {
        Ok(Some(config)) => match chinwag_claude_control::open_work_service(config) {
            Ok(port) => Some(port),
            Err(error) => {
                eprintln!("Could not open owned Claude work: {error}");
                return;
            }
        },
        Ok(None) => None,
        Err(error) => {
            eprintln!("Invalid owned-Claude invocation: {error}");
            return;
        }
    };
    let work = match codex_work_launch::parse(arguments) {
        Ok(Some(config)) => match chinwag_codex_steer::open_work_service(config) {
            Ok(port) => Some(port),
            Err(error) => {
                eprintln!("Could not open owned work: {error}");
                return;
            }
        },
        Ok(None) => None,
        Err(error) => {
            eprintln!("Invalid owned-work invocation: {error}");
            return;
        }
    };
    application().with_assets(assets::Assets).run(move |cx| {
        init(cx);
        cx.on_action(|_: &Quit, cx| cx.quit());
        cx.bind_keys([KeyBinding::new("cmd-q", Quit, None)]);
        cx.set_menus([Menu::new("Chinwag").items([MenuItem::action("Quit Chinwag", Quit)])]);
        if let Some(host) = team_work {
            let show = host.clone();
            cx.on_action(move |_: &ShowTeamWork, cx| {
                open_team_work_window(show.clone(), cx);
                cx.activate(true);
            });
            cx.bind_keys([KeyBinding::new("cmd-0", ShowTeamWork, None)]);
            cx.set_menus([Menu::new("Chinwag").items([
                MenuItem::action("Show team direction", ShowTeamWork),
                MenuItem::action("Quit Chinwag and end team control input", Quit),
            ])]);
            let quit = host.clone();
            let executor = cx.background_executor().clone();
            cx.on_app_quit(move |_| {
                let mut updates = quit.core.subscribe();
                quit.close_controls();
                let mut deadline = Box::pin(executor.timer(Duration::from_secs(3)));
                let quit = quit.clone();
                async move {
                    loop {
                        if quit.locally_closed() {
                            break;
                        }
                        let mut change = Box::pin(updates.changed());
                        let stop = std::future::poll_fn(|cx| {
                            if std::future::Future::poll(deadline.as_mut(), cx).is_ready() {
                                return std::task::Poll::Ready(true);
                            }
                            match std::future::Future::poll(change.as_mut(), cx) {
                                std::task::Poll::Ready(result) => {
                                    std::task::Poll::Ready(result.is_err())
                                }
                                std::task::Poll::Pending => std::task::Poll::Pending,
                            }
                        })
                        .await;
                        if stop {
                            break;
                        }
                    }
                }
            })
            .detach();
            open_team_work_window(host, cx);
            cx.activate(true);
            return;
        }
        if let Some(port) = gemini_work {
            let show = port.clone();
            cx.on_action(move |_: &ShowGeminiWork, cx| {
                if cx.windows().is_empty() {
                    open_gemini_work_window(show.clone(), cx);
                }
                cx.activate(true);
            });
            cx.bind_keys([KeyBinding::new("cmd-0", ShowGeminiWork, None)]);
            cx.set_menus([Menu::new("Chinwag").items([
                MenuItem::action("Show Gemini task window", ShowGeminiWork),
                MenuItem::action("Quit Chinwag and end Gemini input", Quit),
            ])]);
            let quit = port.clone();
            let executor = cx.background_executor().clone();
            cx.on_app_quit(move |_| {
                let mut updates = quit.subscribe();
                let _ = quit.end_input();
                let mut deadline = Box::pin(executor.timer(Duration::from_secs(3)));
                async move {
                    loop {
                        let observed = updates.borrow().clone();
                        if observed.lifecycle.stdin_ended || observed.lifecycle.child_exited {
                            break;
                        }
                        let mut change = Box::pin(updates.changed());
                        let stop = std::future::poll_fn(|cx| {
                            if std::future::Future::poll(deadline.as_mut(), cx).is_ready() {
                                return std::task::Poll::Ready(true);
                            }
                            match std::future::Future::poll(change.as_mut(), cx) {
                                std::task::Poll::Ready(result) => {
                                    std::task::Poll::Ready(result.is_err())
                                }
                                std::task::Poll::Pending => std::task::Poll::Pending,
                            }
                        })
                        .await;
                        if stop {
                            break;
                        }
                    }
                }
            })
            .detach();
            open_gemini_work_window(port, cx);
            cx.activate(true);
            return;
        }
        if let Some(port) = claude_work {
            let show = port.clone();
            cx.on_action(move |_: &ShowClaudeWork, cx| {
                if cx.windows().is_empty() {
                    open_claude_work_window(show.clone(), cx);
                }
                cx.activate(true);
            });
            cx.bind_keys([KeyBinding::new("cmd-0", ShowClaudeWork, None)]);
            cx.set_menus([Menu::new("Chinwag").items([
                MenuItem::action("Show Claude task window", ShowClaudeWork),
                MenuItem::action("Quit Chinwag and end Claude input", Quit),
            ])]);
            let quit = port.clone();
            let executor = cx.background_executor().clone();
            cx.on_app_quit(move |_| {
                let mut updates = quit.subscribe();
                let _ = quit.end_input();
                let mut deadline = Box::pin(executor.timer(Duration::from_secs(3)));
                async move {
                    loop {
                        let observed = updates.borrow().clone();
                        if observed.lifecycle.stdin_ended || observed.lifecycle.child_exited {
                            break;
                        }
                        let mut change = Box::pin(updates.changed());
                        let stop = std::future::poll_fn(|cx| {
                            if std::future::Future::poll(deadline.as_mut(), cx).is_ready() {
                                return std::task::Poll::Ready(true);
                            }
                            match std::future::Future::poll(change.as_mut(), cx) {
                                std::task::Poll::Ready(result) => {
                                    std::task::Poll::Ready(result.is_err())
                                }
                                std::task::Poll::Pending => std::task::Poll::Pending,
                            }
                        })
                        .await;
                        if stop {
                            break;
                        }
                    }
                }
            })
            .detach();
            open_claude_work_window(port, cx);
            cx.activate(true);
            return;
        }
        if let Some(port) = work {
            let show = port.clone();
            cx.on_action(move |_: &ShowOwnedWork, cx| {
                if cx.windows().is_empty() {
                    open_owned_work_window(show.clone(), cx);
                }
                cx.activate(true);
            });
            cx.bind_keys([KeyBinding::new("cmd-0", ShowOwnedWork, None)]);
            cx.set_menus([Menu::new("Chinwag").items([
                MenuItem::action("Show task window", ShowOwnedWork),
                MenuItem::action("Quit Chinwag and close control connection", Quit),
            ])]);
            let quit = port.clone();
            cx.on_app_quit(move |_| {
                let mut updates = quit.subscribe();
                let _ = quit.close();
                async move {
                    while updates.borrow().phase != chinwag_codex_steer::WorkPhase::Closed {
                        if updates.changed().await.is_err() {
                            break;
                        }
                    }
                }
            })
            .detach();
            open_owned_work_window(port, cx);
            cx.activate(true);
            return;
        }
        let mode = AppMode::from_setting(std::env::var("CHINWAG_ALPHA_ONBOARDING").ok().as_deref());
        let bounds = Bounds::centered(
            None,
            if mode == AppMode::CursorOnboarding {
                size(px(720.), px(740.))
            } else {
                size(px(1120.), px(800.))
            },
            cx,
        );
        let options = WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            window_min_size: Some(if mode == AppMode::CursorOnboarding {
                size(px(600.), px(540.))
            } else {
                size(px(800.), px(600.))
            }),
            titlebar: Some(TitlebarOptions {
                title: Some(mode.window_title().into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        if let Err(error) = open_window(options, cx, |window, cx| {
            cx.new(|cx| Workbench::new(window, cx))
        }) {
            eprintln!("Could not open Chinwag: {error}");
            cx.quit();
        }
        cx.activate(true);
    });
}

fn open_team_work_window(host: std::sync::Arc<team_work_ui::DesktopTeamHost>, cx: &mut App) {
    let existing = host.window.lock().ok().and_then(|current| *current);
    if let Some(existing) = existing {
        if existing
            .update(cx, |_, window, _| window.activate_window())
            .is_ok()
        {
            return;
        }
        if let Ok(mut current) = host.window.lock()
            && *current == Some(existing)
        {
            *current = None;
        }
    }
    let options = WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
            None,
            size(px(1180.), px(900.)),
            cx,
        ))),
        window_min_size: Some(size(px(980.), px(700.))),
        titlebar: Some(TitlebarOptions {
            title: Some("Chinwag · team direction".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let retained = host.clone();
    if open_window(options, cx, move |window, cx| {
        cx.new(|cx| team_work_ui::TeamWorkView::new(retained, window, cx))
    })
    .is_err()
    {
        if let Ok(mut current) = host.window.lock() {
            *current = None;
        }
        eprintln!("Could not open team direction window");
    }
}

/// Reuses the exact host-held native port; opening does not call Start or Cancel.
fn open_team_member_window(member: &chinwag_team_direction::Member, cx: &mut App) {
    use chinwag_team_direction::HeldWorkPort;
    let provider = match &member.port {
        HeldWorkPort::Codex(_) => "Codex",
        HeldWorkPort::Claude(_) => "Claude",
        HeldWorkPort::Gemini(_) => "Gemini",
    };
    let options = WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
            None,
            size(px(920.), px(820.)),
            cx,
        ))),
        window_min_size: Some(size(px(680.), px(560.))),
        titlebar: Some(TitlebarOptions {
            title: Some(format!("{} · {} · {provider} work", member.label, member.id).into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let opened = match &member.port {
        HeldWorkPort::Codex(port) => {
            let port = port.clone();
            open_window(options, cx, move |window, cx| {
                cx.new(|cx| codex_work_ui::CodexWorkView::new(port, window, cx))
            })
            .map(|_| ())
        }
        HeldWorkPort::Claude(port) => {
            let port = port.clone();
            open_window(options, cx, move |window, cx| {
                cx.new(|cx| claude_work_ui::ClaudeWorkView::new(port, window, cx))
            })
            .map(|_| ())
        }
        HeldWorkPort::Gemini(port) => {
            let port = port.clone();
            open_window(options, cx, move |window, cx| {
                cx.new(|cx| gemini_work_ui::GeminiWorkView::new(port, window, cx))
            })
            .map(|_| ())
        }
    };
    if opened.is_err() {
        eprintln!("Could not open the owned member work window");
    }
}

fn open_gemini_work_window(
    port: std::sync::Arc<dyn chinwag_gemini_control::HumanWorkPort>,
    cx: &mut App,
) {
    let options = WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
            None,
            size(px(920.), px(820.)),
            cx,
        ))),
        window_min_size: Some(size(px(680.), px(560.))),
        titlebar: Some(TitlebarOptions {
            title: Some("Direct Gemini work".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    if open_window(options, cx, move |window, cx| {
        cx.new(|cx| gemini_work_ui::GeminiWorkView::new(port, window, cx))
    })
    .is_err()
    {
        eprintln!("Could not open owned Gemini work window");
    }
}

fn open_claude_work_window(
    port: std::sync::Arc<dyn chinwag_claude_control::HumanWorkPort>,
    cx: &mut App,
) {
    let options = WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
            None,
            size(px(920.), px(820.)),
            cx,
        ))),
        window_min_size: Some(size(px(680.), px(560.))),
        titlebar: Some(TitlebarOptions {
            title: Some("Direct Claude while it works".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    if open_window(options, cx, move |window, cx| {
        cx.new(|cx| claude_work_ui::ClaudeWorkView::new(port, window, cx))
    })
    .is_err()
    {
        eprintln!("Could not open owned Claude work window");
    }
}

fn open_owned_work_window(
    port: std::sync::Arc<dyn chinwag_codex_steer::HumanWorkPort>,
    cx: &mut App,
) {
    let options = WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
            None,
            size(px(920.), px(820.)),
            cx,
        ))),
        window_min_size: Some(size(px(680.), px(560.))),
        titlebar: Some(TitlebarOptions {
            title: Some("Steer Codex while it works".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    if open_window(options, cx, move |window, cx| {
        cx.new(|cx| codex_work_ui::CodexWorkView::new(port, window, cx))
    })
    .is_err()
    {
        eprintln!("Could not open owned work window");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connected_hint_fixture(
        read_only: bool,
        send_available: bool,
        signed_posting: bool,
        senders: &[&str],
    ) -> Connection {
        Connection::Connected {
            endpoint: "http://127.0.0.1:44341".into(),
            detail: "Fixture".into(),
            read_only,
            send_available,
            signed_posting,
            allowed_senders: senders.iter().map(|sender| (*sender).into()).collect(),
        }
    }

    #[test]
    fn posting_hint_prioritizes_connection_and_read_only_permissions() {
        for connection in [
            Connection::Disconnected,
            Connection::Connecting,
            Connection::Failed("offline".into()),
            connected_hint_fixture(false, false, true, &["Brian"]),
        ] {
            assert!(!posting_hint(&connection, "CODEX").contains("Select Brian"));
            assert!(!posting_hint(&connection, "Brian").contains("Explicit human post"));
        }
        let read_only = connected_hint_fixture(true, true, true, &["Brian"]);
        for sender in SENDERS {
            assert_eq!(
                posting_hint(&read_only, sender),
                "Sending disabled for this read-only connection"
            );
        }
    }

    #[test]
    fn brian_selection_hint_requires_signed_mode_and_actual_permission() {
        let signed = connected_hint_fixture(false, true, true, &["Brian"]);
        assert_eq!(
            posting_hint(&signed, "CODEX"),
            "Select Brian to enable signed posting"
        );
        assert_eq!(
            posting_hint(&signed, "Brian"),
            "Explicit human post · see receipt for signature"
        );
        for connection in [
            connected_hint_fixture(false, true, true, &[]),
            connected_hint_fixture(false, true, false, &["Brian"]),
        ] {
            assert_eq!(
                posting_hint(&connection, "CODEX"),
                "Posting permission is required for this sender"
            );
        }
        let isolated = connected_hint_fixture(false, true, false, &["CODEX", "Brian"]);
        assert_eq!(
            posting_hint(&isolated, "CODEX"),
            "Own sender label · unverified"
        );
    }

    #[test]
    fn native_local_and_fallback_receipts_keep_grok_receipt_unconfirmed() {
        for transport in [
            "local-crdb+jsonl (daemon starting)",
            "local-fallback",
            "LOCAL_LEDGER",
            "fallback",
        ] {
            let label = outbox::receipt_summary(transport, Some(0));
            assert!(label.contains("Stored in native bus; Grok Bot receipt unconfirmed"));
            assert!(label.contains("native subscribers notified: 0"));
            assert!(label.contains(transport));
        }
    }

    #[test]
    fn native_subscriber_notifications_are_not_grok_receipts() {
        let label = outbox::receipt_summary("iroh-gossip", Some(7));
        assert!(label.contains("Grok Bot receipt unconfirmed"));
        assert!(label.contains("native subscribers notified: 7"));
        assert!(
            outbox::receipt_summary("local-crdb+jsonl", None)
                .contains("native subscribers notified: unavailable")
        );
    }

    #[test]
    fn explicit_http_rejection_is_distinct_from_an_unknown_send_outcome() {
        let rejected = ClientError::HttpStatus {
            status: 403,
            detail: "operator restricted".into(),
        };
        assert_eq!(
            explicit_rejection(&rejected).as_deref(),
            Some("HTTP 403: operator restricted")
        );
        let unknown = ClientError::SendOutcomeUnknown {
            reason: "response timed out".into(),
        };
        assert!(explicit_rejection(&unknown).is_none());
        assert!(unknown.send_outcome_unknown());
    }

    #[test]
    fn unknown_status_does_not_enable_sending() {
        assert!(!status_send_available(&serde_json::json!({})));
        assert!(!status_send_available(&serde_json::json!({"ok": true})));
        assert!(!status_send_available(&serde_json::json!({"ok": "true"})));
        assert!(!status_send_available(
            &serde_json::json!({"ok": true, "mode": "isolated-local-alpha", "storage_healthy": null})
        ));
    }

    #[test]
    fn sender_permissions_are_explicit_and_signed_mode_only_allows_brian() {
        let mut signed = serde_json::json!({"ok":true,"mode":"fleet-signed-ui","storage_healthy":true,"read_only":false,"send_allowed":true,"allowed_senders":["Brian"]});
        assert_eq!(status_allowed_senders(&signed), vec!["Brian"]);
        signed["allowed_senders"] = serde_json::json!(["Brian", "CODEX"]);
        assert!(!status_send_available(&signed));
        signed.as_object_mut().unwrap().remove("allowed_senders");
        assert!(status_allowed_senders(&signed).is_empty());
        let legacy = serde_json::json!({"ok":true,"daemon":{}});
        assert!(
            status_allowed_senders(&legacy).is_empty(),
            "missing sender policy must not grant posting identities"
        );
    }

    #[test]
    fn shared_read_only_bus_never_enables_sending() {
        let status = serde_json::json!({
            "ok": true,
            "mode": "fleet-ledger-read-only",
            "read_only": true,
            "send_allowed": false,
            "daemon": {},
            "transport": "local-ledger-read-only"
        });
        assert!(!status_send_available(&status));
        assert!(status_detail(&status).contains("Native coordination bus · read only"));
        assert!(status_detail(&status).contains("signing/delivery not invoked"));
    }

    #[test]
    fn reachable_http_with_stopped_daemon_does_not_enable_send() {
        for status in [
            serde_json::json!({"ok": false, "daemon": null}),
            serde_json::json!({"ok": true, "daemon": null}),
        ] {
            assert!(!status_send_available(&status));
            assert!(status_detail(&status).contains("daemon is stopped or unavailable"));
            assert!(status_detail(&status).contains("sending is disabled"));
        }
        let isolated = serde_json::json!({"ok": true, "mode": "isolated-local-alpha", "live_fleet": false, "storage_healthy": true});
        assert!(status_send_available(&isolated));
        assert!(status_detail(&isolated).contains("fleet delivery disabled"));
    }

    #[test]
    fn endpoint_edit_clears_delivered_receipt_but_retains_uncertainty() {
        let mut delivered = SendState::Delivered {
            id: "old-backend-message".into(),
            seq: 12,
            transport: "iroh-gossip".into(),
            sig_verified: true,
        };
        reset_receipt_on_endpoint_change(&mut delivered);
        assert!(matches!(delivered, SendState::Idle));
        let mut uncertain = SendState::Uncertain {
            body: "Keep this unsent-looking text".into(),
            error: "Response lost from the original backend".into(),
        };
        reset_receipt_on_endpoint_change(&mut uncertain);
        assert!(
            matches!(uncertain, SendState::Uncertain { body, .. } if body == "Keep this unsent-looking text")
        );
    }

    #[test]
    fn signed_native_banner_is_explicit_about_unverified_grok_receipt_without_disabling_send() {
        let status = serde_json::json!({"ok":true,"mode":"fleet-signed-ui","storage_healthy":true,"read_only":false,"send_allowed":true,"allowed_senders":["Brian"]});
        assert!(status_send_available(&status));
        let detail = status_detail(&status);
        assert!(detail.starts_with("Native coordination bus"));
        assert!(detail.contains("does not verify Grok Bot receipt"));
        assert!(!detail.contains("Grok Bot MGMT"));
    }
}
