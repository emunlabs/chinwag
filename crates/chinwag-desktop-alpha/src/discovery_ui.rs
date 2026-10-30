use crate::openings::OpeningAction;
use chinwag_bus_client::{
    ClientInventory, ClientKind, InstallationLocation, InstalledClient, OnboardingStatus,
};
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;

fn snapshot_time(milliseconds: u64) -> String {
    i64::try_from(milliseconds)
        .ok()
        .and_then(DateTime::<Utc>::from_timestamp_millis)
        .map(|time| time.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "Unavailable".into())
}

fn family_label(family: &str) -> String {
    match family {
        "codex_cli" => "Codex CLI".into(),
        "codex_desktop" => "Codex Desktop".into(),
        "chatgpt_desktop" => "ChatGPT".into(),
        "claude_code" => "Claude Code".into(),
        "claude_desktop" => "Claude Desktop".into(),
        "grok_bot" => "Grok Bot".into(),
        "gemini_cli" => "Gemini CLI".into(),
        "gemini_desktop" => "Gemini Desktop".into(),
        "google_antigravity" => "Antigravity".into(),
        "cursor" => "Cursor".into(),
        "opencode" => "OpenCode".into(),
        "aider" => "Aider".into(),
        "github_copilot" => "GitHub Copilot".into(),
        "kiro" => "Kiro".into(),
        "amazon_q" => "Amazon Q".into(),
        "windsurf" => "Windsurf".into(),
        "ollama" => "Ollama".into(),
        "lm_studio" => "LM Studio".into(),
        "goose" => "Goose".into(),
        "amp" => "Amp".into(),
        "droid" => "Droid".into(),
        "continue" => "Continue".into(),
        "cline" => "Cline".into(),
        "roo_code" => "Roo Code".into(),
        "mistral_vibe" => "Mistral Vibe".into(),
        "warp" => "Warp".into(),
        "zed" => "Zed".into(),
        "visual_studio_code" => "Visual Studio Code".into(),
        "jan" => "Jan".into(),
        "msty" => "Msty".into(),
        "cherry_studio" => "Cherry Studio".into(),
        "boltai" => "BoltAI".into(),
        "chatbox" => "Chatbox".into(),
        "gpt4all" => "GPT4All".into(),
        "anything_llm" => "AnythingLLM".into(),
        "perplexity" => "Perplexity".into(),
        _ => family.replace('_', " "),
    }
}

#[derive(Default)]
struct FamilyCounts {
    runtime_groups: usize,
    components: usize,
    installations: usize,
    installation_running_hints: usize,
    application: bool,
    command_line: bool,
}

impl FamilyCounts {
    fn add_kind(&mut self, kind: ClientKind) {
        match kind {
            ClientKind::Application => self.application = true,
            ClientKind::CommandLine => self.command_line = true,
        }
    }

    fn description(&self) -> String {
        let kind = match (self.application, self.command_line) {
            (true, true) => "app and command line",
            (false, true) => "command line",
            _ => "application",
        };
        let installed = match self.installations {
            0 => String::new(),
            1 => "Installed · ".into(),
            count => format!("Installed in {count} locations · "),
        };
        if self.runtime_groups == 0 {
            let running = if self.installation_running_hints == 0 {
                "running not observed".into()
            } else {
                counted(
                    self.installation_running_hints,
                    "running hint",
                    "running hints",
                )
            };
            return format!("{kind} · {installed}{running} · not connected");
        }
        let instances = counted(self.runtime_groups, "running instance", "running instances");
        let components = counted(self.components, "component", "components");
        let hint = if self.installation_running_hints > self.runtime_groups {
            format!(
                " · installation running hints: {}",
                self.installation_running_hints
            )
        } else {
            String::new()
        };
        format!("{kind} · {installed}{instances} · {components} · Detected · not connected{hint}")
    }
}

fn counted(count: usize, singular: &str, plural: &str) -> String {
    format!("{count} {}", if count == 1 { singular } else { plural })
}

fn copy_hint(app: &InstalledClient) -> String {
    let mut parts = vec![family_label(&app.family)];
    if let Some(location) = &app.location {
        parts.push(
            match location {
                InstallationLocation::SharedApplications => "Applications",
                InstallationLocation::UserApplications => "Your Applications",
            }
            .into(),
        );
    }
    if let Some(version) = &app.version {
        parts.push(format!("Version {version}"));
    }
    parts.join(" · ")
}

fn grouped_families(inventory: &ClientInventory) -> BTreeMap<&str, FamilyCounts> {
    let mut families: BTreeMap<&str, FamilyCounts> = BTreeMap::new();
    for client in &inventory.clients {
        let counts = families.entry(&client.family).or_default();
        counts.runtime_groups += 1;
        counts.components += client.component_count;
        counts.add_kind(client.kind);
    }
    if let Some(installations) = &inventory.installations {
        for app in &installations.apps {
            let counts = families.entry(&app.family).or_default();
            counts.installations += 1;
            counts.installation_running_hints += app.running_instances;
            counts.add_kind(app.kind);
        }
    }
    families
}

pub enum InventoryState {
    NotRequested,
    Loading,
    Ready(Box<ClientInventory>),
    Unavailable(String),
}

pub struct DiscoveryPanel {
    pub endpoint: Option<String>,
    pub state: InventoryState,
    pub expanded: bool,
    pub details_expanded: bool,
    pub opening_status: Option<OnboardingStatus>,
    pub opening_notice: Option<String>,
    pub cursor_mcp_status: Option<OnboardingStatus>,
    pub cursor_mcp_notice: Option<String>,
    generation: u64,
}

impl Default for DiscoveryPanel {
    fn default() -> Self {
        Self {
            endpoint: None,
            state: InventoryState::NotRequested,
            expanded: true,
            details_expanded: false,
            opening_status: None,
            opening_notice: None,
            cursor_mcp_status: None,
            cursor_mcp_notice: None,
            generation: 0,
        }
    }
}

impl DiscoveryPanel {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn installed_copy(&self, id: &str) -> Option<InstalledClient> {
        let InventoryState::Ready(inventory) = &self.state else {
            return None;
        };
        inventory
            .installations
            .as_ref()?
            .apps
            .iter()
            .find(|app| app.kind == ClientKind::Application && app.id == id)
            .cloned()
    }

    pub fn clear(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.endpoint = None;
        self.state = InventoryState::NotRequested;
        self.opening_status = None;
        self.opening_notice = None;
        self.cursor_mcp_status = None;
        self.cursor_mcp_notice = None;
    }

    pub fn begin(&mut self, endpoint: String) -> u64 {
        self.generation = self.generation.wrapping_add(1);
        self.endpoint = Some(endpoint);
        self.state = InventoryState::Loading;
        self.opening_status = None;
        self.opening_notice = None;
        self.cursor_mcp_status = None;
        self.cursor_mcp_notice = None;
        self.generation
    }

    pub fn complete(
        &mut self,
        generation: u64,
        endpoint: &str,
        result: Result<ClientInventory, String>,
    ) -> bool {
        if generation != self.generation || self.endpoint.as_deref() != Some(endpoint) {
            return false;
        }
        self.state = match result {
            Ok(inventory) => InventoryState::Ready(Box::new(inventory)),
            Err(error) => InventoryState::Unavailable(error.chars().take(300).collect()),
        };
        true
    }

    pub fn complete_opening_status(
        &mut self,
        generation: u64,
        endpoint: &str,
        result: Result<OnboardingStatus, String>,
    ) -> bool {
        self.complete_action_status(generation, endpoint, OpeningAction::OrdinaryOpen, result)
    }

    pub fn complete_cursor_mcp_status(
        &mut self,
        generation: u64,
        endpoint: &str,
        result: Result<OnboardingStatus, String>,
    ) -> bool {
        self.complete_action_status(generation, endpoint, OpeningAction::CursorMcpSetup, result)
    }

    pub fn action_status(&self, action: OpeningAction) -> Option<&OnboardingStatus> {
        match action {
            OpeningAction::OrdinaryOpen => self.opening_status.as_ref(),
            OpeningAction::CursorMcpSetup => self.cursor_mcp_status.as_ref(),
        }
    }

    pub fn set_action_notice(&mut self, action: OpeningAction, notice: Option<String>) {
        match action {
            OpeningAction::OrdinaryOpen => self.opening_notice = notice,
            OpeningAction::CursorMcpSetup => self.cursor_mcp_notice = notice,
        }
    }

    fn complete_action_status(
        &mut self,
        generation: u64,
        endpoint: &str,
        action: OpeningAction,
        result: Result<OnboardingStatus, String>,
    ) -> bool {
        if generation != self.generation
            || self.endpoint.as_deref() != Some(endpoint)
            || !matches!(self.state, InventoryState::Ready(_))
        {
            return false;
        }
        let (status_slot, notice_slot, disabled, unavailable) = match action {
            OpeningAction::OrdinaryOpen => (
                &mut self.opening_status,
                &mut self.opening_notice,
                "Opening is disabled for this host.",
                "Opening is unavailable on this host. Finding apps still works.",
            ),
            OpeningAction::CursorMcpSetup => (
                &mut self.cursor_mcp_status,
                &mut self.cursor_mcp_notice,
                "Cursor setup is disabled for this host.",
                "Cursor setup is unavailable on this host. Finding apps and ordinary opening still work.",
            ),
        };
        match result {
            Ok(status) if status.validate().is_ok() => {
                *notice_slot = (!status.native_open_allowed).then(|| disabled.into());
                *status_slot = Some(status);
            }
            _ => {
                *status_slot = None;
                *notice_slot = Some(unavailable.into());
            }
        }
        true
    }

    fn action_apps(&self, action: OpeningAction) -> Vec<&InstalledClient> {
        let InventoryState::Ready(inventory) = &self.state else {
            return Vec::new();
        };
        let Some(status) = self.action_status(action) else {
            return Vec::new();
        };
        if !status.native_open_allowed {
            return Vec::new();
        }
        let Some(installed) = &inventory.installations else {
            return Vec::new();
        };
        installed
            .apps
            .iter()
            .filter(|app| {
                app.kind == ClientKind::Application
                    && (action != OpeningAction::CursorMcpSetup || app.family == "cursor")
                    && status.openable_installation_ids.contains(&app.id)
            })
            .collect()
    }

    pub fn action_copies(&self, action: OpeningAction) -> Vec<(String, String)> {
        self.action_apps(action)
            .into_iter()
            .map(|app| (app.id.clone(), copy_hint(app)))
            .collect()
    }

    pub fn copy_disambiguation(&self, id: &str) -> Option<String> {
        let apps = self.actionable_apps();
        let app = apps.iter().find(|app| app.id == id)?;
        let hint = copy_hint(app);
        let ambiguous = apps.iter().filter(|other| copy_hint(other) == hint).count() > 1;
        if !ambiguous && (app.location.is_some() || app.version.is_some()) {
            return None;
        }
        let suffix = (8..=64)
            .step_by(4)
            .filter_map(|length| app.id.get(app.id.len().saturating_sub(length)..))
            .find(|suffix| {
                !apps
                    .iter()
                    .any(|other| other.id != app.id && other.id.ends_with(suffix))
            })
            .unwrap_or(&app.id);
        Some(format!("Copy {suffix}"))
    }

    fn actionable_apps(&self) -> Vec<&InstalledClient> {
        let mut apps = self.action_apps(OpeningAction::OrdinaryOpen);
        for app in self.action_apps(OpeningAction::CursorMcpSetup) {
            if !apps.iter().any(|other| other.id == app.id) {
                apps.push(app);
            }
        }
        apps
    }

    pub fn actionable_copies(&self) -> Vec<(String, String)> {
        self.actionable_apps()
            .into_iter()
            .map(|app| (app.id.clone(), copy_hint(app)))
            .collect()
    }

    pub fn summary(&self) -> String {
        match &self.state {
            InventoryState::NotRequested => {
                "Choose Find apps to check the configured bus host.".into()
            }
            InventoryState::Loading => format!(
                "Finding apps on {}",
                self.endpoint.as_deref().unwrap_or("configured bus")
            ),
            InventoryState::Unavailable(error) => format!("Unavailable · {error}"),
            InventoryState::Ready(inventory) => format!(
                "{} · {} · {}",
                inventory.host_label,
                counted(
                    grouped_families(inventory).len(),
                    "app family",
                    "app families"
                ),
                counted(
                    inventory.clients.len(),
                    "running instance",
                    "running instances"
                )
            ),
        }
    }

    pub fn coverage_lines(&self) -> Vec<String> {
        let InventoryState::Ready(inventory) = &self.state else {
            return Vec::new();
        };
        let c = &inventory.coverage;
        let mut lines = vec![
            format!(
                "Running snapshot: {}",
                snapshot_time(inventory.observed_at_unix_ms)
            ),
            format!(
                "Sampled {}/{} processes · {}/{} candidate components · unresolved components: {}",
                c.sampled_pid_count,
                c.pid_capacity,
                c.candidate_process_count,
                c.candidate_capacity,
                c.unresolved_components
            ),
            format!(
                "Unclassified interpreters: {} (not identified as clients) · raced: {} · denied: {} · unavailable: {} · invalid metadata: {}",
                c.unclassified_interpreters,
                c.raced_processes,
                c.permission_denied_processes,
                c.unavailable_processes,
                c.invalid_process_metadata
            ),
        ];
        if c.pid_capacity_reached || c.candidate_capacity_reached || c.omitted_candidate_count > 0 {
            lines.push(format!("Capacity reached · process cap: {} · candidate cap: {} · omitted candidates: {}. Snapshot coverage is incomplete.",c.pid_capacity_reached,c.candidate_capacity_reached,c.omitted_candidate_count));
        } else {
            lines.push("Bounded snapshot; generic interpreters may host unidentified clients. Discovery grants no admission or control.".into());
        }
        if let Some(installations) = &inventory.installations {
            let c = &installations.coverage;
            lines.push(format!(
                "Installed snapshot: {} · {} installation records · {}/{} entries examined · installation cap: {}",
                snapshot_time(installations.observed_at_unix_ms), installations.apps.len(),
                c.entries_examined, c.entry_capacity, c.installation_capacity
            ));
            lines.push(format!(
                "Installation capacity reached: {} · unavailable roots: {} · invalid metadata: {}. Installation does not establish connection readiness.",
                c.capacity_reached, c.unavailable_roots, c.invalid_metadata
            ));
        } else {
            lines.push("Installed apps were not included by this runtime. Running observations alone cannot identify every installed app.".into());
        }
        lines
    }

    pub fn coverage_warning(&self) -> Option<&'static str> {
        let InventoryState::Ready(inventory) = &self.state else {
            return None;
        };
        let c = &inventory.coverage;
        let incomplete = c.pid_capacity_reached
            || c.candidate_capacity_reached
            || c.omitted_candidate_count > 0
            || c.permission_denied_processes > 0
            || c.unavailable_processes > 0
            || c.invalid_process_metadata > 0
            || inventory.installations.as_ref().is_some_and(|installed| {
                installed.coverage.capacity_reached
                    || installed.coverage.unavailable_roots > 0
                    || installed.coverage.invalid_metadata > 0
            });
        incomplete.then_some("Some apps may be missing. See discovery details.")
    }

    pub fn rows(&self) -> Vec<String> {
        let InventoryState::Ready(inventory) = &self.state else {
            return Vec::new();
        };
        let mut rows: Vec<_> = grouped_families(inventory).into_iter().collect();
        rows.sort_by_cached_key(|(family, counts)| {
            (
                counts.runtime_groups == 0,
                *family != "grok_bot",
                family_label(family).to_lowercase(),
            )
        });
        rows.into_iter()
            .map(|(family, counts)| format!("{} · {}", family_label(family), counts.description()))
            .collect()
    }
}

#[cfg(test)]
mod tests;
