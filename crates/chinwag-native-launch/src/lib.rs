//! Exact-copy native application opening for explicit, host-local onboarding.
//!
//! Installation observations and these opaque operation handles are not account
//! authentication or connector grants. The trusted host must create operations
//! only for human actions and supply fresh observations from its local collector.
//! This module performs no filesystem access, discovery, launching or networking.

use chinwag_client_discovery::{
    ClientFamily, ExecutableFormat, Installation, InstallationKind, catalogue::InstallationMatch,
};
use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[cfg(target_os = "macos")]
pub mod macos;

pub const MAX_PLANS_PER_OPERATION: usize = 128;
pub const MAX_OBSERVATION_AGE: Duration = Duration::from_secs(30);
pub const MAX_OPERATION_LIFETIME: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostIdentity {
    host_id: String,
    boot_id: String,
}

impl HostIdentity {
    pub fn new(host_id: String, boot_id: String) -> Result<Self, LaunchError> {
        if !valid_label(&host_id) || !valid_label(&boot_id) {
            return Err(LaunchError::InvalidHostIdentity);
        }
        Ok(Self { host_id, boot_id })
    }

    pub fn host_id(&self) -> &str {
        &self.host_id
    }

    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }
}

/// A trusted host-local collector observation, not a deserializable launch grant.
#[derive(Debug)]
pub struct NativeObservation {
    host: HostIdentity,
    installation: Installation,
    observed_at: Instant,
}

impl NativeObservation {
    pub fn new(host: HostIdentity, installation: Installation, observed_at: Instant) -> Self {
        Self {
            host,
            installation,
            observed_at,
        }
    }
}

#[derive(Debug)]
struct CoordinatorIdentity;

/// A single human-started operation. Dropping it does not undo an OS request.
#[derive(Debug)]
pub struct HumanOperation {
    owner: Arc<CoordinatorIdentity>,
    generation: u64,
    host: HostIdentity,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
}

impl HumanOperation {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn host(&self) -> &HostIdentity {
        &self.host
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// May also be called by the UI while a worker is awaiting macOS completion.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

/// Exact selected copy, deliberately neither Clone nor serde-compatible.
#[derive(Debug)]
pub struct LaunchTarget {
    installation: Installation,
    host: HostIdentity,
    cancelled: Arc<AtomicBool>,
}

impl LaunchTarget {
    pub fn installation(&self) -> &Installation {
        &self.installation
    }

    pub fn application_path(&self) -> &Path {
        &self.installation.canonical_path
    }

    pub fn executable_path(&self) -> &Path {
        &self.installation.executable_path
    }

    pub fn bundle_id(&self) -> &str {
        // Only validated recipe targets can be constructed by this module.
        self.installation.bundle_id.as_deref().unwrap_or_default()
    }

    pub fn display_name(&self) -> &str {
        &self.installation.display_name
    }

    pub fn metadata_fingerprint(&self) -> &str {
        &self.installation.metadata_fingerprint
    }

    pub fn host(&self) -> &HostIdentity {
        &self.host
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn cancellation_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }
}

/// An opaque once-only plan. Its executor target is inaccessible to callers, so
/// the supported path always passes through fresh coordinator validation.
///
/// ```compile_fail
/// use chinwag_native_launch::LaunchPlan;
/// fn bypass(plan: &LaunchPlan) { let _target = plan.target(); }
/// ```
#[derive(Debug)]
pub struct LaunchPlan {
    owner: Arc<CoordinatorIdentity>,
    generation: u64,
    id: u64,
    deadline: Instant,
    target: LaunchTarget,
}

impl LaunchPlan {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    #[cfg(test)]
    fn target(&self) -> &LaunchTarget {
        &self.target
    }
}

/// OS acknowledgement that this exact copy opened or was reused. This does not
/// establish connection, sign-in, protocol support, account identity or a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenReceipt {
    pub application_path: PathBuf,
    pub bundle_id: String,
    pub process_id: Option<u32>,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum LaunchFailure {
    #[error("native opening rejected: {0}")]
    Rejected(&'static str),
    #[error("native opening unavailable: {0}")]
    Unavailable(&'static str),
    #[error("human access required: {0}")]
    AccessRequired(&'static str),
    #[error("native opening outcome uncertain: {0}")]
    Uncertain(&'static str),
}

/// Implementations must open the exact URL without bundle-ID substitution,
/// request no new application instance or prompts, and never terminate a reused
/// app. macOS may still show Gatekeeper UI. A possible OS submission followed by
/// timeout/cancellation is Uncertain, never safe permission to retry.
pub trait NativeApplicationLauncher {
    fn open_or_reuse(
        &mut self,
        target: &LaunchTarget,
        deadline: Instant,
    ) -> Result<OpenReceipt, LaunchFailure>;
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LaunchError {
    #[error("host and boot identity must be nonempty bounded public labels")]
    InvalidHostIdentity,
    #[error("invalid bounded launch coordinator configuration")]
    InvalidConfiguration,
    #[error("human operation deadline must be in the next five minutes")]
    InvalidDeadline,
    #[error("operation or plan belongs to another coordinator")]
    ForeignOperation,
    #[error("human operation was superseded")]
    StaleGeneration,
    #[error("human operation was cancelled")]
    Cancelled,
    #[error("human operation expired")]
    Expired,
    #[error("host or boot differs from the human operation")]
    HostChanged,
    #[error("installation observation is stale or from the future")]
    StaleObservation,
    #[error("installation does not match a supported native application recipe")]
    UnsupportedInstallation,
    #[error("selected installation changed; start a new explicit operation")]
    InstallationChanged,
    #[error("this exact copy already has a plan in the operation")]
    AlreadyPlanned,
    #[error("this plan has already been attempted; automatic retry is prohibited")]
    AlreadyAttempted,
    #[error("operation plan capacity reached")]
    Capacity,
    #[error("opaque launch identifier capacity exhausted")]
    IdentifierExhausted,
    #[error(transparent)]
    Execution(#[from] LaunchFailure),
}

#[derive(Debug)]
struct PlanState {
    application_path: PathBuf,
    attempted: bool,
}

/// One writer for one current onboarding operation. This is not a second client
/// registry and retains no authentication or connection state. New human intent
/// supersedes old plans; it does not automatically replay any previous attempt.
#[derive(Debug)]
pub struct LaunchCoordinator {
    owner: Arc<CoordinatorIdentity>,
    generation: u64,
    next_plan_id: u64,
    current: Option<Arc<AtomicBool>>,
    max_plans: usize,
    max_observation_age: Duration,
    plans: BTreeMap<u64, PlanState>,
}

impl LaunchCoordinator {
    pub fn new(max_plans: usize, max_observation_age: Duration) -> Result<Self, LaunchError> {
        if max_plans == 0
            || max_plans > MAX_PLANS_PER_OPERATION
            || max_observation_age.is_zero()
            || max_observation_age > MAX_OBSERVATION_AGE
        {
            return Err(LaunchError::InvalidConfiguration);
        }
        Ok(Self {
            owner: Arc::new(CoordinatorIdentity),
            generation: 0,
            next_plan_id: 0,
            current: None,
            max_plans,
            max_observation_age,
            plans: BTreeMap::new(),
        })
    }

    pub fn begin_human_operation(
        &mut self,
        host: HostIdentity,
        deadline: Instant,
        now: Instant,
    ) -> Result<HumanOperation, LaunchError> {
        deadline
            .checked_duration_since(now)
            .filter(|age| !age.is_zero() && *age <= MAX_OPERATION_LIFETIME)
            .ok_or(LaunchError::InvalidDeadline)?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(LaunchError::IdentifierExhausted)?;
        if let Some(previous) = &self.current {
            previous.store(true, Ordering::Release);
        }
        self.generation = generation;
        self.plans.clear();
        let cancelled = Arc::new(AtomicBool::new(false));
        self.current = Some(Arc::clone(&cancelled));
        Ok(HumanOperation {
            owner: Arc::clone(&self.owner),
            generation,
            host,
            deadline,
            cancelled,
        })
    }

    pub fn cancel(&mut self, operation: &HumanOperation) -> Result<(), LaunchError> {
        self.check_owner_generation(&operation.owner, operation.generation)?;
        operation.cancel();
        Ok(())
    }

    pub fn plan(
        &mut self,
        operation: &HumanOperation,
        observation: &NativeObservation,
        now: Instant,
    ) -> Result<LaunchPlan, LaunchError> {
        self.check_operation(operation, now)?;
        self.check_observation(&operation.host, observation, now)?;
        validate_installation(&observation.installation)?;
        if self
            .plans
            .values()
            .any(|entry| entry.application_path == observation.installation.canonical_path)
        {
            return Err(LaunchError::AlreadyPlanned);
        }
        if self.plans.len() == self.max_plans {
            return Err(LaunchError::Capacity);
        }
        let id = self
            .next_plan_id
            .checked_add(1)
            .ok_or(LaunchError::IdentifierExhausted)?;
        self.next_plan_id = id;
        self.plans.insert(
            id,
            PlanState {
                application_path: observation.installation.canonical_path.clone(),
                attempted: false,
            },
        );
        Ok(LaunchPlan {
            owner: Arc::clone(&self.owner),
            generation: operation.generation,
            id,
            deadline: operation.deadline,
            target: LaunchTarget {
                installation: observation.installation.clone(),
                host: operation.host.clone(),
                cancelled: Arc::clone(&operation.cancelled),
            },
        })
    }

    pub fn execute<L: NativeApplicationLauncher, C: FnMut() -> Instant>(
        &mut self,
        plan: &LaunchPlan,
        fresh: &NativeObservation,
        launcher: &mut L,
        mut clock: C,
    ) -> Result<OpenReceipt, LaunchError> {
        self.check_owner_generation(&plan.owner, plan.generation)?;
        let state = self
            .plans
            .get_mut(&plan.id)
            .ok_or(LaunchError::StaleGeneration)?;
        if state.attempted {
            return Err(LaunchError::AlreadyAttempted);
        }
        // Consume even a failed revalidation: any retry needs fresh human intent.
        state.attempted = true;
        let before = clock();
        if plan.target.is_cancelled() {
            return Err(LaunchError::Cancelled);
        }
        if before >= plan.deadline {
            return Err(LaunchError::Expired);
        }
        self.check_observation(&plan.target.host, fresh, before)?;
        validate_installation(&fresh.installation)?;
        if !same_installation(&plan.target.installation, &fresh.installation) {
            return Err(LaunchError::InstallationChanged);
        }
        let freshness_deadline = fresh
            .observed_at
            .checked_add(self.max_observation_age)
            .ok_or(LaunchError::StaleObservation)?;
        let effective_deadline = plan.deadline.min(freshness_deadline);
        if before >= effective_deadline {
            return Err(LaunchError::StaleObservation);
        }
        let result = launcher.open_or_reuse(&plan.target, effective_deadline);
        let after = clock();
        if after < before || after >= effective_deadline || plan.target.is_cancelled() {
            return Err(
                LaunchFailure::Uncertain("completion after cancellation or deadline").into(),
            );
        }
        match result {
            Ok(receipt) => {
                if receipt.application_path != plan.target.application_path()
                    || receipt.bundle_id != plan.target.bundle_id()
                    || receipt.process_id == Some(0)
                {
                    return Err(LaunchFailure::Uncertain(
                        "OS receipt did not identify the exact selected copy",
                    )
                    .into());
                }
                Ok(receipt)
            }
            Err(error) => Err(error.into()),
        }
    }

    fn check_owner_generation(
        &self,
        owner: &Arc<CoordinatorIdentity>,
        generation: u64,
    ) -> Result<(), LaunchError> {
        if !Arc::ptr_eq(&self.owner, owner) {
            return Err(LaunchError::ForeignOperation);
        }
        if generation != self.generation {
            return Err(LaunchError::StaleGeneration);
        }
        Ok(())
    }

    fn check_operation(&self, operation: &HumanOperation, now: Instant) -> Result<(), LaunchError> {
        self.check_owner_generation(&operation.owner, operation.generation)?;
        if operation.cancelled.load(Ordering::Acquire) {
            return Err(LaunchError::Cancelled);
        }
        if now >= operation.deadline {
            return Err(LaunchError::Expired);
        }
        Ok(())
    }

    fn check_observation(
        &self,
        host: &HostIdentity,
        observation: &NativeObservation,
        now: Instant,
    ) -> Result<(), LaunchError> {
        if host != &observation.host {
            return Err(LaunchError::HostChanged);
        }
        if now
            .checked_duration_since(observation.observed_at)
            .is_none_or(|age| age > self.max_observation_age)
        {
            return Err(LaunchError::StaleObservation);
        }
        Ok(())
    }
}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .to_str()
            .is_some_and(|text| text.len() <= 4096 && !text.chars().any(char::is_control))
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

fn validate_installation(installation: &Installation) -> Result<(), LaunchError> {
    let (name, bundle, executable) =
        recipe(installation.family).ok_or(LaunchError::UnsupportedInstallation)?;
    if installation.kind != InstallationKind::Application
        || installation.match_basis != InstallationMatch::PublicBundleIdentity
        || installation.executable.format != ExecutableFormat::MachO
        || installation.bundle_id.as_deref() != Some(bundle)
        || installation.display_name != name
        || !canonical_absolute(&installation.canonical_path)
        || installation
            .canonical_path
            .extension()
            .is_none_or(|extension| extension != "app")
        || installation.executable_path
            != installation
                .canonical_path
                .join("Contents/MacOS")
                .join(executable)
        || !valid_digest(&installation.id)
        || !valid_digest(&installation.metadata_fingerprint)
        || installation.executable.mode & 0o170000 != 0o100000
        || installation.executable.mode & 0o111 == 0
        || installation.executable.size == 0
        || !(0..1_000_000_000).contains(&installation.executable.modified_nanoseconds)
    {
        return Err(LaunchError::UnsupportedInstallation);
    }
    Ok(())
}

fn same_installation(expected: &Installation, fresh: &Installation) -> bool {
    expected.id == fresh.id
        && expected.family == fresh.family
        && expected.kind == fresh.kind
        && expected.match_basis == fresh.match_basis
        && expected.canonical_path == fresh.canonical_path
        && expected.display_name == fresh.display_name
        && expected.bundle_id == fresh.bundle_id
        && expected.executable_path == fresh.executable_path
        && expected.executable == fresh.executable
        && expected.metadata_fingerprint == fresh.metadata_fingerprint
}

fn recipe(family: ClientFamily) -> Option<(&'static str, &'static str, &'static str)> {
    Some(match family {
        ClientFamily::GrokBot => ("Grok Bot", "com.anysphere.sand", "Grok Bot"),
        ClientFamily::ChatgptDesktop => ("ChatGPT", "com.openai.codex", "ChatGPT"),
        ClientFamily::CodexDesktop => ("Codex", "com.openai.codex", "Codex"),
        ClientFamily::ClaudeDesktop => ("Claude", "com.anthropic.claudefordesktop", "Claude"),
        ClientFamily::GeminiDesktop => ("Gemini", "com.google.GeminiMacOS", "Gemini"),
        ClientFamily::GoogleAntigravity => ("Antigravity", "com.google.antigravity", "Antigravity"),
        ClientFamily::Cursor => ("Cursor", "com.todesktop.230313mzl4w4u92", "Cursor"),
        ClientFamily::Windsurf => ("Windsurf", "com.exafunction.windsurf", "Electron"),
        ClientFamily::VisualStudioCode => ("Code", "com.microsoft.VSCode", "Code"),
        ClientFamily::Warp => ("Warp", "dev.warp.Warp-Stable", "stable"),
        ClientFamily::LmStudio => ("LM Studio", "ai.elementlabs.lmstudio", "LM Studio"),
        ClientFamily::AnythingLlm => ("AnythingLLM", "com.anythingllm", "AnythingLLM"),
        _ => return None,
    })
}

#[cfg(test)]
mod tests;
