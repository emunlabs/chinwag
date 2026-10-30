use super::{OnboardingError, disabled_status, observed_installation_id};
use chinwag_bus_client::{NativeOpenReceipt, NativeOpenRequest, NativeOpenState, OnboardingStatus};
use chinwag_client_discovery::{
    ClientFamily, INSTALLATION_CAPACITY, Installation, InstalledSnapshot, InventorySnapshot,
};
use chinwag_native_launch::{
    HostIdentity, HumanOperation, LaunchCoordinator, LaunchError, LaunchFailure,
    NativeApplicationLauncher, NativeObservation, OpenReceipt, is_launch_eligible,
};
use std::{
    collections::BTreeMap,
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    sync::{Arc, Mutex, TryLockError},
    time::{Duration, Instant},
};

mod journal;
use journal::{Domain, Journal};

const CACHE_LIFETIME: Duration = Duration::from_secs(30);
type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;
type Verifier = Arc<
    dyn Fn(&HostIdentity, &Installation) -> Result<NativeObservation, OnboardingError>
        + Send
        + Sync,
>;

pub(super) fn valid_request_id(id: &str) -> bool {
    (16..=100).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}
pub(super) fn valid_installation_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
pub(super) fn message(state: &NativeOpenState) -> &'static str {
    match state {
        NativeOpenState::Pending => {
            "Native application opening is pending; check this request before taking further action."
        }
        NativeOpenState::OpenedOrReused => {
            "macOS acknowledged the selected application opened or was reused. Connection and sign-in are unconfirmed."
        }
        NativeOpenState::Rejected => {
            "Opening was not acknowledged; refresh before another explicit request."
        }
        NativeOpenState::Uncertain => {
            "Native application opening is uncertain; this request will not be repeated automatically."
        }
    }
}
pub(super) fn receipt(
    id: &str,
    installation_id: &str,
    state: NativeOpenState,
) -> NativeOpenReceipt {
    let text = message(&state).into();
    NativeOpenReceipt {
        schema: "chinwag-native-open/v1".into(),
        request_id: id.into(),
        installation_id: installation_id.into(),
        state,
        message: text,
    }
}

#[derive(Clone)]
struct Target {
    host: HostIdentity,
    installation: Installation,
    observed_at: Instant,
    expires: Instant,
    revision: u64,
}
#[derive(Default)]
struct Cache {
    revision: u64,
    targets: BTreeMap<String, Target>,
}
struct Launcher(Box<dyn NativeApplicationLauncher + Send>);
impl NativeApplicationLauncher for Launcher {
    fn open_or_reuse(
        &mut self,
        target: &chinwag_native_launch::LaunchTarget,
        deadline: Instant,
    ) -> Result<OpenReceipt, LaunchFailure> {
        self.0.open_or_reuse(target, deadline)
    }
}

pub struct OnboardingService {
    journal: Mutex<Journal>,
    cache: Mutex<Cache>,
    active: Mutex<()>,
    active_operation: Mutex<Option<Arc<HumanOperation>>>,
    verifier: Verifier,
    launcher: Mutex<Launcher>,
    clock: Clock,
    family: Option<ClientFamily>,
}

impl OnboardingService {
    /// A distinct owner-enabled setup domain, sharing the same consumed-attempt
    /// mechanism. OS acknowledgement is not installation or MCP acceptance.
    pub fn new_cursor_mcp_native(
        journal_dir: &Path,
        binary: &Path,
        endpoint: String,
    ) -> Result<Self, OnboardingError> {
        #[cfg(target_os = "macos")]
        {
            let pinned = super::cursor::PinnedMcpBinary::open(binary)?;
            let spec = chinwag_native_launch::CursorMcpInstall::new(binary.to_owned(), endpoint)
                .map_err(|_| OnboardingError::Invalid)?;
            let mut service = Self::new_parts_in_domain(
                journal_dir,
                Arc::new(move |host, previous| {
                    pinned.revalidate()?;
                    let installation = chinwag_client_discovery::reobserve_application(previous)
                        .map_err(|_| OnboardingError::Unavailable)?;
                    Ok(NativeObservation::new(host.clone(), installation, Instant::now()))
                }),
                Box::new(chinwag_native_launch::macos::MacOsApplicationLauncher::for_cursor_mcp_setup_host(spec)),
                Arc::new(Instant::now),
                Domain::CursorMcpSetup,
            )?;
            service.family = Some(ClientFamily::Cursor);
            Ok(service)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (journal_dir, binary, endpoint);
            Err(OnboardingError::Unavailable)
        }
    }

    /// Caller must have opted into the serviced native main-loop host. This
    /// constructor performs no scan or launch and creates no connector grant.
    pub fn new_native(journal_dir: &Path) -> Result<Self, OnboardingError> {
        #[cfg(target_os = "macos")]
        {
            Self::new_parts(
                journal_dir,
                Arc::new(|host, previous| {
                    let installation = chinwag_client_discovery::reobserve_application(previous)
                        .map_err(|_| OnboardingError::Unavailable)?;
                    Ok(NativeObservation::new(
                        host.clone(),
                        installation,
                        Instant::now(),
                    ))
                }),
                Box::new(
                    chinwag_native_launch::macos::MacOsApplicationLauncher::for_main_loop_host(),
                ),
                Arc::new(Instant::now),
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = journal_dir;
            Err(OnboardingError::Unavailable)
        }
    }

    fn new_parts(
        journal_dir: &Path,
        verifier: Verifier,
        launcher: Box<dyn NativeApplicationLauncher + Send>,
        clock: Clock,
    ) -> Result<Self, OnboardingError> {
        Self::new_parts_in_domain(journal_dir, verifier, launcher, clock, Domain::OrdinaryOpen)
    }

    fn new_parts_in_domain(
        journal_dir: &Path,
        verifier: Verifier,
        launcher: Box<dyn NativeApplicationLauncher + Send>,
        clock: Clock,
        domain: Domain,
    ) -> Result<Self, OnboardingError> {
        Ok(Self {
            journal: Mutex::new(Journal::open_in_domain(journal_dir, domain)?),
            cache: Mutex::new(Cache::default()),
            active: Mutex::new(()),
            active_operation: Mutex::new(None),
            verifier,
            launcher: Mutex::new(Launcher(launcher)),
            clock,
            family: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_fixture(journal_dir: &Path) -> Result<Self, OnboardingError> {
        Self::new_fixture_in_domain(journal_dir, Domain::OrdinaryOpen)
    }

    #[cfg(test)]
    fn new_fixture_in_domain(journal_dir: &Path, domain: Domain) -> Result<Self, OnboardingError> {
        struct FixtureLauncher;
        impl NativeApplicationLauncher for FixtureLauncher {
            fn open_or_reuse(
                &mut self,
                target: &chinwag_native_launch::LaunchTarget,
                _: Instant,
            ) -> Result<OpenReceipt, LaunchFailure> {
                Ok(OpenReceipt {
                    application_path: target.application_path().into(),
                    bundle_id: target.bundle_id().into(),
                    process_id: Some(1),
                })
            }
        }
        Self::new_parts_in_domain(
            journal_dir,
            Arc::new(|host, installation| {
                Ok(NativeObservation::new(
                    host.clone(),
                    installation.clone(),
                    Instant::now(),
                ))
            }),
            Box::new(FixtureLauncher),
            Arc::new(Instant::now),
            domain,
        )
    }

    #[cfg(test)]
    pub(crate) fn new_cursor_fixture(journal_dir: &Path) -> Result<Self, OnboardingError> {
        let mut service = Self::new_fixture_in_domain(journal_dir, Domain::CursorMcpSetup)?;
        service.family = Some(ClientFamily::Cursor);
        Ok(service)
    }

    pub fn invalidate(&self) -> Result<(), OnboardingError> {
        self.invalidate_revision().map(|_| ())
    }

    fn invalidate_revision(&self) -> Result<u64, OnboardingError> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| OnboardingError::Unavailable)?;
        cache.targets.clear();
        let revision = cache.revision.checked_add(1);
        if let Some(revision) = revision {
            cache.revision = revision;
        }
        drop(cache);
        if let Some(operation) = self
            .active_operation
            .lock()
            .map_err(|_| OnboardingError::Unavailable)?
            .as_ref()
        {
            operation.cancel();
        }
        revision.ok_or(OnboardingError::Unavailable)
    }

    pub fn observe(
        &self,
        process: &InventorySnapshot,
        installed: &InstalledSnapshot,
    ) -> Result<(), OnboardingError> {
        let revision = self.invalidate_revision()?;
        if installed.installations.len() > INSTALLATION_CAPACITY {
            return Err(OnboardingError::Invalid);
        }
        let host = HostIdentity::new(process.host.label.clone(), process.host.boot_uuid.clone())
            .map_err(|_| OnboardingError::Invalid)?;
        let now = (self.clock)();
        let expires = now
            .checked_add(CACHE_LIFETIME)
            .ok_or(OnboardingError::Unavailable)?;
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| OnboardingError::Unavailable)?;
        if cache.revision != revision {
            return Err(OnboardingError::Unavailable);
        }
        for installation in &installed.installations {
            if !is_launch_eligible(installation)
                || self
                    .family
                    .is_some_and(|family| family != installation.family)
            {
                continue;
            }
            let id = observed_installation_id(process, installation);
            if cache
                .targets
                .insert(
                    id,
                    Target {
                        host: host.clone(),
                        installation: installation.clone(),
                        observed_at: now,
                        expires,
                        revision,
                    },
                )
                .is_some()
            {
                cache.targets.clear();
                return Err(OnboardingError::Invalid);
            }
        }
        Ok(())
    }

    pub fn status(&self) -> Result<OnboardingStatus, OnboardingError> {
        let journal = self
            .journal
            .lock()
            .map_err(|_| OnboardingError::Unavailable)?;
        if !journal.available() {
            return Ok(disabled_status());
        }
        drop(journal);
        let cache = self
            .cache
            .lock()
            .map_err(|_| OnboardingError::Unavailable)?;
        let now = (self.clock)();
        let ids = cache
            .targets
            .iter()
            .filter(|(_, target)| now < target.expires && now >= target.observed_at)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        Ok(OnboardingStatus {
            schema: "chinwag-native-onboarding/v1".into(),
            native_open_allowed: !ids.is_empty(),
            openable_installation_ids: ids,
        })
    }

    pub fn lookup(&self, request_id: &str) -> Result<Option<NativeOpenReceipt>, OnboardingError> {
        if !valid_request_id(request_id) {
            return Err(OnboardingError::Invalid);
        }
        self.journal
            .lock()
            .map_err(|_| OnboardingError::Unavailable)?
            .lookup(request_id)
    }

    pub fn open(
        &self,
        request_id: &str,
        request: &NativeOpenRequest,
    ) -> Result<NativeOpenReceipt, OnboardingError> {
        if !valid_request_id(request_id) || !valid_installation_id(&request.installation_id) {
            return Err(OnboardingError::Invalid);
        }
        if let Some(existing) = self.cached(request_id, request)? {
            return Ok(existing);
        }
        let _active = self.active.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => OnboardingError::Busy,
            TryLockError::Poisoned(_) => OnboardingError::Unavailable,
        })?;
        if let Some(existing) = self.cached(request_id, request)? {
            return Ok(existing);
        }
        let target = {
            let cache = self
                .cache
                .lock()
                .map_err(|_| OnboardingError::Unavailable)?;
            let now = (self.clock)();
            cache
                .targets
                .get(&request.installation_id)
                .filter(|target| now >= target.observed_at && now < target.expires)
                .cloned()
        };
        // Both file and containing directory have been fsynced before verifier
        // or launcher can run. No journal lock spans the native callback.
        self.journal
            .lock()
            .map_err(|_| OnboardingError::Unavailable)?
            .begin(request_id, &request.installation_id)?;
        let state = match target {
            Some(target) => match catch_unwind(AssertUnwindSafe(|| self.execute(&target))) {
                Ok(state) => state,
                Err(_) => NativeOpenState::Uncertain,
            },
            None => NativeOpenState::Rejected,
        };
        let result = receipt(request_id, &request.installation_id, state);
        self.journal
            .lock()
            .map_err(|_| OnboardingError::Unavailable)?
            .finish(result)
    }

    fn cached(
        &self,
        id: &str,
        request: &NativeOpenRequest,
    ) -> Result<Option<NativeOpenReceipt>, OnboardingError> {
        let existing = self
            .journal
            .lock()
            .map_err(|_| OnboardingError::Unavailable)?
            .lookup(id)?;
        if existing
            .as_ref()
            .is_some_and(|value| value.installation_id != request.installation_id)
        {
            return Err(OnboardingError::Conflict);
        }
        Ok(existing)
    }

    fn current(&self, target: &Target) -> bool {
        let now = (self.clock)();
        now >= target.observed_at
            && now < target.expires
            && self.cache.lock().is_ok_and(|cache| {
                cache.revision == target.revision
                    && cache.targets.values().any(|entry| {
                        entry.host == target.host && entry.installation == target.installation
                    })
            })
    }

    fn execute(&self, target: &Target) -> NativeOpenState {
        if !self.current(target) {
            return NativeOpenState::Rejected;
        }
        let mut coordinator = match LaunchCoordinator::new(1, CACHE_LIFETIME) {
            Ok(value) => value,
            Err(_) => return NativeOpenState::Rejected,
        };
        let now = (self.clock)();
        let operation =
            match coordinator.begin_human_operation(target.host.clone(), target.expires, now) {
                Ok(value) => value,
                Err(_) => return NativeOpenState::Rejected,
            };
        let operation = Arc::new(operation);
        let mut slot = match self.active_operation.lock() {
            Ok(value) => value,
            Err(_) => return NativeOpenState::Rejected,
        };
        *slot = Some(Arc::clone(&operation));
        drop(slot);
        let _operation_guard = ActiveOperation {
            slot: &self.active_operation,
            operation: Arc::clone(&operation),
        };
        if !self.current(target) {
            return NativeOpenState::Rejected;
        }
        let previous = NativeObservation::new(
            target.host.clone(),
            target.installation.clone(),
            target.observed_at,
        );
        let plan = match coordinator.plan(&operation, &previous, now) {
            Ok(value) => value,
            Err(_) => return NativeOpenState::Rejected,
        };
        let fresh = match (self.verifier)(&target.host, &target.installation) {
            Ok(value) => value,
            Err(_) => return NativeOpenState::Rejected,
        };
        if !self.current(target) {
            return NativeOpenState::Rejected;
        }
        let mut launcher = match self.launcher.lock() {
            Ok(value) => value,
            Err(_) => return NativeOpenState::Rejected,
        };
        // Catch while the launcher mutex remains held so a backend panic is an
        // uncertain attempt, not a poisoned global native-opening latch.
        let result = catch_unwind(AssertUnwindSafe(|| {
            coordinator.execute(&plan, &fresh, &mut *launcher, || (self.clock)())
        }));
        let state = match result {
            Ok(Ok(_)) => NativeOpenState::OpenedOrReused,
            Ok(Err(LaunchError::Execution(LaunchFailure::Uncertain(_)))) | Err(_) => {
                NativeOpenState::Uncertain
            }
            Ok(Err(_)) => NativeOpenState::Rejected,
        };
        if matches!(state, NativeOpenState::OpenedOrReused) && !self.current(target) {
            NativeOpenState::Uncertain
        } else {
            state
        }
    }
}

struct ActiveOperation<'a> {
    slot: &'a Mutex<Option<Arc<HumanOperation>>>,
    operation: Arc<HumanOperation>,
}

impl Drop for ActiveOperation<'_> {
    fn drop(&mut self) {
        self.operation.cancel();
        if let Ok(mut slot) = self.slot.lock()
            && slot
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &self.operation))
        {
            *slot = None;
        }
    }
}

#[cfg(test)]
mod tests;
