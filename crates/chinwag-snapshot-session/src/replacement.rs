//! Original private replacement owner. No recovery or filesystem SQLite API.
mod domain;
mod handoff;
#[cfg(feature = "private-probe")]
mod probe_message;
pub use handoff::HandoffRequest;
#[cfg(feature = "private-probe")]
pub use probe_message::SeedMessage;
mod owner;
use crate::{Error, NativeCounts, Rows, Value, native::Connection};
#[cfg(feature = "private-probe")]
pub use domain::SeedThread;
pub use domain::{PinRequest, ThreadStart};
pub use owner::WriteOwner;
use serde_json::Value as Json;
use sha2::{Digest, Sha256};

#[derive(Debug, PartialEq, Eq)]
pub struct Failure {
    pub reason: &'static str,
    pub marker_created_no_retry: bool,
    pub staging_attempted_no_retry: bool,
    pub rename_attempted_no_retry: bool,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason)
    }
}
impl std::error::Error for Failure {}
fn before(reason: &'static str) -> Failure {
    Failure {
        reason,
        marker_created_no_retry: false,
        staging_attempted_no_retry: false,
        rename_attempted_no_retry: false,
    }
}
fn retained(reason: &'static str, staged: bool, renamed: bool) -> Failure {
    Failure {
        reason,
        marker_created_no_retry: true,
        staging_attempted_no_retry: staged,
        rename_attempted_no_retry: renamed,
    }
}
type Result<T> = std::result::Result<T, Failure>;

/// Private control-flow cuts, not OS fault injection or recovery instructions.
#[cfg(feature = "private-probe")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cut {
    AfterNativeClose,
    AfterNextCreate,
    AfterNextWrite,
    AfterNextSync,
    AfterIntent,
    AfterRename,
    AfterPostcheck,
    AfterDataCloses,
    AfterIntentUnlink,
    AfterIntentSync,
    AfterLockClose,
    AfterLockUnlink,
    AfterReleaseSync,
}
struct Control {
    #[cfg(feature = "private-probe")]
    stop: Option<Cut>,
    #[cfg(feature = "private-probe")]
    hook: Option<(Cut, Box<dyn FnOnce()>)>,
}
impl Control {
    fn never() -> Self {
        Self {
            #[cfg(feature = "private-probe")]
            stop: None,
            #[cfg(feature = "private-probe")]
            hook: None,
        }
    }
    #[cfg(feature = "private-probe")]
    fn visit(&mut self, point: Cut, staged: bool, renamed: bool) -> Result<()> {
        if self.hook.as_ref().is_some_and(|(at, _)| *at == point)
            && let Some((_, hook)) = self.hook.take()
        {
            hook();
        }
        if self.stop == Some(point) {
            Err(retained("controlled_original_cut", staged, renamed))
        } else {
            Ok(())
        }
    }
}

/// Observation only, never a constructor for a live owner or prior delivery.
#[derive(Debug)]
pub struct Observation {
    kind: &'static str,
    outcome: &'static str,
    old_sha256: [u8; 32],
    new_sha256: [u8; 32],
    bytes: usize,
    site_id: [u8; 16],
    old_db_version: i64,
    new_db_version: i64,
    request_digest: [u8; 32],
    generation: Option<[u8; 32]>,
    checked_owner_fds: usize,
    native_before_file_release: NativeCounts,
    replacement_identities: Option<Json>,
}
impl Observation {
    /// Checked held/named identity snapshots, never a descriptor or authority.
    pub fn replacement_identities(&self) -> Option<&Json> {
        self.replacement_identities.as_ref()
    }
    pub fn kind(&self) -> &'static str {
        self.kind
    }
    pub fn outcome(&self) -> &'static str {
        self.outcome
    }
    pub fn old_sha256(&self) -> [u8; 32] {
        self.old_sha256
    }
    pub fn new_sha256(&self) -> [u8; 32] {
        self.new_sha256
    }
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    pub fn site_id(&self) -> [u8; 16] {
        self.site_id
    }
    pub fn old_db_version(&self) -> i64 {
        self.old_db_version
    }
    pub fn new_db_version(&self) -> i64 {
        self.new_db_version
    }
    pub fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
    pub fn generation(&self) -> Option<[u8; 32]> {
        self.generation
    }
    pub fn checked_owner_fds(&self) -> usize {
        self.checked_owner_fds
    }
    pub fn native_before_file_release(&self) -> NativeCounts {
        self.native_before_file_release
    }
}
/// Successful original dirty-write completion, no cleanup or delivery authority.
pub struct WriteReceipt {
    observation: Observation,
    response: Json,
    is_error: bool,
}
/// Successful original unchanged-source release, no historical write ack.
pub struct NoWriteReceipt {
    observation: Observation,
    response: Json,
    is_error: bool,
}
pub enum Completion {
    Written(WriteReceipt),
    Unchanged(NoWriteReceipt),
}
impl Completion {
    pub fn observation(&self) -> &Observation {
        match self {
            Self::Written(r) => &r.observation,
            Self::Unchanged(r) => &r.observation,
        }
    }
    pub fn response(&self) -> &Json {
        match self {
            Self::Written(r) => &r.response,
            Self::Unchanged(r) => &r.response,
        }
    }
    pub fn is_error(&self) -> bool {
        match self {
            Self::Written(r) => r.is_error,
            Self::Unchanged(r) => r.is_error,
        }
    }
}
struct Decision {
    dirty: bool,
    response: Json,
    outcome: &'static str,
    is_error: bool,
}
struct Candidate {
    bytes: Vec<u8>,
    sha256: [u8; 32],
}
struct Pending {
    site: [u8; 16],
    old_version: i64,
    new_version: i64,
    request_digest: [u8; 32],
    kind: &'static str,
    decision: Decision,
    native_closed: NativeCounts,
}
/// One original imported logical replica. Neither connection nor bytes escape.
#[must_use = "Consume this session once; Drop retains its marker and yields no completion"]
pub struct WriteSession {
    native: Option<Connection>,
    owner: Option<WriteOwner>,
    site: [u8; 16],
    version: i64,
    schema: Rows,
}
/// Native already checked closed, original file owner still exclusively held.
#[must_use = "Finish the original prepared operation once, never reconstruct it from bytes"]
pub struct PreparedOutcome {
    owner: WriteOwner,
    candidate: Option<Candidate>,
    pending: Pending,
}

impl WriteSession {
    pub fn from_owner(owner: WriteOwner) -> Result<Self> {
        crate::check_header(owner.image()).map_err(|_| retained("write_header", false, false))?;
        let expected =
            crate::template_schema().map_err(|_| retained("write_template", false, false))?;
        let (native, bootstrap) = Connection::open_image_for_probe(owner.image(), false)
            .map_err(|_| retained("write_import", false, false))?;
        let native = native.ok_or_else(|| retained("write_native_missing", false, false))?;
        let validation = (|| {
            crate::check_engine(&native)?;
            if native.query(c"PRAGMA application_id", &[])?
                != vec![vec![Value::Integer(i64::from(
                    crate::schema::APPLICATION_ID,
                ))]]
                || native.query(c"PRAGMA user_version", &[])?
                    != vec![vec![Value::Integer(i64::from(
                        crate::schema::SCHEMA_VERSION,
                    ))]]
                || crate::schema_objects(&native)? != expected
            {
                return Err(Error::Contract("Write schema differs from pinned template"));
            }
            let site = crate::site_id(&native)?;
            if site != crate::metadata_site(&native)?
                || bootstrap.calls != 1
                || bootstrap.deserialize_code != Some(0)
                || bootstrap.extension_code != Some(0)
                || bootstrap.open_code != 0
                || bootstrap.cancelled_temporary != 1
                || bootstrap.restored_original != 0
                || bootstrap.failed_open_checked_closed
            {
                return Err(Error::Contract("Write import identity or lifecycle"));
            }
            Ok((site, db_version(&native)?))
        })();
        match validation {
            Ok((site, version)) => Ok(Self {
                native: Some(native),
                owner: Some(owner),
                site,
                version,
                schema: expected,
            }),
            Err(error) => crate::finish(native, Err::<Self, _>(error))
                .map_err(|_| retained("write_validation_or_close", false, false)),
        }
    }
    pub fn prepare_handoff(
        self,
        request: HandoffRequest,
        cancelled: impl Fn() -> bool,
    ) -> Result<PreparedOutcome> {
        let digest = request.digest();
        self.prepare(
            "local_context_offer_v1",
            digest,
            |native| handoff::record(native, request),
            cancelled,
        )
    }
    #[cfg(feature = "private-probe")]
    pub fn prepare_seed_message_for_private_probe(
        self,
        request: SeedMessage,
    ) -> Result<PreparedOutcome> {
        let digest = request.digest();
        self.prepare(
            "private_seed_message",
            digest,
            |native| probe_message::seed(native, request),
            || false,
        )
    }
    pub fn prepare_pin(
        self,
        request: PinRequest,
        cancelled: impl Fn() -> bool,
    ) -> Result<PreparedOutcome> {
        let digest = request.digest();
        self.prepare(
            "pin_context",
            digest,
            |native| domain::pin(native, request),
            cancelled,
        )
    }
    #[cfg(feature = "private-probe")]
    pub fn prepare_seed_thread_for_private_probe(
        self,
        request: SeedThread,
    ) -> Result<PreparedOutcome> {
        let digest = request.digest();
        self.prepare(
            "private_seed_thread",
            digest,
            |native| domain::seed(native, request),
            || false,
        )
    }
    fn prepare(
        mut self,
        kind: &'static str,
        request_digest: [u8; 32],
        operation: impl FnOnce(&Connection) -> crate::Result<Decision>,
        cancelled: impl Fn() -> bool,
    ) -> Result<PreparedOutcome> {
        let native = self
            .native
            .take()
            .ok_or_else(|| retained("write_native_missing", false, false))?;
        let operation = (|| {
            let decision = run_transaction(&native, operation, cancelled)?;
            let version = db_version(&native)?;
            crate::check_engine(&native)?;
            if crate::schema_objects(&native)? != self.schema {
                return Err(Error::Contract("Write schema changed during operation"));
            }
            if crate::site_id(&native)? != self.site
                || crate::metadata_site(&native)? != self.site
                || (decision.dirty && version <= self.version)
                || (!decision.dirty && version != self.version)
            {
                return Err(Error::Contract(
                    "Write identity or DB version changed unexpectedly",
                ));
            }
            let candidate = if decision.dirty {
                let bytes = native.export_image_for_original_writer()?;
                crate::check_header(&bytes).map_err(Error::Contract)?;
                Some(Candidate {
                    sha256: Sha256::digest(&bytes).into(),
                    bytes,
                })
            } else {
                None
            };
            Ok((decision, version, candidate))
        })();
        // A failed operation or close never returns a prepared capability.
        let (decision, new_version, candidate) = crate::finish(native, operation)
            .map_err(|_| retained("write_operation_export_or_close", false, false))?;
        let mut owner = self
            .owner
            .take()
            .ok_or_else(|| retained("write_owner_missing", false, false))?;
        owner.verify_unchanged()?;
        Ok(PreparedOutcome {
            owner,
            candidate,
            pending: Pending {
                site: self.site,
                old_version: self.version,
                new_version,
                request_digest,
                kind,
                decision,
                native_closed: crate::native_counts_for_private_probe(),
            },
        })
    }
}
impl PreparedOutcome {
    pub fn commit(self, cancelled_before_staging: bool) -> Result<Completion> {
        self.commit_inner(cancelled_before_staging, Control::never())
    }
    #[cfg(feature = "private-probe")]
    pub fn commit_with_controlled_cut_for_private_probe(self, cut: Cut) -> Result<Completion> {
        self.commit_inner(
            false,
            Control {
                stop: Some(cut),
                hook: None,
            },
        )
    }
    /// Runs one fixture-only mutator at a named boundary, then continues the
    /// SAME original operation. No native handle, descriptor or recovery escapes.
    #[cfg(feature = "private-probe")]
    pub fn commit_with_hook_for_private_probe(
        self,
        at: Cut,
        hook: impl FnOnce() + 'static,
    ) -> Result<Completion> {
        self.commit_inner(
            false,
            Control {
                stop: None,
                hook: Some((at, Box::new(hook))),
            },
        )
    }
    fn commit_inner(mut self, cancelled: bool, mut control: Control) -> Result<Completion> {
        #[cfg(feature = "private-probe")]
        control.visit(Cut::AfterNativeClose, false, false)?;
        if cancelled {
            self.candidate = None;
            self.pending.new_version = self.pending.old_version;
            self.pending.decision = domain::cancelled();
        }
        match self.candidate {
            Some(candidate) => {
                let installed = self.owner.install(candidate, self.pending, &mut control)?;
                installed.finish(&mut control).map(Completion::Written)
            }
            None => self
                .owner
                .finish_unchanged(self.pending)
                .map(Completion::Unchanged),
        }
    }
}
fn db_version(native: &Connection) -> crate::Result<i64> {
    match native.query(c"SELECT crsql_db_version()", &[])?.as_slice() {
        [row] => match row.as_slice() {
            [Value::Integer(version)] if *version >= 0 => Ok(*version),
            _ => Err(Error::Contract("DB version value")),
        },
        _ => Err(Error::Contract("DB version row count")),
    }
}
fn run_transaction(
    native: &Connection,
    operation: impl FnOnce(&Connection) -> crate::Result<Decision>,
    cancelled: impl Fn() -> bool,
) -> crate::Result<Decision> {
    if cancelled() {
        return Ok(domain::cancelled());
    }
    native.query(c"BEGIN", &[])?;
    let mut rollback = crate::Rollback {
        connection: native,
        pending: true,
    };
    let decision = match operation(native) {
        Ok(decision) => decision,
        Err(operation) => {
            let cleanup = native.query(c"ROLLBACK", &[]);
            rollback.pending = false;
            return match cleanup {
                Ok(_) => Err(operation),
                Err(cleanup) => Err(Error::Rollback {
                    operation: Box::new(operation),
                    cleanup: Box::new(cleanup),
                }),
            };
        }
    };
    let decision = if cancelled() {
        domain::cancelled()
    } else {
        decision
    };
    if decision.is_error {
        rollback.pending = false;
        native.query(c"ROLLBACK", &[])?;
        return Ok(decision);
    }
    if let Err(operation) = native.query(c"COMMIT", &[]) {
        let cleanup = native.query(c"ROLLBACK", &[]);
        rollback.pending = false;
        return match cleanup {
            Ok(_) => Err(operation),
            Err(cleanup) => Err(Error::Rollback {
                operation: Box::new(operation),
                cleanup: Box::new(cleanup),
            }),
        };
    }
    rollback.pending = false;
    Ok(decision)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn one_row(rows: Rows) -> crate::Result<Option<Vec<Value>>> {
    match rows.len() {
        0 => Ok(None),
        1 => Ok(rows.into_iter().next()),
        _ => Err(Error::Contract("Unexpected row count")),
    }
}
