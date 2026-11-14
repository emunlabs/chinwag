#![forbid(unsafe_code)]
use crate::profile::{McpProfile, rmcp_tools_for_profile};
use chinwag_snapshot_read_owner_private::{ReadOwner, RepositoryAdmission};
use chinwag_snapshot_session_private::{
    Rows, SnapshotSession, Value as SqlValue,
    replacement::{Completion, HandoffRequest, PinRequest, ThreadStart, WriteOwner, WriteSession},
};
use rmcp::{
    RoleServer, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ErrorData, Implementation,
        ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerConfig,
        Tool,
    },
    service::RequestContext,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    borrow::Cow,
    error::Error,
    path::{Path, PathBuf},
    sync::Arc,
    thread::JoinHandle,
};
use tokio::sync::{Semaphore, mpsc, oneshot};

type Reply = oneshot::Sender<Result<Value, String>>;
enum Command {
    Read(ReadArgs, Reply),
    Pin(PinRequest, Reply, RequestControl),
    Handoff(HandoffRequest, Reply),
    Shutdown(oneshot::Sender<Result<(), String>>),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadArgs {
    thread_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ThreadStartArgs {
    repo_id: String,
    branch_ref: String,
    title: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinArgs {
    id: String,
    thread_id: String,
    file_path: String,
    symbol_hash: String,
    source_commit: String,
    body: String,
    created_at_ms: i64,
    #[serde(default)]
    create_thread: Option<ThreadStartArgs>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HandoffArgs {
    id: String,
    thread_id: String,
    target_label: String,
    note: String,
    created_at_ms: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OrgOnlyArgs {
    org_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunStatusArgs {
    org_id: String,
    run_ref: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DocsSearchArgs {
    query: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DocsGetArgs {
    slug: String,
}
pub struct Owner {
    sender: mpsc::Sender<Command>,
    join: JoinHandle<Result<(), String>>,
}
#[derive(Clone)]
pub struct ContextServer {
    sender: Option<mpsc::Sender<Command>>,
    definitions: Arc<Vec<Tool>>,
    permits: Arc<Semaphore>,
    repository_mode: bool,
    profile: McpProfile,
    #[cfg(feature = "private-http-probe")]
    http_lifetime: Option<Arc<crate::http_lifetime::HttpLifetime>>,
}
type WorkerReady = oneshot::Receiver<Result<(), String>>;
type StartedWorker = (ContextServer, Owner, WorkerReady);

struct OperationError {
    message: String,
    original_failed: bool,
}
impl OperationError {
    fn refused(message: String) -> Self {
        Self {
            message,
            original_failed: false,
        }
    }
    fn original(error: impl std::fmt::Display) -> Self {
        Self {
            message: error.to_string(),
            original_failed: true,
        }
    }
}
type Operation = Result<Value, OperationError>;
struct RequestControl {
    #[cfg(all(test, feature = "private-http-probe"))]
    probe: Option<Arc<crate::http_probe::Probe>>,
}
impl RequestControl {
    fn for_server(_server: &ContextServer) -> Self {
        Self {
            #[cfg(all(test, feature = "private-http-probe"))]
            probe: _server
                .http_lifetime
                .as_ref()
                .and_then(|life| life.probe.clone()),
        }
    }
    #[cfg(all(test, feature = "private-http-probe"))]
    fn during_prepare_cancel_check(&self) {
        if let Some(probe) = &self.probe {
            probe.during_prepare_cancel_check();
        }
    }
    fn before_commit(&self) {
        #[cfg(all(test, feature = "private-http-probe"))]
        if let Some(probe) = &self.probe {
            probe.before_commit();
        }
    }
}
fn read_session(repo: &Path) -> Result<SnapshotSession, OperationError> {
    let owner = ReadOwner::acquire_existing_private_fixture(repo).map_err(|e| OperationError {
        message: e.reason.into(),
        original_failed: e.marker_created_no_retry,
    })?;
    SnapshotSession::from_owner(owner).map_err(OperationError::original)
}
fn validate_repository(repo: &Path) -> Result<(), OperationError> {
    // No long-lived filesystem or native handle is retained after this point.
    read_session(repo)?
        .finish()
        .map_err(OperationError::original)?;
    Ok(())
}
fn read(repo: &Path, args: ReadArgs) -> Operation {
    let session = read_session(repo)?;
    let value = session
        .context(&args.thread_id)
        .map_err(|e| e.to_string())
        .and_then(context_data)
        .and_then(bound_output);
    // Even an unknown thread or bounded-output refusal must consume the original
    // checked read release before a tool result is available.
    session.finish().map_err(OperationError::original)?;
    value.map_err(OperationError::refused)
}
fn write_session(repo: &Path) -> Result<WriteSession, OperationError> {
    let owner = WriteOwner::acquire_existing_private_fixture(repo).map_err(|e| OperationError {
        message: e.reason.into(),
        original_failed: e.marker_created_no_retry,
    })?;
    WriteSession::from_owner(owner).map_err(OperationError::original)
}
fn response(completion: Completion) -> Operation {
    if completion.is_error() {
        Err(OperationError::refused(
            completion.response()["error"]
                .as_str()
                .unwrap_or("Private context request refused")
                .into(),
        ))
    } else {
        Ok(completion.response().clone())
    }
}
fn pin(repo: &Path, request: PinRequest, reply: &Reply, control: RequestControl) -> Operation {
    let prepared = write_session(repo)?
        .prepare_pin(request, || {
            #[cfg(all(test, feature = "private-http-probe"))]
            control.during_prepare_cancel_check();
            reply.is_closed()
        })
        .map_err(OperationError::original)?;
    control.before_commit();
    let completion = prepared
        .commit(reply.is_closed())
        .map_err(OperationError::original)?;
    response(completion)
}
fn handoff(repo: &Path, request: HandoffRequest, reply: &Reply) -> Operation {
    let prepared = write_session(repo)?
        .prepare_handoff(request, || reply.is_closed())
        .map_err(OperationError::original)?;
    let completion = prepared
        .commit(reply.is_closed())
        .map_err(OperationError::original)?;
    response(completion)
}
fn deliver(reply: Reply, kind: &str, outcome: Operation) -> Result<(), String> {
    match outcome {
        Ok(value) => {
            let counts = chinwag_snapshot_session_private::native_counts_for_private_probe();
            eprintln!(
                "ROOT_PRIVATE_ANCHORED_REQUEST_FINISHED kind={kind} native_opens={} native_checked_closes={}",
                counts.opens, counts.checked_closes
            );
            let _ = reply.send(Ok(value));
            Ok(())
        }
        Err(error) => {
            let stop = error.original_failed;
            let message = error.message;
            if !stop {
                let counts = chinwag_snapshot_session_private::native_counts_for_private_probe();
                eprintln!(
                    "ROOT_PRIVATE_ANCHORED_REQUEST_REFUSED kind={kind} native_opens={} native_checked_closes={}",
                    counts.opens, counts.checked_closes
                );
            }
            let _ = reply.send(Err(message.clone()));
            if stop { Err(message) } else { Ok(()) }
        }
    }
}
fn admitted_operation(
    admission: &Option<RepositoryAdmission>,
    action: impl FnOnce() -> Operation,
) -> Operation {
    if let Some(guard) = admission {
        guard
            .verify()
            .map_err(|e| OperationError::original(e.reason))?;
    }
    let outcome = action();
    if let Some(guard) = admission {
        guard
            .verify()
            .map_err(|e| OperationError::original(e.reason))?;
    }
    outcome
}

impl Owner {
    pub async fn start(
        repo: PathBuf,
        require_repository: bool,
    ) -> Result<(ContextServer, Self), Box<dyn Error>> {
        let (server, owner, ready) = Self::start_worker(repo, require_repository)?;
        Self::ready_result(server, owner, ready.await)
    }
    fn start_worker(
        repo: PathBuf,
        require_repository: bool,
    ) -> Result<StartedWorker, Box<dyn Error>> {
        if !repo.is_absolute() {
            return Err("Absolute repository required".into());
        }
        let definitions = rmcp_tools_for_profile(McpProfile::LocalRepository)?;
        let (sender, mut receiver) = mpsc::channel(8);
        let (ready_tx, ready_rx) = oneshot::channel();
        let join = std::thread::spawn(move || {
            let admission = if require_repository {
                match RepositoryAdmission::open(&repo) {
                    Ok(guard) => Some(guard),
                    Err(error) => {
                        let message = error.reason.to_owned();
                        let _ = ready_tx.send(Err(message.clone()));
                        return Err(message);
                    }
                }
            } else {
                None
            };
            let outcome = (|| {
                let startup = admitted_operation(&admission, || {
                    validate_repository(&repo)?;
                    Ok(Value::Null)
                });
                if let Err(error) = startup {
                    let _ = ready_tx.send(Err(error.message.clone()));
                    return Err(error.message);
                }
                let _ = ready_tx.send(Ok(()));
                while let Some(command) = receiver.blocking_recv() {
                    match command {
                        Command::Read(args, reply) => {
                            if reply.is_closed() {
                                continue;
                            }
                            let result = admitted_operation(&admission, || read(&repo, args));
                            deliver(reply, "read", result)?;
                        }
                        Command::Pin(args, reply, control) => {
                            if reply.is_closed() {
                                continue;
                            }
                            let result = admitted_operation(&admission, || {
                                pin(&repo, args, &reply, control)
                            });
                            deliver(reply, "pin", result)?;
                        }
                        Command::Handoff(args, reply) => {
                            if reply.is_closed() {
                                continue;
                            }
                            let result =
                                admitted_operation(&admission, || handoff(&repo, args, &reply));
                            deliver(reply, "handoff", result)?;
                        }
                        Command::Shutdown(reply) => {
                            let _ = reply.send(Ok(()));
                            eprintln!("ROOT_PRIVATE_ANCHORED_WORKER_FINISHED");
                            return Ok(());
                        }
                    }
                }
                Ok(())
            })();
            // A fatal original request or startup refusal still closes BOTH held
            // directory chains explicitly; Drop is not a close receipt.
            let closed = admission.map(RepositoryAdmission::finish).transpose();
            match closed {
                Ok(Some(count)) => eprintln!("ROOT_CONTEXT_REPOSITORY_CLOSED fd_count={count}"),
                Ok(None) => (),
                Err(error) => return Err(error.reason.to_owned()),
            }
            outcome
        });
        let server = ContextServer {
            sender: Some(sender.clone()),
            definitions: Arc::new(definitions),
            permits: Arc::new(Semaphore::new(8)),
            repository_mode: require_repository,
            profile: McpProfile::LocalRepository,
            #[cfg(feature = "private-http-probe")]
            http_lifetime: None,
        };
        Ok((server, Self { sender, join }, ready_rx))
    }
    fn ready_result(
        server: ContextServer,
        owner: Self,
        outcome: Result<Result<(), String>, oneshot::error::RecvError>,
    ) -> Result<(ContextServer, Self), Box<dyn Error>> {
        match outcome {
            Ok(Ok(())) => Ok((server, owner)),
            outcome => {
                let closed = owner.join.join();
                Err(format!("Repository startup failed: {outcome:?}; worker={closed:?}").into())
            }
        }
    }
    #[cfg(feature = "private-http-probe")]
    pub fn start_blocking(repo: PathBuf) -> Result<(ContextServer, Self), Box<dyn Error>> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err("HTTP owner startup must run outside a Tokio runtime".into());
        }
        let (server, owner, ready) = Self::start_worker(repo, true)?;
        Self::ready_result(server, owner, ready.blocking_recv())
    }
    #[cfg(feature = "private-http-probe")]
    pub fn shutdown_blocking(self) -> Result<(), Box<dyn Error>> {
        let (tx, rx) = oneshot::channel();
        let sent = self.sender.blocking_send(Command::Shutdown(tx));
        let ended = if sent.is_ok() {
            rx.blocking_recv().ok()
        } else {
            None
        };
        self.join
            .join()
            .map_err(|_| "Private context worker panicked")?
            .map_err(|error| format!("Original private operation failed: {error}"))?;
        ended
            .ok_or("Private worker termination acknowledgment missing")?
            .map_err(|error| format!("Private worker termination: {error}"))?;
        Ok(())
    }
    pub async fn shutdown(self) -> Result<(), Box<dyn Error>> {
        let (tx, rx) = oneshot::channel();
        let sent = self.sender.send(Command::Shutdown(tx)).await;
        let ended = if sent.is_ok() { rx.await.ok() } else { None };
        self.join
            .join()
            .map_err(|_| "Private context worker panicked")?
            .map_err(|e| format!("Original private operation failed: {e}"))?;
        ended
            .ok_or("Private worker termination acknowledgment missing")?
            .map_err(|e| format!("Private worker termination: {e}"))?;
        Ok(())
    }
}
impl ContextServer {
    pub fn new_blind_org() -> Result<Self, Box<dyn Error>> {
        Self::new_catalog_only(McpProfile::BlindOrg)
    }

    pub fn new_catalog_only(profile: McpProfile) -> Result<Self, Box<dyn Error>> {
        let definitions = rmcp_tools_for_profile(profile)?;
        Ok(Self {
            sender: None,
            definitions: Arc::new(definitions),
            permits: Arc::new(Semaphore::new(8)),
            repository_mode: false,
            profile,
            #[cfg(feature = "private-http-probe")]
            http_lifetime: None,
        })
    }
}
#[cfg(feature = "private-http-probe")]
impl ContextServer {
    pub(crate) fn require_modern_http(
        mut self,
        lifetime: Arc<crate::http_lifetime::HttpLifetime>,
    ) -> Self {
        self.http_lifetime = Some(lifetime);
        self
    }
    fn enter_http_handler(&self) -> Result<Option<crate::http_lifetime::Activity>, ErrorData> {
        self.http_lifetime
            .as_ref()
            .map(|lifetime| lifetime.handler())
            .transpose()
            .map_err(|reason| ErrorData::internal_error(reason, None))
    }
}
impl ServerHandler for ContextServer {
    fn get_info(&self) -> ServerConfig {
        let (name, instructions) = match self.profile {
            McpProfile::BlindOrg => (
                "chinwag-blind-org",
                "Authorized blind organization telemetry and curated Chinwag documentation only. Zero source code, file paths, repository leases, or local filesystem access.",
            ),
            McpProfile::LocalRepository if self.repository_mode => (
                "chinwag-context",
                "Read and pin local repository decisions. For the first pin in a new thread, supply create_thread with your repo_id, branch_ref and title labels. Later pins omit create_thread; an identical first-pin retry is safe. Handoff stores a local offer and does not contact its target or grant file-edit authority.",
            ),
            McpProfile::LocalRepository => (
                "chinwag-private-anchored-context",
                "Private operator fixture context only. No file edits, grants, cloud handoff, editor setup or network transport.",
            ),
        };
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(name, "0.0.1"))
            .with_instructions(instructions)
    }
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        #[cfg(feature = "private-http-probe")]
        if self.http_lifetime.is_some() {
            return Cow::Owned(vec![ProtocolVersion::V_2026_07_28]);
        }
        Cow::Owned(vec![
            ProtocolVersion::V_2025_06_18,
            ProtocolVersion::V_2025_11_25,
            ProtocolVersion::V_2026_07_28,
        ])
    }
    async fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        #[cfg(feature = "private-http-probe")]
        let _http_handler = self.enter_http_handler()?;
        Ok(ListToolsResult::with_all_items((*self.definitions).clone()))
    }
    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.definitions.iter().find(|d| d.name == name).cloned()
    }
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        #[cfg(feature = "private-http-probe")]
        let _http_handler = self.enter_http_handler()?;
        let permit = self
            .permits
            .try_acquire()
            .map_err(|_| ErrorData::invalid_params("Private context queue is full", None))?;
        let args = Value::Object(request.arguments.unwrap_or_default());
        if self.profile == McpProfile::BlindOrg {
            let value = execute_blind_org_tool(request.name.as_ref(), args)?;
            drop(permit);
            return Ok(CallToolResult::structured(value).into());
        }
        let sender = self
            .sender
            .as_ref()
            .ok_or_else(|| ErrorData::internal_error("Private context owner unavailable", None))?;
        let (tx, rx) = oneshot::channel();
        let command = match request.name.as_ref() {
            "chinwag_read_thread" => {
                let args: ReadArgs = serde_json::from_value(args).map_err(|_| {
                    ErrorData::invalid_params("Expected only bounded nonempty thread_id", None)
                })?;
                valid_text(&args.thread_id, false)?;
                Command::Read(args, tx)
            }
            "chinwag_pin_context" => {
                let args: PinArgs = serde_json::from_value(args)
                    .map_err(|_| ErrorData::invalid_params("Expected exact pin fields", None))?;
                let start = args
                    .create_thread
                    .map(|thread| {
                        ThreadStart::try_new(thread.repo_id, thread.branch_ref, thread.title)
                    })
                    .transpose()
                    .map_err(|error| ErrorData::invalid_params(error, None))?;
                let mut request = PinRequest::try_new(
                    args.id,
                    args.thread_id,
                    args.file_path,
                    args.symbol_hash,
                    args.source_commit,
                    args.body,
                    args.created_at_ms,
                )
                .map_err(|error| ErrorData::invalid_params(error, None))?;
                if let Some(start) = start {
                    request = request.with_new_thread(start);
                }
                Command::Pin(request, tx, RequestControl::for_server(self))
            }
            "chinwag_handoff" => {
                let args: HandoffArgs = serde_json::from_value(args).map_err(|_| {
                    ErrorData::invalid_params("Expected exact local offer fields", None)
                })?;
                let request = HandoffRequest::try_new(
                    args.id,
                    args.thread_id,
                    args.target_label,
                    args.note,
                    args.created_at_ms,
                )
                .map_err(|error| ErrorData::invalid_params(error, None))?;
                Command::Handoff(request, tx)
            }
            _ => return Err(ErrorData::invalid_params("Unknown context tool", None)),
        };
        // The pinned SDK cancels this request token; it does not drop the
        // handler future for us. Dropping rx closes the original Reply sender.
        // The worker observes that before COMMIT and again before staging.
        let result = tokio::select! {
            biased;
            _ = context.ct.cancelled() => {
                eprintln!("ROOT_PRIVATE_ANCHORED_REQUEST_CANCELLED");
                return Err(ErrorData::internal_error("Private context request cancelled", None));
            }
            result = async {
                #[cfg(all(test, feature = "private-http-probe"))]
                if let Some(probe) = self.http_lifetime.as_ref().and_then(|life| life.probe.as_ref()) {
                    probe.before_enqueue().await;
                }
                sender.send(command).await.map_err(|_| ErrorData::internal_error("Private context owner unavailable", None))?;
                rx.await.map_err(|_| ErrorData::internal_error("Private context result unavailable", None))
            } => result?,
        };
        drop(permit);
        Ok(match result {
            Ok(value) => CallToolResult::structured(value),
            Err(error) => CallToolResult::structured_error(json!({"error":error})),
        }
        .into())
    }
}

const APPROVED_PUBLIC_DOCS: &[(&str, &str, &str)] = &[
    (
        "coordination/overview",
        "Blind Multi-Seat Engineering Coordination",
        "Chinwag coordinates verified delivery state, run receipts, and handoff gates across engineering seats while keeping source code inside local repositories.",
    ),
    (
        "security/blind-boundary",
        "Blind Cloud Capability Boundary",
        "Remote blind-org MCP exposes organization status, opaque run receipts, delivery board progress, credit ledger summaries, and approved public documentation with zero source bytes, file paths, or leases. Emun Labs is pursuing SOC 2.",
    ),
    (
        "setup/connect-local-workspace",
        "Connecting a Local Workspace",
        "Local repository threads and context pins run exclusively through an admitted local chinwag mcp-serve process configured explicitly by the developer.",
    ),
];

fn validate_opaque_id(value: &str) -> Result<(), ErrorData> {
    if value.is_empty()
        || value.len() > 128
        || value.contains("..")
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
    {
        return Err(ErrorData::invalid_params(
            "Expected bounded opaque identifier [A-Za-z0-9._:-]{1,128}",
            None,
        ));
    }
    Ok(())
}

fn contains_interpolation(value: &str) -> bool {
    if value.contains("${") || value.contains("$(") {
        return true;
    }
    let bytes = value.as_bytes();
    for idx in 0..bytes.len() {
        if bytes[idx] == b'$'
            && let Some(next) = bytes.get(idx + 1)
            && (next.is_ascii_uppercase() || *next == b'_')
        {
            return true;
        }
    }
    false
}

fn validate_search_query(value: &str) -> Result<(), ErrorData> {
    if value.is_empty()
        || value.len() > 256
        || value.contains('\0')
        || contains_interpolation(value)
    {
        return Err(ErrorData::invalid_params(
            "Expected bounded search query without null bytes or environment interpolation",
            None,
        ));
    }
    Ok(())
}

fn validate_doc_slug(value: &str) -> Result<(), ErrorData> {
    if value.is_empty()
        || value.len() > 128
        || value.starts_with('/')
        || value.ends_with('/')
        || value.starts_with('.')
        || value.ends_with('.')
        || value.contains("..")
        || value.contains("//")
        || !value.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'/' | b'_' | b'-')
        })
    {
        return Err(ErrorData::invalid_params(
            "Expected canonical documentation slug [a-z0-9./_-]{1,128}",
            None,
        ));
    }
    Ok(())
}

fn execute_blind_org_tool(name: &str, args: Value) -> Result<Value, ErrorData> {
    let payload = match name {
        "chinwag_org_status" => {
            let parsed: OrgOnlyArgs = serde_json::from_value(args)
                .map_err(|_| ErrorData::invalid_params("Expected exact org_id field", None))?;
            validate_opaque_id(&parsed.org_id)?;
            json!({
                "profile": "blind-org",
                "org_id": parsed.org_id,
                "posture": "blind_metadata_only",
                "source_bytes": 0,
                "compliance_note": "Emun Labs is pursuing SOC 2."
            })
        }
        "chinwag_run_status" => {
            let parsed: RunStatusArgs = serde_json::from_value(args).map_err(|_| {
                ErrorData::invalid_params("Expected exact org_id and run_ref fields", None)
            })?;
            validate_opaque_id(&parsed.org_id)?;
            validate_opaque_id(&parsed.run_ref)?;
            json!({
                "profile": "blind-org",
                "org_id": parsed.org_id,
                "run_ref": parsed.run_ref,
                "state": "verified_blind_receipt_lookup_ready",
                "source_bytes": 0
            })
        }
        "chinwag_board_status" => {
            let parsed: OrgOnlyArgs = serde_json::from_value(args)
                .map_err(|_| ErrorData::invalid_params("Expected exact org_id field", None))?;
            validate_opaque_id(&parsed.org_id)?;
            json!({
                "profile": "blind-org",
                "org_id": parsed.org_id,
                "open_gates": 0,
                "file_scopes_exposed": 0,
                "source_bytes": 0
            })
        }
        "chinwag_credit_ledger" => {
            let parsed: OrgOnlyArgs = serde_json::from_value(args)
                .map_err(|_| ErrorData::invalid_params("Expected exact org_id field", None))?;
            validate_opaque_id(&parsed.org_id)?;
            json!({
                "profile": "blind-org",
                "org_id": parsed.org_id,
                "read_only": true,
                "available_credits": 0,
                "verified_receipts": 0
            })
        }
        "chinwag_docs_search" => {
            let parsed: DocsSearchArgs = serde_json::from_value(args)
                .map_err(|_| ErrorData::invalid_params("Expected exact query field", None))?;
            validate_search_query(&parsed.query)?;
            let needle = parsed.query.to_ascii_lowercase();
            let hits: Vec<Value> = APPROVED_PUBLIC_DOCS
                .iter()
                .filter(|(slug, title, summary)| {
                    slug.to_ascii_lowercase().contains(&needle)
                        || title.to_ascii_lowercase().contains(&needle)
                        || summary.to_ascii_lowercase().contains(&needle)
                })
                .map(|(slug, title, summary)| {
                    json!({
                        "slug": slug,
                        "title": title,
                        "summary": summary
                    })
                })
                .collect();
            json!({
                "profile": "blind-org",
                "query": parsed.query,
                "results": hits
            })
        }
        "chinwag_docs_get" => {
            let parsed: DocsGetArgs = serde_json::from_value(args)
                .map_err(|_| ErrorData::invalid_params("Expected exact slug field", None))?;
            validate_doc_slug(&parsed.slug)?;
            let entry = APPROVED_PUBLIC_DOCS
                .iter()
                .find(|(slug, _, _)| *slug == parsed.slug)
                .map(|(slug, title, summary)| {
                    json!({
                        "found": true,
                        "slug": slug,
                        "title": title,
                        "body": summary
                    })
                })
                .unwrap_or_else(|| {
                    json!({
                        "found": false,
                        "slug": parsed.slug
                    })
                });
            json!({
                "profile": "blind-org",
                "document": entry
            })
        }
        _ => {
            return Err(ErrorData::invalid_params(
                "Tool is not available in blind-org profile",
                None,
            ));
        }
    };
    bound_output(payload).map_err(|reason| ErrorData::internal_error(reason, None))
}
fn valid_text(text: &str, empty: bool) -> Result<(), ErrorData> {
    if (!empty && text.is_empty()) || text.len() > chinwag_snapshot_session_private::MAX_VALUE_BYTES
    {
        return Err(ErrorData::invalid_params(
            "Text is empty or exceeds byte limit",
            None,
        ));
    }
    Ok(())
}
pub(crate) fn bound_output(value: Value) -> Result<Value, String> {
    if serde_json::to_vec(&value).map_err(|e| e.to_string())?.len()
        > crate::wire::MAX_TOOL_DATA_BYTES
    {
        Err("Private context result exceeds output limit".into())
    } else {
        Ok(value)
    }
}
pub(crate) fn context_data(
    context: chinwag_snapshot_session_private::ThreadContext,
) -> Result<Value, String> {
    if context.thread.len() != 1 {
        return Err("Unknown or invalid thread".into());
    }
    Ok(
        json!({"thread":objects(context.thread,&["id","repo_id","branch_ref","title","created_at_ms","updated_at_ms"])?[0],"messages":objects(context.messages,&["id","thread_id","author_key_id","role","body","created_at_ms"])?,"pins":objects(context.pins,&["id","thread_id","file_path","symbol_hash","source_commit","body","created_at_ms"])?}),
    )
}
fn objects(rows: Rows, names: &[&str]) -> Result<Vec<Value>, String> {
    rows.into_iter()
        .map(|row| {
            if row.len() != names.len() {
                return Err("Stored row has unexpected width".into());
            }
            let mut object = serde_json::Map::new();
            for (name, value) in names.iter().zip(row) {
                let value = match value {
                    SqlValue::Text(text) => Value::String(text),
                    SqlValue::Integer(integer) => json!(integer),
                    _ => return Err("Stored context has unexpected value type".into()),
                };
                object.insert((*name).into(), value);
            }
            Ok(Value::Object(object))
        })
        .collect()
}
