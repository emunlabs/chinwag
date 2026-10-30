use super::*;
use chinwag_connector_registry::{AuthorityKind, BindingState, Limits, Registry};
use std::{
    fs,
    net::TcpListener,
    os::unix::fs::{PermissionsExt, symlink},
};

fn root() -> (tempfile::TempDir, PathBuf) {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    (temporary, root)
}

fn host() -> Arc<Mutex<ConnectorHost>> {
    Arc::new(Mutex::new(ConnectorHost::new(
        Registry::new(Limits {
            max_grants: 8,
            max_bindings: 8,
            max_lease: LEASE,
        })
        .unwrap(),
    )))
}

fn endpoint() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    (listener, origin)
}

fn assert_no_request(listener: &TcpListener) {
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}

fn error_of<T>(result: Result<T>) -> McpOwnerError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("unexpected owner enrollment success"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_owner_export_is_private_fixed_scope_and_shutdown_really_drains() {
    let (_temporary, root) = root();
    let (listener, endpoint) = endpoint();
    let host = host();
    let existing_stdio = {
        let mut shared = host.lock().unwrap();
        shared
            .set_enabled(BuiltinConnector::NativeInbox, true)
            .unwrap();
        let connection = ConnectionId::new("existing-owner-stdio").unwrap();
        let decision = OwnerLocalDecision::new(
            "existing-owner-stdio-launch",
            connection.clone(),
            Destination::new(format!("{endpoint}/"), NativeRoom::Mgmt).unwrap(),
        )
        .unwrap();
        shared
            .admit_local_inbox(decision, &connection, LEASE, Instant::now())
            .unwrap()
    };
    let output = root.join("capability.json");
    let owner = HttpMcpOwner::start(&endpoint, host.clone(), &output)
        .await
        .unwrap();
    let bytes = fs::read(&output).unwrap();
    assert!(bytes.len() <= MAX_DOCUMENT);
    assert_eq!(fs::metadata(&output).unwrap().mode() & 0o777, 0o600);
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["schema"], "chinwag-owner-http-mcp/v1");
    assert_eq!(value["url"], format!("{endpoint}/api/mcp"));
    assert_eq!(value["room"], "#mgmt");
    assert_eq!(value["lease_seconds"], 900);
    assert_eq!(value.as_object().unwrap().len(), 5);
    let authorization = value["headers"]["Authorization"].as_str().unwrap();
    let token = authorization.strip_prefix("Bearer ").unwrap();
    assert!(
        token.len() == 64
            && token
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );
    let binding = owner.enrollment.0.binding.clone();
    assert_eq!(
        binding.authority,
        AuthorityKind::OwnerLocalHttpCapabilityUnattributed
    );
    assert_eq!(binding.destination.endpoint_id(), format!("{endpoint}/"));
    assert_eq!(binding.destination.room(), NativeRoom::Mgmt);
    assert!(binding.connection.as_str().starts_with("owner-http-"));
    assert_eq!(binding.connection.as_str().len(), "owner-http-".len() + 32);
    assert!(!binding.connection.as_str().contains(token));
    let initial = owner.transport().lifecycle_snapshot();
    assert!(!initial.session_started);
    assert_eq!(initial.connection_observation.read_windows_prepared, 0);
    let status = serde_json::to_string(&initial).unwrap();
    assert!(
        !status.contains(token) && !status.contains("Authorization") && !status.contains("Bearer")
    );
    assert_no_request(&listener);
    tokio::time::timeout(Duration::from_secs(3), owner.shutdown())
        .await
        .unwrap()
        .unwrap();
    let final_snapshot = owner.transport().lifecycle_snapshot();
    assert!(final_snapshot.session_closed);
    assert!(final_snapshot.reader_worker_joined);
    assert_eq!(
        host.lock()
            .unwrap()
            .inspect_binding(binding.id, Instant::now())
            .unwrap()
            .state,
        BindingState::Revoked
    );
    {
        let mut shared = host.lock().unwrap();
        assert_eq!(
            shared
                .inspect_binding(existing_stdio.id, Instant::now())
                .unwrap(),
            existing_stdio
        );
        let now = Instant::now();
        let invocation = shared
            .begin(
                BuiltinConnector::NativeInbox,
                now + Duration::from_secs(1),
                now,
            )
            .unwrap();
        assert_eq!(
            shared.inbox(&invocation, &existing_stdio, Instant::now, |scope| scope
                .authority()),
            Ok(AuthorityKind::OwnerLocalStdioUnattributed)
        );
    }
    assert_eq!(fs::read(&output).unwrap(), bytes);
    assert_no_request(&listener);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_http_port_is_canonical_without_binding_or_requesting_port_eighty() {
    let (_temporary, root) = root();
    let output = root.join("owner-default-port.json");
    // This deliberately creates no listener and issues no transport request.
    // Startup constructs the bounded reader; it must not read the bus.
    let owner = HttpMcpOwner::start("http://127.0.0.1:80", host(), &output)
        .await
        .unwrap();
    let document: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(document["url"], "http://127.0.0.1/api/mcp");
    assert_eq!(
        owner.enrollment.0.binding.destination.endpoint_id(),
        "http://127.0.0.1/"
    );
    let initial = owner.transport().lifecycle_snapshot();
    assert!(!initial.session_started);
    assert!(initial.connection_observation.negotiated_protocol.is_none());
    assert_eq!(initial.connection_observation.catalogue_outputs_prepared, 0);
    assert_eq!(initial.connection_observation.read_windows_prepared, 0);
    tokio::time::timeout(Duration::from_secs(3), owner.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert!(owner.transport().lifecycle_snapshot().reader_worker_joined);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn existing_capability_is_never_adopted_renewed_or_changed_even_after_shutdown() {
    let (_temporary, root) = root();
    let (listener, endpoint) = endpoint();
    let host = host();
    let output = root.join("capability.json");
    let owner = HttpMcpOwner::start(&endpoint, host.clone(), &output)
        .await
        .unwrap();
    let original = fs::read(&output).unwrap();
    let binding = owner.enrollment.0.binding.clone();
    assert_eq!(
        error_of(HttpMcpOwner::start(&endpoint, host.clone(), &output).await),
        McpOwnerError::CapabilityFileExists
    );
    assert_eq!(
        host.lock()
            .unwrap()
            .inspect_binding(binding.id, Instant::now())
            .unwrap(),
        binding
    );
    owner.shutdown().await.unwrap();
    assert_eq!(
        error_of(HttpMcpOwner::start(&endpoint, host, &output).await),
        McpOwnerError::CapabilityFileExists
    );
    assert_eq!(fs::read(&output).unwrap(), original);
    assert_no_request(&listener);
}

#[test]
fn existing_special_nodes_and_aliases_are_rejected_without_reading_or_replacing_them() {
    let (_temporary, root) = root();
    let existing = root.join("keep.json");
    fs::write(&existing, b"original").unwrap();
    let alias = root.join("alias.json");
    symlink(&existing, &alias).unwrap();
    let directory = root.join("directory.json");
    fs::create_dir(&directory).unwrap();
    let fifo = root.join("fifo.json");
    let name = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    // Temporary fixture node only, not a client process or an external command.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    for path in [&existing, &alias, &directory, &fifo] {
        assert_eq!(
            error_of(CapabilityOutput::prepare(path)),
            McpOwnerError::CapabilityFileExists
        );
    }
    assert_eq!(fs::read(&existing).unwrap(), b"original");
    assert!(
        fs::symlink_metadata(&alias)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn parent_scope_is_exact_owned_and_nonsymlink_with_no_directory_creation() {
    let (_temporary, root) = root();
    let alias = root.join("alias");
    symlink(&root, &alias).unwrap();
    let writable = root.join("writable");
    fs::create_dir(&writable).unwrap();
    fs::set_permissions(&writable, fs::Permissions::from_mode(0o777)).unwrap();
    for path in [
        PathBuf::from("relative.json"),
        root.join("./dot.json"),
        root.join("../escape.json"),
        alias.join("cap.json"),
        writable.join("cap.json"),
        root.join("missing/cap.json"),
    ] {
        assert_eq!(
            error_of(CapabilityOutput::prepare(&path)),
            McpOwnerError::InvalidCapabilityPath
        );
    }
    assert!(!root.join("missing").exists());
}

#[test]
fn late_file_replacement_or_mutation_is_retained_as_uncertain_not_reported_as_exported() {
    for replace in [false, true] {
        let (_temporary, root) = root();
        let output = root.join("owner.json");
        let file = CapabilityOutput::prepare(&output).unwrap();
        let document = owner_document("http://127.0.0.1:1/", &"0".repeat(64)).unwrap();
        let result = file.write_new(&document, || {
            if replace {
                fs::rename(&output, root.join("original.json")).unwrap();
            }
            fs::write(&output, b"foreign replacement").unwrap();
        });
        let error = error_of(result);
        assert_eq!(error, McpOwnerError::CapabilityStorage);
        assert_eq!(fs::read(&output).unwrap(), b"foreign replacement");
        assert!(!format!("{error:?} {error}").contains(&"0".repeat(64)));
        if replace {
            assert_eq!(fs::read(root.join("original.json")).unwrap(), document);
        }
    }
}

#[test]
fn parent_replacement_after_write_cannot_redirect_the_private_export() {
    let (_temporary, root) = root();
    let parent = root.join("parent");
    let moved = root.join("moved");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let output = parent.join("owner.json");
    let prepared = CapabilityOutput::prepare(&output).unwrap();
    let document = owner_document("http://127.0.0.1:1/", &"0".repeat(64)).unwrap();
    let result = prepared.write_new(&document, || {
        fs::rename(&parent, &moved).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&output, b"new parent bytes").unwrap();
    });
    assert!(result.is_err());
    assert_eq!(fs::read(&output).unwrap(), b"new parent bytes");
    assert_eq!(fs::read(moved.join("owner.json")).unwrap(), document);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_drop_never_blocks_on_shared_reader_lock_and_later_shutdown_observes_drain() {
    let (_temporary, root) = root();
    let (listener, endpoint) = endpoint();
    let host = host();
    let owner = HttpMcpOwner::start(&endpoint, host.clone(), &root.join("owner.json"))
        .await
        .unwrap();
    let binding = owner.enrollment.0.binding.clone();
    let transport = owner.transport();
    {
        let lock = host.lock().unwrap();
        let (sent, received) = std::sync::mpsc::channel();
        let dropped = std::thread::spawn(move || {
            drop(owner);
            let _ = sent.send(());
        });
        let completed = received.recv_timeout(Duration::from_secs(3));
        drop(lock);
        assert!(
            completed.is_ok(),
            "Drop must fence and schedule, not block on the shared writer"
        );
        dropped.join().unwrap();
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let state = host
                .lock()
                .unwrap()
                .inspect_binding(binding.id, Instant::now())
                .unwrap()
                .state;
            if state == BindingState::Revoked {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(3), transport.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert!(transport.lifecycle_snapshot().reader_worker_joined);
    assert_no_request(&listener);
}
