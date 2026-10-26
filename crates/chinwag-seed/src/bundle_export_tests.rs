use super::*;
use crate::{
    bundle_intake::{BundleOperatorConfig, BundleVerifier},
    owned_process::execute_guarded,
};
use ssh_key::{LineEnding, PrivateKey, private::Ed25519Keypair};
use std::os::unix::fs::PermissionsExt;
use std::{ffi::OsString, os::unix::fs::symlink, path::Path};

struct Fixture {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    source: PathBuf,
    hooks: PathBuf,
    bundle: PathBuf,
    signers: PathBuf,
    key: PathBuf,
    builder: [u8; 32],
    oid: String,
    tree: String,
}

impl Fixture {
    async fn new(format: &str, actual_signer_seed: u8) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let source = root.join("source");
        let hooks = root.join("fixture-hooks");
        for path in [&source, &hooks] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = root.join("temporary-fixture-key");
        let actual = PrivateKey::from(Ed25519Keypair::from_seed(&[actual_signer_seed; 32]));
        actual.write_openssh_file(&key, LineEnding::LF).unwrap();
        let builder_pair = Ed25519Keypair::from_seed(&[0x51; 32]);
        let builder = builder_pair.public.0;
        let builder_key = PrivateKey::from(builder_pair);
        let signers = root.join("builder-signers");
        write_private(
            &signers,
            format!(
                "fixture {}\n",
                builder_key.public_key().to_openssh().unwrap()
            )
            .as_bytes(),
        );
        let mut fixture = Self {
            _temporary: temporary,
            root: root.clone(),
            source,
            hooks,
            bundle: root.join("received.bundle"),
            signers,
            key,
            builder,
            oid: String::new(),
            tree: String::new(),
        };
        fixture
            .git(&[
                "init".into(),
                "--initial-branch=fixture".into(),
                format!("--object-format={format}").into(),
                prefixed("--template=", &fixture.hooks),
            ])
            .await;
        fs::create_dir(fixture.source.join("src")).unwrap();
        write_private(
            &fixture.source.join("Cargo.toml"),
            b"[package]\nname='temporary-bundle-fixture'\nversion='0.0.0'\nedition='2024'\n",
        );
        write_private(
            &fixture.source.join("src/lib.rs"),
            b"#[test] fn received_source() { assert_eq!(6 * 7, 42); }\n",
        );
        fixture.git(&["add".into(), ".".into()]).await;
        fixture
            .git(&[
                "-c".into(),
                "user.name=Temporary test fixture".into(),
                "-c".into(),
                "user.email=fixture@example.invalid".into(),
                "-c".into(),
                prefixed("user.signingkey=", &fixture.key),
                "commit".into(),
                "-S".into(),
                "-m".into(),
                "Temporary fixture, not Genesis".into(),
            ])
            .await;
        fixture.oid = fixture.line(&["rev-parse".into(), "HEAD".into()]).await;
        fixture.tree = fixture
            .line(&["rev-parse".into(), "HEAD^{tree}".into()])
            .await;
        fixture
            .git(&[
                "bundle".into(),
                "create".into(),
                fixture.bundle.clone().into_os_string(),
                "HEAD".into(),
            ])
            .await;
        fs::set_permissions(&fixture.bundle, fs::Permissions::from_mode(0o600)).unwrap();
        fixture
    }

    async fn git(&self, args: &[OsString]) -> CommandReport {
        let mut command = Command::new("/usr/bin/git");
        command
            .current_dir(&self.source)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.hooks)
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args(["-c", "core.fsmonitor=false", "-c", "gpg.format=ssh"])
            .args(["-c", "gpg.ssh.program=/usr/bin/ssh-keygen"])
            .arg("-c")
            .arg(prefixed("core.hooksPath=", &self.hooks))
            .args(args);
        let job = Arc::new(Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap());
        let result = execute_guarded(command, Duration::from_secs(10), DIAGNOSTIC_LIMIT, job)
            .await
            .unwrap();
        assert!(result.success, "fixture command failed: {result:?}");
        result
    }

    async fn line(&self, args: &[OsString]) -> String {
        String::from_utf8(self.git(args).await.stdout)
            .unwrap()
            .trim_end_matches('\n')
            .to_owned()
    }

    fn intake_config(&self, label: &str) -> BundleOperatorConfig {
        let quarantine = self.root.join(format!("quarantine-{label}"));
        let templates = self.root.join(format!("templates-{label}"));
        for path in [&quarantine, &templates] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let bytes = fs::read(&self.bundle).unwrap();
        BundleOperatorConfig {
            bundle: self.bundle.clone(),
            quarantine,
            empty_templates: templates,
            builder_signers: self.signers.clone(),
            expected: BundleExpectation::new(
                &self.oid,
                &self.tree,
                *blake3::hash(&bytes).as_bytes(),
                bytes.len() as u64,
                self.builder,
            )
            .unwrap(),
        }
    }

    fn export_config(&self, label: &str) -> ExportOperatorConfig {
        for path in [self.source.join(".git"), self.source.join(".git/objects")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let export = self.root.join(format!("export-{label}"));
        let staging = self.root.join(format!("staging-{label}"));
        let templates = self.root.join(format!("export-templates-{label}"));
        for path in [&export, &staging, &templates] {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        ExportOperatorConfig {
            source: self.source.clone(),
            export,
            staging,
            empty_templates: templates,
            builder_signers: self.signers.clone(),
            candidate: GitCandidate::new(&self.oid, &self.tree, self.builder).unwrap(),
        }
    }

    fn source_bytes(&self) -> Vec<Vec<u8>> {
        [
            ".git/HEAD",
            ".git/config",
            ".git/index",
            "Cargo.toml",
            "src/lib.rs",
        ]
        .into_iter()
        .map(|path| fs::read(self.source.join(path)).unwrap())
        .collect()
    }
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

/// Explicit callback uncertainty, not an elapsed deadline or a peer failure.
/// Actual signed temporary Git export, real tag and in-memory MCP only.
#[tokio::test]
async fn public_callback_unknown_is_immediate_cached_and_model_visible_without_reexport() {
    use crate::send_owner::{CallbackOutcome, Error as SendError, SendOwner, mcp::SendServer};
    use futures_util::StreamExt;
    use iroh_blobs::store::mem::MemStore;
    use rig_core::tool::DynamicTool;
    use rig_rmcp::McpConnection;
    use rmcp::{ServiceExt, model::ClientConfig};
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::oneshot;

    tokio::time::timeout(Duration::from_secs(60), async {
        for format in ["sha1", "sha256"] {
            let fixture = Fixture::new(format, 0x51).await;
            let pinned = fixture.export_config("explicit-unknown");
            let config = || ExportOperatorConfig {
                source: pinned.source.clone(), export: pinned.export.clone(),
                staging: pinned.staging.clone(), empty_templates: pinned.empty_templates.clone(),
                builder_signers: pinned.builder_signers.clone(),
                candidate: GitCandidate::new(&fixture.oid, &fixture.tree, fixture.builder).unwrap(),
            };
            let before = fixture.source_bytes();
            let refs = fixture.git(&["show-ref".into()]).await.stdout;
            let memory = Arc::new(MemStore::new());
            let store = memory.clone();
            let count = Arc::new(AtomicUsize::new(0));
            let observed_count = count.clone();
            let (started, observed) = oneshot::channel();
            let owner = SendOwner::open(config(), move |prepared| async move {
                observed_count.fetch_add(1, Ordering::SeqCst);
                let expected = prepared.expectation().clone();
                let tag = store.add_bytes(prepared.into_bytes()).temp_tag().await.unwrap();
                assert_eq!(*tag.hash().as_bytes(), expected.hash());
                // Real Git is done. The result must arrive at this SAME instant,
                // without waiting for the 30s callback or 300s client deadline.
                tokio::time::pause();
                started.send(tokio::time::Instant::now()).unwrap();
                drop(tag);
                CallbackOutcome::Unknown
            }).unwrap();
            let server = SendServer::new(owner).unwrap();
            let handler = server.clone();
            let (client_io, server_io) = tokio::io::duplex(32768);
            let serving = tokio::spawn(async move {
                handler.serve(tokio::io::split(server_io)).await.unwrap().waiting().await.unwrap();
            });
            let client = McpConnection::new(ClientConfig::default().serve(tokio::io::split(client_io)).await.unwrap());
            let tool: DynamicTool = client.tools().await.unwrap().pop().unwrap().try_into().unwrap();
            let calling_tool = tool.clone();
            let calling = tokio::spawn(async move { calling_tool.run(json!({})).await });
            let instant = observed.await.unwrap();
            let error = calling.await.unwrap().unwrap_err();
            let unchanged_clock = tokio::time::Instant::now() == instant;
            tokio::time::resume();
            assert!(unchanged_clock, "explicit Unknown must not wait for a deadline");
            assert_eq!(error.model_output().as_json(), Some(&json!({"error":"send_unknown_no_retry"})));
            for _ in 0..2 {
                assert_eq!(tool.run(json!({})).await.unwrap_err().model_output().as_json(), Some(&json!({"error":"send_unknown_no_retry"})));
            }
            assert_eq!(count.load(Ordering::SeqCst), 1);
            let tags = memory.tags().list_temp_tags().await.unwrap().collect::<Vec<_>>().await;
            assert!(tags.is_empty());
            assert_eq!(server.shutdown().await.unwrap_err(), SendError::Unknown);
            assert_eq!(tool.run(json!({})).await.unwrap_err().model_output().as_json(), Some(&json!({"error":"send_unavailable_no_retry"})));
            let marker = fs::read(pinned.staging.join(ATTEMPT)).unwrap();
            assert!(matches!(SendOwner::open(config(), |_| async { CallbackOutcome::PublishedLocal }), Err(SendError::Unavailable)));
            assert_eq!(fs::read(pinned.staging.join(ATTEMPT)).unwrap(), marker);
            assert_eq!(fixture.source_bytes(), before);
            assert_eq!(fixture.git(&["show-ref".into()]).await.stdout, refs);
            client.close().await;
            serving.await.unwrap();
            println!("explicit_callback_unknown format={format} same_instant=true model_json=true cached_count1=true tag0=true shutdown_unknown=true occupied_refused=true");
        }
    }).await.unwrap();
}

/// Real Git/export/store objects in a temporary fixture. No Endpoint, room,
/// socket, peer, native model call, received-source Cargo run or seal is used.
#[tokio::test]
async fn socket_free_send_owner_keeps_real_tag_until_orderly_drain() {
    use crate::send_owner::{CallbackOutcome, LocalNote, SendOwner, mcp::SendServer};
    use futures_util::StreamExt;
    use iroh_blobs::store::mem::MemStore;
    use rig_core::tool::DynamicTool;
    use rig_rmcp::McpConnection;
    use rmcp::{ServiceExt, model::ClientConfig};
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::oneshot;

    tokio::time::timeout(Duration::from_secs(60), async {
        for format in ["sha1", "sha256"] {
            let fixture = Fixture::new(format, 0x51).await;
            let pinned = fixture.export_config("socket-free-send");
            let config = || ExportOperatorConfig {
                source: pinned.source.clone(),
                export: pinned.export.clone(),
                staging: pinned.staging.clone(),
                empty_templates: pinned.empty_templates.clone(),
                builder_signers: pinned.builder_signers.clone(),
                candidate: GitCandidate::new(&fixture.oid, &fixture.tree, fixture.builder).unwrap(),
            };
            let before = fixture.source_bytes();
            let refs = fixture.git(&["show-ref".into()]).await.stdout;
            let memory = Arc::new(MemStore::new());
            let store = memory.clone();
            let calls = Arc::new(AtomicUsize::new(0));
            let count = calls.clone();
            let (started, observed) = oneshot::channel();
            let (release, gate) = oneshot::channel();
            let owner = SendOwner::open(config(), move |prepared| async move {
                count.fetch_add(1, Ordering::SeqCst);
                let expected = prepared.expectation().clone();
                let tag = store.add_bytes(prepared.into_bytes()).temp_tag().await.unwrap();
                assert_eq!(*tag.hash().as_bytes(), expected.hash());
                started.send((tag.hash(), expected)).unwrap();
                gate.await.unwrap();
                drop(tag);
                CallbackOutcome::PublishedLocal
            }).unwrap();
            let server = SendServer::new(owner).unwrap();
            let handler = server.clone();
            let (client_io, server_io) = tokio::io::duplex(32768);
            let serving = tokio::spawn(async move {
                handler.serve(tokio::io::split(server_io)).await.unwrap()
                    .waiting().await.unwrap();
            });
            let client = McpConnection::new(ClientConfig::default()
                .serve(tokio::io::split(client_io)).await.unwrap());
            let tools = client.tools().await.unwrap();
            assert_eq!(tools.len(), 1);
            let tool = DynamicTool::try_from(tools.into_iter().next().unwrap()).unwrap();
            assert_eq!(tool.name(), "send_git_bundle_over_iroh");
            let first = tool.clone();
            let waiting = tokio::spawn(async move { first.run(json!({})).await });
            let (hash, expected) = observed.await.unwrap();
            assert_eq!(expected.oid(), fixture.oid);
            assert_eq!(expected.tree(), fixture.tree);
            assert_eq!(expected.builder(), fixture.builder);
            let bytes = memory.blobs().get_bytes(hash).await.unwrap();
            assert_eq!(bytes.as_ref(), fs::read(pinned.staging.join(BUNDLE)).unwrap());
            assert_eq!(bytes.len() as u64, expected.size());
            assert_eq!(*blake3::hash(&bytes).as_bytes(), expected.hash());

            // Abort the CLIENT waiter, without claiming how the remote handler
            // processes cancellation. The service still owns the real job/tag.
            waiting.abort();
            assert!(waiting.await.unwrap_err().is_cancelled());
            let tags = memory.tags().list_temp_tags().await.unwrap().collect::<Vec<_>>().await;
            assert_eq!(tags.len(), 1);
            assert_eq!(tags[0].hash, hash);
            assert_eq!(calls.load(Ordering::SeqCst), 1);

            // Borrow the SAME drain across this timeout; dropping only its
            // temporary observation must not drop the owned shutdown future.
            let draining = server.shutdown();
            tokio::pin!(draining);
            assert!(tokio::time::timeout(Duration::from_millis(20), draining.as_mut()).await.is_err());
            assert!(tool.run(json!({})).await.is_err());
            let tags = memory.tags().list_temp_tags().await.unwrap().collect::<Vec<_>>().await;
            assert_eq!(tags.len(), 1);
            assert_eq!(tags[0].hash, hash);
            release.send(()).unwrap();
            assert_eq!(draining.await.unwrap(), Some(LocalNote::PublishedLocal));
            assert!(memory.tags().list_temp_tags().await.unwrap().collect::<Vec<_>>().await.is_empty());
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.source_bytes(), before);
            assert_eq!(fixture.git(&["show-ref".into()]).await.stdout, refs);
            let marker = fs::read(pinned.staging.join(ATTEMPT)).unwrap();
            assert!(matches!(SendOwner::open(config(), |_| async { CallbackOutcome::PublishedLocal }),
                Err(crate::send_owner::Error::Unavailable)));
            assert_eq!(fs::read(pinned.staging.join(ATTEMPT)).unwrap(), marker);
            client.close().await;
            serving.await.unwrap();
            memory.shutdown().await.unwrap();
            eprintln!("socket_free_send_fixture format={format} callback_count=1 actual_temp_tag_while_client_aborted=1 actual_temp_tag_while_draining=1 actual_temp_tags_after_return=0 source_and_refs_unchanged=true occupied_reopen_refused=true");
        }
    }).await.unwrap();
}

#[tokio::test]
async fn real_signed_export_roundtrips_sha1_and_sha256_without_touching_source() {
    for format in ["sha1", "sha256"] {
        let fixture = Fixture::new(format, 0x51).await;
        let config = fixture.export_config("roundtrip");
        let staged = config.staging.join(BUNDLE);
        let before = fixture.source_bytes();
        let refs = fixture.git(&["show-ref".into()]).await.stdout;
        let exporter = BundleExporter::open(config).unwrap();
        let prepared = exporter.prepare().await.unwrap();
        assert_eq!(prepared.expectation().oid(), fixture.oid);
        assert_eq!(prepared.expectation().tree(), fixture.tree);
        assert_eq!(prepared.expectation().builder(), fixture.builder);
        assert_eq!(prepared.expectation().size(), prepared.bytes().len() as u64);
        assert_eq!(
            prepared.expectation().hash(),
            *blake3::hash(prepared.bytes()).as_bytes()
        );
        assert_eq!(fs::read(&staged).unwrap(), prepared.bytes());
        let mut intake = fixture.intake_config("roundtrip");
        intake.bundle = staged;
        intake.expected = prepared.expectation().clone();
        let verified = BundleVerifier::open(intake)
            .unwrap()
            .verify()
            .await
            .unwrap();
        assert_eq!(verified.oid(), fixture.oid);
        assert_eq!(verified.hash(), prepared.expectation().hash());
        assert_eq!(fixture.source_bytes(), before);
        assert_eq!(fixture.git(&["show-ref".into()]).await.stdout, refs);
        assert!(matches!(
            exporter.prepare().await,
            Err(Error::AlreadyAttempted)
        ));
        assert_eq!(
            prepared.into_bytes(),
            fs::read(exporter.staging.join(BUNDLE)).unwrap()
        );
    }
}

/// Pause time only after real Git prepare has finished. The callback future
/// holds an actual tag and never completes; its deadline is an Unknown result,
/// not evidence about any peer. No endpoint, room, socket or native model.
#[tokio::test]
async fn public_send_deadline_drops_real_tag_and_caches_unknown_without_reexport() {
    use crate::send_owner::{CallbackOutcome, Error as SendError, SendOwner};
    use futures_util::StreamExt;
    use iroh_blobs::store::mem::MemStore;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::oneshot;

    tokio::time::timeout(Duration::from_secs(60), async {
        let fixture = Fixture::new("sha1", 0x51).await;
        let pinned = fixture.export_config("deadline");
        let config = || ExportOperatorConfig {
            source: pinned.source.clone(),
            export: pinned.export.clone(),
            staging: pinned.staging.clone(),
            empty_templates: pinned.empty_templates.clone(),
            builder_signers: pinned.builder_signers.clone(),
            candidate: GitCandidate::new(&fixture.oid, &fixture.tree, fixture.builder).unwrap(),
        };
        let before = fixture.source_bytes();
        let refs = fixture.git(&["show-ref".into()]).await.stdout;
        let memory = Arc::new(MemStore::new());
        let store = memory.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let (started, observed) = oneshot::channel();
        let owner = SendOwner::open(config(), move |prepared| async move {
            count.fetch_add(1, Ordering::SeqCst);
            let expected = prepared.expectation().clone();
            let tag = store.add_bytes(prepared.into_bytes()).temp_tag().await.unwrap();
            assert_eq!(*tag.hash().as_bytes(), expected.hash());
            started.send((tag.hash(), expected)).unwrap();
            let result = std::future::pending::<CallbackOutcome>().await;
            drop(tag);
            result
        }).unwrap();
        let waiting = owner.attach().unwrap().wait();
        tokio::pin!(waiting);
        let (hash, expected) = observed.await.unwrap();
        assert_eq!(expected.oid(), fixture.oid);
        assert_eq!(expected.tree(), fixture.tree);
        assert_eq!(expected.builder(), fixture.builder);
        let bytes = memory.blobs().get_bytes(hash).await.unwrap();
        assert_eq!(bytes.as_ref(), fs::read(pinned.staging.join(BUNDLE)).unwrap());
        assert_eq!(bytes.len() as u64, expected.size());
        assert_eq!(*blake3::hash(&bytes).as_bytes(), expected.hash());
        let tags = memory.tags().list_temp_tags().await.unwrap().collect::<Vec<_>>().await;
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].hash, hash);
        let marker = fs::read(pinned.staging.join(ATTEMPT)).unwrap();

        // Cooperative time, after all external-process work has completed.
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(15)).await;
        assert!(futures_util::poll!(waiting.as_mut()).is_pending());
        tokio::time::advance(Duration::from_secs(16)).await;
        let after_advance = tokio::time::Instant::now();
        assert_eq!(waiting.await, Err(SendError::Unknown));
        assert_eq!(tokio::time::Instant::now(), after_advance);
        tokio::time::resume();
        assert_eq!(owner.attach().unwrap().wait().await, Err(SendError::Unknown));
        assert_eq!(owner.finish().await, Err(SendError::Unknown));
        assert!(memory.tags().list_temp_tags().await.unwrap().collect::<Vec<_>>().await.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(fs::read(pinned.staging.join(ATTEMPT)).unwrap(), marker);
        assert!(matches!(SendOwner::open(config(), |_| async { CallbackOutcome::PublishedLocal }),
            Err(SendError::Unavailable)));
        assert_eq!(fixture.source_bytes(), before);
        assert_eq!(fixture.git(&["show-ref".into()]).await.stdout, refs);
        memory.shutdown().await.unwrap();
        eprintln!("socket_free_send_deadline tag_before=1 pending_before_deadline=true unknown_after_deadline=true tag_after=0 callback_count=1 cached_unknown=true source_refs_marker_unchanged=true occupied_reopen_refused=true");
    }).await.unwrap();
}

/// Exercise the actual timeout error through the local Rig/RMCP boundary.
/// All Git and store objects are fixtures; the transport is an in-memory duplex.
#[tokio::test]
async fn public_send_deadline_reaches_mcp_unknown_error_without_reexport() {
    use crate::send_owner::{CallbackOutcome, Error as SendError, SendOwner, mcp::SendServer};
    use futures_util::StreamExt;
    use iroh_blobs::store::mem::MemStore;
    use rig_core::tool::DynamicTool;
    use rig_rmcp::McpConnection;
    use rmcp::{ServiceExt, model::ClientConfig};
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::oneshot;

    tokio::time::timeout(Duration::from_secs(60), async {
        let fixture = Fixture::new("sha1", 0x51).await;
        let pinned = fixture.export_config("deadline-wire");
        let config = || ExportOperatorConfig {
            source: pinned.source.clone(),
            export: pinned.export.clone(),
            staging: pinned.staging.clone(),
            empty_templates: pinned.empty_templates.clone(),
            builder_signers: pinned.builder_signers.clone(),
            candidate: GitCandidate::new(&fixture.oid, &fixture.tree, fixture.builder).unwrap(),
        };
        let before = fixture.source_bytes();
        let refs = fixture.git(&["show-ref".into()]).await.stdout;
        let memory = Arc::new(MemStore::new());
        let store = memory.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let (started, observed) = oneshot::channel();
        let owner = SendOwner::open(config(), move |prepared| async move {
            count.fetch_add(1, Ordering::SeqCst);
            let expected = prepared.expectation().clone();
            let tag = store.add_bytes(prepared.into_bytes()).temp_tag().await.unwrap();
            assert_eq!(*tag.hash().as_bytes(), expected.hash());
            started.send((tag.hash(), expected)).unwrap();
            let result = std::future::pending::<CallbackOutcome>().await;
            drop(tag);
            result
        }).unwrap();
        let server = SendServer::new(owner).unwrap();
        let handler = server.clone();
        let (client_io, server_io) = tokio::io::duplex(32768);
        let serving = tokio::spawn(async move {
            handler.serve(tokio::io::split(server_io)).await.unwrap()
                .waiting().await.unwrap();
        });
        let client = McpConnection::new(ClientConfig::default()
            .serve(tokio::io::split(client_io)).await.unwrap());
        let tools = client.tools().await.unwrap();
        assert_eq!(tools.len(), 1);
        let tool = DynamicTool::try_from(tools.into_iter().next().unwrap()).unwrap();
        assert_eq!(tool.name(), "send_git_bundle_over_iroh");
        let first = tool.clone();
        let waiting = tokio::spawn(async move { first.run(json!({})).await });
        let (hash, expected) = observed.await.unwrap();
        assert_eq!(expected.oid(), fixture.oid);
        assert_eq!(expected.tree(), fixture.tree);
        assert_eq!(expected.builder(), fixture.builder);
        let bytes = memory.blobs().get_bytes(hash).await.unwrap();
        assert_eq!(bytes.as_ref(), fs::read(pinned.staging.join(BUNDLE)).unwrap());
        assert_eq!(bytes.len() as u64, expected.size());
        assert_eq!(*blake3::hash(&bytes).as_bytes(), expected.hash());
        let tags = memory.tags().list_temp_tags().await.unwrap().collect::<Vec<_>>().await;
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].hash, hash);
        let marker = fs::read(pinned.staging.join(ATTEMPT)).unwrap();

        // No external process is running when time is paused. The client must
        // receive the owner deadline result without auto-advancing to a later
        // client-request timeout to manufacture a terminal error.
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(31)).await;
        let after_advance = tokio::time::Instant::now();
        let error = waiting.await.unwrap().unwrap_err();
        assert_eq!(tokio::time::Instant::now(), after_advance);
        tokio::time::resume();
        // Rig Display is a host diagnostic. The model gets this typed payload.
        assert_eq!(error.model_output().as_json(), Some(&json!({"error":"send_unknown_no_retry"})));
        assert!(memory.tags().list_temp_tags().await.unwrap().collect::<Vec<_>>().await.is_empty());
        for _ in 0..2 {
            let error = tool.run(json!({})).await.unwrap_err();
            assert_eq!(error.model_output().as_json(), Some(&json!({"error":"send_unknown_no_retry"})));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(server.shutdown().await, Err(SendError::Unknown));
        let error = tool.run(json!({})).await.unwrap_err();
        assert_eq!(error.model_output().as_json(), Some(&json!({"error":"send_unavailable_no_retry"})));
        assert!(matches!(SendOwner::open(config(), |_| async { CallbackOutcome::PublishedLocal }),
            Err(SendError::Unavailable)));
        assert_eq!(fs::read(pinned.staging.join(ATTEMPT)).unwrap(), marker);
        assert_eq!(fixture.source_bytes(), before);
        assert_eq!(fixture.git(&["show-ref".into()]).await.stdout, refs);
        client.close().await;
        serving.await.unwrap();
        memory.shutdown().await.unwrap();
        eprintln!("socket_free_deadline_wire actual_unknown_error=true cached_unknown_calls=2 tag_after=0 callback_count=1 shutdown_unknown=true postclose_unavailable=true source_refs_marker_unchanged=true occupied_reopen_refused=true");
    }).await.unwrap();
}

#[tokio::test]
async fn wrong_tree_or_signer_cannot_initialize_export_and_attempt_cannot_be_replayed() {
    for wrong_signer in [false, true] {
        let fixture = Fixture::new("sha1", if wrong_signer { 0x52 } else { 0x51 }).await;
        let mut config = fixture.export_config("refused");
        if !wrong_signer {
            config.candidate =
                GitCandidate::new(&fixture.oid, &"0".repeat(40), fixture.builder).unwrap();
        }
        let staging = config.staging.clone();
        let export = config.export.clone();
        let exporter = BundleExporter::open(config).unwrap();
        let before = fixture.source_bytes();
        assert!(exporter.prepare().await.is_err());
        assert!(fs::read_dir(&export).unwrap().next().is_none());
        assert!(staging.join(ATTEMPT).is_file());
        assert!(!staging.join(BUNDLE).exists());
        let marker = fs::read(staging.join(ATTEMPT)).unwrap();
        assert!(matches!(
            exporter.prepare().await,
            Err(Error::AlreadyAttempted)
        ));
        assert_eq!(marker, fs::read(staging.join(ATTEMPT)).unwrap());
        assert_eq!(fixture.source_bytes(), before);
    }
}

#[tokio::test]
async fn source_gitfile_symlink_alternates_and_public_directory_are_refused() {
    let fixture = Fixture::new("sha1", 0x51).await;
    let mut config = fixture.export_config("symlink");
    let alias = fixture.root.join("source-alias");
    symlink(&fixture.source, &alias).unwrap();
    config.source = alias;
    assert!(BundleExporter::open(config).is_err());
    let config = fixture.export_config("public");
    fs::set_permissions(&config.export, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(BundleExporter::open(config).is_err());
    let config = fixture.export_config("alternate");
    write_private(
        &fixture.source.join(".git/objects/info/alternates"),
        b"/does/not/matter\n",
    );
    assert!(BundleExporter::open(config).is_err());
    fs::remove_file(fixture.source.join(".git/objects/info/alternates")).unwrap();
    let config = fixture.export_config("gitfile");
    fs::rename(
        fixture.source.join(".git"),
        fixture.source.join("actual-git"),
    )
    .unwrap();
    write_private(&fixture.source.join(".git"), b"gitdir: actual-git\n");
    assert!(BundleExporter::open(config).is_err());
}

fn reopen(exporter: &BundleExporter, signers: &Path) -> ExportOperatorConfig {
    ExportOperatorConfig {
        source: exporter.source.clone(),
        export: exporter.export.clone(),
        staging: exporter.staging.clone(),
        empty_templates: exporter.templates.clone(),
        builder_signers: signers.to_owned(),
        candidate: exporter.candidate.clone(),
    }
}

#[tokio::test]
async fn independent_openers_share_one_exclusive_attempt_and_cold_open_cannot_rebuild() {
    let fixture = Fixture::new("sha1", 0x51).await;
    let first = BundleExporter::open(fixture.export_config("race")).unwrap();
    let second = BundleExporter::open(reopen(&first, &fixture.signers)).unwrap();
    let (a, b) = tokio::join!(first.prepare(), second.prepare());
    assert_ne!(a.is_ok(), b.is_ok());
    let bytes = fs::read(first.staging.join(BUNDLE)).unwrap();
    assert_eq!(a.or(b).unwrap().bytes(), bytes);
    let marker = fs::read(first.staging.join(ATTEMPT)).unwrap();
    assert!(BundleExporter::open(reopen(&first, &fixture.signers)).is_err());
    assert_eq!(fs::read(first.staging.join(BUNDLE)).unwrap(), bytes);
    assert_eq!(fs::read(first.staging.join(ATTEMPT)).unwrap(), marker);
}

#[tokio::test]
async fn canceled_prepare_leaves_attempt_evidence_and_never_rearms() {
    use std::{future::Future, task::Poll};
    let fixture = Fixture::new("sha1", 0x51).await;
    let exporter = BundleExporter::open(fixture.export_config("canceled")).unwrap();
    let mut work = Box::pin(exporter.prepare());
    std::future::poll_fn(|context| {
        assert!(work.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    assert!(exporter.staging.join(ATTEMPT).is_file());
    let marker = fs::read(exporter.staging.join(ATTEMPT)).unwrap();
    drop(work);
    assert!(matches!(
        exporter.prepare().await,
        Err(Error::AlreadyAttempted)
    ));
    assert!(BundleExporter::open(reopen(&exporter, &fixture.signers)).is_err());
    assert_eq!(fs::read(exporter.staging.join(ATTEMPT)).unwrap(), marker);
    assert!(!exporter.staging.join(BUNDLE).exists());
}
