//! Controlled local transport tests. These do not establish WAN, Cloudflare,
//! relay availability, processing, task start or production K2 authority.

use super::*;

#[test]
fn remote_storage_ack_requires_every_original_and_peer_witness() {
    let temporary = tempfile::tempdir().unwrap();
    let message = super::tests::native_publication_fixture(temporary.path());
    let peer = SecretKey::generate().public();
    for failure in 0..8 {
        let mut ack = FederationAck {
            publication: BusAck {
                ok: true,
                seq: 7,
                message_id: message.id.clone(),
                daemon_endpoint_id: peer.to_string(),
                transport: "iroh".into(),
                room: message.room.clone(),
                subscribers_notified: 0,
                sig_verified: true,
            },
            original_digest_sha256: message.digest_sha256.clone(),
        };
        match failure {
            0 => {}
            1 => ack.publication.ok = false,
            2 => ack.publication.seq = 0,
            3 => ack.publication.message_id.push('x'),
            4 => ack.publication.room.push('x'),
            5 => ack.publication.daemon_endpoint_id = SecretKey::generate().public().to_string(),
            6 => ack.original_digest_sha256 = "00".repeat(32),
            7 => ack.publication.sig_verified = false,
            _ => unreachable!(),
        }
        assert_eq!(
            valid_remote_publication_ack(peer, &message, &ack),
            failure == 0
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn local_receipt_and_posture_queries_do_not_publish_or_replay() {
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    let original = super::tests::native_publication_fixture(&root);
    let (shutdown, stopped) = tokio::sync::oneshot::channel::<()>();
    let mut output = Vec::new();
    // Explicit loopback destination keeps all packets on this host. The peer
    // below binds a real non-loopback source, which the server must refuse.
    let daemon = run_daemon_loop_inner(
        root.clone(),
        0,
        None,
        true,
        &mut output,
        async {
            let _ = stopped.await;
        },
        None,
        Some(([127, 0, 0, 1], 0).into()),
    );
    let exercise = async {
        let result = async {
            let daemon = wait_for_owned_daemon(&root).await?;
            let posture = query_local_daemon(&daemon, &BusFrame::NetworkPosture).await?;
            assert_eq!(posture["network"]["mode"], "LEGACY_LOCAL_ONLY");
            assert_eq!(posture["socket_liveness"], "UNKNOWN");
            let frame = BusFrame::FederationReceipt {
                original_id: original.id.clone(),
                original_digest_sha256: original.digest_sha256.clone(),
            };
            let absent = query_local_daemon(&daemon, &frame).await?;
            assert_eq!(absent["federation"]["outcome"], "UNKNOWN");
            let first = publish_over_iroh_quic(&daemon, SecretKey::generate(), &original).await?;
            assert!(valid_publication_ack(&daemon, &original, &first));
            let journal = one_original_journal(&root, &original)?;
            let before = query_local_daemon(&daemon, &frame).await?;
            assert_eq!(before["federation"]["outcome"], "PUBLISH_ONLY");
            let _ = publish_over_iroh_quic(&daemon, SecretKey::generate(), &original).await?;
            let after = query_local_daemon(&daemon, &frame).await?;
            assert_eq!(before, after);
            assert_eq!(one_original_journal(&root, &original)?, journal);
            let mut invalid_route = daemon.clone();
            invalid_route.bound_sockets = vec!["192.0.2.1:44330".into()];
            assert!(query_local_daemon(&invalid_route, &frame).await.is_err());
            // Bypass the client helper deliberately. A real non-loopback
            // transport peer must reach the server's refusal boundary too.
            let local_ip = discover_non_loopback_ipv4()
                .into_iter()
                .next()
                .ok_or_else(|| {
                    "this native transport test requires a non-loopback interface".to_owned()
                })?;
            let route = daemon.bound_sockets.iter().filter_map(|raw| raw.parse::<SocketAddr>().ok())
                .find(|socket| socket.is_ipv4() && socket.ip().is_loopback())
                .ok_or_else(|| format!("daemon has no IPv4 loopback route: {:?}", daemon.bound_sockets))?;
            let original_routes: DaemonState = serde_json::from_slice(&fs::read(daemon_json_path(&root)).map_err(|error| error.to_string())?).map_err(|error| error.to_string())?;
            for query in [frame, BusFrame::NetworkPosture] {
                let client = Endpoint::builder(presets::Minimal)
                .relay_mode(RelayMode::Disabled)
                .clear_address_lookup()
                .clear_ip_transports()
                .bind_addr(format!("{local_ip}:0").parse::<SocketAddr>().unwrap())
                .map_err(|_| "test bind address refused".to_owned())?
                .bind()
                .await
                .map_err(|_| "test endpoint bind failed".to_owned())?;
                let address = EndpointAddr::from_parts(
                    daemon.endpoint_id.parse().unwrap(),
                    // Keep the destination local to this host while the
                    // explicitly bound peer source remains non-loopback. The
                    // daemon must reject that actual source transport path.
                    [TransportAddr::Ip(route)],
                );
                let connection =
                    tokio::time::timeout(Duration::from_secs(5), client.connect(address, BUS_ALPN))
                        .await
                        .map_err(|_| format!("adversarial test connect timeout: source={local_ip}, destination={route}, query={query:?}, daemon_routes={:?}, client_sockets={:?}", original_routes.bound_sockets, client.bound_sockets()))?
                        .map_err(|_| "adversarial test must actually connect".to_owned())?;
                let (mut send, mut recv) = connection
                    .open_bi()
                    .await
                    .map_err(|_| "test stream failed".to_owned())?;
                send.write_all(&serde_json::to_vec(&query).unwrap())
                    .await
                    .map_err(|_| "test frame write failed".to_owned())?;
                send.finish()
                    .map_err(|_| "test frame finish failed".to_owned())?;
                let _ =
                    tokio::time::timeout(Duration::from_secs(3), recv.read_to_end(MAX_FRAME_BYTES))
                        .await;
                let close = tokio::time::timeout(Duration::from_secs(3), connection.closed())
                    .await
                    .map_err(|_| "server did not close refused query".to_owned())?;
                match close {
                    iroh::endpoint::ConnectionError::ApplicationClosed(close) => {
                        assert_eq!(close.reason.as_ref(), b"local_query_refused");
                    }
                    _ => return Err("server did not explicitly refuse non-loopback query".into()),
                }
                client.close().await;
            }
            assert_eq!(one_original_journal(&root, &original)?, journal);
            Ok::<(), String>(())
        }
        .await;
        let _ = shutdown.send(());
        result
    };
    let (exit, result) = tokio::join!(daemon, exercise);
    assert_eq!(exit, 0);
    result.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn pending_room_owner_does_not_starve_local_publication_or_observation() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    let original = super::tests::native_publication_fixture(&root);
    let entered = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    struct DriverDrop(Arc<AtomicBool>);
    impl Drop for DriverDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let driver_entered = entered.clone();
    let driver_dropped = dropped.clone();
    let driver = Box::pin(async move {
        let _guard = DriverDrop(driver_dropped);
        driver_entered.store(true, Ordering::SeqCst);
        std::future::pending::<RoomOwnerFailure>().await
    });
    let (shutdown, stopped) = tokio::sync::oneshot::channel::<()>();
    let mut output = Vec::new();
    let daemon = run_daemon_loop_inner(
        root.clone(),
        0,
        None,
        true,
        &mut output,
        async {
            let _ = stopped.await;
        },
        Some(driver),
        None,
    );
    let exercise = async {
        let result = async {
            let daemon = wait_for_owned_daemon(&root).await?;
            tokio::time::timeout(Duration::from_secs(5), async {
                while !entered.load(Ordering::SeqCst) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .map_err(|_| "controlled room owner was not polled")?;
            let posture = tokio::time::timeout(
                Duration::from_secs(5),
                query_local_daemon(&daemon, &BusFrame::NetworkPosture),
            )
            .await
            .map_err(|_| "pending owner starved posture query")??;
            assert_eq!(posture["network"]["mode"], "LEGACY_LOCAL_ONLY");
            let ack = tokio::time::timeout(
                Duration::from_secs(5),
                publish_over_iroh_quic(&daemon, SecretKey::generate(), &original),
            )
            .await
            .map_err(|_| "pending owner starved local publication")??;
            assert!(valid_publication_ack(&daemon, &original, &ack));
            let receipt = tokio::time::timeout(
                Duration::from_secs(5),
                query_local_daemon(
                    &daemon,
                    &BusFrame::FederationReceipt {
                        original_id: original.id.clone(),
                        original_digest_sha256: original.digest_sha256.clone(),
                    },
                ),
            )
            .await
            .map_err(|_| "pending owner starved receipt query")??;
            assert_eq!(receipt["federation"]["outcome"], "PUBLISH_ONLY");
            let _ = one_original_journal(&root, &original)?;
            assert!(
                !dropped.load(Ordering::SeqCst),
                "owner future was cancelled by unrelated I/O"
            );
            Ok::<(), String>(())
        }
        .await;
        let _ = shutdown.send(());
        result
    };
    let (exit, result) = tokio::join!(daemon, exercise);
    assert_eq!(exit, 0);
    result.unwrap();
    assert!(
        dropped.load(Ordering::SeqCst),
        "shutdown did not retire the original owner future"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn room_receive_failure_exits_unsuccessfully() {
    use chinwag_swarm::room::Error;
    for (error, expected) in [
        (Error::Malformed, "the room response is malformed"),
        (
            Error::WebSocket("protocol"),
            "the room WebSocket operation failed (protocol)",
        ),
        (
            Error::WebSocketClosed(1000),
            "the room WebSocket closed with code 1000",
        ),
    ] {
        let temporary = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temporary.path()).unwrap();
        let _original = super::tests::native_publication_fixture(&root);
        let mut output = Vec::new();
        let exit = run_daemon_loop_inner(
            root,
            0,
            None,
            true,
            &mut output,
            std::future::pending(),
            Some(Box::pin(async move {
                RoomOwnerFailure::ReceiveFailed(error.to_string())
            })),
            None,
        )
        .await;
        assert_eq!(exit, 1, "unexpected room failure must not report success");
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains(&format!(
            "original room receive failed: {expected}; no retry"
        )));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn room_renewal_failure_exits_unsuccessfully_and_preserves_reason() {
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    let _original = super::tests::native_publication_fixture(&root);
    let mut output = Vec::new();
    let exit = run_daemon_loop_inner(
        root,
        0,
        None,
        true,
        &mut output,
        std::future::pending(),
        Some(Box::pin(async {
            RoomOwnerFailure::RenewalUnknown(
                chinwag_swarm::room::Error::Http("timeout").to_string(),
            )
        })),
        None,
    )
    .await;
    assert_eq!(exit, 1);
    assert!(String::from_utf8(output).unwrap().contains(
        "transport presence renewal unknown or refused: the room HTTP request failed (timeout); no retry"
    ));
}

async fn wait_for_owned_daemon(root: &Path) -> Result<DaemonState, String> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(bytes) = fs::read(daemon_json_path(root))
                && let Ok(mut daemon) = serde_json::from_slice::<DaemonState>(&bytes)
            {
                if daemon.pid != std::process::id()
                    || daemon.product_governor != "DISABLED_CONTROLLED_INSTANCE"
                {
                    return Err("state did not describe this controlled daemon".into());
                }
                // Keep the address family used by the external IPv4 probe.
                // Iroh may bind IPv4 and IPv6 to different ephemeral ports.
                // Do not consult or mutate global CHINWAG_BUS_* routing state.
                let local = daemon
                    .bound_sockets
                    .iter()
                    .filter_map(|raw| raw.parse::<SocketAddr>().ok())
                    .find(|socket| {
                        socket.is_ipv4() && socket.ip().is_loopback() && socket.port() != 0
                    })
                    .ok_or("daemon did not report a bound IPv4 loopback socket")?;
                daemon.bound_sockets = vec![local.to_string()];
                return Ok(daemon);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .map_err(|_| "controlled daemon did not become ready within five seconds".to_owned())?
}

fn one_original_journal(root: &Path, expected: &BusMessage) -> Result<Vec<u8>, String> {
    let bytes = fs::read(messages_jsonl_path(root)).map_err(|error| error.to_string())?;
    if !bytes.ends_with(b"\n") {
        return Err("journal did not have a complete terminal row".into());
    }
    let rows: Vec<BusMessage> = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).map_err(|error| error.to_string()))
        .collect::<Result<_, _>>()?;
    if rows.len() != 1 {
        return Err(format!(
            "expected exactly one journal row, got {}",
            rows.len()
        ));
    }
    let mut row = rows[0].clone();
    if row.seq != 1
        || row.id != expected.id
        || row.digest_sha256 != expected.digest_sha256
        || row.body != expected.body
        || row.signature_ed25519 != expected.signature_ed25519
        || !verify_detached_bus_signature(root, &mut row)
    {
        return Err("journal row did not preserve the verified original".into());
    }
    Ok(bytes)
}

#[tokio::test(flavor = "current_thread")]
async fn actual_loopback_daemon_persists_once_replays_and_refuses_invalid_originals() {
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    let original = super::tests::native_publication_fixture(&root);
    let signing = actor_signing_secret_at("RUST", &root.join("fixture-signing")).unwrap();
    let (shutdown, stopped) = tokio::sync::oneshot::channel::<()>();
    let mut daemon_output = Vec::new();
    let daemon = run_daemon_loop(root.clone(), 0, None, true, &mut daemon_output, async {
        let _ = stopped.await;
    });
    let exercise = async {
        let result: Result<Vec<u8>, String> = async {
            let daemon = wait_for_owned_daemon(&root).await?;
            let first = publish_over_iroh_quic(&daemon, SecretKey::generate(), &original).await?;
            if !valid_publication_ack(&daemon, &original, &first)
                || first.seq != 1
                || first.subscribers_notified != 0
            {
                return Err(
                    "actual publication ACK must correlate and report zero consumers".into(),
                );
            }
            let journal = one_original_journal(&root, &original)?;

            let replay = publish_over_iroh_quic(&daemon, SecretKey::generate(), &original).await?;
            if !valid_publication_ack(&daemon, &original, &replay)
                || replay.seq != first.seq
                || replay.subscribers_notified != 0
                || one_original_journal(&root, &original)? != journal
            {
                return Err("exact transport replay appended or repeated local fanout".into());
            }

            // This conflict carries a genuinely valid signature and digest,
            // so refusal must come from immutable original identity handling.
            let mut conflict = original.clone();
            conflict.body.push_str(" changed under the original ID");
            conflict.digest_sha256 = compute_message_digest(
                conflict.ts_unix,
                &conflict.room,
                &conflict.sender,
                &conflict.sender_endpoint_id,
                conflict.to.as_deref(),
                conflict.task_id.as_deref(),
                &conflict.body,
            );
            sign_bus_message(&mut conflict, &signing);
            if !verify_detached_bus_signature(&root, &mut conflict) {
                return Err("controlled original conflict was not genuinely signed".into());
            }
            let refused = publish_over_iroh_quic(&daemon, SecretKey::generate(), &conflict).await?;
            if refused.ok
                || !refused.sig_verified
                || refused.seq != 0
                || refused.message_id != original.id
                || refused.subscribers_notified != 0
                || one_original_journal(&root, &original)? != journal
            {
                return Err("signed original conflict escaped its refusal boundary".into());
            }

            let mut invalid = original.clone();
            invalid.id = "bus-controlled-invalid-signature".into();
            invalid.body.push_str(" tampered without re-signing");
            let refused = publish_over_iroh_quic(&daemon, SecretKey::generate(), &invalid).await?;
            if refused.ok
                || refused.sig_verified
                || refused.seq != 0
                || refused.message_id != invalid.id
                || refused.subscribers_notified != 0
                || one_original_journal(&root, &original)? != journal
            {
                return Err("invalid signature escaped its refusal boundary".into());
            }
            Ok(journal)
        }
        .await;
        let _ = shutdown.send(());
        result
    };

    let (status, result) = tokio::time::timeout(Duration::from_secs(60), async {
        tokio::join!(daemon, exercise)
    })
    .await
    .expect("owned daemon and all original transport attempts must finish within sixty seconds");
    assert_eq!(status, 0, "{}", String::from_utf8_lossy(&daemon_output));
    let journal = result.expect("actual controlled daemon transport checks must pass");
    assert_eq!(one_original_journal(&root, &original).unwrap(), journal);
    assert!(!root.join("TASKS.md").exists());
    assert!(!root.join(".chinwag/bus/bus.sqlite").exists());
}

#[test]
fn relay_only_production_bind_decision_is_loopback_and_pending_selection_stays_denied() {
    for port in [0, 44330] {
        let address = configured_bus_bind_addr(port, true).unwrap();
        assert!(address.ip().is_loopback());
        assert_eq!(address.port(), port);
    }
    assert!(configured_bus_bind_addr(0, false).is_none());
    assert!(
        configured_bus_bind_addr(44330, false)
            .unwrap()
            .ip()
            .is_unspecified()
    );

    // Construct selections only. Never bind an endpoint carrying this relay
    // policy or send a DNS/HTTP/relay request to an unprovisioned service.
    let coordinator = SecretKey::generate().public();
    let peer = SecretKey::generate().public();
    let local = SecretKey::generate().public();
    let selection = NetworkSelection::try_new(
        "https://coordinator.invalid".into(),
        &coordinator.to_string(),
        &peer.to_string(),
        "https://owned-relay.invalid",
        "https://owned-relay.invalid",
        "controlled-relay-bind".into(),
        1,
        true,
    )
    .unwrap();
    let gate = selection.pending_gate(local).unwrap();
    assert!(selection.relay_only());
    assert!(gate.current_peer().is_err());
    assert!(gate.check_peer(peer).is_err());
    assert!(selection.current_address(&gate).is_err());
}
