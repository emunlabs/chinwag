//! Controlled local transport tests. These do not establish WAN, Cloudflare,
//! relay availability, processing, task start or production K2 authority.

use super::*;

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
                // Use only an actual reported local socket. Do not consult or
                // mutate global CHINWAG_BUS_* routing environment in this test.
                let local = daemon
                    .bound_sockets
                    .iter()
                    .filter_map(|raw| raw.parse::<SocketAddr>().ok())
                    .find(|socket| socket.ip().is_loopback() && socket.port() != 0)
                    .ok_or("daemon did not report a bound loopback socket")?;
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
