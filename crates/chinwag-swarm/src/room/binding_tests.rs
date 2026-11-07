//! Private synthetic ordinary-room facts. No real coordinator or relay is used.
use super::*;
use crate::room_wire::{Challenge, sign_advertisement, storage_receipt_for_private_test};
use std::sync::atomic::{AtomicU64, Ordering};

struct TestClock {
    wall: AtomicU64,
    millis: AtomicU64,
    base: Instant,
}
impl TestClock {
    fn new() -> Self {
        Self {
            wall: AtomicU64::new(1000),
            millis: AtomicU64::new(0),
            base: Instant::now(),
        }
    }
}
impl Clock for TestClock {
    fn now(&self) -> Result<(u64, Instant), BindingError> {
        Ok((
            self.wall.load(Ordering::SeqCst),
            self.base + Duration::from_millis(self.millis.load(Ordering::SeqCst)),
        ))
    }
}
fn identity() -> Identity {
    Identity::test_identity(rand::random())
}
fn advertisement(identity: &Identity, session: u8, revision: u64, expiry: u64) -> Advertisement {
    let challenge = Challenge {
        room: "genesis".into(),
        actor_id: identity.endpoint_id().to_string(),
        operation: "advertise".into(),
        session_id: format!("{session:02x}").repeat(32),
        nonce: format!("{:02x}", session.wrapping_add(1)).repeat(32),
        expiry_unix: expiry,
    };
    sign_advertisement(
        identity,
        &challenge,
        revision,
        vec!["127.0.0.1:44330".parse().unwrap()],
        1000,
    )
    .unwrap()
}
fn renewed_own(fixture: &Fixture, revision: u64, expiry: u64, nonce: u8) -> Advertisement {
    let challenge = Challenge {
        room: "genesis".into(),
        actor_id: fixture.local.endpoint_id().to_string(),
        operation: "advertise".into(),
        session_id: "01".repeat(32),
        nonce: format!("{nonce:02x}").repeat(32),
        expiry_unix: expiry,
    };
    sign_advertisement(
        &fixture.local,
        &challenge,
        revision,
        vec!["127.0.0.1:44330".parse().unwrap()],
        fixture.clock.wall.load(Ordering::SeqCst),
    )
    .unwrap()
}
struct Fixture {
    local: Identity,
    peer: Identity,
    coordinator: Identity,
    clock: Arc<TestClock>,
    gate: DaemonPeerGate,
    owner: DaemonRoomOwner,
}
impl Fixture {
    fn new() -> Self {
        let local = identity();
        let peer = identity();
        let coordinator = identity();
        let clock = Arc::new(TestClock::new());
        let policy = Arc::new(
            RelayPolicy::from_local_manifest(
                Some("https://owned-relay.invalid"),
                Some("https://owned-relay.invalid"),
            )
            .unwrap(),
        );
        let config = DaemonPairConfig::try_new(
            "selected-config-v1".into(),
            7,
            local.endpoint_id(),
            peer.endpoint_id(),
            coordinator.endpoint_id(),
            policy,
        )
        .unwrap();
        let gate = DaemonPeerGate::with_clock(config, clock.clone());
        let mut owner = gate
            .begin_owner(
                local.endpoint_id(),
                coordinator.endpoint_id(),
                gate.configuration().relay_policy(),
                "https://owned-room.invalid/",
            )
            .unwrap();
        let own = advertisement(&local, 1, 1, 1060);
        let receipt = storage_receipt_for_private_test(&coordinator, &own);
        owner.bind_own(own, receipt, &"01".repeat(32)).unwrap();
        Self {
            local,
            peer,
            coordinator,
            clock,
            gate,
            owner,
        }
    }
    fn bind_peer(&mut self, session: u8, revision: u64) -> Advertisement {
        let advertisement = advertisement(&self.peer, session, revision, 1060);
        let receipt = storage_receipt_for_private_test(&self.coordinator, &advertisement);
        self.owner.bind_peer(&advertisement, &receipt).unwrap();
        advertisement
    }
}

#[test]
fn selected_pins_and_own_receipt_alone_do_not_admit_a_peer() {
    let fixture = Fixture::new();
    assert!(fixture.gate.current_peer().is_err());
    assert!(fixture.gate.check_peer(fixture.peer.endpoint_id()).is_err());
}
#[test]
fn fresh_owned_renewal_invalidates_snapshots_without_extending_peer_presence() {
    let mut fixture = Fixture::new();
    fixture.bind_peer(3, 1);
    let old_snapshot = fixture.gate.current_peer().unwrap();
    fixture.clock.wall.store(1030, Ordering::SeqCst);
    fixture.clock.millis.store(30_000, Ordering::SeqCst);
    let ticket = fixture.owner.prepare_renewal().unwrap();
    assert_eq!(ticket.next_revision().unwrap(), 2);
    let ad = renewed_own(&fixture, 2, 1090, 11);
    let receipt = storage_receipt_for_private_test(&fixture.coordinator, &ad);
    fixture.owner.commit_renewal(ticket, ad, receipt).unwrap();
    assert!(old_snapshot.local_session_id().is_err());
    assert!(
        old_snapshot
            .revalidate_for(fixture.peer.endpoint_id())
            .is_err()
    );
    assert_eq!(
        fixture.owner.remaining_validity().unwrap(),
        Duration::from_secs(60)
    );
    assert!(fixture.gate.current_peer().is_ok());
    fixture.clock.wall.store(1060, Ordering::SeqCst);
    fixture.clock.millis.store(60_000, Ordering::SeqCst);
    assert!(fixture.owner.remaining_validity().is_ok());
    assert!(
        fixture.gate.current_peer().is_err(),
        "peer retains its original expiry"
    );
}
#[test]
fn renewal_cannot_resurrect_an_expired_revoked_or_stale_owner() {
    for failure in 0..4 {
        let mut fixture = Fixture::new();
        fixture.clock.wall.store(1030, Ordering::SeqCst);
        fixture.clock.millis.store(30_000, Ordering::SeqCst);
        let ticket = fixture.owner.prepare_renewal().unwrap();
        let ad = renewed_own(&fixture, 2, 1090, 11);
        let receipt = storage_receipt_for_private_test(&fixture.coordinator, &ad);
        match failure {
            0 => fixture.clock.wall.store(1060, Ordering::SeqCst),
            1 => fixture.clock.millis.store(60_000, Ordering::SeqCst),
            2 => fixture.gate.revoke().unwrap(),
            3 => {
                let other = fixture.owner.prepare_renewal().unwrap();
                fixture
                    .owner
                    .commit_renewal(other, ad.clone(), receipt.clone())
                    .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            fixture.owner.commit_renewal(ticket, ad, receipt).is_err(),
            "case {failure}"
        );
    }
}
#[test]
fn renewal_requires_fresh_receipt_nonce_next_revision_and_later_expiry() {
    for failure in 0..6 {
        let mut fixture = Fixture::new();
        fixture.clock.wall.store(1030, Ordering::SeqCst);
        fixture.clock.millis.store(30_000, Ordering::SeqCst);
        let ticket = fixture.owner.prepare_renewal().unwrap();
        let mut ad = renewed_own(
            &fixture,
            if failure == 0 { 1 } else { 2 },
            if failure == 1 { 1060 } else { 1090 },
            if failure == 2 { 2 } else { 11 },
        );
        if failure == 3 {
            ad = advertisement(&fixture.local, 5, 2, 1090);
        }
        let mut receipt = storage_receipt_for_private_test(&fixture.coordinator, &ad);
        if failure == 4 {
            receipt.revision = 7;
        }
        if failure == 5 {
            receipt = storage_receipt_for_private_test(&identity(), &ad);
        }
        assert!(
            fixture.owner.commit_renewal(ticket, ad, receipt).is_err(),
            "case {failure}"
        );
        assert_eq!(
            fixture.owner.remaining_validity().unwrap(),
            Duration::from_secs(30)
        );
    }
}
#[test]
fn an_earlier_own_nonce_cannot_reenter_after_an_intervening_valid_renewal() {
    let mut fixture = Fixture::new();
    fixture.clock.wall.store(1030, Ordering::SeqCst);
    fixture.clock.millis.store(30_000, Ordering::SeqCst);
    let first = fixture.owner.prepare_renewal().unwrap();
    let ad = renewed_own(&fixture, 2, 1090, 11);
    let receipt = storage_receipt_for_private_test(&fixture.coordinator, &ad);
    fixture.owner.commit_renewal(first, ad, receipt).unwrap();
    fixture.clock.wall.store(1040, Ordering::SeqCst);
    fixture.clock.millis.store(40_000, Ordering::SeqCst);
    let second = fixture.owner.prepare_renewal().unwrap();
    // Reuse the INITIAL nonce, not the current predecessor's nonce. Every
    // other witness is valid and the previous authorization is still live.
    let replay = renewed_own(&fixture, 3, 1100, 2);
    let receipt = storage_receipt_for_private_test(&fixture.coordinator, &replay);
    assert!(matches!(
        fixture.owner.commit_renewal(second, replay, receipt),
        Err(BindingError::Replay)
    ));
    assert_eq!(
        fixture.owner.remaining_validity().unwrap(),
        Duration::from_secs(50)
    );
}
#[test]
fn own_nonce_history_exhaustion_revokes_without_eviction_or_lease_extension() {
    let mut fixture = Fixture::new();
    fixture.bind_peer(3, 1);
    fixture.clock.wall.store(1030, Ordering::SeqCst);
    fixture.clock.millis.store(30_000, Ordering::SeqCst);
    // Private bounded-storage fixture, not live coordinator traffic.
    fixture
        .gate
        .shared
        .state
        .lock()
        .unwrap()
        .own_nonces
        .extend((1..MAX_OWN_PRESENCE_NONCES - 1).map(|index| format!("{index:064x}")));
    let ticket = fixture.owner.prepare_renewal().unwrap();
    let ad = renewed_own(&fixture, 2, 1090, 11);
    let receipt = storage_receipt_for_private_test(&fixture.coordinator, &ad);
    fixture.owner.commit_renewal(ticket, ad, receipt).unwrap();
    assert_eq!(
        fixture.gate.shared.state.lock().unwrap().own_nonces.len(),
        MAX_OWN_PRESENCE_NONCES
    );
    assert!(fixture.gate.current_peer().is_ok());
    fixture.clock.wall.store(1040, Ordering::SeqCst);
    fixture.clock.millis.store(40_000, Ordering::SeqCst);
    let ticket = fixture.owner.prepare_renewal().unwrap();
    let ad = renewed_own(&fixture, 3, 1100, 12);
    let receipt = storage_receipt_for_private_test(&fixture.coordinator, &ad);
    assert!(matches!(
        fixture.owner.commit_renewal(ticket, ad, receipt),
        Err(BindingError::Replay)
    ));
    assert!(matches!(
        fixture.owner.remaining_validity(),
        Err(BindingError::Revoked)
    ));
    assert!(matches!(
        fixture.gate.current_peer(),
        Err(BindingError::Revoked)
    ));
    assert_eq!(
        fixture.gate.shared.state.lock().unwrap().own_nonces.len(),
        MAX_OWN_PRESENCE_NONCES
    );
}
#[test]
fn failed_receipt_does_not_consume_nonce_history_or_change_own_lease() {
    let mut fixture = Fixture::new();
    fixture.clock.wall.store(1030, Ordering::SeqCst);
    fixture.clock.millis.store(30_000, Ordering::SeqCst);
    let ticket = fixture.owner.prepare_renewal().unwrap();
    let ad = renewed_own(&fixture, 2, 1090, 11);
    let receipt = storage_receipt_for_private_test(&identity(), &ad);
    assert!(fixture.owner.commit_renewal(ticket, ad, receipt).is_err());
    let state = fixture.gate.shared.state.lock().unwrap();
    assert_eq!(state.own_nonces, vec!["02".repeat(32)]);
    assert_eq!(state.own.as_ref().unwrap().advertisement.revision, 1);
}
#[test]
fn refresh_cadence_is_fixed_per_verified_lease_not_reset_by_reads_or_tickets() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.owner.renewal_wait().unwrap(),
        Duration::from_secs(30)
    );
    fixture.clock.wall.store(1020, Ordering::SeqCst);
    fixture.clock.millis.store(20_000, Ordering::SeqCst);
    let _ticket = fixture.owner.prepare_renewal().unwrap();
    assert_eq!(
        fixture.owner.renewal_wait().unwrap(),
        Duration::from_secs(10)
    );
    assert_eq!(
        fixture.owner.remaining_validity().unwrap(),
        Duration::from_secs(40)
    );
    fixture.clock.wall.store(1030, Ordering::SeqCst);
    fixture.clock.millis.store(30_000, Ordering::SeqCst);
    assert_eq!(fixture.owner.renewal_wait().unwrap(), Duration::ZERO);
}
#[test]
fn sanitized_posture_is_current_and_cannot_promote_expired_presence() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.gate.posture().unwrap().phase, "PENDING");
    fixture.bind_peer(3, 1);
    assert_eq!(fixture.gate.posture().unwrap().phase, "LIVE_AT_OBSERVATION");
    let view = serde_json::to_string(&fixture.gate.posture().unwrap()).unwrap();
    for private in ["session", "nonce", "signature", "origin", "address"] {
        assert!(!view.contains(private));
    }
    fixture.clock.wall.store(1060, Ordering::SeqCst);
    assert_eq!(fixture.gate.posture().unwrap().phase, "HELD");
    fixture.gate.revoke().unwrap();
    assert_eq!(fixture.gate.posture().unwrap().phase, "HELD");
}
#[test]
fn verified_remote_join_retains_exact_ordinary_records_and_selected_route() {
    let mut fixture = Fixture::new();
    let ad = fixture.bind_peer(3, 1);
    let proof = fixture.gate.current_peer().unwrap();
    assert_eq!(proof.peer_advertisement().session_id, ad.session_id);
    assert_eq!(proof.peer_storage_receipt().advertisement_sha256.len(), 64);
    assert_eq!(proof.local_session_id().unwrap(), "01".repeat(32));
    assert_eq!(proof.configuration_id().unwrap(), "selected-config-v1");
    assert_eq!(proof.configuration_generation().unwrap(), 7);
    assert_eq!(
        proof.control_plane_origin().unwrap(),
        "https://owned-room.invalid/"
    );
    let (own, receipt) = proof.own_advertisement_and_receipt().unwrap();
    room_wire::verify_advertisement(&own, fixture.local.endpoint_id(), 1000).unwrap();
    room_wire::verify_receipt(&receipt, fixture.coordinator.endpoint_id(), &own).unwrap();
    let address = proof.revalidate_for(fixture.peer.endpoint_id()).unwrap();
    assert!(same_endpoint(address.id, fixture.peer.endpoint_id()));
    assert_eq!(address.relay_urls().count(), 1);
    assert_eq!(
        address.relay_urls().next(),
        fixture.gate.configuration().relay_policy().relay_url()
    );
}
#[test]
fn each_remote_receipt_join_mismatch_is_refused() {
    for field in 0..7 {
        let mut fixture = Fixture::new();
        let ad = advertisement(&fixture.peer, 3, 1, 1060);
        let mut receipt = storage_receipt_for_private_test(&fixture.coordinator, &ad);
        match field {
            0 => receipt.actor_id = "33".repeat(32),
            1 => receipt.session_id = "44".repeat(32),
            2 => receipt.challenge_nonce = "55".repeat(32),
            3 => receipt.revision = 2,
            4 => receipt.expiry_unix = 1059,
            5 => receipt.advertisement_sha256 = "66".repeat(32),
            6 => receipt.signature = "00".repeat(64),
            _ => unreachable!(),
        }
        assert!(
            fixture.owner.bind_peer(&ad, &receipt).is_err(),
            "field {field}"
        );
        assert!(fixture.gate.current_peer().is_err());
    }
}
#[test]
fn another_coordinator_or_actor_cannot_fill_the_selected_binding() {
    let mut fixture = Fixture::new();
    let ad = advertisement(&fixture.peer, 3, 1, 1060);
    let wrong = identity();
    let receipt = storage_receipt_for_private_test(&wrong, &ad);
    assert!(fixture.owner.bind_peer(&ad, &receipt).is_err());
    let wrong_ad = advertisement(&wrong, 3, 1, 1060);
    let receipt = storage_receipt_for_private_test(&fixture.coordinator, &wrong_ad);
    assert!(fixture.owner.bind_peer(&wrong_ad, &receipt).is_err());
    assert!(fixture.gate.current_peer().is_err());
}
#[test]
fn a_new_revision_invalidates_old_snapshots_and_each_frame_checks_current_state() {
    let mut fixture = Fixture::new();
    fixture.bind_peer(3, 1);
    let old = fixture.gate.current_peer().unwrap();
    fixture.gate.check_peer(fixture.peer.endpoint_id()).unwrap();
    fixture.bind_peer(3, 2);
    assert!(matches!(
        old.revalidate_for(fixture.peer.endpoint_id()),
        Err(BindingError::Revoked)
    ));
    assert!(old.local_session_id().is_err());
    assert!(old.own_advertisement_and_receipt().is_err());
    assert!(old.control_plane_origin().is_err());
    fixture.gate.check_peer(fixture.peer.endpoint_id()).unwrap();
    fixture.gate.revoke().unwrap();
    assert!(fixture.gate.check_peer(fixture.peer.endpoint_id()).is_err());
}
#[test]
fn original_owner_drop_revokes_all_issued_snapshots_and_hooks() {
    let mut fixture = Fixture::new();
    fixture.bind_peer(3, 1);
    let proof = fixture.gate.current_peer().unwrap();
    let gate = fixture.gate.clone();
    let peer = fixture.peer.endpoint_id();
    drop(fixture);
    assert!(proof.revalidate_for(peer).is_err());
    assert!(gate.check_peer(peer).is_err());
}
#[test]
fn missing_receipt_clear_keeps_a_peer_pending_until_a_new_verified_update() {
    let mut fixture = Fixture::new();
    fixture.bind_peer(3, 1);
    let old = fixture.gate.current_peer().unwrap();
    fixture.owner.clear_peer().unwrap();
    assert!(fixture.gate.check_peer(fixture.peer.endpoint_id()).is_err());
    assert!(old.local_session_id().is_err());
    fixture.bind_peer(3, 2);
    fixture.gate.check_peer(fixture.peer.endpoint_id()).unwrap();
}
#[test]
fn retired_sessions_and_duplicate_revisions_do_not_reenter() {
    let mut fixture = Fixture::new();
    let old = fixture.bind_peer(3, 1);
    let receipt = storage_receipt_for_private_test(&fixture.coordinator, &old);
    assert!(matches!(
        fixture.owner.bind_peer(&old, &receipt),
        Err(BindingError::Replay)
    ));
    fixture.bind_peer(5, 1);
    let retired = advertisement(&fixture.peer, 3, 2, 1060);
    let receipt = storage_receipt_for_private_test(&fixture.coordinator, &retired);
    assert!(matches!(
        fixture.owner.bind_peer(&retired, &receipt),
        Err(BindingError::Replay)
    ));
}
#[test]
fn wall_expiry_clock_rollback_and_monotonic_expiry_cannot_renew_admission() {
    for (wall, millis) in [(1060, 0), (500, 0), (1000, 60_000)] {
        let mut fixture = Fixture::new();
        fixture.bind_peer(3, 1);
        fixture.clock.wall.store(wall, Ordering::SeqCst);
        fixture.clock.millis.store(millis, Ordering::SeqCst);
        assert!(fixture.gate.check_peer(fixture.peer.endpoint_id()).is_err());
    }
}
#[test]
fn actual_peer_pin_and_local_configuration_must_match() {
    let mut fixture = Fixture::new();
    fixture.bind_peer(3, 1);
    let stranger = identity();
    assert!(matches!(
        fixture.gate.check_peer(stranger.endpoint_id()),
        Err(BindingError::Endpoint)
    ));
    assert!(
        fixture
            .gate
            .begin_owner(
                fixture.peer.endpoint_id(),
                fixture.coordinator.endpoint_id(),
                fixture.gate.configuration().relay_policy(),
                "https://owned-room.invalid/"
            )
            .is_err()
    );
    assert!(
        DaemonPairConfig::try_new(
            "config".into(),
            0,
            fixture.local.endpoint_id(),
            fixture.peer.endpoint_id(),
            fixture.coordinator.endpoint_id(),
            Arc::new(RelayPolicy::Disabled)
        )
        .is_err()
    );
    assert!(
        DaemonPairConfig::try_new(
            "config".into(),
            1,
            fixture.local.endpoint_id(),
            fixture.local.endpoint_id(),
            fixture.coordinator.endpoint_id(),
            Arc::new(RelayPolicy::Disabled)
        )
        .is_err()
    );
}
#[test]
fn daemon_only_zero_direct_profile_needs_own_relay_and_matching_storage_receipt() {
    let mut fixture = Fixture::new();
    let challenge = Challenge {
        room: "genesis".into(),
        actor_id: fixture.peer.endpoint_id().to_string(),
        operation: "advertise".into(),
        session_id: "03".repeat(32),
        nonce: "04".repeat(32),
        expiry_unix: 1060,
    };
    assert!(sign_advertisement(&fixture.peer, &challenge, 1, vec![], 1000).is_err());
    assert!(
        room_wire::sign_daemon_advertisement(
            &fixture.peer,
            &challenge,
            1,
            vec![],
            1000,
            &RelayPolicy::Disabled
        )
        .is_err()
    );
    let wire = room_wire::sign_daemon_advertisement(
        &fixture.peer,
        &challenge,
        1,
        vec![],
        1000,
        fixture.gate.configuration().relay_policy(),
    )
    .unwrap();
    assert!(wire.direct_addresses.is_empty());
    assert!(room_wire::verify_advertisement(&wire, fixture.peer.endpoint_id(), 1000).is_err());
    assert!(
        room_wire::verify_daemon_advertisement(
            &wire,
            fixture.peer.endpoint_id(),
            1000,
            &RelayPolicy::Disabled
        )
        .is_err()
    );
    assert!(fixture.gate.current_peer().is_err());
    let receipt = storage_receipt_for_private_test(&fixture.coordinator, &wire);
    fixture.owner.bind_peer(&wire, &receipt).unwrap();
    let address = fixture
        .gate
        .current_peer()
        .unwrap()
        .revalidate_for(fixture.peer.endpoint_id())
        .unwrap();
    assert_eq!(address.ip_addrs().count(), 0);
    assert_eq!(address.relay_urls().count(), 1);
}
#[test]
fn remaining_daemon_wait_uses_original_wall_and_monotonic_cutoff() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.owner.remaining_validity().unwrap(),
        Duration::from_secs(60)
    );
    fixture.clock.wall.store(1020, Ordering::SeqCst);
    fixture.clock.millis.store(20_000, Ordering::SeqCst);
    assert_eq!(
        fixture.owner.remaining_validity().unwrap(),
        Duration::from_secs(40)
    );
    fixture.clock.wall.store(1000, Ordering::SeqCst);
    assert_eq!(
        fixture.owner.remaining_validity().unwrap(),
        Duration::from_secs(40)
    );
    fixture.clock.millis.store(60_000, Ordering::SeqCst);
    assert!(fixture.owner.remaining_validity().is_err());
}
#[test]
fn own_advertisement_session_and_storage_receipt_cannot_be_replaced() {
    let local = identity();
    let peer = identity();
    let coordinator = identity();
    let config = DaemonPairConfig::try_new(
        "config".into(),
        1,
        local.endpoint_id(),
        peer.endpoint_id(),
        coordinator.endpoint_id(),
        Arc::new(RelayPolicy::Disabled),
    )
    .unwrap();
    let gate = DaemonPeerGate::with_clock(config, Arc::new(TestClock::new()));
    let mut owner = gate
        .begin_owner(
            local.endpoint_id(),
            coordinator.endpoint_id(),
            &RelayPolicy::Disabled,
            "https://room.invalid/",
        )
        .unwrap();
    let own = advertisement(&local, 1, 1, 1060);
    let receipt = storage_receipt_for_private_test(&coordinator, &own);
    assert!(
        owner
            .bind_own(own.clone(), receipt.clone(), &"ff".repeat(32))
            .is_err()
    );
    owner
        .bind_own(own.clone(), receipt.clone(), &own.session_id)
        .unwrap();
    assert!(
        owner
            .bind_own(own.clone(), receipt, &own.session_id)
            .is_err()
    );
}
#[tokio::test]
async fn pending_hooks_refuse_and_verified_hooks_follow_live_revocation() {
    let mut fixture = Fixture::new();
    let hooks = fixture.gate.hooks();
    let address = EndpointAddr::new(fixture.peer.endpoint_id());
    assert!(matches!(
        hooks.before_connect(&address, b"chinwag/bus/1").await,
        BeforeConnectOutcome::Reject
    ));
    fixture.bind_peer(3, 1);
    assert!(matches!(
        hooks.before_connect(&address, b"chinwag/bus/1").await,
        BeforeConnectOutcome::Accept
    ));
    fixture.gate.revoke().unwrap();
    assert!(matches!(
        hooks.before_connect(&address, b"chinwag/bus/1").await,
        BeforeConnectOutcome::Reject
    ));
}
#[tokio::test]
async fn daemon_signer_is_bound_to_the_actual_endpoint_and_reuses_room_codec() {
    use iroh::{RelayMode, endpoint::presets};
    let key = SecretKey::from_bytes(&rand::random());
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(key.clone())
        .clear_address_lookup()
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap();
    let wrong = SecretKey::from_bytes(&rand::random());
    assert!(DaemonRoomIdentity::for_endpoint(wrong, &endpoint).is_err());
    let identity = DaemonRoomIdentity::for_endpoint(key, &endpoint).unwrap();
    let challenge = Challenge {
        room: "genesis".into(),
        actor_id: identity.endpoint_id().to_string(),
        operation: "advertise".into(),
        session_id: "01".repeat(32),
        nonce: "02".repeat(32),
        expiry_unix: 1060,
    };
    let wire = sign_advertisement(
        &identity,
        &challenge,
        1,
        vec!["127.0.0.1:44330".parse().unwrap()],
        1000,
    )
    .unwrap();
    room_wire::verify_advertisement(&wire, endpoint.id(), 1000).unwrap();
    endpoint.close().await;
}
