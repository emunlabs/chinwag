use super::*;
use std::cell::Cell;

fn registry() -> Registry {
    Registry::new(Limits {
        max_grants: 8,
        max_bindings: 8,
        max_lease: Duration::from_secs(60),
    })
    .unwrap()
}

fn destination(room: NativeRoom) -> Destination {
    Destination::new("http://127.0.0.1:44339", room).unwrap()
}

fn decision(connection: &ConnectionId, destination: &Destination) -> OwnerLocalDecision {
    OwnerLocalDecision::new(
        "owner-launch-approval-1",
        connection.clone(),
        destination.clone(),
    )
    .unwrap()
}

fn admit(
    registry: &mut Registry,
    connection: &ConnectionId,
    target: &Destination,
    now: Instant,
) -> Registration {
    let grant = registry
        .grant_local(decision(connection, target), Duration::from_secs(60), now)
        .unwrap();
    registry
        .register_local(grant, connection, Duration::from_secs(10), now)
        .unwrap()
}

#[test]
fn owner_local_inbox_dispatch_is_exact_and_unattributed() {
    let now = Instant::now();
    let mut registry = registry();
    let connection = ConnectionId::new("owner-pipe-1").unwrap();
    let target = destination(NativeRoom::Mgmt);
    let registration = admit(&mut registry, &connection, &target, now);
    assert_eq!(registration.disposition, RegistrationDisposition::Created);
    let binding = registration.binding;
    assert_eq!(
        binding.integration_class,
        IntegrationClass::ClientInitiatedMcp
    );
    assert_eq!(
        binding.authority,
        AuthorityKind::OwnerLocalStdioUnattributed
    );
    assert_eq!(binding.capability, Capability::InboxRead);
    assert_eq!(binding.owner_decision_reference, "owner-launch-approval-1");
    let calls = Cell::new(0);
    let result = registry
        .with_read(
            binding.id,
            binding.generation,
            &connection,
            &target,
            now,
            |scope| {
                calls.set(calls.get() + 1);
                assert_eq!(scope.binding(), binding.id);
                assert_eq!(scope.generation(), binding.generation);
                assert_eq!(scope.destination(), &target);
                assert_eq!(
                    scope.authority(),
                    AuthorityKind::OwnerLocalStdioUnattributed
                );
                assert_eq!(scope.capability(), Capability::InboxRead);
                "bounded inbox result"
            },
        )
        .unwrap();
    assert_eq!(result, "bounded inbox result");
    assert_eq!(calls.get(), 1);
}

#[test]
fn only_four_exact_native_rooms_exist_and_endpoint_identity_is_not_normalized() {
    for room in [
        NativeRoom::Alpha,
        NativeRoom::Mgmt,
        NativeRoom::Eng,
        NativeRoom::Qa,
    ] {
        assert_eq!(NativeRoom::try_from(room.as_str()).unwrap(), room);
    }
    for invalid in [
        "mgmt",
        "#MGMT",
        "#grok",
        "*",
        "c5a97346-e424-44bf-90d2-9caaa7594c11",
    ] {
        assert_eq!(
            NativeRoom::try_from(invalid),
            Err(RegistryError::InvalidField("native room"))
        );
    }
    assert_ne!(
        destination(NativeRoom::Mgmt),
        Destination::new("http://localhost:44339", NativeRoom::Mgmt).unwrap()
    );
}

#[test]
fn duplicate_registration_preserves_identity_generation_and_original_deadline() {
    let now = Instant::now();
    let mut registry = registry();
    let connection = ConnectionId::new("pipe-1").unwrap();
    let target = destination(NativeRoom::Alpha);
    let first = admit(&mut registry, &connection, &target, now).binding;
    let duplicate = registry
        .register_local(
            first.grant,
            &connection,
            Duration::from_secs(50),
            now + Duration::from_secs(3),
        )
        .unwrap();
    assert_eq!(duplicate.disposition, RegistrationDisposition::Existing);
    assert_eq!(duplicate.binding, first);
    assert_eq!(
        duplicate.binding.lease_expires_at,
        now + Duration::from_secs(10)
    );
}

#[test]
fn another_grant_cannot_replace_an_existing_connection_binding() {
    let now = Instant::now();
    let mut registry = registry();
    let connection = ConnectionId::new("pipe-1").unwrap();
    let target = destination(NativeRoom::Alpha);
    let first = admit(&mut registry, &connection, &target, now).binding;
    let other = registry
        .grant_local(
            decision(&connection, &destination(NativeRoom::Mgmt)),
            Duration::from_secs(60),
            now,
        )
        .unwrap();
    assert_eq!(
        registry.register_local(other, &connection, Duration::from_secs(10), now),
        Err(RegistryError::BindingConflict)
    );
    assert_eq!(registry.inspect(first.id, now).unwrap(), first);
    registry
        .with_read(
            first.id,
            first.generation,
            &connection,
            &target,
            now,
            |_| (),
        )
        .unwrap();
}

#[test]
fn wrong_connection_destination_and_generation_never_run_the_reader() {
    let now = Instant::now();
    let mut registry = registry();
    let connection = ConnectionId::new("pipe-1").unwrap();
    let wrong = ConnectionId::new("pipe-2").unwrap();
    let target = destination(NativeRoom::Mgmt);
    let binding = admit(&mut registry, &connection, &target, now).binding;
    let calls = Cell::new(0);
    assert_eq!(
        registry.register_local(binding.grant, &wrong, Duration::from_secs(10), now),
        Err(RegistryError::ConnectionMismatch)
    );
    assert_eq!(
        registry.with_read(binding.id, binding.generation, &wrong, &target, now, |_| {
            calls.set(1)
        }),
        Err(RegistryError::ConnectionMismatch)
    );
    assert_eq!(
        registry.with_read(
            binding.id,
            binding.generation + 1,
            &connection,
            &target,
            now,
            |_| calls.set(1)
        ),
        Err(RegistryError::StaleGeneration)
    );
    for other in [
        destination(NativeRoom::Eng),
        Destination::new("http://127.0.0.1:44341", NativeRoom::Mgmt).unwrap(),
    ] {
        assert_eq!(
            registry.with_read(
                binding.id,
                binding.generation,
                &connection,
                &other,
                now,
                |_| calls.set(1)
            ),
            Err(RegistryError::DestinationMismatch)
        );
    }
    assert_eq!(calls.get(), 0);
}

#[test]
fn lease_expires_at_the_exact_deadline_and_cannot_be_renewed_afterward() {
    let now = Instant::now();
    let mut registry = registry();
    let connection = ConnectionId::new("pipe-1").unwrap();
    let target = destination(NativeRoom::Alpha);
    let binding = admit(&mut registry, &connection, &target, now).binding;
    let deadline = binding.lease_expires_at;
    registry
        .with_read(
            binding.id,
            binding.generation,
            &connection,
            &target,
            deadline - Duration::from_nanos(1),
            |_| (),
        )
        .unwrap();
    assert_eq!(
        registry.with_read(
            binding.id,
            binding.generation,
            &connection,
            &target,
            deadline,
            |_| panic!("expired lease ran read")
        ),
        Err(RegistryError::BindingUnavailable(BindingState::Expired))
    );
    assert_eq!(
        registry.renew_local(
            binding.id,
            binding.generation,
            &connection,
            Duration::from_secs(10),
            deadline
        ),
        Err(RegistryError::BindingUnavailable(BindingState::Expired))
    );
    assert_eq!(
        registry.inspect(binding.id, deadline).unwrap().state,
        BindingState::Expired
    );
    assert_eq!(
        registry.register_local(
            binding.grant,
            &connection,
            Duration::from_secs(10),
            deadline
        ),
        Err(RegistryError::BindingUnavailable(BindingState::Expired))
    );
}

#[test]
fn renewal_is_generation_checked_and_never_extends_the_owner_grant() {
    let now = Instant::now();
    let mut registry = registry();
    let connection = ConnectionId::new("pipe-1").unwrap();
    let target = destination(NativeRoom::Alpha);
    let grant = registry
        .grant_local(decision(&connection, &target), Duration::from_secs(12), now)
        .unwrap();
    let binding = registry
        .register_local(grant, &connection, Duration::from_secs(10), now)
        .unwrap()
        .binding;
    let renewed = registry
        .renew_local(
            binding.id,
            binding.generation,
            &connection,
            Duration::from_secs(60),
            now + Duration::from_secs(5),
        )
        .unwrap();
    assert_eq!(renewed.lease_expires_at, now + Duration::from_secs(12));
    assert_eq!(renewed.generation, binding.generation + 1);
    assert_eq!(
        registry.renew_local(
            binding.id,
            binding.generation,
            &connection,
            Duration::from_secs(10),
            now + Duration::from_secs(5)
        ),
        Err(RegistryError::StaleGeneration)
    );
    assert_eq!(
        registry.with_read(
            binding.id,
            binding.generation,
            &connection,
            &target,
            now + Duration::from_secs(5),
            |_| ()
        ),
        Err(RegistryError::StaleGeneration)
    );
    registry
        .with_read(
            binding.id,
            renewed.generation,
            &connection,
            &target,
            now + Duration::from_secs(11),
            |_| (),
        )
        .unwrap();
    assert_eq!(
        registry.with_read(
            binding.id,
            renewed.generation,
            &connection,
            &target,
            now + Duration::from_secs(12),
            |_| ()
        ),
        Err(RegistryError::GrantExpired)
    );
}

#[test]
fn revocation_rejects_stale_renewals_and_does_not_break_unrelated_binding() {
    let now = Instant::now();
    let mut registry = registry();
    let first_connection = ConnectionId::new("pipe-1").unwrap();
    let second_connection = ConnectionId::new("pipe-2").unwrap();
    let first_target = destination(NativeRoom::Mgmt);
    let second_target = destination(NativeRoom::Qa);
    let first = admit(&mut registry, &first_connection, &first_target, now).binding;
    let second = admit(&mut registry, &second_connection, &second_target, now).binding;
    registry.revoke(first.grant).unwrap();
    let revoked = registry.inspect(first.id, now).unwrap();
    assert_eq!(revoked.state, BindingState::Revoked);
    assert_eq!(
        registry.renew_local(
            first.id,
            first.generation,
            &first_connection,
            Duration::from_secs(10),
            now
        ),
        Err(RegistryError::StaleGeneration)
    );
    assert_eq!(
        registry.renew_local(
            first.id,
            revoked.generation,
            &first_connection,
            Duration::from_secs(10),
            now
        ),
        Err(RegistryError::GrantRevoked)
    );
    assert_eq!(
        registry.with_read(
            first.id,
            revoked.generation,
            &first_connection,
            &first_target,
            now,
            |_| ()
        ),
        Err(RegistryError::GrantRevoked)
    );
    registry
        .with_read(
            second.id,
            second.generation,
            &second_connection,
            &second_target,
            now,
            |_| (),
        )
        .unwrap();
}

#[test]
fn invalidation_and_disconnect_remove_admission_without_any_process_action() {
    let now = Instant::now();
    let mut registry = registry();
    let connection = ConnectionId::new("pipe-1").unwrap();
    let target = destination(NativeRoom::Mgmt);
    let binding = admit(&mut registry, &connection, &target, now).binding;
    registry
        .invalidate(
            binding.id,
            binding.generation,
            InvalidationReason::EndpointChanged,
        )
        .unwrap();
    let invalid = registry.inspect(binding.id, now).unwrap();
    assert_eq!(
        invalid.state,
        BindingState::Invalidated(InvalidationReason::EndpointChanged)
    );
    assert_eq!(
        registry.renew_local(
            binding.id,
            binding.generation,
            &connection,
            Duration::from_secs(10),
            now
        ),
        Err(RegistryError::StaleGeneration)
    );
    assert_eq!(
        registry.renew_local(
            binding.id,
            invalid.generation,
            &connection,
            Duration::from_secs(10),
            now
        ),
        Err(RegistryError::BindingUnavailable(invalid.state))
    );
    registry.disconnect(binding.id, invalid.generation).unwrap();
    let disconnected = registry.inspect(binding.id, now).unwrap();
    assert_eq!(disconnected.state, BindingState::Disconnected);
    assert_eq!(
        registry.with_read(
            binding.id,
            disconnected.generation,
            &connection,
            &target,
            now,
            |_| ()
        ),
        Err(RegistryError::BindingUnavailable(
            BindingState::Disconnected
        ))
    );
    assert_eq!(
        registry.register_local(binding.grant, &connection, Duration::from_secs(10), now),
        Err(RegistryError::BindingUnavailable(
            BindingState::Disconnected
        ))
    );
}

#[test]
fn registry_limits_include_retired_records_and_do_not_evict_working_bindings() {
    let now = Instant::now();
    let mut registry = Registry::new(Limits {
        max_grants: 2,
        max_bindings: 1,
        max_lease: Duration::from_secs(60),
    })
    .unwrap();
    let connection = ConnectionId::new("pipe-1").unwrap();
    let target = destination(NativeRoom::Alpha);
    let first = admit(&mut registry, &connection, &target, now).binding;
    let second_connection = ConnectionId::new("pipe-2").unwrap();
    let second = registry
        .grant_local(
            decision(&second_connection, &target),
            Duration::from_secs(60),
            now,
        )
        .unwrap();
    assert_eq!(
        registry.register_local(second, &second_connection, Duration::from_secs(10), now),
        Err(RegistryError::CapacityReached("binding"))
    );
    registry
        .with_read(
            first.id,
            first.generation,
            &connection,
            &target,
            now,
            |_| (),
        )
        .unwrap();
    registry.revoke(second).unwrap();
    assert_eq!(
        registry.grant_local(
            decision(&second_connection, &target),
            Duration::from_secs(10),
            now
        ),
        Err(RegistryError::CapacityReached("grant"))
    );
}

#[test]
fn invalid_input_duration_and_backwards_clock_are_rejected() {
    assert!(
        Registry::new(Limits {
            max_grants: 0,
            max_bindings: 1,
            max_lease: Duration::from_secs(1)
        })
        .is_err()
    );
    for invalid in ["", "client info", "pipe/one", "pipe\n", &"x".repeat(129)] {
        assert!(ConnectionId::new(invalid).is_err());
    }
    for invalid in ["", "http://localhost:1\n", "bad endpoint"] {
        assert!(Destination::new(invalid, NativeRoom::Alpha).is_err());
    }
    let connection = ConnectionId::new("pipe-1").unwrap();
    let target = destination(NativeRoom::Alpha);
    assert!(OwnerLocalDecision::new(" ", connection.clone(), target.clone()).is_err());
    assert!(OwnerLocalDecision::new("approval\n", connection.clone(), target.clone()).is_err());
    let mut registry = registry();
    let now = Instant::now();
    assert_eq!(
        registry.grant_local(decision(&connection, &target), Duration::ZERO, now),
        Err(RegistryError::InvalidDuration)
    );
    assert_eq!(
        registry.grant_local(decision(&connection, &target), Duration::from_secs(61), now),
        Err(RegistryError::InvalidDuration)
    );
    let binding = admit(&mut registry, &connection, &target, now).binding;
    registry
        .inspect(binding.id, now + Duration::from_secs(2))
        .unwrap();
    assert_eq!(
        registry.with_read(
            binding.id,
            binding.generation,
            &connection,
            &target,
            now,
            |_| ()
        ),
        Err(RegistryError::ClockRegression)
    );
}

#[test]
fn new_registry_does_not_restore_a_prior_binding_or_grant() {
    let now = Instant::now();
    let mut first = registry();
    let connection = ConnectionId::new("pipe-1").unwrap();
    let target = destination(NativeRoom::Alpha);
    let binding = admit(&mut first, &connection, &target, now).binding;
    let mut fresh = registry();
    assert_eq!(
        fresh.inspect(binding.id, now),
        Err(RegistryError::UnknownBinding)
    );
    assert_eq!(
        fresh.register_local(binding.grant, &connection, Duration::from_secs(10), now),
        Err(RegistryError::UnknownGrant)
    );
}

#[test]
fn repeated_revocation_is_idempotent_and_generation_exhaustion_cannot_preserve_authority() {
    let now = Instant::now();
    let mut registry = registry();
    let connection = ConnectionId::new("pipe-1").unwrap();
    let target = destination(NativeRoom::Alpha);
    let binding = admit(&mut registry, &connection, &target, now).binding;
    registry.bindings.get_mut(&binding.id).unwrap().generation = u64::MAX;
    registry.revoke(binding.grant).unwrap();
    let first = registry.inspect(binding.id, now).unwrap();
    registry.revoke(binding.grant).unwrap();
    assert_eq!(registry.inspect(binding.id, now).unwrap(), first);
    assert_eq!(
        registry.with_read(binding.id, u64::MAX, &connection, &target, now, |_| ()),
        Err(RegistryError::GrantRevoked)
    );
    let second_connection = ConnectionId::new("pipe-2").unwrap();
    let second = admit(&mut registry, &second_connection, &target, now).binding;
    registry.bindings.get_mut(&second.id).unwrap().generation = u64::MAX;
    registry.disconnect(second.id, u64::MAX).unwrap();
    assert_eq!(
        registry.with_read(
            second.id,
            u64::MAX,
            &second_connection,
            &target,
            now,
            |_| ()
        ),
        Err(RegistryError::BindingUnavailable(
            BindingState::Disconnected
        ))
    );
}

#[test]
fn atomic_admission_failure_does_not_poison_single_slot_and_repeat_never_extends_lease() {
    let now = Instant::now();
    let mut registry = Registry::new(Limits {
        max_grants: 1,
        max_bindings: 1,
        max_lease: Duration::from_secs(60),
    })
    .unwrap();
    let connection = ConnectionId::new("pipe-1").unwrap();
    let wrong = ConnectionId::new("wrong-pipe").unwrap();
    let target = destination(NativeRoom::Mgmt);
    let owner = decision(&connection, &target);
    assert_eq!(
        registry.admit_local(owner.clone(), &wrong, Duration::from_secs(10), now),
        Err(RegistryError::ConnectionMismatch)
    );
    let first = registry
        .admit_local(owner.clone(), &connection, Duration::from_secs(10), now)
        .unwrap();
    assert_eq!(first.disposition, RegistrationDisposition::Created);
    let duplicate = registry
        .admit_local(
            owner,
            &connection,
            Duration::from_secs(60),
            now + Duration::from_secs(2),
        )
        .unwrap();
    assert_eq!(duplicate.disposition, RegistrationDisposition::Existing);
    assert_eq!(duplicate.binding, first.binding);
    assert_eq!(
        duplicate.binding.lease_expires_at,
        now + Duration::from_secs(10)
    );
}

#[test]
fn atomic_conflicting_decision_and_destination_consume_no_grant_slot() {
    let now = Instant::now();
    let mut registry = Registry::new(Limits {
        max_grants: 2,
        max_bindings: 2,
        max_lease: Duration::from_secs(60),
    })
    .unwrap();
    let connection = ConnectionId::new("pipe-1").unwrap();
    let target = destination(NativeRoom::Mgmt);
    let first = registry
        .admit_local(
            decision(&connection, &target),
            &connection,
            Duration::from_secs(10),
            now,
        )
        .unwrap()
        .binding;
    for conflict in [
        OwnerLocalDecision::new(
            "different-owner-decision",
            connection.clone(),
            target.clone(),
        )
        .unwrap(),
        decision(&connection, &destination(NativeRoom::Eng)),
    ] {
        assert_eq!(
            registry.admit_local(conflict, &connection, Duration::from_secs(10), now),
            Err(RegistryError::BindingConflict)
        );
    }
    let other = ConnectionId::new("pipe-2").unwrap();
    registry
        .grant_local(decision(&other, &target), Duration::from_secs(10), now)
        .expect("conflicts must leave second grant slot available");
    registry
        .with_read(
            first.id,
            first.generation,
            &connection,
            &target,
            now,
            |_| (),
        )
        .unwrap();
}

#[test]
fn atomic_binding_capacity_failure_consumes_no_grant_or_identifier() {
    let now = Instant::now();
    let mut registry = Registry::new(Limits {
        max_grants: 2,
        max_bindings: 1,
        max_lease: Duration::from_secs(60),
    })
    .unwrap();
    let first = ConnectionId::new("pipe-1").unwrap();
    let second = ConnectionId::new("pipe-2").unwrap();
    let target = destination(NativeRoom::Mgmt);
    registry
        .admit_local(
            decision(&first, &target),
            &first,
            Duration::from_secs(10),
            now,
        )
        .unwrap();
    for _ in 0..2 {
        assert_eq!(
            registry.admit_local(
                decision(&second, &target),
                &second,
                Duration::from_secs(10),
                now
            ),
            Err(RegistryError::CapacityReached("binding"))
        );
    }
    registry
        .grant_local(decision(&second, &target), Duration::from_secs(10), now)
        .expect("failed binding admission must not allocate a grant");
}

fn http_decision(connection: &ConnectionId, destination: &Destination) -> OwnerLocalDecision {
    OwnerLocalDecision::new_http_capability(
        "owner-http-enrollment-1",
        connection.clone(),
        destination.clone(),
    )
    .unwrap()
}

#[test]
fn http_owner_grant_projects_its_canonical_authority_to_view_and_read_scope() {
    let now = Instant::now();
    let mut registry = registry();
    let connection = ConnectionId::new("owner-http-1").unwrap();
    let target = destination(NativeRoom::Mgmt);
    let grant = registry
        .grant_local(
            http_decision(&connection, &target),
            Duration::from_secs(30),
            now,
        )
        .unwrap();
    let binding = registry
        .register_local(grant, &connection, Duration::from_secs(10), now)
        .unwrap()
        .binding;
    assert_eq!(
        binding.authority,
        AuthorityKind::OwnerLocalHttpCapabilityUnattributed
    );
    assert_eq!(
        binding.integration_class,
        IntegrationClass::ClientInitiatedMcp
    );
    assert_eq!(binding.capability, Capability::InboxRead);
    assert_eq!(binding.owner_decision_reference, "owner-http-enrollment-1");
    assert_eq!(binding.lease_expires_at, now + Duration::from_secs(10));
    assert_eq!(binding.grant_expires_at, now + Duration::from_secs(30));
    let observed = registry
        .with_read(
            binding.id,
            binding.generation,
            &connection,
            &target,
            now,
            |scope| {
                assert_eq!(scope.destination(), &target);
                assert_eq!(scope.capability(), Capability::InboxRead);
                scope.authority()
            },
        )
        .unwrap();
    assert_eq!(
        observed,
        AuthorityKind::OwnerLocalHttpCapabilityUnattributed
    );
    assert_eq!(registry.inspect(binding.id, now).unwrap(), binding);
}

#[test]
fn repeating_http_admission_at_capacity_keeps_original_grant_and_lease() {
    let now = Instant::now();
    let mut registry = Registry::new(Limits {
        max_grants: 1,
        max_bindings: 1,
        max_lease: Duration::from_secs(60),
    })
    .unwrap();
    let connection = ConnectionId::new("owner-http-1").unwrap();
    let target = destination(NativeRoom::Mgmt);
    let owner = http_decision(&connection, &target);
    let first = registry
        .admit_local(owner.clone(), &connection, Duration::from_secs(10), now)
        .unwrap();
    let duplicate = registry
        .admit_local(
            owner.clone(),
            &connection,
            Duration::from_secs(60),
            now + Duration::from_secs(2),
        )
        .unwrap();
    assert_eq!(first.disposition, RegistrationDisposition::Created);
    assert_eq!(duplicate.disposition, RegistrationDisposition::Existing);
    assert_eq!(duplicate.binding, first.binding);
    assert_eq!(
        duplicate.binding.lease_expires_at,
        now + Duration::from_secs(10)
    );
    assert_eq!(
        duplicate.binding.grant_expires_at,
        now + Duration::from_secs(10)
    );
    assert_eq!(
        registry.admit_local(
            owner,
            &connection,
            Duration::from_secs(60),
            now + Duration::from_secs(10),
        ),
        Err(RegistryError::GrantExpired)
    );
    assert_eq!(registry.grants.len(), 1);
    assert_eq!(registry.bindings.len(), 1);
}

#[test]
fn authority_cannot_switch_on_the_same_connection_or_consume_capacity_on_conflict() {
    let now = Instant::now();
    for http_first in [false, true] {
        let mut registry = Registry::new(Limits {
            max_grants: 2,
            max_bindings: 2,
            max_lease: Duration::from_secs(60),
        })
        .unwrap();
        let connection = ConnectionId::new("same-owner-connection").unwrap();
        let target = destination(NativeRoom::Mgmt);
        // Identical reference, connection and destination isolate authority as
        // the sole conflict. Neither constructor accepts a secret or a token.
        let stdio =
            OwnerLocalDecision::new("same-owner-reference", connection.clone(), target.clone())
                .unwrap();
        let http = OwnerLocalDecision::new_http_capability(
            "same-owner-reference",
            connection.clone(),
            target.clone(),
        )
        .unwrap();
        assert_ne!(stdio, http);
        let (first, conflict) = if http_first {
            (http, stdio)
        } else {
            (stdio, http)
        };
        let original = registry
            .admit_local(first, &connection, Duration::from_secs(10), now)
            .unwrap()
            .binding;
        let next_id = registry.next_id;
        for _ in 0..2 {
            assert_eq!(
                registry.admit_local(conflict.clone(), &connection, Duration::from_secs(20), now),
                Err(RegistryError::BindingConflict)
            );
        }
        assert_eq!(registry.next_id, next_id);
        assert_eq!(registry.grants.len(), 1);
        assert_eq!(registry.bindings.len(), 1);
        assert_eq!(registry.inspect(original.id, now).unwrap(), original);
        let other = ConnectionId::new("unrelated-owner-connection").unwrap();
        let other_binding = registry
            .admit_local(
                decision(&other, &target),
                &other,
                Duration::from_secs(10),
                now,
            )
            .expect("conflicting authority must leave the other slot usable")
            .binding;
        assert_eq!(other_binding.grant, GrantId(next_id));
        assert_eq!(other_binding.id, BindingId(next_id + 1));
    }
}

#[test]
fn http_constructor_reuses_bounded_owner_reference_validation() {
    let connection = ConnectionId::new("owner-http-1").unwrap();
    let target = destination(NativeRoom::Mgmt);
    for reference in ["", " ", "owner\nreference", &"x".repeat(257)] {
        assert_eq!(
            OwnerLocalDecision::new_http_capability(reference, connection.clone(), target.clone()),
            Err(RegistryError::InvalidField("owner decision reference"))
        );
    }
}
