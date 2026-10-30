use super::*;
use chinwag_connector_registry::{BindingState, Destination, Limits, NativeRoom};
use std::cell::Cell;

fn registry() -> Registry {
    Registry::new(Limits {
        max_grants: 8,
        max_bindings: 8,
        max_lease: Duration::from_secs(60),
    })
    .unwrap()
}

fn target(room: NativeRoom) -> Destination {
    Destination::new("http://127.0.0.1:44339", room).unwrap()
}

fn admit(host: &mut ConnectorHost, connection: &str, now: Instant) -> BindingView {
    let connection = ConnectionId::new(connection).unwrap();
    let decision = OwnerLocalDecision::new(
        "explicit-owner-launch",
        connection.clone(),
        target(NativeRoom::Mgmt),
    )
    .unwrap();
    host.admit_local_inbox(decision, &connection, Duration::from_secs(10), now)
        .unwrap()
}

fn enabled_host(now: Instant) -> (ConnectorHost, BindingView) {
    let mut host = ConnectorHost::new(registry());
    host.set_enabled(BuiltinConnector::NativeInbox, true)
        .unwrap();
    host.set_enabled(BuiltinConnector::NativeClients, true)
        .unwrap();
    let binding = admit(&mut host, "pipe-1", now);
    (host, binding)
}

fn invocation(host: &ConnectorHost, plugin: BuiltinConnector, now: Instant) -> Invocation {
    host.begin(plugin, now + Duration::from_secs(30), now)
        .unwrap()
}

#[test]
fn descriptors_are_versioned_builtin_support_not_external_loader_or_grants() {
    let clients = BuiltinConnector::NativeClients.descriptor();
    let inbox = BuiltinConnector::NativeInbox.descriptor();
    for descriptor in [clients, inbox] {
        assert_eq!(descriptor.schema, "chinwag-builtin-connector/v1");
        assert_eq!(descriptor.host_api_version, 1);
        assert_eq!(descriptor.version, "0.1.0");
        assert_eq!(descriptor.execution, ExecutionKind::BuiltinTrusted);
    }
    assert_ne!(clients.plugin_id, inbox.plugin_id);
    assert_eq!(
        clients.capabilities,
        &[
            Capability::RunningMetadataRead,
            Capability::InstalledMetadataRead
        ]
    );
    assert_eq!(inbox.capabilities, &[Capability::NativeInboxRead]);
    let now = Instant::now();
    let mut host = ConnectorHost::new(registry());
    assert!(!host.inspect(BuiltinConnector::NativeInbox).enabled);
    let connection = ConnectionId::new("pipe").unwrap();
    let decision =
        OwnerLocalDecision::new("owner", connection.clone(), target(NativeRoom::Mgmt)).unwrap();
    assert_eq!(
        host.admit_local_inbox(decision, &connection, Duration::from_secs(1), now),
        Err(ConnectorError::Disabled)
    );
}

#[test]
fn clients_collect_once_and_preserve_typed_service_errors() {
    let now = Instant::now();
    let (mut host, _) = enabled_host(now);
    let invocation = invocation(&host, BuiltinConnector::NativeClients, now);
    let calls = Cell::new(0);
    let result = host.clients(
        &invocation,
        || now,
        || {
            calls.set(calls.get() + 1);
            Err::<usize, _>("metadata unavailable")
        },
    );
    assert_eq!(result, Ok(Err("metadata unavailable")));
    assert_eq!(calls.get(), 1);
    assert_eq!(invocation.connector(), BuiltinConnector::NativeClients);
    assert_eq!(
        invocation.generation(),
        host.inspect(BuiltinConnector::NativeClients).generation
    );
    assert_eq!(invocation.deadline(), now + Duration::from_secs(30));
}

#[test]
fn disabled_and_stale_invocations_never_collect() {
    let now = Instant::now();
    let (mut host, _) = enabled_host(now);
    let old = invocation(&host, BuiltinConnector::NativeClients, now);
    host.set_enabled(BuiltinConnector::NativeClients, false)
        .unwrap();
    assert!(matches!(
        host.begin(
            BuiltinConnector::NativeClients,
            now + Duration::from_secs(1),
            now
        ),
        Err(ConnectorError::Disabled)
    ));
    assert_eq!(
        host.clients(&old, || now, || panic!("disabled plugin collected")),
        Err(ConnectorError::Disabled)
    );
    host.set_enabled(BuiltinConnector::NativeClients, true)
        .unwrap();
    assert_eq!(
        host.clients(&old, || now, || panic!("stale activation collected")),
        Err(ConnectorError::StaleInvocation)
    );
    let current = invocation(&host, BuiltinConnector::NativeClients, now);
    assert_eq!(host.clients(&current, || now, || 7), Ok(7));
}

#[test]
fn undeclared_cross_component_calls_never_invoke_services() {
    let now = Instant::now();
    let (mut host, binding) = enabled_host(now);
    let clients = invocation(&host, BuiltinConnector::NativeClients, now);
    let inbox = invocation(&host, BuiltinConnector::NativeInbox, now);
    assert_eq!(
        host.inbox(
            &clients,
            &binding,
            || now,
            |_| panic!("metadata plugin read inbox")
        ),
        Err(ConnectorError::UndeclaredCapability)
    );
    assert_eq!(
        host.clients(&inbox, || now, || panic!("inbox plugin scanned clients")),
        Err(ConnectorError::UndeclaredCapability)
    );
}

#[test]
fn expiry_prevents_dispatch_and_discards_late_metadata_result() {
    let now = Instant::now();
    let (mut host, _) = enabled_host(now);
    assert!(matches!(
        host.begin(BuiltinConnector::NativeClients, now, now),
        Err(ConnectorError::DeadlineExpired)
    ));
    let deadline = now + Duration::from_secs(1);
    let invocation = host
        .begin(BuiltinConnector::NativeClients, deadline, now)
        .unwrap();
    assert_eq!(
        host.clients(
            &invocation,
            || deadline,
            || panic!("expired dispatch collected")
        ),
        Err(ConnectorError::DeadlineExpired)
    );
    let time = Cell::new(now);
    let calls = Cell::new(0);
    assert_eq!(
        host.clients(
            &invocation,
            || time.get(),
            || {
                calls.set(1);
                time.set(deadline);
                42
            }
        ),
        Err(ConnectorError::DeadlineExpired)
    );
    assert_eq!(calls.get(), 1);
}

#[test]
fn enabled_descriptor_cannot_adopt_foreign_registry_binding_even_with_forged_view_grant() {
    let now = Instant::now();
    let mut registry = registry();
    let foreign_connection = ConnectionId::new("foreign-pipe").unwrap();
    let grant = registry
        .grant_local(
            OwnerLocalDecision::new(
                "foreign-owner",
                foreign_connection.clone(),
                target(NativeRoom::Qa),
            )
            .unwrap(),
            Duration::from_secs(60),
            now,
        )
        .unwrap();
    let mut foreign = registry
        .register_local(grant, &foreign_connection, Duration::from_secs(60), now)
        .unwrap()
        .binding;
    let mut host = ConnectorHost::new(registry);
    host.set_enabled(BuiltinConnector::NativeInbox, true)
        .unwrap();
    let invocation = invocation(&host, BuiltinConnector::NativeInbox, now);
    assert_eq!(
        host.inbox(
            &invocation,
            &foreign,
            || now,
            |_| panic!("foreign binding read")
        ),
        Err(ConnectorError::ForeignBinding)
    );
    let owned = admit(&mut host, "owned-pipe", now);
    foreign.grant = owned.grant;
    assert_eq!(
        host.inbox(
            &invocation,
            &foreign,
            || now,
            |_| panic!("forged view adopted foreign binding")
        ),
        Err(ConnectorError::ForeignBinding)
    );
    assert_eq!(
        host.disconnect_binding(foreign.id, foreign.generation),
        Err(ConnectorError::ForeignBinding)
    );
    assert_eq!(
        host.inbox(
            &invocation,
            &owned,
            || now,
            |scope| scope.destination().room()
        ),
        Ok(NativeRoom::Mgmt)
    );
}

#[test]
fn foreign_destination_connection_and_stale_binding_generation_are_rejected() {
    let now = Instant::now();
    let (mut host, binding) = enabled_host(now);
    let invocation = invocation(&host, BuiltinConnector::NativeInbox, now);
    let mut wrong = binding.clone();
    wrong.destination = target(NativeRoom::Eng);
    assert_eq!(
        host.inbox(&invocation, &wrong, || now, |_| ()),
        Err(ConnectorError::Admission(
            RegistryError::DestinationMismatch
        ))
    );
    wrong = binding.clone();
    wrong.connection = ConnectionId::new("other").unwrap();
    assert_eq!(
        host.inbox(&invocation, &wrong, || now, |_| ()),
        Err(ConnectorError::Admission(RegistryError::ConnectionMismatch))
    );
    wrong = binding.clone();
    wrong.generation += 1;
    assert_eq!(
        host.inbox(&invocation, &wrong, || now, |_| ()),
        Err(ConnectorError::Admission(RegistryError::StaleGeneration))
    );
}

#[test]
fn disable_revokes_only_inbox_and_reenable_does_not_restore_old_grants() {
    let now = Instant::now();
    let (mut host, binding) = enabled_host(now);
    let clients = invocation(&host, BuiltinConnector::NativeClients, now);
    let old_inbox = invocation(&host, BuiltinConnector::NativeInbox, now);
    host.set_enabled(BuiltinConnector::NativeInbox, false)
        .unwrap();
    assert_eq!(
        host.clients(&clients, || now, || "same metadata component"),
        Ok("same metadata component")
    );
    assert_eq!(
        host.inspect_binding(binding.id, now).unwrap().state,
        BindingState::Revoked
    );
    assert_eq!(
        host.inbox(&old_inbox, &binding, || now, |_| ()),
        Err(ConnectorError::Disabled)
    );
    host.set_enabled(BuiltinConnector::NativeInbox, true)
        .unwrap();
    assert_eq!(
        host.inbox(&old_inbox, &binding, || now, |_| ()),
        Err(ConnectorError::StaleInvocation)
    );
    let current = invocation(&host, BuiltinConnector::NativeInbox, now);
    let revoked = host.inspect_binding(binding.id, now).unwrap();
    assert_eq!(
        host.inbox(&current, &revoked, || now, |_| ()),
        Err(ConnectorError::Admission(RegistryError::GrantRevoked))
    );
    let fresh = admit(&mut host, "fresh-pipe", now);
    assert_eq!(
        host.inbox(&current, &fresh, || now, |_| "fresh owner grant"),
        Ok("fresh owner grant")
    );
}

#[test]
fn inbox_deadline_and_owner_lease_are_checked_after_original_callback() {
    let now = Instant::now();
    let (mut host, binding) = enabled_host(now);
    let deadline = now + Duration::from_secs(1);
    let short_invocation = host
        .begin(BuiltinConnector::NativeInbox, deadline, now)
        .unwrap();
    let time = Cell::new(now);
    let calls = Cell::new(0);
    assert_eq!(
        host.inbox(
            &short_invocation,
            &binding,
            || time.get(),
            |_| {
                calls.set(1);
                time.set(deadline);
                7
            }
        ),
        Err(ConnectorError::DeadlineExpired)
    );
    assert_eq!(calls.get(), 1);
    let invocation = invocation(&host, BuiltinConnector::NativeInbox, now);
    time.set(now);
    assert_eq!(
        host.inbox(
            &invocation,
            &binding,
            || time.get(),
            |_| {
                time.set(binding.lease_expires_at);
                7
            }
        ),
        Err(ConnectorError::Admission(RegistryError::GrantExpired))
    );
}

#[test]
fn disconnect_only_removes_admission_and_generation_exhaustion_fails_closed() {
    let now = Instant::now();
    let (mut host, binding) = enabled_host(now);
    host.disconnect_binding(binding.id, binding.generation)
        .unwrap();
    let disconnected = host.inspect_binding(binding.id, now).unwrap();
    assert_eq!(disconnected.state, BindingState::Disconnected);
    let invocation = invocation(&host, BuiltinConnector::NativeInbox, now);
    assert_eq!(
        host.inbox(&invocation, &disconnected, || now, |_| ()),
        Err(ConnectorError::Admission(
            RegistryError::BindingUnavailable(BindingState::Disconnected)
        ))
    );
    host.activations[BuiltinConnector::NativeClients.index()].generation = u64::MAX;
    assert_eq!(
        host.set_enabled(BuiltinConnector::NativeClients, false),
        Err(ConnectorError::GenerationExhausted)
    );
    assert!(!host.inspect(BuiltinConnector::NativeClients).enabled);
    assert_eq!(
        host.set_enabled(BuiltinConnector::NativeClients, true),
        Err(ConnectorError::GenerationExhausted)
    );
    assert!(!host.inspect(BuiltinConnector::NativeClients).enabled);
}

#[test]
fn host_admission_is_atomic_and_repeating_the_owner_decision_returns_existing_scope() {
    let now = Instant::now();
    let registry = Registry::new(Limits {
        max_grants: 1,
        max_bindings: 1,
        max_lease: Duration::from_secs(60),
    })
    .unwrap();
    let mut host = ConnectorHost::new(registry);
    host.set_enabled(BuiltinConnector::NativeInbox, true)
        .unwrap();
    let connection = ConnectionId::new("pipe").unwrap();
    let decision =
        OwnerLocalDecision::new("owner", connection.clone(), target(NativeRoom::Mgmt)).unwrap();
    assert_eq!(
        host.admit_local_inbox(
            decision.clone(),
            &ConnectionId::new("wrong").unwrap(),
            Duration::from_secs(10),
            now
        ),
        Err(ConnectorError::Admission(RegistryError::ConnectionMismatch))
    );
    let first = host
        .admit_local_inbox(decision.clone(), &connection, Duration::from_secs(10), now)
        .unwrap();
    let duplicate = host
        .admit_local_inbox(
            decision,
            &connection,
            Duration::from_secs(60),
            now + Duration::from_secs(1),
        )
        .unwrap();
    assert_eq!(duplicate, first);
    assert_eq!(host.inbox_grants.len(), 1);
    assert_eq!(host.inbox_bindings.len(), 1);
}
