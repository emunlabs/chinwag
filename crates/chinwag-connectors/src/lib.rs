//! Built-in connector components and their host-owned capability boundary.
//!
//! These are trusted linked Rust components, not dynamically loaded or isolated
//! external plugins. Descriptors advertise implementation support, never grants.
//! The host owns the sole supplied admission registry. Services remain callbacks
//! under host control; no component can supply arbitrary filesystem/network RPC.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use chinwag_connector_registry::{
    BindingId, BindingView, ConnectionId, GrantId, OwnerLocalDecision, ReadScope, Registry,
    RegistryError,
};

pub type Result<T> = std::result::Result<T, ConnectorError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltinConnector {
    NativeClients,
    NativeInbox,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    RunningMetadataRead,
    InstalledMetadataRead,
    NativeInboxRead,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RunningMetadataRead => "running_metadata_read",
            Self::InstalledMetadataRead => "installed_metadata_read",
            Self::NativeInboxRead => "native_inbox_read",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionKind {
    BuiltinTrusted,
}

impl ExecutionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BuiltinTrusted => "builtin_trusted",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct BuiltinDescriptor {
    pub schema: &'static str,
    pub plugin_id: &'static str,
    pub display_name: &'static str,
    pub version: &'static str,
    pub host_api_version: u16,
    pub execution: ExecutionKind,
    pub capabilities: &'static [Capability],
}

const NATIVE_CLIENTS: BuiltinDescriptor = BuiltinDescriptor {
    schema: "chinwag-builtin-connector/v1",
    plugin_id: "com.emunlabs.connector.native-clients",
    display_name: "Native client metadata",
    version: "0.1.0",
    host_api_version: 1,
    execution: ExecutionKind::BuiltinTrusted,
    capabilities: &[
        Capability::RunningMetadataRead,
        Capability::InstalledMetadataRead,
    ],
};

const NATIVE_INBOX: BuiltinDescriptor = BuiltinDescriptor {
    schema: "chinwag-builtin-connector/v1",
    plugin_id: "com.emunlabs.connector.native-inbox",
    display_name: "Native coordination inbox",
    version: "0.1.0",
    host_api_version: 1,
    execution: ExecutionKind::BuiltinTrusted,
    capabilities: &[Capability::NativeInboxRead],
};

impl BuiltinConnector {
    pub fn descriptor(self) -> &'static BuiltinDescriptor {
        match self {
            Self::NativeClients => &NATIVE_CLIENTS,
            Self::NativeInbox => &NATIVE_INBOX,
        }
    }

    fn index(self) -> usize {
        match self {
            Self::NativeClients => 0,
            Self::NativeInbox => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectorError {
    #[error("built-in connector is disabled")]
    Disabled,
    #[error("connector invocation belongs to an older activation generation")]
    StaleInvocation,
    #[error("connector does not declare the requested capability")]
    UndeclaredCapability,
    #[error("connector invocation deadline expired")]
    DeadlineExpired,
    #[error("connector activation generations exhausted; connector is disabled")]
    GenerationExhausted,
    #[error("inbox binding was not admitted by this connector host")]
    ForeignBinding,
    #[error(transparent)]
    Admission(#[from] RegistryError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectorView {
    pub connector: BuiltinConnector,
    pub enabled: bool,
    pub generation: u64,
}

/// Host-created invocation context, not a serialized client authority claim.
#[derive(Debug, Clone, Copy)]
pub struct Invocation {
    connector: BuiltinConnector,
    generation: u64,
    deadline: Instant,
}

impl Invocation {
    pub fn connector(&self) -> BuiltinConnector {
        self.connector
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
}

#[derive(Clone, Copy)]
struct Activation {
    enabled: bool,
    generation: u64,
}

/// One host, one existing registry. The grant set stores ownership references,
/// not another instance/binding map. Each component begins disabled.
pub struct ConnectorHost {
    registry: Registry,
    activations: [Activation; 2],
    inbox_grants: BTreeSet<GrantId>,
    inbox_bindings: BTreeSet<BindingId>,
}

impl ConnectorHost {
    pub fn new(registry: Registry) -> Self {
        Self {
            registry,
            activations: [Activation {
                enabled: false,
                generation: 0,
            }; 2],
            inbox_grants: BTreeSet::new(),
            inbox_bindings: BTreeSet::new(),
        }
    }

    pub fn inspect(&self, connector: BuiltinConnector) -> ConnectorView {
        let activation = self.activations[connector.index()];
        ConnectorView {
            connector,
            enabled: activation.enabled,
            generation: activation.generation,
        }
    }

    pub fn set_enabled(
        &mut self,
        connector: BuiltinConnector,
        enabled: bool,
    ) -> Result<ConnectorView> {
        let activation = &mut self.activations[connector.index()];
        if activation.enabled == enabled {
            return Ok(self.inspect(connector));
        }
        let generation = activation.generation.checked_add(1);
        activation.enabled = enabled && generation.is_some();
        if let Some(generation) = generation {
            activation.generation = generation;
        }
        if !activation.enabled && connector == BuiltinConnector::NativeInbox {
            for &grant in &self.inbox_grants {
                self.registry.revoke(grant)?;
            }
        }
        if generation.is_none() {
            return Err(ConnectorError::GenerationExhausted);
        }
        Ok(self.inspect(connector))
    }

    pub fn begin(
        &self,
        connector: BuiltinConnector,
        deadline: Instant,
        now: Instant,
    ) -> Result<Invocation> {
        let activation = self.activations[connector.index()];
        if !activation.enabled {
            return Err(ConnectorError::Disabled);
        }
        if now >= deadline {
            return Err(ConnectorError::DeadlineExpired);
        }
        Ok(Invocation {
            connector,
            generation: activation.generation,
            deadline,
        })
    }

    /// Explicit host metadata scope only: no client admission is created.
    /// The service is collected exactly once, with pre/post invocation checks.
    pub fn clients<T>(
        &mut self,
        invocation: &Invocation,
        mut clock: impl FnMut() -> Instant,
        collect: impl FnOnce() -> T,
    ) -> Result<T> {
        let started = clock();
        self.check(invocation, Capability::RunningMetadataRead, started)?;
        self.check(invocation, Capability::InstalledMetadataRead, started)?;
        let result = collect();
        let finished = clock();
        self.check(invocation, Capability::RunningMetadataRead, finished)?;
        self.check(invocation, Capability::InstalledMetadataRead, finished)?;
        Ok(result)
    }

    /// Only the trusted owner-local stdio or scoped HTTP enrollment boundary
    /// calls this method. The decision retains its transport authority; enabling
    /// the descriptor alone cannot manufacture the decision or grant. Raw HTTP
    /// credentials and client-supplied identity/session fields stay outside it.
    pub fn admit_local_inbox(
        &mut self,
        decision: OwnerLocalDecision,
        connection: &ConnectionId,
        lease: Duration,
        now: Instant,
    ) -> Result<BindingView> {
        if !self.activations[BuiltinConnector::NativeInbox.index()].enabled {
            return Err(ConnectorError::Disabled);
        }
        let binding = self
            .registry
            .admit_local(decision, connection, lease, now)?
            .binding;
        self.inbox_grants.insert(binding.grant);
        self.inbox_bindings.insert(binding.id);
        Ok(binding)
    }

    /// Performs one bounded synchronous read with the current owner grant.
    /// The callback can return its own Result; callers flatten it explicitly.
    pub fn inbox<T>(
        &mut self,
        invocation: &Invocation,
        binding: &BindingView,
        mut clock: impl FnMut() -> Instant,
        read: impl FnOnce(&ReadScope<'_>) -> T,
    ) -> Result<T> {
        let now = clock();
        self.check(invocation, Capability::NativeInboxRead, now)?;
        if !self.inbox_grants.contains(&binding.grant) || !self.inbox_bindings.contains(&binding.id)
        {
            return Err(ConnectorError::ForeignBinding);
        }
        let result = self.registry.with_read(
            binding.id,
            binding.generation,
            &binding.connection,
            &binding.destination,
            now,
            read,
        )?;
        let finished = clock();
        self.check(invocation, Capability::NativeInboxRead, finished)?;
        self.registry.with_read(
            binding.id,
            binding.generation,
            &binding.connection,
            &binding.destination,
            finished,
            |_| (),
        )?;
        Ok(result)
    }

    pub fn revoke(&mut self, grant: GrantId) -> Result<()> {
        if !self.inbox_grants.contains(&grant) {
            return Err(ConnectorError::ForeignBinding);
        }
        Ok(self.registry.revoke(grant)?)
    }

    pub fn inspect_binding(&mut self, binding: BindingId, now: Instant) -> Result<BindingView> {
        if !self.inbox_bindings.contains(&binding) {
            return Err(ConnectorError::ForeignBinding);
        }
        let view = self.registry.inspect(binding, now)?;
        if !self.inbox_grants.contains(&view.grant) {
            return Err(ConnectorError::ForeignBinding);
        }
        Ok(view)
    }

    pub fn disconnect_binding(&mut self, binding: BindingId, generation: u64) -> Result<()> {
        // No external process/application lifecycle call is part of this host.
        if !self.inbox_bindings.contains(&binding) {
            return Err(ConnectorError::ForeignBinding);
        }
        Ok(self.registry.disconnect(binding, generation)?)
    }

    fn check(&self, invocation: &Invocation, capability: Capability, now: Instant) -> Result<()> {
        if !invocation
            .connector
            .descriptor()
            .capabilities
            .contains(&capability)
        {
            return Err(ConnectorError::UndeclaredCapability);
        }
        let activation = self.activations[invocation.connector.index()];
        if !activation.enabled {
            return Err(ConnectorError::Disabled);
        }
        if activation.generation != invocation.generation {
            return Err(ConnectorError::StaleInvocation);
        }
        if now >= invocation.deadline {
            return Err(ConnectorError::DeadlineExpired);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
