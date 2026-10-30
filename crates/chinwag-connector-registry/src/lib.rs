//! In-process admission for one explicitly granted owner-local stdio inbox.
//!
//! The caller is the trusted launch boundary. MCP clientInfo, process names and
//! HTTP headers cannot create grants here. Local stdio authority identifies no
//! named application, human account or native conversation. This registry starts
//! empty and neither persists nor restores trust. It performs no external I/O.
#![deny(unsafe_code)]

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

pub type Result<T> = std::result::Result<T, RegistryError>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    #[error("invalid {0}")]
    InvalidField(&'static str),
    #[error("registry limits must be nonzero")]
    InvalidLimits,
    #[error("lease duration is zero or exceeds the configured maximum")]
    InvalidDuration,
    #[error("lease deadline cannot be represented")]
    TimeOverflow,
    #[error("registry clock moved backwards")]
    ClockRegression,
    #[error("registry {0} capacity reached")]
    CapacityReached(&'static str),
    #[error("registry identifiers exhausted")]
    IdentifierExhausted,
    #[error("unknown owner grant")]
    UnknownGrant,
    #[error("unknown connector binding")]
    UnknownBinding,
    #[error("owner grant has been revoked")]
    GrantRevoked,
    #[error("owner grant has expired")]
    GrantExpired,
    #[error("connection does not match the owner-local grant")]
    ConnectionMismatch,
    #[error("destination is outside the exact granted inbox")]
    DestinationMismatch,
    #[error("connection already has another binding or grant")]
    BindingConflict,
    #[error("binding generation changed; discard the stale completion")]
    StaleGeneration,
    #[error("binding is unavailable: {0:?}")]
    BindingUnavailable(BindingState),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConnectionId(String);

impl ConnectionId {
    /// Created by the trusted pipe owner, never from MCP clientInfo.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(RegistryError::InvalidField("connection identifier"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NativeRoom {
    Alpha,
    Mgmt,
    Eng,
    Qa,
}

impl NativeRoom {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Alpha => "#alpha",
            Self::Mgmt => "#mgmt",
            Self::Eng => "#eng",
            Self::Qa => "#qa",
        }
    }
}

impl TryFrom<&str> for NativeRoom {
    type Error = RegistryError;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "#alpha" => Ok(Self::Alpha),
            "#mgmt" => Ok(Self::Mgmt),
            "#eng" => Ok(Self::Eng),
            "#qa" => Ok(Self::Qa),
            _ => Err(RegistryError::InvalidField("native room")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    endpoint_id: String,
    room: NativeRoom,
}

impl Destination {
    /// Exact identity supplied after the launch boundary validates its endpoint.
    /// This method never normalizes endpoints or interprets topic/display names.
    pub fn new(endpoint_id: impl Into<String>, room: NativeRoom) -> Result<Self> {
        let endpoint_id = endpoint_id.into();
        if endpoint_id.is_empty()
            || endpoint_id.len() > 2048
            || endpoint_id.chars().any(char::is_whitespace)
            || endpoint_id.chars().any(char::is_control)
        {
            return Err(RegistryError::InvalidField("endpoint identifier"));
        }
        Ok(Self { endpoint_id, room })
    }

    pub fn endpoint_id(&self) -> &str {
        &self.endpoint_id
    }

    pub fn room(&self) -> NativeRoom {
        self.room
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    InboxRead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrationClass {
    ClientInitiatedMcp,
    /// Descriptive only: v1 provides no native admission or evidence constructor.
    NativeExisting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityKind {
    OwnerLocalStdioUnattributed,
}

/// An owner-local launch decision, not a wire request or an account assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerLocalDecision {
    reference: String,
    connection: ConnectionId,
    destination: Destination,
}

impl OwnerLocalDecision {
    pub fn new(
        reference: impl Into<String>,
        connection: ConnectionId,
        destination: Destination,
    ) -> Result<Self> {
        let reference = reference.into();
        if reference.trim().is_empty()
            || reference.len() > 256
            || reference.chars().any(char::is_control)
        {
            return Err(RegistryError::InvalidField("owner decision reference"));
        }
        Ok(Self {
            reference,
            connection,
            destination,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct GrantId(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BindingId(u64);

/// IDs are registry-local references, never bearer credentials.
impl std::fmt::Display for GrantId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "grant-{}", self.0)
    }
}

impl std::fmt::Display for BindingId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "binding-{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidationReason {
    ConnectionLost,
    EndpointChanged,
    OwnerScopeChanged,
    ProofLost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingState {
    Active,
    Expired,
    Revoked,
    Invalidated(InvalidationReason),
    Disconnected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingView {
    pub id: BindingId,
    pub grant: GrantId,
    pub generation: u64,
    pub connection: ConnectionId,
    pub destination: Destination,
    pub authority: AuthorityKind,
    pub integration_class: IntegrationClass,
    pub capability: Capability,
    pub state: BindingState,
    pub lease_expires_at: Instant,
    pub grant_expires_at: Instant,
    pub owner_decision_reference: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationDisposition {
    Created,
    Existing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub disposition: RegistrationDisposition,
    pub binding: BindingView,
}

/// Borrowed only for this synchronous dispatch; never a reusable authority token.
pub struct ReadScope<'a> {
    binding: BindingId,
    generation: u64,
    destination: &'a Destination,
}

impl ReadScope<'_> {
    pub fn binding(&self) -> BindingId {
        self.binding
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn destination(&self) -> &Destination {
        self.destination
    }
    pub fn capability(&self) -> Capability {
        Capability::InboxRead
    }
    pub fn authority(&self) -> AuthorityKind {
        AuthorityKind::OwnerLocalStdioUnattributed
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_grants: usize,
    pub max_bindings: usize,
    pub max_lease: Duration,
}

struct Grant {
    decision: OwnerLocalDecision,
    expires_at: Instant,
    revoked: bool,
}

// Only grant_local/register_local construct this evidence. No native/account
// proof can be supplied through a process label or a deserialized JSON object.
struct LocalStdioEvidence {
    connection: ConnectionId,
}

struct Binding {
    id: BindingId,
    grant: GrantId,
    generation: u64,
    evidence: LocalStdioEvidence,
    lease_expires_at: Instant,
    state: BindingState,
}

/// The runtime owns one writer. Mutating/dispatch methods require `&mut self`.
/// Retired records count against capacity; restarting yields an empty registry.
pub struct Registry {
    limits: Limits,
    next_id: u64,
    last_now: Option<Instant>,
    grants: BTreeMap<GrantId, Grant>,
    bindings: BTreeMap<BindingId, Binding>,
    connections: BTreeMap<ConnectionId, BindingId>,
}

impl Registry {
    pub fn new(limits: Limits) -> Result<Self> {
        if limits.max_grants == 0 || limits.max_bindings == 0 || limits.max_lease.is_zero() {
            return Err(RegistryError::InvalidLimits);
        }
        Ok(Self {
            limits,
            next_id: 1,
            last_now: None,
            grants: BTreeMap::new(),
            bindings: BTreeMap::new(),
            connections: BTreeMap::new(),
        })
    }

    pub fn grant_local(
        &mut self,
        decision: OwnerLocalDecision,
        grant_ttl: Duration,
        now: Instant,
    ) -> Result<GrantId> {
        self.accept_now(now)?;
        let expires_at = self.deadline(grant_ttl, now)?;
        if self.grants.len() >= self.limits.max_grants {
            return Err(RegistryError::CapacityReached("grant"));
        }
        let id = GrantId(self.take_id()?);
        self.grants.insert(
            id,
            Grant {
                decision,
                expires_at,
                revoked: false,
            },
        );
        Ok(id)
    }

    /// Atomically admits one owner-local decision. Invalid/conflicting requests
    /// consume no grant, binding or identifier. Exact repetition preserves the
    /// original lease, even when the registry is otherwise at capacity.
    pub fn admit_local(
        &mut self,
        decision: OwnerLocalDecision,
        connection: &ConnectionId,
        lease: Duration,
        now: Instant,
    ) -> Result<Registration> {
        self.accept_now(now)?;
        let expires_at = self.deadline(lease, now)?;
        if &decision.connection != connection {
            return Err(RegistryError::ConnectionMismatch);
        }
        if let Some(&id) = self.connections.get(connection) {
            let binding = self
                .bindings
                .get(&id)
                .ok_or(RegistryError::UnknownBinding)?;
            let grant = self
                .grants
                .get(&binding.grant)
                .ok_or(RegistryError::UnknownGrant)?;
            if grant.decision != decision {
                return Err(RegistryError::BindingConflict);
            }
            self.valid_binding(id, binding.generation, connection, now)?;
            return Ok(Registration {
                disposition: RegistrationDisposition::Existing,
                binding: self.view(id, now)?,
            });
        }
        if self.grants.len() >= self.limits.max_grants {
            return Err(RegistryError::CapacityReached("grant"));
        }
        if self.bindings.len() >= self.limits.max_bindings {
            return Err(RegistryError::CapacityReached("binding"));
        }
        let next_id = self
            .next_id
            .checked_add(2)
            .ok_or(RegistryError::IdentifierExhausted)?;
        let grant = GrantId(self.next_id);
        let id = BindingId(self.next_id + 1);
        self.grants.insert(
            grant,
            Grant {
                decision,
                expires_at,
                revoked: false,
            },
        );
        self.bindings.insert(
            id,
            Binding {
                id,
                grant,
                generation: 1,
                evidence: LocalStdioEvidence {
                    connection: connection.clone(),
                },
                lease_expires_at: expires_at,
                state: BindingState::Active,
            },
        );
        self.connections.insert(connection.clone(), id);
        self.next_id = next_id;
        Ok(Registration {
            disposition: RegistrationDisposition::Created,
            binding: self.view(id, now)?,
        })
    }

    pub fn register_local(
        &mut self,
        grant: GrantId,
        connection: &ConnectionId,
        lease_ttl: Duration,
        now: Instant,
    ) -> Result<Registration> {
        self.accept_now(now)?;
        let requested_deadline = self.deadline(lease_ttl, now)?;
        let owner_grant = self.valid_grant(grant, now)?;
        if &owner_grant.decision.connection != connection {
            return Err(RegistryError::ConnectionMismatch);
        }
        if let Some(&id) = self.connections.get(connection) {
            let binding = self
                .bindings
                .get(&id)
                .ok_or(RegistryError::UnknownBinding)?;
            if binding.grant != grant {
                return Err(RegistryError::BindingConflict);
            }
            self.valid_binding(id, binding.generation, connection, now)?;
            return Ok(Registration {
                disposition: RegistrationDisposition::Existing,
                binding: self.view(id, now)?,
            });
        }
        let lease_expires_at = requested_deadline.min(owner_grant.expires_at);
        if self.bindings.len() >= self.limits.max_bindings {
            return Err(RegistryError::CapacityReached("binding"));
        }
        let id = BindingId(self.take_id()?);
        self.bindings.insert(
            id,
            Binding {
                id,
                grant,
                generation: 1,
                evidence: LocalStdioEvidence {
                    connection: connection.clone(),
                },
                lease_expires_at,
                state: BindingState::Active,
            },
        );
        self.connections.insert(connection.clone(), id);
        Ok(Registration {
            disposition: RegistrationDisposition::Created,
            binding: self.view(id, now)?,
        })
    }

    pub fn renew_local(
        &mut self,
        binding: BindingId,
        expected_generation: u64,
        connection: &ConnectionId,
        lease_ttl: Duration,
        now: Instant,
    ) -> Result<BindingView> {
        self.accept_now(now)?;
        let requested_deadline = self.deadline(lease_ttl, now)?;
        let current = self.valid_binding(binding, expected_generation, connection, now)?;
        let grant_expiry = self.valid_grant(current.grant, now)?.expires_at;
        let generation = current
            .generation
            .checked_add(1)
            .ok_or(RegistryError::IdentifierExhausted)?;
        let current = self
            .bindings
            .get_mut(&binding)
            .ok_or(RegistryError::UnknownBinding)?;
        current.lease_expires_at = requested_deadline.min(grant_expiry);
        current.generation = generation;
        self.view(binding, now)
    }

    /// The callback must finish its bounded inbox read here, not defer work or
    /// attach/wake a client. It runs under the runtime's single registry writer.
    pub fn with_read<T>(
        &mut self,
        binding: BindingId,
        expected_generation: u64,
        connection: &ConnectionId,
        destination: &Destination,
        now: Instant,
        read: impl FnOnce(&ReadScope<'_>) -> T,
    ) -> Result<T> {
        self.accept_now(now)?;
        let current = self.valid_binding(binding, expected_generation, connection, now)?;
        let grant = self.valid_grant(current.grant, now)?;
        if &grant.decision.destination != destination {
            return Err(RegistryError::DestinationMismatch);
        }
        let scope = ReadScope {
            binding,
            generation: current.generation,
            destination: &grant.decision.destination,
        };
        Ok(read(&scope))
    }

    pub fn revoke(&mut self, grant: GrantId) -> Result<()> {
        let owner_grant = self
            .grants
            .get_mut(&grant)
            .ok_or(RegistryError::UnknownGrant)?;
        if owner_grant.revoked {
            return Ok(());
        }
        owner_grant.revoked = true;
        for binding in self
            .bindings
            .values_mut()
            .filter(|binding| binding.grant == grant)
        {
            binding.generation = binding.generation.saturating_add(1);
            binding.state = BindingState::Revoked;
        }
        Ok(())
    }

    pub fn invalidate(
        &mut self,
        binding: BindingId,
        expected_generation: u64,
        reason: InvalidationReason,
    ) -> Result<()> {
        self.set_state(
            binding,
            expected_generation,
            BindingState::Invalidated(reason),
        )
    }

    /// Disconnects admission only; no client/process lifecycle operation exists.
    pub fn disconnect(&mut self, binding: BindingId, expected_generation: u64) -> Result<()> {
        self.set_state(binding, expected_generation, BindingState::Disconnected)
    }

    pub fn inspect(&mut self, binding: BindingId, now: Instant) -> Result<BindingView> {
        self.accept_now(now)?;
        self.view(binding, now)
    }

    fn accept_now(&mut self, now: Instant) -> Result<()> {
        if self.last_now.is_some_and(|previous| now < previous) {
            return Err(RegistryError::ClockRegression);
        }
        self.last_now = Some(now);
        Ok(())
    }

    fn deadline(&self, ttl: Duration, now: Instant) -> Result<Instant> {
        if ttl.is_zero() || ttl > self.limits.max_lease {
            return Err(RegistryError::InvalidDuration);
        }
        now.checked_add(ttl).ok_or(RegistryError::TimeOverflow)
    }

    fn take_id(&mut self) -> Result<u64> {
        let id = self.next_id;
        self.next_id = id
            .checked_add(1)
            .ok_or(RegistryError::IdentifierExhausted)?;
        Ok(id)
    }

    fn valid_grant(&self, id: GrantId, now: Instant) -> Result<&Grant> {
        let grant = self.grants.get(&id).ok_or(RegistryError::UnknownGrant)?;
        if grant.revoked {
            return Err(RegistryError::GrantRevoked);
        }
        if now >= grant.expires_at {
            return Err(RegistryError::GrantExpired);
        }
        Ok(grant)
    }

    fn valid_binding(
        &self,
        id: BindingId,
        generation: u64,
        connection: &ConnectionId,
        now: Instant,
    ) -> Result<&Binding> {
        let binding = self
            .bindings
            .get(&id)
            .ok_or(RegistryError::UnknownBinding)?;
        if binding.generation != generation {
            return Err(RegistryError::StaleGeneration);
        }
        if &binding.evidence.connection != connection {
            return Err(RegistryError::ConnectionMismatch);
        }
        self.valid_grant(binding.grant, now)?;
        if binding.state != BindingState::Active {
            return Err(RegistryError::BindingUnavailable(binding.state));
        }
        if now >= binding.lease_expires_at {
            return Err(RegistryError::BindingUnavailable(BindingState::Expired));
        }
        Ok(binding)
    }

    fn set_state(&mut self, id: BindingId, generation: u64, state: BindingState) -> Result<()> {
        let binding = self
            .bindings
            .get_mut(&id)
            .ok_or(RegistryError::UnknownBinding)?;
        if binding.generation != generation {
            return Err(RegistryError::StaleGeneration);
        }
        if matches!(
            binding.state,
            BindingState::Revoked | BindingState::Disconnected
        ) {
            return Err(RegistryError::BindingUnavailable(binding.state));
        }
        // Revocation/invalidation must still remove authority at exhaustion.
        binding.generation = binding.generation.saturating_add(1);
        binding.state = state;
        Ok(())
    }

    fn view(&self, id: BindingId, now: Instant) -> Result<BindingView> {
        let binding = self
            .bindings
            .get(&id)
            .ok_or(RegistryError::UnknownBinding)?;
        let grant = self
            .grants
            .get(&binding.grant)
            .ok_or(RegistryError::UnknownGrant)?;
        let state = if grant.revoked {
            BindingState::Revoked
        } else if binding.state != BindingState::Active {
            binding.state
        } else if now >= binding.lease_expires_at || now >= grant.expires_at {
            BindingState::Expired
        } else {
            BindingState::Active
        };
        Ok(BindingView {
            id: binding.id,
            grant: binding.grant,
            generation: binding.generation,
            connection: binding.evidence.connection.clone(),
            destination: grant.decision.destination.clone(),
            authority: AuthorityKind::OwnerLocalStdioUnattributed,
            integration_class: IntegrationClass::ClientInitiatedMcp,
            capability: Capability::InboxRead,
            state,
            lease_expires_at: binding.lease_expires_at,
            grant_expires_at: grant.expires_at,
            owner_decision_reference: grant.decision.reference.clone(),
        })
    }
}

#[cfg(test)]
mod tests;
