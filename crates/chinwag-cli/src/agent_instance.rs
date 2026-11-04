// Copyright 2026 Emun Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Seat identity and exact, opaque conversation addresses.
//!
//! The seat key authenticates the seat. An instance suffix is signed routing
//! context, not a separate key or an independent authorization grant.

use std::fmt;

pub const MAX_INSTANCE_BYTES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorAddress {
    seat: String,
    instance: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchIdentity {
    child: ActorAddress,
    parent: ActorAddress,
}

impl DispatchIdentity {
    pub fn new(child: ActorAddress, parent: ActorAddress) -> Result<Self, InstanceError> {
        if child.is_human() || child.seat() == "ALL" {
            return Err(InstanceError::InvalidAddress);
        }
        Ok(Self {
            child: child.require_instance()?,
            parent: parent.require_instance()?,
        })
    }

    pub fn child(&self) -> &ActorAddress {
        &self.child
    }

    pub fn parent(&self) -> &ActorAddress {
        &self.parent
    }

    pub fn environment(&self) -> [(String, String); 4] {
        [
            ("CHINWAG_ACTOR".to_owned(), self.child.to_string()),
            (
                "CHINWAG_INSTANCE_ID".to_owned(),
                self.child.instance().unwrap_or_default().to_owned(),
            ),
            ("CHINWAG_CALLER".to_owned(), self.parent.to_string()),
            (
                "CHINWAG_PARENT_INSTANCE".to_owned(),
                self.parent.to_string(),
            ),
        ]
    }

    /// Addresses have already rejected shell syntax. Quotes still keep '#'
    /// inside a value when this context crosses the SSH command boundary.
    pub fn remote_environment(&self) -> String {
        self.environment()
            .iter()
            .map(|(key, value)| format!("{key}='{value}'"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstanceError {
    InvalidAddress,
    MissingInstance,
    MissingCaller,
    ConflictingInstance,
    EntropyUnavailable,
    SigningIdentityUnavailable,
    PublicationRejected,
}

impl fmt::Display for InstanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidAddress => "invalid_actor_instance",
            Self::MissingInstance => "agent_instance_required",
            Self::MissingCaller => "agent_caller_required",
            Self::ConflictingInstance => "conflicting_actor_instance",
            Self::EntropyUnavailable => "instance_entropy_unavailable",
            Self::SigningIdentityUnavailable => "signing_identity_unavailable",
            Self::PublicationRejected => "bus_publication_rejected",
        })
    }
}

impl ActorAddress {
    pub fn parse(raw: &str) -> Result<Self, InstanceError> {
        let raw = raw.trim().trim_start_matches('@').trim();
        let raw = raw.trim_start_matches(['■', '◆', '●']).trim();
        let (seat, instance) = match raw.split_once('#') {
            Some((seat, instance)) => (seat, Some(validate_instance(instance)?)),
            None => (raw, None),
        };
        if seat.is_empty()
            || seat.len() > 64
            || !seat.as_bytes()[0].is_ascii_alphanumeric()
            || !seat
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
        {
            return Err(InstanceError::InvalidAddress);
        }
        let upper = seat.to_ascii_uppercase();
        let seat = match upper.as_str() {
            "BRIAN" | "ACTOR-BRIAN" => "Brian".to_owned(),
            "NIC" | "NICOLA" | "ACTOR-NIC" => "Nic".to_owned(),
            _ => upper,
        };
        if seat == "ALL" && instance.is_some() {
            return Err(InstanceError::InvalidAddress);
        }
        Ok(Self { seat, instance })
    }

    pub fn seat(&self) -> &str {
        &self.seat
    }

    pub fn instance(&self) -> Option<&str> {
        self.instance.as_deref()
    }

    pub fn is_human(&self) -> bool {
        self.seat == "Brian" || self.seat == "Nic"
    }

    pub fn record_author(&self) -> String {
        match self.instance() {
            Some(instance) => format!("{}#{instance}@chinwag.sh", self.seat.to_ascii_lowercase()),
            None => format!("{}@chinwag.sh", self.seat.to_ascii_lowercase()),
        }
    }

    pub fn with_instance(mut self, instance: &str) -> Result<Self, InstanceError> {
        if self.seat == "ALL" {
            return Err(InstanceError::InvalidAddress);
        }
        let instance = validate_instance(instance)?;
        if self.instance.as_ref().is_some_and(|old| old != &instance) {
            return Err(InstanceError::ConflictingInstance);
        }
        self.instance = Some(instance);
        Ok(self)
    }

    pub fn require_instance(self) -> Result<Self, InstanceError> {
        if !self.is_human() && self.instance.is_none() {
            return Err(InstanceError::MissingInstance);
        }
        Ok(self)
    }
}

impl fmt::Display for ActorAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.seat)?;
        if let Some(instance) = &self.instance {
            write!(f, "#{instance}")?;
        }
        Ok(())
    }
}

pub fn validate_instance(raw: &str) -> Result<String, InstanceError> {
    if raw.is_empty()
        || raw.len() > MAX_INSTANCE_BYTES
        || raw.starts_with('.')
        || raw.ends_with('.')
        || !raw
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
    {
        return Err(InstanceError::InvalidAddress);
    }
    Ok(raw.to_owned())
}

pub fn resolve_actor(
    raw: &str,
    explicit: Option<&str>,
    inherited: Option<&str>,
) -> Result<ActorAddress, InstanceError> {
    let mut address = ActorAddress::parse(raw)?;
    if let Some(instance) = explicit {
        address = address.with_instance(instance)?;
    } else if address.instance.is_none()
        && !address.is_human()
        && let Some(instance) = inherited
    {
        address = address.with_instance(instance)?;
    }
    address.require_instance()
}

/// Only explicit conversation context is inherited. A terminal or parent PID
/// cannot distinguish parallel conversations hosted by the same process.
pub fn inherited_instance() -> Result<Option<String>, InstanceError> {
    for key in [
        "CHINWAG_INSTANCE_ID",
        "CHINWAG_THREAD_ID",
        "CODEX_THREAD_ID",
        "ANTIGRAVITY_CONVERSATION_ID",
        "CONVERSATION_ID",
    ] {
        match std::env::var(key) {
            Ok(value) => return validate_instance(&value).map(Some),
            Err(std::env::VarError::NotPresent) => {}
            Err(std::env::VarError::NotUnicode(_)) => return Err(InstanceError::InvalidAddress),
        }
    }
    Ok(None)
}

pub fn resolve_from_environment(
    raw: &str,
    explicit: Option<&str>,
) -> Result<ActorAddress, InstanceError> {
    let address = ActorAddress::parse(raw)?;
    let inherited = if address.instance().is_none() && !address.is_human() && explicit.is_none() {
        inherited_instance()?
    } else {
        None
    };
    resolve_actor(raw, explicit, inherited.as_deref())
}

#[cfg(unix)]
pub fn new_instance_id() -> Result<String, InstanceError> {
    use std::io::Read;
    let mut bytes = [0_u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut bytes))
        .map_err(|_| InstanceError::EntropyUnavailable)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// A base-seat query aggregates its instances; a qualified query sees only that
/// instance and explicit seat/all broadcasts. Instance spelling is exact.
pub fn recipient_matches(query: &ActorAddress, recipient: &ActorAddress) -> bool {
    recipient.seat == "ALL"
        || (query.seat == recipient.seat
            && (query.instance.is_none()
                || recipient.instance.is_none()
                || query.instance == recipient.instance))
}

pub fn parse_recipients(raw: &str) -> Result<Vec<ActorAddress>, InstanceError> {
    let mut recipients = Vec::new();
    for value in raw.split(',') {
        if recipients.len() == 32 {
            return Err(InstanceError::InvalidAddress);
        }
        recipients.push(ActorAddress::parse(value)?);
    }
    Ok(recipients)
}

pub fn inbox_matches(query: &ActorAddress, to: Option<&str>, body: &str) -> bool {
    if let Some(to) = to {
        return parse_recipients(to).is_ok_and(|targets| {
            targets
                .iter()
                .any(|target| recipient_matches(query, target))
        });
    }
    body_mentions(query, body)
}

pub fn body_mentions(query: &ActorAddress, body: &str) -> bool {
    body.match_indices('@').any(|(offset, _)| {
        if offset > 0
            && body[..offset]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '#'))
        {
            return false;
        }
        let token: String = body[offset + 1..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '#'))
            .collect();
        let token = token.trim_end_matches('.');
        ActorAddress::parse(token).is_ok_and(|recipient| recipient_matches(query, &recipient))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_conversation_ids_remain_distinct() {
        let a = ActorAddress::parse("WORKHORSE#01a146d0-d769-7a02-a1a5-75c407ffaa3c").unwrap();
        let b = ActorAddress::parse("WORKHORSE#01a146d0-d769-7a02-a1a5-75c407ffaa3d").unwrap();
        assert_ne!(a, b);
        assert!(a.to_string().ends_with("75c407ffaa3c"));
    }

    #[test]
    fn invalid_or_oversized_tags_are_rejected_without_aliasing() {
        for tag in ["", "review!one", "a#b", ".hidden", "trailing.", "a b"] {
            assert!(ActorAddress::parse(&format!("WORKHORSE#{tag}")).is_err());
        }
        assert!(ActorAddress::parse(&format!("WORKHORSE#{}", "a".repeat(129))).is_err());
        assert!(ActorAddress::parse(&format!("WORKHORSE#{}", "a".repeat(128))).is_ok());
        for address in [
            "ALL#one",
            "-WORKHORSE#one",
            "WORKHORSE#bad/tag",
            "WORKHORSE#bad';cmd",
        ] {
            assert!(ActorAddress::parse(address).is_err());
        }
    }

    #[test]
    fn explicit_instance_is_checked_even_on_qualified_addresses() {
        assert_eq!(
            resolve_actor("WORKHORSE#one", Some("two"), None),
            Err(InstanceError::ConflictingInstance)
        );
        assert_eq!(
            resolve_actor("WORKHORSE", None, None),
            Err(InstanceError::MissingInstance)
        );
        assert!(resolve_actor("Brian", None, None).is_ok());
    }

    #[test]
    fn sibling_prefixes_and_case_distinct_instances_do_not_match() {
        let q = ActorAddress::parse("WORKHORSE#rev-thread-id").unwrap();
        assert!(!body_mentions(
            &q,
            "Reply to @WORKHORSE#rev-thread-identity."
        ));
        assert!(body_mentions(&q, "Reply to @WORKHORSE#rev-thread-id."));
        assert!(!body_mentions(&q, "mail@WORKHORSE#rev-thread-id"));
        assert!(!body_mentions(&q, "@WORKHORSE#REV-THREAD-ID"));
    }

    #[test]
    fn base_and_all_broadcasts_are_explicit_and_aggregate_queries_work() {
        let instance = ActorAddress::parse("WORKHORSE#one").unwrap();
        let base = ActorAddress::parse("WORKHORSE").unwrap();
        assert!(body_mentions(&instance, "@WORKHORSE: notice"));
        assert!(body_mentions(&instance, "@ALL notice"));
        assert!(body_mentions(&base, "@WORKHORSE#two notice"));
        assert!(!body_mentions(&instance, "@WORKHORSE#two notice"));
    }

    #[test]
    fn structured_recipient_wins_over_mentions_in_message_text() {
        let q = ActorAddress::parse("WORKHORSE#one").unwrap();
        assert!(!inbox_matches(
            &q,
            Some("WORKHORSE#two"),
            "Quoted @WORKHORSE#one"
        ));
        assert!(inbox_matches(
            &q,
            Some("RUST#two,@WORKHORSE#one"),
            "Fixture"
        ));
        assert!(inbox_matches(&q, Some("WORKHORSE"), "Broadcast"));
        assert!(!inbox_matches(&q, Some("WORKHORSE#one!"), "@ALL"));
    }

    #[test]
    fn dispatch_context_preserves_child_and_parent_on_both_host_boundaries() {
        let child = ActorAddress::parse("WORKHORSE#01a146d0-d769-7a02-a1a5-75c407ffaa3c").unwrap();
        let parent = ActorAddress::parse("GEMINI-PM#parent-01").unwrap();
        let identity = DispatchIdentity::new(child.clone(), parent.clone()).unwrap();
        let env = identity.environment();
        assert_eq!(env[0].1, child.to_string());
        assert_eq!(env[1].1, child.instance().unwrap());
        assert_eq!(env[2].1, parent.to_string());
        for (key, value) in env {
            assert!(
                identity
                    .remote_environment()
                    .contains(&format!("{key}='{value}'"))
            );
        }
        assert!(ActorAddress::parse("WORKHORSE#bad';command").is_err());
    }

    #[test]
    fn record_authors_keep_case_sensitive_instances() {
        let a = ActorAddress::parse("WORKHORSE#MixedCase").unwrap();
        let b = ActorAddress::parse("WORKHORSE#mixedcase").unwrap();
        assert_eq!(a.record_author(), "workhorse#MixedCase@chinwag.sh");
        assert_ne!(a.record_author(), b.record_author());
    }
}
