//! Owner-signed enrollment and revocation. Wire messages cannot issue grants.
#![forbid(unsafe_code)]

use crate::{agent_instance::ActorAddress, bus_wait_message::decode};
use iroh::{EndpointId, Signature};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostGrant {
    pub schema: String,
    pub grant_id: String,
    pub authority_epoch: u64,
    pub actor: String,
    pub host_kind: String,
    pub host_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_node: Option<String>,
    pub conversation_id: String,
    pub supports_idempotent_admission_lookup: bool,
    #[serde(default)]
    pub allow_legacy_plaintext: bool,
    pub owner: String,
    pub granted_capabilities: Vec<String>,
    pub allowed_rooms: Vec<String>,
    pub allowed_tasks: Vec<String>,
    pub max_turns_quota: u64,
    pub enrolled_at_unix: u64,
    pub expires_at_unix: u64,
    pub issuer_pubkey_ed25519: String,
    pub issuer_signature_ed25519: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub schema: String,
    pub min_authority_epoch: u64,
    pub revoked_grant_ids: Vec<String>,
    pub issuer_pubkey_ed25519: String,
    pub issuer_signature_ed25519: String,
}

/// Closed owner schemas contain only safe integers, strings, booleans and
/// arrays. Root keys are sorted explicitly rather than relying on a global
/// serde_json feature selection. The signature field is the sole omission.
pub fn owner_payload<T: Serialize>(domain: &str, value: &T) -> Result<Vec<u8>, String> {
    let value = serde_json::to_value(value).map_err(|_| "OWNER_ENCODING")?;
    let object = value.as_object().ok_or("OWNER_ENCODING")?;
    let fields: BTreeMap<_, _> = object
        .iter()
        .filter(|(key, _)| key.as_str() != "issuer_signature_ed25519")
        .map(|(key, value)| (key.as_str(), value))
        .collect();
    let mut bytes = domain.as_bytes().to_vec();
    bytes.extend(serde_json::to_vec(&fields).map_err(|_| "OWNER_ENCODING")?);
    Ok(bytes)
}
fn verify_owner<T: Serialize>(
    domain: &str,
    value: &T,
    issuer: &str,
    signature: &str,
    pinned: EndpointId,
) -> Result<(), String> {
    if issuer != pinned.to_string() {
        return Err("UNTRUSTED_ENROLLMENT_ISSUER".into());
    }
    let signature = Signature::from_bytes(&decode::<64>(signature)?);
    pinned
        .verify(&owner_payload(domain, value)?, &signature)
        .map_err(|_| "INVALID_OWNER_SIGNATURE".into())
}

impl HostGrant {
    pub fn verify(
        &self,
        authority: &Authority,
        pinned: EndpointId,
        actor: &str,
        now: u64,
    ) -> Result<(), String> {
        authority.verify(pinned)?;
        verify_owner(
            "chinwag-host-enrollment-v3|",
            self,
            &self.issuer_pubkey_ed25519,
            &self.issuer_signature_ed25519,
            pinned,
        )?;
        ActorAddress::parse(actor)
            .and_then(ActorAddress::require_instance)
            .map_err(|_| "INVALID_ENROLLED_ACTOR")?;
        if self.schema != "chinwag.host.enrollment.v3"
            || self.actor != actor
            || self.conversation_id.is_empty()
            || self.conversation_id.len() > 256
            || self.conversation_id.chars().any(char::is_control)
            || self.grant_id.is_empty()
            || self.grant_id.len() > 160
            || self.host_version.len() > 128
            || !matches!(
                self.host_kind.as_str(),
                "antigravity_bg_task" | "codex_app_server"
            )
            || !self.granted_capabilities.iter().any(|c| c == "bus_wait")
            || !self
                .granted_capabilities
                .iter()
                .any(|c| c == "same_chat_wake")
            || self.allowed_rooms.is_empty()
            || self.allowed_rooms.len() > 32
            || self.allowed_tasks.is_empty()
            || self.allowed_tasks.len() > 64
            || self
                .allowed_rooms
                .iter()
                .any(|s| !s.starts_with('#') || s.len() > 128)
            || self
                .allowed_tasks
                .iter()
                .any(|s| s.is_empty() || s.len() > 256)
            || !(1..=32).contains(&self.max_turns_quota)
            || self.authority_epoch > 9_007_199_254_740_991
            || self.enrolled_at_unix > now
            || self.expires_at_unix < now
            || self.expires_at_unix <= self.enrolled_at_unix
            || self.expires_at_unix > 9_007_199_254_740_991
            || self.authority_epoch < authority.min_authority_epoch
            || authority.revoked_grant_ids.contains(&self.grant_id)
        {
            return Err("WAKE_HELD_ENROLLMENT_INACTIVE".into());
        }
        Ok(())
    }
}
impl Authority {
    pub fn verify(&self, pinned: EndpointId) -> Result<(), String> {
        if self.schema != "chinwag.host.authority.v1"
            || self.min_authority_epoch > 9_007_199_254_740_991
            || self.revoked_grant_ids.len() > 1024
            || self.revoked_grant_ids.iter().any(|id| id.len() > 160)
        {
            return Err("INVALID_OWNER_AUTHORITY".into());
        }
        verify_owner(
            "chinwag-host-authority-v1|",
            self,
            &self.issuer_pubkey_ed25519,
            &self.issuer_signature_ed25519,
            pinned,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus_wait_message::hex;
    use iroh::SecretKey;

    #[test]
    fn grant_rejects_forgery_revocation_expiry_and_wrong_conversation() {
        let owner = SecretKey::generate();
        let mut authority = Authority {
            schema: "chinwag.host.authority.v1".into(),
            min_authority_epoch: 1,
            revoked_grant_ids: vec![],
            issuer_pubkey_ed25519: owner.public().to_string(),
            issuer_signature_ed25519: String::new(),
        };
        authority.issuer_signature_ed25519 = hex(&owner
            .sign(&owner_payload("chinwag-host-authority-v1|", &authority).unwrap())
            .to_bytes());
        let mut grant = HostGrant {
            schema: "chinwag.host.enrollment.v3".into(),
            grant_id: "test".into(),
            authority_epoch: 1,
            actor: "WORKHORSE#fixture".into(),
            host_kind: "antigravity_bg_task".into(),
            host_version: "test".into(),
            host_node: None,
            conversation_id: "fixture".into(),
            supports_idempotent_admission_lookup: false,
            allow_legacy_plaintext: false,
            owner: "test owner".into(),
            granted_capabilities: vec!["bus_wait".into(), "same_chat_wake".into()],
            allowed_rooms: vec!["#eng".into()],
            allowed_tasks: vec!["TEST".into()],
            max_turns_quota: 32,
            enrolled_at_unix: 1,
            expires_at_unix: 100,
            issuer_pubkey_ed25519: owner.public().to_string(),
            issuer_signature_ed25519: String::new(),
        };
        grant.issuer_signature_ed25519 = hex(&owner
            .sign(&owner_payload("chinwag-host-enrollment-v3|", &grant).unwrap())
            .to_bytes());
        assert!(
            grant
                .verify(&authority, owner.public(), "WORKHORSE#fixture", 2)
                .is_ok()
        );
        assert!(
            grant
                .verify(&authority, owner.public(), "WORKHORSE#other", 2)
                .is_err()
        );
        assert!(
            grant
                .verify(&authority, owner.public(), "WORKHORSE#fixture", 101)
                .is_err()
        );
        let mut forged = grant.clone();
        forged.max_turns_quota = 100;
        assert!(
            forged
                .verify(&authority, owner.public(), "WORKHORSE#fixture", 2)
                .is_err()
        );
        // Only an owner signature can bind the qualified native actor to this
        // exact different host conversation. It is no live access proof.
        grant.conversation_id = "different-exact-host-chat".into();
        assert!(
            grant
                .verify(&authority, owner.public(), "WORKHORSE#fixture", 2)
                .is_err()
        );
        grant.issuer_signature_ed25519 = hex(&owner
            .sign(&owner_payload("chinwag-host-enrollment-v3|", &grant).unwrap())
            .to_bytes());
        assert!(
            grant
                .verify(&authority, owner.public(), "WORKHORSE#fixture", 2)
                .is_ok()
        );
        assert!(
            grant
                .verify(&authority, owner.public(), "WORKHORSE", 2)
                .is_err()
        );
        let mut changed_chat = grant.clone();
        changed_chat.conversation_id = "wrong-chat".into();
        assert!(
            changed_chat
                .verify(&authority, owner.public(), "WORKHORSE#fixture", 2)
                .is_err()
        );
        authority.revoked_grant_ids.push("test".into());
        authority.issuer_signature_ed25519 = hex(&owner
            .sign(&owner_payload("chinwag-host-authority-v1|", &authority).unwrap())
            .to_bytes());
        assert!(
            grant
                .verify(&authority, owner.public(), "WORKHORSE#fixture", 2)
                .is_err()
        );
    }
}
