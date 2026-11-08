// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Verify the original initiating agent's native bus signature. This supplies
//! one origin binding; it is not GitHub OIDC admission or remediation authority.
//! The seat key authenticates the seat. The exact instance suffix is a signed
//! routing assertion, not proof that a separate process/chat owns another key.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const MAX_ORIGINAL_BYTES: usize = 32 * 1024;
const INTENT_SCHEMA: &str = "chinwag.ci-dispatch-intent.v1";

#[derive(Deserialize)]
struct NativeOriginal {
    id: String,
    ts_unix: u64,
    sender: String,
    sender_endpoint_id: String,
    to: String,
    room: String,
    task_id: String,
    body: String,
    digest_sha256: String,
    pubkey_ed25519: String,
    signature_ed25519: String,
    // Native view metadata (sequence, sig_verified, formatted time) is ignored.
    // None of it can replace verification of the original signed fields.
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentSpec {
    pub schema: String,
    pub repository: String,
    pub repository_id: u64,
    pub source_commit: String,
    pub workflow_ref: String,
    pub workflow_commit: String,
    pub recipient_instance: String,
    pub delivery_profile_sha256: String,
    pub command_sha256: String,
    pub nonce: String,
    pub expires_unix: u64,
}

/// These expected values must come from the trusted local authority, not the
/// original being verified. `now_unix` is the caller's clock observation; this
/// module does not claim a K2 or hardware-trusted time source.
pub struct IntentVerification<'a> {
    pub initiator_instance: &'a str,
    pub initiator_public_key: [u8; 32],
    /// Exact, qualified admission recipient from trusted local policy. A
    /// different signed destination (including broadcasts/lists) grants this
    /// coordinator no right to admit the intent.
    pub admission_addressee: &'a str,
    pub task_id: &'a str,
    pub room: &'a str,
    pub now_unix: u64,
}

pub struct VerifiedIntent {
    spec: IntentSpec,
    original_id: String,
    original_digest: [u8; 32],
    initiating_instance: String,
    issued_unix: u64,
}

impl VerifiedIntent {
    pub fn spec(&self) -> &IntentSpec {
        &self.spec
    }

    pub fn original_id(&self) -> &str {
        &self.original_id
    }

    pub fn original_digest(&self) -> &[u8; 32] {
        &self.original_digest
    }

    pub fn initiating_instance(&self) -> &str {
        &self.initiating_instance
    }
    pub fn issued_unix(&self) -> u64 {
        self.issued_unix
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum IntentError {
    #[error("CI dispatch original is malformed or exceeds its bound")]
    Format,
    #[error("CI dispatch original does not match the expected initiating identity or scope")]
    Scope,
    #[error("CI dispatch original signature or digest is invalid")]
    Authentication,
    #[error("CI dispatch intent is expired, future-dated, or exceeds its lifetime")]
    Lifetime,
}

fn canonical_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn qualified_instance(value: &str) -> bool {
    value.split_once('#').is_some_and(|(seat, instance)| {
        !seat.is_empty()
            && seat.len() <= 64
            && seat.as_bytes()[0].is_ascii_alphanumeric()
            && seat != "ALL"
            && seat.bytes().all(|byte| {
                byte.is_ascii_uppercase() || byte.is_ascii_digit() || b"_-".contains(&byte)
            })
            && (1..=128).contains(&instance.len())
            && !instance.starts_with('.')
            && !instance.ends_with('.')
            && instance
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    })
}

fn valid_workflow(value: &str, repository: &str) -> bool {
    let Some((path, branch)) = value.split_once('@') else {
        return false;
    };
    let Some(file) = path.strip_prefix(&format!("{repository}/.github/workflows/")) else {
        return false;
    };
    let Some(branch) = branch.strip_prefix("refs/heads/") else {
        return false;
    };
    !file.starts_with('.')
        && (file.ends_with(".yml") || file.ends_with(".yaml"))
        && file
            .chars()
            .all(|c| c.is_alphanumeric() || "._-".contains(c))
        && branch.split('/').all(|part| {
            !part.is_empty()
                && !part.starts_with('.')
                && !part.ends_with('.')
                && !part.ends_with(".lock")
                && !part.contains("..")
                && part
                    .chars()
                    .all(|c| c.is_alphanumeric() || "._-".contains(c))
        })
        && value.len() <= 1024
}

fn valid_spec(spec: &IntentSpec) -> bool {
    let repo = spec
        .repository
        .split_once('/')
        .is_some_and(|(owner, name)| {
            [owner, name].iter().all(|part| {
                !part.is_empty()
                    && part.len() <= 100
                    && *part != "."
                    && *part != ".."
                    && part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            })
        });
    spec.schema == INTENT_SCHEMA
        && repo
        && spec.repository_id > 0
        && canonical_hex(&spec.source_commit, 20)
        && canonical_hex(&spec.workflow_commit, 20)
        && valid_workflow(&spec.workflow_ref, &spec.repository)
        && qualified_instance(&spec.recipient_instance)
        && canonical_hex(&spec.delivery_profile_sha256, 32)
        && canonical_hex(&spec.command_sha256, 32)
        && canonical_hex(&spec.nonce, 32)
}

/// Checks the existing `chinwag-bus-sig-v2` seven-field signature and the native
/// digest independently. The returned value has no public constructor or
/// deserializer. Storage, replay consumption, exact GitHub run binding, OIDC,
/// finite coordinator authorization and any repair admission are separate gates.
pub fn verify_original(
    json: &[u8],
    expected: IntentVerification<'_>,
) -> Result<VerifiedIntent, IntentError> {
    if json.len() > MAX_ORIGINAL_BYTES {
        return Err(IntentError::Format);
    }
    let original: NativeOriginal = serde_json::from_slice(json).map_err(|_| IntentError::Format)?;
    if !qualified_instance(expected.initiator_instance)
        || !qualified_instance(expected.admission_addressee)
        || original.sender != expected.initiator_instance
        || original.task_id != expected.task_id
        || original.room != expected.room
        || original.sender_endpoint_id != hex::encode(expected.initiator_public_key)
        || original.pubkey_ed25519 != original.sender_endpoint_id
    {
        return Err(IntentError::Scope);
    }
    if !canonical_hex(&original.digest_sha256, 32)
        || !canonical_hex(&original.signature_ed25519, 64)
    {
        return Err(IntentError::Format);
    }
    let fields = [
        original.id.as_str(),
        &original.ts_unix.to_string(),
        &original.sender,
        &original.to,
        &original.room,
        &original.task_id,
        &original.body,
    ];
    let signed = format!(
        "chinwag-bus-sig-v2|{}",
        fields
            .iter()
            .map(|s| format!("{}:{s}", s.len()))
            .collect::<Vec<_>>()
            .join("|")
    );
    let public = VerifyingKey::from_bytes(&expected.initiator_public_key)
        .map_err(|_| IntentError::Authentication)?;
    let signature = Signature::from_slice(
        &hex::decode(&original.signature_ed25519).map_err(|_| IntentError::Format)?,
    )
    .map_err(|_| IntentError::Format)?;
    public
        .verify_strict(signed.as_bytes(), &signature)
        .map_err(|_| IntentError::Authentication)?;
    let digest_input = format!(
        "chinwag-bus-v1|{}|{}|{}|{}|{}|{}|{}",
        original.ts_unix,
        original.room,
        original.sender,
        original.sender_endpoint_id,
        original.to,
        original.task_id,
        original.body
    );
    let digest: [u8; 32] = Sha256::digest(digest_input.as_bytes()).into();
    if hex::encode(digest) != original.digest_sha256 {
        return Err(IntentError::Authentication);
    }
    if original.to != expected.admission_addressee {
        return Err(IntentError::Scope);
    }
    let spec: IntentSpec = serde_json::from_str(&original.body).map_err(|_| IntentError::Format)?;
    if !valid_spec(&spec) || spec.recipient_instance != original.sender {
        return Err(IntentError::Scope);
    }
    if expected.now_unix < original.ts_unix
        || spec.expires_unix <= expected.now_unix
        || spec.expires_unix.saturating_sub(original.ts_unix) > 3600
    {
        return Err(IntentError::Lifetime);
    }
    Ok(VerifiedIntent {
        spec,
        original_id: original.id,
        original_digest: digest,
        initiating_instance: original.sender,
        issued_unix: original.ts_unix,
    })
}
