// Copyright (c) 2026 Emun Labs, Inc. (1401 Lavaca St STE 81335, Austin, TX 78701)
// SPDX-License-Identifier: Apache-2.0

//! High-level ChaCha20-Poly1305 AEAD envelope over Pairing-Based ACU Encryption (`EncryptedCiPayload`)
//! for Chinwag CI/CD root-cause payloads, Zero-Plaintext-At-Rest Inboxes (`ACU AND (Recipient OR Archive)`),
//! Cloudflare R2 Parquet `acu_ciphertext` BLOB storage, and Brian's 2-of-2 Split-Key ACU Instant Revocation pattern.

use crate::AcuError;
use crate::acu::{
    AcuCiphertext, PartialDecryptionShare, acu_combine, acu_combine_unverified,
    acu_encrypt_with_g1, read_u32_be, take_slice,
};
use crate::keys::{SeatPublicKey, sample_nonzero_scalar};
use crate::lsss::{AccessTree, LsssMatrix};
use bls12_381::{G1Projective, Gt};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

/// Default key-branch identifier for the responsible Human / AI Agent Seat in the Split-Key CI pattern.
pub const DEFAULT_AGENT_BRANCH_ID: &str = "branch:8687872";

/// Default key-branch identifier for the Always-On Revocation Access Control Unit (`ACU`).
pub const DEFAULT_REVOCATION_ACU_ID: &str = "branch:98939834";

/// Default seat identifier for the Zero-Plaintext-At-Rest Message Archive Unit (`archive:vault`).
pub const DEFAULT_MESSAGE_ARCHIVE_ID: &str = "archive:vault";

const ACU_HKDF_SALT: &[u8] = b"chinwag-acu/v1/gt-chacha20poly1305-salt";
const ACU_AAD_DOMAIN: &str = "chinwag-acu-ci-envelope/v1";
const ENCRYPTED_PAYLOAD_MAGIC: &[u8; 8] = b"CHWGAEAD";
const MAX_SERIALIZED_BLOB_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn is_valid_metadata_token(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
}

/// Encrypted CI/CD root-cause or inbox message envelope combining an [`AcuCiphertext`] (`CHWGACU2`)
/// header with a ChaCha20-Poly1305 authenticated ciphertext (`aead_ciphertext`).
///
/// Because the symmetric key $k_{\text{sym}} \in \{0,1\}^{256}$ is derived from the ACU
/// target-group secret $K \in \mathbb{G}_T$, the [`AcuCiphertext`] header can dynamically
/// evolve its access policy across epochs (`insert_key`, `insert_sibling_key`, `escalate_threshold`,
/// `revoke_and_rerandomize`) by the ACU operator without ever decrypting or re-encrypting `aead_ciphertext`,
/// while keeping the basis commitments $V_0, \dots, V_{k-1}$ sealed exclusively under `pk_ACU`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedCiPayload {
    /// Dynamic ACU header (`CHWGACU2`) encapsulating $K \in \mathbb{G}_T$.
    pub acu_ciphertext: AcuCiphertext,
    /// 96-bit ChaCha20-Poly1305 nonce.
    pub nonce: [u8; 12],
    /// Canonical associated data (AAD) binding repository, task, and initial policy epoch.
    pub associated_data: Vec<u8>,
    /// ChaCha20-Poly1305 authenticated ciphertext + 128-bit Poly1305 tag.
    pub aead_ciphertext: Vec<u8>,
}

impl EncryptedCiPayload {
    /// Serialize this [`EncryptedCiPayload`] into a deterministic binary BLOB (`CHWGAEAD` wrapping `CHWGACU2`)
    /// suitable for storing in the `acu_ciphertext` BLOB column of a Cloudflare R2 Parquet archive.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let acu_ct_bytes = self.acu_ciphertext.to_bytes();
        let mut out = Vec::with_capacity(
            8 + 12
                + 4
                + self.associated_data.len()
                + 4
                + self.aead_ciphertext.len()
                + 4
                + acu_ct_bytes.len(),
        );
        out.extend_from_slice(ENCRYPTED_PAYLOAD_MAGIC);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(self.associated_data.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.associated_data);
        out.extend_from_slice(&(self.aead_ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.aead_ciphertext);
        out.extend_from_slice(&(acu_ct_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&acu_ct_bytes);
        out
    }

    /// Deserialize an [`EncryptedCiPayload`] from its canonical binary BLOB representation (`CHWGAEAD`),
    /// failing closed with [`AcuError::InsecureLegacyFormat`] if the inner header uses `CHWGACU1`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AcuError> {
        if bytes.len() > MAX_SERIALIZED_BLOB_BYTES {
            return Err(AcuError::SerializationError(
                "EncryptedCiPayload exceeds max size",
            ));
        }
        let mut cursor = 0usize;
        let magic = take_slice(bytes, &mut cursor, 8)?;
        if magic != ENCRYPTED_PAYLOAD_MAGIC {
            return Err(AcuError::SerializationError(
                "invalid EncryptedCiPayload magic",
            ));
        }
        let nonce_slice = take_slice(bytes, &mut cursor, 12)?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(nonce_slice);

        let aad_len = read_u32_be(bytes, &mut cursor)? as usize;
        if aad_len == 0 || aad_len > MAX_SERIALIZED_BLOB_BYTES {
            return Err(AcuError::SerializationError(
                "invalid associated_data length",
            ));
        }
        let associated_data = take_slice(bytes, &mut cursor, aad_len)?.to_vec();

        let aead_len = read_u32_be(bytes, &mut cursor)? as usize;
        if !(16..=MAX_SERIALIZED_BLOB_BYTES).contains(&aead_len) {
            return Err(AcuError::SerializationError(
                "invalid aead_ciphertext length",
            ));
        }
        let aead_ciphertext = take_slice(bytes, &mut cursor, aead_len)?.to_vec();

        let acu_ct_len = read_u32_be(bytes, &mut cursor)? as usize;
        let acu_ct_slice = take_slice(bytes, &mut cursor, acu_ct_len)?;
        if cursor != bytes.len() {
            return Err(AcuError::SerializationError(
                "trailing bytes in EncryptedCiPayload",
            ));
        }
        let acu_ciphertext = AcuCiphertext::from_bytes(acu_ct_slice)?;

        Ok(Self {
            acu_ciphertext,
            nonce,
            associated_data,
            aead_ciphertext,
        })
    }

    /// Build Brian's canonical 2-of-2 Split-Key Instant Revocation policy:
    ///
    /// $$\text{Leaf}(\texttt{agent\_branch\_id}) \;\wedge\; \text{Leaf}(\texttt{acu\_branch\_id})$$
    ///
    /// By default: `"branch:8687872"` (Responsible Human / AI Agent Seat) `AND` `"branch:98939834"` (Revocation ACU).
    #[must_use]
    pub fn build_split_key_acu_policy(agent_branch_id: &str, acu_branch_id: &str) -> AccessTree {
        AccessTree::And(vec![
            AccessTree::Leaf(agent_branch_id.to_string()),
            AccessTree::Leaf(acu_branch_id.to_string()),
        ])
    }

    /// Encrypt a CI/CD root-cause payload directly under the 2-of-2 Split-Key ACU policy
    /// (`agent_pk.seat_id` `AND` `acu_pk.seat_id`), sealing basis commitments exclusively under `acu_pk`.
    pub fn encrypt_split_key_with_acu(
        plaintext: &[u8],
        agent_pk: &SeatPublicKey,
        acu_pk: &SeatPublicKey,
        repo_id: &str,
        task_id: &str,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, AcuError> {
        let tree = Self::build_split_key_acu_policy(&agent_pk.seat_id, &acu_pk.seat_id);
        let mut seat_keys = BTreeMap::new();
        seat_keys.insert(agent_pk.seat_id.clone(), agent_pk.clone());
        seat_keys.insert(acu_pk.seat_id.clone(), acu_pk.clone());
        Self::encrypt(plaintext, &tree, &seat_keys, acu_pk, repo_id, task_id, rng)
    }

    /// Build the canonical **Zero-Plaintext-At-Rest Inbox + Forensic Archive** 2-of-3 policy
    /// anchored on the CISO's Access Control Unit (`ACU`):
    ///
    /// $$\text{Leaf}(\texttt{acu\_seat\_id}) \;\wedge\; \bigl(\text{Leaf}(\texttt{recipient\_seat\_id}) \;\vee\; \text{Leaf}(\texttt{archive\_seat\_id})\bigr)$$
    #[must_use]
    pub fn build_acu_recipient_or_archive_policy(
        acu_seat_id: &str,
        recipient_seat_id: &str,
        archive_seat_id: &str,
    ) -> AccessTree {
        AccessTree::And(vec![
            AccessTree::Leaf(acu_seat_id.to_string()),
            AccessTree::Or(vec![
                AccessTree::Leaf(recipient_seat_id.to_string()),
                AccessTree::Leaf(archive_seat_id.to_string()),
            ]),
        ])
    }

    /// Encrypt a bus message or CI/CD payload under the canonical **Zero-Plaintext-At-Rest Inbox + Archive**
    /// policy (`ACU AND (Recipient OR Archive)`), sealing basis commitments exclusively under `acu_pk`.
    pub fn encrypt_with_acu_and_archive(
        plaintext: &[u8],
        acu_pk: &SeatPublicKey,
        recipient_pk: &SeatPublicKey,
        archive_pk: &SeatPublicKey,
        repo_id: &str,
        task_id: &str,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, AcuError> {
        let tree = Self::build_acu_recipient_or_archive_policy(
            &acu_pk.seat_id,
            &recipient_pk.seat_id,
            &archive_pk.seat_id,
        );
        let mut seat_keys = BTreeMap::new();
        seat_keys.insert(acu_pk.seat_id.clone(), acu_pk.clone());
        seat_keys.insert(recipient_pk.seat_id.clone(), recipient_pk.clone());
        seat_keys.insert(archive_pk.seat_id.clone(), archive_pk.clone());
        Self::encrypt(plaintext, &tree, &seat_keys, acu_pk, repo_id, task_id, rng)
    }

    /// Encrypt arbitrary plaintext bytes under a general monotone [`AccessTree`] and seat directory,
    /// sealing the dynamic policy basis commitments exclusively under `acu_pk`.
    pub fn encrypt(
        plaintext: &[u8],
        tree: &AccessTree,
        seat_keys: &BTreeMap<String, SeatPublicKey>,
        acu_pk: &SeatPublicKey,
        repo_id: &str,
        task_id: &str,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, AcuError> {
        if !is_valid_metadata_token(repo_id) || !is_valid_metadata_token(task_id) {
            return Err(AcuError::InvalidMetadata);
        }
        let matrix = LsssMatrix::from_tree(tree)?;

        // Sample uniform session secret in G1 -> Gt so c0_g1 = payload_g1 + g1 * s is 48-byte compressible.
        let mut k_scalar = sample_nonzero_scalar(rng);
        let mut payload_g1 = G1Projective::generator() * k_scalar;
        k_scalar.zeroize();

        let enc_res = acu_encrypt_with_g1(&payload_g1, &matrix, seat_keys, acu_pk, rng);
        payload_g1.zeroize();
        let (acu_ciphertext, mut payload_gt) = enc_res?;

        let associated_data = encode_associated_data(repo_id, task_id, acu_ciphertext.policy_epoch);
        let sym_key = derive_aead_key_from_gt(&payload_gt, &associated_data);
        payload_gt.zeroize();

        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*sym_key));
        let aead_ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| AcuError::AeadFailure)?;

        Ok(Self {
            acu_ciphertext,
            nonce,
            associated_data,
            aead_ciphertext,
        })
    }

    /// Combine authorized [`PartialDecryptionShare`]s (strictly verifying each share via
    /// [`crate::acu::acu_verify_partial_share`], `policy_epoch`, and row/seat binding against
    /// `seat_keys` without requiring cleartext basis commitments) and decrypt the ChaCha20-Poly1305 payload.
    pub fn decrypt(
        &self,
        shares: &[PartialDecryptionShare],
        seat_keys: &BTreeMap<String, SeatPublicKey>,
    ) -> Result<Vec<u8>, AcuError> {
        let mut recovered_gt = acu_combine(&self.acu_ciphertext, shares, seat_keys)?;
        let res = self.decrypt_with_gt(&recovered_gt);
        recovered_gt.zeroize();
        res
    }

    /// Combine [`PartialDecryptionShare`]s using raw LSSS weights without pre-verifying
    /// individual pairing shares against `seat_keys`, then attempt ChaCha20-Poly1305 decryption.
    /// If any share is stale or forged, the recovered $\mathbb{G}_T$ element will not match $K$
    /// and ChaCha20-Poly1305 authentication will fail closed with [`AcuError::AeadFailure`].
    pub fn decrypt_unverified(
        &self,
        shares: &[PartialDecryptionShare],
    ) -> Result<Vec<u8>, AcuError> {
        let mut recovered_gt = acu_combine_unverified(&self.acu_ciphertext, shares)?;
        let res = self.decrypt_with_gt(&recovered_gt);
        recovered_gt.zeroize();
        res
    }

    fn decrypt_with_gt(&self, recovered_gt: &Gt) -> Result<Vec<u8>, AcuError> {
        let sym_key = derive_aead_key_from_gt(recovered_gt, &self.associated_data);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&*sym_key));
        cipher
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.aead_ciphertext,
                    aad: &self.associated_data,
                },
            )
            .map_err(|_| AcuError::AeadFailure)
    }
}

/// Derive a 256-bit ChaCha20-Poly1305 key from a target-group element $K \in \mathbb{G}_T$
/// and context AAD via HKDF-SHA256, zeroizing the canonical $\mathbb{F}_{p^{12}}$ representation on drop.
pub fn derive_aead_key_from_gt(element: &Gt, associated_data: &[u8]) -> Zeroizing<[u8; 32]> {
    let canonical_fp12 = Zeroizing::new(format!("{element:?}"));
    let hk = Hkdf::<Sha256>::new(Some(ACU_HKDF_SALT), canonical_fp12.as_bytes());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(associated_data, &mut *okm)
        .expect("32-byte HKDF-SHA256 output is always valid");
    okm
}

fn encode_associated_data(repo_id: &str, task_id: &str, created_epoch: u64) -> Vec<u8> {
    format!("{ACU_AAD_DOMAIN}\nrepo={repo_id}\ntask={task_id}\ncreated_epoch={created_epoch}\n")
        .into_bytes()
}
