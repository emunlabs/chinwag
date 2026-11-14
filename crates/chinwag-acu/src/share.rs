// Copyright (c) 2026 Emun Labs, Inc. (1401 Lavaca St STE 81335, Austin, TX 78701)
// SPDX-License-Identifier: Apache-2.0

//! Pure-$\mathbb{G}_1$ (`48`-byte) verifiable partial decryption shares, Dual-Mode strong
//! Fiat–Shamir Chaum–Pedersen `DLEQ` proofs (`64`-byte compact Mode A & `128`-byte batchable
//! Mode B with recursive binary-splitting fault isolation), and `64`-byte pure-$\mathbb{G}_1$
//! Schnorr row-randomness proofs $\pi^{\mathsf{row}}_j$ / $\pi^{\mathsf{upd}}_{E,j}$
//! (`ePrint v2` §6.1–§6.3, Theorem 3(iii), Theorem 4(i); `CHWG-PAT-11B-v2` `[0010]`–`[0015]`).

use crate::AcuError;
use crate::acu::CiphertextRow;
use crate::framing::{
    hash_to_nonzero_scalar, lp64_str, read_g1_compressed, read_lp64_str, read_scalar, read_u8,
    read_u32_be, read_u64_be, take_slice,
};
use crate::keys::{MAX_SEAT_ID_BYTES, SeatPublicKey, SeatSecretKey, is_valid_seat_id};
use bls12_381::{G1Affine, G1Projective, Scalar};
use ff::Field;
use hkdf::Hkdf;
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::Sha256;
use std::collections::BTreeMap;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const ROW_POK_DST: &[u8] = b"chinwag.acu.v2.row-pok";
const ROW_UPD_POK_DST: &[u8] = b"chinwag.acu.v2.row-upd-pok";
const DLEQ_CHALLENGE_DST: &[u8] = b"chinwag.acu.v2.dleq";
const DLEQ_NONCE_SALT: &[u8] = b"chinwag-acu/v2/dleq-hedged-nonce-salt";
const DLEQ_NONCE_INFO: &[u8] = b"chinwag-acu/v2/dleq-hedged-nonce-info";
const ROW_POK_NONCE_SALT: &[u8] = b"chinwag-acu/v2/row-pok-nonce-salt";
const ROW_POK_NONCE_INFO: &[u8] = b"chinwag-acu/v2/row-pok-nonce-info";
const PARTIAL_SHARE_MAGIC: &[u8; 8] = b"CHWGSHR2";

/// Proof serialization mode for [`PartialDecryptionShare`] (`CHWG-PAT-11B-v2` `[0011]`–`[0014]`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DleqMode {
    /// Mode A (`64` B): compact $(\mathsf{ch}_j, z_j) \in (\mathbb{F}_r^*)^2$ verified individually
    /// via 2-scalar reconstruction and constant-time challenge comparison.
    Compact,
    /// Mode B (`128` B): batchable $(R_{j,1}, R_{j,2}, z_j) \in \mathbb{G}_1^2 \times \mathbb{F}_r^*$
    /// supporting multi-scalar batch verification with independent 128-bit randomizers $(\alpha_j, \beta_j)$
    /// and $O(b \log |\Gamma|)$ recursive binary-splitting fault isolation.
    Batchable,
}

/// Strong Fiat–Shamir Chaum–Pedersen `DLEQ` proof over $\mathbb{G}_1$ proving
/// $\log_{G_1}(pk_i) = \log_{c_{j,2}}(c_{j,1} - S_j)$.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DleqProof {
    /// Mode A (`64` bytes): `(challenge, response)`.
    Compact {
        /// Fiat–Shamir challenge $\mathsf{ch}_j \in \mathbb{F}_r^*$.
        challenge: Scalar,
        /// Schnorr response $z_j = t_j + \mathsf{ch}_j \cdot sk_i \pmod{r}$.
        response: Scalar,
    },
    /// Mode B (`128` bytes): `(commitment_g1, commitment_c2, response)`.
    Batchable {
        /// First commitment $R_{j,1} = t_j \cdot G_1 \in \mathbb{G}_1^*$.
        commitment_g1: G1Projective,
        /// Second commitment $R_{j,2} = t_j \cdot c_{j,2} \in \mathbb{G}_1^*$.
        commitment_c2: G1Projective,
        /// Schnorr response $z_j = t_j + \mathsf{ch}_j \cdot sk_i \pmod{r}$.
        response: Scalar,
    },
}

impl DleqProof {
    /// Return the mode (`Compact` vs `Batchable`) of this proof.
    #[must_use]
    pub const fn mode(&self) -> DleqMode {
        match self {
            Self::Compact { .. } => DleqMode::Compact,
            Self::Batchable { .. } => DleqMode::Batchable,
        }
    }

    /// Canonical wire size (`64` bytes for Mode A, `128` bytes for Mode B).
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        match self {
            Self::Compact { .. } => 64,
            Self::Batchable { .. } => 128,
        }
    }

    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Compact {
                challenge,
                response,
            } => {
                out.push(0x01);
                out.extend_from_slice(&challenge.to_bytes());
                out.extend_from_slice(&response.to_bytes());
            }
            Self::Batchable {
                commitment_g1,
                commitment_c2,
                response,
            } => {
                out.push(0x02);
                out.extend_from_slice(&G1Affine::from(*commitment_g1).to_compressed());
                out.extend_from_slice(&G1Affine::from(*commitment_c2).to_compressed());
                out.extend_from_slice(&response.to_bytes());
            }
        }
    }

    pub(crate) fn decode_from(bytes: &[u8], cursor: &mut usize) -> Result<Self, AcuError> {
        let tag = read_u8(bytes, cursor)?;
        match tag {
            0x01 => {
                let challenge = read_scalar(bytes, cursor)?;
                let response = read_scalar(bytes, cursor)?;
                if bool::from(challenge.is_zero()) || bool::from(response.is_zero()) {
                    return Err(AcuError::SerializationError("zero scalar in Compact DLEQ"));
                }
                Ok(Self::Compact {
                    challenge,
                    response,
                })
            }
            0x02 => {
                let commitment_g1 = read_g1_compressed(bytes, cursor)?;
                let commitment_c2 = read_g1_compressed(bytes, cursor)?;
                let response = read_scalar(bytes, cursor)?;
                if bool::from(commitment_g1.is_identity())
                    || bool::from(commitment_c2.is_identity())
                    || bool::from(response.is_zero())
                {
                    return Err(AcuError::SerializationError(
                        "identity or zero scalar in Batchable DLEQ",
                    ));
                }
                Ok(Self::Batchable {
                    commitment_g1,
                    commitment_c2,
                    response,
                })
            }
            _ => Err(AcuError::SerializationError("unknown DleqProof mode tag")),
        }
    }
}

/// Pure-$\mathbb{G}_1$ (`48`-byte) verifiable partial decryption share $S_j = c_{j,1} - sk_i c_{j,2} = \lambda_j G_1$
/// emitted by seat $\rho(j)$ (`ePrint v2` §6.2).
///
/// Replaces legacy `576`-byte $\mathbb{G}_T$ shares (`12x` smaller share payload, `0` pairings per custodian,
/// `0` pairings during share verification, and **only `1` pairing total** at final `acu_combine`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialDecryptionShare {
    /// 32-byte object identifier $O$ binding this share against cross-object replay.
    pub object_digest: [u8; 32],
    /// Row index $j$ in [`crate::AcuCiphertext::rows`] that this share decrypts.
    pub row_index: usize,
    /// Per-object blind row locator $\ell_j$ (`32` bytes).
    pub row_locator: [u8; 32],
    /// Seat identifier $\rho(j)$ that produced this share.
    pub seat_id: String,
    /// Policy epoch $E \ge 1$ of the ciphertext when this share was computed.
    pub policy_epoch: u64,
    /// Unblinded $\mathbb{G}_1$ share $S_j = c_{j,1} - sk_i \cdot c_{j,2} = \lambda_j G_1 \in \mathbb{G}_1$.
    pub share_g1: G1Projective,
    /// Dual-mode strong Fiat–Shamir Chaum–Pedersen `DLEQ` proof (`64` B Mode A or `128` B Mode B).
    pub proof: DleqProof,
}

impl PartialDecryptionShare {
    /// Canonical compressed `48`-byte encoding of $S_j \in \mathbb{G}_1$.
    #[must_use]
    pub fn share_compressed_bytes(&self) -> [u8; 48] {
        G1Affine::from(self.share_g1).to_compressed()
    }

    /// Serialize this [`PartialDecryptionShare`] into canonical `CHWGSHR2` binary bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32 + 4 + 32 + 8 + self.seat_id.len() + 8 + 48 + 129);
        out.extend_from_slice(PARTIAL_SHARE_MAGIC);
        out.extend_from_slice(&self.object_digest);
        out.extend_from_slice(&(self.row_index as u32).to_be_bytes());
        out.extend_from_slice(&self.row_locator);
        lp64_str(&mut out, &self.seat_id);
        out.extend_from_slice(&self.policy_epoch.to_be_bytes());
        out.extend_from_slice(&G1Affine::from(self.share_g1).to_compressed());
        self.proof.encode_into(&mut out);
        out
    }

    /// Deserialize a [`PartialDecryptionShare`] from canonical `CHWGSHR2` bytes, validating
    /// curve + prime-$r$ subgroup membership (`Lim–Lee` gate) on every $\mathbb{G}_1$ point.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AcuError> {
        let mut cursor = 0usize;
        let magic = take_slice(bytes, &mut cursor, 8)?;
        if magic != PARTIAL_SHARE_MAGIC {
            return Err(AcuError::SerializationError(
                "invalid PartialDecryptionShare magic",
            ));
        }
        let obj_slice = take_slice(bytes, &mut cursor, 32)?;
        let mut object_digest = [0u8; 32];
        object_digest.copy_from_slice(obj_slice);

        let row_index = read_u32_be(bytes, &mut cursor)? as usize;
        let loc_slice = take_slice(bytes, &mut cursor, 32)?;
        let mut row_locator = [0u8; 32];
        row_locator.copy_from_slice(loc_slice);

        let seat_id = read_lp64_str(bytes, &mut cursor, MAX_SEAT_ID_BYTES)?;
        if !is_valid_seat_id(&seat_id) {
            return Err(AcuError::InvalidSeatId);
        }
        let policy_epoch = read_u64_be(bytes, &mut cursor)?;
        if policy_epoch == 0 {
            return Err(AcuError::SerializationError("policy_epoch must be >= 1"));
        }
        let share_g1 = read_g1_compressed(bytes, &mut cursor)?;
        let proof = DleqProof::decode_from(bytes, &mut cursor)?;
        if cursor != bytes.len() {
            return Err(AcuError::SerializationError(
                "trailing bytes in PartialDecryptionShare",
            ));
        }
        Ok(Self {
            object_digest,
            row_index,
            row_locator,
            seat_id,
            policy_epoch,
            share_g1,
            proof,
        })
    }
}

/// `64`-byte pure-$\mathbb{G}_1$ strong Fiat–Shamir Schnorr proof of row randomness knowledge
/// (`ePrint v2` §6.1 Step 2, §6.3 Ops 1–2, Remark 1 & Theorem 3(iii)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowPok {
    /// Fiat–Shamir challenge $\mathsf{ch}^{\mathsf{row}}_j \in \mathbb{F}_r^*$.
    pub challenge: Scalar,
    /// Schnorr response $z^{\mathsf{row}}_j = u_j + \mathsf{ch}^{\mathsf{row}}_j r_j \pmod{r}$.
    pub response: Scalar,
}

impl RowPok {
    /// Encode `(challenge, response)` into `64` canonical bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.challenge.to_bytes());
        out[32..].copy_from_slice(&self.response.to_bytes());
        out
    }

    /// Decode `(challenge, response)` from `64` canonical bytes.
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, AcuError> {
        let mut cursor = 0usize;
        let challenge = read_scalar(bytes, &mut cursor)?;
        let response = read_scalar(bytes, &mut cursor)?;
        if bool::from(challenge.is_zero()) || bool::from(response.is_zero()) {
            return Err(AcuError::InvalidRowPok);
        }
        Ok(Self {
            challenge,
            response,
        })
    }
}

/// Signed/verifiable homomorphic row-rerandomization step attached during `revoke_and_rerandomize`
/// or `escalate_threshold` (`ePrint v2` §6.3 Ops 1–2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowUpdateProof {
    /// Target epoch $E \ge 2$ of this update.
    pub epoch: u64,
    /// Digest $h_{H_{E-1}}$ of the predecessor header.
    pub prev_header_digest: [u8; 32],
    /// Row index $j$ at `epoch`.
    pub row_index: u32,
    /// Additive shift $\Delta c_{j,1} = \delta_j G_1 + r'_j pk_{\rho(j)} \in \mathbb{G}_1$.
    pub delta_c1: G1Projective,
    /// Randomness delta $\Delta c_{j,2} = r'_j G_1 \in \mathbb{G}_1^*$.
    pub delta_c2: G1Projective,
    /// `64`-byte Schnorr proof of knowledge of $r'_j$ in $\Delta c_{j,2} = r'_j G_1$.
    pub pok: RowPok,
}

/// Prove initial row randomness knowledge $\pi^{\mathsf{row}}_j$ for $c_{j,2} = r_j G_1$ bound to
/// `(object_digest, init_matrix_digest, init_epoch, init_row_index, row_locator, G_1, pk_i, c_{j,1}, c_{j,2})`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_row_pok(
    object_digest: &[u8; 32],
    init_matrix_digest: &[u8; 32],
    init_epoch: u64,
    init_row_index: u32,
    row_locator: &[u8; 32],
    pk1: &G1Projective,
    c1: &G1Projective,
    c2: &G1Projective,
    r_j: &Scalar,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<RowPok, AcuError> {
    if bool::from(r_j.is_zero()) {
        return Err(AcuError::InvalidSecretKey);
    }
    let pk1_aff = G1Affine::from(*pk1);
    let c1_aff = G1Affine::from(*c1);
    let c2_aff = G1Affine::from(*c2);
    if bool::from(c2_aff.is_identity()) {
        return Err(AcuError::InvalidRowPok);
    }

    let mut r_bytes = Zeroizing::new(r_j.to_bytes());
    let mut rnd_hedge = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut rnd_hedge[..]);
    let mut ikm = Zeroizing::new([0u8; 96]);
    ikm[..32].copy_from_slice(&*r_bytes);
    r_bytes.zeroize();
    ikm[32..64].copy_from_slice(&*rnd_hedge);
    rnd_hedge.zeroize();
    ikm[64..96].copy_from_slice(object_digest);

    let hk = Hkdf::<Sha256>::new(Some(ROW_POK_NONCE_SALT), &*ikm);
    let g1 = G1Projective::generator();

    for ctr in 0u32.. {
        let mut info = Vec::with_capacity(ROW_POK_NONCE_INFO.len() + 8);
        info.extend_from_slice(ROW_POK_NONCE_INFO);
        info.extend_from_slice(&init_row_index.to_be_bytes());
        info.extend_from_slice(&ctr.to_be_bytes());

        let mut wide = Zeroizing::new([0u8; 64]);
        hk.expand(&info, &mut *wide)
            .map_err(|_| AcuError::InvalidRowPok)?;
        let mut u_j = Scalar::from_bytes_wide(&wide);
        wide.zeroize();
        if bool::from(u_j.is_zero()) {
            continue;
        }
        let u_g1_aff = G1Affine::from(g1 * u_j);
        if bool::from(u_g1_aff.is_identity()) {
            u_j.zeroize();
            continue;
        }
        let ch = compute_row_pok_challenge(
            object_digest,
            init_matrix_digest,
            init_epoch,
            init_row_index,
            row_locator,
            &pk1_aff,
            &c1_aff,
            &c2_aff,
            &u_g1_aff,
        )?;
        let z = u_j + ch * *r_j;
        u_j.zeroize();
        if !bool::from(z.is_zero()) {
            return Ok(RowPok {
                challenge: ch,
                response: z,
            });
        }
    }
    unreachable!("unbounded counter finds valid RowPok nonce w.h.p.")
}

/// Verify initial row randomness proof $\pi^{\mathsf{row}}_j$ in constant time.
#[allow(clippy::too_many_arguments)]
pub fn verify_initial_row_pok(
    object_digest: &[u8; 32],
    init_matrix_digest: &[u8; 32],
    init_epoch: u64,
    init_row_index: u32,
    row_locator: &[u8; 32],
    pk1: &G1Projective,
    c1: &G1Projective,
    c2: &G1Projective,
    pok: &RowPok,
) -> bool {
    if init_epoch == 0 || bool::from(pok.challenge.is_zero()) || bool::from(pok.response.is_zero())
    {
        return false;
    }
    let pk1_aff = G1Affine::from(*pk1);
    let c1_aff = G1Affine::from(*c1);
    let c2_aff = G1Affine::from(*c2);
    if bool::from(pk1_aff.is_identity())
        || !bool::from(pk1_aff.is_torsion_free())
        || !bool::from(c1_aff.is_torsion_free())
        || bool::from(c2_aff.is_identity())
        || !bool::from(c2_aff.is_torsion_free())
    {
        return false;
    }
    let u_g1 = G1Projective::generator() * pok.response - *c2 * pok.challenge;
    let u_g1_aff = G1Affine::from(u_g1);
    if bool::from(u_g1_aff.is_identity()) {
        return false;
    }
    let Ok(expected) = compute_row_pok_challenge(
        object_digest,
        init_matrix_digest,
        init_epoch,
        init_row_index,
        row_locator,
        &pk1_aff,
        &c1_aff,
        &c2_aff,
        &u_g1_aff,
    ) else {
        return false;
    };
    bool::from(pok.challenge.to_bytes().ct_eq(&expected.to_bytes()))
}

#[allow(clippy::too_many_arguments)]
fn compute_row_pok_challenge(
    object_digest: &[u8; 32],
    init_matrix_digest: &[u8; 32],
    init_epoch: u64,
    init_row_index: u32,
    row_locator: &[u8; 32],
    pk1_aff: &G1Affine,
    c1_aff: &G1Affine,
    c2_aff: &G1Affine,
    u_g1_aff: &G1Affine,
) -> Result<Scalar, AcuError> {
    let mut msg = Vec::with_capacity(64 + 8 + 4 + 32 + 48 * 5);
    msg.extend_from_slice(object_digest);
    msg.extend_from_slice(init_matrix_digest);
    msg.extend_from_slice(&init_epoch.to_be_bytes());
    msg.extend_from_slice(&init_row_index.to_be_bytes());
    msg.extend_from_slice(row_locator);
    msg.extend_from_slice(&G1Affine::generator().to_compressed());
    msg.extend_from_slice(&pk1_aff.to_compressed());
    msg.extend_from_slice(&c1_aff.to_compressed());
    msg.extend_from_slice(&c2_aff.to_compressed());
    msg.extend_from_slice(&u_g1_aff.to_compressed());
    hash_to_nonzero_scalar(&msg, ROW_POK_DST)
}

/// Prove epoch-rerandomization randomness knowledge $\pi^{\mathsf{upd}}_{E,j}$ for $\Delta c_{j,2} = r'_j G_1$.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove_update_row_pok(
    object_digest: &[u8; 32],
    epoch: u64,
    prev_header_digest: &[u8; 32],
    row_index: u32,
    pk1: &G1Projective,
    delta_c1: &G1Projective,
    delta_c2: &G1Projective,
    r_prime: &Scalar,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<RowPok, AcuError> {
    if epoch < 2 || bool::from(r_prime.is_zero()) {
        return Err(AcuError::InvalidRowPok);
    }
    let pk1_aff = G1Affine::from(*pk1);
    let dc1_aff = G1Affine::from(*delta_c1);
    let dc2_aff = G1Affine::from(*delta_c2);
    if bool::from(dc2_aff.is_identity()) {
        return Err(AcuError::InvalidRowPok);
    }

    let mut r_bytes = Zeroizing::new(r_prime.to_bytes());
    let mut rnd_hedge = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut rnd_hedge[..]);
    let mut ikm = Zeroizing::new([0u8; 96]);
    ikm[..32].copy_from_slice(&*r_bytes);
    r_bytes.zeroize();
    ikm[32..64].copy_from_slice(&*rnd_hedge);
    rnd_hedge.zeroize();
    ikm[64..96].copy_from_slice(prev_header_digest);

    let hk = Hkdf::<Sha256>::new(Some(ROW_POK_NONCE_SALT), &*ikm);
    let g1 = G1Projective::generator();

    for ctr in 0u32.. {
        let mut info = Vec::with_capacity(ROW_POK_NONCE_INFO.len() + 12);
        info.extend_from_slice(ROW_POK_NONCE_INFO);
        info.extend_from_slice(&epoch.to_be_bytes());
        info.extend_from_slice(&ctr.to_be_bytes());

        let mut wide = Zeroizing::new([0u8; 64]);
        hk.expand(&info, &mut *wide)
            .map_err(|_| AcuError::InvalidRowPok)?;
        let mut u_j = Scalar::from_bytes_wide(&wide);
        wide.zeroize();
        if bool::from(u_j.is_zero()) {
            continue;
        }
        let u_g1_aff = G1Affine::from(g1 * u_j);
        if bool::from(u_g1_aff.is_identity()) {
            u_j.zeroize();
            continue;
        }
        let ch = compute_update_pok_challenge(
            object_digest,
            epoch,
            prev_header_digest,
            row_index,
            &pk1_aff,
            &dc1_aff,
            &dc2_aff,
            &u_g1_aff,
        )?;
        let z = u_j + ch * *r_prime;
        u_j.zeroize();
        if !bool::from(z.is_zero()) {
            return Ok(RowPok {
                challenge: ch,
                response: z,
            });
        }
    }
    unreachable!("unbounded counter finds valid update RowPok nonce w.h.p.")
}

/// Verify a single [`RowUpdateProof`] against `object_digest` and `pk1`.
pub fn verify_update_row_pok(
    object_digest: &[u8; 32],
    pk1: &G1Projective,
    upd: &RowUpdateProof,
) -> bool {
    if upd.epoch < 2
        || bool::from(upd.pok.challenge.is_zero())
        || bool::from(upd.pok.response.is_zero())
    {
        return false;
    }
    let pk1_aff = G1Affine::from(*pk1);
    let dc1_aff = G1Affine::from(upd.delta_c1);
    let dc2_aff = G1Affine::from(upd.delta_c2);
    if bool::from(pk1_aff.is_identity())
        || !bool::from(pk1_aff.is_torsion_free())
        || !bool::from(dc1_aff.is_torsion_free())
        || bool::from(dc2_aff.is_identity())
        || !bool::from(dc2_aff.is_torsion_free())
    {
        return false;
    }
    let u_g1 = G1Projective::generator() * upd.pok.response - upd.delta_c2 * upd.pok.challenge;
    let u_g1_aff = G1Affine::from(u_g1);
    if bool::from(u_g1_aff.is_identity()) {
        return false;
    }
    let Ok(expected) = compute_update_pok_challenge(
        object_digest,
        upd.epoch,
        &upd.prev_header_digest,
        upd.row_index,
        &pk1_aff,
        &dc1_aff,
        &dc2_aff,
        &u_g1_aff,
    ) else {
        return false;
    };
    bool::from(upd.pok.challenge.to_bytes().ct_eq(&expected.to_bytes()))
}

#[allow(clippy::too_many_arguments)]
fn compute_update_pok_challenge(
    object_digest: &[u8; 32],
    epoch: u64,
    prev_header_digest: &[u8; 32],
    row_index: u32,
    pk1_aff: &G1Affine,
    dc1_aff: &G1Affine,
    dc2_aff: &G1Affine,
    u_g1_aff: &G1Affine,
) -> Result<Scalar, AcuError> {
    let mut msg = Vec::with_capacity(32 + 8 + 32 + 4 + 48 * 5);
    msg.extend_from_slice(object_digest);
    msg.extend_from_slice(&epoch.to_be_bytes());
    msg.extend_from_slice(prev_header_digest);
    msg.extend_from_slice(&row_index.to_be_bytes());
    msg.extend_from_slice(&G1Affine::generator().to_compressed());
    msg.extend_from_slice(&pk1_aff.to_compressed());
    msg.extend_from_slice(&dc1_aff.to_compressed());
    msg.extend_from_slice(&dc2_aff.to_compressed());
    msg.extend_from_slice(&u_g1_aff.to_compressed());
    hash_to_nonzero_scalar(&msg, ROW_UPD_POK_DST)
}

/// Verify the complete row-randomness proof chain (`init_c1/init_c2` + `row_pok` + all homomorphic
/// `updates`) for `row` against `object_digest` and `seat_pk` (`Theorem 3(iii)` active-oracle gate).
#[must_use]
pub fn verify_row_randomness_chain(
    object_digest: &[u8; 32],
    row: &CiphertextRow,
    seat_pk: &SeatPublicKey,
) -> bool {
    let expected_final_idx = row
        .updates
        .last()
        .map_or(row.init_row_index, |u| u.row_index) as usize;
    if !seat_pk.verify_consistency()
        || row.seat_id != seat_pk.seat_id
        || row.row_index != expected_final_idx
        || !bool::from(row.object_digest.ct_eq(object_digest))
    {
        return false;
    }
    if !verify_initial_row_pok(
        object_digest,
        &row.init_matrix_digest,
        row.init_epoch,
        row.init_row_index,
        &row.row_locator,
        &seat_pk.pk1,
        &row.init_c1,
        &row.init_c2,
        &row.row_pok,
    ) {
        return false;
    }
    let mut folded_c1 = row.init_c1;
    let mut folded_c2 = row.init_c2;
    let mut last_epoch = row.init_epoch;
    for upd in &row.updates {
        if upd.epoch <= last_epoch || !verify_update_row_pok(object_digest, &seat_pk.pk1, upd) {
            return false;
        }
        last_epoch = upd.epoch;
        folded_c1 += upd.delta_c1;
        folded_c2 += upd.delta_c2;
    }
    folded_c1 == row.c1 && folded_c2 == row.c2
}

/// Emit a verifiable `48`-byte $\mathbb{G}_1$ partial decryption share $S_j = c_{j,1} - sk_i c_{j,2}$
/// with a strong Fiat–Shamir Chaum–Pedersen `DLEQ` proof in the requested [`DleqMode`].
pub fn emit_partial_share_with_mode(
    object_digest: &[u8; 32],
    row: &CiphertextRow,
    secret_key: &SeatSecretKey,
    policy_epoch: u64,
    mode: DleqMode,
) -> PartialDecryptionShare {
    let pk1 = G1Projective::generator() * secret_key.sk;
    let pk1_aff = G1Affine::from(pk1);
    let c1_aff = G1Affine::from(row.c1);
    let c2_aff = G1Affine::from(row.c2);

    let w_j = row.c2 * secret_key.sk;
    let share_g1 = row.c1 - w_j;
    let s_aff = G1Affine::from(share_g1);
    let w_aff = G1Affine::from(w_j);

    let mut sk_bytes = Zeroizing::new(secret_key.sk.to_bytes());
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 + 32 + 8 + 4 + 32 + 96));
    ikm.extend_from_slice(&*sk_bytes);
    sk_bytes.zeroize();
    ikm.extend_from_slice(object_digest);
    ikm.extend_from_slice(&policy_epoch.to_be_bytes());
    ikm.extend_from_slice(&(row.row_index as u32).to_be_bytes());
    ikm.extend_from_slice(&row.row_locator);
    ikm.extend_from_slice(&c1_aff.to_compressed());
    ikm.extend_from_slice(&c2_aff.to_compressed());

    let hk = Hkdf::<Sha256>::new(Some(DLEQ_NONCE_SALT), &ikm);
    let g1 = G1Projective::generator();

    for ctr in 0u32.. {
        let mut info = Vec::with_capacity(DLEQ_NONCE_INFO.len() + 4);
        info.extend_from_slice(DLEQ_NONCE_INFO);
        info.extend_from_slice(&ctr.to_be_bytes());

        let mut wide = Zeroizing::new([0u8; 64]);
        hk.expand(&info, &mut *wide)
            .expect("64-byte HKDF-SHA256 output is always valid");
        let mut t_j = Scalar::from_bytes_wide(&wide);
        wide.zeroize();
        if bool::from(t_j.is_zero()) {
            continue;
        }
        let r1 = g1 * t_j;
        let r2 = row.c2 * t_j;
        let r1_aff = G1Affine::from(r1);
        let r2_aff = G1Affine::from(r2);
        if bool::from(r1_aff.is_identity()) || bool::from(r2_aff.is_identity()) {
            t_j.zeroize();
            continue;
        }
        let Ok(ch) = compute_dleq_challenge(
            object_digest,
            policy_epoch,
            row.row_index as u32,
            &row.row_locator,
            &pk1_aff,
            &c1_aff,
            &c2_aff,
            &s_aff,
            &w_aff,
            &r1_aff,
            &r2_aff,
        ) else {
            t_j.zeroize();
            continue;
        };
        let z = t_j + ch * secret_key.sk;
        t_j.zeroize();
        if bool::from(z.is_zero()) {
            continue;
        }
        let proof = match mode {
            DleqMode::Compact => DleqProof::Compact {
                challenge: ch,
                response: z,
            },
            DleqMode::Batchable => DleqProof::Batchable {
                commitment_g1: r1,
                commitment_c2: r2,
                response: z,
            },
        };
        return PartialDecryptionShare {
            object_digest: *object_digest,
            row_index: row.row_index,
            row_locator: row.row_locator,
            seat_id: secret_key.seat_id.clone(),
            policy_epoch,
            share_g1,
            proof,
        };
    }
    unreachable!("unbounded counter finds valid DLEQ nonce on ctr = 0 w.h.p.")
}

/// Verify a single [`PartialDecryptionShare`] (Mode A `64` B or Mode B `128` B) purely in $\mathbb{G}_1$
/// (`0` pairings!) against `object_digest`, `expected_epoch`, `row`, and `seat_pk`.
#[must_use]
pub fn verify_partial_share_for_object(
    object_digest: &[u8; 32],
    expected_epoch: u64,
    row: &CiphertextRow,
    seat_pk: &SeatPublicKey,
    share: &PartialDecryptionShare,
) -> bool {
    if expected_epoch == 0
        || share.policy_epoch != expected_epoch
        || share.row_index != row.row_index
        || share.seat_id != row.seat_id
        || share.seat_id != seat_pk.seat_id
        || !bool::from(share.object_digest.ct_eq(object_digest))
        || !bool::from(share.row_locator.ct_eq(&row.row_locator))
        || !seat_pk.verify_consistency()
    {
        return false;
    }

    let pk1_aff = G1Affine::from(seat_pk.pk1);
    let c1_aff = G1Affine::from(row.c1);
    let c2_aff = G1Affine::from(row.c2);
    let s_aff = G1Affine::from(share.share_g1);
    if !bool::from(c1_aff.is_torsion_free())
        || bool::from(c2_aff.is_identity())
        || !bool::from(c2_aff.is_torsion_free())
        || !bool::from(s_aff.is_torsion_free())
    {
        return false;
    }

    let w_j = row.c1 - share.share_g1;
    let w_aff = G1Affine::from(w_j);

    match &share.proof {
        DleqProof::Compact {
            challenge,
            response,
        } => {
            if bool::from(challenge.is_zero()) || bool::from(response.is_zero()) {
                return false;
            }
            let r1 = G1Projective::generator() * *response - seat_pk.pk1 * *challenge;
            let r2 = row.c2 * *response - w_j * *challenge;
            let r1_aff = G1Affine::from(r1);
            let r2_aff = G1Affine::from(r2);
            if bool::from(r1_aff.is_identity()) || bool::from(r2_aff.is_identity()) {
                return false;
            }
            let Ok(expected_ch) = compute_dleq_challenge(
                object_digest,
                expected_epoch,
                row.row_index as u32,
                &row.row_locator,
                &pk1_aff,
                &c1_aff,
                &c2_aff,
                &s_aff,
                &w_aff,
                &r1_aff,
                &r2_aff,
            ) else {
                return false;
            };
            bool::from(challenge.to_bytes().ct_eq(&expected_ch.to_bytes()))
        }
        DleqProof::Batchable {
            commitment_g1,
            commitment_c2,
            response,
        } => {
            if bool::from(response.is_zero()) {
                return false;
            }
            let r1_aff = G1Affine::from(*commitment_g1);
            let r2_aff = G1Affine::from(*commitment_c2);
            if bool::from(r1_aff.is_identity())
                || !bool::from(r1_aff.is_torsion_free())
                || bool::from(r2_aff.is_identity())
                || !bool::from(r2_aff.is_torsion_free())
            {
                return false;
            }
            let Ok(ch) = compute_dleq_challenge(
                object_digest,
                expected_epoch,
                row.row_index as u32,
                &row.row_locator,
                &pk1_aff,
                &c1_aff,
                &c2_aff,
                &s_aff,
                &w_aff,
                &r1_aff,
                &r2_aff,
            ) else {
                return false;
            };
            let leg1 = G1Projective::generator() * *response - seat_pk.pk1 * ch - *commitment_g1;
            let leg2 = row.c2 * *response - w_j * ch - *commitment_c2;
            bool::from(leg1.is_identity()) && bool::from(leg2.is_identity())
        }
    }
}

/// Batch-verify a slice of Mode B (`128`-byte [`DleqProof::Batchable`]) partial shares using
/// **two independent 128-bit CSPRNG weights** $(\alpha_j, \beta_j)$ per row (`CHWG-PAT-11B-v2` `[0013]`):
///
/// $$\Bigl(\sum_j \alpha_j z_j\Bigr) G_1 - \sum_j (\alpha_j \mathsf{ch}_j) pk_{\rho(j)} - \sum_j \alpha_j R_{j,1}
///   + \sum_j (\beta_j z_j) c_{j,2} - \sum_j (\beta_j \mathsf{ch}_j) W_j - \sum_j \beta_j R_{j,2} = \mathcal{O}.$$
///
/// If any share uses Mode A (`Compact`), falls back cleanly to individual constant-time verification
/// on that share while batch-verifying all Mode B shares.
pub fn batch_verify_partial_shares_with_rng(
    object_digest: &[u8; 32],
    expected_epoch: u64,
    rows: &[CiphertextRow],
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    shares: &[PartialDecryptionShare],
    rng: &mut (impl RngCore + CryptoRng),
) -> bool {
    if expected_epoch == 0 || shares.is_empty() {
        return false;
    }

    let mut sum_alpha_z = Scalar::ZERO;
    let mut acc = G1Projective::identity();
    let mut saw_batchable = false;

    for share in shares {
        let Some(row) = rows.get(share.row_index) else {
            return false;
        };
        let Some(seat_pk) = seat_keys.get(&row.seat_id) else {
            return false;
        };
        if share.policy_epoch != expected_epoch
            || share.seat_id != row.seat_id
            || share.seat_id != seat_pk.seat_id
            || !bool::from(share.object_digest.ct_eq(object_digest))
            || !bool::from(share.row_locator.ct_eq(&row.row_locator))
            || !seat_pk.verify_consistency()
        {
            return false;
        }

        match &share.proof {
            DleqProof::Compact { .. } => {
                if !verify_partial_share_for_object(
                    object_digest,
                    expected_epoch,
                    row,
                    seat_pk,
                    share,
                ) {
                    return false;
                }
            }
            DleqProof::Batchable {
                commitment_g1,
                commitment_c2,
                response,
            } => {
                if bool::from(response.is_zero()) {
                    return false;
                }
                let pk1_aff = G1Affine::from(seat_pk.pk1);
                let c1_aff = G1Affine::from(row.c1);
                let c2_aff = G1Affine::from(row.c2);
                let s_aff = G1Affine::from(share.share_g1);
                let r1_aff = G1Affine::from(*commitment_g1);
                let r2_aff = G1Affine::from(*commitment_c2);
                if !bool::from(c1_aff.is_torsion_free())
                    || bool::from(c2_aff.is_identity())
                    || !bool::from(c2_aff.is_torsion_free())
                    || !bool::from(s_aff.is_torsion_free())
                    || bool::from(r1_aff.is_identity())
                    || !bool::from(r1_aff.is_torsion_free())
                    || bool::from(r2_aff.is_identity())
                    || !bool::from(r2_aff.is_torsion_free())
                {
                    return false;
                }
                let w_j = row.c1 - share.share_g1;
                let w_aff = G1Affine::from(w_j);
                let Ok(ch) = compute_dleq_challenge(
                    object_digest,
                    expected_epoch,
                    row.row_index as u32,
                    &row.row_locator,
                    &pk1_aff,
                    &c1_aff,
                    &c2_aff,
                    &s_aff,
                    &w_aff,
                    &r1_aff,
                    &r2_aff,
                ) else {
                    return false;
                };

                // Sample two independent 128-bit non-zero weights (alpha_j, beta_j) so Leg 1 and Leg 2
                // can never cancel or collapse into a single-leg check.
                let alpha = sample_nonzero_u128_scalar(rng);
                let beta = sample_nonzero_u128_scalar(rng);

                sum_alpha_z += alpha * *response;
                acc -= seat_pk.pk1 * (alpha * ch);
                acc -= *commitment_g1 * alpha;
                acc += row.c2 * (beta * *response);
                acc -= w_j * (beta * ch);
                acc -= *commitment_c2 * beta;
                saw_batchable = true;
            }
        }
    }

    if !saw_batchable {
        return true;
    }
    acc += G1Projective::generator() * sum_alpha_z;
    bool::from(acc.is_identity())
}

/// Batch-verify [`PartialDecryptionShare`]s using `OsRng` for 128-bit $(\alpha_j, \beta_j)$ weights.
#[must_use]
pub fn batch_verify_partial_shares(
    object_digest: &[u8; 32],
    expected_epoch: u64,
    rows: &[CiphertextRow],
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    shares: &[PartialDecryptionShare],
) -> bool {
    batch_verify_partial_shares_with_rng(
        object_digest,
        expected_epoch,
        rows,
        seat_keys,
        shares,
        &mut OsRng,
    )
}

/// Recursive binary-splitting fault isolation (`CHWG-PAT-11B-v2` `[0014]`): returns the sorted
/// slice indices (`0..shares.len()`) of every invalid [`PartialDecryptionShare`] in $O(b \log |\Gamma|)$
/// batch checks.
pub fn isolate_invalid_partial_shares(
    object_digest: &[u8; 32],
    expected_epoch: u64,
    rows: &[CiphertextRow],
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    shares: &[PartialDecryptionShare],
    rng: &mut (impl RngCore + CryptoRng),
) -> Vec<usize> {
    if shares.is_empty() {
        return Vec::new();
    }
    let mut bad = Vec::new();
    isolate_recursive(
        object_digest,
        expected_epoch,
        rows,
        seat_keys,
        shares,
        0,
        &mut bad,
        rng,
    );
    bad
}

#[allow(clippy::too_many_arguments)]
fn isolate_recursive(
    object_digest: &[u8; 32],
    expected_epoch: u64,
    rows: &[CiphertextRow],
    seat_keys: &BTreeMap<String, SeatPublicKey>,
    sub: &[PartialDecryptionShare],
    base_offset: usize,
    out_bad: &mut Vec<usize>,
    rng: &mut (impl RngCore + CryptoRng),
) {
    if sub.is_empty() {
        return;
    }
    if batch_verify_partial_shares_with_rng(
        object_digest,
        expected_epoch,
        rows,
        seat_keys,
        sub,
        rng,
    ) {
        return;
    }
    if sub.len() == 1 {
        let share = &sub[0];
        let valid = rows
            .get(share.row_index)
            .and_then(|r| seat_keys.get(&r.seat_id).map(|pk| (r, pk)))
            .is_some_and(|(r, pk)| {
                verify_partial_share_for_object(object_digest, expected_epoch, r, pk, share)
            });
        if !valid {
            out_bad.push(base_offset);
        }
        return;
    }
    let mid = sub.len() / 2;
    isolate_recursive(
        object_digest,
        expected_epoch,
        rows,
        seat_keys,
        &sub[..mid],
        base_offset,
        out_bad,
        rng,
    );
    isolate_recursive(
        object_digest,
        expected_epoch,
        rows,
        seat_keys,
        &sub[mid..],
        base_offset + mid,
        out_bad,
        rng,
    );
}

fn sample_nonzero_u128_scalar(rng: &mut (impl RngCore + CryptoRng)) -> Scalar {
    loop {
        let mut raw = [0u8; 32];
        rng.fill_bytes(&mut raw[..16]);
        if !bool::from(raw[..16].ct_eq(&[0u8; 16])) {
            return Scalar::from_bytes(&raw).expect("128-bit value is strictly < BLS12-381 r");
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn compute_dleq_challenge(
    object_digest: &[u8; 32],
    epoch: u64,
    row_index: u32,
    row_locator: &[u8; 32],
    pk1_aff: &G1Affine,
    c1_aff: &G1Affine,
    c2_aff: &G1Affine,
    s_aff: &G1Affine,
    w_aff: &G1Affine,
    r1_aff: &G1Affine,
    r2_aff: &G1Affine,
) -> Result<Scalar, AcuError> {
    let mut msg = Vec::with_capacity(32 + 8 + 4 + 32 + 48 * 8);
    msg.extend_from_slice(object_digest);
    msg.extend_from_slice(&epoch.to_be_bytes());
    msg.extend_from_slice(&row_index.to_be_bytes());
    msg.extend_from_slice(row_locator);
    msg.extend_from_slice(&G1Affine::generator().to_compressed());
    msg.extend_from_slice(&pk1_aff.to_compressed());
    msg.extend_from_slice(&c1_aff.to_compressed());
    msg.extend_from_slice(&c2_aff.to_compressed());
    msg.extend_from_slice(&s_aff.to_compressed());
    msg.extend_from_slice(&w_aff.to_compressed());
    msg.extend_from_slice(&r1_aff.to_compressed());
    msg.extend_from_slice(&r2_aff.to_compressed());
    hash_to_nonzero_scalar(&msg, DLEQ_CHALLENGE_DST)
}
