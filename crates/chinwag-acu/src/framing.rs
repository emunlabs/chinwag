// Copyright (c) 2026 Emun Labs, Inc. (1401 Lavaca St STE 81335, Austin, TX 78701)
// SPDX-License-Identifier: Apache-2.0

//! Canonical length-prefixed binary framing (`LP`), zero-heap canonical `576`-byte
//! $\mathbb{F}_{p^{12}}$ (`bls12_381::Gt`) extraction, and RFC 9380 `expand_message_xmd`
//! (`SHA-256`, `L = 48`) hash-to-scalar derivation over $\mathbb{F}_r$.

use crate::AcuError;
use bls12_381::{G1Affine, G1Projective, Gt, Scalar};
use core::fmt;
use ff::Field;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// Canonical byte length of a `BLS12-381` target-group element in $\mathbb{F}_{p^{12}} = (\mathbb{F}_p)^{12}$
/// (`12` canonical big-endian $\mathbb{F}_p$ limbs $\times$ `48` bytes/limb = `576` bytes).
pub const GT_CANONICAL_BYTES: usize = 576;

/// Big-endian `BLS12-381` base-field prime modulus $p$ (`381` bits in `48` bytes):
/// `0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab`.
const BLS12_381_FP_MODULUS_BE: [u8; 48] = [
    0x1a, 0x01, 0x11, 0xea, 0x39, 0x7f, 0xe6, 0x9a, 0x4b, 0x1b, 0xa7, 0xb6, 0x43, 0x4b, 0xac, 0xd7,
    0x64, 0x77, 0x4b, 0x84, 0xf3, 0x85, 0x12, 0xbf, 0x67, 0x30, 0xd2, 0xa0, 0xf6, 0xb0, 0xf6, 0x24,
    0x1e, 0xab, 0xff, 0xfe, 0xb1, 0x53, 0xff, 0xff, 0xb9, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xab,
];

/// Append injective 64-bit big-endian length-prefixed bytes `LP(x) = u64be(x.len()) || x`.
#[inline]
pub fn lp64(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Alias for [`lp64`] used across protocol and archive binary framing.
#[inline]
pub fn lp64_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    lp64(out, bytes);
}

/// Append injective 64-bit big-endian length-prefixed UTF-8 string `LP(s)`.
#[inline]
pub fn lp64_str(out: &mut Vec<u8>, s: &str) {
    lp64(out, s.as_bytes());
}

/// Read an exact `len`-byte slice from `bytes` advancing `cursor`, or fail closed on truncation.
#[inline]
pub fn take_slice<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    len: usize,
) -> Result<&'a [u8], AcuError> {
    let end = cursor
        .checked_add(len)
        .ok_or(AcuError::SerializationError("cursor overflow"))?;
    if end > bytes.len() {
        return Err(AcuError::SerializationError("unexpected EOF"));
    }
    let slice = &bytes[*cursor..end];
    *cursor = end;
    Ok(slice)
}

/// Read a single `u8` advancing `cursor`.
#[inline]
pub fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, AcuError> {
    let slice = take_slice(bytes, cursor, 1)?;
    Ok(slice[0])
}

/// Read a big-endian `u16` advancing `cursor`.
#[inline]
pub fn read_u16_be(bytes: &[u8], cursor: &mut usize) -> Result<u16, AcuError> {
    let slice = take_slice(bytes, cursor, 2)?;
    let mut arr = [0u8; 2];
    arr.copy_from_slice(slice);
    Ok(u16::from_be_bytes(arr))
}

/// Read a big-endian `u32` advancing `cursor`.
#[inline]
pub fn read_u32_be(bytes: &[u8], cursor: &mut usize) -> Result<u32, AcuError> {
    let slice = take_slice(bytes, cursor, 4)?;
    let mut arr = [0u8; 4];
    arr.copy_from_slice(slice);
    Ok(u32::from_be_bytes(arr))
}

/// Read a big-endian `u64` advancing `cursor`.
#[inline]
pub fn read_u64_be(bytes: &[u8], cursor: &mut usize) -> Result<u64, AcuError> {
    let slice = take_slice(bytes, cursor, 8)?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(slice);
    Ok(u64::from_be_bytes(arr))
}

/// Read a 64-bit big-endian length-prefixed slice bounded by `max_len`.
pub fn read_lp64<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    max_len: usize,
) -> Result<&'a [u8], AcuError> {
    let raw_len = read_u64_be(bytes, cursor)?;
    let len = usize::try_from(raw_len)
        .map_err(|_| AcuError::SerializationError("LP64 length overflow"))?;
    if len > max_len {
        return Err(AcuError::SerializationError("LP64 field exceeds max_len"));
    }
    take_slice(bytes, cursor, len)
}

/// Alias for [`read_lp64`] used across protocol and archive binary framing.
#[inline]
pub fn read_lp64_bytes<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    max_len: usize,
) -> Result<&'a [u8], AcuError> {
    read_lp64(bytes, cursor, max_len)
}

/// Read a 64-bit big-endian length-prefixed UTF-8 string bounded by `max_len`.
pub fn read_lp64_str(bytes: &[u8], cursor: &mut usize, max_len: usize) -> Result<String, AcuError> {
    let slice = read_lp64(bytes, cursor, max_len)?;
    let s = std::str::from_utf8(slice)
        .map_err(|_| AcuError::SerializationError("LP64 string is not valid UTF-8"))?;
    Ok(s.to_string())
}

/// Read a canonical compressed `48`-byte `BLS12-381` $\mathbb{G}_1$ point (enforcing curve + prime-$r$
/// torsion-free subgroup membership via `G1Affine::from_compressed`).
pub fn read_g1_compressed(bytes: &[u8], cursor: &mut usize) -> Result<G1Projective, AcuError> {
    let slice = take_slice(bytes, cursor, 48)?;
    let mut arr = [0u8; 48];
    arr.copy_from_slice(slice);
    let aff: Option<G1Affine> = G1Affine::from_compressed(&arr).into();
    let aff = aff.ok_or(AcuError::SerializationError(
        "invalid compressed G1 point or subgroup violation",
    ))?;
    Ok(G1Projective::from(aff))
}

/// Read a canonical compressed `48`-byte non-identity `BLS12-381` $\mathbb{G}_1^*$ point.
pub fn read_nonidentity_g1_compressed(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<G1Projective, AcuError> {
    let pt = read_g1_compressed(bytes, cursor)?;
    if bool::from(pt.is_identity()) {
        return Err(AcuError::SerializationError(
            "unexpected identity G1 point on wire",
        ));
    }
    Ok(pt)
}

/// Read a canonical `32`-byte little-endian $\mathbb{F}_r$ scalar (`< r`).
pub fn read_scalar(bytes: &[u8], cursor: &mut usize) -> Result<Scalar, AcuError> {
    let slice = take_slice(bytes, cursor, 32)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(slice);
    let scalar: Option<Scalar> = Scalar::from_bytes(&arr).into();
    scalar.ok_or(AcuError::SerializationError("non-canonical F_r scalar"))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GtParseState {
    SeekingZero,
    SawZero,
    ReadingHex { nibble_idx: u8, hi_nibble: u8 },
    AfterHex,
}

struct GtCanonicalSink {
    out: Zeroizing<[u8; GT_CANONICAL_BYTES]>,
    limb_idx: usize,
    state: GtParseState,
    failed: bool,
}

impl Drop for GtCanonicalSink {
    fn drop(&mut self) {
        if let GtParseState::ReadingHex {
            ref mut hi_nibble, ..
        } = self.state
        {
            hi_nibble.zeroize();
        }
    }
}

impl fmt::Write for GtCanonicalSink {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.failed {
            return Err(fmt::Error);
        }
        for b in s.bytes() {
            match self.state {
                GtParseState::SeekingZero => {
                    if b == b'0' {
                        self.state = GtParseState::SawZero;
                    }
                }
                GtParseState::SawZero => {
                    if b == b'x' {
                        if self.limb_idx >= 12 {
                            self.failed = true;
                            return Err(fmt::Error);
                        }
                        self.state = GtParseState::ReadingHex {
                            nibble_idx: 0,
                            hi_nibble: 0,
                        };
                    } else if b == b'0' {
                        self.state = GtParseState::SawZero;
                    } else {
                        self.state = GtParseState::SeekingZero;
                    }
                }
                GtParseState::ReadingHex {
                    nibble_idx,
                    mut hi_nibble,
                } => {
                    let Some(val) = decode_lowercase_hex_nibble(b) else {
                        hi_nibble.zeroize();
                        self.failed = true;
                        return Err(fmt::Error);
                    };
                    if (nibble_idx & 1) == 0 {
                        self.state = GtParseState::ReadingHex {
                            nibble_idx: nibble_idx + 1,
                            hi_nibble: val,
                        };
                    } else {
                        let byte_offset = self.limb_idx * 48 + (nibble_idx as usize / 2);
                        self.out[byte_offset] = (hi_nibble << 4) | val;
                        hi_nibble.zeroize();
                        if nibble_idx == 95 {
                            self.limb_idx += 1;
                            self.state = GtParseState::AfterHex;
                        } else {
                            self.state = GtParseState::ReadingHex {
                                nibble_idx: nibble_idx + 1,
                                hi_nibble: 0,
                            };
                        }
                    }
                }
                GtParseState::AfterHex => {
                    if decode_lowercase_hex_nibble(b).is_some() {
                        // Reject overlong (> 96 nibble) hex limb fail-closed.
                        self.failed = true;
                        return Err(fmt::Error);
                    }
                    if b == b'0' {
                        self.state = GtParseState::SawZero;
                    } else {
                        self.state = GtParseState::SeekingZero;
                    }
                }
            }
        }
        Ok(())
    }
}

#[inline]
const fn decode_lowercase_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Extract the unique, canonical `576`-byte big-endian $\mathbb{F}_{p^{12}} = (\mathbb{F}_p)^{12}$
/// representation of a `bls12_381::Gt` element into a stack-allocated [`Zeroizing<[u8; 576]>`].
///
/// Because `bls12_381 = "=0.8.0"` keeps `Gt`'s inner `Fp12` field `pub(crate)` without exposing
/// `Gt::to_bytes()` and `chinwag-acu` enforces `#![forbid(unsafe_code)]`, this function streams
/// `Fp`'s canonical `48`-byte big-endian Montgomery-reduced limbs through a stack-only
/// `core::fmt::Write` state machine (with **zero** heap `String` allocations and **zero**
/// `format!()` macro calls), enforcing:
/// 1. Exact `12` limbs $\times$ `48` bytes (`576` bytes total),
/// 2. Strict lowercase hex grammar per `0x`-prefixed limb, and
/// 3. Strict canonical base-field bound `< p` on all `12` limbs.
pub fn gt_canonical_bytes(element: &Gt) -> Result<Zeroizing<[u8; GT_CANONICAL_BYTES]>, AcuError> {
    let mut sink = GtCanonicalSink {
        out: Zeroizing::new([0u8; GT_CANONICAL_BYTES]),
        limb_idx: 0,
        state: GtParseState::SeekingZero,
        failed: false,
    };
    if fmt::write(&mut sink, format_args!("{element}")).is_err()
        || sink.failed
        || sink.limb_idx != 12
        || !matches!(
            sink.state,
            GtParseState::SeekingZero | GtParseState::AfterHex
        )
    {
        return Err(AcuError::SerializationError(
            "canonical Gt Fp12 extraction failed",
        ));
    }

    for limb in sink.out.chunks_exact(48) {
        if limb >= BLS12_381_FP_MODULUS_BE.as_slice() {
            return Err(AcuError::SerializationError(
                "non-canonical Fp limb >= p in Gt",
            ));
        }
    }

    let mut result = Zeroizing::new([0u8; GT_CANONICAL_BYTES]);
    result.copy_from_slice(&*sink.out);
    Ok(result)
}

/// RFC 9380 §5.3.1 `expand_message_xmd` instantiated with `SHA-256` (`b_in_bytes = 32`, `s_in_bytes = 64`).
pub fn expand_message_xmd_sha256(
    msg: &[u8],
    dst: &[u8],
    len_in_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, AcuError> {
    const B_IN_BYTES: usize = 32;
    const S_IN_BYTES: usize = 64;

    if dst.is_empty() {
        return Err(AcuError::InvalidMetadata);
    }
    let ell = len_in_bytes.div_ceil(B_IN_BYTES);
    if ell > 255 || len_in_bytes > 65535 || len_in_bytes == 0 {
        return Err(AcuError::SerializationError(
            "expand_message_xmd length out of RFC 9380 bounds",
        ));
    }

    // RFC 9380 §5.3.3: oversize DST (> 255 bytes) hashes down with "H2C-OVERSIZE-DST-".
    let hashed_dst: [u8; 32];
    let effective_dst: &[u8] = if dst.len() > 255 {
        let mut h = Sha256::new();
        h.update(b"H2C-OVERSIZE-DST-");
        h.update(dst);
        hashed_dst = h.finalize().into();
        &hashed_dst
    } else {
        dst
    };
    let dst_len_byte = effective_dst.len() as u8;

    let z_pad = [0u8; S_IN_BYTES];
    let l_i_b_str = (len_in_bytes as u16).to_be_bytes();

    // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
    let mut h0 = Sha256::new();
    h0.update(z_pad);
    h0.update(msg);
    h0.update(l_i_b_str);
    h0.update([0u8]);
    h0.update(effective_dst);
    h0.update([dst_len_byte]);
    let mut b0 = Zeroizing::new([0u8; B_IN_BYTES]);
    b0.copy_from_slice(&h0.finalize());

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let mut h1 = Sha256::new();
    h1.update(*b0);
    h1.update([1u8]);
    h1.update(effective_dst);
    h1.update([dst_len_byte]);
    let mut b_prev = Zeroizing::new([0u8; B_IN_BYTES]);
    b_prev.copy_from_slice(&h1.finalize());

    let mut uniform = Zeroizing::new(Vec::with_capacity(ell * B_IN_BYTES));
    uniform.extend_from_slice(&*b_prev);

    for i in 2..=ell {
        let mut xored = Zeroizing::new([0u8; B_IN_BYTES]);
        for k in 0..B_IN_BYTES {
            xored[k] = b0[k] ^ b_prev[k];
        }
        let mut hi = Sha256::new();
        hi.update(*xored);
        hi.update([i as u8]);
        hi.update(effective_dst);
        hi.update([dst_len_byte]);
        b_prev.copy_from_slice(&hi.finalize());
        uniform.extend_from_slice(&*b_prev);
    }

    uniform.truncate(len_in_bytes);
    Ok(uniform)
}

/// RFC 9380 `hash_to_field` onto `bls12_381::Scalar` ($\mathbb{F}_r$) using `L = 48` uniform bytes
/// (`384` bits -> `OS2IP mod r` with modular bias $< 2^{-128}$).
pub fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Result<Scalar, AcuError> {
    let uniform = expand_message_xmd_sha256(msg, dst, 48)?;
    let mut wide_le = Zeroizing::new([0u8; 64]);
    // RFC 9380 OS2IP interprets `uniform[0..48]` as big-endian; reversing into `[0..48]`
    // with `[48..64] = 0` yields the exact little-endian 512-bit integer for `from_bytes_wide`.
    for (idx, &b) in uniform.iter().rev().enumerate() {
        wide_le[idx] = b;
    }
    Ok(Scalar::from_bytes_wide(&wide_le))
}

/// Deterministically derive a non-zero Fiat–Shamir challenge scalar in $\mathbb{F}_r^*$ via RFC 9380
/// `hash_to_scalar` (`L = 48`).
pub fn hash_to_nonzero_scalar(msg: &[u8], dst: &[u8]) -> Result<Scalar, AcuError> {
    let first = hash_to_scalar(msg, dst)?;
    if !bool::from(first.is_zero()) {
        return Ok(first);
    }
    for ctr in 1u32.. {
        let mut retry_msg = Vec::with_capacity(msg.len() + 4);
        retry_msg.extend_from_slice(msg);
        retry_msg.extend_from_slice(&ctr.to_be_bytes());
        let cand = hash_to_scalar(&retry_msg, dst)?;
        if !bool::from(cand.is_zero()) {
            return Ok(cand);
        }
    }
    unreachable!("unbounded counter finds non-zero F_r challenge w.h.p.")
}

/// Sample a uniformly distributed scalar over the full field $\mathbb{F}_r$ (including $0$,
/// `< 2^{-256}` bias via 512-bit wide reduction inside `Scalar::random`).
#[inline]
pub(crate) fn sample_uniform_scalar(rng: &mut (impl RngCore + CryptoRng)) -> Scalar {
    Scalar::random(rng)
}

/// Zero-dependency `serde` helper for fixed `[u8; 64]` Ed25519 signatures.
pub(crate) mod serde_bytes64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(crate) fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes.as_slice().serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = Vec::<u8>::deserialize(deserializer)?;
        <[u8; 64]>::try_from(vec.as_slice())
            .map_err(|_| serde::de::Error::custom("expected exact 64-byte Ed25519 signature"))
    }
}
