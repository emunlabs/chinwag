# Seed capsule format v1

The capsule contains a 256-byte clear header followed by authenticated
ciphertext. All integers in the header use little-endian encoding.

The content key is 32 fresh random bytes. ChaCha20-Poly1305 encrypts the
zstd-compressed payload with that key. Its associated data is the complete
256-byte header.

Each recipient slot wraps the same content key with RFC 9180 HPKE base mode.
The suite uses X25519-HKDF-SHA256, HKDF-SHA256, and ChaCha20-Poly1305.
The first slot is the public demo recipient for `emunlabs/chinwag`.
The second slot is a distinct organization recipient.

## Header fields

| Offset | Bytes | Value |
| --- | --- | --- |
| `0x00` | 8 | ASCII `EMUNVLT1` |
| `0x08` | 2 | Version `1` |
| `0x0a` | 2 | Header length `256` |
| `0x0c` | 2 | HPKE KEM `0x0020` |
| `0x0e` | 2 | HPKE KDF `0x0001` |
| `0x10` | 2 | HPKE AEAD `0x0003` |
| `0x12` | 2 | Required recipient flags `3` |
| `0x14` | 4 | Plaintext length |
| `0x18` | 4 | Compressed length |
| `0x1c` | 4 | Ciphertext length, including the 16-byte tag |
| `0x20` | 12 | Content nonce |
| `0x2c` | 1 | Demo recipient kind `1` |
| `0x2d` | 1 | Organization recipient kind `2` |
| `0x2e` | 2 | Zero |
| `0x30` | 16 | Demo key ID |
| `0x40` | 32 | Demo HPKE encapsulated key |
| `0x60` | 48 | Demo wrapped content key |
| `0x90` | 16 | Organization key ID |
| `0xa0` | 32 | Organization HPKE encapsulated key |
| `0xc0` | 48 | Organization wrapped content key |
| `0xf0` | 16 | Zero |

A key ID contains the first 16 bytes of SHA-256 of the raw X25519 public key.
The reader rejects unsupported suite values, flags, recipient kinds, and
nonzero reserved bytes.

## Binding and limits

The HPKE `info` and wrap associated data both contain this byte string:

```text
chinwag-vault/v1\0emunlabs/chinwag\0<source-oid>\0<slot-label>
```

Each `\0` represents one NUL byte. The slot labels are `demo-public-repo` and
`org`. The source OID is lowercase hexadecimal with either 40 or 64 digits.
The reader supplies the expected OID. A capsule copied to a different Git
note target fails authentication.

Plaintext is limited to 4 MiB. Compressed data is limited to 4 MiB plus 64 KiB.
The reader checks declared lengths before decryption and limits decompression
to the declared plaintext length plus one byte. Extra frames and trailing
compressed data fail validation.

The payload is opaque bytes at this layer. The later record publisher must
validate the flight schema and signatures before attaching a capsule to a commit.
No Git-note update or disclosure decision occurs inside the capsule codec.
