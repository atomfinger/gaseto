# ECDSA P-384 in PASETO V3

## ECDSA

ECDSA (Elliptic Curve Digital Signature Algorithm) is a digital signature scheme
based on elliptic curve cryptography. Signing produces a signature that anyone
holding the corresponding public key can verify, without being able to forge new
signatures.

## P-384

P-384 (also known as secp384r1 or NIST P-384) is a specific elliptic curve
standardised by NIST. Its key sizes — 48-byte private scalar, 49-byte compressed
public point — give a 192-bit security level, which PASETO V3 requires.

The public key is stored in **compressed form**: a single prefix byte (`0x02` or
`0x03`, indicating whether the Y coordinate is even or odd) followed by the
48-byte X coordinate, for a total of 49 bytes.

## SHA-384

SHA-384 is the hash function used during signing and verification. The message is
hashed before the elliptic curve math, so the signature covers a fixed-size
digest rather than the raw message bytes.

## Signature formats: DER vs. IEEE P1363

An ECDSA signature consists of two large integers, conventionally called `r` and
`s`. There are two common ways to encode them as bytes:

**DER (Distinguished Encoding Rules):** A variable-length ASN.1 format used by
most cryptographic libraries and TLS. Each integer is length-prefixed, and a
leading `0x00` byte is added when the high bit of `r` or `s` would otherwise
look like a negative sign. This is what Erlang's `crypto` module produces and
consumes.

**IEEE P1363:** A fixed-length format used by PASETO and many web standards
(e.g. JSON Web Signatures). `r` and `s` are each zero-padded to exactly 48 bytes
and concatenated, giving a flat 96-byte signature with no length fields.

Because Erlang's `crypto` module works in DER and PASETO requires P1363, the
`ecdsa` module converts between the two formats on every sign and verify call.
