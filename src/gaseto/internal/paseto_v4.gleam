//// PASETO v4: XChaCha20 with keyed BLAKE2b (local) and Ed25519 (public).

import gaseto/error.{
  InvalidPem, PublicHalfDoesNotMatchSeed, SmallOrderPublicKey, TokenNotAuthentic,
  UnexpectedCreationFailure, UnexpectedKeyFailure, UnexpectedValidationFailure,
}
import gaseto/internal/pem
import gaseto/internal/protocol.{
  type Contents, type TokenParts, Contents, LocalBody, SignedBody,
}
import gleam/bit_array
import gleam/bool
import gleam/crypto
import gleam/int
import gleam/list
import gleam/result
import kryptos/eddsa
import kryptos/stream

const local_header: String = "v4.local."

const public_header: String = "v4.public."

const local_key_size: Int = 32

const local_nonce_size: Int = 32

const local_tag_size: Int = 32

// Split into the encryption key and the XChaCha20 nonce
const local_encryption_key_material_size: Int = 56

const local_encryption_key_size: Int = 32

const local_xchacha20_nonce_size: Int = 24

const local_authentication_key_size: Int = 32

// The 32-byte seed followed by the 32-byte public key
const public_secret_key_size: Int = 64

const public_secret_key_seed_size: Int = 32

const public_key_size: Int = 32

const public_signature_size: Int = 64

/// Ed25519 public keys of small order, compared with the sign bit cleared. A
/// signature for one of these can be forged without the secret key. The spec
/// writes the check as libsodium's `crypto_sign_verify_detached`
/// ([version 4, Verify](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#verify)),
/// which refuses these keys
/// ([libsodium 1.0.18, `ge25519_has_small_order`](https://github.com/jedisct1/libsodium/blob/1.0.18/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c)),
/// so Gaseto refuses them too.
const small_order_public_keys: List(BitArray) = [
  <<
    0x0000000000000000000000000000000000000000000000000000000000000000:size(256),
  >>,
  <<
    0x0100000000000000000000000000000000000000000000000000000000000000:size(256),
  >>,
  <<
    0x26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05:size(256),
  >>,
  <<
    0xc7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a:size(256),
  >>,
  <<
    0xecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f:size(256),
  >>,
  <<
    0xedffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f:size(256),
  >>,
  <<
    0xeeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f:size(256),
  >>,
]

/// Keyed BLAKE2b from eblake2, because OTP's BLAKE2b takes no key or output
/// length.
fn blake2b(output_length: Int, message: BitArray, key: BitArray) -> BitArray {
  // eblake2 always returns `{ok, Hash}`, so this cannot fail
  let assert Ok(hash) = eblake2_blake2b(output_length, message, key)
  hash
}

@external(erlang, "eblake2", "blake2b")
fn eblake2_blake2b(
  output_length: Int,
  message: BitArray,
  key: BitArray,
) -> Result(BitArray, Nil)

pub opaque type LocalKey {
  LocalKey(bytes: BitArray)
}

pub opaque type SecretKey {
  SecretKey(private_key: eddsa.PrivateKey, public_key: PublicKey)
}

pub opaque type PublicKey {
  PublicKey(public_key: eddsa.PublicKey)
}

pub fn local_key_from_hex(
  key_hex: String,
) -> Result(LocalKey, error.KeyLoadingError) {
  protocol.decode_hex_key(key_hex, local_key_size)
  |> result.map(LocalKey)
}

pub fn secret_key_from_hex(
  key_hex: String,
) -> Result(SecretKey, error.KeyLoadingError) {
  use secret_key_bytes <- result.try(protocol.decode_hex_key(
    key_hex,
    public_secret_key_size,
  ))
  // `decode_hex_key` has checked that there are exactly 64 bytes
  let assert <<
    seed:bytes-size(public_secret_key_seed_size),
    embedded_public_key:bytes-size(public_key_size),
  >> = secret_key_bytes
  use #(private_key, derived_public_key) <- result.try(result.replace_error(
    eddsa.from_bytes(eddsa.Ed25519, seed),
    UnexpectedKeyFailure("making an Ed25519 key from the seed failed"),
  ))
  // Catches corrupt or mixed-up key material
  case eddsa.public_key_to_bytes(derived_public_key) == embedded_public_key {
    True ->
      Ok(SecretKey(private_key:, public_key: PublicKey(derived_public_key)))
    False -> Error(PublicHalfDoesNotMatchSeed)
  }
}

pub fn public_key_from_hex(
  key_hex: String,
) -> Result(PublicKey, error.KeyLoadingError) {
  use public_key_bytes <- result.try(protocol.decode_hex_key(
    key_hex,
    public_key_size,
  ))
  public_key_from_bytes(public_key_bytes)
}

/// PKCS #8 files often leave out the public key, so it is derived from the
/// seed.
pub fn secret_key_from_pem(
  key_pem: String,
) -> Result(SecretKey, error.KeyLoadingError) {
  use seed <- result.try(pem.ed25519_secret_key(key_pem))
  use #(private_key, public_key) <- result.try(
    eddsa.from_bytes(eddsa.Ed25519, seed) |> result.replace_error(InvalidPem),
  )
  Ok(SecretKey(private_key:, public_key: PublicKey(public_key)))
}

pub fn public_key_from_pem(
  key_pem: String,
) -> Result(PublicKey, error.KeyLoadingError) {
  use public_key_bytes <- result.try(pem.ed25519_public_key(key_pem))
  case bit_array.byte_size(public_key_bytes) {
    size if size == public_key_size -> public_key_from_bytes(public_key_bytes)
    _ -> Error(InvalidPem)
  }
}

/// kryptos only checks the length, so small-order keys are refused here.
fn public_key_from_bytes(
  public_key_bytes: BitArray,
) -> Result(PublicKey, error.KeyLoadingError) {
  use <- bool.guard(
    when: is_small_order(public_key_bytes),
    return: Error(SmallOrderPublicKey),
  )
  eddsa.public_key_from_bytes(eddsa.Ed25519, public_key_bytes)
  |> result.map(PublicKey)
  |> result.replace_error(UnexpectedKeyFailure(
    "making an Ed25519 public key failed",
  ))
}

fn is_small_order(public_key_bytes: BitArray) -> Bool {
  let without_sign_bit = case public_key_bytes {
    <<rest:bytes-size(31), last_byte>> -> <<
      rest:bits,
      { int.bitwise_and(last_byte, 0x7f) },
    >>
    _ -> public_key_bytes
  }
  list.contains(small_order_public_keys, without_sign_bit)
}

pub fn generate_local_key() -> LocalKey {
  LocalKey(crypto.strong_random_bytes(local_key_size))
}

pub fn generate_secret_key() -> SecretKey {
  let #(private_key, public_key) = eddsa.generate_key_pair(eddsa.Ed25519)
  SecretKey(private_key:, public_key: PublicKey(public_key))
}

pub fn secret_key_to_public_key(key: SecretKey) -> PublicKey {
  key.public_key
}

pub fn local_key_to_hex(key: LocalKey) -> String {
  protocol.encode_hex_key(key.bytes)
}

/// The seed followed by the public key, as `secret_key_from_hex` reads it.
pub fn secret_key_to_hex(key: SecretKey) -> String {
  protocol.encode_hex_key(<<
    eddsa.to_bytes(key.private_key):bits,
    eddsa.public_key_to_bytes(key.public_key.public_key):bits,
  >>)
}

pub fn public_key_to_hex(key: PublicKey) -> String {
  protocol.encode_hex_key(eddsa.public_key_to_bytes(key.public_key))
}

/// Takes the nonce instead of making it, so the spec's
/// [test vectors](https://github.com/paseto-standard/test-vectors), which give
/// a fixed nonce, can be checked byte for byte. `gaseto.encrypt` passes
/// a new random nonce every time.
pub fn encrypt(
  key: LocalKey,
  payload: String,
  footer: BitArray,
  nonce: BitArray,
  implicit_assertion: BitArray,
) -> Result(String, error.TokenCreationError) {
  use _ <- result.try(case bit_array.byte_size(nonce) {
    size if size == local_nonce_size -> Ok(Nil)
    _ -> Error(UnexpectedCreationFailure("the nonce is not 32 bytes"))
  })
  let #(encryption_key, xchacha20_nonce, authentication_key) =
    derive_local_keys(key.bytes, nonce)
  use ciphertext <- result.try(
    xchacha20(encryption_key, xchacha20_nonce, bit_array.from_string(payload))
    |> result.map_error(UnexpectedCreationFailure),
  )
  let authentication_tag =
    local_authentication_tag(
      authentication_key,
      nonce,
      ciphertext,
      footer,
      implicit_assertion,
    )
  Ok(protocol.encode_token(
    local_header,
    bit_array.concat([nonce, ciphertext, authentication_tag]),
    footer,
  ))
}

/// The parts come from a token that `gaseto` has read with this version's
/// `local` header.
pub fn decrypt(
  key: LocalKey,
  parts: TokenParts,
  implicit_assertion: BitArray,
) -> Result(Contents, error.TokenValidationError) {
  use LocalBody(nonce:, ciphertext:, authentication_tag:) <- result.try(
    protocol.split_local_body(
      parts,
      nonce_size: local_nonce_size,
      tag_size: local_tag_size,
    ),
  )
  let #(encryption_key, xchacha20_nonce, authentication_key) =
    derive_local_keys(key.bytes, nonce)
  // Checked in constant time, before anything is decrypted
  let expected_tag =
    local_authentication_tag(
      authentication_key,
      nonce,
      ciphertext,
      protocol.footer(parts),
      implicit_assertion,
    )
  use _ <- result.try(
    case crypto.secure_compare(authentication_tag, expected_tag) {
      True -> Ok(Nil)
      False -> Error(TokenNotAuthentic)
    },
  )
  use plaintext <- result.try(
    xchacha20(encryption_key, xchacha20_nonce, ciphertext)
    |> result.map_error(UnexpectedValidationFailure),
  )
  use payload <- result.try(protocol.payload_to_string(plaintext))
  Ok(Contents(payload:, footer: protocol.footer(parts)))
}

pub fn sign(
  key: SecretKey,
  payload: String,
  footer: BitArray,
  implicit_assertion: BitArray,
) -> Result(String, error.TokenCreationError) {
  let payload_bytes = bit_array.from_string(payload)
  let signature =
    eddsa.sign(
      key.private_key,
      public_signing_input(payload_bytes, footer, implicit_assertion),
    )
  Ok(protocol.encode_token(
    public_header,
    bit_array.append(payload_bytes, signature),
    footer,
  ))
}

/// The parts come from a token that `gaseto` has read with this version's
/// `public` header.
pub fn verify(
  key: PublicKey,
  parts: TokenParts,
  implicit_assertion: BitArray,
) -> Result(Contents, error.TokenValidationError) {
  use SignedBody(payload: payload_bytes, signature:) <- result.try(
    protocol.split_signed_body(parts, signature_size: public_signature_size),
  )
  let signing_input =
    public_signing_input(
      payload_bytes,
      protocol.footer(parts),
      implicit_assertion,
    )
  case eddsa.verify(key.public_key, signing_input, signature:) {
    True -> {
      use payload <- result.try(protocol.payload_to_string(payload_bytes))
      Ok(Contents(payload:, footer: protocol.footer(parts)))
    }
    False -> Error(TokenNotAuthentic)
  }
}

fn local_authentication_tag(
  authentication_key: BitArray,
  nonce: BitArray,
  ciphertext: BitArray,
  footer: BitArray,
  implicit_assertion: BitArray,
) -> BitArray {
  protocol.pre_authentication_encode([
    bit_array.from_string(local_header),
    nonce,
    ciphertext,
    footer,
    implicit_assertion,
  ])
  |> blake2b(local_tag_size, _, authentication_key)
}

fn public_signing_input(
  payload_bytes: BitArray,
  footer: BitArray,
  implicit_assertion: BitArray,
) -> BitArray {
  protocol.pre_authentication_encode([
    bit_array.from_string(public_header),
    payload_bytes,
    footer,
    implicit_assertion,
  ])
}

fn derive_local_keys(
  master_key: BitArray,
  nonce: BitArray,
) -> #(BitArray, BitArray, BitArray) {
  let encryption_key_material =
    blake2b(
      local_encryption_key_material_size,
      bit_array.append(<<"paseto-encryption-key":utf8>>, nonce),
      master_key,
    )
  // BLAKE2b returns exactly the 56 bytes asked for
  let assert <<
    encryption_key:bytes-size(local_encryption_key_size),
    xchacha20_nonce:bytes-size(local_xchacha20_nonce_size),
  >> = encryption_key_material
  let authentication_key =
    blake2b(
      local_authentication_key_size,
      bit_array.append(<<"paseto-auth-key-for-aead":utf8>>, nonce),
      master_key,
    )
  #(encryption_key, xchacha20_nonce, authentication_key)
}

fn xchacha20(
  encryption_key: BitArray,
  nonce: BitArray,
  data: BitArray,
) -> Result(BitArray, String) {
  use cipher <- result.try(
    stream.xchacha20(encryption_key, nonce:, counter: 0)
    |> result.replace_error("setting up XChaCha20 failed"),
  )
  stream.xor(cipher, data)
  |> result.replace_error("running XChaCha20 failed")
}
