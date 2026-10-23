//// PASETO v3: AES-256-CTR with HMAC-SHA-384 (local) and ECDSA P-384 (public).

import gaseto/error.{
  InvalidPem, NotACompressedPoint, NotOnCurve, OutsideCurveRange,
  TokenNotAuthentic, UnexpectedCreationFailure, UnexpectedValidationFailure,
}
import gaseto/internal/pem
import gaseto/internal/protocol.{
  type Contents, type TokenParts, Contents, LocalBody, SignedBody,
}
import gleam/bit_array
import gleam/crypto
import gleam/int
import gleam/option.{Some}
import gleam/result
import kryptos/block
import kryptos/crypto as kryptos_crypto
import kryptos/ec
import kryptos/ecdsa
import kryptos/hash

const local_header: String = "v3.local."

const public_header: String = "v3.public."

const local_key_size: Int = 32

const local_nonce_size: Int = 32

const local_tag_size: Int = 48

// Split into the encryption key and the AES-CTR nonce
const local_encryption_key_material_size: Int = 48

const local_encryption_key_size: Int = 32

const local_counter_nonce_size: Int = 16

const public_secret_key_size: Int = 48

const public_key_size: Int = 49

const public_coordinate_size: Int = 48

const public_signature_size: Int = 96

// A secret scalar must be in the range 1 to n - 1
const p384_order: Int =
  0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973

pub opaque type LocalKey {
  LocalKey(bytes: BitArray)
}

pub opaque type SecretKey {
  SecretKey(private_key: ec.PrivateKey, public_key: PublicKey)
}

pub opaque type PublicKey {
  PublicKey(public_key: ec.PublicKey, compressed_public_key: BitArray)
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
  secret_key_from_bytes(secret_key_bytes)
}

pub fn secret_key_from_pem(
  key_pem: String,
) -> Result(SecretKey, error.KeyLoadingError) {
  use scalar <- result.try(pem.p384_secret_key(key_pem))
  use scalar <- result.try(
    pad_scalar(scalar) |> result.replace_error(InvalidPem),
  )
  secret_key_from_bytes(scalar)
}

/// Unlike `public_key_from_hex`, this also takes an uncompressed point, which is how
/// most tools write P-384 public keys.
pub fn public_key_from_pem(
  key_pem: String,
) -> Result(PublicKey, error.KeyLoadingError) {
  use point <- result.try(pem.p384_public_key(key_pem))
  use public_key <- result.try(
    ec.public_key_from_raw_point(ec.P384, point)
    |> result.replace_error(NotOnCurve),
  )
  Ok(PublicKey(
    public_key:,
    compressed_public_key: compress_public_key(public_key),
  ))
}

fn secret_key_from_bytes(
  secret_key_bytes: BitArray,
) -> Result(SecretKey, error.KeyLoadingError) {
  use _ <- result.try(case secret_key_bytes {
    <<scalar:size(384)>> if scalar > 0 && scalar < p384_order -> Ok(Nil)
    _ -> Error(OutsideCurveRange)
  })
  use #(private_key, public_key) <- result.try(result.replace_error(
    ec.from_bytes(ec.P384, secret_key_bytes),
    OutsideCurveRange,
  ))
  Ok(new_secret_key(private_key, public_key))
}

pub fn generate_local_key() -> LocalKey {
  LocalKey(crypto.strong_random_bytes(local_key_size))
}

pub fn generate_secret_key() -> SecretKey {
  let #(private_key, public_key) = ec.generate_key_pair(ec.P384)
  new_secret_key(private_key, public_key)
}

pub fn secret_key_to_public_key(key: SecretKey) -> PublicKey {
  key.public_key
}

pub fn local_key_to_hex(key: LocalKey) -> String {
  protocol.encode_hex_key(key.bytes)
}

pub fn secret_key_to_hex(key: SecretKey) -> String {
  // kryptos never returns a P-384 scalar longer than 48 bytes
  let assert Ok(scalar) = pad_scalar(ec.to_bytes(key.private_key))
  protocol.encode_hex_key(scalar)
}

pub fn public_key_to_hex(key: PublicKey) -> String {
  protocol.encode_hex_key(key.compressed_public_key)
}

/// A scalar with leading zero bytes may be stored shorter than 48 bytes.
fn pad_scalar(scalar: BitArray) -> Result(BitArray, Nil) {
  case public_secret_key_size - bit_array.byte_size(scalar) {
    padding_size if padding_size >= 0 ->
      Ok(<<0:size(padding_size * 8), scalar:bits>>)
    _ -> Error(Nil)
  }
}

/// V3 signs over the public key, so it is derived here.
fn new_secret_key(
  private_key: ec.PrivateKey,
  public_key: ec.PublicKey,
) -> SecretKey {
  SecretKey(
    private_key:,
    public_key: PublicKey(
      public_key:,
      compressed_public_key: compress_public_key(public_key),
    ),
  )
}

pub fn public_key_from_hex(
  key_hex: String,
) -> Result(PublicKey, error.KeyLoadingError) {
  use public_key_bytes <- result.try(protocol.decode_hex_key(
    key_hex,
    public_key_size,
  ))
  case public_key_bytes {
    <<0x02, _:bytes>> | <<0x03, _:bytes>> ->
      ec.public_key_from_raw_point(ec.P384, public_key_bytes)
      |> result.map(PublicKey(_, compressed_public_key: public_key_bytes))
      |> result.replace_error(NotOnCurve)
    _ -> Error(NotACompressedPoint)
  }
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
  use #(encryption_key, counter_nonce, authentication_key) <- result.try(
    derive_local_keys(key.bytes, nonce)
    |> result.map_error(UnexpectedCreationFailure),
  )
  use ciphertext <- result.try(
    aes_256_ctr(encryption_key, counter_nonce, bit_array.from_string(payload))
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
  use #(encryption_key, counter_nonce, authentication_key) <- result.try(
    derive_local_keys(key.bytes, nonce)
    |> result.map_error(UnexpectedValidationFailure),
  )
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
    aes_256_ctr(encryption_key, counter_nonce, ciphertext)
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
  // PASETO needs the fixed-size r || s form, not DER
  let signature =
    ecdsa.sign_rs(
      key.private_key,
      public_signing_input(
        key.public_key.compressed_public_key,
        payload_bytes,
        footer,
        implicit_assertion,
      ),
      hash.Sha384,
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
      key.compressed_public_key,
      payload_bytes,
      protocol.footer(parts),
      implicit_assertion,
    )
  case ecdsa.verify_rs(key.public_key, signing_input, signature, hash.Sha384) {
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
  |> crypto.hmac(crypto.Sha384, authentication_key)
}

fn public_signing_input(
  compressed_public_key: BitArray,
  payload_bytes: BitArray,
  footer: BitArray,
  implicit_assertion: BitArray,
) -> BitArray {
  protocol.pre_authentication_encode([
    compressed_public_key,
    bit_array.from_string(public_header),
    payload_bytes,
    footer,
    implicit_assertion,
  ])
}

/// The spec's pubKeyCompress
/// ([ECDSA Public Key Point Compression](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#ecdsa-public-key-point-compression)).
/// kryptos only exports uncompressed points.
fn compress_public_key(public_key: ec.PublicKey) -> BitArray {
  // kryptos always writes a P-384 public key as an uncompressed 97-byte point
  let assert <<
    0x04,
    x_coordinate:bytes-size(public_coordinate_size),
    _:bytes-size(public_coordinate_size - 1),
    y_last_byte,
  >> = ec.public_key_to_raw_point(public_key)
  <<{ 0x02 + int.bitwise_and(y_last_byte, 1) }, x_coordinate:bits>>
}

fn derive_local_keys(
  master_key: BitArray,
  nonce: BitArray,
) -> Result(#(BitArray, BitArray, BitArray), String) {
  use encryption_key_material <- result.try(
    kryptos_crypto.hkdf(
      hash.Sha384,
      input: master_key,
      salt: Some(<<>>),
      info: bit_array.append(<<"paseto-encryption-key":utf8>>, nonce),
      length: local_encryption_key_material_size,
    )
    |> result.replace_error("deriving the encryption key with HKDF failed"),
  )
  use #(encryption_key, counter_nonce) <- result.try(
    case encryption_key_material {
      <<
        encryption_key:bytes-size(local_encryption_key_size),
        counter_nonce:bytes-size(local_counter_nonce_size),
      >> -> Ok(#(encryption_key, counter_nonce))
      _ -> Error("splitting the derived encryption key failed")
    },
  )
  use authentication_key <- result.try(
    kryptos_crypto.hkdf(
      hash.Sha384,
      input: master_key,
      salt: Some(<<>>),
      info: bit_array.append(<<"paseto-auth-key-for-aead":utf8>>, nonce),
      length: local_tag_size,
    )
    |> result.replace_error("deriving the authentication key with HKDF failed"),
  )
  Ok(#(encryption_key, counter_nonce, authentication_key))
}

/// CTR mode encrypts and decrypts with the same operation.
fn aes_256_ctr(
  encryption_key: BitArray,
  counter_nonce: BitArray,
  data: BitArray,
) -> Result(BitArray, String) {
  use cipher <- result.try(
    block.aes_256(encryption_key)
    |> result.replace_error("setting up AES-256 failed"),
  )
  use context <- result.try(
    block.ctr(cipher, nonce: counter_nonce)
    |> result.replace_error("setting up AES-CTR failed"),
  )
  block.encrypt(context, data)
  |> result.replace_error("running AES-256-CTR failed")
}
