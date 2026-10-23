import gaseto.{PasetoV3, PasetoV4}
import gaseto/error
import gaseto/paseto_v3_test_vector
import gaseto/paseto_v4_test_vector
import gleam/bit_array
import gleam/list
import gleam/option.{Some}
import gleam/string
import kryptos/ec
import kryptos/eddsa

pub fn generated_local_key_encrypts_and_decrypts_test() -> Nil {
  use version <- list.each([PasetoV3, PasetoV4])
  let key = gaseto.generate_local_key(version)
  let claims = gaseto.new_claims() |> gaseto.with_subject("alice")
  let assert Ok(token) = gaseto.encrypt(claims, key)
  let assert Ok(token) = gaseto.decrypt(token, key, gaseto.new_rules())
  assert gaseto.subject(token) == Some("alice")
}

pub fn generated_secret_key_signs_for_its_public_key_test() -> Nil {
  use version <- list.each([PasetoV3, PasetoV4])
  let secret_key = gaseto.generate_secret_key(version)
  let public_key = gaseto.secret_key_to_public_key(secret_key)
  let claims = gaseto.new_claims() |> gaseto.with_subject("alice")
  let assert Ok(token) = gaseto.sign(claims, secret_key)
  let assert Ok(token) = gaseto.verify(token, public_key, gaseto.new_rules())
  assert gaseto.subject(token) == Some("alice")
}

pub fn a_public_key_does_not_verify_another_secret_keys_tokens_test() -> Nil {
  use version <- list.each([PasetoV3, PasetoV4])
  let secret_key = gaseto.generate_secret_key(version)
  let other_secret_key = gaseto.generate_secret_key(version)
  let assert Ok(token) = gaseto.sign(gaseto.new_claims(), secret_key)
  let other_public_key = gaseto.secret_key_to_public_key(other_secret_key)
  assert gaseto.verify(token, other_public_key, gaseto.new_rules())
    == Error(error.TokenNotAuthentic)
}

pub fn generated_keys_are_different_every_time_test() -> Nil {
  use version <- list.each([PasetoV3, PasetoV4])
  assert gaseto.local_key_to_hex(gaseto.generate_local_key(version))
    != gaseto.local_key_to_hex(gaseto.generate_local_key(version))
  let first = gaseto.generate_secret_key(version)
  let second = gaseto.generate_secret_key(version)
  assert gaseto.secret_key_to_hex(first) != gaseto.secret_key_to_hex(second)
}

pub fn generated_keys_keep_their_version_test() -> Nil {
  let version_3_key = gaseto.generate_local_key(PasetoV3)
  let version_4_key = gaseto.generate_local_key(PasetoV4)
  let assert Ok(token) = gaseto.encrypt(gaseto.new_claims(), version_4_key)
  assert gaseto.decrypt(token, version_3_key, gaseto.new_rules())
    == Error(error.UnexpectedVersion(expected: "v3", found: "v4"))
}

pub fn exported_keys_load_again_test() -> Nil {
  use #(version, secret_key_size, public_key_size) <- list.each([
    #(PasetoV3, 48, 49),
    #(PasetoV4, 64, 32),
  ])
  let local_key_hex =
    gaseto.local_key_to_hex(gaseto.generate_local_key(version))
  assert string.length(local_key_hex) == 64
  let assert Ok(local_key) = gaseto.local_key_from_hex(version, local_key_hex)
  assert gaseto.local_key_to_hex(local_key) == local_key_hex

  let secret_key = gaseto.generate_secret_key(version)
  let secret_key_hex = gaseto.secret_key_to_hex(secret_key)
  let public_key_hex =
    gaseto.public_key_to_hex(gaseto.secret_key_to_public_key(secret_key))
  assert string.length(secret_key_hex) == secret_key_size * 2
  assert string.length(public_key_hex) == public_key_size * 2
  let assert Ok(loaded_secret_key) =
    gaseto.secret_key_from_hex(version, secret_key_hex)
  let assert Ok(loaded_public_key) =
    gaseto.public_key_from_hex(version, public_key_hex)
  assert gaseto.secret_key_to_hex(loaded_secret_key) == secret_key_hex
  assert gaseto.public_key_to_hex(loaded_public_key) == public_key_hex
}

pub fn exported_hex_is_lowercase_test() -> Nil {
  let key_hex = string.repeat("AB", 32)
  let assert Ok(key) = gaseto.local_key_from_hex(PasetoV4, key_hex)
  assert gaseto.local_key_to_hex(key) == string.lowercase(key_hex)
}

pub fn version_3_vector_keys_export_unchanged_test() -> Nil {
  use vector <- list.each(paseto_v3_test_vector.public_vectors)
  assert_exports_unchanged(PasetoV3, vector.secret_key, vector.public_key)
}

pub fn version_4_vector_keys_export_unchanged_test() -> Nil {
  use vector <- list.each(paseto_v4_test_vector.public_vectors)
  assert_exports_unchanged(PasetoV4, vector.secret_key, vector.public_key)
}

pub fn version_3_secret_key_with_leading_zeros_exports_in_full_test() -> Nil {
  let secret_key_hex = string.repeat("00", 2) <> string.repeat("11", 46)
  let assert Ok(secret_key) =
    gaseto.secret_key_from_hex(PasetoV3, secret_key_hex)
  assert gaseto.secret_key_to_hex(secret_key) == secret_key_hex
}

fn assert_exports_unchanged(
  version: gaseto.PasetoVersion,
  secret_key_hex: String,
  public_key_hex: String,
) -> Nil {
  let assert Ok(secret_key) =
    gaseto.secret_key_from_hex(version, secret_key_hex)
  assert gaseto.secret_key_to_hex(secret_key) == secret_key_hex
  // The derived public key is the one the vector gives
  assert gaseto.public_key_to_hex(gaseto.secret_key_to_public_key(secret_key))
    == public_key_hex
}

pub fn version_3_vector_pem_keys_match_their_hex_keys_test() -> Nil {
  use vector <- list.each(paseto_v3_test_vector.public_vectors)
  // The secret key is SEC1 and the public key is an uncompressed point
  assert_pem_matches_hex(
    PasetoV3,
    vector.secret_key_pem,
    vector.secret_key,
    vector.public_key_pem,
    vector.public_key,
  )
}

pub fn version_4_vector_pem_keys_match_their_hex_keys_test() -> Nil {
  use vector <- list.each(paseto_v4_test_vector.public_vectors)
  assert_pem_matches_hex(
    PasetoV4,
    vector.secret_key_pem,
    vector.secret_key,
    vector.public_key_pem,
    vector.public_key,
  )
}

pub fn pkcs8_pem_keys_sign_and_verify_test() -> Nil {
  let #(p384_private_key, p384_public_key) = ec.generate_key_pair(ec.P384)
  let assert Ok(p384_secret_pem) = ec.to_pem(p384_private_key)
  let assert Ok(p384_public_pem) = ec.public_key_to_pem(p384_public_key)
  let #(ed25519_private_key, ed25519_public_key) =
    eddsa.generate_key_pair(eddsa.Ed25519)
  let assert Ok(ed25519_secret_pem) = eddsa.to_pem(ed25519_private_key)
  let assert Ok(ed25519_public_pem) =
    eddsa.public_key_to_pem(ed25519_public_key)
  use #(version, secret_pem, public_pem) <- list.each([
    #(PasetoV3, p384_secret_pem, p384_public_pem),
    #(PasetoV4, ed25519_secret_pem, ed25519_public_pem),
  ])
  assert string.contains(secret_pem, "BEGIN PRIVATE KEY")
  let assert Ok(secret_key) = gaseto.secret_key_from_pem(version, secret_pem)
  let assert Ok(public_key) = gaseto.public_key_from_pem(version, public_pem)
  let assert Ok(token) = gaseto.sign(gaseto.new_claims(), secret_key)
  let assert Ok(_) = gaseto.verify(token, public_key, gaseto.new_rules())
  Nil
}

pub fn pem_with_a_separate_curve_block_is_read_test() -> Nil {
  // As `openssl ecparam -genkey` writes it
  let assert [vector, ..] = paseto_v3_test_vector.public_vectors
  let curve_block =
    "-----BEGIN EC PARAMETERS-----\nBgUrgQQAIg==\n-----END EC PARAMETERS-----\n"
  let assert Ok(secret_key) =
    gaseto.secret_key_from_pem(PasetoV3, curve_block <> vector.secret_key_pem)
  assert gaseto.secret_key_to_hex(secret_key) == vector.secret_key
}

pub fn secret_pem_of_the_wrong_kind_is_refused_test() -> Nil {
  let assert [version_3, ..] = paseto_v3_test_vector.public_vectors
  let assert [version_4, ..] = paseto_v4_test_vector.public_vectors
  let #(p256_secret_pem, _) = other_curve_pems(PasetoV3)
  let #(ed448_secret_pem, _) = other_curve_pems(PasetoV4)
  use #(version, secret_pem) <- list.each([
    // Another version's key
    #(PasetoV4, version_3.secret_key_pem),
    #(PasetoV3, version_4.secret_key_pem),
    // A public key where a secret key is needed
    #(PasetoV3, version_3.public_key_pem),
    #(PasetoV4, version_4.public_key_pem),
    // Other curves
    #(PasetoV3, p256_secret_pem),
    #(PasetoV4, ed448_secret_pem),
    // More than one key
    #(PasetoV4, version_4.secret_key_pem <> "\n" <> version_4.secret_key_pem),
    // Not PEM
    #(PasetoV4, ""),
    #(PasetoV4, "hello"),
    #(PasetoV4, version_4.secret_key),
    #(PasetoV4, "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"),
  ])
  assert gaseto.secret_key_from_pem(version, secret_pem)
    == Error(error.InvalidPem)
}

pub fn public_pem_of_the_wrong_kind_is_refused_test() -> Nil {
  let assert [version_3, ..] = paseto_v3_test_vector.public_vectors
  let assert [version_4, ..] = paseto_v4_test_vector.public_vectors
  let #(_, p256_public_pem) = other_curve_pems(PasetoV3)
  let #(_, ed448_public_pem) = other_curve_pems(PasetoV4)
  use #(version, public_pem) <- list.each([
    // Another version's key
    #(PasetoV4, version_3.public_key_pem),
    #(PasetoV3, version_4.public_key_pem),
    // A secret key where a public key is needed
    #(PasetoV3, version_3.secret_key_pem),
    #(PasetoV4, version_4.secret_key_pem),
    // Other curves
    #(PasetoV3, p256_public_pem),
    #(PasetoV4, ed448_public_pem),
    // Not PEM
    #(PasetoV4, ""),
    #(PasetoV4, version_4.public_key),
  ])
  assert gaseto.public_key_from_pem(version, public_pem)
    == Error(error.InvalidPem)
}

/// PEM keys on a curve the version does not use: P-256 instead of P-384, and
/// Ed448 instead of Ed25519.
fn other_curve_pems(version: gaseto.PasetoVersion) -> #(String, String) {
  case version {
    PasetoV3 -> {
      let #(private_key, public_key) = ec.generate_key_pair(ec.P256)
      let assert Ok(secret_pem) = ec.to_pem(private_key)
      let assert Ok(public_pem) = ec.public_key_to_pem(public_key)
      #(secret_pem, public_pem)
    }
    PasetoV4 -> {
      let #(private_key, public_key) = eddsa.generate_key_pair(eddsa.Ed448)
      let assert Ok(secret_pem) = eddsa.to_pem(private_key)
      let assert Ok(public_pem) = eddsa.public_key_to_pem(public_key)
      #(secret_pem, public_pem)
    }
  }
}

fn assert_pem_matches_hex(
  version: gaseto.PasetoVersion,
  secret_key_pem: String,
  secret_key_hex: String,
  public_key_pem: String,
  public_key_hex: String,
) -> Nil {
  let assert Ok(secret_key) =
    gaseto.secret_key_from_pem(version, secret_key_pem)
  let assert Ok(public_key) =
    gaseto.public_key_from_pem(version, public_key_pem)
  assert gaseto.secret_key_to_hex(secret_key) == secret_key_hex
  assert gaseto.public_key_to_hex(public_key) == public_key_hex
  // Tokens signed with the PEM key verify with the hex key, and back
  let assert Ok(hex_public_key) =
    gaseto.public_key_from_hex(version, public_key_hex)
  let assert Ok(token) = gaseto.sign(gaseto.new_claims(), secret_key)
  let assert Ok(_) = gaseto.verify(token, hex_public_key, gaseto.new_rules())
  Nil
}

pub fn small_order_version_4_public_keys_are_refused_test() -> Nil {
  use key_hex <- list.each([
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    // The same keys with the sign bit set
    "0000000000000000000000000000000000000000000000000000000000000080",
    "0100000000000000000000000000000000000000000000000000000000000080",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  ])
  assert gaseto.public_key_from_hex(PasetoV4, key_hex)
    == Error(error.SmallOrderPublicKey)
  assert gaseto.public_key_from_pem(PasetoV4, ed25519_public_key_pem(key_hex))
    == Error(error.SmallOrderPublicKey)
}

pub fn ordinary_version_4_public_keys_are_accepted_from_pem_and_hex_test() -> Nil {
  let secret_key = gaseto.generate_secret_key(PasetoV4)
  let key_hex =
    gaseto.secret_key_to_public_key(secret_key) |> gaseto.public_key_to_hex
  let assert Ok(_) = gaseto.public_key_from_hex(PasetoV4, key_hex)
  let assert Ok(_) =
    gaseto.public_key_from_pem(PasetoV4, ed25519_public_key_pem(key_hex))
  Nil
}

pub fn version_3_pem_public_key_with_a_compressed_point_is_read_test() -> Nil {
  let assert [vector, ..] = paseto_v3_test_vector.public_vectors
  // The vectors give the compressed point in hex and an uncompressed PEM
  let assert Ok(der) =
    bit_array.base16_decode(
      "3046301006072a8648ce3d020106052b81040022033200" <> vector.public_key,
    )
  let compressed_pem =
    "-----BEGIN PUBLIC KEY-----\n"
    <> bit_array.base64_encode(der, True)
    <> "\n-----END PUBLIC KEY-----\n"
  let assert Ok(public_key) =
    gaseto.public_key_from_pem(PasetoV3, compressed_pem)
  assert gaseto.public_key_to_hex(public_key) == vector.public_key
}

/// A SubjectPublicKeyInfo PEM around raw Ed25519 public key bytes.
fn ed25519_public_key_pem(key_hex: String) -> String {
  let assert Ok(der) =
    bit_array.base16_decode("302a300506032b6570032100" <> key_hex)
  "-----BEGIN PUBLIC KEY-----\n"
  <> bit_array.base64_encode(der, True)
  <> "\n-----END PUBLIC KEY-----\n"
}

pub fn version_3_pem_secret_key_with_a_short_scalar_is_padded_test() -> Nil {
  // SEC1 allows the scalar without its leading zero byte: 47 bytes here
  let scalar_hex = string.repeat("11", 47)
  let assert Ok(der) =
    bit_array.base16_decode(
      "303d020101042f" <> scalar_hex <> "a00706052b81040022",
    )
  let pem =
    "-----BEGIN EC PRIVATE KEY-----\n"
    <> bit_array.base64_encode(der, True)
    <> "\n-----END EC PRIVATE KEY-----\n"
  let assert Ok(secret_key) = gaseto.secret_key_from_pem(PasetoV3, pem)
  assert gaseto.secret_key_to_hex(secret_key) == "00" <> scalar_hex
}
