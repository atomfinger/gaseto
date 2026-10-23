import gaseto.{Local, PasetoV3, Public}
import gaseto/error
import gaseto/internal/paseto_v3
import gaseto/paseto_v3_test_vector
import gaseto/tampered_token
import gaseto/test_support
import gleam/bit_array
import gleam/json
import gleam/list
import gleam/option.{Some}
import gleam/string

pub fn local_vectors_decrypt_test() -> Nil {
  use vector <- list.each(paseto_v3_test_vector.local_vectors)
  let assert Ok(key) = gaseto.local_key_from_hex(PasetoV3, vector.key)
  let assert Ok(token) =
    gaseto.decrypt(
      vector.token,
      key,
      test_support.vector_rules(vector.implicit_assertion),
    )
  assert gaseto.payload(token) == vector.payload
  assert gaseto.footer(token) == <<vector.footer:utf8>>
  assert gaseto.purpose(token) == Local
  assert gaseto.version(token) == PasetoV3
}

pub fn local_vectors_encrypt_to_the_exact_token_test() -> Nil {
  // A fixed nonce makes encryption deterministic
  use vector <- list.each(paseto_v3_test_vector.local_vectors)
  let assert Ok(key) = paseto_v3.local_key_from_hex(vector.key)
  let assert Ok(nonce) = bit_array.base16_decode(vector.nonce)
  let assert Ok(token) =
    paseto_v3.encrypt(key, vector.payload, <<vector.footer:utf8>>, nonce, <<
      vector.implicit_assertion:utf8,
    >>)
  assert token == vector.token
}

pub fn local_round_trip_test() -> Nil {
  use vector <- list.each(paseto_v3_test_vector.local_vectors)
  let assert Ok(key) = gaseto.local_key_from_hex(PasetoV3, vector.key)
  let claims =
    gaseto.new_claims()
    |> gaseto.with_subject("user-42")
    |> gaseto.with_claim("data", json.string(vector.payload))
    |> gaseto.with_footer(<<vector.footer:utf8>>)
    |> gaseto.with_implicit_assertion(<<vector.implicit_assertion:utf8>>)
  let assert Ok(token) = gaseto.encrypt(claims, key)
  let rules =
    gaseto.new_rules()
    |> gaseto.expect_implicit_assertion(<<vector.implicit_assertion:utf8>>)
  let assert Ok(decrypted) = gaseto.decrypt(token, key, rules)
  assert gaseto.subject(decrypted) == Some("user-42")
  assert gaseto.footer(decrypted) == <<vector.footer:utf8>>
}

pub fn public_vectors_verify_test() -> Nil {
  use vector <- list.each(paseto_v3_test_vector.public_vectors)
  let assert Ok(key) = gaseto.public_key_from_hex(PasetoV3, vector.public_key)
  let assert Ok(token) =
    gaseto.verify(
      vector.token,
      key,
      test_support.vector_rules(vector.implicit_assertion),
    )
  assert gaseto.payload(token) == vector.payload
  assert gaseto.footer(token) == <<vector.footer:utf8>>
  assert gaseto.purpose(token) == Public
  assert gaseto.version(token) == PasetoV3
}

pub fn public_round_trip_test() -> Nil {
  // ECDSA is randomised, so check by verifying. This also checks the public
  // key that signing derives from the secret key.
  use vector <- list.each(paseto_v3_test_vector.public_vectors)
  let assert Ok(secret_key) =
    gaseto.secret_key_from_hex(PasetoV3, vector.secret_key)
  let assert Ok(public_key) =
    gaseto.public_key_from_hex(PasetoV3, vector.public_key)
  let claims =
    gaseto.new_claims()
    |> gaseto.with_subject("user-42")
    |> gaseto.with_footer(<<vector.footer:utf8>>)
    |> gaseto.with_implicit_assertion(<<vector.implicit_assertion:utf8>>)
  let assert Ok(token) = gaseto.sign(claims, secret_key)
  assert gaseto.unverified_footer(token) == Ok(<<vector.footer:utf8>>)
  let rules =
    gaseto.new_rules()
    |> gaseto.expect_implicit_assertion(<<vector.implicit_assertion:utf8>>)
  let assert Ok(verified) = gaseto.verify(token, public_key, rules)
  assert gaseto.subject(verified) == Some("user-42")
  assert gaseto.footer(verified) == <<vector.footer:utf8>>
}

pub fn failure_vectors_are_rejected_for_the_right_reason_test() -> Nil {
  use vector <- list.each(paseto_v3_test_vector.failure_vectors)
  let rules = test_support.vector_rules(vector.implicit_assertion)
  case vector.name {
    "3-F-1" -> {
      // A local token given a public key
      let assert Ok(key) = gaseto.public_key_from_hex(PasetoV3, vector.key)
      assert gaseto.verify(vector.token, key, rules)
        == Error(error.UnexpectedPurpose(expected: "public", found: "local"))
    }
    "3-F-2" -> {
      // A public token given a local key
      let assert Ok(key) = gaseto.local_key_from_hex(PasetoV3, vector.key)
      assert gaseto.decrypt(vector.token, key, rules)
        == Error(error.UnexpectedPurpose(expected: "local", found: "public"))
    }
    "3-F-3" -> {
      // A V4 token given a V3 key
      let assert Ok(key) = gaseto.local_key_from_hex(PasetoV3, vector.key)
      assert gaseto.decrypt(vector.token, key, rules)
        == Error(error.UnexpectedVersion(expected: "v3", found: "v4"))
    }
    "3-F-4" | "3-F-5" -> {
      // A changed last character and base64url padding both fail strict
      // decoding before the tag is checked
      let assert Ok(key) = gaseto.local_key_from_hex(PasetoV3, vector.key)
      assert gaseto.decrypt(vector.token, key, rules)
        == Error(error.InvalidFormat(error.NotBase64Url))
    }
    name -> panic as { "No expectation for failure vector " <> name }
  }
}

pub fn changed_local_token_is_rejected_test() -> Nil {
  let vector = paseto_v3_test_vector.first_local_vector()
  let assert Ok(key) = gaseto.local_key_from_hex(PasetoV3, vector.key)
  let rules = test_support.vector_rules("")
  let assert Error(error.TokenNotAuthentic) =
    gaseto.decrypt(tampered_token.with_changed_body(vector.token), key, rules)
  let assert Error(error.TokenNotAuthentic) =
    gaseto.decrypt(tampered_token.with_changed_footer(vector.token), key, rules)
  Nil
}

pub fn changed_public_token_is_rejected_test() -> Nil {
  let vector = paseto_v3_test_vector.first_public_vector()
  let assert Ok(key) = gaseto.public_key_from_hex(PasetoV3, vector.public_key)
  let rules = test_support.vector_rules("")
  let assert Error(error.TokenNotAuthentic) =
    gaseto.verify(tampered_token.with_changed_body(vector.token), key, rules)
  let assert Error(error.TokenNotAuthentic) =
    gaseto.verify(tampered_token.with_changed_footer(vector.token), key, rules)
  Nil
}

pub fn wrong_key_of_the_right_length_is_rejected_test() -> Nil {
  let assert Ok(other_key) =
    gaseto.local_key_from_hex(PasetoV3, string.repeat("ab", 32))
  let assert Error(error.TokenNotAuthentic) =
    gaseto.decrypt(
      paseto_v3_test_vector.first_local_vector().token,
      other_key,
      test_support.vector_rules(""),
    )
  Nil
}

pub fn missing_implicit_assertion_is_rejected_test() -> Nil {
  let assert Ok(vector) =
    list.find(paseto_v3_test_vector.local_vectors, fn(vector) {
      vector.implicit_assertion != ""
    })
  let assert Ok(key) = gaseto.local_key_from_hex(PasetoV3, vector.key)
  let assert Error(error.TokenNotAuthentic) =
    gaseto.decrypt(vector.token, key, test_support.vector_rules(""))
  Nil
}

pub fn secret_key_outside_the_curve_range_is_rejected_test() -> Nil {
  let outside = Error(error.OutsideCurveRange)
  assert gaseto.secret_key_from_hex(PasetoV3, string.repeat("00", 48))
    == outside
  assert gaseto.secret_key_from_hex(PasetoV3, string.repeat("ff", 48))
    == outside
}

pub fn uncompressed_public_key_is_rejected_test() -> Nil {
  // The spec requires compressed points
  // (https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#verify)
  let assert Ok(<<_prefix, x_coordinate:bytes>>) =
    bit_array.base16_decode(
      paseto_v3_test_vector.first_public_vector().public_key,
    )
  let uncompressed = bit_array.base16_encode(<<0x04, x_coordinate:bits>>)
  assert gaseto.public_key_from_hex(PasetoV3, uncompressed)
    == Error(error.NotACompressedPoint)
}

pub fn public_key_off_the_curve_is_rejected_test() -> Nil {
  // No point on P-384 has 1 as its X coordinate
  let off_curve = "02" <> string.repeat("00", 47) <> "01"
  assert gaseto.public_key_from_hex(PasetoV3, off_curve)
    == Error(error.NotOnCurve)
}

pub fn invalid_keys_are_rejected_test() -> Nil {
  assert gaseto.local_key_from_hex(PasetoV3, "not hex") == Error(error.NotHex)
  assert gaseto.local_key_from_hex(PasetoV3, "abcd")
    == Error(error.WrongLength(expected: 32, found: 2))
  assert gaseto.secret_key_from_hex(PasetoV3, "abcd")
    == Error(error.WrongLength(expected: 48, found: 2))
  assert gaseto.public_key_from_hex(PasetoV3, "abcd")
    == Error(error.WrongLength(expected: 49, found: 2))
}
