import gaseto.{Local, PasetoV3, PasetoV4, Public}
import gaseto/error
import gaseto/internal/paseto_v4
import gaseto/paseto_v4_test_vector
import gaseto/tampered_token
import gaseto/test_support
import gleam/bit_array
import gleam/json
import gleam/list
import gleam/option.{Some}
import gleam/string
import kryptos/eddsa

pub fn local_vectors_decrypt_test() -> Nil {
  use vector <- list.each(paseto_v4_test_vector.local_vectors)
  let assert Ok(key) = gaseto.local_key_from_hex(PasetoV4, vector.key)
  let assert Ok(token) =
    gaseto.decrypt(
      vector.token,
      key,
      test_support.vector_rules(vector.implicit_assertion),
    )
  assert gaseto.payload(token) == vector.payload
  assert gaseto.footer(token) == <<vector.footer:utf8>>
  assert gaseto.purpose(token) == Local
  assert gaseto.version(token) == PasetoV4
}

pub fn local_vectors_encrypt_to_the_exact_token_test() -> Nil {
  // A fixed nonce makes encryption deterministic
  use vector <- list.each(paseto_v4_test_vector.local_vectors)
  let assert Ok(key) = paseto_v4.local_key_from_hex(vector.key)
  let assert Ok(nonce) = bit_array.base16_decode(vector.nonce)
  let assert Ok(token) =
    paseto_v4.encrypt(key, vector.payload, <<vector.footer:utf8>>, nonce, <<
      vector.implicit_assertion:utf8,
    >>)
  assert token == vector.token
}

pub fn local_round_trip_test() -> Nil {
  use vector <- list.each(paseto_v4_test_vector.local_vectors)
  let assert Ok(key) = gaseto.local_key_from_hex(PasetoV4, vector.key)
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

pub fn binary_footer_round_trip_test() -> Nil {
  // The spec puts no restrictions on the footer, so it need not be UTF-8
  // (https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md#optional-footer)
  let assert Ok(key) =
    gaseto.local_key_from_hex(
      PasetoV4,
      paseto_v4_test_vector.first_local_vector().key,
    )
  let footer = <<0xff, 0x00, 0xfe>>
  let claims = gaseto.new_claims() |> gaseto.with_footer(footer)
  let assert Ok(token) = gaseto.encrypt(claims, key)
  assert gaseto.unverified_footer(token) == Ok(footer)
  let assert Ok(decrypted) = gaseto.decrypt(token, key, gaseto.new_rules())
  assert gaseto.footer(decrypted) == footer
}

pub fn public_vectors_verify_test() -> Nil {
  use vector <- list.each(paseto_v4_test_vector.public_vectors)
  let assert Ok(key) = gaseto.public_key_from_hex(PasetoV4, vector.public_key)
  let assert Ok(token) =
    gaseto.verify(
      vector.token,
      key,
      test_support.vector_rules(vector.implicit_assertion),
    )
  assert gaseto.payload(token) == vector.payload
  assert gaseto.footer(token) == <<vector.footer:utf8>>
  assert gaseto.purpose(token) == Public
  assert gaseto.version(token) == PasetoV4
}

pub fn public_vectors_sign_to_the_exact_token_test() -> Nil {
  // Ed25519 is deterministic
  use vector <- list.each(paseto_v4_test_vector.public_vectors)
  let assert Ok(key) = paseto_v4.secret_key_from_hex(vector.secret_key)
  let assert Ok(token) =
    paseto_v4.sign(key, vector.payload, <<vector.footer:utf8>>, <<
      vector.implicit_assertion:utf8,
    >>)
  assert token == vector.token
}

pub fn public_round_trip_test() -> Nil {
  let vector = paseto_v4_test_vector.first_public_vector()
  let assert Ok(secret_key) =
    gaseto.secret_key_from_hex(PasetoV4, vector.secret_key)
  let assert Ok(public_key) =
    gaseto.public_key_from_hex(PasetoV4, vector.public_key)
  let claims =
    gaseto.new_claims()
    |> gaseto.with_subject("user-42")
    |> gaseto.with_footer(<<"{\"kid\":\"key-1\"}":utf8>>)
  let assert Ok(token) = gaseto.sign(claims, secret_key)
  assert gaseto.unverified_footer(token) == Ok(<<"{\"kid\":\"key-1\"}":utf8>>)
  let assert Ok(verified) = gaseto.verify(token, public_key, gaseto.new_rules())
  assert gaseto.subject(verified) == Some("user-42")
}

pub fn failure_vectors_are_rejected_for_the_right_reason_test() -> Nil {
  use vector <- list.each(paseto_v4_test_vector.failure_vectors)
  let rules = test_support.vector_rules(vector.implicit_assertion)
  case vector.name {
    "4-F-1" -> {
      // A local token given a public key
      let assert Ok(key) =
        gaseto.public_key_from_hex(PasetoV4, vector.public_key)
      assert gaseto.verify(vector.token, key, rules)
        == Error(error.UnexpectedPurpose(expected: "public", found: "local"))
    }
    "4-F-2" -> {
      // A public token given a local key
      let assert Ok(key) = gaseto.local_key_from_hex(PasetoV4, vector.key)
      assert gaseto.decrypt(vector.token, key, rules)
        == Error(error.UnexpectedPurpose(expected: "local", found: "public"))
    }
    "4-F-3" -> {
      // A valid V3 token given a V4 key
      let assert Ok(key) = gaseto.local_key_from_hex(PasetoV4, vector.key)
      assert gaseto.decrypt(vector.token, key, rules)
        == Error(error.UnexpectedVersion(expected: "v4", found: "v3"))
    }
    "4-F-4" | "4-F-5" -> {
      // A changed last character and base64url padding both fail strict
      // decoding before the tag is checked
      let assert Ok(key) = gaseto.local_key_from_hex(PasetoV4, vector.key)
      assert gaseto.decrypt(vector.token, key, rules)
        == Error(error.InvalidFormat(error.NotBase64Url))
    }
    name -> panic as { "No expectation for failure vector " <> name }
  }
}

pub fn changed_local_token_is_rejected_test() -> Nil {
  let vector = paseto_v4_test_vector.first_local_vector()
  let assert Ok(key) = gaseto.local_key_from_hex(PasetoV4, vector.key)
  let rules = test_support.vector_rules("")
  let assert Error(error.TokenNotAuthentic) =
    gaseto.decrypt(tampered_token.with_changed_body(vector.token), key, rules)
  let assert Error(error.TokenNotAuthentic) =
    gaseto.decrypt(tampered_token.with_changed_footer(vector.token), key, rules)
  Nil
}

pub fn changed_public_token_is_rejected_test() -> Nil {
  let vector = paseto_v4_test_vector.first_public_vector()
  let assert Ok(key) = gaseto.public_key_from_hex(PasetoV4, vector.public_key)
  let rules = test_support.vector_rules("")
  let assert Error(error.TokenNotAuthentic) =
    gaseto.verify(tampered_token.with_changed_body(vector.token), key, rules)
  let assert Error(error.TokenNotAuthentic) =
    gaseto.verify(tampered_token.with_changed_footer(vector.token), key, rules)
  Nil
}

pub fn wrong_key_of_the_right_length_is_rejected_test() -> Nil {
  let assert Ok(other_local_key) =
    gaseto.local_key_from_hex(PasetoV4, string.repeat("ab", 32))
  let assert Error(error.TokenNotAuthentic) =
    gaseto.decrypt(
      paseto_v4_test_vector.first_local_vector().token,
      other_local_key,
      test_support.vector_rules(""),
    )

  let #(_, other_public_key) = eddsa.generate_key_pair(eddsa.Ed25519)
  let assert Ok(other_public_key) =
    gaseto.public_key_from_hex(
      PasetoV4,
      bit_array.base16_encode(eddsa.public_key_to_bytes(other_public_key)),
    )
  let assert Error(error.TokenNotAuthentic) =
    gaseto.verify(
      paseto_v4_test_vector.first_public_vector().token,
      other_public_key,
      test_support.vector_rules(""),
    )
  Nil
}

pub fn key_of_another_version_is_rejected_test() -> Nil {
  // A 32-byte key fits both versions, but the version must still match
  let vector = paseto_v4_test_vector.first_local_vector()
  let assert Ok(key) = gaseto.local_key_from_hex(PasetoV3, vector.key)
  assert gaseto.decrypt(vector.token, key, test_support.vector_rules(""))
    == Error(error.UnexpectedVersion(expected: "v3", found: "v4"))
}

pub fn invalid_keys_are_rejected_test() -> Nil {
  let seed =
    string.slice(paseto_v4_test_vector.first_public_vector().secret_key, 0, 64)
  assert gaseto.local_key_from_hex(PasetoV4, "not hex") == Error(error.NotHex)
  assert gaseto.local_key_from_hex(PasetoV4, "abcd")
    == Error(error.WrongLength(expected: 32, found: 2))
  assert gaseto.public_key_from_hex(PasetoV4, "abcd")
    == Error(error.WrongLength(expected: 32, found: 2))
  assert gaseto.secret_key_from_hex(PasetoV4, seed)
    == Error(error.WrongLength(expected: 64, found: 32))
  assert gaseto.secret_key_from_hex(PasetoV4, seed <> string.repeat("00", 32))
    == Error(error.PublicHalfDoesNotMatchSeed)
}

pub fn verified_payload_that_is_not_json_is_rejected_test() -> Nil {
  // Signed with the internal module, which does not check the payload
  let vector = paseto_v4_test_vector.first_public_vector()
  let assert Ok(internal_key) = paseto_v4.secret_key_from_hex(vector.secret_key)
  let assert Ok(token) = paseto_v4.sign(internal_key, "not json", <<>>, <<>>)
  let assert Ok(key) = gaseto.public_key_from_hex(PasetoV4, vector.public_key)
  let assert Error(error.InvalidPayload) =
    gaseto.verify(token, key, gaseto.new_rules())
  Nil
}

pub fn header_is_compared_as_bytes_test() -> Nil {
  // A combining mark after "v4.local." would join the "." into one grapheme.
  // Read as bytes, the header matches and the body is then not base64.
  let assert Ok(key) =
    gaseto.local_key_from_hex(
      PasetoV4,
      paseto_v4_test_vector.first_local_vector().key,
    )
  let assert "v4.local." <> body =
    paseto_v4_test_vector.first_local_vector().token
  assert gaseto.decrypt("v4.local.\u{0301}" <> body, key, gaseto.new_rules())
    == Error(error.InvalidFormat(error.NotBase64Url))
}
