import gaseto.{LocalKey}
import gaseto/paseto_v3
import gaseto/paseto_v3_test_vectors
import gaseto/token.{Local, Public}
import gleam/io
import gleam/list
import gleam/option
import gleam/string

// ─── Helpers ───────────────────────────────────────────────────────────────

/// Extracts the base64url payload and optional base64url footer from a full PASETO token string.
fn parse_token_body(token_string: String) -> #(String, option.Option(String)) {
  case string.split(token_string, ".") {
    [_, _, payload] -> #(payload, option.None)
    [_, _, payload, footer] -> #(payload, option.Some(footer))
    _ -> #("", option.None)
  }
}

fn option_from_string(s: String) -> option.Option(String) {
  case s {
    "" -> option.None
    _ -> option.Some(s)
  }
}

// ─── Local (V3.local) Tests ─────────────────────────────────────────────────

pub fn verify_v3_local_decode_test() {
  paseto_v3_test_vectors.paseto_v3_local_test_vectors
  |> list.each(fn(vector) {
    io.println("Testing decode V3 local: " <> vector.name)
    let #(payload_b64, footer_b64) = parse_token_body(vector.token)
    let assert Ok(tok) =
      paseto_v3.decrypt_local(
        vector.key,
        payload_b64,
        footer_b64,
        vector.implicit_assertion,
      )
    let expected_footer = option_from_string(vector.footer)
    assert tok.payload == vector.payload
    assert tok.footer == expected_footer
    assert tok.purpose == Local
    assert tok.version == token.PasetoV3
    io.println("Testing decode V3 local: " <> vector.name <> " | Passed")
  })
}

pub fn verify_v3_local_encode_and_decode_test() {
  // Round-trip test: encrypt with a random nonce, then decrypt, check payload.
  // Only vectors with no implicit assertion can use the gaseto public API (which passes "" implicitly).
  paseto_v3_test_vectors.paseto_v3_local_test_vectors
  |> list.filter(fn(v) { v.implicit_assertion == "" })
  |> list.each(fn(vector) {
    io.println("Testing encode/decode V3 local: " <> vector.name)
    let footer_option = option_from_string(vector.footer)
    let assert Ok(encrypted_token) =
      gaseto.encrypt(
        vector.payload,
        LocalKey(vector.key),
        token.PasetoV3,
        footer_option,
      )
    let token_string = gaseto.to_string(encrypted_token)
    let assert Ok(decrypted) = gaseto.decrypt(token_string, LocalKey(vector.key))
    assert decrypted.payload == vector.payload
    assert decrypted.footer == footer_option
    assert decrypted.purpose == Local
    assert decrypted.version == token.PasetoV3
    io.println(
      "Testing encode/decode V3 local: " <> vector.name <> " | Passed",
    )
  })
}

// ─── Public (V3.public) Tests ────────────────────────────────────────────────

pub fn verify_v3_public_decode_test() {
  paseto_v3_test_vectors.paseto_v3_public_test_vectors
  |> list.each(fn(vector) {
    io.println("Testing decode V3 public: " <> vector.name)
    let #(payload_b64, footer_b64) = parse_token_body(vector.token)
    let assert Ok(tok) =
      paseto_v3.decrypt_public(
        vector.public_key,
        payload_b64,
        footer_b64,
        vector.implicit_assertion,
      )
    let expected_footer = option_from_string(vector.footer)
    assert tok.payload == vector.payload
    assert tok.footer == expected_footer
    assert tok.purpose == Public
    assert tok.version == token.PasetoV3
    io.println("Testing decode V3 public: " <> vector.name <> " | Passed")
  })
}

pub fn verify_v3_public_sign_and_verify_test() {
  paseto_v3_test_vectors.paseto_v3_public_test_vectors
  |> list.each(fn(vector) {
    io.println("Testing sign/verify V3 public: " <> vector.name)
    let footer_option = option_from_string(vector.footer)
    let assert Ok(signed_token) =
      paseto_v3.encrypt_public(
        vector.secret_key,
        vector.public_key,
        vector.payload,
        footer_option,
        vector.implicit_assertion,
      )
    let token_string = gaseto.to_string(signed_token)
    let #(payload_b64, footer_b64) = parse_token_body(token_string)
    let assert Ok(verified) =
      paseto_v3.decrypt_public(
        vector.public_key,
        payload_b64,
        footer_b64,
        vector.implicit_assertion,
      )
    assert verified.payload == vector.payload
    assert verified.footer == footer_option
    assert verified.purpose == Public
    assert verified.version == token.PasetoV3
    io.println(
      "Testing sign/verify V3 public: " <> vector.name <> " | Passed",
    )
  })
}

// ─── Failure Cases ───────────────────────────────────────────────────────────

pub fn verify_v3_failure_cases_test() {
  paseto_v3_test_vectors.paseto_v3_fail_test_vectors
  |> list.each(fn(vector) {
    io.println("Testing failure case: " <> vector.name)
    let assert Error(_) = gaseto.decrypt(vector.token, LocalKey(vector.key))
    io.println("Testing failure case: " <> vector.name <> " | Passed")
  })
}
