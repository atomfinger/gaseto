import gaseto.{PasetoV4}
import gaseto/error
import gaseto/paseto_v4_test_vector
import gaseto/test_support
import gleam/json
import gleam/list
import gleam/string

pub fn header_is_case_sensitive_test() -> Nil {
  let token = paseto_v4_test_vector.first_local_vector().token
  let upper_case_version = string.replace(token, "v4.", "V4.")
  let upper_case_purpose = string.replace(token, ".local.", ".LOCAL.")
  assert gaseto.decrypt(
      upper_case_version,
      test_support.first_local_key(),
      test_support.vector_rules(""),
    )
    == Error(error.InvalidFormat(error.UnknownVersion("V4")))
  assert gaseto.decrypt(
      upper_case_purpose,
      test_support.first_local_key(),
      test_support.vector_rules(""),
    )
    == Error(error.InvalidFormat(error.UnknownPurpose("LOCAL")))
  Nil
}

pub fn malformed_tokens_report_what_is_wrong_test() -> Nil {
  let body =
    string.drop_start(paseto_v4_test_vector.first_local_vector().token, 9)
  use #(token, expected) <- list.each([
    #("v9.local." <> body, error.UnknownVersion("v9")),
    #("v4.secret." <> body, error.UnknownPurpose("secret")),
    #("v4.local", error.WrongNumberOfSegments),
    #("v4.local." <> body <> ".e30.e30", error.WrongNumberOfSegments),
    #("v4.local." <> body <> ".", error.EmptyFooterSegment),
    #("v4.local.not*base64", error.NotBase64Url),
    #("v4.local." <> body <> "=", error.NotBase64Url),
    // Three bytes cannot hold a nonce and a tag
    #("v4.local.AAAA", error.BodyTooShort),
  ])
  assert gaseto.decrypt(
      token,
      test_support.first_local_key(),
      test_support.vector_rules(""),
    )
    == Error(error.InvalidFormat(expected))
}

pub fn a_public_token_too_short_for_a_signature_is_refused_test() -> Nil {
  let assert [vector, ..] = paseto_v4_test_vector.public_vectors
  let assert Ok(public_key) =
    gaseto.public_key_from_hex(PasetoV4, vector.public_key)
  assert gaseto.verify("v4.public.AAAA", public_key, gaseto.new_rules())
    == Error(error.InvalidFormat(error.BodyTooShort))
}

pub fn unverified_footer_reports_format_errors_test() -> Nil {
  let body =
    string.drop_start(paseto_v4_test_vector.first_local_vector().token, 9)
  use #(token, expected) <- list.each([
    #("", error.WrongNumberOfSegments),
    #("hello", error.WrongNumberOfSegments),
    #("v1.local." <> body, error.UnsupportedVersion("v1")),
    #("v9.local." <> body, error.UnknownVersion("v9")),
    #("v4.secret." <> body, error.UnknownPurpose("secret")),
    #("v4.local." <> body <> ".", error.EmptyFooterSegment),
    #("v4.local." <> body <> ".not*base64", error.NotBase64Url),
    #("v4.local." <> body <> ".e30.e30", error.WrongNumberOfSegments),
  ])
  assert gaseto.unverified_footer(token) == Error(expected)
}

pub fn deprecated_versions_are_not_supported_test() -> Nil {
  let token = paseto_v4_test_vector.first_local_vector().token
  let version_1_token = string.replace(token, "v4.local.", "v1.local.")
  let version_2_token = string.replace(token, "v4.local.", "v2.local.")
  assert gaseto.decrypt(
      version_1_token,
      test_support.first_local_key(),
      test_support.vector_rules(""),
    )
    == Error(error.InvalidFormat(error.UnsupportedVersion("v1")))
  assert gaseto.decrypt(
      version_2_token,
      test_support.first_local_key(),
      test_support.vector_rules(""),
    )
    == Error(error.InvalidFormat(error.UnsupportedVersion("v2")))
}

pub fn tokens_longer_than_the_limit_are_refused_test() -> Nil {
  // Refused before anything else, so the rest need not be a token at all
  let too_long = string.repeat("a", 8193)
  assert gaseto.decrypt(
      too_long,
      test_support.first_local_key(),
      gaseto.new_rules(),
    )
    == Error(error.TokenTooLong(length: 8193, max_length: 8192))
}

pub fn the_token_length_limit_can_be_raised_test() -> Nil {
  let claims =
    gaseto.new_claims()
    |> gaseto.with_claim("padding", json.string(string.repeat("a", 9000)))
  let assert Ok(token) = gaseto.encrypt(claims, test_support.first_local_key())
  let assert Error(error.TokenTooLong(_, max_length: 8192)) =
    gaseto.decrypt(token, test_support.first_local_key(), gaseto.new_rules())
  let assert Ok(_) =
    gaseto.decrypt(
      token,
      test_support.first_local_key(),
      gaseto.new_rules() |> gaseto.allow_token_length(up_to: 16_384),
    )
  Nil
}
