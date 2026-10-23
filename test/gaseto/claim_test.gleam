import gaseto
import gaseto/error
import gaseto/test_support
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleam/time/duration
import gleam/time/timestamp

pub fn payload_must_be_a_json_object_with_unique_keys_test() -> Nil {
  use payload <- list.each([
    "", "[]", "[{\"a\":1}]", "\"text\"", "42", "{\"a\":1,\"a\":2}",
    "{\"a\":{\"b\":1,\"b\":2}}", "{\"a\":1,\"\\u0061\":2}",
    "{\"a\":[{\"b\":1,\"b\":2}]}", "{\"sub\":\"alice\",\"sub\":\"bob\"}",
    "{\"a\":1,}", "{\"a\":1} trailing", "not json",
  ])
  let assert Error(error.InvalidPayload) =
    gaseto.decrypt(
      test_support.encrypt_raw_payload(payload),
      test_support.first_local_key(),
      gaseto.new_rules() |> gaseto.allow_no_expiration,
    )
  Nil
}

pub fn same_key_in_different_objects_is_accepted_test() -> Nil {
  use payload <- list.each([
    "{\"a\":{\"b\":1},\"b\":2}", "{\"a\":[{\"b\":1},{\"b\":2}]}",
    "{\"a\":{\"a\":{\"a\":1}}}",
  ])
  let assert Ok(_) =
    gaseto.decrypt(
      test_support.encrypt_raw_payload(payload),
      test_support.first_local_key(),
      gaseto.new_rules() |> gaseto.allow_no_expiration,
    )
  Nil
}

pub fn registered_claim_that_is_null_is_refused_test() -> Nil {
  let assert Error(error.InvalidClaim(name: "sub", error: error.NotAString)) =
    gaseto.decrypt(
      test_support.encrypt_raw_payload("{\"sub\":null}"),
      test_support.first_local_key(),
      gaseto.new_rules() |> gaseto.allow_no_expiration,
    )
  Nil
}

pub fn custom_claim_with_the_same_key_in_nested_objects_is_accepted_test() -> Nil {
  let nested =
    json.object([
      #("a", json.object([#("a", json.int(1))])),
      #("b", json.preprocessed_array([json.object([#("a", json.int(2))])])),
    ])
  let claims = gaseto.new_claims() |> gaseto.with_claim("a", nested)
  let assert Ok(token) = test_support.round_trip(claims, gaseto.new_rules())
  assert json.parse(
      gaseto.payload(token),
      decode.at(["a", "b"], decode.list(decode.at(["a"], decode.int))),
    )
    == Ok([2])
}

pub fn custom_claim_with_repeated_keys_is_refused_test() -> Nil {
  let repeated =
    json.object([
      #("a", json.int(1)),
      #("b", json.object([#("c", json.int(2)), #("c", json.int(3))])),
    ])
  let claims = gaseto.new_claims() |> gaseto.with_claim("data", repeated)
  assert gaseto.encrypt(claims, test_support.first_local_key())
    == Error(error.RepeatedKeyInClaim("data"))
}

pub fn default_claims_expire_in_an_hour_test() -> Nil {
  let assert Ok(token) =
    test_support.round_trip(gaseto.new_claims(), gaseto.new_rules())
  let assert Some(issued_at) = gaseto.issued_at(token)
  let assert Some(expires_at) = gaseto.expires_at(token)
  assert timestamp.difference(issued_at, expires_at) == duration.hours(1)
  // The spec recommends whole seconds and a "Z" offset
  // (https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md#payload-claims)
  let assert Ok(times) =
    json.parse(gaseto.payload(token), {
      use expires_at <- decode.field("exp", decode.string)
      use issued_at <- decode.field("iat", decode.string)
      decode.success([expires_at, issued_at])
    })
  use time <- list.each(times)
  assert string.ends_with(time, "Z")
  assert !string.contains(time, ".")
}

pub fn claims_are_read_back_test() -> Nil {
  let claims =
    gaseto.new_claims()
    |> gaseto.with_issuer("auth.example.com")
    |> gaseto.with_subject("user-42")
    |> gaseto.with_audience("api")
    |> gaseto.with_token_identifier("token-1")
    |> gaseto.with_claim("role", json.string("admin"))
  let rules =
    gaseto.new_rules()
    |> gaseto.issued_by("auth.example.com")
    |> gaseto.for_subject("user-42")
    |> gaseto.for_audience("api")
    |> gaseto.identified_by("token-1")
  let assert Ok(token) = test_support.round_trip(claims, rules)
  assert gaseto.issuer(token) == Some("auth.example.com")
  assert gaseto.subject(token) == Some("user-42")
  assert gaseto.audience(token) == Some("api")
  assert gaseto.token_identifier(token) == Some("token-1")
  assert json.parse(gaseto.payload(token), decode.at(["role"], decode.string))
    == Ok("admin")
}

pub fn claims_that_differ_from_the_rules_are_refused_test() -> Nil {
  let claims = gaseto.new_claims() |> gaseto.with_issuer("someone-else")
  assert test_support.round_trip(
      claims,
      gaseto.new_rules() |> gaseto.issued_by("me"),
    )
    == Error(error.UnexpectedClaim(
      name: "iss",
      expected: "me",
      found: Some("someone-else"),
    ))
  // A required claim that is missing is refused too
  assert test_support.round_trip(
      claims,
      gaseto.new_rules() |> gaseto.for_audience("api"),
    )
    == Error(error.UnexpectedClaim(name: "aud", expected: "api", found: None))
}

pub fn registered_claim_names_are_refused_as_custom_claims_test() -> Nil {
  let claims = gaseto.new_claims() |> gaseto.with_claim("exp", json.int(0))
  assert gaseto.encrypt(claims, test_support.first_local_key())
    == Error(error.ReservedClaimName("exp"))
}

pub fn implicit_assertion_must_match_test() -> Nil {
  let claims =
    gaseto.new_claims() |> gaseto.with_implicit_assertion(<<"user-42":utf8>>)
  let assert Error(error.TokenNotAuthentic) =
    test_support.round_trip(claims, gaseto.new_rules())
  let assert Ok(_) =
    test_support.round_trip(
      claims,
      gaseto.new_rules()
        |> gaseto.expect_implicit_assertion(<<"user-42":utf8>>),
    )
  Nil
}

pub fn not_before_is_read_back_test() -> Nil {
  let a_minute_ago =
    test_support.whole_seconds(timestamp.add(
      timestamp.system_time(),
      duration.minutes(-1),
    ))
  let claims = gaseto.new_claims() |> gaseto.with_not_before(a_minute_ago)
  let assert Ok(token) = test_support.round_trip(claims, gaseto.new_rules())
  assert gaseto.not_before(token) == Some(a_minute_ago)
}
