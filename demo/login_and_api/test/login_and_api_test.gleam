import api_service
import gaseto.{PasetoV4}
import gleam/dynamic/decode
import gleam/http
import gleam/http/response
import gleam/json
import gleam/option.{Some}
import gleam/time/duration
import gleam/time/timestamp
import gleeunit
import key_file
import login_service
import token_claim
import wisp
import wisp/simulate

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn login_gives_a_bearer_token_test() -> Nil {
  let keys = new_key_pair()
  let response = log_in(keys, "bob")
  assert response.status == 200
  let assert Ok(#(token_type, expires_in)) =
    json.parse(simulate.read_body(response), {
      use token_type <- decode.field("token_type", decode.string)
      use expires_in <- decode.field("expires_in", decode.int)
      decode.success(#(token_type, expires_in))
    })
  assert token_type == "Bearer"
  assert expires_in == 15 * 60
}

pub fn the_token_names_the_user_issuer_and_audience_test() -> Nil {
  let keys = new_key_pair()
  let assert Ok(token) =
    gaseto.verify(
      access_token(keys, "bob"),
      keys.public_key,
      gaseto.new_rules(),
    )
  assert gaseto.subject(token) == Some("bob")
  assert gaseto.issuer(token) == Some(token_claim.issuer)
  assert gaseto.audience(token) == Some(token_claim.audience)
  let assert Some(expires_at) = gaseto.expires_at(token)
  let assert Some(issued_at) = gaseto.issued_at(token)
  assert timestamp.difference(issued_at, expires_at) == duration.minutes(15)
}

pub fn the_api_accepts_a_token_from_the_login_service_test() -> Nil {
  let keys = new_key_pair()
  let response = call_api(keys, "Bearer " <> access_token(keys, "bob"))
  assert response.status == 200
  assert simulate.read_body(response) == "{\"user\":\"bob\"}"
}

pub fn the_bearer_scheme_is_not_case_sensitive_test() -> Nil {
  let keys = new_key_pair()
  let response = call_api(keys, "bearer " <> access_token(keys, "bob"))
  assert response.status == 200
}

pub fn the_api_refuses_a_request_without_a_token_test() -> Nil {
  let keys = new_key_pair()
  let response =
    api_service.handle_request(
      simulate.request(http.Get, "/me"),
      keys.public_key,
    )
  assert_unauthorized(response)
}

pub fn the_api_refuses_other_schemes_test() -> Nil {
  let keys = new_key_pair()
  assert_unauthorized(call_api(keys, "Basic " <> access_token(keys, "bob")))
  assert_unauthorized(call_api(keys, access_token(keys, "bob")))
}

pub fn the_api_refuses_a_token_signed_with_another_key_test() -> Nil {
  let keys = new_key_pair()
  let other_keys = new_key_pair()
  assert_unauthorized(call_api(
    keys,
    "Bearer " <> access_token(other_keys, "bob"),
  ))
}

pub fn the_api_refuses_a_token_for_another_audience_test() -> Nil {
  let keys = new_key_pair()
  let claims =
    gaseto.new_claims()
    |> gaseto.with_issuer(token_claim.issuer)
    |> gaseto.with_audience("other.example.com")
    |> gaseto.with_subject("bob")
  assert_unauthorized(call_api(keys, "Bearer " <> sign(claims, keys)))
}

pub fn the_api_refuses_a_token_from_another_issuer_test() -> Nil {
  let keys = new_key_pair()
  let claims =
    gaseto.new_claims()
    |> gaseto.with_issuer("other.example.com")
    |> gaseto.with_audience(token_claim.audience)
    |> gaseto.with_subject("bob")
  assert_unauthorized(call_api(keys, "Bearer " <> sign(claims, keys)))
}

pub fn the_api_refuses_an_expired_token_test() -> Nil {
  let keys = new_key_pair()
  let an_hour_ago = timestamp.add(timestamp.system_time(), duration.hours(-1))
  let claims =
    gaseto.new_claims()
    |> gaseto.with_issuer(token_claim.issuer)
    |> gaseto.with_audience(token_claim.audience)
    |> gaseto.with_subject("bob")
    |> gaseto.with_issued_at(an_hour_ago)
    |> gaseto.with_expires_at(timestamp.add(an_hour_ago, duration.minutes(15)))
  assert_unauthorized(call_api(keys, "Bearer " <> sign(claims, keys)))
}

pub fn logging_in_without_a_user_is_a_bad_request_test() -> Nil {
  let keys = new_key_pair()
  let request = simulate.request(http.Post, "/login") |> simulate.form_body([])
  assert login_service.handle_request(request, keys.secret_key).status == 400
}

pub fn the_api_accepts_a_token_that_expired_within_the_clock_skew_test() -> Nil {
  let keys = new_key_pair()
  let ten_seconds_ago =
    timestamp.add(timestamp.system_time(), duration.seconds(-10))
  assert call_api(keys, "Bearer " <> sign(expiring_at(ten_seconds_ago), keys)).status
    == 200
}

pub fn the_api_refuses_a_token_that_expired_beyond_the_clock_skew_test() -> Nil {
  let keys = new_key_pair()
  let a_minute_ago =
    timestamp.add(timestamp.system_time(), duration.minutes(-1))
  assert_unauthorized(call_api(
    keys,
    "Bearer " <> sign(expiring_at(a_minute_ago), keys),
  ))
}

pub fn keys_are_read_from_hex_or_pem_test() -> Nil {
  let assert Ok(from_hex) = key_file.secret_key(vector_secret_key_hex <> "\n")
  let assert Ok(from_pem) = key_file.secret_key(vector_secret_key_pem)
  assert gaseto.secret_key_to_hex(from_hex) == vector_secret_key_hex
  assert gaseto.secret_key_to_hex(from_pem) == vector_secret_key_hex
  let assert Ok(from_hex) = key_file.public_key(vector_public_key_hex <> "\n")
  let assert Ok(from_pem) = key_file.public_key(vector_public_key_pem)
  assert gaseto.public_key_to_hex(from_hex) == vector_public_key_hex
  assert gaseto.public_key_to_hex(from_pem) == vector_public_key_hex
}

pub fn a_key_file_with_something_else_is_refused_test() -> Nil {
  let assert Error(_) = key_file.secret_key("not a key")
  let assert Error(_) = key_file.secret_key(vector_public_key_pem)
  let assert Error(_) = key_file.public_key(vector_secret_key_pem)
  Nil
}

type KeyPair {
  KeyPair(secret_key: gaseto.SecretKey, public_key: gaseto.PublicKey)
}

// The key pair from the spec's test vector 4-S-1, in both formats
const vector_secret_key_hex: String =
  "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"

const vector_public_key_hex: String =
  "1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"

const vector_secret_key_pem: String =
  "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n-----END PRIVATE KEY-----"

const vector_public_key_pem: String =
  "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n-----END PUBLIC KEY-----"

fn new_key_pair() -> KeyPair {
  let secret_key = gaseto.generate_secret_key(PasetoV4)
  KeyPair(secret_key:, public_key: gaseto.secret_key_to_public_key(secret_key))
}

fn log_in(keys: KeyPair, user: String) -> wisp.Response {
  let request =
    simulate.request(http.Post, "/login")
    |> simulate.form_body([#("user", user)])
  login_service.handle_request(request, keys.secret_key)
}

fn access_token(keys: KeyPair, user: String) -> String {
  let assert Ok(token) =
    json.parse(
      simulate.read_body(log_in(keys, user)),
      decode.at(["access_token"], decode.string),
    )
  token
}

fn sign(claims: gaseto.Claims, keys: KeyPair) -> String {
  let assert Ok(token) = gaseto.sign(claims, keys.secret_key)
  token
}

fn call_api(keys: KeyPair, authorization: String) -> wisp.Response {
  let request =
    simulate.request(http.Get, "/me")
    |> simulate.header("authorization", authorization)
  api_service.handle_request(request, keys.public_key)
}

fn assert_unauthorized(response: wisp.Response) -> Nil {
  assert response.status == 401
  assert response.get_header(response, "www-authenticate") == Ok("Bearer")
}

fn expiring_at(expires_at: timestamp.Timestamp) -> gaseto.Claims {
  gaseto.new_claims()
  |> gaseto.with_issuer(token_claim.issuer)
  |> gaseto.with_audience(token_claim.audience)
  |> gaseto.with_subject("bob")
  |> gaseto.with_issued_at(timestamp.add(expires_at, duration.minutes(-15)))
  |> gaseto.with_expires_at(expires_at)
}
