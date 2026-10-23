import gaseto.{PasetoV4}
import gaseto/error
import gaseto/internal/paseto_v4
import gaseto/paseto_v4_test_vector
import gleam/float
import gleam/time/timestamp.{type Timestamp}

/// The official vectors expire in 2022, so they are checked at a time before
/// that.
pub fn vector_rules(implicit_assertion: String) -> gaseto.Rules {
  gaseto.new_rules()
  |> gaseto.checked_at(timestamp.from_unix_seconds(1_609_459_200))
  |> gaseto.expect_implicit_assertion(<<implicit_assertion:utf8>>)
}

pub fn first_local_key() -> gaseto.LocalKey {
  let assert Ok(key) =
    gaseto.local_key_from_hex(
      PasetoV4,
      paseto_v4_test_vector.first_local_vector().key,
    )
  key
}

/// A token with exactly this payload, which `with_claim` could not make.
pub fn encrypt_raw_payload(payload: String) -> String {
  let assert Ok(key) =
    paseto_v4.local_key_from_hex(paseto_v4_test_vector.first_local_vector().key)
  let assert Ok(token) =
    paseto_v4.encrypt(key, payload, <<>>, <<0:size(256)>>, <<>>)
  token
}

pub fn round_trip(
  claims: gaseto.Claims,
  rules: gaseto.Rules,
) -> Result(gaseto.Token, error.TokenValidationError) {
  let assert Ok(token) = gaseto.encrypt(claims, first_local_key())
  gaseto.decrypt(token, first_local_key(), rules)
}

/// Tokens leave out fractions of a second, so times are compared without them.
pub fn whole_seconds(time: Timestamp) -> Timestamp {
  time
  |> timestamp.to_unix_seconds
  |> float.truncate
  |> timestamp.from_unix_seconds
}
