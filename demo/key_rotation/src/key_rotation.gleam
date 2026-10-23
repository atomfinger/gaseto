//// Rotating keys. Each token names the key that signed it in its footer
//// (`kid`), and the verifier keeps a ring of public keys by name. During a
//// rotation the ring holds both the old and the new key, so tokens signed
//// with either still verify. Once the old tokens have expired, the old key is
//// removed.

import gaseto.{PasetoV4}
import gaseto/error
import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/dynamic/decode
import gleam/io
import gleam/json
import gleam/result
import gleam/string

/// Why a token from a key ring could not be verified.
pub type VerifyError {
  /// The token cannot be read, so its footer cannot be found.
  UnreadableToken(error: error.TokenFormatError)
  /// The footer is not JSON with a `kid` string.
  NoKeyIdentifier(error: error.FooterDecodingError)
  /// The ring has no key with this name.
  UnknownKey(key_identifier: String)
  /// The key was found, but the token was refused.
  Refused(error: error.TokenValidationError)
}

pub fn main() -> Nil {
  // The keys are generated here so the demo runs on its own. A real service
  // loads them.
  let old_secret_key = gaseto.generate_secret_key(PasetoV4)
  let new_secret_key = gaseto.generate_secret_key(PasetoV4)
  let claims = gaseto.new_claims() |> gaseto.with_subject("user-42")
  let assert Ok(old_token) = sign(claims, "2026-01", old_secret_key)
  let assert Ok(new_token) = sign(claims, "2026-07", new_secret_key)

  let during_rotation =
    dict.from_list([
      #("2026-01", gaseto.secret_key_to_public_key(old_secret_key)),
      #("2026-07", gaseto.secret_key_to_public_key(new_secret_key)),
    ])
  let after_rotation = dict.delete(during_rotation, "2026-01")

  report("Old token, during the rotation", old_token, during_rotation)
  report("New token, during the rotation", new_token, during_rotation)
  report("Old token, after the rotation", old_token, after_rotation)
  report("New token, after the rotation", new_token, after_rotation)
}

/// Signs the claims and names the key in the footer.
pub fn sign(
  claims: gaseto.Claims,
  key_identifier: String,
  secret_key: gaseto.SecretKey,
) -> Result(String, error.TokenCreationError) {
  let footer =
    json.object([#("kid", json.string(key_identifier))])
    |> json.to_string
    |> bit_array.from_string
  claims |> gaseto.with_footer(footer) |> gaseto.sign(secret_key)
}

/// Picks the key named in the footer, then verifies the token with it. The
/// footer is only trusted to choose the key: the signature covers it, so a
/// changed `kid` makes the token fail.
pub fn verify(
  token: String,
  key_ring: Dict(String, gaseto.PublicKey),
  rules: gaseto.Rules,
) -> Result(gaseto.Token, VerifyError) {
  use footer <- result.try(
    gaseto.unverified_footer(token) |> result.map_error(UnreadableToken),
  )
  use key_identifier <- result.try(
    gaseto.decode_footer(
      footer,
      gaseto.default_footer_rules,
      decode.at(["kid"], decode.string),
    )
    |> result.map_error(NoKeyIdentifier),
  )
  use public_key <- result.try(
    dict.get(key_ring, key_identifier)
    |> result.replace_error(UnknownKey(key_identifier)),
  )
  gaseto.verify(token, public_key, rules) |> result.map_error(Refused)
}

fn report(
  label: String,
  token: String,
  key_ring: Dict(String, gaseto.PublicKey),
) -> Nil {
  let outcome = case verify(token, key_ring, gaseto.new_rules()) {
    Ok(_) -> "verified"
    Error(error) -> "refused: " <> string.inspect(error)
  }
  io.println(label <> ": " <> outcome)
}
