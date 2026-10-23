import gaseto.{PasetoV4}
import gaseto/error
import gleam/dict
import gleam/option.{Some}
import gleeunit
import key_rotation.{NoKeyIdentifier, Refused, UnknownKey, UnreadableToken}

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn tokens_from_both_keys_verify_during_a_rotation_test() -> Nil {
  let old_secret_key = gaseto.generate_secret_key(PasetoV4)
  let new_secret_key = gaseto.generate_secret_key(PasetoV4)
  let key_ring =
    dict.from_list([
      #("old", gaseto.secret_key_to_public_key(old_secret_key)),
      #("new", gaseto.secret_key_to_public_key(new_secret_key)),
    ])
  let claims = gaseto.new_claims() |> gaseto.with_subject("user-42")
  let assert Ok(old_token) = key_rotation.sign(claims, "old", old_secret_key)
  let assert Ok(new_token) = key_rotation.sign(claims, "new", new_secret_key)
  let assert Ok(old) =
    key_rotation.verify(old_token, key_ring, gaseto.new_rules())
  let assert Ok(new) =
    key_rotation.verify(new_token, key_ring, gaseto.new_rules())
  assert gaseto.subject(old) == Some("user-42")
  assert gaseto.subject(new) == Some("user-42")
}

pub fn tokens_from_a_removed_key_are_refused_test() -> Nil {
  let old_secret_key = gaseto.generate_secret_key(PasetoV4)
  let new_secret_key = gaseto.generate_secret_key(PasetoV4)
  let key_ring =
    dict.from_list([#("new", gaseto.secret_key_to_public_key(new_secret_key))])
  let assert Ok(old_token) =
    key_rotation.sign(gaseto.new_claims(), "old", old_secret_key)
  assert key_rotation.verify(old_token, key_ring, gaseto.new_rules())
    == Error(UnknownKey("old"))
}

pub fn a_token_naming_the_wrong_key_is_refused_test() -> Nil {
  // The footer says "new", but the old key signed it
  let old_secret_key = gaseto.generate_secret_key(PasetoV4)
  let new_secret_key = gaseto.generate_secret_key(PasetoV4)
  let key_ring =
    dict.from_list([#("new", gaseto.secret_key_to_public_key(new_secret_key))])
  let assert Ok(token) =
    key_rotation.sign(gaseto.new_claims(), "new", old_secret_key)
  assert key_rotation.verify(token, key_ring, gaseto.new_rules())
    == Error(Refused(error.TokenNotAuthentic))
}

pub fn a_token_without_a_key_identifier_is_refused_test() -> Nil {
  let secret_key = gaseto.generate_secret_key(PasetoV4)
  let key_ring =
    dict.from_list([#("new", gaseto.secret_key_to_public_key(secret_key))])
  let assert Ok(no_footer) = gaseto.sign(gaseto.new_claims(), secret_key)
  let assert Ok(other_footer) =
    gaseto.new_claims()
    |> gaseto.with_footer(<<"{\"key\":\"new\"}":utf8>>)
    |> gaseto.sign(secret_key)
  let assert Error(NoKeyIdentifier(_)) =
    key_rotation.verify(no_footer, key_ring, gaseto.new_rules())
  let assert Error(NoKeyIdentifier(_)) =
    key_rotation.verify(other_footer, key_ring, gaseto.new_rules())
  Nil
}

pub fn an_unreadable_token_is_refused_test() -> Nil {
  assert key_rotation.verify("not a token", dict.new(), gaseto.new_rules())
    == Error(UnreadableToken(error.WrongNumberOfSegments))
}

pub fn main_runs_test() -> Nil {
  key_rotation.main()
}
