import gaseto.{PasetoV3, PasetoV4}
import generate_keys
import gleam/list
import gleam/option.{Some}
import gleeunit

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn printed_keys_load_and_work_together_test() -> Nil {
  use version <- list.each([PasetoV3, PasetoV4])
  let keys = generate_keys.new_keys(version)
  let assert Ok(local_key) =
    gaseto.local_key_from_hex(version, keys.local_key_hex)
  let assert Ok(secret_key) =
    gaseto.secret_key_from_hex(version, keys.secret_key_hex)
  let assert Ok(public_key) =
    gaseto.public_key_from_hex(version, keys.public_key_hex)
  let claims = gaseto.new_claims() |> gaseto.with_subject("alice")

  let assert Ok(token) = gaseto.encrypt(claims, local_key)
  let assert Ok(token) = gaseto.decrypt(token, local_key, gaseto.new_rules())
  assert gaseto.subject(token) == Some("alice")

  let assert Ok(token) = gaseto.sign(claims, secret_key)
  let assert Ok(token) = gaseto.verify(token, public_key, gaseto.new_rules())
  assert gaseto.subject(token) == Some("alice")
}

pub fn keys_are_new_every_time_test() -> Nil {
  use version <- list.each([PasetoV3, PasetoV4])
  assert generate_keys.new_keys(version) != generate_keys.new_keys(version)
}

pub fn main_prints_without_failing_test() -> Nil {
  generate_keys.main()
}
