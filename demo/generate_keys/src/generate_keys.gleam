//// Prints a new local key and a new key pair for each version.

import gaseto.{PasetoV3, PasetoV4}
import gleam/io
import gleam/list

pub type NewKeys {
  NewKeys(
    version: gaseto.PasetoVersion,
    local_key_hex: String,
    secret_key_hex: String,
    public_key_hex: String,
  )
}

pub fn main() -> Nil {
  use keys <- list.each([new_keys(PasetoV4), new_keys(PasetoV3)])
  let label = case keys.version {
    PasetoV4 -> "Version 4"
    PasetoV3 -> "Version 3"
  }
  print(label <> " local key", keys.local_key_hex)
  print(label <> " secret key", keys.secret_key_hex)
  print(label <> " public key", keys.public_key_hex)
}

pub fn new_keys(version: gaseto.PasetoVersion) -> NewKeys {
  let secret_key = gaseto.generate_secret_key(version)
  NewKeys(
    version:,
    local_key_hex: gaseto.generate_local_key(version)
      |> gaseto.local_key_to_hex,
    secret_key_hex: gaseto.secret_key_to_hex(secret_key),
    public_key_hex: gaseto.secret_key_to_public_key(secret_key)
      |> gaseto.public_key_to_hex,
  )
}

fn print(label: String, key_hex: String) -> Nil {
  io.println(label <> ":\n" <> key_hex <> "\n")
}
