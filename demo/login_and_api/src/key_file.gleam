import envoy
import gaseto.{PasetoV4}
import gaseto/error
import gleam/string
import simplifile

/// Reads the file named in an environment variable.
pub fn read(variable: String) -> String {
  let assert Ok(path) = envoy.get(variable)
    as { "Set " <> variable <> " to the path of the key file" }
  let assert Ok(contents) = simplifile.read(path)
    as { "Could not read the file in " <> variable }
  contents
}

/// A version 4 secret key, in hex as `generate_keys` prints it, or in PEM as
/// `openssl genpkey` writes it.
pub fn secret_key(
  text: String,
) -> Result(gaseto.SecretKey, error.KeyLoadingError) {
  case is_pem(text) {
    True -> gaseto.secret_key_from_pem(PasetoV4, text)
    False -> gaseto.secret_key_from_hex(PasetoV4, string.trim(text))
  }
}

/// A version 4 public key, in hex as `generate_keys` prints it, or in PEM as
/// `openssl pkey -pubout` writes it.
pub fn public_key(
  text: String,
) -> Result(gaseto.PublicKey, error.KeyLoadingError) {
  case is_pem(text) {
    True -> gaseto.public_key_from_pem(PasetoV4, text)
    False -> gaseto.public_key_from_hex(PasetoV4, string.trim(text))
  }
}

fn is_pem(text: String) -> Bool {
  string.starts_with(string.trim_start(text), "-----BEGIN")
}
