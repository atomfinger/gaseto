import gaseto/paseto_v1
import gaseto/paseto_v3
import gaseto/token.{
  type PasetoVersion, type Token, Local, PasetoV1, PasetoV2, PasetoV3, PasetoV4,
  Public,
}
import gleam/option.{type Option}
import gleam/result
import gleam/string

pub type Error {
  ParseTokenError(message: String)
  InvalidTokenFormat(message: String)
  EncodeTokenError
  DecodeTokenError(message: String)
  NotImplementedError
}

/// The key material passed to encrypt and decrypt.
/// Use LocalKey for symmetric local tokens and KeyPair for asymmetric public tokens.
pub type Key {
  LocalKey(key: String)
  KeyPair(secret_key: String, public_key: String)
}

pub fn to_string(token: Token) -> String {
  paseto_version_to_string(token.version)
  <> "."
  <> paseto_purpose_to_string(token.purpose)
  <> "."
  <> token.payload
  <> case token.footer {
    option.Some(footer) -> "." <> footer
    option.None -> ""
  }
}

/// Encrypts or signs a payload depending on the key type.
/// LocalKey produces a local (encrypted) token; KeyPair produces a public (signed) token.
pub fn encrypt(
  payload: String,
  with_key: Key,
  with_version: PasetoVersion,
  with_footer: Option(String),
) -> Result(Token, Error) {
  case with_version, with_key {
    PasetoV1, LocalKey(key) ->
      case paseto_v1.encrypt(Local, key, payload, with_footer) {
        Ok(token) -> Ok(token)
        Error(_e) -> Error(EncodeTokenError)
      }
    PasetoV1, KeyPair(secret_key, _) ->
      case paseto_v1.encrypt(Public, secret_key, payload, with_footer) {
        Ok(token) -> Ok(token)
        Error(_e) -> Error(EncodeTokenError)
      }
    PasetoV3, LocalKey(key) ->
      case paseto_v3.encrypt(Local, key, payload, with_footer) {
        Ok(token) -> Ok(token)
        Error(_e) -> Error(EncodeTokenError)
      }
    PasetoV3, KeyPair(secret_key, public_key) ->
      case
        paseto_v3.encrypt_public(secret_key, public_key, payload, with_footer, "")
      {
        Ok(token) -> Ok(token)
        Error(_e) -> Error(EncodeTokenError)
      }
    _, _ -> Error(NotImplementedError)
  }
}

/// Decrypts or verifies a token depending on the key type.
/// LocalKey is used for local tokens; KeyPair uses the public_key for verification.
pub fn decrypt(token: String, with_key: Key) -> Result(Token, Error) {
  use #(version, purpose, payload, footer): #(
    String,
    String,
    String,
    option.Option(String),
  ) <- result.try(parse_token_parts(token))
  use paseto_version <- result.try(parse_paseto_version(version))
  use paseto_purpose <- result.try(parse_paseto_purpose(purpose))

  case paseto_version, with_key {
    PasetoV1, LocalKey(key) ->
      case paseto_v1.decrypt(paseto_purpose, payload, footer, key) {
        Ok(token) -> Ok(token)
        Error(_e) -> Error(DecodeTokenError("V1 decryption failed"))
      }
    PasetoV1, KeyPair(_, public_key) ->
      case paseto_v1.decrypt(paseto_purpose, payload, footer, public_key) {
        Ok(token) -> Ok(token)
        Error(_e) -> Error(DecodeTokenError("V1 verification failed"))
      }
    PasetoV3, LocalKey(key) ->
      case paseto_v3.decrypt(paseto_purpose, payload, footer, key, "") {
        Ok(token) -> Ok(token)
        Error(_e) -> Error(DecodeTokenError("V3 decryption failed"))
      }
    PasetoV3, KeyPair(_, public_key) ->
      case paseto_v3.decrypt(paseto_purpose, payload, footer, public_key, "") {
        Ok(token) -> Ok(token)
        Error(_e) -> Error(DecodeTokenError("V3 verification failed"))
      }
    _, _ -> Error(NotImplementedError)
  }
}

fn parse_token_parts(
  token: String,
) -> Result(#(String, String, String, option.Option(String)), Error) {
  case string.split(token, on: ".") {
    [version, purpose, payload] -> Ok(#(version, purpose, payload, option.None))
    [version, purpose, payload, footer] ->
      Ok(#(version, purpose, payload, option.Some(footer)))
    _ -> Error(ParseTokenError("Incorrect token syntax"))
  }
}

fn parse_paseto_version(version: String) -> Result(PasetoVersion, Error) {
  case string.lowercase(version) {
    "v1" -> Ok(PasetoV1)
    "v2" -> Ok(PasetoV2)
    "v3" -> Ok(PasetoV3)
    "v4" -> Ok(PasetoV4)
    _ -> Error(ParseTokenError("Invalid paseto version: " <> version))
  }
}

fn paseto_version_to_string(version: PasetoVersion) -> String {
  case version {
    PasetoV4 -> "v4"
    PasetoV3 -> "v3"
    PasetoV2 -> "v2"
    PasetoV1 -> "v1"
  }
}

fn paseto_purpose_to_string(purpose: token.PasetoPurpose) -> String {
  case purpose {
    Public -> "public"
    Local -> "local"
  }
}

fn parse_paseto_purpose(purpose: String) -> Result(token.PasetoPurpose, Error) {
  case string.lowercase(purpose) {
    "local" -> Ok(Local)
    "public" -> Ok(Public)
    _ -> Error(ParseTokenError("Invalid paseto purpose: " <> purpose))
  }
}
