import gaseto/paseto_v1
import gaseto/token.{
  type PasetoPurpose, type PasetoVersion, type Token, Local, PasetoV1, PasetoV2,
  PasetoV3, PasetoV4, Public,
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

pub fn decrypt(token: String, decode_key: String) -> Result(Token, Error) {
  use
    #(version, purpose, payload, footer): #(
      String,
      String,
      String,
      option.Option(String),
    )
  <- result.try(parse_token_parts(token))
  use paseto_version <- result.try(parse_paseto_version(version))
  use paseto_purpose <- result.try(parse_paseto_purpose(purpose))

  case paseto_version {
    PasetoV4 -> Error(NotImplementedError)
    PasetoV3 -> Error(NotImplementedError)
    PasetoV2 -> Error(NotImplementedError)
    PasetoV1 -> {
      case paseto_v1.decrypt(paseto_purpose, payload, footer, decode_key) {
        Ok(token) -> Ok(token)
        Error(error) -> {
          Error(DecodeTokenError("Neij"))
        }
      }
    }
  }
}

pub fn encrypt(
  payload: String,
  with_key: String,
  with_version: PasetoVersion,
  with_purpose: PasetoPurpose,
  with_footer: Option(String),
) -> Result(Token, Error) {
  case with_version {
    PasetoV1 ->
      case paseto_v1.encrypt(with_purpose, with_key, payload, with_footer) {
        Ok(token) -> Ok(token)
        Error(e) -> {
          Error(EncodeTokenError)
        }
      }
    PasetoV2 -> Error(NotImplementedError)
    PasetoV3 -> Error(NotImplementedError)
    PasetoV4 -> Error(NotImplementedError)
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

fn paseto_purpose_to_string(purpose: PasetoPurpose) -> String {
  case purpose {
    Public -> "public"
    Local -> "local"
  }
}

fn parse_paseto_purpose(purpose: String) -> Result(PasetoPurpose, Error) {
  case string.lowercase(purpose) {
    "local" -> Ok(Local)
    "public" -> Ok(Public)
    _ -> Error(ParseTokenError("Invalid paseto purpose: " <> purpose))
  }
}
