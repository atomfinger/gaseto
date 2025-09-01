import gleam/io
import gleam/option.{type Option}
import gleam/result
import gleam/string

pub type Error {
  ParseTokenError(message: String)
}

pub type Token {
  Token(
    version: PasetoVersion,
    purpose: PasetoPurpose,
    payload: String,
    footer: Option(String),
  )
}

pub type PasetoVersion {
  PasetoV1
  PasetoV2
  PasetoV3
  PasetoV4
}

pub type PasetoPurpose {
  Local
  Public
}

pub fn parse_token(token: String) -> Result(Token, Error) {
  use #(version, purpose, payload): #(String, String, String) <- result.try(
    parse_token_parts(token),
  )
  use paseto_version <- result.try(parse_paseto_version(version))
  use paseto_purpose <- result.try(parse_paseto_purpose(purpose))

  todo
}

fn parse_token_parts(token: String) -> Result(#(String, String, String), Error) {
  case string.split(token, on: ".") {
    [version, purpose, payload] -> Ok(#(version, purpose, payload))
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

fn parse_paseto_purpose(purpose: String) -> Result(PasetoPurpose, Error) {
  case string.lowercase(purpose) {
    "local" -> Ok(Local)
    "public" -> Ok(Public)
    _ -> Error(ParseTokenError("Invalid paseto purpose: " <> purpose))
  }
}
