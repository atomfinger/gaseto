import gleam/option

pub type Token {
  Token(
    version: PasetoVersion,
    purpose: PasetoPurpose,
    payload: String,
    footer: option.Option(String),
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
