import gaseto.{type PasetoPurpose, type PasetoVersion, PasetoV3, PasetoV4}
import gleam/dynamic/decode
import gleam/int
import gleam/io
import gleam/json
import gleam/list
import gleam/result
import gleam/string
import simplifile

const go_tokens_path: String = "interop/go_tokens.json"

const gaseto_tokens_path: String = "interop/gaseto_tokens.json"

const cases_per_kind: Int = 25

const kinds: List(#(PasetoVersion, PasetoPurpose)) = [
  #(PasetoV3, gaseto.Local),
  #(PasetoV3, gaseto.Public),
  #(PasetoV4, gaseto.Local),
  #(PasetoV4, gaseto.Public),
]

/// Characters that JSON encoders treat differently: quotes, backslashes,
/// control characters, HTML characters Go escapes, and multi-byte UTF-8.
const characters: String = "abcXYZ019 \"\\/\n\t<>&'é€😀\u{2028}"

/// One token, with the key and the values needed to check it. For a public
/// token the key is the public key.
type TokenCase {
  TokenCase(
    kind: String,
    key: String,
    token: String,
    footer: String,
    implicit_assertion: String,
    data: String,
  )
}

pub fn main() -> Nil {
  check_go_tokens()
  make_gaseto_tokens()
}

fn check_go_tokens() -> Nil {
  let assert Ok(go_tokens) = simplifile.read(go_tokens_path)
    as "run `go run . make go_tokens.json` in interop first"
  let assert Ok(token_cases) =
    json.parse(go_tokens, decode.list(token_case_decoder()))
  let failures =
    list.filter_map(token_cases, fn(token_case) {
      case check(token_case) {
        Ok(Nil) -> Error(Nil)
        Error(reason) -> Ok(token_case.kind <> ": " <> reason)
      }
    })
  list.each(failures, io.println)
  let count = int.to_string(list.length(token_cases))
  case failures {
    [] -> io.println("Gaseto accepted all " <> count <> " tokens")
    _ ->
      panic as {
        "Gaseto refused "
        <> int.to_string(list.length(failures))
        <> " of "
        <> count
        <> " tokens"
      }
  }
}

fn check(token_case: TokenCase) -> Result(Nil, String) {
  let rules =
    gaseto.new_rules()
    |> gaseto.issued_by("go-paseto")
    |> gaseto.for_audience("gaseto")
    |> gaseto.expect_implicit_assertion(<<token_case.implicit_assertion:utf8>>)
  use token <- result.try(read(token_case, rules))
  let data =
    json.parse(gaseto.payload(token), decode.at(["data"], decode.string))
  let footer = gaseto.footer(token)
  case data == Ok(token_case.data), footer == <<token_case.footer:utf8>> {
    False, _ -> Error("the data claim differs")
    _, False -> Error("the footer differs")
    True, True -> Ok(Nil)
  }
}

fn read(
  token_case: TokenCase,
  rules: gaseto.Rules,
) -> Result(gaseto.Token, String) {
  case token_case.kind {
    "v3.local" -> decrypt(PasetoV3, token_case, rules)
    "v4.local" -> decrypt(PasetoV4, token_case, rules)
    "v3.public" -> verify(PasetoV3, token_case, rules)
    "v4.public" -> verify(PasetoV4, token_case, rules)
    kind -> Error("unknown kind " <> kind)
  }
}

fn decrypt(
  version: PasetoVersion,
  token_case: TokenCase,
  rules: gaseto.Rules,
) -> Result(gaseto.Token, String) {
  use key <- result.try(
    gaseto.local_key_from_hex(version, token_case.key)
    |> result.map_error(string.inspect),
  )
  gaseto.decrypt(token_case.token, key, rules)
  |> result.map_error(string.inspect)
}

fn verify(
  version: PasetoVersion,
  token_case: TokenCase,
  rules: gaseto.Rules,
) -> Result(gaseto.Token, String) {
  use key <- result.try(
    gaseto.public_key_from_hex(version, token_case.key)
    |> result.map_error(string.inspect),
  )
  gaseto.verify(token_case.token, key, rules)
  |> result.map_error(string.inspect)
}

fn make_gaseto_tokens() -> Nil {
  let token_cases =
    list.flat_map(kinds, fn(kind) {
      let #(version, purpose) = kind
      list.repeat(Nil, cases_per_kind)
      |> list.index_map(fn(_, index) { make(version, purpose, index) })
    })
  let encoded = json.array(token_cases, encode_token_case) |> json.to_string
  let assert Ok(Nil) = simplifile.write(gaseto_tokens_path, encoded)
  io.println(
    "Gaseto made " <> int.to_string(list.length(token_cases)) <> " tokens",
  )
}

fn make(
  version: PasetoVersion,
  purpose: PasetoPurpose,
  index: Int,
) -> TokenCase {
  let data = random_text(int.random(600))
  let footer = case index % 2 {
    0 -> ""
    _ -> "{\"kid\":\"gaseto-key-" <> int.to_string(index) <> "\"}"
  }
  let implicit_assertion = random_text(int.random(3) * 10)
  let claims =
    gaseto.new_claims()
    |> gaseto.with_issuer("gaseto")
    |> gaseto.with_audience("go-paseto")
    |> gaseto.with_subject("user-" <> int.to_string(index))
    |> gaseto.with_claim("data", json.string(data))
    |> gaseto.with_footer(<<footer:utf8>>)
    |> gaseto.with_implicit_assertion(<<implicit_assertion:utf8>>)
  let #(kind, key, token) = case purpose {
    gaseto.Local -> {
      let key = gaseto.generate_local_key(version)
      let assert Ok(token) = gaseto.encrypt(claims, key)
      #("local", gaseto.local_key_to_hex(key), token)
    }
    gaseto.Public -> {
      let secret_key = gaseto.generate_secret_key(version)
      let assert Ok(token) = gaseto.sign(claims, secret_key)
      let public_key = gaseto.secret_key_to_public_key(secret_key)
      #("public", gaseto.public_key_to_hex(public_key), token)
    }
  }
  let version_name = case version {
    PasetoV3 -> "v3"
    PasetoV4 -> "v4"
  }
  TokenCase(
    kind: version_name <> "." <> kind,
    key:,
    token:,
    footer:,
    implicit_assertion:,
    data:,
  )
}

fn random_text(length: Int) -> String {
  let graphemes = string.to_graphemes(characters)
  let count = list.length(graphemes)
  list.repeat(Nil, length)
  |> list.map(fn(_) {
    let assert [grapheme, ..] = list.drop(graphemes, int.random(count))
    grapheme
  })
  |> string.concat
}

fn token_case_decoder() -> decode.Decoder(TokenCase) {
  use kind <- decode.field("kind", decode.string)
  use key <- decode.field("key", decode.string)
  use token <- decode.field("token", decode.string)
  use footer <- decode.field("footer", decode.string)
  use implicit_assertion <- decode.field("implicit_assertion", decode.string)
  use data <- decode.field("data", decode.string)
  decode.success(TokenCase(
    kind:,
    key:,
    token:,
    footer:,
    implicit_assertion:,
    data:,
  ))
}

fn encode_token_case(token_case: TokenCase) -> json.Json {
  json.object([
    #("kind", json.string(token_case.kind)),
    #("key", json.string(token_case.key)),
    #("token", json.string(token_case.token)),
    #("footer", json.string(token_case.footer)),
    #("implicit_assertion", json.string(token_case.implicit_assertion)),
    #("data", json.string(token_case.data)),
  ])
}
