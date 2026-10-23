# Gaseto

[![Package Version](https://img.shields.io/hexpm/v/gaseto)](https://hex.pm/packages/gaseto)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/gaseto/)

Gaseto is a Gleam implementation of [PASETO (Platform-Agnostic SEcurity TOkens)](https://paseto.io/).

New to PASETO? These explain what it is and why it exists:

- [paseto.io](https://paseto.io/): what PASETO is.
- [No Way, JOSE!](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid): the weaknesses of JWT that PASETO fixes.
- [The PASETO specification](https://github.com/paseto-standard/paseto-spec): the details this library follows.

> **Note:** This library targets the Erlang runtime only. JavaScript is not currently supported.

## Features

Supports [versions 3 and 4](https://github.com/paseto-standard/paseto-spec/tree/master/docs/01-Protocol-Versions), both `local` and `public` tokens. Use version 4 unless you need NIST-approved algorithms. Versions 1 and 2 are deprecated by the spec and not supported.

## Installation

```sh
gleam add gaseto
```

Needs Erlang/OTP 27 or newer.

## Usage

```gleam
import gaseto.{PasetoV4}
import gleam/option

pub fn main() -> Nil {
  let assert Ok(key) = gaseto.local_key_from_hex(PasetoV4, key_hex)

  let claims = gaseto.new_claims() |> gaseto.with_subject("user-42")
  let assert Ok(token) = gaseto.encrypt(claims, key)

  let assert Ok(decrypted) = gaseto.decrypt(token, key, gaseto.new_rules())
  assert gaseto.subject(decrypted) == option.Some("user-42")
}
```

To choose, load and make keys, see the [keys guide](https://hexdocs.pm/gaseto/keys.html) ([source](https://github.com/atomfinger/gaseto/blob/main/doc/keys.md)).

### Using it with HTTP

Send the token in a response, and read it back from the `Authorization: Bearer <token>` header on later requests. This uses [gleam_http](https://hex.pm/packages/gleam_http), so it works with Wisp, Mist and other servers built on it:

```gleam
// After a login: sign a token and return it
let claims =
  gaseto.new_claims()
  |> gaseto.with_issuer("auth.example.com")
  |> gaseto.with_subject(user_identifier)
let assert Ok(token) = gaseto.sign(claims, secret_key)
let login_response =
  response.new(200)
  |> response.set_header("content-type", "application/json")
  |> response.set_body(
    json.object([
      #("access_token", json.string(token)),
      #("token_type", json.string("Bearer")),
    ])
    |> json.to_string,
  )

// On a later request: verify the token and get the user identifier
let rules = gaseto.new_rules() |> gaseto.issued_by("auth.example.com")
let user_identifier = {
  use authorization <- result.try(request.get_header(request, "authorization"))
  use token <- result.try(case string.split_once(authorization, " ") {
    Ok(#(scheme, token)) ->
      case string.lowercase(scheme) {
        "bearer" -> Ok(string.trim(token))
        _ -> Error(Nil)
      }
    Error(Nil) -> Error(Nil)
  })
  use verified <- result.try(
    gaseto.verify(token, public_key, rules) |> result.replace_error(Nil),
  )
  option.to_result(gaseto.subject(verified), Nil)
}
```

The [HTTP guide](https://hexdocs.pm/gaseto/http.html) ([source](https://github.com/atomfinger/gaseto/blob/main/doc/http.md)) has the full version, including the 401 response. A `gaseto_http` package that does this for you is planned.

The [demo](https://github.com/atomfinger/gaseto/tree/main/demo) directory has small projects that show Gaseto in use.

Further documentation can be found at <https://hexdocs.pm/gaseto>.

## Development

```sh
gleam test  # Run the tests
```

To check that Gaseto and [go-paseto](https://github.com/aidantwoods/go-paseto)
accept each other's tokens, which needs Go:

```sh
(cd interop && go run . make go_tokens.json)
gleam run -m interop
(cd interop && go run . check gaseto_tokens.json)
```
