# Gaseto

[![Package Version](https://img.shields.io/hexpm/v/gaseto)](https://hex.pm/packages/gaseto)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/gaseto/)

Gaseto is a Gleam implementation of [PASETO (Platform-Agnostic SEcurity TOkens)](https://paseto.io/).

New to PASETO? These explain what it is and why it exists:

- [paseto.io](https://paseto.io/): what PASETO is.
- [No Way, JOSE!](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid): the weaknesses of JWT that PASETO fixes.
- [The PASETO specification](https://github.com/paseto-standard/paseto-spec): the details this library follows.

## Features

Supports [versions 3 and 4](https://github.com/paseto-standard/paseto-spec/tree/master/docs/01-Protocol-Versions), both `local` and `public` tokens. Use version 4 unless you are limited to NIST-approved algorithms, then use version 3, which uses them throughout. Versions 1 and 2 are deprecated by the spec and not supported.

## Installation

```sh
gleam add gaseto
```

Gaseto runs on Erlang and needs OTP 27 or newer.

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

To send tokens in HTTP responses and check them on requests, use [gaseto_http](https://github.com/atomfinger/gaseto_http). It works with Wisp, Mist and other servers built on [gleam_http](https://hex.pm/packages/gleam_http).

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
