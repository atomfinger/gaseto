# gaseto

[![Package Version](https://img.shields.io/hexpm/v/gaseto)](https://hex.pm/packages/gaseto)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/gaseto/)

`gaseto` is a Gleam implementation of [PASETO (Platform-Agnostic SEcurity TOkens)](https://paseto.io/).

PASETO is a specification for secure stateless tokens. Unlike JWT, which gives developers too many choices, PASETO specifies a small number of cryptographic suites to use.

### 🚧 This project is in construction. Not production ready 🚧

## Features

- PASETO v1
  - `v1.local`: Symmetric authenticated encryption using AES-256-CTR and HMAC-SHA-384.
  - `v1.public`: Asymmetric authentication using RSA-PSS with SHA-384.

_Before V1:_

- [ ] PASETO V2 support
- [ ] PASERK key conversion

_After V1:_

- [ ] PASETO V3/V4 support

## Installation

```sh
gleam add gaseto
```

## Usage

Here's an example of how to create and verify a `v1.local` PASETO token.

```gleam
import gleam/result
import gleam/option.{None}
import gaseto
import gaseto/token

pub fn main() {
  let key = "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"
  let payload = "{"data":"this is a signed message","exp":"2019-01-01T00:00:00+00:00"}"

  // Create a token
  let assert Ok(encrypted_token) =
    gaseto.encrypt(
      payload,
      key,
      token.PasetoV1,
      token.Local,
      None,
    )

  let token_string = gaseto.to_string(encrypted_token)

  // Verify the token
  let assert Ok(decrypted_token) =
    gaseto.decrypt(token_string, key)

  assert decrypted_token.payload == payload
}
```

Further documentation can be found at <https://hexdocs.pm/gaseto>.

## Development

```sh
gleam run   # Run the project
gleam test  # Run the tests
```

