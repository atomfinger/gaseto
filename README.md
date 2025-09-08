# gaseto

[![Package Version](https://img.shields.io/hexpm/v/gaseto)](https://hex.pm/packages/gaseto)
[![Hex Docs](https://img.shields.io/badge/hex-docs-ffaff3)](https://hexdocs.pm/gaseto/)

`gaseto` is a Gleam implementation of [PASETO (Platform-Agnostic SEcurity TOkens)](https://paseto.io/).

PASETO is a specification for secure stateless tokens. Unlike JWT, which gives developers too many choices, PASETO specifies a small number of cryptographic suites to use.

> **Note:** This library targets the Erlang runtime only. JavaScript is not supported.

### 🚧 This project is in construction. Not production ready 🚧

## Features

- **PASETO V3** _(recommended)_
  - `v3.local`: Symmetric authenticated encryption using AES-256-CTR and HMAC-SHA-384, with HKDF-SHA-384 key derivation.
  - `v3.public`: Asymmetric authentication using ECDSA with P-384 and SHA-384.
- **PASETO V1** _(deprecated — the PASETO standard itself has deprecated V1 in favour of V3)_
  - `v1.local`: Symmetric authenticated encryption using AES-256-CTR and HMAC-SHA-384.
  - `v1.public`: Asymmetric authentication using RSA-PSS with SHA-384.

## Installation

```sh
gleam add gaseto
```

## Usage

Here's an example of how to create and verify a `v3.local` PASETO token:

```gleam
import gleam/option.{None}
import gaseto.{LocalKey}
import gaseto/token

pub fn main() {
  let key = LocalKey("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
  let payload = "{\"data\":\"this is a signed message\",\"exp\":\"2019-01-01T00:00:00+00:00\"}"

  let assert Ok(encrypted_token) = gaseto.encrypt(payload, key, token.PasetoV3, None)
  let token_string = gaseto.to_string(encrypted_token)
  let assert Ok(decrypted_token) = gaseto.decrypt(token_string, key)

  let assert True = decrypted_token.payload == payload
}
```

For `v3.public`, use a `KeyPair`:

```gleam
import gleam/option.{None}
import gaseto.{KeyPair}
import gaseto/token

pub fn main() {
  let key = KeyPair(
    secret_key: "...",  // 48-byte P-384 private scalar, hex-encoded
    public_key: "...",  // 49-byte compressed P-384 point, hex-encoded
  )
  let payload = "{\"data\":\"hello\",\"exp\":\"2025-01-01T00:00:00+00:00\"}"

  let assert Ok(signed_token) = gaseto.encrypt(payload, key, token.PasetoV3, None)
  let token_string = gaseto.to_string(signed_token)
  let assert Ok(verified) = gaseto.decrypt(token_string, key)

  let assert True = verified.payload == payload
}
```

Further documentation can be found at <https://hexdocs.pm/gaseto>.

## Development

```sh
gleam test  # Run the tests
```
