# Keys

## Which kind of key you need

PASETO has two kinds of token, and each has its own kind of key. The spec
gives
[examples of what each is for](https://github.com/paseto-standard/paseto-spec/blob/master/docs/README.md#what-should-we-use-paseto-for).

- **A local key** makes `local` tokens with `encrypt` and reads them with
  `decrypt`. It is one shared key. The claims are encrypted, so only someone
  with the key can read them. Anyone with the key can also make tokens. Use it
  when the same app makes and reads the tokens, for example a
  ["remember me" cookie](https://paragonie.com/blog/2015/04/secure-authentication-php-with-long-term-persistence#title.2.1).
- **A key pair** makes `public` tokens. The secret key makes tokens with
  `sign`, and the public key checks them with `verify`. The claims are not
  encrypted, so anyone can read them. Use it when other services need to check
  tokens but must not be able to make them, for example a login service that
  gives out tokens which your APIs check. Only the login service has the
  secret key.

Each key belongs to one version. Use version 4 unless you need NIST-approved
algorithms, then use version 3. A key for one version does not work with the
other.

## Loading keys

For how to manage keys, see the
[OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html).

This example reads a version 4 secret key from a file, using
[simplifile](https://hexdocs.pm/simplifile/):

```gleam
import gaseto
import gleam/string
import simplifile

pub fn load_secret_key(path: String) -> gaseto.SecretKey {
  let assert Ok(secret_key_hex) = simplifile.read(path)
  let assert Ok(secret_key) =
    gaseto.secret_key_from_hex(gaseto.PasetoV4, string.trim(secret_key_hex))
  secret_key
}
```

For a key in a PEM file, use `secret_key_from_pem` or `public_key_from_pem`
instead.

## Generating keys

Generate each key once, outside your app. A key generated when your app starts
would change on every restart, which makes all earlier tokens invalid, and
every copy of your app would have its own key.

Gaseto reads keys as hex, and secret and public keys also as PEM. In hex:

| Key | Version 4 | Version 3 |
|---|---|---|
| Local key | 32 random bytes | 32 random bytes |
| Secret key | An [Ed25519](https://datatracker.ietf.org/doc/html/rfc8032) seed (32 bytes), followed by its public key (32 bytes) | A [P-384](https://csrc.nist.gov/pubs/sp/800/186/final) secret key (48 bytes) |
| Public key | An Ed25519 public key (32 bytes) | A compressed P-384 point (49 bytes) |

Version 3 signs with [ECDSA](https://csrc.nist.gov/pubs/fips/186-5/final).
The spec has the details for
[version 3](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md)
and
[version 4](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md).

### With Gaseto

Gaseto can generate keys and write them as hex. The
[generate_keys demo](https://github.com/atomfinger/gaseto/tree/main/demo/generate_keys)
is a small Gleam project that prints new keys of every kind. Run it with
`gleam run`. This is how it makes them:

```gleam
let local_key = gaseto.generate_local_key(gaseto.PasetoV4)
gaseto.local_key_to_hex(local_key)

let secret_key = gaseto.generate_secret_key(gaseto.PasetoV4)
gaseto.secret_key_to_hex(secret_key)
gaseto.secret_key_to_public_key(secret_key) |> gaseto.public_key_to_hex
```

### With OpenSSL

A local key, with [`openssl rand`](https://docs.openssl.org/3.0/man1/openssl-rand/):

```sh
openssl rand -hex 32
```

A key pair, with
[`openssl genpkey`](https://docs.openssl.org/3.0/man1/openssl-genpkey/) and
[`openssl pkey`](https://docs.openssl.org/3.0/man1/openssl-pkey/). For version
4:

```sh
openssl genpkey -algorithm ed25519 -out secret_key.pem
openssl pkey -in secret_key.pem -pubout -out public_key.pem
```

For version 3:

```sh
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out secret_key.pem
openssl pkey -in secret_key.pem -pubout -out public_key.pem
```

Load them with `secret_key_from_pem` and `public_key_from_pem`.
