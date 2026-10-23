# Using Gaseto with HTTP

This guide shows how to send a token in an HTTP response and check it on later
requests. It uses [gleam_http](https://hex.pm/packages/gleam_http), so it works
with Wisp, Mist and any other server built on it. A separate `gaseto_http`
package is planned to do this for you; until then, this is all it takes.

The usual way to send a token is the `Authorization: Bearer <token>` header
([RFC 6750](https://www.rfc-editor.org/rfc/rfc6750)).

## Keys

Load the keys once when your app starts. The secret key signs tokens, and the
public key verifies them. A service that only checks tokens needs only the
public key. See [Keys](keys.html) to make and load a key pair.

```gleam
let assert Ok(secret_key) = gaseto.secret_key_from_hex(gaseto.PasetoV4, secret_key_hex)
let assert Ok(public_key) = gaseto.public_key_from_hex(gaseto.PasetoV4, public_key_hex)
```

## Creating a token and sending it

After a successful login, sign a token and return it as JSON.

```gleam
import gaseto
import gleam/http/response.{type Response}
import gleam/json

pub fn login_response(
  user_identifier: String,
  secret_key: gaseto.SecretKey,
) -> Response(String) {
  let claims =
    gaseto.new_claims()
    |> gaseto.with_issuer("auth.example.com")
    |> gaseto.with_subject(user_identifier)
  case gaseto.sign(claims, secret_key) {
    Ok(token) ->
      response.new(200)
      |> response.set_header("content-type", "application/json")
      |> response.set_body(
        json.object([
          #("access_token", json.string(token)),
          #("token_type", json.string("Bearer")),
          #("expires_in", json.int(3600)),
        ])
        |> json.to_string,
      )
    Error(_) -> response.new(500) |> response.set_body("")
  }
}
```

`new_claims` makes the token expire after one hour, which is why
`expires_in` is 3600.

## Checking the token on a request

Read the header, take the token after `Bearer`, and verify it. The rules check
the expiry and the issuer. The result is the user identifier from the `sub` claim.

```gleam
import gaseto
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/option
import gleam/result
import gleam/string

pub fn authenticate(
  request: Request(body),
  public_key: gaseto.PublicKey,
) -> Result(String, Nil) {
  use authorization <- result.try(request.get_header(request, "authorization"))
  use token <- result.try(case string.split_once(authorization, " ") {
    Ok(#(scheme, token)) ->
      case string.lowercase(scheme) {
        "bearer" -> Ok(string.trim(token))
        _ -> Error(Nil)
      }
    Error(Nil) -> Error(Nil)
  })
  let rules = gaseto.new_rules() |> gaseto.issued_by("auth.example.com")
  use verified <- result.try(
    gaseto.verify(token, public_key, rules) |> result.replace_error(Nil),
  )
  option.to_result(gaseto.subject(verified), Nil)
}

pub fn unauthorized_response() -> Response(String) {
  response.new(401)
  |> response.set_header("www-authenticate", "Bearer")
  |> response.set_body("")
}
```

In a request handler:

```gleam
case authenticate(request, public_key) {
  Ok(user_identifier) -> show_profile(user_identifier)
  Error(Nil) -> unauthorized_response()
}
```

## Cookies

For a browser, you can store a `local` token in a cookie instead. Encrypt it with
a `LocalKey`, set it with `response.set_cookie`, and read it back with
`request.get_cookies` before calling `gaseto.decrypt`.
For how to set cookies safely, see the
[OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies).
