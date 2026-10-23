//// Gives out `public` tokens. It is the only service with the secret key.

import gaseto
import gleam/erlang/process
import gleam/http.{Post}
import gleam/json
import gleam/list
import gleam/time/duration
import key_file
import mist
import token_claim
import wisp.{type Request, type Response}
import wisp/wisp_mist

const token_lifetime_minutes: Int = 15

pub fn main() -> Nil {
  wisp.configure_logger()
  let assert Ok(secret_key) =
    key_file.secret_key(key_file.read("SECRET_KEY_FILE"))
    as "SECRET_KEY_FILE does not hold a version 4 secret key in hex or PEM"
  let assert Ok(_) =
    wisp_mist.handler(handle_request(_, secret_key), wisp.random_string(64))
    |> mist.new
    |> mist.port(4001)
    |> mist.start
  process.sleep_forever()
}

pub fn handle_request(
  request: Request,
  secret_key: gaseto.SecretKey,
) -> Response {
  use <- wisp.log_request(request)
  use <- wisp.rescue_crashes
  case request.method, wisp.path_segments(request) {
    Post, ["login"] -> log_in(request, secret_key)
    _, _ -> wisp.not_found()
  }
}

fn log_in(request: Request, secret_key: gaseto.SecretKey) -> Response {
  use form <- wisp.require_form(request)
  // A real login service checks a password here
  use user <- require_field(form, "user")
  let claims =
    gaseto.new_claims()
    |> gaseto.with_issuer(token_claim.issuer)
    |> gaseto.with_audience(token_claim.audience)
    |> gaseto.with_subject(user)
    |> gaseto.expires_in(duration.minutes(token_lifetime_minutes))
  case gaseto.sign(claims, secret_key) {
    Ok(token) ->
      json.object([
        #("access_token", json.string(token)),
        #("token_type", json.string("Bearer")),
        #("expires_in", json.int(token_lifetime_minutes * 60)),
      ])
      |> json.to_string
      |> wisp.json_response(200)
    Error(_) -> wisp.internal_server_error()
  }
}

fn require_field(
  form: wisp.FormData,
  name: String,
  next: fn(String) -> Response,
) -> Response {
  case list.key_find(form.values, name) {
    Ok(value) -> next(value)
    Error(Nil) -> wisp.bad_request("Missing the " <> name <> " field")
  }
}
