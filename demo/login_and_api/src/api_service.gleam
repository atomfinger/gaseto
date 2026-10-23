//// Checks the tokens from the login service. It only has the public key, so
//// it can check tokens but not make them.

import gaseto
import gleam/erlang/process
import gleam/http.{Get}
import gleam/http/request
import gleam/json
import gleam/option
import gleam/result
import gleam/string
import gleam/time/duration
import key_file
import mist
import token_claim
import wisp.{type Request, type Response}
import wisp/wisp_mist

pub fn main() -> Nil {
  wisp.configure_logger()
  let assert Ok(public_key) =
    key_file.public_key(key_file.read("PUBLIC_KEY_FILE"))
    as "PUBLIC_KEY_FILE does not hold a version 4 public key in hex or PEM"
  let assert Ok(_) =
    wisp_mist.handler(handle_request(_, public_key), wisp.random_string(64))
    |> mist.new
    |> mist.port(4002)
    |> mist.start
  process.sleep_forever()
}

pub fn handle_request(
  request: Request,
  public_key: gaseto.PublicKey,
) -> Response {
  use <- wisp.log_request(request)
  use <- wisp.rescue_crashes
  case request.method, wisp.path_segments(request) {
    Get, ["me"] ->
      case authenticate(request, public_key) {
        Ok(user) ->
          json.object([#("user", json.string(user))])
          |> json.to_string
          |> wisp.json_response(200)
        Error(Nil) ->
          wisp.response(401) |> wisp.set_header("www-authenticate", "Bearer")
      }
    _, _ -> wisp.not_found()
  }
}

fn authenticate(
  request: Request,
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
  let rules =
    gaseto.new_rules()
    |> gaseto.issued_by(token_claim.issuer)
    |> gaseto.for_audience(token_claim.audience)
    // The login service runs on another server, whose clock may differ a little
    |> gaseto.allow_clock_skew(duration.seconds(30))
  use verified <- result.try(
    gaseto.verify(token, public_key, rules) |> result.replace_error(Nil),
  )
  option.to_result(gaseto.subject(verified), Nil)
}
