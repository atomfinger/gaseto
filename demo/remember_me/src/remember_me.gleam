//// A "remember me" cookie holding a `local` token, as the spec suggests
//// (https://github.com/paseto-standard/paseto-spec/blob/master/docs/README.md#what-should-we-use-paseto-for).
//// The token only carries a random login identifier, and the server keeps a
//// record of which identifiers are valid. Logging out deletes the record, so
//// a stolen copy of the cookie stops working too.

import envoy
import gaseto.{PasetoV4}
import gleam/bit_array
import gleam/crypto
import gleam/erlang/process
import gleam/http.{Get, Post}
import gleam/list
import gleam/option
import gleam/result
import gleam/string
import gleam/time/duration
import mist
import remembered_login
import simplifile
import wisp.{type Request, type Response}
import wisp/wisp_mist

const cookie_name: String = "remember_me"

/// 30 days.
const remember_for_seconds: Int = 2_592_000

pub type Context {
  Context(key: gaseto.LocalKey, logins: remembered_login.Store)
}

pub fn main() -> Nil {
  wisp.configure_logger()
  let assert Ok(logins) = remembered_login.start()
  let context = Context(key: load_local_key(), logins:)
  // wisp signs its own cookies with this. The token cookie does not need it.
  let wisp_secret_key_base = wisp.random_string(64)
  let assert Ok(_) =
    wisp_mist.handler(handle_request(_, context), wisp_secret_key_base)
    |> mist.new
    |> mist.port(4000)
    |> mist.start
  process.sleep_forever()
}

/// `LOCAL_KEY_FILE` names the file that holds the key.
fn load_local_key() -> gaseto.LocalKey {
  let assert Ok(path) = envoy.get("LOCAL_KEY_FILE")
    as "Set LOCAL_KEY_FILE to the path of the key file"
  let assert Ok(key_hex) = simplifile.read(path)
    as "Could not read the file in LOCAL_KEY_FILE"
  let assert Ok(key) = gaseto.local_key_from_hex(PasetoV4, string.trim(key_hex))
    as "LOCAL_KEY_FILE does not hold a version 4 local key"
  key
}

pub fn handle_request(request: Request, context: Context) -> Response {
  use <- wisp.log_request(request)
  use <- wisp.rescue_crashes
  case request.method, wisp.path_segments(request) {
    Get, [] -> home(request, context)
    Post, ["login"] -> log_in(request, context)
    Post, ["logout"] -> log_out(request, context)
    _, _ -> wisp.not_found()
  }
}

fn home(request: Request, context: Context) -> Response {
  let user = {
    use login_identifier <- result.try(login_identifier_from_cookie(
      request,
      context,
    ))
    remembered_login.find(context.logins, login_identifier)
  }
  case user {
    Ok(user) -> wisp.ok() |> wisp.string_body("Welcome back, " <> user <> "\n")
    Error(Nil) -> wisp.ok() |> wisp.string_body("I do not know you yet\n")
  }
}

fn log_in(request: Request, context: Context) -> Response {
  use form <- wisp.require_form(request)
  // A real app checks a password here
  use user <- require_field(form, "user")
  let login_identifier =
    crypto.strong_random_bytes(32) |> bit_array.base64_url_encode(False)
  let claims =
    gaseto.new_claims()
    |> gaseto.with_token_identifier(login_identifier)
    |> gaseto.expires_in(duration.seconds(remember_for_seconds))
  case gaseto.encrypt(claims, context.key) {
    Ok(token) -> {
      remembered_login.remember(context.logins, login_identifier, user)
      wisp.ok()
      |> wisp.string_body("Remembered " <> user <> "\n")
      |> wisp.set_cookie(
        request,
        cookie_name,
        token,
        wisp.PlainText,
        remember_for_seconds,
      )
    }
    Error(_) -> wisp.internal_server_error()
  }
}

fn log_out(request: Request, context: Context) -> Response {
  case login_identifier_from_cookie(request, context) {
    Ok(login_identifier) ->
      remembered_login.forget(context.logins, login_identifier)
    Error(Nil) -> Nil
  }
  wisp.ok()
  |> wisp.string_body("Forgotten\n")
  |> wisp.set_cookie(request, cookie_name, "", wisp.PlainText, 0)
}

fn login_identifier_from_cookie(
  request: Request,
  context: Context,
) -> Result(String, Nil) {
  // The token protects itself, so the cookie can be plain text
  use token <- result.try(wisp.get_cookie(request, cookie_name, wisp.PlainText))
  use token <- result.try(
    gaseto.decrypt(token, context.key, gaseto.new_rules())
    |> result.replace_error(Nil),
  )
  option.to_result(gaseto.token_identifier(token), Nil)
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
