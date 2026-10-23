import gaseto.{PasetoV4}
import gleam/bit_array
import gleam/http
import gleam/http/response
import gleam/list
import gleam/option.{None}
import gleam/result
import gleam/string
import gleeunit
import remember_me.{Context}
import remembered_login
import wisp
import wisp/simulate

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn a_new_visitor_is_not_known_test() -> Nil {
  let context = new_context()
  let response = remember_me.handle_request(home_request(), context)
  assert response.status == 200
  assert simulate.read_body(response) == "I do not know you yet\n"
}

pub fn a_logged_in_visitor_is_welcomed_back_test() -> Nil {
  let context = new_context()
  let #(login, login_response) = log_in(context, "alice")
  assert simulate.read_body(login_response) == "Remembered alice\n"
  let response =
    remember_me.handle_request(
      simulate.session(home_request(), login, login_response),
      context,
    )
  assert simulate.read_body(response) == "Welcome back, alice\n"
}

pub fn logging_out_stops_a_stolen_copy_of_the_cookie_test() -> Nil {
  let context = new_context()
  let #(login, login_response) = log_in(context, "alice")
  let stolen = simulate.session(home_request(), login, login_response)
  let logout =
    simulate.session(
      simulate.browser_request(http.Post, "/logout"),
      login,
      login_response,
    )
  let logout_response = remember_me.handle_request(logout, context)
  assert simulate.read_body(logout_response) == "Forgotten\n"
  // The browser's own cookie is cleared
  let after_logout = simulate.session(home_request(), logout, logout_response)
  assert simulate.read_body(remember_me.handle_request(after_logout, context))
    == "I do not know you yet\n"
  // A copy taken before the logout is refused, even though its token is valid
  assert simulate.read_body(remember_me.handle_request(stolen, context))
    == "I do not know you yet\n"
}

pub fn logging_out_one_login_keeps_the_others_test() -> Nil {
  let context = new_context()
  let #(phone, phone_response) = log_in(context, "alice")
  let #(laptop, laptop_response) = log_in(context, "alice")
  let logout =
    simulate.session(
      simulate.browser_request(http.Post, "/logout"),
      phone,
      phone_response,
    )
  let _ = remember_me.handle_request(logout, context)
  let laptop_home = simulate.session(home_request(), laptop, laptop_response)
  assert simulate.read_body(remember_me.handle_request(laptop_home, context))
    == "Welcome back, alice\n"
}

pub fn the_cookie_holds_only_a_random_login_identifier_test() -> Nil {
  let context = new_context()
  let #(_, first_response) = log_in(context, "alice")
  let #(_, second_response) = log_in(context, "alice")
  let first = decrypt_cookie(first_response, context)
  let second = decrypt_cookie(second_response, context)
  assert gaseto.subject(first) == None
  assert !string.contains(gaseto.payload(first), "alice")
  assert gaseto.token_identifier(first) != gaseto.token_identifier(second)
}

pub fn the_cookie_is_http_only_secure_and_same_site_test() -> Nil {
  let #(_, login_response) = log_in(new_context(), "alice")
  let assert Ok(set_cookie) = response.get_header(login_response, "set-cookie")
  assert string.starts_with(set_cookie, "remember_me=")
  assert string.contains(set_cookie, "HttpOnly")
  assert string.contains(set_cookie, "Secure")
  assert string.contains(set_cookie, "SameSite=Lax")
  assert string.contains(set_cookie, "Max-Age=2592000")
}

pub fn a_valid_token_without_a_record_is_refused_test() -> Nil {
  // As after a restart: same key, but the records are gone
  let context = new_context()
  let #(login, login_response) = log_in(context, "alice")
  let assert Ok(empty_logins) = remembered_login.start()
  let restarted = Context(..context, logins: empty_logins)
  let home = simulate.session(home_request(), login, login_response)
  assert simulate.read_body(remember_me.handle_request(home, restarted))
    == "I do not know you yet\n"
}

pub fn a_token_from_another_key_is_refused_test() -> Nil {
  let context = new_context()
  let other = new_context()
  let #(login, login_response) = log_in(other, "alice")
  let home = simulate.session(home_request(), login, login_response)
  assert simulate.read_body(remember_me.handle_request(home, context))
    == "I do not know you yet\n"
}

pub fn a_token_without_a_login_identifier_is_refused_test() -> Nil {
  let context = new_context()
  let assert Ok(token) = gaseto.encrypt(gaseto.new_claims(), context.key)
  let home =
    home_request() |> simulate.cookie("remember_me", token, wisp.PlainText)
  assert simulate.read_body(remember_me.handle_request(home, context))
    == "I do not know you yet\n"
}

pub fn a_garbled_cookie_is_refused_test() -> Nil {
  let context = new_context()
  let home =
    home_request()
    |> simulate.cookie("remember_me", "v4.local.garbage", wisp.PlainText)
  assert simulate.read_body(remember_me.handle_request(home, context))
    == "I do not know you yet\n"
}

pub fn logging_in_without_a_user_is_a_bad_request_test() -> Nil {
  let request =
    simulate.browser_request(http.Post, "/login") |> simulate.form_body([])
  assert remember_me.handle_request(request, new_context()).status == 400
}

pub fn logging_out_without_a_cookie_is_fine_test() -> Nil {
  let request = simulate.browser_request(http.Post, "/logout")
  assert remember_me.handle_request(request, new_context()).status == 200
}

fn new_context() -> remember_me.Context {
  let key = gaseto.generate_local_key(PasetoV4)
  let assert Ok(logins) = remembered_login.start()
  Context(key:, logins:)
}

fn home_request() -> wisp.Request {
  simulate.browser_request(http.Get, "/")
}

fn log_in(
  context: remember_me.Context,
  user: String,
) -> #(wisp.Request, wisp.Response) {
  let request =
    simulate.browser_request(http.Post, "/login")
    |> simulate.form_body([#("user", user)])
  #(request, remember_me.handle_request(request, context))
}

fn decrypt_cookie(
  login_response: wisp.Response,
  context: remember_me.Context,
) -> gaseto.Token {
  let assert Ok(token) =
    response.get_cookies(login_response)
    |> list.key_find("remember_me")
    |> result.try(bit_array.base64_decode)
    |> result.try(bit_array.to_string)
  let assert Ok(token) = gaseto.decrypt(token, context.key, gaseto.new_rules())
  token
}
