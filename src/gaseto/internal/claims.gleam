import gaseto/error
import gaseto/internal/json_object
import gleam/bool
import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/json.{type Json}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/order
import gleam/result
import gleam/string
import gleam/time/calendar
import gleam/time/duration.{type Duration}
import gleam/time/timestamp.{type Timestamp}

pub type RegisteredClaims {
  RegisteredClaims(
    issuer: Option(String),
    subject: Option(String),
    audience: Option(String),
    expires_at: Option(Timestamp),
    not_before: Option(Timestamp),
    issued_at: Option(Timestamp),
    token_identifier: Option(String),
  )
}

pub type Builder {
  Builder(
    issuer: Option(String),
    subject: Option(String),
    audience: Option(String),
    expiration: Expiration,
    not_before: Option(Timestamp),
    issued_at: Option(Timestamp),
    token_identifier: Option(String),
    custom: Dict(String, Json),
    footer: BitArray,
    implicit_assertion: BitArray,
  )
}

pub type Expiration {
  ExpiresIn(Duration)
  ExpiresAt(Timestamp)
  NeverExpires
}

pub type Rules {
  Rules(
    issuer: Option(String),
    subject: Option(String),
    audience: Option(String),
    token_identifier: Option(String),
    expiration: ExpirationRule,
    checked_at: Option(Timestamp),
    clock_skew: Duration,
    max_token_length: Int,
    implicit_assertion: BitArray,
  )
}

pub type ExpirationRule {
  RequireExpiration
  AllowNoExpiration
}

const registered_claim_names: List(String) = [
  "iss", "sub", "aud", "exp", "nbf", "iat", "jti",
]

/// The spec recommends that tokens expire by default, after one hour
/// ([Default Expiration Claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/05-API-UX.md#default-expiration-claims)).
pub fn new_builder() -> Builder {
  Builder(
    issuer: None,
    subject: None,
    audience: None,
    expiration: ExpiresIn(duration.hours(1)),
    not_before: None,
    issued_at: None,
    token_identifier: None,
    custom: dict.new(),
    footer: <<>>,
    implicit_assertion: <<>>,
  )
}

pub fn new_rules() -> Rules {
  Rules(
    issuer: None,
    subject: None,
    audience: None,
    token_identifier: None,
    expiration: RequireExpiration,
    checked_at: None,
    clock_skew: duration.seconds(0),
    max_token_length: 8192,
    implicit_assertion: <<>>,
  )
}

pub fn encode(
  builder: Builder,
  now: Timestamp,
) -> Result(String, error.TokenCreationError) {
  use _ <- result.try(list.try_each(
    dict.to_list(builder.custom),
    check_custom_claim,
  ))
  let expires_at = case builder.expiration {
    ExpiresIn(duration) -> Some(timestamp.add(now, duration))
    ExpiresAt(time) -> Some(time)
    NeverExpires -> None
  }
  let registered_fields =
    [
      #("iss", option.map(builder.issuer, json.string)),
      #("sub", option.map(builder.subject, json.string)),
      #("aud", option.map(builder.audience, json.string)),
      #("exp", option.map(expires_at, time_to_json)),
      #("nbf", option.map(builder.not_before, time_to_json)),
      #("iat", Some(time_to_json(option.unwrap(builder.issued_at, now)))),
      #("jti", option.map(builder.token_identifier, json.string)),
    ]
    |> list.filter_map(fn(field) {
      case field {
        #(name, Some(value)) -> Ok(#(name, value))
        #(_, None) -> Error(Nil)
      }
    })
  Ok(
    json.object(list.append(registered_fields, dict.to_list(builder.custom)))
    |> json.to_string,
  )
}

/// The payload is only inspected after the token has been verified.
pub fn open(
  payload: String,
  rules: Rules,
) -> Result(RegisteredClaims, error.TokenValidationError) {
  use claims <- result.try(decode(payload))
  use _ <- result.try(check_times(claims, rules))
  use _ <- result.try(expect_claim("iss", rules.issuer, claims.issuer))
  use _ <- result.try(expect_claim("sub", rules.subject, claims.subject))
  use _ <- result.try(expect_claim("aud", rules.audience, claims.audience))
  use _ <- result.try(expect_claim(
    "jti",
    rules.token_identifier,
    claims.token_identifier,
  ))
  Ok(claims)
}

fn check_custom_claim(
  custom_claim: #(String, Json),
) -> Result(Nil, error.TokenCreationError) {
  let #(name, _value) = custom_claim
  use <- bool.guard(
    when: list.contains(registered_claim_names, name),
    return: Error(error.ReservedClaimName(name)),
  )
  // A custom claim can hold an object that repeats a key
  case json_object.decode(json.to_string(json.object([custom_claim]))) {
    Ok(_) -> Ok(Nil)
    Error(Nil) -> Error(error.RepeatedKeyInClaim(name))
  }
}

fn decode(
  payload: String,
) -> Result(RegisteredClaims, error.TokenValidationError) {
  use claims <- result.try(
    json_object.decode(payload) |> result.replace_error(error.InvalidPayload),
  )
  use issuer <- result.try(string_claim(claims, "iss"))
  use subject <- result.try(string_claim(claims, "sub"))
  use audience <- result.try(string_claim(claims, "aud"))
  use token_identifier <- result.try(string_claim(claims, "jti"))
  use expires_at <- result.try(time_claim(claims, "exp"))
  use not_before <- result.try(time_claim(claims, "nbf"))
  use issued_at <- result.try(time_claim(claims, "iat"))
  Ok(RegisteredClaims(
    issuer:,
    subject:,
    audience:,
    expires_at:,
    not_before:,
    issued_at:,
    token_identifier:,
  ))
}

fn check_times(
  claims: RegisteredClaims,
  rules: Rules,
) -> Result(Nil, error.TokenValidationError) {
  let now = option.lazy_unwrap(rules.checked_at, timestamp.system_time)
  // Each check gives the token the benefit of the allowed skew
  let latest_now = timestamp.add(now, rules.clock_skew)
  use _ <- result.try(case claims.expires_at, rules.expiration {
    None, RequireExpiration -> Error(error.MissingExpiration)
    None, AllowNoExpiration -> Ok(Nil)
    Some(expires_at), _ ->
      case timestamp.compare(now, timestamp.add(expires_at, rules.clock_skew)) {
        order.Gt -> Error(error.Expired(expired_at: expires_at))
        order.Lt | order.Eq -> Ok(Nil)
      }
  })
  use _ <- result.try(case claims.not_before {
    Some(not_before) ->
      case timestamp.compare(latest_now, not_before) {
        order.Lt -> Error(error.NotYetValid(valid_from: not_before))
        order.Gt | order.Eq -> Ok(Nil)
      }
    None -> Ok(Nil)
  })
  case claims.issued_at {
    Some(issued_at) ->
      case timestamp.compare(latest_now, issued_at) {
        order.Lt -> Error(error.IssuedInTheFuture(issued_at:))
        order.Gt | order.Eq -> Ok(Nil)
      }
    None -> Ok(Nil)
  }
}

fn expect_claim(
  name: String,
  expected: Option(String),
  found: Option(String),
) -> Result(Nil, error.TokenValidationError) {
  case expected {
    None -> Ok(Nil)
    Some(value) if found == Some(value) -> Ok(Nil)
    Some(value) -> Error(error.UnexpectedClaim(name:, expected: value, found:))
  }
}

/// The spec recommends leaving out fractional seconds and writing "Z"
/// ([Registered Claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md#payload-claims)).
fn time_to_json(time: Timestamp) -> Json {
  let #(seconds, _nanoseconds) = timestamp.to_unix_seconds_and_nanoseconds(time)
  timestamp.from_unix_seconds(seconds)
  |> timestamp.to_rfc3339(calendar.utc_offset)
  |> json.string
}

/// A registered claim that holds a string, if the payload has it.
fn string_claim(
  claims: Dict(String, Dynamic),
  name: String,
) -> Result(Option(String), error.TokenValidationError) {
  case dict.get(claims, name) {
    Error(Nil) -> Ok(None)
    Ok(value) ->
      decode.run(value, decode.string)
      |> result.map(Some)
      |> result.replace_error(error.InvalidClaim(name:, error: error.NotAString))
  }
}

/// A registered claim that holds a time, if the payload has it.
fn time_claim(
  claims: Dict(String, Dynamic),
  name: String,
) -> Result(Option(Timestamp), error.TokenValidationError) {
  use text <- result.try(string_claim(claims, name))
  case text {
    None -> Ok(None)
    Some(text) ->
      parse_time(text)
      |> result.map(Some)
      |> result.replace_error(error.InvalidClaim(
        name:,
        error: error.NotAnRfc3339Time,
      ))
  }
}

/// The spec requires RFC 3339 with an uppercase "T" between date and time,
/// and an uppercase "Z"
/// ([Registered Claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md#payload-claims)).
/// `timestamp.parse_rfc3339` also accepts the lowercase forms.
fn parse_time(text: String) -> Result(Timestamp, Nil) {
  case <<text:utf8>>, string.contains(text, "z") {
    <<_date:bytes-size(10), "T":utf8, _time:bytes>>, False ->
      timestamp.parse_rfc3339(text)
    _, _ -> Error(Nil)
  }
}
