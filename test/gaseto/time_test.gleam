import gaseto
import gaseto/error
import gaseto/test_support
import gleam/list
import gleam/option.{None, Some}
import gleam/order
import gleam/time/duration
import gleam/time/timestamp

pub fn allow_no_expiration_still_checks_an_expiration_test() -> Nil {
  let an_hour_ago =
    test_support.whole_seconds(timestamp.add(
      timestamp.system_time(),
      duration.hours(-1),
    ))
  let claims =
    gaseto.new_claims()
    |> gaseto.with_issued_at(timestamp.add(an_hour_ago, duration.hours(-1)))
    |> gaseto.with_expires_at(an_hour_ago)
  assert test_support.round_trip(
      claims,
      gaseto.new_rules() |> gaseto.allow_no_expiration,
    )
    == Error(error.Expired(expired_at: an_hour_ago))
}

pub fn expiry_is_required_unless_allowed_test() -> Nil {
  let claims = gaseto.new_claims() |> gaseto.never_expires
  assert test_support.round_trip(claims, gaseto.new_rules())
    == Error(error.MissingExpiration)
  let assert Ok(token) =
    test_support.round_trip(
      claims,
      gaseto.new_rules() |> gaseto.allow_no_expiration,
    )
  assert gaseto.expires_at(token) == None
}

pub fn times_are_checked_test() -> Nil {
  let now = timestamp.system_time()
  let an_hour_ago = timestamp.add(now, duration.hours(-1))
  let in_an_hour = timestamp.add(now, duration.hours(1))

  let assert Error(error.Expired(_)) =
    test_support.round_trip(
      gaseto.new_claims() |> gaseto.with_expires_at(an_hour_ago),
      gaseto.new_rules(),
    )
  let assert Error(error.NotYetValid(_)) =
    test_support.round_trip(
      gaseto.new_claims() |> gaseto.with_not_before(in_an_hour),
      gaseto.new_rules(),
    )
  let assert Error(error.IssuedInTheFuture(_)) =
    test_support.round_trip(
      gaseto.new_claims() |> gaseto.with_issued_at(in_an_hour),
      gaseto.new_rules(),
    )
  Nil
}

pub fn token_is_valid_at_its_expiry_time_test() -> Nil {
  // The spec: valid while the current time is at or before `exp`
  // (https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/02-Validators.md)
  let expires_at = timestamp.from_unix_seconds(4_102_444_800)
  let claims =
    gaseto.new_claims()
    |> gaseto.with_expires_at(expires_at)
    |> gaseto.with_issued_at(timestamp.from_unix_seconds(0))
  let assert Ok(_) =
    test_support.round_trip(
      claims,
      gaseto.new_rules() |> gaseto.checked_at(expires_at),
    )
  Nil
}

pub fn checked_at_moves_the_clock_test() -> Nil {
  let claims = gaseto.new_claims() |> gaseto.expires_in(duration.minutes(5))
  let in_ten_minutes =
    timestamp.add(timestamp.system_time(), duration.minutes(10))
  let assert Error(error.Expired(expired_at)) =
    test_support.round_trip(
      claims,
      gaseto.new_rules() |> gaseto.checked_at(in_ten_minutes),
    )
  assert timestamp.compare(expired_at, in_ten_minutes) == order.Lt
}

pub fn clock_skew_accepts_times_that_are_slightly_off_test() -> Nil {
  let now = timestamp.from_unix_seconds(1_800_000_000)
  let rules =
    gaseto.new_rules()
    |> gaseto.checked_at(now)
    |> gaseto.allow_clock_skew(duration.seconds(30))
  let ten_seconds_ago = timestamp.add(now, duration.seconds(-10))
  let in_ten_seconds = timestamp.add(now, duration.seconds(10))
  let in_an_hour = timestamp.add(now, duration.hours(1))
  let issued_long_ago = timestamp.add(now, duration.hours(-1))

  let assert Ok(_) =
    test_support.round_trip(
      gaseto.new_claims()
        |> gaseto.with_issued_at(issued_long_ago)
        |> gaseto.with_expires_at(ten_seconds_ago),
      rules,
    )
  let assert Ok(_) =
    test_support.round_trip(
      gaseto.new_claims()
        |> gaseto.with_issued_at(issued_long_ago)
        |> gaseto.with_not_before(in_ten_seconds)
        |> gaseto.with_expires_at(in_an_hour),
      rules,
    )
  let assert Ok(_) =
    test_support.round_trip(
      gaseto.new_claims()
        |> gaseto.with_issued_at(in_ten_seconds)
        |> gaseto.with_expires_at(in_an_hour),
      rules,
    )
  Nil
}

pub fn clock_skew_still_refuses_times_beyond_it_test() -> Nil {
  let now = timestamp.from_unix_seconds(1_800_000_000)
  let rules =
    gaseto.new_rules()
    |> gaseto.checked_at(now)
    |> gaseto.allow_clock_skew(duration.seconds(30))
  let a_minute_ago = timestamp.add(now, duration.minutes(-1))
  let in_a_minute = timestamp.add(now, duration.minutes(1))
  let in_an_hour = timestamp.add(now, duration.hours(1))
  let issued_long_ago = timestamp.add(now, duration.hours(-1))

  assert test_support.round_trip(
      gaseto.new_claims()
        |> gaseto.with_issued_at(issued_long_ago)
        |> gaseto.with_expires_at(a_minute_ago),
      rules,
    )
    == Error(error.Expired(expired_at: a_minute_ago))
  assert test_support.round_trip(
      gaseto.new_claims()
        |> gaseto.with_issued_at(issued_long_ago)
        |> gaseto.with_not_before(in_a_minute)
        |> gaseto.with_expires_at(in_an_hour),
      rules,
    )
    == Error(error.NotYetValid(valid_from: in_a_minute))
  assert test_support.round_trip(
      gaseto.new_claims()
        |> gaseto.with_issued_at(in_a_minute)
        |> gaseto.with_expires_at(in_an_hour),
      rules,
    )
    == Error(error.IssuedInTheFuture(issued_at: in_a_minute))
}

pub fn clock_skew_is_exact_at_its_limit_test() -> Nil {
  let now = timestamp.from_unix_seconds(1_800_000_000)
  let rules =
    gaseto.new_rules()
    |> gaseto.checked_at(now)
    |> gaseto.allow_clock_skew(duration.seconds(30))
  let issued_long_ago = timestamp.add(now, duration.hours(-1))
  let claims = fn(expires_at) {
    gaseto.new_claims()
    |> gaseto.with_issued_at(issued_long_ago)
    |> gaseto.with_expires_at(expires_at)
  }
  let assert Ok(_) =
    test_support.round_trip(
      claims(timestamp.add(now, duration.seconds(-30))),
      rules,
    )
  let assert Error(error.Expired(_)) =
    test_support.round_trip(
      claims(timestamp.add(now, duration.seconds(-31))),
      rules,
    )
  Nil
}

pub fn no_clock_skew_is_allowed_by_default_test() -> Nil {
  let now = timestamp.from_unix_seconds(1_800_000_000)
  let one_second_ago = timestamp.add(now, duration.seconds(-1))
  let claims =
    gaseto.new_claims()
    |> gaseto.with_issued_at(timestamp.add(now, duration.hours(-1)))
    |> gaseto.with_expires_at(one_second_ago)
  let assert Error(error.Expired(_)) =
    test_support.round_trip(
      claims,
      gaseto.new_rules() |> gaseto.checked_at(now),
    )
  Nil
}

pub fn negative_clock_skew_counts_as_none_test() -> Nil {
  let now = timestamp.from_unix_seconds(1_800_000_000)
  let rules =
    gaseto.new_rules()
    |> gaseto.checked_at(now)
    |> gaseto.allow_clock_skew(duration.seconds(-30))
  let issued_long_ago = timestamp.add(now, duration.hours(-1))
  let claims = fn(expires_at) {
    gaseto.new_claims()
    |> gaseto.with_issued_at(issued_long_ago)
    |> gaseto.with_expires_at(expires_at)
  }
  // A negative skew would otherwise refuse a token that is still valid
  let assert Ok(_) =
    test_support.round_trip(
      claims(timestamp.add(now, duration.seconds(10))),
      rules,
    )
  let assert Error(error.Expired(_)) =
    test_support.round_trip(
      claims(timestamp.add(now, duration.seconds(-1))),
      rules,
    )
  Nil
}

pub fn badly_formatted_times_are_refused_test() -> Nil {
  let decrypt = fn(payload) {
    gaseto.decrypt(
      test_support.encrypt_raw_payload(payload),
      test_support.first_local_key(),
      gaseto.new_rules(),
    )
  }
  assert decrypt("{\"exp\":1700000000}")
    == Error(error.InvalidClaim(name: "exp", error: error.NotAString))
  use payload <- list.each([
    "{\"exp\":\"2099-01-01t00:00:00Z\"}", "{\"exp\":\"2099-01-01T00:00:00z\"}",
    "{\"exp\":\"2099-01-01 00:00:00Z\"}", "{\"exp\":\"tomorrow\"}",
  ])
  assert decrypt(payload)
    == Error(error.InvalidClaim(name: "exp", error: error.NotAnRfc3339Time))
}

pub fn fractional_seconds_and_offsets_are_read_test() -> Nil {
  // The spec: parsers SHOULD accept fractional seconds
  // (https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md#payload-claims)
  let read_expiry = fn(time) {
    let assert Ok(token) =
      gaseto.decrypt(
        test_support.encrypt_raw_payload("{\"exp\":\"" <> time <> "\"}"),
        test_support.first_local_key(),
        gaseto.new_rules() |> gaseto.checked_at(timestamp.from_unix_seconds(0)),
      )
    gaseto.expires_at(token)
  }
  assert read_expiry("2099-01-01T00:00:00.5Z")
    == Some(timestamp.from_unix_seconds_and_nanoseconds(
      4_070_908_800,
      500_000_000,
    ))
  assert read_expiry("2099-01-01T01:00:00+01:00")
    == Some(timestamp.from_unix_seconds(4_070_908_800))
}
