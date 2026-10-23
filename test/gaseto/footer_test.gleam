import gaseto.{FooterRules}
import gaseto/error
import gaseto/paseto_v4_test_vector
import gleam/dynamic/decode
import gleam/list
import gleam/string

pub fn unverified_footer_reads_the_footer_test() -> Nil {
  let assert Ok(vector) =
    list.find(paseto_v4_test_vector.local_vectors, fn(vector) {
      vector.footer != ""
    })
  assert gaseto.unverified_footer(vector.token) == Ok(<<vector.footer:utf8>>)
  assert gaseto.unverified_footer(
      paseto_v4_test_vector.first_local_vector().token,
    )
    == Ok(<<>>)
}

pub fn footer_is_decoded_test() -> Nil {
  let key_identifier_decoder = decode.at(["kid"], decode.string)
  use #(footer, key_identifier) <- list.each([
    #("{\"kid\":\"k4.lid.abc\"}", "k4.lid.abc"),
    // Brackets, quotes and backslashes inside strings are not structure
    #("{\"kid\":\"[[{{\\\"\\\\\"}", "[[{{\"\\"),
  ])
  assert gaseto.decode_footer(
      <<footer:utf8>>,
      gaseto.default_footer_rules,
      key_identifier_decoder,
    )
    == Ok(key_identifier)
}

pub fn footer_rules_are_enforced_test() -> Nil {
  let rules = FooterRules(max_length: 64, max_depth: 2, max_keys: 2)
  let decoder = decode.dynamic
  assert gaseto.decode_footer(<<string.repeat("a", 65):utf8>>, rules, decoder)
    == Error(error.FooterTooLong(length: 65, max_length: 64))
  assert gaseto.decode_footer(<<"{\"a\":{\"b\":1}}":utf8>>, rules, decoder)
    == Error(error.FooterTooDeep(depth: 3, max_depth: 2))
  assert gaseto.decode_footer(
      <<"{\"a\":1,\"b\":2,\"c\":3}":utf8>>,
      rules,
      decoder,
    )
    == Error(error.FooterHasTooManyKeys(key_count: 3, max_keys: 2))
  let assert Error(error.FooterDecodeFailed(_)) =
    gaseto.decode_footer(
      <<"{\"a\":1}":utf8>>,
      rules,
      decode.at(["kid"], decode.string),
    )
  Nil
}

pub fn malformed_footers_are_rejected_test() -> Nil {
  use footer <- list.each(["{\"a\":[1}", "{\"a\":1", "]", "{\"a\":\"open"])
  assert gaseto.decode_footer(
      <<footer:utf8>>,
      gaseto.default_footer_rules,
      decode.dynamic,
    )
    == Error(error.FooterIsMalformed)
}

pub fn escaped_backslash_does_not_hide_nesting_test() -> Nil {
  // An escaped backslash before a closing quote once threw the quote
  // counting off, letting deep nesting through
  let deep = string.repeat("[", 3000) <> string.repeat("]", 3000)
  let footer = "{\"k\":\"\\\\\",\"x\":" <> deep <> ",\"z\":\"\\\\\"}"
  assert gaseto.decode_footer(
      <<footer:utf8>>,
      gaseto.default_footer_rules,
      decode.dynamic,
    )
    == Error(error.FooterTooDeep(depth: 3002, max_depth: 2))
}

pub fn keys_ending_in_a_backslash_are_counted_test() -> Nil {
  let rules = FooterRules(max_length: 64, max_depth: 2, max_keys: 1)
  assert gaseto.decode_footer(
      <<"{\"a\\\\\":1,\"b\\\\\":2}":utf8>>,
      rules,
      decode.dynamic,
    )
    == Error(error.FooterHasTooManyKeys(key_count: 2, max_keys: 1))
}
