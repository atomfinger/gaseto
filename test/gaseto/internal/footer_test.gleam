import gaseto/error.{FooterHasTooManyKeys, FooterIsMalformed, FooterTooDeep}
import gaseto/internal/footer
import gleam/list

fn check(json: String) -> Result(Nil, error.FooterDecodingError) {
  footer.check(<<json:utf8>>, max_length: 1000, max_depth: 2, max_keys: 2)
}

pub fn depth_counts_a_plain_value_as_one_test() -> Nil {
  use json <- list.each(["\"text\"", "42", "{}", "[]", "{\"a\":1}", "[1,2]"])
  assert check(json) == Ok(Nil)
}

pub fn nesting_beyond_the_limit_is_refused_test() -> Nil {
  assert check("{\"a\":{}}") == Error(FooterTooDeep(depth: 3, max_depth: 2))
  assert check("[[[]]]") == Error(FooterTooDeep(depth: 4, max_depth: 2))
}

pub fn brackets_and_colons_inside_strings_are_text_test() -> Nil {
  assert check("{\"a\":\"[[{{::\"}") == Ok(Nil)
}

pub fn an_escaped_quote_does_not_end_a_string_test() -> Nil {
  assert check("{\"a\":\"\\\"[[[\"}") == Ok(Nil)
  assert check("{\"a\":\"\\\\\"}") == Ok(Nil)
}

pub fn keys_are_counted_over_all_objects_test() -> Nil {
  assert check("{\"a\":1,\"b\":2}") == Ok(Nil)
  assert check("{\"a\":1,\"b\":2,\"c\":3}")
    == Error(FooterHasTooManyKeys(key_count: 3, max_keys: 2))
  let nested = "[{\"a\":1},{\"b\":2},{\"c\":3}]"
  assert footer.check(
      <<nested:utf8>>,
      max_length: 1000,
      max_depth: 3,
      max_keys: 2,
    )
    == Error(FooterHasTooManyKeys(key_count: 3, max_keys: 2))
}

pub fn unbalanced_input_is_malformed_test() -> Nil {
  use json <- list.each([
    "{", "[", "}", "]", "{]", "[}", "{\"a\":1}}", "\"never closed",
    "\"ends with a backslash\\",
  ])
  assert check(json) == Error(FooterIsMalformed)
}
