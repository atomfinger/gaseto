import gaseto/internal/json_object
import gleam/dict
import gleam/dynamic
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{None}

pub fn objects_with_unique_keys_are_decoded_test() -> Nil {
  use source <- list.each([
    "{}",
    "{\"a\":1}",
    " \n\t{\"a\":1}\r\n ",
    // Names are compared exactly
    "{\"a\":1,\"A\":2,\"a \":3}",
    // The same name in different objects is allowed
    "{\"a\":{\"b\":1},\"b\":2}",
    "{\"a\":[{\"b\":1},{\"b\":2}]}",
    "{\"a\":{\"a\":{\"a\":1}}}",
    "{\"a\":{},\"b\":{}}",
  ])
  let assert Ok(_) = json_object.decode(source) as source
  Nil
}

pub fn repeated_keys_are_refused_test() -> Nil {
  use source <- list.each([
    "{\"a\":1,\"a\":2}",
    "{\"a\":1,\"a\":1}",
    "{\"a\":1,\"b\":2,\"a\":3}",
    "{\"a\":{\"b\":1},\"a\":2}",
    "{\"sub\":\"alice\",\"sub\":\"bob\"}",
    // Escapes are decoded before names are compared
    "{\"a\":1,\"\\u0061\":2}",
    "{\"x\":{\"b\":1,\"b\":2}}",
    "{\"x\":[{\"b\":1},{\"b\":2,\"b\":3}]}",
    "{\"x\":{\"y\":{\"z\":{\"b\":1,\"b\":2}}}}",
  ])
  assert json_object.decode(source) == Error(Nil) as source
}

pub fn anything_but_an_object_is_refused_test() -> Nil {
  use source <- list.each([
    "", "   ", "[]", "[{}]", "\"text\"", "42", "1.5", "null", "true",
  ])
  assert json_object.decode(source) == Error(Nil) as source
}

pub fn invalid_json_is_refused_test() -> Nil {
  use source <- list.each([
    "{\"a\":1,}",
    "{\"a\":[1,]}",
    "{\"a\":1} x",
    "{\"a\":1}{}",
    "{\"a\":1",
    "{'a':1}",
    "{a:1}",
    "{\"a\":01}",
    "{\"a\":NaN}",
    "{\"a\":\"\\x\"}",
    "{\"a\":\"\\ud800\"}",
  ])
  assert json_object.decode(source) == Error(Nil) as source
}

pub fn values_are_the_same_as_from_gleam_json_test() -> Nil {
  use source <- list.each([
    "{}",
    "{\"s\":\"x\",\"i\":-1,\"f\":1.5e3,\"t\":true,\"z\":false,\"n\":null}",
    "{\"l\":[1,[2,{}],{\"k\":[]}],\"o\":{\"k\":{\"k\":\"v\"}}}",
    "{\"u\":\"\\u00e9\\ud83d\\ude00\\n\",\"big\":123456789012345678901234567890}",
  ])
  let assert Ok(value) = json_object.decode(source) as source
  assert Ok(value)
    == json.parse(source, decode.dict(decode.string, decode.dynamic))
    as source
}

pub fn values_run_through_decoders_test() -> Nil {
  let source =
    "{\"name\":\"Ada\",\"age\":36,\"nickname\":null,\"tags\":[\"a\",\"b\"]}"
  let assert Ok(object) = json_object.decode(source)
  assert field(object, "name", decode.string) == Ok("Ada")
  assert field(object, "age", decode.int) == Ok(36)
  assert field(object, "nickname", decode.optional(decode.string)) == Ok(None)
  assert field(object, "tags", decode.list(decode.string)) == Ok(["a", "b"])
}

fn field(
  object: dict.Dict(String, dynamic.Dynamic),
  name: String,
  decoder: decode.Decoder(a),
) -> Result(a, List(decode.DecodeError)) {
  let assert Ok(value) = dict.get(object, name)
  decode.run(value, decoder)
}
