import gaseto/error.{
  FooterHasTooManyKeys, FooterIsMalformed, FooterTooDeep, FooterTooLong,
}
import gleam/bit_array
import gleam/bool
import gleam/int
import gleam/result

type Shape {
  Shape(depth: Int, key_count: Int)
}

type Bracket {
  Brace
  Square
}

type Scan {
  Scan(
    open_brackets: List(Bracket),
    // The length of `open_brackets`, kept so it is not recounted per bracket
    depth: Int,
    deepest: Int,
    key_count: Int,
  )
}

/// A footer can be read before the token is checked, so it may come from an
/// attacker. Very deep nesting can exhaust a JSON parser, and very many keys
/// allow hash-collision attacks, so the spec asks for both to be limited
/// before parsing
/// ([Storing JSON in the Footer](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md#storing-json-in-the-footer)).
///
/// This reads each byte once and only looks at quotes, backslashes, brackets
/// and colons. The spec's regex approach is not used: it needs a pass per
/// level of nesting, and it misses keys written with a space before the
/// colon. Depth follows the spec: a scalar has depth 1 and a flat object
/// depth 2
/// ([Enforcing Maximum Depth](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md#enforcing-maximum-depth-without-parsing-the-json-string)).
pub fn check(
  footer: BitArray,
  max_length max_length: Int,
  max_depth max_depth: Int,
  max_keys max_keys: Int,
) -> Result(Nil, error.FooterDecodingError) {
  let length = bit_array.byte_size(footer)
  use <- bool.guard(
    when: length > max_length,
    return: Error(FooterTooLong(length:, max_length:)),
  )
  use Shape(depth:, key_count:) <- result.try(
    scan_json(
      footer,
      Scan(open_brackets: [], depth: 0, deepest: 0, key_count: 0),
    )
    |> result.replace_error(FooterIsMalformed),
  )
  use <- bool.guard(
    when: depth > max_depth,
    return: Error(FooterTooDeep(depth:, max_depth:)),
  )
  use <- bool.guard(
    when: key_count > max_keys,
    return: Error(FooterHasTooManyKeys(key_count:, max_keys:)),
  )
  Ok(Nil)
}

/// Outside strings, brackets change the depth and each ":" follows a key.
fn scan_json(json: BitArray, state: Scan) -> Result(Shape, Nil) {
  case json {
    <<>> -> finish(state)
    <<"\"":utf8, rest:bytes>> -> scan_string(rest, state)
    <<"{":utf8, rest:bytes>> -> scan_json(rest, open(state, Brace))
    <<"[":utf8, rest:bytes>> -> scan_json(rest, open(state, Square))
    <<"}":utf8, rest:bytes>> -> close(rest, state, Brace)
    <<"]":utf8, rest:bytes>> -> close(rest, state, Square)
    <<":":utf8, rest:bytes>> ->
      scan_json(rest, Scan(..state, key_count: state.key_count + 1))
    <<_, rest:bytes>> -> scan_json(rest, state)
    // Only a bit array that is not whole bytes ends up here
    _ -> Error(Nil)
  }
}

/// Inside a string, brackets and colons are just text. A backslash escapes
/// the next character, so `\"` does not end the string.
fn scan_string(json: BitArray, state: Scan) -> Result(Shape, Nil) {
  case json {
    <<"\"":utf8, rest:bytes>> -> scan_json(rest, state)
    <<"\\":utf8, _escaped, rest:bytes>> -> scan_string(rest, state)
    <<_, rest:bytes>> -> scan_string(rest, state)
    // The string never ends
    _ -> Error(Nil)
  }
}

fn open(state: Scan, bracket: Bracket) -> Scan {
  let depth = state.depth + 1
  Scan(
    ..state,
    open_brackets: [bracket, ..state.open_brackets],
    depth:,
    deepest: int.max(state.deepest, depth),
  )
}

/// A closing bracket must match the last one opened.
fn close(rest: BitArray, state: Scan, bracket: Bracket) -> Result(Shape, Nil) {
  case state.open_brackets {
    [last_opened, ..still_open] if last_opened == bracket ->
      scan_json(
        rest,
        Scan(..state, open_brackets: still_open, depth: state.depth - 1),
      )
    _ -> Error(Nil)
  }
}

/// The spec counts a value with no brackets as depth 1.
fn finish(state: Scan) -> Result(Shape, Nil) {
  case state.open_brackets {
    [] -> Ok(Shape(depth: state.deepest + 1, key_count: state.key_count))
    _ -> Error(Nil)
  }
}
