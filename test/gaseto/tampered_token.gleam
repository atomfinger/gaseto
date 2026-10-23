//// Changes tokens while keeping their base64url canonical, so a test reaches
//// the tag or signature check instead of failing at decoding.

import gleam/bit_array
import gleam/int
import gleam/string

pub fn with_changed_body(token: String) -> String {
  let assert [version, purpose, encoded_body, ..footer] =
    string.split(token, on: ".")
  let assert Ok(<<first_byte, rest:bytes>>) =
    bit_array.base64_url_decode(encoded_body)
  let changed_body = <<{ int.bitwise_exclusive_or(first_byte, 1) }, rest:bits>>
  string.join(
    [
      version,
      purpose,
      bit_array.base64_url_encode(changed_body, False),
      ..footer
    ],
    with: ".",
  )
}

pub fn with_changed_footer(token: String) -> String {
  let assert [version, purpose, encoded_body, ..] = string.split(token, on: ".")
  string.join(
    [
      version,
      purpose,
      encoded_body,
      bit_array.base64_url_encode(<<"{\"kid\":\"changed\"}":utf8>>, False),
    ],
    with: ".",
  )
}
