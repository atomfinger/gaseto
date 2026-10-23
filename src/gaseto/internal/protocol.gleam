import gaseto/error
import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string

/// An empty footer means there is no footer, as in the spec
/// ([version 4, Encrypt](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#encrypt)).
pub type Contents {
  Contents(payload: String, footer: BitArray)
}

pub opaque type TokenParts {
  TokenParts(body: BitArray, footer: BitArray)
}

pub fn footer(parts: TokenParts) -> BitArray {
  parts.footer
}

/// Splits what follows the header: the body, and the footer if there is one.
pub fn split_body(rest: String) -> Result(TokenParts, error.TokenFormatError) {
  use #(encoded_body, encoded_footer) <- result.try(
    case string.split(rest, on: ".") {
      [encoded_body] -> Ok(#(encoded_body, None))
      // Encoders never write an empty footer
      [_, ""] -> Error(error.EmptyFooterSegment)
      [encoded_body, encoded_footer] ->
        Ok(#(encoded_body, Some(encoded_footer)))
      _ -> Error(error.WrongNumberOfSegments)
    },
  )
  use body <- result.try(decode_base64_url(encoded_body))
  use footer <- result.try(case encoded_footer {
    Some(encoded_footer) -> decode_base64_url(encoded_footer)
    None -> Ok(<<>>)
  })
  Ok(TokenParts(body:, footer:))
}

/// The body of a `local` token: a nonce, the ciphertext and an
/// authentication tag.
pub type LocalBody {
  LocalBody(nonce: BitArray, ciphertext: BitArray, authentication_tag: BitArray)
}

pub fn split_local_body(
  parts: TokenParts,
  nonce_size nonce_size: Int,
  tag_size tag_size: Int,
) -> Result(LocalBody, error.TokenValidationError) {
  let ciphertext_size = bit_array.byte_size(parts.body) - nonce_size - tag_size
  case parts.body {
    <<
      nonce:bytes-size(nonce_size),
      ciphertext:bytes-size(ciphertext_size),
      authentication_tag:bytes-size(tag_size),
    >>
      if ciphertext_size >= 0
    -> Ok(LocalBody(nonce:, ciphertext:, authentication_tag:))
    _ -> Error(error.InvalidFormat(error.BodyTooShort))
  }
}

/// The body of a `public` token: the payload and its signature.
pub type SignedBody {
  SignedBody(payload: BitArray, signature: BitArray)
}

pub fn split_signed_body(
  parts: TokenParts,
  signature_size signature_size: Int,
) -> Result(SignedBody, error.TokenValidationError) {
  let payload_size = bit_array.byte_size(parts.body) - signature_size
  case parts.body {
    <<payload:bytes-size(payload_size), signature:bytes>> if payload_size >= 0 ->
      Ok(SignedBody(payload:, signature:))
    _ -> Error(error.InvalidFormat(error.BodyTooShort))
  }
}

pub fn pre_authentication_encode(parts: List(BitArray)) -> BitArray {
  let start: BitArray = little_endian_64_encode(list.length(parts))
  list.fold(parts, start, fn(accumulator, part) {
    let part_length: Int = bit_array.byte_size(part)
    bit_array.concat([accumulator, little_endian_64_encode(part_length), part])
  })
}

pub fn encode_token(
  header: String,
  body: BitArray,
  footer: BitArray,
) -> String {
  header
  <> bit_array.base64_url_encode(body, False)
  <> case footer {
    <<>> -> ""
    _ -> "." <> bit_array.base64_url_encode(footer, False)
  }
}

pub fn decode_hex_key(
  key_hex: String,
  expected_size: Int,
) -> Result(BitArray, error.KeyLoadingError) {
  use key: BitArray <- result.try(result.replace_error(
    bit_array.base16_decode(key_hex),
    error.NotHex,
  ))
  case bit_array.byte_size(key) {
    size if size == expected_size -> Ok(key)
    size -> Error(error.WrongLength(expected: expected_size, found: size))
  }
}

/// Lowercase, as most tools write hex.
pub fn encode_hex_key(key: BitArray) -> String {
  bit_array.base16_encode(key) |> string.lowercase
}

pub fn payload_to_string(
  payload_bytes: BitArray,
) -> Result(String, error.TokenValidationError) {
  result.replace_error(bit_array.to_string(payload_bytes), error.InvalidPayload)
}

/// The spec forbids `=` padding and non-zero trailing bits
/// ([Base64 Decoding](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Common.md#base64-decoding)),
/// but `bit_array.base64_url_decode` accepts both. Encoding the result again
/// and comparing refuses them.
fn decode_base64_url(
  segment: String,
) -> Result(BitArray, error.TokenFormatError) {
  use decoded: BitArray <- result.try(result.replace_error(
    bit_array.base64_url_decode(segment),
    error.NotBase64Url,
  ))
  case bit_array.base64_url_encode(decoded, False) == segment {
    True -> Ok(decoded)
    False -> Error(error.NotBase64Url)
  }
}

/// The spec requires the most significant bit to be cleared
/// ([PAE Definition](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Common.md#pae-definition)).
fn little_endian_64_encode(value: Int) -> BitArray {
  <<int.bitwise_and(value, 0x7FFFFFFFFFFFFFFF):little-size(64)>>
}
