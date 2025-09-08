//// PASETO Pre-Authentication Encoding (PAE) and token encoding utilities
//// shared across all PASETO versions.
////
//// PAE is defined in the PASETO spec as a deterministic encoding of a list
//// of byte strings into a single byte string for authentication. Every PASETO
//// version uses the same PAE algorithm.

import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result

/// Encodes a list of byte strings as a single authenticated message using
/// PASETO Pre-Authentication Encoding (PAE).
pub fn pre_auth_encode(parts: List(BitArray)) -> BitArray {
  let start: BitArray = le64_encode(list.length(parts))
  list.fold(parts, start, fn(accumulator, part) {
    let part_length: Int = bit_array.byte_size(part)
    bit_array.concat([accumulator, le64_encode(part_length), part])
  })
}

/// Decodes an optional base64url-encoded footer to raw bytes.
/// Returns a plain String error so callers can map it into their own error type.
pub fn decode_footer(
  encoded_footer: Option(String),
) -> Result(BitArray, String) {
  result.map_error(
    case encoded_footer {
      Some(footer_string) -> bit_array.base64_url_decode(footer_string)
      None -> Ok(<<>>)
    },
    fn(_) { "Token footer is not valid base64url" },
  )
}

/// Converts raw footer bytes back to an optional string, treating empty as None.
pub fn footer_bytes_to_option(footer_bytes: BitArray) -> Option(String) {
  case bit_array.to_string(footer_bytes) {
    Ok("") -> None
    Ok(footer_string) -> Some(footer_string)
    Error(_) -> None
  }
}

/// Encodes an integer as an 8-byte little-endian value.
fn le64_encode(value: Int) -> BitArray {
  <<value:little-size(64)>>
}
