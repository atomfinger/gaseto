//// ECDSA P-384 + SHA-384 signing and verification for PASETO V3 public tokens.
////
//// Erlang's `crypto` module produces DER-encoded signatures, while PASETO requires
//// the flat IEEE P1363 format (r || s, 96 bytes). This module handles the conversion.
////
//// See `doc/ecdsa-p384.md` for background on the algorithms and formats involved.

import gleam/bit_array
import gleam/result

/// Signs data using ECDSA with P-384 and SHA-384.
/// Returns the DER-encoded signature from Erlang's crypto module.
@external(erlang, "gaseto_ecdsa_ffi", "sign_p384")
fn crypto_sign_p384(data: BitArray, private_key: BitArray) -> BitArray

/// Verifies a DER-encoded ECDSA P-384 + SHA-384 signature
@external(erlang, "gaseto_ecdsa_ffi", "verify_p384")
fn crypto_verify_p384(
  data: BitArray,
  der_signature: BitArray,
  public_key: BitArray,
) -> Bool

/// Signs data using ECDSA with P-384 curve and SHA-384.
/// Returns the signature in IEEE P1363 format
pub fn sign_p384(
  data: BitArray,
  private_key: BitArray,
) -> Result(BitArray, String) {
  crypto_sign_p384(data, private_key) |> der_to_p1363()
}

/// Verifies an ECDSA P-384 + SHA-384 signature.
/// Expects the signature in IEEE P1363 format.
/// The public key should be in compressed form (49 bytes: 02/03 prefix + 48-byte X).
pub fn verify_p384(
  data: BitArray,
  p1363_signature: BitArray,
  public_key: BitArray,
) -> Bool {
  case p1363_to_der(p1363_signature) {
    Error(_) -> False
    Ok(der_signature) -> crypto_verify_p384(data, der_signature, public_key)
  }
}

/// Converts a DER-encoded ECDSA signature to IEEE P1363 format.
/// DER format: 30 <total_length> 02 <r_length> <r_bytes> 02 <s_length> <s_bytes>
/// P1363 format: r (48 bytes, big-endian) || s (48 bytes, big-endian)
fn der_to_p1363(der: BitArray) -> Result(BitArray, String) {
  case der {
    <<0x30, _total_length, 0x02, r_length, r_and_s_section:bytes>> -> {
      use r_raw_bytes <- result.try(
        bit_array.slice(r_and_s_section, 0, r_length)
        |> result.map_error(fn(_) { "Could not extract r from DER" }),
      )
      let s_start_offset = r_length
      let r_and_s_section_size = bit_array.byte_size(r_and_s_section)
      use s_section <- result.try(
        bit_array.slice(
          r_and_s_section,
          s_start_offset,
          r_and_s_section_size - s_start_offset,
        )
        |> result.map_error(fn(_) { "Could not extract s header from DER" }),
      )
      case s_section {
        <<0x02, s_length, s_raw_section:bytes>> -> {
          use s_raw_bytes <- result.try(
            bit_array.slice(s_raw_section, 0, s_length)
            |> result.map_error(fn(_) { "Could not extract s from DER" }),
          )
          Ok(bit_array.append(
            normalize_to_48(r_raw_bytes),
            normalize_to_48(s_raw_bytes),
          ))
        }
        _ -> Error("Invalid S INTEGER in DER signature")
      }
    }
    _ -> Error("Invalid DER ECDSA signature format")
  }
}

/// Pads or trims a big-endian integer to exactly 48 bytes by
/// either removing leading zeros or adding them
fn normalize_to_48(value: BitArray) -> BitArray {
  let byte_count = bit_array.byte_size(value)
  case byte_count {
    count if count > 48 -> {
      case bit_array.slice(value, count - 48, 48) {
        Ok(trimmed) -> trimmed
        Error(_) -> value
      }
    }
    48 -> value
    count -> {
      let padding_bits = { 48 - count } * 8
      bit_array.append(<<0:size(padding_bits)>>, value)
    }
  }
}

/// Converts a 96-byte IEEE P1363 signature (r || s) to DER format
fn p1363_to_der(p1363_signature: BitArray) -> Result(BitArray, String) {
  case bit_array.byte_size(p1363_signature) {
    96 -> {
      use r_component: BitArray <- result.try(
        bit_array.slice(p1363_signature, 0, 48)
        |> result.map_error(fn(_) { "Could not slice r from P1363" }),
      )
      use s_component: BitArray <- result.try(
        bit_array.slice(p1363_signature, 48, 48)
        |> result.map_error(fn(_) { "Could not slice s from P1363" }),
      )
      let r_der_integer: BitArray = encode_der_integer(r_component)
      let s_der_integer: BitArray = encode_der_integer(s_component)
      let der_inner: BitArray = bit_array.append(r_der_integer, s_der_integer)
      let inner_length: Int = bit_array.byte_size(der_inner)
      Ok(<<0x30, inner_length, der_inner:bits>>)
    }
    _ -> Error("P1363 signature must be 96 bytes for P-384")
  }
}

/// Encodes a big-endian integer as a DER INTEGER element (tag 0x02)
fn encode_der_integer(raw_integer: BitArray) -> BitArray {
  let stripped_integer: BitArray = strip_leading_zeros(raw_integer)
  let sign_padded_integer: BitArray = case stripped_integer {
    <<>> -> <<0>>
    <<high_byte, _:bytes>> if high_byte >= 128 ->
      bit_array.append(<<0>>, stripped_integer)
    _ -> stripped_integer
  }
  let integer_length: Int = bit_array.byte_size(sign_padded_integer)
  <<0x02, integer_length, sign_padded_integer:bits>>
}

/// Strips all leading 0x00 bytes from a bit array.
fn strip_leading_zeros(data: BitArray) -> BitArray {
  case data {
    <<0, rest:bytes>> -> strip_leading_zeros(rest)
    _ -> data
  }
}
