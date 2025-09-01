import gleeunit
import gleam/bit_array
import gleam/list
import gleam/result
import gleam/string
import hkdf_erlang

pub fn main() -> Nil {
  gleeunit.main()
}

fn char_to_int(char: String) -> Result(Int, Nil) {
  case char {
    "0" -> Ok(0)
    "1" -> Ok(1)
    "2" -> Ok(2)
    "3" -> Ok(3)
    "4" -> Ok(4)
    "5" -> Ok(5)
    "6" -> Ok(6)
    "7" -> Ok(7)
    "8" -> Ok(8)
    "9" -> Ok(9)
    "a" -> Ok(10)
    "b" -> Ok(11)
    "c" -> Ok(12)
    "d" -> Ok(13)
    "e" -> Ok(14)
    "f" -> Ok(15)
    _ -> Error(Nil)
  }
}

fn decode_hex(hex: String) -> Result(BitArray, Nil) {
  let chars = string.to_graphemes(hex)
  let pairs = list.sized_chunk(chars, 2)

  let bytes_result =
    list.try_map(pairs, fn(pair) {
      case pair {
        [high, low] -> {
          use high_val <- result.try(char_to_int(string.lowercase(high)))
          use low_val <- result.try(char_to_int(string.lowercase(low)))
          Ok(high_val * 16 + low_val)
        }
        _ -> Error(Nil)
      }
    })

  case bytes_result {
    Ok(bytes) -> {
      let bit_arrays = list.map(bytes, fn(byte) { <<byte:size(8)>> })
      Ok(list.fold(bit_arrays, <<>>, bit_array.append))
    }
    Error(e) -> Error(e)
  }
}

pub fn hkdf_test() {
  let ikm_hex = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
  let assert Ok(ikm) = decode_hex(ikm_hex)
  assert bit_array.byte_size(ikm) == 22

  let salt_hex = "000102030405060708090a0b0c"
  let assert Ok(salt) = decode_hex(salt_hex)
  assert bit_array.byte_size(salt) == 13

  let info_hex = "f0f1f2f3f4f5f6f7f8f9"
  let assert Ok(info) = decode_hex(info_hex)
  assert bit_array.byte_size(info) == 10

  let okm_hex =
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
  let assert Ok(expected) = decode_hex(okm_hex)
  let derived =
    hkdf_erlang.derive(#("sha256"), ikm, info, salt, 42)
  assert derived == expected
}
