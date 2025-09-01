import gaseto/hkdf
import gleam/bit_array
import gleam/crypto
import gleam/list
import gleam/result
import gleam/string
import gleeunit/should

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

pub fn sha256_basic_test() {
  let ikm_hex = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
  let salt_hex = "000102030405060708090a0b0c"
  let info_hex = "f0f1f2f3f4f5f6f7f8f9"
  let prk_hext =
    "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
  let okm_hex =
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
  let size = 42
  let algorithm = crypto.Sha256

  let assert Ok(ikm) = decode_hex(ikm_hex)
  let assert Ok(salt) = decode_hex(salt_hex)
  let assert Ok(info) = decode_hex(info_hex)
  let assert Ok(prk) = decode_hex(prk_hext)
  let assert Ok(okm) = decode_hex(okm_hex)

  let assert Ok(derived) = hkdf.hkdf_derive(algorithm, salt, ikm, info, size)
  assert prk == hkdf.extract(algorithm, salt, ikm)
  assert Ok(okm) == hkdf.expand(algorithm, prk, info, size)
  assert derived == okm
}

pub fn sha256_long_entries_test() {
  let ikm_hex =
    "000102030405060708090a0b0c0d0e0f"
    <> "101112131415161718191a1b1c1d1e1f"
    <> "202122232425262728292a2b2c2d2e2f"
    <> "303132333435363738393a3b3c3d3e3f"
    <> "404142434445464748494a4b4c4d4e4f"

  let salt_hex =
    "606162636465666768696a6b6c6d6e6f"
    <> "707172737475767778797a7b7c7d7e7f"
    <> "808182838485868788898a8b8c8d8e8f"
    <> "909192939495969798999a9b9c9d9e9f"
    <> "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"

  let info_hex =
    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
    <> "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
    <> "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
    <> "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
    <> "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"

  let prk_hex =
    "06a6b88c5853361a06104c9ceb35b45c" <> "ef760014904671014a193f40c15fc244"

  let okm_hex =
    "b11e398dc80327a1c8e7f78c596a4934"
    <> "4f012eda2d4efad8a050cc4c19afa97c"
    <> "59045a99cac7827271cb41c65e590e09"
    <> "da3275600c2f09b8367793a9aca3db71"
    <> "cc30c58179ec3e87c14c01d5c1f3434f"
    <> "1d87"

  let size = 82
  let algorithm = crypto.Sha256

  let assert Ok(ikm) = decode_hex(ikm_hex)
  let assert Ok(salt) = decode_hex(salt_hex)
  let assert Ok(info) = decode_hex(info_hex)
  let assert Ok(prk) = decode_hex(prk_hex)
  let assert Ok(okm) = decode_hex(okm_hex)

  let assert Ok(derived) = hkdf.hkdf_derive(algorithm, salt, ikm, info, size)
  assert prk == hkdf.extract(algorithm, salt, ikm)
  assert Ok(okm) == hkdf.expand(algorithm, prk, info, size)
  assert derived == okm
}

pub fn sha256_zero_salt_and_info_test() {
  let ikm_hex = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
  let salt_hex = ""
  let info_hex = ""
  let prk_hex =
    "19ef24a32c717b167f33a91d6f648bdf" <> "96596776afdb6377ac434c1c293ccb04"
  let okm_hex =
    "8da4e775a563c18f715f802a063c5a31"
    <> "b8a11f5c5ee1879ec3454e5f3c738d2d"
    <> "9d201395faa4b61a96c8"

  let size = 42
  let algorithm = crypto.Sha256

  let assert Ok(ikm) = decode_hex(ikm_hex)
  let assert Ok(salt) = decode_hex(salt_hex)
  let assert Ok(info) = decode_hex(info_hex)
  let assert Ok(prk) = decode_hex(prk_hex)
  let assert Ok(okm) = decode_hex(okm_hex)

  let assert Ok(derived) = hkdf.hkdf_derive(algorithm, salt, ikm, info, size)
  assert prk == hkdf.extract(algorithm, salt, ikm)
  assert Ok(okm) == hkdf.expand(algorithm, prk, info, size)
  assert derived == okm
}

pub fn expand_invalid_zero_length_test() {
  let algorithm = crypto.Sha256
  let assert Ok(prk) =
    decode_hex(
      "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
    )
  let assert Ok(info) = decode_hex("f0f1f2f3f4f5f6f7f8f9")
  should.be_error(hkdf.expand(algorithm, prk, info, 0))
}

pub fn expand_invalid_negative_length_test() {
  let algorithm = crypto.Sha256
  let assert Ok(prk) =
    decode_hex(
      "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
    )
  let assert Ok(info) = decode_hex("f0f1f2f3f4f5f6f7f8f9")
  should.be_error(hkdf.expand(algorithm, prk, info, -1))
}

pub fn expand_invalid_length_test() {
  let algorithm = crypto.Sha256
  let assert Ok(prk) =
    decode_hex(
      "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
    )
  let assert Ok(info) = decode_hex("f0f1f2f3f4f5f6f7f8f9")
  // SHA256 hash length is 32 bytes
  let too_long = 255 * 32 + 1
  should.be_error(hkdf.expand(algorithm, prk, info, too_long))
}
