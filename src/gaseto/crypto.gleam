@external(erlang, "crypto", "crypto_one_time")
pub fn crypto_one_time(
  algorithm: atom,
  key: BitArray,
  iv: BitArray,
  data: BitArray,
  encrypt: Bool,
) -> BitArray

@external(erlang, "crypto", "mac")
pub fn crypto_mac(type_: atom, key: BitArray, data: BitArray) -> BitArray

@external(erlang, "hkdf", "derive")
pub fn hkdf_derive(
  algorithm: atom,
  ikm: BitArray,
  info: BitArray,
  salt: BitArray,
  length: Int,
) -> BitArray
