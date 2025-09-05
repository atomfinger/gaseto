@external(erlang, "crypto", "crypto_one_time")
pub fn crypto_one_time(
  algorithm: atom,
  key: BitArray,
  iv: BitArray,
  data: BitArray,
  encrypt: Bool,
) -> BitArray
