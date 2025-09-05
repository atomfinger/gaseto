import gleam/dynamic.{type Dynamic}

@external(erlang, "public_key", "pem_decode")
pub fn pem_decode(pem: BitArray) -> List(Dynamic)

@external(erlang, "public_key", "pem_entry_decode")
pub fn pem_entry_decode(entry: Dynamic) -> Dynamic

@external(erlang, "public_key", "sign")
pub fn rsa_sign(data: BitArray, hash: atom, key: Dynamic) -> BitArray

@external(erlang, "public_key", "sign")
pub fn rsa_pss_sign(
  data: BitArray,
  digest_type: atom,
  key: Dynamic,
  options: List(#(atom, atom)),
) -> BitArray

@external(erlang, "public_key", "sign")
pub fn rsa_sign_with_options(
  data: BitArray,
  digest_type: atom,
  key: Dynamic,
  options: List(#(atom, Dynamic)),
) -> BitArray

@external(erlang, "public_key", "pem_decode")
pub fn decode_pem(pem_bytes: BitArray) -> List(dynamic.Dynamic)

@external(erlang, "public_key", "pem_entry_decode")
pub fn decode_pem_entry(pem_entry: dynamic.Dynamic) -> dynamic.Dynamic

@external(erlang, "public_key", "verify")
pub fn rsa_verify(
  data: BitArray,
  hash: atom,
  sig: BitArray,
  key: Dynamic,
) -> Bool

@external(erlang, "public_key", "verify")
pub fn rsa_verify_with_options(
  data: BitArray,
  hash_algorithm: atom,
  signature: BitArray,
  public_key: dynamic.Dynamic,
  options: List(#(atom, Dynamic)),
) -> Bool

pub fn load_private_key_from_pem(pem: BitArray) -> Result(Dynamic, String) {
  case pem_decode(pem) {
    [entry, ..] -> Ok(pem_entry_decode(entry))
    [] -> Error("pem_decode returned no entries")
  }
}
