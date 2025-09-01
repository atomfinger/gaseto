import gaseto
import gaseto/crypto as gaseto_crypto
import gleam/bit_array
import gleam/crypto
import gleam/option.{type Option}
import gleam/result

pub type GasetoV1Error {
  InvalidTokenType(message: String)
  UnexpectedEncryptionError(message: String)
}

pub fn decrypt_token(token: gaseto.Token, secret_key: String) {
  case token.version, token.purpose {
    gaseto.PasetoV1, gaseto.Local -> todo
    gaseto.PasetoV1, gaseto.Public -> todo
    _, _ -> Error(InvalidTokenType("Unsupported version"))
  }
}

pub fn encrypt(shared_secret: String, payload: String, footer: Option(String)) {
  let random_key: BitArray = crypto.strong_random_bytes(32)
  let bit_payload = bit_array.from_string(payload)
  let bit_footer = case footer {
    option.Some(f) -> option.Some(bit_array.from_string(f))
    option.None -> option.None
  }
  let nounce = crypto.hmac(bit_payload, crypto.Sha384, random_key)

  todo
}

fn decrypt_local(payload: String, key: String, footer: Option(String)) {
  todo
}

/// Compute a 32-byte nonce from payload and randomKey
pub fn get_nonce(
  payload: BitArray,
  random_key: BitArray,
) -> Result(BitArray, GasetoV1Error) {
  let full: BitArray = crypto.hmac(payload, crypto.Sha384, random_key)
  case bit_array.slice(from: full, at: 0, take: 32) {
    Ok(result) -> Ok(result)
    Error(_) -> Error(UnexpectedEncryptionError("Could not slice bit-array"))
  }
}

pub fn aead_encrypt(
  payload: String,
  key: BitArray,
  footer: Option(String),
  n: BitArray,
) -> Result(String, GasetoV1Error) {
  let hash_algo = #("sha384")
  let header = "v1.local."
  use nonce <- result.try(get_nonce(bit_array.from_string(payload), n))

  // Split nonce (32 bytes) into 16 + 16
  let assert Ok(leftmost) = bit_array.slice(nonce, 0, 16)
  let assert Ok(rightmost) = bit_array.slice(nonce, 16, 32)

  todo
  // let ek = hkdf_derive(hash_algo, key, 32, leftmost, "paseto-encryption-key")
  // let ak = hkdf_derive(hash_algo, key, 32, leftmost, "paseto-auth-key-for-aead")
  //
  // let ciphertext =
  //   crypto_one_time(#("aes_256_ctr"), ek, rightmost, payload, True)
  //
  // let pre_auth_hash =
  //   [
  //     header_local,
  //     nonce,
  //     ciphertext,
  //     footer |> option.unwrap("") |> string.to_utf8,
  //   ]
  //   |> pre_auth_encode
  //   |> hmac_sha384(ak)
  //
  // let token =
  //   b64_encode_token(
  //     header_local,
  //     bit_array.concat([nonce, ciphertext, pre_auth_hash]),
  //     footer,
  //   )
  //
  // token
}

pub fn aes_256_ctr(key: BitArray, data: BitArray, nonce: BitArray) -> BitArray {
  gaseto_crypto.crypto_one_time(#("aes_256_ctr"), key, nonce, data, True)
}
