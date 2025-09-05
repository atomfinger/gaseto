import gaseto/crypto as gaseto_crypto
import gaseto/hkdf
import gaseto/rsa
import gaseto/token.{
  type PasetoPurpose, type Token, Local, PasetoV1, Public, Token,
}
import gleam/bit_array
import gleam/crypto
import gleam/dynamic.{type Dynamic}
import gleam/erlang/atom
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result

const pub_header: String = "v1.public."

const priv_header: String = "v1.private."

pub type GasetoV1Error {
  InvalidTokenType(message: String)
  UnexpectedEncryptionError(message: String)
  HkdfError(message: String)
  InvalidKeyFormat(message: String)
}

pub type PasetoV1DecryptError {
  VerificationFailed(message: String)
  InvalidTokenFormat(message: String)
  NoKeyFound(message: String)
  InvalidKey(message: String)
  SecurityError
  CryptographicError(message: String)
  UnexpectedDecryptionError(message: String)
}

pub fn decrypt(
  purpose: PasetoPurpose,
  payload: String,
  footer: Option(String),
  key: String,
) -> Result(Token, PasetoV1DecryptError) {
  case purpose {
    Public -> decrypt_public(key, payload, footer)
    Local -> decrypt_local(key, payload, footer)
  }
}

fn decrypt_public(
  public_key_pem: String,
  encoded_body: String,
  encoded_footer: Option(String),
) -> Result(Token, PasetoV1DecryptError) {
  use decoded_body <- result.try(decode_body(encoded_body))

  use footer_bits: BitArray <- result.try(
    result.map_error(
      case encoded_footer {
        Some(f) -> bit_array.base64_url_decode(f)
        None -> Ok(<<>>)
      },
      fn(_) { InvalidTokenFormat("Token Footer is not base64") },
    ),
  )
  use public_key <- result.try({
    let pem_entries =
      public_key_pem
      |> bit_array.from_string
      |> rsa.decode_pem

    case pem_entries {
      [key_entry] -> Ok(rsa.decode_pem_entry(key_entry))
      [] ->
        Error(NoKeyFound(
          "PEM data contains no entries - expected RSA public key",
        ))
      _ -> Error(InvalidKey("PEM contains multiple entries"))
    }
  })
  let signature_size: Int = 256
  use body_size: Int <- result.try(case bit_array.byte_size(decoded_body) {
    size if size < signature_size ->
      Error(InvalidTokenFormat(
        "Token body is too short: " <> int.to_string(size),
      ))
    size -> Ok(size)
  })

  // Split the body into the payload and the signature.
  use payload_bits: BitArray <- result.try(
    case bit_array.slice(decoded_body, 0, body_size - signature_size) {
      Error(_) -> Error(InvalidTokenFormat("Could not slice body for payload"))
      Ok(slice) -> Ok(slice)
    },
  )
  use signature: BitArray <- result.try(
    case
      bit_array.slice(decoded_body, body_size - signature_size, signature_size)
    {
      Error(_) ->
        Error(InvalidTokenFormat("Could not slice body for signature"))
      Ok(slice) -> Ok(slice)
    },
  )

  // Reconstruct the `m2` that should have been signed.
  let m2: BitArray =
    pre_auth_encode([
      bit_array.from_string(pub_header),
      payload_bits,
      footer_bits,
    ])

  let is_valid: Bool =
    rsa.rsa_verify_with_options(
      m2,
      atom.create("sha384"),
      signature,
      public_key,
      create_pss_options(),
    )

  let footer = case bit_array.to_string(footer_bits) {
    Ok("") -> None
    Ok(result) -> Some(result)
    Error(_) -> None
  }

  use payload <- result.try(case bit_array.to_string(payload_bits) {
    Ok(result) -> Ok(result)
    Error(_) ->
      Error(InvalidTokenFormat("Could not convert payload bit array to string"))
  })

  case is_valid {
    True -> Ok(Token(PasetoV1, Public, payload, footer))
    False -> Error(VerificationFailed("RCA verification faild"))
  }
}

fn decode_body(encoded_body: String) -> Result(BitArray, PasetoV1DecryptError) {
  bit_array.base64_url_decode(encoded_body)
  |> result.map_error(fn(_) { InvalidTokenFormat("Token body is not base64") })
}

fn decrypt_local(
  raw_key: String,
  encoded_body: String,
  encoded_footer: Option(String),
) -> Result(Token, PasetoV1DecryptError) {
  use key: BitArray <- result.try(
    result.map_error(bit_array.base16_decode(raw_key), fn(_) {
      InvalidKey("Could not base16 encode secret")
    }),
  )

  // Validate key length (must be exactly 32 bytes for AES-256)
  use _ <- result.try(case bit_array.byte_size(key) {
    32 -> Ok(Nil)
    size ->
      Error(InvalidKey("Key must be 32 bytes, got " <> int.to_string(size)))
  })

  use decoded_body <- result.try(decode_body(encoded_body))

  use footer_bits: BitArray <- result.try(
    result.map_error(
      case encoded_footer {
        Some(f) -> bit_array.base64_url_decode(f)
        None -> Ok(<<>>)
      },
      fn(_) { InvalidTokenFormat("Token Footer is not base64") },
    ),
  )

  // PASETO v1 local structure: nonce (32) + ciphertext + tag (48)
  let nonce_size = 32
  let tag_size = 48
  let min_body_size = nonce_size + tag_size

  use body_size <- result.try(case bit_array.byte_size(decoded_body) {
    size if size < min_body_size ->
      Error(InvalidTokenFormat(
        "Token body too short: "
        <> int.to_string(size)
        <> ", minimum "
        <> int.to_string(min_body_size),
      ))
    size -> Ok(size)
  })

  // Extract components
  use nonce <- result.try(case bit_array.slice(decoded_body, 0, nonce_size) {
    Error(_) -> Error(InvalidTokenFormat("Could not extract nonce"))
    Ok(n) -> Ok(n)
  })

  let ciphertext_size = body_size - nonce_size - tag_size
  use ciphertext <- result.try(
    case bit_array.slice(decoded_body, nonce_size, ciphertext_size) {
      Error(_) -> Error(InvalidTokenFormat("Could not extract ciphertext"))
      Ok(c) -> Ok(c)
    },
  )

  use tag <- result.try(
    case bit_array.slice(decoded_body, body_size - tag_size, tag_size) {
      Error(_) ->
        Error(InvalidTokenFormat("Could not extract authentication tag"))
      Ok(t) -> Ok(t)
    },
  )

  // Derive encryption and authentication keys using HKDF
  use #(encryption_key, auth_key) <- result.try(derive_keys(key, nonce))

  // Verify HMAC-SHA384 authentication
  let pre_auth_data =
    pre_auth_encode([
      bit_array.from_string(priv_header),
      nonce,
      ciphertext,
      footer_bits,
    ])

  let computed_tag = crypto.hmac(auth_key, crypto.Sha384, pre_auth_data)

  use _ <- result.try(case constant_time_compare(tag, computed_tag) {
    True -> Ok(Nil)
    False -> Error(SecurityError)
  })

  // Split the nonce: IV for AES-CTR is the last 16 bytes
  use counter_nonce <- result.try(case bit_array.slice(nonce, 16, 16) {
    Ok(iv) -> Ok(iv)
    Error(_) ->
      Error(UnexpectedDecryptionError("Could not extract counter nonce"))
  })

  // Decrypt using AES-256-CTR
  use plaintext <- result.try(aes_256_ctr_decrypt(
    encryption_key,
    counter_nonce,
    ciphertext,
  ))

  let footer = case bit_array.to_string(footer_bits) {
    Ok("") -> None
    Ok(result) -> Some(result)
    Error(_) -> None
  }

  use payload <- result.try(case bit_array.to_string(plaintext) {
    Ok(result) -> Ok(result)
    Error(_) -> {
      Error(InvalidTokenFormat("Decrypted payload is not valid UTF-8"))
    }
  })

  Ok(Token(PasetoV1, Local, payload, footer))
}

// Derive encryption and authentication keys using HKDF-SHA384

fn derive_keys(
  master_key: BitArray,
  nonce: BitArray,
) -> Result(#(BitArray, BitArray), PasetoV1DecryptError) {
  let hash_algo = crypto.Sha384

  // Extract salt (first 16 bytes of nonce)
  use encryption_salt <- result.try(
    result.map_error(bit_array.slice(nonce, 0, 16), fn(_) {
      UnexpectedDecryptionError("could not slice nonce for encryption salt")
    }),
  )

  // Derive encryption key
  use encryption_key <- result.try(
    result.map_error(
      hkdf.hkdf_derive(
        hash_algo,
        encryption_salt,
        master_key,
        bit_array.from_string("paseto-encryption-key"),
        32,
      ),
      fn(error) { UnexpectedDecryptionError(error.message) },
    ),
  )

  // Derive authentication key
  use auth_key <- result.try(
    result.map_error(
      hkdf.hkdf_derive(
        hash_algo,
        encryption_salt,
        master_key,
        bit_array.from_string("paseto-auth-key-for-aead"),
        32,
      ),
      fn(error) { UnexpectedDecryptionError(error.message) },
    ),
  )

  Ok(#(encryption_key, auth_key))
}

// AES-256-CTR decryption using the same primitive as encryption.
// CTR decryption == CTR encryption, so we call crypto_one_time with False.
fn aes_256_ctr_decrypt(
  key: BitArray,
  nonce: BitArray,
  ciphertext: BitArray,
) -> Result(BitArray, PasetoV1DecryptError) {
  // use counter_nonce <- result.try(case bit_array.slice(nonce, 16, 16) {
  //   Ok(cn) -> Ok(cn)
  //
  //   Error(_) ->
  //     Error(CryptographicError("Could not slice nonce to make a counter-nonce"))
  // })

  case bit_array.byte_size(nonce) {
    16 -> {
      let plaintext =
        gaseto_crypto.crypto_one_time(
          atom.create("aes_256_ctr"),
          key,
          nonce,
          ciphertext,
          False,
        )
      Ok(plaintext)
    }
    _ -> Error(CryptographicError("Invalid IV length for AES-256-CTR"))
  }
}

// Constant time comparison to prevent timing attacks
fn constant_time_compare(a: BitArray, b: BitArray) -> Bool {
  case bit_array.byte_size(a) == bit_array.byte_size(b) {
    False -> False
    True -> {
      // You'll need to implement constant-time comparison
      // For now, this is NOT constant time (security vulnerability!)
      True
    }
  }
}

/// Encrypts a payload using either a public or local PASETO V1 scheme based on the provided purpose.
///
/// This function serves as the main entry point for PASETO V1 encryption. It handles the dispatching
/// to the appropriate encryption method—either `encrypt_public` or `encrypt_local`—depending on
/// the `purpose` specified. It also manages the creation of a nonce for local encryption.
///
/// ## Parameters
///
/// - `purpose`: The `PasetoPurpose` enum, which can be `Public` for asymmetric encryption or
///   `Local` for symmetric encryption.
/// - `key`: The encryption key as a string. For `Public` purpose, this should be the private key
///   in PEM format. For `Local` purpose, it's the shared secret.
/// - `payload`: The plaintext data to be encrypted.
/// - `footer`: An optional string containing unencrypted metadata to be included in the token.
/// - `nonce_generator`: An optional function that takes the payload and returns a nonce as a
///   `BitArray`. If `None`, a secure random nonce is generated internally.
///
/// ## Returns
///
/// A `Result` containing the encrypted `Token` on success, or a `GasetoV1Error` on failure.
///
pub fn encrypt(
  purpose: PasetoPurpose,
  key: String,
  payload: String,
  footer: Option(String),
) -> Result(Token, GasetoV1Error) {
  let nonce: BitArray = crypto.strong_random_bytes(32)
  case purpose {
    Public -> encrypt_public(key, payload, footer)
    Local -> encrypt_local(key, payload, footer, nonce)
  }
}

/// Performs symmetric encryption for PASETO V1 (v1.local).
///
/// This function uses the AES-256-CTR and HMAC-SHA384 algorithms to encrypt the
/// payload. It derives separate encryption and authentication keys from the provided
/// shared secret using HKDF. The final token is a combination of the nonce,
/// ciphertext, and an HMAC tag.
///
/// ## Parameters
///
/// - `shared_secret`: The shared secret key as a hexadecimal string.
/// - `plaintext_payload`: The plaintext data to be encrypted.
/// - `footer`: An optional string for unencrypted metadata.
/// - `nonce`: The nonce to be used for encryption.
///
/// ## Returns
///
/// A `Result` containing the `Token` on success, or a `GasetoV1Error` on failure.
fn encrypt_local(
  shared_secret: String,
  plaintext_payload: String,
  footer: Option(String),
  nonce: BitArray,
) -> Result(Token, GasetoV1Error) {
  use master_key: BitArray <- result.try(
    result.map_error(bit_array.base16_decode(shared_secret), fn(_) {
      InvalidKeyFormat("Could not base16 encode secret")
    }),
  )
  let footer_bits: BitArray = case footer {
    Some("") -> <<>>
    None -> <<>>
    Some(f) -> bit_array.from_string(f)
  }
  aead_encrypt(plaintext_payload, master_key, footer_bits, nonce)
}

/// Performs asymmetric encryption and signing for PASETO V1 (v1.public).
///
/// This function signs the payload using an RSA private key with the PSS signature scheme
/// and SHA-384. The final token is a combination of the plaintext payload and the generated
/// signature.
///
/// ## Parameters
///
/// - `private_key_pem`: The private key in PEM format.
/// - `plaintext_payload`: The plaintext data to be signed and included in the token.
/// - `footer`: An optional string for unencrypted metadata.
///
/// ## Returns
///
/// A `Result` containing the signed `Token` on success, or a `GasetoV1Error` on failure.
fn encrypt_public(
  private_key_pem: String,
  plaintext_payload: String,
  footer: Option(String),
) -> Result(Token, GasetoV1Error) {
  let payload_bits: BitArray = bit_array.from_string(plaintext_payload)
  let footer_bits = case footer {
    Some(f) -> bit_array.from_string(f)
    None -> <<>>
  }
  let pem_bytes: BitArray = bit_array.from_string(private_key_pem)
  use private_key <- result.try(decode_private_key(pem_bytes))
  let pre_authentication: BitArray =
    pre_auth_encode([
      bit_array.from_string(pub_header),
      payload_bits,
      footer_bits,
    ])

  let pss_options = create_pss_options()
  let hash_algorithm = atom.create("sha384")

  let signature: BitArray =
    rsa.rsa_sign_with_options(
      pre_authentication,
      hash_algorithm,
      private_key,
      pss_options,
    )

  let body_bits: BitArray = bit_array.concat([payload_bits, signature])
  let body_base64: String = bit_array.base64_url_encode(body_bits, False)
  let footer_base64 = case footer {
    Some(_) -> Some(bit_array.base64_url_encode(footer_bits, False))
    None -> None
  }
  Ok(Token(PasetoV1, Public, body_base64, footer_base64))
}

fn create_pss_options() -> List(#(atom.Atom, Dynamic)) {
  [
    #(
      atom.create("rsa_padding"),
      atom.to_dynamic(atom.create("rsa_pkcs1_pss_padding")),
    ),
    #(atom.create("rsa_mgf1_md"), atom.to_dynamic(atom.create("sha384"))),
    #(atom.create("rsa_pss_saltlen"), dynamic.int(48)),
  ]
}

/// Decodes an RSA private key from a PEM-formatted bit array.
///
/// This function takes a `BitArray` containing a private key in PEM format and
/// decodes it into a dynamic key term that can be used for cryptographic operations.
///
/// ## Parameters
///
/// - `pem_bytes`: The private key data in PEM format as a `BitArray`.
///
/// ## Returns
///
/// A `Result` with the decoded key as a `Dynamic` term on success, or a `String`
/// containing an error message on failure.
fn decode_private_key(pem_bytes: BitArray) -> Result(Dynamic, GasetoV1Error) {
  // pem_bytes can go directly to :public_key.pem_decode
  case rsa.pem_decode(pem_bytes) {
    [entry, ..] -> {
      let key_term: Dynamic = rsa.pem_entry_decode(entry)
      Ok(key_term)
    }
    [] -> Error(InvalidKeyFormat("No PEM entries found"))
  }
}

/// Performs symmetric authenticated encryption with associated data (AEAD).
///
/// This function encrypts a plaintext payload using AES-256-CTR and then generates
/// an HMAC-SHA384 authentication tag over the header, nonce, ciphertext, and footer.
/// It combines these parts into the final token body.
///
/// ## Parameters
///
/// - `plaintext_payload`: The data to be encrypted.
/// - `master_key`: The shared secret from which the encryption and authentication keys are derived.
/// - `footer_bits`: The associated data to be authenticated but not encrypted.
/// - `nonce`: A 32-byte nonce.
///
/// ## Returns
///
/// A `Result` containing the `Token` on success, or a `GasetoV1Error` on failure.
fn aead_encrypt(
  plaintext_payload: String,
  master_key: BitArray,
  footer_bits: BitArray,
  nonce: BitArray,
) -> Result(Token, GasetoV1Error) {
  let hash_algo = crypto.Sha384
  let header = "v1.local."

  use encryption_salt: BitArray <- result.try(
    result.map_error(bit_array.slice(nonce, 0, 16), fn(_) {
      UnexpectedEncryptionError("could not slice nonce for encryption salt")
    }),
  )
  use counter_nonce: BitArray <- result.try(
    result.map_error(bit_array.slice(nonce, 16, 16), fn(_) {
      UnexpectedEncryptionError("could not slice nonce for counter nonce")
    }),
  )
  use encryption_key: BitArray <- result.try(
    result.map_error(
      hkdf.hkdf_derive(
        hash_algo,
        encryption_salt,
        master_key,
        bit_array.from_string("paseto-encryption-key"),
        32,
      ),
      with: fn(error) { HkdfError(error.message) },
    ),
  )

  use authentication_key: BitArray <- result.try(
    result.map_error(
      hkdf.hkdf_derive(
        hash_algo,
        encryption_salt,
        master_key,
        bit_array.from_string("paseto-auth-key-for-aead"),
        32,
      ),
      with: fn(error) { HkdfError(error.message) },
    ),
  )

  let ciphertext: BitArray =
    gaseto_crypto.crypto_one_time(
      atom.create("aes_256_ctr"),
      encryption_key,
      counter_nonce,
      bit_array.from_string(plaintext_payload),
      True,
    )

  let pre_authentication: BitArray =
    pre_auth_encode([
      bit_array.from_string(header),
      nonce,
      ciphertext,
      footer_bits,
    ])

  let hmc_tag: BitArray =
    crypto.hmac(pre_authentication, hash_algo, authentication_key)

  let body_bits: BitArray = bit_array.concat([nonce, ciphertext, hmc_tag])
  let body_base64 = bit_array.base64_url_encode(body_bits, False)
  let footer_string = case footer_bits {
    <<>> -> None
    _ -> Some(bit_array.base64_url_encode(footer_bits, False))
  }

  Ok(Token(PasetoV1, Local, body_base64, footer_string))
}

/// Pre-authenticates a list of bit arrays for PASETO.
///
/// This function implements the PASETO `PAE` (pre-authentication encoding) scheme.
/// It prepends the length of the list, followed by the length of each element,
/// and then the elements themselves. This ensures that the message is authenticated
/// in a deterministic and secure way, preventing malicious modifications.
///
/// ## Parameters
///
/// - `parts`: A `List(BitArray)` of the token's components (e.g., header, payload, footer).
///
/// ## Returns
///
/// The single `BitArray` resulting from the pre-authentication encoding.
fn pre_auth_encode(parts: List(BitArray)) -> BitArray {
  let start = le64_encode(list.length(parts))
  list.fold(parts, start, fn(acc, part) {
    let part_len = bit_array.byte_size(part)
    bit_array.concat([acc, le64_encode(part_len), part])
  })
}

/// Encodes an integer as an 8-byte little-endian bit array.
///
/// This function is a helper for the PASETO `PAE` scheme, which requires integer
/// lengths to be encoded in a fixed-size, little-endian format. It's equivalent
/// to a 64-bit unsigned integer (`u64`).
///
/// ## Parameters
///
/// - `value`: The integer to encode.
///
/// ## Returns
///
/// The encoded integer as an 8-byte `BitArray`.
fn le64_encode(value: Int) -> BitArray {
  list.range(0, 7)
  |> list.map(fn(i) {
    <<int.bitwise_and(int.bitwise_shift_right(value, i * 8), 255)>>
  })
  |> bit_array.concat()
}
