import gaseto/crypto as gaseto_crypto
import gaseto/ecdsa
import gaseto/hkdf
import gaseto/pae
import gaseto/token.{
  type PasetoPurpose, type Token, Local, PasetoV3, Public, Token,
}
import gleam/bit_array
import gleam/crypto
import gleam/erlang/atom
import gleam/int
import gleam/option.{type Option, None, Some}
import gleam/result

const local_header: String = "v3.local."

const public_header: String = "v3.public."

// V3.local sizes
const local_master_key_size: Int = 32

const local_nonce_size: Int = 32

const local_tag_size: Int = 48

// Encryption key material is derived as a single HKDF output that is then
// split into the encryption key (32 bytes) and the counter nonce (16 bytes).
const local_encryption_key_material_size: Int = 48

const local_encryption_key_size: Int = 32

const local_counter_nonce_size: Int = 16

// V3.public sizes
const public_secret_key_size: Int = 48

const public_key_size: Int = 49

// P-384 P1363 signature: r (48 bytes) || s (48 bytes)
const public_signature_size: Int = 96

pub type GasetoV3Error {
  InvalidTokenType(message: String)
  UnexpectedEncryptionError(message: String)
  HkdfError(message: String)
  InvalidKeyFormat(message: String)
  EcdsaError(message: String)
}

pub type PasetoV3DecryptError {
  VerificationFailed(message: String)
  InvalidTokenFormat(message: String)
  InvalidKey(message: String)
  SecurityError
  CryptographicError(message: String)
  UnexpectedDecryptionError(message: String)
}

/// Routes encryption to the appropriate V3 scheme.
/// Note: V3.public requires both secret and public keys — use encrypt_public directly.
pub fn encrypt(
  purpose: PasetoPurpose,
  key: String,
  payload: String,
  footer: Option(String),
) -> Result(Token, GasetoV3Error) {
  case purpose {
    Local -> {
      let nonce: BitArray = crypto.strong_random_bytes(32)
      encrypt_local(key, payload, footer, nonce, "")
    }
    Public ->
      Error(InvalidTokenType(
        "V3 public signing requires both secret and public keys; use encrypt_public directly",
      ))
  }
}

/// Routes decryption to the appropriate V3 scheme.
/// For V3.public, key should be the hex-encoded compressed P-384 public key (49 bytes = 98 hex chars).
pub fn decrypt(
  purpose: PasetoPurpose,
  payload: String,
  footer: Option(String),
  key: String,
  implicit_assertion: String,
) -> Result(Token, PasetoV3DecryptError) {
  case purpose {
    Local -> decrypt_local(key, payload, footer, implicit_assertion)
    Public -> decrypt_public(key, payload, footer, implicit_assertion)
  }
}

/// Encrypts a payload using V3.local (AES-256-CTR + HMAC-SHA384).
/// The nonce parameter allows injecting a deterministic nonce for testing.
pub fn encrypt_local(
  shared_secret: String,
  plaintext_payload: String,
  footer: Option(String),
  nonce: BitArray,
  implicit_assertion: String,
) -> Result(Token, GasetoV3Error) {
  use master_key: BitArray <- result.try(
    result.map_error(bit_array.base16_decode(shared_secret), fn(_) {
      InvalidKeyFormat("Could not hex-decode secret key")
    }),
  )
  use _ <- result.try(case bit_array.byte_size(master_key) {
    size if size == local_master_key_size -> Ok(Nil)
    size ->
      Error(InvalidKeyFormat(
        "Key must be 32 bytes, got " <> int.to_string(size),
      ))
  })
  let footer_bytes: BitArray = case footer {
    Some("") -> <<>>
    None -> <<>>
    Some(footer_string) -> bit_array.from_string(footer_string)
  }
  aead_encrypt(
    plaintext_payload,
    master_key,
    footer_bytes,
    nonce,
    footer,
    implicit_assertion,
  )
}

fn aead_encrypt(
  plaintext_payload: String,
  master_key: BitArray,
  footer_bytes: BitArray,
  nonce: BitArray,
  footer: Option(String),
  implicit_assertion: String,
) -> Result(Token, GasetoV3Error) {
  use #(encryption_key, counter_nonce, authentication_key) <- result.try(
    result.map_error(derive_local_keys(master_key, nonce), fn(message) {
      HkdfError(message)
    }),
  )

  // Encrypt with AES-256-CTR
  let ciphertext: BitArray =
    gaseto_crypto.crypto_one_time(
      atom.create("aes_256_ctr"),
      encryption_key,
      counter_nonce,
      bit_array.from_string(plaintext_payload),
      True,
    )

  // Compute HMAC-SHA384 over PAE(header, nonce, ciphertext, footer, implicit_assertion).
  // V3 PAE has 5 parts (includes implicit assertion, unlike V1 which has 4).
  let pre_authentication_data: BitArray =
    pae.pre_auth_encode([
      bit_array.from_string(local_header),
      nonce,
      ciphertext,
      footer_bytes,
      bit_array.from_string(implicit_assertion),
    ])
  let authentication_tag: BitArray =
    crypto.hmac(pre_authentication_data, crypto.Sha384, authentication_key)

  let token_body_bytes: BitArray =
    bit_array.concat([nonce, ciphertext, authentication_tag])
  let token_body_base64: String =
    bit_array.base64_url_encode(token_body_bytes, False)
  let token_footer_base64: Option(String) = case footer_bytes {
    <<>> -> None
    _ -> Some(bit_array.base64_url_encode(footer_bytes, False))
  }
  let _ = footer
  Ok(Token(PasetoV3, Local, token_body_base64, token_footer_base64))
}

/// Decrypts a V3.local token.
/// encoded_body is the base64url-encoded payload section (without the "v3.local." header).
/// encoded_footer is the base64url-encoded footer (without the dot separator).
pub fn decrypt_local(
  raw_key: String,
  encoded_body: String,
  encoded_footer: Option(String),
  implicit_assertion: String,
) -> Result(Token, PasetoV3DecryptError) {
  use master_key: BitArray <- result.try(
    result.map_error(bit_array.base16_decode(raw_key), fn(_) {
      InvalidKey("Could not hex-decode secret key")
    }),
  )
  use _ <- result.try(case bit_array.byte_size(master_key) {
    size if size == local_master_key_size -> Ok(Nil)
    size ->
      Error(InvalidKey("Key must be 32 bytes, got " <> int.to_string(size)))
  })
  use decoded_body: BitArray <- result.try(
    result.map_error(bit_array.base64_url_decode(encoded_body), fn(_) {
      InvalidTokenFormat("Token body is not valid base64url")
    }),
  )
  // Strict base64url validation: re-encode the decoded bytes and verify they
  // match the original string. This catches tokens where the trailing padding
  // bits of the last base64url character are non-zero — a sign of tampering or
  // a non-canonical encoding that a lenient decoder would silently accept.
  use _ <- result.try(
    case bit_array.base64_url_encode(decoded_body, False) == encoded_body {
      True -> Ok(Nil)
      False ->
        Error(InvalidTokenFormat("Token body has invalid base64url encoding"))
    },
  )
  use footer_bytes: BitArray <- result.try(
    result.map_error(pae.decode_footer(encoded_footer), fn(message) {
      InvalidTokenFormat(message)
    }),
  )
  use #(nonce, ciphertext, authentication_tag) <- result.try(
    parse_local_token_body(decoded_body),
  )

  // Derive the same encryption key, counter nonce, and authentication key that
  // were used during encryption, using the nonce embedded in the token.
  use #(encryption_key, counter_nonce, authentication_key) <- result.try(
    result.map_error(derive_local_keys(master_key, nonce), fn(message) {
      UnexpectedDecryptionError(message)
    }),
  )

  // Verify the authentication tag before decrypting. This authenticate-then-
  // decrypt ordering prevents padding oracle and chosen-ciphertext attacks.
  let pre_authentication_data: BitArray =
    pae.pre_auth_encode([
      bit_array.from_string(local_header),
      nonce,
      ciphertext,
      footer_bytes,
      bit_array.from_string(implicit_assertion),
    ])
  let computed_tag: BitArray =
    crypto.hmac(pre_authentication_data, crypto.Sha384, authentication_key)
  use _ <- result.try(case authentication_tag == computed_tag {
    True -> Ok(Nil)
    False -> Error(SecurityError)
  })

  // Decrypt with AES-256-CTR (CTR mode encryption and decryption are identical)
  let plaintext: BitArray =
    gaseto_crypto.crypto_one_time(
      atom.create("aes_256_ctr"),
      encryption_key,
      counter_nonce,
      ciphertext,
      False,
    )

  use payload: String <- result.try(
    result.map_error(bit_array.to_string(plaintext), fn(_) {
      InvalidTokenFormat("Decrypted payload is not valid UTF-8")
    }),
  )
  Ok(Token(PasetoV3, Local, payload, pae.footer_bytes_to_option(footer_bytes)))
}

/// Signs a payload using V3.public (ECDSA P-384 + SHA-384).
/// secret_key_hex: hex-encoded 48-byte P-384 private key scalar
/// public_key_hex: hex-encoded 49-byte compressed P-384 public key (02/03 prefix + 48-byte X)
pub fn encrypt_public(
  secret_key_hex: String,
  public_key_hex: String,
  payload: String,
  footer: Option(String),
  implicit_assertion: String,
) -> Result(Token, GasetoV3Error) {
  use secret_key: BitArray <- result.try(
    result.map_error(bit_array.base16_decode(secret_key_hex), fn(_) {
      InvalidKeyFormat("Could not hex-decode secret key")
    }),
  )
  use _ <- result.try(case bit_array.byte_size(secret_key) {
    size if size == public_secret_key_size -> Ok(Nil)
    size ->
      Error(InvalidKeyFormat(
        "Secret key must be 48 bytes for P-384, got " <> int.to_string(size),
      ))
  })
  use public_key: BitArray <- result.try(
    result.map_error(bit_array.base16_decode(public_key_hex), fn(_) {
      InvalidKeyFormat("Could not hex-decode public key")
    }),
  )
  use _ <- result.try(case bit_array.byte_size(public_key) {
    size if size == public_key_size -> Ok(Nil)
    size ->
      Error(InvalidKeyFormat(
        "Public key must be 49 bytes (compressed P-384), got "
        <> int.to_string(size),
      ))
  })

  let payload_bytes: BitArray = bit_array.from_string(payload)
  let footer_bytes: BitArray = case footer {
    Some(footer_string) -> bit_array.from_string(footer_string)
    None -> <<>>
  }

  // The PAE for V3.public binds the compressed public key as the first element,
  // ensuring the signature is tied to a specific key and cannot be replayed with
  // a different key that happens to produce the same payload bytes.
  let signing_input: BitArray =
    pae.pre_auth_encode([
      public_key,
      bit_array.from_string(public_header),
      payload_bytes,
      footer_bytes,
      bit_array.from_string(implicit_assertion),
    ])

  use signature: BitArray <- result.try(
    result.map_error(ecdsa.sign_p384(signing_input, secret_key), fn(error) {
      EcdsaError(error)
    }),
  )

  let token_body_bytes: BitArray = bit_array.append(payload_bytes, signature)
  let token_body_base64: String =
    bit_array.base64_url_encode(token_body_bytes, False)
  let token_footer_base64: Option(String) = case footer_bytes {
    <<>> -> None
    _ -> Some(bit_array.base64_url_encode(footer_bytes, False))
  }
  Ok(Token(PasetoV3, Public, token_body_base64, token_footer_base64))
}

/// Verifies a V3.public token and extracts the payload.
/// public_key_hex: hex-encoded 49-byte compressed P-384 public key
/// encoded_body: base64url-encoded body (without "v3.public." header)
/// encoded_footer: base64url-encoded footer (without dot separator), if present
pub fn decrypt_public(
  public_key_hex: String,
  encoded_body: String,
  encoded_footer: Option(String),
  implicit_assertion: String,
) -> Result(Token, PasetoV3DecryptError) {
  use public_key: BitArray <- result.try(
    result.map_error(bit_array.base16_decode(public_key_hex), fn(_) {
      InvalidKey("Could not hex-decode public key")
    }),
  )
  use _ <- result.try(case bit_array.byte_size(public_key) {
    size if size == public_key_size -> Ok(Nil)
    size ->
      Error(InvalidKey(
        "Public key must be 49 bytes (compressed P-384), got "
        <> int.to_string(size),
      ))
  })
  use decoded_body: BitArray <- result.try(
    result.map_error(bit_array.base64_url_decode(encoded_body), fn(_) {
      InvalidTokenFormat("Token body is not valid base64url")
    }),
  )
  use footer_bytes: BitArray <- result.try(
    result.map_error(pae.decode_footer(encoded_footer), fn(message) {
      InvalidTokenFormat(message)
    }),
  )

  // V3.public token body structure: payload || signature (96 bytes)
  let decoded_body_size: Int = bit_array.byte_size(decoded_body)
  use _ <- result.try(case decoded_body_size < public_signature_size {
    True ->
      Error(InvalidTokenFormat(
        "Token body too short to contain signature: "
        <> int.to_string(decoded_body_size),
      ))
    False -> Ok(Nil)
  })
  use payload_bytes: BitArray <- result.try(
    result.map_error(
      bit_array.slice(
        decoded_body,
        0,
        decoded_body_size - public_signature_size,
      ),
      fn(_) { InvalidTokenFormat("Could not extract payload") },
    ),
  )
  use signature: BitArray <- result.try(
    result.map_error(
      bit_array.slice(
        decoded_body,
        decoded_body_size - public_signature_size,
        public_signature_size,
      ),
      fn(_) { InvalidTokenFormat("Could not extract signature") },
    ),
  )

  // Reconstruct the signing input and verify
  let signing_input: BitArray =
    pae.pre_auth_encode([
      public_key,
      bit_array.from_string(public_header),
      payload_bytes,
      footer_bytes,
      bit_array.from_string(implicit_assertion),
    ])

  case ecdsa.verify_p384(signing_input, signature, public_key) {
    False ->
      Error(VerificationFailed("ECDSA P-384 signature verification failed"))
    True -> {
      use payload: String <- result.try(
        result.map_error(bit_array.to_string(payload_bytes), fn(_) {
          InvalidTokenFormat("Payload is not valid UTF-8")
        }),
      )
      Ok(Token(
        PasetoV3,
        Public,
        payload,
        pae.footer_bytes_to_option(footer_bytes),
      ))
    }
  }
}

/// Derives the three local symmetric keys from the master key and nonce using HKDF-SHA384.
/// Returns #(encryption_key 32 bytes, counter_nonce 16 bytes, authentication_key 48 bytes).
/// Returns a plain String error so callers can map it into their own error type.
fn derive_local_keys(
  master_key: BitArray,
  nonce: BitArray,
) -> Result(#(BitArray, BitArray, BitArray), String) {
  let hash_algorithm: crypto.HashAlgorithm = crypto.Sha384

  // Derive the encryption key (32 bytes) and counter nonce (16 bytes) from a
  // single 48-byte HKDF output. The info string binds the derived key to this
  // specific nonce, preventing key reuse across encryptions.
  let encryption_key_info: BitArray =
    bit_array.concat([
      bit_array.from_string("paseto-encryption-key"),
      nonce,
    ])
  use encryption_key_material: BitArray <- result.try(
    result.map_error(
      hkdf.hkdf_derive(
        hash_algorithm,
        <<>>,
        master_key,
        encryption_key_info,
        local_encryption_key_material_size,
      ),
      fn(error) { error.message },
    ),
  )
  use encryption_key: BitArray <- result.try(
    result.map_error(
      bit_array.slice(encryption_key_material, 0, local_encryption_key_size),
      fn(_) { "Could not slice encryption key from HKDF output" },
    ),
  )
  use counter_nonce: BitArray <- result.try(
    result.map_error(
      bit_array.slice(
        encryption_key_material,
        local_encryption_key_size,
        local_counter_nonce_size,
      ),
      fn(_) { "Could not slice counter nonce from HKDF output" },
    ),
  )

  // Derive a separate authentication key so that the HMAC key is never the
  // same as the encryption key, even for the same master key and nonce.
  let authentication_key_info: BitArray =
    bit_array.concat([
      bit_array.from_string("paseto-auth-key-for-aead"),
      nonce,
    ])
  use authentication_key: BitArray <- result.try(
    result.map_error(
      hkdf.hkdf_derive(
        hash_algorithm,
        <<>>,
        master_key,
        authentication_key_info,
        local_tag_size,
      ),
      fn(error) { error.message },
    ),
  )

  Ok(#(encryption_key, counter_nonce, authentication_key))
}

/// Parses a decoded V3.local token body into its three components.
/// Token body structure: nonce (32 bytes) || ciphertext || authentication tag (48 bytes).
fn parse_local_token_body(
  decoded_body: BitArray,
) -> Result(#(BitArray, BitArray, BitArray), PasetoV3DecryptError) {
  let min_body_size: Int = local_nonce_size + local_tag_size

  use body_size: Int <- result.try(case bit_array.byte_size(decoded_body) {
    size if size < min_body_size ->
      Error(InvalidTokenFormat(
        "Token body too short: "
        <> int.to_string(size)
        <> ", minimum "
        <> int.to_string(min_body_size),
      ))
    size -> Ok(size)
  })
  use nonce: BitArray <- result.try(
    result.map_error(bit_array.slice(decoded_body, 0, local_nonce_size), fn(_) {
      InvalidTokenFormat("Could not extract nonce")
    }),
  )
  let ciphertext_size: Int = body_size - local_nonce_size - local_tag_size
  use ciphertext: BitArray <- result.try(
    result.map_error(
      bit_array.slice(decoded_body, local_nonce_size, ciphertext_size),
      fn(_) { InvalidTokenFormat("Could not extract ciphertext") },
    ),
  )
  use authentication_tag: BitArray <- result.try(
    result.map_error(
      bit_array.slice(decoded_body, body_size - local_tag_size, local_tag_size),
      fn(_) { InvalidTokenFormat("Could not extract authentication tag") },
    ),
  )
  Ok(#(nonce, ciphertext, authentication_tag))
}
