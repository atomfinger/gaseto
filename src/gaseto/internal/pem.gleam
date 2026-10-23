//// Raw key bytes from PEM files. The checks on the bytes themselves are left
//// to the version modules, so PEM and hex keys are checked the same way.

import gaseto/error
import gleam/result

/// The 32-byte seed of an Ed25519 key, in PKCS #8.
pub fn ed25519_secret_key(
  pem: String,
) -> Result(BitArray, error.KeyLoadingError) {
  ffi_ed25519_secret_key(pem) |> result.replace_error(error.InvalidPem)
}

pub fn ed25519_public_key(
  pem: String,
) -> Result(BitArray, error.KeyLoadingError) {
  ffi_ed25519_public_key(pem) |> result.replace_error(error.InvalidPem)
}

/// The secret scalar of a P-384 key, in SEC1 or PKCS #8.
pub fn p384_secret_key(pem: String) -> Result(BitArray, error.KeyLoadingError) {
  ffi_p384_secret_key(pem) |> result.replace_error(error.InvalidPem)
}

/// The point of a P-384 public key, compressed or not.
pub fn p384_public_key(pem: String) -> Result(BitArray, error.KeyLoadingError) {
  ffi_p384_public_key(pem) |> result.replace_error(error.InvalidPem)
}

@external(erlang, "gaseto_pem_ffi", "ed25519_secret_key")
fn ffi_ed25519_secret_key(pem: String) -> Result(BitArray, Nil)

@external(erlang, "gaseto_pem_ffi", "ed25519_public_key")
fn ffi_ed25519_public_key(pem: String) -> Result(BitArray, Nil)

@external(erlang, "gaseto_pem_ffi", "p384_secret_key")
fn ffi_p384_secret_key(pem: String) -> Result(BitArray, Nil)

@external(erlang, "gaseto_pem_ffi", "p384_public_key")
fn ffi_p384_public_key(pem: String) -> Result(BitArray, Nil)
