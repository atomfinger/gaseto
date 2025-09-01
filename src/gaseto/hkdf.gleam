//// HKDF (HMAC-based Key Derivation Function) implementation.
////
//// Provides functions to derive cryptographic keys from input key material
//// using the HKDF construction defined in RFC 5869.
////
//// The module provides three main functions:
//// 1. `extract` – Generates a pseudorandom key (PRK) from input key material and an optional salt.
//// 2. `expand` – Uses the PRK to derive output key material of the desired length,
////    optionally including application-specific context information.
//// 3. `hkdf_derive` – Convenience function that performs both `extract` and `expand` in a single call.
//// let prk = hkdf.extract(crypto.Sha256, salt, ikm)
//// let okm = hkdf.expand(crypto.Sha256, prk, context_info, 32)
//// or in one step:
//// let okm = hkdf.hkdf_derive(crypto.Sha256, salt, ikm, context_info, 32)

import gleam/bit_array
import gleam/crypto
import gleam/result

pub type HkdfError {
  BadLength(message: String)
}

/// Computes the HKDF extract step.
/// 
/// # Parameters
/// - `hash_algorithm`: The hash function to use (e.g., Sha256, Sha512).
/// - `salt_value`: A cryptographic salt value (BitArray).
/// - `input_key_material`: The input key material (BitArray) to extract the pseudorandom key from.
/// 
/// # Returns
/// A pseudorandom key as a BitArray.
pub fn extract(
  hash_algorithm: crypto.HashAlgorithm,
  salt_value: BitArray,
  input_key_material: BitArray,
) -> BitArray {
  crypto.hmac(input_key_material, hash_algorithm, salt_value)
}

/// Convenience function that performs the full HKDF key derivation (extract + expand) in a single call.
/// 
/// # Parameters
/// - `hash_algorithm`: The hash function to use (e.g., Sha256, Sha512).
/// - `salt_value`: Optional salt value (BitArray) used in the extract step.
/// - `input_key_material`: The input key material (BitArray) to derive the key from.
/// - `context_information`: Optional context/application-specific information (BitArray) used in the expand step.
/// - `desired_output_length`: Desired length of the derived key (Int).
///
/// # Returns
/// - `Ok(BitArray)`: The derived key of the requested length.
/// - `Error(HkdfError)`: If any step fails (e.g., invalid length).
pub fn hkdf_derive(
  hash_algorithm: crypto.HashAlgorithm,
  salt_value: BitArray,
  input_key_material: BitArray,
  context_information: BitArray,
  desired_output_length: Int,
) -> Result(BitArray, HkdfError) {
  let pseudorandom_key = extract(hash_algorithm, salt_value, input_key_material)
  let output_key_material =
    expand(
      hash_algorithm,
      pseudorandom_key,
      context_information,
      desired_output_length,
    )
  output_key_material
}

/// Computes the HKDF expand step to derive output key material of the desired length.
///
/// # Parameters
/// - `hash_algorithm`: The hash function to use (e.g., Sha256, Sha512).
/// - `pseudorandom_key`: The PRK obtained from the extract step (BitArray).
/// - `context_info`: Optional context and application-specific information (BitArray).
/// - `output_length`: The desired length of the derived key (Int).
///
/// # Returns
/// - `Ok(BitArray)`: The derived key of the requested length.
/// - `Error(HkdfError)`
pub fn expand(
  hash_algorithm: crypto.HashAlgorithm,
  pseudorandom_key: BitArray,
  context_info: BitArray,
  output_length: Int,
) -> Result(BitArray, HkdfError) {
  let hash_length = case hash_algorithm {
    crypto.Md5 -> 16
    crypto.Sha1 -> 20
    crypto.Sha224 -> 28
    crypto.Sha256 -> 32
    crypto.Sha384 -> 48
    crypto.Sha512 -> 64
  }

  case output_length {
    length if length <= 0 ->
      Error(BadLength("Invalid length: expand length is 0 or less"))
    length if length > 255 * hash_length ->
      Error(BadLength("Invalid length: expand length is too long"))
    _ -> {
      let iterations: Int = { output_length + hash_length - 1 } / hash_length
      let okm: BitArray =
        do_expand(
          hash_algorithm,
          pseudorandom_key,
          context_info,
          iterations,
          <<>>,
          // initial T value
          <<>>,
          // initial OKM value
          1,
          // block counter
        )
      bit_array.slice(okm, 0, output_length)
      |> result.unwrap(<<>>)
      |> Ok
    }
  }
}

/// Recursive helper function for HKDF expand.
/// 
/// # Parameters
/// - `hash_algorithm`: Hash function to use.
/// - `pseudorandom_key`: PRK from the extract step.
/// - `context_info`: Optional context/application info.
/// - `remaining_blocks`: Number of blocks left to generate.
/// - `previous_block`: The previous block output (T(n-1)).
/// - `accumulated_output`: Concatenated output key material so far.
/// - `block_index`: Current block index (1-based).
///
/// # Returns
/// Concatenated output key material as BitArray.
fn do_expand(
  hash_algorithm: crypto.HashAlgorithm,
  pseudorandom_key: BitArray,
  context_info: BitArray,
  remaining_blocks: Int,
  previous_block: BitArray,
  accumulated_output: BitArray,
  block_index: Int,
) -> BitArray {
  case remaining_blocks {
    0 -> accumulated_output
    _ -> {
      let input_block =
        bit_array.append(bit_array.append(previous_block, context_info), <<
          block_index:8,
        >>)
      let current_block =
        crypto.hmac(input_block, hash_algorithm, pseudorandom_key)
      do_expand(
        hash_algorithm,
        pseudorandom_key,
        context_info,
        remaining_blocks - 1,
        current_block,
        bit_array.append(accumulated_output, current_block),
        block_index + 1,
      )
    }
  }
}
