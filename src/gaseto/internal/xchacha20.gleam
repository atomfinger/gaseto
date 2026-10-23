//// XChaCha20, built from OTP's ChaCha20, because OTP has neither XChaCha20
//// nor the HChaCha20 function it needs
//// ([XChaCha draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03)).

import gleam/int

/// The first row of every ChaCha20 state.
const chacha20_constants: BitArray = <<"expand 32-byte k":utf8>>

/// Encrypts or decrypts, which is the same operation, starting at block 0 as
/// PASETO version 4 does.
pub fn encrypt(key: BitArray, nonce: BitArray, data: BitArray) -> BitArray {
  // Version 4 always derives a 24-byte nonce
  let assert <<hchacha20_input:bytes-size(16), chacha20_nonce:bytes-size(8)>> =
    nonce
  let subkey = hchacha20(key, hchacha20_input)
  chacha20(subkey, <<0:32, 0:32, chacha20_nonce:bits>>, data)
}

/// HChaCha20 is the ChaCha20 block function without its final addition of
/// the starting state
/// ([HChaCha20](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03#section-2.2)).
/// One block of ChaCha20 output for the same state, minus that starting state,
/// is therefore HChaCha20. The rounds still come from OTP; only the
/// subtraction is done here.
fn hchacha20(key: BitArray, input: BitArray) -> BitArray {
  // ChaCha20 output is as long as its input: one 64-byte block here
  let assert <<
    first_row:bytes-size(16),
    _:bytes-size(32),
    last_row:bytes-size(16),
  >> = chacha20(key, input, <<0:512>>)
  <<
    subtract_words(first_row, chacha20_constants):bits,
    subtract_words(last_row, input):bits,
  >>
}

/// Subtracts 32-bit little-endian words, wrapping around as ChaCha20's own
/// addition does.
fn subtract_words(left: BitArray, right: BitArray) -> BitArray {
  case left, right {
    <<left_word:32-little, left_rest:bytes>>,
      <<right_word:32-little, right_rest:bytes>>
    -> <<
      int.bitwise_and(left_word - right_word, 0xFFFFFFFF):32-little,
      subtract_words(left_rest, right_rest):bits,
    >>
    _, _ -> <<>>
  }
}

@external(erlang, "gaseto_chacha20_ffi", "chacha20")
fn chacha20(key: BitArray, iv: BitArray, data: BitArray) -> BitArray
