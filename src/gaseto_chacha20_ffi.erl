-module(gaseto_chacha20_ffi).
-export([chacha20/3]).

%% OTP's ChaCha20 is OpenSSL's, which takes a 16-byte IV that starts with a
%% little-endian block counter. Four zero bytes and then a 12-byte nonce give
%% RFC 8439's ChaCha20 with the counter at 0.
chacha20(Key, Iv, Data) ->
    crypto:crypto_one_time(chacha20, Key, Iv, Data, true).
