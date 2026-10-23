-module(gaseto_chacha20_ffi).
-export([chacha20/3]).

%% OTP's ChaCha20 takes a 16-byte IV: the 4-byte block counter, then the
%% 12-byte nonce.
chacha20(Key, Iv, Data) ->
    crypto:crypto_one_time(chacha20, Key, Iv, Data, true).
