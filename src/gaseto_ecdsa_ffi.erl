-module(gaseto_ecdsa_ffi).
-export([sign_p384/2, verify_p384/3]).

%% Signs data using ECDSA with P-384 and SHA-384.
%% Returns the DER-encoded signature.
sign_p384(Data, PrivateKey) ->
    crypto:sign(ecdsa, sha384, Data, [PrivateKey, secp384r1]).

%% Verifies a DER-encoded ECDSA P-384 + SHA-384 signature.
verify_p384(Data, Signature, PublicKey) ->
    crypto:verify(ecdsa, sha384, Data, Signature, [PublicKey, secp384r1]).
