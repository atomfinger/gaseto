-module(gaseto_pem_ffi).
-export([
    ed25519_secret_key/1, ed25519_public_key/1,
    p384_secret_key/1, p384_public_key/1
]).

-include_lib("public_key/include/public_key.hrl").

-define(ED25519, {1, 3, 101, 112}).
-define(P384, {1, 3, 132, 0, 34}).

ed25519_secret_key(Pem) ->
    case decode(Pem) of
        {ok, #'ECPrivateKey'{privateKey = Seed, parameters = {namedCurve, ?ED25519}}} ->
            {ok, Seed};
        _ -> {error, nil}
    end.

ed25519_public_key(Pem) ->
    case decode(Pem) of
        {ok, {#'ECPoint'{point = Point}, {namedCurve, ?ED25519}}} -> {ok, Point};
        _ -> {error, nil}
    end.

%% The secret scalar, from either a SEC1 or a PKCS #8 file.
p384_secret_key(Pem) ->
    case decode(Pem) of
        {ok, #'ECPrivateKey'{privateKey = Scalar, parameters = {namedCurve, ?P384}}} ->
            {ok, Scalar};
        _ -> {error, nil}
    end.

%% The point as stored, compressed or not.
p384_public_key(Pem) ->
    case decode(Pem) of
        {ok, {#'ECPoint'{point = Point}, {namedCurve, ?P384}}} -> {ok, Point};
        _ -> {error, nil}
    end.

decode(Pem) ->
    try
        Entries = public_key:pem_decode(Pem),
        case [Entry || Entry <- Entries, element(1, Entry) =/= 'EcpkParameters'] of
            [Entry] -> {ok, public_key:pem_entry_decode(Entry)};
            _ -> {error, nil}
        end
    catch
        _:_ -> {error, nil}
    end.
