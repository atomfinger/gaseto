-module(gaseto_json_ffi).
-export([decode_object_with_unique_keys/1]).

%% The spec requires unique key names
%% (https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md),
%% but OTP's `json:decode`, which gleam_json uses, keeps only the last value of
%% a repeated key. This decodes once, refuses repeated keys, and returns the
%% value for Gaseto's decoders.
decode_object_with_unique_keys(Json) ->
    Decoders = #{
        object_start => fun(_ParentAccumulator) -> #{} end,
        object_push => fun(Key, Value, Object) ->
            case maps:is_key(Key, Object) of
                true -> throw(repeated_key);
                false -> Object#{Key => Value}
            end
        end,
        object_finish => fun(Object, ParentAccumulator) ->
            {Object, ParentAccumulator}
        end
    },
    try json:decode(Json, ok, Decoders) of
        {Object, ok, <<>>} when is_map(Object) -> {ok, Object};
        _ -> {error, nil}
    catch
        _:_ -> {error, nil}
    end.
