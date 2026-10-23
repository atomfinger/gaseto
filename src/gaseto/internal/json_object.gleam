import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}

/// Decodes a JSON object, refusing any object in it that repeats a key, as
/// the spec requires
/// ([Payload Processing](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md)).
/// The top level is always an object, so it comes back as a dictionary.
@external(erlang, "gaseto_json_ffi", "decode_object_with_unique_keys")
pub fn decode(json: String) -> Result(Dict(String, Dynamic), Nil)
