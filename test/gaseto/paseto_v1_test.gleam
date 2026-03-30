import gaseto.{KeyPair, LocalKey}
import gaseto/paseto_v1_test_vectors
import gaseto/token.{Local, Public}
import gleam/io
import gleam/list
import gleam/option

pub fn verify_v1_local_decode_test() {
  paseto_v1_test_vectors.paseto_v1_local_test_vectors
  |> list.each(fn(vector) {
    io.println("Testing decode V1 local: " <> vector.name)
    let assert Ok(token) = gaseto.decrypt(vector.token, LocalKey(vector.key))
    let vector_footer = case vector.footer {
      "" -> option.None
      _ -> option.Some(vector.footer)
    }
    assert token.payload == vector.payload
    assert token.footer == vector_footer
    assert token.purpose == Local
    assert token.version == token.PasetoV1

    io.println("Testing decode V1 local: " <> vector.name <> " | Passed")
  })
}

pub fn verify_v1_local_encode_and_decode_test() {
  paseto_v1_test_vectors.paseto_v1_local_test_vectors
  |> list.each(fn(vector) {
    io.println("Testing encode/decode V1 local: " <> vector.name)
    let vector_footer = case vector.footer {
      "" -> option.None
      _ -> option.Some(vector.footer)
    }
    let assert Ok(encrypted_token) =
      gaseto.encrypt(
        vector.payload,
        LocalKey(vector.key),
        token.PasetoV1,
        vector_footer,
      )

    let string_token: String = gaseto.to_string(encrypted_token)
    let assert Ok(token) = gaseto.decrypt(string_token, LocalKey(vector.key))

    assert token.payload == vector.payload
    assert token.footer == vector_footer
    assert token.purpose == Local
    assert token.version == token.PasetoV1

    io.println("Testing encode/decode V1 local: " <> vector.name <> " | Passed")
  })
}

pub fn verify_v1_public_decode_test() {
  paseto_v1_test_vectors.paseto_v1_public_test_vectors
  |> list.each(fn(vector) {
    io.println("Testing decode V1 public: " <> vector.name)
    let assert Ok(token) =
      gaseto.decrypt(
        vector.token,
        KeyPair(secret_key: vector.secret_key, public_key: vector.public_key),
      )
    let vector_footer = case vector.footer {
      "" -> option.None
      _ -> option.Some(vector.footer)
    }
    assert token.payload == vector.payload
    assert token.footer == vector_footer
    assert token.purpose == Public
    assert token.version == token.PasetoV1

    io.println("Testing decode V1 public: " <> vector.name <> " | Passed")
  })
}

pub fn verify_v1_public_encode_and_decode_test() {
  paseto_v1_test_vectors.paseto_v1_public_test_vectors
  |> list.each(fn(vector) {
    io.println("Testing encode/decode V1 public: " <> vector.name)
    let vector_footer = case vector.footer {
      "" -> option.None
      _ -> option.Some(vector.footer)
    }
    let key_pair =
      KeyPair(secret_key: vector.secret_key, public_key: vector.public_key)
    let assert Ok(signed_token) =
      gaseto.encrypt(vector.payload, key_pair, token.PasetoV1, vector_footer)
    let string_token: String = gaseto.to_string(signed_token)
    let assert Ok(token) = gaseto.decrypt(string_token, key_pair)

    assert token.payload == vector.payload
    assert token.footer == vector_footer
    assert token.purpose == Public
    assert token.version == token.PasetoV1

    io.println(
      "Testing encode/decode V1 public: " <> vector.name <> " | Passed",
    )
  })
}

// Passing an RSA PEM key as a LocalKey should fail — it is not a valid
// hex-encoded 32-byte AES key.
pub fn verify_v1_local_wrong_key_material_encode_test() {
  let vector = paseto_v1_test_vectors.paseto_v1_local_test_vector_with_rsa_keys
  let assert Error(_) =
    gaseto.encrypt(vector.payload, LocalKey(vector.public_key), token.PasetoV1, option.None)
}

pub fn verify_v1_local_wrong_key_material_decode_test() {
  let vector = paseto_v1_test_vectors.paseto_v1_local_test_vector_with_rsa_keys
  let assert Error(_) =
    gaseto.decrypt(
      vector.token,
      KeyPair(secret_key: vector.secret_key, public_key: vector.public_key),
    )
}

// Passing a 32-byte symmetric key as a KeyPair should fail — it is not a
// valid RSA private key.
pub fn verify_v1_public_wrong_key_material_encode_test() {
  let vector =
    paseto_v1_test_vectors.paseto_v1_public_test_bector_with_local_key
  let assert Error(_) =
    gaseto.encrypt(
      vector.payload,
      KeyPair(secret_key: vector.key, public_key: vector.key),
      token.PasetoV1,
      option.None,
    )
}

pub fn verify_v1_public_wrong_key_material_decode_test() {
  let vector =
    paseto_v1_test_vectors.paseto_v1_public_test_bector_with_local_key
  let assert Error(_) = gaseto.decrypt(vector.token, LocalKey(vector.key))
}
