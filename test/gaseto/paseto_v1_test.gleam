import gaseto
import gaseto/paseto_v1_test_vectors
import gaseto/token.{Local, Public}
import gleam/io
import gleam/list
import gleam/option

pub fn verify_v1_local_decode_test() {
  paseto_v1_test_vectors.paseto_v1_local_test_vectors
  |> list.each(fn(vector) {
    io.println("Testing decode V1 local: " <> vector.name)
    let assert Ok(token) = gaseto.decrypt(vector.token, vector.key)
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
        vector.key,
        token.PasetoV1,
        Local,
        vector_footer,
      )

    let string_token: String = gaseto.to_string(encrypted_token)
    let assert Ok(token) = gaseto.decrypt(string_token, vector.key)

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
    let assert Ok(token) = gaseto.decrypt(vector.token, vector.public_key)
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
    let assert Ok(encrypted_token) =
      gaseto.encrypt(
        vector.payload,
        vector.secret_key,
        token.PasetoV1,
        Public,
        vector_footer,
      )
    let string_token: String = gaseto.to_string(encrypted_token)
    let assert Ok(token) = gaseto.decrypt(string_token, vector.public_key)

    assert token.payload == vector.payload
    assert token.footer == vector_footer
    assert token.purpose == Public
    assert token.version == token.PasetoV1

    io.println(
      "Testing encode/decode V1 public: " <> vector.name <> " | Passed",
    )
  })
}

pub fn verify_v1_local_with_public_key_pair_decode_test() {
  let vector = paseto_v1_test_vectors.paseto_v1_local_test_vector_with_rsa_keys
  let assert Error(_) = gaseto.decrypt(vector.token, vector.public_key)
}

pub fn verify_v1_local_with_public_key_pair_encode_test() {
  let vector = paseto_v1_test_vectors.paseto_v1_local_test_vector_with_rsa_keys
  let vector_footer = case vector.footer {
    "" -> option.None
    _ -> option.Some(vector.footer)
  }
  let assert Error(_) =
    gaseto.encrypt(
      vector.payload,
      vector.secret_key,
      token.PasetoV1,
      Local,
      vector_footer,
    )
}

pub fn verify_v1_public_with_local_key_decode_test() {
  let vector =
    paseto_v1_test_vectors.paseto_v1_public_test_bector_with_local_key
  let assert Error(_) = gaseto.decrypt(vector.token, vector.key)
}

pub fn verify_v1_public_with_local_key_encode_test() {
  let vector =
    paseto_v1_test_vectors.paseto_v1_public_test_bector_with_local_key
  let vector_footer = case vector.footer {
    "" -> option.None
    _ -> option.Some(vector.footer)
  }
  let assert Error(_) =
    gaseto.encrypt(
      vector.payload,
      vector.key,
      token.PasetoV1,
      Public,
      vector_footer,
    )
}
