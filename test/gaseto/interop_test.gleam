//// Tokens made by another PASETO library, go-paseto v1.6.0
//// (https://github.com/aidantwoods/go-paseto), with keys it generated. Each
//// has the same claims, the footer `{"kid":"go-key-1"}` and the implicit
//// assertion "tenant-7".

import gaseto.{PasetoV3, PasetoV4}
import gaseto/error
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{Some}

const version_3_local_key: String =
  "8b4dea805b3f6138f5ae0c1b377de381aa67effc38eb37699936e998304f4210"

const version_3_local_token: String =
  "v3.local.ZK4SEsZ7SBelm5sOhP2zOD7lOkgC6U4upY0-AndfIZfCiLGKSSEfL9vahrx_sdbhRQHvkagPCy9IYUTYMEKk1yRf8Ej93A8L_7fpJ8ma4IF-y3N3r1rSY84en1lW5OAONUp1oKNUipG1bjGF1mTgH4Qnuplq_UnkxOiaSf9wUxZ5KMHLHjK8fe8nB6GluVTDs1ZqwQi5q-iWGEqklvh5d3P2pQ7aTikqt_Slta4UdS2CQfGpGh_vnyv0lrgmsR4qlgUlop_rcnghQ6YIQy223Lhdmta3LaiBCPCteayd3gzFIHfNmd8-tCTBYj07Hcw-8NulSgyqX8fSPA.eyJraWQiOiJnby1rZXktMSJ9"

const version_3_public_key: String =
  "028215af1f8cddc936463449a202af322b2c4d92689a472c664b539e63affb0d42bbb92a9ac40efadf831a8dbf9659f6f9"

const version_3_public_token: String =
  "v3.public.eyJhdWQiOiJnYXNldG8iLCJleHAiOiIyMDk5LTAxLTAxVDAwOjAwOjAwWiIsImlhdCI6IjIwMjYtMDEtMDFUMDA6MDA6MDBaIiwiaXNzIjoiZ28tcGFzZXRvIiwianRpIjoiaW50ZXJvcC0xIiwibmJmIjoiMjAyNi0wMS0wMVQwMDowMDowMFoiLCJyb2xlIjoiYWRtaW4iLCJzdWIiOiJ1c2VyLTQyIn3-7lWMr5hEd0U8pJwVuIt-EfDM7-_K62S1DZXYm7HTK44oJB74ft1D0vhzMHo-V8cs8_xxeh9XjjXkE1u_fpeZ5mEzXyB4-NN2g1SYmqUS9CT7cvshS6VdSUsA02kL_go.eyJraWQiOiJnby1rZXktMSJ9"

const version_3_secret_key: String =
  "a2a7713d5fa9f4de4684b33bd9237f3881b85c3bd9f4eeeb4387537086bb66121226413304bb03b1c7dad31402c8eb15"

const version_4_local_key: String =
  "0006ee75ed0fc39cc050ea1ccada7d3a23ef3be93d2dab4efb747d407d090a59"

const version_4_local_token: String =
  "v4.local.EfChklKBnzmd_ACpdby9gbqZ-s9lNj2ygQ8vhKdNpxpkc0r-OWkVcuznNxjraYs6qSQEZbfm_9WApqkHyn5-ukKYJ_CXlBMJF8LjNeLaHtCjjAzkVkgt_6yPuWTAWdDZdHPDaX6E_lP0OtMXn16JVjjIVIlPQg7DavOcLUgYd_l2sT5vt25i5xGHfAgy80wMh76lYODZ66-Tq7hoCdNVaZmy595RSLSrsIX-2OybSMwTFB8u-77wGrwwpIoY7LfRJ65p81CVZdyNeONWFhJ32NYjmMWGaTVSKP6jV_IeMYe6tu6El45-oUWX.eyJraWQiOiJnby1rZXktMSJ9"

const version_4_public_key: String =
  "59db93a7b56b6196bf0c572684a0cb3a940386ae844783a73a78fa0bd5e78ea1"

const version_4_public_token: String =
  "v4.public.eyJhdWQiOiJnYXNldG8iLCJleHAiOiIyMDk5LTAxLTAxVDAwOjAwOjAwWiIsImlhdCI6IjIwMjYtMDEtMDFUMDA6MDA6MDBaIiwiaXNzIjoiZ28tcGFzZXRvIiwianRpIjoiaW50ZXJvcC0xIiwibmJmIjoiMjAyNi0wMS0wMVQwMDowMDowMFoiLCJyb2xlIjoiYWRtaW4iLCJzdWIiOiJ1c2VyLTQyIn0KFX9esRgk7AZDjCcGTQD5vCJlMCzaR9Txt81YipLLHP-BlJLYW_REMm4HTcTVsp61NakT3x-cGjvEzjFH0QUC.eyJraWQiOiJnby1rZXktMSJ9"

const version_4_secret_key: String =
  "469d550869918b4bcfa9692267a0e5cdbcaca6aa91664db221e90773a74fd49759db93a7b56b6196bf0c572684a0cb3a940386ae844783a73a78fa0bd5e78ea1"

pub fn tokens_from_go_paseto_are_read_test() -> Nil {
  use token <- list.each(read_all(implicit_assertion: "tenant-7"))
  let assert Ok(token) = token
  assert gaseto.issuer(token) == Some("go-paseto")
  assert gaseto.subject(token) == Some("user-42")
  assert gaseto.audience(token) == Some("gaseto")
  assert gaseto.token_identifier(token) == Some("interop-1")
  assert gaseto.footer(token) == <<"{\"kid\":\"go-key-1\"}":utf8>>
  assert json.parse(gaseto.payload(token), decode.at(["role"], decode.string))
    == Ok("admin")
}

pub fn tokens_from_go_paseto_need_the_same_implicit_assertion_test() -> Nil {
  use token <- list.each(read_all(implicit_assertion: "tenant-8"))
  assert token == Error(error.TokenNotAuthentic)
}

fn read_all(
  implicit_assertion implicit_assertion: String,
) -> List(Result(gaseto.Token, error.TokenValidationError)) {
  let rules =
    gaseto.new_rules()
    |> gaseto.issued_by("go-paseto")
    |> gaseto.for_audience("gaseto")
    |> gaseto.expect_implicit_assertion(<<implicit_assertion:utf8>>)
  let assert Ok(version_3_local) =
    gaseto.local_key_from_hex(PasetoV3, version_3_local_key)
  let assert Ok(version_4_local) =
    gaseto.local_key_from_hex(PasetoV4, version_4_local_key)
  let assert Ok(version_3_public) =
    gaseto.public_key_from_hex(PasetoV3, version_3_public_key)
  let assert Ok(version_4_public) =
    gaseto.public_key_from_hex(PasetoV4, version_4_public_key)
  [
    gaseto.decrypt(version_3_local_token, version_3_local, rules),
    gaseto.decrypt(version_4_local_token, version_4_local, rules),
    gaseto.verify(version_3_public_token, version_3_public, rules),
    gaseto.verify(version_4_public_token, version_4_public, rules),
  ]
}

pub fn go_paseto_secret_keys_load_test() -> Nil {
  let assert Ok(version_3_secret) =
    gaseto.secret_key_from_hex(PasetoV3, version_3_secret_key)
  let assert Ok(version_4_secret) =
    gaseto.secret_key_from_hex(PasetoV4, version_4_secret_key)
  assert gaseto.public_key_to_hex(gaseto.secret_key_to_public_key(
      version_3_secret,
    ))
    == version_3_public_key
  assert gaseto.public_key_to_hex(gaseto.secret_key_to_public_key(
      version_4_secret,
    ))
    == version_4_public_key
}
