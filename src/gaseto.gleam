//// PASETO tokens for Gleam.
////
//// New to PASETO? See [paseto.io](https://paseto.io/), the article
//// [No Way, JOSE!](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid)
//// on why it exists, and the
//// [specification](https://github.com/paseto-standard/paseto-spec).
////
//// A `local` token is encrypted with a shared key. A `public` token is signed
//// with a secret key and checked with the matching public key. Anyone can
//// read the claims in a public token.
////
//// Versions 3 and 4 are supported. Use version 4 unless you are limited to
//// NIST-approved algorithms, then use version 3, which uses them throughout. Versions 1 and 2 are deprecated by the
//// spec and not supported.
////
//// ```gleam
//// let assert Ok(key) = gaseto.local_key_from_hex(gaseto.PasetoV4, key_hex)
//// let claims = gaseto.new_claims() |> gaseto.with_subject("user-42")
//// let assert Ok(token) = gaseto.encrypt(claims, key)
//// let assert Ok(opened) = gaseto.decrypt(token, key, gaseto.new_rules())
//// gaseto.subject(opened)
//// // -> Some("user-42")
//// ```
////
//// To send tokens in HTTP responses and check them on requests, use
//// [gaseto_http](https://github.com/atomfinger/gaseto_http). To choose, load
//// and make keys, see [Keys](keys.html).

import gaseto/error
import gaseto/internal/claims as internal_claims
import gaseto/internal/footer as internal_footer
import gaseto/internal/paseto_v3
import gaseto/internal/paseto_v4
import gaseto/internal/protocol.{type Contents}
import gleam/bool
import gleam/crypto
import gleam/dict
import gleam/dynamic/decode
import gleam/json.{type Json}
import gleam/option.{type Option, Some}
import gleam/result
import gleam/string
import gleam/time/duration.{type Duration}
import gleam/time/timestamp.{type Timestamp}

/// Which PASETO version a key and its tokens use. Each version is a fixed set
/// of algorithms
/// ([Protocol Versions](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/README.md)).
pub type PasetoVersion {
  /// AES-256-CTR with HMAC-SHA-384, and ECDSA with P-384. Use it when you
  /// are limited to NIST-approved algorithms.
  PasetoV3
  /// XChaCha20 with BLAKE2b, and Ed25519. Use this one unless you need
  /// version 3.
  PasetoV4
}

/// What kind of token it is. The spec gives
/// [examples of what each is for](https://github.com/paseto-standard/paseto-spec/blob/master/docs/README.md#what-should-we-use-paseto-for),
/// and [Keys](keys.html) explains which key each needs.
pub type PasetoPurpose {
  /// Encrypted with one shared key, so only someone with the key can read
  /// the claims or make tokens. Use it when the same app makes and reads the
  /// tokens.
  Local
  /// Signed with a secret key and checked with its public key. Anyone can
  /// read the claims, but only the holder of the secret key can make tokens.
  /// Use it when other services need to check tokens they must not make.
  Public
}

/// A token that has been decrypted or verified, and whose claims passed the
/// rules. Only `decrypt` and `verify` can make one. Read it with `subject`,
/// `payload` and the other functions named after its claims.
pub opaque type Token {
  Token(
    version: PasetoVersion,
    purpose: PasetoPurpose,
    claims: internal_claims.RegisteredClaims,
    payload: String,
    footer: BitArray,
  )
}

/// What to put in a new token. Claims are the facts a token carries, such as
/// who it is about and when it expires. They are stored as a JSON object in
/// the token. The spec reserves seven registered claims
/// ([Registered Claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md#payload-claims)),
/// which mean the same as in JWT
/// ([RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1)),
/// except that times are written as RFC 3339 text. You can add your own. A token can also have a footer and an implicit
/// assertion. Start with `new_claims`.
pub opaque type Claims {
  Claims(builder: internal_claims.Builder)
}

/// What `decrypt` and `verify` check in a token: its times, the claim values
/// you require, and the implicit assertion. Start with `new_rules`.
pub opaque type Rules {
  Rules(rules: internal_claims.Rules)
}

/// A shared key for `local` tokens. Make one with `local_key_from_hex`.
pub opaque type LocalKey {
  V3LocalKey(paseto_v3.LocalKey)
  V4LocalKey(paseto_v4.LocalKey)
}

/// A secret key for signing `public` tokens. Make one with `secret_key_from_hex`.
pub opaque type SecretKey {
  V3SecretKey(paseto_v3.SecretKey)
  V4SecretKey(paseto_v4.SecretKey)
}

/// A public key for verifying `public` tokens. Make one with `public_key_from_hex`.
pub opaque type PublicKey {
  V3PublicKey(paseto_v3.PublicKey)
  V4PublicKey(paseto_v4.PublicKey)
}

/// Makes a shared key from 32 bytes written as hex.
///
/// ```gleam
/// let assert Ok(key) = gaseto.local_key_from_hex(gaseto.PasetoV4, key_hex)
/// ```
pub fn local_key_from_hex(
  version: PasetoVersion,
  key: String,
) -> Result(LocalKey, error.KeyLoadingError) {
  case version {
    PasetoV3 -> paseto_v3.local_key_from_hex(key) |> result.map(V3LocalKey)
    PasetoV4 -> paseto_v4.local_key_from_hex(key) |> result.map(V4LocalKey)
  }
}

/// Makes a secret key from hex. Version 3 takes a 48-byte P-384 secret.
/// Version 4 takes a 64-byte Ed25519 key: the seed followed by the public key.
///
/// ```gleam
/// let assert Ok(secret_key) = gaseto.secret_key_from_hex(gaseto.PasetoV4, secret_key_hex)
/// ```
pub fn secret_key_from_hex(
  version: PasetoVersion,
  key: String,
) -> Result(SecretKey, error.KeyLoadingError) {
  case version {
    PasetoV3 -> paseto_v3.secret_key_from_hex(key) |> result.map(V3SecretKey)
    PasetoV4 -> paseto_v4.secret_key_from_hex(key) |> result.map(V4SecretKey)
  }
}

/// Makes a public key from hex. Version 3 takes a 49-byte compressed P-384
/// point. Version 4 takes a 32-byte Ed25519 public key.
///
/// ```gleam
/// let assert Ok(public_key) = gaseto.public_key_from_hex(gaseto.PasetoV4, public_key_hex)
/// ```
pub fn public_key_from_hex(
  version: PasetoVersion,
  key: String,
) -> Result(PublicKey, error.KeyLoadingError) {
  case version {
    PasetoV3 -> paseto_v3.public_key_from_hex(key) |> result.map(V3PublicKey)
    PasetoV4 -> paseto_v4.public_key_from_hex(key) |> result.map(V4PublicKey)
  }
}

/// Makes a secret key from a PEM file: an Ed25519 key in PKCS #8 for version
/// 4, or a P-384 key in SEC1 or PKCS #8 for version 3. `openssl genpkey`
/// writes PKCS #8, and `openssl ecparam -genkey` writes SEC1.
///
/// ```gleam
/// let assert Ok(secret_key) =
///   gaseto.secret_key_from_pem(gaseto.PasetoV4, secret_key_pem)
/// ```
pub fn secret_key_from_pem(
  version: PasetoVersion,
  pem: String,
) -> Result(SecretKey, error.KeyLoadingError) {
  case version {
    PasetoV3 -> paseto_v3.secret_key_from_pem(pem) |> result.map(V3SecretKey)
    PasetoV4 -> paseto_v4.secret_key_from_pem(pem) |> result.map(V4SecretKey)
  }
}

/// Makes a public key from a PEM file, as `openssl pkey -pubout` writes it.
///
/// ```gleam
/// let assert Ok(public_key) =
///   gaseto.public_key_from_pem(gaseto.PasetoV4, public_key_pem)
/// ```
pub fn public_key_from_pem(
  version: PasetoVersion,
  pem: String,
) -> Result(PublicKey, error.KeyLoadingError) {
  case version {
    PasetoV3 -> paseto_v3.public_key_from_pem(pem) |> result.map(V3PublicKey)
    PasetoV4 -> paseto_v4.public_key_from_pem(pem) |> result.map(V4PublicKey)
  }
}

/// Generates a new shared key. Generate a key once and keep it: a key
/// generated each time your app starts would change on every restart, which
/// makes all earlier tokens invalid. To store it, see `local_key_to_hex`.
///
/// ```gleam
/// let key = gaseto.generate_local_key(gaseto.PasetoV4)
/// ```
pub fn generate_local_key(version: PasetoVersion) -> LocalKey {
  case version {
    PasetoV3 -> V3LocalKey(paseto_v3.generate_local_key())
    PasetoV4 -> V4LocalKey(paseto_v4.generate_local_key())
  }
}

/// Generates a new secret key. Get its public key with
/// `secret_key_to_public_key`. Generate a key once and keep it, as with
/// `generate_local_key`. To store it, see `secret_key_to_hex`.
///
/// ```gleam
/// let secret_key = gaseto.generate_secret_key(gaseto.PasetoV4)
/// let public_key = gaseto.secret_key_to_public_key(secret_key)
/// ```
pub fn generate_secret_key(version: PasetoVersion) -> SecretKey {
  case version {
    PasetoV3 -> V3SecretKey(paseto_v3.generate_secret_key())
    PasetoV4 -> V4SecretKey(paseto_v4.generate_secret_key())
  }
}

/// The public key that checks tokens signed with this secret key.
pub fn secret_key_to_public_key(secret_key: SecretKey) -> PublicKey {
  case secret_key {
    V3SecretKey(key) -> V3PublicKey(paseto_v3.secret_key_to_public_key(key))
    V4SecretKey(key) -> V4PublicKey(paseto_v4.secret_key_to_public_key(key))
  }
}

/// The key as hex, as `local_key_from_hex` reads it. For how to manage keys, see
/// [Keys](keys.html).
pub fn local_key_to_hex(key: LocalKey) -> String {
  case key {
    V3LocalKey(key) -> paseto_v3.local_key_to_hex(key)
    V4LocalKey(key) -> paseto_v4.local_key_to_hex(key)
  }
}

/// The key as hex, as `secret_key_from_hex` reads it. For how to manage keys, see
/// [Keys](keys.html).
pub fn secret_key_to_hex(key: SecretKey) -> String {
  case key {
    V3SecretKey(key) -> paseto_v3.secret_key_to_hex(key)
    V4SecretKey(key) -> paseto_v4.secret_key_to_hex(key)
  }
}

/// The key as hex, as `public_key_from_hex` reads it.
pub fn public_key_to_hex(key: PublicKey) -> String {
  case key {
    V3PublicKey(key) -> paseto_v3.public_key_to_hex(key)
    V4PublicKey(key) -> paseto_v4.public_key_to_hex(key)
  }
}

/// New claims for a token. By default the token expires one hour after it is
/// created, as the spec recommends
/// ([Default Expiration Claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/05-API-UX.md#default-expiration-claims)),
/// and `iat` is set to the time it is created.
///
/// ```gleam
/// let claims =
///   gaseto.new_claims()
///   |> gaseto.with_subject("user-42")
///   |> gaseto.expires_in(duration.minutes(15))
/// ```
pub fn new_claims() -> Claims {
  Claims(internal_claims.new_builder())
}

/// Sets `iss` (issuer): who made the token, such as your login service.
/// Readers can require it with `issued_by`
/// ([RFC 7519, `iss`](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1)).
pub fn with_issuer(claims: Claims, issuer: String) -> Claims {
  Claims(internal_claims.Builder(..claims.builder, issuer: Some(issuer)))
}

/// Sets `sub` (subject): who or what the token is about, usually a user
/// identifier. Readers can require it with `for_subject`
/// ([RFC 7519, `sub`](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2)).
pub fn with_subject(claims: Claims, subject: String) -> Claims {
  Claims(internal_claims.Builder(..claims.builder, subject: Some(subject)))
}

/// Sets `aud` (audience): who the token is meant for, such as the service
/// that should accept it. Readers require it with `for_audience`, so a token
/// made for one service is refused by another
/// ([RFC 7519, `aud`](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3)).
pub fn with_audience(claims: Claims, audience: String) -> Claims {
  Claims(internal_claims.Builder(..claims.builder, audience: Some(audience)))
}

/// Sets `jti` (token identifier): a unique identifier for this token. A
/// server can use it to remember tokens it has cancelled or already seen.
/// Readers can require it with `identified_by`
/// ([RFC 7519, `jti`](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7)).
pub fn with_token_identifier(
  claims: Claims,
  token_identifier: String,
) -> Claims {
  let token_identifier = Some(token_identifier)
  Claims(internal_claims.Builder(..claims.builder, token_identifier:))
}

/// Sets `exp` (expiration) to this time
/// ([RFC 7519, `exp`](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4)).
/// After it, the token is refused ([Validators](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/02-Validators.md)).
/// Fractions of a second are left out, as the spec recommends
/// ([Registered Claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md#payload-claims)).
pub fn with_expires_at(claims: Claims, time: Timestamp) -> Claims {
  let expiration = internal_claims.ExpiresAt(time)
  Claims(internal_claims.Builder(..claims.builder, expiration:))
}

/// Sets `exp` (expiration) to this long after the token is created
/// ([RFC 7519, `exp`](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4)).
/// After that, the token is refused ([Validators](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/02-Validators.md)).
pub fn expires_in(claims: Claims, duration: Duration) -> Claims {
  let expiration = internal_claims.ExpiresIn(duration)
  Claims(internal_claims.Builder(..claims.builder, expiration:))
}

/// Leaves out `exp` (expiration), so the token never expires. Only use this
/// when you really need it. `new_rules` refuses such tokens unless the reader uses
/// `allow_no_expiration`.
pub fn never_expires(claims: Claims) -> Claims {
  let expiration = internal_claims.NeverExpires
  Claims(internal_claims.Builder(..claims.builder, expiration:))
}

/// Sets `nbf` (not before): the token is refused before this time. Use it for
/// a token that should only start working later
/// ([RFC 7519, `nbf`](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5)).
/// Fractions of a second are left out, as the spec recommends
/// ([Registered Claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md#payload-claims)).
pub fn with_not_before(claims: Claims, time: Timestamp) -> Claims {
  Claims(internal_claims.Builder(..claims.builder, not_before: Some(time)))
}

/// Sets `iat` (issued at), when the token was made, to this time instead of
/// the time the token is created
/// ([RFC 7519, `iat`](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6)).
/// A token issued in the future is refused ([Validators](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/02-Validators.md)).
/// Fractions of a second are left out, as the spec recommends
/// ([Registered Claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md#payload-claims)).
pub fn with_issued_at(claims: Claims, time: Timestamp) -> Claims {
  Claims(internal_claims.Builder(..claims.builder, issued_at: Some(time)))
}

/// Adds a claim of your own. The registered names (`iss`, `sub`, `aud`,
/// `exp`, `nbf`, `iat` and `jti`) are refused when the token is created,
/// because the spec reserves them
/// ([Registered Claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md#payload-claims)).
/// Use their own functions instead.
///
/// Adding a claim with the same name again replaces the first value.
///
/// ```gleam
/// gaseto.new_claims() |> gaseto.with_claim("role", json.string("admin"))
/// ```
pub fn with_claim(claims: Claims, name: String, value: Json) -> Claims {
  let custom = dict.insert(claims.builder.custom, name, value)
  Claims(internal_claims.Builder(..claims.builder, custom:))
}

/// Adds a footer: data stored in the token next to the claims. It is not
/// encrypted, so anyone can read it, even in a `local` token, but it cannot be
/// changed without breaking the token. A common use is a key identifier
/// (`kid`), so the reader knows which key to use
/// ([Optional Footer](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md#optional-footer),
/// [Key-ID Support](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md#key-id-support)).
/// It can be any bytes, and is often JSON text. An empty footer means no
/// footer.
///
/// ```gleam
/// gaseto.new_claims() |> gaseto.with_footer(<<"{\"kid\":\"key-1\"}":utf8>>)
/// ```
pub fn with_footer(claims: Claims, footer: BitArray) -> Claims {
  Claims(internal_claims.Builder(..claims.builder, footer:))
}

/// Adds an implicit assertion: data that is covered by the tag or signature
/// but not stored in the token. The reader must give the same value with
/// `expect_implicit_assertion`, or the token is refused. Use it to tie a token
/// to something both sides already know, such as a user identifier, without
/// putting it in the token
/// ([Implicit Assertions](https://github.com/paseto-standard/paseto-spec/blob/master/docs/README.md#implicit-assertions)).
pub fn with_implicit_assertion(
  claims: Claims,
  implicit_assertion: BitArray,
) -> Claims {
  Claims(internal_claims.Builder(..claims.builder, implicit_assertion:))
}

/// Rules that require an `exp` claim, as the spec recommends
/// ([Default Expiration Claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/05-API-UX.md#default-expiration-claims)),
/// and check the times against the current time. A token is refused after its
/// `exp` (expiration), before its `nbf` (not before), or if its `iat` (issued
/// at) is in the future.
///
/// ```gleam
/// let rules =
///   gaseto.new_rules()
///   |> gaseto.issued_by("auth.example.com")
///   |> gaseto.for_audience("api")
/// ```
pub fn new_rules() -> Rules {
  Rules(internal_claims.new_rules())
}

/// Requires `iss` (issuer) to be this value, so only tokens made by this
/// issuer are accepted. See `with_issuer`.
pub fn issued_by(rules: Rules, issuer: String) -> Rules {
  Rules(internal_claims.Rules(..rules.rules, issuer: Some(issuer)))
}

/// Requires `sub` (subject) to be this value, so only tokens about this
/// subject are accepted. See `with_subject`.
pub fn for_subject(rules: Rules, subject: String) -> Rules {
  Rules(internal_claims.Rules(..rules.rules, subject: Some(subject)))
}

/// Requires `aud` (audience) to be this value, so tokens meant for someone
/// else are refused. See `with_audience`.
pub fn for_audience(rules: Rules, audience: String) -> Rules {
  Rules(internal_claims.Rules(..rules.rules, audience: Some(audience)))
}

/// Requires `jti` (token identifier) to be this value. See
/// `with_token_identifier`.
pub fn identified_by(rules: Rules, token_identifier: String) -> Rules {
  let token_identifier = Some(token_identifier)
  Rules(internal_claims.Rules(..rules.rules, token_identifier:))
}

/// Accepts tokens without an `exp` (expiration) claim. If a token has one, it is still
/// checked.
pub fn allow_no_expiration(rules: Rules) -> Rules {
  let expiration = internal_claims.AllowNoExpiration
  Rules(internal_claims.Rules(..rules.rules, expiration:))
}

/// Checks `exp`, `nbf` and `iat` against this time instead of the current
/// time. Useful in tests.
pub fn checked_at(rules: Rules, time: Timestamp) -> Rules {
  Rules(internal_claims.Rules(..rules.rules, checked_at: Some(time)))
}

/// Accepts tokens whose times are off by up to this much, for when the clocks
/// of the servers that make and check tokens differ a little. It applies to
/// `exp`, `nbf` and `iat`. A negative duration counts as none. By default no
/// difference is allowed.
///
/// ```gleam
/// gaseto.new_rules() |> gaseto.allow_clock_skew(duration.seconds(30))
/// ```
pub fn allow_clock_skew(rules: Rules, up_to skew: Duration) -> Rules {
  // `duration.compare` ignores the sign, so the seconds are checked instead
  let skew = case duration.to_seconds_and_nanoseconds(skew) {
    #(seconds, _) if seconds < 0 -> duration.seconds(0)
    _ -> skew
  }
  Rules(internal_claims.Rules(..rules.rules, clock_skew: skew))
}

/// Refuses tokens longer than this many bytes, before any cryptography. A
/// token can come from anyone, and checking it takes time in proportion to
/// its length, so a very long token could be used to waste CPU time. The
/// default is 8192 bytes, Gaseto's own choice, which is more than most tokens
/// need and matches a common limit for HTTP headers.
///
/// ```gleam
/// gaseto.new_rules() |> gaseto.allow_token_length(up_to: 16_384)
/// ```
pub fn allow_token_length(rules: Rules, up_to max_length: Int) -> Rules {
  Rules(internal_claims.Rules(..rules.rules, max_token_length: max_length))
}

/// Requires the token to have been made with this implicit assertion. An
/// implicit assertion is data that is covered by the tag or signature but not
/// stored in the token, so the reader has to know it already. See
/// `with_implicit_assertion`
/// ([Implicit Assertions](https://github.com/paseto-standard/paseto-spec/blob/master/docs/README.md#implicit-assertions)).
pub fn expect_implicit_assertion(
  rules: Rules,
  implicit_assertion: BitArray,
) -> Rules {
  Rules(internal_claims.Rules(..rules.rules, implicit_assertion:))
}

/// Creates an encrypted `local` token.
///
/// ```gleam
/// let assert Ok(token) = gaseto.encrypt(claims, key)
/// // token == "v4.local.…"
/// ```
pub fn encrypt(
  claims: Claims,
  key: LocalKey,
) -> Result(String, error.TokenCreationError) {
  let internal_claims.Builder(footer:, implicit_assertion:, ..) = claims.builder
  use payload <- result.try(internal_claims.encode(
    claims.builder,
    timestamp.system_time(),
  ))
  let nonce = crypto.strong_random_bytes(32)
  case key {
    V3LocalKey(key) ->
      paseto_v3.encrypt(key, payload, footer, nonce, implicit_assertion)
    V4LocalKey(key) ->
      paseto_v4.encrypt(key, payload, footer, nonce, implicit_assertion)
  }
}

/// Decrypts a `local` token and checks it against the rules. The key must
/// have the same version as the token. Tokens longer than 8192 bytes are
/// refused unless the rules allow more, see `allow_token_length`.
///
/// ```gleam
/// case gaseto.decrypt(token, key, gaseto.new_rules()) {
///   Ok(token) -> Ok(gaseto.subject(token))
///   Error(error.Expired(_)) -> Error("Please log in again")
///   Error(_) -> Error("Invalid token")
/// }
/// ```
pub fn decrypt(
  token: String,
  key: LocalKey,
  rules: Rules,
) -> Result(Token, error.TokenValidationError) {
  let key_version = case key {
    V3LocalKey(_) -> PasetoV3
    V4LocalKey(_) -> PasetoV4
  }
  use read <- result.try(read_token_for(token, key_version, Local, rules))
  let implicit_assertion = rules.rules.implicit_assertion
  use contents <- result.try(case key {
    V3LocalKey(key) -> paseto_v3.decrypt(key, read.parts, implicit_assertion)
    V4LocalKey(key) -> paseto_v4.decrypt(key, read.parts, implicit_assertion)
  })
  to_token(read, contents, rules)
}

/// Creates a signed `public` token. Anyone can read its claims.
///
/// ```gleam
/// let assert Ok(token) = gaseto.sign(claims, secret_key)
/// // token == "v4.public.…"
/// ```
pub fn sign(
  claims: Claims,
  key: SecretKey,
) -> Result(String, error.TokenCreationError) {
  let internal_claims.Builder(footer:, implicit_assertion:, ..) = claims.builder
  use payload <- result.try(internal_claims.encode(
    claims.builder,
    timestamp.system_time(),
  ))
  case key {
    V3SecretKey(key) -> paseto_v3.sign(key, payload, footer, implicit_assertion)
    V4SecretKey(key) -> paseto_v4.sign(key, payload, footer, implicit_assertion)
  }
}

/// Verifies a `public` token and checks it against the rules. The key must
/// have the same version as the token. Tokens longer than 8192 bytes are
/// refused unless the rules allow more, see `allow_token_length`.
///
/// ```gleam
/// let assert Ok(token) = gaseto.verify(token, public_key, rules)
/// gaseto.subject(token)
/// ```
pub fn verify(
  token: String,
  key: PublicKey,
  rules: Rules,
) -> Result(Token, error.TokenValidationError) {
  let key_version = case key {
    V3PublicKey(_) -> PasetoV3
    V4PublicKey(_) -> PasetoV4
  }
  use read <- result.try(read_token_for(token, key_version, Public, rules))
  let implicit_assertion = rules.rules.implicit_assertion
  use contents <- result.try(case key {
    V3PublicKey(key) -> paseto_v3.verify(key, read.parts, implicit_assertion)
    V4PublicKey(key) -> paseto_v4.verify(key, read.parts, implicit_assertion)
  })
  to_token(read, contents, rules)
}

/// The token's version.
pub fn version(token: Token) -> PasetoVersion {
  token.version
}

/// Whether the token is `local` or `public`.
pub fn purpose(token: Token) -> PasetoPurpose {
  token.purpose
}

/// The `iss` (issuer) claim: who made the token. See `with_issuer`.
pub fn issuer(token: Token) -> Option(String) {
  token.claims.issuer
}

/// The `sub` (subject) claim: who or what the token is about. See
/// `with_subject`.
pub fn subject(token: Token) -> Option(String) {
  token.claims.subject
}

/// The `aud` (audience) claim: who the token is meant for. See
/// `with_audience`.
pub fn audience(token: Token) -> Option(String) {
  token.claims.audience
}

/// The `exp` (expiration) claim: when the token stops being valid. See
/// `with_expires_at`.
pub fn expires_at(token: Token) -> Option(Timestamp) {
  token.claims.expires_at
}

/// The `nbf` (not before) claim: when the token starts being valid. See
/// `with_not_before`.
pub fn not_before(token: Token) -> Option(Timestamp) {
  token.claims.not_before
}

/// The `iat` (issued at) claim: when the token was made. See
/// `with_issued_at`.
pub fn issued_at(token: Token) -> Option(Timestamp) {
  token.claims.issued_at
}

/// The `jti` (token identifier) claim: a unique identifier for the token.
/// See `with_token_identifier`.
pub fn token_identifier(token: Token) -> Option(String) {
  token.claims.token_identifier
}

/// The whole payload, a JSON object. Read your own claims from it with a
/// decoder.
///
/// ```gleam
/// json.parse(gaseto.payload(token), decode.at(["role"], decode.string))
/// ```
pub fn payload(token: Token) -> String {
  token.payload
}

/// The footer, as raw bytes. It has been checked along with the token, unlike
/// `unverified_footer`. It is often JSON text: decode it with `decode_footer`,
/// or turn it into a `String` with `bit_array.to_string`. It is empty if the
/// token has none. See `with_footer`.
pub fn footer(token: Token) -> BitArray {
  token.footer
}

/// Reads the footer without checking the token. Use it to find which key to
/// use, for example from a `kid` (key identifier) field. Do not trust anything else in it until
/// the token has been decrypted or verified. It is empty if the token has no
/// footer.
///
/// ```gleam
/// let key_identifier_decoder = decode.at(["kid"], decode.string)
/// let assert Ok(footer) = gaseto.unverified_footer(token)
/// let assert Ok(key_identifier) =
///   gaseto.decode_footer(footer, gaseto.default_footer_rules, key_identifier_decoder)
/// ```
pub fn unverified_footer(
  token: String,
) -> Result(BitArray, error.TokenFormatError) {
  read_token(token) |> result.map(fn(read) { protocol.footer(read.parts) })
}

/// Limits that `decode_footer` checks before it parses a JSON footer. A
/// footer can be read before the token is checked, so it can come from
/// anyone, and a very long, deeply nested or key-heavy JSON footer can
/// overload a JSON parser. The spec requires libraries to offer such a check
/// ([Storing JSON in the Footer](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md#storing-json-in-the-footer)).
pub type FooterRules {
  FooterRules(
    /// The most bytes the footer may have.
    max_length: Int,
    /// How deeply objects and arrays may nest. 1 is a value with no object
    /// or array, and 2 is one object or array with no nesting inside.
    max_depth: Int,
    /// The most keys the footer may have, counted over all objects.
    max_keys: Int,
  )
}

/// At most 8192 bytes and 512 keys, with no nested objects or arrays. No
/// nesting is the spec's recommended default
/// ([Storing JSON in the Footer](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md#storing-json-in-the-footer)).
/// The length and key limits are Gaseto's own.
pub const default_footer_rules: FooterRules =
  FooterRules(max_length: 8192, max_depth: 2, max_keys: 512)

/// Decodes a JSON footer, after checking it against the rules. The check
/// protects the JSON parser from footers that are very large, deeply nested,
/// or have many keys. The spec requires libraries to offer such a check for
/// JSON footers
/// ([Storing JSON in the Footer](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md#storing-json-in-the-footer)).
///
/// ```gleam
/// let key_identifier_decoder = decode.at(["kid"], decode.string)
/// gaseto.decode_footer(footer, gaseto.default_footer_rules, key_identifier_decoder)
/// ```
pub fn decode_footer(
  footer: BitArray,
  rules: FooterRules,
  decoder: decode.Decoder(a),
) -> Result(a, error.FooterDecodingError) {
  let FooterRules(max_length:, max_depth:, max_keys:) = rules
  use _ <- result.try(internal_footer.check(
    footer,
    max_length:,
    max_depth:,
    max_keys:,
  ))
  json.parse_bits(footer, decoder) |> result.map_error(error.FooterDecodeFailed)
}

/// A token split into its header and parts, before anything is checked.
type ReadToken {
  ReadToken(
    version: PasetoVersion,
    purpose: PasetoPurpose,
    parts: protocol.TokenParts,
  )
}

/// Compares the header as bytes, so a combining character after it cannot
/// merge with its final ".".
fn read_token(token: String) -> Result(ReadToken, error.TokenFormatError) {
  use #(version, purpose, rest) <- result.try(case token {
    "v3.local." <> rest -> Ok(#(PasetoV3, Local, rest))
    "v3.public." <> rest -> Ok(#(PasetoV3, Public, rest))
    "v4.local." <> rest -> Ok(#(PasetoV4, Local, rest))
    "v4.public." <> rest -> Ok(#(PasetoV4, Public, rest))
    _ -> Error(header_error(token))
  })
  use parts <- result.try(protocol.split_body(rest))
  Ok(ReadToken(version:, purpose:, parts:))
}

/// Names what is wrong with a header that is not one Gaseto reads.
fn header_error(token: String) -> error.TokenFormatError {
  case string.split(token, on: ".") {
    [version, purpose, _, ..] ->
      case version {
        "v1" | "v2" -> error.UnsupportedVersion(version)
        "v3" | "v4" -> error.UnknownPurpose(purpose)
        _ -> error.UnknownVersion(version)
      }
    _ -> error.WrongNumberOfSegments
  }
}

/// Reads a token for a key, refusing it before any cryptography if it is too
/// long, or has another purpose or version than the key.
fn read_token_for(
  token: String,
  key_version: PasetoVersion,
  key_purpose: PasetoPurpose,
  rules: Rules,
) -> Result(ReadToken, error.TokenValidationError) {
  let length = string.byte_size(token)
  let max_length = rules.rules.max_token_length
  use <- bool.guard(
    when: length > max_length,
    return: Error(error.TokenTooLong(length:, max_length:)),
  )
  use read <- result.try(
    read_token(token) |> result.map_error(error.InvalidFormat),
  )
  use <- bool.guard(
    when: read.purpose != key_purpose,
    return: Error(error.UnexpectedPurpose(
      expected: purpose_name(key_purpose),
      found: purpose_name(read.purpose),
    )),
  )
  use <- bool.guard(
    when: read.version != key_version,
    return: Error(error.UnexpectedVersion(
      expected: version_name(key_version),
      found: version_name(read.version),
    )),
  )
  Ok(read)
}

fn to_token(
  read: ReadToken,
  contents: Contents,
  rules: Rules,
) -> Result(Token, error.TokenValidationError) {
  let protocol.Contents(payload:, footer:) = contents
  internal_claims.open(payload, rules.rules)
  |> result.map(fn(claims) {
    Token(
      version: read.version,
      purpose: read.purpose,
      claims:,
      payload:,
      footer:,
    )
  })
}

fn version_name(version: PasetoVersion) -> String {
  case version {
    PasetoV3 -> "v3"
    PasetoV4 -> "v4"
  }
}

fn purpose_name(purpose: PasetoPurpose) -> String {
  case purpose {
    Local -> "local"
    Public -> "public"
  }
}
