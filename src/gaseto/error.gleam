//// The errors Gaseto returns.
////
//// ```gleam
//// case gaseto.decrypt(token, key, gaseto.new_rules()) {
////   Ok(token) -> Ok(gaseto.subject(token))
////   Error(error.Expired(_)) -> Error("Please log in again")
////   Error(_) -> Error("Invalid token")
//// }
//// ```

import gleam/json
import gleam/option.{type Option}
import gleam/time/timestamp.{type Timestamp}

/// Why a key could not be loaded from hex or PEM.
pub type KeyLoadingError {
  /// The key is not written as hex.
  NotHex
  /// The key has the wrong number of bytes. The spec sets the size of a local
  /// key ([version 3, Encrypt](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#encrypt),
  /// [version 4, Encrypt](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#encrypt))
  /// and of a version 3 secret key
  /// ([version 3, Sign](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#sign))
  /// and public key
  /// ([version 3, Verify](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#verify)).
  /// The version 4 key sizes come from Ed25519.
  WrongLength(expected: Int, found: Int)
  /// The version 3 secret key is out of range. Version 3 uses the P-384
  /// elliptic curve
  /// ([NIST SP 800-186, section 3.2.1.4](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf)),
  /// and a secret key is a number that must be at least 1 and less than the
  /// curve's order, a fixed number that comes with the curve
  /// ([FIPS 186-5, section 6.4.1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf)).
  OutsideCurveRange
  /// A version 3 public key must start with 02 or 03, because the spec
  /// requires a compressed point
  /// ([version 3, Verify](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version3.md#verify)).
  NotACompressedPoint
  /// The version 3 public key is not a point on the P-384 elliptic curve
  /// ([NIST SP 800-186, section 3.2.1.4](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf)), so it
  /// cannot be a real public key.
  NotOnCurve
  /// The second half of a version 4 secret key is not the public key of its
  /// first half.
  PublicHalfDoesNotMatchSeed
  /// The version 4 public key is one of a few special values that would let
  /// anyone forge tokens for it. The spec writes the check as libsodium's
  /// `crypto_sign_verify_detached`, which refuses these keys
  /// ([version 4, Verify](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#verify)).
  SmallOrderPublicKey
  /// The text is not one PEM key of the kind needed: an Ed25519 key for
  /// version 4, or a P-384 key for version 3. Keys protected by a password
  /// are not read.
  InvalidPem
  /// This should never happen. It means a bug in Gaseto or a library it uses.
  /// `reason` says which step failed.
  UnexpectedKeyFailure(reason: String)
}

/// Why `encrypt` or `sign` could not create a token.
pub type TokenCreationError {
  /// A claim of your own uses one of the registered names (`iss`, `sub`,
  /// `aud`, `exp`, `nbf`, `iat` or `jti`). The spec reserves these names
  /// ([Registered Claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md#payload-claims)).
  ReservedClaimName(name: String)
  /// A claim of your own holds an object that repeats a key. The spec
  /// requires unique key names
  /// ([Payload Processing](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md)).
  RepeatedKeyInClaim(name: String)
  /// This should never happen. It means a bug in Gaseto or a library it uses.
  /// `reason` says which step failed.
  UnexpectedCreationFailure(reason: String)
}

/// Why `decrypt` or `verify` refused a token.
pub type TokenValidationError {
  /// The token is longer than the rules allow. See `allow_token_length`.
  TokenTooLong(length: Int, max_length: Int)
  /// The token cannot be read.
  InvalidFormat(error: TokenFormatError)
  /// The token's version is not the key's version, for example `"v4"` and
  /// `"v3"`. The spec requires a key to be used only with its own version
  /// ([Algorithm Lucidity](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/03-Algorithm-Lucidity.md#paseto-cryptography-key-requirements)).
  UnexpectedVersion(expected: String, found: String)
  /// A `"local"` token was given where a `"public"` one was expected, or the
  /// other way around. The spec requires a key to be used only for its own
  /// purpose
  /// ([Algorithm Lucidity](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/03-Algorithm-Lucidity.md#paseto-cryptography-key-requirements)).
  UnexpectedPurpose(expected: String, found: String)
  /// The tag or signature does not match. Either the token was changed, or
  /// the key or implicit assertion is wrong. On purpose, it does not say which.
  TokenNotAuthentic
  /// The payload is not UTF-8 text, is not a JSON object, or repeats a key.
  /// The spec requires a JSON object with unique key names
  /// ([Payload Processing](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/01-Payload-Processing.md)).
  InvalidPayload
  /// A registered claim has the wrong format.
  InvalidClaim(name: String, error: ClaimFormatError)
  /// The token has no `exp` claim. The spec recommends requiring one by
  /// default
  /// ([Default Expiration Claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/05-API-UX.md#default-expiration-claims)),
  /// so `new_rules` does. Use `allow_no_expiration` to accept such tokens.
  MissingExpiration
  /// The token expired at this time.
  Expired(expired_at: Timestamp)
  /// The token is not valid until this time (its `nbf` claim).
  NotYetValid(valid_from: Timestamp)
  /// The token says it was issued in the future (its `iat` claim).
  IssuedInTheFuture(issued_at: Timestamp)
  /// A claim does not have the value the rules expect.
  UnexpectedClaim(name: String, expected: String, found: Option(String))
  /// This should never happen. It means a bug in Gaseto or a library it uses.
  /// `reason` says which step failed.
  UnexpectedValidationFailure(reason: String)
}

/// Why a token's format cannot be read. `unverified_footer` returns it
/// directly; `decrypt` and `verify` wrap it in `InvalidFormat`.
pub type TokenFormatError {
  /// The version is not one the spec defines
  /// ([Message Format](https://github.com/paseto-standard/paseto-spec/blob/master/docs/README.md#paseto-message-format)).
  UnknownVersion(version: String)
  /// The token uses version 1 or 2. The spec defines them, but Gaseto does
  /// not support them because the spec deprecates them
  /// ([version 1](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version1.md),
  /// [version 2](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version2.md)).
  UnsupportedVersion(version: String)
  /// The purpose is not `local` or `public`, the only ones the spec allows
  /// ([Message Format](https://github.com/paseto-standard/paseto-spec/blob/master/docs/README.md#paseto-message-format)).
  UnknownPurpose(purpose: String)
  /// A token has three or four parts separated by dots
  /// ([Message Format](https://github.com/paseto-standard/paseto-spec/blob/master/docs/README.md#paseto-message-format)).
  WrongNumberOfSegments
  /// The token ends with a dot but no footer. The spec only adds the dot
  /// when there is a footer ([version 4, Encrypt](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Version4.md#encrypt)).
  EmptyFooterSegment
  /// A part is not strict, unpadded base64url, as the spec requires
  /// ([Base64 Decoding](https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Common.md#base64-decoding)).
  NotBase64Url
  /// The token is too short to hold its nonce, tag or signature.
  BodyTooShort
}

/// What is wrong with a registered claim in a token.
pub type ClaimFormatError {
  /// The spec defines the registered claims as strings
  /// ([Registered Claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md#payload-claims)).
  NotAString
  /// The spec requires times in RFC 3339, with an uppercase "T" and "Z"
  /// ([Registered Claims](https://github.com/paseto-standard/paseto-spec/blob/master/docs/02-Implementation-Guide/04-Claims.md#payload-claims)).
  NotAnRfc3339Time
}

/// Why `decode_footer` could not decode a footer: it broke a limit in
/// `FooterRules`, or the decoder failed.
pub type FooterDecodingError {
  /// The footer is longer than `FooterRules` allows.
  FooterTooLong(length: Int, max_length: Int)
  /// The footer is nested deeper than `FooterRules` allows.
  FooterTooDeep(depth: Int, max_depth: Int)
  /// The footer has more keys than `FooterRules` allows.
  FooterHasTooManyKeys(key_count: Int, max_keys: Int)
  /// The brackets or quotes do not match, so the footer is not valid JSON.
  FooterIsMalformed
  /// The footer passed the checks, but the decoder failed.
  FooterDecodeFailed(error: json.DecodeError)
}
