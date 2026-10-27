# Changelog

All notable changes to Gaseto are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and Gaseto adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] - 2026-10-27

### Changed

- Version 4 `local` tokens use XChaCha20 from kryptos instead of Gaseto's own
  implementation built on OTP's ChaCha20. Tokens are unchanged.
- Gaseto now requires kryptos 1.6.0 or newer.

## [1.0.0] - 2026-10-24

### Added

- PASETO version 3 `local` and `public` tokens.
- PASETO version 4 `local` and `public` tokens.

[unreleased]: https://github.com/atomfinger/gaseto/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/atomfinger/gaseto/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/atomfinger/gaseto/releases/tag/v1.0.0
