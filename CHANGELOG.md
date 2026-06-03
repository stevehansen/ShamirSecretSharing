# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-06-03

### Added
- Authenticated shares: `AuthenticatedSecretSplitter` / `AuthenticatedSecretCombiner` wrap shares with an HMAC so forged or corrupted shares are detected (`ShareAuthenticationException`) instead of silently reconstructing a wrong secret. The HMAC key is itself recursively split across the shares.
- `RandomSource` abstraction with `CryptoRandomSource` (production) and `SequenceRandomSource` (deterministic, for tests), plus a `ShamirSecretSharingService(int prime, RandomSource randomSource)` constructor overload. (#12)
- `SecretSplitter` and `SecretCombiner` as standalone, single-purpose entry points; `ShamirSecretSharingService` now delegates to them. (#13)
- `FiniteField.Default` shared GF(257) instance.

### Fixed
- `FiniteField` now rejects composite moduli (including Carmichael numbers) with a Miller–Rabin primality check. Previously a composite modulus was silently accepted and produced incorrect results. (#14)
- `Share.ToString()` zero-pads the X-coordinate to 2 hex digits. `Share.Parse` accepts both old and new encodings, so existing serialized shares remain readable.
- Polynomial coefficients are now sampled without modulo bias.

### Changed
- `FiniteField` is now `sealed`. Deriving from it was never supported; if you did, this is a source-breaking change.

## [1.0.0] - 2025-05-10

### Added
- Initial release: `(t, n)` threshold Shamir's Secret Sharing over GF(257) (configurable prime), byte-wise polynomial split/reconstruct via Lagrange interpolation.
- `Share` record with compact hex string serialization (`ToString()` / `Parse()`).
- String secret convenience overloads (UTF-8 by default).
- NuGet packaging with SourceLink, embedded README/icon, and `.snupkg` symbols.

[Unreleased]: https://github.com/stevehansen/ShamirSecretSharing/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/stevehansen/ShamirSecretSharing/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/stevehansen/ShamirSecretSharing/releases/tag/v1.0.0
