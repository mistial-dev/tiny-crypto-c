<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Changelog

## 2.0.0

### Cryptography

- Added DRBG mechanisms, KMAC, RFC 5869 HKDF, AES-KW/KWP, deterministic
  ECDSA signing, raw RSA, RSA-4096, and ISO 9797 DES MAC support.
- Added authenticated one-shot GCM decryption and hardened stateful failure
  handling, work budgets, argument validation, and secret-state wiping.

### Certificates and cards

- Added OCSP with CRL conflict handling, RFC 5914 trust anchors with RFC 5937
  constraints, and stricter CRL signer authorization.
- Added APDU channels, PIV secure messaging, VCI, composed card checking, and
  PIV/TWIC credential validation with shared identifier policy.

### Breaking changes

- Expanded checked byte spans across one-shot cryptography, protocol parsers,
  FASC-N and UUID writers. Standardized C++ lifecycle names and added the APDU
  channel wrapper. Result types remain module-specific as documented in
  `docs/api.md`.
- Removed `TC_ZEROIZE` and `TC_STRICT`; their checks are always enabled.
- Renamed CMake feature switches and added independent RSA modulus-size gates.
  See `docs/migration-2.0.md` for the complete mapping.

### Testing and packaging

- Added bounded resource profiles, sanitizer and embedded builds, independent
  cryptographic vectors, synthetic TWIC APDUs, and checksum-pinned external
  corpus support.

## 1.0.1

- Adds embedded PIV/TWIC validation, PKI support, and target benchmarks.

## 1.0.0

- Initial release.
