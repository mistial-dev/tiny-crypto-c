<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Changelog

## 2.0.0

- Breaking changes to public C and C++ interfaces; consumers must review calls
  when upgrading from 1.x.
- Stateful crypto lifecycle checks and authenticated GCM decryption.
- ECDSA signing and raw RSA.
- ISO 9797 DES MAC support.
- Stricter CRL, PIV, and TWIC trust checks.
- RFC 5914 trust anchors with RFC 5937 constraints.
- Synthetic TWIC APDUs and independent test vectors.
- Heap-free shared crypto and PKI cores.
- RFC 5869 HKDF with SP 800-56C Rev. 1 and Rev. 2 HKDF vector coverage.

## 1.0.1

- Adds embedded PIV/TWIC validation, PKI support, and target benchmarks.

## 1.0.0

- Initial release.
