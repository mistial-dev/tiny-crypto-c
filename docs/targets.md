<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Application targets

`TINY_CRYPTO_TARGET` turns on the algorithm and format switches of a predefined set and turns the
rest off. An explicit value that disagrees stops configuration with "conflicts with <target>".
Resource tuning, such as byte-limb arithmetic and the AES S-box, stays with
`TINY_CRYPTO_RESOURCE_PROFILE`, so any target works with `micro`, `mini` or `desktop`.

```sh
cmake -S . -B build -DTINY_CRYPTO_TARGET=piv -DTINY_CRYPTO_RESOURCE_PROFILE=mini
```

An empty target leaves each switch to you. A platform port can add required features, such as the
ESP-IDF image hashes, to any target.

## full

Every algorithm and format the library provides, including MD5, single DES, P-192, RSA-1024, the
TDEA-CMAC KBKDF PRF, OCSP, the EAC CVC reader and the DRBGs.

## piv

Exactly the algorithms SP 800-78-5 allows for SP 800-73-5, plus the readers the PIV modules use.

| Use                                 | Algorithms                                           | Source                        |
| ----------------------------------- | ---------------------------------------------------- | ----------------------------- |
| Card keys 9A, 9C, 9D, 9E            | RSA 2048 and 3072, ECDSA and ECDH on P-256 and P-384 | SP 800-78-5 Table 1           |
| Signed objects, certificates, CRLs  | RSA 2048, 3072 and 4096, ECDSA, SHA-256 and SHA-384  | SP 800-78-5 Table 2           |
| Card Application Administration Key | AES-128, AES-192 and AES-256                         | SP 800-78-5 Tables 7 and 9    |
| Secure messaging CS2 and CS7        | ECDH, one-step KDF, AES-CBC, AES-CMAC                | SP 800-73-5 Part 2 section 4  |
| Compressed certificates             | GZIP                                                 | SP 800-73-5 Part 1 appendix A |

It also enables TLV with BER, DER, the APDU channel, PIV commands, OIDs, CHUID and object readers,
FASC-N, X.509 parsing, path validation, CRL revocation, CMS and CMS validation, key challenges, PIV
CVCs, secure messaging, VCI, the catalog, key proofs, credential validation and the card check.
TWIC support stays off.

SP 800-78-5 still lists two items this target omits:

- 3TDEA for the administration key (Tables 7 and 9). Footnote 9 notes that SP 800-131A Rev. 2
  disallowed it after 2023.
- RSA-1024 for retired key-management keys (Table 10). SP 800-73-5 Part 1 Table 6 excludes them
  from on-card key generation.

OCSP is outside the target because RFC 6960 section 4.2.1 byKey responder IDs need SHA-1.

## twic

`piv` plus the TWIC Legacy and NEXGEN additions from TWIC Part 2 v5. `TINY_CRYPTO_ENABLE_TWIC` adds
the TWIC application, card profiles and their rules to the PIV modules, with the NEXGEN UUID
helpers. The target also enables:

- SHA-1 and RSA-1024 for Legacy TWIC signatures and key proofs (section 3.3.4)
- the TWIC Privacy Key and its AAMVA barcode fields (section 4.9)
- private-object encryption with AES-128 ECB
- the canceled card list reader (TWIC Part 4)

## desfire

The primitives that MIFARE DESFire applications built on dfc-core call: AES-128 CBC, and DES ECB
and CBC with 8-byte single DES, 16-byte two-key TDEA and 24-byte three-key TDEA keys. The
application computes its own CMAC and CRC. No hash, MAC, KDF, TLV or public-key code is built.

## Standards status

Every algorithm in a target works for every operation. The status below guides the choice of a
target or custom selection.

| Algorithm           | Status                                                                                          |
| ------------------- | ----------------------------------------------------------------------------------------------- |
| RSA-1024            | SP 800-131A Rev. 2 Table 2: disallowed for signature generation, legacy use for verification    |
| P-192               | SP 800-186 section 3.2.1.1: legacy use, which section 3.1.2 limits to processing protected data |
| Two-key TDEA        | SP 800-131A Rev. 2 Table 1: disallowed for encryption, legacy use for decryption                |
| Three-key TDEA      | SP 800-131A Rev. 2 Table 1: encryption disallowed after 2023, legacy use for decryption         |
| TDEA-CMAC KBKDF PRF | SP 800-131A Rev. 2 Table 7: disallowed with two-key TDEA, and with three-key TDEA after 2023    |
| SHA-1 signatures    | SP 800-131A Rev. 2 Table 8: disallowed for signature generation                                 |
| MD5                 | RFC 6151: broken collision resistance                                                           |

## Testing

`test_application_targets` configures, builds and runs `tests/cmake/target_consumer` for every
target under each resource profile. The consumer checks each set at compile time and runs
known-answer tests. The test also checks that forcing a switch against a target fails
configuration.
