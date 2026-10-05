<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Migrating to 2.0

Version 2.0 changes public interfaces across the algorithm and protocol layers. Update all calls
in one source change. Each operation has one 2.0 entry point.

## Byte ranges and results

Pass immutable byte ranges as `TC_bytes` and writable ranges as `TC_buffer`. Cipher keys and IVs,
in-place block modes, streaming and one-shot authenticated encryption, MACs, key wrap, hash input,
KDFs, protocol parsers and writers all take spans. Hash digests go to fixed arrays of the digest
length. `TC_random_fn` callbacks take a pointer and a length.

Operation statuses share `TC_result`. The module names, such as `TC_status`, `TC_RSA_result` and
`TC_TLV_result`, are aliases with their value names intact. Call sites may keep the module names or
use one `TC_result` handler across modules. See the [result model](api.md#result-model).

Records filled by parsing and validation use the `_report` suffix, including
`TC_X509_path_report`, `TC_X509_validation_report`, `TC_X509_ocsp_report`,
`TC_X509_revocation_report` and the PIV credential reports. The `_result` and `_status` suffixes
name operation status aliases and domain state.

Streaming hash and MAC contexts use `init`, `update`, `final` and `ctx_clear`. Streaming GCM
encryption uses `init`, `aad_update`, `encrypt_update`, `encrypt_finish` and `ctx_clear`. C++
owners use `finish` and clear their state on destruction. One-shot functions name their operation,
such as `digest`, `encrypt`, `sign` or `verify`.

## Workspaces and execution

Cryptographic one-shots take configuration, inputs, outputs and workspace, then the work budget or
`TC_execution` ([argument order](api.md#naming-and-argument-order)). RSA and EC randomized
operations share `TC_execution`. ECDSA signing is deterministic and takes `TC_ECDSA_sign_options`
plus a work budget.

## RSA sizes

Enable each required modulus size with `TINY_CRYPTO_RSA_ENABLE_1024`, `_2048`, `_3072` and
`_4096`. RSA-1024 is an interoperability option and defaults off. PIV and TWIC key policy rejects
it, except TWIC Legacy key proofs that set `allow_rsa1024`.

## Removed switches

2.0 removes `TC_ZEROIZE` and `TC_STRICT`. Public argument checks and secret-state wiping are
unconditional.

The `retired_options` table in `cmake/features.json` maps each CMake option name released in 1.x
to its replacement. Configuration stops on a retired name and reports the replacement.

## Authentication behavior

An authenticated revocation from either OCSP or a CRL wins over a good result. PIV and TWIC card
checking requires a complete canonical inventory, authenticated Discovery data and a card CVC bound
to the live secure-messaging session. GCM decryption is one-shot, so plaintext is released only
after tag verification.
