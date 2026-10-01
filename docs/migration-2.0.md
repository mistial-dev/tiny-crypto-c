<!-- SPDX-FileCopyrightText: Mistial Dev -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Migrating to 2.0

Version 2.0 updates public interfaces across algorithms and protocol layers.
Update all calls as one source change; the library does not provide duplicate
1.x entry points.

## Byte ranges and results

Pass immutable byte ranges as `TC_bytes` and writable ranges as `TC_buffer`
where the function declares a span. One-shot authenticated encryption, key
wrap, hash and KDF interfaces use spans, as do protocol parsers and writers.
In-place block-mode and some streaming cipher/MAC functions retain pointer and
length parameters. Result types remain module-specific; use the result table
in `docs/api.md` rather than converting values between enums.

Streaming C contexts use `init`, `update`, `final` and `ctx_clear`. C++ owners
use `finish` and clear their state on destruction. One-shot functions name the
operation they perform, such as `digest`, `encrypt`, `sign` or `verify`.

## Workspaces and execution

Cryptographic one-shots take configuration, inputs, outputs, workspace, then
the work budget or `TC_execution`. RSA and EC randomized operations share
`TC_execution`. ECDSA signing is deterministic and takes
`TC_ECDSA_sign_options` plus a work budget.

## RSA sizes

Enable required modulus sizes independently with
`TINY_CRYPTO_RSA_ENABLE_1024`, `_2048`, `_3072` and `_4096`. RSA-1024 is a
legacy interoperability option and defaults off. PIV and TWIC profiles reject
it.

## Removed switches

`TC_ZEROIZE` and `TC_STRICT` were removed. Public argument checks and
secret-state wiping are unconditional.

The authoritative old-to-new CMake option mapping is the `retired_options`
table in `cmake/features.json`. Only option names that appeared in a released
1.x version are accepted.

## Authentication behavior

An authenticated revocation from either OCSP or a CRL wins over a good result.
PIV/TWIC card checking requires a complete canonical inventory, authenticated
Discovery data, and a card CVC bound to the live secure-messaging session.
GCM decryption remains one-shot so plaintext is released only after tag
verification.
