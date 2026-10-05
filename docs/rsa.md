<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# RSA

Enable `TINY_CRYPTO_ENABLE_RSA=ON` and include `<tiny_crypto/rsa.h>` for PKCS #1 v1.5 and PSS
signatures over precomputed digests, OAEP, raw RSA operations, key generation and private-key
validation. Callers choose the key sizes and hashes their protocol accepts and apply trust policy
separately. The [native X.509 provider](x509-crypto.md) uses RSA verification, and
[testing](testing.md) describes the OpenSSL cross-checks.

## Keys and sizes

The supported moduli are 1024, 2048, 3072 and 4096 bits, each with a
`TINY_CRYPTO_RSA_ENABLE_<bits>` option. 2048, 3072 and 4096 are on by default. A disabled size
returns `TC_RSA_UNSUPPORTED`, the size and work helpers return zero for it, and
`TC_RSA_modulus_supported(bits)` reports it. `TC_RSA_MAX_MODULUS_BYTES` (512) sizes one
modulus-length value, such as a signature or encoded message.

Pass key components as unsigned big-endian magnitudes without ASN.1 sign padding. Signatures,
ciphertexts and raw inputs have the modulus length `L`, and digests the selected hash's length.
`TC_DER_rsa_public` in `<tiny_crypto/der.h>` reads a PKCS #1 `RSAPublicKey` into borrowed
magnitudes and checks integer encoding and positivity. The RSA calls check the arithmetic
constraints, and the caller applies key-strength policy.

`TINY_CRYPTO_RSA_SMALL=ON`, the micro profile default, selects byte limbs. AVR always uses byte
limbs, and other native builds use 32-bit limbs. PKCS #1 v1.5 verification and signing take the
digest directly, so they work with the hash disabled, and verification also needs no EC.

## Workspaces

Each operation takes caller-owned, aligned `TC_RSA_word` scratch, sized at run time with
`TC_RSA_workspace_words(TC_RSA_OPERATION_<name>, bits)` or for a static array with
`TC_RSA_<name>_WORKSPACE_WORDS(bits)`. The names are `VERIFY` (v1.5 and PSS), `ENCRYPT` (OAEP),
`RAW_PUBLIC`, `VALIDATE`, `CRT` (CRT validation and derivation), `SIGN` (v1.5 and PSS), `DECRYPT`
(OAEP), `RAW_PRIVATE` and `KEYGEN`. Keep the workspace exclusive to one call and off small task
stacks. Calls wipe the scratch they used.

## Status rule

Every RSA function checks its arguments once and reports the first problem in this order:

1. `TC_RSA_ARGUMENT`: a NULL pointer, overlapping or misaligned storage, or a digest whose length
   differs from its known hash.
1. `TC_RSA_UNSUPPORTED` or `TC_RSA_INVALID` for the key: an unsupported modulus size, or a
   malformed modulus, exponent, private component or CRT value.
1. `TC_RSA_UNSUPPORTED` or `TC_RSA_INVALID` for the scheme: a disabled or unknown hash, or
   parameters such as a salt or label too long for the modulus.
1. `TC_RSA_INVALID` for received data: a signature, ciphertext or raw input of the wrong length.
1. `TC_RSA_LIMIT`: an output buffer shorter than the modulus or the documented size, then too
   little workspace, blinding attempts or work.

After these checks, a representative at or above the modulus returns `TC_RSA_INVALID`.
`TC_RSA_ERROR` reports an RNG failure, a hash failure, or a private-key result that fails its
check with the public exponent. Only `TC_RSA_OK` accepts a signature.

These rules apply to every function unless its section says otherwise:

- Inputs may share storage. Outputs, length objects, workspace, work budget and RNG state are
  disjoint from the inputs, key metadata and each other.

- Outputs may be larger than required. Each call writes exactly the documented length, and only on
  `TC_RSA_OK`.

- Argument errors and limits found before arithmetic leave outputs, workspace and work unchanged.
  A blinding limit reached after rejected factors consumes the work of each attempt and wipes the
  workspace.

- Private-key operations take a validated, unchanged key and a `TC_RSA_execution` with a
  cryptographically secure RNG that fills each request completely, a blinding-attempt limit and a
  work budget. They blind the input and check the result with the public exponent before writing
  it.

## Work budgets

`TC_work_budget.remaining` is a `uint32_t` count of modular operations, encoded and masked bytes,
hash invocations and RNG requests. Work spent before an invalid signature is detected still
counts. The work functions return the exact cost of one successful call, or zero when the
operation would reject the arguments or the cost exceeds `UINT32_MAX`:

| Operation                  | Work                                                                                             |
| -------------------------- | ------------------------------------------------------------------------------------------------ |
| `TC_RSA_raw_public`        | `TC_RSA_public_work(&key)`                                                                       |
| `TC_RSA_verify_v15_digest` | `TC_RSA_public_work(&key) + TC_RSA_encode_v15_work(&options, L)`                                 |
| `TC_RSA_verify_pss_digest` | `TC_RSA_public_work(&key) + TC_RSA_encode_pss_work(&options, L)`                                 |
| `TC_RSA_verify_*_prepared` | `TC_RSA_prepared_public_work(&setup)` in place of `TC_RSA_public_work`                           |
| `TC_RSA_encrypt_oaep`      | `1 + TC_RSA_oaep_work(&options, L) + TC_RSA_public_work(&key)`                                   |
| `TC_RSA_raw_private`       | `TC_RSA_private_work(&key, A)` for a key without CRT values                                      |
| `TC_RSA_sign_v15_digest`   | `TC_RSA_private_work(&key, A) + TC_RSA_encode_v15_work(&options, L)`                             |
| `TC_RSA_sign_pss_digest`   | `TC_RSA_private_work(&key, A) + TC_RSA_encode_pss_work(&options, L)`, plus 1 for a nonempty salt |
| `TC_RSA_decrypt_oaep`      | `TC_RSA_private_work(&key, A) + TC_RSA_oaep_work(&options, L)`                                   |

`A` is the number of blinding attempts, which must match `execution.random_attempts`. Each
rejected blinding factor costs one more attempt. `TC_RSA_private_work` selects the CRT cost when
`key->crt` is set and reads nothing else beyond `key->public_key`. Operations check the cost of
all `A` attempts before any arithmetic or RNG request. See the
[library work rules](api.md#work-budgets), and add costs with overflow checks, as the
[signing](../examples/rsa_sign.c) and [encryption](../examples/rsa_encrypt.c) examples do.

For reference, with exponent length `E`:

| Operation                | Work                                                           |
| ------------------------ | -------------------------------------------------------------- |
| Public operation         | `16*L + 16*E + 4`, or `16*E + 4` with a prepared key           |
| Private operation        | `32*L + 32*E + 8`, or `48*L + 32*E + 12` with CRT values       |
| Each blinding attempt    | `16*L + 1` more                                                |
| Public-key preparation   | `16*L + 1`                                                     |
| CRT validation           | `32*L + 1`                                                     |
| CRT derivation           | `48*L + 3`                                                     |
| Private-key validation   | `TC_RSA_VALIDATE_WORK(bits, attempts)`                         |
| Key generation, one step | `TC_RSA_KEYGEN_STEP_WORK(bits)` lets any pending unit progress |

## Verification

`TC_RSA_verify_v15_digest` verifies a SHA-1, SHA-224, SHA-256, SHA-384 or SHA-512 digest with
PKCS #1 v1.5 and the hash in `TC_RSA_v15_options`. `TC_RSA_verify_pss_digest` takes explicit
message hash, MGF hash and salt length, needs both hashes enabled, and adds a local hash context
and a 64-byte digest buffer to the stack. Validate certificate chains separately.

For repeated verification with one key, `TC_RSA_prepare_public_key` initializes a caller-owned
`TC_RSA_prepared_public_key` with a cache of one modulus width of limbs, a temporary workspace of
two widths and a budget of `16 * modulus_bytes + 1`. Keep the borrowed key and the cache alive and
unchanged until `TC_RSA_prepared_public_key_clear`, and verify with `TC_RSA_verify_v15_prepared`
or `TC_RSA_verify_pss_prepared` and a separate verification workspace.

## Encoding for card and hardware signing

`TC_RSA_encode_v15_digest` builds the complete EMSA-PKCS1-v1_5 representative of a digest for a
card or hardware key, with no hash context or RSA workspace. `TC_RSA_encode_pss_digest` builds an
EMSA-PSS representative with explicit, enabled message and MGF hashes and a caller-supplied salt
from a cryptographic random source, whose length matches the options. `emBits` is one less than
the modulus width. [Card-key authentication](credential-reader.md#card-key-authentication) shows a
card submission.

Output capacity is 128, 256, 384 or 512 bytes for an enabled RSA-1024, 2048, 3072 or 4096 size.
Failures preserve the
output and work, except a hash failure during PSS encoding, which wipes the output and consumes
work. Check the budget with `TC_RSA_encode_v15_work` or `TC_RSA_encode_pss_work` before drawing
digest or salt bytes from a random source, as `TC_key_challenge_prepare` does.

## Raw operations

`TC_RSA_raw_public` and `TC_RSA_raw_private` apply RSAEP/RSAVP1 and RSADP/RSASP1 ([RFC 8017,
sections 5.1 and 5.2](https://www.rfc-editor.org/rfc/rfc8017.html#section-5)) to one
caller-formatted representative of the modulus length, which must be less than the modulus, into
an output of at least the modulus length. They add no padding. `TC_RSA_raw_private` takes the
private exponent as a magnitude of 1 to `L` bytes.

## Key generation

`TC_RSA_keygen_init` and `TC_RSA_keygen_step` generate two-prime keys of an enabled size with
public exponent 65537 and no heap use. The modulus and private exponent need `bits/8` bytes, each
prime `bits/16` bytes and the exponent three bytes. Short outputs or workspace return
`TC_RSA_LIMIT`, and a NULL buffer or overlap `TC_RSA_ARGUMENT`, both with state, outputs and
workspace unchanged.

Zero `TC_RSA_keygen_state` before first use. State, scratch, output metadata and outputs must be
mutually disjoint and stay alive across steps. `TC_RSA_keygen_init` takes cumulative candidate and
RNG-request limits. Each `TC_RSA_keygen_step` takes a work allowance and returns
`TC_RSA_IN_PROGRESS` before exceeding it. Call it again with the same state and callbacks. The work
units are a candidate, a Miller-Rabin setup, a Miller-Rabin round and the final derivation of `n`
and `d`. A cancellation callback runs between units, and cancellation returns `TC_RSA_CANCELLED`
with retained secrets wiped.

The generator follows FIPS 186-5 appendix A.1.1:

- It sets the top two bits of each prime, which exceeds the `sqrt(2) * 2^(nlen/2 - 1)` lower
  bound.
- It rejects small-prime factors and any prime with `p - 1` divisible by 65537.
- It requires `|p - q| > 2^(nlen/2 - 100)`.
- It performs 65 independent Miller-Rabin rounds on each accepted candidate.
- It sets `d = e^-1 mod LCM(p - 1, q - 1)` and generates new primes in the rare case
  `d <= 2^(nlen/2)`.

Candidate residue checks, the prime-distance comparison, the GCD, the LCM and the derivation of `d`
run in time that depends only on the key size. Candidate search time reveals only how many
candidates were rejected. The RNG callback returns `TC_OK` only after filling the complete
request.

Outputs are written only after both primes, `n` and `d` are derived. RNG errors and terminal
limits preserve every output and wipe retained candidates. Call `TC_RSA_keygen_clear` after
success or when abandoning an operation. The fixed-width outputs serve directly as
`TC_RSA_private_key` views. Validate or test the key before provisioning it to
persistent storage.

## Private-key import

`TC_DER_private_key_info` in `<tiny_crypto/der.h>` reads DER PKCS #8 containers, version 0 or the
version 1 form with a public key ([RFC 5958](https://www.rfc-editor.org/rfc/rfc5958.html#section-2)),
into borrowed algorithm, key and optional attribute spans. Check the algorithm OID, parameters and
attributes before passing the key span to an algorithm-specific reader, and check public and
private key consistency before use.

`TC_DER_rsa_private` reads a DER PKCS #1 two-prime private key
([RFC 8017, Appendix A.1.2](https://www.rfc-editor.org/rfc/rfc8017.html#appendix-A.1.2)) into
borrowed magnitudes for all eight components. It checks structure and integer encoding only.
Multi-prime version 1 returns `TC_TLV_UNSUPPORTED`, and the output must be disjoint from the
encoding.

`TC_KEY_rsa_private_read` in `<tiny_crypto/key.h>` imports a PKCS #8 RSA key with
`TINY_CRYPTO_ENABLE_DER=ON`, also without X.509, into a `TC_KEY_rsa_private_key` with borrowed
components, attributes and algorithm parameters. An included public key must match the private
key's modulus and exponent, and an output that overlaps the encoding returns `TC_TLV_ARGUMENT`.

Before signing, pass the selected `TC_signature_algorithm` to
`TC_KEY_rsa_private_signature_check`. A `TC_KEY_RSA_PSS` key permits PSS only, within its encoded
digest, mask digest and minimum salt length. A `TC_KEY_RSA` key permits both schemes. Apply
application policy and check compiled algorithm support separately. Keep the source bytes
protected and unchanged while any imported view is in use.

The compiled [key-loading example](../examples/rsa_read.c) has PKCS #1 and PKCS #8 entry points
that validate the factors and CRT fields, set `TC_RSA_private_key.crt` and sign with one
caller-owned workspace. The PKCS #8 entry point checks that the key permits v1.5.
`example_sign_rsa_pkcs8_pss_sha256` signs with PSS, SHA-256/MGF1-SHA-256 and a 32-byte salt,
checking those choices against the key's restrictions before validation or RNG use. For repeated
signing, validate a parsed key once while its bytes stay unchanged.

## Private-key validation

`TC_RSA_validate_private_key` checks a borrowed `TC_RSA_private_key`. `d`, `p` and `q` are
nonempty magnitudes of at most the modulus length, with leading zeros accepted. Keep all five
components stable during validation. The checks are `n = p*q` with distinct odd factors of half
the modulus width, then FIPS 186-5 appendix A.1.1:

- `sqrt(2) * 2^(nlen/2 - 1) <= p, q`, checked exactly as `p^2 >= 2^(nlen - 1)`.
- `|p - q| > 2^(nlen/2 - 100)`.
- `2^(nlen/2) < d < LCM(p - 1, q - 1)` and `e*d = 1 mod LCM(p - 1, q - 1)`.
- The public exponent range of `TC_RSA_exponent_policy`. `TC_RSA_EXPONENT_FIPS` requires an odd
  `2^16 < e < 2^256`, which `TC_RSA_exponent_in_fips_range` tests. `TC_RSA_EXPONENT_ANY_ODD`
  accepts any odd `3 <= e < n` for keys outside FIPS 186-5, such as test vectors with `e = 3`.

Each factor then receives `TC_RSA_VALIDATION_ROUNDS` (65) Miller-Rabin rounds at the factor
width, and three is handled exactly. Supply an independent cryptographically secure random source
and at least 65 requests per factor, since rejection sampling can need extra requests.
`TC_RSA_LIMIT` reports exhausted requests, work or storage.

The GCD, LCM and comparisons on secret values run in time that depends only on the key size.
Validation returns `TC_RSA_INVALID` early at a failed public or structural check: an exponent
outside the policy, a factor of the wrong width, a private exponent that is zero, even or at least
`n`, an even, equal or unit factor, or `n != p*q`. The remaining FIPS 186-5 criteria accumulate as
masks without branching, and Miller-Rabin stops at the first composite factor. Early-return timing
can reveal which check rejected a key, and every such key is invalid.

For a fixed composite candidate, the Miller-Rabin bound is `4^-rounds`. The 65-round policy gives
a conservative combined bound of `2^-129` across two factors, assuming independent uniform bases
([FIPS 186-5 Appendix C.1][fips1865]). Key-strength policy, provenance and authorization remain
application checks.

`TC_RSA_VALIDATE_WORK(bits, A)` is the budget for a `bits`-bit key with at most `A` requests per
factor. Evaluate it with `uint32_t` operands, also on 16-bit targets. The full cost is checked
before any arithmetic or RNG request.

The compiled [validation example](../examples/rsa_validate.c)
([header](../examples/rsa_validate.h)) exposes `example_validate_rsa_key`, which allows four RNG
requests per required round. Accept the components only on `TC_RSA_OK`, and treat `TC_RSA_LIMIT`
as an incomplete validation.

## CRT values

For imported CRT components, validate the private key first, then call `TC_RSA_validate_crt` with
a `TC_RSA_crt` holding `dp`, `dq` and `q_inverse` to compare the reduced exponents and check the
coefficient and its range. `TC_RSA_derive_crt` computes them from `n`,
`e`, `d`, `p` and `q` into caller-owned outputs of half the modulus length each, written together
on success. Both use the CRT workspace, and a validation workspace can be reused.

Assign the validated view to `TC_RSA_private_key.crt`. Signing, decryption and
`TC_RSA_private_work` then use the CRT kernel with unchanged PKCS #1 encoding. It blinds modulo
`n`, performs two half-width exponentiations and checks the recombined result with the public
exponent.

## Signing

`TC_RSA_sign_v15_digest` signs a precomputed SHA digest with PKCS #1 v1.5.
`TC_RSA_sign_pss_digest` takes `TC_RSA_pss_options` with the message hash, MGF hash and salt
length, and needs both hashes enabled. The salt length is at most `L - H - 2` for message-hash
length `H`, and a nonempty salt adds one RNG request. The signature buffer needs at least the
modulus length.

The compiled [v1.5 signing example](../examples/rsa_sign.c) ([header](../examples/rsa_sign.h))
declares `example_sign_rsa_v15_digest`, which builds a workspace view over caller-owned storage and
budgets four blinding attempts.

## OAEP encryption

`TC_RSA_encrypt_oaep` follows
[RFC 8017, section 7.1.1](https://www.rfc-editor.org/rfc/rfc8017.html#section-7.1.1) with
`TC_RSA_oaep_options` holding the message hash, MGF hash and borrowed label, both hashes enabled.
The message holds up to `modulus_bytes - 2*hash_digest_bytes - 2` bytes. Use `{NULL, 0}` for an
empty message or label. The call requests one seed, ignores `random_attempts` and checks the work
before the seed request. The ciphertext needs at least the modulus length.

The compiled [SHA-256 example](../examples/rsa_encrypt.c) uses SHA-256 for both hashes, computes
the work budget and checks it for overflow before requesting randomness.

## OAEP decryption

`TC_RSA_decrypt_oaep` takes `TC_RSA_oaep_options` with both enabled hashes and the label
(`{NULL, 0}` when empty), and a ciphertext of the modulus length. Allocate at least
`modulus_bytes - 2*hash_digest_bytes - 2` plaintext bytes. A smaller buffer returns
`TC_RSA_LIMIT` before the private-key operation. That check and the work check use only public
sizes, draw no randomness and consume no work, so the status never distinguishes valid from
invalid padding (RFC 8017 section 7.1.2).

Decoding runs in scratch, and wrong labels and invalid padding return `TC_RSA_INVALID`.

## Side channels

Private exponentiation processes padded exponent widths with fixed loop counts, and arithmetic
selection avoids secret-indexed memory. RNG rejection sampling has a variable attempt count, and
component encodings expose their public byte lengths. Constant-time behavior depends on the
compiler and target and has no independent certification.

## C++11

`<tiny_crypto/rsa.hpp>` wraps each C function as `tiny_crypto::rsa_<name>`, such as
`rsa_sign_pss_digest`, with the same results and lifetimes, no allocation and no exceptions.
Wrappers take references to keys, workspaces, budgets and `rsa_execution` objects. Encoders and raw
operations take the output as `tiny_crypto::buffer` or a C array. `rsa_decrypt_oaep` takes the
output length by reference, `rsa_validate_private_key` defaults to `TC_RSA_EXPONENT_FIPS`, and
`rsa_modulus_supported` and `rsa_exponent_in_fips_range` return `bool`. `rsa_workspace_for(words)`
builds a borrowed view over a `TC_RSA_word` array. Copies of a view share its scratch, so keep the
array alive and exclusive to one operation.

```cpp
TC_RSA_word words[TC_RSA_RAW_PUBLIC_WORKSPACE_WORDS(2048)];
const tiny_crypto::rsa_workspace workspace = tiny_crypto::rsa_workspace_for(words);
uint8_t representative[256];
TC_work_budget work = {tiny_crypto::rsa_public_work(key)};
if (tiny_crypto::rsa_raw_public(key, signature, workspace, representative, work) != TC_RSA_OK)
  return false; /* representative is unchanged */
```

[fips1865]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
