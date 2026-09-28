# HKDF

Enable `TINY_CRYPTO_ENABLE_HMAC`, `TINY_CRYPTO_ENABLE_HKDF`, and at least one
SHA family in CMake. Include `<tiny_crypto/hkdf.h>` for C or
`<tiny_crypto/hkdf.hpp>` for C++.

The API implements RFC 5869 extract and expand using HMAC-SHA-1, SHA-224,
SHA-256, SHA-384, or SHA-512 when the corresponding hash is enabled. Use
`TC_HKDF_SHA256_derive` for one output. It extracts a PRK, expands the requested
key, then clears the PRK. The [C example](../examples/hkdf.c) checks every
return value and clears its input and output after use.

`extract` and `derive` take the input keying material as an array of
`TC_bytes` spans, which the HMAC reads in order as one concatenated input. Pass
one span for an ordinary secret.

For NIST SP 800-56C revision 1, pass the shared secret `Z` as the input keying
material and the protocol's encoded `FixedInfo` as `info`. Revision 2 permits a
hybrid shared secret `Z || T`: pass `Z` and `T` as two spans. The library reads
them in place without assembling another buffer. Applications construct `FixedInfo`
according to their protocol. The ACVP adapter's `uPartyInfo || vPartyInfo || l`
encoding belongs to the test fixture.

For several outputs from the same shared secret, call `extract` once, then
`expand` with a distinct `info` value for each output. Clear the PRK with
`TC_secure_zero` after the last expansion. Limit its use to this derivation
operation. Use domain-separated `info` values for different keys.

All lengths are bytes. `extract` writes one hash digest to a caller-owned PRK
buffer. `expand` needs a PRK of at least one digest and writes 1 through
`255 * HashLen` bytes. A null salt, input span, or `info` pointer is accepted
when its length is zero, and a zero `ikm_count` is an empty input. An omitted RFC salt has the standard all-zero HMAC key
effect. Outputs must not overlap any input span. Invalid arguments return
`TC_ERROR` without changing output. A failure after processing begins clears
output. The caller owns every input and output buffer and keeps inputs stable
until the function returns.

The NIST [SP 800-56C revisions 1 and 2](https://csrc.nist.gov/pubs/sp/800/56/c/r2/final)
cover more extraction and expansion combinations than this HKDF API. The
implemented scope is HMAC-based HKDF for the enabled SHA families. The pinned
[ACVP corpus](../tests/vectors/kdf/acvp_hkdf/README.md) checks SHA2-224/256/384/512
for both revisions. The library holds no ACVP or FIPS validation.
