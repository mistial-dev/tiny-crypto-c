<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# HKDF

Enable `TINY_CRYPTO_ENABLE_HMAC`, `TINY_CRYPTO_ENABLE_HKDF` and at least one SHA family. Include
`<tiny_crypto/hkdf.h>` for C or `<tiny_crypto/hkdf.hpp>` for C++.

The API implements RFC 5869 extract and expand with HMAC-SHA-1, SHA-224, SHA-256, SHA-384 or
SHA-512. Each enabled hash has `TC_HKDF_SHA*_extract`, `TC_HKDF_SHA*_expand` and
`TC_HKDF_SHA*_derive`.

## Quick start

`TC_HKDF_SHA256_derive` extracts a PRK, expands one output and clears the PRK. The
[C example](../examples/hkdf.c) runs it on the RFC 5869 appendix A.1 inputs, and
`test_hkdf_example` builds and runs that example.

```c
#include <tiny_crypto/hkdf.h>

/* Derive a 32-byte session key from a shared secret. */
TC_status derive_session_key(const uint8_t* secret, size_t secret_length,
                             const uint8_t* salt, size_t salt_length,
                             uint8_t key[32])
{
  static const uint8_t info[] = "example session key v1";
  /* The input keying material is a list of spans. A hybrid secret Z || T
   * from SP 800-56C revision 2 passes as two entries. */
  const TC_bytes ikm[] = {{secret, secret_length}};
  const TC_status status =
      TC_HKDF_SHA256_derive((TC_bytes){salt, salt_length}, ikm, 1,
                            (TC_bytes){info, sizeof info - 1}, (TC_buffer){key, 32});

  /* Argument errors leave key unchanged. Later failures wipe it. */
  return status;
}
```

Wipe the secret with `TC_secure_zero` when it is no longer needed, and wipe `key` when the session
ends.

## Inputs and outputs

`extract` and `derive` take the input keying material as an array of `TC_bytes` spans that HMAC
reads in order as one input. Pass one span for an ordinary secret. A zero `ikm_count` is an empty
input, and an empty salt acts as the RFC's all-zero HMAC key.

For NIST SP 800-56C revision 1, pass the shared secret `Z` as the input keying material and the
protocol's encoded `FixedInfo` as `info`. For a revision 2 hybrid secret `Z || T`, pass `Z` and `T`
as two spans, which the library reads in place. Applications build `FixedInfo` for their protocol.
The ACVP adapter's `uPartyInfo || vPartyInfo || l` encoding belongs to the test fixture.

To derive several outputs from one shared secret, call `extract` once, then `expand` once per
output with a distinct, domain-separated `info`. Use the PRK only for this derivation and clear it
with `TC_secure_zero` after the last expansion.

Lengths are in bytes. `extract` writes one digest to a caller-owned PRK array. `expand` needs a PRK
of at least one digest. `expand` and `derive` write exactly `output.capacity` bytes, from 1 through
`255 * HashLen`.

## Failure behavior

The functions return `TC_OK` or `TC_ERROR`. The output must be disjoint from every input span and
from the `ikm` array. Argument errors leave the output unchanged, and a later failure clears it.
See [failure state and wiping](api.md#failure-state-and-wiping) and
[input stability](api.md#input-stability-and-overlap).

## Conformance and limitations

NIST [SP 800-56C revisions 1 and 2](https://csrc.nist.gov/pubs/sp/800/56/c/r2/final) allow more
extraction and expansion combinations. This API covers HMAC-based HKDF for the enabled SHA
families. The pinned [ACVP corpus](../tests/vectors/kdf/acvp_hkdf/README.md) checks
SHA2-224/256/384/512 for both revisions. The library holds no ACVP or FIPS validation.
