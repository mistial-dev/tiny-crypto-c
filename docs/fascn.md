<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# FASC-N identifiers

Include `<tiny_crypto/fascn.h>` and enable `TINY_CRYPTO_ENABLE_FASCN`. `TC_FASCN_read` decodes a
25-byte FASC-N into numeric fields. It checks the sentinels, field separators, decimal digits, odd
parity and longitudinal checksum of
[PACS TIG v2.3, sections 6.1–6.3](https://www.idmanagement.gov/docs/pacs-tig-scepacs.pdf).

Agency, system and organization have four digits, credential six and person ten. Series, issue,
category and association have one each. `TC_FASCN_write` restores leading zeros and writes exactly
`TC_FASCN_BYTES`, including parity and checksum. A value wider than its field returns
`TC_TLV_ARGUMENT`, and a short output buffer returns `TC_TLV_LIMIT`.

Both functions write output only on `TC_TLV_OK` and need disjoint input and output. The decoded
structure holds values only, with no borrowed pointers. The codec uses fixed-size local storage.

```c
TC_FASCN fields;
uint8_t encoded[TC_FASCN_BYTES];
TC_TLV_result result = TC_FASCN_read(input, &fields);
if (result != TC_TLV_OK) return result;
result = TC_FASCN_write(&fields, (TC_buffer){encoded, sizeof encoded});
if (result != TC_TLV_OK) return result;
```

The codec checks syntax only. Category values and other issuer policy need application checks.
Authenticate the containing object and apply the selected PIV or TWIC identifier policy before
using the identifier.

## NEXGEN TWIC UUIDs

Include `<tiny_crypto/twic_uuid.h>` and enable `TINY_CRYPTO_ENABLE_TWIC_UUID`, which requires FASC-N
support. TWIC Part 2 v5 Appendix D defines the mapping. `TC_TWIC_uuid_read` checks the NEXGEN
namespace, version, variant and reserved bits and returns the 14-digit agency, system and
credential number as a `uint64_t`. `TC_TWIC_uuid_write` writes the 16-byte UUID for a number up to
99999999999999 and returns `TC_TLV_ARGUMENT` above that. Both preserve output on error.

`TC_TWIC_uuid_match` compares a UUID with the first three fields of a decoded FASC-N. Use its match
result only after `TC_TLV_OK`. The UUID omits series, issue and person, which remain part of the
full FASC-N identity. Use this binding for the TWIC application. PIV-I activation can replace the
PIV application's FASC-N with a placeholder, which needs its own application policy.
