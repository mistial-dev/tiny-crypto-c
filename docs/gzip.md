<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# GZIP decoding

Enable `TINY_CRYPTO_ENABLE_GZIP` (direct-source builds: `TC_ENABLE_GZIP=1`) and include
`<tiny_crypto/gzip.h>`. The desktop profile enables it, and the `full`, `piv` and `twic`
[application targets](targets.md) enable it in every profile for compressed card certificates. The
decoder builds independently of the cryptographic algorithms and certificate parsers.

`TC_GZIP_decode` takes the complete input, a `TC_GZIP_workspace`, a remaining work budget, output
storage and an output-length pointer. All storage is caller-owned and must be disjoint. The
workspace needs no initialization and can be reused across calls.

```c
enum { CERTIFICATE_CAPACITY = 4096, DECODE_WORK_LIMIT = 100000 };
uint8_t certificate[CERTIFICATE_CAPACITY];
TC_GZIP_workspace workspace;
size_t work = DECODE_WORK_LIMIT;
size_t certificate_length;
const TC_buffer output = {certificate, sizeof certificate};

/* compressed is a TC_bytes span over the received GZIP member. */
TC_GZIP_result result = TC_GZIP_decode(compressed, &workspace, &work, output,
                                       &certificate_length);
if (result == TC_GZIP_OK) {
    /* Parse the complete certificate, then verify its signature and trust. */
}
TC_secure_zero(certificate, sizeof certificate);
```

Choose the capacity and budget for the objects the application accepts. Work counts input bits,
Huffman table entries, expanded bytes and checksum bytes, so the bound is the same on every
processor. Each call consumes the budget, and on LIMIT the unspent remainder stays in `*work`.
Refill it before an independent operation. See [work budgets](api.md#work-budgets).

## Results

| Result                | Meaning                                                            |
| --------------------- | ------------------------------------------------------------------ |
| `TC_GZIP_OK`          | Writes the decoded length. Bytes past it stay unchanged.           |
| `TC_GZIP_LIMIT`       | Output capacity or work ran out.                                   |
| `TC_GZIP_INVALID`     | Malformed framing or compressed data, or a checksum/size mismatch. |
| `TC_GZIP_UNSUPPORTED` | Unsupported compression method.                                    |
| `TC_GZIP_ARGUMENT`    | Invalid pointer or overlapping storage. All storage is preserved.  |

Failures other than `TC_GZIP_ARGUMENT` clear the whole output capacity and leave the length
parameter unchanged. The workspace is cleared after processing.

## Format support

The decoder handles stored, fixed-Huffman and dynamic-Huffman DEFLATE blocks, optional GZIP header
fields and concatenated members. Each member has its own history, CRC32 and size checks, while
output capacity and work cover the whole input. Trailing bytes outside a member fail. Decoded
output doubles as back-reference history.

GZIP checksums detect accidental corruption. Authenticate the decoded credential with signature
and trust validation.

## C++

`tiny_crypto::GZIPDecoder` in `<tiny_crypto/gzip.hpp>` owns one reusable workspace. `decode` takes
the same spans as the C function, with work and length by reference:

```cpp
#include <tiny_crypto/gzip.hpp>

/* The decoder owns its workspace, so keep it out of small stacks. */
static tiny_crypto::GZIPDecoder decoder;

TC_GZIP_result inflate(TC_bytes compressed, uint8_t (&decoded)[4096], size_t& length)
{
  size_t work = 100000;
  return decoder.decode(compressed, work, TC_buffer{decoded, sizeof decoded}, length);
}
```

`decoder.decode(compressed, work, decoded, length)` infers the size of a C array.

## PIV certificates

`TC_PIV_certificate_read` reports compressed certificate bytes as `TC_PIV_CERTIFICATE_GZIP`.
`TC_PIV_certificate_decode` reads the container, decompresses a GZIP certificate and checks that the
result is one DER SEQUENCE. Require the X.509 parser to consume the entire result.

## Tests

```sh
ctest --test-dir build -R '^test_(inflate|gzip_decode|gzip_differential|gzip_corpus)$' --output-on-failure
```

The differential test uses Python's zlib across compression levels and strategies to check decoded
bytes, corrupted checksums, concatenated members and short output capacity. With the default
`TINY_CRYPTO_TEST_TLV_CORPUS` of `tests/vectors`, `test_gzip_corpus` compares the SD33 compressed
certificate objects with Python's decoder and rejects checksum mutations.
`test_piv_certificate_corpus` uses the same corpus to check the certificate containers, including
PIV/TWIC profile mismatches and extra fields, without decompression. See
[Testing](testing.md#fuzzing) for the bounded decoder fuzz harness.
