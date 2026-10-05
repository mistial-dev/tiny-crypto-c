<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# MD5 download checksums

Enable `TINY_CRYPTO_ENABLE_MD5=ON` (on by default in the desktop profile) and include
`<tiny_crypto/md5.h>`. MD5 exists to check published download checksums such as the TSA CCL.
Its collision resistance is broken, so a download that affects credential acceptance needs
authenticated transport or trusted provisioning.

`TC_MD5_init`, `TC_MD5_update` and `TC_MD5_final` hash chunked input, and `TC_MD5_digest` hashes
one buffer. The digest is `TC_MD5_DIGESTLEN` (16) bytes. Hash the exact downloaded bytes,
including line endings, and compare the digest with the decoded expected checksum once the file
is complete.

Initialize a context before first use and again after finalization. The context must be disjoint
from input and output. One-shot input and output may overlap. `TC_MD5_final` and
`TC_MD5_ctx_clear` wipe the context. Other failure behavior follows the
[library rules](api.md#failure-state-and-wiping).

In C++11, `tiny_crypto::MD5` from `<tiny_crypto/hash.hpp>` provides `update`, `finish`, `reset`
and a static `digest` over `bytes` and `buffer` spans or C arrays. A successful `finish` resets the
object for another message, and destruction clears it.

The implementation follows [RFC 1321](https://www.rfc-editor.org/rfc/rfc1321.html) and shares
64-byte buffering and padding with the SHA-1/SHA-224/SHA-256 core. Length encoding uses the low
64 bits of the bit count. With `TC_AVR_PROGMEM`, AVR constant tables live in program memory.

`test_md5` and `test_cpp_md5` cover RFC known answers, padding-boundary answers at every split, a
million-byte message, the wipe after finalization, invalid arguments and supported overlap:

```sh
ctest --test-dir build --output-on-failure -R '^test_(cpp_)?md5$'
```

The [CCL external-file test](twic-ccl.md#tests) checks a downloaded list against its separately
supplied checksum.
