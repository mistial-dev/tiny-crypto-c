<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# C++ wrappers

The C++11 wrappers live in namespace `tiny_crypto`. Each `.hpp` header wraps
the C header of the same name and builds only the parts its configuration
enables. `<tiny_crypto/tiny_crypto.hpp>` includes every enabled wrapper. The
C contracts in [Working with the API](api.md) apply unchanged: results,
failure and wipe rules, input stability and work budgets.

## Quick start

```cpp
#include <tiny_crypto/hash.hpp>

/* Check an HMAC-SHA-256 tag received with a message, then hash the message
 * for a log record. */
TC_status accept_message(tiny_crypto::bytes key, tiny_crypto::bytes message,
                         tiny_crypto::bytes received_tag,
                         uint8_t (&digest)[tiny_crypto::SHA256::digest_size])
{
  /* verify compares received_tag.length bytes in constant time. */
  TC_status status = tiny_crypto::HMAC_SHA256::verify(key, message, received_tag);
  if (status != TC_OK)
    return status; /* TC_MISMATCH for a wrong tag, TC_ERROR for bad arguments */

  tiny_crypto::SHA256 hash;
  status = hash.update(message);
  if (status == TC_OK)
    status = hash.finish(digest);
  return status; /* The destructor wipes the hash context on every path. */
}
```

The Arduino-style examples [`aes_ctr.cpp`](../examples/aes_ctr.cpp),
[`sha256.cpp`](../examples/sha256.cpp), [`des_ctr.cpp`](../examples/des_ctr.cpp)
and [`kbkdf.cpp`](../examples/kbkdf.cpp) build and run on the host as
`test_example_*`.

## Conventions

- Calls are `noexcept`, allocate nothing, throw nothing and need no standard
  library.
- Every call that returns a status, result enumerator, size or work value is
  marked `TC_CPP_NODISCARD`. That is `[[nodiscard]]` in C++17 and
  `warn_unused_result` on GCC and Clang in C++11. Build with
  `-Wunused-result` enabled, the default on GCC and Clang, so a discarded
  verification or cipher result is reported.
- Results are the C result types, such as `TC_status`, `TC_EC_result`,
  `TC_RSA_result` and `TC_TLV_result`. Typedefs such as `ec_result` and
  `rsa_result` name them in the namespace.
- `tiny_crypto::bytes` is `TC_bytes` and `tiny_crypto::buffer` is `TC_buffer`.
  Keys, IVs, AAD, messages and received tags are `bytes` spans. Outputs are
  `buffer` spans or fixed-size C arrays whose size is part of the type. Array
  overloads deduce the span length.
- Two kinds of call take a pointer. Block-mode calls (`encrypt_cbc`,
  `xcrypt_ctr` and the others), `AES_dynamic` CBC and `GCM::encrypt_update`
  transform a caller buffer in place and take a pointer and length or an
  array. `encrypt_ecb` and `decrypt_ecb` transform one block in place.
- Wrappers add length checks before the C call. A wrong key or IV length, or a
  digest buffer whose capacity differs from the digest size, returns
  `TC_ERROR`. Every argument error leaves outputs unchanged.

`tiny_crypto::ct_equal(a, b)` compares two `bytes` spans. It returns `TC_OK`
for equal contents and lengths, `TC_MISMATCH` when the contents or the lengths
differ, and `TC_ERROR` for a span with NULL data and a nonzero length. Lengths
are public. Timing depends on the shorter length and is independent of content.

## Object lifecycle

Cipher, hash, MAC, DRBG, GZIP, PIV SM and PIV link classes own their C state.
They delete their copy operations, so key material and generator state are
never duplicated. `TLVReader` holds only a cursor over borrowed input, so it
may be copied, and a copy acts as a saved position. `drbg`, `piv_sm` and
`piv_link` also delete their move operations. Destruction clears the context.
Keyed classes follow init, update, finish or clear:

| Class              | Key                                                | finish                                                            |
| ------------------ | -------------------------------------------------- | ----------------------------------------------------------------- |
| `AES`              | `TC_AES_KEYLEN` bytes, optional 16-byte IV         | none                                                              |
| `GCM`              | `TC_AES_KEYLEN` bytes and an IV                    | `encrypt_finish` writes `tag_length()` bytes and consumes the key |
| `AES_CMAC`         | `TC_AES_KEYLEN` bytes                              | writes a 16-byte tag and consumes the key                         |
| `AES_dynamic`      | 16, 24 or 32 bytes                                 | none                                                              |
| `AES_dynamic_CMAC` | 16, 24 or 32 bytes                                 | `final` writes a 16-byte tag and consumes the key                 |
| `DES`              | 8 bytes, or 16 or 24 with TDEA, optional 8-byte IV | none                                                              |
| `DES_CMAC`         | 8, 16 or 24 bytes                                  | writes an 8-byte tag and consumes the key                         |
| `DES_ISO9797`      | algorithm, padding and 16 or 24 bytes              | writes the 8-byte MAC and consumes the key                        |
| `HMAC_SHA*`        | any length                                         | writes `tag_size` bytes and consumes the key                      |
| `KMAC256`          | any length, optional customization                 | `final` writes `out.capacity` bytes and consumes the key          |
| `SHA*`, `MD5`      | none                                               | writes the digest and starts the next message                     |

A default-constructed object, a failed `init`, a completed finish and `clear`
all leave a keyed object unkeyed. `KMAC256` is the exception for `init`: a
rejected `init` leaves the object unchanged. Later update and finish calls return
`TC_ERROR` until the next successful `init`. `clear` wipes the key schedule
early, for example after an abandoned message. A hash object starts a message
at construction, and `reset` discards a partial message. Compare a received
tag with a `*_verify` wrapper or `tiny_crypto::ct_equal`, which run in
constant time.

`drbg` uninstantiates on destruction. `random_source()` returns a
`TC_random_source` for the C APIs, and the `drbg` object must outlive it.
`TLVReader::init` and `init_child` leave the reader unusable on failure, and
`next` on an unusable reader returns `TC_TLV_ARGUMENT`. `GZIPDecoder` owns
reusable decoding scratch, and input and output stay caller-owned. The
`piv_sm` session is cleared on destruction.

`piv_link` follows init, commands and clear. `init`, `select`, `get_data`,
`verify_status` and `pin_verify` forward to the C functions, `status` and
`info` report the link state, and `native` returns the `TC_PIV_link` for the C
layers built on it. The destructor calls `TC_PIV_link_clear`, which wipes the
borrowed command scratch, so the scratch buffer and the transport context
outlive the object.

`piv_sm_key_request`, `piv_link_secure` and `piv_link_unsecure` in
`piv_sm_apdu.hpp` take a `piv_link` and a `piv_sm` by reference. A secured
link borrows the session, the workspace and the secure messaging scratch.
Declare the `piv_sm` before the `piv_link`, so the link is destroyed first and
clears the bound session while it exists. `piv_sm::native` returns the
`TC_PIV_SM`. `piv_discovery_get` and `piv_vci_establish` in `piv_vci.hpp` take
the `piv_link` by reference and follow the same lifetime.

`piv_inventory` in `piv_catalog.hpp` wraps a `TC_PIV_inventory` over a caller
object array. `read` takes the `piv_link`, an optional plan, the pool and the
work counter. `find`, `size` and `operator[]` return the entries, which borrow
the pool. The destructor calls `TC_PIV_inventory_clear`, which wipes the pool
bytes the objects use and the object array, so both outlive the object.
Copying and moving are deleted. `piv_catalog_count`, `piv_catalog_at` and
`piv_catalog_find` wrap the catalog lookups.

`piv_key_prove` in `piv_key_proof.hpp` takes the `piv_link`, the request, the
provider, the workspace and the work budget by reference.
`piv_key_parameters_select` wraps the key policy.

## GCM streaming

`GCM` streams encryption only. Supply all AAD before the first
`encrypt_update`, which encrypts data in place. `encrypt_finish` writes exactly
`tag_length()` bytes and consumes the key. Decrypt GCM with the one-shot
`gcm_decrypt` or `gcm_decrypt_short_tag`, which verify the tag before any
plaintext is released. A `GCM` object initialized with a short tag uses the
`_short_tag` rules of [tag lengths](api.md#tag-lengths).

## One-shot functions

Hash, HMAC, MD5 and KMAC256 inputs are `TC_bytes` spans in C and `bytes` in
C++. Fixed-length digests and full HMAC tags go to digest-sized arrays. A
one-shot HMAC writes `tag.capacity` bytes, from `TC_HMAC_MIN_TAG_LEN` to the
digest length, and verification compares `tag.length` bytes. KMAC256 writes
`out.capacity` bytes, and that length is part of the MAC input.

```c
uint8_t tag[16];
TC_status status = TC_HMAC_SHA256_digest((TC_bytes){key, sizeof key},
                                         (TC_bytes){message, message_length},
                                         (TC_buffer){tag, sizeof tag});
if (status != TC_OK)
  return status; /* tag is unchanged */
```

The one-shot MAC wrappers are `aes_cmac`, `des_cmac` and `des_iso9797_mac`,
each with `*_verify`, `*_short_tag` and `*_verify_short_tag` forms. They take
the key, message and tag as spans and follow the [tag length](api.md#tag-lengths)
rules of their C functions. The one-shot GCM, CCM, EAX, EAX' and SIV wrappers
take the key as `bytes`. GCM, CCM, EAX and EAX' need `TC_AES_KEYLEN` bytes and
SIV needs `TC_AES_SIV_KEYLEN`.

The key wrap functions `aes_kw_wrap`, `aes_kw_unwrap`, `aes_kwp_wrap` and
`aes_kwp_unwrap` take the KEK, input and output as spans. `aes_kwp_unwrap`
reports the key data length through a `size_t&`. The KEK length follows the
build policy that `TC_AES_KW_KEK_LENGTH_SUPPORTED` reports.

The APDU functions `apdu_command_size`, `apdu_command_encode`,
`apdu_response_read` and `apdu_status_classify` forward to the
[APDU codec](apdu.md). Commands and responses keep the C structures, named
`apdu_command` and `apdu_response`. The [PIV card command](piv-card.md) functions
`piv_application_read` and `piv_status_classify` forward to their C functions.

The KDF wrappers `hkdf_sha*_extract`, `hkdf_sha*_expand`, `hkdf_sha*_derive`,
the `sskdf_sha*` functions and the KBKDF families forward to their C functions
with the same span arguments. The EC and RSA wrappers in `ec.hpp` and
`rsa.hpp` take references in place of pointers and keep the C statuses,
execution descriptors and work rules.

```cpp
#include <tiny_crypto/des.hpp>

/* Check a retail MAC (ISO/IEC 9797-1 algorithm 3) received with a message. */
bool retail_mac_valid(const uint8_t (&key)[16], tiny_crypto::bytes message,
                      const uint8_t (&received)[TC_DES_BLOCKLEN])
{
  tiny_crypto::DES_ISO9797 mac;
  uint8_t computed[TC_DES_BLOCKLEN];
  if (mac.init(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, key) != TC_OK ||
      mac.update(message) != TC_OK || mac.finish(computed) != TC_OK)
    return false; /* The destructor wipes the key schedule. */
  const bool valid = tiny_crypto::ct_equal({computed, sizeof computed},
                                           {received, sizeof received}) == TC_OK;
  TC_secure_zero(computed, sizeof computed);
  return valid;
}
```

For a single buffer, one call does the same and returns `TC_OK`,
`TC_MISMATCH` or `TC_ERROR`:

```cpp
#include <tiny_crypto/des.hpp>

TC_status retail_mac_check(const uint8_t (&key)[16], tiny_crypto::bytes message,
                           const uint8_t (&received)[TC_DES_BLOCKLEN])
{
  return tiny_crypto::des_iso9797_verify(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, {key, 16},
                                         message, {received, 8});
}
```

## Testing

The doctest suites in `tests/cpp` run as `test_cpp_*`. The build compiles
`tests/cpp/header_compile.cpp`, which instantiates every wrapper, as C++17 with
warnings treated as errors. `tests/cpp/copy_contract.cpp` asserts the copy and
move rules of [Object lifecycle](#object-lifecycle) in C++11.
`test_cpp_nodiscard` checks that a discarded result is diagnosed. Run them with:

```sh
ctest --test-dir build -R '^test_cpp_' --output-on-failure
```
