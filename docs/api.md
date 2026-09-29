<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Working with the API

Include the public header for the operation you need. The C headers support
C99 and C++11. C++ wrappers live in `tiny_crypto`. Build options determine which
implementations are linked. See the [configuration options](../README.md#configuration)
and [installed examples](testing.md).

## Buffers and lifetimes

`TC_bytes` describes borrowed, immutable bytes:

```c
TC_bytes message = {encoded, encoded_length};
```

The structure owns no storage. Keep `encoded` alive and unchanged while a
reader, parsed object, or validation result refers to it. An empty span may use
`NULL` with length zero. Individual schemas can require nonempty input.

Parsers return views into the input. Reusing a receive buffer invalidates those
views. Finish operations that consume the views before receiving another object,
or copy the specific bytes your application needs to retain.

Output arrays use explicit capacities. A returned length describes the bytes
written. Spare capacity follows the operation's documented contract.
Check each declaration for permitted in-place use and overlap restrictions.
For key derivation, see the [HKDF guide](hkdf.md) for PRK lifetime, output
limits, and hybrid shared-secret inputs.

`TC_buffer` pairs writable `data` with byte `capacity`. `TC_random_source` pairs
a random-fill callback with its context. Random callbacks must fill the entire
requested buffer before returning `TC_OK`. `TC_work_budget.remaining` is a
shared 32-bit operation allowance. Calls reduce it by work completed on success
and failure.

## Workspaces and limits

Workspaces hold caller-owned scratch. Use static or application-owned storage
for large RSA and certificate-validation workspaces on constrained devices.
Keep workspace metadata alive for every operation that refers to it.

The [validation setup guide](validation.md) shows checked arena sizing and the
micro, mini, and desktop capacity presets. RSA calls group scheme settings in
operation options and random/work limits in an execution descriptor.

Calls sharing writable scratch require application serialization. Independent
contexts and disjoint scratch can be used concurrently, subject to provider and
storage callback requirements.

Parsing limits bound input size, value size, element count and nesting depth.
Where an operation takes a work counter, initialize it before the operation and
reuse it across the related calls. A limit result requires an explicit application
decision about retrying with additional resources. Work units follow the API's
accounting rules and are independent of elapsed time.

## Parsing, signatures and trust

Choose the operation that answers your application's question:

- Readers check the documented encoding and schema and return borrowed views.
- Signature verification authenticates bytes using a supplied key.
- Path validation checks a certificate against supplied trust and policy.
- CMS credential validation combines content binding, signature verification,
  path construction and CRL revocation checking for one selected signer.

CMS parsing and key-based signature verification use `<tiny_crypto/cms.h>`.
Include `<tiny_crypto/cms_validation.h>` only when signer discovery, paths, or
revocation are part of the application. `<tiny_crypto/validation.h>` adds the
shared arena and policy context for complete CMS and X.509 validation. Both
validation headers are selected by `TINY_CRYPTO_ENABLE_CMS_VALIDATION`.

`<tiny_crypto/x509_ocsp.h>` encodes bounded OCSP requests and verifies complete
DER OCSP responses, including stapled responses. Supply the certificate and its
issuer from a validated path, a signature provider, a `TC_X509_revocation_time`
and a `TC_X509_path_workspace`. The BasicOCSPResponse inside the response is
parsed under the same `TC_TLV_limits` as the outer response. A delegated
responder is validated as a one-certificate path below the issuer with the
OCSPSigning purpose. `responder_certificate` then borrows its certificate and
`responder_nocheck` reports `id-pkix-ocsp-nocheck`. Without nocheck, the caller
establishes the delegate's revocation status (RFC 6960 4.2.2.2.1).
`TC_X509_ocsp_request_encode` reports the required size with `TC_TLV_LIMIT`
for a short or empty buffer. OCSP requires SHA-1.

`TC_X509_ocsp_response_verify` returns `TC_TLV_OK` only for an authenticated,
fresh GOOD or REVOKED status, with the CRLReason when the response has one. An
authenticated unknown status and the unsigned error responses (internalError,
tryLater, sigRequired, unauthorized) return `TC_TLV_UNSUPPORTED`. CRL and OCSP
results share `TC_X509_revocation_status` and the freshness rule of
`TC_X509_revocation_time`. `TC_X509_path_check_revocation` accepts one OCSP
response per path member and falls back to CRLs for a member without an
accepted response. It accepts a delegate without nocheck only when the CRL
index proves that delegate unrevoked. The CMS and credential validation APIs
use CRL evidence only.

PIV/TWIC object policy and the final access decision require their own checks.
Select compatibility options explicitly, including TWIC signed/unsigned CHUID
profiles and CMS signed-attribute encoding.

`TC_PIV_printed_read` parses PIV printed information or decrypted TWIC DFC109
contents. Select the profile and whether the input includes the outer `53`
container. The returned text fields borrow the input buffer. PIV dates use
`YYYYMMMDD`. TWIC dates use `DDMMMYYYY`.

`TC_PIV_fingerprint_read` validates an INCITS 378-2004 minutiae record against
the PIV card profile. It checks the fixed header, two finger views, minutiae,
dimensions, resolution, quality values, and the required empty extension areas.
The accepted record remains in caller-owned storage for a biometric matcher.

`TC_PIV_face_read` validates INCITS 385-2004 record framing and each image block.
`TC_PIV_FACE_PROFILE_PIV` applies the SP 800-76-2 Full Frontal and minimum-width
requirements. `TC_PIV_FACE_PROFILE_TWIC` accepts the Basic records found on
TWIC credentials while retaining the structural, image-encoding, color-space,
source, pose, feature-point, and length checks. Use
`TC_PIV_face_image_read` to obtain a borrowed image and its dimensions.

`TC_PIV_biometric_validation_request.format` binds an authenticated CBEFF object
to its expected modality and record type. Set `require_current` when the CBEFF
validity period is part of the credential decision. The comparison uses the
shared validation-context time, including both boundary instants.
Iris credential validation reports unsupported because the library has no
ISO/IEC 19794-6 record reader.

After authenticating the Security Object and signed CHUID, call
`TC_PIV_printed_expiration_check`. It requires the printed date to match the
CHUID date and checks the application evaluation time through the end of that
day. A successful parse supplies structure only. Authentication and freshness
come from the validation calls.

The [credential validation example](credential-validation.md) composes certificate trust,
identifier checks, cancellation, fresh key possession, signed objects and a
bounded list of biometric objects using retained inputs. Reader commands live in the example
application's proof callback and transport layer.

`TC_PIV_CHUID_read` also provides `TC_CHUID_PROFILE_LEGACY_KEY_MAP`
for PIV-shaped CHUIDs containing the historical Authentication Key Map (`3D`).
Select this profile explicitly for compatible credentials. It accepts one map
of up to 512 bytes immediately before the signature and returns its borrowed
value in `authentication_key_map`. `signed_content` includes the map's exact
tag, length and value. Authenticate the signature before using the map.
An empty present map has a non-NULL pointer.
Current PIV and TWIC profiles retain their field schemas. See
[SP 800-73-2, Part 1, Table 8](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-73-2.pdf)
for the field definition.

`TC_PIV_CHUID_validate` is the public signed-CHUID composition workflow. Its
request binds borrowed CHUID bytes to identifiers and expiration from an already
validated card certificate, with an explicit PIV, TWIC Legacy, or TWIC NEXGEN
profile. `TC_validation_options` provides one evaluation time and signature
provider plus separate certificate and CRL-signer policies. Initialize a
`TC_validation_context` with held certificate/CRL trust and a sized
`TC_CMS_credential_workspace`. A successful `TC_PIV_CHUID_result` supplies the
authenticated object and signer to dependent biometric and Security Object
requests, which reject a result from another profile or evaluation time.
Callers retain responsibility for transport, cancellation status, and
authorization.

## Results and cleanup

Use the named results for the operation you called. `TC_status`, parser results,
signature results and credential verdicts have distinct contracts. Compare
against the exact success or acceptance enumerator. Avoid treating a result as
a Boolean or converting between enums numerically.

Setup helpers return `TC_result`. Successful setup returns `TC_RESULT_OK`.

Handle malformed input, unsupported algorithms, exhausted limits and unavailable
evidence explicitly. A successful parse supplies structure for later checks.
CMS and CVC credential workflows share `TC_credential_status`, including distinct
revoked, unavailable, unsupported, limit and error outcomes.
Accept a credential only after every required authentication and policy check
has succeeded.

Public declarations specify which outputs survive failure and which scratch or
work counters may change. Secret-producing operations also specify wiping
behavior. Clear application-held keys and plaintext with `TC_secure_zero` when
their lifetime ends. Release acquired snapshots on every exit path.

## Authenticated encryption

The one-shot AEAD functions in `<tiny_crypto/aes.h>` (GCM, CCM, EAX, EAX' and
SIV) share one contract.

- Encrypt writes `plaintext.length` bytes of ciphertext and `tag.capacity` tag
  bytes. Decrypt writes `ciphertext.length` bytes of plaintext and checks
  `tag.length` tag bytes. EAX' and SIV use fixed-size tag arrays.
- The text output capacity must be at least the text input length. Bytes past
  the text length are never written.
- Text input and output are the same buffer or fully disjoint. The tag is
  disjoint from the text output. SIV associated data is disjoint from the text
  output. A violation returns `TC_ERROR` before a write.
- The key, and the nonce and associated data of GCM, CCM, EAX and EAX', may
  share storage with the text output. Each is read in full before the first
  output write.
- The caller keeps the key, nonce, associated data, text input and received
  tag stable for the duration of the call. No other thread or DMA transfer may
  write them. GCM, CCM, EAX and EAX' decrypt read the ciphertext twice, once to
  authenticate it and once to decrypt it.
- `TC_ERROR` before any write reports a NULL key or tag, a NULL span with a
  nonzero length, a short text output, a forbidden overlap, or a nonce, tag or
  text length outside the mode's range.
- GCM, CCM, EAX and EAX' verify the tag before writing plaintext. SIV decrypt
  writes candidate plaintext first and recomputes the synthetic IV over the
  associated data and that plaintext (RFC 5297 section 2.7).
- After the argument checks, every failure wipes the text output. A tag that
  fails to verify returns `TC_MISMATCH`. A cipher backend failure returns
  `TC_ERROR`. In-place callers lose the input in both cases. The tag output is
  written only on success.

GCM decryption is one-shot. The streaming `TC_AES_GCM_ctx` API encrypts only.
Use `TC_AES_GCM_encrypt_short_tag` and `TC_AES_GCM_decrypt_short_tag` for the
4 and 8-byte tags of SP 800-38D appendix C.

```c
TC_status status = TC_AES_GCM_decrypt(key, (TC_bytes){iv, 12}, (TC_bytes){aad, aad_length},
                                      (TC_bytes){packet, packet_length},
                                      (TC_bytes){tag, 16},
                                      (TC_buffer){packet, packet_length});
if (status != TC_OK)
  return status; /* packet holds no plaintext */
```

## Tag lengths

`TC_MIN_TAG_LEN` in `config.h` sets one minimum tag length for CCM, EAX,
AES-CMAC and DES-CMAC. It defaults to 8 bytes, the 64-bit floor of SP 800-38B
Appendix A.2, and a build may raise it to 16. Values outside 8..16 stop the
build. A value above 8 also requires `TC_DES_ENABLE_CMAC=0`, since a DES-CMAC
tag holds at most 8 bytes.

| Mode | Default entry points | `_short_tag` entry points |
| --- | --- | --- |
| CCM | even lengths from `TC_MIN_TAG_LEN` to 16 | even lengths from 4 up to `TC_MIN_TAG_LEN - 1` |
| EAX | `TC_MIN_TAG_LEN`..16 | 1..`TC_MIN_TAG_LEN - 1` |
| AES-CMAC | `TC_MIN_TAG_LEN`..16 | 1..`TC_MIN_TAG_LEN - 1` |
| DES-CMAC | `TC_MIN_TAG_LEN`..8 | 1..`TC_MIN_TAG_LEN - 1` |
| GCM | 12..16 | 4 or 8 (SP 800-38D appendix C) |
| ISO 9797-1 | 8 | 4..7 |

Each length has exactly one entry point. The other entry point returns
`TC_ERROR` and leaves every output unchanged. A zero-length tag is never
accepted. Short tags are the leading bytes of the full tag. Call a
`_short_tag` form only when the protocol fixes that tag length and limits the
number of failed verifications for a key. EAX' is exempt from the minimum
because ANSI C12.22 fixes its tag at 4 bytes.

```c
/* A protocol with 4-byte CCM tags selects the short-tag call. */
TC_status status = TC_AES_CCM_decrypt_short_tag(key, (TC_bytes){nonce, 13},
                                                (TC_bytes){header, header_length},
                                                (TC_bytes){packet, packet_length},
                                                (TC_bytes){tag, 4},
                                                (TC_buffer){packet, packet_length});
if (status != TC_OK)
  return status; /* packet holds no plaintext */
```

## C++ wrappers

The C++11 wrappers in `tiny_crypto` return the C result types. Every call that
returns a status or result enumerator is marked `[[nodiscard]]` in C++17 and
`warn_unused_result` on GCC and Clang in C++11. Build with `-Wunused-result`
enabled (the default on GCC and Clang) so a discarded verification or cipher
result is reported. Wrapper calls are `noexcept`.

Cipher, hash and MAC classes own their C context, clear it on destruction and
delete their copy operations. A failed `init` of `AES`, `GCM`, `DES`,
`AES_dynamic`, `AES_dynamic_CMAC` or an HMAC class leaves the object unkeyed.
Later cipher, update and finish calls then return `TC_ERROR` until the next
successful `init`.
`basic_hash::finish` starts the next message. `basic_hmac::finish` consumes
the key.

The one-shot GCM, CCM, EAX, EAX' and SIV wrappers take the key as `bytes`.
GCM, CCM, EAX and EAX' need `TC_AES_KEYLEN` bytes and SIV needs
`TC_AES_SIV_KEYLEN`. Another length returns `TC_ERROR` before any output is
written. `GCM` streams encryption only. Decrypt GCM with `gcm_decrypt` or
`gcm_decrypt_short_tag`. The `ccm_*_short_tag`, `eax_*_short_tag`,
`aes_cmac_short_tag` and `des_cmac_short_tag` wrappers follow the
[tag length](#tag-lengths) rules of their C functions.

```cpp
const tiny_crypto::bytes key = {key_bytes, sizeof key_bytes};
if (tiny_crypto::ccm_decrypt(key, nonce, aad, ciphertext, tag, plaintext) != TC_OK) {
  /* Reject the packet. */
}
```

## Block cipher modes

The AES and DES CBC, CTR, OFB and ECB functions, and the DES CFB functions,
transform `buf` in place. They share one argument rule:

- The context must be initialized. `buf` may be `NULL` only with length zero.
- CBC lengths are a multiple of the block size.
- `buf`, an IV passed to `set_iv`, and CMAC or ISO 9797 input and tags must be
  disjoint from the context. A span inside the context would change round
  keys, the feedback register or the MAC state during the call.

An argument error returns `TC_ERROR` and leaves the buffer and context
unchanged. A block cipher failure part way through a call wipes the buffer and
clears the context, so neither partial output nor a broken chaining value
survives. ECB and dynamic-key CBC take a const key, so their failures wipe the
buffer and, for CBC, the IV. CTR returns `TC_ERROR` without output when a
request needs a counter block beyond the space of the IV.

## DES and TDEA

Enable `TINY_CRYPTO_ENABLE_DES=ON` and include `<tiny_crypto/des.h>`. One
`struct TC_DES_ctx` serves single DES and TDEA. The key length passed to
`TC_DES_init_ctx` or `TC_DES_init_ctx_iv` selects the cipher. `TC_DES_KEYLEN`
(8 bytes) selects single DES. `TC_DES_KEYLEN_2KEY` (16) and
`TC_DES_KEYLEN_3KEY` (24) select two- and three-key TDEA when
`TINY_CRYPTO_DES_TDES` is on. Every mode function takes the same context.
A failed init wipes the context, so an earlier key cannot be used after a
failed re-init. `TC_DES_ctx_set_iv` starts a new message under the same key.

CFB64 processes whole 8-byte segments. A call may end with one short segment,
which finishes the message. Later CFB64 calls return `TC_ERROR` until a new IV
is set. Split a stream at multiples of 8 bytes to get the same output as a
single call.

```c
#include <tiny_crypto/des.h>

int main(void)
{
    static const uint8_t key[TC_DES_KEYLEN_3KEY] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
        0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23
    };
    static const uint8_t iv[TC_DES_BLOCKLEN] = {0};
    uint8_t data[16] = "legacy payload";
    struct TC_DES_ctx ctx;
    int failed;

    failed = TC_DES_init_ctx_iv(&ctx, key, sizeof key, iv) != TC_OK ||
             TC_DES_CTR_crypt(&ctx, data, sizeof data) != TC_OK;
    TC_DES_ctx_clear(&ctx);
    return failed;
}
```

## DES message authentication

Enable both `TINY_CRYPTO_ENABLE_DES=ON` and `TINY_CRYPTO_DES_ISO9797=ON` to use
ISO/IEC 9797-1 MAC algorithms 1 and 3. Include `<tiny_crypto/des.h>`.
Algorithm 1 accepts 16 or 24-byte TDEA keys. Algorithm 3, the retail MAC,
accepts a 16-byte two-key input and finishes with D(K2) then E(K1). A 24-byte
key selects the three-key retail extension, which finishes with E(K3). That
extension is outside ISO/IEC 9797-1.
ISO/IEC 9797-1:2011 clause 5 restricts single DES to Algorithms 3 and 4.
`TINY_CRYPTO_DES_REJECT_WEAK_KEYS=ON` also rejects ISO 9797 keys with a weak
component, K1 = K2 or K2 = K3, since clause 7.4 requires independent keys.
Choose no padding for block-aligned input, method 1
for zero padding of a partial block, or method 2 for an `0x80` byte followed by
zeroes. Method 1 processes an empty message as one zero block. No padding
requires a nonempty message. The protocol must
fix or authenticate the message length when using either of those choices.

`TC_DES_ISO9797_MAC` and `TC_DES_ISO9797_verify` require the full 8-byte MAC.
Use the explicit `_short_tag` forms for 4 to 7 leading bytes when a protocol
requires truncation. Verification returns `TC_MISMATCH` for a different tag.
For incremental input, call `TC_DES_ISO9797_init`, `update`, and `final` in
order. Successful finalization consumes and clears the context. An update with
invalid arguments leaves the context unchanged, and an update that fails while
processing clears it. Input and tag buffers that overlap the context return
`TC_ERROR` with the context unchanged. A key that overlaps it returns
`TC_ERROR` from init.

```c
#include <tiny_crypto/des.h>

int main(void)
{
    const uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    const uint8_t message[] = "Now is the time for all ";
    uint8_t tag[TC_DES_BLOCKLEN];

    if (TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG3,
                           TC_DES_ISO9797_PAD2, key, sizeof key,
                           message, sizeof message - 1,
                           tag, sizeof tag) != TC_OK)
        return 1;

    /* Use tag with the message in the application protocol. */
    TC_secure_zero(tag, sizeof tag);
    return 0;
}
```

## Complete workflows

- [Validation setup](validation.md) covers arenas, shared contexts, and
  borrowed results.
- [CMS validation](cms.md) covers content, signer paths, CRLs and a runnable tool.
- [Certificate paths](x509-path.md) explains trust inputs and path construction.
- [PIV CVC validation](piv-cvc.md) covers signer trust and secure-messaging
  CVC chains.
- [Trust stores](x509-store.md) covers snapshot ownership and publication.
- [Trust anchors](x509-trust-anchors.md) covers RFC 5914 input and RFC 5937
  path constraints.
- [TWIC cancellation lists](twic-ccl.md) covers import, lookup and freshness.
- [Credential reader](credential-reader.md) describes the supported card checks.
- [GZIP decoding](gzip.md) shows bounded output and caller-owned scratch.

Run the [documented test suites](testing.md) for the features your build enables.
