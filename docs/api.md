<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Working with the API

This page holds the contracts every module shares. The C headers support C99 and C++11. Each
public header opens with a block that links here and lists its scope, standards, configuration
macros and limitations. Function comments give the exceptions and the conditions behind each
status. [C++ wrappers](cpp.md) covers the C++11 layer.

## Build configuration

The [configuration options](../README.md#configuration) select which features compile. A public
header declares a function only in configurations that compile it, so a call into a disabled
feature fails at compile time as an undeclared function. A disabled feature's source compiles to
nothing, so a build may compile every `src/*.c` file and still link only the enabled code.

## Result model

Every status-returning public operation returns `TC_result`. The names below are typedef aliases
of it. They keep call sites descriptive and let one handler take results from any module. Compare
against the named success value instead of treating a result as a Boolean.

| Result name                                                                  | Returned by                                                      | Success               |
| ---------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------- |
| `TC_status`                                                                  | AES, DES, hashes, HMAC, MD5, KMAC256, KBKDF, HKDF, SSKDF, PIV SM | `TC_OK`               |
| `TC_EC_result`, `TC_RSA_result`, `TC_GZIP_result`, `TC_key_challenge_result` | EC, RSA, GZIP, key challenges                                    | `*_OK`                |
| `TC_DRBG_result`                                                             | SP 800-90A DRBGs                                                 | `TC_DRBG_OK`          |
| `TC_TLV_result`                                                              | TLV, DER, X.509, CMS, CRL, OCSP, CVC and PIV/TWIC readers        | `TC_TLV_OK`           |
| `TC_X509_signature_result`, `TC_X509_path_status`                            | signature providers, path validation                             | `*_VALID`             |
| `TC_credential_status`                                                       | CMS, CHUID, biometric, security-object and SM validation         | `TC_CREDENTIAL_VALID` |
| `TC_TWIC_CCL_result`                                                         | TWIC canceled card lists                                         | `TC_TWIC_CCL_OK`      |
| `TC_APDU_result`                                                             | ISO/IEC 7816-4 APDU encoding and exchange                        | `TC_APDU_OK`          |
| `TC_PIV_result`                                                              | PIV and TWIC card commands                                       | `TC_PIV_OK`           |
| `TC_result`                                                                  | workspace sizing and setup helpers                               | `TC_RESULT_OK`        |

`TC_status` reports a failed authentication or comparison as `TC_MISMATCH`, an alias of
`TC_RESULT_INVALID`. Every other failure is `TC_ERROR`, an alias of `TC_RESULT_ERROR`: a NULL
pointer, a bad length, a short output, an overlap, a missing IV or key, or a backend failure.

Records filled by parsing and validation use the `_report` suffix. `TC_X509_path_report` holds the
selected key and policies, and the function that fills it returns `TC_X509_path_status`.

Each shared value has one meaning:

- `INVALID`: received data is malformed or fails a check, such as a bad encoding, a failed
  signature or a point off the curve.
- `LIMIT`: a caller-supplied bound ran out, such as output capacity, workspace or frames, a work
  budget, random attempts or a `TC_TLV_limits` bound. More resources may succeed.
- `ARGUMENT`: a caller error, such as a NULL pointer, a span with NULL data and a nonzero length, a
  forbidden overlap or a parameter outside the function's domain.
- `UNSUPPORTED`: well-formed input that uses an algorithm, size, version or feature outside this
  library or build.
- `ERROR`: a random source, signature provider, cipher backend, storage source or internal
  self-check failed.

Some modules add their own values:

- RSA: `TC_RSA_IN_PROGRESS` and `TC_RSA_CANCELLED` for stepwise key generation.
- PIV commands: `TC_PIV_CARD_STATUS` for a card answer other than success, and `TC_PIV_REFUSED`
  for a safety rule that stopped a command before it was sent.
- DRBG: `TC_DRBG_ENTROPY` for a failed entropy source, with the DRBG state unchanged.
- TLV: `TC_TLV_END` (no more siblings) and `TC_TLV_MORE` (a root reader needs more input) are
  reader states. `TC_TLV_IO` reports backing storage that failed to supply bytes. Path and
  credential validation report it as their ERROR value.
- Revocation: `TC_X509_REVOCATION_UNDETERMINED` means no evidence covers a certificate.
  `TC_CREDENTIAL_REVOKED` and `TC_CREDENTIAL_UNAVAILABLE` separate revoked credentials from
  missing trust or evidence.

UNSUPPORTED and LIMIT never report success. A validation stopped by an unsupported feature or an
exhausted limit fails closed.

## Failure state and wiping

These rules hold for every public function unless its header states an exception:

1. Each public entry checks its arguments once, before any write. An argument error leaves every
   output, context, workspace, work budget and random source unchanged. So does a capacity or work
   preflight that returns LIMIT before processing starts.
1. Readers and parsers write their result only on success. A failed read leaves `out` unchanged.
1. After the argument checks, a failure wipes any output that could hold partial plaintext, keys
   or unauthenticated data. The output then holds zero bytes. In-place callers lose the input.
1. Frames, workspaces and other scratch are provisional. Any failure may change them. Scratch that
   held secrets is wiped before return.
1. Work budgets decrease by the work completed, on success and on failure.
1. A final or finish call consumes and wipes its context. A failure while processing clears the
   context, so no partial chaining value or key stays usable. `*_clear` functions always wipe and
   accept a NULL context.
1. Key schedules, MAC states and stack secrets are wiped before return.

Wiping is unconditional. Defining `TC_ZEROIZE` or `TC_STRICT` stops the build with an `#error`.
`TC_secure_zero` is a best-effort wipe for application buffers. Copies held in CPU registers
remain. Clear application keys and plaintext with it when their lifetime ends, and release acquired
snapshots on every exit path.

### Documented exceptions

These functions depart from the rules above by design. Their headers give the details.

- Modules that return `TC_status` (AES, DES, hashes, HMAC, MD5, KMAC256, KBKDF, HKDF, SSKDF and
  PIV SM) report a short output buffer as `TC_ERROR`, because `TC_status` has no LIMIT value.
- `TC_TWIC_CCL_stream_update` makes argument errors sticky after init. The stream returns the first
  error until the next init, so a rejected chunk can never be skipped.
- `TC_CMS_signer_verify_digest` checks the digest length after algorithm resolution, because the
  resolved hash sets the length. An argument error there can follow charged work.

## Buffers and lifetimes

`TC_bytes` is a borrowed, immutable span:

```c
TC_bytes message = {encoded, encoded_length};
```

It owns no storage. Keep `encoded` alive and unchanged while any reader, parsed object or
validation result refers to it. An empty span may use `NULL` with length zero. Some schemas
require nonempty input.

`TC_buffer` pairs writable `data` with a byte `capacity`. A returned length gives the bytes
written. Spare capacity follows each operation's contract.

Parsers return views into their input. Reusing the receive buffer invalidates them. Finish with
the views before receiving the next object, or copy the bytes the application keeps.

`TC_random_source` pairs a fill callback with its context. The callback fills the whole requested
buffer before it returns `TC_OK`.

### Input stability and overlap

- Keep every input stable for the duration of the call. No other thread, interrupt handler or DMA
  transfer may write it. Some operations read an input twice. GCM, CCM, EAX and EAX' decryption
  authenticate the ciphertext and then decrypt it.
- Inputs may share storage with each other.
- Outputs, contexts, workspaces and work counters must be disjoint from the inputs and from each
  other unless the header permits in-place use. The block-mode, AEAD, key wrap, KMAC and MD5
  functions list their permitted in-place and overlap cases.
- A checked overlap returns the module's argument error before any write. An undetectable overlap,
  such as one through a second mapping of the same memory, is undefined behavior.

## Workspaces and limits

A workspace is caller-owned scratch. On constrained devices, put large RSA and
certificate-validation workspaces in static or application-owned storage. Keep workspace
descriptors alive for every operation that refers to them. Descriptors that only point at caller
storage, such as `TC_X509_workspace`, `TC_X509_path_workspace`, `TC_CMS_path_workspace` and
`TC_RSA_workspace`, are passed as const pointers or as `TC_TLV_frames` values, and calls write the
storage they point to. Storage types such as `TC_EC_workspace` and `TC_GZIP_workspace`, and
readers, contexts and results, are passed mutable.

The [validation setup guide](validation.md) shows checked arena sizing and the micro, mini and
desktop capacity presets. RSA calls group scheme settings in operation options and random and work
limits in an execution descriptor.

Calls that share writable scratch need application serialization. Independent contexts and
disjoint scratch may run concurrently, subject to provider and storage callback requirements.

Parsing limits bound input size, value size, element count and nesting depth. On a LIMIT result,
the application decides explicitly whether to retry with more resources.

## Work budgets

Operations that can run long take an explicit work budget. The two budget types count different
units.

`TC_work_budget` holds a `uint32_t remaining` count of algorithm units. EC, RSA and key challenges
take it, usually inside an execution descriptor.

- EC charges one unit per curve bit for each scalar multiplication or modular inversion, and one
  unit per point validation and random request. `TC_EC_operation_work(curve, operation)` returns
  the exact cost of one operation or one attempt of a randomized operation.
- RSA charges modular operations and encoding comparisons. `TC_RSA_public_work`,
  `TC_RSA_private_work`, `TC_RSA_encode_v15_work`, `TC_RSA_encode_pss_work`, `TC_RSA_oaep_work`,
  `TC_RSA_VALIDATE_WORK` and `TC_RSA_KEYGEN_STEP_WORK` give the exact or sufficient costs. See
  [RSA work budgets](rsa.md#work-budgets).
- These operations check their full cost before arithmetic or any random request. A short budget
  returns LIMIT with outputs, work and the random source unchanged.

`size_t* work` is a remaining count of processing units for parsing and validation. X.509, CMS,
CRL, OCSP, path validation, credential validation, LDS, PIV card identifiers, PIV CVC chains, SM
authentication and GZIP take it.

- A unit is one byte examined or one element, candidate, comparison or decoding step. Each header
  names what its function charges, such as traversed bytes, digest input or table entries.
- Charges are incremental. A charge larger than the remaining budget returns the module's LIMIT
  value, and no later step runs. The PKI modules then set `*work` to zero. GZIP leaves the unspent
  remainder in `*work`.
- Signature verification first charges one unit plus the signed bytes, signature and key
  encoding. The provider then consumes its own work and never increases it. The native provider
  reserves `TC_X509_native_workspace.signature_work` for each attempt.
  `TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK` covers the supported curves and RSA sizes with ordinary
  exponents.
- Share one counter across related calls, such as the init and next calls of a reader or the steps
  of one credential decision, so the whole operation has one bound.

Size a `size_t` budget from the input size and the number of passes. Start with a few times the
total input bytes plus one signature reservation per signature the operation can check. Tune it
against the largest inputs the application accepts. Work units are independent of elapsed time.

## Naming and argument order

Public C names start with `TC_` and a module prefix, such as `TC_AES_`, `TC_X509_` or `TC_PIV_SM_`.
Types use a lowercase noun after the prefix, such as `TC_X509_certificate` and `TC_EC_workspace`.
Enumerators and macros are uppercase. Configuration macros are `TC_ENABLE_*` for a module and
`TC_<MODULE>_ENABLE_*` for a mode or variant. C++ wrappers live in namespace `tiny_crypto`.

Function names end with the operation:

- `init`, `update`, `final` or `finish`, and `ctx_clear` or `clear` for stateful contexts.
  `set_iv` loads an IV for the next message.
- `read` parses one object into borrowed views. `next` returns the next item from a reader, and
  `END` reports the end.
- `write` and `encode` produce an encoding into a caller buffer.
- `verify` checks a signature, MAC or tag. `validate` applies a policy or a complete path, key or
  credential check. `check` tests one property or one kind of evidence, such as revocation.
- `_work`, `_size`, `_BYTES` and `_WORDS` give the cost or storage a call needs, so callers can size
  budgets and buffers first.
- `_short_tag` selects tag lengths below the default minimum.
- `wrap` and `unwrap` protect and recover key data under a key-encryption key.

Arguments follow the operation:

1. The context, session or reader, when the call has one.
1. Configuration: algorithm, profile, options or policy.
1. Inputs, as `TC_bytes` spans or input structures.
1. For parsers and validators: limits, frames, workspace and the `size_t` work counter, then the
   output last.
1. For cryptographic one-shots: outputs after the inputs. EC and RSA then take the workspace and
   the `TC_work_budget` or execution descriptor last.

No public function takes more than eight parameters. A call that needs more takes a `*_request`
structure and a context, such as `TC_CMS_validation_request` with a `TC_validation_context`.

## Parsing, signatures and trust

Choose the operation that answers the application's question:

- Readers check the documented encoding and schema and return borrowed views.
- Signature verification authenticates bytes with a supplied key.
- Path validation checks a certificate against supplied trust and policy.
- CMS credential validation combines content binding, signature verification, path construction
  and CRL revocation checking for one selected signer.

A successful parse supplies structure only. Handle malformed input, unsupported algorithms,
exhausted limits and unavailable evidence explicitly. Accept a credential only after every required
authentication and policy check succeeds. CMS and CVC credential workflows share
`TC_credential_status`, which separates revoked, unavailable, unsupported, limit and error
outcomes.

`<tiny_crypto/cms.h>` parses CMS and verifies signatures under a known key. Add
`<tiny_crypto/cms_validation.h>` when signer discovery, paths or revocation are part of the
application. `<tiny_crypto/validation.h>` adds the shared arena and policy context for complete CMS
and X.509 validation. `TINY_CRYPTO_ENABLE_CMS_VALIDATION` selects both validation headers.

PIV and TWIC object policy and the final access decision need their own checks. Select
compatibility options explicitly, including the TWIC signed and unsigned CHUID profiles and CMS
signed-attribute encoding.

### Certificates

`TC_X509_read` reads one DER certificate into caller-owned scratch:

```c
#include <tiny_crypto/x509.h>

TC_TLV_result read_certificate(TC_bytes der, TC_X509_certificate* certificate)
{
  TC_TLV_frame frames[16];
  TC_bytes extension_oids[32];
  const TC_X509_workspace workspace = {{frames, 16}, extension_oids, 32};
  const TC_TLV_limits limits = {8192, 8192, 1024, 16};

  /* certificate borrows der and changes only on TC_TLV_OK. */
  return TC_X509_read(der, &limits, &workspace, certificate);
}
```

Choose the limits for the application. The workspace needs one frame per nesting level and one
OID slot per extension. Exceeding a limit returns `TC_TLV_LIMIT`. Results borrow the input, so keep
it alive while using them. The workspace is reusable after the call.

`certificate.public_key` identifies the subject's algorithm, key size and named curve.
`TC_X509_subject_public_key` reads a standalone SubjectPublicKeyInfo. The extension iterator gives
each extension's OID, critical flag and value. Extension decoders take the value as a `TC_bytes`
span with its own limits, which cover the outer element and every element beneath it. Readers such
as `TC_X509_general_names_init` bind their input, limits and frames at init, and each `next` call
spends the budget left by earlier calls.

`<tiny_crypto/key_challenge.h>` prepares and verifies a fresh proof-of-possession challenge from a
validated public key and explicit signature parameters. Protocol code owns card commands and slot
policy and selects the algorithm, key usage and transport identifiers before issuing a challenge.

### Card verifiable certificates

[PIV CVC verification](piv-cvc.md) covers `TC_PIV_CVC_read` and chain verification.

`<tiny_crypto/eac_cvc.h>` reads BSI TR-03110 EAC certificates with `TC_EAC_CVC_read`, plus a
standalone public-key reader and an extension iterator. The certificate reader takes the encoding
as `TC_bytes`, `TC_TLV_limits` and a `TC_EAC_CVC_workspace` of caller-owned `TC_TLV_frames`.
Returned fields borrow the input. Keep the input, frames and output disjoint. The signed span
covers the complete `7F4E` body, tag and length included. Unknown extensions are preserved.
Unsupported key or authorization OIDs return `TC_TLV_UNSUPPORTED`. The public-key reader also
accepts RI-ECDH templates, which are unusable as certificate-signing keys.

`TC_EAC_CVC_check_encoding` checks coordinate and signature widths. Pass the resolved issuer key,
which sets the signature width, and, for an EC subject without explicit parameters, its inherited
domain parameters. Missing context returns `TC_TLV_ARGUMENT`.

The PIV and EAC CVC readers take one complete object and report a truncated encoding as
`TC_TLV_INVALID`.

### CHUID

`TC_PIV_CHUID_read` returns the FASC-N, card UUID (GUID), optional cardholder UUID, expiration
date and signature. Select `TC_PIV_CHUID_CONTENTS` for the object contents or
`TC_PIV_CHUID_CONTAINER` for a `53`-wrapped object. Choose the profile from the requested card
object:

- `TC_CHUID_PROFILE_PIV` follows SP 800-73-5 Part 1 Table 10. It rejects Buffer Length (`EE`),
  Organizational Identifier (`32`) and DUNS (`33`). It requires an RFC 4122 GUID of version 1, 4 or
  5 and a version 4 Cardholder UUID (sections 3.4.1 and 3.4.2).
- `TC_CHUID_PROFILE_PIV_SP800_73_4` reads PIV CHUIDs issued under SP 800-73-4 or earlier, and the
  PIV application of a TWIC card. It accepts `EE`, `32` and `33`, any GUID version, and one
  Authentication Key Map (`3D`) of up to 512 bytes immediately before the signature
  ([SP 800-73-2, Part 1, Table 8](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-73-2.pdf)).
  `authentication_key_map` borrows the map's value, and an empty present map has a non-NULL
  pointer. `signed_content` includes the map's exact tag, length and value. Authenticate the
  signature before using the map.
- `TC_CHUID_PROFILE_TWIC_SIGNED` and `TC_CHUID_PROFILE_TWIC_UNSIGNED` follow TWIC Part 2 v5
  sections 4.6.3 and 4.6.1. Unsigned TWIC omits the signature and cardholder UUID.

`signed_content` excludes Buffer Length (SP 800-73-4 Part 1 section 3.1.2).

`TC_PIV_CHUID_validate` authenticates a signed CHUID against an already validated card
certificate under an explicit PIV, TWIC Legacy or TWIC NEXGEN profile. Its `TC_PIV_CHUID_report`
feeds the dependent biometric and Security Object requests, which reject a report from another
profile or evaluation time. [CMS](cms.md) covers the request, and
[credential validation](validation.md) shows the order of the checks. Transport, cancellation
status and authorization stay with the caller.

### Printed information and biometrics

`TC_PIV_printed_read` parses PIV printed information or decrypted TWIC DFC109 contents. Select the
profile and whether the input includes the outer `53` container. Text fields borrow the input. PIV
dates use `YYYYMMMDD` and TWIC dates `DDMMMYYYY`. After authenticating the Security Object and
signed CHUID, call `TC_PIV_printed_expiration_check`. It requires the printed date to match the
CHUID date and accepts evaluation times through the end of that day.

`TC_PIV_fingerprint_read` validates an INCITS 378-2004 minutiae record against the PIV card
profile. It checks the fixed header, two finger views, minutiae, dimensions, resolution, quality
values and the required empty extension areas. The record stays in caller storage for a biometric
matcher.

`TC_PIV_face_read` validates INCITS 385-2004 record framing and each image block.
`TC_PIV_FACE_PROFILE_PIV` applies the SP 800-76-2 Full Frontal and minimum-width requirements.
`TC_PIV_FACE_PROFILE_TWIC` accepts the Basic records found on TWIC credentials and keeps the
structural, image-encoding, color-space, source, pose, feature-point and length checks.
`TC_PIV_face_image_read` returns a borrowed image and its dimensions.

`TC_PIV_biometric_validation_request.format` binds an authenticated CBEFF object to its expected
modality and record type. Set `require_current` when the CBEFF validity period is part of the
credential decision. The comparison uses the shared validation-context time and includes both
boundary instants. Iris credential validation returns UNSUPPORTED because the library has no
ISO/IEC 19794-6 record reader.

The [credential validation example](credential-validation.md) composes certificate trust,
identifier checks, cancellation, fresh key possession, signed objects and a bounded list of
biometric objects from retained inputs. Reader commands live in its proof callback and transport
layer.

## Revocation

CRL and OCSP evidence share `TC_X509_revocation_status` and the freshness rule of
`TC_X509_revocation_time`. `TC_X509_path_check_revocation` checks a validated path from the
anchor-issued certificate to the target. It accepts one OCSP response per path member and falls
back to CRLs for a member without an accepted response. The CMS and credential validators use CRL
evidence only.

`TC_validation_options.revocation` (`TC_validation_revocation`) sets the evidence policy of the
CMS, X.509 and credential validators. The zero value, `TC_VALIDATION_REVOCATION_REQUIRED`, returns
`TC_CREDENTIAL_UNAVAILABLE` for a path member without current CRL evidence.
`TC_VALIDATION_REVOCATION_WHEN_AVAILABLE` accepts that member and reports `revocation_checked` 0.
Both values check covering CRLs, so a revoked member returns `TC_CREDENTIAL_REVOKED` and an
unsupported CRL returns `TC_CREDENTIAL_UNSUPPORTED`. Select the policy at the application boundary
and treat `revocation_checked` 0 as missing evidence.

[X.509 path revocation](x509-revocation.md) and [X.509 OCSP](x509-ocsp.md) cover configuration,
responder authorization, workspace sizing and results.

## Authenticated encryption

The one-shot AEAD functions in `<tiny_crypto/aes.h>` (GCM, CCM, EAX, EAX' and SIV) share one
contract:

- Encrypt writes `plaintext.length` bytes of ciphertext and `tag.capacity` tag bytes. Decrypt
  writes `ciphertext.length` bytes of plaintext and checks `tag.length` tag bytes, over the entire
  tag. EAX' and SIV use fixed-size tag arrays.
- The text output capacity must be at least the text input length. Bytes past the text length are
  never written.
- Text input and output are the same buffer or fully disjoint. The tag is disjoint from the text
  output. SIV associated data is disjoint from the text output. A violation returns `TC_ERROR`
  before any write.
- The key, and the nonce and associated data of GCM, CCM, EAX and EAX', may share storage with the
  text output. Each is read in full before the first output write.
- Every input stays stable for the call, as [input stability](#input-stability-and-overlap)
  requires.
- `TC_ERROR` before any write reports a NULL key or tag, a NULL span with a nonzero length, a short
  text output, a forbidden overlap, or a nonce, tag or text length outside the mode's range.
- GCM, CCM, EAX and EAX' verify the tag before writing plaintext. SIV decryption writes candidate
  plaintext first and recomputes the synthetic IV over the associated data and that plaintext
  (RFC 5297 section 2.7).
- After the argument checks, every failure wipes the text output, separate or in place. A tag that
  fails to verify returns `TC_MISMATCH`. A cipher backend failure returns `TC_ERROR`. The tag
  output is written only on success.

GCM decryption is one-shot. The streaming `TC_AES_GCM_ctx` API encrypts only. The
[tag lengths](#tag-lengths) table lists the `_short_tag` forms for shorter protocol tags.

```c
TC_status status = TC_AES_GCM_decrypt(key, (TC_bytes){iv, 12}, (TC_bytes){aad, aad_length},
                                      (TC_bytes){packet, packet_length},
                                      (TC_bytes){tag, 16},
                                      (TC_buffer){packet, packet_length});
if (status != TC_OK)
  return status; /* packet holds no plaintext */
```

## Key wrap

`<tiny_crypto/aes_kw.h>` provides one-shot SP 800-38F KW and KWP wrap and unwrap. Unwrap uses the
output as its working area and checks the integrity value after the inverse wrapping function.
Every failure after the argument checks wipes that area. A failed integrity, length indicator or
padding check returns `TC_MISMATCH`. Inputs and outputs may overlap in any way. See
[AES key wrap](aes-kw.md) for KEK lengths, buffer sizes and limits.

## Tag lengths

`TC_MIN_TAG_LEN` in `config.h` sets the minimum tag length for the default CCM, EAX, AES-CMAC,
DES-CMAC and KMAC entry points. It defaults to 8 bytes, the 64-bit floor of SP 800-38B Appendix
A.2, and a build may raise it to 16. Values outside 8..16 stop the build. A value above 8 also
requires `TC_DES_ENABLE_CMAC=0`, since a DES-CMAC tag holds at most 8 bytes.

The default HMAC minimum for a digest of `L` bytes is `TC_HMAC_MIN_TAG_LEN_FOR(L)`: the largest of
`L / 2`, `TC_HMAC_MIN_TAG_LEN` and `TC_MIN_TAG_LEN`. RFC 2104 section 5 recommends at least half
the digest and at least 80 bits, so `TC_HMAC_MIN_TAG_LEN` defaults to 16 and a value below 10
stops the build. HMAC and KMAC tags never go below `TC_HASH_MAC_MIN_TAG_LEN` (4 bytes), the 32-bit
floor of SP 800-107 Rev. 1 section 5.3.3 and SP 800-185 section 8.4.2.

| Mode       | Default entry points                                    | `_short_tag` entry points                      |
| ---------- | ------------------------------------------------------- | ---------------------------------------------- |
| CCM        | even lengths from `TC_MIN_TAG_LEN` to 16                | even lengths from 4 up to `TC_MIN_TAG_LEN - 1` |
| EAX        | `TC_MIN_TAG_LEN`..16                                    | 1..`TC_MIN_TAG_LEN - 1`                        |
| AES-CMAC   | `TC_MIN_TAG_LEN`..16                                    | 1..`TC_MIN_TAG_LEN - 1`                        |
| DES-CMAC   | `TC_MIN_TAG_LEN`..8                                     | 1..`TC_MIN_TAG_LEN - 1`                        |
| GCM        | 12..16                                                  | 4 or 8 (SP 800-38D appendix C)                 |
| ISO 9797-1 | 8                                                       | 4..7                                           |
| HMAC       | `TC_HMAC_MIN_TAG_LEN_FOR(digest length)`..digest length | 4..default minimum - 1                         |
| KMAC256    | `TC_MIN_TAG_LEN`..`UINT64_MAX / 8`                      | 4..`TC_MIN_TAG_LEN - 1`                        |

Each accepted length has exactly one entry point. The other entry point returns `TC_ERROR` and
leaves every output unchanged. A zero-length tag is never accepted. Short tags are the leading
bytes of the full tag. Call a `_short_tag` form only when the protocol fixes that tag length and
limits the number of failed verifications for a key. GCM short tags use
`TC_AES_GCM_init_short_tag` or the one-shot `_short_tag` functions, and the GCM packet limits still
apply. EAX' is exempt from the minimum because ANSI C12.22 fixes its tag at 4 bytes.

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

## Hashes and key derivation

SHA-1, SHA-224 and SHA-256 share `hash.c`. SHA-384 and SHA-512 share a 64-bit core in
`sha512.c`. SHA-224 and SHA-384 reuse the SHA-256 and SHA-512 compression functions, and each hash
is enabled independently.

SHA-1 serves compatibility. Avoid it for new collision-resistant signatures and content identity.
HMAC-SHA-1 is a separate construction whose security is independent of collision resistance. It
remains an acceptable MAC and KBKDF PRF, and it is the smallest HMAC option on AVR.

`<tiny_crypto/kdf.h>` implements the SP 800-108r1 KBKDF in counter, feedback and double-pipeline
mode. Each PRF has its own function family, such as `TC_KBKDF_HMAC_SHA256_counter` and
`TC_KBKDF_AES_CMAC_feedback`, so unused PRFs compile out. The build needs at least one PRF: HMAC
with an enabled SHA digest, `TINY_CRYPTO_AES_ENABLE_CMAC` or `TINY_CRYPTO_DES_ENABLE_CMAC`.
SP 800-131A Rev. 2 Table 7 disallows the TDEA-CMAC PRF after 2023, so enable it only for protocols
that still derive keys with TDEA. `kdf.h` describes the SP 800-108r1 key-control mitigations for
the CMAC PRFs.

Put the purpose, parties and requested length in the KBKDF fixed input so keys for different uses
differ. `TC_KBKDF_fixed_input` builds `Label || 0x00 || Context || [L]_32`. Never reuse a
key-derivation key as a derived key. Lengths are in bytes. A derivation of
`n = ceil(out_len / h)` PRF blocks needs `n <= 2^r - 1` for an `r`-bit counter. Outputs must be
disjoint from every input. `TC_ERROR` after derivation starts wipes the output.

`TC_SSKDF_SHA1` through `TC_SSKDF_SHA512` implement the SP 800-56C Rev. 2 one-step KDF, one
function per enabled SHA. They take FixedInfo as spans, so callers need no concatenation buffer.
[HKDF](hkdf.md) covers RFC 5869 extract, expand and derive.

## Block cipher modes

Key a context with `TC_AES_init` or `TC_DES_init`. Init leaves the context without an IV. Load a
fresh IV with `TC_AES_set_iv` or `TC_DES_set_iv` before each message in an IV mode (CBC, CTR, OFB
and the DES CFB modes). Until then those modes return `TC_ERROR`, even for an empty buffer, so a
missing `set_iv` call never encrypts under a fixed zero IV. ECB and the MACs need no IV.

Calls after `set_iv` continue one message: CBC and CFB chain from the last ciphertext, and CTR and
OFB continue the keystream. The IV stays loaded until the next init or clear, so start every new
message with `set_iv`. SP 800-38A section 5.3 and Appendix C require an unpredictable CBC and CFB
IV and a unique OFB IV per message, and Appendix B requires unique CTR counter blocks under one
key. Clear the context with `TC_AES_ctx_clear` or `TC_DES_ctx_clear` when its lifetime ends.

CTR, CBC, ECB, OFB and CFB provide no authentication. Pair them with a MAC or use GCM, CCM, EAX or
SIV. Never reuse a CTR, GCM, CCM, EAX or OFB nonce with the same key.

The AES and DES CBC, CTR, OFB and ECB functions, and the DES CFB functions, transform `buf` in
place under one argument rule:

- The context must be initialized, and an IV mode needs an IV from `set_iv`. `buf` may be `NULL`
  only with length zero.
- CBC lengths are a multiple of the block size.
- `buf`, an IV passed to `set_iv`, and CMAC or ISO 9797 input and tags must be disjoint from the
  context. A span inside the context would change round keys, the feedback register or the MAC
  state during the call.

An argument error returns `TC_ERROR` and leaves the buffer and context unchanged. A block cipher
failure part way through a call wipes the buffer and clears the context, so neither partial output
nor a broken chaining value survives. ECB and dynamic-key CBC take a const key, so their failures
wipe the buffer and, for CBC, the IV. CTR returns `TC_ERROR` without output when a request needs a
counter block beyond the space of the IV.

## DES and TDEA

Enable `TINY_CRYPTO_ENABLE_DES=ON` and include `<tiny_crypto/des.h>`. One `struct TC_DES_ctx`
serves single DES and TDEA, and the key length passed to `TC_DES_init` selects the cipher.
`TC_DES_KEYLEN` (8 bytes) selects single DES. `TC_DES_KEYLEN_2KEY` (16) and `TC_DES_KEYLEN_3KEY`
(24) select two- and three-key TDEA when `TINY_CRYPTO_DES_ENABLE_TDES` is on. Every mode function
takes the same context. A failed init wipes the context, so an earlier key is unusable after a
failed re-init. `TC_DES_set_iv` loads the IV for the first message and starts each later message
under the same key.

DES has a 56-bit effective key and exists for protocols that require it. Its table lookups have no
cache-timing protection. Limit 3DES to compatibility code as well.
`TINY_CRYPTO_DES_REJECT_WEAK_KEYS=ON` rejects weak or semi-weak DES component keys and TDEA
bundles that collapse to single DES. It defaults off so published DES test vectors with such keys
still run.

CFB64 processes whole 8-byte segments. A call may end with one short segment, which finishes the
message. Later CFB64 calls return `TC_ERROR` until a new IV is set. Split a stream at multiples of
8 bytes to get the same output as a single call.

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
    uint8_t data[16] = "DES-CBC payload";
    struct TC_DES_ctx ctx;
    int failed;

    failed = TC_DES_init(&ctx, (TC_bytes){key, sizeof key}) != TC_OK ||
             TC_DES_set_iv(&ctx, (TC_bytes){iv, sizeof iv}) != TC_OK ||
             TC_DES_CTR_crypt(&ctx, (TC_buffer){data, sizeof data}) != TC_OK;
    TC_DES_ctx_clear(&ctx);
    return failed;
}
```

## DES message authentication

Enable `TINY_CRYPTO_ENABLE_DES=ON` and `TINY_CRYPTO_DES_ENABLE_ISO9797=ON` for ISO/IEC 9797-1 MAC
algorithms 1 and 3, and include `<tiny_crypto/des.h>`. The ISO 9797-1 MAC is off in every resource
profile.

- `TC_DES_ISO9797_ALG1` accepts 16 or 24-byte TDEA keys.
- `TC_DES_ISO9797_ALG3`, the retail MAC, accepts exactly 16 bytes, K1 || K2, and finishes with
  D(K2) then E(K1).
- `TC_DES_ISO9797_ALG3_3KEY_EXTENSION` takes exactly 24 bytes and finishes with E(K3). This
  extension is outside ISO/IEC 9797-1.

ISO/IEC 9797-1:2011 clause 5 restricts single DES to Algorithms 3 and 4. Every build rejects a key
with K1 = K2 or K2 = K3, compared without parity bits, since such a key cancels a DES stage and
clause 7.4 requires independent keys. `TINY_CRYPTO_DES_REJECT_WEAK_KEYS=ON` also rejects weak and
semi-weak component keys.

Choose no padding for block-aligned input, method 1 for zero padding of a partial block, or method
2 for an `0x80` byte followed by zeroes. Method 1 processes an empty message as one zero block. No
padding requires a nonempty message. With either of those two choices, the protocol must fix or
authenticate the message length.

`TC_DES_ISO9797_MAC` and `TC_DES_ISO9797_verify` require the full 8-byte MAC. The `_short_tag`
forms take 4 to 7 leading bytes for protocols that truncate. Verification returns `TC_MISMATCH`
for a different tag. For incremental input, call `TC_DES_ISO9797_init`, `update` and `final` in
order under the [failure rules](#failure-state-and-wiping). Input and tag buffers that overlap the
context return `TC_ERROR` with the context unchanged. A key that overlaps it returns `TC_ERROR`
from init.

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

    if (TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2,
                           (TC_bytes){key, sizeof key},
                           (TC_bytes){message, sizeof message - 1},
                           (TC_buffer){tag, sizeof tag}) != TC_OK)
        return 1;

    /* Use tag with the message in the application protocol. */
    TC_secure_zero(tag, sizeof tag);
    return 0;
}
```

## Complete workflows

- [Validation setup](validation.md): arenas, shared contexts and borrowed results.
- [CMS validation](cms.md): content, signer paths, CRLs and a runnable tool.
- [Certificate paths](x509-path.md): trust inputs and path construction.
- [PIV CVC validation](piv-cvc.md): signer trust and secure-messaging CVC chains.
- [Trust stores](x509-store.md): snapshot ownership and publication.
- [Trust anchors](x509-trust-anchors.md): RFC 5914 input and RFC 5937 path constraints.
- [TWIC cancellation lists](twic-ccl.md): import, lookup and freshness.
- [Credential reader](credential-reader.md): the supported card checks.
- [GZIP decoding](gzip.md): bounded output and caller-owned scratch.
- [TLV parsing](tlv.md) and [DER values](der.md): bounded readers.
- [AES key wrap](aes-kw.md): KEK lengths, buffer sizing and unwrap failure.
- [HKDF](hkdf.md), [DRBG](drbg.md), [RSA](rsa.md) and [elliptic curves](ec.md): the cryptographic
  modules.

Run the [documented test suites](testing.md) for the features your build enables.
