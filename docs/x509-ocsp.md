<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# X.509 OCSP

Include `<tiny_crypto/x509_ocsp.h>` and enable `TINY_CRYPTO_ENABLE_X509_OCSP`. OCSP requires
`TINY_CRYPTO_ENABLE_X509_PATH` and SHA-1, because a byKey ResponderID is always a SHA-1 key hash
(RFC 6960 section 4.2.1).

The module handles one certificate at a time:

- `TC_X509_ocsp_request_encode` writes an unsigned DER OCSPRequest (RFC 6960 section 4.1.1) with an
  optional RFC 9654 nonce.
- `TC_X509_ocsp_response_verify` authenticates a complete DER OCSPResponse, including a stapled
  one, and reports GOOD or REVOKED.

The caller validates the certificate path, generates the nonce, carries the request and response
over HTTP (RFC 6960 appendix A) and makes the acceptance decision. To apply OCSP to a whole path
with CRL fallback, use [path revocation](x509-revocation.md#ocsp-evidence).

## Quick start

[examples/x509_ocsp.c](../examples/x509_ocsp.c) wraps both calls with fixed limits and the
[shared X.509 workspace](../examples/x509_workspace.h). Fill the nonce from a DRBG or another
approved random source.

```c
static ExampleX509Workspace storage;
uint8_t nonce[EXAMPLE_OCSP_NONCE_LENGTH];
uint8_t request[EXAMPLE_OCSP_REQUEST_CAPACITY];
size_t request_length = 0;
if (example_ocsp_request(certificate, &issuer, nonce, &storage,
                         (TC_buffer){request, sizeof request},
                         &request_length) != TC_TLV_OK)
    return EXAMPLE_OCSP_ERROR;
/* POST request[0..request_length) and read the response. */

ExampleOcspCheck check;
memset(&check, 0, sizeof check);
check.certificate = certificate;
check.issuer = &issuer;
check.nonce = (TC_bytes){nonce, sizeof nonce};
check.response = response;
check.at = now;
check.verifier = &verifier;
TC_X509_ocsp_report result;
switch (example_ocsp_check(&check, &storage, &result)) {
case EXAMPLE_OCSP_GOOD:
    return accept(&result);
case EXAMPLE_OCSP_REVOKED:
    return reject_revoked(result.revocation_time, result.reason);
case EXAMPLE_OCSP_CHECK_RESPONDER:
    /* Check result.responder_certificate against a CRL first. */
    return check_responder(result.responder_certificate);
default:
    /* NO_DECISION, REJECTED, LIMIT or ERROR: try CRLs or fail closed. */
    return use_crls();
}
```

`certificate` is the DER certificate and `issuer` is the `TC_X509_trust_anchor` of its issuer from
the validated path. `verifier` is a `TC_X509_signature_provider`, such as `TC_X509_native_provider`.
The example wipes its storage and zeroes `result` after every verification failure.

## Encoding a request

Set `TC_X509_ocsp_encode_request`:

- `certificate`: the DER certificate to check.
- `issuer`: its issuer's name and public key. The certificate's issuer Name must match
  `issuer->name`.
- `hash`: the CertID hash, `TC_HASH_SHA256`, or `TC_HASH_SHA1` for a responder that accepts only
  SHA-1 CertIDs. Other hashes return `TC_TLV_UNSUPPORTED`.
- `nonce`: empty, or 32 to 128 caller-generated random bytes (RFC 9654 section 2.1).
- `parsing`: limits for parsing the certificate.

The workspace supplies frames, OIDs and Name buffers to parse the certificate and compare its
issuer. The request size depends only on the hash, serial number length and nonce length. Pass an
empty `TC_buffer` to query it. A short buffer returns `TC_TLV_LIMIT` with `*length` set to the
required size and the buffer unchanged. Other failures after the argument checks set `*length` to 0.
The output must be disjoint from the inputs, the request, `work` and `length`.

## Verifying a response

Set `TC_X509_ocsp_verify_request`:

- `response`: one complete DER OCSPResponse.
- `certificate` and `issuer`: the certificate and its issuer from a validated path.
- `expected_nonce`: the nonce sent in the request, or empty. A present nonce must be echoed byte for
  byte in responseExtensions. Leave it empty for a stapled or pre-produced response and rely on
  freshness.
- `certificates`: an optional `TC_X509_store_source` of delegate candidates, searched after the
  response's certs field.
- `time`: a `TC_X509_revocation_time`. The response must meet the shared
  [freshness rule](x509-revocation.md#freshness), including the producedAt bound.
- `max_responses`: the most SingleResponses read. It must be nonzero.
- `max_certificates`: the most delegate candidates examined across the response and the store. Zero
  suffices for an issuer-signed response.
- `parsing`: limits for the OCSPResponse, the inner BasicOCSPResponse, the certificate and every
  delegate candidate.
- `signatures`: the signature provider.

The response must hold exactly one SingleResponse for the certificate, with a SHA-1 or SHA-256
CertID that matches the issuer name hash, issuer key hash and serial number. Other SingleResponses
may cover other certificates. A SingleResponse with any other CertID hash makes the whole response
`TC_TLV_UNSUPPORTED`, even when it covers another certificate. An unknown critical extension in
responseExtensions or singleExtensions is `TC_TLV_UNSUPPORTED` (RFC 5280 section 4.2). A nonce is
accepted only as a noncritical responseExtension of 1 to 128 bytes.

## Responder authorization

RFC 6960 section 4.2.2.2 allows two signers:

- The issuer, named byName or byKey in the ResponderID. The signature must verify under
  `issuer->public_key`.
- A delegate the issuer certified directly. It must match the ResponderID and validate as a
  one-certificate path below the issuer at `time.at` with `time.clock_skew_seconds`. It needs
  `id-kp-OCSPSigning` in extendedKeyUsage and digitalSignature in a present keyUsage.
  anyExtendedKeyUsage alone is rejected, and path validation rejects unknown critical extensions.

`TC_X509_ocsp_response_verify` holds only the issuer name and key and treats the issuer as a bare
trust anchor, so a delegate is checked without the anchor's CertPathControls or constraints from
certificates above the issuer. [Path revocation](x509-revocation.md#ocsp-evidence) validates each
delegate under the selected anchor's names, policy set, policy flags and `x509_unusable` gate, with
every upstream constraint (RFC 5937 section 3.1, RFC 5914 section 2.5).

For a delegate, `responder_certificate` borrows its DER from the response or the store record, and
`responder_nocheck` reports `id-pkix-ocsp-nocheck`. Without nocheck, the caller establishes the
delegate's own revocation status before relying on the result (RFC 6960 section 4.2.2.2.1). [Path
revocation](x509-revocation.md#ocsp-evidence) does this with the CRL index. For an issuer-signed
response, `responder_certificate` is empty and `responder_nocheck` is zero.

## Results

| Result               | Meaning                                                                                                                                                                                         |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TC_TLV_OK`          | Authenticated and fresh. `status` is `TC_X509_REVOCATION_GOOD` or `TC_X509_REVOCATION_REVOKED`.                                                                                                 |
| `TC_TLV_UNSUPPORTED` | No decision: an authenticated unknown status, internalError, tryLater, sigRequired, unauthorized, or an unknown response type, CertID hash, version, critical extension or signature algorithm. |
| `TC_TLV_INVALID`     | Malformed DER, malformedRequest, no or a duplicate SingleResponse for the certificate, a wrong issuer, a nonce mismatch, stale or future times, removeFromCRL, or no authorized signer.         |
| `TC_TLV_LIMIT`       | Work, a parsing limit, workspace capacity, `max_responses` or `max_certificates` ran out.                                                                                                       |
| `TC_TLV_ARGUMENT`    | A required pointer is NULL, the nonce length is outside 32 to 128, `max_responses` is zero or `time.at` is invalid. A store callback or signature provider failure is also ARGUMENT.            |

REVOKED fills `revocation_time` and, when `has_reason` is set, `reason` with the CRLReason. Read
`next_update` only when `has_next_update` is set. Argument errors found at entry leave the result
and work unchanged. Every other failure zeroes the result. UNSUPPORTED and LIMIT never report a
status. Treat them like INVALID and fall back to CRLs or fail closed.

## Workspace and work

Both calls take a `TC_X509_path_workspace`:

- `frames`: one entry per constructed nesting level of the deepest object parsed, usually an
  embedded delegate certificate.
- `oids`: the extensions of each extension list.
- Name buffers: Name comparison.
- Delegate validation also uses one `certificates` entry, one `summaries` entry and the policy
  arrays.

The workspace holds parser views only. Serialize calls that share it.

Each call charges the response and BasicOCSPResponse bytes, the bytes hashed for each matching
CertID, Name comparison, extension walks, delegate path validation and every signature check. A
delegated response costs roughly one path validation and two signature checks. The example's
`EXAMPLE_OCSP_WORK_LIMIT` covers every SD 33 response. See [Work budgets](api.md#work-budgets) for
units and the native provider's per-signature reservation.

Keep the response, certificate, store records and issuer bytes unchanged during the call and while
`responder_certificate` is in use.

## Limitations

- Requests are unsigned and cover one certificate.
- CertIDs use SHA-1 or SHA-256.
- The module has no transport, cache or response pre-fetching.
- The low-level verify checks a delegate below the bare issuer and leaves the revocation check of a
  delegate without nocheck to the caller, as described under [responder
  authorization](#responder-authorization).

## Testing

`test_x509_ocsp_sd33` verifies the NIST SD 33 captured responses, compares request encoding with
OpenSSL-generated requests and runs the example. `test_x509_ocsp_icam` covers the ICAM delegates
with and without nocheck, store-supplied delegates and the composed path check. With
`TINY_CRYPTO_TEST_OPENSSL=ON`, `test_x509_ocsp_openssl` generates issuer-signed and delegated
responses and covers rejected delegates, CertID hashes, duplicate SingleResponses, critical
extensions, nonces, work limits and CRL fallback. `fuzz_ocsp` fuzzes both operations. See
[Running the tests](testing.md).
