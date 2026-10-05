<!-- SPDX-FileCopyrightText: Mistial Dev -->

<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Native signature verification

`<tiny_crypto/x509_crypto.h>` supplies a native signature provider for the X.509 message, digest,
certificate and path APIs. Enable X.509, the EC and RSA algorithms you need, and the hashes your
certificates use.

```c
TC_ECDSA_workspace ec;
TC_RSA_word words[TC_RSA_VERIFY_WORKSPACE_WORDS(3072)];
const TC_RSA_workspace rsa = {words, sizeof words / sizeof *words};
const TC_X509_native_workspace scratch = {&ec, &rsa, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
TC_X509_signature_provider provider = TC_X509_native_provider(&scratch);
```

Pass `provider` to `TC_X509_signature_verify` or set it as the path options' `signatures` field.
Set an unused EC or RSA workspace pointer to NULL. Keep the workspace metadata alive for every call
and serialize calls that share scratch. Overlap rules follow
[Input stability and overlap](api.md#input-stability-and-overlap).

The provider hashes message segments in order without copying them. It verifies DER ECDSA
signatures on the enabled P-192, P-256 and P-384 curves and RSA PKCS#1 v1.5 and PSS. Algorithms
missing from the build, and keys on a disabled or unidentified curve, return
`TC_X509_SIGNATURE_UNSUPPORTED`. A PSS-only key rejects v1.5
signatures. When PSS key parameters are present, the signature and MGF hashes must match them and
the salt length must meet the key's minimum.

For content already hashed, call `TC_X509_signature_verify_digest` with a `TC_signature_algorithm`
that names the scheme, the digest hash and, for PSS, the MGF hash and salt length in bytes. The
digest is used as supplied. PSS still needs its signature and MGF hash implementations to check the
encoding. ECDSA and v1.5 accept external digests without the matching hash implementation.

A custom provider supplies `verify`, `verify_digest` or both, with unused callbacks set to NULL. A
missing operation returns `UNSUPPORTED`, and digest verification never falls back to the message
callback. Each callback receives the message as ordered spans, which may be empty, and hashes them
in order. Callbacks enforce key restrictions and algorithm parameters, perform the cryptographic
check and only decrease `work`.

`signature_work` is reserved from the shared budget for each attempt. Parsing, input checks and
hashing charge work too. `TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK` covers the supported curves and
RSA sizes with ordinary public exponents. See [Work budgets](api.md#work-budgets).

A valid signature authenticates bytes under a key. Path validation and application rules decide
trusted issuers, permitted uses, validity and accepted algorithms.

Configure with `-DTINY_CRYPTO_TEST_OPENSSL=ON` to build the OpenSSL comparison test
`test_x509_native`, then run the provider tests:

```sh
ctest --test-dir build -R '^test_x509_(native|signature)$' --output-on-failure
```
