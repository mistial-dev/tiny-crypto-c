/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Native signature provider for the X.509 APIs: ECDSA and RSA PKCS #1 v1.5
 * and PSS verification over caller workspaces.
 * Standards: FIPS 186-5, RFC 8017, RFC 5758, RFC 4055.
 * Configuration: TC_ENABLE_X509 with TC_ENABLE_EC or TC_ENABLE_RSA and the
 * hashes the certificates use.
 * Contracts: docs/api.md, including its size_t work units.
 * Guide: docs/x509-crypto.md. */
#ifndef TINY_CRYPTO_X509_CRYPTO_H_
#define TINY_CRYPTO_X509_CRYPTO_H_
#include <tiny_crypto/x509.h>
#include <tiny_crypto/ec.h>
#include <tiny_crypto/rsa.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Budget for supported curves and RSA sizes with ordinary public exponents. */
#define TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK 32768u

typedef struct {
  TC_ECDSA_workspace* ec;
  const TC_RSA_workspace* rsa;
  /* Reserved from the shared budget for each crypto attempt. */
  size_t signature_work;
} TC_X509_native_workspace;

/* Native ECDSA and RSA v1.5/PSS provider for message and digest verification.
 * Enable the required EC/RSA and hash implementations in the build. A missing
 * algorithm returns UNSUPPORTED. A missing required workspace returns ERROR.
 * Either workspace may be NULL when its algorithm is not used.
 *
 * Keep workspace metadata alive while using the provider. Crypto scratch must
 * be separate from metadata, message/key/signature bytes and the work counter.
 * Calls sharing scratch must be serialized. The provider hashes borrowed
 * segments without allocation, using one temporary hash context and digest.
 * The digest operation uses the supplied digest as-is. PSS still needs its
 * signature and MGF hashes to check the encoded signature.
 * This verifies signatures. Certificate trust and application policy are
 * separate steps. */
TC_X509_signature_provider TC_X509_native_provider(const TC_X509_native_workspace* workspace);

#ifdef __cplusplus
}
#endif
#endif
