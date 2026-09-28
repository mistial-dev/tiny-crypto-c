/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TINY_CRYPTO_KEY_CHALLENGE_H_
#define TINY_CRYPTO_KEY_CHALLENGE_H_
#include <tiny_crypto/x509.h>
#include <tiny_crypto/rsa.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  TC_KEY_CHALLENGE_OK,
  TC_KEY_CHALLENGE_INVALID,
  TC_KEY_CHALLENGE_UNSUPPORTED,
  TC_KEY_CHALLENGE_LIMIT,
  TC_KEY_CHALLENGE_ERROR
} TC_key_challenge_result;

typedef struct {
  TC_signature_algorithm signature;
} TC_key_challenge_options;

/* Storage bounds for one challenge. The input holds an RSA encoded message
 * of the modulus length, or an ECDSA digest. PSS salts are at most one
 * SHA-512 digest long. */
enum {
  TC_KEY_CHALLENGE_MAX_DIGEST_BYTES = 64,
  TC_KEY_CHALLENGE_MAX_SALT_BYTES = 64,
#if TC_ENABLE_RSA
  TC_KEY_CHALLENGE_MAX_INPUT_BYTES = TC_RSA_MAX_MODULUS_BYTES
#else
  TC_KEY_CHALLENGE_MAX_INPUT_BYTES = TC_KEY_CHALLENGE_MAX_DIGEST_BYTES
#endif
};

/* Caller-owned state for one proof-of-possession challenge. Keep key and
 * provider inputs alive and unchanged until verify or clear. The returned
 * challenge borrows this storage. Do not copy an active workspace. */
typedef struct {
  uint8_t digest[TC_KEY_CHALLENGE_MAX_DIGEST_BYTES];
  uint8_t challenge[TC_KEY_CHALLENGE_MAX_INPUT_BYTES];
  TC_signature_algorithm signature;
  size_t digest_length;
  uint32_t state;
} TC_key_challenge_workspace;

/* Generate a fresh random digest and prepare the input for a private-key
 * operation. RSA returns an encoded representative of the modulus length.
 * ECDSA returns the digest.
 *
 * Supported keys are RSA moduli accepted by TC_RSA_modulus_supported, with
 * PKCS #1 v1.5 or PSS and a salt of at most TC_KEY_CHALLENGE_MAX_SALT_BYTES,
 * and ECDSA keys. Other keys, schemes and sizes return UNSUPPORTED.
 *
 * Work is the digest length, plus the salt length for PSS, plus
 * TC_RSA_encode_v15_work or TC_RSA_encode_pss_work for RSA. A smaller budget
 * returns LIMIT before any RNG use.
 *
 * Preflight failures preserve workspace, out and work. Failures after RNG use
 * wipe workspace. Keep all storage disjoint. */
TC_key_challenge_result TC_key_challenge_prepare(const TC_X509_public_key* key,
                                                 const TC_key_challenge_options* options,
                                                 TC_random_source random,
                                                 TC_key_challenge_workspace* workspace,
                                                 TC_work_budget* work, TC_bytes* out);

/* Verify the private operation's result against the retained digest. This
 * clears every initialized challenge. A bad proof returns INVALID. Exhausted
 * work returns LIMIT. Keep borrowed inputs and provider state disjoint from
 * workspace. */
TC_key_challenge_result TC_key_challenge_verify(const TC_X509_public_key* key, TC_bytes signature,
                                                const TC_X509_signature_provider* provider,
                                                TC_key_challenge_workspace* workspace,
                                                TC_work_budget* work);

/* Abandon an active challenge and wipe its digest and representative. */
void TC_key_challenge_clear(TC_key_challenge_workspace* workspace);

#ifdef __cplusplus
}
#endif
#endif
