/*
 * SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
/* Shared types for every module: TC_bytes and TC_buffer spans, random
 * sources, TC_work_budget, the common result enums and constant-time helpers.
 * Configuration: includes config.h.
 * Work: the functions in this header charge no work budget.
 * Contracts: docs/api.md, including the result model and work-budget units. */
#ifndef TINY_CRYPTO_COMMON_H_
#define TINY_CRYPTO_COMMON_H_

#include <tiny_crypto/config.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Result of the symmetric, hash, MAC and KDF APIs: TC_OK, TC_MISMATCH for a
 * tag or comparison that differs, and TC_ERROR for every other failure.
 * Authentication failures stay separate from argument errors so protocols
 * can reject hostile packets without treating them as internal errors. */
typedef int TC_status;
/* Random-fill callback. user is the TC_random_source context. Fill all
 * length bytes of output from a cryptographically secure source and return
 * TC_OK, or return another status when the request cannot be filled in
 * full. Library operations treat any other status as a failed source and
 * discard output. */
typedef TC_status (*TC_random_fn)(void* user, uint8_t* output, size_t length);
/* Borrowed immutable bytes. Keep the backing storage alive and unchanged while
 * a reader or parsed view uses it. NULL data is valid only for an empty span. */
typedef struct {
  const uint8_t* data;
  size_t length;
} TC_bytes;

/* Caller-owned writable storage. capacity counts bytes. */
typedef struct {
  uint8_t* data;
  size_t capacity;
} TC_buffer;

/* A random callback and its context. The caller owns context and keeps it
 * alive while any operation holds the source. */
typedef struct {
  TC_random_fn fill;
  void* context;
} TC_random_source;

/* Remaining algorithm units for EC, RSA and key challenges. Each header gives
 * its unit and cost functions. Operations consume the budget on success and
 * on failure (docs/api.md, Work budgets). */
typedef struct {
  uint32_t remaining;
} TC_work_budget;

/* Shared execution resources for randomized public-key operations. */
typedef struct {
  TC_random_source random;
  size_t random_attempts;
  TC_work_budget work;
} TC_execution;

/* Setup and resource-management results. */
typedef enum {
  TC_RESULT_OK,
  TC_RESULT_ARGUMENT,
  TC_RESULT_LIMIT,
  TC_RESULT_UNSUPPORTED,
  TC_RESULT_ERROR
} TC_result;

/* Credential validation combines signatures, trust policy and status evidence. */
typedef enum {
  TC_CREDENTIAL_VALID,
  TC_CREDENTIAL_INVALID,
  TC_CREDENTIAL_REVOKED,
  TC_CREDENTIAL_UNSUPPORTED,
  TC_CREDENTIAL_LIMIT,
  TC_CREDENTIAL_ERROR,
  /* A required trust or evidence source is unavailable. */
  TC_CREDENTIAL_UNAVAILABLE
} TC_credential_status;

/* Each identifier exists whether or not its hash is enabled. */
typedef enum {
  TC_HASH_UNKNOWN,
  TC_HASH_SHA1,
  TC_HASH_SHA224,
  TC_HASH_SHA256,
  TC_HASH_SHA384,
  TC_HASH_SHA512
} TC_hash_algorithm;

typedef enum {
  TC_EC_UNKNOWN,
  TC_EC_P256,
  TC_EC_P384,
  TC_EC_P521,
  TC_EC_P224,
  TC_EC_SECP256K1,
  TC_EC_BRAINPOOL_P256,
  TC_EC_BRAINPOOL_P384,
  TC_EC_BRAINPOOL_P512,
  TC_EC_P192
} TC_EC_curve;

#define TC_ERROR (-1)
#define TC_OK 0
#define TC_MISMATCH 1

/* Best-effort secret wipe: write zero to length bytes of memory through
 * volatile stores. GCC and Clang builds add a compiler memory barrier. This
 * defeats common dead-store removal. memory must be writable for length bytes. NULL is
 * accepted only when length is zero. Copies already held in CPU registers
 * or elsewhere remain. */
void TC_secure_zero(void* memory, size_t length);

/* Constant-time comparison of length bytes. length is public, and the scan
 * always covers every byte. a and b may overlap.
 * Returns TC_OK when the bytes are equal, TC_MISMATCH when any byte differs
 * and TC_ERROR when length is nonzero and a or b is NULL. */
TC_status TC_ct_equal(const uint8_t* a, const uint8_t* b, size_t length);

#ifdef __cplusplus
}
#endif

#endif
