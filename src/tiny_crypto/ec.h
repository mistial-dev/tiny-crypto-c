/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Elliptic-curve operations on P-192, P-256 and P-384: key generation,
 * public-key derivation and validation, ECDH and ECDSA.
 * Standards: FIPS 186-5, SP 800-186, SP 800-56A Rev. 3, SEC 1.
 * Configuration: TC_ENABLE_EC, TC_EC_ENABLE_P192/P256/P384 and TC_EC_SMALL.
 * Limitations: uncompressed SEC 1 points only. P-192 is off by default.
 * Contracts: docs/api.md, including its TC_work_budget units. Guide: docs/ec.md. */
#ifndef TINY_CRYPTO_EC_H_
#define TINY_CRYPTO_EC_H_
#include <tiny_crypto/common.h>

#if TC_EC_SMALL || defined(__AVR__)
typedef uint8_t TC_EC_word;
#define TC_EC_WORD_BITS 8
#else
typedef uint32_t TC_EC_word;
#define TC_EC_WORD_BITS 32
#endif
#if TC_EC_ENABLE_P384
#define TC_EC_MAX_BYTES 48
#else
#define TC_EC_MAX_BYTES 32
#endif
#define TC_EC_MAX_WORDS (TC_EC_MAX_BYTES / (TC_EC_WORD_BITS / 8))

/* Scratch storage for one operation. Members are private to the implementation.
 * Each concurrent operation needs its own workspace. */
typedef struct {
  TC_EC_word fields[30][TC_EC_MAX_WORDS];
  TC_EC_word product[2 * TC_EC_MAX_WORDS + 2];
  TC_EC_word reduced[TC_EC_MAX_WORDS];
} TC_EC_workspace;

typedef struct {
  TC_EC_workspace ec;
  TC_EC_word scalars[2][TC_EC_MAX_WORDS];
  TC_EC_word point[3][TC_EC_MAX_WORDS];
} TC_ECDSA_workspace;

#ifdef __cplusplus
extern "C" {
#endif

/* Results. Every EC function checks its arguments once, in this order, and
 * reports the first problem it finds:
 *
 *   TC_EC_ARGUMENT     NULL pointers, an empty digest and overlapping storage.
 *   TC_EC_UNSUPPORTED  a curve that is unknown or disabled in this build.
 *   TC_EC_INVALID      a private key, public key or signature whose length
 *                      does not match the curve.
 *   TC_EC_LIMIT        a caller output buffer shorter than required, then
 *                      too little work or too few random attempts.
 *
 * After these checks, TC_EC_INVALID also reports a private scalar outside
 * [1, n - 1], a point that is not on the curve and a signature that does not
 * verify. TC_EC_ERROR reports a random source failure or a signature that
 * failed its own verification. Output buffers larger than required are
 * accepted, and exactly the documented length is written. Outputs change only
 * on TC_EC_OK. UNSUPPORTED and LIMIT never report success. Argument errors
 * and limits found before arithmetic leave the workspace, the work budget and
 * the random source untouched. */
typedef enum {
  TC_EC_OK,
  TC_EC_INVALID,
  TC_EC_LIMIT,
  TC_EC_ARGUMENT,
  TC_EC_UNSUPPORTED,
  TC_EC_ERROR
} TC_EC_result;

/* Randomized operations draw from random, making at most random_attempts
 * requests. Work is reduced by the units completed on success and failure. */
typedef struct {
  TC_random_source random;
  size_t random_attempts;
  TC_work_budget work;
} TC_EC_execution;

typedef enum {
  TC_EC_OPERATION_PUBLIC_KEY,
  TC_EC_OPERATION_VALIDATE,
  TC_EC_OPERATION_ECDH,
  TC_EC_OPERATION_VERIFY,
  TC_EC_OPERATION_SIGN,    /* one nonce attempt, including self-verification */
  TC_EC_OPERATION_GENERATE /* one scalar attempt */
} TC_EC_operation;

/* Work units for one operation, or one attempt of a randomized operation, on
 * curve. A scalar multiplication or a modular inversion costs one unit per
 * curve bit; point validation and each random request cost one unit. Zero for
 * an unsupported curve or unknown operation. An operation checks its full cost
 * before it starts and returns LIMIT, with work unchanged, when the budget is
 * short. */
uint32_t TC_EC_operation_work(TC_EC_curve curve, TC_EC_operation operation);

/* Bytes in one coordinate or private scalar of curve: 24 for P-192, 32 for
 * P-256 and 48 for P-384. Zero for a curve that is unknown or disabled in this
 * build. A SEC 1 uncompressed public key is 1 + 2 * width bytes and a fixed
 * r || s signature is 2 * width bytes. */
size_t TC_EC_coordinate_bytes(TC_EC_curve curve);

/* Scalars and coordinates are fixed-width, big-endian values of
 * TC_EC_coordinate_bytes(curve) bytes. Public keys use SEC 1 uncompressed
 * encoding, 04 || X || Y. Input lengths must match the curve exactly. Output
 * buffers need at least the required capacity. Output and workspace must not
 * overlap each other or any input. Scratch is wiped after use. Private-scalar
 * operations use constant-work point multiplication. */
TC_EC_result TC_EC_public_key(TC_EC_curve curve, TC_bytes private_key, TC_buffer public_key,
                              TC_EC_workspace* workspace, TC_work_budget* work);
/* Generate a private scalar and matching SEC 1 public key. The RNG must be
 * cryptographically secure and fill the whole request. Out-of-range scalar
 * draws are retried within execution->random_attempts. Temporary scalar and
 * public-key storage is wiped on return. The RNG context must not overlap the
 * outputs or workspace. */
TC_EC_result TC_EC_generate_key_pair(TC_EC_curve curve, TC_buffer private_key, TC_buffer public_key,
                                     TC_EC_workspace* workspace, TC_EC_execution* execution);
/* Check that an uncompressed public key is a point on the curve (SEC 1
 * 3.2.2.1). */
TC_EC_result TC_EC_validate_public_key(TC_EC_curve curve, TC_bytes public_key,
                                       TC_EC_workspace* workspace, TC_work_budget* work);
/* Write the shared point's X coordinate, including leading zero bytes, after
 * validating the peer key. Pass this value through the protocol's key
 * derivation function before use. */
TC_EC_result TC_ECDH(TC_EC_curve curve, TC_bytes private_key, TC_bytes peer_public_key,
                     TC_buffer shared_secret, TC_EC_workspace* workspace, TC_work_budget* work);

/* Verify a precomputed digest with a SEC 1 uncompressed public key.
 * Signature encoding is fixed-width big-endian r || s. Convert DER signatures
 * first. Digests longer than the curve order are truncated to their leftmost
 * bytes. Both high and low s are accepted. Verification branches on public
 * scalar bits. TC_EC_INVALID means the signature or public key is invalid. */
TC_EC_result TC_ECDSA_verify_digest(TC_EC_curve curve, TC_bytes public_key, TC_bytes digest,
                                    TC_bytes signature, TC_ECDSA_workspace* workspace,
                                    TC_work_budget* work);

/* Sign a precomputed digest with a fixed-width private scalar. public_key is
 * the matching SEC 1 public key. The RNG supplies an independent secret nonce
 * on each attempt, within execution->random_attempts. It must be
 * cryptographically secure and fill the entire request. Signature encoding is
 * fixed-width big-endian r || s. Digests longer than the order are truncated
 * to their leftmost bytes. With TC_ECDSA_SIGN_VERIFY (default 1), the
 * signature is verified against public_key before it is written, so a fault
 * or a public key that does not match returns TC_EC_ERROR. Inputs, output and
 * workspace must be pairwise disjoint. The RNG context must not overlap them. */
TC_EC_result TC_ECDSA_sign_digest(TC_EC_curve curve, TC_bytes private_key, TC_bytes public_key,
                                  TC_bytes digest, TC_buffer signature,
                                  TC_ECDSA_workspace* workspace, TC_EC_execution* execution);

#ifdef __cplusplus
}
#endif
#endif
