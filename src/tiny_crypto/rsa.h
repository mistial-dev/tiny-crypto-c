/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* RSA public and private-key operations: PKCS #1 v1.5 and PSS signatures,
 * OAEP, raw operations, key validation, CRT derivation and stepwise key
 * generation.
 * Standards: RFC 8017, FIPS 186-5 appendices A.1 and C.
 * Configuration: TC_ENABLE_RSA and TC_RSA_SMALL.
 * Limitations: two-prime keys of 1024, 2048, 3072 or 4096 bits.
 * Contracts: docs/api.md, including its TC_work_budget units.
 * Guide: docs/rsa.md. */
#ifndef TINY_CRYPTO_RSA_H_
#define TINY_CRYPTO_RSA_H_
#include <tiny_crypto/common.h>
#if TC_RSA_SMALL || defined(__AVR__)
typedef uint8_t TC_RSA_word;
#define TC_RSA_WORD_BITS 8
#else
typedef uint32_t TC_RSA_word;
#define TC_RSA_WORD_BITS 32
#endif

/* Supported moduli are 1024, 2048, 3072 and 4096 bits. Size caller storage
 * that holds a modulus-length value, such as an encoded message or a
 * signature, from TC_RSA_MAX_MODULUS_BYTES. */
#define TC_RSA_MAX_MODULUS_BITS 4096u
#define TC_RSA_MAX_MODULUS_BYTES (TC_RSA_MAX_MODULUS_BITS / 8u)

/* Results. Every RSA function checks its arguments once, in this order, and
 * reports the first problem it finds:
 *
 *   TC_RSA_ARGUMENT     NULL pointers, overlapping or misaligned storage, and
 *                       a digest whose length differs from its known hash.
 *   TC_RSA_UNSUPPORTED  a modulus size, hash or option the build does not
 *                       implement.
 *   TC_RSA_INVALID      a malformed key or CRT value, out-of-range scheme
 *                       parameters, then received data: a signature,
 *                       ciphertext or raw input of the wrong length.
 *   TC_RSA_LIMIT        a caller output buffer shorter than required, then
 *                       too little workspace, RNG attempts or work.
 *
 * The arithmetic finds a representative at or above the modulus and returns
 * TC_RSA_INVALID after the limit checks pass. Output buffers larger than
 * required are accepted, and exactly the documented length is written.
 * UNSUPPORTED and LIMIT never report success. Argument errors and limits
 * found before arithmetic leave every output, the workspace and the work
 * budget unchanged. */
typedef enum {
  TC_RSA_OK,
  TC_RSA_INVALID,
  TC_RSA_LIMIT,
  TC_RSA_ARGUMENT,
  TC_RSA_UNSUPPORTED,
  TC_RSA_ERROR, /* Random-source, hash or private-operation verification failure. */
  TC_RSA_IN_PROGRESS,
  TC_RSA_CANCELLED
} TC_RSA_result;
typedef struct {
  TC_bytes modulus, exponent;
} TC_RSA_public_key;
typedef struct {
  TC_bytes dp, dq, q_inverse;
} TC_RSA_crt;
typedef struct {
  TC_RSA_public_key public_key;
  TC_bytes d, p, q;
  /* Optional validated CRT values. NULL selects full-width exponentiation. */
  const TC_RSA_crt* crt;
} TC_RSA_private_key;
typedef struct {
  TC_buffer dp, dq, q_inverse;
} TC_RSA_crt_output;
typedef struct {
  TC_RSA_word* words;
  size_t capacity;
} TC_RSA_workspace;
/* Optional setup for repeated verification with an unchanged borrowed key.
 * Initialize with TC_RSA_prepare_public_key and clear before releasing the key. */
typedef struct {
  TC_RSA_public_key key;
  TC_RSA_workspace r2;
  uint32_t marker;
} TC_RSA_prepared_public_key;
typedef int (*TC_RSA_cancel_fn)(void* user);
typedef struct {
  TC_buffer modulus, exponent, d, p, q;
} TC_RSA_keygen_output;
typedef struct {
  uint32_t candidate_attempts;
  uint32_t random_requests;
} TC_RSA_keygen_limits;
typedef struct {
  TC_random_source random;
  size_t random_attempts;
  /* Reduced by work completed on success and failure. */
  TC_work_budget work;
} TC_RSA_execution;
typedef struct {
  TC_hash_algorithm hash;
} TC_RSA_v15_options;
typedef struct {
  TC_hash_algorithm hash, mgf_hash;
  size_t salt_length;
} TC_RSA_pss_options;
typedef struct {
  TC_hash_algorithm hash, mgf_hash;
  TC_bytes label;
} TC_RSA_oaep_options;
/* Public exponent range accepted by private-key validation. The zero value
 * applies FIPS 186-5. ANY_ODD admits keys outside FIPS 186-5, such as test
 * vectors with e = 3. */
typedef enum { TC_RSA_EXPONENT_FIPS = 0, TC_RSA_EXPONENT_ANY_ODD } TC_RSA_exponent_policy;

/* Caller-owned resumable state. Zero-initialize before the first init and
 * access it only through the key-generation functions below. */
typedef struct {
  TC_RSA_workspace workspace;
  TC_RSA_keygen_output output;
  uint32_t marker, bits, candidate_limit, random_limit;
  uint32_t candidates, random_requests;
  uint16_t phase, rounds, twos;
  uint16_t reserved;
} TC_RSA_keygen_state;

/* Workspace limbs per operation for a supported, constant key size in bits,
 * for static arrays. TC_RSA_workspace_words gives the same values at run
 * time. Verification uses nine limb arrays and two carry words. */
#define TC_RSA_VERIFY_WORKSPACE_WORDS(bits) (9u * ((bits) / TC_RSA_WORD_BITS) + 2u)
#define TC_RSA_VALIDATE_WORKSPACE_WORDS(bits) (12u * ((bits) / TC_RSA_WORD_BITS) + 2u)
#define TC_RSA_CRT_WORKSPACE_WORDS(bits) (8u * ((bits) / TC_RSA_WORD_BITS))
#define TC_RSA_SIGN_WORKSPACE_WORDS(bits) (14u * ((bits) / TC_RSA_WORD_BITS))
#define TC_RSA_DECRYPT_WORKSPACE_WORDS(bits) (14u * ((bits) / TC_RSA_WORD_BITS))
#define TC_RSA_ENCRYPT_WORKSPACE_WORDS(bits) TC_RSA_VERIFY_WORKSPACE_WORDS(bits)
#define TC_RSA_RAW_PUBLIC_WORKSPACE_WORDS(bits) (8u * ((bits) / TC_RSA_WORD_BITS) + 2u)
#define TC_RSA_RAW_PRIVATE_WORKSPACE_WORDS(bits) (13u * ((bits) / TC_RSA_WORD_BITS))
#define TC_RSA_VALIDATION_ROUNDS 65u
/* Work that TC_RSA_validate_private_key can consume for a bits-bit key with
 * attempts RNG requests allowed per factor: the component checks, then one
 * Miller-Rabin setup, TC_RSA_VALIDATION_ROUNDS rounds and every request for
 * each half-width factor. */
#define TC_RSA_VALIDATE_WORK(bits, attempts)                                                       \
  (48u * ((bits) / 8u) + 2u +                                                                      \
   2u * ((24u * ((bits) / 16u) + 3u) + TC_RSA_VALIDATION_ROUNDS * (24u * ((bits) / 16u) + 1u) +    \
         (attempts)))
#define TC_RSA_KEYGEN_PUBLIC_EXPONENT 65537u
#define TC_RSA_KEYGEN_WORKSPACE_WORDS(bits) (7u * ((bits) / TC_RSA_WORD_BITS) + 2u)
#define TC_RSA_KEYGEN_STEP_WORK(bits) (24u * ((bits) / 16u) + 3u)

#ifdef __cplusplus
extern "C" {
#endif
/* Operations with distinct workspace requirements. */
typedef enum {
  TC_RSA_OPERATION_VERIFY,      /* PKCS #1 v1.5 and PSS verification */
  TC_RSA_OPERATION_ENCRYPT,     /* OAEP encryption */
  TC_RSA_OPERATION_RAW_PUBLIC,  /* TC_RSA_raw_public */
  TC_RSA_OPERATION_VALIDATE,    /* TC_RSA_validate_private_key */
  TC_RSA_OPERATION_CRT,         /* TC_RSA_validate_crt and TC_RSA_derive_crt */
  TC_RSA_OPERATION_SIGN,        /* PKCS #1 v1.5 and PSS signing */
  TC_RSA_OPERATION_DECRYPT,     /* OAEP decryption */
  TC_RSA_OPERATION_RAW_PRIVATE, /* TC_RSA_raw_private */
  TC_RSA_OPERATION_KEYGEN       /* TC_RSA_keygen_init */
} TC_RSA_operation;
/* Workspace limbs for operation at a key size in bits. Zero for an
 * unsupported key size or an unknown operation. */
size_t TC_RSA_workspace_words(TC_RSA_operation operation, size_t bits);

/* Prepare a borrowed public key for repeated v1.5 or PSS verification.
 * Cache needs one modulus width of limbs and scratch needs two; scratch is
 * wiped on return. Keep the cache and borrowed key bytes unchanged and alive
 * until clear. Setup, key, cache, scratch, and work must be disjoint. The
 * work is 16*modulus_bytes + 1. */
TC_RSA_result TC_RSA_prepare_public_key(TC_RSA_prepared_public_key* setup,
                                        const TC_RSA_public_key* key, const TC_RSA_workspace* cache,
                                        const TC_RSA_workspace* workspace, TC_work_budget* work);
void TC_RSA_prepared_public_key_clear(TC_RSA_prepared_public_key* setup);

/* Generate a two-prime RSA key with e=65537 and d = e^-1 mod LCM(p-1, q-1)
 * under FIPS 186-5 appendix A.1.1. Output capacities must be at
 * least bits/8 for modulus and d, bits/16 for p and q, and three bytes for e.
 * Output buffers remain unchanged until a complete key is published. Scratch,
 * state, outputs and their metadata must be mutually disjoint. init returns
 * ARGUMENT for a NULL pointer or buffer, misaligned scratch, overlap or an
 * active state, UNSUPPORTED for another key size, and LIMIT for zero limits
 * or a buffer or scratch shorter than required. Failures leave state,
 * outputs and scratch unchanged.
 *
 * Each step performs at most work->remaining units and returns
 * TC_RSA_IN_PROGRESS when more work is needed. The configured limits bound
 * candidate generation and every RNG request across all steps. Cancellation
 * and terminal failures wipe retained candidates. TC_RSA_KEYGEN_STEP_WORK(bits) lets every pending unit
 * make progress. The RNG must fill each request completely. Callback contexts
 * must be separate from state, scratch and outputs. Call clear after success or
 * whenever abandoning an in-progress operation. */
TC_RSA_result TC_RSA_keygen_init(TC_RSA_keygen_state* state, size_t bits,
                                 const TC_RSA_keygen_output* output, TC_RSA_keygen_limits limits,
                                 const TC_RSA_workspace* workspace);
TC_RSA_result TC_RSA_keygen_step(TC_RSA_keygen_state* state, TC_random_source random,
                                 TC_RSA_cancel_fn cancel, void* cancel_context,
                                 TC_work_budget* work);
void TC_RSA_keygen_clear(TC_RSA_keygen_state* state);

/* Apply RSA (RFC 8017 sections 5.1 and 5.2) to one already formatted,
 * fixed-width representative. No padding, hashing or encoding is provided.
 * Callers select and validate their protocol's encoding. Input has the
 * modulus length and must be less than the modulus, otherwise the result is
 * TC_RSA_INVALID. output.capacity is at least modulus.length, a shorter
 * buffer returns TC_RSA_LIMIT, and exactly modulus.length bytes are written,
 * only on TC_RSA_OK. Scratch is wiped after use. All borrowed inputs,
 * output, metadata, work and scratch are disjoint.
 *
 * The private operation takes a private exponent of 1 to modulus.length
 * bytes. It blinds the input, and verifies the result with the public
 * exponent before publishing it. A failed verification returns
 * TC_RSA_ERROR. Its RNG must provide full-width unpredictable bytes and its
 * context must not overlap the other arguments. The work is
 * TC_RSA_public_work(key) for the public operation and TC_RSA_private_work
 * for a key without CRT values for the private operation. */
TC_RSA_result TC_RSA_raw_public(const TC_RSA_public_key* key, TC_bytes input,
                                const TC_RSA_workspace* workspace, TC_buffer output,
                                TC_work_budget* work);
TC_RSA_result TC_RSA_raw_private(const TC_RSA_public_key* key, TC_bytes private_exponent,
                                 TC_bytes input, const TC_RSA_workspace* workspace,
                                 TC_buffer output, TC_RSA_execution* execution);

/* Return 1 when bits names a supported modulus size, otherwise 0. */
int TC_RSA_modulus_supported(size_t bits);

/* Work contracts. TC_work_budget counts public work units: modular
 * operations, encoded and masked bytes, hash invocations and RNG requests. It
 * does not measure time. The functions below return the exact work of one
 * successful call, or 0 for a NULL argument, an unknown or disabled hash, an
 * unsupported size or key, parameters the operation rejects, or a cost
 * above UINT32_MAX. Operations add them as follows:
 *
 *   TC_RSA_raw_public           TC_RSA_public_work
 *   TC_RSA_verify_v15_digest    TC_RSA_public_work + TC_RSA_encode_v15_work
 *   TC_RSA_verify_pss_digest    TC_RSA_public_work + TC_RSA_encode_pss_work
 *   TC_RSA_verify_*_prepared    TC_RSA_prepared_public_work in place of
 *                               TC_RSA_public_work
 *   TC_RSA_encrypt_oaep         1 + TC_RSA_oaep_work + TC_RSA_public_work
 *   TC_RSA_raw_private          TC_RSA_private_work
 *   TC_RSA_sign_v15_digest      TC_RSA_private_work + TC_RSA_encode_v15_work
 *   TC_RSA_sign_pss_digest      TC_RSA_private_work + TC_RSA_encode_pss_work
 *                               + 1 when salt_length is nonzero
 *   TC_RSA_decrypt_oaep         TC_RSA_private_work + TC_RSA_oaep_work
 *
 * Each operation checks its cost, with one blinding attempt for private
 * keys, before arithmetic or any RNG request. A smaller budget returns
 * TC_RSA_LIMIT and leaves outputs, work and the RNG untouched. A rejected
 * blinding factor costs one more attempt, so budget TC_RSA_private_work with
 * execution.random_attempts to cover every attempt. Verification consumes
 * work up to the point where it detects an invalid signature. */

/* EMSA-PKCS1-v1_5 and EMSA-PSS encoding for a modulus of modulus_bytes. The
 * same cost covers PSS encoding and PSS verification. */
uint32_t TC_RSA_encode_v15_work(const TC_RSA_v15_options* options, size_t modulus_bytes);
uint32_t TC_RSA_encode_pss_work(const TC_RSA_pss_options* options, size_t modulus_bytes);
/* EME-OAEP encoding or decoding with both MGF1 masks: modulus_bytes +
 * label length + 1, then D + ceil(D/G)*(H + 5) and H + ceil(H/G)*(D + 5)
 * for message-hash length H, MGF-hash length G and D = modulus_bytes - H - 1. */
uint32_t TC_RSA_oaep_work(const TC_RSA_oaep_options* options, size_t modulus_bytes);
/* One public operation: 16*modulus_bytes + 16*exponent_bytes + 4. */
uint32_t TC_RSA_public_work(const TC_RSA_public_key* key);
/* One public operation with the setup's cached R^2: 16*exponent_bytes + 4.
 * Preparing the setup costs 16*modulus_bytes + 1. Returns 0 for a setup that
 * TC_RSA_prepare_public_key did not initialize. */
uint32_t TC_RSA_prepared_public_work(const TC_RSA_prepared_public_key* setup);
/* One private operation with at most attempts blinding requests, attempts
 * from 1. Full width costs 32*modulus_bytes + 32*exponent_bytes + 8, and a
 * key with key->crt set costs 48*modulus_bytes + 32*exponent_bytes + 12.
 * Each attempt adds 16*modulus_bytes + 1. Only key->public_key and whether
 * key->crt is NULL are read, so a raw private operation can pass a key that
 * holds only its public key. */
uint32_t TC_RSA_private_work(const TC_RSA_private_key* key, size_t attempts);

/* Encode a precomputed SHA digest using EMSA-PKCS1-v1_5 (RFC 8017 section 9.2).
 * Used when a card or hardware provider performs the RSA private operation.
 * encoded.capacity is the modulus size: 128, 256, 384 or 512 bytes. No hashing or key
 * operation is performed. encoded and work are disjoint from the options, the
 * digest and each other. All failures preserve output. The work is
 * TC_RSA_encode_v15_work. */
TC_RSA_result TC_RSA_encode_v15_digest(const TC_RSA_v15_options* options, TC_bytes digest,
                                       TC_buffer encoded, TC_work_budget* work);

/* Encode a digest and caller-supplied salt using EMSA-PSS (RFC 8017 section 9.1.1).
 * encoded.capacity is the modulus size: 128, 256, 384 or 512 bytes. emBits is one
 * less than that size in bits. salt.length must equal options->salt_length,
 * otherwise the result is TC_RSA_ARGUMENT. Generate salt with a cryptographic RNG. Inputs may share storage. encoded
 * and work are disjoint from every input and each other. The work is
 * TC_RSA_encode_pss_work, and a smaller budget returns TC_RSA_LIMIT with
 * output and work unchanged. A hash failure during encoding returns
 * TC_RSA_ERROR, wipes output and consumes work. */
TC_RSA_result TC_RSA_encode_pss_digest(const TC_RSA_pss_options* options, TC_bytes digest,
                                       TC_bytes salt, TC_buffer encoded, TC_work_budget* work);

/* OAEP encryption (RFC 8017 section 7.1.1) with explicit message and MGF
 * hashes. Both must be enabled. Message length is at most modulus_bytes -
 * 2*hash_bytes - 2, and a longer message returns TC_RSA_INVALID. An empty
 * label is {NULL,0}. ciphertext.capacity is at least the modulus length, a
 * shorter buffer returns TC_RSA_LIMIT, and exactly the modulus length is
 * written, only on TC_RSA_OK. The RNG supplies one hash-sized seed and a
 * failed request returns TC_RSA_ERROR. Keep output, scratch and RNG state
 * separate from inputs and metadata. Used scratch is wiped. The work is
 * 1 + TC_RSA_oaep_work + TC_RSA_public_work and is checked in full before the
 * seed request. */
TC_RSA_result TC_RSA_encrypt_oaep(const TC_RSA_public_key* key, const TC_RSA_oaep_options* options,
                                  TC_bytes plaintext, const TC_RSA_workspace* workspace,
                                  TC_buffer ciphertext, TC_RSA_execution* execution);

/* OAEP decryption (RFC 8017 section 7.1.2) with a validated, unchanged
 * private key and explicit hashes. Both hashes must be enabled. Ciphertext
 * has the modulus length, otherwise the result is TC_RSA_INVALID. Label bytes
 * are borrowed. {NULL,0} selects an empty label. plaintext_length is an
 * aligned size_t. plaintext.capacity must be at least modulus_bytes -
 * 2*hash_bytes - 2. A smaller buffer returns TC_RSA_LIMIT before decryption,
 * without drawing randomness or consuming work, so the status reveals nothing
 * about the padding (RFC 8017 section 7.1.2). Invalid padding and a wrong
 * label return TC_RSA_INVALID. Plaintext and its length change only on
 * TC_RSA_OK. Output bytes, length, scratch and RNG state are separate from
 * each other, inputs and metadata. Used scratch is wiped on return. The work
 * is TC_RSA_private_work + TC_RSA_oaep_work. */
TC_RSA_result TC_RSA_decrypt_oaep(const TC_RSA_private_key* key, const TC_RSA_oaep_options* options,
                                  TC_bytes ciphertext, const TC_RSA_workspace* workspace,
                                  TC_buffer plaintext, size_t* plaintext_length,
                                  TC_RSA_execution* execution);

/* Sign a precomputed SHA digest with PKCS#1 v1.5 (RFC 8017 section 8.2.1)
 * using a validated private key. Validate the components before use and keep
 * them unchanged afterward. signature.capacity is at least the modulus
 * length, a shorter buffer returns TC_RSA_LIMIT, and exactly the modulus
 * length is written, only on TC_RSA_OK. All input, output, metadata, scratch
 * and RNG state are disjoint. RNG requests provide blinding factors, and
 * execution.random_attempts bounds rejected factors. A failed RNG request
 * returns TC_RSA_ERROR. The result is checked with the public exponent before
 * it is published, and a failed check returns TC_RSA_ERROR. Used scratch is
 * wiped. Hash implementations are optional. The work is TC_RSA_private_work +
 * TC_RSA_encode_v15_work. */
TC_RSA_result TC_RSA_sign_v15_digest(const TC_RSA_private_key* key,
                                     const TC_RSA_v15_options* options, TC_bytes digest,
                                     const TC_RSA_workspace* workspace, TC_buffer signature,
                                     TC_RSA_execution* execution);

/* PSS signing (RFC 8017 section 8.1.1) uses explicit message/MGF hashes and
 * salt length. Both hashes must be enabled. The RNG supplies salt and
 * blinding bytes, and a zero-length salt skips its RNG request. Output,
 * workspace, key and status rules match v1.5 signing. The work is
 * TC_RSA_private_work + TC_RSA_encode_pss_work, plus 1 for a salt request. */
TC_RSA_result TC_RSA_sign_pss_digest(const TC_RSA_private_key* key,
                                     const TC_RSA_pss_options* options, TC_bytes digest,
                                     const TC_RSA_workspace* workspace, TC_buffer signature,
                                     TC_RSA_execution* execution);

/* Validate two-prime RSA components at 1024, 2048, 3072 or 4096 bits. Public components
 * use minimal unsigned encodings. d, p and q are nonempty unsigned magnitudes,
 * at most the modulus length; leading zero bytes are accepted.
 * All key bytes are borrowed and must remain stable throughout the call.
 * Checks component equations and runs 65 Miller-Rabin rounds per factor.
 * execution.random must provide independent cryptographically secure bytes.
 * execution.random_attempts bounds total RNG requests per factor and must be
 * at least 65. RNG state must be separate from key bytes, metadata and
 * workspace. Scratch is wiped after use.
 * The work budget is 32-bit on every target, including targets with 16-bit size_t.
 *
 * The FIPS 186-5 appendix A.1.1 criteria are checked in addition to the
 * component equations: sqrt(2) 2^(nlen/2 - 1) <= p, q; |p - q| >
 * 2^(nlen/2 - 100); 2^(nlen/2) < d < LCM(p - 1, q - 1); and e d = 1 mod
 * LCM(p - 1, q - 1). exponent_policy selects the public exponent range:
 * TC_RSA_EXPONENT_FIPS requires TC_RSA_exponent_in_fips_range, and
 * TC_RSA_EXPONENT_ANY_ODD accepts any odd 3 <= e < n. Every other criterion
 * applies under both policies. An unknown policy returns TC_RSA_ARGUMENT.
 * Key-strength and application acceptance policies belong to the caller. */
TC_RSA_result TC_RSA_validate_private_key(const TC_RSA_private_key* key,
                                          TC_RSA_exponent_policy exponent_policy,
                                          const TC_RSA_workspace* workspace,
                                          TC_RSA_execution* execution);
/* 1 when a big-endian magnitude is odd and 2^16 < e < 2^256 (FIPS 186-5
 * A.1.1), otherwise 0. Leading zero octets are ignored. */
int TC_RSA_exponent_in_fips_range(TC_bytes exponent);

/* Check CRT components against an already validated, unchanged private key.
 * Magnitudes are nonempty, at most the modulus length, and fit half the
 * modulus length after optional leading zero bytes, otherwise the result is
 * TC_RSA_INVALID. Scratch must be separate from all key bytes and metadata.
 * Used scratch is wiped. Preflight failures preserve it. The work is
 * 32*modulus_bytes+1. Key validation remains a prerequisite. */
TC_RSA_result TC_RSA_validate_crt(const TC_RSA_private_key* key, const TC_RSA_crt* crt,
                                  const TC_RSA_workspace* workspace, TC_work_budget* work);

/* Derive fixed-width dP, dQ and qInv from an already validated private key.
 * Each output needs modulus_bytes/2 capacity, and a shorter buffer returns
 * TC_RSA_LIMIT. Exactly modulus_bytes/2 bytes are written to each. Outputs
 * change together only on success and must be mutually disjoint from the
 * key, metadata and scratch. Used scratch is wiped. The work is
 * 48*modulus_bytes+3. */
TC_RSA_result TC_RSA_derive_crt(const TC_RSA_private_key* key, const TC_RSA_crt_output* output,
                                const TC_RSA_workspace* workspace, TC_work_budget* work);

/* Verify a precomputed SHA-1/224/256/384/512 digest with PKCS#1 v1.5 (RFC
 * 8017 section 8.2.2). Modulus and exponent are unsigned, minimal big-endian
 * encodings, without DER sign padding. Modulus size is exactly 1024, 2048,
 * 3072 or 4096 bits. A signature of another length, or one that does not
 * match, returns TC_RSA_INVALID. Acceptance policy belongs to the caller.
 *
 * All bytes are borrowed for this call. Workspace must be aligned, separate from
 * inputs and metadata, and exclusive to the operation. Scratch is wiped after
 * verification. No hash implementation is required for this prehashed API.
 * The work is TC_RSA_public_work + TC_RSA_encode_v15_work and is checked
 * before arithmetic. Unsupported hashes, invalid signatures and exhausted
 * limits are distinct results. This does not validate a certificate or
 * establish trust. */
TC_RSA_result TC_RSA_verify_v15_digest(const TC_RSA_public_key* key,
                                       const TC_RSA_v15_options* options, TC_bytes digest,
                                       TC_bytes signature, const TC_RSA_workspace* workspace,
                                       TC_work_budget* work);
/* Use an initialized setup with unchanged borrowed key and cache storage.
 * Verification workspace and all inputs must be separate from that setup. A
 * setup that TC_RSA_prepare_public_key did not initialize returns
 * TC_RSA_ARGUMENT. The work is TC_RSA_prepared_public_work +
 * TC_RSA_encode_v15_work. */
TC_RSA_result TC_RSA_verify_v15_prepared(const TC_RSA_prepared_public_key* setup,
                                         const TC_RSA_v15_options* options, TC_bytes digest,
                                         TC_bytes signature, const TC_RSA_workspace* workspace,
                                         TC_work_budget* work);

/* PSS verification (RFC 8017 section 8.1.2) uses explicit message/MGF hashes
 * and salt length, with the same key, workspace and status rules. Both hashes
 * must be enabled. No automatic salt detection. Additional stack storage
 * holds one hash context and a 64-byte digest buffer. The work is
 * TC_RSA_public_work + TC_RSA_encode_pss_work, or
 * TC_RSA_prepared_public_work + TC_RSA_encode_pss_work for a setup. */
TC_RSA_result TC_RSA_verify_pss_digest(const TC_RSA_public_key* key,
                                       const TC_RSA_pss_options* options, TC_bytes digest,
                                       TC_bytes signature, const TC_RSA_workspace* workspace,
                                       TC_work_budget* work);
/* Same PSS checks as the one-shot verifier, reusing the setup's R² cache. */
TC_RSA_result TC_RSA_verify_pss_prepared(const TC_RSA_prepared_public_key* setup,
                                         const TC_RSA_pss_options* options, TC_bytes digest,
                                         TC_bytes signature, const TC_RSA_workspace* workspace,
                                         TC_work_budget* work);
#ifdef __cplusplus
}
#endif
#endif
