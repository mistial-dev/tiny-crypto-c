/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Shared Merkle-Damgard hash and HMAC core. Each algorithm supplies one
 * descriptor with its block geometry, compression function, digest
 * serializer and typed views of its public contexts. The core owns buffering,
 * padding, length limits, keyed-state checks, HMAC key handling and wiping. */
#ifndef TC_HASH_CORE_INTERNAL_H_
#define TC_HASH_CORE_INTERNAL_H_

#include <tiny_crypto/common.h>
#include "hash_stream_internal.h"

#define TC_HASH_CORE_ENABLED (TC_ENABLE_MD5 || TC_ENABLE_SHA1 || \
    TC_ENABLE_SHA224 || TC_ENABLE_SHA256 || TC_ENABLE_SHA384 || TC_ENABLE_SHA512)

#if TC_HASH_CORE_ENABLED

/* Borrowed pointers into one public hash context. context and size cover the
 * whole object for argument checks and wiping. */
typedef struct {
  void* context;
  size_t size;
  uint64_t* count;
  void* state;
  uint8_t* used;
  uint8_t* active;
  uint8_t* buffer;
} tc_hash_view;

/* An HMAC context holds its inner hash context and the outer chaining state
 * after the opad block. context and size cover the whole HMAC object. */
typedef struct {
  tc_hash_view inner;
  void* outer_state;
  void* context;
  size_t size;
} tc_hmac_view;

/* Every public hash context names its fields Count, State, BufLen, active and
 * Buf, and every HMAC context names them Inner and OuterState. */
#define TC_HASH_VIEW(ctx) ((tc_hash_view){ (ctx), sizeof *(ctx), &(ctx)->Count, \
    (ctx)->State, &(ctx)->BufLen, &(ctx)->active, (ctx)->Buf })
#define TC_HMAC_VIEW(ctx) ((tc_hmac_view){ TC_HASH_VIEW(&(ctx)->Inner), \
    (ctx)->OuterState, (ctx), sizeof *(ctx) })

/* One descriptor per enabled algorithm. The per-algorithm file owns the
 * compression function, the initial chaining values and the digest word
 * order. The core treats the chaining state as opaque bytes. */
typedef struct {
  uint8_t block_bytes;       /* 64 or 128 */
  uint8_t length_bytes;      /* 8 or 16: size of the padded bit-length field */
  uint8_t digest_bytes;      /* SHA-224 and SHA-384 truncate the state */
  uint8_t length_encoding;   /* tc_hash_length_encoding: big-endian SHA, little-endian MD5 */
  uint64_t max_message_bytes; /* bit length must fit the padded length field */
  void (*state_init)(void* state);
  tc_hash_block_fn compress; /* compress(state, block) */
  void (*digest_out)(const void* state, uint8_t* digest);
  tc_hash_view (*view)(void* context);     /* build TC_HASH_VIEW for the typed context */
  tc_hmac_view (*hmac_view)(void* context); /* NULL when HMAC is disabled */
} tc_hash_algorithm_info;

/* Name an HMAC view function in a descriptor, or NULL without HMAC. */
#if TC_ENABLE_HMAC
  #define TC_HASH_HMAC_VIEW(function) function
#else
  #define TC_HASH_HMAC_VIEW(function) NULL
#endif

/* AVR builds keep descriptors in program memory, and the core copies one out
 * per public call. Define descriptors with this storage class. */
#if defined(__AVR__) && TC_AVR_PROGMEM
  #include <avr/pgmspace.h>
  #define TC_HASH_INFO_STORAGE PROGMEM
#else
  #define TC_HASH_INFO_STORAGE
#endif

#if TC_ENABLE_SHA384 || TC_ENABLE_SHA512
  #define TC_HASH_CORE_MAX_BLOCK 128u
  #define TC_HASH_CORE_MAX_DIGEST 64u
#else
  #define TC_HASH_CORE_MAX_BLOCK 64u
  #define TC_HASH_CORE_MAX_DIGEST 32u
#endif

/* Descriptors for the enabled SHA algorithms, defined in hash.c and sha512.c. */
#if TC_ENABLE_SHA1
extern const tc_hash_algorithm_info tc_sha1_info TC_HASH_INFO_STORAGE;
#endif
#if TC_ENABLE_SHA224
extern const tc_hash_algorithm_info tc_sha224_info TC_HASH_INFO_STORAGE;
#endif
#if TC_ENABLE_SHA256
extern const tc_hash_algorithm_info tc_sha256_info TC_HASH_INFO_STORAGE;
#endif
#if TC_ENABLE_SHA384
extern const tc_hash_algorithm_info tc_sha384_info TC_HASH_INFO_STORAGE;
#endif
#if TC_ENABLE_SHA512
extern const tc_hash_algorithm_info tc_sha512_info TC_HASH_INFO_STORAGE;
#endif

/* Descriptor for a run-time selected SHA algorithm, or NULL when the
 * algorithm is unknown or disabled. Pass the result to the core functions
 * below with a TC_hash_context or TC_HMAC_context. */
const tc_hash_algorithm_info* tc_hash_core_lookup(TC_hash_algorithm algorithm);

/* Sizes read from a stored descriptor. */
size_t tc_hash_core_digest_bytes(const tc_hash_algorithm_info* info);
size_t tc_hash_core_block_bytes(const tc_hash_algorithm_info* info);

/* Plain hashes. info points at a TC_HASH_INFO_STORAGE descriptor and context
 * at the matching public context type.
 *
 * A context is live from a successful init until final or clear. init wipes
 * the whole context first, so it also restarts a live context. update accepts
 * length 0 with a NULL pointer, and data must stay clear of the context.
 * update returns TC_ERROR for NULL or overlapping arguments, an inactive
 * context, or a total length past max_message_bytes, and leaves the context
 * unchanged in each case. final writes digest_bytes and consumes the context.
 * TC_ZEROIZE builds wipe it, and other builds mark it inactive. The digest
 * must stay clear of the context. clear wipes the context and accepts NULL. */
TC_status tc_hash_core_init(const tc_hash_algorithm_info* info, void* context);
TC_status tc_hash_core_update(const tc_hash_algorithm_info* info, void* context,
    const uint8_t* data, size_t length);
TC_status tc_hash_core_final(const tc_hash_algorithm_info* info, void* context,
    uint8_t* digest);
void tc_hash_core_clear(const tc_hash_algorithm_info* info, void* context);
/* One-shot hash through init, update and final. workspace is the caller's
 * typed context, so the stack holds one context for any algorithm. Once the
 * arguments pass their checks, workspace is wiped before return. */
TC_status tc_hash_core_digest(const tc_hash_algorithm_info* info, void* workspace,
    const uint8_t* data, size_t length, uint8_t* digest);

#if TC_ENABLE_HMAC
/* HMAC (FIPS 198-1) over the same descriptor. init wipes the HMAC context,
 * hashes keys longer than one block in the inner context, then stores the
 * inner state after K0 ^ ipad and the outer chaining state after K0 ^ opad.
 * The key block is wiped before return, and a failed init leaves the context
 * wiped and inactive. update and final follow the plain-hash rules above.
 * final computes H((K0 ^ opad) || inner digest) from the saved outer state
 * and writes digest_bytes. */
TC_status tc_hmac_core_init(const tc_hash_algorithm_info* info, void* context,
    const uint8_t* key, size_t key_length);
TC_status tc_hmac_core_update(const tc_hash_algorithm_info* info, void* context,
    const uint8_t* data, size_t length);
TC_status tc_hmac_core_final(const tc_hash_algorithm_info* info, void* context,
    uint8_t* tag);
void tc_hmac_core_clear(const tc_hash_algorithm_info* info, void* context);
/* One-shot HMAC truncated to tag_length bytes, which must be at least
 * TC_HMAC_MIN_TAG_LEN and at most digest_bytes (SP 800-107). workspace is the
 * caller's HMAC context. Once the arguments pass their checks, workspace is
 * wiped before return. */
TC_status tc_hmac_core_digest(const tc_hash_algorithm_info* info, void* workspace,
    const uint8_t* key, size_t key_length, const uint8_t* message,
    size_t message_length, uint8_t* tag, size_t tag_length);
/* Recompute a truncated tag and compare it with TC_ct_equal. Returns TC_OK on
 * a match, TC_MISMATCH otherwise, and TC_ERROR for invalid arguments. The
 * computed tag is wiped before return. */
TC_status tc_hmac_core_verify(const tc_hash_algorithm_info* info, void* workspace,
    const uint8_t* key, size_t key_length, const uint8_t* message,
    size_t message_length, const uint8_t* tag, size_t tag_length);
#endif

/* Serialize the leading words of a chaining state into digest. These are the
 * digest_out helpers: SHA-1/SHA-224/SHA-256 use big-endian 32-bit words,
 * SHA-384/SHA-512 big-endian 64-bit words, MD5 little-endian 32-bit words.
 * Truncated variants pass fewer words than the state holds. */
void tc_hash_store_be32_words(uint8_t* digest, const void* state, size_t words);
void tc_hash_store_be64_words(uint8_t* digest, const void* state, size_t words);
void tc_hash_store_le32_words(uint8_t* digest, const void* state, size_t words);

#endif /* TC_HASH_CORE_ENABLED */
#endif
