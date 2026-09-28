/* SPDX-License-Identifier: GPL-2.0-or-later
 * Private AES interface. Only the block cipher crosses translation units. */
#ifndef TC_AES_INTERNAL_H
#define TC_AES_INTERNAL_H
#include <tiny_crypto/aes.h>
#if TC_AES_ENABLE_DYNAMIC
#include <tiny_crypto/aes_dynamic.h>
#endif
#include "internal.h"
#if TC_AES_ENABLE_DYNAMIC
static inline int tc_aes_dynamic_key_valid(const TC_AES_dynamic_key* ctx)
{
  return ctx && (ctx->rounds == 10 || ctx->rounds == 12 || ctx->rounds == 14);
}
#endif

typedef uint8_t state_t[4][4];
TC_status tc_aes_cipher(state_t* state, const uint8_t* round_key);
TC_status tc_aes_cipher_rounds(state_t* state, const uint8_t* round_key, uint8_t rounds);
/* Inverse cipher rounds, built when CBC, ECB, CAVP or dynamic keys are enabled. */
TC_status tc_aes_inverse_rounds(state_t* state, const uint8_t* round_key, uint8_t rounds);
#define TC_AES_FIXED_ROUNDS (TC_AES_KEY_BITS / 32 + 6)

static inline void tc_aes_copy_bytes(uint8_t* dst, const uint8_t* src, size_t length)
{
  memcpy(dst, src, length);
}

#if TC_AES_ENABLE_GCM ||                                    \
    TC_AES_ENABLE_CCM ||                                    \
    TC_AES_ENABLE_EAX ||                                    \
    TC_AES_ENABLE_EAX_PRIME ||                        \
    TC_AES_ENABLE_SIV
/*
 * Completely disjoint buffers. An exact alias counts as overlap.
 * Empty lengths are always treated as disjoint.
 *
 * The range test uses uintptr_t subtraction, which stays portable across
 * unrelated objects and MCU ABIs where relational compares and pa+len do not.
 */
static inline int tc_aes_buffers_disjoint(const void* a, size_t a_len, const void* b, size_t b_len)
{
  return tc_internal_ranges_disjoint(a, a_len, b, b_len);
}

/*
 * Buffer relationship for one-shot in/out pairs:
 *   exact alias (same pointer) — OK
 *   completely disjoint — OK
 *   partial overlap — rejected (TC_ERROR)
 * Empty lengths are always OK.
 */
static inline int tc_aes_buffers_ok(const void* a, size_t a_len, const void* b, size_t b_len)
{
  const uintptr_t pa = (uintptr_t)a;
  const uintptr_t pb = (uintptr_t)b;

  if (a_len == 0 || b_len == 0 || pa == pb)
    return 1;
  return tc_aes_buffers_disjoint(a, a_len, b, b_len);
}
#endif

#endif
