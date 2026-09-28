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

/* The forward cipher serves every mode. The inverse cipher serves CBC
 * decryption, ECB, dynamic keys and the CAVP hooks. */
#define TC_AES_NEED_FORWARD                                                                        \
  (TC_AES_ENABLE_CBC || TC_AES_ENABLE_ECB || TC_AES_ENABLE_CTR || TC_AES_ENABLE_OFB ||             \
   TC_AES_ENABLE_GCM || TC_AES_ENABLE_CCM || TC_AES_ENABLE_EAX || TC_AES_ENABLE_EAX_PRIME ||       \
   TC_AES_ENABLE_SIV || TC_AES_ENABLE_CMAC || TC_AES_CAVP || TC_AES_ENABLE_DYNAMIC)
#define TC_AES_NEED_INVERSE                                                                        \
  (TC_AES_ENABLE_CBC || TC_AES_ENABLE_ECB || TC_AES_CAVP || TC_AES_ENABLE_DYNAMIC)
/* AEAD modes that check one-shot input and output buffers. */
#define TC_AES_NEED_AEAD_BUFFERS                                                                   \
  (TC_AES_ENABLE_GCM || TC_AES_ENABLE_CCM || TC_AES_ENABLE_EAX || TC_AES_ENABLE_EAX_PRIME ||       \
   TC_AES_ENABLE_SIV)

typedef uint8_t state_t[4][4];
TC_status tc_aes_cipher(state_t* state, const uint8_t* round_key);
TC_status tc_aes_cipher_rounds(state_t* state, const uint8_t* round_key, uint8_t rounds);
/* Inverse cipher rounds, built when CBC, ECB, CAVP or dynamic keys are enabled. */
TC_status tc_aes_inverse_rounds(state_t* state, const uint8_t* round_key, uint8_t rounds);
#define TC_AES_FIXED_ROUNDS (TC_AES_KEY_BITS / 32 + 6)

#if TC_AES_NEED_AEAD_BUFFERS
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
  return tc_internal_ranges_disjoint(a, a_len, b, b_len);
}
#endif

#endif
