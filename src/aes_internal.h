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
 * One-shot AEAD text check. Both spans need storage unless empty, the output
 * holds input.length bytes, and input and output are exact aliases or fully
 * disjoint. Partial overlap is rejected.
 */
static inline int tc_aes_text_ok(TC_bytes input, TC_buffer output)
{
  if (!tc_internal_span_valid(input.data, input.length) || output.capacity < input.length)
    return 0;
  if (input.length == 0)
    return 1;
  return output.data != NULL &&
         ((const void*)input.data == (const void*)output.data ||
          tc_internal_ranges_disjoint(input.data, input.length, output.data, input.length));
}
#endif

#endif
