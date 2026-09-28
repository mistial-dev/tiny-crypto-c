/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_RSA_BLINDING_INTERNAL_H_
#define TC_RSA_BLINDING_INTERNAL_H_
#include "mp_inverse_internal.h"
#include <tiny_crypto/rsa.h>

/* Sample 1 < blind < modulus with an inverse. Modulus, blind, inverse and
 * arena are separate. Arena has at least 5n limbs; its first n hold the RNG
 * draw and its next n are the range-check scratch. */
static inline TC_RSA_result tc_rsa_sample_blinding(const tc_mp_word* modulus, tc_mp_word* blind,
                                                   tc_mp_word* inverse, tc_mp_word* arena, size_t n,
                                                   TC_random_fn random, void* random_context,
                                                   size_t max_attempts, uint32_t* work)
{
  const size_t length = n * sizeof(tc_mp_word);
  const size_t attempt_work = 16 * length + 1;
  tc_mp_word* reduced = arena + n;
  for (size_t attempt = 0; attempt < max_attempts; ++attempt) {
    if (*work < attempt_work)
      return TC_RSA_LIMIT;
    *work -= attempt_work;
    if (random(random_context, (uint8_t*)arena, length) != TC_OK)
      return TC_RSA_ERROR;
    tc_mp_from_be(blind, (const uint8_t*)arena, length);
    const tc_mp_word below_modulus = tc_mp_subtract(reduced, blind, modulus, n);
    tc_mp_word above_one = (tc_mp_word)(blind[0] & ~1u);
    for (size_t i = 1; i < n; ++i)
      above_one |= blind[i];
    if (below_modulus && above_one && tc_mp_inverse(inverse, blind, modulus, n, arena))
      return TC_RSA_OK;
  }
  return TC_RSA_LIMIT;
}
#endif
