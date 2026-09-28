/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Shared AES MAC primitives: the counter-mode keystream used by EAX and SIV,
 * and CMAC subkey derivation (NIST SP 800-38B). */
#include "aes_mac_core_internal.h"

#if TC_AES_ENABLE_EAX ||                                    \
    TC_AES_ENABLE_EAX_PRIME ||                        \
    TC_AES_ENABLE_SIV
TC_status tc_aes_mac_ctr_xor(const uint8_t* round_key, const uint8_t initial[TC_AES_BLOCKLEN],
                             const uint8_t* input, uint8_t* output, size_t length,
                             tc_aes_mac_ctr_bits bits)
{
  uint8_t counter[TC_AES_BLOCKLEN];
  uint8_t stream[TC_AES_BLOCKLEN];
  size_t offset = 0;
  TC_status status = TC_OK;

  tc_aes_copy_bytes(counter, initial, TC_AES_BLOCKLEN);
  if (bits.enabled) {
    counter[bits.first_clear_bit] &= 0x7fu;
    counter[bits.second_clear_bit] &= 0x7fu;
  }
  while (offset < length) {
    const size_t count = length - offset < TC_AES_BLOCKLEN ? length - offset : TC_AES_BLOCKLEN;
    tc_aes_copy_bytes(stream, counter, TC_AES_BLOCKLEN);
    status = tc_aes_cipher((state_t*)stream, round_key);
    if (status != TC_OK)
      break;
    for (size_t i = 0; i < count; ++i)
      output[offset + i] = (uint8_t)(input[offset + i] ^ stream[i]);
    tc_internal_increment_be(counter, TC_AES_BLOCKLEN);
    offset += count;
  }
#if TC_ZEROIZE
  TC_secure_zero(counter, sizeof(counter));
  TC_secure_zero(stream, sizeof(stream));
#endif
  return status;
}
#endif

/* AES-CMAC (SP 800-38B) shared by public CMAC and SIV-S2V. */
#if TC_AES_ENABLE_CMAC || TC_AES_ENABLE_SIV || TC_AES_ENABLE_DYNAMIC
/* Derive both final-block subkeys from AES_K(0). */
TC_status tc_aes_cmac_generate_subkeys(const uint8_t* round_key, uint8_t rounds,
                                       uint8_t k1[TC_AES_BLOCKLEN], uint8_t k2[TC_AES_BLOCKLEN])
{
  uint8_t l[TC_AES_BLOCKLEN] = {0};

  TC_status status = tc_aes_cipher_rounds((state_t*)l, round_key, rounds);
  if (status != TC_OK)
    goto done;
  tc_aes_copy_bytes(k1, l, TC_AES_BLOCKLEN);
  tc_aes_gf128_double(k1);
  tc_aes_copy_bytes(k2, k1, TC_AES_BLOCKLEN);
  tc_aes_gf128_double(k2);
done:
#if TC_ZEROIZE
  TC_secure_zero(l, sizeof(l));
#endif
  return status;
}
#endif
