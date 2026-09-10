/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Test-only reference implementation for the hardware GHASH hook. */
#include <string.h>

#include <tiny_crypto/aes.h>

#if TC_AES_GCM_GHASH_MODE == TC_AES_GCM_GHASH_MODE_HARDWARE
void TC_AES_GCM_hardware_multiply(uint8_t result[16],
                                  const uint8_t left[16],
                                  const uint8_t right[16])
{
  uint8_t value[16];
  uint8_t product[16] = { 0 };
  unsigned byte;
  unsigned bit;

  memcpy(value, right, sizeof(value));
  for (byte = 0; byte < 16; ++byte)
  {
    for (bit = 0; bit < 8; ++bit)
    {
      const uint8_t mask =
        (uint8_t)(0u - ((left[byte] >> (7u - bit)) & 1u));
      const uint8_t lsb = (uint8_t)(0u - (value[15] & 1u));
      unsigned i;

      for (i = 0; i < 16; ++i)
        product[i] ^= (uint8_t)(value[i] & mask);
      for (i = 15; i > 0; --i)
        value[i] = (uint8_t)((value[i] >> 1) | (value[i - 1] << 7));
      value[0] = (uint8_t)((value[0] >> 1) ^ (0xe1u & lsb));
    }
  }
  memcpy(result, product, sizeof(product));
}
#endif
