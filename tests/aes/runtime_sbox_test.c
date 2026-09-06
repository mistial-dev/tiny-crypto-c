/*
 * SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <tiny_crypto/aes.h>

int main(void)
{
  struct TC_AES_ctx ctx;
  uint8_t key[TC_AES_KEYLEN] = { 0 };
  uint8_t tag[TC_AES_CMAC_TAG_MAX];

  if (TC_AES_init_ctx(&ctx, key) != TC_ERROR)
    return 1;
  if (TC_AES_CMAC(key, NULL, 0, tag, sizeof(tag)) != TC_ERROR)
    return 2;
  TC_AES_init_sbox();
  if (TC_AES_init_ctx(&ctx, key) != TC_OK)
    return 3;
  if (TC_AES_CMAC(key, NULL, 0, tag, sizeof(tag)) != TC_OK)
    return 4;
  return 0;
}
