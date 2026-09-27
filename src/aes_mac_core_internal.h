/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_AES_MAC_CORE_INTERNAL_H_
#define TC_AES_MAC_CORE_INTERNAL_H_
#include "aes_internal.h"
#include "mac_core_internal.h"

typedef struct {
  const uint8_t* round_key;
  uint8_t rounds;
} tc_aes_mac_key;

static inline TC_status tc_aes_mac_encrypt(const void* cipher, uint8_t* block)
{
  const tc_aes_mac_key* key = (const tc_aes_mac_key*)cipher;
  return tc_aes_cipher_rounds((state_t*)block,key->round_key,key->rounds);
}

static inline tc_mac_cipher tc_aes_mac_cipher(const tc_aes_mac_key* key)
{
  const tc_mac_cipher cipher = {TC_AES_BLOCKLEN,key,tc_aes_mac_encrypt};
  return cipher;
}
#endif
