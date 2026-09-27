/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_MAC_CORE_INTERNAL_H_
#define TC_MAC_CORE_INTERNAL_H_
#include <tiny_crypto/common.h>

typedef struct {
  size_t block_size;
  const void* cipher;
  TC_status (*encrypt)(const void* cipher, uint8_t* block);
} tc_mac_cipher;

/* Big-endian GF doubling. input and output may be the same block. */
void tc_mac_gf_double(uint8_t* output, const uint8_t* input,
    size_t block_size, uint8_t reduction);

/* The caller owns the chaining value and partial block; used is at most block_size.
 * retain_last leaves a complete final block for CMAC subkey selection. */
TC_status tc_mac_cbc_block(const tc_mac_cipher* cipher, uint8_t* mac, const uint8_t* block);
TC_status tc_mac_cbc_update(const tc_mac_cipher* cipher, uint8_t* mac, uint8_t* block,
    size_t* used, const uint8_t* data, size_t length, int retain_last);
TC_status tc_mac_cbc_pad(const tc_mac_cipher* cipher, uint8_t* mac, uint8_t* block,
    size_t* used);
TC_status tc_mac_cmac_final(const tc_mac_cipher* cipher, uint8_t* mac, uint8_t* block,
    size_t used, const uint8_t* complete_subkey, const uint8_t* partial_subkey,
    uint8_t* tag);
#endif
