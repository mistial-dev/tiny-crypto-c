/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* AES with the key length chosen per context: 128, 192 or 256-bit keys for
 * single blocks, CBC and CMAC. aes.h provides the fixed-size AES API.
 * Standards: FIPS 197, SP 800-38A (CBC), SP 800-38B (CMAC).
 * Configuration: TC_ENABLE_AES and TC_AES_ENABLE_DYNAMIC.
 * Contracts: docs/api.md. */
#ifndef TINY_CRYPTO_AES_DYNAMIC_H_
#define TINY_CRYPTO_AES_DYNAMIC_H_
#include <tiny_crypto/aes.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Key length is selected per context. aes.h provides the fixed-size AES API. */
typedef struct {
  uint8_t round_key[240];
  uint8_t rounds;
} TC_AES_dynamic_key;
typedef struct {
  TC_AES_dynamic_key key;
  uint8_t mac[16], buffer[16], k1[16], k2[16], used;
} TC_AES_dynamic_CMAC;

/* Keys are 16, 24, or 32 bytes. Input keys must not overlap the context.
 * Any init failure clears the context, so no earlier key or MAC session stays
 * usable. Clear is unconditional. */
TC_status TC_AES_dynamic_key_init(TC_AES_dynamic_key* ctx, const uint8_t* key, size_t key_len);
void TC_AES_dynamic_key_clear(TC_AES_dynamic_key* ctx);
/* Transform one block in place. block must be disjoint from ctx. Argument
 * errors leave block unchanged. A cipher failure wipes block. */
TC_status TC_AES_dynamic_encrypt(const TC_AES_dynamic_key* ctx, uint8_t block[16]);
TC_status TC_AES_dynamic_decrypt(const TC_AES_dynamic_key* ctx, uint8_t block[16]);

/* CBC operates in place, without padding, and updates iv for the next call.
 * ctx, iv, and buffer must be disjoint. A zero-length buffer may be NULL.
 * A cipher failure part way through wipes buffer and iv. */
TC_status TC_AES_dynamic_CBC_encrypt(const TC_AES_dynamic_key* ctx, uint8_t iv[16], uint8_t* buffer,
                                     size_t length);
TC_status TC_AES_dynamic_CBC_decrypt(const TC_AES_dynamic_key* ctx, uint8_t iv[16], uint8_t* buffer,
                                     size_t length);

TC_status TC_AES_dynamic_CMAC_init(TC_AES_dynamic_CMAC* ctx, const uint8_t* key, size_t key_len);
TC_status TC_AES_dynamic_CMAC_update(TC_AES_dynamic_CMAC* ctx, const uint8_t* data, size_t length);
/* Produces the full tag and clears the context. Callers may truncate the tag. */
TC_status TC_AES_dynamic_CMAC_final(TC_AES_dynamic_CMAC* ctx, uint8_t tag[16]);
void TC_AES_dynamic_CMAC_clear(TC_AES_dynamic_CMAC* ctx);
#ifdef __cplusplus
}
#endif
#endif
