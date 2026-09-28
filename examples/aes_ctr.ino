/*
 * SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Arduino sketch: AES-128-CTR encrypt then decrypt a buffer. The key and IV
 * are fixed demonstration values. A real application uses a secret key and a
 * counter block that is never reused with that key.
 */
#include <tiny_crypto/aes.h>
#include <stdint.h>
#include <string.h>

static int aes_ctr_roundtrip(void)
{
  static const uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
  static const uint8_t iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  uint8_t data[16] = {'H', 'e', 'l', 'l', 'o', ' ', '1', '6',
                      'B', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
  uint8_t original[sizeof(data)];
  struct TC_AES_ctx ctx;
  int failed;

  memcpy(original, data, sizeof(data));
  /* CTR encryption and decryption are the same operation with the same IV. */
  failed = TC_AES_init_ctx_iv(&ctx, key, iv) != TC_OK ||
           TC_AES_CTR_crypt(&ctx, data, sizeof(data)) != TC_OK ||
           TC_AES_ctx_set_iv(&ctx, iv) != TC_OK ||
           TC_AES_CTR_crypt(&ctx, data, sizeof(data)) != TC_OK;
  TC_AES_ctx_clear(&ctx);
  return failed || memcmp(data, original, sizeof(data)) != 0;
}

void setup(void)
{
  if (aes_ctr_roundtrip() != 0)
    for (;;) {
      /* Stop on failure. */
    }
}

void loop(void)
{}
