/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/tiny_crypto.h>
#include <string.h>
int main(void)
{
  static const uint8_t expected[TC_SHA256_DIGESTLEN] = {
    0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
    0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
  };
  uint8_t result[TC_SHA256_DIGESTLEN];
  uint8_t key[32] = {0};
  if (TC_KMAC256_digest(key, sizeof(key), NULL, 0, NULL, 0,
                       result, sizeof(result)) != TC_OK) return 1;
  return TC_SHA256_digest((const uint8_t*)"abc", 3, result) != TC_OK ||
         memcmp(result, expected, sizeof(result)) != 0;
}
