/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* FIPS 197 appendix C.1 AES-128 known answer, run on an emulated
 * ATmega328P. The result is written to USART0 as AES-OK or AES-BAD. */
#include <avr/io.h>
#include <string.h>
#include <tiny_crypto/aes.h>

static void put_string(const char* text)
{
  while (*text) {
    while (!(UCSR0A & (1 << UDRE0))) {
    }
    UDR0 = (uint8_t)*text++;
  }
}

int main(void)
{
  static const uint8_t key[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  static const uint8_t plaintext[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  static const uint8_t ciphertext[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                                         0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
  struct TC_AES_key_ctx schedule;
  uint8_t block[16];
  UCSR0B = 1 << TXEN0;
  UCSR0C = 3 << UCSZ00;
#if TC_AES_SBOX_MODE == TC_AES_SBOX_MODE_RUNTIME
  TC_AES_init_sbox();
#endif
  memcpy(block, plaintext, sizeof block);
  const int ok =
      TC_AES_key_init(&schedule, key) == TC_OK && TC_AES_ECB_encrypt(&schedule, block) == TC_OK &&
      !memcmp(block, ciphertext, sizeof block) && TC_AES_ECB_decrypt(&schedule, block) == TC_OK &&
      !memcmp(block, plaintext, sizeof block);
  put_string(ok ? "AES-OK\n" : "AES-BAD\n");
  for (;;) {
  }
}
