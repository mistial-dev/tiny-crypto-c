/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TEST_FASCN_FIXTURE_H_
#define TEST_FASCN_FIXTURE_H_
#include <stdint.h>

/* TWIC Appendix D's example number, with the remaining fields set to zero.
 * Characters: b7099d1055d048796d0d0d0000000000000000fb.
 * Each nibble is LSB-first with odd parity; the last nibble is the LRC. */
static const uint8_t test_card_fascn[25] = {
  0xd7,0x03,0x39,0xda,0x01,0xad,0x6c,0x12,0x0b,0x93,
  0x6d,0x83,0x60,0xd8,0x21,0x08,0x42,0x10,0x84,0x21,
  0x08,0x42,0x10,0x87,0xfa
};
#endif
