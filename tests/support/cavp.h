/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TINY_CRYPTO_TEST_CAVP_H
#define TINY_CRYPTO_TEST_CAVP_H

#include <stddef.h>
#include <stdint.h>

int tc_cavp_hex_nibble(int c);
long tc_cavp_parse_hex(const char* text, uint8_t* output, size_t capacity);
const char* tc_cavp_field_value(const char* line, const char* name);
void tc_cavp_print_bytes(const char* label, const uint8_t* data, size_t length);

#endif
