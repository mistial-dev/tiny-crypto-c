/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TINY_CRYPTO_TEST_UTIL_H
#define TINY_CRYPTO_TEST_UTIL_H

#include <stddef.h>
#include <stdint.h>

void tc_test_fill_bytes(uint8_t* output, size_t length,
                        uint8_t seed, uint8_t stride);
void tc_test_fill_incrementing(uint8_t* output, size_t length);
void tc_test_fill_stride3(uint8_t* output, size_t length, uint8_t seed);
int tc_test_all_zero(const void* memory, size_t length);
size_t tc_test_decode_hex(const char* text, uint8_t* output, size_t capacity);
size_t tc_test_decode_hex_relaxed(const char* text, uint8_t* output,
                                  size_t capacity);

#endif
