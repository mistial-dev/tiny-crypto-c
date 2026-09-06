/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "test_util.h"

#include "cavp.h"

#include <stdint.h>

void tc_test_fill_bytes(uint8_t* output, size_t length,
                        uint8_t seed, uint8_t stride)
{
  size_t i;
  for (i = 0; i < length; ++i)
    output[i] = (uint8_t)(seed + stride * (uint8_t)i);
}

void tc_test_fill_incrementing(uint8_t* output, size_t length)
{
  tc_test_fill_bytes(output, length, 0, 1);
}

void tc_test_fill_stride3(uint8_t* output, size_t length, uint8_t seed)
{
  tc_test_fill_bytes(output, length, seed, 3);
}

int tc_test_all_zero(const void* memory, size_t length)
{
  const uint8_t* bytes = (const uint8_t*)memory;
  size_t i;
  for (i = 0; i < length; ++i)
    if (bytes[i] != 0)
      return 0;
  return 1;
}

size_t tc_test_decode_hex(const char* text, uint8_t* output, size_t capacity)
{
  size_t length = 0;

  while (*text != '\0' && *text != '"' && *text != '\r' && *text != '\n')
  {
    const int high = tc_cavp_hex_nibble((unsigned char)*text++);
    int low;
    if (high < 0 || *text == '\0' || *text == '"' ||
        *text == '\r' || *text == '\n')
      return SIZE_MAX;
    low = tc_cavp_hex_nibble((unsigned char)*text++);
    if (low < 0 || length == capacity)
      return SIZE_MAX;
    output[length++] = (uint8_t)((high << 4) | low);
  }
  return length;
}

size_t tc_test_decode_hex_relaxed(const char* text, uint8_t* output,
                                  size_t capacity)
{
  size_t length = 0;

  while (*text != '\0')
  {
    const int high = tc_cavp_hex_nibble((unsigned char)*text++);
    int low;
    if (high < 0)
      continue;
    if (*text == '\0')
      return SIZE_MAX;
    low = tc_cavp_hex_nibble((unsigned char)*text++);
    if (low < 0 || length == capacity)
      return SIZE_MAX;
    output[length++] = (uint8_t)((high << 4) | low);
  }
  return length;
}
