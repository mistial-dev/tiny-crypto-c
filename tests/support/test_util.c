/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "test_util.h"

#include <stdint.h>

void tc_test_fill_bytes(uint8_t* output, size_t length, uint8_t seed, uint8_t stride)
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

int tc_test_all_value(const void* memory, size_t length, uint8_t value)
{
  const uint8_t* bytes = (const uint8_t*)memory;
  size_t i;
  for (i = 0; i < length; ++i)
    if (bytes[i] != value)
      return 0;
  return 1;
}

int tc_test_all_zero(const void* memory, size_t length)
{
  return tc_test_all_value(memory, length, 0);
}
