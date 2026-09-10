/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/gzip.h>
#include <stdlib.h>
#include <string.h>

enum { OUTPUT_CAPACITY = 8192, WORK_LIMIT = 100000 };

static void check_decode(const uint8_t* input, size_t length, size_t capacity,
    size_t budget)
{
  uint8_t output[OUTPUT_CAPACITY + 1];
  TC_GZIP_workspace workspace;
  size_t decoded = SIZE_MAX, work = budget;
  memset(output,0x5a,sizeof output);
  memset(&workspace,0xa5,sizeof workspace);
  TC_GZIP_result result = TC_GZIP_decode(input,length,output,capacity,
      &workspace,&work,&decoded);
  if (result == TC_GZIP_ARGUMENT || work > budget) abort();
  const uint8_t* scratch = (const uint8_t*)&workspace;
  for (size_t i = 0; i < sizeof workspace; ++i)
    if (scratch[i]) abort();
  if (result == TC_GZIP_OK) {
    if (decoded > capacity) abort();
    for (size_t i = decoded; i < sizeof output; ++i)
      if (output[i] != 0x5a) abort();
  } else {
    if (decoded != SIZE_MAX) abort();
    for (size_t i = 0; i < capacity; ++i)
      if (output[i]) abort();
    for (size_t i = capacity; i < sizeof output; ++i)
      if (output[i] != 0x5a) abort();
  }
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  check_decode(data,size,OUTPUT_CAPACITY,WORK_LIMIT);
  /* Retain the complete member while varying resource limits. */
  size_t selector = size ? data[size - 1] : 0;
  check_decode(data,size,selector * 32,selector * 128);
  return 0;
}
