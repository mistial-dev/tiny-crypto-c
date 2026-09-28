/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * TC_random_fn adapter over an instantiated DRBG, for the library APIs that
 * take a TC_random_source. */
#include <tiny_crypto/drbg.h>

#if TC_ENABLE_DRBG

TC_status TC_DRBG_random(void* user, uint8_t* output, size_t length)
{
  const TC_bytes empty = {NULL, 0};
  TC_DRBG* drbg = (TC_DRBG*)user;
  size_t offset = 0;

  /* A zero-length request still checks that the DRBG is instantiated. */
  do {
#if SIZE_MAX > TC_DRBG_MAX_REQUEST_BYTES
    const size_t chunk =
        length - offset < TC_DRBG_MAX_REQUEST_BYTES ? length - offset : TC_DRBG_MAX_REQUEST_BYTES;
#else
    const size_t chunk = length - offset; /* size_t cannot exceed a request */
#endif
    if (TC_DRBG_generate(drbg, output == NULL ? NULL : output + offset, chunk, 0, empty) !=
        TC_DRBG_OK) {
      if (output != NULL)
        TC_secure_zero(output, length);
      return TC_ERROR;
    }
    offset += chunk;
  } while (offset < length);
  return TC_OK;
}

TC_random_source TC_DRBG_random_source(TC_DRBG* drbg)
{
  TC_random_source source = {TC_DRBG_random, drbg};
  return source;
}

#endif
