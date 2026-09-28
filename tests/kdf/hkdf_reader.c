/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Byte-output adapter for the vendored Wycheproof HKDF corpus. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tiny_crypto/hkdf.h>
#include "test_util.h"

typedef TC_status (*derive_fn)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*,
                               size_t, uint8_t*, size_t);
typedef TC_status (*hybrid_fn)(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*,
                               size_t, const uint8_t*, size_t, uint8_t*, size_t);

static derive_fn select_hash(const char* name)
{
#if TC_ENABLE_SHA1
  if (strcmp(name, "sha1") == 0)
    return TC_HKDF_SHA1_derive;
#endif
#if TC_ENABLE_SHA224
  if (strcmp(name, "sha224") == 0)
    return TC_HKDF_SHA224_derive;
#endif
#if TC_ENABLE_SHA256
  if (strcmp(name, "sha256") == 0)
    return TC_HKDF_SHA256_derive;
#endif
#if TC_ENABLE_SHA384
  if (strcmp(name, "sha384") == 0)
    return TC_HKDF_SHA384_derive;
#endif
#if TC_ENABLE_SHA512
  if (strcmp(name, "sha512") == 0)
    return TC_HKDF_SHA512_derive;
#endif
  return NULL;
}

static hybrid_fn select_hybrid(const char* name)
{
#if TC_ENABLE_SHA224
  if (strcmp(name, "sha224") == 0)
    return TC_HKDF_SHA224_derive_hybrid;
#endif
#if TC_ENABLE_SHA256
  if (strcmp(name, "sha256") == 0)
    return TC_HKDF_SHA256_derive_hybrid;
#endif
#if TC_ENABLE_SHA384
  if (strcmp(name, "sha384") == 0)
    return TC_HKDF_SHA384_derive_hybrid;
#endif
#if TC_ENABLE_SHA512
  if (strcmp(name, "sha512") == 0)
    return TC_HKDF_SHA512_derive_hybrid;
#endif
  return NULL;
}

static int read_hex(const char* text, uint8_t* bytes, size_t capacity, size_t* length)
{
  size_t digits = strlen(text);
  if (digits > 2u * capacity || (digits & 1u) != 0)
    return 0;
  *length = tc_test_decode_hex(text, bytes, capacity);
  return *length == digits / 2u;
}

int main(int argc, char** argv)
{
  static uint8_t output[16321];
  static uint8_t ikm[8192], auxiliary[8192], info[16420];
  uint8_t salt[256];
  size_t ikm_len, salt_len, info_len, auxiliary_len = 0;
  unsigned long output_len;
  char* end;
  derive_fn derive;
  hybrid_fn hybrid;

  if ((argc != 6 && argc != 7) || (argc == 6 && (derive = select_hash(argv[1])) == NULL) ||
      (argc == 7 && (hybrid = select_hybrid(argv[1])) == NULL) ||
      !read_hex(argv[2], ikm, sizeof ikm, &ikm_len) ||
      !read_hex(argv[3], salt, sizeof salt, &salt_len) ||
      !read_hex(argv[4], info, sizeof info, &info_len) ||
      (argc == 7 && !read_hex(argv[6], auxiliary, sizeof auxiliary, &auxiliary_len)))
    return 2;
  errno = 0;
  output_len = strtoul(argv[5], &end, 10);
  if (errno != 0 || *end != '\0' || output_len > sizeof output)
    return 2;
  if ((argc == 6 &&
       derive(salt_len ? salt : NULL, salt_len, ikm_len ? ikm : NULL, ikm_len,
              info_len ? info : NULL, info_len, output, (size_t)output_len) != TC_OK) ||
      (argc == 7 && hybrid(salt_len ? salt : NULL, salt_len, ikm_len ? ikm : NULL, ikm_len,
                           auxiliary_len ? auxiliary : NULL, auxiliary_len, info_len ? info : NULL,
                           info_len, output, (size_t)output_len) != TC_OK))
    return 1;
  if (fwrite(output, 1, (size_t)output_len, stdout) != (size_t)output_len)
    return 2;
  return 0;
}
