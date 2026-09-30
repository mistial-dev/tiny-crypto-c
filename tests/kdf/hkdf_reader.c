/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Byte-output adapter for the vendored Wycheproof HKDF corpus. */
#include <errno.h>
#include "binary_stdio.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tiny_crypto/hkdf.h>
#include "cavp.h"

typedef TC_status (*derive_fn)(TC_bytes, const TC_bytes*, size_t, TC_bytes, TC_buffer);

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

static int read_hex(const char* text, uint8_t* bytes, size_t capacity, size_t* length)
{
  return tc_test_hex_decode(text, TC_TEST_HEX_FIELD, bytes, capacity, length) &&
         *length * 2u == strlen(text);
}

int main(int argc, char** argv)
{
  static uint8_t output[16321];
  static uint8_t ikm[8192], auxiliary[8192], info[16420];
  uint8_t salt[256];
  size_t ikm_len, salt_len, info_len, auxiliary_len = 0;
  unsigned long output_len;
  char* end;
  derive_fn derive = NULL;
  TC_status status;

  /* argv: hash ikm salt info length [auxiliary]. A sixth argument is the
   * SP 800-56C revision 2 hybrid secret T, which follows Z as a second part. */
  if ((argc != 6 && argc != 7) || !tc_test_binary_stdio())
    return 2;
  derive = select_hash(argv[1]);
  if (derive == NULL || !read_hex(argv[2], ikm, sizeof ikm, &ikm_len) ||
      !read_hex(argv[3], salt, sizeof salt, &salt_len) ||
      !read_hex(argv[4], info, sizeof info, &info_len) ||
      (argc == 7 && !read_hex(argv[6], auxiliary, sizeof auxiliary, &auxiliary_len)))
    return 2;
  errno = 0;
  output_len = strtoul(argv[5], &end, 10);
  if (errno != 0 || *end != '\0' || output_len > sizeof output)
    return 2;
  const TC_bytes parts[] = {{ikm_len ? ikm : NULL, ikm_len},
                            {auxiliary_len ? auxiliary : NULL, auxiliary_len}};
  status =
      derive((TC_bytes){salt_len ? salt : NULL, salt_len}, parts, argc == 7 ? 2 : 1,
             (TC_bytes){info_len ? info : NULL, info_len}, (TC_buffer){output, (size_t)output_len});
  if (status != TC_OK)
    return 1;
  if (fwrite(output, 1, (size_t)output_len, stdout) != (size_t)output_len)
    return 2;
  return 0;
}
