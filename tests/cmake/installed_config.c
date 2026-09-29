/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Compiled against the installed headers with no -D definitions. The
 * installed build_config.h must supply the library's configuration: SHA-384
 * and PIV SM cipher suite 7, which the default header profile omits. */
#include <tiny_crypto/hash.h>
#include <tiny_crypto/piv_sm.h>
#include <string.h>

#if !TC_ENABLE_SHA384 || !TC_ENABLE_PIV_SM || !TC_PIV_SM_ENABLE_CS7
#error "The installed headers lost the library configuration"
#endif
/* Cipher suite 7 sets the session key size used by the PIV SM structures. */
#if TC_PIV_SM_KEY_BYTES != 32
#error "The installed PIV SM layout differs from the library"
#endif

int main(void)
{
  /* FIPS 180-4 example: SHA-384("abc"). */
  static const uint8_t expected[TC_SHA384_DIGESTLEN] = {
      0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69,
      0x9a, 0xc6, 0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
      0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b,
      0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7};
  uint8_t digest[TC_SHA384_DIGESTLEN];
  if (TC_SHA384_digest((TC_bytes){(const uint8_t*)"abc", 3}, digest) != TC_OK)
    return 1;
  return memcmp(digest, expected, sizeof digest) == 0 ? 0 : 1;
}
