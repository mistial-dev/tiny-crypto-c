/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Includes feature headers directly with their features disabled. A header
 * that still declares a disabled API compiles cleanly and then fails at link
 * time, so each probe below redeclares a public name as an object. The
 * redeclaration is a compile error whenever the header declares that name. */
#include <tiny_crypto/hash.h>
#include <tiny_crypto/kdf.h>
#include <tiny_crypto/md5.h>
#include <tiny_crypto/sskdf.h>

#if TC_ENABLE_MD5 || TC_ENABLE_SSKDF || TC_ENABLE_KDF
#error "this probe needs MD5, SSKDF and KBKDF disabled"
#endif

int TC_MD5_init;
int TC_MD5_digest;
struct TC_MD5_ctx {
  int probe;
};

int TC_SSKDF_SHA1;
int TC_SSKDF_SHA224;
int TC_SSKDF_SHA256;
int TC_SSKDF_SHA384;
int TC_SSKDF_SHA512;

#if TC_KBKDF_HAVE_HMAC || TC_KBKDF_HAVE_AES_CMAC || TC_KBKDF_HAVE_DES_CMAC
#error "KBKDF PRF availability must follow TC_ENABLE_KDF"
#endif
int TC_KBKDF_fixed_input;
int TC_KBKDF_HMAC_SHA256_counter;
int TC_KBKDF_AES_CMAC_counter;
struct TC_KBKDF_params {
  int probe;
};

#if defined(TC_TEST_HEADER_NO_SHA)
#if TC_ENABLE_SHA1 || TC_ENABLE_SHA224 || TC_ENABLE_SHA256 || TC_ENABLE_SHA384 || TC_ENABLE_SHA512
#error "this profile must disable every SHA"
#endif
int TC_SHA256_init;
int TC_SHA256_digest;
struct TC_SHA256_ctx {
  int probe;
};
#else
/* The enabled hash API stays declared next to the disabled KDF headers. */
TC_status (*const tc_feature_off_sha256)(const uint8_t*, size_t,
                                         uint8_t[TC_SHA256_DIGESTLEN]) = TC_SHA256_digest;
#endif
