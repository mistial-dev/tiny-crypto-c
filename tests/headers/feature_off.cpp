/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * C++ counterpart of feature_off.c. Each wrapper header is included directly
 * with its feature disabled, and a namespace-scope object with a wrapper's
 * name fails to compile whenever the header still declares that wrapper. */
#include <tiny_crypto/aes_kw.hpp>
#include <tiny_crypto/hash.hpp>
#include <tiny_crypto/kdf.hpp>
#include <tiny_crypto/sskdf.hpp>

#if TC_ENABLE_MD5 || TC_ENABLE_SSKDF || TC_ENABLE_KDF
#error "this probe needs MD5, SSKDF and KBKDF disabled"
#endif
#if TC_AES_ENABLE_KW
#error "this probe needs AES key wrap disabled"
#endif

namespace tiny_crypto {
extern int sskdf_sha1;
extern int sskdf_sha224;
extern int sskdf_sha256;
extern int sskdf_sha384;
extern int sskdf_sha512;
extern int kbkdf_fixed_input;
extern int kbkdf_hmac_sha256_counter;
extern int MD5;
extern int aes_kw_wrap;
extern int aes_kwp_unwrap;
#if defined(TC_TEST_HEADER_NO_SHA)
extern int SHA256;
extern int HMAC_SHA256;
#endif
} // namespace tiny_crypto

extern "C" {
extern int TC_SSKDF_SHA256;
extern int TC_KBKDF_fixed_input;
extern int TC_MD5_init;
extern int TC_AES_KW_wrap;
}
