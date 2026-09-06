/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */

#include <tiny_crypto/tiny_crypto.hpp>

void tiny_crypto_cpp_header_compile(void) {
#if TC_ENABLE_KMAC256
    tiny_crypto::KMAC256 kmac;
    (void)kmac;
#endif
#if TC_ENABLE_AES
    tiny_crypto::AES aes;
    (void)aes;
#endif
#if TC_ENABLE_SHA256
    tiny_crypto::SHA256 hash;
    (void)hash;
#endif
}
