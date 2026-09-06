/*
 * SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TINY_CRYPTO_HPP_
#define TINY_CRYPTO_HPP_

#ifndef __cplusplus
#error Do not include tiny_crypto.hpp in a C project, include tiny_crypto.h instead
#endif

#include <tiny_crypto/common.hpp>

#if TC_ENABLE_KMAC256
#include <tiny_crypto/kmac.hpp>
#endif

#if TC_ENABLE_AES
#include <tiny_crypto/aes.hpp>
#endif

#if TC_ENABLE_DES
#include <tiny_crypto/des.hpp>
#endif

#if TC_ENABLE_SHA1 || TC_ENABLE_SHA224 || TC_ENABLE_SHA256 || \
    TC_ENABLE_SHA384 || TC_ENABLE_SHA512
#include <tiny_crypto/hash.hpp>
#endif

#if TC_ENABLE_KDF
#include <tiny_crypto/kdf.hpp>
#endif

#endif
