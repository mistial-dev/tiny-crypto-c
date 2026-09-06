/*
 * SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef TINY_CRYPTO_H_
#define TINY_CRYPTO_H_

/* Include this umbrella for the configured product profile. Granular headers
 * remain available when firmware wants to minimize preprocessing work. */
#include <tiny_crypto/common.h>

#if TC_ENABLE_KMAC256
#include <tiny_crypto/kmac.h>
#endif

#if TC_ENABLE_AES
#include <tiny_crypto/aes.h>
#endif

#if TC_ENABLE_DES
#include <tiny_crypto/des.h>
#endif

#if TC_ENABLE_SHA1 || TC_ENABLE_SHA224 || TC_ENABLE_SHA256 || \
    TC_ENABLE_SHA384 || TC_ENABLE_SHA512
#include <tiny_crypto/hash.h>
#endif

#if TC_ENABLE_KDF
#include <tiny_crypto/kdf.h>
#endif

#endif
