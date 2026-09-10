/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/tiny_crypto.h>
#if TC_RESOURCE_PROFILE != EXPECT_PROFILE
#error "Resource profile was not propagated"
#endif
#if TC_ENABLE_PIV_CVC != EXPECT_CAPABILITIES || TC_ENABLE_X509 != EXPECT_CAPABILITIES || \
    TC_ENABLE_DES != EXPECT_CAPABILITIES || TC_ENABLE_SHA384 != EXPECT_CAPABILITIES || \
    TC_AES_ENABLE_DYNAMIC != EXPECT_CAPABILITIES || TC_ENABLE_SSKDF != EXPECT_CAPABILITIES || \
    TC_ENABLE_EC != EXPECT_CAPABILITIES
#error "Capability defaults disagree"
#endif
#if defined(EXPECT_OVERRIDE)
#if TC_AES_WIDE_OPS != 0
#error "Explicit configuration must override profile defaults"
#endif
#elif TC_AES_WIDE_OPS != EXPECT_WIDE
#error "Native-width default disagrees"
#endif
#if TC_AES_TINY != EXPECT_TINY || TC_EC_SMALL != EXPECT_TINY || TC_AES_GCM_GHASH_MODE != EXPECT_GHASH
#error "Memory defaults disagree"
#endif
#if TC_ZEROIZE != 1 || TC_STRICT != 1 || TC_AES_SBOX_MODE != 1
#error "Profiles must retain security defaults"
#endif
typedef int tc_profile_checked;
