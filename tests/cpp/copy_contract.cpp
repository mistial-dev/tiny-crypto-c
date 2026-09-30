/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Copy and move contract of the C++ wrappers (docs/cpp.md, Object
 * lifecycle). The build compiles this object as C++11 with every wrapper
 * family enabled and warnings treated as errors. */
#include <tiny_crypto/tiny_crypto.hpp>
#include <type_traits>

#if !TC_ENABLE_AES || !TC_AES_ENABLE_GCM || !TC_AES_ENABLE_CMAC || !TC_AES_ENABLE_DYNAMIC ||       \
    !TC_ENABLE_DES || !TC_DES_ENABLE_CMAC || !TC_DES_ENABLE_ISO9797 || !TC_ENABLE_MD5 ||           \
    !TC_ENABLE_SHA256 || !TC_ENABLE_HMAC || !TC_ENABLE_KMAC256 || !TC_ENABLE_GZIP ||               \
    !TC_ENABLE_DRBG || !TC_ENABLE_PIV_SM || !TC_ENABLE_TLV
#error copy_contract.cpp needs every wrapper family enabled
#endif

/* Classes that own C state delete both copy operations. */
#define TC_ASSERT_NOT_COPYABLE(type)                                                               \
  static_assert(!std::is_copy_constructible<type>::value, #type " must not copy-construct");       \
  static_assert(!std::is_copy_assignable<type>::value, #type " must not copy-assign")

/* drbg and piv_sm also delete both move operations. */
#define TC_ASSERT_NOT_MOVABLE(type)                                                                \
  static_assert(!std::is_move_constructible<type>::value, #type " must not move-construct");       \
  static_assert(!std::is_move_assignable<type>::value, #type " must not move-assign")

TC_ASSERT_NOT_COPYABLE(tiny_crypto::AES);
TC_ASSERT_NOT_COPYABLE(tiny_crypto::GCM);
TC_ASSERT_NOT_COPYABLE(tiny_crypto::AES_CMAC);
TC_ASSERT_NOT_COPYABLE(tiny_crypto::AES_dynamic);
TC_ASSERT_NOT_COPYABLE(tiny_crypto::AES_dynamic_CMAC);
TC_ASSERT_NOT_COPYABLE(tiny_crypto::DES);
TC_ASSERT_NOT_COPYABLE(tiny_crypto::DES_CMAC);
TC_ASSERT_NOT_COPYABLE(tiny_crypto::DES_ISO9797);
/* Each hash and HMAC typedef instantiates basic_hash or basic_hmac. */
TC_ASSERT_NOT_COPYABLE(tiny_crypto::MD5);
TC_ASSERT_NOT_COPYABLE(tiny_crypto::SHA256);
TC_ASSERT_NOT_COPYABLE(tiny_crypto::HMAC_SHA256);
TC_ASSERT_NOT_COPYABLE(tiny_crypto::KMAC256);
TC_ASSERT_NOT_COPYABLE(tiny_crypto::GZIPDecoder);
TC_ASSERT_NOT_COPYABLE(tiny_crypto::drbg);
TC_ASSERT_NOT_MOVABLE(tiny_crypto::drbg);
TC_ASSERT_NOT_COPYABLE(tiny_crypto::piv_sm);
TC_ASSERT_NOT_MOVABLE(tiny_crypto::piv_sm);

/* TLVReader holds a cursor over borrowed input, and a copy is a saved
 * position. tests/cpp/tlv.cpp checks that a copy continues independently. */
static_assert(std::is_copy_constructible<tiny_crypto::TLVReader>::value,
              "TLVReader copies a saved position");
static_assert(std::is_copy_assignable<tiny_crypto::TLVReader>::value,
              "TLVReader assigns a saved position");
