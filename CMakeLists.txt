# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later

cmake_minimum_required(VERSION 3.24)
project(tiny-crypto-c VERSION 2.0.0 LANGUAGES C)
include(GNUInstallDirs)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR AND
   NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

include(cmake/Profiles.cmake)

tc_profile_option(TINY_CRYPTO_ENABLE_AES TC_ENABLE_AES "Build AES")
tc_profile_option(TINY_CRYPTO_ENABLE_DES TC_ENABLE_DES "Build DES and 3DES")
tc_profile_option(TINY_CRYPTO_ENABLE_SHA1 TC_ENABLE_SHA1 "Build SHA-1")
tc_profile_option(TINY_CRYPTO_ENABLE_SHA224 TC_ENABLE_SHA224 "Build SHA-224")
tc_profile_option(TINY_CRYPTO_ENABLE_SHA256 TC_ENABLE_SHA256 "Build SHA-256")
tc_profile_option(TINY_CRYPTO_ENABLE_SHA384 TC_ENABLE_SHA384 "Build SHA-384")
tc_profile_option(TINY_CRYPTO_ENABLE_SHA512 TC_ENABLE_SHA512 "Build SHA-512")
tc_profile_option(TINY_CRYPTO_ENABLE_HMAC TC_ENABLE_HMAC "Build HMAC")
tc_profile_option(TINY_CRYPTO_ENABLE_KMAC256 TC_ENABLE_KMAC256 "Build fixed-output KMAC256")
tc_profile_option(TINY_CRYPTO_ENABLE_TLV TC_ENABLE_TLV "Build bounded TLV readers")
tc_profile_option(TINY_CRYPTO_ENABLE_DER TC_ENABLE_DER "Build DER value helpers")
tc_profile_option(TINY_CRYPTO_ENABLE_X509 TC_ENABLE_X509 "Build X.509 certificate parser")
tc_profile_option(TINY_CRYPTO_ENABLE_EAC_CVC TC_ENABLE_EAC_CVC "Build EAC card verifiable certificate parser")
tc_profile_option(TINY_CRYPTO_ENABLE_PIV_CVC TC_ENABLE_PIV_CVC "Build PIV secure messaging CVC parser")
tc_profile_option(TINY_CRYPTO_ENABLE_PIV_CHUID TC_ENABLE_PIV_CHUID "Build PIV CHUID parser")
tc_profile_option(TINY_CRYPTO_ENABLE_TWIC_CCL TC_ENABLE_TWIC_CCL "Build TWIC canceled card list reader")
tc_profile_option(TINY_CRYPTO_ENABLE_MD5 TC_ENABLE_MD5 "Build legacy MD5 checksums")
tc_profile_option(TINY_CRYPTO_ENABLE_GZIP TC_ENABLE_GZIP "Build bounded GZIP decompression")
tc_profile_option(TINY_CRYPTO_TLV_BER TC_TLV_ENABLE_BER "Accept ASN.1 BER including indefinite lengths")
tc_profile_option(TINY_CRYPTO_TLV_STREAM TC_TLV_ENABLE_STREAM "Expose incremental TLV parsing")
tc_profile_option(TINY_CRYPTO_ENABLE_KDF TC_ENABLE_KDF "Build SP 800-108 KBKDF over the enabled HMAC/CMAC PRFs")
tc_profile_option(TINY_CRYPTO_ENABLE_HKDF TC_ENABLE_HKDF "Build RFC 5869 HKDF over enabled HMAC-SHA algorithms")
tc_profile_option(TINY_CRYPTO_ENABLE_SSKDF TC_ENABLE_SSKDF "Build the single-step hash KDF")
tc_profile_option(TINY_CRYPTO_ENABLE_DRBG TC_ENABLE_DRBG "Build NIST SP 800-90A DRBGs")
tc_profile_option(TINY_CRYPTO_DRBG_HASH TC_DRBG_ENABLE_HASH "Build Hash_DRBG")
tc_profile_option(TINY_CRYPTO_DRBG_HMAC TC_DRBG_ENABLE_HMAC "Build HMAC_DRBG")
tc_profile_option(TINY_CRYPTO_DRBG_CTR TC_DRBG_ENABLE_CTR "Build CTR_DRBG over dynamic AES")
tc_profile_option(TINY_CRYPTO_ENABLE_EC TC_ENABLE_EC "Build P-192/P-256/P-384 ECDH, ECDSA and key generation")
tc_profile_option(TINY_CRYPTO_ENABLE_RSA TC_ENABLE_RSA "Build RSA verification, signing, OAEP, key validation and key generation")
tc_profile_option(TINY_CRYPTO_RSA_SMALL TC_RSA_SMALL "Use byte limbs for RSA arithmetic")
tc_profile_option(TINY_CRYPTO_EC_P192 TC_EC_ENABLE_P192 "Enable P-192 for legacy protocols")
tc_profile_option(TINY_CRYPTO_EC_P256 TC_EC_ENABLE_P256 "Enable P-256")
tc_profile_option(TINY_CRYPTO_EC_P384 TC_EC_ENABLE_P384 "Enable P-384")
tc_profile_option(TINY_CRYPTO_EC_SMALL TC_EC_SMALL "Use byte limbs for elliptic-curve arithmetic")
tc_profile_option(TINY_CRYPTO_AVR_PROGMEM TC_AVR_PROGMEM "Keep constant tables in AVR flash")

set(TINY_CRYPTO_AES_KEY_BITS 128 CACHE STRING "AES key size: 128, 192, or 256")
set_property(CACHE TINY_CRYPTO_AES_KEY_BITS PROPERTY STRINGS 128 192 256)
tc_register_definition(TC_AES_KEY_BITS "${TINY_CRYPTO_AES_KEY_BITS}")
tc_profile_option(TINY_CRYPTO_AES_DYNAMIC TC_AES_ENABLE_DYNAMIC "Build length-aware AES key, CBC, and CMAC APIs")
tc_profile_option(TINY_CRYPTO_AES_CBC TC_AES_ENABLE_CBC "Build AES-CBC")
tc_profile_option(TINY_CRYPTO_AES_ECB TC_AES_ENABLE_ECB "Build AES-ECB")
tc_profile_option(TINY_CRYPTO_AES_CTR TC_AES_ENABLE_CTR "Build AES-CTR")
tc_profile_option(TINY_CRYPTO_AES_OFB TC_AES_ENABLE_OFB "Build AES-OFB")
tc_profile_option(TINY_CRYPTO_AES_GCM TC_AES_ENABLE_GCM "Build AES-GCM")
tc_profile_option(TINY_CRYPTO_AES_CCM TC_AES_ENABLE_CCM "Build AES-CCM")
tc_profile_option(TINY_CRYPTO_AES_EAX TC_AES_ENABLE_EAX "Build AES-EAX")
tc_profile_option(TINY_CRYPTO_AES_EAX_PRIME TC_AES_ENABLE_EAX_PRIME "Build ANSI C12.22 EAX-prime")
tc_profile_option(TINY_CRYPTO_AES_SIV TC_AES_ENABLE_SIV "Build AES-SIV")
tc_profile_option(TINY_CRYPTO_AES_CMAC TC_AES_ENABLE_CMAC "Build AES-CMAC")
tc_profile_option(TINY_CRYPTO_AES_KW TC_AES_ENABLE_KW "Build AES key wrap (KW and KWP)")
set(TINY_CRYPTO_AES_SBOX "constant-time" CACHE STRING
    "AES S-box: constant-time, runtime, or fast")
set_property(CACHE TINY_CRYPTO_AES_SBOX PROPERTY STRINGS constant-time runtime fast)
set(TINY_CRYPTO_AES_GHASH "profile" CACHE STRING
    "GCM multiply: profile, auto, bitwise, wide, fast-table, or hardware")
set_property(CACHE TINY_CRYPTO_AES_GHASH PROPERTY STRINGS
             profile auto bitwise wide fast-table hardware)
# config.h numbers the S-box modes from 1 and the GHASH modes from 0.
set(sbox_values constant-time runtime fast)
list(FIND sbox_values "${TINY_CRYPTO_AES_SBOX}" sbox_index)
if(sbox_index EQUAL -1)
  message(FATAL_ERROR "Unknown TINY_CRYPTO_AES_SBOX value")
endif()
math(EXPR sbox_value "${sbox_index} + 1")
tc_register_definition(TC_AES_SBOX_MODE ${sbox_value})
set(ghash_values auto bitwise wide fast-table hardware)
if(TINY_CRYPTO_AES_GHASH STREQUAL "profile")
  set(ghash_value ${tc_profile_default_TC_AES_GCM_GHASH_MODE})
else()
  list(FIND ghash_values "${TINY_CRYPTO_AES_GHASH}" ghash_value)
endif()
if(ghash_value EQUAL -1)
  message(FATAL_ERROR "Unknown TINY_CRYPTO_AES_GHASH value")
endif()
tc_register_definition(TC_AES_GCM_GHASH_MODE ${ghash_value})
tc_profile_option(TINY_CRYPTO_AES_WIDE_OPS TC_AES_WIDE_OPS "Use native-width AES helpers")
tc_profile_option(TINY_CRYPTO_AES_TINY TC_AES_TINY "Reject large per-context GHASH tables")

tc_profile_option(TINY_CRYPTO_DES_ECB TC_DES_ENABLE_ECB "Build DES-ECB")
tc_profile_option(TINY_CRYPTO_DES_CBC TC_DES_ENABLE_CBC "Build DES-CBC")
tc_profile_option(TINY_CRYPTO_DES_CTR TC_DES_ENABLE_CTR "Build DES-CTR")
tc_profile_option(TINY_CRYPTO_DES_OFB TC_DES_ENABLE_OFB "Build DES-OFB")
tc_profile_option(TINY_CRYPTO_DES_CFB1 TC_DES_ENABLE_CFB1 "Build DES-CFB1")
tc_profile_option(TINY_CRYPTO_DES_CFB8 TC_DES_ENABLE_CFB8 "Build DES-CFB8")
tc_profile_option(TINY_CRYPTO_DES_CFB64 TC_DES_ENABLE_CFB64 "Build DES-CFB64")
tc_profile_option(TINY_CRYPTO_DES_TDES TC_DES_ENABLE_TDES "Build 3DES")
tc_profile_option(TINY_CRYPTO_DES_CMAC TC_DES_ENABLE_CMAC "Build TDEA-CMAC")
tc_profile_option(TINY_CRYPTO_DES_ISO9797 TC_DES_ENABLE_ISO9797 "Build ISO 9797-1 DES MAC")
tc_profile_option(TINY_CRYPTO_DES_REJECT_WEAK_KEYS TC_DES_REJECT_WEAK_KEYS "Reject weak DES keys and degenerate TDEA bundles")

include(cmake/Features.cmake)

tc_taf_choice_option(TINY_CRYPTO_TAF_CERTIFICATE TC_TAF_ENABLE_CERTIFICATE
  "Accept RFC 5914 Certificate choices")
tc_taf_choice_option(TINY_CRYPTO_TAF_TBS_CERTIFICATE TC_TAF_ENABLE_TBS_CERTIFICATE
  "Accept RFC 5914 TBSCertificate choices")
tc_taf_choice_option(TINY_CRYPTO_TAF_TRUST_ANCHOR_INFO TC_TAF_ENABLE_TRUST_ANCHOR_INFO
  "Accept RFC 5914 TrustAnchorInfo choices")

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  option(TINY_CRYPTO_BUILD_TESTS "Build host tests" ON)
else()
  option(TINY_CRYPTO_BUILD_TESTS "Build host tests" OFF)
endif()
option(TINY_CRYPTO_TEST_FULL "Run checked-in CAVP corpora" OFF)
set(TINY_CRYPTO_SANITIZE "" CACHE STRING
    "Test sanitizers, for example address,undefined")

tc_profile_option(TINY_CRYPTO_ENABLE_PIV_SM TC_ENABLE_PIV_SM "Build PIV secure messaging for the client")
tc_profile_option(TINY_CRYPTO_PIV_SM_CS2 TC_PIV_SM_ENABLE_CS2 "Enable PIV SM cipher suite 2")
tc_profile_option(TINY_CRYPTO_PIV_SM_CS7 TC_PIV_SM_ENABLE_CS7 "Enable PIV SM cipher suite 7")

get_property(TC_PUBLIC_DEFINITIONS GLOBAL PROPERTY TINY_CRYPTO_PUBLIC_DEFINITIONS)
# An empty library has no use. Every other dependency rule lives in config.h.
if(NOT TC_PUBLIC_DEFINITIONS MATCHES "(^|;)TC_ENABLE_[A-Z0-9_]+=1(;|$)")
  message(FATAL_ERROR "Enable at least one algorithm or parser")
endif()
include(cmake/ConfigCheck.cmake)
tc_check_config("${TC_PUBLIC_DEFINITIONS}")
set(tc_build_config "${CMAKE_CURRENT_BINARY_DIR}/install-include/tiny_crypto/build_config.h")
tc_write_build_config("${tc_build_config}" "${TC_PUBLIC_DEFINITIONS}")

function(tc_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4)
  elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
  endif()
endfunction()

# block_modes.c holds the CBC, CTR and OFB cores shared by AES and DES. A
# target that lists both families compiles it once.
set(tc_aes_sources src/aes.c src/aes_modes.c src/block_modes.c src/aes_ghash.c src/aes_gcm.c
  src/aes_ccm.c src/aes_mac.c src/aes_cmac.c src/aes_eax.c src/aes_siv.c src/aes_kw.c
  src/mac_core.c)
set(tc_des_sources src/des.c src/des_modes.c src/block_modes.c src/des_mac.c)
set(tc_hash_sources src/hash.c src/sha512.c src/hash_core.c)
set(tc_drbg_sources src/drbg.c src/drbg_hash.c src/drbg_hmac.c src/drbg_ctr.c src/drbg_random.c)
set(tc_rsa_sources src/rsa_workspace.c src/rsa_keygen.c src/rsa_private.c src/rsa_public.c src/rsa_oaep.c)

# One utility translation unit keeps zeroization and constant-time comparison
# consistent across algorithms, and avoids duplicate code in firmware images.
set(tc_sources src/common.c)
if(TINY_CRYPTO_ENABLE_TLV)
  list(APPEND tc_sources src/tlv.c src/tlv_walk.c)
endif()
if(TINY_CRYPTO_ENABLE_DER)
  list(APPEND tc_sources src/der.c src/pki_key.c)
endif()
if(TINY_CRYPTO_ENABLE_X509)
  list(APPEND tc_sources src/x509.c src/x509_crypto.c src/x509_time.c
    src/x509_key.c src/x509_ext.c src/x509_name.c src/x509_name_constraints.c src/pki_signature_oid.c
    src/asn1_string.c src/unicode.c)
endif()
if(TINY_CRYPTO_ENABLE_EAC_CVC)
  list(APPEND tc_sources src/eac_cvc.c)
endif()
if(TINY_CRYPTO_ENABLE_PIV_CVC)
  list(APPEND tc_sources src/piv_cvc.c src/piv_cvc_verify.c)
endif()
if(TINY_CRYPTO_ENABLE_PIV_CHUID)
  list(APPEND tc_sources src/piv_chuid.c)
endif()
if(TINY_CRYPTO_ENABLE_PIV_CHUID OR TINY_CRYPTO_ENABLE_PIV_OBJECTS)
  list(APPEND tc_sources src/piv_container_internal.c)
endif()
if(TINY_CRYPTO_ENABLE_PIV_OBJECTS OR TINY_CRYPTO_ENABLE_PIV_CHUID OR
   TINY_CRYPTO_ENABLE_TWIC_CCL OR TINY_CRYPTO_ENABLE_TWIC_TPK OR
   TINY_CRYPTO_ENABLE_AAMVA)
  list(APPEND tc_sources src/credential_text_internal.c)
endif()
if(TINY_CRYPTO_ENABLE_TWIC_CCL)
  list(APPEND tc_sources src/twic_ccl.c)
endif()
if(TINY_CRYPTO_ENABLE_GZIP)
  list(APPEND tc_sources src/gzip_api.c src/gzip.c src/inflate.c
    src/inflate_bits.c src/inflate_tables.c src/inflate_tree.c)
endif()
if(TINY_CRYPTO_ENABLE_MD5)
  list(APPEND tc_sources src/md5.c)
endif()
if(TINY_CRYPTO_ENABLE_KMAC256)
  list(APPEND tc_sources src/kmac.c)
endif()
if(TINY_CRYPTO_ENABLE_AES)
  list(APPEND tc_sources ${tc_aes_sources})
endif()
if(TINY_CRYPTO_ENABLE_DES)
  list(APPEND tc_sources ${tc_des_sources})
  if((TINY_CRYPTO_DES_CMAC OR TINY_CRYPTO_DES_ISO9797) AND NOT TINY_CRYPTO_ENABLE_AES)
    list(APPEND tc_sources src/mac_core.c)
  endif()
endif()
if(TINY_CRYPTO_ENABLE_SHA1 OR TINY_CRYPTO_ENABLE_SHA224 OR TINY_CRYPTO_ENABLE_SHA256)
  list(APPEND tc_sources src/hash.c)
endif()
if(TINY_CRYPTO_ENABLE_SHA384 OR TINY_CRYPTO_ENABLE_SHA512)
  list(APPEND tc_sources src/sha512.c)
endif()
list(APPEND tc_sources src/hash_core.c src/pki_storage.c)
if(TINY_CRYPTO_ENABLE_KDF)
  list(APPEND tc_sources src/kdf.c)
endif()
if(TINY_CRYPTO_ENABLE_HKDF)
  list(APPEND tc_sources src/hkdf.c)
endif()
if(TINY_CRYPTO_ENABLE_DRBG)
  list(APPEND tc_sources ${tc_drbg_sources})
endif()
if(TINY_CRYPTO_ENABLE_SSKDF)
  list(APPEND tc_sources src/sskdf.c)
endif()
if(TINY_CRYPTO_ENABLE_EC)
  list(APPEND tc_sources src/ec.c)
endif()
if(TINY_CRYPTO_ENABLE_RSA)
  list(APPEND tc_sources ${tc_rsa_sources})
endif()
if(TINY_CRYPTO_ENABLE_PIV_SM)
  list(APPEND tc_sources src/piv_sm.c src/piv_sm_message.c)
  if(TINY_CRYPTO_ENABLE_PIV_CVC AND TINY_CRYPTO_ENABLE_X509)
    list(APPEND tc_sources src/piv_sm_authenticate.c)
  endif()
endif()
tc_append_module_sources(tc_sources)
list(REMOVE_DUPLICATES tc_sources)

add_library(tiny-crypto-c STATIC ${tc_sources})
add_library(tiny-crypto-c::tiny-crypto-c ALIAS tiny-crypto-c)
target_include_directories(tiny-crypto-c PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
# The build tree passes the configuration as definitions. The installed
# build_config.h carries it for installed consumers, with or without CMake.
target_compile_definitions(tiny-crypto-c PUBLIC "$<BUILD_INTERFACE:${TC_PUBLIC_DEFINITIONS}>")
tc_warnings(tiny-crypto-c)

include(cmake/Sanitizers.cmake)
tc_use_test_sanitizers(tiny-crypto-c)

find_program(TC_SIZE_TOOL NAMES llvm-size size)
if(TC_SIZE_TOOL)
  set(tc_size_command ${TC_SIZE_TOOL} $<TARGET_FILE:tiny-crypto-c>)
else()
  # Keep the frontend target portable even on toolchains without binutils.
  set(tc_size_command ${CMAKE_COMMAND} -E echo
      "No size utility found; inspect $<TARGET_FILE:tiny-crypto-c>")
endif()
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(tc_size_target size)
else()
  set(tc_size_target tiny-crypto-c-size)
endif()
add_custom_target(${tc_size_target}
  COMMAND ${tc_size_command}
  DEPENDS tiny-crypto-c
  COMMENT "Static-library section sizes for the selected profile")

include(cmake/Fixtures.cmake)
include(cmake/Tests.cmake)
include(cmake/Benchmarks.cmake)

if(ESP_PLATFORM)
  # ESP-IDF components link SDK targets that exist only inside an ESP-IDF build.
  return()
endif()

include(CMakePackageConfigHelpers)
install(TARGETS tiny-crypto-c EXPORT tiny-crypto-cTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY src/tiny_crypto DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  PATTERN build_config.h EXCLUDE)
install(FILES ${tc_build_config} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tiny_crypto)
install(FILES LICENSE LICENSES/Unicode-3.0.txt
  DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/tiny-crypto-c)

set(tc_cmake_dir ${CMAKE_INSTALL_LIBDIR}/cmake/tiny-crypto-c)
configure_package_config_file(cmake/tiny-crypto-cConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/tiny-crypto-cConfig.cmake
  INSTALL_DESTINATION ${tc_cmake_dir})
write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/tiny-crypto-cConfigVersion.cmake
  VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/tiny-crypto-cConfig.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/tiny-crypto-cConfigVersion.cmake
        DESTINATION ${tc_cmake_dir})
install(EXPORT tiny-crypto-cTargets FILE tiny-crypto-cTargets.cmake
  NAMESPACE tiny-crypto-c:: DESTINATION ${tc_cmake_dir})
