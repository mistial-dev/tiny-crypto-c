# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later

cmake_minimum_required(VERSION 3.24)
project(tiny-crypto-c VERSION 1.0.0 LANGUAGES C)
include(GNUInstallDirs)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR AND
   NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(TINY_CRYPTO_ENABLE_AES "Build AES" ON)
option(TINY_CRYPTO_ENABLE_DES "Build DES and 3DES" OFF)
option(TINY_CRYPTO_ENABLE_SHA1 "Build SHA-1" OFF)
option(TINY_CRYPTO_ENABLE_SHA224 "Build SHA-224" OFF)
option(TINY_CRYPTO_ENABLE_SHA256 "Build SHA-256" ON)
option(TINY_CRYPTO_ENABLE_SHA384 "Build SHA-384" OFF)
option(TINY_CRYPTO_ENABLE_SHA512 "Build SHA-512" OFF)
option(TINY_CRYPTO_ENABLE_HMAC "Build HMAC" OFF)
option(TINY_CRYPTO_ENABLE_KMAC256 "Build fixed-output KMAC256" OFF)
option(TINY_CRYPTO_ENABLE_KDF "Build SP 800-108 KBKDF over the enabled HMAC/CMAC PRFs" OFF)
option(TINY_CRYPTO_ZEROIZE "Wipe secret state after use" ON)
option(TINY_CRYPTO_STRICT "Validate public API pointers" ON)
option(TINY_CRYPTO_AVR_PROGMEM "Keep constant tables in AVR flash" ON)

set(TINY_CRYPTO_AES_KEY_BITS 128 CACHE STRING "AES key size: 128, 192, or 256")
set_property(CACHE TINY_CRYPTO_AES_KEY_BITS PROPERTY STRINGS 128 192 256)
option(TINY_CRYPTO_AES_CBC "Build AES-CBC" OFF)
option(TINY_CRYPTO_AES_ECB "Build AES-ECB" OFF)
option(TINY_CRYPTO_AES_CTR "Build AES-CTR" ON)
option(TINY_CRYPTO_AES_OFB "Build AES-OFB" OFF)
option(TINY_CRYPTO_AES_GCM "Build AES-GCM" OFF)
option(TINY_CRYPTO_AES_CCM "Build AES-CCM" OFF)
option(TINY_CRYPTO_AES_EAX "Build AES-EAX" OFF)
option(TINY_CRYPTO_AES_EAX_PRIME "Build ANSI C12.22 EAX-prime" OFF)
option(TINY_CRYPTO_AES_SIV "Build AES-SIV" OFF)
option(TINY_CRYPTO_AES_CMAC "Build AES-CMAC" OFF)
set(TINY_CRYPTO_AES_SBOX "constant-time" CACHE STRING
    "AES S-box: constant-time, runtime, or fast")
set_property(CACHE TINY_CRYPTO_AES_SBOX PROPERTY STRINGS constant-time runtime fast)
set(TINY_CRYPTO_AES_GHASH "auto" CACHE STRING
    "GCM multiply: auto, bitwise, wide, fast-table, or hardware")
set_property(CACHE TINY_CRYPTO_AES_GHASH PROPERTY STRINGS
             auto bitwise wide fast-table hardware)
option(TINY_CRYPTO_AES_WIDE_OPS "Use native-width AES helpers" OFF)
option(TINY_CRYPTO_AES_TINY "Reject large per-context GHASH tables" OFF)

option(TINY_CRYPTO_DES_ECB "Build DES-ECB" OFF)
option(TINY_CRYPTO_DES_CBC "Build DES-CBC" OFF)
option(TINY_CRYPTO_DES_CTR "Build DES-CTR" ON)
option(TINY_CRYPTO_DES_OFB "Build DES-OFB" OFF)
option(TINY_CRYPTO_DES_CFB1 "Build DES-CFB1" OFF)
option(TINY_CRYPTO_DES_CFB8 "Build DES-CFB8" OFF)
option(TINY_CRYPTO_DES_CFB64 "Build DES-CFB64" OFF)
option(TINY_CRYPTO_DES_TDES "Build 3DES" ON)
option(TINY_CRYPTO_DES_CMAC "Build TDEA-CMAC" OFF)
option(TINY_CRYPTO_DES_REJECT_WEAK_KEYS
       "Reject weak DES keys and degenerate TDEA bundles" OFF)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  option(TINY_CRYPTO_BUILD_TESTS "Build host tests" ON)
else()
  option(TINY_CRYPTO_BUILD_TESTS "Build host tests" OFF)
endif()
option(TINY_CRYPTO_TEST_FULL "Run checked-in CAVP corpora" OFF)
set(TINY_CRYPTO_SANITIZE "" CACHE STRING
    "Test sanitizers, for example address,undefined")

set(tc_any_sha OFF)
if(TINY_CRYPTO_ENABLE_SHA1 OR TINY_CRYPTO_ENABLE_SHA224 OR
   TINY_CRYPTO_ENABLE_SHA256 OR TINY_CRYPTO_ENABLE_SHA384 OR
   TINY_CRYPTO_ENABLE_SHA512)
  set(tc_any_sha ON)
endif()
if(NOT TINY_CRYPTO_ENABLE_AES AND NOT TINY_CRYPTO_ENABLE_DES AND NOT tc_any_sha
   AND NOT TINY_CRYPTO_ENABLE_KMAC256)
  message(FATAL_ERROR "Enable at least one algorithm")
endif()
if(TINY_CRYPTO_ENABLE_HMAC AND NOT tc_any_sha)
  message(FATAL_ERROR "HMAC requires at least one SHA algorithm")
endif()
if(TINY_CRYPTO_ENABLE_DES AND NOT TINY_CRYPTO_DES_ECB AND
   NOT TINY_CRYPTO_DES_CBC AND NOT TINY_CRYPTO_DES_CTR AND
   NOT TINY_CRYPTO_DES_OFB AND NOT TINY_CRYPTO_DES_CFB1 AND
   NOT TINY_CRYPTO_DES_CFB8 AND NOT TINY_CRYPTO_DES_CFB64 AND
   NOT TINY_CRYPTO_DES_CMAC)
  message(FATAL_ERROR "DES requires at least one enabled mode or CMAC")
endif()
set(tc_kdf_prf OFF)
if(TINY_CRYPTO_ENABLE_HMAC AND tc_any_sha)
  set(tc_kdf_prf ON)
endif()
if(TINY_CRYPTO_ENABLE_AES AND TINY_CRYPTO_AES_CMAC)
  set(tc_kdf_prf ON)
endif()
if(TINY_CRYPTO_ENABLE_DES AND TINY_CRYPTO_DES_CMAC)
  set(tc_kdf_prf ON)
endif()
if(TINY_CRYPTO_ENABLE_KDF AND NOT tc_kdf_prf)
  message(FATAL_ERROR "KDF requires a PRF: HMAC with a SHA, AES-CMAC, or TDEA-CMAC")
endif()
if(NOT TINY_CRYPTO_AES_KEY_BITS MATCHES "^(128|192|256)$")
  message(FATAL_ERROR "TINY_CRYPTO_AES_KEY_BITS must be 128, 192, or 256")
endif()

function(tc_bool option output)
  if(${option})
    set(${output} 1 PARENT_SCOPE)
  else()
    set(${output} 0 PARENT_SCOPE)
  endif()
endfunction()

function(tc_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4)
  elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
  endif()
endfunction()

foreach(pair
    "TINY_CRYPTO_ENABLE_AES;TC_ENABLE_AES"
    "TINY_CRYPTO_ENABLE_DES;TC_ENABLE_DES"
    "TINY_CRYPTO_ENABLE_SHA1;TC_ENABLE_SHA1"
    "TINY_CRYPTO_ENABLE_SHA224;TC_ENABLE_SHA224"
    "TINY_CRYPTO_ENABLE_SHA256;TC_ENABLE_SHA256"
    "TINY_CRYPTO_ENABLE_SHA384;TC_ENABLE_SHA384"
    "TINY_CRYPTO_ENABLE_SHA512;TC_ENABLE_SHA512"
    "TINY_CRYPTO_ENABLE_HMAC;TC_ENABLE_HMAC"
    "TINY_CRYPTO_ENABLE_KMAC256;TC_ENABLE_KMAC256"
    "TINY_CRYPTO_ENABLE_KDF;TC_ENABLE_KDF"
    "TINY_CRYPTO_ZEROIZE;TC_ZEROIZE"
    "TINY_CRYPTO_STRICT;TC_STRICT"
    "TINY_CRYPTO_AVR_PROGMEM;TC_AVR_PROGMEM"
    "TINY_CRYPTO_AES_CBC;TC_AES_ENABLE_CBC"
    "TINY_CRYPTO_AES_ECB;TC_AES_ENABLE_ECB"
    "TINY_CRYPTO_AES_CTR;TC_AES_ENABLE_CTR"
    "TINY_CRYPTO_AES_OFB;TC_AES_ENABLE_OFB"
    "TINY_CRYPTO_AES_GCM;TC_AES_ENABLE_GCM"
    "TINY_CRYPTO_AES_CCM;TC_AES_ENABLE_CCM"
    "TINY_CRYPTO_AES_EAX;TC_AES_ENABLE_EAX"
    "TINY_CRYPTO_AES_EAX_PRIME;TC_AES_ENABLE_EAX_PRIME"
    "TINY_CRYPTO_AES_SIV;TC_AES_ENABLE_SIV"
    "TINY_CRYPTO_AES_CMAC;TC_AES_ENABLE_CMAC"
    "TINY_CRYPTO_AES_WIDE_OPS;TC_AES_WIDE_OPS"
    "TINY_CRYPTO_AES_TINY;TC_AES_TINY"
    "TINY_CRYPTO_DES_ECB;TC_DES_ENABLE_ECB"
    "TINY_CRYPTO_DES_CBC;TC_DES_ENABLE_CBC"
    "TINY_CRYPTO_DES_CTR;TC_DES_ENABLE_CTR"
    "TINY_CRYPTO_DES_OFB;TC_DES_ENABLE_OFB"
    "TINY_CRYPTO_DES_CFB1;TC_DES_ENABLE_CFB1"
    "TINY_CRYPTO_DES_CFB8;TC_DES_ENABLE_CFB8"
    "TINY_CRYPTO_DES_CFB64;TC_DES_ENABLE_CFB64"
    "TINY_CRYPTO_DES_TDES;TC_DES_ENABLE_TDES"
    "TINY_CRYPTO_DES_CMAC;TC_DES_ENABLE_CMAC"
    "TINY_CRYPTO_DES_REJECT_WEAK_KEYS;TC_DES_REJECT_WEAK_KEYS")
  list(GET pair 0 option_name)
  list(GET pair 1 macro_name)
  tc_bool(${option_name} macro_value)
  list(APPEND TC_PUBLIC_DEFINITIONS ${macro_name}=${macro_value})
endforeach()

set(sbox_values constant-time runtime fast)
list(FIND sbox_values "${TINY_CRYPTO_AES_SBOX}" sbox_index)
if(sbox_index EQUAL -1)
  message(FATAL_ERROR "Unknown TINY_CRYPTO_AES_SBOX value")
endif()
math(EXPR sbox_value "${sbox_index} + 1")

set(ghash_values auto bitwise wide fast-table hardware)
list(FIND ghash_values "${TINY_CRYPTO_AES_GHASH}" ghash_value)
if(ghash_value EQUAL -1)
  message(FATAL_ERROR "Unknown TINY_CRYPTO_AES_GHASH value")
endif()
if(TINY_CRYPTO_AES_TINY AND TINY_CRYPTO_AES_GHASH STREQUAL "fast-table")
  message(FATAL_ERROR "The tiny profile rejects the 256-byte GHASH table")
endif()

list(APPEND TC_PUBLIC_DEFINITIONS
  TC_AES_KEY_BITS=${TINY_CRYPTO_AES_KEY_BITS}
  TC_AES_SBOX_MODE=${sbox_value}
  TC_AES_GCM_GHASH_MODE=${ghash_value})

set(tc_aes_sources src/aes.c src/aes_gcm.c src/aes_ccm.c src/aes_mac.c)

# One utility translation unit keeps zeroization and constant-time comparison
# consistent across algorithms, and avoids duplicate code in firmware images.
set(tc_sources src/common.c)
if(TINY_CRYPTO_ENABLE_KMAC256)
  list(APPEND tc_sources src/kmac.c)
endif()
if(TINY_CRYPTO_ENABLE_AES)
  list(APPEND tc_sources ${tc_aes_sources})
endif()
if(TINY_CRYPTO_ENABLE_DES)
  list(APPEND tc_sources src/des.c)
endif()
if(TINY_CRYPTO_ENABLE_SHA1 OR TINY_CRYPTO_ENABLE_SHA224 OR TINY_CRYPTO_ENABLE_SHA256)
  list(APPEND tc_sources src/hash.c)
endif()
if(TINY_CRYPTO_ENABLE_SHA384 OR TINY_CRYPTO_ENABLE_SHA512)
  list(APPEND tc_sources src/sha512.c)
endif()
if(TINY_CRYPTO_ENABLE_KDF)
  list(APPEND tc_sources src/kdf.c)
endif()

add_library(tiny-crypto-c STATIC ${tc_sources})
add_library(tiny-crypto-c::tiny-crypto-c ALIAS tiny-crypto-c)
target_include_directories(tiny-crypto-c PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_compile_definitions(tiny-crypto-c PUBLIC ${TC_PUBLIC_DEFINITIONS})
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

include(cmake/Tests.cmake)
include(cmake/Benchmarks.cmake)

include(CMakePackageConfigHelpers)
install(TARGETS tiny-crypto-c EXPORT tiny-crypto-cTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY src/tiny_crypto DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

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
