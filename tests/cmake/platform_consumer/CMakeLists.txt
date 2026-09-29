# SPDX-License-Identifier: GPL-2.0-or-later
#
# Host stand-in for the ESP-IDF component. It applies the port's platform
# features and compiles the port sources against the configured library.
cmake_minimum_required(VERSION 3.24)
project(platform_consumer LANGUAGES C)
set(TINY_CRYPTO_BUILD_TESTS OFF)
set(TINY_CRYPTO_BUILD_BENCHMARKS OFF)
include("${SOURCE_DIR}/ports/esp-idf/tiny-crypto-c/platform_features.cmake")
add_subdirectory("${SOURCE_DIR}" library)

set(port "${SOURCE_DIR}/ports/esp-idf")
set(stubs "${SOURCE_DIR}/tests/esp_idf/include")
set(vendor "${port}/vendor/bootloader_support")
add_library(platform_hash OBJECT "${port}/bootloader_hash.c")
target_include_directories(platform_hash PRIVATE "${stubs}" "${vendor}/private_include")
target_link_libraries(platform_hash PRIVATE tiny-crypto-c)
if(CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME)
  add_library(platform_rsa OBJECT "${port}/signed_update_rsa.c")
  target_include_directories(platform_rsa PRIVATE "${stubs}" "${vendor}/src/secure_boot_v2")
  target_link_libraries(platform_rsa PRIVATE tiny-crypto-c)
endif()
if(CONFIG_SECURE_SIGNED_APPS_ECDSA_V2_SCHEME)
  add_library(platform_ecdsa OBJECT "${port}/signed_update_ecdsa.c")
  target_include_directories(platform_ecdsa PRIVATE "${stubs}" "${vendor}/src/secure_boot_v2")
  target_compile_definitions(platform_ecdsa PRIVATE TC_TEST_IDF_ECDSA=1)
  target_link_libraries(platform_ecdsa PRIVATE tiny-crypto-c)
endif()
