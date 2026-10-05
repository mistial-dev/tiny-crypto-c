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
# cmake/features.json declares every feature option. Features.cmake resolves
# them and selects the sources they compile.
include(cmake/Features.cmake)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  option(TINY_CRYPTO_BUILD_TESTS "Build host tests" ON)
else()
  option(TINY_CRYPTO_BUILD_TESTS "Build host tests" OFF)
endif()
option(TINY_CRYPTO_TEST_FULL "Run checked-in CAVP corpora" OFF)
option(TINY_CRYPTO_TEST_PIV_CARD "Build the opt-in PIV card hardware tests over PC/SC" OFF)
set(TINY_CRYPTO_SANITIZE "" CACHE STRING
    "Test sanitizers, for example address,undefined")

# config.h owns every dependency rule. A build with every feature off is valid
# and contains only the core sources.
get_property(TC_PUBLIC_DEFINITIONS GLOBAL PROPERTY TINY_CRYPTO_PUBLIC_DEFINITIONS)
include(cmake/ConfigCheck.cmake)
tc_check_config("${TC_PUBLIC_DEFINITIONS}")
set(tc_build_config "${CMAKE_CURRENT_BINARY_DIR}/install-include/tiny_crypto/build_config.h")
tc_write_build_config("${tc_build_config}" "${TC_PUBLIC_DEFINITIONS}")

function(tc_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4)
  elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wundef)
  endif()
endfunction()

# Family source lists for the test libraries, which select modes with their
# own definitions.
tc_registry_family_sources(tc_aes_sources TC_ENABLE_AES)
tc_registry_family_sources(tc_des_sources TC_ENABLE_DES)
tc_registry_family_sources(tc_hash_sources TC_ENABLE_SHA1 TC_ENABLE_SHA224 TC_ENABLE_SHA256
  TC_ENABLE_SHA384 TC_ENABLE_SHA512)
tc_registry_family_sources(tc_drbg_sources TC_ENABLE_DRBG)
tc_registry_family_sources(tc_rsa_sources TC_ENABLE_RSA)

tc_registry_sources(tc_sources)

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
