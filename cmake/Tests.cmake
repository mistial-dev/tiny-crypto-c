# SPDX-License-Identifier: GPL-2.0-or-later

if(TINY_CRYPTO_BUILD_TESTS)
  enable_language(CXX)
  set(CMAKE_CXX_STANDARD 11)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  set(CMAKE_CXX_EXTENSIONS OFF)
  enable_testing()
  find_package(Python3 COMPONENTS Interpreter QUIET)
  if(Python3_Interpreter_FOUND)
    add_test(NAME test_benchmark_report
      COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_benchmark_report.py)
  endif()

  add_test(NAME test_installed_consumer
    COMMAND ${CMAKE_COMMAND}
      -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
      -DBINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}/installed-consumer
      -DC_COMPILER=${CMAKE_C_COMPILER}
      -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/installed_consumer.cmake)
  # Recursive make exports Debug during sanitizer runs. The package test must
  # still configure, build, and install the same configuration.
  add_test(NAME test_installed_consumer_debug_environment
    COMMAND ${CMAKE_COMMAND} -E env CMAKE_BUILD_TYPE=Debug
      ${CMAKE_COMMAND}
      -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
      -DBINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}/installed-consumer-debug-environment
      -DC_COMPILER=${CMAKE_C_COMPILER}
      -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/installed_consumer.cmake)
  foreach(sbox runtime fast)
    if(sbox STREQUAL "runtime")
      set(value 2)
    else()
      set(value 3)
    endif()
    add_test(NAME test_benchmark_${sbox}
      COMMAND ${CMAKE_COMMAND}
        -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -DBINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}/benchmark-${sbox}
        -DC_COMPILER=${CMAKE_C_COMPILER} -DSBOX=${sbox} -DSBOX_VALUE=${value}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/benchmark_profile.cmake)
  endforeach()

  add_test(NAME test_reject_des_without_consumer
    COMMAND ${CMAKE_COMMAND}
      -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
      -DBINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}/invalid-des-profile
      -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/reject_des_without_consumer.cmake)

  # µunit uses C11 atomics when Clang exposes them in C99 mode. Keep the
  # vendored source unchanged and suppress that extension warning locally.
  if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    set_source_files_properties(tests/support/munit.c PROPERTIES
      COMPILE_OPTIONS -Wno-c11-extensions)
  endif()

  include(${CMAKE_CURRENT_LIST_DIR}/TestProfiles.cmake)

  tc_add_linked_test(test_kmac tiny-crypto-c-test tests/kmac/test.c)
  tc_add_test_library(tiny-crypto-c-test-kmac-relaxed src/common.c src/kmac.c)
  target_compile_definitions(tiny-crypto-c-test-kmac-relaxed PUBLIC
    TC_ENABLE_KMAC256=1 TC_ENABLE_AES=0 TC_ENABLE_SHA256=0
    TC_ZEROIZE=0 TC_STRICT=0)
  tc_add_linked_test(test_kmac_relaxed tiny-crypto-c-test-kmac-relaxed tests/kmac/test.c)

  tc_add_c_test(test_hash tiny-crypto-c-test
    tests/hash/test.c tests/hash/hmac_test.c tests/hash/cavp.c)
  target_include_directories(test_hash PRIVATE tests/hash)
  target_compile_definitions(test_hash PRIVATE
    CAVP_VECTOR_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/hash/cavp"
    HMAC_WYCHEPROOF_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/hash/wycheproof")

  function(tc_add_aes_test target library)
    tc_add_c_test(${target} ${library} tests/aes/test.c tests/aes/cavp.c
      tests/aes/eax_test.c tests/aes/siv_test.c tests/aes/cmac_test.c)
    target_include_directories(${target} PRIVATE tests/aes)
    target_compile_definitions(${target} PRIVATE
      CAVP_VECTOR_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/aes/cavp"
      EAX_VECTOR_FILE="${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/aes/eax/aes_eax_test.json"
      SIV_VECTOR_FILE="${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/aes/siv/aead_aes_siv_cmac_test.json"
      CMAC_WYCHEPROOF_FILE="${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/aes/cmac/aes_cmac_test.json"
      CMAC_CAVP_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/aes/cmac")
  endfunction()

  tc_add_aes_test(test_aes tiny-crypto-c-test)
  tc_add_aes_test(test_aes_192 tiny-crypto-c-test-aes192)
  tc_add_aes_test(test_aes_256 tiny-crypto-c-test-aes256)

  tc_add_c_test(test_des tiny-crypto-c-test
    tests/des/test.c tests/des/test_edge_vectors.c)
  target_include_directories(test_des PRIVATE tests/des)
  target_compile_definitions(test_des PRIVATE
    CAVP_VECTOR_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/des/cavp")

  if(TINY_CRYPTO_TEST_FULL)
    add_executable(test_des_cavp
      tests/des/cavp_main.c tests/des/cavp.c
      tests/support/cavp.c tests/support/munit.c)
    target_link_libraries(test_des_cavp PRIVATE tiny-crypto-c-test)
    target_include_directories(test_des_cavp PRIVATE tests/support tests/des)
    target_compile_definitions(test_des_cavp PRIVATE
      CAVP_VECTOR_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/des/cavp")
    tc_warnings(test_des_cavp)
    tc_use_test_sanitizers(test_des_cavp)
    foreach(group kat mmt mct-ecb mct-cbc mct-cfb1 mct-cfb8 mct-cfb64 mct-ofb)
      add_test(NAME test_des_cavp_${group}
        COMMAND test_des_cavp /tiny-des-cavp/${group})
    endforeach()
  endif()

  # One KDF binary per AES key size: each runs the AES-CMAC CAVP sections for
  # its key size, and the 128-bit binary also runs every non-AES PRF section.
  function(tc_add_kdf_test target library)
    tc_add_c_test(${target} ${library}
      tests/kdf/test.c tests/kdf/kbkdf_test.c tests/kdf/cavp.c)
    target_include_directories(${target} PRIVATE tests/kdf)
    target_compile_definitions(${target} PRIVATE
      KDF_CAVP_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/vectors/kdf/cavp")
  endfunction()

  tc_add_kdf_test(test_kdf tiny-crypto-c-test)
  tc_add_kdf_test(test_kdf_192 tiny-crypto-c-test-aes192)
  tc_add_kdf_test(test_kdf_256 tiny-crypto-c-test-aes256)

  tc_add_c_test(test_des_weak_keys_allowed tiny-crypto-c-test
    tests/des/weak_keys_test.c)
  tc_add_c_test(test_des_weak_keys_rejected tiny-crypto-c-test-des-reject-weak
    tests/des/weak_keys_test.c)

  tc_add_linked_test(test_default_profile tiny-crypto-c
    tests/default_profile.c)

  tc_add_linked_test(test_aes_runtime_sbox tiny-crypto-c-test-aes-runtime-sbox
    tests/aes/runtime_sbox_test.c)

  foreach(ghash_mode 1 2 3 4)
    tc_add_linked_test(test_aes_gcm_${ghash_mode}
      tiny-crypto-c-test-gcm-${ghash_mode} tests/aes/gcm_profile_test.c
      tests/aes/gcm_hardware_stub.c)
  endforeach()

  # C++ wrapper suites use the vendored doctest header (tests/support/doctest.h)
  # with one shared main so each binary supports doctest's filters and reporters.
  if(tc_build_cpp_tests)
    foreach(algorithm hash aes des kdf kmac)
      tc_add_linked_test(test_cpp_${algorithm} tiny-crypto-c-test
        tests/cpp/${algorithm}.cpp tests/cpp/main.cpp)
      target_include_directories(test_cpp_${algorithm} PRIVATE
        tests/support tests/${algorithm})
    endforeach()

    foreach(key_bits 192 256)
      foreach(algorithm aes kdf)
        tc_add_linked_test(test_cpp_${algorithm}_${key_bits}
          tiny-crypto-c-test-aes${key_bits}
          tests/cpp/${algorithm}.cpp tests/cpp/main.cpp)
        target_include_directories(test_cpp_${algorithm}_${key_bits} PRIVATE
          tests/support tests/${algorithm})
      endforeach()
    endforeach()
  endif()

  add_library(test_cpp_headers_cxx17 OBJECT tests/cpp/header_compile.cpp)
  target_include_directories(test_cpp_headers_cxx17 PRIVATE src)
  set_property(TARGET test_cpp_headers_cxx17 PROPERTY CXX_STANDARD 17)
  target_compile_definitions(test_cpp_headers_cxx17 PRIVATE
    ${tc_full_definitions} TC_AES_KEY_BITS=128 TC_AES_ENABLE_EAX_PRIME=1)

  find_program(TC_AVR_CXX NAMES avr-g++)
  if(TC_AVR_CXX)
    add_test(NAME test_cpp_headers_avr
      COMMAND ${TC_AVR_CXX} -std=gnu++11 -fno-exceptions -fno-rtti
        -DTC_ENABLE_KMAC256=1
        -mmcu=atmega328p -I${CMAKE_CURRENT_SOURCE_DIR}/src
        -c ${CMAKE_CURRENT_SOURCE_DIR}/tests/cpp/header_compile.cpp
        -o ${CMAKE_CURRENT_BINARY_DIR}/tiny-crypto-c-header-compile.o)
  endif()

endif()
