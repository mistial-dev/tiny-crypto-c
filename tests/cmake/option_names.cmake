# SPDX-License-Identifier: GPL-2.0-or-later
#
# Configure with retired, removed and misspelled option names. Each must stop
# the configure and name the problem. Registered options, with or without a
# cache type, must configure.

if(NOT SOURCE_DIR OR NOT BINARY_DIR OR NOT C_COMPILER)
  message(FATAL_ERROR "SOURCE_DIR, BINARY_DIR and C_COMPILER are required")
endif()

function(configure_case name expected)
  set(tree "${BINARY_DIR}/${name}")
  file(REMOVE_RECURSE "${tree}")
  execute_process(COMMAND "${CMAKE_COMMAND}" -S "${SOURCE_DIR}" -B "${tree}"
    -DCMAKE_C_COMPILER=${C_COMPILER}
    -DTINY_CRYPTO_BUILD_TESTS=OFF -DTINY_CRYPTO_BUILD_BENCHMARKS=OFF ${ARGN}
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE errors)
  file(REMOVE_RECURSE "${tree}")
  if(expected STREQUAL "")
    if(result)
      message(FATAL_ERROR "${name}: configure failed: ${errors}")
    endif()
  elseif(NOT result)
    message(FATAL_ERROR "${name}: configure accepted ${ARGN}")
  elseif(NOT errors MATCHES "${expected}")
    message(FATAL_ERROR "${name}: expected \"${expected}\" in: ${errors}")
  endif()
endfunction()

configure_case(renamed "TINY_CRYPTO_AES_CBC was renamed to TINY_CRYPTO_AES_ENABLE_CBC"
  -DTINY_CRYPTO_AES_CBC=ON)
configure_case(renamed_value "TINY_CRYPTO_AES_SBOX was renamed to TINY_CRYPTO_AES_SBOX_MODE"
  -DTINY_CRYPTO_AES_SBOX:STRING=table)
configure_case(removed "TINY_CRYPTO_ZEROIZE was removed" -DTINY_CRYPTO_ZEROIZE=OFF)
configure_case(misspelled "TINY_CRYPTO_ENABLE_AESS is not an option" -DTINY_CRYPTO_ENABLE_AESS=ON)
configure_case(registered ""
  -DTINY_CRYPTO_ENABLE_AES:STRING=ON -DTINY_CRYPTO_AES_ENABLE_CBC=OFF
  -DTINY_CRYPTO_TEST_FULL:BOOL=OFF)
