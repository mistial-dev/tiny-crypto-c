# SPDX-License-Identifier: GPL-2.0-or-later

file(REMOVE_RECURSE "${BINARY_DIR}")
execute_process(
  COMMAND "${CMAKE_COMMAND}" -S "${SOURCE_DIR}" -B "${BINARY_DIR}"
    -DTINY_CRYPTO_BUILD_TESTS=OFF
    -DTINY_CRYPTO_ENABLE_DES=ON
    -DTINY_CRYPTO_DES_ECB=OFF
    -DTINY_CRYPTO_DES_CBC=OFF
    -DTINY_CRYPTO_DES_CTR=OFF
    -DTINY_CRYPTO_DES_OFB=OFF
    -DTINY_CRYPTO_DES_CFB1=OFF
    -DTINY_CRYPTO_DES_CFB8=OFF
    -DTINY_CRYPTO_DES_CFB64=OFF
    -DTINY_CRYPTO_DES_CMAC=OFF
  RESULT_VARIABLE result
  OUTPUT_VARIABLE output
  ERROR_VARIABLE error)

if(result EQUAL 0)
  message(FATAL_ERROR "DES without a consumer was accepted")
endif()
if(NOT "${output}${error}" MATCHES "DES requires at least one enabled mode or CMAC")
  message(FATAL_ERROR "DES profile failed for the wrong reason:\n${output}${error}")
endif()
