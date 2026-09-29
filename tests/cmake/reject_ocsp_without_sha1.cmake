# SPDX-License-Identifier: GPL-2.0-or-later

# A byKey ResponderID is a SHA-1 key hash (RFC 6960 4.2.1), so OCSP needs SHA-1.
file(REMOVE_RECURSE "${BINARY_DIR}")
execute_process(
  COMMAND "${CMAKE_COMMAND}" -S "${SOURCE_DIR}" -B "${BINARY_DIR}"
    -DTINY_CRYPTO_BUILD_TESTS=OFF
    -DTINY_CRYPTO_ENABLE_TLV=ON
    -DTINY_CRYPTO_ENABLE_DER=ON
    -DTINY_CRYPTO_ENABLE_X509=ON
    -DTINY_CRYPTO_ENABLE_X509_PATH=ON
    -DTINY_CRYPTO_ENABLE_X509_OCSP=ON
    -DTINY_CRYPTO_ENABLE_SHA256=ON
    -DTINY_CRYPTO_ENABLE_SHA1=OFF
  RESULT_VARIABLE result
  OUTPUT_VARIABLE output
  ERROR_VARIABLE error)

if(result EQUAL 0)
  message(FATAL_ERROR "OCSP without SHA-1 was accepted")
endif()
if(NOT "${output}${error}" MATCHES "TINY_CRYPTO_ENABLE_X509_OCSP requires TINY_CRYPTO_ENABLE_SHA1")
  message(FATAL_ERROR "OCSP profile failed for the wrong reason:\n${output}${error}")
endif()
