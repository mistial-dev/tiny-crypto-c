# SPDX-License-Identifier: GPL-2.0-or-later
function(run)
  execute_process(COMMAND ${ARGV} RESULT_VARIABLE status
    OUTPUT_VARIABLE output ERROR_VARIABLE error)
  if(NOT status EQUAL 0)
    message(FATAL_ERROR "${ARGV}\n${output}\n${error}")
  endif()
  set(last_output "${output}" PARENT_SCOPE)
endfunction()
run("${CMAKE_COMMAND}" -S "${SOURCE_DIR}" -B "${BINARY_DIR}"
  "-DCMAKE_C_COMPILER=${C_COMPILER}" -DCMAKE_BUILD_TYPE=Release
  -DTINY_CRYPTO_BUILD_TESTS=OFF -DTINY_CRYPTO_BUILD_BENCHMARKS=ON
  -DTINY_CRYPTO_AES_KEY_BITS=256 "-DTINY_CRYPTO_AES_SBOX=${SBOX}"
  -DTINY_CRYPTO_AES_GCM=ON -DTINY_CRYPTO_AES_GHASH=wide)
run("${CMAKE_COMMAND}" --build "${BINARY_DIR}" --config Release
  --target benchmark_aes)
if(EXISTS "${BINARY_DIR}/Release/benchmark_aes.exe")
  set(executable "${BINARY_DIR}/Release/benchmark_aes.exe")
else()
  set(executable "${BINARY_DIR}/benchmark_aes")
endif()
run("${executable}")
if(NOT last_output MATCHES "key_bits=256 sbox=${SBOX_VALUE} ghash=2")
  message(FATAL_ERROR "Benchmark did not use the requested profile: ${last_output}")
endif()
