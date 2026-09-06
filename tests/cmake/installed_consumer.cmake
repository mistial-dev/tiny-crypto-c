# SPDX-License-Identifier: GPL-2.0-or-later
function(run)
  execute_process(COMMAND ${ARGV} RESULT_VARIABLE status
    OUTPUT_VARIABLE output ERROR_VARIABLE error)
  if(NOT status EQUAL 0)
    message(FATAL_ERROR "${ARGV}\n${output}\n${error}")
  endif()
endfunction()
run("${CMAKE_COMMAND}" -S "${SOURCE_DIR}" -B "${BINARY_DIR}/library"
  -DCMAKE_BUILD_TYPE=Release
  "-DCMAKE_C_COMPILER=${C_COMPILER}" -DTINY_CRYPTO_BUILD_TESTS=OFF
  -DTINY_CRYPTO_BUILD_BENCHMARKS=OFF
  -DTINY_CRYPTO_ENABLE_KMAC256=ON
  "-DCMAKE_INSTALL_PREFIX=${BINARY_DIR}/prefix"
  -DCMAKE_INSTALL_INCLUDEDIR=custom-include)
run("${CMAKE_COMMAND}" --build "${BINARY_DIR}/library" --config Release)
run("${CMAKE_COMMAND}" --install "${BINARY_DIR}/library" --config Release)
run("${CMAKE_COMMAND}" -S "${SOURCE_DIR}/tests/cmake/consumer"
  -DCMAKE_BUILD_TYPE=Release
  -B "${BINARY_DIR}/consumer" "-DCMAKE_C_COMPILER=${C_COMPILER}"
  "-DCMAKE_PREFIX_PATH=${BINARY_DIR}/prefix")
run("${CMAKE_COMMAND}" --build "${BINARY_DIR}/consumer" --config Release)
run("${CMAKE_CTEST_COMMAND}" --test-dir "${BINARY_DIR}/consumer"
  -C Release --output-on-failure)
