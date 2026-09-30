# SPDX-License-Identifier: GPL-2.0-or-later

# Build the shipped library with every registered feature and module on, check
# that every src/*.c is in the archive, then apply the allocator check. The
# default archive covers only the configured profile, so this is the check
# that reaches the PKI, PIV, SM and TWIC modules.
# OPTIONS is the comma-separated TC_FEATURE_OPTIONS list that every
# tc_profile_option call records.
string(REPLACE "," ";" feature_options "${OPTIONS}")
set(options)
foreach(option IN LISTS feature_options)
  list(APPEND options "-D${option}=ON")
endforeach()
list(LENGTH options option_count)
if(option_count LESS 20)
  message(FATAL_ERROR "Found only ${option_count} feature options")
endif()

execute_process(COMMAND "${CMAKE_COMMAND}" -S "${SOURCE_DIR}" -B "${BINARY_DIR}"
  -DCMAKE_C_COMPILER=${C_COMPILER} -DCMAKE_BUILD_TYPE=Release
  -DTINY_CRYPTO_BUILD_TESTS=OFF -DTINY_CRYPTO_BUILD_BENCHMARKS=OFF ${options}
  RESULT_VARIABLE result OUTPUT_QUIET ERROR_VARIABLE errors)
if(result)
  message(FATAL_ERROR "All-features configure failed: ${errors}")
endif()
execute_process(COMMAND "${CMAKE_COMMAND}" --build "${BINARY_DIR}" --target tiny-crypto-c
  --parallel 4 RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE errors)
if(result)
  message(FATAL_ERROR "All-features build failed: ${output}\n${errors}")
endif()

file(GLOB_RECURSE archive "${BINARY_DIR}/*tiny-crypto-c.a")
list(FILTER archive EXCLUDE REGEX "/_deps/")
list(LENGTH archive archive_count)
if(NOT archive_count EQUAL 1)
  message(FATAL_ERROR "Expected one library archive, found: ${archive}")
endif()
execute_process(COMMAND "${AR}" t "${archive}" RESULT_VARIABLE result OUTPUT_VARIABLE members)
if(result)
  message(FATAL_ERROR "Could not list ${archive}")
endif()
file(GLOB library_sources RELATIVE "${SOURCE_DIR}/src" "${SOURCE_DIR}/src/*.c")
foreach(source IN LISTS library_sources)
  string(REGEX REPLACE "\\.c$" "" stem "${source}")
  if(NOT members MATCHES "(^|\n)${stem}\\.c\\.o(bj)?\n")
    message(FATAL_ERROR "src/${source} is not built by any feature option, so the heap check cannot see it")
  endif()
endforeach()

execute_process(COMMAND "${CMAKE_COMMAND}" -DNM=${NM} -DARCHIVE=${archive}
  -P "${SOURCE_DIR}/tests/cmake/heap_free.cmake"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE errors)
if(result)
  message(FATAL_ERROR "${output}${errors}")
endif()
