# SPDX-License-Identifier: GPL-2.0-or-later
#
# Build the library with every AUTO/ON/OFF feature option OFF. The build must
# configure, compile without warnings, and archive only the minimal core.
# OPTIONS is the comma-separated TC_FEATURE_OPTIONS list. Value options keep
# their defaults, since they select implementations and compile no sources.

if(NOT SOURCE_DIR OR NOT BINARY_DIR OR NOT C_COMPILER OR NOT AR OR NOT OPTIONS)
  message(FATAL_ERROR "SOURCE_DIR, BINARY_DIR, C_COMPILER, AR and OPTIONS are required")
endif()
file(REMOVE_RECURSE "${BINARY_DIR}")

# The minimal core: common.c holds wiping, constant-time comparison and the
# span helpers every module uses. features.json lists it as core_sources.
set(expected_members common.c)

string(REPLACE "," ";" feature_options "${OPTIONS}")
set(options)
foreach(option IN LISTS feature_options)
  list(APPEND options "-D${option}=OFF")
endforeach()
execute_process(COMMAND "${CMAKE_COMMAND}" -S "${SOURCE_DIR}" -B "${BINARY_DIR}"
  -DCMAKE_C_COMPILER=${C_COMPILER} -DCMAKE_BUILD_TYPE=Release
  -DCMAKE_COMPILE_WARNING_AS_ERROR=ON
  -DTINY_CRYPTO_BUILD_TESTS=OFF -DTINY_CRYPTO_BUILD_BENCHMARKS=OFF ${options}
  RESULT_VARIABLE result OUTPUT_QUIET ERROR_VARIABLE errors)
if(result)
  message(FATAL_ERROR "All-off configure failed: ${errors}")
endif()
execute_process(COMMAND "${CMAKE_COMMAND}" --build "${BINARY_DIR}" --target tiny-crypto-c
  --parallel 4 RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE errors)
if(result OR output MATCHES "warning:" OR errors MATCHES "warning:")
  message(FATAL_ERROR "All-off build failed or warned: ${output}\n${errors}")
endif()

file(GLOB_RECURSE archive "${BINARY_DIR}/*tiny-crypto-c.a")
list(LENGTH archive archive_count)
if(NOT archive_count EQUAL 1)
  message(FATAL_ERROR "Expected one library archive, found: ${archive}")
endif()
execute_process(COMMAND "${AR}" t "${archive}" RESULT_VARIABLE result OUTPUT_VARIABLE listing)
if(result)
  message(FATAL_ERROR "Could not list ${archive}")
endif()
string(REPLACE "\n" ";" listing "${listing}")
set(members)
foreach(member IN LISTS listing)
  # Skip the symbol table entry that some archivers list.
  if(member STREQUAL "" OR member MATCHES "^__\\.SYMDEF")
    continue()
  endif()
  string(REGEX REPLACE "\\.o(bj)?$" "" member "${member}")
  string(REGEX REPLACE "\\.c$" "" member "${member}")
  list(APPEND members "${member}.c")
endforeach()
list(SORT members)
if(NOT members STREQUAL expected_members)
  message(FATAL_ERROR "All-off archive holds ${members}, expected ${expected_members}")
endif()

file(READ "${SOURCE_DIR}/cmake/features.json" registry)
string(JSON core_count LENGTH "${registry}" core_sources)
string(JSON core GET "${registry}" core_sources 0)
if(NOT core_count EQUAL 1 OR NOT core STREQUAL "src/common.c")
  message(FATAL_ERROR "features.json core_sources differs from the asserted minimal core")
endif()
