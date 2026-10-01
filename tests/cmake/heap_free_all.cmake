# SPDX-License-Identifier: GPL-2.0-or-later

# Build the shipped library with every registered feature and module on, check
# that every src/*.c is in the archive, then apply the allocator check. The
# default archive covers only the configured profile, so this is the check
# that reaches the PKI, PIV, SM and TWIC modules.
# OPTIONS is the comma-separated TC_FEATURE_OPTIONS list of every AUTO/ON/OFF
# option in cmake/features.json. The all-on build keeps value options at their
# defaults. A second pass then builds each other value of each value option
# with only its parent feature on, under the desktop profile, and applies the
# same check, since each value compiles a different implementation.
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

function(check_heap_free archive label)
  execute_process(COMMAND "${CMAKE_COMMAND}" -DNM=${NM} -DARCHIVE=${archive}
    -P "${SOURCE_DIR}/tests/cmake/heap_free.cmake"
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE errors)
  if(result)
    message(FATAL_ERROR "${label}: ${output}${errors}")
  endif()
endfunction()
check_heap_free("${archive}" "All features")

# Value pass. Every switch is OFF except the parent of the value option and the
# parent's sub-features. Those stay AUTO, so the desktop profile turns their
# modes on. Every option is passed, so a value from an earlier case never stays
# in the cache.
file(READ "${SOURCE_DIR}/cmake/features.json" registry)
string(JSON feature_count LENGTH "${registry}" features)
math(EXPR feature_last "${feature_count} - 1")
set(switches)
set(value_features)
foreach(index RANGE ${feature_last})
  string(JSON macro GET "${registry}" features ${index} macro)
  string(JSON parent ERROR_VARIABLE no_parent GET "${registry}" features ${index} parent)
  string(JSON kind ERROR_VARIABLE no_values TYPE "${registry}" features ${index} values)
  if(no_values)
    list(APPEND switches ${macro})
    if(no_parent)
      set(parent_${macro} "")
    else()
      set(parent_${macro} ${parent})
    endif()
  else()
    list(APPEND value_features ${index})
  endif()
endforeach()

set(value_cases 0)
foreach(index IN LISTS value_features)
  string(JSON macro GET "${registry}" features ${index} macro)
  string(JSON parent GET "${registry}" features ${index} parent)
  string(JSON default GET "${registry}" features ${index} default)
  string(JSON name_count LENGTH "${registry}" features ${index} values)
  math(EXPR name_last "${name_count} - 1")
  foreach(entry RANGE ${name_last})
    string(JSON name GET "${registry}" features ${index} values ${entry} name)
    if(name STREQUAL default)
      continue()
    endif()
    set(case_options -DTINY_CRYPTO_RESOURCE_PROFILE=desktop)
    foreach(switch IN LISTS switches)
      string(REGEX REPLACE "^TC_" "TINY_CRYPTO_" option "${switch}")
      if(switch STREQUAL parent)
        list(APPEND case_options -D${option}=ON)
      elseif(parent_${switch} STREQUAL parent)
        list(APPEND case_options -D${option}=AUTO)
      else()
        list(APPEND case_options -D${option}=OFF)
      endif()
    endforeach()
    foreach(other IN LISTS value_features)
      string(JSON other_macro GET "${registry}" features ${other} macro)
      string(JSON other_default GET "${registry}" features ${other} default)
      string(REGEX REPLACE "^TC_" "TINY_CRYPTO_" option "${other_macro}")
      if(other_macro STREQUAL macro)
        list(APPEND case_options "-D${option}=${name}")
      else()
        list(APPEND case_options "-D${option}=${other_default}")
      endif()
    endforeach()
    set(label "${macro}=${name}")
    execute_process(COMMAND "${CMAKE_COMMAND}" -S "${SOURCE_DIR}" -B "${BINARY_DIR}-values"
      -DCMAKE_C_COMPILER=${C_COMPILER} -DCMAKE_BUILD_TYPE=Release
      -DTINY_CRYPTO_BUILD_TESTS=OFF -DTINY_CRYPTO_BUILD_BENCHMARKS=OFF ${case_options}
      RESULT_VARIABLE result OUTPUT_QUIET ERROR_VARIABLE errors)
    if(result)
      message(FATAL_ERROR "${label}: configure failed: ${errors}")
    endif()
    execute_process(COMMAND "${CMAKE_COMMAND}" --build "${BINARY_DIR}-values"
      --target tiny-crypto-c --parallel 4
      RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE errors)
    if(result)
      message(FATAL_ERROR "${label}: build failed: ${output}\n${errors}")
    endif()
    file(GLOB_RECURSE value_archive "${BINARY_DIR}-values/*tiny-crypto-c.a")
    list(FILTER value_archive EXCLUDE REGEX "/_deps/")
    check_heap_free("${value_archive}" "${label}")
    math(EXPR value_cases "${value_cases} + 1")
  endforeach()
endforeach()
if(value_cases LESS 1)
  message(FATAL_ERROR "Found no value option to check")
endif()
message(STATUS "Checked ${value_cases} value option cases")
