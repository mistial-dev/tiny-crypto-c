# SPDX-License-Identifier: GPL-2.0-or-later
# Checks that discarding a C++ wrapper status is diagnosed. Each line of
# tests/cpp/nodiscard_compile.cpp marked DISCARDED must draw an unused-result
# warning, and no other line may. C++11 uses warn_unused_result and C++17 uses
# [[nodiscard]], so both standards are checked. GCC reports unused results
# during code generation, so the check compiles an object in place of
# -fsyntax-only. EXTRA_FLAGS adds target flags, for example for avr-g++.
set(source "${SOURCE_DIR}/tests/cpp/nodiscard_compile.cpp")
file(STRINGS "${source}" source_lines)
set(expected "")
set(line_number 0)
foreach(line IN LISTS source_lines)
  math(EXPR line_number "${line_number} + 1")
  if(line MATCHES "/\\* DISCARDED \\*/")
    list(APPEND expected ${line_number})
  endif()
endforeach()
list(LENGTH expected expected_count)
if(expected_count EQUAL 0)
  message(FATAL_ERROR "No DISCARDED lines found in ${source}")
endif()

file(MAKE_DIRECTORY "${BINARY_DIR}")
foreach(standard 11 17)
  execute_process(
    COMMAND "${CXX_COMPILER}" ${EXTRA_FLAGS} -std=c++${standard} -c -o "${BINARY_DIR}/nodiscard_compile_${standard}.o"
      -Wunused-result -fno-diagnostics-color -I "${SOURCE_DIR}/src" "${source}"
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE errors)
  if(result)
    message(FATAL_ERROR "C++${standard} compile failed:\n${output}${errors}")
  endif()
  string(REGEX MATCHALL "nodiscard_compile\\.cpp:[0-9]+:[0-9]+: warning: [^\n]*\\[-Wunused-result\\]"
    diagnostics "${errors}")
  set(warned "")
  foreach(diagnostic IN LISTS diagnostics)
    string(REGEX REPLACE "^nodiscard_compile\\.cpp:([0-9]+):.*" "\\1" warned_line "${diagnostic}")
    list(APPEND warned ${warned_line})
  endforeach()
  list(REMOVE_DUPLICATES warned)
  list(SORT warned COMPARE NATURAL)
  if(NOT warned STREQUAL expected)
    set(missing ${expected})
    if(warned)
      list(REMOVE_ITEM missing ${warned})
    endif()
    set(extra ${warned})
    list(REMOVE_ITEM extra ${expected})
    message(FATAL_ERROR "C++${standard} unused-result diagnostics differ.\n"
      "Lines without a warning: ${missing}\nUnexpected warning lines: ${extra}\n${errors}")
  endif()
endforeach()
