# SPDX-License-Identifier: GPL-2.0-or-later
# Checks that every public C++ header stops a C build with its #error guard.
# Each src/tiny_crypto/*.hpp compiled as C must fail with
# "Do not include <name>.hpp in a C project".
file(GLOB headers "${SOURCE_DIR}/src/tiny_crypto/*.hpp")
list(LENGTH headers header_count)
if(header_count EQUAL 0)
  message(FATAL_ERROR "No C++ headers found in ${SOURCE_DIR}/src/tiny_crypto")
endif()
foreach(header IN LISTS headers)
  get_filename_component(name "${header}" NAME)
  execute_process(
    COMMAND "${C_COMPILER}" -x c -fsyntax-only -fno-diagnostics-color -I "${SOURCE_DIR}/src"
      "${header}"
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE errors)
  if(NOT result)
    message(FATAL_ERROR "${name} compiled as C without an error")
  endif()
  if(NOT errors MATCHES "error: [^\n]*Do not include ${name} in a C project")
    message(FATAL_ERROR "${name} lacks the C project guard:\n${output}${errors}")
  endif()
endforeach()
