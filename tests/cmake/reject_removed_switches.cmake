# SPDX-License-Identifier: GPL-2.0-or-later
#
# Checks that config.h rejects the removed TC_ZEROIZE and TC_STRICT switches.
# Wiping and public argument checks are unconditional, so a build that still
# sets either switch must fail instead of silently keeping the old intent.

file(MAKE_DIRECTORY "${BINARY_DIR}")
set(probe "${BINARY_DIR}/removed_switch_probe.c")
file(WRITE "${probe}" "#include <tiny_crypto/config.h>\nint tc_removed_switch_probe;\n")

foreach(definition TC_ZEROIZE=0 TC_ZEROIZE=1 TC_STRICT=0 TC_STRICT=1)
  execute_process(
    COMMAND "${C_COMPILER}" -I "${SOURCE_DIR}/src" "-D${definition}" -c "${probe}"
      -o "${BINARY_DIR}/removed_switch_probe.o"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error)
  if(result EQUAL 0)
    message(FATAL_ERROR "${definition} was accepted")
  endif()
  if(NOT "${output}${error}" MATCHES "TC_ZEROIZE and TC_STRICT are removed")
    message(FATAL_ERROR "${definition} failed for the wrong reason:\n${output}${error}")
  endif()
endforeach()
