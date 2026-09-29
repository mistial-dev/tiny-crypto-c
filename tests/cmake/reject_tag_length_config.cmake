# SPDX-License-Identifier: GPL-2.0-or-later
#
# Checks that config.h rejects minimum tag lengths outside 1..16. A zero
# minimum would let a zero-length tag authenticate any message.

file(MAKE_DIRECTORY "${BINARY_DIR}")
set(probe "${BINARY_DIR}/tag_length_probe.c")
file(WRITE "${probe}" "#include <tiny_crypto/config.h>\nint tc_tag_length_probe;\n")

function(tc_compile_probe definition result_var output_var)
  execute_process(
    COMMAND "${C_COMPILER}" -I "${SOURCE_DIR}/src" "-D${definition}" -c "${probe}"
      -o "${BINARY_DIR}/tag_length_probe.o"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error)
  set(${result_var} "${result}" PARENT_SCOPE)
  set(${output_var} "${output}${error}" PARENT_SCOPE)
endfunction()

foreach(macro TC_AES_EAX_MIN_TAG_LEN TC_AES_CMAC_MIN_TAG_LEN)
  foreach(value 0 17)
    tc_compile_probe("${macro}=${value}" result output)
    if(result EQUAL 0)
      message(FATAL_ERROR "${macro}=${value} was accepted")
    endif()
    if(NOT output MATCHES "${macro} must be in 1..16")
      message(FATAL_ERROR "${macro}=${value} failed for the wrong reason:\n${output}")
    endif()
  endforeach()
  foreach(value 1 16)
    tc_compile_probe("${macro}=${value}" result output)
    if(NOT result EQUAL 0)
      message(FATAL_ERROR "${macro}=${value} was rejected:\n${output}")
    endif()
  endforeach()
endforeach()
