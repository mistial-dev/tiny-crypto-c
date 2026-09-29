# SPDX-License-Identifier: GPL-2.0-or-later
#
# Checks that config.h keeps TC_MIN_TAG_LEN in 8..16 and rejects the removed
# per-mode minimum tag length macros.

file(MAKE_DIRECTORY "${BINARY_DIR}")
set(probe "${BINARY_DIR}/tag_length_probe.c")
file(WRITE "${probe}" "#include <tiny_crypto/config.h>\nint tc_tag_length_probe;\n")

# Compile the probe with each extra argument as a -D definition.
function(tc_compile_probe result_var output_var)
  set(definitions)
  foreach(definition IN LISTS ARGN)
    list(APPEND definitions "-D${definition}")
  endforeach()
  execute_process(
    COMMAND "${C_COMPILER}" -I "${SOURCE_DIR}/src" ${definitions} -c "${probe}"
      -o "${BINARY_DIR}/tag_length_probe.o"
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error)
  set(${result_var} "${result}" PARENT_SCOPE)
  set(${output_var} "${output}${error}" PARENT_SCOPE)
endfunction()

foreach(value 0 7 17)
  tc_compile_probe(result output "TC_MIN_TAG_LEN=${value}" TC_ENABLE_DES=0)
  if(result EQUAL 0)
    message(FATAL_ERROR "TC_MIN_TAG_LEN=${value} was accepted")
  endif()
  if(NOT output MATCHES "TC_MIN_TAG_LEN must be in 8..16")
    message(FATAL_ERROR "TC_MIN_TAG_LEN=${value} failed for the wrong reason:\n${output}")
  endif()
endforeach()

foreach(value 8 16)
  tc_compile_probe(result output "TC_MIN_TAG_LEN=${value}" TC_ENABLE_DES=0)
  if(NOT result EQUAL 0)
    message(FATAL_ERROR "TC_MIN_TAG_LEN=${value} was rejected:\n${output}")
  endif()
endforeach()

# A minimum above the 8-byte DES block leaves DES-CMAC without a default tag.
tc_compile_probe(result output TC_MIN_TAG_LEN=9 TC_ENABLE_DES=1 TC_DES_ENABLE_CMAC=1)
if(result EQUAL 0 OR NOT output MATCHES "TC_MIN_TAG_LEN above 8 requires TC_DES_ENABLE_CMAC=0")
  message(FATAL_ERROR "TC_MIN_TAG_LEN=9 with DES-CMAC was not rejected:\n${output}")
endif()

# Defining a per-mode minimum stops the build.
foreach(macro TC_AES_EAX_MIN_TAG_LEN TC_AES_CMAC_MIN_TAG_LEN TC_DES_CMAC_MIN_TAG_LEN)
  tc_compile_probe(result output "${macro}=8")
  if(result EQUAL 0 OR NOT output MATCHES "Per-mode minimum tag lengths are removed")
    message(FATAL_ERROR "${macro} was not rejected:\n${output}")
  endif()
endforeach()
