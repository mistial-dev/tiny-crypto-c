# SPDX-License-Identifier: GPL-2.0-or-later
# Checks that RSA, EC and key-challenge work stays 32 bits wide.
#
# 1. Every declaration in the scanned headers with a parameter named work, or
#    a TC_work_budget* parameter of any name, must have a TC_EXPECT_FUNCTION
#    check in tests/work_budget/types.c. The scan must also find one known
#    budget function from each header group, so a broken pattern cannot pass
#    by matching nothing.
# 2. tests/work_budget/types.c must compile with -Werror. Its checks pin the
#    budget type, the execution descriptors, the cost functions and every
#    function with a budget parameter to their exact types.
# 3. Each negative fixture in tests/work_budget/fixtures must compile with
#    TC_FIXTURE_CORRECT and fail without it, so every guard is shown to fire.
#
# C_COMPILER is the compiler and FLAGS its extra flags, for example -mmcu.
# NARROWING=ON states that FLAGS enable the 16-bit narrowing diagnostics that
# the AVR compile checks use, which adds the size_t_alias fixture.
set(guard_dir "${SOURCE_DIR}/tests/work_budget")
set(scanned_headers
  src/tiny_crypto/ec.h src/tiny_crypto/key_challenge.h src/tiny_crypto/rsa.h
  src/rsa_internal.h src/rsa_padding_internal.h src/rsa_prime_internal.h
  src/rsa_private_internal.h)
set(definitions -DTC_ENABLE_RSA=1 -DTC_ENABLE_EC=1 -DTC_ENABLE_KEY_CHALLENGE=1
  -DTC_ENABLE_X509=1 -DTC_ENABLE_TLV=1 -DTC_ENABLE_DER=1)

# A parameter list holds no parentheses, braces or semicolons, so this
# matches each declaration or call and its complete parameter list.
file(READ "${guard_dir}/types.c" guard_source)
set(unchecked "")
set(found "")
foreach(header IN LISTS scanned_headers)
  file(READ "${SOURCE_DIR}/${header}" header_source)
  string(REGEX MATCHALL "[A-Za-z_][A-Za-z0-9_]*\\([^;{}()]*\\)" calls "${header_source}")
  foreach(call IN LISTS calls)
    if(NOT call MATCHES "[^A-Za-z0-9_]work[ \t\r\n]*\\)$" AND
       NOT call MATCHES "[^A-Za-z0-9_]work[ \t\r\n]*," AND
       NOT call MATCHES "[^A-Za-z0-9_]TC_work_budget[ \t\r\n]*\\*")
      continue()
    endif()
    string(REGEX REPLACE "\\(.*" "" name "${call}")
    list(APPEND found "${name}")
    if(NOT guard_source MATCHES "TC_EXPECT_FUNCTION\\([ \t\r\n]*${name},")
      list(APPEND unchecked "${header}: ${name}")
    endif()
  endforeach()
endforeach()
foreach(known TC_ECDH TC_key_challenge_verify TC_RSA_verify_pss_digest tc_rsa_mgf1_xor
    tc_rsa_sample_blinding tc_rsa_probable_prime_magnitude)
  list(FIND found "${known}" known_index)
  if(known_index EQUAL -1)
    message(FATAL_ERROR "The header scan did not find ${known}. Fix the scan pattern.")
  endif()
endforeach()
if(unchecked)
  list(REMOVE_DUPLICATES unchecked)
  list(JOIN unchecked "\n  " unchecked_text)
  message(FATAL_ERROR "tests/work_budget/types.c lacks TC_EXPECT_FUNCTION checks for:\n  ${unchecked_text}")
endif()

file(MAKE_DIRECTORY "${BINARY_DIR}")
set(compile "${C_COMPILER}" -std=c99 -Wall -Wextra -Werror -fno-diagnostics-color ${FLAGS}
  ${definitions} -I "${SOURCE_DIR}/src" -I "${guard_dir}")

execute_process(COMMAND ${compile} -c "${guard_dir}/types.c" -o "${BINARY_DIR}/types.o"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE errors)
if(result)
  message(FATAL_ERROR "tests/work_budget/types.c must compile:\n${output}${errors}")
endif()

set(fixtures cast_helper size_t_helper wide_units)
if(NARROWING)
  list(APPEND fixtures size_t_alias)
endif()
foreach(fixture IN LISTS fixtures)
  set(source "${guard_dir}/fixtures/${fixture}.c")
  execute_process(COMMAND ${compile} -DTC_FIXTURE_CORRECT -c "${source}"
      -o "${BINARY_DIR}/${fixture}_correct.o"
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE errors)
  if(result)
    message(FATAL_ERROR "The correct form of ${fixture}.c must compile:\n${output}${errors}")
  endif()
  execute_process(COMMAND ${compile} -c "${source}" -o "${BINARY_DIR}/${fixture}_wrong.o"
    RESULT_VARIABLE result OUTPUT_QUIET ERROR_QUIET)
  if(NOT result)
    message(FATAL_ERROR "The guard missed the size_t budget in ${fixture}.c")
  endif()
endforeach()
