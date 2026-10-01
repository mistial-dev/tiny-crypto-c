# SPDX-License-Identifier: GPL-2.0-or-later
#
# Checks that the ESP-IDF port's platform features apply without a role
# target. The default profile omits SHA-384/512, RSA and EC, so the port
# sources compile only when the platform floor selects them.

if(NOT SOURCE_DIR OR NOT BINARY_DIR OR NOT C_COMPILER)
  message(FATAL_ERROR "SOURCE_DIR, BINARY_DIR and C_COMPILER are required")
endif()
file(REMOVE_RECURSE "${BINARY_DIR}")

function(tc_platform_configure result_var output_var)
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -S "${SOURCE_DIR}/tests/cmake/platform_consumer"
      -B "${BINARY_DIR}" "-DSOURCE_DIR=${SOURCE_DIR}" "-DCMAKE_C_COMPILER=${C_COMPILER}"
      -U "TINY_CRYPTO_*" -DTINY_CRYPTO_TARGET= -DCONFIG_SECURE_SIGNED_ON_UPDATE=1
      -DCONFIG_SECURE_SIGNED_APPS_RSA_SCHEME=1 -DCONFIG_SECURE_SIGNED_APPS_ECDSA_V2_SCHEME=1
      ${ARGN}
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error)
  set(${result_var} "${result}" PARENT_SCOPE)
  set(${output_var} "${output}${error}" PARENT_SCOPE)
endfunction()

tc_platform_configure(result output)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "Platform features without a target failed:\n${output}")
endif()
execute_process(COMMAND "${CMAKE_COMMAND}" --build "${BINARY_DIR}" --parallel 4
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "Port sources failed to build without a target:\n${output}${error}")
endif()

# An explicit OFF for a platform feature fails instead of dropping it.
foreach(option TINY_CRYPTO_ENABLE_SHA384 TINY_CRYPTO_ENABLE_RSA TINY_CRYPTO_EC_ENABLE_P192)
  tc_platform_configure(result output "-D${option}=OFF")
  if(result EQUAL 0)
    message(FATAL_ERROR "${option}=OFF was accepted with the platform floor")
  endif()
  if(NOT output MATCHES "${option} is required by the platform port")
    message(FATAL_ERROR "${option}=OFF failed for the wrong reason:\n${output}")
  endif()
endforeach()
