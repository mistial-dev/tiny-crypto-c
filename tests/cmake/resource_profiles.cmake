# SPDX-License-Identifier: GPL-2.0-or-later
foreach(settings "desktop;3;1;1;0;2" "micro;1;0;0;1;1" "mini;2;0;1;0;0" "desktop;3;1;1;0;2")
  list(GET settings 0 name)
  list(GET settings 1 profile)
  list(GET settings 2 capabilities)
  list(GET settings 3 wide)
  list(GET settings 4 tiny)
  list(GET settings 5 ghash)
  execute_process(COMMAND "${CMAKE_COMMAND}" -S "${SOURCE_DIR}/tests/cmake/profile_consumer"
    -B "${BINARY_DIR}" -DSOURCE_DIR=${SOURCE_DIR} -DCMAKE_C_COMPILER=${C_COMPILER}
    -DTINY_CRYPTO_RESOURCE_PROFILE=${name} -DEXPECT_PROFILE=${profile}
    -DTINY_CRYPTO_AES_WIDE_OPS=AUTO -DOVERRIDE_WIDE=OFF
    -DEXPECT_CAPABILITIES=${capabilities} -DEXPECT_WIDE=${wide}
    -DEXPECT_TINY=${tiny} -DEXPECT_GHASH=${ghash}
    RESULT_VARIABLE result OUTPUT_QUIET ERROR_VARIABLE errors)
  if(result)
    message(FATAL_ERROR "${name} configure failed: ${errors}")
  endif()
  execute_process(COMMAND "${CMAKE_COMMAND}" --build "${BINARY_DIR}" --target profile_configured profile_direct
    RESULT_VARIABLE result OUTPUT_QUIET ERROR_VARIABLE errors)
  if(result)
    message(FATAL_ERROR "${name} defaults failed: ${errors}")
  endif()
endforeach()
execute_process(COMMAND "${CMAKE_COMMAND}" -S "${SOURCE_DIR}/tests/cmake/profile_consumer"
  -B "${BINARY_DIR}" -DTINY_CRYPTO_AES_WIDE_OPS=OFF -DOVERRIDE_WIDE=ON
  RESULT_VARIABLE result OUTPUT_QUIET ERROR_VARIABLE errors)
if(result)
  message(FATAL_ERROR "Profile override configure failed: ${errors}")
endif()
execute_process(COMMAND "${CMAKE_COMMAND}" --build "${BINARY_DIR}" --target profile_configured profile_direct
  RESULT_VARIABLE result OUTPUT_QUIET ERROR_VARIABLE errors)
if(result)
  message(FATAL_ERROR "Profile override failed: ${errors}")
endif()
