# SPDX-License-Identifier: GPL-2.0-or-later
set(required_options TINY_CRYPTO_ENABLE_KMAC256 TINY_CRYPTO_ENABLE_GZIP
  TINY_CRYPTO_ENABLE_RSA TINY_CRYPTO_ENABLE_EC TINY_CRYPTO_ENABLE_SHA1 TINY_CRYPTO_TLV_BER)
set(auto_options)
foreach(required IN LISTS required_options)
  list(APPEND auto_options "-D${required}=AUTO")
endforeach()
foreach(profile micro mini desktop)
  foreach(role piv-acu piv-pd)
    execute_process(COMMAND "${CMAKE_COMMAND}" -S "${SOURCE_DIR}/tests/cmake/role_consumer"
      -B "${BINARY_DIR}" -DSOURCE_DIR=${SOURCE_DIR} -DCMAKE_C_COMPILER=${C_COMPILER}
      -DTINY_CRYPTO_TARGET=${role} -DTINY_CRYPTO_RESOURCE_PROFILE=${profile}
      ${auto_options}
      RESULT_VARIABLE result OUTPUT_QUIET ERROR_VARIABLE errors)
    if(result)
      message(FATAL_ERROR "${role}/${profile}: ${errors}")
    endif()
    execute_process(COMMAND "${CMAKE_COMMAND}" --build "${BINARY_DIR}" --config Release --parallel
      RESULT_VARIABLE result OUTPUT_QUIET ERROR_VARIABLE errors)
    if(result)
      message(FATAL_ERROR "${role}/${profile}: ${errors}")
    endif()
    execute_process(COMMAND "${CMAKE_CTEST_COMMAND}" --test-dir "${BINARY_DIR}"
      -C Release --output-on-failure
      RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE errors)
    if(result)
      message(FATAL_ERROR "${role}/${profile} runtime: ${output}\n${errors}")
    endif()
  endforeach()
endforeach()
foreach(required IN LISTS required_options)
  execute_process(COMMAND "${CMAKE_COMMAND}" -S "${SOURCE_DIR}/tests/cmake/role_consumer"
    -B "${BINARY_DIR}" ${auto_options} "-D${required}=OFF"
    RESULT_VARIABLE result OUTPUT_QUIET ERROR_VARIABLE errors)
  if(NOT result OR NOT errors MATCHES "conflicts with piv-pd")
    message(FATAL_ERROR "Role accepted missing ${required}: ${errors}")
  endif()
endforeach()
