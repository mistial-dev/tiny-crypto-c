# SPDX-License-Identifier: GPL-2.0-or-later
# Configure, build and run tests/cmake/target_consumer for every application
# target under every resource profile, then check that an explicit switch
# outside a target's set fails configuration.
if(NOT SOURCE_DIR OR NOT BINARY_DIR OR NOT C_COMPILER)
  message(FATAL_ERROR "SOURCE_DIR, BINARY_DIR and C_COMPILER are required")
endif()

function(configure_consumer label)
  # Start from a fresh tree so cache entries from earlier runs cannot apply.
  file(REMOVE_RECURSE "${BINARY_DIR}")
  execute_process(COMMAND "${CMAKE_COMMAND}" -S "${SOURCE_DIR}/tests/cmake/target_consumer"
    -B "${BINARY_DIR}" -DSOURCE_DIR=${SOURCE_DIR} -DCMAKE_C_COMPILER=${C_COMPILER} ${ARGN}
    RESULT_VARIABLE result OUTPUT_QUIET ERROR_VARIABLE errors)
  set(configure_result ${result} PARENT_SCOPE)
  set(configure_errors "${errors}" PARENT_SCOPE)
endfunction()

foreach(profile micro mini desktop)
  foreach(target full piv twic desfire)
    configure_consumer(${target}/${profile} -DTINY_CRYPTO_TARGET=${target}
      -DTINY_CRYPTO_RESOURCE_PROFILE=${profile})
    if(configure_result)
      message(FATAL_ERROR "${target}/${profile}: ${configure_errors}")
    endif()
    execute_process(COMMAND "${CMAKE_COMMAND}" --build "${BINARY_DIR}" --config Release --parallel
      RESULT_VARIABLE result OUTPUT_QUIET ERROR_VARIABLE errors)
    if(result)
      message(FATAL_ERROR "${target}/${profile}: ${errors}")
    endif()
    execute_process(COMMAND "${CMAKE_CTEST_COMMAND}" --test-dir "${BINARY_DIR}"
      -C Release --output-on-failure
      RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE errors)
    if(result)
      message(FATAL_ERROR "${target}/${profile} runtime: ${output}\n${errors}")
    endif()
  endforeach()
endforeach()

# A switch the target leaves out cannot be forced on, and one it selects
# cannot be forced off.
foreach(case "piv;TINY_CRYPTO_ENABLE_SHA1=ON" "piv;TINY_CRYPTO_RSA_ENABLE_1024=ON"
             "desfire;TINY_CRYPTO_ENABLE_SHA256=ON" "twic;TINY_CRYPTO_ENABLE_SHA1=OFF"
             "full;TINY_CRYPTO_EC_ENABLE_P192=OFF")
  list(GET case 0 target)
  list(GET case 1 option)
  configure_consumer(${target} -DTINY_CRYPTO_TARGET=${target} -D${option})
  if(NOT configure_result OR NOT configure_errors MATCHES "conflicts with ${target}")
    message(FATAL_ERROR "${target} accepted ${option}: ${configure_errors}")
  endif()
endforeach()
