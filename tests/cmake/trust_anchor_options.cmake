# SPDX-FileCopyrightText: Mistial Dev
# SPDX-License-Identifier: GPL-2.0-or-later

if(NOT SOURCE_DIR OR NOT BINARY_DIR OR NOT C_COMPILER)
  message(FATAL_ERROR "SOURCE_DIR, BINARY_DIR and C_COMPILER are required")
endif()
# Start from fresh trees so cache entries from earlier runs cannot apply.
file(REMOVE_RECURSE "${BINARY_DIR}")
file(MAKE_DIRECTORY "${BINARY_DIR}")
file(WRITE "${BINARY_DIR}/probe.c" "#include <tiny_crypto/x509_trust_anchor.h>\nint main(void) { return 0; }\n")

function(configure_case label expected master cert tbs info path)
  execute_process(COMMAND "${CMAKE_COMMAND}" -S "${SOURCE_DIR}"
      -B "${BINARY_DIR}/${label}"
      -DTINY_CRYPTO_BUILD_TESTS=OFF -DCMAKE_COMPILE_WARNING_AS_ERROR=ON
      -DTINY_CRYPTO_RESOURCE_PROFILE=desktop
      -DTINY_CRYPTO_ENABLE_TRUST_ANCHOR_FORMAT=${master}
      -DTINY_CRYPTO_TAF_ENABLE_CERTIFICATE=${cert}
      -DTINY_CRYPTO_TAF_ENABLE_TBS_CERTIFICATE=${tbs}
      -DTINY_CRYPTO_TAF_ENABLE_TRUST_ANCHOR_INFO=${info}
      -DTINY_CRYPTO_ENABLE_X509_PATH=${path}
      OUTPUT_VARIABLE output ERROR_VARIABLE error RESULT_VARIABLE result)
  if(expected STREQUAL "pass" AND NOT result EQUAL 0)
    message(FATAL_ERROR "${label} should configure: ${output}\n${error}")
  endif()
  if(expected STREQUAL "fail" AND result EQUAL 0)
    message(FATAL_ERROR "${label} should fail configuration")
  endif()
endfunction()

foreach(mask RANGE 1 7)
  math(EXPR cert "${mask} & 1")
  math(EXPR tbs "(${mask} >> 1) & 1")
  math(EXPR info "(${mask} >> 2) & 1")
  configure_case("mask-${mask}" pass ON ${cert} ${tbs} ${info} ON)
  execute_process(COMMAND "${CMAKE_COMMAND}" --build "${BINARY_DIR}/mask-${mask}"
      --target tiny-crypto-c --parallel 4
      OUTPUT_VARIABLE output ERROR_VARIABLE error RESULT_VARIABLE result)
  if(NOT result EQUAL 0)
    message(FATAL_ERROR "mask ${mask} should build: ${output}\n${error}")
  endif()
endforeach()
configure_case(none fail ON OFF OFF OFF ON)
configure_case(orphan fail OFF ON OFF OFF ON)
configure_case(no-path fail ON ON OFF OFF OFF)
# AUTO follows the master switch, including when it is enabled on a profile
# whose ordinary defaults omit X.509.
execute_process(COMMAND "${CMAKE_COMMAND}" -S "${SOURCE_DIR}"
    -B "${BINARY_DIR}/auto"
    -DTINY_CRYPTO_BUILD_TESTS=OFF
    -DTINY_CRYPTO_ENABLE_TRUST_ANCHOR_FORMAT=ON
    -DTINY_CRYPTO_ENABLE_X509_PATH=ON
    -DTINY_CRYPTO_ENABLE_X509=ON
    -DTINY_CRYPTO_ENABLE_DER=ON
    -DTINY_CRYPTO_ENABLE_TLV=ON
    OUTPUT_VARIABLE output ERROR_VARIABLE error RESULT_VARIABLE result)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "AUTO choices should configure: ${output}\n${error}")
endif()

foreach(mask RANGE 1 7)
  math(EXPR cert "${mask} & 1")
  math(EXPR tbs "(${mask} >> 1) & 1")
  math(EXPR info "(${mask} >> 2) & 1")
  execute_process(COMMAND "${C_COMPILER}" -std=c99 -fsyntax-only
      -I "${SOURCE_DIR}/src" -DTC_RESOURCE_PROFILE=3
      -DTC_ENABLE_TRUST_ANCHOR_FORMAT=1
      -DTC_TAF_ENABLE_CERTIFICATE=${cert}
      -DTC_TAF_ENABLE_TBS_CERTIFICATE=${tbs}
      -DTC_TAF_ENABLE_TRUST_ANCHOR_INFO=${info}
      "${BINARY_DIR}/probe.c"
      OUTPUT_VARIABLE output ERROR_VARIABLE error RESULT_VARIABLE result)
  if(NOT result EQUAL 0)
    message(FATAL_ERROR "direct-source mask ${mask} should compile: ${output}\n${error}")
  endif()
endforeach()
foreach(definition IN ITEMS
    "TC_ENABLE_TRUST_ANCHOR_FORMAT=2"
    "TC_TAF_ENABLE_CERTIFICATE=2"
    "TC_TAF_ENABLE_TBS_CERTIFICATE=2"
    "TC_TAF_ENABLE_TRUST_ANCHOR_INFO=2")
  execute_process(COMMAND "${C_COMPILER}" -std=c99 -fsyntax-only
      -I "${SOURCE_DIR}/src" -DTC_RESOURCE_PROFILE=3 -D${definition}
      "${BINARY_DIR}/probe.c"
      OUTPUT_QUIET ERROR_QUIET RESULT_VARIABLE result)
  if(result EQUAL 0)
    message(FATAL_ERROR "direct-source invalid ${definition} should fail")
  endif()
endforeach()
foreach(arguments IN ITEMS
    "TC_ENABLE_TRUST_ANCHOR_FORMAT=1,TC_TAF_ENABLE_CERTIFICATE=0,TC_TAF_ENABLE_TBS_CERTIFICATE=0,TC_TAF_ENABLE_TRUST_ANCHOR_INFO=0"
    "TC_ENABLE_TRUST_ANCHOR_FORMAT=0,TC_TAF_ENABLE_CERTIFICATE=1"
    "TC_ENABLE_TRUST_ANCHOR_FORMAT=1,TC_ENABLE_X509_PATH=0")
  string(REPLACE "," ";" definitions "${arguments}")
  set(command "${C_COMPILER}" -std=c99 -fsyntax-only
      -I "${SOURCE_DIR}/src" -DTC_RESOURCE_PROFILE=3)
  foreach(definition IN LISTS definitions)
    list(APPEND command "-D${definition}")
  endforeach()
  list(APPEND command "${BINARY_DIR}/probe.c")
  execute_process(COMMAND ${command} OUTPUT_QUIET ERROR_QUIET RESULT_VARIABLE result)
  if(result EQUAL 0)
    message(FATAL_ERROR "direct-source invalid mask ${arguments} should fail")
  endif()
endforeach()
execute_process(COMMAND "${C_COMPILER}" -std=c99 -fsyntax-only
    -I "${SOURCE_DIR}/src" -DTC_RESOURCE_PROFILE=0
    -DTC_ENABLE_TRUST_ANCHOR_FORMAT=1 -DTC_ENABLE_X509_PATH=1
    -DTC_ENABLE_X509=1 -DTC_ENABLE_DER=1 -DTC_ENABLE_TLV=1
    "${BINARY_DIR}/probe.c"
    OUTPUT_VARIABLE output ERROR_VARIABLE error RESULT_VARIABLE result)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "direct-source AUTO choices should follow master: ${output}\n${error}")
endif()
