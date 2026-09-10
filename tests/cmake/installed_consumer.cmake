# SPDX-License-Identifier: GPL-2.0-or-later
function(run)
  execute_process(COMMAND ${ARGV} RESULT_VARIABLE status
    OUTPUT_VARIABLE output ERROR_VARIABLE error)
  if(NOT status EQUAL 0)
    message(FATAL_ERROR "${ARGV}\n${output}\n${error}")
  endif()
endfunction()
run("${CMAKE_COMMAND}" -S "${SOURCE_DIR}" -B "${BINARY_DIR}/library"
  -DCMAKE_BUILD_TYPE=Release
  "-DCMAKE_C_COMPILER=${C_COMPILER}" -DTINY_CRYPTO_BUILD_TESTS=OFF
  -DTINY_CRYPTO_BUILD_BENCHMARKS=OFF
  -DTINY_CRYPTO_ENABLE_KMAC256=ON
  -DTINY_CRYPTO_ENABLE_RSA=ON
  -DTINY_CRYPTO_ENABLE_TLV=ON -DTINY_CRYPTO_ENABLE_DER=ON
  -DTINY_CRYPTO_TLV_BER=ON
  -DTINY_CRYPTO_ENABLE_X509=ON -DTINY_CRYPTO_ENABLE_PIV_CVC=ON
  -DTINY_CRYPTO_ENABLE_KEY_CHALLENGE=ON
  -DTINY_CRYPTO_ENABLE_X509_PATH=ON
  -DTINY_CRYPTO_ENABLE_X509_REVOCATION=ON
  -DTINY_CRYPTO_ENABLE_CMS=ON
  -DTINY_CRYPTO_ENABLE_PIV_OIDS=ON
  -DTINY_CRYPTO_ENABLE_CMS_VALIDATION=ON
  -DTINY_CRYPTO_ENABLE_FASCN=ON -DTINY_CRYPTO_ENABLE_TWIC_UUID=ON
  -DTINY_CRYPTO_ENABLE_PIV_OBJECTS=ON -DTINY_CRYPTO_ENABLE_CREDENTIAL=ON
  -DTINY_CRYPTO_ENABLE_AAMVA=ON -DTINY_CRYPTO_ENABLE_TWIC_TPK=ON
  -DTINY_CRYPTO_ENABLE_TWIC_OBJECT_CRYPTO=ON
  -DTINY_CRYPTO_ENABLE_PIV_CHUID=ON
  -DTINY_CRYPTO_ENABLE_TWIC_CCL=ON
  -DTINY_CRYPTO_ENABLE_MD5=ON
  -DTINY_CRYPTO_ENABLE_GZIP=ON
  -DTINY_CRYPTO_ENABLE_EAC_CVC=ON
  -DTINY_CRYPTO_ENABLE_PIV_SM=ON -DTINY_CRYPTO_ENABLE_EC=ON
  -DTINY_CRYPTO_ENABLE_SSKDF=ON -DTINY_CRYPTO_ENABLE_SHA384=ON
  -DTINY_CRYPTO_AES_DYNAMIC=ON -DTINY_CRYPTO_AES_ECB=ON
  "-DCMAKE_INSTALL_PREFIX=${BINARY_DIR}/prefix"
  -DCMAKE_INSTALL_INCLUDEDIR=custom-include)
run("${CMAKE_COMMAND}" --build "${BINARY_DIR}/library" --config Release)
run("${CMAKE_COMMAND}" --install "${BINARY_DIR}/library" --config Release)
file(STRINGS "${BINARY_DIR}/library/install_manifest.txt" installed)
foreach(path IN LISTS installed)
  if(path MATCHES "/share/licenses/tiny-crypto-c/(LICENSE|Unicode-3\\.0\\.txt)$")
    continue()
  endif()
  if(NOT path MATCHES "/(custom-include/tiny_crypto/[^/]+\\.(h|hpp)|lib[^/]*/(libtiny-crypto-c\\.a|tiny-crypto-c\\.lib|cmake/tiny-crypto-c/[^/]+\\.cmake))$")
    message(FATAL_ERROR "Unexpected product file: ${path}")
  endif()
endforeach()
foreach(license LICENSE LICENSES/Unicode-3.0.txt)
  get_filename_component(name "${license}" NAME)
  file(SHA256 "${SOURCE_DIR}/${license}" source_license)
  file(SHA256 "${BINARY_DIR}/prefix/share/licenses/tiny-crypto-c/${name}" installed_license)
  if(NOT source_license STREQUAL installed_license)
    message(FATAL_ERROR "Installed ${name} differs from the source notice")
  endif()
endforeach()
# Copy the consumer so relative includes cannot reach the source tree.
file(COPY "${SOURCE_DIR}/tests/cmake/consumer/" DESTINATION "${BINARY_DIR}/consumer-source")
file(COPY "${SOURCE_DIR}/examples/x509_client.c" "${SOURCE_DIR}/examples/x509_client.h"
  "${SOURCE_DIR}/examples/x509_workspace.h"
  "${SOURCE_DIR}/examples/cms_reader.c" "${SOURCE_DIR}/examples/cms_reader.h"
  "${SOURCE_DIR}/examples/cms_validate.c" "${SOURCE_DIR}/examples/cms_validate.h"
  "${SOURCE_DIR}/examples/credential_object.c" "${SOURCE_DIR}/examples/credential_object.h"
  "${SOURCE_DIR}/examples/cms_check.c"
  "${SOURCE_DIR}/examples/pki_input.c" "${SOURCE_DIR}/examples/pki_input.h"
  "${SOURCE_DIR}/examples/card_key_policy.c" "${SOURCE_DIR}/examples/card_key_policy.h"
  "${SOURCE_DIR}/examples/credential_auth.c" "${SOURCE_DIR}/examples/credential_auth.h"
  "${SOURCE_DIR}/examples/credential_validate.c" "${SOURCE_DIR}/examples/credential_validate.h"
  "${SOURCE_DIR}/examples/credential_io.c" "${SOURCE_DIR}/examples/credential_io.h"
  "${SOURCE_DIR}/examples/rsa_encrypt.c" "${SOURCE_DIR}/examples/rsa_encrypt.h"
  "${SOURCE_DIR}/examples/twic_ccl_storage.c" "${SOURCE_DIR}/examples/twic_ccl_storage.h"
  "${SOURCE_DIR}/examples/twic_ccl_import.c" "${SOURCE_DIR}/examples/twic_ccl_import.h"
  "${SOURCE_DIR}/examples/credential_workflow.c" "${SOURCE_DIR}/examples/credential_workflow.h"
  DESTINATION "${BINARY_DIR}/consumer-source/example")
set(consumer_compiler_options)
if(CXX_COMPILER)
  list(APPEND consumer_compiler_options "-DCMAKE_CXX_COMPILER=${CXX_COMPILER}")
endif()
run("${CMAKE_COMMAND}" -S "${BINARY_DIR}/consumer-source"
  -DCMAKE_BUILD_TYPE=Release
  -B "${BINARY_DIR}/consumer" "-DCMAKE_C_COMPILER=${C_COMPILER}"
  ${consumer_compiler_options}
  "-DCMAKE_PREFIX_PATH=${BINARY_DIR}/prefix")
run("${CMAKE_COMMAND}" --build "${BINARY_DIR}/consumer" --config Release)
run("${CMAKE_CTEST_COMMAND}" --test-dir "${BINARY_DIR}/consumer"
  -C Release --output-on-failure)

if(CMAKE_HOST_APPLE)
  file(COPY "${SOURCE_DIR}/examples/credential_check.c"
    "${SOURCE_DIR}/examples/twic_authenticate.c"
    "${SOURCE_DIR}/examples/credential_object.c" "${SOURCE_DIR}/examples/credential_object.h"
    "${SOURCE_DIR}/examples/cms_reader.c" "${SOURCE_DIR}/examples/cms_reader.h"
    "${SOURCE_DIR}/examples/cms_validate.c" "${SOURCE_DIR}/examples/cms_validate.h"
    "${SOURCE_DIR}/examples/credential_system.c" "${SOURCE_DIR}/examples/credential_system.h"
    "${SOURCE_DIR}/examples/card_key_policy.c" "${SOURCE_DIR}/examples/card_key_policy.h"
    "${SOURCE_DIR}/examples/credential_auth.c" "${SOURCE_DIR}/examples/credential_auth.h"
    "${SOURCE_DIR}/examples/credential_validate.c" "${SOURCE_DIR}/examples/credential_validate.h"
    "${SOURCE_DIR}/examples/x509_workspace.h"
    "${SOURCE_DIR}/examples/x509_revocation.c" "${SOURCE_DIR}/examples/x509_revocation.h"
    "${SOURCE_DIR}/examples/pki_input.c" "${SOURCE_DIR}/examples/pki_input.h"
    "${SOURCE_DIR}/examples/credential_io.c" "${SOURCE_DIR}/examples/credential_io.h"
    "${SOURCE_DIR}/examples/credential_pcsc.c" "${SOURCE_DIR}/examples/credential_pcsc.h"
    DESTINATION "${BINARY_DIR}/credential-source")
  file(COPY "${SOURCE_DIR}/examples/credential_check/"
    DESTINATION "${BINARY_DIR}/credential-source/credential_check")
  run("${CMAKE_COMMAND}" -S "${BINARY_DIR}/credential-source/credential_check"
    -B "${BINARY_DIR}/credential-consumer" -DCMAKE_BUILD_TYPE=Release
    "-DCMAKE_C_COMPILER=${C_COMPILER}" "-DCMAKE_PREFIX_PATH=${BINARY_DIR}/prefix")
  run("${CMAKE_COMMAND}" --build "${BINARY_DIR}/credential-consumer" --config Release)
  run("${CMAKE_CTEST_COMMAND}" --test-dir "${BINARY_DIR}/credential-consumer"
    -C Release --output-on-failure)
endif()
