# SPDX-License-Identifier: GPL-2.0-or-later
#
# Checks that CMake enforces the dependency rules in config.h. Each invalid
# option set must fail configuration with the config.h #error text. Each edge
# profile that config.h accepts must configure and build.
#
# One build directory is reused. Every case clears the TINY_CRYPTO_* cache
# entries first, so options from one case never reach the next.

if(NOT SOURCE_DIR OR NOT BINARY_DIR OR NOT C_COMPILER)
  message(FATAL_ERROR "SOURCE_DIR, BINARY_DIR and C_COMPILER are required")
endif()
file(REMOVE_RECURSE "${BINARY_DIR}")

function(tc_configure_case options result_var output_var)
  set(arguments)
  foreach(option IN LISTS options)
    list(APPEND arguments "-D${option}")
  endforeach()
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -S "${SOURCE_DIR}" -B "${BINARY_DIR}"
      "-DCMAKE_C_COMPILER=${C_COMPILER}" -U "TINY_CRYPTO_*"
      -DTINY_CRYPTO_BUILD_TESTS=OFF -DTINY_CRYPTO_BUILD_BENCHMARKS=OFF ${arguments}
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error)
  set(${result_var} "${result}" PARENT_SCOPE)
  set(${output_var} "${output}${error}" PARENT_SCOPE)
endfunction()

# Expect configuration to fail with a message that contains expected.
function(tc_reject name options expected)
  tc_configure_case("${options}" result output)
  if(result EQUAL 0)
    message(FATAL_ERROR "${name}: ${options} was accepted")
  endif()
  string(FIND "${output}" "${expected}" position)
  if(position EQUAL -1)
    message(FATAL_ERROR "${name}: expected \"${expected}\":\n${output}")
  endif()
endfunction()

# Expect the options to configure and the library to build.
function(tc_accept name options)
  tc_configure_case("${options}" result output)
  if(NOT result EQUAL 0)
    message(FATAL_ERROR "${name}: ${options} was rejected:\n${output}")
  endif()
  execute_process(
    COMMAND "${CMAKE_COMMAND}" --build "${BINARY_DIR}" --target tiny-crypto-c --parallel 4
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error)
  if(NOT result EQUAL 0)
    message(FATAL_ERROR "${name}: build failed:\n${output}${error}")
  endif()
endfunction()

set(tlv TINY_CRYPTO_ENABLE_TLV=ON)
set(der ${tlv} TINY_CRYPTO_ENABLE_DER=ON)
set(x509 ${der} TINY_CRYPTO_ENABLE_X509=ON)
set(path ${x509} TINY_CRYPTO_ENABLE_X509_PATH=ON)
set(revocation ${path} TINY_CRYPTO_ENABLE_X509_REVOCATION=ON)
set(cms ${x509} TINY_CRYPTO_TLV_BER=ON TINY_CRYPTO_ENABLE_PIV_OIDS=ON TINY_CRYPTO_ENABLE_CMS=ON)
set(cms_validation ${cms} ${revocation} TINY_CRYPTO_ENABLE_CMS_VALIDATION=ON)
set(piv_objects ${cms} TINY_CRYPTO_ENABLE_FASCN=ON TINY_CRYPTO_ENABLE_TWIC_UUID=ON
  TINY_CRYPTO_ENABLE_PIV_OBJECTS=ON)
set(no_sha TINY_CRYPTO_ENABLE_SHA1=OFF TINY_CRYPTO_ENABLE_SHA224=OFF
  TINY_CRYPTO_ENABLE_SHA256=OFF TINY_CRYPTO_ENABLE_SHA384=OFF TINY_CRYPTO_ENABLE_SHA512=OFF)
set(no_des_modes TINY_CRYPTO_DES_ECB=OFF TINY_CRYPTO_DES_CBC=OFF TINY_CRYPTO_DES_CTR=OFF
  TINY_CRYPTO_DES_OFB=OFF TINY_CRYPTO_DES_CFB1=OFF TINY_CRYPTO_DES_CFB8=OFF
  TINY_CRYPTO_DES_CFB64=OFF TINY_CRYPTO_DES_CMAC=OFF TINY_CRYPTO_DES_ISO9797=OFF)
set(piv_sm TINY_CRYPTO_ENABLE_PIV_SM=ON TINY_CRYPTO_AES_DYNAMIC=ON TINY_CRYPTO_ENABLE_SSKDF=ON
  TINY_CRYPTO_ENABLE_EC=ON TINY_CRYPTO_ENABLE_SHA384=ON)

# Rules owned by CMake itself.
tc_reject(nothing_enabled
  "TINY_CRYPTO_ENABLE_AES=OFF;${no_sha}" "Enable at least one algorithm or parser")
tc_reject(bad_choice "TINY_CRYPTO_ENABLE_MD5=maybe" "TINY_CRYPTO_ENABLE_MD5 must be AUTO, ON, or OFF")
tc_reject(bad_sbox "TINY_CRYPTO_AES_SBOX=table" "Unknown TINY_CRYPTO_AES_SBOX value")
tc_reject(bad_ghash "TINY_CRYPTO_AES_GHASH=table" "Unknown TINY_CRYPTO_AES_GHASH value")

# Rules owned by config.h, in header order.
tc_reject(hmac_without_sha "TINY_CRYPTO_ENABLE_HMAC=ON;${no_sha}"
  "HMAC requires an enabled SHA algorithm")
tc_reject(eac_without_der "${tlv};TINY_CRYPTO_ENABLE_EAC_CVC=ON"
  "EAC CVC parsing requires TC_ENABLE_DER")
tc_reject(piv_cvc_without_der "${tlv};TINY_CRYPTO_ENABLE_PIV_CVC=ON"
  "PIV CVC parsing requires DER")
tc_reject(x509_without_der "${tlv};TINY_CRYPTO_ENABLE_X509=ON" "X.509 parsing requires DER")
tc_reject(key_challenge_without_x509 "${der};TINY_CRYPTO_ENABLE_KEY_CHALLENGE=ON"
  "Key challenges require X.509 public-key metadata")
tc_reject(twic_uuid_without_fascn "TINY_CRYPTO_ENABLE_TWIC_UUID=ON"
  "TWIC UUID matching requires FASC-N support")
tc_reject(twic_tpk_without_tlv "TINY_CRYPTO_ENABLE_TWIC_TPK=ON"
  "TWIC TPK parsing requires TLV support")
tc_reject(chuid_without_tlv "TINY_CRYPTO_ENABLE_PIV_CHUID=ON" "CHUID parsing requires TLV")
tc_reject(der_without_tlv "TINY_CRYPTO_ENABLE_DER=ON"
  "DER, BER, and incremental parsing require TC_ENABLE_TLV")
tc_reject(taf_without_path "${x509};TINY_CRYPTO_ENABLE_TRUST_ANCHOR_FORMAT=ON"
  "Trust-anchor format requires X.509 path support")
tc_reject(taf_without_choice "${path};TINY_CRYPTO_ENABLE_TRUST_ANCHOR_FORMAT=ON;TINY_CRYPTO_TAF_CERTIFICATE=OFF;TINY_CRYPTO_TAF_TBS_CERTIFICATE=OFF;TINY_CRYPTO_TAF_TRUST_ANCHOR_INFO=OFF"
  "Trust-anchor format requires at least one choice")
tc_reject(taf_choice_without_format "${path};TINY_CRYPTO_TAF_CERTIFICATE=ON"
  "Trust-anchor choices require trust-anchor format")
tc_reject(path_without_x509 "${der};TINY_CRYPTO_ENABLE_X509_PATH=ON"
  "X.509 path validation requires the X.509 reader")
tc_reject(revocation_without_path "${x509};TINY_CRYPTO_ENABLE_X509_REVOCATION=ON"
  "X.509 revocation requires path validation")
tc_reject(ocsp_without_path "${x509};TINY_CRYPTO_ENABLE_SHA1=ON;TINY_CRYPTO_ENABLE_X509_OCSP=ON"
  "X.509 OCSP requires path validation")
tc_reject(ocsp_without_sha1 "${path};TINY_CRYPTO_ENABLE_X509_OCSP=ON" "X.509 OCSP requires SHA-1")
tc_reject(cms_without_ber "${cms};TINY_CRYPTO_TLV_BER=OFF"
  "CMS requires X.509, BER parsing, and PIV/TWIC identifier classification")
tc_reject(cms_validation_without_revocation "${cms};TINY_CRYPTO_ENABLE_CMS_VALIDATION=ON"
  "CMS validation requires CMS and X.509 revocation support")
tc_reject(piv_objects_without_uuid "${piv_objects};TINY_CRYPTO_ENABLE_TWIC_UUID=OFF"
  "PIV object readers require CMS, TWIC UUID, and PIV/TWIC identifiers")
tc_reject(credential_without_chuid "${piv_objects};${cms_validation};TINY_CRYPTO_ENABLE_CREDENTIAL=ON"
  "Credential composition requires PIV objects, CHUID, and CMS validation")
tc_reject(hkdf_without_hmac "TINY_CRYPTO_ENABLE_HKDF=ON"
  "HKDF requires HMAC and an enabled SHA algorithm")
tc_reject(ec_without_curve "TINY_CRYPTO_ENABLE_EC=ON;TINY_CRYPTO_EC_P256=OFF;TINY_CRYPTO_EC_P384=OFF"
  "EC requires at least one curve")
tc_reject(sskdf_without_sha "TINY_CRYPTO_ENABLE_SSKDF=ON;${no_sha}"
  "Single-step KDF requires an enabled SHA algorithm")
tc_reject(dynamic_without_aes "TINY_CRYPTO_ENABLE_AES=OFF;TINY_CRYPTO_AES_DYNAMIC=ON"
  "Dynamic AES requires TC_ENABLE_AES")
tc_reject(aes_key_bits "TINY_CRYPTO_AES_KEY_BITS=100" "TC_AES_KEY_BITS must be 128, 192, or 256")
tc_reject(tiny_fast_table "TINY_CRYPTO_AES_TINY=ON;TINY_CRYPTO_AES_GHASH=fast-table"
  "TC_AES_TINY forbids the 256-byte fast GHASH table")
tc_reject(twic_object_aes256
  "TINY_CRYPTO_ENABLE_TWIC_OBJECT_CRYPTO=ON;TINY_CRYPTO_AES_ECB=ON;TINY_CRYPTO_AES_KEY_BITS=256"
  "TWIC object encryption requires AES-128 ECB")
tc_reject(des_without_mode "TINY_CRYPTO_ENABLE_DES=ON;${no_des_modes}"
  "DES requires at least one enabled mode or MAC")
tc_reject(kdf_without_prf "TINY_CRYPTO_ENABLE_KDF=ON"
  "TC_ENABLE_KDF needs a PRF: HMAC with an enabled SHA, TC_AES_ENABLE_CMAC or TC_DES_ENABLE_CMAC")
tc_reject(piv_sm_without_sskdf "${piv_sm};TINY_CRYPTO_ENABLE_SSKDF=OFF"
  "PIV SM requires dynamic AES, SHA-256, single-step KDF, and EC")
tc_reject(piv_sm_without_suite "${piv_sm};TINY_CRYPTO_PIV_SM_CS2=OFF;TINY_CRYPTO_PIV_SM_CS7=OFF"
  "PIV SM requires at least one cipher suite")
tc_reject(cs2_without_p256 "${piv_sm};TINY_CRYPTO_EC_P256=OFF" "CS2 requires P-256")
tc_reject(cs7_without_sha384 "${piv_sm};TINY_CRYPTO_ENABLE_SHA384=OFF"
  "CS7 requires P-384 and SHA-384")
tc_reject(drbg_without_mechanism "TINY_CRYPTO_ENABLE_DRBG=ON"
  "DRBG requires at least one mechanism")
tc_reject(hash_drbg_without_sha
  "TINY_CRYPTO_ENABLE_DRBG=ON;TINY_CRYPTO_DRBG_HASH=ON;${no_sha}"
  "Hash_DRBG requires a SHA algorithm")
tc_reject(hmac_drbg_without_hmac "TINY_CRYPTO_ENABLE_DRBG=ON;TINY_CRYPTO_DRBG_HMAC=ON"
  "HMAC_DRBG requires TC_ENABLE_HMAC")
tc_reject(ctr_drbg_without_dynamic "TINY_CRYPTO_ENABLE_DRBG=ON;TINY_CRYPTO_DRBG_CTR=ON"
  "CTR_DRBG requires TC_ENABLE_AES and TC_AES_ENABLE_DYNAMIC")

# Edge profiles that config.h accepts.
tc_accept(ec_p192_only
  "TINY_CRYPTO_ENABLE_EC=ON;TINY_CRYPTO_EC_P192=ON;TINY_CRYPTO_EC_P256=OFF;TINY_CRYPTO_EC_P384=OFF")
tc_accept(sha384_only
  "TINY_CRYPTO_ENABLE_AES=OFF;${no_sha};TINY_CRYPTO_ENABLE_SHA384=ON")
tc_accept(des_iso9797_only
  "TINY_CRYPTO_ENABLE_AES=OFF;${no_sha};TINY_CRYPTO_ENABLE_DES=ON;${no_des_modes};TINY_CRYPTO_DES_ISO9797=ON")
tc_accept(sskdf_sha1_only
  "TINY_CRYPTO_ENABLE_SSKDF=ON;${no_sha};TINY_CRYPTO_ENABLE_SHA1=ON")
