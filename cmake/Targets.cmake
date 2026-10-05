# SPDX-License-Identifier: GPL-2.0-or-later

# An application target fixes the algorithm and format switches to one
# predefined set. Every switch the set omits resolves to OFF, and an explicit
# value that disagrees with the set fails configuration. Resource tuning stays
# with TINY_CRYPTO_RESOURCE_PROFILE.
#
#   full     every algorithm and format.
#   piv      SP 800-73-5 with the SP 800-78-5 algorithms.
#   twic     piv plus the TWIC Legacy and NEXGEN additions (TWIC Part 2 v5).
#   desfire  the MIFARE DESFire primitives that dfc-core uses.
set(TINY_CRYPTO_TARGET "" CACHE STRING "Application target: full, piv, twic, desfire, or empty")
set(tc_targets full piv twic desfire)
set_property(CACHE TINY_CRYPTO_TARGET PROPERTY STRINGS "" ${tc_targets})
if(NOT TINY_CRYPTO_TARGET STREQUAL "" AND NOT TINY_CRYPTO_TARGET IN_LIST tc_targets)
  message(FATAL_ERROR "Unknown TINY_CRYPTO_TARGET: ${TINY_CRYPTO_TARGET}")
endif()

# SP 800-78-5 algorithms for SP 800-73-5:
#   Table 1 and 2: RSA 2048 and 3072 card keys, RSA 4096 for object
#     signatures, ECDSA and ECDH on P-256 and P-384, SHA-256 and SHA-384.
#   Table 7 and 9: AES-128, AES-192 and AES-256 for the administration key.
#   SP 800-73-5 Part 2 section 4: CS2 and CS7 secure messaging with the
#     one-step KDF, AES-CBC and AES-CMAC.
#   SP 800-73-5 Part 1 appendix A: GZIP-compressed certificates.
# The object, path, revocation and CMS layers are what the PIV object
# readers, credential validation and the card check build on.
set(tc_target_piv
  TC_ENABLE_SHA256 TC_ENABLE_SHA384
  TC_ENABLE_AES TC_AES_ENABLE_DYNAMIC TC_AES_ENABLE_ECB TC_AES_ENABLE_CBC TC_AES_ENABLE_CMAC
  TC_ENABLE_SSKDF
  TC_ENABLE_EC TC_EC_ENABLE_P256 TC_EC_ENABLE_P384
  TC_ENABLE_RSA TC_RSA_ENABLE_2048 TC_RSA_ENABLE_3072 TC_RSA_ENABLE_4096
  TC_ENABLE_GZIP
  TC_ENABLE_TLV TC_TLV_ENABLE_BER TC_ENABLE_DER TC_ENABLE_APDU
  TC_ENABLE_FASCN TC_ENABLE_TWIC_UUID TC_ENABLE_PIV_OIDS TC_ENABLE_PIV_CHUID
  TC_ENABLE_X509 TC_ENABLE_X509_PATH TC_ENABLE_X509_REVOCATION
  TC_ENABLE_CMS TC_ENABLE_CMS_VALIDATION TC_ENABLE_KEY_CHALLENGE
  TC_ENABLE_PIV_COMMAND TC_ENABLE_PIV_OBJECTS TC_ENABLE_PIV_CVC TC_ENABLE_CREDENTIAL
  TC_ENABLE_PIV_SM TC_PIV_SM_ENABLE_CS2 TC_PIV_SM_ENABLE_CS7 TC_ENABLE_PIV_SM_APDU
  TC_ENABLE_PIV_VCI TC_ENABLE_PIV_CATALOG TC_ENABLE_PIV_KEY_PROOF TC_ENABLE_PIV_CARD_CHECK)

# TWIC Part 2 v5: SHA-1 and RSA-1024 for Legacy TWIC signatures and key
# proofs (section 3.3.4), the TWIC Privacy Key and its barcode (section 4.9,
# AAMVA DL/ID Annex D), private-object encryption with AES-128 ECB, and the
# canceled card list (Part 4).
set(tc_target_twic ${tc_target_piv}
  TC_ENABLE_SHA1 TC_RSA_ENABLE_1024
  TC_ENABLE_AAMVA TC_ENABLE_TWIC_TPK TC_ENABLE_TWIC_CCL TC_ENABLE_TWIC_OBJECT_CRYPTO)

# dfc-core uses AES-128 CBC and DES ECB and CBC with single DES, two-key
# and three-key TDEA keys. It computes its own CMAC and CRC.
set(tc_target_desfire
  TC_ENABLE_AES TC_AES_ENABLE_CBC
  TC_ENABLE_DES TC_DES_ENABLE_ECB TC_DES_ENABLE_CBC TC_DES_ENABLE_TDES)

set(tc_target_features ${tc_target_${TINY_CRYPTO_TARGET}} ${tc_platform_features})

# Switches an application target decides. Tuning options such as
# TC_AES_SBOX_MODE, TC_EC_SMALL and TC_RSA_SMALL stay with the resource
# profile.
set(tc_target_switch_pattern
  "^TC_(ENABLE_|AES_ENABLE_|DES_ENABLE_|TLV_ENABLE_|EC_ENABLE_|RSA_ENABLE_|PIV_SM_ENABLE_|DRBG_ENABLE_|TAF_ENABLE_)")

function(tc_target_default macro output)
  if(TINY_CRYPTO_TARGET STREQUAL "" OR NOT macro MATCHES "${tc_target_switch_pattern}")
    set(${output} "" PARENT_SCOPE)
  elseif(TINY_CRYPTO_TARGET STREQUAL "full" OR macro IN_LIST tc_target_features)
    set(${output} 1 PARENT_SCOPE)
  else()
    set(${output} 0 PARENT_SCOPE)
  endif()
endfunction()
