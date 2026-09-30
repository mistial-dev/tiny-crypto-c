# SPDX-License-Identifier: GPL-2.0-or-later

# Module options and translation units. config.h owns the dependency rules,
# and ConfigCheck.cmake applies them to the selected options.
set(tc_module_features)

macro(tc_module_feature option macro_name description)
  tc_profile_option(${option} ${macro_name} "${description}")
  list(APPEND tc_module_features ${macro_name})
  set(tc_module_option_${macro_name} ${option})
endmacro()

tc_module_feature(TINY_CRYPTO_ENABLE_AAMVA TC_ENABLE_AAMVA
  "Build ANSI AAMVA payload readers")
set(tc_module_sources_TC_ENABLE_AAMVA src/aamva.c)

tc_module_feature(TINY_CRYPTO_ENABLE_FASCN TC_ENABLE_FASCN
  "Build FASC-N readers and writers")
set(tc_module_sources_TC_ENABLE_FASCN src/fascn.c)

tc_module_feature(TINY_CRYPTO_ENABLE_TWIC_UUID TC_ENABLE_TWIC_UUID
  "Build TWIC NEXGEN UUID helpers")
set(tc_module_sources_TC_ENABLE_TWIC_UUID src/twic_uuid.c)

tc_module_feature(TINY_CRYPTO_ENABLE_TWIC_TPK TC_ENABLE_TWIC_TPK
  "Build TWIC Privacy Key container readers")
set(tc_module_sources_TC_ENABLE_TWIC_TPK src/twic_tpk.c)

tc_module_feature(TINY_CRYPTO_ENABLE_TWIC_OBJECT_CRYPTO
  TC_ENABLE_TWIC_OBJECT_CRYPTO "Build TWIC private-object encryption")
set(tc_module_sources_TC_ENABLE_TWIC_OBJECT_CRYPTO src/twic_cipher.c)

tc_module_feature(TINY_CRYPTO_ENABLE_APDU TC_ENABLE_APDU
  "Build ISO/IEC 7816-4 APDU encoding and exchange")
set(tc_module_sources_TC_ENABLE_APDU src/apdu_encode.c src/apdu_response.c src/apdu_channel.c)

tc_module_feature(TINY_CRYPTO_ENABLE_PIV_COMMAND TC_ENABLE_PIV_COMMAND
  "Build PIV and TWIC card commands over the APDU channel")
set(tc_module_sources_TC_ENABLE_PIV_COMMAND
  src/piv_aid.c src/piv_link.c src/piv_select.c src/piv_get_data.c src/piv_verify.c
  src/piv_status.c src/piv_template_internal.c src/piv_container_internal.c)

tc_module_feature(TINY_CRYPTO_ENABLE_PIV_SM_APDU TC_ENABLE_PIV_SM_APDU
  "Build PIV secure messaging framing on the card link")
set(tc_module_sources_TC_ENABLE_PIV_SM_APDU src/piv_sm_apdu.c src/piv_sm_key_request.c)

tc_module_feature(TINY_CRYPTO_ENABLE_PIV_VCI TC_ENABLE_PIV_VCI
  "Build the PIV virtual contact interface on a secured card link")
set(tc_module_sources_TC_ENABLE_PIV_VCI src/piv_discovery_get.c src/piv_vci.c)

tc_module_feature(TINY_CRYPTO_ENABLE_PIV_CATALOG TC_ENABLE_PIV_CATALOG
  "Build the PIV and TWIC data object catalogs and the card inventory")
set(tc_module_sources_TC_ENABLE_PIV_CATALOG src/piv_catalog.c src/piv_inventory.c)

tc_module_feature(TINY_CRYPTO_ENABLE_PIV_KEY_PROOF TC_ENABLE_PIV_KEY_PROOF
  "Build PIV and TWIC card key proofs over GENERAL AUTHENTICATE")
set(tc_module_sources_TC_ENABLE_PIV_KEY_PROOF src/piv_key_policy.c src/piv_key_proof.c)

tc_module_feature(TINY_CRYPTO_ENABLE_PIV_CARD_CHECK TC_ENABLE_PIV_CARD_CHECK
  "Build the composed PIV and TWIC card check")
set(tc_module_sources_TC_ENABLE_PIV_CARD_CHECK
  src/piv_card_check.c src/piv_card_check_certificates.c src/piv_card_check_signed.c
  src/piv_card_check_keys.c src/piv_card_check_report.c)

tc_module_feature(TINY_CRYPTO_ENABLE_PIV_OIDS TC_ENABLE_PIV_OIDS
  "Build registered PIV and TWIC identifier classification")
set(tc_module_sources_TC_ENABLE_PIV_OIDS src/piv_oid.c)

# TC_ENABLE_X509 selects the certificate reader. The layers below opt into
# path construction, revocation, and CMS independently.
tc_module_feature(TINY_CRYPTO_ENABLE_KEY_CHALLENGE TC_ENABLE_KEY_CHALLENGE
  "Build generic public-key proof-of-possession challenges")
set(tc_module_sources_TC_ENABLE_KEY_CHALLENGE src/key_challenge.c)

tc_module_feature(TINY_CRYPTO_ENABLE_X509_PATH TC_ENABLE_X509_PATH
  "Build X.509 path validation and stores")
set(tc_module_sources_TC_ENABLE_X509_PATH
  src/x509_path.c src/x509_path_extensions.c src/x509_path_workspace.c src/x509_search.c src/x509_store.c src/x509_store_anchor.c
  src/x509_policy.c)

tc_module_feature(TINY_CRYPTO_ENABLE_TRUST_ANCHOR_FORMAT TC_ENABLE_TRUST_ANCHOR_FORMAT
  "Build RFC 5914 trust-anchor format reader")
set(tc_module_sources_TC_ENABLE_TRUST_ANCHOR_FORMAT src/x509_trust_anchor.c)

tc_module_feature(TINY_CRYPTO_ENABLE_X509_REVOCATION TC_ENABLE_X509_REVOCATION
  "Build X.509 CRL and revocation validation")
set(tc_module_sources_TC_ENABLE_X509_REVOCATION
  src/x509_crl.c src/x509_crl_extensions.c src/x509_crl_selected.c src/x509_crl_evidence.c src/x509_crl_entries.c src/x509_revocation.c src/x509_crl_scope.c src/x509_crl_scope_storage.c src/x509_crl_delta.c src/source.c src/source_der.c src/x509_crl_source.c src/x509_crl_prepare.c)

tc_module_feature(TINY_CRYPTO_ENABLE_X509_OCSP TC_ENABLE_X509_OCSP
  "Build X.509 OCSP request and response processing")
set(tc_module_sources_TC_ENABLE_X509_OCSP src/x509_ocsp.c)

tc_module_feature(TINY_CRYPTO_ENABLE_CMS TC_ENABLE_CMS
  "Build CMS parsing and signature verification")
set(tc_module_sources_TC_ENABLE_CMS src/cms.c)

tc_module_feature(TINY_CRYPTO_ENABLE_CMS_VALIDATION TC_ENABLE_CMS_VALIDATION
  "Build CMS path and revocation validation")
set(tc_module_sources_TC_ENABLE_CMS_VALIDATION
  src/cms_collections.c src/cms_path.c src/validation.c)

tc_module_feature(TINY_CRYPTO_ENABLE_PIV_OBJECTS TC_ENABLE_PIV_OBJECTS
  "Build PIV and TWIC credential-object readers")
set(tc_module_sources_TC_ENABLE_PIV_OBJECTS
  src/piv_cms.c src/piv_biometric.c src/piv_certificate.c src/piv_certificate_decode.c
  src/piv_card.c src/lds.c src/piv_security.c src/piv_printed.c src/piv_aid.c
  src/piv_discovery.c src/piv_ccc.c src/piv_key_history.c src/piv_bit_group.c
  src/piv_pairing_code.c src/piv_card_objects_internal.c)

tc_module_feature(TINY_CRYPTO_ENABLE_CREDENTIAL TC_ENABLE_CREDENTIAL
  "Build composed PIV and TWIC credential validation")
set(tc_module_sources_TC_ENABLE_CREDENTIAL src/credential.c src/credential_policy.c
  src/credential_session.c src/credential_security.c src/credential_signer.c)

function(tc_append_module_sources output)
  set(sources ${${output}})
  foreach(macro_name IN LISTS tc_module_features)
    set(option_name ${tc_module_option_${macro_name}})
    if(${option_name})
      list(APPEND sources ${tc_module_sources_${macro_name}})
    endif()
  endforeach()
  set(${output} ${sources} PARENT_SCOPE)
endfunction()
