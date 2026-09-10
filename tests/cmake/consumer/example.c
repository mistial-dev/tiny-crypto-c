/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "cms_reader.h"
#include "credential_auth.h"
#include "credential_object.h"
#include "credential_validate.h"
#include "credential_workflow.h"
#include "pki_input.h"
#include "rsa_encrypt.h"
#include "twic_ccl_import.h"
#include "twic_ccl_storage.h"
#include "x509_client.h"
#include <tiny_crypto/fascn.h>
#include <tiny_crypto/gzip.h>
#include <tiny_crypto/key.h>
#include <tiny_crypto/lds.h>
#include <tiny_crypto/piv_card.h>
#include <tiny_crypto/piv_certificate.h>
#include <tiny_crypto/piv_cms.h>
#include <tiny_crypto/piv_cvc.h>
#include <tiny_crypto/piv_security.h>
#include <tiny_crypto/piv_sm.h>
#include <tiny_crypto/piv_sm_authenticate.h>
#include <tiny_crypto/twic_uuid.h>
#ifdef __cplusplus
#include <tiny_crypto/gzip.hpp>
#endif
#include <string.h>
#include <tiny_crypto/aamva.h>
#include <tiny_crypto/twic_tpk.h>

static TC_status unavailable_random(void *context, uint8_t *output,
                                    size_t length) {
  (void)output;
  (void)length;
  ++*(size_t *)context;
  return TC_ERROR;
}

static TC_status append_ccl_key(void *context,
                                const TC_TWIC_CCL_record *record) {
  memcpy(context, record->fascn, TC_TWIC_CCL_FASCN_BYTES);
  return TC_OK;
}

static TC_status read_ccl_key(void *context, size_t position, TC_bytes *out) {
  if (position)
    return TC_ERROR;
  out->data = (const uint8_t *)context;
  out->length = TC_TWIC_CCL_FASCN_BYTES;
  return TC_OK;
}

static TC_status read_ccl_storage(void *context, size_t offset, uint8_t *out,
                                  size_t length) {
  if (offset || length != TC_TWIC_CCL_FASCN_BYTES)
    return TC_ERROR;
  memcpy(out, context, length);
  return TC_OK;
}

int main(void) {
  {
    const uint8_t guid[16] = {0};
    const TC_bytes empty = {NULL, 0}, identifier = {guid, sizeof guid};
    TC_PIV_card_identifiers identifiers;
    size_t work = 1;
    if (TC_PIV_authentication_identifiers_read(
            empty, identifier, NULL, NULL, 0,
            &work, &identifiers) != TC_TLV_ARGUMENT ||
        work != 1)
      return 1;
    if (TC_TWIC_authentication_identifiers_read(
            empty, identifier, NULL, NULL, 0,
            &work, &identifiers) != TC_TLV_ARGUMENT ||
        work != 1)
      return 1;
  }
  if (example_credential_validate(NULL, NULL, NULL, NULL, NULL) !=
      EXAMPLE_CREDENTIAL_ERROR)
    return 1;
  {
    const uint8_t packed[TC_TWIC_CCL_FASCN_BYTES] = {0};
    const TC_bytes image = {packed, sizeof packed};
    TC_TWIC_CCL_index index;
    int listed = 0;
    if (TC_TWIC_CCL_index_from_memory(&image, 1, &index) != TC_TWIC_CCL_OK ||
        TC_TWIC_CCL_index_contains(&index, image, 1, &listed) !=
            TC_TWIC_CCL_OK ||
        !listed)
      return 1;
  }
  {
    ExampleX509Source arrays = {NULL, 0, NULL, 0};
    const TC_X509_store_source source = example_x509_source(&arrays);
    TC_bytes candidate = {NULL, 0};
    size_t work = 1;
    if (source.candidate_count || source.anchor_count ||
        source.candidate(source.context, 0, &work, &candidate) !=
            TC_TLV_ARGUMENT ||
        work != 1)
      return 1;
  }
  if (example_twic_authenticate(NULL, NULL, NULL, NULL, NULL, NULL) !=
      EXAMPLE_TWIC_ERROR)
    return 1;
  {
    const TC_X509_time at = {2026, 9, 9, 0, 0, 0};
    int64_t seconds = 0;
    if (TC_X509_time_to_unix(&at, &seconds) != TC_TLV_OK ||
        seconds != INT64_C(1788912000))
      return 1;
  }
  {
    uint8_t digest[32] = {0}, encoded[128];
    const TC_bytes input = {digest, sizeof digest};
    const TC_buffer output = {encoded, sizeof encoded};
    const TC_RSA_v15_options options = {TC_HASH_SHA256};
    TC_work_budget work = {sizeof encoded};
    if (TC_RSA_encode_v15_digest(&options, input,
                                 output,
                                 &work) != TC_RSA_OK)
      return 1;
    const uint8_t salt[32] = {0};
    const TC_bytes salt_bytes = {salt, sizeof salt};
    const TC_RSA_pss_options pss = {TC_HASH_SHA256, TC_HASH_SHA256,
                                    sizeof salt};
    work.remaining = UINT32_MAX;
    if (TC_RSA_encode_pss_digest(&pss, input, salt_bytes,
                                 output,
                                 &work) != TC_RSA_OK ||
        (encoded[0] & 0x80) || encoded[sizeof encoded - 1] != 0xbc)
      return 1;
    if (example_card_check_key(NULL, EXAMPLE_CARD_KEY_CARD_AUTHENTICATION, NULL,
                               NULL, NULL, NULL, NULL, NULL,
                               NULL) != EXAMPLE_CARD_KEY_ERROR)
      return 1;
  }
  {
    static TC_GZIP_workspace workspace;
    const uint8_t encoded[] = {0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 2, 0xff,
                               3,    0,    0, 0, 0, 0, 0, 0, 0, 0};
    size_t budget = 4096, length = SIZE_MAX;
    if (TC_GZIP_decode(encoded, sizeof encoded, NULL, 0, &workspace, &budget,
                       &length) != TC_GZIP_OK ||
        length)
      return 1;
#ifdef __cplusplus
    tiny_crypto::GZIPDecoder decoder;
    budget = 4096;
    length = SIZE_MAX;
    if (decoder.decode(encoded, sizeof encoded, nullptr, 0, budget, length) !=
            TC_GZIP_OK ||
        length)
      return 1;
#endif
  }
  {
    static ExampleCMSCredentialWorkspace scratch;
    TC_X509_store store;
    TC_X509_store_snapshot slot;
    const TC_X509_store_source source = {NULL, 0, 0, NULL, NULL};
    const TC_bytes empty = {NULL, 0};
    TC_bytes barcode_field;
    TC_TWIC_tpk privacy_key;
    TC_PIV_certificate certificate_container;
    if (TC_PIV_certificate_read(empty, TC_PIV_CERTIFICATE_SLOT,
                                &certificate_container) != TC_TLV_INVALID)
      return 1;
    if (TC_AAMVA_subfile_find(empty, "ZT", &barcode_field) != TC_TLV_INVALID)
      return 1;
    if (TC_AAMVA_field_find(empty, "ZTA", &barcode_field) != TC_TLV_INVALID)
      return 1;
    if (TC_TWIC_tpk_read(empty, TC_TWIC_TPK_CARD, &privacy_key) !=
        TC_TLV_INVALID)
      return 1;
    const TC_CMS_verification_policy cms_policy = {
        TC_CMS_ATTRIBUTES_DER, TC_CMS_RSA_PARAMETERS_ALLOW_ABSENT};
    size_t work = 100;
    TC_PIV_CMS_object piv_object;
    TC_PIV_CBEFF biometric;
    TC_PIV_CBEFF_metadata biometric_metadata;
    int identifiers_match = -1;
    if (TC_PIV_CBEFF_read(empty, &biometric) != TC_TLV_INVALID)
      return 1;
    if (TC_PIV_CBEFF_metadata_read(empty, &biometric_metadata) !=
        TC_TLV_INVALID)
      return 1;
    if (TC_PIV_CBEFF_format_identify(NULL) != TC_PIV_CBEFF_FORMAT_UNKNOWN)
      return 1;
    if (TC_PIV_CMS_identifiers_match(NULL, TC_PIV_CMS_BIOMETRIC, empty, empty,
                                     NULL, NULL, 0, &work,
                                     &identifiers_match) != TC_TLV_ARGUMENT ||
        work != 100 || identifiers_match != -1)
      return 1;
    if (TC_PIV_CMS_read(empty, TC_PIV_CMS_CHUID, TC_PIV_OIDS_TWIC_COMPATIBLE,
                        TC_CMS_ATTRIBUTES_DER, NULL, NULL, 0, &work,
                        &piv_object) != TC_TLV_ARGUMENT ||
        work != 100)
      return 1;
    if (TC_CMS_signer_verify_content_with_policy(
            NULL, empty, empty, TC_CMS_CONTENT_RAW, cms_policy, NULL, NULL,
            NULL, NULL, &work) != TC_X509_SIGNATURE_ERROR ||
        work != 100)
      return 1;
    if (TC_CMS_signer_verify_digest_with_policy(
            NULL, empty, empty, cms_policy, NULL, NULL, NULL, NULL, &work) !=
            TC_X509_SIGNATURE_ERROR ||
        work != 100)
      return 1;
    memset(&store, 0, sizeof store);
    memset(&slot, 0, sizeof slot);
    const TC_CMS_validation_request request = {empty, 0, empty, NULL, 0, empty};
    if (TC_LDS_read(empty, NULL, NULL, 0, &work, NULL) != TC_TLV_ARGUMENT ||
        work != 100)
      return 1;
    if (TC_FASCN_read(empty, NULL) != TC_TLV_ARGUMENT ||
        TC_FASCN_write(NULL, NULL, 0) != TC_TLV_ARGUMENT)
      return 1;
    if (TC_TWIC_uuid_read(empty, NULL) != TC_TLV_ARGUMENT ||
        TC_TWIC_uuid_write(0, NULL, 0) != TC_TLV_ARGUMENT ||
        TC_TWIC_uuid_match(empty, NULL, NULL) != TC_TLV_ARGUMENT)
      return 1;
    if (TC_LDS_read_content(empty, NULL, NULL, 0, &work, NULL, 0, NULL) !=
            TC_TLV_ARGUMENT ||
        work != 100)
      return 1;
    if (TC_LDS_hash_find(NULL, 1, NULL, NULL, 0, &work, NULL) !=
            TC_TLV_ARGUMENT ||
        work != 100)
      return 1;
    if (TC_LDS_hash_check(NULL, 1, NULL, 0, NULL, NULL, 0, &work, NULL) !=
            TC_TLV_ARGUMENT ||
        work != 100)
      return 1;
    if (TC_PIV_security_read(empty, TC_PIV_SECURITY_CONTENTS, NULL) !=
        TC_TLV_ARGUMENT)
      return 1;
    if (TC_PIV_security_group_find(NULL, 0, NULL) != TC_TLV_ARGUMENT)
      return 1;
    if (TC_PIV_CVC_chain_verify(NULL, NULL, NULL, NULL, &work, NULL) !=
            TC_X509_SIGNATURE_ERROR ||
        work != 100)
      return 1;
#if TC_ENABLE_PIV_SM && TC_ENABLE_PIV_CVC && TC_ENABLE_X509
    {
      TC_PIV_SM session = {0};
      TC_PIV_SM_authentication_workspace sm_workspace;
      if (TC_PIV_SM_authenticate_response(
              &session, NULL, &work, &sm_workspace) != TC_CREDENTIAL_ERROR ||
          work != 100)
        return 1;
    }
#endif
    if (example_validate_cvc(NULL, NULL, NULL, NULL, &work, NULL, NULL) !=
            TC_CREDENTIAL_ERROR ||
        work != 100)
      return 1;
    if (example_validate_biometric(NULL, NULL, NULL, NULL, &work, &scratch) !=
            TC_CREDENTIAL_ERROR ||
        work != 100)
      return 1;
    if (example_validate_security(NULL, NULL, NULL, NULL, &work, NULL) !=
            TC_CREDENTIAL_ERROR ||
        work != 100)
      return 1;
    if (example_twic_inventory_read(NULL, EXAMPLE_CARD_MODEL_TWIC_NEXGEN,
                                    EXAMPLE_CARD_READ_SHORT, NULL, 0, 0, &work,
                                    NULL) != EXAMPLE_CARD_ARGUMENT ||
        work != 100)
      return 1;
    if (example_read_card_identity(empty, TC_TWIC_NEXGEN_CARD, NULL, NULL,
                                   &work, NULL) != TC_TLV_ARGUMENT ||
        work != 100)
      return 1;
    if (TC_PIV_CHUID_validate(NULL, NULL, &work, NULL) != TC_CREDENTIAL_ERROR ||
        work != 100)
      return 1;
    {
      static TC_validation_storage arena[1024];
      const TC_buffer storage = {(uint8_t *)arena, sizeof arena};
      TC_validation_capacity capacity;
      TC_validation_workspace validation;
      size_t required;
      if (TC_validation_capacity_init(TC_VALIDATION_MICRO, &capacity) !=
              TC_RESULT_OK ||
          TC_validation_workspace_size(&capacity, &required) != TC_RESULT_OK ||
          required > sizeof arena ||
          TC_validation_workspace_init(
              &capacity, storage,
              &validation) != TC_RESULT_OK ||
          validation.credential.path != &validation.path)
        return 1;
    }
    if (TC_PIV_biometric_validate(NULL, NULL, &work) != TC_CREDENTIAL_ERROR ||
        work != 100 ||
        TC_PIV_security_validate(NULL, NULL, NULL, &work, NULL) !=
            TC_CREDENTIAL_ERROR ||
        work != 100 ||
        TC_TWIC_unsigned_CHUID_validate(NULL, NULL, NULL, &work) !=
            TC_CREDENTIAL_ERROR ||
        work != 100)
      return 1;
    if (example_validate_cms_from_store(&request, &store, NULL, NULL, &work,
                                        &scratch) != TC_CREDENTIAL_UNAVAILABLE)
      return 1;
    if (TC_X509_store_prepare(&slot, &source) != TC_TLV_OK ||
        TC_X509_store_publish(&store, 0, &slot) != TC_TLV_OK)
      return 1;
    if (example_validate_cms_from_store(&request, &store, NULL, NULL, &work,
                                        &scratch) != TC_CREDENTIAL_ERROR ||
        slot.readers || work != 100)
      return 1;
    if (TC_CMS_signed_data_path_build_parts(empty, 0, empty, NULL, 0, NULL,
                                            NULL, NULL, &work,
                                            NULL) != TC_X509_PATH_ERROR ||
        work != 100)
      return 1;
  }
  {
    uint8_t fascn[TC_TWIC_CCL_FASCN_BYTES] = {0};
    static const uint8_t csv[] =
        "00000000000000000000000000000000000000000000000000,29Feb2024\r\n";
    const TC_bytes input = {csv, sizeof csv - 1}, query = {fascn, sizeof fascn};
    ExampleTwicCclStorage storage = {
        fascn, read_ccl_storage, sizeof fascn, {0}};
    TC_TWIC_CCL_index index;
    int listed = 0;
    if (TC_TWIC_CCL_contains(input, query, 1, &listed) != TC_TWIC_CCL_OK ||
        !listed)
      return 1;
    if (example_twic_ccl_open(&storage, 1, &index) != TC_TWIC_CCL_OK)
      return 1;
    listed = 0;
    if (TC_TWIC_CCL_index_contains(&index, query, 1, &listed) !=
            TC_TWIC_CCL_OK ||
        !listed)
      return 1;
    TC_TWIC_CCL_store store;
    TC_TWIC_CCL_snapshot snapshot;
    const TC_TWIC_CCL_metadata metadata = {100, 101};
    const TC_TWIC_CCL_freshness_policy policy = {120, 30, 0};
    ExampleTwicCclResult checked = {0, 0};
    memset(&store, 0, sizeof store);
    memset(&snapshot, 0, sizeof snapshot);
    if (TC_TWIC_CCL_store_prepare(&snapshot, &index, &metadata) !=
            TC_TWIC_CCL_OK ||
        TC_TWIC_CCL_store_publish(&store, 0, &snapshot) != TC_TWIC_CCL_OK ||
        example_check_twic_cancellation(&store, &policy, 10, query, 1,
                                        &checked) != TC_TWIC_CCL_OK ||
        !checked.listed || !checked.age_warning || snapshot.readers)
      return 1;
    uint8_t checksum[TC_MD5_DIGESTLEN], staged_key[TC_TWIC_CCL_FASCN_BYTES];
    ExampleTwicCclImport import_state;
    const TC_TWIC_CCL_source staged_source = {staged_key, 1, read_ccl_key};
    TC_TWIC_CCL_snapshot proposed;
    memset(&proposed, 0, sizeof proposed);
    if (TC_MD5_digest(csv, sizeof csv - 1, checksum) != TC_OK ||
        example_twic_ccl_import_init(&import_state, checksum, sizeof csv - 1, 1,
                                     append_ccl_key,
                                     staged_key) != TC_TWIC_CCL_OK ||
        example_twic_ccl_import_update(&import_state, input) !=
            TC_TWIC_CCL_OK ||
        example_twic_ccl_import_finish(&import_state, &staged_source, &metadata,
                                       &proposed) != TC_TWIC_CCL_OK ||
        store.current != &snapshot ||
        TC_TWIC_CCL_store_publish(&store, 1, &proposed) != TC_TWIC_CCL_OK)
      return 1;
    example_twic_ccl_import_clear(&import_state);
  }
  {
    enum { KEY_BITS = 1024, KEY_BYTES = KEY_BITS / 8 };
    uint8_t modulus[KEY_BYTES], exponent[] = {3}, ciphertext[KEY_BYTES];
    TC_RSA_word scratch[TC_RSA_ENCRYPT_WORKSPACE_WORDS(KEY_BITS)];
    const TC_RSA_public_key key = {{modulus, sizeof modulus},
                                   {exponent, sizeof exponent}};
    const TC_bytes empty = {NULL, 0};
    size_t calls = 0;
    memset(modulus, 0xff, sizeof modulus);
    memset(ciphertext, 0xa5, sizeof ciphertext);
    memset(scratch, 0xa5, sizeof scratch);
    if (example_encrypt_rsa_oaep_sha256(
            &key, empty, empty, ciphertext, sizeof ciphertext,
            unavailable_random, &calls, scratch,
            sizeof scratch / sizeof *scratch) != TC_RSA_ERROR)
      return 1;
    if (calls != 1 || TC_RSA_encrypt_workspace_words(KEY_BITS) !=
                          sizeof scratch / sizeof *scratch)
      return 1;
    for (size_t i = 0; i < sizeof ciphertext; ++i)
      if (ciphertext[i] != 0xa5)
        return 1;
    for (size_t i = 0; i < sizeof scratch / sizeof *scratch; ++i)
      if (scratch[i])
        return 1;
  }
  {
    const uint8_t encoded[] = {
        0x30, 49,   2, 1,  0, 0x30, 13, 6, 9,  0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 1, 1,  1, 5,    0,  4, 29, 0x30, 27,   2,    1,
        0,    2,    1, 15, 2, 1,    3,  2, 1,  3,    2,    1,    3,
        2,    1,    5, 2,  1, 1,    2,  1, 3,  2,    1,    2};
    const TC_bytes input = {encoded, sizeof encoded};
    const TC_signature_algorithm operation = {
        TC_SIGNATURE_RSA_PSS, TC_HASH_SHA256, TC_HASH_SHA256, 32};
    TC_KEY_rsa_private_key key;
    if (TC_KEY_rsa_private_read(input, &key) != TC_TLV_OK ||
        key.type != TC_KEY_RSA || key.components.modulus.length != 1 ||
        key.components.modulus.data[0] != 15)
      return 1;
    if (TC_KEY_rsa_private_signature_check(&key, &operation) != TC_TLV_OK)
      return 1;
  }
  static ExampleX509Workspace storage;
  const uint8_t invalid_certificate[] = {0x30, 0};
  const TC_bytes chain = {invalid_certificate, sizeof invalid_certificate};
  const TC_X509_time at = {2026, 1, 1, 0, 0, 0};
  TC_X509_trust_anchor anchor;
  TC_X509_signature_provider verifier;
  TC_X509_path_result result, unchanged;
  memset(&anchor, 0, sizeof anchor);
  memset(&verifier, 0, sizeof verifier);
  memset(&result, 0xa5, sizeof result);
  memcpy(&unchanged, &result, sizeof result);

  if (example_check_client_certificate(&chain, 1, &anchor, &at, &verifier,
                                       65535, &storage,
                                       &result) != TC_X509_PATH_INVALID)
    return 1;
  if (memcmp(&result, &unchanged, sizeof result))
    return 2;
  if (example_check_client_certificate(&chain, 1, &anchor, &at, &verifier, 0,
                                       &storage, &result) != TC_X509_PATH_LIMIT)
    return 3;
  if (memcmp(&result, &unchanged, sizeof result))
    return 4;
  if (example_check_client_certificate(&chain, 1, &anchor, &at, &verifier,
                                       65535, NULL,
                                       &result) != TC_X509_PATH_ERROR)
    return 5;
  if (memcmp(&result, &unchanged, sizeof result))
    return 6;
  {
    static ExampleCMSWorkspace cms_storage;
    const TC_bytes empty = {NULL, 0};
    TC_CMS_signed_data cms, saved;
    memset(&cms, 0xa5, sizeof cms);
    memcpy(&saved, &cms, sizeof saved);
    if (example_read_cms(empty, 4096, &cms_storage, &cms) != TC_TLV_MORE)
      return 7;
    if (memcmp(&cms, &saved, sizeof cms))
      return 8;
    if (example_read_cms(empty, 0, &cms_storage, &cms) != TC_TLV_LIMIT)
      return 9;
    if (memcmp(&cms, &saved, sizeof cms))
      return 10;
    if (example_read_cms(empty, 4096, NULL, &cms) != TC_TLV_ARGUMENT)
      return 11;
    TC_CMS_signer_info signer, saved_signer;
    memset(&signer, 0xa5, sizeof signer);
    memcpy(&saved_signer, &signer, sizeof signer);
    if (example_read_cms_signer(empty, 4096, &cms_storage, &signer) !=
        TC_TLV_MORE)
      return 12;
    if (memcmp(&signer, &saved_signer, sizeof signer))
      return 13;
    if (example_read_cms_signer(empty, 0, &cms_storage, &signer) !=
        TC_TLV_LIMIT)
      return 14;
    if (memcmp(&signer, &saved_signer, sizeof signer))
      return 15;
    if (example_read_cms_signer(empty, 4096, NULL, &signer) != TC_TLV_ARGUMENT)
      return 16;
    const uint8_t empty_set[] = {0x31, 0};
    const TC_bytes signers = {empty_set, sizeof empty_set};
    const TC_TLV_limits limits = {4096, 4096, 64, EXAMPLE_CMS_FRAME_CAPACITY};
    TC_TLV_reader reader;
    size_t work = 4096;
    if (TC_CMS_signers_init(signers, &limits, cms_storage.frames,
                            EXAMPLE_CMS_FRAME_CAPACITY, &work,
                            &reader) != TC_TLV_OK)
      return 17;
    work = 0;
    if (TC_CMS_signer_next(&reader, cms_storage.frames,
                           EXAMPLE_CMS_FRAME_CAPACITY, &work,
                           &signer) != TC_TLV_END)
      return 18;
    if (memcmp(&signer, &saved_signer, sizeof signer) || work)
      return 19;
    if (example_parse_cms_signers(signers, 4096, &cms_storage) != TC_TLV_OK)
      return 20;
    if (example_parse_cms_signers(signers, 0, &cms_storage) != TC_TLV_LIMIT)
      return 21;
    const uint8_t type[] = {42, 3};
    enum { SHA256_DIGEST_BYTES = 32 };
    uint8_t digest[SHA256_DIGEST_BYTES] = {0};
    const TC_bytes content_type = {type, sizeof type};
    const TC_bytes computed = {digest, sizeof digest};
    TC_CMS_signed_attributes attributes;
    memset(&attributes, 0, sizeof attributes);
    attributes.content_type = content_type;
    attributes.message_digest = computed;
    int matched = -1;
    work = 4096;
    if (TC_CMS_content_digest_check(&attributes, content_type, TC_HASH_SHA256,
                                    computed, &work, &matched) != TC_TLV_OK ||
        matched != 1)
      return 22;
    work = 0;
    matched = -1;
    if (TC_CMS_content_digest_check(&attributes, content_type, TC_HASH_SHA256,
                                    computed, &work,
                                    &matched) != TC_TLV_LIMIT ||
        matched != -1)
      return 23;
    const uint8_t empty_content[] = {4, 0};
    const TC_bytes encoded_content = {empty_content, sizeof empty_content};
    const uint8_t sha256_empty[SHA256_DIGEST_BYTES] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
        0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
        0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
    work = 4096;
    if (TC_CMS_content_digest(encoded_content, TC_HASH_SHA256, &limits,
                              cms_storage.frames, EXAMPLE_CMS_FRAME_CAPACITY,
                              &work, digest, sizeof digest) != TC_TLV_OK)
      return 24;
    if (memcmp(digest, sha256_empty, sizeof digest))
      return 25;
    work = 0;
    if (TC_CMS_content_digest(encoded_content, TC_HASH_SHA256, &limits,
                              cms_storage.frames, EXAMPLE_CMS_FRAME_CAPACITY,
                              &work, digest, sizeof digest) != TC_TLV_LIMIT)
      return 26;
    if (memcmp(digest, sha256_empty, sizeof digest))
      return 27;
    const TC_signature_algorithm signature_algorithm = {
        TC_SIGNATURE_ECDSA, TC_HASH_SHA256, TC_HASH_UNKNOWN, 0};
    work = 4096;
    if (TC_X509_signature_verify_digest(computed, &signature_algorithm, empty,
                                        &anchor.public_key, &verifier,
                                        &work) != TC_X509_SIGNATURE_UNSUPPORTED)
      return 28;
    static ExampleCMSVerifyWorkspace verification;
    memset(&signer, 0, sizeof signer);
    if (example_verify_cms_digest(&signer, content_type, computed,
                                  TC_CMS_ATTRIBUTES_DER, &anchor.public_key,
                                  &verifier, 4096, &verification) !=
        TC_X509_SIGNATURE_UNSUPPORTED)
      return 29;
    if (example_verify_cms_digest(&signer, content_type, computed,
                                  TC_CMS_ATTRIBUTES_DER, &anchor.public_key,
                                  &verifier, 0,
                                  &verification) != TC_X509_SIGNATURE_LIMIT)
      return 30;
    if (example_verify_cms_digest(&signer, content_type, computed,
                                  TC_CMS_ATTRIBUTES_DER, &anchor.public_key,
                                  &verifier, 4096,
                                  NULL) != TC_X509_SIGNATURE_ERROR)
      return 31;
    if (example_verify_cms_content(
            &signer, content_type, empty, TC_CMS_CONTENT_RAW,
            TC_CMS_ATTRIBUTES_DER, &anchor.public_key, &verifier, 4096,
            &verification) != TC_X509_SIGNATURE_UNSUPPORTED)
      return 32;
    if (example_verify_cms_content(&signer, content_type, empty,
                                   TC_CMS_CONTENT_RAW, TC_CMS_ATTRIBUTES_DER,
                                   &anchor.public_key, &verifier, 0,
                                   &verification) != TC_X509_SIGNATURE_LIMIT)
      return 33;
    if (example_verify_cms_content(&signer, content_type, empty,
                                   TC_CMS_CONTENT_RAW, TC_CMS_ATTRIBUTES_DER,
                                   &anchor.public_key, &verifier, 4096,
                                   NULL) != TC_X509_SIGNATURE_ERROR)
      return 34;
    static ExampleCMSPathWorkspace path_storage;
    TC_CMS_path_options settings;
    TC_X509_store_source source;
    TC_X509_search_result path_result, saved_path;
    memset(&settings, 0, sizeof settings);
    memset(&source, 0, sizeof source);
    memset(&path_result, 0xa5, sizeof path_result);
    memcpy(&saved_path, &path_result, sizeof path_result);
    settings.path.parsing = limits;
    if (example_find_cms_signer_path(&signer, content_type, computed, empty,
                                     &source, &settings, 4096, &path_storage,
                                     &path_result) != TC_X509_PATH_INVALID)
      return 35;
    if (memcmp(&path_result, &saved_path, sizeof path_result))
      return 36;
    if (example_find_cms_signer_path(&signer, content_type, computed, empty,
                                     &source, &settings, 0, &path_storage,
                                     &path_result) != TC_X509_PATH_LIMIT)
      return 37;
    if (memcmp(&path_result, &saved_path, sizeof path_result))
      return 38;
    if (example_find_cms_signer_path(&signer, content_type, computed, empty,
                                     &source, &settings, 4096, NULL,
                                     &path_result) != TC_X509_PATH_ERROR)
      return 39;
    if (example_check_cms_signed_data(chain, 0, content_type, empty, &source,
                                      &settings, 4096, &path_storage,
                                      &path_result) != TC_X509_PATH_INVALID)
      return 40;
    if (memcmp(&path_result, &saved_path, sizeof path_result))
      return 41;
    if (example_check_cms_signed_data(chain, 0, content_type, empty, &source,
                                      &settings, 0, &path_storage,
                                      &path_result) != TC_X509_PATH_LIMIT)
      return 42;
    if (memcmp(&path_result, &saved_path, sizeof path_result))
      return 43;
    if (example_check_cms_signed_data(chain, 0, content_type, empty, &source,
                                      &settings, 4096, NULL,
                                      &path_result) != TC_X509_PATH_ERROR)
      return 44;
  }
  return 0;
}
