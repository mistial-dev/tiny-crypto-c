/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/cms.h>
#include <tiny_crypto/x509_crypto.h>
#include <tiny_crypto/hash.h>
#include <tiny_crypto/piv_oid.h>
#include <tiny_crypto/piv_cms.h>
#include "../../src/cms_internal.h"
#include "cms_crl_harness.h"
#include "munit.h"
#include "test_util.h"
#include <stdio.h>
#include <string.h>

static const TC_CMS_verification_policy cms_policy = {.envelope = TC_CMS_ENVELOPE_BER};
/* Indexed by TC_CMS_attribute_encoding, with every PIV and TWIC identifier. */
static const TC_CMS_verification_policy cms_attribute_policies[] = {
    {.attributes = TC_CMS_ATTRIBUTES_DER, .attribute_oids = TC_CMS_ATTRIBUTE_OIDS_PIV_TWIC},
    {.attributes = TC_CMS_ATTRIBUTES_BER_DEFINITE_ORDER,
     .attribute_oids = TC_CMS_ATTRIBUTE_OIDS_PIV_TWIC}};

static const char* vector_path;
static const char* biometric_path;

static MunitResult biometric_signatures(const MunitParameter params[], void* context)
{
  enum {
    INPUT_BYTES = 16384,
    FRAME_COUNT = 24,
    OID_COUNT = 32,
    NAME_SCALARS = 256,
    NAME_ATTRIBUTES = 32,
    WORK = 1000000
  };
  static char line[8 * INPUT_BYTES + 64];
  static const uint8_t sha256_oid[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1};
  static uint8_t bytes[4][INPUT_BYTES];
  TC_TLV_frame frames[FRAME_COUNT];
  TC_bytes oids[OID_COUNT];
  uint32_t left[NAME_SCALARS], right[NAME_SCALARS];
  uint8_t flags[NAME_ATTRIBUTES];
  const TC_X509_name_workspace names = {left, right, NAME_SCALARS, flags, NAME_ATTRIBUTES};
  const TC_TLV_limits limits = {INPUT_BYTES, INPUT_BYTES, 2048, FRAME_COUNT};
  TC_X509_workspace parser = {frames, FRAME_COUNT, oids, OID_COUNT};
  TC_ECDSA_workspace ec;
  TC_RSA_word words[TC_RSA_VERIFY_WORKSPACE_WORDS(3072)];
  const TC_RSA_workspace rsa = {words, sizeof words / sizeof *words};
  const TC_X509_native_workspace native = {&ec, &rsa, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  const TC_X509_signature_provider provider = TC_X509_native_provider(&native);
  const TC_CMS_signature_workspace verification = {frames, FRAME_COUNT, NULL, 0};
  size_t count = 0;
  (void)params;
  (void)context;
  if (!biometric_path)
    return MUNIT_SKIP;
  FILE* file = fopen(biometric_path, "r");
  munit_assert_not_null(file);
  while (fgets(line, sizeof line, file)) {
    char* verdict = strtok(line, " \t\r\n");
    munit_assert_not_null(verdict);
    char* binding = strtok(NULL, " \t\r\n");
    munit_assert_not_null(binding);
    const int invalid_binding = !strcmp(binding, "invalid"),
              identifiers_match = !strcmp(binding, "match");
    munit_assert_true(invalid_binding || identifiers_match || !strcmp(binding, "mismatch"));
    char* header = strtok(NULL, " \t\r\n");
    munit_assert_not_null(header);
    const int header_matches = !strcmp(header, "match");
    munit_assert_true(header_matches || !strcmp(header, "mismatch"));
    char* metadata_verdict = strtok(NULL, " \t\r\n");
    munit_assert_not_null(metadata_verdict);
    const int invalid_metadata = !strcmp(metadata_verdict, "invalid");
    munit_assert_true(invalid_metadata || !strcmp(metadata_verdict, "valid"));
    const int valid = !strcmp(verdict, "valid");
    const int missing = !strcmp(verdict, "missing-signer");
    munit_assert_true(valid || missing || !strcmp(verdict, "invalid"));
    TC_bytes inputs[4];
    for (size_t i = 0; i < 4; ++i) {
      char* hex = strtok(NULL, " \t\r\n");
      munit_assert_not_null(hex);
      inputs[i] = (TC_bytes){bytes[i], tc_test_decode_hex(hex, bytes[i], sizeof bytes[i])};
      munit_assert_size(inputs[i].length * 2, ==, strlen(hex));
    }
    munit_assert_null(strtok(NULL, " \t\r\n"));
    enum { FASCN_BYTES = 25, UUID_BYTES = 16 };
    munit_assert_size(inputs[3].length, ==, FASCN_BYTES + UUID_BYTES);
    TC_PIV_CBEFF biometric;
    munit_assert_int(TC_PIV_CBEFF_read(inputs[1], &biometric), ==, TC_TLV_OK);
    TC_PIV_CBEFF_metadata metadata, preserved_metadata;
    memset(&preserved_metadata, 0xa5, sizeof preserved_metadata);
    memcpy(&metadata, &preserved_metadata, sizeof metadata);
    munit_assert_int(TC_PIV_CBEFF_metadata_read(inputs[1], &metadata), ==,
                     invalid_metadata ? TC_TLV_INVALID : TC_TLV_OK);
    if (invalid_metadata)
      munit_assert_memory_equal(sizeof metadata, &metadata, &preserved_metadata);
    munit_assert_size(biometric.signature.length, ==, inputs[0].length);
    munit_assert_memory_equal(inputs[0].length, biometric.signature.data, inputs[0].data);
    munit_assert_size(biometric.fascn.length, ==, FASCN_BYTES);
    munit_assert_int(memcmp(biometric.fascn.data, inputs[3].data, FASCN_BYTES) == 0, ==,
                     header_matches);
    inputs[1] = biometric.signed_content;
    size_t work = WORK;
    for (unsigned mode = 0; mode < 2; ++mode) {
      TC_PIV_CMS_object object;
      work = WORK;
      munit_assert_int(
          TC_PIV_CMS_read(
              inputs[0], TC_PIV_CMS_BIOMETRIC,
              &(TC_CMS_verification_policy){.attributes = (TC_CMS_attribute_encoding)mode,
                                            .attribute_oids = TC_CMS_ATTRIBUTE_OIDS_PIV},
              &limits, (TC_TLV_frames){frames, FRAME_COUNT}, &work, &object),
          ==, invalid_binding ? TC_TLV_INVALID : TC_TLV_OK);
      if (invalid_binding)
        continue;
      int matched = -1;
      munit_assert_int(TC_PIV_CMS_identifiers_match(
                           &object, TC_PIV_CMS_BIOMETRIC, (TC_bytes){inputs[3].data, FASCN_BYTES},
                           (TC_bytes){inputs[3].data + FASCN_BYTES, UUID_BYTES}, &limits,
                           (TC_TLV_frames){frames, FRAME_COUNT}, &work, &matched),
                       ==, TC_TLV_OK);
      if (matched != identifiers_match)
        munit_errorf("biometric record %zu: identifier match %d", count, matched);
      TC_TLV_element uuid;
      munit_assert_int(TC_TLV_read(object.attributes.entry_uuid_octets.data,
                                   object.attributes.entry_uuid_octets.length, TC_TLV_DER, &limits,
                                   &uuid),
                       ==, TC_TLV_OK);
      munit_assert_int(TC_PIV_CMS_identifiers_match(
                           &object, TC_PIV_CMS_BIOMETRIC, biometric.fascn, uuid.value, &limits,
                           (TC_TLV_frames){frames, FRAME_COUNT}, &work, &matched),
                       ==, TC_TLV_OK);
      munit_assert_int(matched, ==, 1);
    }
    work = WORK;
    TC_CMS_signed_data envelope, chuid;
    TC_CMS_signer_info signer;
    TC_TLV_reader signers, certificates;
    TC_TLV_element collection, element;
    munit_assert_int(TC_CMS_signed_data_read(inputs[0], &cms_policy, &limits,
                                             (TC_TLV_frames){frames, FRAME_COUNT}, &work,
                                             &envelope),
                     ==, TC_TLV_OK);
    munit_assert_int(TC_CMS_signers_init(envelope.signers, &cms_policy, &limits,
                                         (TC_TLV_frames){frames, FRAME_COUNT}, &work, &signers),
                     ==, TC_TLV_OK);
    munit_assert_int(
        TC_CMS_signer_next(&signers, (TC_TLV_frames){frames, FRAME_COUNT}, &work, &signer), ==,
        TC_TLV_OK);
    munit_assert_int(TC_CMS_signed_data_read(inputs[2], &cms_policy, &limits,
                                             (TC_TLV_frames){frames, FRAME_COUNT}, &work, &chuid),
                     ==, TC_TLV_OK);
    munit_assert_int(TC_TLV_read(chuid.certificates.data, chuid.certificates.length, TC_TLV_BER,
                                 &limits, &collection),
                     ==, TC_TLV_OK);
    munit_assert_int(TC_TLV_reader_init(&certificates, collection.value.data,
                                        collection.value.length, TC_TLV_BER, &limits),
                     ==, TC_TLV_OK);
    int found = 0;
    TC_TLV_result status;
    while ((status = TC_TLV_next(&certificates, &element)) == TC_TLV_OK) {
      TC_X509_certificate certificate;
      int matched;
      const tc_pki_tree_workspace tree = {frames, FRAME_COUNT, &work};
      munit_assert_int(TC_X509_read(element.encoded.data, element.encoded.length, &limits, &parser,
                                    &certificate),
                       ==, TC_TLV_OK);
      munit_assert_int(tc_cms_signer_matches(&signer, TC_TLV_BER, &certificate, &limits, &names,
                                             &tree, &matched),
                       ==, TC_TLV_OK);
      if (!matched)
        continue;
      ++found;
      uint8_t digest[TC_SHA256_DIGESTLEN];
      const TC_bytes content_digest = {digest, sizeof digest};
      munit_assert_size(signer.digest_algorithm.oid.length, ==, sizeof sha256_oid);
      munit_assert_memory_equal(sizeof sha256_oid, signer.digest_algorithm.oid.data, sha256_oid);
      munit_assert_int(TC_SHA256_digest(inputs[1], digest), ==, TC_OK);
      const TC_CMS_verification_policy invalid_policy = {
          .attributes = TC_CMS_ATTRIBUTES_DER, .rsa_parameters = (TC_CMS_rsa_parameters)2};
      work = WORK;
      munit_assert_int(
          TC_CMS_signer_verify_content(
              &(TC_CMS_signer_verify_request){&signer, envelope.content_type, invalid_policy,
                                              &certificate.public_key, &provider, &limits},
              inputs[1], TC_CMS_CONTENT_RAW, &verification, &work),
          ==, TC_X509_SIGNATURE_ERROR);
      munit_assert_size(work, ==, WORK);
      for (unsigned mode = 0; mode < 4; ++mode) {
        const TC_CMS_verification_policy policy = {
            .attributes = (TC_CMS_attribute_encoding)(mode % 2),
            .rsa_parameters =
                mode < 2 ? TC_CMS_RSA_PARAMETERS_NULL : TC_CMS_RSA_PARAMETERS_ALLOW_ABSENT,
            .attribute_oids = TC_CMS_ATTRIBUTE_OIDS_PIV};
        const int accepted = valid && (mode >= 2 || signer.signature_algorithm.parameters.length);
        work = WORK;
        if (mode < 2) {
          munit_assert_int(
              TC_CMS_signer_verify_content(
                  &(TC_CMS_signer_verify_request){&signer,
                                                  envelope.content_type,
                                                  {.attributes = policy.attributes,
                                                   .rsa_parameters = TC_CMS_RSA_PARAMETERS_NULL,
                                                   .attribute_oids = TC_CMS_ATTRIBUTE_OIDS_PIV},
                                                  &certificate.public_key,
                                                  &provider,
                                                  &limits},
                  inputs[1], TC_CMS_CONTENT_RAW, &verification, &work),
              ==, accepted ? TC_X509_SIGNATURE_VALID : TC_X509_SIGNATURE_INVALID);
          work = WORK;
        }
        TC_X509_signature_result result = TC_CMS_signer_verify_content(
            &(TC_CMS_signer_verify_request){&signer, envelope.content_type, policy,
                                            &certificate.public_key, &provider, &limits},
            inputs[1], TC_CMS_CONTENT_RAW, &verification, &work);
        if (result != (accepted ? TC_X509_SIGNATURE_VALID : TC_X509_SIGNATURE_INVALID))
          munit_errorf("biometric record %zu mode %u: signature returned %d", count, mode, result);
        work = WORK;
        munit_assert_int(
            TC_CMS_signer_verify_digest(
                &(TC_CMS_signer_verify_request){&signer, envelope.content_type, policy,
                                                &certificate.public_key, &provider, &limits},
                content_digest, &verification, &work),
            ==, result);
        if (accepted) {
          digest[0] ^= 1;
          work = WORK;
          munit_assert_int(
              TC_CMS_signer_verify_digest(
                  &(TC_CMS_signer_verify_request){&signer, envelope.content_type, policy,
                                                  &certificate.public_key, &provider, &limits},
                  content_digest, &verification, &work),
              ==, TC_X509_SIGNATURE_INVALID);
          digest[0] ^= 1;
          bytes[1][inputs[1].length - 1] ^= 1;
          work = WORK;
          munit_assert_int(
              TC_CMS_signer_verify_content(
                  &(TC_CMS_signer_verify_request){&signer, envelope.content_type, policy,
                                                  &certificate.public_key, &provider, &limits},
                  inputs[1], TC_CMS_CONTENT_RAW, &verification, &work),
              ==, TC_X509_SIGNATURE_INVALID);
          bytes[1][inputs[1].length - 1] ^= 1;
        }
      }
    }
    munit_assert_int(status, ==, TC_TLV_END);
    munit_assert_int(found, ==, missing ? 0 : 1);
    ++count;
  }
  munit_assert_false(ferror(file));
  munit_assert_int(fclose(file), ==, 0);
  munit_assert_size(count, >=, 111);
  return MUNIT_OK;
}

static MunitResult captured(const MunitParameter params[], void* context)
{
  enum { INPUT_BYTES = 16384, FRAME_COUNT = 24, ELEMENT_COUNT = 2048, WORK = 1000000 };
  static char line[2 * INPUT_BYTES + 32];
  static uint8_t bytes[INPUT_BYTES];
  TC_TLV_frame frames[FRAME_COUNT];
  const TC_TLV_limits limits = {INPUT_BYTES, INPUT_BYTES, ELEMENT_COUNT, FRAME_COUNT};
  static const uint8_t chuid_type[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 6, 1};
  static const uint8_t biometric_type[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 6, 2};
  static const uint8_t security_type[] = {0x2b, 0x1b, 1, 1, 1};
  size_t count = 0;
  (void)params;
  (void)context;
  if (!vector_path)
    return MUNIT_SKIP;
  FILE* file = fopen(vector_path, "r");
  munit_assert_not_null(file);
  while (fgets(line, sizeof line, file)) {
    char* kind = strtok(line, " \t\r\n");
    char* verdict = strtok(NULL, " \t\r\n");
    char* hex = strtok(NULL, " \t\r\n");
    munit_assert_not_null(kind);
    munit_assert_not_null(verdict);
    munit_assert_not_null(hex);
    const int invalid_attributes = !strcmp(verdict, "invalid-attributes");
    munit_assert_true(invalid_attributes || !strcmp(verdict, "valid"));
    munit_assert_null(strtok(NULL, " \t\r\n"));
    const int chuid = !strcmp(kind, "chuid");
    const int biometric = !strcmp(kind, "biometric");
    munit_assert_true(chuid || biometric || !strcmp(kind, "security"));
    size_t length = tc_test_decode_hex(hex, bytes, sizeof bytes), work = WORK;
    munit_assert_size(length * 2, ==, strlen(hex));
    TC_CMS_signed_data envelope, saved;
    TC_CMS_signer_info signer;
    TC_TLV_reader signers;
    munit_assert_int(TC_CMS_signed_data_read((TC_bytes){bytes, length}, &cms_policy, &limits,
                                             (TC_TLV_frames){frames, FRAME_COUNT}, &work,
                                             &envelope),
                     ==, TC_TLV_OK);
    munit_assert_uint(envelope.version, ==, 3);
    munit_assert_int(envelope.has_content, ==, !(chuid || biometric));
    const TC_bytes type = chuid       ? (TC_bytes){chuid_type, sizeof chuid_type}
                          : biometric ? (TC_bytes){biometric_type, sizeof biometric_type}
                                      : (TC_bytes){security_type, sizeof security_type};
    munit_assert_size(envelope.content_type.length, ==, type.length);
    munit_assert_memory_equal(type.length, envelope.content_type.data, type.data);
    if (biometric || chuid) {
      for (unsigned profile = TC_PIV_OIDS_ONLY; profile <= TC_PIV_OIDS_TWIC_COMPATIBLE; ++profile)
        munit_assert_int(TC_PIV_oid_identify(envelope.content_type, (TC_PIV_oid_profile)profile),
                         ==, biometric ? TC_PIV_OID_BIOMETRIC_CONTENT : TC_PIV_OID_CHUID_CONTENT);
    }
    munit_assert_int(TC_CMS_signers_init(envelope.signers, &cms_policy, &limits,
                                         (TC_TLV_frames){frames, FRAME_COUNT}, &work, &signers),
                     ==, TC_TLV_OK);
    munit_assert_int(
        TC_CMS_signer_next(&signers, (TC_TLV_frames){frames, FRAME_COUNT}, &work, &signer), ==,
        TC_TLV_OK);
    munit_assert_uint(signer.version, ==, 1);
    munit_assert_int(
        TC_CMS_signer_next(&signers, (TC_TLV_frames){frames, FRAME_COUNT}, &work, &signer), ==,
        TC_TLV_END);
    for (unsigned mode = 0; mode < 2; ++mode) {
      TC_CMS_signed_attributes attributes;
      TC_CMS_signed_attributes untouched;
      memset(&untouched, 0xa5, sizeof untouched);
      memcpy(&attributes, &untouched, sizeof attributes);
      work = WORK;
      TC_TLV_result status = TC_CMS_signed_attributes_read(
          signer.signed_attributes, &cms_attribute_policies[mode], &limits,
          (TC_TLV_frames){frames, FRAME_COUNT}, &work, &attributes);
      if (chuid || biometric) {
        TC_PIV_CMS_object object, preserved;
        memset(&preserved, 0xa5, sizeof preserved);
        const TC_PIV_CMS_kind object_kind = chuid ? TC_PIV_CMS_CHUID : TC_PIV_CMS_BIOMETRIC;
        const TC_bytes input = {bytes, length};
        const TC_TLV_result expected = invalid_attributes || (biometric && status == TC_TLV_OK &&
                                                              !attributes.entry_uuid_octets.data)
                                           ? TC_TLV_INVALID
                                           : TC_TLV_OK;
        for (unsigned oids = TC_CMS_ATTRIBUTE_OIDS_PIV; oids <= TC_CMS_ATTRIBUTE_OIDS_PIV_TWIC;
             ++oids) {
          work = WORK;
          memcpy(&object, &preserved, sizeof object);
          munit_assert_int(
              TC_PIV_CMS_read(
                  input, object_kind,
                  &(TC_CMS_verification_policy){.attributes = (TC_CMS_attribute_encoding)mode,
                                                .attribute_oids = (TC_CMS_attribute_oids)oids},
                  &limits, (TC_TLV_frames){frames, FRAME_COUNT}, &work, &object),
              ==, expected);
          if (expected != TC_TLV_OK)
            munit_assert_memory_equal(sizeof object, &object, &preserved);
          else {
            munit_assert_ptr_equal(object.envelope.encoded.data, bytes);
            const size_t required = WORK - work;
            munit_assert_size(required, >, 0);
            for (unsigned short_budget = 0; short_budget < 2; ++short_budget) {
              work = required - short_budget;
              memcpy(&object, &preserved, sizeof object);
              munit_assert_int(
                  TC_PIV_CMS_read(
                      input, object_kind,
                      &(TC_CMS_verification_policy){.attributes = (TC_CMS_attribute_encoding)mode,
                                                    .attribute_oids = (TC_CMS_attribute_oids)oids},
                      &limits, (TC_TLV_frames){frames, FRAME_COUNT}, &work, &object),
                  ==, short_budget ? TC_TLV_LIMIT : TC_TLV_OK);
              if (short_budget)
                munit_assert_memory_equal(sizeof object, &object, &preserved);
              else
                munit_assert_size(work, ==, 0);
            }
          }
        }
        if (expected == TC_TLV_OK) {
          static const uint8_t sha256_oid[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1};
          munit_assert_size(signer.digest_algorithm.oid.length, ==, sizeof sha256_oid);
          munit_assert_memory_equal(sizeof sha256_oid - 1, signer.digest_algorithm.oid.data,
                                    sha256_oid);
          const size_t hash_offset =
              (size_t)(signer.digest_algorithm.oid.data - bytes) + sizeof sha256_oid - 1;
          const uint8_t original_hash = bytes[hash_offset];
          /* Select a different SHA-2 digest without changing the encoding size. */
          bytes[hash_offset] = original_hash == 1 ? 2 : 1;
          work = WORK;
          memcpy(&object, &preserved, sizeof object);
          munit_assert_int(
              TC_PIV_CMS_read(
                  input, object_kind,
                  &(TC_CMS_verification_policy){.attributes = (TC_CMS_attribute_encoding)mode,
                                                .attribute_oids = TC_CMS_ATTRIBUTE_OIDS_PIV},
                  &limits, (TC_TLV_frames){frames, FRAME_COUNT}, &work, &object),
              ==, TC_TLV_INVALID);
          munit_assert_memory_equal(sizeof object, &object, &preserved);
          bytes[hash_offset] = original_hash;
        }
        static union {
          TC_PIV_CMS_object object;
          uint8_t bytes[INPUT_BYTES];
        } alias;
        memcpy(alias.bytes, bytes, length);
        work = WORK;
        munit_assert_int(
            TC_PIV_CMS_read(
                (TC_bytes){alias.bytes, length}, object_kind,
                &(TC_CMS_verification_policy){.attributes = (TC_CMS_attribute_encoding)mode,
                                              .attribute_oids = TC_CMS_ATTRIBUTE_OIDS_PIV},
                &limits, (TC_TLV_frames){frames, FRAME_COUNT}, &work, &alias.object),
            ==, TC_TLV_ARGUMENT);
        munit_assert_size(work, ==, WORK);
        munit_assert_memory_equal(length, alias.bytes, bytes);
        work = WORK;
        memcpy(&object, &preserved, sizeof object);
        munit_assert_int(
            TC_PIV_CMS_read(
                input, chuid ? TC_PIV_CMS_BIOMETRIC : TC_PIV_CMS_CHUID,
                &(TC_CMS_verification_policy){.attributes = (TC_CMS_attribute_encoding)mode,
                                              .attribute_oids = TC_CMS_ATTRIBUTE_OIDS_PIV},
                &limits, (TC_TLV_frames){frames, FRAME_COUNT}, &work, &object),
            ==, TC_TLV_INVALID);
        munit_assert_memory_equal(sizeof object, &object, &preserved);
        work = 0;
        munit_assert_int(
            TC_PIV_CMS_read(
                input, object_kind,
                &(TC_CMS_verification_policy){.attributes = (TC_CMS_attribute_encoding)mode,
                                              .attribute_oids = TC_CMS_ATTRIBUTE_OIDS_PIV},
                &limits, (TC_TLV_frames){frames, FRAME_COUNT}, &work, &object),
            ==, TC_TLV_LIMIT);
        munit_assert_memory_equal(sizeof object, &object, &preserved);
      }
      if (invalid_attributes) {
        munit_assert_int(status, ==, TC_TLV_INVALID);
        munit_assert_memory_equal(sizeof attributes, &attributes, &untouched);
        continue;
      }
      if (status != TC_TLV_OK)
        munit_errorf("record %zu mode %u: attributes returned %d", count, mode, status);
      munit_assert_size(attributes.content_type.length, ==, type.length);
      munit_assert_memory_equal(type.length, attributes.content_type.data, type.data);
      munit_assert_int(attributes.signer_name.data != NULL, ==, chuid || biometric);
      munit_assert_int(attributes.fascn_octets.data != NULL, ==, biometric);
      munit_assert_ptr_equal(attributes.signature_input[1].data, signer.signed_attributes.data + 1);
    }
    memset(&saved, 0xa5, sizeof saved);
    for (size_t prefix = 0; prefix < length; ++prefix) {
      work = WORK;
      memcpy(&envelope, &saved, sizeof envelope);
      munit_assert_int(TC_CMS_signed_data_read((TC_bytes){bytes, prefix}, &cms_policy, &limits,
                                               (TC_TLV_frames){frames, FRAME_COUNT}, &work,
                                               &envelope),
                       !=, TC_TLV_OK);
      munit_assert_memory_equal(sizeof envelope, &envelope, &saved);
    }
    ++count;
  }
  munit_assert_false(ferror(file));
  munit_assert_int(fclose(file), ==, 0);
  munit_assert_size(count, >, 0);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
      {"/captured", captured, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/biometric-signatures", biometric_signatures, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/cms", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  if (argc == 3 && !strcmp(argv[1], "--cms-vectors")) {
    vector_path = argv[2];
    argv[1] = "/cms/captured";
    argc = 2;
  }
  if (argc == 3 && !strcmp(argv[1], "--biometric-vectors")) {
    biometric_path = argv[2];
    argv[1] = "/cms/biometric-signatures";
    argc = 2;
  }
  return munit_suite_main(&suite, NULL, argc, argv);
}
