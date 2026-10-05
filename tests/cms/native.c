/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* CMS SignedData, CHUID and security-object signatures with the native
 * provider. path.c covers the signer path builder and credential validation,
 * and revocation.c covers signed CRLs. */
#include "../../examples/cms_reader.h"
#include "../../examples/credential_object.h"
#include "../../examples/credential_workflow.h"
#include "../../examples/x509_revocation.h"
#include "../../src/cms_digest_internal.h"
#include "../../src/cms_internal.h"
#include "cms_crl_harness.h"
#include "../../src/cms_signature_internal.h"
#include "../../src/pki_identifier_internal.h"
#include "../../src/pki_tree_internal.h"
#include <tiny_crypto/x509_crypto.h>
#include "../../src/source_internal.h"
#include "../../src/x509_crl_internal.h"
#include "../x509/openssl_fixture.h"
#include "envelope.h"
#include "fascn_fixture.h"
#include "munit.h"
#include "test_util.h"
#include "native_support.h"
#include "openssl_fixture.h"
#include "source.h"
#include <openssl/cms.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <tiny_crypto/piv_chuid.h>
#include <tiny_crypto/piv_cms.h>
#include <tiny_crypto/twic_tpk.h>
#include <tiny_crypto/x509_crl_source.h>
#include <tiny_crypto/x509_crypto.h>
#include "x509_crl_harness.h"

/* Verify through the native provider's digest callback. max_work is the
 * provider's per-signature budget, so 0 exercises its LIMIT path. */
static TC_X509_signature_result verify_digest_native(const TC_signature_algorithm* algorithm,
                                                     const TC_X509_public_key* key, TC_bytes digest,
                                                     TC_bytes signature, TC_ECDSA_workspace* ec,
                                                     const TC_RSA_workspace* rsa, size_t max_work)
{
  const TC_X509_native_workspace native = {ec, rsa, max_work};
  const TC_X509_signature_provider provider = TC_X509_native_provider(&native);
  size_t work = SIZE_MAX;
  return provider.verify_digest(provider.context, digest, algorithm, signature, key, &work);
}

TC_TEST(content_signature)
{
  enum {
    FRAME_CAPACITY = 8,
    WORK_BUDGET = 100000,
    TLV_HEADER_BYTES = 2,
    SPKI_CAPACITY = 128,
    SIGNATURE_CAPACITY = 80,
    CONTENT_MUTATION_OFFSET = 10
  };
  static const struct {
    TC_CMS_attribute_encoding mode;
    int reversed, long_length;
  } cases[] = {{TC_CMS_ATTRIBUTES_DER, 0, 0},
               {TC_CMS_ATTRIBUTES_BER_DEFINITE_ORDER, 1, 0},
               {TC_CMS_ATTRIBUTES_BER_DEFINITE_ORDER, 0, 1}};
  static const uint8_t content_type[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 1};
  static const uint8_t type_attribute[] = {0x30, 24,   6,    9,    0x2a, 0x86, 0x48, 0x86, 0xf7,
                                           0x0d, 1,    9,    3,    0x31, 11,   6,    9,    0x2a,
                                           0x86, 0x48, 0x86, 0xf7, 0x0d, 1,    7,    1};
  static const uint8_t digest_attribute_header[] = {0x30, 47, 6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7,
                                                    0x0d, 1,  9, 4, 0x31, 34,   4,    32};
  static const uint8_t signature_oid[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2};
  static const uint8_t message[] = {'a', 'b', 'c'};
  uint8_t content[] = {0x24, 0x80, 4, 1, 'a', 0x24, 0x80, 4, 2, 'b', 'c', 0, 0, 0, 0};
  uint8_t digest_attribute[sizeof digest_attribute_header + TC_SHA256_DIGESTLEN];
  uint8_t attributes[TLV_HEADER_BYTES + 1 + sizeof type_attribute + sizeof digest_attribute];
  uint8_t spki[SPKI_CAPACITY], signature[SIGNATURE_CAPACITY], digest[TC_SHA256_DIGESTLEN];
  TC_TLV_limits limits = {WORK_BUDGET, WORK_BUDGET, 32, FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_ECDSA_workspace ec;
  TC_X509_native_workspace workspace = {&ec, NULL, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  TC_X509_signature_provider provider = TC_X509_native_provider(&workspace);
  const TC_DER_algorithm algorithm = {{signature_oid, sizeof signature_oid}, {NULL, 0}};
  TC_X509_public_key key;
  EVP_PKEY* generated = EVP_EC_gen("prime256v1");
  EVP_MD_CTX* signer = EVP_MD_CTX_new();
  unsigned char* cursor = spki;
  unsigned digest_length;
  int spki_length;
  munit_assert_not_null(generated);
  munit_assert_not_null(signer);
  spki_length = i2d_PUBKEY(generated, NULL);
  munit_assert_int(spki_length, >, 0);
  munit_assert_size((size_t)spki_length, <=, sizeof spki);
  munit_assert_int(i2d_PUBKEY(generated, &cursor), ==, spki_length);
  munit_assert_int(TC_X509_subject_public_key((TC_bytes){spki, (size_t)spki_length}, &key), ==,
                   TC_TLV_OK);
  memcpy(digest_attribute, digest_attribute_header, sizeof digest_attribute_header);
  munit_assert_int(EVP_Digest(message, sizeof message,
                              digest_attribute + sizeof digest_attribute_header, &digest_length,
                              EVP_sha256(), NULL),
                   ==, 1);
  munit_assert_uint(digest_length, ==, TC_SHA256_DIGESTLEN);

  for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
    const TC_CMS_attribute_encoding mode = cases[i].mode;
    const size_t header_length = TLV_HEADER_BYTES + cases[i].long_length;
    const size_t value_length = sizeof type_attribute + sizeof digest_attribute;
    const size_t attributes_length = header_length + value_length;
    TC_CMS_signed_attributes parsed, saved;
    size_t signature_length = sizeof signature, work = WORK_BUDGET;
    int matched = -1;
    attributes[0] = 0x31;
    attributes[1] = cases[i].long_length ? 0x81 : (uint8_t)value_length;
    if (cases[i].long_length)
      attributes[2] = (uint8_t)value_length;
    if (cases[i].reversed) {
      memcpy(attributes + header_length, digest_attribute, sizeof digest_attribute);
      memcpy(attributes + header_length + sizeof digest_attribute, type_attribute,
             sizeof type_attribute);
    } else {
      memcpy(attributes + header_length, type_attribute, sizeof type_attribute);
      memcpy(attributes + header_length + sizeof type_attribute, digest_attribute,
             sizeof digest_attribute);
    }
    /* Sign SET OF, then carry the same length and values under IMPLICIT [0]. */
    munit_assert_int(EVP_DigestSignInit(signer, NULL, EVP_sha256(), NULL, generated), ==, 1);
    munit_assert_int(
        EVP_DigestSign(signer, signature, &signature_length, attributes, attributes_length), ==, 1);
    attributes[0] = 0xa0;
    munit_assert_int(
        TC_CMS_signed_attributes_read((TC_bytes){attributes, attributes_length},
                                      &(TC_CMS_verification_policy){.attributes = mode}, &limits,
                                      (TC_TLV_frames){frames, FRAME_CAPACITY}, &work, &parsed),
        ==, TC_TLV_OK);
    munit_assert_int(TC_CMS_content_digest((TC_bytes){content, sizeof content}, TC_HASH_SHA256,
                                           &limits, (TC_TLV_frames){frames, FRAME_CAPACITY}, &work,
                                           (TC_buffer){digest, sizeof digest}),
                     ==, TC_TLV_OK);
    munit_assert_int(TC_CMS_content_digest_check(
                         &parsed, (TC_bytes){content_type, sizeof content_type}, TC_HASH_SHA256,
                         (TC_bytes){digest, sizeof digest}, &work, &matched),
                     ==, TC_TLV_OK);
    munit_assert_int(matched, ==, 1);
    munit_assert_int(TC_X509_signature_verify_message(
                         parsed.signature_input,
                         sizeof parsed.signature_input / sizeof *parsed.signature_input, &algorithm,
                         (TC_bytes){signature, signature_length}, &key, &provider, &work),
                     ==, TC_X509_SIGNATURE_VALID);

    {
      uint8_t encoded_signature[SIGNATURE_CAPACITY + TLV_HEADER_BYTES];
      TC_CMS_signer_info info = {0};
      tc_hash_info hash;
      const TC_CMS_signature_workspace verification = {{frames, FRAME_CAPACITY}, NULL, 0};
      munit_assert_true(tc_hash_info_get(TC_HASH_SHA256, &hash));
      munit_assert_size(signature_length, <, 128);
      encoded_signature[0] = 4;
      encoded_signature[1] = (uint8_t)signature_length;
      memcpy(encoded_signature + TLV_HEADER_BYTES, signature, signature_length);
      info.digest_algorithm = (TC_DER_algorithm){hash.oid, {NULL, 0}};
      info.signature_algorithm = algorithm;
      info.signed_attributes = (TC_bytes){attributes, attributes_length};
      info.signature = (TC_bytes){encoded_signature, signature_length + TLV_HEADER_BYTES};
      size_t verification_work = WORK_BUDGET;
      munit_assert_int(TC_CMS_signer_verify_digest(
                           &(TC_CMS_signer_verify_request){
                               &info,
                               (TC_bytes){content_type, sizeof content_type},
                               {.attributes = mode, .rsa_parameters = TC_CMS_RSA_PARAMETERS_NULL},
                               &key,
                               &provider,
                               &limits},
                           (TC_bytes){digest, sizeof digest}, &verification, &verification_work),
                       ==, TC_X509_SIGNATURE_VALID);
      {
        uint8_t cached_digest[TC_CMS_SIGNED_DIGEST_BYTES];
        tc_cms_signed_attrs_cache cache = {0};
        signature_retry_probe retry = {provider, 0, 1, TC_X509_SIGNATURE_INVALID};
        TC_X509_signature_provider retry_provider = provider;
        size_t cached_remaining, uncached_remaining;
        cache.digest = cached_digest;
        cache.capacity = sizeof cached_digest;
        retry_provider.context = &retry;
        retry_provider.verify_digest = retry_digest;
        verification_work = WORK_BUDGET;
        munit_assert_int(
            tc_cms_signer_verify(
                &(TC_CMS_signer_verify_request){
                    &info, (TC_bytes){content_type, sizeof content_type},
                    (TC_CMS_verification_policy){.attributes = mode,
                                                 .rsa_parameters = TC_CMS_RSA_PARAMETERS_NULL},
                    &key, &retry_provider, &limits},
                (TC_bytes){digest, sizeof digest}, TC_CMS_VERIFY_DIGEST, &verification,
                &verification_work, NULL, &cache),
            ==, TC_X509_SIGNATURE_INVALID);
        munit_assert_int(cache.valid, ==, 1);
        verification_work = WORK_BUDGET;
        munit_assert_int(
            tc_cms_signer_verify(
                &(TC_CMS_signer_verify_request){
                    &info, (TC_bytes){content_type, sizeof content_type},
                    (TC_CMS_verification_policy){.attributes = mode,
                                                 .rsa_parameters = TC_CMS_RSA_PARAMETERS_NULL},
                    &key, &retry_provider, &limits},
                (TC_bytes){digest, sizeof digest}, TC_CMS_VERIFY_DIGEST, &verification,
                &verification_work, NULL, &cache),
            ==, TC_X509_SIGNATURE_VALID);
        cached_remaining = verification_work;
        munit_assert_size(retry.calls, ==, 2);
        verification_work = WORK_BUDGET;
        munit_assert_int(
            tc_cms_signer_verify(
                &(TC_CMS_signer_verify_request){
                    &info, (TC_bytes){content_type, sizeof content_type},
                    (TC_CMS_verification_policy){.attributes = mode,
                                                 .rsa_parameters = TC_CMS_RSA_PARAMETERS_NULL},
                    &key, &provider, &limits},
                (TC_bytes){digest, sizeof digest}, TC_CMS_VERIFY_DIGEST, &verification,
                &verification_work, NULL, NULL),
            ==, TC_X509_SIGNATURE_VALID);
        uncached_remaining = verification_work;
        munit_assert_size(cached_remaining, >, uncached_remaining);
      }
      if (mode != TC_CMS_ATTRIBUTES_DER) {
        verification_work = WORK_BUDGET;
        munit_assert_int(
            TC_CMS_signer_verify_digest(
                &(TC_CMS_signer_verify_request){&info,
                                                (TC_bytes){content_type, sizeof content_type},
                                                {.attributes = TC_CMS_ATTRIBUTES_DER,
                                                 .rsa_parameters = TC_CMS_RSA_PARAMETERS_NULL},
                                                &key,
                                                &provider,
                                                &limits},
                (TC_bytes){digest, sizeof digest}, &verification, &verification_work),
            ==, TC_X509_SIGNATURE_INVALID);
      }
      encoded_signature[signature_length + TLV_HEADER_BYTES - 1] ^= 1;
      verification_work = WORK_BUDGET;
      munit_assert_int(TC_CMS_signer_verify_digest(
                           &(TC_CMS_signer_verify_request){
                               &info,
                               (TC_bytes){content_type, sizeof content_type},
                               {.attributes = mode, .rsa_parameters = TC_CMS_RSA_PARAMETERS_NULL},
                               &key,
                               &provider,
                               &limits},
                           (TC_bytes){digest, sizeof digest}, &verification, &verification_work),
                       ==, TC_X509_SIGNATURE_INVALID);
    }

    /* Changed content must fail binding even though signedAttrs still verify.
     */
    content[CONTENT_MUTATION_OFFSET] ^= 1;
    work = WORK_BUDGET;
    munit_assert_int(TC_CMS_content_digest((TC_bytes){content, sizeof content}, TC_HASH_SHA256,
                                           &limits, (TC_TLV_frames){frames, FRAME_CAPACITY}, &work,
                                           (TC_buffer){digest, sizeof digest}),
                     ==, TC_TLV_OK);
    munit_assert_int(TC_CMS_content_digest_check(
                         &parsed, (TC_bytes){content_type, sizeof content_type}, TC_HASH_SHA256,
                         (TC_bytes){digest, sizeof digest}, &work, &matched),
                     ==, TC_TLV_OK);
    munit_assert_int(matched, ==, 0);
    munit_assert_int(TC_X509_signature_verify_message(
                         parsed.signature_input,
                         sizeof parsed.signature_input / sizeof *parsed.signature_input, &algorithm,
                         (TC_bytes){signature, signature_length}, &key, &provider, &work),
                     ==, TC_X509_SIGNATURE_VALID);
    content[CONTENT_MUTATION_OFFSET] ^= 1;
    signature[signature_length - 1] ^= 1;
    work = WORK_BUDGET;
    munit_assert_int(TC_X509_signature_verify_message(
                         parsed.signature_input,
                         sizeof parsed.signature_input / sizeof *parsed.signature_input, &algorithm,
                         (TC_bytes){signature, signature_length}, &key, &provider, &work),
                     ==, TC_X509_SIGNATURE_INVALID);
    if (mode != TC_CMS_ATTRIBUTES_DER) {
      memcpy(&saved, &parsed, sizeof saved);
      work = WORK_BUDGET;
      munit_assert_int(TC_CMS_signed_attributes_read(
                           (TC_bytes){attributes, attributes_length}, &cms_policy, &limits,
                           (TC_TLV_frames){frames, FRAME_CAPACITY}, &work, &parsed),
                       ==, TC_TLV_INVALID);
      munit_assert_memory_equal(sizeof parsed, &parsed, &saved);
    }
  }
  EVP_MD_CTX_free(signer);
  EVP_PKEY_free(generated);
  return MUNIT_OK;
}

TC_TEST(rsa_signature)
{
  enum { SPKI_CAPACITY = 512, MAX_RSA_BITS = 3072 };
  static const unsigned key_sizes[] = {1024, 2048, MAX_RSA_BITS};
  static const uint8_t rsa_oid[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1};
  static const uint8_t null_parameters[] = {5, 0};
  static const uint8_t message[] = {'a', 'b', 'c'};
  const TC_bytes part = {message, sizeof message};
  TC_CMS_signer_info info = {0};
  tc_cms_signature_algorithm algorithm;
  tc_hash_info hash;
  TC_hash_context hash_workspace;
  TC_RSA_word words[TC_RSA_VERIFY_WORKSPACE_WORDS(MAX_RSA_BITS)];
  TC_RSA_workspace workspace = {words, sizeof words / sizeof *words};
  uint8_t spki[SPKI_CAPACITY], signature[MAX_RSA_BITS / 8], digest[TC_SHA256_DIGESTLEN];
  munit_assert_true(tc_hash_info_get(TC_HASH_SHA256, &hash));
  info.digest_algorithm = (TC_DER_algorithm){hash.oid, {NULL, 0}};
  info.signature_algorithm =
      (TC_DER_algorithm){{rsa_oid, sizeof rsa_oid}, {null_parameters, sizeof null_parameters}};
  for (size_t i = 0; i < sizeof key_sizes / sizeof *key_sizes; ++i) {
    EVP_PKEY* generated = EVP_RSA_gen(key_sizes[i]);
    EVP_MD_CTX* signer = EVP_MD_CTX_new();
    unsigned char* cursor = spki;
    size_t signature_length = sizeof signature;
    TC_X509_public_key key;
    int spki_length;
    munit_assert_not_null(generated);
    munit_assert_not_null(signer);
    spki_length = i2d_PUBKEY(generated, NULL);
    munit_assert_int(spki_length, >, 0);
    munit_assert_size((size_t)spki_length, <=, sizeof spki);
    munit_assert_int(i2d_PUBKEY(generated, &cursor), ==, spki_length);
    munit_assert_int(TC_X509_subject_public_key((TC_bytes){spki, (size_t)spki_length}, &key), ==,
                     TC_TLV_OK);
    munit_assert_int(EVP_DigestSignInit(signer, NULL, EVP_sha256(), NULL, generated), ==, 1);
    munit_assert_int(EVP_DigestSign(signer, signature, &signature_length, message, sizeof message),
                     ==, 1);
    const TC_bytes signature_bytes = {signature, signature_length};
    munit_assert_int(tc_cms_signature_resolve_policy(&info, &key, TC_TLV_DER, NULL, NULL,
                                                     TC_CMS_RSA_PARAMETERS_NULL, &algorithm),
                     ==, TC_TLV_OK);
    munit_assert_int(
        tc_hash_digest_parts(algorithm.content_hash, &part, 1, digest, &hash_workspace), ==, TC_OK);
    munit_assert_int(verify_digest_native(&algorithm.signature, &key,
                                          (TC_bytes){digest, sizeof digest}, signature_bytes, NULL,
                                          &workspace, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK),
                     ==, TC_X509_SIGNATURE_VALID);
    {
      enum { HEADER_BYTES = 4, FRAME_CAPACITY = 8, WORK_BUDGET = 100000 };
      static const uint8_t data_type[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 1};
      uint8_t encoded_signature[sizeof signature + HEADER_BYTES];
      TC_TLV_frame frames[FRAME_CAPACITY];
      const TC_TLV_limits limits = {sizeof encoded_signature, sizeof encoded_signature, 32,
                                    FRAME_CAPACITY};
      const TC_CMS_signature_workspace verification = {{frames, FRAME_CAPACITY}, NULL, 0};
      const TC_X509_native_workspace native = {NULL, &workspace,
                                               TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
      const TC_X509_signature_provider provider = TC_X509_native_provider(&native);
      encoded_signature[0] = 4;
      encoded_signature[1] = 0x82;
      encoded_signature[2] = (uint8_t)(signature_length >> 8);
      encoded_signature[3] = (uint8_t)signature_length;
      memcpy(encoded_signature + HEADER_BYTES, signature, signature_length);
      info.signature = (TC_bytes){encoded_signature, signature_length + HEADER_BYTES};
      size_t work = WORK_BUDGET;
      munit_assert_int(
          TC_CMS_signer_verify_digest(
              &(TC_CMS_signer_verify_request){&info,
                                              (TC_bytes){data_type, sizeof data_type},
                                              {.attributes = TC_CMS_ATTRIBUTES_DER,
                                               .rsa_parameters = TC_CMS_RSA_PARAMETERS_NULL},
                                              &key,
                                              &provider,
                                              &limits},
              (TC_bytes){digest, sizeof digest}, &verification, &work),
          ==, TC_X509_SIGNATURE_VALID);
      digest[0] ^= 1;
      work = WORK_BUDGET;
      munit_assert_int(
          TC_CMS_signer_verify_digest(
              &(TC_CMS_signer_verify_request){&info,
                                              (TC_bytes){data_type, sizeof data_type},
                                              {.attributes = TC_CMS_ATTRIBUTES_DER,
                                               .rsa_parameters = TC_CMS_RSA_PARAMETERS_NULL},
                                              &key,
                                              &provider,
                                              &limits},
              (TC_bytes){digest, sizeof digest}, &verification, &work),
          ==, TC_X509_SIGNATURE_INVALID);
      digest[0] ^= 1;
      info.signature = (TC_bytes){NULL, 0};
    }
    digest[0] ^= 1;
    munit_assert_int(verify_digest_native(&algorithm.signature, &key,
                                          (TC_bytes){digest, sizeof digest}, signature_bytes, NULL,
                                          &workspace, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK),
                     ==, TC_X509_SIGNATURE_INVALID);
    digest[0] ^= 1;
    signature[signature_length - 1] ^= 1;
    munit_assert_int(verify_digest_native(&algorithm.signature, &key,
                                          (TC_bytes){digest, sizeof digest}, signature_bytes, NULL,
                                          &workspace, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK),
                     ==, TC_X509_SIGNATURE_INVALID);
    EVP_MD_CTX_free(signer);
    EVP_PKEY_free(generated);
  }
  return MUNIT_OK;
}

TC_TEST(signed_data)
{
  enum {
    ENCODED_CAPACITY = 4096,
    FRAME_CAPACITY = 16,
    ELEMENT_LIMIT = 256,
    WORK_BUDGET = 100000,
    NAME_SCALARS = 64,
    NAME_ATTRIBUTES = 8
  };
  static const uint8_t message[] = {'a', 'b', 'c'};
  const unsigned flags[] = {CMS_BINARY | CMS_NOSMIMECAP,
                            CMS_BINARY | CMS_NOSMIMECAP | CMS_USE_KEYID};
  uint8_t encoded[ENCODED_CAPACITY], certificate_der[ENCODED_CAPACITY], other_der[ENCODED_CAPACITY];
  uint8_t digest[TC_SHA512_DIGESTLEN];
  uint8_t name_flags[NAME_ATTRIBUTES];
  uint32_t name_left[NAME_SCALARS], name_right[NAME_SCALARS];
  const TC_X509_name_workspace names = {name_left, name_right, NAME_SCALARS, name_flags,
                                        NAME_ATTRIBUTES};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_bytes extension_oids[NAME_ATTRIBUTES];
  TC_X509_workspace parser = {{frames, FRAME_CAPACITY}, extension_oids, NAME_ATTRIBUTES};
  TC_X509_certificate parsed_certificate;
  const TC_TLV_limits limits = {ENCODED_CAPACITY, ENCODED_CAPACITY, ELEMENT_LIMIT, FRAME_CAPACITY};
  TC_hash_context hash_workspace;
  TC_ECDSA_workspace ec;
  const TC_X509_native_workspace native = {&ec, NULL, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  const TC_X509_signature_provider provider = TC_X509_native_provider(&native);
  TC_X509_public_key key;
  EVP_PKEY* generated = EVP_EC_gen("prime256v1");
  EVP_PKEY* other_key = EVP_EC_gen("prime256v1");
  X509 *certificate, *other_certificate;
  unsigned char* cursor;
  size_t certificate_length, other_length;
  munit_assert_not_null(generated);
  munit_assert_not_null(other_key);
  certificate = make_certificate(generated, "CMS signer", NULL);
  add_extension(certificate, NID_subject_key_identifier, "hash");
  certificate_length = encode_certificate(certificate, generated, EVP_sha256(), certificate_der,
                                          sizeof certificate_der);
  munit_assert_int(TC_X509_read((TC_bytes){certificate_der, certificate_length}, &limits, &parser,
                                &parsed_certificate),
                   ==, TC_TLV_OK);
  key = parsed_certificate.public_key;
  other_certificate = make_certificate(other_key, "Other signer", NULL);
  add_extension(other_certificate, NID_subject_key_identifier, "hash");
  other_length =
      encode_certificate(other_certificate, other_key, EVP_sha256(), other_der, sizeof other_der);
  for (size_t i = 0; i < sizeof flags / sizeof *flags; ++i) {
    BIO* input = BIO_new_mem_buf(message, sizeof message);
    CMS_ContentInfo* cms;
    TC_CMS_signed_data container;
    TC_CMS_signer_info signer;
    tc_cms_signature_algorithm algorithm;
    TC_CMS_signed_attributes attributes;
    TC_TLV_reader signers;
    TC_TLV_element element;
    TC_bytes signature;
    tc_hash_info hash;
    size_t work = WORK_BUDGET;
    const tc_pki_tree_workspace workspace = {frames, FRAME_CAPACITY, &work};
    int encoded_length, matched = -1;
    munit_assert_not_null(input);
    cms = CMS_sign(certificate, generated, NULL, input, flags[i]);
    munit_assert_not_null(cms);
    encoded_length = i2d_CMS_ContentInfo(cms, NULL);
    munit_assert_int(encoded_length, >, 0);
    munit_assert_size((size_t)encoded_length, <=, sizeof encoded);
    cursor = encoded;
    munit_assert_int(i2d_CMS_ContentInfo(cms, &cursor), ==, encoded_length);
    munit_assert_int(
        tc_cms_signed_data_read((TC_bytes){encoded, (size_t)encoded_length}, TC_TLV_BER, &limits,
                                (TC_TLV_frames){frames, FRAME_CAPACITY}, &work, &container),
        ==, TC_TLV_OK);
    munit_assert_true(container.has_content);
    munit_assert_int(tc_cms_signed_data_version_check(&container, TC_TLV_BER, &limits, &workspace),
                     ==, TC_TLV_OK);
    ++container.version;
    munit_assert_int(tc_cms_signed_data_version_check(&container, TC_TLV_BER, &limits, &workspace),
                     ==, TC_TLV_INVALID);
    --container.version;
    munit_assert_int(TC_CMS_signers_init(container.signers, &cms_policy, &limits,
                                         (TC_TLV_frames){frames, FRAME_CAPACITY}, &work, &signers),
                     ==, TC_TLV_OK);
    munit_assert_int(
        TC_CMS_signer_next(&signers, (TC_TLV_frames){frames, FRAME_CAPACITY}, &work, &signer), ==,
        TC_TLV_OK);
    munit_assert_true(tc_pki_end(&signers));
    munit_assert_int(
        TC_CMS_signer_next(&signers, (TC_TLV_frames){frames, FRAME_CAPACITY}, &work, &signer), ==,
        TC_TLV_END);
    munit_assert_int(tc_pki_tree_read(signer.encoded, TC_TLV_BER, &limits, &workspace, &element),
                     ==, TC_TLV_OK);
    munit_assert_uint(signer.version, ==, flags[i] & CMS_USE_KEYID ? 3 : 1);
    munit_assert_int(tc_cms_signer_matches(&signer, TC_TLV_BER, &parsed_certificate, &limits,
                                           &names, &workspace, &matched),
                     ==, TC_TLV_OK);
    munit_assert_int(matched, ==, 1);
    {
      const TC_bytes records[] = {{other_der, other_length}, {certificate_der, certificate_length}};
      candidate_source source = {records, sizeof records / sizeof records[0], 0, TC_TLV_OK, 0};
      const TC_X509_store_source external = {&source, source.count, 0, read_candidate, NULL};
      tc_cms_candidates candidates;
      TC_X509_certificate selected;
      TC_bytes selected_der = {NULL, 0};
      munit_assert_int(
          tc_cms_candidates_init(container.certificates, &external, 3,
                                 sizeof encoded + sizeof certificate_der + sizeof other_der,
                                 &limits, &workspace, &candidates),
          ==, TC_TLV_OK);
      const tc_cms_candidates start = candidates;
      const size_t before_search = work;
      munit_assert_int(tc_cms_signer_candidate_next(&candidates, &signer, TC_TLV_BER, &names,
                                                    &workspace, &parser, &selected, &selected_der),
                       ==, TC_TLV_OK);
      munit_assert_size(source.calls, ==, 0);
      munit_assert_ptr_equal(selected_der.data, selected.encoded.data);
      key = selected.public_key;
      {
        const size_t required = before_search - work, remaining_work = work;
        const size_t budgets[] = {0, required - 1, required};
        for (size_t budget = 0; budget < sizeof budgets / sizeof budgets[0]; ++budget) {
          tc_cms_candidates probe = start, saved;
          TC_bytes output = selected_der;
          memcpy(&saved, &probe, sizeof saved);
          work = budgets[budget];
          TC_TLV_result result = tc_cms_signer_candidate_next(
              &probe, &signer, TC_TLV_BER, &names, &workspace, &parser, &selected, &output);
          munit_assert_int(result, ==, budgets[budget] == required ? TC_TLV_OK : TC_TLV_LIMIT);
          munit_assert_ptr_equal(output.data, selected_der.data);
          if (result == TC_TLV_LIMIT)
            munit_assert_memory_equal(sizeof probe, &probe, &saved);
          else
            munit_assert_size(work, ==, 0);
        }
        work = remaining_work;
      }
      munit_assert_int(tc_cms_signer_candidate_next(&candidates, &signer, TC_TLV_BER, &names,
                                                    &workspace, &parser, &selected, &selected_der),
                       ==, TC_TLV_OK);
      munit_assert_size(source.calls, ==, source.count);
      munit_assert_ptr_equal(selected_der.data, certificate_der);
      {
        TC_X509_store_source nonmatching = external;
        tc_cms_candidates no_match;
        nonmatching.candidate_count = 1;
        munit_assert_int(tc_cms_candidates_init((TC_bytes){NULL, 0}, &nonmatching, 1,
                                                sizeof other_der, &limits, &workspace, &no_match),
                         ==, TC_TLV_OK);
        munit_assert_int(tc_cms_signer_candidate_next(&no_match, &signer, TC_TLV_BER, &names,
                                                      &workspace, &parser, &selected,
                                                      &selected_der),
                         ==, TC_TLV_END);
        munit_assert_size(no_match.collection.external_index, ==, 1);
        munit_assert_ptr_equal(selected_der.data, certificate_der);
      }
      munit_assert_int(tc_cms_signer_candidate_next(&candidates, &signer, TC_TLV_BER, &names,
                                                    &workspace, &parser, &selected, &selected_der),
                       ==, TC_TLV_END);
      munit_assert_ptr_equal(selected_der.data, certificate_der);
    }
    munit_assert_int(tc_cms_signature_resolve_policy(&signer, &key, TC_TLV_BER, &limits, &workspace,
                                                     TC_CMS_RSA_PARAMETERS_NULL, &algorithm),
                     ==, TC_TLV_OK);
    munit_assert_true(tc_hash_info_get(algorithm.content_hash, &hash));
    munit_assert_int(TC_CMS_content_digest(container.content, algorithm.content_hash, &limits,
                                           (TC_TLV_frames){frames, FRAME_CAPACITY}, &work,
                                           (TC_buffer){digest, sizeof digest}),
                     ==, TC_TLV_OK);
    uint8_t content_digest_bytes[TC_SHA512_DIGESTLEN];
    memcpy(content_digest_bytes, digest, hash.digest_length);
    const TC_bytes computed_content = {content_digest_bytes, hash.digest_length};
    munit_assert_int(TC_CMS_signed_attributes_read(signer.signed_attributes, &cms_policy, &limits,
                                                   (TC_TLV_frames){frames, FRAME_CAPACITY}, &work,
                                                   &attributes),
                     ==, TC_TLV_OK);
    munit_assert_int(
        TC_CMS_content_digest_check(&attributes, container.content_type, algorithm.content_hash,
                                    (TC_bytes){digest, hash.digest_length}, &work, &matched),
        ==, TC_TLV_OK);
    munit_assert_int(matched, ==, 1);
    {
      const TC_CMS_signature_workspace verification = {{frames, FRAME_CAPACITY}, NULL, 0};
      size_t verification_work = WORK_BUDGET;
      const TC_bytes content_digest = {digest, hash.digest_length};
      munit_assert_int(
          TC_CMS_signer_verify_digest(
              &(TC_CMS_signer_verify_request){&signer,
                                              container.content_type,
                                              {.attributes = TC_CMS_ATTRIBUTES_DER,
                                               .rsa_parameters = TC_CMS_RSA_PARAMETERS_NULL},
                                              &key,
                                              &provider,
                                              &limits},
              content_digest, &verification, &verification_work),
          ==, TC_X509_SIGNATURE_VALID);
      ExampleCMSVerifyWorkspace example;
      munit_assert_int(example_verify_cms_digest(&signer, container.content_type, content_digest,
                                                 &key, &provider, WORK_BUDGET, &example),
                       ==, TC_X509_SIGNATURE_VALID);
      munit_assert_int(example_verify_cms_digest(&signer, container.content_type, content_digest,
                                                 &key, &provider, 0, &example),
                       ==, TC_X509_SIGNATURE_LIMIT);
      munit_assert_int(example_verify_cms_content(&signer, container.content_type,
                                                  container.content, TC_CMS_CONTENT_BER_OCTETS,
                                                  &key, &provider, WORK_BUDGET, &example),
                       ==, TC_X509_SIGNATURE_VALID);
      munit_assert_int(example_verify_cms_content(&signer, container.content_type,
                                                  container.content, TC_CMS_CONTENT_BER_OCTETS,
                                                  &key, &provider, 0, &example),
                       ==, TC_X509_SIGNATURE_LIMIT);
      const size_t required = WORK_BUDGET - verification_work;
      verification_work = required;
      munit_assert_int(
          TC_CMS_signer_verify_digest(
              &(TC_CMS_signer_verify_request){&signer,
                                              container.content_type,
                                              {.attributes = TC_CMS_ATTRIBUTES_DER,
                                               .rsa_parameters = TC_CMS_RSA_PARAMETERS_NULL},
                                              &key,
                                              &provider,
                                              &limits},
              content_digest, &verification, &verification_work),
          ==, TC_X509_SIGNATURE_VALID);
      munit_assert_size(verification_work, ==, 0);
      verification_work = required - 1;
      munit_assert_int(
          TC_CMS_signer_verify_digest(
              &(TC_CMS_signer_verify_request){&signer,
                                              container.content_type,
                                              {.attributes = TC_CMS_ATTRIBUTES_DER,
                                               .rsa_parameters = TC_CMS_RSA_PARAMETERS_NULL},
                                              &key,
                                              &provider,
                                              &limits},
              content_digest, &verification, &verification_work),
          ==, TC_X509_SIGNATURE_LIMIT);
      digest[0] ^= 1;
      verification_work = WORK_BUDGET;
      munit_assert_int(
          TC_CMS_signer_verify_digest(
              &(TC_CMS_signer_verify_request){&signer,
                                              container.content_type,
                                              {.attributes = TC_CMS_ATTRIBUTES_DER,
                                               .rsa_parameters = TC_CMS_RSA_PARAMETERS_NULL},
                                              &key,
                                              &provider,
                                              &limits},
              content_digest, &verification, &verification_work),
          ==, TC_X509_SIGNATURE_INVALID);
      digest[0] ^= 1;
    }
    munit_assert_true(tc_hash_info_get(algorithm.signature.hash, &hash));
    munit_assert_int(
        tc_hash_digest_parts(algorithm.signature.hash, attributes.signature_input,
                             sizeof attributes.signature_input / sizeof *attributes.signature_input,
                             digest, &hash_workspace),
        ==, TC_OK);
    munit_assert_int(
        tc_pki_octets_contiguous(signer.signature, 4, TC_TLV_BER, &limits,
                                 &(tc_pki_tree_workspace){frames, FRAME_CAPACITY, &work},
                                 (TC_buffer){NULL, 0}, &signature),
        ==, TC_TLV_OK);
    munit_assert_int(TC_X509_signature_verify_digest((TC_bytes){digest, hash.digest_length},
                                                     &algorithm.signature, signature, &key,
                                                     &provider, &work),
                     ==, TC_X509_SIGNATURE_VALID);
    {
      enum { SIGNATURE_CAPACITY = 80, CHUNK_FRAMING = 12 };
      uint8_t chunked[SIGNATURE_CAPACITY + CHUNK_FRAMING], scratch[SIGNATURE_CAPACITY];
      uint8_t signer_encoded[ENCODED_CAPACITY];
      const size_t prefix = (size_t)(signer.signature.data - element.value.data);
      const size_t suffix = element.value.length - prefix - signer.signature.length;
      munit_assert_size(signature.length, <=, SIGNATURE_CAPACITY);
      /* Split the DER ECDSA value at every byte, including its INTEGER headers.
       */
      for (size_t split = 0; split <= signature.length; ++split) {
        size_t offset = 0;
        TC_bytes joined = {NULL, 99};
        chunked[offset++] = 0x24;
        chunked[offset++] = 0x80;
        chunked[offset++] = 4;
        chunked[offset++] = (uint8_t)split;
        memcpy(chunked + offset, signature.data, split);
        offset += split;
        chunked[offset++] = 0x24;
        chunked[offset++] = 0x80;
        chunked[offset++] = 4;
        chunked[offset++] = (uint8_t)(signature.length - split);
        memcpy(chunked + offset, signature.data + split, signature.length - split);
        offset += signature.length - split;
        memset(chunked + offset, 0, 4);
        offset += 4;
        TC_CMS_signer_info parsed_chunks;
        size_t signer_length = 0;
        munit_assert_size(prefix + offset + suffix + 4, <=, sizeof signer_encoded);
        signer_encoded[signer_length++] = 0x30;
        signer_encoded[signer_length++] = 0x80;
        memcpy(signer_encoded + signer_length, element.value.data, prefix);
        signer_length += prefix;
        memcpy(signer_encoded + signer_length, chunked, offset);
        signer_length += offset;
        memcpy(signer_encoded + signer_length, signer.signature.data + signer.signature.length,
               suffix);
        signer_length += suffix;
        memset(signer_encoded + signer_length, 0, 2);
        signer_length += 2;
        work = WORK_BUDGET;
        munit_assert_int(
            TC_CMS_signer_info_read((TC_bytes){signer_encoded, signer_length}, &cms_policy, &limits,
                                    (TC_TLV_frames){frames, FRAME_CAPACITY}, &work, &parsed_chunks),
            ==, TC_TLV_OK);
        munit_assert_uint(parsed_chunks.version, ==, signer.version);
        munit_assert_int(
            tc_pki_octets_contiguous(parsed_chunks.signature, 4, TC_TLV_BER, &limits,
                                     &(tc_pki_tree_workspace){frames, FRAME_CAPACITY, &work},
                                     (TC_buffer){scratch, sizeof scratch}, &joined),
            ==, TC_TLV_OK);
        munit_assert_size(joined.length, ==, signature.length);
        munit_assert_memory_equal(joined.length, joined.data, signature.data);
        munit_assert_int(verify_digest_native(&algorithm.signature, &key,
                                              (TC_bytes){digest, hash.digest_length}, joined, &ec,
                                              NULL, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK),
                         ==, TC_X509_SIGNATURE_VALID);
        const TC_CMS_signature_workspace verification = {
            {frames, FRAME_CAPACITY}, scratch, sizeof scratch};
        size_t verification_work = WORK_BUDGET;
        munit_assert_int(
            TC_CMS_signer_verify_digest(
                &(TC_CMS_signer_verify_request){&parsed_chunks,
                                                container.content_type,
                                                {.attributes = TC_CMS_ATTRIBUTES_DER,
                                                 .rsa_parameters = TC_CMS_RSA_PARAMETERS_NULL},
                                                &key,
                                                &provider,
                                                &limits},
                computed_content, &verification, &verification_work),
            ==, TC_X509_SIGNATURE_VALID);
        if (split && split < signature.length) {
          TC_CMS_signature_workspace short_workspace = verification;
          short_workspace.signature_capacity = signature.length - 1;
          verification_work = WORK_BUDGET;
          munit_assert_int(
              TC_CMS_signer_verify_digest(
                  &(TC_CMS_signer_verify_request){&parsed_chunks,
                                                  container.content_type,
                                                  {.attributes = TC_CMS_ATTRIBUTES_DER,
                                                   .rsa_parameters = TC_CMS_RSA_PARAMETERS_NULL},
                                                  &key,
                                                  &provider,
                                                  &limits},
                  computed_content, &short_workspace, &verification_work),
              ==, TC_X509_SIGNATURE_LIMIT);
          munit_assert_ptr_equal(joined.data, scratch);
          scratch[joined.length - 1] ^= 1;
          munit_assert_int(verify_digest_native(&algorithm.signature, &key,
                                                (TC_bytes){digest, hash.digest_length}, joined, &ec,
                                                NULL, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK),
                           ==, TC_X509_SIGNATURE_INVALID);
          work = WORK_BUDGET;
          joined = (TC_bytes){NULL, 99};
          munit_assert_int(
              tc_pki_octets_contiguous((TC_bytes){chunked, offset}, 4, TC_TLV_BER, &limits,
                                       &(tc_pki_tree_workspace){frames, FRAME_CAPACITY, &work},
                                       (TC_buffer){scratch, signature.length - 1}, &joined),
              ==, TC_TLV_LIMIT);
          munit_assert_null(joined.data);
          munit_assert_size(joined.length, ==, 99);
        }
      }
    }
    digest[0] ^= 1;
    munit_assert_int(verify_digest_native(&algorithm.signature, &key,
                                          (TC_bytes){digest, hash.digest_length}, signature, &ec,
                                          NULL, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK),
                     ==, TC_X509_SIGNATURE_INVALID);
    CMS_ContentInfo_free(cms);
    BIO_free(input);
  }
  X509_free(certificate);
  EVP_PKEY_free(generated);
  X509_free(other_certificate);
  EVP_PKEY_free(other_key);
  return MUNIT_OK;
}

/* The template has no entries. Each partition carries its own reason mask. */

typedef struct {
  EVP_PKEY* key;
  const TC_X509_signature_provider* provider;
  TC_TWIC_CCL_store* ccl_store;
  TC_TWIC_CCL_snapshot* replacement_ccl;
  int tamper;
  unsigned calls;
  ExampleCredentialCardKey expected_key;
} workflow_proof;

static TC_status workflow_card_proof(void* context, TC_PIV_card_profile profile,
                                     ExampleCredentialCardKey key_reference,
                                     const TC_X509_public_key* key,
                                     const TC_key_challenge_options* challenge)
{
  workflow_proof* proof = context;
  munit_assert_true(profile == TC_PIV_CARD || profile == TC_TWIC_LEGACY_CARD ||
                    profile == TC_TWIC_NEXGEN_CARD);
  munit_assert_int(key_reference, ==, proof->expected_key);
  uint8_t digest[48], signature[384];
  const size_t digest_length = challenge->signature.hash == TC_HASH_SHA384 ? 48 : 32;
  const EVP_MD* digest_method = digest_length == 48 ? EVP_sha384() : EVP_sha256();
  size_t length = sizeof signature, work = 1000000;
  munit_assert_int(RAND_bytes(digest, (int)digest_length), ==, 1);
  EVP_PKEY_CTX* signing = EVP_PKEY_CTX_new(proof->key, NULL);
  munit_assert_not_null(signing);
  munit_assert_int(EVP_PKEY_sign_init(signing), ==, 1);
  const int rsa = EVP_PKEY_base_id(proof->key) == EVP_PKEY_RSA;
  const int pss = challenge->signature.scheme == TC_SIGNATURE_RSA_PSS;
  if (rsa) {
    munit_assert_true(pss || challenge->signature.scheme == TC_SIGNATURE_RSA_V15);
    munit_assert_int(
        EVP_PKEY_CTX_set_rsa_padding(signing, pss ? RSA_PKCS1_PSS_PADDING : RSA_PKCS1_PADDING), ==,
        1);
  } else {
    munit_assert_int(EVP_PKEY_base_id(proof->key), ==, EVP_PKEY_EC);
    munit_assert_int(challenge->signature.scheme, ==, TC_SIGNATURE_ECDSA);
  }
  munit_assert_int(EVP_PKEY_CTX_set_signature_md(signing, digest_method), ==, 1);
  if (pss) {
    munit_assert_int(EVP_PKEY_CTX_set_rsa_mgf1_md(signing, EVP_sha256()), ==, 1);
    munit_assert_int(
        EVP_PKEY_CTX_set_rsa_pss_saltlen(signing, (int)challenge->signature.salt_length), ==, 1);
  }
  munit_assert_int(EVP_PKEY_sign(signing, signature, &length, digest, digest_length), ==, 1);
  EVP_PKEY_CTX_free(signing);
  signature[0] ^= (uint8_t)proof->tamper;
  ++proof->calls;
  TC_X509_signature_result status =
      TC_X509_signature_verify_digest((TC_bytes){digest, digest_length}, &challenge->signature,
                                      (TC_bytes){signature, length}, key, proof->provider, &work);
  TC_secure_zero(digest, sizeof digest);
  TC_secure_zero(signature, sizeof signature);
  if (status == TC_X509_SIGNATURE_VALID && proof->replacement_ccl) {
    munit_assert_int(TC_TWIC_CCL_store_publish(proof->ccl_store, 1, proof->replacement_ccl), ==,
                     TC_TWIC_CCL_OK);
    proof->replacement_ccl = NULL;
  }
  return status == TC_X509_SIGNATURE_VALID     ? TC_OK
         : status == TC_X509_SIGNATURE_INVALID ? TC_MISMATCH
                                               : TC_ERROR;
}

/* Synthetic issuing CA and content signer for the credential workflow. */
typedef struct {
  X509* root;
  EVP_PKEY* root_key;
  X509* signer;
  EVP_PKEY* signer_key;
} credential_issuers;

/* Signed card objects. Empty unsigned_chuid and printed spans are omitted. */
typedef struct {
  TC_bytes chuid, security;
  const TC_PIV_security_data* inventory;
  size_t inventory_count;
  TC_bytes unsigned_chuid, printed;
} credential_objects;

static void credential_public_workflow(const credential_issuers* issuers,
                                       TC_PIV_card_profile profile, unsigned ec_bits,
                                       const credential_objects* objects,
                                       const TC_validation_context* content)
{
  X509* const root = issuers->root;
  EVP_PKEY* const root_key = issuers->root_key;
  X509* const signer = issuers->signer;
  EVP_PKEY* const signer_key = issuers->signer_key;
  const TC_bytes chuid = objects->chuid;
  const TC_bytes security = objects->security;
  const TC_PIV_security_data* inventory = objects->inventory;
  const size_t inventory_count = objects->inventory_count;
  const TC_bytes unsigned_chuid = objects->unsigned_chuid;
  const TC_bytes printed = objects->printed;
  enum { OBJECT_BYTES = 4096, ARENA_UNITS = 1024, WORK = 2000000 };
  static TC_validation_storage arena[ARENA_UNITS];
  uint8_t certificate_bytes[OBJECT_BYTES], biometric[OBJECT_BYTES], face_biometric[OBJECT_BYTES],
      lds_content[OBJECT_BYTES];
  EVP_PKEY* private_key = ec_bits == 256   ? EVP_EC_gen("prime256v1")
                          : ec_bits == 384 ? EVP_EC_gen("secp384r1")
                                           : EVP_RSA_gen(2048);
  munit_assert_not_null(private_key);
  X509* certificate = make_certificate(private_key, "Synthetic card", root);
  add_extension(certificate, NID_basic_constraints, "critical,CA:FALSE");
  add_extension(certificate, NID_key_usage, "critical,digitalSignature");
  add_extension(certificate, NID_ext_key_usage,
                profile == TC_PIV_CARD ? "2.16.840.1.101.3.6.8" : "1.3.6.1.4.1.29138.6.8");
  add_card_identifiers(certificate, (TC_bytes){test_card_fascn, sizeof test_card_fascn},
                       "urn:uuid:91be2094-f6dc-5349-8000-4090e49e505c");
  const TC_bytes card = {certificate_bytes,
                         encode_certificate(certificate, root_key, EVP_sha256(), certificate_bytes,
                                            sizeof certificate_bytes)};
  uint8_t alternate_eku_bytes[OBJECT_BYTES];
  X509* alternate_eku_certificate = X509_dup(certificate);
  munit_assert_not_null(alternate_eku_certificate);
  const int eku_position = X509_get_ext_by_NID(alternate_eku_certificate, NID_ext_key_usage, -1);
  munit_assert_int(eku_position, >=, 0);
  X509_EXTENSION_free(X509_delete_ext(alternate_eku_certificate, eku_position));
  add_extension(alternate_eku_certificate, NID_ext_key_usage,
                profile == TC_PIV_CARD ? "1.3.6.1.4.1.29138.6.8" : "2.16.840.1.101.3.6.8");
  const TC_bytes alternate_eku_card = {
      alternate_eku_bytes, encode_certificate(alternate_eku_certificate, root_key, EVP_sha256(),
                                              alternate_eku_bytes, sizeof alternate_eku_bytes)};
  X509_free(alternate_eku_certificate);
  uint8_t piv_auth_bytes[OBJECT_BYTES];
  X509* piv_auth_certificate = X509_dup(certificate);
  munit_assert_not_null(piv_auth_certificate);
  GENERAL_NAMES* piv_auth_names =
      X509_get_ext_d2i(piv_auth_certificate, NID_subject_alt_name, NULL, NULL);
  GENERAL_NAME* cardholder_name = GENERAL_NAME_new();
  ASN1_IA5STRING* cardholder_uri = ASN1_IA5STRING_new();
  static const char cardholder_uuid[] = "urn:uuid:10213243-5465-4768-899a-abbccddeeff0";
  munit_assert_not_null(piv_auth_names);
  munit_assert_not_null(cardholder_name);
  munit_assert_not_null(cardholder_uri);
  munit_assert_int(ASN1_STRING_set(cardholder_uri, cardholder_uuid, (int)strlen(cardholder_uuid)),
                   ==, 1);
  GENERAL_NAME_set0_value(cardholder_name, GEN_URI, cardholder_uri);
  munit_assert_int(sk_GENERAL_NAME_push(piv_auth_names, cardholder_name), >, 0);
  munit_assert_int(X509_add1_ext_i2d(piv_auth_certificate, NID_subject_alt_name, piv_auth_names, 0,
                                     X509V3_ADD_REPLACE),
                   ==, 1);
  GENERAL_NAMES_free(piv_auth_names);
  const TC_bytes piv_auth_card = {piv_auth_bytes,
                                  encode_certificate(piv_auth_certificate, root_key, EVP_sha256(),
                                                     piv_auth_bytes, sizeof piv_auth_bytes)};
  X509_free(piv_auth_certificate);
  uint8_t absent_uuid_bytes[OBJECT_BYTES], expired_card_bytes[OBJECT_BYTES],
      wrong_identity_bytes[OBJECT_BYTES];
  X509* absent_uuid_certificate = X509_dup(certificate);
  munit_assert_not_null(absent_uuid_certificate);
  GENERAL_NAMES* names =
      X509_get_ext_d2i(absent_uuid_certificate, NID_subject_alt_name, NULL, NULL);
  munit_assert_not_null(names);
  for (int i = sk_GENERAL_NAME_num(names) - 1; i >= 0; --i)
    if (sk_GENERAL_NAME_value(names, i)->type == GEN_URI)
      GENERAL_NAME_free(sk_GENERAL_NAME_delete(names, i));
  munit_assert_int(X509_add1_ext_i2d(absent_uuid_certificate, NID_subject_alt_name, names, 0,
                                     X509V3_ADD_REPLACE),
                   ==, 1);
  GENERAL_NAMES_free(names);
  const TC_bytes absent_uuid_card = {
      absent_uuid_bytes, encode_certificate(absent_uuid_certificate, root_key, EVP_sha256(),
                                            absent_uuid_bytes, sizeof absent_uuid_bytes)};
  X509_free(absent_uuid_certificate);
  X509* expired_certificate = X509_dup(certificate);
  munit_assert_not_null(expired_certificate);
  munit_assert_int(
      ASN1_TIME_set_string_X509(X509_getm_notAfter(expired_certificate), "20250101000000Z"), ==, 1);
  const TC_bytes expired_card = {expired_card_bytes,
                                 encode_certificate(expired_certificate, root_key, EVP_sha256(),
                                                    expired_card_bytes, sizeof expired_card_bytes)};
  X509_free(expired_certificate);
  X509* wrong_identity_certificate = X509_dup(certificate);
  munit_assert_not_null(wrong_identity_certificate);
  const int san_position =
      X509_get_ext_by_NID(wrong_identity_certificate, NID_subject_alt_name, -1);
  munit_assert_int(san_position, >=, 0);
  X509_EXTENSION_free(X509_delete_ext(wrong_identity_certificate, san_position));
  uint8_t wrong_fascn[sizeof test_card_fascn];
  memcpy(wrong_fascn, test_card_fascn, sizeof wrong_fascn);
  wrong_fascn[0] ^= 1;
  add_card_identifiers(wrong_identity_certificate, (TC_bytes){wrong_fascn, sizeof wrong_fascn},
                       "urn:uuid:91be2094-f6dc-5349-8000-4090e49e505c");
  const TC_bytes wrong_identity_card = {
      wrong_identity_bytes, encode_certificate(wrong_identity_certificate, root_key, EVP_sha256(),
                                               wrong_identity_bytes, sizeof wrong_identity_bytes)};
  X509_free(wrong_identity_certificate);
  uint8_t revoked_crl_bytes[OBJECT_BYTES];
  const TC_bytes revoked_crl = {
      revoked_crl_bytes,
      encode_issuer_crl(root, root_key, certificate, revoked_crl_bytes, sizeof revoked_crl_bytes)};
  TC_TLV_frame crl_frames[16];
  TC_bytes crl_oids[16];
  TC_X509_workspace crl_parser = {{crl_frames, 16}, crl_oids, 16};
  TC_X509_crl_record revoked_record;
  TC_X509_crl_index revoked_index;
  size_t crl_work = WORK;
  munit_assert_int(TC_X509_crl_index_init(&revoked_crl, 1, &content->options->parsing, &crl_parser,
                                          &crl_work, &revoked_record, 1, &revoked_index),
                   ==, TC_TLV_OK);
  EVP_PKEY* wrong_root_key = EVP_EC_gen("prime256v1");
  munit_assert_not_null(wrong_root_key);
  X509* wrong_root = X509_dup(root);
  munit_assert_not_null(wrong_root);
  munit_assert_int(X509_set_pubkey(wrong_root, wrong_root_key), ==, 1);
  uint8_t wrong_root_bytes[OBJECT_BYTES];
  const size_t wrong_root_length = encode_certificate(wrong_root, wrong_root_key, EVP_sha256(),
                                                      wrong_root_bytes, sizeof wrong_root_bytes);
  TC_X509_certificate parsed_wrong_root;
  munit_assert_int(TC_X509_read((TC_bytes){wrong_root_bytes, wrong_root_length},
                                &content->options->parsing, &crl_parser, &parsed_wrong_root),
                   ==, TC_TLV_OK);
  TC_X509_store_anchor wrong_anchor = {
      .trust = {parsed_wrong_root.subject, parsed_wrong_root.public_key}};
  const TC_X509_store_source wrong_trust = {&wrong_anchor, 0, 1, NULL, crl_trust_anchor};
  X509_free(wrong_root);
  TC_PIV_CHUID parsed;
  munit_assert_int(TC_PIV_CHUID_read(chuid, TC_PIV_CHUID_CONTENTS,
                                     profile == TC_PIV_CARD ? TC_CHUID_PROFILE_PIV
                                                            : TC_CHUID_PROFILE_TWIC_SIGNED,
                                     &parsed),
                   ==, TC_TLV_OK);
  const size_t biometric_length = encode_biometric(signer, signer_key, 0, parsed.fascn,
                                                   parsed.card_uuid, biometric, sizeof biometric);
  static const uint8_t piv_face_record[] = {
      'F', 'A', 'C', 0,    '0', '1',  '0', 0, 0, 0, 0, 50, 0,    1,    0,    0,   0,
      36,  0,   0,   0,    0,   0,    0,   0, 0, 0, 1, 0,  0,    0,    0,    0,   0,
      1,   0,   1,   0xa5, 2,   0x58, 1,   2, 0, 0, 0, 0,  0xff, 0xd8, 0xff, 0xd9};
  uint8_t face_record[sizeof piv_face_record];
  memcpy(face_record, piv_face_record, sizeof face_record);
  if (profile != TC_PIV_CARD) {
    face_record[26] = face_record[27] = 0;
    face_record[34] = 0;
    face_record[36] = 1;
    face_record[37] = 18;
  }
  const size_t face_length = encode_biometric_record(
      &(biometric_signer){signer, signer_key, 0, 0, 0},
      &(biometric_record){
          parsed.fascn, parsed.card_uuid, {face_record, sizeof face_record}, 0x0501, 2, 0x20},
      (TC_buffer){face_biometric, sizeof face_biometric});
  TC_validation_capacity capacity;
  TC_validation_workspace workspace;
  munit_assert_int(TC_validation_capacity_init(TC_VALIDATION_MICRO, &capacity), ==, TC_RESULT_OK);
  munit_assert_int(TC_validation_workspace_init(
                       &capacity, (TC_buffer){(uint8_t*)arena, sizeof arena}, &workspace),
                   ==, TC_RESULT_OK);
  TC_validation_options card_options = *content->options;
  static const uint8_t piv_purpose[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 6, 8};
  static const uint8_t twic_purpose[] = {0x2b, 6, 1, 4, 1, 0x81, 0xe3, 0x52, 6, 8};
  card_options.certificate.purpose = profile == TC_PIV_CARD
                                         ? (TC_bytes){piv_purpose, sizeof piv_purpose}
                                         : (TC_bytes){twic_purpose, sizeof twic_purpose};
  TC_validation_options content_options = *content->options;
  content_options.certificate.purpose = (TC_bytes){NULL, 0};
  TC_validation_context card_context, content_context;
  munit_assert_int(TC_validation_context_init(&content->trust, &card_options, &workspace.credential,
                                              &card_context),
                   ==, TC_RESULT_OK);
  munit_assert_int(TC_validation_context_init(&content->trust, &content_options,
                                              &workspace.credential, &content_context),
                   ==, TC_RESULT_OK);
  int64_t now;
  munit_assert_int(TC_X509_time_to_unix(&card_options.at, &now), ==, TC_TLV_OK);
  workflow_proof proof = {private_key, &card_options.signatures, NULL, NULL, 0, 0, 0};
  enum {
    VALID,
    BAD_PROOF,
    CANCELLED,
    STALE,
    TAMPERED,
    EXHAUSTED,
    MISSING_CRL,
    ABSENT_UUID,
    SUPERSEDED_CCL,
    RSA_PSS,
    REVOKED_CARD,
    EXPIRED_CARD,
    WRONG_IDENTITY,
    WRONG_ROOT,
    MISSING_REQUIRED,
    CCL_LIMIT,
    ALTERNATE_EKU,
    PIV_AUTHENTICATION,
    PIV_AUTHENTICATION_TWIC_READER,
    CARD_AUTHENTICATION_TWIC_READER,
    CASES
  };
  const ExampleCredentialVerdict expected[] = {
      EXAMPLE_CREDENTIAL_VALID,       EXAMPLE_CREDENTIAL_PROOF_FAILED,
      EXAMPLE_CREDENTIAL_CANCELLED,   EXAMPLE_CREDENTIAL_STALE,
      EXAMPLE_CREDENTIAL_INVALID,     EXAMPLE_CREDENTIAL_LIMIT,
      EXAMPLE_CREDENTIAL_UNAVAILABLE, EXAMPLE_CREDENTIAL_VALID,
      EXAMPLE_CREDENTIAL_STALE,       EXAMPLE_CREDENTIAL_VALID,
      EXAMPLE_CREDENTIAL_REVOKED,     EXAMPLE_CREDENTIAL_INVALID,
      EXAMPLE_CREDENTIAL_INVALID,     EXAMPLE_CREDENTIAL_INVALID,
      EXAMPLE_CREDENTIAL_UNAVAILABLE, EXAMPLE_CREDENTIAL_LIMIT,
      EXAMPLE_CREDENTIAL_VALID,       EXAMPLE_CREDENTIAL_VALID,
      EXAMPLE_CREDENTIAL_VALID,       EXAMPLE_CREDENTIAL_ERROR};
  for (unsigned variant = 0; variant < CASES; ++variant) {
    if (profile == TC_PIV_CARD &&
        (variant == CANCELLED || variant == STALE || variant == ABSENT_UUID ||
         variant == SUPERSEDED_CCL || variant == CCL_LIMIT))
      continue;
    if (profile != TC_PIV_CARD && variant >= PIV_AUTHENTICATION)
      continue;
    uint8_t cancellation[25];
    memset(cancellation, 0xff, sizeof cancellation);
    if (variant == CANCELLED)
      memcpy(cancellation, test_card_fascn, sizeof cancellation);
    const TC_bytes packed = {cancellation, sizeof cancellation};
    TC_TWIC_CCL_index index;
    TC_TWIC_CCL_snapshot slot = {0}, replacement = {0}, *held;
    TC_TWIC_CCL_store store = {0};
    const TC_TWIC_CCL_metadata metadata = {(uint64_t)now - 2, (uint64_t)now - 1};
    munit_assert_int(TC_TWIC_CCL_index_from_memory(&packed, 1, &index), ==, TC_TWIC_CCL_OK);
    munit_assert_int(TC_TWIC_CCL_store_prepare(&slot, &index, &metadata), ==, TC_TWIC_CCL_OK);
    munit_assert_int(TC_TWIC_CCL_store_publish(&store, 0, &slot), ==, TC_TWIC_CCL_OK);
    munit_assert_int(TC_TWIC_CCL_store_acquire(&store, &held), ==, TC_TWIC_CCL_OK);
    if (variant == SUPERSEDED_CCL) {
      munit_assert_int(TC_TWIC_CCL_store_prepare(&replacement, &index, &metadata), ==,
                       TC_TWIC_CCL_OK);
      proof.ccl_store = &store;
      proof.replacement_ccl = &replacement;
    }
    ExampleCredentialValidationRequest request = {0};
    request.profile = profile;
    request.certificate = variant == ABSENT_UUID                      ? absent_uuid_card
                          : variant == EXPIRED_CARD                   ? expired_card
                          : variant == WRONG_IDENTITY                 ? wrong_identity_card
                          : variant == ALTERNATE_EKU                  ? alternate_eku_card
                          : variant == PIV_AUTHENTICATION             ? piv_auth_card
                          : variant == PIV_AUTHENTICATION_TWIC_READER ? absent_uuid_card
                                                                      : card;
    request.chuid = chuid;
    request.chuid_encoding = TC_PIV_CHUID_CONTENTS;
    request.chuid_profile =
        profile == TC_PIV_CARD ? TC_CHUID_PROFILE_PIV : TC_CHUID_PROFILE_TWIC_SIGNED;
    if (variant == PIV_AUTHENTICATION || variant == PIV_AUTHENTICATION_TWIC_READER)
      request.card_key = EXAMPLE_CREDENTIAL_PIV_AUTHENTICATION;
    if (variant == PIV_AUTHENTICATION_TWIC_READER || variant == CARD_AUTHENTICATION_TWIC_READER)
      request.twic_reader_policy = 1;
    proof.expected_key = request.card_key;
    if (profile != TC_PIV_CARD) {
      request.ccl = held;
      request.freshness =
          (TC_TWIC_CCL_freshness_policy){(uint64_t)now, variant == STALE ? 0 : 60, 0};
      request.ccl_reads = 4;
      if (variant == CCL_LIMIT)
        request.ccl_reads = 0;
    }
    request.proof = workflow_card_proof;
    request.proof_context = &proof;
    request.required_objects = EXAMPLE_CREDENTIAL_REQUIRE_SECURITY |
                               EXAMPLE_CREDENTIAL_REQUIRE_FINGERPRINT |
                               EXAMPLE_CREDENTIAL_REQUIRE_FACE;
    if (unsigned_chuid.length)
      request.required_objects |= EXAMPLE_CREDENTIAL_REQUIRE_UNSIGNED_CHUID;
    if (printed.length)
      request.required_objects |= EXAMPLE_CREDENTIAL_REQUIRE_PRINTED;
    request.rsa_padding = variant == RSA_PSS ? TC_PIV_RSA_PSS : TC_PIV_RSA_PKCS1_V15;
    request.security = (ExampleCredentialSecurityInput){security,
                                                        TC_PIV_SECURITY_CONTENTS,
                                                        inventory,
                                                        inventory_count,
                                                        unsigned_chuid,
                                                        TC_PIV_CHUID_CONTENTS,
                                                        {lds_content, sizeof lds_content},
                                                        printed};
    const ExampleCredentialBiometricInput biometric_inputs[] = {
        {{biometric, biometric_length}, TC_PIV_CMS_BIOMETRIC, TC_PIV_CBEFF_FINGERPRINT_TEMPLATE, 0},
        {{face_biometric, face_length}, TC_PIV_CMS_BIOMETRIC, TC_PIV_CBEFF_FACE_IMAGE, 0}};
    request.biometrics = biometric_inputs;
    request.biometric_count = sizeof biometric_inputs / sizeof *biometric_inputs;
    if (variant == MISSING_REQUIRED)
      request.biometric_count = 1;
    proof.tamper = variant == BAD_PROOF;
    proof.calls = 0;
    if (variant == TAMPERED)
      biometric[biometric_length - 1] ^= 1;
    const TC_X509_crl_index no_crls = {NULL, 0, 0};
    card_context.trust.crls = variant == MISSING_CRL    ? &no_crls
                              : variant == REVOKED_CARD ? &revoked_index
                                                        : content->trust.crls;
    card_context.trust.certificates =
        variant == WRONG_ROOT ? &wrong_trust : content->trust.certificates;
    size_t work = variant == EXHAUSTED ? 0 : WORK;
    ExampleCredentialValidationResult result, unchanged;
    memset(&result, 0xa5, sizeof result);
    memcpy(&unchanged, &result, sizeof result);
    const ExampleCredentialVerdict wanted =
        variant == ALTERNATE_EKU
            ? (profile == TC_PIV_CARD ? EXAMPLE_CREDENTIAL_INVALID : EXAMPLE_CREDENTIAL_VALID)
            : expected[variant];
    munit_assert_int(
        example_credential_validate(&request, &card_context, &content_context, &work, &result), ==,
        wanted);
    const int accepted_variant = variant == VALID || variant == ABSENT_UUID || variant == RSA_PSS ||
                                 variant == PIV_AUTHENTICATION ||
                                 variant == PIV_AUTHENTICATION_TWIC_READER ||
                                 (variant == ALTERNATE_EKU && profile != TC_PIV_CARD);
    if (accepted_variant) {
      munit_assert_ptr_equal(result.card.certificate.encoded.data, request.certificate.data);
      if (variant == ABSENT_UUID)
        munit_assert_size(result.identifiers.uuid_urn.length, ==, 0);
      munit_assert_true(result.has_security);
      munit_assert_ptr_equal(result.security.objects, inventory);
      munit_assert_int(result.has_printed, ==, printed.length != 0);
      if (printed.length)
        munit_assert_ptr_equal(result.printed.name.data, printed.data + 2);
      memset(arena, 0, sizeof arena);
      munit_assert_memory_equal(parsed.fascn.length, result.chuid.object.fascn.data,
                                parsed.fascn.data);
      munit_assert_size(result.biometric_count, ==, request.biometric_count);
      for (size_t i = 0; i < result.biometric_count; ++i) {
        munit_assert_int(result.biometrics[i].format, ==, biometric_inputs[i].format);
        munit_assert_int(result.biometrics[i].profile, ==, profile);
        munit_assert_ptr(result.biometrics[i].record.data, >=, biometric_inputs[i].encoded.data);
        munit_assert_ptr(result.biometrics[i].record.data + result.biometrics[i].record.length, <=,
                         biometric_inputs[i].encoded.data + biometric_inputs[i].encoded.length);
      }
      if (variant == VALID) {
        const unsigned calls = proof.calls;
        request.biometric_count = 4;
        work = WORK;
        munit_assert_int(example_credential_validate(&request, &card_context, &content_context,
                                                     &work, &unchanged),
                         ==, EXAMPLE_CREDENTIAL_ERROR);
        request.biometric_count = 2;
        request.biometrics = NULL;
        munit_assert_int(example_credential_validate(&request, &card_context, &content_context,
                                                     &work, &unchanged),
                         ==, EXAMPLE_CREDENTIAL_ERROR);
        const ExampleCredentialBiometricInput duplicates[] = {biometric_inputs[0],
                                                              biometric_inputs[0]};
        request.biometrics = duplicates;
        munit_assert_int(example_credential_validate(&request, &card_context, &content_context,
                                                     &work, &unchanged),
                         ==, EXAMPLE_CREDENTIAL_ERROR);
        request.biometrics = biometric_inputs;
        const TC_PIV_security_data* security_objects = request.security.objects;
        request.security.objects = NULL;
        work = WORK;
        munit_assert_int(example_credential_validate(&request, &card_context, &content_context,
                                                     &work, &unchanged),
                         ==, EXAMPLE_CREDENTIAL_ERROR);
        request.security.objects = security_objects;
        request.required_objects |= 1u << 31;
        work = WORK;
        munit_assert_int(example_credential_validate(&request, &card_context, &content_context,
                                                     &work, &unchanged),
                         ==, EXAMPLE_CREDENTIAL_ERROR);
        request.required_objects &= ~(1u << 31);
        request.required_objects |= EXAMPLE_CREDENTIAL_REQUIRE_IRIS;
        work = WORK;
        munit_assert_int(example_credential_validate(&request, &card_context, &content_context,
                                                     &work, &unchanged),
                         ==, EXAMPLE_CREDENTIAL_UNAVAILABLE);
        request.required_objects &= ~EXAMPLE_CREDENTIAL_REQUIRE_IRIS;
        munit_assert_uint(proof.calls, ==, calls);
        if (profile != TC_PIV_CARD) {
          request.profile = TC_TWIC_LEGACY_CARD;
          work = WORK;
          munit_assert_int(example_credential_validate(&request, &card_context, &content_context,
                                                       &work, &unchanged),
                           ==, EXAMPLE_CREDENTIAL_INVALID);
        }
      }
    } else
      munit_assert_memory_equal(sizeof result, &result, &unchanged);
    if (variant == CANCELLED || variant == STALE || variant == EXHAUSTED ||
        variant == MISSING_CRL || variant == REVOKED_CARD || variant == EXPIRED_CARD ||
        variant == WRONG_IDENTITY || variant == WRONG_ROOT || variant == MISSING_REQUIRED ||
        variant == CCL_LIMIT || variant == CARD_AUTHENTICATION_TWIC_READER ||
        (variant == ALTERNATE_EKU && profile == TC_PIV_CARD))
      munit_assert_uint(proof.calls, ==, 0);
    proof.ccl_store = NULL;
    proof.replacement_ccl = NULL;
    if (variant == TAMPERED)
      biometric[biometric_length - 1] ^= 1;
    munit_assert_int(TC_TWIC_CCL_store_release(held), ==, TC_TWIC_CCL_OK);
  }
  X509_free(certificate);
  EVP_PKEY_free(private_key);
  EVP_PKEY_free(wrong_root_key);
}

static MunitResult chuid_signature(const MunitParameter params[], void* user)
{
  enum {
    OBJECT_BYTES = 4096,
    CERT_BYTES = 1024,
    PREFIX_BYTES = 55,
    CMS_HEADER_BYTES = 4,
    FRAME_COUNT = 16,
    OID_COUNT = 16,
    WORK = 100000
  };
  uint8_t encoded[OBJECT_BYTES] = {0x30, 25}, certificate_bytes[CERT_BYTES], root_bytes[CERT_BYTES];
  memcpy(encoded + 2, test_card_fascn, sizeof test_card_fascn);
  uint8_t content[PREFIX_BYTES + 2], digest[TC_SHA256_DIGESTLEN];
  static const uint8_t content_type[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 6, 1};
  TC_TLV_frame frames[FRAME_COUNT];
  TC_bytes oids[OID_COUNT];
  const TC_TLV_limits limits = {OBJECT_BYTES, OBJECT_BYTES, 256, FRAME_COUNT};
  TC_X509_workspace parser = {{frames, FRAME_COUNT}, oids, OID_COUNT};
  TC_ECDSA_workspace ec;
  TC_RSA_word rsa_words[TC_RSA_VERIFY_WORKSPACE_WORDS(3072)];
  const TC_RSA_workspace rsa = {rsa_words, sizeof rsa_words / sizeof *rsa_words};
  const TC_X509_native_workspace native = {&ec, &rsa, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  const TC_X509_signature_provider provider = TC_X509_native_provider(&native);
  const TC_CMS_signature_workspace verification = {{frames, FRAME_COUNT}, NULL, 0};
  EVP_PKEY* key = EVP_EC_gen("prime256v1");
  EVP_PKEY* root_key = EVP_EC_gen("prime256v1");
  munit_assert_not_null(key);
  munit_assert_not_null(root_key);
  X509* root = make_certificate(root_key, "CHUID root", NULL);
  add_extension(root, NID_basic_constraints, "critical,CA:TRUE");
  add_extension(root, NID_key_usage, "critical,keyCertSign,cRLSign");
  const TC_bytes root_der = {
      root_bytes, encode_certificate(root, root_key, EVP_sha256(), root_bytes, sizeof root_bytes)};
  X509* certificate = make_certificate(key, "CHUID signer", root);
  add_extension(certificate, NID_basic_constraints, "critical,CA:FALSE");
  add_extension(certificate, NID_key_usage, "critical,digitalSignature");
  const char* signer_profile = munit_parameters_get(params, "signer-profile");
  const int twic_purpose = !strcmp(signer_profile, "twic");
  const int both_purposes = !strcmp(signer_profile, "both");
  const int wrong_signer_name = !strcmp(signer_profile, "wrong-name");
  add_extension(certificate, NID_ext_key_usage,
                both_purposes  ? "2.16.840.1.101.3.6.7,1.3.6.1.4.1.29138.6.7"
                : twic_purpose ? "1.3.6.1.4.1.29138.6.7"
                               : "2.16.840.1.101.3.6.7");
  const char* signing_policy = munit_parameters_get(params, "policy");
  if (strcmp(signing_policy, "absent"))
    add_extension(certificate, NID_certificate_policies,
                  !strcmp(signing_policy, "required") ? "2.16.840.1.101.3.2.1.3.39"
                  : !strcmp(signing_policy, "any")    ? "2.5.29.32.0"
                                                      : "1.2.3.4");
  size_t certificate_length = encode_certificate(certificate, root_key, EVP_sha256(),
                                                 certificate_bytes, sizeof certificate_bytes);
  TC_X509_certificate signer_certificate;
  munit_assert_int(TC_X509_read((TC_bytes){certificate_bytes, certificate_length}, &limits, &parser,
                                &signer_certificate),
                   ==, TC_TLV_OK);
  encoded[27] = 0x34;
  encoded[28] = 16;
  static const uint8_t card_guid[] = {0x91, 0xbe, 0x20, 0x94, 0xf6, 0xdc, 0x53, 0x49,
                                      0x80, 0,    0x40, 0x90, 0xe4, 0x9e, 0x50, 0x5c};
  memcpy(encoded + 29, card_guid, sizeof card_guid);
  encoded[45] = 0x35;
  encoded[46] = 8;
  memcpy(encoded + 47, "20260101", 8);
  memcpy(content, encoded, PREFIX_BYTES);
  content[PREFIX_BYTES] = 0xfe;
  content[PREFIX_BYTES + 1] = 0;
  const unsigned flags = CMS_BINARY | CMS_NOSMIMECAP | CMS_DETACHED;
  CMS_ContentInfo* cms = CMS_sign(certificate, key, NULL, NULL, flags | CMS_PARTIAL);
  BIO* input = BIO_new_mem_buf(content, sizeof content);
  ASN1_OBJECT* oid = OBJ_txt2obj("2.16.840.1.101.3.6.1", 1);
  munit_assert_not_null(cms);
  munit_assert_not_null(input);
  munit_assert_not_null(oid);
  munit_assert_int(CMS_set1_eContentType(cms, oid), ==, 1);
  set_cms_signer_name(cms, X509_get_subject_name(wrong_signer_name ? root : certificate));
  const char* fascn_namespace = munit_parameters_get(params, "fascn");
  const int has_fascn = strcmp(fascn_namespace, "absent") != 0;
  const int has_uuid = strcmp(munit_parameters_get(params, "uuid"), "present") == 0;
  if (has_fascn)
    add_cms_octet_attribute(cms,
                            strcmp(fascn_namespace, "twic") == 0 ? "1.3.6.1.4.1.29138.6.6"
                                                                 : "2.16.840.1.101.3.6.6",
                            encoded + 2, encoded[1]);
  if (has_uuid)
    add_cms_octet_attribute(cms, "1.3.6.1.1.16.4", encoded + 29, encoded[28]);
  munit_assert_int(CMS_final(cms, input, NULL, flags), ==, 1);
  int cms_length = i2d_CMS_ContentInfo(cms, NULL);
  munit_assert_int(cms_length, >, 0);
  munit_assert_size((size_t)cms_length, <=, sizeof encoded - PREFIX_BYTES - CMS_HEADER_BYTES - 2);
  encoded[PREFIX_BYTES] = 0x3e;
  encoded[PREFIX_BYTES + 1] = 0x82;
  encoded[PREFIX_BYTES + 2] = (uint8_t)((unsigned)cms_length >> 8);
  encoded[PREFIX_BYTES + 3] = (uint8_t)cms_length;
  unsigned char* cursor = encoded + PREFIX_BYTES + CMS_HEADER_BYTES;
  munit_assert_int(i2d_CMS_ContentInfo(cms, &cursor), ==, cms_length);
  *cursor++ = 0xfe;
  *cursor++ = 0;
  const size_t length = (size_t)(cursor - encoded);
  for (unsigned profile = TC_CHUID_PROFILE_PIV; profile <= TC_CHUID_PROFILE_TWIC_SIGNED;
       ++profile) {
    TC_PIV_CHUID chuid;
    TC_PIV_CMS_object object;
    size_t work = WORK;
    munit_assert_int(TC_PIV_CHUID_read((TC_bytes){encoded, length}, TC_PIV_CHUID_CONTENTS,
                                       (TC_PIV_CHUID_profile)profile, &chuid),
                     ==, TC_TLV_OK);
    munit_assert_int(TC_PIV_CMS_read(chuid.signature, TC_PIV_CMS_CHUID,
                                     &(TC_CMS_verification_policy){
                                         .attribute_oids = TC_CMS_ATTRIBUTE_OIDS_PIV_TWIC},
                                     &limits, (TC_TLV_frames){frames, FRAME_COUNT}, &work, &object),
                     ==, TC_TLV_OK);
    TC_CMS_signer_info signer = object.signer;
    TC_CMS_signed_attributes attributes = object.attributes;
    munit_assert_size(object.certificate.length, ==, certificate_length);
    munit_assert_memory_equal(certificate_length, object.certificate.data, certificate_bytes);
    /* Authenticate the detached object and check its content signer's CRL. */
    {
      enum { CLEAR, REVOKED, WRONG_ROOT, ALTERED_CONTENT, TRUST_CASES, TRUST_WORK = 1000000 };
      static const uint8_t content_signing[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 6, 7};
      static const uint8_t twic_content_signing[] = {0x2b, 6, 1, 4, 1, 0x81, 0xe3, 0x52, 6, 7};
      TC_X509_certificate parsed_root;
      munit_assert_int(TC_X509_read(root_der, &limits, &parser, &parsed_root), ==, TC_TLV_OK);
      TC_X509_store_anchor anchor = {.trust = {parsed_root.subject, parsed_root.public_key},
                                     .usage = TC_X509_ANCHOR_USAGE_CRL_SIGN};
      const TC_X509_store_source anchors = {&anchor, 0, 1, NULL, crl_trust_anchor};
      candidate_source supplied = {&root_der, 1, 0, TC_TLV_OK, 0};
      const TC_X509_store_source issuers = {&supplied, 1, 0, read_candidate, NULL};
      combined_store_source combined = {&issuers, &anchors};
      const TC_X509_store_source source = {&combined, 1, 1, combined_candidate, combined_anchor};
      TC_X509_store store = {0};
      TC_X509_store_snapshot slot = {0};
      munit_assert_int(TC_X509_store_prepare(&slot, &source), ==, TC_TLV_OK);
      munit_assert_int(TC_X509_store_publish(&store, 0, &slot), ==, TC_TLV_OK);
      TC_CMS_path_options options = {0};
      options.path.at = (TC_X509_time){2026, 1, 1, 0, 0, 0};
      options.path.parsing = limits;
      options.path.max_certificates = EXAMPLE_X509_PATH_CAPACITY;
      options.path.max_input = OBJECT_BYTES;
      options.path.max_work = TRUST_WORK;
      options.path.signatures = provider;
      options.path.purpose = twic_purpose
                                 ? (TC_bytes){twic_content_signing, sizeof twic_content_signing}
                                 : (TC_bytes){content_signing, sizeof content_signing};
      options.path.key_usage = TC_KEY_USAGE_DIGITAL_SIGNATURE;
      options.path.flags = TC_X509_PATH_REQUIRE_KEY_USAGE |
                           TC_X509_PATH_REQUIRE_EXTENDED_KEY_USAGE |
                           TC_X509_PATH_INHIBIT_ANY_PURPOSE;
      options.max_candidates = EXAMPLE_CMS_CERTIFICATE_CAPACITY;
      options.max_candidate_bytes = OBJECT_BYTES;
      options.verification.attribute_oids = TC_CMS_ATTRIBUTE_OIDS_PIV_TWIC;
      TC_X509_path_options crl_policy = options.path;
      crl_policy.purpose = (TC_bytes){NULL, 0};
      crl_policy.key_usage = TC_KEY_USAGE_CRL_SIGN;
      crl_policy.flags = 0;
      ExampleCMSCredentialWorkspace storage;
      const TC_CMS_validation_request request = {
          chuid.signature,      0, {content_type, sizeof content_type},
          chuid.signed_content, 2, {NULL, 0}};
      for (unsigned variant = 0; variant < TRUST_CASES; ++variant) {
        uint8_t crl_bytes[CERT_BYTES];
        const TC_bytes crl = {crl_bytes, encode_issuer_crl(root, root_key,
                                                           variant == REVOKED ? certificate : NULL,
                                                           crl_bytes, sizeof crl_bytes)};
        TC_X509_crl_record record;
        TC_X509_crl_index index;
        work = TRUST_WORK;
        munit_assert_int(
            TC_X509_crl_index_init(&crl, 1, &limits, &parser, &work, &record, 1, &index), ==,
            TC_TLV_OK);
        const TC_CMS_revocation_policy revocation = {
            &index, &crl_policy, OBJECT_BYTES, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER};
        if (variant == WRONG_ROOT)
          anchor.trust.public_key = signer_certificate.public_key;
        if (variant == ALTERED_CONTENT)
          encoded[29] ^= 1;
        work = TRUST_WORK;
        munit_assert_int(example_validate_cms_from_store(&request, &store, &options, &revocation,
                                                         &work, &storage),
                         ==,
                         wrong_signer_name    ? TC_CREDENTIAL_INVALID
                         : variant == CLEAR   ? TC_CREDENTIAL_VALID
                         : variant == REVOKED ? TC_CREDENTIAL_REVOKED
                                              : TC_CREDENTIAL_INVALID);
        munit_assert_size(slot.readers, ==, 0);
        TC_X509_store_snapshot* held;
        munit_assert_int(TC_X509_store_acquire(&store, &held), ==, TC_TLV_OK);
        static const uint8_t uuid_urn[] = "urn:uuid:91be2094-f6dc-5349-8000-4090e49e505c";
        const TC_PIV_card_identifiers card = {
            chuid.fascn, {NULL, 0}, {uuid_urn, sizeof uuid_urn - 1}, {NULL, 0}};
        const TC_X509_time card_expiration = {2027, 1, 1, 0, 0, 0};
        const TC_PIV_CHUID_validation_request object_request = {
            {encoded, length},
            TC_PIV_CHUID_CONTENTS,
            profile == TC_CHUID_PROFILE_PIV ? TC_PIV_CARD : TC_TWIC_NEXGEN_CARD,
            profile,
            0,
            &card,
            &card_expiration};
        TC_CMS_path_workspace object_path = example_cms_path_workspace(&storage.cms);
        const TC_CMS_credential_workspace object_workspace =
            example_cms_credential_workspace(&storage, &object_path);
        TC_validation_options object_options;
        munit_assert_int(example_validation_options(&options, &revocation, &object_options), ==,
                         TC_RESULT_OK);
        const TC_validation_trust object_trust = {&held->source, revocation.index};
        TC_validation_context object_context;
        munit_assert_int(TC_validation_context_init(&object_trust, &object_options,
                                                    &object_workspace, &object_context),
                         ==, TC_RESULT_OK);
        TC_PIV_CHUID_report accepted_chuid;
        memset(&accepted_chuid, 0xa5, sizeof accepted_chuid);
        TC_PIV_CHUID_report saved_chuid;
        memcpy(&saved_chuid, &accepted_chuid, sizeof saved_chuid);
        work = TRUST_WORK;
        /* twicFASC-N lies outside the PIV attribute identifiers, so the PIV
         * profile reads it as an unsupported attribute. Altered content fails
         * the card binding before the signature object is read. */
        const int namespace_rejected = profile == TC_CHUID_PROFILE_PIV &&
                                       !strcmp(fascn_namespace, "twic") &&
                                       variant != ALTERED_CONTENT;
        const int profile_rejected = namespace_rejected || (profile == TC_CHUID_PROFILE_PIV &&
                                                            strcmp(signing_policy, "required"));
        const int purpose_rejected = profile == TC_CHUID_PROFILE_PIV && twic_purpose;
        memset(&storage, 0xa5, sizeof storage);
        const uint8_t* wiped = (const uint8_t*)&storage;
        munit_assert_int(
            TC_PIV_CHUID_validate(&object_request, &object_context, &work, &accepted_chuid), ==,
            purpose_rejected                        ? TC_CREDENTIAL_ERROR
            : namespace_rejected                    ? TC_CREDENTIAL_UNSUPPORTED
            : profile_rejected || wrong_signer_name ? TC_CREDENTIAL_INVALID
            : variant == CLEAR                      ? TC_CREDENTIAL_VALID
            : variant == REVOKED                    ? TC_CREDENTIAL_REVOKED
                                                    : TC_CREDENTIAL_INVALID);
        if (variant == CLEAR && profile == TC_CHUID_PROFILE_PIV &&
            !strcmp(signing_policy, "absent") && !twic_purpose && !wrong_signer_name &&
            strcmp(fascn_namespace, "twic")) {
          TC_PIV_CHUID_validation_request twic_reader = object_request;
          twic_reader.twic_reader_policy = 1;
          work = TRUST_WORK;
          munit_assert_int(
              TC_PIV_CHUID_validate(&twic_reader, &object_context, &work, &accepted_chuid), ==,
              TC_CREDENTIAL_INVALID);
        }
        if (purpose_rejected)
          munit_assert_size(work, ==, TRUST_WORK);
        if (!purpose_rejected && !profile_rejected && !wrong_signer_name && variant == CLEAR) {
          munit_assert_ptr_equal(accepted_chuid.object.fascn.data, chuid.fascn.data);
          munit_assert_size(accepted_chuid.signer.length, ==, object.certificate.length);
          munit_assert_memory_equal(accepted_chuid.signer.length, accepted_chuid.signer.data,
                                    object.certificate.data);
          munit_assert_int(accepted_chuid.profile, ==, object_request.profile);
          TC_X509_validation_report signer_result;
          size_t certificate_work = TRUST_WORK;
          munit_assert_int(TC_X509_validate(accepted_chuid.signer, &object_context,
                                            &certificate_work, &signer_result),
                           ==, TC_CREDENTIAL_VALID);
          munit_assert_ptr_equal(signer_result.certificate.encoded.data,
                                 accepted_chuid.signer.data);
          munit_assert_int(signer_result.at.year, ==, object_options.at.year);
          /* A result sharing bytes with the scopes, signer_path or
           * signer_policies scratch is ERROR before any work. */
          for (unsigned area = 0; area < 3; ++area) {
            union {
              TC_PIV_CHUID_report result;
              TC_X509_revocation_scope scopes[EXAMPLE_CMS_CRL_CAPACITY];
              TC_bytes signer_path[EXAMPLE_X509_PATH_CAPACITY];
              TC_bytes signer_policies[EXAMPLE_X509_POLICY_CAPACITY];
            } shared;
            TC_CMS_credential_workspace result_alias = object_workspace;
            if (area == 0)
              result_alias.scopes = shared.scopes;
            if (area == 1)
              result_alias.signer_path = shared.signer_path;
            if (area == 2)
              result_alias.signer_policies = shared.signer_policies;
            TC_validation_context result_context;
            munit_assert_int(TC_validation_context_init(&object_trust, &object_options,
                                                        &result_alias, &result_context),
                             ==, TC_RESULT_OK);
            uint8_t saved_shared[sizeof shared];
            memset(&shared, 0xa5, sizeof shared);
            memcpy(saved_shared, &shared, sizeof shared);
            size_t alias_work = TRUST_WORK;
            munit_assert_int(TC_PIV_CHUID_validate(&object_request, &result_context, &alias_work,
                                                   &shared.result),
                             ==, TC_CREDENTIAL_ERROR);
            munit_assert_size(alias_work, ==, TRUST_WORK);
            munit_assert_memory_equal(sizeof shared, &shared, saved_shared);
          }
          if (object_request.profile != TC_PIV_CARD) {
            TC_validation_options alias_options = object_options;
            alias_options.certificate.purpose =
                twic_purpose ? (TC_bytes){content_signing, sizeof content_signing}
                             : (TC_bytes){twic_content_signing, sizeof twic_content_signing};
            TC_validation_context alias_context;
            munit_assert_int(TC_validation_context_init(&object_trust, &alias_options,
                                                        &object_workspace, &alias_context),
                             ==, TC_RESULT_OK);
            TC_PIV_CHUID_report alias_result;
            size_t alias_work = TRUST_WORK;
            munit_assert_int(
                TC_PIV_CHUID_validate(&object_request, &alias_context, &alias_work, &alias_result),
                ==, TC_CREDENTIAL_VALID);
          }
          memset(&storage, 0, sizeof storage);
          munit_assert_memory_equal(accepted_chuid.signer.length, accepted_chuid.signer.data,
                                    object.certificate.data);
        } else
          munit_assert_memory_equal(sizeof saved_chuid, &saved_chuid, &accepted_chuid);
        if (variant == CLEAR && !strcmp(fascn_namespace, "piv") && has_uuid &&
            !strcmp(signing_policy, "required") && !strcmp(signer_profile, "piv")) {
          const size_t chuid_work = work;
          /* The CHUID accepted in this evaluation, as TC_PIV_CHUID_validate
           * reports it. Dependent objects take identifiers and the signer from it. */
          TC_PIV_CHUID_report bound_chuid = {chuid, object.certificate, object_options.at,
                                             object_request.profile, 1};
          TC_PIV_biometric_report biometric_result;
          {
            uint8_t security[OBJECT_BYTES];
            uint8_t unsigned_chuid[PREFIX_BYTES + 2];
            memcpy(unsigned_chuid, encoded, PREFIX_BYTES);
            unsigned_chuid[PREFIX_BYTES] = 0xfe;
            unsigned_chuid[PREFIX_BYTES + 1] = 0;
            const TC_bytes contents[] = {{encoded, length},
                                         {unsigned_chuid, sizeof unsigned_chuid}};
            /* GET DATA's response wrapper is outside the stored object content.
             */
            const uint8_t response_header[] = {0x53, 0x82, (uint8_t)(length >> 8), (uint8_t)length};
            const TC_bytes wrapped[] = {{response_header, sizeof response_header}, contents[0]};
            const TC_bytes without_check = {unsigned_chuid, PREFIX_BYTES};
            const size_t security_length =
                encode_security_object(certificate, key, contents, security, sizeof security);
            ExampleSecurityData inventory[] = {{0x3000, &contents[0], 1},
                                               {0x3002, &contents[1], 1}};
            ExampleSecurityRequest security_request = {{security, security_length},
                                                       TC_PIV_SECURITY_CONTENTS,
                                                       object_request.profile,
                                                       &bound_chuid,
                                                       &card_expiration,
                                                       inventory,
                                                       2};
            ExampleSecurityWorkspace security_storage;
            work = TRUST_WORK;
            munit_assert_int(example_validate_security(&security_request, held, &options,
                                                       &revocation, &work, &security_storage),
                             ==, TC_CREDENTIAL_VALID);
            const uint8_t* cleared = (const uint8_t*)&security_storage;
            for (size_t i = 0; i < sizeof security_storage; ++i)
              munit_assert_uint(cleared[i], ==, 0);
            if (object_request.profile == TC_TWIC_NEXGEN_CARD) {
              static const uint8_t printed[] = {
                  0x01, 0x04, 'T', 'E', 'S', 'T', 0x02, 0x00, 0x04, 0x09, '0',
                  '1',  'J',  'A', 'N', '2', '0', '2',  '6',  0x05, 0x08, '1',
                  '2',  '3',  '4', '5', '6', '7', '8',  0x06, 0x08, '7',  '0',
                  '9',  '9',  '1', '2', '3', '4', 0x07, 0x00, 0x08, 0x00};
              static const uint8_t record[] = {1, 2, 3, 4};
              const TC_TWIC_tpk privacy_key = {{0}};
              uint8_t printed_cipher[64], biometric_cipher[34], mixed_security[OBJECT_BYTES];
              memcpy(printed_cipher, printed, sizeof printed);
              memcpy(biometric_cipher + 2, record, sizeof record);
              size_t printed_length, biometric_length;
              munit_assert_int(TC_TWIC_object_encrypt(
                                   &privacy_key, (TC_buffer){printed_cipher, sizeof printed_cipher},
                                   sizeof printed, &printed_length),
                               ==, TC_OK);
              munit_assert_int(TC_TWIC_object_encrypt(
                                   &privacy_key,
                                   (TC_buffer){biometric_cipher + 2, sizeof biometric_cipher - 2},
                                   sizeof record, &biometric_length),
                               ==, TC_OK);
              biometric_cipher[0] = 0xbc;
              biometric_cipher[1] = (uint8_t)biometric_length;
              const uint16_t containers[] = {0x3001, 0x2003};
              const TC_bytes selected[] = {{printed, sizeof printed},
                                           {biometric_cipher, biometric_length + 2}};
              const size_t mixed_length = encode_security_inventory(
                  certificate, key, containers, selected, 2, mixed_security, sizeof mixed_security);
              TC_bytes supplied[] = {selected[0], selected[1]};
              ExampleSecurityData mixed_inventory[] = {{containers[0], &supplied[0], 1},
                                                       {containers[1], &supplied[1], 1}};
              ExampleSecurityRequest mixed_request = {{mixed_security, mixed_length},
                                                      TC_PIV_SECURITY_CONTENTS,
                                                      TC_TWIC_NEXGEN_CARD,
                                                      &bound_chuid,
                                                      &card_expiration,
                                                      mixed_inventory,
                                                      2};
              for (unsigned choice = 0; choice < 3; ++choice) {
                supplied[0] =
                    choice == 1 ? (TC_bytes){printed_cipher, printed_length} : selected[0];
                supplied[1] = choice == 2 ? (TC_bytes){record, sizeof record} : selected[1];
                work = TRUST_WORK;
                munit_assert_int(example_validate_security(&mixed_request, held, &options,
                                                           &revocation, &work, &security_storage),
                                 ==, choice == 0 ? TC_CREDENTIAL_VALID : TC_CREDENTIAL_INVALID);
              }
              const uint16_t full_containers[] = {0x3000, 0x3002, 0x3001};
              const TC_bytes full_contents[] = {
                  contents[0], contents[1], {printed, sizeof printed}};
              const size_t full_length =
                  encode_security_inventory(certificate, key, full_containers, full_contents, 3,
                                            mixed_security, sizeof mixed_security);
              ExampleSecurityData full_inventory[] = {{full_containers[0], &full_contents[0], 1},
                                                      {full_containers[1], &full_contents[1], 1},
                                                      {full_containers[2], &full_contents[2], 1}};
              credential_public_workflow(
                  &(credential_issuers){root, root_key, certificate, key}, TC_TWIC_NEXGEN_CARD, 0,
                  &(credential_objects){contents[0], (TC_bytes){mixed_security, full_length},
                                        full_inventory, 3, contents[1], full_contents[2]},
                  &object_context);
            }
            if (object_request.profile != TC_PIV_CARD) {
              TC_CMS_path_workspace security_path =
                  example_cms_path_workspace(&security_storage.credential.cms);
              const TC_CMS_credential_workspace security_credential =
                  example_cms_credential_workspace(&security_storage.credential, &security_path);
              const TC_PIV_security_validation_workspace security_workspace = {
                  security_storage.content, sizeof security_storage.content};
              TC_validation_context security_context;
              TC_PIV_security_report accepted_security;
              const TC_TWIC_unsigned_CHUID_validation_request unsigned_request = {
                  contents[1], TC_PIV_CHUID_CONTENTS, object_request.profile, &card,
                  &accepted_security};
              munit_assert_int(TC_validation_context_init(&object_trust, &object_options,
                                                          &security_credential, &security_context),
                               ==, TC_RESULT_OK);
              work = TRUST_WORK;
              munit_assert_int(TC_PIV_security_validate(&security_request, &security_context,
                                                        &security_workspace, &work,
                                                        &accepted_security),
                               ==, TC_CREDENTIAL_VALID);
              munit_assert_int(
                  TC_TWIC_unsigned_CHUID_validate(&unsigned_request, &security_context, &work), ==,
                  TC_CREDENTIAL_VALID);
              munit_assert_ptr_equal(accepted_security.objects, inventory);
              memset(&security_storage, 0, sizeof security_storage);
              munit_assert_int(
                  TC_TWIC_unsigned_CHUID_validate(&unsigned_request, &security_context, &work), ==,
                  TC_CREDENTIAL_VALID);
              /* Counter aliases must leave the retained evidence unchanged. */
              TC_TWIC_unsigned_CHUID_validation_request overlapping_request = unsigned_request;
              const size_t encoded_length = overlapping_request.encoded.length;
              munit_assert_int(TC_TWIC_unsigned_CHUID_validate(&overlapping_request,
                                                               &security_context,
                                                               &overlapping_request.encoded.length),
                               ==, TC_CREDENTIAL_ERROR);
              munit_assert_size(overlapping_request.encoded.length, ==, encoded_length);
              const size_t part_length = contents[1].length;
              munit_assert_int(TC_TWIC_unsigned_CHUID_validate(&unsigned_request, &security_context,
                                                               (size_t*)&contents[1].length),
                               ==, TC_CREDENTIAL_ERROR);
              munit_assert_size(contents[1].length, ==, part_length);
              const size_t signer_length = accepted_security.signer.length;
              munit_assert_int(TC_TWIC_unsigned_CHUID_validate(&unsigned_request, &security_context,
                                                               &accepted_security.signer.length),
                               ==, TC_CREDENTIAL_ERROR);
              munit_assert_size(accepted_security.signer.length, ==, signer_length);
              const size_t input_limit = object_options.parsing.max_input;
              munit_assert_int(TC_TWIC_unsigned_CHUID_validate(&unsigned_request, &security_context,
                                                               &object_options.parsing.max_input),
                               ==, TC_CREDENTIAL_ERROR);
              munit_assert_size(object_options.parsing.max_input, ==, input_limit);
              TC_validation_options next_time = object_options;
              next_time.at.second = 1;
              TC_validation_context later_context = security_context;
              later_context.options = &next_time;
              munit_assert_int(
                  TC_TWIC_unsigned_CHUID_validate(&unsigned_request, &later_context, &work), ==,
                  TC_CREDENTIAL_ERROR);
              const size_t before_overlap = work;
              munit_assert_int(TC_PIV_security_validate(
                                   &security_request, &security_context, &security_workspace, &work,
                                   (TC_PIV_security_report*)security_storage.content),
                               ==, TC_CREDENTIAL_ERROR);
              munit_assert_size(work, ==, before_overlap);
              credential_public_workflow(
                  &(credential_issuers){root, root_key, certificate, key}, object_request.profile,
                  0,
                  &(credential_objects){contents[0], (TC_bytes){security, security_length},
                                        inventory, 2, contents[1], (TC_bytes){0}},
                  &object_context);
            }
            if (object_request.profile == TC_PIV_CARD)
              credential_public_workflow(
                  &(credential_issuers){root, root_key, certificate, key}, TC_PIV_CARD, 0,
                  &(credential_objects){contents[0], (TC_bytes){security, security_length},
                                        inventory, 2, (TC_bytes){0}, (TC_bytes){0}},
                  &object_context);
            if (object_request.profile == TC_PIV_CARD)
              credential_public_workflow(
                  &(credential_issuers){root, root_key, certificate, key}, TC_PIV_CARD, 256,
                  &(credential_objects){contents[0], (TC_bytes){security, security_length},
                                        inventory, 2, (TC_bytes){0}, (TC_bytes){0}},
                  &object_context);
            if (object_request.profile == TC_PIV_CARD)
              credential_public_workflow(
                  &(credential_issuers){root, root_key, certificate, key}, TC_PIV_CARD, 384,
                  &(credential_objects){contents[0], (TC_bytes){security, security_length},
                                        inventory, 2, (TC_bytes){0}, (TC_bytes){0}},
                  &object_context);
            enum {
              MISSING,
              EXTRA,
              DUPLICATE,
              WRONG_BYTES,
              WRONG_MAP,
              WRONG_SIGNER,
              RESPONSE_WRAPPER,
              OMITTED_CHECK,
              EMPTY_PARTS,
              NO_WORK,
              SECURITY_CASES
            };
            for (unsigned failure = 0; failure < SECURITY_CASES; ++failure) {
              security_request.count = failure == MISSING ? 1 : 2;
              inventory[1].container = failure == EXTRA       ? 0x9999
                                       : failure == DUPLICATE ? 0x3000
                                                              : 0x3002;
              inventory[1].parts = failure == WRONG_BYTES ? &contents[0] : &contents[1];
              inventory[0].parts = failure == RESPONSE_WRAPPER ? wrapped : &contents[0];
              inventory[0].count = failure == RESPONSE_WRAPPER ? 2 : 1;
              if (failure == EMPTY_PARTS)
                inventory[0].count = 0;
              if (failure == OMITTED_CHECK)
                inventory[1].parts = &without_check;
              TC_PIV_CHUID_report wrong_signer = bound_chuid;
              wrong_signer.signer = root_der;
              security_request.chuid = failure == WRONG_SIGNER ? &wrong_signer : &bound_chuid;
              if (failure == WRONG_MAP)
                security[4] = 1;
              work = failure == NO_WORK ? 0 : TRUST_WORK;
              munit_assert_int(example_validate_security(&security_request, held, &options,
                                                         &revocation, &work, &security_storage),
                               ==,
                               failure == NO_WORK       ? TC_CREDENTIAL_LIMIT
                               : failure == EMPTY_PARTS ? TC_CREDENTIAL_ERROR
                                                        : TC_CREDENTIAL_INVALID);
              if (failure == MISSING || failure == DUPLICATE || failure == EMPTY_PARTS)
                munit_assert_size(work, ==, TRUST_WORK);
              security[4] = 0;
            }
            work = TRUST_WORK;
            uint8_t revoked_crl_bytes[CERT_BYTES];
            const TC_bytes revoked_crl = {
                revoked_crl_bytes, encode_issuer_crl(root, root_key, certificate, revoked_crl_bytes,
                                                     sizeof revoked_crl_bytes)};
            TC_X509_crl_record revoked_record;
            TC_X509_crl_index revoked_index;
            munit_assert_int(TC_X509_crl_index_init(&revoked_crl, 1, &limits, &parser, &work,
                                                    &revoked_record, 1, &revoked_index),
                             ==, TC_TLV_OK);
            TC_CMS_revocation_policy revoked_options = revocation;
            revoked_options.index = &revoked_index;
            work = TRUST_WORK;
            munit_assert_int(example_validate_security(&security_request, held, &options,
                                                       &revoked_options, &work, &security_storage),
                             ==, TC_CREDENTIAL_REVOKED);
          }
          uint8_t biometric[OBJECT_BYTES];
          const size_t biometric_length = encode_biometric(
              certificate, key, 0, chuid.fascn, chuid.card_uuid, biometric, sizeof biometric);
          ExampleBiometricRequest biometric_request = {{biometric, biometric_length},
                                                       object_request.profile,
                                                       &bound_chuid,
                                                       &card_expiration,
                                                       TC_PIV_CMS_BIOMETRIC,
                                                       TC_PIV_CBEFF_FINGERPRINT_TEMPLATE,
                                                       0};
          {
            uint8_t encrypted[OBJECT_BYTES], recovered[OBJECT_BYTES];
            const TC_TWIC_tpk privacy_key = {
                {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}};
            EVP_CIPHER_CTX* cipher = EVP_CIPHER_CTX_new();
            munit_assert_not_null(cipher);
            munit_assert_int(
                EVP_EncryptInit_ex(cipher, EVP_aes_128_ecb(), NULL, privacy_key.key, NULL), ==, 1);
            int written, tail;
            munit_assert_int(
                EVP_EncryptUpdate(cipher, encrypted, &written, biometric, (int)biometric_length),
                ==, 1);
            munit_assert_int(EVP_EncryptFinal_ex(cipher, encrypted + written, &tail), ==, 1);
            const size_t encrypted_length = (size_t)written + (size_t)tail;
            EVP_CIPHER_CTX_free(cipher);
            for (unsigned wrong_key = 0; wrong_key < 2; ++wrong_key) {
              TC_TWIC_tpk selected_key = privacy_key;
              selected_key.key[0] ^= (uint8_t)wrong_key;
              memcpy(recovered, encrypted, encrypted_length);
              size_t plaintext_length = 0;
              TC_credential_status authenticated = TC_CREDENTIAL_INVALID;
              if (TC_TWIC_object_decrypt(&selected_key, (TC_buffer){recovered, encrypted_length},
                                         &plaintext_length) == TC_OK) {
                ExampleBiometricRequest decrypted = biometric_request;
                decrypted.encoded = (TC_bytes){recovered, plaintext_length};
                work = TRUST_WORK;
                authenticated = example_validate_biometric(&decrypted, held, &options, &revocation,
                                                           &work, &storage, &biometric_result);
              }
              if (wrong_key)
                munit_assert_int(authenticated, !=, TC_CREDENTIAL_VALID);
              else {
                munit_assert_int(authenticated, ==, TC_CREDENTIAL_VALID);
                munit_assert_size(plaintext_length, ==, biometric_length);
                munit_assert_memory_equal(biometric_length, recovered, biometric);
              }
              TC_secure_zero(recovered, sizeof recovered);
              TC_secure_zero(&selected_key, sizeof selected_key);
            }
          }
          enum {
            BIO_VALID,
            BIO_RECORD,
            BIO_HEADER,
            BIO_GUID,
            BIO_SIGNER,
            BIO_WORK,
            BIO_PROFILE,
            BIO_FORMAT,
            BIO_IRIS,
            BIO_DATE,
            BIO_EXPIRED,
            BIO_CASES
          };
          for (unsigned check = 0; check < BIO_CASES; ++check) {
            ExampleBiometricRequest changed = biometric_request;
            TC_PIV_CHUID_report changed_chuid = bound_chuid;
            changed.chuid = &changed_chuid;
            uint8_t other_guid[16];
            memcpy(other_guid, chuid.card_uuid.data, sizeof other_guid);
            other_guid[0] ^= 1;
            if (check == BIO_RECORD)
              biometric[88] ^= 1;
            if (check == BIO_HEADER)
              biometric[59] ^= 1;
            if (check == BIO_GUID)
              changed_chuid.object.card_uuid = (TC_bytes){other_guid, sizeof other_guid};
            if (check == BIO_SIGNER)
              changed_chuid.signer = root_der;
            if (check == BIO_PROFILE)
              changed.signature_profile = TC_PIV_CMS_CHUID;
            if (check == BIO_FORMAT)
              changed.format = TC_PIV_CBEFF_FACE_IMAGE;
            if (check == BIO_IRIS)
              changed.format = TC_PIV_CBEFF_IRIS_IMAGE;
            if (check == BIO_DATE || check == BIO_EXPIRED)
              changed.require_current = 1;
            TC_CMS_path_options biometric_options = options;
            TC_X509_path_options biometric_crl_policy = crl_policy;
            TC_CMS_revocation_policy biometric_revocation = revocation;
            if (check == BIO_EXPIRED) {
              biometric_options.path.at.year = 2029;
              changed_chuid.at = biometric_options.path.at;
              biometric_crl_policy.at = biometric_options.path.at;
              biometric_revocation.signer_policy = &biometric_crl_policy;
            }
            work = check == BIO_WORK ? 0 : TRUST_WORK;
            memset(&storage, 0xa5, sizeof storage);
            munit_assert_int(example_validate_biometric(&changed, held, &biometric_options,
                                                        &biometric_revocation, &work, &storage,
                                                        &biometric_result),
                             ==,
                             check == BIO_PROFILE                      ? TC_CREDENTIAL_ERROR
                             : check == BIO_IRIS                       ? TC_CREDENTIAL_UNSUPPORTED
                             : check == BIO_VALID || check == BIO_DATE ? TC_CREDENTIAL_VALID
                             : check == BIO_WORK                       ? TC_CREDENTIAL_LIMIT
                                                                       : TC_CREDENTIAL_INVALID);
            for (size_t i = 0; i < sizeof storage; ++i)
              munit_assert_uint(wiped[i], ==, 0);
            if (check == BIO_PROFILE)
              munit_assert_size(work, ==, TRUST_WORK);
            if (check == BIO_RECORD)
              biometric[88] ^= 1;
            if (check == BIO_HEADER)
              biometric[59] ^= 1;
          }
          for (unsigned attributes = 0; attributes < 4; ++attributes) {
            const TC_bytes empty = {NULL, 0};
            ExampleBiometricRequest legacy = biometric_request;
            legacy.encoded.length = encode_biometric(
                certificate, key, 0, attributes & 1 ? chuid.fascn : empty,
                attributes & 2 ? chuid.card_uuid : empty, biometric, sizeof biometric);
            for (unsigned selected = 0; selected < 2; ++selected) {
              legacy.signature_profile =
                  selected ? TC_PIV_CMS_BIOMETRIC_FIPS201_1 : TC_PIV_CMS_BIOMETRIC;
              work = TRUST_WORK;
              munit_assert_int(example_validate_biometric(&legacy, held, &options, &revocation,
                                                          &work, &storage, &biometric_result),
                               ==,
                               (attributes & 1) && (selected || (attributes & 2))
                                   ? TC_CREDENTIAL_VALID
                                   : TC_CREDENTIAL_INVALID);
            }
          }
          EVP_PKEY* biometric_key = EVP_EC_gen("prime256v1");
          munit_assert_not_null(biometric_key);
          X509* biometric_signer = make_certificate(biometric_key, "Biometric signer", root);
          munit_assert_int(ASN1_INTEGER_set(X509_get_serialNumber(biometric_signer), 2), ==, 1);
          add_extension(biometric_signer, NID_basic_constraints, "critical,CA:FALSE");
          add_extension(biometric_signer, NID_key_usage, "critical,digitalSignature");
          add_extension(biometric_signer, NID_ext_key_usage, "2.16.840.1.101.3.6.7");
          add_extension(biometric_signer, NID_certificate_policies, "2.16.840.1.101.3.2.1.3.39");
          uint8_t biometric_certificate[CERT_BYTES];
          /* Reissued certificates still carry the same mathematical key. */
          for (unsigned reissued = 0; reissued < 3; ++reissued) {
            X509* redundant = reissued ? biometric_signer : certificate;
            if (reissued) {
              munit_assert_int(
                  EVP_PKEY_set_utf8_string_param(key, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                                                 reissued == 2 ? "compressed" : "uncompressed"),
                  ==, 1);
              munit_assert_int(X509_set_pubkey(redundant, key), ==, 1);
              const size_t redundant_length =
                  encode_certificate(redundant, root_key, EVP_sha256(), biometric_certificate,
                                     sizeof biometric_certificate);
              TC_X509_certificate redundant_view;
              munit_assert_int(TC_X509_read((TC_bytes){biometric_certificate, redundant_length},
                                            &limits, &parser, &redundant_view),
                               ==, TC_TLV_OK);
              munit_assert_size(redundant_view.public_key.key.length, ==, reissued == 2 ? 33 : 65);
            }
            biometric_request.encoded.length = encode_biometric(
                redundant, key, 1, chuid.fascn, chuid.card_uuid, biometric, sizeof biometric);
            work = TRUST_WORK;
            munit_assert_int(example_validate_biometric(&biometric_request, held, &options,
                                                        &revocation, &work, &storage,
                                                        &biometric_result),
                             ==, TC_CREDENTIAL_INVALID);
          }
          munit_assert_int(EVP_PKEY_set_utf8_string_param(
                               key, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, "uncompressed"),
                           ==, 1);
          munit_assert_int(X509_set_pubkey(biometric_signer, biometric_key), ==, 1);
          (void)encode_certificate(biometric_signer, root_key, EVP_sha256(), biometric_certificate,
                                   sizeof biometric_certificate);
          biometric_request.encoded.length =
              encode_biometric(biometric_signer, biometric_key, 1, chuid.fascn, chuid.card_uuid,
                               biometric, sizeof biometric);
          work = TRUST_WORK;
          munit_assert_int(example_validate_biometric(&biometric_request, held, &options,
                                                      &revocation, &work, &storage,
                                                      &biometric_result),
                           ==, TC_CREDENTIAL_VALID);
          const size_t biometric_work = TRUST_WORK - work;
          work = biometric_work - 1;
          munit_assert_int(example_validate_biometric(&biometric_request, held, &options,
                                                      &revocation, &work, &storage,
                                                      &biometric_result),
                           ==, TC_CREDENTIAL_LIMIT);
          TC_CMS_path_options bounded = options;
          bounded.path.parsing.max_input = biometric_request.encoded.length - 1;
          work = TRUST_WORK;
          munit_assert_int(example_validate_biometric(&biometric_request, held, &bounded,
                                                      &revocation, &work, &storage,
                                                      &biometric_result),
                           ==, TC_CREDENTIAL_LIMIT);
          {
            uint8_t revoked_bytes[CERT_BYTES];
            const TC_bytes revoked_crl = {revoked_bytes,
                                          encode_issuer_crl(root, root_key, biometric_signer,
                                                            revoked_bytes, sizeof revoked_bytes)};
            TC_X509_crl_record revoked_record;
            TC_X509_crl_index revoked_index;
            work = TRUST_WORK;
            munit_assert_int(TC_X509_crl_index_init(&revoked_crl, 1, &limits, &parser, &work,
                                                    &revoked_record, 1, &revoked_index),
                             ==, TC_TLV_OK);
            TC_CMS_revocation_policy revoked_options = revocation;
            revoked_options.index = &revoked_index;
            work = TRUST_WORK;
            munit_assert_int(example_validate_biometric(&biometric_request, held, &options,
                                                        &revoked_options, &work, &storage,
                                                        &biometric_result),
                             ==, TC_CREDENTIAL_REVOKED);
          }
          /* Omission with a different signing key must fail CHUID signer
           * selection. */
          biometric_request.encoded.length =
              encode_biometric(biometric_signer, biometric_key, 0, chuid.fascn, chuid.card_uuid,
                               biometric, sizeof biometric);
          work = TRUST_WORK;
          munit_assert_int(example_validate_biometric(&biometric_request, held, &options,
                                                      &revocation, &work, &storage,
                                                      &biometric_result),
                           ==, TC_CREDENTIAL_INVALID);
          EVP_PKEY_free(biometric_key);
          static const unsigned rsa_sizes[] = {1024, 2048, 3072};
          for (size_t size = 0; size < sizeof rsa_sizes / sizeof *rsa_sizes; ++size) {
            EVP_PKEY* rsa_key = EVP_RSA_gen(rsa_sizes[size]);
            munit_assert_not_null(rsa_key);
            munit_assert_int(X509_set_pubkey(biometric_signer, rsa_key), ==, 1);
            const size_t rsa_certificate_length =
                encode_certificate(biometric_signer, root_key, EVP_sha256(), biometric_certificate,
                                   sizeof biometric_certificate);
            const TC_bytes rsa_certificate = {biometric_certificate, rsa_certificate_length};
            bound_chuid.signer = object.certificate;
            biometric_request.encoded.length =
                encode_biometric(biometric_signer, rsa_key, 1, chuid.fascn, chuid.card_uuid,
                                 biometric, sizeof biometric);
            work = TRUST_WORK;
            munit_assert_int(example_validate_biometric(&biometric_request, held, &options,
                                                        &revocation, &work, &storage,
                                                        &biometric_result),
                             ==, TC_CREDENTIAL_VALID);
            bound_chuid.signer = rsa_certificate;
            work = TRUST_WORK;
            munit_assert_int(example_validate_biometric(&biometric_request, held, &options,
                                                        &revocation, &work, &storage,
                                                        &biometric_result),
                             ==, TC_CREDENTIAL_INVALID);
            biometric_request.encoded.length =
                encode_biometric(biometric_signer, rsa_key, 0, chuid.fascn, chuid.card_uuid,
                                 biometric, sizeof biometric);
            work = TRUST_WORK;
            munit_assert_int(example_validate_biometric(&biometric_request, held, &options,
                                                        &revocation, &work, &storage,
                                                        &biometric_result),
                             ==, TC_CREDENTIAL_VALID);
            EVP_PKEY_free(rsa_key);
          }
          X509_free(biometric_signer);
          work = chuid_work;
        }
        if (variant == CLEAR && !purpose_rejected && !profile_rejected && !wrong_signer_name) {
          enum {
            WRONG_FASCN,
            WRONG_UUID,
            LATE_CARD_EXPIRATION,
            LAST_SECOND,
            EXPIRED_DATE,
            ZERO_WORK,
            SHORT_WORK,
            UNSIGNED_OBJECT,
            OBJECT_CASES
          };
          const size_t required_work = TRUST_WORK - work;
          for (unsigned check = 0; check < OBJECT_CASES; ++check) {
            TC_PIV_CHUID_validation_request changed = object_request;
            uint8_t unsigned_chuid[PREFIX_BYTES + 2];
            memcpy(unsigned_chuid, encoded, PREFIX_BYTES);
            unsigned_chuid[PREFIX_BYTES] = 0xfe;
            unsigned_chuid[PREFIX_BYTES + 1] = 0;
            if (check == UNSIGNED_OBJECT) {
              TC_PIV_CHUID unsigned_view;
              changed.encoded = (TC_bytes){unsigned_chuid, sizeof unsigned_chuid};
              munit_assert_int(TC_PIV_CHUID_read((TC_bytes){unsigned_chuid, sizeof unsigned_chuid},
                                                 TC_PIV_CHUID_CONTENTS,
                                                 TC_CHUID_PROFILE_TWIC_UNSIGNED, &unsigned_view),
                               ==, TC_TLV_OK);
            }
            TC_PIV_card_identifiers other_card = card;
            uint8_t other_fascn[25];
            memcpy(other_fascn, chuid.fascn.data, sizeof other_fascn);
            other_fascn[0] ^= 1;
            static const uint8_t other_uuid[] = "urn:uuid:91be2094-f6dc-5349-8000-000000005678";
            const TC_X509_time later = {2029, 1, 1, 0, 0, 0};
            TC_CMS_path_options changed_options = options;
            TC_X509_path_options changed_crl_policy = crl_policy;
            TC_CMS_revocation_policy changed_revocation = revocation;
            changed.card = &other_card;
            if (check == WRONG_FASCN)
              other_card.fascn = (TC_bytes){other_fascn, sizeof other_fascn};
            if (check == WRONG_UUID)
              other_card.uuid_urn = (TC_bytes){other_uuid, sizeof other_uuid - 1};
            if (check == LATE_CARD_EXPIRATION)
              changed.card_expiration = &later;
            if (check == LAST_SECOND)
              changed_options.path.at = (TC_X509_time){2026, 1, 1, 23, 59, 59};
            if (check == EXPIRED_DATE)
              changed_options.path.at.day = 2;
            changed_crl_policy.at = changed_options.path.at;
            changed_revocation.signer_policy = &changed_crl_policy;
            TC_validation_options changed_validation;
            munit_assert_int(example_validation_options(&changed_options, &changed_revocation,
                                                        &changed_validation),
                             ==, TC_RESULT_OK);
            TC_validation_context changed_context;
            munit_assert_int(TC_validation_context_init(&object_trust, &changed_validation,
                                                        &object_workspace, &changed_context),
                             ==, TC_RESULT_OK);
            work = check == ZERO_WORK ? 0 : check == SHORT_WORK ? required_work - 1 : TRUST_WORK;
            const TC_credential_status expected =
                check == ZERO_WORK || check == SHORT_WORK ? TC_CREDENTIAL_LIMIT
                : check == LAST_SECOND ||
                        (check == LATE_CARD_EXPIRATION && profile != TC_CHUID_PROFILE_PIV)
                    ? TC_CREDENTIAL_VALID
                    : TC_CREDENTIAL_INVALID;
            munit_assert_int(
                TC_PIV_CHUID_validate(&changed, &changed_context, &work, &accepted_chuid), ==,
                expected);
          }
        }
        munit_assert_int(TC_X509_store_release(held), ==, TC_TLV_OK);
        anchor.trust.public_key = parsed_root.public_key;
        if (variant == ALTERED_CONTENT)
          encoded[29] ^= 1;
      }
    }
    munit_assert_int(attributes.fascn_octets.data != NULL, ==, has_fascn);
    munit_assert_int(attributes.entry_uuid_octets.data != NULL, ==, has_uuid);
    int identifiers_match = -1;
    munit_assert_int(TC_PIV_CMS_identifiers_match(
                         &object, TC_PIV_CMS_CHUID, chuid.fascn, chuid.card_uuid, &limits,
                         (TC_TLV_frames){frames, FRAME_COUNT}, &work, &identifiers_match),
                     ==, TC_TLV_OK);
    munit_assert_int(identifiers_match, ==, 1);
    size_t identifier_values[2] = {0, 0};
    const TC_bytes identifiers[] = {attributes.fascn_octets, attributes.entry_uuid_octets};
    const TC_bytes expected[] = {chuid.fascn, chuid.card_uuid};
    for (size_t i = 0; i < sizeof identifiers / sizeof *identifiers; ++i) {
      if (!identifiers[i].data)
        continue;
      TC_TLV_reader octets;
      TC_TLV_element element;
      munit_assert_int(TC_TLV_reader_init(&octets, identifiers[i], TC_TLV_DER, &limits), ==,
                       TC_TLV_OK);
      munit_assert_int(TC_TLV_next(&octets, &element), ==, TC_TLV_OK);
      munit_assert_size(element.value.length, ==, expected[i].length);
      munit_assert_memory_equal(expected[i].length, element.value.data, expected[i].data);
      identifier_values[i] = (size_t)(element.value.data - encoded);
    }
    enum {
      ORIGINAL,
      CHANGED_UUID,
      OMITTED_FE,
      CHANGED_FASCN_ATTRIBUTE,
      CHANGED_UUID_ATTRIBUTE,
      VARIANTS
    };
    for (unsigned variant = ORIGINAL; variant < VARIANTS; ++variant) {
      if ((variant == CHANGED_FASCN_ATTRIBUTE && !has_fascn) ||
          (variant == CHANGED_UUID_ATTRIBUTE && !has_uuid))
        continue;
      struct TC_SHA256_ctx hash;
      if (variant == CHANGED_UUID)
        encoded[29] ^= 1;
      if (variant >= CHANGED_FASCN_ATTRIBUTE)
        encoded[identifier_values[variant - CHANGED_FASCN_ATTRIBUTE]] ^= 1;
      munit_assert_int(TC_SHA256_init(&hash), ==, TC_OK);
      for (size_t i = 0; i < (variant == OMITTED_FE ? 1u : 2u); ++i)
        munit_assert_int(TC_SHA256_update(&hash, chuid.signed_content[i]), ==, TC_OK);
      munit_assert_int(TC_SHA256_final(&hash, digest), ==, TC_OK);
      work = WORK;
      munit_assert_int(
          TC_CMS_signer_verify_digest(
              &(TC_CMS_signer_verify_request){&signer,
                                              (TC_bytes){content_type, sizeof content_type},
                                              {.attribute_oids = TC_CMS_ATTRIBUTE_OIDS_PIV_TWIC},
                                              &signer_certificate.public_key,
                                              &provider,
                                              &limits},
              (TC_bytes){digest, sizeof digest}, &verification, &work),
          ==, variant ? TC_X509_SIGNATURE_INVALID : TC_X509_SIGNATURE_VALID);
      if (variant == CHANGED_UUID)
        encoded[29] ^= 1;
      if (variant >= CHANGED_FASCN_ATTRIBUTE)
        encoded[identifier_values[variant - CHANGED_FASCN_ATTRIBUTE]] ^= 1;
    }
  }
  ASN1_OBJECT_free(oid);
  BIO_free(input);
  CMS_ContentInfo_free(cms);
  X509_free(certificate);
  EVP_PKEY_free(key);
  X509_free(root);
  EVP_PKEY_free(root_key);
  (void)user;
  return MUNIT_OK;
}

TC_TEST(sp800_73_4_chuid_key_map_signature)
{
  enum { CAPACITY = 2048, CERTIFICATE_BYTES = 1024, FRAMES = 16, OIDS = 16, WORK = 100000 };
  uint8_t encoded[CAPACITY], certificate_bytes[CERTIFICATE_BYTES];
  static const uint8_t signed_content[] = {
      0x30, 25,   0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce, 0x73, 0x9d,
      0x83, 0x68, 0x58, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0xc8, 0x42, 0x10, 0xc3,
      0xeb, 0x34, 16,   0x91, 0xbe, 0x20, 0x94, 0xf6, 0xdc, 0x53, 0x49, 0x80, 0x00,
      0x40, 0x90, 0xe4, 0x9e, 0x50, 0x5c, 0x35, 8,    '2',  '0',  '2',  '6',  '0',
      '1',  '0',  '1',  0x3d, 3,    0x01, 0x02, 0x03, 0xfe, 0};
  static const uint8_t content_type[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 6, 1};
  EVP_PKEY* key = EVP_EC_gen("prime256v1");
  munit_assert_not_null(key);
  X509* certificate = make_certificate(key, "SP 800-73-4 CHUID signer", NULL);
  add_extension(certificate, NID_basic_constraints, "critical,CA:FALSE");
  add_extension(certificate, NID_key_usage, "critical,digitalSignature");
  const size_t certificate_length = encode_certificate(certificate, key, EVP_sha256(),
                                                       certificate_bytes, sizeof certificate_bytes);
  const unsigned flags = CMS_BINARY | CMS_NOSMIMECAP | CMS_DETACHED;
  CMS_ContentInfo* cms = CMS_sign(certificate, key, NULL, NULL, flags | CMS_PARTIAL);
  BIO* input = BIO_new_mem_buf(signed_content, sizeof signed_content);
  ASN1_OBJECT* oid = OBJ_txt2obj("2.16.840.1.101.3.6.1", 1);
  munit_assert_not_null(cms);
  munit_assert_not_null(input);
  munit_assert_not_null(oid);
  munit_assert_int(CMS_set1_eContentType(cms, oid), ==, 1);
  set_cms_signer_name(cms, X509_get_subject_name(certificate));
  add_cms_octet_attribute(cms, "2.16.840.1.101.3.6.6", signed_content + 2, signed_content[1]);
  add_cms_octet_attribute(cms, "1.3.6.1.1.16.4", signed_content + 29, signed_content[28]);
  munit_assert_int(CMS_final(cms, input, NULL, flags), ==, 1);
  const int cms_length = i2d_CMS_ContentInfo(cms, NULL);
  munit_assert_int(cms_length, >, 0);
  const size_t prefix_length = sizeof signed_content - 2;
  munit_assert_size(prefix_length + 4 + (size_t)cms_length + 2, <=, sizeof encoded);
  memcpy(encoded, signed_content, prefix_length);
  encoded[prefix_length] = 0x3e;
  encoded[prefix_length + 1] = 0x82;
  encoded[prefix_length + 2] = (uint8_t)((unsigned)cms_length >> 8);
  encoded[prefix_length + 3] = (uint8_t)cms_length;
  unsigned char* cursor = encoded + prefix_length + 4;
  munit_assert_int(i2d_CMS_ContentInfo(cms, &cursor), ==, cms_length);
  *cursor++ = 0xfe;
  *cursor++ = 0;
  const size_t encoded_length = (size_t)(cursor - encoded);

  TC_PIV_CHUID chuid;
  munit_assert_int(TC_PIV_CHUID_read((TC_bytes){encoded, encoded_length}, TC_PIV_CHUID_CONTENTS,
                                     TC_CHUID_PROFILE_PIV_SP800_73_4, &chuid),
                   ==, TC_TLV_OK);
  TC_PIV_CHUID unchanged;
  memset(&unchanged, 0xa5, sizeof unchanged);
  TC_PIV_CHUID strict = unchanged;
  munit_assert_int(TC_PIV_CHUID_read((TC_bytes){encoded, encoded_length}, TC_PIV_CHUID_CONTENTS,
                                     TC_CHUID_PROFILE_PIV, &strict),
                   !=, TC_TLV_OK);
  munit_assert_memory_equal(sizeof strict, &strict, &unchanged);

  TC_TLV_frame frames[FRAMES];
  const TC_TLV_limits limits = {CAPACITY, CAPACITY, 256, FRAMES};
  TC_PIV_CMS_object object;
  size_t work = WORK;
  munit_assert_int(
      TC_PIV_CMS_read(chuid.signature, TC_PIV_CMS_CHUID,
                      &(TC_CMS_verification_policy){.attribute_oids = TC_CMS_ATTRIBUTE_OIDS_PIV},
                      &limits, (TC_TLV_frames){frames, FRAMES}, &work, &object),
      ==, TC_TLV_OK);
  TC_bytes oids[OIDS];
  TC_X509_workspace parser = {{frames, FRAMES}, oids, OIDS};
  TC_X509_certificate parsed_certificate;
  munit_assert_int(TC_X509_read((TC_bytes){certificate_bytes, certificate_length}, &limits, &parser,
                                &parsed_certificate),
                   ==, TC_TLV_OK);
  TC_ECDSA_workspace ec;
  const TC_X509_native_workspace native = {&ec, NULL, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  const TC_X509_signature_provider provider = TC_X509_native_provider(&native);
  const TC_CMS_signature_workspace signature = {{frames, FRAMES}, NULL, 0};
  for (unsigned changed = 0; changed < 2; ++changed) {
    uint8_t digest[TC_SHA256_DIGESTLEN];
    struct TC_SHA256_ctx hash;
    if (changed)
      encoded[prefix_length - 3] ^= 1;
    munit_assert_int(TC_SHA256_init(&hash), ==, TC_OK);
    for (size_t i = 0; i < 2; ++i)
      munit_assert_int(TC_SHA256_update(&hash, chuid.signed_content[i]), ==, TC_OK);
    munit_assert_int(TC_SHA256_final(&hash, digest), ==, TC_OK);
    work = WORK;
    munit_assert_int(
        TC_CMS_signer_verify_digest(
            &(TC_CMS_signer_verify_request){&object.signer,
                                            (TC_bytes){content_type, sizeof content_type},
                                            {.attribute_oids = TC_CMS_ATTRIBUTE_OIDS_PIV_TWIC},
                                            &parsed_certificate.public_key,
                                            &provider,
                                            &limits},
            (TC_bytes){digest, sizeof digest}, &signature, &work),
        ==, changed ? TC_X509_SIGNATURE_INVALID : TC_X509_SIGNATURE_VALID);
  }
  ASN1_OBJECT_free(oid);
  BIO_free(input);
  CMS_ContentInfo_free(cms);
  X509_free(certificate);
  EVP_PKEY_free(key);
  return MUNIT_OK;
}

TC_TEST(security_profile)
{
  enum { CAPACITY = 4096, FRAMES = 16, WORK = 100000 };
  static const uint8_t content[] = {0x30, 0};
  uint8_t encoded[CAPACITY], certificate_bytes[CAPACITY];
  TC_TLV_frame frames[FRAMES];
  TC_bytes oids[FRAMES];
  const TC_TLV_limits limits = {CAPACITY, CAPACITY, 256, FRAMES};
  TC_X509_workspace parser = {{frames, FRAMES}, oids, FRAMES};
  EVP_PKEY* key = EVP_EC_gen("prime256v1");
  munit_assert_not_null(key);
  X509* certificate = make_certificate(key, "Synthetic security-object signer", NULL);
  add_extension(certificate, NID_subject_key_identifier, "hash");
  const size_t certificate_length =
      encode_certificate(certificate, key, EVP_sha256(), certificate_bytes, CAPACITY);
  TC_X509_certificate parsed_certificate;
  munit_assert_int(TC_X509_read((TC_bytes){certificate_bytes, certificate_length}, &limits, &parser,
                                &parsed_certificate),
                   ==, TC_TLV_OK);
  TC_ECDSA_workspace ec;
  const TC_X509_native_workspace native = {&ec, NULL, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  const TC_X509_signature_provider provider = TC_X509_native_provider(&native);
  const TC_CMS_signature_workspace signature = {{frames, FRAMES}, NULL, 0};
  enum { VALID, DETACHED, EMBEDDED_CERTIFICATE, WRONG_TYPE, MRTD_TYPE, NO_ATTRIBUTES, VARIANTS };
  for (unsigned key_id = 0; key_id < 2; ++key_id) {
    for (unsigned variant = 0; variant < VARIANTS; ++variant) {
      unsigned flags = CMS_BINARY | CMS_NOSMIMECAP;
      if (key_id)
        flags |= CMS_USE_KEYID;
      if (variant != EMBEDDED_CERTIFICATE)
        flags |= CMS_NOCERTS;
      if (variant == DETACHED)
        flags |= CMS_DETACHED;
      if (variant == NO_ATTRIBUTES)
        flags |= CMS_NOATTR;
      CMS_ContentInfo* cms = CMS_sign(certificate, key, NULL, NULL, flags | CMS_PARTIAL);
      ASN1_OBJECT* oid = OBJ_txt2obj(variant == WRONG_TYPE  ? "1.2.3.4"
                                     : variant == MRTD_TYPE ? "2.23.136.1.1.1"
                                                            : "1.3.27.1.1.1",
                                     1);
      BIO* input = BIO_new_mem_buf(content, sizeof content);
      munit_assert_not_null(cms);
      munit_assert_not_null(oid);
      munit_assert_not_null(input);
      munit_assert_int(CMS_set1_eContentType(cms, oid), ==, 1);
      munit_assert_int(CMS_final(cms, input, NULL, flags), ==, 1);
      const int length = i2d_CMS_ContentInfo(cms, NULL);
      munit_assert_int(length, >, 0);
      munit_assert_int(length, <=, CAPACITY);
      unsigned char* cursor = encoded;
      munit_assert_int(i2d_CMS_ContentInfo(cms, &cursor), ==, length);
      TC_PIV_CMS_object object, preserved;
      memset(&preserved, 0xa5, sizeof preserved);
      object = preserved;
      size_t work = WORK;
      const TC_TLV_result result = TC_PIV_CMS_read(
          (TC_bytes){encoded, (size_t)length}, TC_PIV_CMS_SECURITY,
          &(TC_CMS_verification_policy){.attribute_oids = TC_CMS_ATTRIBUTE_OIDS_PIV_TWIC}, &limits,
          (TC_TLV_frames){frames, FRAMES}, &work, &object);
      if (variant == VALID) {
        munit_assert_int(result, ==, TC_TLV_OK);
        munit_assert_uint(object.signer.version, ==, key_id ? 3 : 1);
        munit_assert_null(object.attributes.signer_name.data);
        const size_t required = WORK - work;
        TC_PIV_CMS_object budget_object = preserved;
        for (size_t budget = 0; budget <= required; ++budget) {
          work = budget;
          budget_object = preserved;
          munit_assert_int(
              TC_PIV_CMS_read(
                  (TC_bytes){encoded, (size_t)length}, TC_PIV_CMS_SECURITY,
                  &(TC_CMS_verification_policy){.attribute_oids = TC_CMS_ATTRIBUTE_OIDS_PIV},
                  &limits, (TC_TLV_frames){frames, FRAMES}, &work, &budget_object),
              ==, budget == required ? TC_TLV_OK : TC_TLV_LIMIT);
          if (budget < required)
            munit_assert_memory_equal(sizeof budget_object, &budget_object, &preserved);
        }
        work = WORK;
        munit_assert_int(
            TC_CMS_signer_verify_content(
                &(TC_CMS_signer_verify_request){&object.signer,
                                                object.envelope.content_type,
                                                {.attribute_oids = TC_CMS_ATTRIBUTE_OIDS_PIV_TWIC},
                                                &parsed_certificate.public_key,
                                                &provider,
                                                &limits},
                object.envelope.content, TC_CMS_CONTENT_BER_OCTETS, &signature, &work),
            ==, TC_X509_SIGNATURE_VALID);
        const size_t changed =
            (size_t)(object.envelope.content.data - encoded) + object.envelope.content.length - 1;
        encoded[changed] ^= 1;
        work = WORK;
        munit_assert_int(
            TC_CMS_signer_verify_content(
                &(TC_CMS_signer_verify_request){&object.signer,
                                                object.envelope.content_type,
                                                {.attribute_oids = TC_CMS_ATTRIBUTE_OIDS_PIV_TWIC},
                                                &parsed_certificate.public_key,
                                                &provider,
                                                &limits},
                object.envelope.content, TC_CMS_CONTENT_BER_OCTETS, &signature, &work),
            ==, TC_X509_SIGNATURE_INVALID);
        encoded[changed] ^= 1;
        /* PIV objects need a PIV identifier set. Other policies are argument
         * errors that leave work and out unchanged. */
        const TC_CMS_verification_policy generic = {.attribute_oids = TC_CMS_ATTRIBUTE_OIDS_CMS};
        const TC_CMS_verification_policy unknown_set = {.attribute_oids = (TC_CMS_attribute_oids)3};
        const TC_CMS_verification_policy* rejected[] = {NULL, &generic, &unknown_set};
        for (size_t i = 0; i < sizeof rejected / sizeof *rejected; ++i) {
          work = WORK;
          object = preserved;
          munit_assert_int(TC_PIV_CMS_read((TC_bytes){encoded, (size_t)length}, TC_PIV_CMS_SECURITY,
                                           rejected[i], &limits, (TC_TLV_frames){frames, FRAMES},
                                           &work, &object),
                           ==, TC_TLV_ARGUMENT);
          munit_assert_size(work, ==, WORK);
          munit_assert_memory_equal(sizeof object, &object, &preserved);
        }
        /* The profile leaves LDS schema validation to TC_LDS_read. */
        for (size_t prefix = 0; prefix < (size_t)length; ++prefix) {
          work = WORK;
          object = preserved;
          munit_assert_int(
              TC_PIV_CMS_read(
                  (TC_bytes){encoded, prefix}, TC_PIV_CMS_SECURITY,
                  &(TC_CMS_verification_policy){.attribute_oids = TC_CMS_ATTRIBUTE_OIDS_PIV},
                  &limits, (TC_TLV_frames){frames, FRAMES}, &work, &object),
              !=, TC_TLV_OK);
          munit_assert_memory_equal(sizeof object, &object, &preserved);
        }
      } else {
        munit_assert_int(result, !=, TC_TLV_OK);
        munit_assert_memory_equal(sizeof object, &object, &preserved);
      }
      ASN1_OBJECT_free(oid);
      BIO_free(input);
      CMS_ContentInfo_free(cms);
    }
  }
  X509_free(certificate);
  EVP_PKEY_free(key);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  static char* fascn_namespaces[] = {"absent", "piv", "twic", NULL};
  static char* uuid_presence[] = {"absent", "present", NULL};
  static char* signing_policies[] = {"required", "absent", "any", "other", NULL};
  static char* signer_profiles[] = {"piv", "wrong-name", "twic", "both", NULL};
  static MunitParameterEnum fascn_params[] = {{"fascn", fascn_namespaces},
                                              {"uuid", uuid_presence},
                                              {"policy", signing_policies},
                                              {"signer-profile", signer_profiles},
                                              {NULL, NULL}};
  MunitTest tests[] = {
      {"/content-signature", content_signature, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/rsa-signature", rsa_signature, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/signed-data", signed_data, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/chuid-signature", chuid_signature, NULL, NULL, MUNIT_TEST_OPTION_NONE, fascn_params},
      {"/sp800-73-4-chuid-key-map-signature", sp800_73_4_chuid_key_map_signature, NULL, NULL,
       MUNIT_TEST_OPTION_NONE, NULL},
      {"/security-profile", security_profile, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/cms/native", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
