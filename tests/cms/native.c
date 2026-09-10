/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../examples/cms_reader.h"
#include "../../examples/credential_object.h"
#include "../../examples/credential_workflow.h"
#include "../../examples/x509_revocation.h"
#include "../../src/cms_digest_internal.h"
#include "../../src/cms_internal.h"
#include "../../src/cms_signature_internal.h"
#include "../../src/pki_identifier_internal.h"
#include "../../src/pki_octets_hash_internal.h"
#include "../../src/pki_tree_internal.h"
#include "../../src/pki_verify_internal.h"
#include "../../src/source_internal.h"
#include "../../src/x509_crl_internal.h"
#include "../x509/openssl_fixture.h"
#include "envelope.h"
#include "fascn_fixture.h"
#include "munit.h"
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

typedef struct {
  const TC_X509_store_source *certificates;
  const TC_X509_store_source *anchors;
} combined_store_source;

static void assert_evidence_equal(const tc_x509_crl_evidence *left,
                                  const tc_x509_crl_evidence *right) {
  int equal = 0;
  munit_assert_int(tc_x509_crl_evidence_equal(left, right, &equal), ==,
                   TC_TLV_OK);
  munit_assert_true(equal);
}

static TC_TLV_result combined_candidate(void *context, size_t index,
                                        size_t *work, TC_bytes *out) {
  const TC_X509_store_source *source =
      ((combined_store_source *)context)->certificates;
  return source->candidate(source->context, index, work, out);
}

static TC_TLV_result combined_anchor(void *context, size_t index, size_t *work,
                                     TC_X509_store_anchor *out) {
  const TC_X509_store_source *source =
      ((combined_store_source *)context)->anchors;
  return source->anchor(source->context, index, work, out);
}

typedef struct {
  candidate_source *source;
  const TC_X509_revocation_node *dependency;
  TC_TLV_result failure;
  size_t failures;
} dependency_source_probe;

static TC_TLV_result read_dependency_candidate(void *context, size_t index,
                                               size_t *work, TC_bytes *out) {
  dependency_source_probe *probe = context;
  if (probe->dependency && probe->dependency->certificate.data &&
      probe->dependency->status != TC_X509_CRL_UNDETERMINED) {
    ++probe->failures;
    return probe->failure;
  }
  return read_candidate(probe->source, index, work, out);
}

typedef struct {
  TC_TLV_result result;
  int matched, increase_work;
} candidate_filter_probe;
static TC_TLV_result
probe_candidate_filter(const void *context,
                       const TC_X509_certificate *candidate,
                       const TC_TLV_limits *limits,
                       const tc_pki_tree_workspace *tree, int *matched) {
  const candidate_filter_probe *probe = context;
  (void)candidate;
  (void)limits;
  if (probe->increase_work)
    ++*tree->work;
  if (probe->matched >= 0)
    *matched = probe->matched;
  return probe->result;
}

typedef struct {
  TC_bytes signer;
  size_t anchor, calls;
  TC_X509_path_status result;
  int increase_work;
  TC_TLV_result *source_status;
  size_t accept_calls;
} crl_path_probe;

static TC_X509_path_status check_crl_path(void *context,
                                          const TC_X509_search_result *path,
                                          const tc_x509_crl_selected *selected,
                                          size_t *work) {
  crl_path_probe *probe = context;
  ++probe->calls;
  munit_assert_size(path->count, >, 0);
  munit_assert_size(path->anchor_index, ==, probe->anchor);
  if (selected) {
    munit_assert_not_null(selected->base);
    munit_assert_not_null(selected->base_info);
    munit_assert_false(selected->base_info->present & TC_CRL_EXT_DELTA);
    munit_assert_int(!!selected->delta, ==, !!selected->delta_info);
    if (selected->delta)
      munit_assert_true(selected->delta_info->present & TC_CRL_EXT_DELTA);
  }
  if (probe->signer.data) {
    munit_assert_size(path->path[path->count - 1].length, ==,
                      probe->signer.length);
    munit_assert_memory_equal(probe->signer.length,
                              path->path[path->count - 1].data,
                              probe->signer.data);
  }
  if (probe->increase_work)
    ++*work;
  else {
    if (!*work)
      return TC_X509_PATH_LIMIT;
    --*work;
  }
  if (probe->source_status)
    *probe->source_status = TC_TLV_UNSUPPORTED;
  return probe->calls <= probe->accept_calls ? TC_X509_PATH_VALID
                                             : probe->result;
}

typedef struct {
  crl_path_probe path;
  TC_bytes base, delta;
  size_t pairs;
} selected_crl_probe;

static TC_X509_path_status
check_selected_crl_path(void *context, const TC_X509_search_result *path,
                        const tc_x509_crl_selected *selected, size_t *work) {
  selected_crl_probe *probe = context;
  TC_X509_path_status result =
      check_crl_path(&probe->path, path, selected, work);
  if (selected && selected->delta) {
    ++probe->pairs;
    munit_assert_ptr_equal(selected->base->encoded.data, probe->base.data);
    munit_assert_size(selected->base->encoded.length, ==, probe->base.length);
    munit_assert_ptr_equal(selected->delta->encoded.data, probe->delta.data);
    munit_assert_size(selected->delta->encoded.length, ==, probe->delta.length);
  }
  return result;
}

typedef struct {
  crl_path_probe path;
  TC_bytes signer;
  TC_X509_path_status result;
} unresolved_crl_probe;

static TC_X509_path_status
check_unresolved_crl_path(void *context, const TC_X509_search_result *path,
                          const tc_x509_crl_selected *selected, size_t *work) {
  unresolved_crl_probe *probe = context;
  TC_X509_path_status result =
      check_crl_path(&probe->path, path, selected, work);
  if (result != TC_X509_PATH_VALID)
    return result;
  const TC_bytes signer = path->path[path->count - 1];
  return signer.length == probe->signer.length &&
                 !memcmp(signer.data, probe->signer.data, signer.length)
             ? probe->result
             : TC_X509_PATH_VALID;
}

static TC_TLV_result crl_trust_anchor(void *context, size_t index, size_t *work,
                                      TC_X509_store_anchor *out) {
  if (!*work)
    return TC_TLV_LIMIT;
  --*work;
  *out = ((const TC_X509_store_anchor *)context)[index];
  return TC_TLV_OK;
}

typedef struct {
  TC_X509_signature_provider native;
  size_t calls, failure_call;
  TC_X509_signature_result failure;
} signature_retry_probe;
static TC_X509_signature_result
retry_signature(void *context, const TC_bytes *message, size_t count,
                const TC_DER_algorithm *algorithm, TC_bytes signature,
                const TC_X509_public_key *key, size_t *work) {
  signature_retry_probe *probe = context;
  if (++probe->calls == probe->failure_call)
    return probe->failure;
  return probe->native.verify(probe->native.context, message, count, algorithm,
                              signature, key, work);
}

static TC_X509_signature_result
retry_digest(void *context, TC_bytes digest,
             const TC_signature_algorithm *algorithm, TC_bytes signature,
             const TC_X509_public_key *key, size_t *work) {
  signature_retry_probe *probe = context;
  if (++probe->calls == probe->failure_call)
    return probe->failure;
  return probe->native.verify_digest(probe->native.context, digest, algorithm,
                                     signature, key, work);
}

static MunitResult content_signature(const MunitParameter params[],
                                     void *user) {
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
  static const uint8_t content_type[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                         0x0d, 1,    7,    1};
  static const uint8_t type_attribute[] = {
      0x30, 24, 6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 3,
      0x31, 11, 6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 1};
  static const uint8_t digest_attribute_header[] = {
      0x30, 47, 6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7,
      0x0d, 1,  9, 4, 0x31, 34,   4,    32};
  static const uint8_t signature_oid[] = {0x2a, 0x86, 0x48, 0xce,
                                          0x3d, 4,    3,    2};
  static const uint8_t message[] = {'a', 'b', 'c'};
  uint8_t content[] = {0x24, 0x80, 4,   1, 'a', 0x24, 0x80, 4,
                       2,    'b',  'c', 0, 0,   0,    0};
  uint8_t
      digest_attribute[sizeof digest_attribute_header + TC_SHA256_DIGESTLEN];
  uint8_t attributes[TLV_HEADER_BYTES + 1 + sizeof type_attribute +
                     sizeof digest_attribute];
  uint8_t spki[SPKI_CAPACITY], signature[SIGNATURE_CAPACITY],
      digest[TC_SHA256_DIGESTLEN];
  TC_TLV_limits limits = {WORK_BUDGET, WORK_BUDGET, 32, FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_ECDSA_workspace ec;
  TC_X509_native_workspace workspace = {&ec, NULL,
                                        TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  TC_X509_signature_provider provider = TC_X509_native_provider(&workspace);
  const TC_DER_algorithm algorithm = {{signature_oid, sizeof signature_oid},
                                      {NULL, 0}};
  TC_X509_public_key key;
  tc_hash_workspace hash_workspace;
  EVP_PKEY *generated = EVP_EC_gen("prime256v1");
  EVP_MD_CTX *signer = EVP_MD_CTX_new();
  unsigned char *cursor = spki;
  unsigned digest_length;
  int spki_length;
  (void)params;
  (void)user;
  munit_assert_not_null(generated);
  munit_assert_not_null(signer);
  spki_length = i2d_PUBKEY(generated, NULL);
  munit_assert_int(spki_length, >, 0);
  munit_assert_size((size_t)spki_length, <=, sizeof spki);
  munit_assert_int(i2d_PUBKEY(generated, &cursor), ==, spki_length);
  munit_assert_int(TC_X509_subject_public_key(spki, (size_t)spki_length, &key),
                   ==, TC_TLV_OK);
  memcpy(digest_attribute, digest_attribute_header,
         sizeof digest_attribute_header);
  munit_assert_int(EVP_Digest(message, sizeof message,
                              digest_attribute + sizeof digest_attribute_header,
                              &digest_length, EVP_sha256(), NULL),
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
      memcpy(attributes + header_length, digest_attribute,
             sizeof digest_attribute);
      memcpy(attributes + header_length + sizeof digest_attribute,
             type_attribute, sizeof type_attribute);
    } else {
      memcpy(attributes + header_length, type_attribute, sizeof type_attribute);
      memcpy(attributes + header_length + sizeof type_attribute,
             digest_attribute, sizeof digest_attribute);
    }
    /* Sign SET OF, then carry the same length and values under IMPLICIT [0]. */
    munit_assert_int(
        EVP_DigestSignInit(signer, NULL, EVP_sha256(), NULL, generated), ==, 1);
    munit_assert_int(EVP_DigestSign(signer, signature, &signature_length,
                                    attributes, attributes_length),
                     ==, 1);
    attributes[0] = 0xa0;
    munit_assert_int(TC_CMS_signed_attributes_read(
                         (TC_bytes){attributes, attributes_length}, mode,
                         &limits, frames, FRAME_CAPACITY, &work, &parsed),
                     ==, TC_TLV_OK);
    munit_assert_int(tc_pki_octets_hash((TC_bytes){content, sizeof content},
                                        TC_TLV_BER, &limits, frames,
                                        FRAME_CAPACITY, TC_HASH_SHA256,
                                        &hash_workspace, &work, digest),
                     ==, TC_TLV_OK);
    munit_assert_int(TC_CMS_content_digest_check(
                         &parsed, (TC_bytes){content_type, sizeof content_type},
                         TC_HASH_SHA256, (TC_bytes){digest, sizeof digest},
                         &work, &matched),
                     ==, TC_TLV_OK);
    munit_assert_int(matched, ==, 1);
    munit_assert_int(
        TC_X509_signature_verify_message(
            parsed.signature_input,
            sizeof parsed.signature_input / sizeof *parsed.signature_input,
            &algorithm, (TC_bytes){signature, signature_length}, &key,
            &provider, &work),
        ==, TC_X509_SIGNATURE_VALID);

    {
      uint8_t encoded_signature[SIGNATURE_CAPACITY + TLV_HEADER_BYTES];
      TC_CMS_signer_info info = {0};
      tc_hash_info hash;
      const TC_CMS_signature_workspace verification = {frames, FRAME_CAPACITY,
                                                       NULL, 0};
      munit_assert_true(tc_hash_info_get(TC_HASH_SHA256, &hash));
      munit_assert_size(signature_length, <, 128);
      encoded_signature[0] = 4;
      encoded_signature[1] = (uint8_t)signature_length;
      memcpy(encoded_signature + TLV_HEADER_BYTES, signature, signature_length);
      info.digest_algorithm = (TC_DER_algorithm){hash.oid, {NULL, 0}};
      info.signature_algorithm = algorithm;
      info.signed_attributes = (TC_bytes){attributes, attributes_length};
      info.signature =
          (TC_bytes){encoded_signature, signature_length + TLV_HEADER_BYTES};
      size_t verification_work = WORK_BUDGET;
      munit_assert_int(TC_CMS_signer_verify_digest(
                           &info, (TC_bytes){content_type, sizeof content_type},
                           (TC_bytes){digest, sizeof digest}, mode, &key,
                           &provider, &limits, &verification,
                           &verification_work),
                       ==, TC_X509_SIGNATURE_VALID);
      if (mode != TC_CMS_ATTRIBUTES_DER) {
        verification_work = WORK_BUDGET;
        munit_assert_int(
            TC_CMS_signer_verify_digest(
                &info, (TC_bytes){content_type, sizeof content_type},
                (TC_bytes){digest, sizeof digest}, TC_CMS_ATTRIBUTES_DER, &key,
                &provider, &limits, &verification, &verification_work),
            ==, TC_X509_SIGNATURE_INVALID);
      }
      encoded_signature[signature_length + TLV_HEADER_BYTES - 1] ^= 1;
      verification_work = WORK_BUDGET;
      munit_assert_int(TC_CMS_signer_verify_digest(
                           &info, (TC_bytes){content_type, sizeof content_type},
                           (TC_bytes){digest, sizeof digest}, mode, &key,
                           &provider, &limits, &verification,
                           &verification_work),
                       ==, TC_X509_SIGNATURE_INVALID);
    }

    /* Changed content must fail binding even though signedAttrs still verify.
     */
    content[CONTENT_MUTATION_OFFSET] ^= 1;
    work = WORK_BUDGET;
    munit_assert_int(tc_pki_octets_hash((TC_bytes){content, sizeof content},
                                        TC_TLV_BER, &limits, frames,
                                        FRAME_CAPACITY, TC_HASH_SHA256,
                                        &hash_workspace, &work, digest),
                     ==, TC_TLV_OK);
    munit_assert_int(TC_CMS_content_digest_check(
                         &parsed, (TC_bytes){content_type, sizeof content_type},
                         TC_HASH_SHA256, (TC_bytes){digest, sizeof digest},
                         &work, &matched),
                     ==, TC_TLV_OK);
    munit_assert_int(matched, ==, 0);
    munit_assert_int(
        TC_X509_signature_verify_message(
            parsed.signature_input,
            sizeof parsed.signature_input / sizeof *parsed.signature_input,
            &algorithm, (TC_bytes){signature, signature_length}, &key,
            &provider, &work),
        ==, TC_X509_SIGNATURE_VALID);
    content[CONTENT_MUTATION_OFFSET] ^= 1;
    signature[signature_length - 1] ^= 1;
    work = WORK_BUDGET;
    munit_assert_int(
        TC_X509_signature_verify_message(
            parsed.signature_input,
            sizeof parsed.signature_input / sizeof *parsed.signature_input,
            &algorithm, (TC_bytes){signature, signature_length}, &key,
            &provider, &work),
        ==, TC_X509_SIGNATURE_INVALID);
    if (mode != TC_CMS_ATTRIBUTES_DER) {
      memcpy(&saved, &parsed, sizeof saved);
      work = WORK_BUDGET;
      munit_assert_int(TC_CMS_signed_attributes_read(
                           (TC_bytes){attributes, attributes_length},
                           TC_CMS_ATTRIBUTES_DER, &limits, frames,
                           FRAME_CAPACITY, &work, &parsed),
                       ==, TC_TLV_INVALID);
      munit_assert_memory_equal(sizeof parsed, &parsed, &saved);
    }
  }
  EVP_MD_CTX_free(signer);
  EVP_PKEY_free(generated);
  return MUNIT_OK;
}

static MunitResult rsa_signature(const MunitParameter params[], void *user) {
  enum { SPKI_CAPACITY = 512, MAX_RSA_BITS = 3072 };
  static const unsigned key_sizes[] = {1024, 2048, MAX_RSA_BITS};
  static const uint8_t rsa_oid[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                    0x0d, 1,    1,    1};
  static const uint8_t null_parameters[] = {5, 0};
  static const uint8_t message[] = {'a', 'b', 'c'};
  const TC_bytes part = {message, sizeof message};
  tc_cms_signer_info info = {0};
  tc_cms_signature_algorithm algorithm;
  tc_hash_info hash;
  tc_hash_workspace hash_workspace;
  TC_RSA_word words[TC_RSA_VERIFY_WORKSPACE_WORDS(MAX_RSA_BITS)];
  TC_RSA_workspace workspace = {words, sizeof words / sizeof *words};
  uint8_t spki[SPKI_CAPACITY], signature[MAX_RSA_BITS / 8],
      digest[TC_SHA256_DIGESTLEN];
  (void)params;
  (void)user;
  munit_assert_true(tc_hash_info_get(TC_HASH_SHA256, &hash));
  info.digest_algorithm = (TC_DER_algorithm){hash.oid, {NULL, 0}};
  info.signature_algorithm = (TC_DER_algorithm){
      {rsa_oid, sizeof rsa_oid}, {null_parameters, sizeof null_parameters}};
  for (size_t i = 0; i < sizeof key_sizes / sizeof *key_sizes; ++i) {
    EVP_PKEY *generated = EVP_RSA_gen(key_sizes[i]);
    EVP_MD_CTX *signer = EVP_MD_CTX_new();
    unsigned char *cursor = spki;
    size_t signature_length = sizeof signature;
    TC_X509_public_key key;
    int spki_length;
    munit_assert_not_null(generated);
    munit_assert_not_null(signer);
    spki_length = i2d_PUBKEY(generated, NULL);
    munit_assert_int(spki_length, >, 0);
    munit_assert_size((size_t)spki_length, <=, sizeof spki);
    munit_assert_int(i2d_PUBKEY(generated, &cursor), ==, spki_length);
    munit_assert_int(
        TC_X509_subject_public_key(spki, (size_t)spki_length, &key), ==,
        TC_TLV_OK);
    munit_assert_int(
        EVP_DigestSignInit(signer, NULL, EVP_sha256(), NULL, generated), ==, 1);
    munit_assert_int(EVP_DigestSign(signer, signature, &signature_length,
                                    message, sizeof message),
                     ==, 1);
    const TC_bytes signature_bytes = {signature, signature_length};
    munit_assert_int(tc_cms_signature_resolve(&info, &key, &algorithm), ==,
                     TC_TLV_OK);
    munit_assert_int(tc_hash_digest_parts(algorithm.content_hash, &part, 1,
                                          digest, &hash_workspace),
                     ==, TC_OK);
    munit_assert_int(
        tc_pki_verify_digest(&algorithm.signature, &key,
                             (TC_bytes){digest, sizeof digest}, signature_bytes,
                             NULL, &workspace,
                             TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK),
        ==, TC_X509_SIGNATURE_VALID);
    {
      enum { HEADER_BYTES = 4, FRAME_CAPACITY = 8, WORK_BUDGET = 100000 };
      static const uint8_t data_type[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                          0x0d, 1,    7,    1};
      uint8_t encoded_signature[sizeof signature + HEADER_BYTES];
      TC_TLV_frame frames[FRAME_CAPACITY];
      const TC_TLV_limits limits = {sizeof encoded_signature,
                                    sizeof encoded_signature, 32,
                                    FRAME_CAPACITY};
      const TC_CMS_signature_workspace verification = {frames, FRAME_CAPACITY,
                                                       NULL, 0};
      const TC_X509_native_workspace native = {
          NULL, &workspace, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
      const TC_X509_signature_provider provider =
          TC_X509_native_provider(&native);
      encoded_signature[0] = 4;
      encoded_signature[1] = 0x82;
      encoded_signature[2] = (uint8_t)(signature_length >> 8);
      encoded_signature[3] = (uint8_t)signature_length;
      memcpy(encoded_signature + HEADER_BYTES, signature, signature_length);
      info.signature =
          (TC_bytes){encoded_signature, signature_length + HEADER_BYTES};
      size_t work = WORK_BUDGET;
      munit_assert_int(TC_CMS_signer_verify_digest(
                           &info, (TC_bytes){data_type, sizeof data_type},
                           (TC_bytes){digest, sizeof digest},
                           TC_CMS_ATTRIBUTES_DER, &key, &provider, &limits,
                           &verification, &work),
                       ==, TC_X509_SIGNATURE_VALID);
      digest[0] ^= 1;
      work = WORK_BUDGET;
      munit_assert_int(TC_CMS_signer_verify_digest(
                           &info, (TC_bytes){data_type, sizeof data_type},
                           (TC_bytes){digest, sizeof digest},
                           TC_CMS_ATTRIBUTES_DER, &key, &provider, &limits,
                           &verification, &work),
                       ==, TC_X509_SIGNATURE_INVALID);
      digest[0] ^= 1;
      info.signature = (TC_bytes){NULL, 0};
    }
    digest[0] ^= 1;
    munit_assert_int(
        tc_pki_verify_digest(&algorithm.signature, &key,
                             (TC_bytes){digest, sizeof digest}, signature_bytes,
                             NULL, &workspace,
                             TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK),
        ==, TC_X509_SIGNATURE_INVALID);
    digest[0] ^= 1;
    signature[signature_length - 1] ^= 1;
    munit_assert_int(
        tc_pki_verify_digest(&algorithm.signature, &key,
                             (TC_bytes){digest, sizeof digest}, signature_bytes,
                             NULL, &workspace,
                             TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK),
        ==, TC_X509_SIGNATURE_INVALID);
    EVP_MD_CTX_free(signer);
    EVP_PKEY_free(generated);
  }
  return MUNIT_OK;
}

static MunitResult signed_data(const MunitParameter params[], void *user) {
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
  uint8_t encoded[ENCODED_CAPACITY], certificate_der[ENCODED_CAPACITY],
      other_der[ENCODED_CAPACITY];
  uint8_t digest[TC_SHA512_DIGESTLEN];
  uint8_t name_flags[NAME_ATTRIBUTES];
  uint32_t name_left[NAME_SCALARS], name_right[NAME_SCALARS];
  const TC_X509_name_workspace names = {name_left, name_right, NAME_SCALARS,
                                        name_flags, NAME_ATTRIBUTES};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_bytes extension_oids[NAME_ATTRIBUTES];
  TC_X509_workspace parser = {frames, FRAME_CAPACITY, extension_oids,
                              NAME_ATTRIBUTES};
  TC_X509_certificate parsed_certificate;
  const TC_TLV_limits limits = {ENCODED_CAPACITY, ENCODED_CAPACITY,
                                ELEMENT_LIMIT, FRAME_CAPACITY};
  tc_hash_workspace hash_workspace;
  TC_ECDSA_workspace ec;
  const TC_X509_native_workspace native = {
      &ec, NULL, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  const TC_X509_signature_provider provider = TC_X509_native_provider(&native);
  TC_X509_public_key key;
  EVP_PKEY *generated = EVP_EC_gen("prime256v1");
  EVP_PKEY *other_key = EVP_EC_gen("prime256v1");
  X509 *certificate, *other_certificate;
  unsigned char *cursor;
  size_t certificate_length, other_length;
  (void)params;
  (void)user;
  munit_assert_not_null(generated);
  munit_assert_not_null(other_key);
  certificate = make_certificate(generated, "CMS signer", NULL);
  add_extension(certificate, NID_subject_key_identifier, "hash");
  certificate_length =
      encode_certificate(certificate, generated, EVP_sha256(), certificate_der,
                         sizeof certificate_der);
  munit_assert_int(TC_X509_read(certificate_der, certificate_length, &limits,
                                &parser, &parsed_certificate),
                   ==, TC_TLV_OK);
  key = parsed_certificate.public_key;
  other_certificate = make_certificate(other_key, "Other signer", NULL);
  add_extension(other_certificate, NID_subject_key_identifier, "hash");
  other_length = encode_certificate(other_certificate, other_key, EVP_sha256(),
                                    other_der, sizeof other_der);
  for (size_t i = 0; i < sizeof flags / sizeof *flags; ++i) {
    BIO *input = BIO_new_mem_buf(message, sizeof message);
    CMS_ContentInfo *cms;
    tc_cms_signed_data container;
    tc_cms_signer_info signer;
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
    munit_assert_int(tc_cms_signed_data_read(
                         (TC_bytes){encoded, (size_t)encoded_length}, &limits,
                         frames, FRAME_CAPACITY, &work, &container),
                     ==, TC_TLV_OK);
    munit_assert_true(container.has_content);
    munit_assert_int(
        tc_cms_signed_data_version_check(&container, &limits, &workspace), ==,
        TC_TLV_OK);
    ++container.version;
    munit_assert_int(
        tc_cms_signed_data_version_check(&container, &limits, &workspace), ==,
        TC_TLV_INVALID);
    --container.version;
    munit_assert_int(TC_CMS_signers_init(container.signers, &limits, frames,
                                         FRAME_CAPACITY, &work, &signers),
                     ==, TC_TLV_OK);
    munit_assert_int(
        TC_CMS_signer_next(&signers, frames, FRAME_CAPACITY, &work, &signer),
        ==, TC_TLV_OK);
    munit_assert_true(tc_pki_end(&signers));
    munit_assert_int(
        TC_CMS_signer_next(&signers, frames, FRAME_CAPACITY, &work, &signer),
        ==, TC_TLV_END);
    munit_assert_int(tc_pki_tree_read(signer.encoded, TC_TLV_BER, &limits,
                                      &workspace, &element),
                     ==, TC_TLV_OK);
    munit_assert_uint(signer.version, ==, flags[i] & CMS_USE_KEYID ? 3 : 1);
    munit_assert_int(tc_cms_signer_matches(&signer, TC_TLV_BER,
                                           &parsed_certificate, &limits, &names,
                                           &workspace, &matched),
                     ==, TC_TLV_OK);
    munit_assert_int(matched, ==, 1);
    {
      const TC_bytes records[] = {{other_der, other_length},
                                  {certificate_der, certificate_length}};
      candidate_source source = {records, sizeof records / sizeof records[0], 0,
                                 TC_TLV_OK, 0};
      const TC_X509_store_source external = {&source, source.count, 0,
                                             read_candidate, NULL};
      tc_cms_candidates candidates;
      TC_X509_certificate selected;
      TC_bytes selected_der = {NULL, 0};
      munit_assert_int(
          tc_cms_candidates_init(container.certificates, &external, 3,
                                 sizeof encoded + sizeof certificate_der +
                                     sizeof other_der,
                                 &limits, &workspace, &candidates),
          ==, TC_TLV_OK);
      const tc_cms_candidates start = candidates;
      const size_t before_search = work;
      munit_assert_int(tc_cms_signer_candidate_next(
                           &candidates, &signer, TC_TLV_BER, &names, &workspace,
                           &parser, &selected, &selected_der),
                       ==, TC_TLV_OK);
      munit_assert_size(source.calls, ==, 0);
      munit_assert_ptr_equal(selected_der.data, selected.encoded.data);
      key = selected.public_key;
      {
        const size_t required = before_search - work, remaining_work = work;
        const size_t budgets[] = {0, required - 1, required};
        for (size_t budget = 0; budget < sizeof budgets / sizeof budgets[0];
             ++budget) {
          tc_cms_candidates probe = start, saved;
          TC_bytes output = selected_der;
          memcpy(&saved, &probe, sizeof saved);
          work = budgets[budget];
          TC_TLV_result result = tc_cms_signer_candidate_next(
              &probe, &signer, TC_TLV_BER, &names, &workspace, &parser,
              &selected, &output);
          munit_assert_int(result, ==,
                           budgets[budget] == required ? TC_TLV_OK
                                                       : TC_TLV_LIMIT);
          munit_assert_ptr_equal(output.data, selected_der.data);
          if (result == TC_TLV_LIMIT)
            munit_assert_memory_equal(sizeof probe, &probe, &saved);
          else
            munit_assert_size(work, ==, 0);
        }
        work = remaining_work;
      }
      munit_assert_int(tc_cms_signer_candidate_next(
                           &candidates, &signer, TC_TLV_BER, &names, &workspace,
                           &parser, &selected, &selected_der),
                       ==, TC_TLV_OK);
      munit_assert_size(source.calls, ==, source.count);
      munit_assert_ptr_equal(selected_der.data, certificate_der);
      {
        TC_X509_store_source nonmatching = external;
        tc_cms_candidates no_match;
        nonmatching.candidate_count = 1;
        munit_assert_int(tc_cms_candidates_init(
                             (TC_bytes){NULL, 0}, &nonmatching, 1,
                             sizeof other_der, &limits, &workspace, &no_match),
                         ==, TC_TLV_OK);
        munit_assert_int(tc_cms_signer_candidate_next(
                             &no_match, &signer, TC_TLV_BER, &names, &workspace,
                             &parser, &selected, &selected_der),
                         ==, TC_TLV_END);
        munit_assert_size(no_match.collection.external_index, ==, 1);
        munit_assert_ptr_equal(selected_der.data, certificate_der);
      }
      munit_assert_int(tc_cms_signer_candidate_next(
                           &candidates, &signer, TC_TLV_BER, &names, &workspace,
                           &parser, &selected, &selected_der),
                       ==, TC_TLV_END);
      munit_assert_ptr_equal(selected_der.data, certificate_der);
    }
    munit_assert_int(tc_cms_signature_resolve_profile(&signer, &key, TC_TLV_BER,
                                                      &limits, &workspace,
                                                      &algorithm),
                     ==, TC_TLV_OK);
    munit_assert_true(tc_hash_info_get(algorithm.content_hash, &hash));
    munit_assert_int(TC_CMS_content_digest(
                         container.content, algorithm.content_hash, &limits,
                         frames, FRAME_CAPACITY, &work, digest, sizeof digest),
                     ==, TC_TLV_OK);
    uint8_t content_digest_bytes[TC_SHA512_DIGESTLEN];
    memcpy(content_digest_bytes, digest, hash.digest_length);
    const TC_bytes computed_content = {content_digest_bytes,
                                       hash.digest_length};
    munit_assert_int(TC_CMS_signed_attributes_read(
                         signer.signed_attributes, TC_CMS_ATTRIBUTES_DER,
                         &limits, frames, FRAME_CAPACITY, &work, &attributes),
                     ==, TC_TLV_OK);
    munit_assert_int(
        TC_CMS_content_digest_check(
            &attributes, container.content_type, algorithm.content_hash,
            (TC_bytes){digest, hash.digest_length}, &work, &matched),
        ==, TC_TLV_OK);
    munit_assert_int(matched, ==, 1);
    {
      const TC_CMS_signature_workspace verification = {frames, FRAME_CAPACITY,
                                                       NULL, 0};
      size_t verification_work = WORK_BUDGET;
      const TC_bytes content_digest = {digest, hash.digest_length};
      munit_assert_int(TC_CMS_signer_verify_digest(
                           &signer, container.content_type, content_digest,
                           TC_CMS_ATTRIBUTES_DER, &key, &provider, &limits,
                           &verification, &verification_work),
                       ==, TC_X509_SIGNATURE_VALID);
      ExampleCMSVerifyWorkspace example;
      munit_assert_int(
          example_verify_cms_digest(&signer, container.content_type,
                                    content_digest, TC_CMS_ATTRIBUTES_DER, &key,
                                    &provider, WORK_BUDGET, &example),
          ==, TC_X509_SIGNATURE_VALID);
      munit_assert_int(example_verify_cms_digest(
                           &signer, container.content_type, content_digest,
                           TC_CMS_ATTRIBUTES_DER, &key, &provider, 0, &example),
                       ==, TC_X509_SIGNATURE_LIMIT);
      munit_assert_int(example_verify_cms_content(
                           &signer, container.content_type, container.content,
                           TC_CMS_CONTENT_BER_OCTETS, TC_CMS_ATTRIBUTES_DER,
                           &key, &provider, WORK_BUDGET, &example),
                       ==, TC_X509_SIGNATURE_VALID);
      munit_assert_int(example_verify_cms_content(
                           &signer, container.content_type, container.content,
                           TC_CMS_CONTENT_BER_OCTETS, TC_CMS_ATTRIBUTES_DER,
                           &key, &provider, 0, &example),
                       ==, TC_X509_SIGNATURE_LIMIT);
      const size_t required = WORK_BUDGET - verification_work;
      verification_work = required;
      munit_assert_int(TC_CMS_signer_verify_digest(
                           &signer, container.content_type, content_digest,
                           TC_CMS_ATTRIBUTES_DER, &key, &provider, &limits,
                           &verification, &verification_work),
                       ==, TC_X509_SIGNATURE_VALID);
      munit_assert_size(verification_work, ==, 0);
      verification_work = required - 1;
      munit_assert_int(TC_CMS_signer_verify_digest(
                           &signer, container.content_type, content_digest,
                           TC_CMS_ATTRIBUTES_DER, &key, &provider, &limits,
                           &verification, &verification_work),
                       ==, TC_X509_SIGNATURE_LIMIT);
      digest[0] ^= 1;
      verification_work = WORK_BUDGET;
      munit_assert_int(TC_CMS_signer_verify_digest(
                           &signer, container.content_type, content_digest,
                           TC_CMS_ATTRIBUTES_DER, &key, &provider, &limits,
                           &verification, &verification_work),
                       ==, TC_X509_SIGNATURE_INVALID);
      digest[0] ^= 1;
    }
    munit_assert_true(tc_hash_info_get(algorithm.signature.hash, &hash));
    munit_assert_int(tc_hash_digest_parts(
                         algorithm.signature.hash, attributes.signature_input,
                         sizeof attributes.signature_input /
                             sizeof *attributes.signature_input,
                         digest, &hash_workspace),
                     ==, TC_OK);
    munit_assert_int(tc_pki_octets_contiguous(signer.signature, 4, TC_TLV_BER,
                                              &limits, frames, FRAME_CAPACITY,
                                              &work, NULL, 0, &signature),
                     ==, TC_TLV_OK);
    munit_assert_int(
        TC_X509_signature_verify_digest((TC_bytes){digest, hash.digest_length},
                                        &algorithm.signature, signature, &key,
                                        &provider, &work),
        ==, TC_X509_SIGNATURE_VALID);
    {
      enum { SIGNATURE_CAPACITY = 80, CHUNK_FRAMING = 12 };
      uint8_t chunked[SIGNATURE_CAPACITY + CHUNK_FRAMING],
          scratch[SIGNATURE_CAPACITY];
      uint8_t signer_encoded[ENCODED_CAPACITY];
      const size_t prefix =
          (size_t)(signer.signature.data - element.value.data);
      const size_t suffix =
          element.value.length - prefix - signer.signature.length;
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
        memcpy(chunked + offset, signature.data + split,
               signature.length - split);
        offset += signature.length - split;
        memset(chunked + offset, 0, 4);
        offset += 4;
        tc_cms_signer_info parsed_chunks;
        size_t signer_length = 0;
        munit_assert_size(prefix + offset + suffix + 4, <=,
                          sizeof signer_encoded);
        signer_encoded[signer_length++] = 0x30;
        signer_encoded[signer_length++] = 0x80;
        memcpy(signer_encoded + signer_length, element.value.data, prefix);
        signer_length += prefix;
        memcpy(signer_encoded + signer_length, chunked, offset);
        signer_length += offset;
        memcpy(signer_encoded + signer_length,
               signer.signature.data + signer.signature.length, suffix);
        signer_length += suffix;
        memset(signer_encoded + signer_length, 0, 2);
        signer_length += 2;
        work = WORK_BUDGET;
        munit_assert_int(
            TC_CMS_signer_info_read((TC_bytes){signer_encoded, signer_length},
                                    TC_TLV_BER, &limits, frames, FRAME_CAPACITY,
                                    &work, &parsed_chunks),
            ==, TC_TLV_OK);
        munit_assert_uint(parsed_chunks.version, ==, signer.version);
        munit_assert_int(
            tc_pki_octets_contiguous(parsed_chunks.signature, 4, TC_TLV_BER,
                                     &limits, frames, FRAME_CAPACITY, &work,
                                     scratch, sizeof scratch, &joined),
            ==, TC_TLV_OK);
        munit_assert_size(joined.length, ==, signature.length);
        munit_assert_memory_equal(joined.length, joined.data, signature.data);
        munit_assert_int(tc_pki_verify_digest(
                             &algorithm.signature, &key,
                             (TC_bytes){digest, hash.digest_length}, joined,
                             &ec, NULL, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK),
                         ==, TC_X509_SIGNATURE_VALID);
        const TC_CMS_signature_workspace verification = {
            frames, FRAME_CAPACITY, scratch, sizeof scratch};
        size_t verification_work = WORK_BUDGET;
        munit_assert_int(
            TC_CMS_signer_verify_digest(&parsed_chunks, container.content_type,
                                        computed_content, TC_CMS_ATTRIBUTES_DER,
                                        &key, &provider, &limits, &verification,
                                        &verification_work),
            ==, TC_X509_SIGNATURE_VALID);
        if (split && split < signature.length) {
          TC_CMS_signature_workspace short_workspace = verification;
          short_workspace.signature_capacity = signature.length - 1;
          verification_work = WORK_BUDGET;
          munit_assert_int(TC_CMS_signer_verify_digest(
                               &parsed_chunks, container.content_type,
                               computed_content, TC_CMS_ATTRIBUTES_DER, &key,
                               &provider, &limits, &short_workspace,
                               &verification_work),
                           ==, TC_X509_SIGNATURE_LIMIT);
          munit_assert_ptr_equal(joined.data, scratch);
          scratch[joined.length - 1] ^= 1;
          munit_assert_int(
              tc_pki_verify_digest(&algorithm.signature, &key,
                                   (TC_bytes){digest, hash.digest_length},
                                   joined, &ec, NULL,
                                   TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK),
              ==, TC_X509_SIGNATURE_INVALID);
          work = WORK_BUDGET;
          joined = (TC_bytes){NULL, 99};
          munit_assert_int(tc_pki_octets_contiguous(
                               (TC_bytes){chunked, offset}, 4, TC_TLV_BER,
                               &limits, frames, FRAME_CAPACITY, &work, scratch,
                               signature.length - 1, &joined),
                           ==, TC_TLV_LIMIT);
          munit_assert_null(joined.data);
          munit_assert_size(joined.length, ==, 99);
        }
      }
    }
    digest[0] ^= 1;
    munit_assert_int(
        tc_pki_verify_digest(&algorithm.signature, &key,
                             (TC_bytes){digest, hash.digest_length}, signature,
                             &ec, NULL, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK),
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
static X509_CRL *make_partition_crl(X509_CRL *template, EVP_PKEY *key,
                                    uint16_t reasons, int revoked) {
  enum { KEY_COMPROMISE = 1, TARGET_SERIAL = 9, LAST_REASON_BIT = 8 };
  X509_CRL *crl = X509_CRL_dup(template);
  ISSUING_DIST_POINT *point = ISSUING_DIST_POINT_new();
  munit_assert_not_null(crl);
  munit_assert_not_null(point);
  point->onlysomereasons = ASN1_BIT_STRING_new();
  munit_assert_not_null(point->onlysomereasons);
  for (unsigned bit = KEY_COMPROMISE; bit <= LAST_REASON_BIT; ++bit)
    if (reasons & (1u << bit))
      munit_assert_int(
          ASN1_BIT_STRING_set_bit(point->onlysomereasons, (int)bit, 1), ==, 1);
  munit_assert_int(X509_CRL_add1_ext_i2d(crl, NID_issuing_distribution_point,
                                         point, 1, X509V3_ADD_REPLACE),
                   ==, 1);
  ISSUING_DIST_POINT_free(point);
  if (revoked) {
    X509_REVOKED *item = X509_REVOKED_new();
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    ASN1_ENUMERATED *reason = ASN1_ENUMERATED_new();
    ASN1_TIME *revoked_at = ASN1_STRING_dup(X509_CRL_get0_lastUpdate(crl));
    munit_assert_not_null(item);
    munit_assert_not_null(serial);
    munit_assert_not_null(reason);
    munit_assert_not_null(revoked_at);
    munit_assert_int(ASN1_INTEGER_set(serial, TARGET_SERIAL), ==, 1);
    munit_assert_int(ASN1_ENUMERATED_set(reason, KEY_COMPROMISE), ==, 1);
    munit_assert_int(X509_REVOKED_set_serialNumber(item, serial), ==, 1);
    munit_assert_int(X509_REVOKED_set_revocationDate(item, revoked_at), ==, 1);
    munit_assert_int(
        X509_REVOKED_add1_ext_i2d(item, NID_crl_reason, reason, 0, 0), ==, 1);
    munit_assert_int(X509_CRL_add0_revoked(crl, item), ==, 1);
    ASN1_TIME_free(revoked_at);
    ASN1_ENUMERATED_free(reason);
    ASN1_INTEGER_free(serial);
  }
  munit_assert_int(X509_CRL_sign(crl, key, EVP_sha256()), >, 0);
  return crl;
}

static MunitResult revocations(const MunitParameter params[], void *user) {
  const char *group = munit_parameters_get(params, "group");
  const char *outcome = munit_parameters_get(params, "outcome");
  munit_assert_not_null(group);
  munit_assert_not_null(outcome);
  const int check_signer = strcmp(group, "signer") == 0;
  const int check_discovery = strcmp(group, "discovery") == 0;
  const int check_selection = strcmp(group, "selection") == 0;
  munit_assert_true(check_signer || check_discovery || check_selection);
  munit_assert_true(strcmp(outcome, "clear") == 0 ||
                    strcmp(outcome, "revoked") == 0);
  const unsigned revoked = strcmp(outcome, "revoked") == 0;
  enum {
    ENCODED_CAPACITY = 4096,
    SPKI_CAPACITY = 128,
    FRAME_CAPACITY = 16,
    EXTENSION_CAPACITY = 8,
    NAME_SCALARS = 128,
    WORK_BUDGET = 100000,
    PATH_CAPACITY = 2,
    POLICY_CAPACITY = 16,
    TRUST_WORK_BUDGET = 1000000
  };
  uint8_t encoded[ENCODED_CAPACITY], spki[SPKI_CAPACITY],
      signer_der[ENCODED_CAPACITY];
  uint8_t denied_der[ENCODED_CAPACITY];
  uint8_t expired_der[ENCODED_CAPACITY];
  uint8_t other_spki[SPKI_CAPACITY];
  uint32_t name_left[NAME_SCALARS], name_right[NAME_SCALARS];
  uint8_t name_flags[EXTENSION_CAPACITY];
  const TC_X509_name_workspace names = {name_left, name_right, NAME_SCALARS,
                                        name_flags, EXTENSION_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_bytes oids[EXTENSION_CAPACITY];
  TC_X509_policy_node nodes[POLICY_CAPACITY];
  TC_X509_policy_edge edges[POLICY_CAPACITY];
  TC_X509_policy_expected expected[POLICY_CAPACITY];
  TC_X509_policy_mapping mappings[POLICY_CAPACITY];
  TC_bytes policies[POLICY_CAPACITY], path[PATH_CAPACITY];
  TC_X509_search_frame search_frames[PATH_CAPACITY];
  TC_X509_path_workspace validation = TC_X509_PATH_WORKSPACE_INIT(
      frames, oids, name_left, name_right, name_flags, nodes, edges, expected,
      mappings, policies);
  TC_X509_search_workspace search = {path, search_frames, PATH_CAPACITY};
  TC_X509_workspace parser = {frames, FRAME_CAPACITY, oids, EXTENSION_CAPACITY};
  TC_X509_certificate signer;
  const TC_TLV_limits limits = {ENCODED_CAPACITY, ENCODED_CAPACITY, 256,
                                FRAME_CAPACITY};
  size_t work;
  const tc_pki_tree_workspace tree = {frames, FRAME_CAPACITY, &work};
  TC_ECDSA_workspace ec;
  TC_X509_native_workspace native = {&ec, NULL,
                                     TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  TC_X509_signature_provider provider = TC_X509_native_provider(&native);
  TC_X509_public_key key;
  EVP_PKEY *generated = EVP_EC_gen("prime256v1");
  EVP_PKEY *other_key = EVP_EC_gen("prime256v1");
  TC_X509_public_key other_public;
  X509 *certificate;
  ASN1_TIME *date = ASN1_TIME_new();
  ASN1_TIME *next_date = ASN1_TIME_new();
  unsigned char *cursor = spki;
  (void)user;
  munit_assert_not_null(generated);
  munit_assert_not_null(date);
  munit_assert_not_null(next_date);
  munit_assert_int(ASN1_TIME_set_string(next_date, "270101000000Z"), ==, 1);
  munit_assert_not_null(other_key);
  int other_length = i2d_PUBKEY(other_key, NULL);
  munit_assert_int(other_length, >, 0);
  munit_assert_size((size_t)other_length, <=, sizeof other_spki);
  cursor = other_spki;
  munit_assert_int(i2d_PUBKEY(other_key, &cursor), ==, other_length);
  munit_assert_int(TC_X509_subject_public_key(other_spki, (size_t)other_length,
                                              &other_public),
                   ==, TC_TLV_OK);
  munit_assert_int(ASN1_TIME_set_string(date, "260101000000Z"), ==, 1);
  certificate = make_certificate(generated, "CRL issuer", NULL);
  add_extension(certificate, NID_subject_key_identifier, "hash");
  munit_assert_int(X509_sign(certificate, generated, EVP_sha256()), >, 0);
  int signer_length = i2d_X509(certificate, NULL);
  munit_assert_int(signer_length, >, 0);
  munit_assert_size((size_t)signer_length, <=, sizeof signer_der);
  cursor = signer_der;
  munit_assert_int(i2d_X509(certificate, &cursor), ==, signer_length);
  munit_assert_int(TC_X509_read(signer_der, (size_t)signer_length, &limits,
                                &parser, &signer),
                   ==, TC_TLV_OK);
  X509 *denied_certificate = X509_dup(certificate);
  munit_assert_not_null(denied_certificate);
  add_extension(denied_certificate, NID_key_usage, "critical,digitalSignature");
  size_t denied_length =
      encode_certificate(denied_certificate, generated, EVP_sha256(),
                         denied_der, sizeof denied_der);
  X509_free(denied_certificate);
  X509 *expired_certificate = X509_dup(certificate);
  munit_assert_not_null(expired_certificate);
  munit_assert_int(
      ASN1_TIME_set_string_X509(X509_getm_notAfter(expired_certificate),
                                "20250101000000Z"),
      ==, 1);
  size_t expired_length =
      encode_certificate(expired_certificate, generated, EVP_sha256(),
                         expired_der, sizeof expired_der);
  X509_free(expired_certificate);
  cursor = spki;
  int spki_length = i2d_PUBKEY(generated, NULL);
  munit_assert_int(spki_length, >, 0);
  munit_assert_size((size_t)spki_length, <=, sizeof spki);
  munit_assert_int(i2d_PUBKEY(generated, &cursor), ==, spki_length);
  munit_assert_int(TC_X509_subject_public_key(spki, (size_t)spki_length, &key),
                   ==, TC_TLV_OK);
  TC_X509_store_anchor anchors[2] = {0};
  anchors[0].trust = (TC_X509_trust_anchor){signer.subject, other_public};
  anchors[1].trust = (TC_X509_trust_anchor){signer.subject, signer.public_key};
  const TC_X509_store_source source = {anchors, 0, 2, NULL, crl_trust_anchor};
  TC_X509_path_options options = {0};
  options.at = (TC_X509_time){2026, 1, 1, 0, 0, 0};
  options.parsing = limits;
  options.max_certificates = PATH_CAPACITY;
  options.max_input = ENCODED_CAPACITY;
  options.signatures = provider;
  {
    X509_CRL *crl = X509_CRL_new();
    BIO *content = BIO_new_mem_buf("crl", 3);
    CMS_ContentInfo *cms;
    tc_cms_signed_data container;
    TC_TLV_reader records, entries;
    TC_TLV_element record;
    tc_x509_crl parsed;
    tc_x509_crl_extension_info crl_info;
    tc_x509_crl_entry entry;
    munit_assert_not_null(crl);
    munit_assert_not_null(content);
    munit_assert_int(X509_CRL_set_version(crl, 1), ==, 1);
    munit_assert_int(
        X509_CRL_set_issuer_name(crl, X509_get_subject_name(certificate)), ==,
        1);
    munit_assert_int(X509_CRL_set1_lastUpdate(crl, date), ==, 1);
    munit_assert_int(X509_CRL_set1_nextUpdate(crl, next_date), ==, 1);
    {
      ASN1_INTEGER *number = ASN1_INTEGER_new();
      munit_assert_not_null(number);
      munit_assert_int(ASN1_INTEGER_set(number, 1), ==, 1);
      munit_assert_int(X509_CRL_add1_ext_i2d(crl, NID_crl_number, number, 0, 0),
                       ==, 1);
      ASN1_INTEGER_free(number);
    }
    {
      AUTHORITY_KEYID *authority = AUTHORITY_KEYID_new();
      munit_assert_not_null(authority);
      authority->keyid =
          X509_get_ext_d2i(certificate, NID_subject_key_identifier, NULL, NULL);
      munit_assert_not_null(authority->keyid);
      munit_assert_int(X509_CRL_add1_ext_i2d(crl, NID_authority_key_identifier,
                                             authority, 0, 0),
                       ==, 1);
      AUTHORITY_KEYID_free(authority);
    }
    if (revoked) {
      X509_REVOKED *item = X509_REVOKED_new();
      ASN1_INTEGER *serial = ASN1_INTEGER_new();
      munit_assert_not_null(item);
      munit_assert_not_null(serial);
      munit_assert_int(ASN1_INTEGER_set(serial, 9), ==, 1);
      munit_assert_int(X509_REVOKED_set_serialNumber(item, serial), ==, 1);
      munit_assert_int(X509_REVOKED_set_revocationDate(item, date), ==, 1);
      munit_assert_int(X509_CRL_add0_revoked(crl, item), ==, 1);
      ASN1_INTEGER_free(serial);
    }
    munit_assert_int(X509_CRL_sign(crl, generated, EVP_sha256()), >, 0);
    cms = CMS_sign(certificate, generated, NULL, content,
                   CMS_BINARY | CMS_NOSMIMECAP);
    munit_assert_not_null(cms);
    munit_assert_int(CMS_add1_crl(cms, crl), ==, 1);
    int length = i2d_CMS_ContentInfo(cms, NULL);
    munit_assert_int(length, >, 0);
    munit_assert_size((size_t)length, <=, sizeof encoded);
    cursor = encoded;
    munit_assert_int(i2d_CMS_ContentInfo(cms, &cursor), ==, length);
    work = WORK_BUDGET;
    munit_assert_int(
        tc_cms_signed_data_read((TC_bytes){encoded, (size_t)length}, &limits,
                                frames, FRAME_CAPACITY, &work, &container),
        ==, TC_TLV_OK);
    munit_assert_int(
        tc_cms_signed_data_version_check(&container, &limits, &tree), ==,
        TC_TLV_OK);
    munit_assert_int(tc_pki_tree_open(container.revocations, 0xa1, TC_TLV_BER,
                                      &limits, &tree, &records),
                     ==, TC_TLV_OK);
    munit_assert_int(tc_pki_tree_next(&records, &tree, &record), ==, TC_TLV_OK);
    munit_assert_true(tc_pki_end(&records));
    munit_assert_int(tc_x509_crl_read(record.encoded, &limits, &tree, &parsed),
                     ==, TC_TLV_OK);
    munit_assert_int(tc_x509_crl_extensions_check(&parsed, &limits, &tree, oids,
                                                  EXTENSION_CAPACITY),
                     ==, TC_TLV_OK);
    munit_assert_int(
        tc_x509_crl_extension_info_read(parsed.extensions, &limits, &tree, oids,
                                        EXTENSION_CAPACITY, &crl_info),
        ==, TC_TLV_OK);
    if (check_signer) {
      work = WORK_BUDGET;
      munit_assert_int(tc_x509_crl_anchor_check(&parsed, &anchors[1].trust,
                                                &provider, &limits, &names,
                                                &work),
                       ==, TC_X509_SIGNATURE_VALID);
      const size_t required = WORK_BUDGET - work;
      munit_assert_size(required, >, 0);
      for (unsigned short_budget = 0; short_budget < 2; ++short_budget) {
        work = required - short_budget;
        munit_assert_int(
            tc_x509_crl_anchor_check(&parsed, &anchors[1].trust, &provider,
                                     &limits, &names, &work),
            ==,
            short_budget ? TC_X509_SIGNATURE_LIMIT : TC_X509_SIGNATURE_VALID);
      }
      work = WORK_BUDGET;
      munit_assert_int(tc_x509_crl_anchor_check(&parsed, &anchors[0].trust,
                                                &provider, &limits, &names,
                                                &work),
                       ==, TC_X509_SIGNATURE_INVALID);
      uint8_t changed_name[ENCODED_CAPACITY], signature[SPKI_CAPACITY];
      munit_assert_size(anchors[1].trust.name.length, <=, sizeof changed_name);
      memcpy(changed_name, anchors[1].trust.name.data,
             anchors[1].trust.name.length);
      changed_name[anchors[1].trust.name.length - 1] = 'x';
      TC_X509_trust_anchor other = anchors[1].trust;
      other.name.data = changed_name;
      work = WORK_BUDGET;
      munit_assert_int(tc_x509_crl_anchor_check(&parsed, &other, &provider,
                                                &limits, &names, &work),
                       ==, TC_X509_SIGNATURE_INVALID);
      munit_assert_size(parsed.signature.length, <=, sizeof signature);
      memcpy(signature, parsed.signature.data, parsed.signature.length);
      signature[parsed.signature.length - 1] ^= 1;
      tc_x509_crl damaged = parsed;
      damaged.signature.data = signature;
      work = WORK_BUDGET;
      munit_assert_int(tc_x509_crl_anchor_check(&damaged, &anchors[1].trust,
                                                &provider, &limits, &names,
                                                &work),
                       ==, TC_X509_SIGNATURE_INVALID);
      work = WORK_BUDGET;
      munit_assert_int(tc_x509_crl_anchor_check(&parsed, &anchors[1].trust,
                                                NULL, &limits, &names, &work),
                       ==, TC_X509_SIGNATURE_UNSUPPORTED);
      munit_assert_int(tc_x509_crl_anchor_check(&parsed, NULL, &provider,
                                                &limits, &names, &work),
                       ==, TC_X509_SIGNATURE_ERROR);
    }
    if (check_signer) {
      int matched;
      munit_assert_true(crl_info.present & TC_CRL_EXT_AUTHORITY);
      munit_assert_int(tc_pki_authority_matches(&crl_info.authority, &signer,
                                                &limits, &tree, &names,
                                                &matched),
                       ==, TC_TLV_OK);
      munit_assert_true(matched);
    }
    if (check_signer) {
      const TC_bytes candidates[] = {{denied_der, denied_length},
                                     {signer_der, (size_t)signer_length}};
      candidate_source source = {candidates, 2, 0, TC_TLV_OK, 0};
      TC_X509_store_source external = {&source, source.count, 0, read_candidate,
                                       NULL};
      tc_cms_candidates reader, start, saved;
      TC_X509_certificate candidate;
      TC_bytes selected = {NULL, 0}, previous;
      work = WORK_BUDGET;
      munit_assert_int(
          tc_cms_candidates_init(container.certificates, &external, 3,
                                 sizeof encoded + sizeof signer_der +
                                     sizeof denied_der,
                                 &limits, &tree, &reader),
          ==, TC_TLV_OK);
      start = reader;
      work = WORK_BUDGET;
      munit_assert_int(tc_cms_crl_signer_candidate_next(
                           &reader, &parsed, &crl_info, &names, &tree, &parser,
                           &candidate, &selected),
                       ==, TC_TLV_OK);
      const size_t required = WORK_BUDGET - work;
      munit_assert_size(selected.length, ==, (size_t)signer_length);
      munit_assert_memory_equal(selected.length, selected.data, signer_der);
      munit_assert_int(tc_x509_crl_signer_check(&parsed, &candidate, &provider,
                                                &limits, &names, &work),
                       ==, TC_X509_SIGNATURE_VALID);
      reader = start;
      work = 0;
      previous = selected;
      memcpy(&saved, &reader, sizeof saved);
      munit_assert_int(tc_cms_crl_signer_candidate_next(
                           &reader, &parsed, &crl_info, &names, &tree, &parser,
                           &candidate, &selected),
                       ==, TC_TLV_LIMIT);
      munit_assert_memory_equal(sizeof reader, &reader, &saved);
      munit_assert_ptr_equal(selected.data, previous.data);
      munit_assert_size(selected.length, ==, previous.length);
      work = required;
      munit_assert_int(tc_cms_crl_signer_candidate_next(
                           &reader, &parsed, &crl_info, &names, &tree, &parser,
                           &candidate, &selected),
                       ==, TC_TLV_OK);
      munit_assert_size(work, ==, 0);
      work = WORK_BUDGET;
      munit_assert_int(tc_cms_crl_signer_candidate_next(
                           &reader, &parsed, &crl_info, &names, &tree, &parser,
                           &candidate, &selected),
                       ==, TC_TLV_OK);
      munit_assert_ptr_equal(selected.data, signer_der);
      munit_assert_size(source.calls, ==, source.count);
      previous = selected;
      munit_assert_int(tc_cms_crl_signer_candidate_next(
                           &reader, &parsed, &crl_info, &names, &tree, &parser,
                           &candidate, &selected),
                       ==, TC_TLV_END);
      munit_assert_ptr_equal(selected.data, previous.data);
      munit_assert_size(selected.length, ==, previous.length);
      {
        tc_x509_crl_extension_info wrong = crl_info;
        static const uint8_t unknown_key[] = {0};
        wrong.authority.key_identifier =
            (TC_bytes){unknown_key, sizeof unknown_key};
        reader = start;
        work = WORK_BUDGET;
        munit_assert_int(tc_cms_crl_signer_candidate_next(
                             &reader, &parsed, &wrong, &names, &tree, &parser,
                             &candidate, &selected),
                         ==, TC_TLV_END);
        munit_assert_ptr_equal(selected.data, previous.data);
        munit_assert_size(selected.length, ==, previous.length);
      }
      {
        const candidate_filter_probe failures[] = {
            {TC_TLV_OK, -1, 0},   {TC_TLV_OK, 2, 0},
            {TC_TLV_END, 0, 0},   {TC_TLV_OK, 1, 1},
            {TC_TLV_LIMIT, 1, 0}, {TC_TLV_UNSUPPORTED, 1, 0}};
        for (size_t i = 0; i < sizeof failures / sizeof failures[0]; ++i) {
          reader = start;
          work = WORK_BUDGET;
          memcpy(&saved, &reader, sizeof saved);
          const TC_TLV_result expected =
              failures[i].result == TC_TLV_LIMIT ||
                      failures[i].result == TC_TLV_UNSUPPORTED
                  ? failures[i].result
                  : TC_TLV_ARGUMENT;
          munit_assert_int(tc_cms_x509_candidate_next(
                               &reader, probe_candidate_filter, &failures[i],
                               &tree, &parser, &candidate, &selected),
                           ==, expected);
          munit_assert_memory_equal(sizeof reader, &reader, &saved);
          munit_assert_ptr_equal(selected.data, previous.data);
          munit_assert_size(selected.length, ==, previous.length);
          if (failures[i].increase_work)
            munit_assert_size(work, ==, 0);
        }
      }
    }
    munit_assert_uint(parsed.version, ==, 2);
    if (check_discovery) {
      TC_X509_search_result found, saved;
      memset(&saved, 0xa5, sizeof saved);
      memcpy(&found, &saved, sizeof found);
      work = TRUST_WORK_BUDGET;
      munit_assert_int(tc_x509_crl_signer_validate(&parsed, &signer, &source, 1,
                                                   &options, &validation,
                                                   &search, &work, &found),
                       ==, TC_X509_PATH_VALID);
      munit_assert_size(found.anchor_index, ==, 1);
      munit_assert_size(found.count, ==, 1);
      munit_assert_ptr_equal(found.path[0].data, signer_der);
      const size_t required = TRUST_WORK_BUDGET - work;
      munit_assert_size(found.validation.work_used, ==, required);
      for (unsigned failure = 0; failure < 5; ++failure) {
        TC_X509_path_options rejected = options;
        size_t anchor_index = 1;
        work = TRUST_WORK_BUDGET;
        if (failure == 0)
          anchor_index = 0;
        if (failure == 1)
          rejected.at.year = 2029;
        if (failure == 2)
          rejected.flags |= TC_X509_PATH_REQUIRE_KEY_USAGE;
        if (failure == 3)
          work = required - 1;
        if (failure == 4)
          encoded[(size_t)(parsed.signature.data - encoded) +
                  parsed.signature.length - 1] ^= 1;
        memcpy(&found, &saved, sizeof found);
        munit_assert_int(
            tc_x509_crl_signer_validate(&parsed, &signer, &source, anchor_index,
                                        &rejected, &validation, &search, &work,
                                        &found),
            ==, failure == 3 ? TC_X509_PATH_LIMIT : TC_X509_PATH_INVALID);
        munit_assert_memory_equal(sizeof found, &found, &saved);
        if (failure == 4)
          encoded[(size_t)(parsed.signature.data - encoded) +
                  parsed.signature.length - 1] ^= 1;
      }
      work = required;
      munit_assert_int(tc_x509_crl_signer_validate(&parsed, &signer, &source, 1,
                                                   &options, &validation,
                                                   &search, &work, &found),
                       ==, TC_X509_PATH_VALID);
      munit_assert_size(work, ==, 0);
      {
        TC_X509_certificate denied_signer;
        munit_assert_int(TC_X509_read(denied_der, denied_length, &limits,
                                      &parser, &denied_signer),
                         ==, TC_TLV_OK);
        work = TRUST_WORK_BUDGET;
        memcpy(&found, &saved, sizeof found);
        munit_assert_int(tc_x509_crl_signer_validate(
                             &parsed, &denied_signer, &source, 1, &options,
                             &validation, &search, &work, &found),
                         ==, TC_X509_PATH_INVALID);
        munit_assert_memory_equal(sizeof found, &found, &saved);
        work = TRUST_WORK_BUDGET;
        munit_assert_int(tc_x509_crl_signer_validate(
                             &parsed, &signer, &source, source.anchor_count,
                             &options, &validation, &search, &work, &found),
                         ==, TC_X509_PATH_ERROR);
        munit_assert_memory_equal(sizeof found, &found, &saved);
        munit_assert_size(work, ==, TRUST_WORK_BUDGET);
        options.signatures.verify = NULL;
        munit_assert_int(tc_x509_crl_signer_validate(&parsed, &signer, &source,
                                                     1, &options, &validation,
                                                     &search, &work, &found),
                         ==, TC_X509_PATH_UNSUPPORTED);
        munit_assert_memory_equal(sizeof found, &found, &saved);
      }
      {
        const TC_bytes records[] = {{expired_der, expired_length},
                                    {denied_der, denied_length},
                                    {signer_der, (size_t)signer_length},
                                    {signer_der, (size_t)signer_length}};
        candidate_source candidates = {records, 4, 0, TC_TLV_OK, 0};
        const TC_X509_store_source external = {&candidates, candidates.count, 0,
                                               read_candidate, NULL};
        tc_cms_candidates reader, before;
        options.signatures = provider;
        work = TRUST_WORK_BUDGET;
        munit_assert_int(
            tc_cms_candidates_init(
                (TC_bytes){NULL, 0}, &external, candidates.count,
                sizeof expired_der + sizeof denied_der + 2 * sizeof signer_der,
                &limits, &tree, &reader),
            ==, TC_TLV_OK);
        memcpy(&before, &reader, sizeof before);
        work = TRUST_WORK_BUDGET;
        munit_assert_int(tc_cms_crl_signer_find(&reader, &parsed, &crl_info,
                                                &source, 1, &options, &tree,
                                                &validation, &search, &found),
                         ==, TC_X509_PATH_VALID);
        munit_assert_size(candidates.calls, ==, 3);
        munit_assert_ptr_equal(found.path[found.count - 1].data, signer_der);
        munit_assert_memory_equal(sizeof reader, &reader, &before);
        const size_t search_work = TRUST_WORK_BUDGET - work;
        munit_assert_size(found.validation.work_used, ==, search_work);
        work = search_work - 1;
        memcpy(&found, &saved, sizeof found);
        munit_assert_int(tc_cms_crl_signer_find(&reader, &parsed, &crl_info,
                                                &source, 1, &options, &tree,
                                                &validation, &search, &found),
                         ==, TC_X509_PATH_LIMIT);
        munit_assert_memory_equal(sizeof found, &found, &saved);
        munit_assert_size(work, ==, 0);
        work = search_work;
        munit_assert_int(tc_cms_crl_signer_find(&reader, &parsed, &crl_info,
                                                &source, 1, &options, &tree,
                                                &validation, &search, &found),
                         ==, TC_X509_PATH_VALID);
        munit_assert_size(work, ==, 0);
        signature_retry_probe probe = {provider, 0, 2,
                                       TC_X509_SIGNATURE_UNSUPPORTED};
        options.signatures =
            (TC_X509_signature_provider){retry_signature, &probe, NULL};
        work = TRUST_WORK_BUDGET;
        candidates.calls = 0;
        munit_assert_int(tc_cms_crl_signer_find(&reader, &parsed, &crl_info,
                                                &source, 1, &options, &tree,
                                                &validation, &search, &found),
                         ==, TC_X509_PATH_VALID);
        munit_assert_size(candidates.calls, ==, candidates.count);
        munit_assert_size(probe.calls, ==, 4);
        probe.calls = 0;
        probe.failure = TC_X509_SIGNATURE_ERROR;
        work = TRUST_WORK_BUDGET;
        candidates.calls = 0;
        memcpy(&found, &saved, sizeof found);
        munit_assert_int(tc_cms_crl_signer_find(&reader, &parsed, &crl_info,
                                                &source, 1, &options, &tree,
                                                &validation, &search, &found),
                         ==, TC_X509_PATH_ERROR);
        munit_assert_size(candidates.calls, ==, 3);
        munit_assert_memory_equal(sizeof found, &found, &saved);
        options.signatures.verify = NULL;
        work = TRUST_WORK_BUDGET;
        memcpy(&found, &saved, sizeof found);
        munit_assert_int(tc_cms_crl_signer_find(&reader, &parsed, &crl_info,
                                                &source, 1, &options, &tree,
                                                &validation, &search, &found),
                         ==, TC_X509_PATH_UNSUPPORTED);
        munit_assert_memory_equal(sizeof found, &found, &saved);
        options.signatures = provider;
        work = TRUST_WORK_BUDGET;
        munit_assert_int(tc_cms_crl_signer_find(&reader, &parsed, &crl_info,
                                                &source, 0, &options, &tree,
                                                &validation, &search, &found),
                         ==, TC_X509_PATH_INVALID);
        munit_assert_memory_equal(sizeof found, &found, &saved);
        munit_assert_memory_equal(sizeof reader, &reader, &before);
        {
          const uint8_t serial = 9;
          TC_X509_certificate target = {0};
          target.serial = (TC_bytes){&serial, 1};
          target.issuer = parsed.issuer;
          const tc_pki_distribution_point point = {0};
          const tc_x509_crl_query query = {&target, &point, 0};
          const tc_x509_crl_selected selected = {&parsed, &crl_info, NULL,
                                                 NULL};
          tc_x509_crl_evidence evidence = {0}, initial = {0};
          tc_x509_crl_status status;
          initial.reasons = 1u << 1;
          evidence = initial;
          work = TRUST_WORK_BUDGET;
          candidates.calls = 0;
          munit_assert_int(tc_cms_crl_process(
                               &reader, &selected, &query, &source, 1, &options,
                               &tree, &validation, &search, &evidence, &found),
                           ==, TC_TLV_OK);
          const size_t required = TRUST_WORK_BUDGET - work;
          munit_assert_size(found.validation.work_used, ==, required);
          munit_assert_size(candidates.calls, ==, 3);
          munit_assert_ptr_equal(found.path[found.count - 1].data, signer_der);
          munit_assert_int(tc_x509_crl_evidence_status(&evidence, &status), ==,
                           TC_TLV_OK);
          munit_assert_int(status, ==,
                           revoked ? TC_X509_CRL_REVOKED
                                   : TC_X509_CRL_UNREVOKED);
          const tc_x509_crl_evidence terminal = evidence;
          work = 0;
          memcpy(&found, &saved, sizeof found);
          munit_assert_int(tc_cms_crl_process(
                               &reader, &selected, &query, &source, 1, &options,
                               &tree, &validation, &search, &evidence, &found),
                           ==, TC_TLV_END);
          munit_assert_memory_equal(sizeof evidence, &evidence, &terminal);
          munit_assert_memory_equal(sizeof found, &found, &saved);
          munit_assert_size(candidates.calls, ==, 3);
          evidence = initial;
          work = required;
          munit_assert_int(tc_cms_crl_process(
                               &reader, &selected, &query, &source, 1, &options,
                               &tree, &validation, &search, &evidence, &found),
                           ==, TC_TLV_OK);
          munit_assert_size(work, ==, 0);
          enum {
            SHORT,
            ANCHOR,
            PROVIDER,
            SOURCE_ERROR,
            MALFORMED,
            INCREASE_WORK,
            NO_MATCH,
            STALE,
            RETRY_UNSUPPORTED,
            RETRY_ERROR
          };
          const struct {
            unsigned kind;
            TC_TLV_result result;
          } cases[] = {{SHORT, TC_TLV_LIMIT},
                       {ANCHOR, TC_TLV_INVALID},
                       {PROVIDER, TC_TLV_UNSUPPORTED},
                       {SOURCE_ERROR, TC_TLV_UNSUPPORTED},
                       {MALFORMED, TC_TLV_INVALID},
                       {INCREASE_WORK, TC_TLV_ARGUMENT},
                       {NO_MATCH, TC_TLV_INVALID},
                       {STALE, TC_TLV_END},
                       {RETRY_UNSUPPORTED, TC_TLV_OK},
                       {RETRY_ERROR, TC_TLV_ARGUMENT}};
          static const uint8_t malformed[] = {0x31, 0};
          const TC_bytes bad_records[] = {{malformed, sizeof malformed}};
          const TC_bytes denied_records[] = {{denied_der, denied_length},
                                             {denied_der, denied_length},
                                             {denied_der, denied_length},
                                             {denied_der, denied_length}};
          const TC_X509_crl_record indexed_record = {parsed, crl_info,
                                                     TC_TLV_OK};
          const TC_X509_crl_index crl_index = {&indexed_record, 1, 0};
          evidence = initial;
          work = TRUST_WORK_BUDGET;
          munit_assert_int(
              tc_cms_crl_index_process(&reader, &crl_index, 0,
                                       TC_X509_CRL_DELTA_IF_AVAILABLE, &query,
                                       &source, 1, &options, &tree, &validation,
                                       &search, &evidence, &found),
              ==, TC_TLV_OK);
          const size_t indexed_required = TRUST_WORK_BUDGET - work;
          evidence = initial;
          work = indexed_required;
          munit_assert_int(
              tc_cms_crl_index_process(&reader, &crl_index, 0,
                                       TC_X509_CRL_DELTA_IF_AVAILABLE, &query,
                                       &source, 1, &options, &tree, &validation,
                                       &search, &evidence, &found),
              ==, TC_TLV_OK);
          munit_assert_size(work, ==, 0);
          uint8_t signature_states[1];
          evidence = initial;
          work = TRUST_WORK_BUDGET;
          munit_assert_int(
              tc_cms_crl_scope_process(
                  &reader, &crl_index, 0, TC_X509_CRL_DELTA_IF_AVAILABLE,
                  TC_X509_CRL_ORDER_NUMBER, &query, &source, 1, &options, &tree,
                  &validation, &search, signature_states,
                  sizeof signature_states, &evidence, &found),
              ==, TC_TLV_OK);
          const size_t scope_required = TRUST_WORK_BUDGET - work;
          evidence = initial;
          work = scope_required;
          munit_assert_int(
              tc_cms_crl_scope_process(
                  &reader, &crl_index, 0, TC_X509_CRL_DELTA_IF_AVAILABLE,
                  TC_X509_CRL_ORDER_NUMBER, &query, &source, 1, &options, &tree,
                  &validation, &search, signature_states,
                  sizeof signature_states, &evidence, &found),
              ==, TC_TLV_OK);
          munit_assert_size(work, ==, 0);
          enum { COVERED_REASONS, OTHER_ISSUER, FILTER_CASES };
          static const uint8_t other_issuer[] = {0x30, 0x0c, 0x31, 0x0a, 0x30,
                                                 0x08, 0x06, 0x03, 0x55, 0x04,
                                                 0x03, 0x0c, 0x01, 'x'};
          for (unsigned filter = COVERED_REASONS; filter < FILTER_CASES;
               ++filter) {
            TC_X509_certificate filtered_target = target;
            tc_pki_distribution_point filtered_point = point;
            if (filter == COVERED_REASONS) {
              filtered_point.has_reasons = 1;
              filtered_point.reasons = initial.reasons;
            } else
              filtered_target.issuer =
                  (TC_bytes){other_issuer, sizeof other_issuer};
            const tc_x509_crl_query filtered_query = {&filtered_target,
                                                      &filtered_point, 0};
            TC_X509_path_options filtered_options = options;
            filtered_options.signatures.verify = NULL;
            candidates =
                (candidate_source){records, 4, 0, TC_TLV_UNSUPPORTED, 0};
            evidence = initial;
            found = saved;
            work = TRUST_WORK_BUDGET;
            signature_states[0] = 0xa5;
            munit_assert_int(tc_cms_crl_scope_process(
                                 &reader, &crl_index, 0,
                                 TC_X509_CRL_DELTA_IF_AVAILABLE,
                                 TC_X509_CRL_ORDER_NUMBER, &filtered_query,
                                 &source, 1, &filtered_options, &tree,
                                 &validation, &search, signature_states,
                                 sizeof signature_states, &evidence, &found),
                             ==, TC_TLV_END);
            const size_t filter_work = TRUST_WORK_BUDGET - work;
            munit_assert_memory_equal(sizeof evidence, &evidence, &initial);
            munit_assert_memory_equal(sizeof found, &found, &saved);
            munit_assert_size(candidates.calls, ==, 0);
            munit_assert_uint(signature_states[0], ==, 0xa5);
            work = filter_work - 1;
            munit_assert_int(tc_cms_crl_scope_process(
                                 &reader, &crl_index, 0,
                                 TC_X509_CRL_DELTA_IF_AVAILABLE,
                                 TC_X509_CRL_ORDER_NUMBER, &filtered_query,
                                 &source, 1, &filtered_options, &tree,
                                 &validation, &search, signature_states,
                                 sizeof signature_states, &evidence, &found),
                             ==, TC_TLV_LIMIT);
            munit_assert_memory_equal(sizeof evidence, &evidence, &initial);
            munit_assert_memory_equal(sizeof found, &found, &saved);
            work = filter_work;
            munit_assert_int(tc_cms_crl_scope_process(
                                 &reader, &crl_index, 0,
                                 TC_X509_CRL_DELTA_IF_AVAILABLE,
                                 TC_X509_CRL_ORDER_NUMBER, &filtered_query,
                                 &source, 1, &filtered_options, &tree,
                                 &validation, &search, signature_states,
                                 sizeof signature_states, &evidence, &found),
                             ==, TC_TLV_END);
            munit_assert_size(work, ==, 0);
            munit_assert_size(candidates.calls, ==, 0);
            munit_assert_uint(signature_states[0], ==, 0xa5);
          }
          for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
            TC_X509_path_options checked = options;
            size_t anchor_index = 1;
            signature_retry_probe retry = {provider, 0, 2,
                                           TC_X509_SIGNATURE_UNSUPPORTED};
            candidates = (candidate_source){records, 4, 0, TC_TLV_OK, 0};
            evidence = initial;
            work = TRUST_WORK_BUDGET;
            memcpy(&found, &saved, sizeof found);
            switch (cases[i].kind) {
            case SHORT:
              work = required - 1;
              break;
            case ANCHOR:
              anchor_index = 0;
              break;
            case PROVIDER:
              checked.signatures.verify = NULL;
              break;
            case SOURCE_ERROR:
              candidates.status = TC_TLV_UNSUPPORTED;
              break;
            case MALFORMED:
              candidates.records = bad_records;
              candidates.count = 1;
              break;
            case INCREASE_WORK:
              candidates.increase_work = 1;
              break;
            case NO_MATCH:
              candidates.records = denied_records;
              break;
            case STALE:
              checked.at = parsed.next_update;
              break;
            case RETRY_ERROR:
              retry.failure = TC_X509_SIGNATURE_ERROR; /* fall through */
            case RETRY_UNSUPPORTED:
              checked.signatures =
                  (TC_X509_signature_provider){retry_signature, &retry, NULL};
              break;
            }
            munit_assert_int(tc_cms_crl_process(&reader, &selected, &query,
                                                &source, anchor_index, &checked,
                                                &tree, &validation, &search,
                                                &evidence, &found),
                             ==, cases[i].result);
            munit_assert_memory_equal(sizeof reader, &reader, &before);
            if (cases[i].result != TC_TLV_OK) {
              munit_assert_memory_equal(sizeof evidence, &evidence, &initial);
              munit_assert_memory_equal(sizeof found, &found, &saved);
            } else {
              munit_assert_size(candidates.calls, ==, 4);
              munit_assert_size(retry.calls, ==, 4);
              munit_assert_size(found.validation.work_used, ==,
                                TRUST_WORK_BUDGET - work);
              munit_assert_int(tc_x509_crl_evidence_status(&evidence, &status),
                               ==, TC_TLV_OK);
              munit_assert_int(status, ==,
                               revoked ? TC_X509_CRL_REVOKED
                                       : TC_X509_CRL_UNREVOKED);
            }
            if (cases[i].kind == SOURCE_ERROR || cases[i].kind == MALFORMED ||
                cases[i].kind == INCREASE_WORK || cases[i].kind == STALE)
              munit_assert_size(candidates.calls, ==, 1);
            if (cases[i].kind == RETRY_ERROR)
              munit_assert_size(candidates.calls, ==, 3);
            for (unsigned scope = 0; scope < 2; ++scope) {
              candidates.calls = 0;
              retry.calls = 0;
              evidence = initial;
              memcpy(&found, &saved, sizeof found);
              const size_t operation_work =
                  scope ? scope_required : indexed_required;
              work = cases[i].kind == SHORT ? operation_work - 1
                                            : TRUST_WORK_BUDGET;
              TC_TLV_result result =
                  scope
                      ? tc_cms_crl_scope_process(
                            &reader, &crl_index, 0,
                            TC_X509_CRL_DELTA_IF_AVAILABLE,
                            TC_X509_CRL_ORDER_NUMBER, &query, &source,
                            anchor_index, &checked, &tree, &validation, &search,
                            signature_states, sizeof signature_states,
                            &evidence, &found)
                      : tc_cms_crl_index_process(&reader, &crl_index, 0,
                                                 TC_X509_CRL_DELTA_IF_AVAILABLE,
                                                 &query, &source, anchor_index,
                                                 &checked, &tree, &validation,
                                                 &search, &evidence, &found);
              munit_assert_int(result, ==, cases[i].result);
              munit_assert_memory_equal(sizeof reader, &reader, &before);
              if (cases[i].result != TC_TLV_OK) {
                munit_assert_memory_equal(sizeof evidence, &evidence, &initial);
                munit_assert_memory_equal(sizeof found, &found, &saved);
              } else {
                munit_assert_size(candidates.calls, ==, 4);
                munit_assert_size(retry.calls, ==, 4);
                munit_assert_size(found.validation.work_used, ==,
                                  TRUST_WORK_BUDGET - work);
                munit_assert_int(
                    tc_x509_crl_evidence_status(&evidence, &status), ==,
                    TC_TLV_OK);
                munit_assert_int(status, ==,
                                 revoked ? TC_X509_CRL_REVOKED
                                         : TC_X509_CRL_UNREVOKED);
              }
            }
          }
          const void *state_overlaps[] = {&options,
                                          &validation,
                                          &search,
                                          &tree,
                                          &reader,
                                          &external,
                                          &crl_index,
                                          &indexed_record,
                                          &query,
                                          &target,
                                          &point,
                                          parsed.encoded.data,
                                          target.serial.data,
                                          frames,
                                          oids,
                                          name_left,
                                          name_right,
                                          name_flags,
                                          nodes,
                                          edges,
                                          expected,
                                          mappings,
                                          policies,
                                          path,
                                          search_frames,
                                          &evidence,
                                          &found,
                                          &work};
          for (size_t overlap = 0;
               overlap < sizeof state_overlaps / sizeof *state_overlaps;
               ++overlap) {
            candidates = (candidate_source){records, 4, 0, TC_TLV_OK, 0};
            evidence = initial;
            found = saved;
            work = TRUST_WORK_BUDGET;
            munit_assert_int(
                tc_cms_crl_scope_process(
                    &reader, &crl_index, 0, TC_X509_CRL_DELTA_IF_AVAILABLE,
                    TC_X509_CRL_ORDER_NUMBER, &query, &source, 1, &options,
                    &tree, &validation, &search,
                    (uint8_t *)state_overlaps[overlap], 1, &evidence, &found),
                ==, TC_TLV_ARGUMENT);
            munit_assert_memory_equal(sizeof evidence, &evidence, &initial);
            munit_assert_memory_equal(sizeof found, &found, &saved);
            munit_assert_size(work, ==, TRUST_WORK_BUDGET);
            munit_assert_size(candidates.calls, ==, 0);
          }
          const void *returned_overlaps[] = {
              frames,           oids,      name_left, name_right,
              name_flags,       nodes,     edges,     expected,
              mappings,         policies,  path,      search_frames,
              signature_states, &evidence, &found,    &work};
          for (size_t overlap = 0;
               overlap < sizeof returned_overlaps / sizeof *returned_overlaps;
               ++overlap) {
            const TC_bytes returned = {returned_overlaps[overlap], 1};
            candidates = (candidate_source){&returned, 1, 0, TC_TLV_OK, 0};
            evidence = initial;
            found = saved;
            work = TRUST_WORK_BUDGET;
            munit_assert_int(
                tc_cms_crl_scope_process(
                    &reader, &crl_index, 0, TC_X509_CRL_DELTA_IF_AVAILABLE,
                    TC_X509_CRL_ORDER_NUMBER, &query, &source, 1, &options,
                    &tree, &validation, &search, signature_states,
                    sizeof signature_states, &evidence, &found),
                ==, TC_TLV_ARGUMENT);
            munit_assert_memory_equal(sizeof evidence, &evidence, &initial);
            munit_assert_memory_equal(sizeof found, &found, &saved);
            munit_assert_size(candidates.calls, ==, 1);
          }
          const TC_bytes anchor_name = anchors[1].trust.name;
          for (size_t overlap = 0;
               overlap < sizeof returned_overlaps / sizeof *returned_overlaps;
               ++overlap) {
            candidates = (candidate_source){records, 4, 0, TC_TLV_OK, 0};
            anchors[1].trust.name = (TC_bytes){returned_overlaps[overlap], 1};
            evidence = initial;
            found = saved;
            work = TRUST_WORK_BUDGET;
            munit_assert_int(
                tc_cms_crl_scope_process(
                    &reader, &crl_index, 0, TC_X509_CRL_DELTA_IF_AVAILABLE,
                    TC_X509_CRL_ORDER_NUMBER, &query, &source, 1, &options,
                    &tree, &validation, &search, signature_states,
                    sizeof signature_states, &evidence, &found),
                ==, TC_TLV_ARGUMENT);
            munit_assert_memory_equal(sizeof evidence, &evidence, &initial);
            munit_assert_memory_equal(sizeof found, &found, &saved);
          }
          anchors[1].trust.name = anchor_name;
          candidates = (candidate_source){records, 4, 0, TC_TLV_OK, 0};
          const tc_pki_tree_workspace partial_tree = {
              frames + 1, FRAME_CAPACITY - 1, &work};
          evidence = initial;
          found = saved;
          work = TRUST_WORK_BUDGET;
          munit_assert_int(
              tc_cms_crl_scope_process(
                  &reader, &crl_index, 0, TC_X509_CRL_DELTA_IF_AVAILABLE,
                  TC_X509_CRL_ORDER_NUMBER, &query, &source, 1, &options,
                  &partial_tree, &validation, &search, signature_states,
                  sizeof signature_states, &evidence, &found),
              ==, TC_TLV_ARGUMENT);
          munit_assert_memory_equal(sizeof evidence, &evidence, &initial);
          munit_assert_memory_equal(sizeof found, &found, &saved);
          munit_assert_size(work, ==, TRUST_WORK_BUDGET);
          munit_assert_size(candidates.calls, ==, 0);
          if (!revoked) {
            enum { PARTITIONS = 2, KEY_COMPROMISE_MASK = 1u << 1 };
            {
              uint8_t replacement_der[ENCODED_CAPACITY],
                  alternative_der[ENCODED_CAPACITY];
              uint8_t rollover_der[PARTITIONS][ENCODED_CAPACITY];
              X509 *replacement =
                  make_certificate(other_key, "CRL issuer", certificate);
              munit_assert_int(
                  ASN1_INTEGER_set(X509_get_serialNumber(replacement), 2), ==,
                  1);
              add_extension(replacement, NID_subject_key_identifier, "hash");
              add_extension(replacement, NID_key_usage, "critical,cRLSign");
              const size_t replacement_length =
                  encode_certificate(replacement, generated, EVP_sha256(),
                                     replacement_der, sizeof replacement_der);
              TC_X509_certificate replacement_view;
              work = TRUST_WORK_BUDGET;
              munit_assert_int(TC_X509_read(replacement_der, replacement_length,
                                            &limits, &parser,
                                            &replacement_view),
                               ==, TC_TLV_OK);
              TC_bytes rollover_inputs[PARTITIONS];
              X509_CRL *newest = NULL;
              for (unsigned generation = 0; generation < PARTITIONS;
                   ++generation) {
                X509_CRL *variant = make_partition_crl(
                    crl, generation ? other_key : generated,
                    TC_X509_CRL_ALL_REASONS, (int)generation);
                if (generation) {
                  ASN1_INTEGER *number = ASN1_INTEGER_new();
                  ASN1_TIME *update = ASN1_TIME_new();
                  AUTHORITY_KEYID *authority = AUTHORITY_KEYID_new();
                  munit_assert_not_null(number);
                  munit_assert_not_null(update);
                  munit_assert_not_null(authority);
                  munit_assert_int(ASN1_INTEGER_set(number, 2), ==, 1);
                  munit_assert_int(
                      ASN1_TIME_set_string(update, "260102000000Z"), ==, 1);
                  authority->keyid = X509_get_ext_d2i(
                      replacement, NID_subject_key_identifier, NULL, NULL);
                  munit_assert_not_null(authority->keyid);
                  munit_assert_int(X509_CRL_add1_ext_i2d(variant,
                                                         NID_crl_number, number,
                                                         0, X509V3_ADD_REPLACE),
                                   ==, 1);
                  munit_assert_int(X509_CRL_add1_ext_i2d(
                                       variant, NID_authority_key_identifier,
                                       authority, 0, X509V3_ADD_REPLACE),
                                   ==, 1);
                  munit_assert_int(X509_CRL_set1_lastUpdate(variant, update),
                                   ==, 1);
                  munit_assert_int(
                      X509_CRL_sign(variant, other_key, EVP_sha256()), >, 0);
                  AUTHORITY_KEYID_free(authority);
                  ASN1_TIME_free(update);
                  ASN1_INTEGER_free(number);
                }
                const int length = i2d_X509_CRL(variant, NULL);
                munit_assert_int(length, >, 0);
                munit_assert_size((size_t)length, <=,
                                  sizeof rollover_der[generation]);
                unsigned char *destination = rollover_der[generation];
                munit_assert_int(i2d_X509_CRL(variant, &destination), ==,
                                 length);
                rollover_inputs[generation] =
                    (TC_bytes){rollover_der[generation], (size_t)length};
                if (generation)
                  newest = variant;
                else
                  X509_CRL_free(variant);
              }
              munit_assert_int(
                  ASN1_INTEGER_set(X509_get_serialNumber(replacement), 3), ==,
                  1);
              const size_t alternative_length =
                  encode_certificate(replacement, generated, EVP_sha256(),
                                     alternative_der, sizeof alternative_der);
              X509_free(replacement);
              const TC_bytes signer_inputs[] = {
                  {signer_der, (size_t)signer_length},
                  {replacement_der, replacement_length}};
              candidate_source signer_source = {signer_inputs, PARTITIONS, 0,
                                                TC_TLV_OK, 0};
              const TC_X509_store_source signer_records = {
                  &signer_source, PARTITIONS, 0, read_candidate, NULL};
              candidate_source rollover_source = {rollover_inputs, PARTITIONS,
                                                  0, TC_TLV_OK, 0};
              const tc_pki_record_source rollover_records = {
                  &rollover_source, PARTITIONS, read_candidate};
              TC_X509_path_options rollover_options = options;
              rollover_options.at.day = 2;
              enum { NEWER, TIED, BAD_SIGNATURE, UNNUMBERED, ROLLOVER_CASES };
              for (unsigned kind = NEWER; kind < ROLLOVER_CASES; ++kind) {
                ASN1_INTEGER *number = ASN1_INTEGER_new();
                ASN1_TIME *update = ASN1_TIME_new();
                munit_assert_not_null(number);
                munit_assert_not_null(update);
                munit_assert_int(ASN1_INTEGER_set(number, kind == TIED ? 1 : 2),
                                 ==, 1);
                munit_assert_int(ASN1_TIME_set_string(
                                     update, kind == TIED ? "260101000000Z"
                                                          : "260102000000Z"),
                                 ==, 1);
                munit_assert_int(X509_CRL_add1_ext_i2d(newest, NID_crl_number,
                                                       number, 0,
                                                       X509V3_ADD_REPLACE),
                                 ==, 1);
                munit_assert_int(X509_CRL_set1_lastUpdate(newest, update), ==,
                                 1);
                ASN1_TIME_free(update);
                ASN1_INTEGER_free(number);
                if (kind == UNNUMBERED) {
                  const int extension =
                      X509_CRL_get_ext_by_NID(newest, NID_crl_number, -1);
                  munit_assert_int(extension, >=, 0);
                  X509_EXTENSION_free(X509_CRL_delete_ext(newest, extension));
                }
                munit_assert_int(X509_CRL_sign(newest, other_key, EVP_sha256()),
                                 >, 0);
                const int length = i2d_X509_CRL(newest, NULL);
                munit_assert_int(length, >, 0);
                munit_assert_size((size_t)length, <=, sizeof rollover_der[1]);
                unsigned char *destination = rollover_der[1];
                munit_assert_int(i2d_X509_CRL(newest, &destination), ==,
                                 length);
                if (kind == BAD_SIGNATURE)
                  rollover_der[1][length - 1] ^= 1;
                rollover_inputs[1] =
                    (TC_bytes){rollover_der[1], (size_t)length};
                for (unsigned order = 0; order < PARTITIONS; ++order) {
                  tc_cms_candidates rollover_candidates;
                  tc_cms_revocations rollover_reader;
                  TC_X509_crl_record rows[PARTITIONS];
                  TC_X509_crl_index index;
                  uint8_t states[PARTITIONS];
                  work = TRUST_WORK_BUDGET;
                  munit_assert_int(tc_cms_candidates_init(
                                       (TC_bytes){NULL, 0}, &signer_records,
                                       PARTITIONS,
                                       PARTITIONS * ENCODED_CAPACITY, &limits,
                                       &tree, &rollover_candidates),
                                   ==, TC_TLV_OK);
                  munit_assert_int(tc_cms_revocations_init(
                                       (TC_bytes){NULL, 0}, &rollover_records,
                                       PARTITIONS, sizeof rollover_der, &limits,
                                       &tree, &rollover_reader),
                                   ==, TC_TLV_OK);
                  munit_assert_int(
                      tc_cms_crl_index_init(&rollover_reader, &tree, oids,
                                            EXTENSION_CAPACITY, rows,
                                            PARTITIONS, &index),
                      ==, TC_TLV_OK);
                  for (unsigned reference = 0; reference < PARTITIONS;
                       ++reference) {
                    const unsigned generation =
                        order ? PARTITIONS - 1 - reference : reference;
                    munit_assert_int(
                        tc_x509_crl_signer_validate(
                            &rows[reference].crl,
                            generation ? &replacement_view : &signer, &source,
                            1, &rollover_options, &validation, &search, &work,
                            &found),
                        ==,
                        generation && kind == BAD_SIGNATURE
                            ? TC_X509_PATH_INVALID
                            : TC_X509_PATH_VALID);
                  }
                  crl_path_probe probe = {
                      {NULL, 0}, 1, 0, TC_X509_PATH_VALID, 0, NULL, 0};
                  const tc_x509_crl_path_check check = {&probe, check_crl_path};
                  evidence = (tc_x509_crl_evidence){0};
                  work = TRUST_WORK_BUDGET;
                  const tc_x509_crl_evidence empty = {0};
                  const TC_TLV_result expected_result =
                      kind == TIED         ? TC_TLV_INVALID
                      : kind == UNNUMBERED ? TC_TLV_UNSUPPORTED
                                           : TC_TLV_OK;
                  munit_assert_int(tc_cms_crl_point_process(
                                       &rollover_candidates, &index,
                                       TC_X509_CRL_COMPLETE_ONLY,
                                       TC_X509_CRL_ORDER_NUMBER, &query,
                                       &source, 1, &rollover_options, &tree,
                                       &validation, &search, states,
                                       sizeof states, &check, &evidence),
                                   ==, expected_result);
                  munit_assert_size(probe.calls, ==,
                                    kind == BAD_SIGNATURE ? 1 : PARTITIONS);
                  if (expected_result == TC_TLV_OK) {
                    munit_assert_int(
                        tc_x509_crl_evidence_status(&evidence, &status), ==,
                        TC_TLV_OK);
                    munit_assert_int(status, ==,
                                     kind == BAD_SIGNATURE
                                         ? TC_X509_CRL_UNREVOKED
                                         : TC_X509_CRL_REVOKED);
                    if (kind == NEWER)
                      munit_assert_uint(evidence.revocation.reason, ==, 1);
                  } else
                    munit_assert_memory_equal(sizeof evidence, &evidence,
                                              &empty);
                  const size_t required_work = TRUST_WORK_BUDGET - work;
                  const tc_x509_crl_evidence expected_evidence = evidence;
                  munit_assert_size(required_work, >, 0);
                  for (unsigned short_budget = 0; short_budget < 2;
                       ++short_budget) {
                    evidence = empty;
                    probe.calls = 0;
                    work = required_work - short_budget;
                    munit_assert_int(
                        tc_cms_crl_point_process(
                            &rollover_candidates, &index,
                            TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER,
                            &query, &source, 1, &rollover_options, &tree,
                            &validation, &search, states, sizeof states, &check,
                            &evidence),
                        ==, short_budget ? TC_TLV_LIMIT : expected_result);
                    if (short_budget)
                      munit_assert_memory_equal(sizeof evidence, &evidence,
                                                &empty);
                    else
                      assert_evidence_equal(&evidence, &expected_evidence);
                  }
                  if (kind == NEWER || kind == TIED) {
                    if (kind == NEWER) {
                      TC_X509_revocation_node nodes[1];
                      const tc_cms_crl_resolution resolution = {
                          &rollover_candidates,
                          &index,
                          &source,
                          &rollover_options,
                          1,
                          TC_X509_CRL_COMPLETE_ONLY,
                          TC_X509_CRL_ORDER_NUMBER};
                      const tc_x509_crl_resolution_workspace workspace = {
                          &tree,         &validation, &search, states,
                          sizeof states, nodes,       1};
                      evidence = empty;
                      work = TRUST_WORK_BUDGET;
                      munit_assert_int(
                          tc_cms_crl_resolve(&replacement_view, &resolution,
                                             &workspace, &evidence),
                          ==, TC_TLV_UNSUPPORTED);
                      munit_assert_memory_equal(sizeof evidence, &evidence,
                                                &empty);
                      munit_assert_int(nodes[0].status, ==,
                                       TC_X509_CRL_UNDETERMINED);
                    }
                    for (unsigned generation = 0; generation < PARTITIONS;
                         ++generation) {
                      for (unsigned rejected = 0; rejected < 2; ++rejected) {
                        unresolved_crl_probe unresolved = {
                            {{NULL, 0}, 1, 0, TC_X509_PATH_VALID, 0, NULL, 0},
                            signer_inputs[generation],
                            rejected ? TC_X509_PATH_INVALID
                                     : TC_X509_PATH_UNSUPPORTED};
                        const tc_x509_crl_path_check pending_check = {
                            &unresolved, check_unresolved_crl_path};
                        const TC_TLV_result pending_result =
                            !rejected && (generation || kind == TIED)
                                ? TC_TLV_UNSUPPORTED
                                : TC_TLV_OK;
                        evidence = empty;
                        work = TRUST_WORK_BUDGET;
                        munit_assert_int(tc_cms_crl_point_process(
                                             &rollover_candidates, &index,
                                             TC_X509_CRL_COMPLETE_ONLY,
                                             TC_X509_CRL_ORDER_NUMBER, &query,
                                             &source, 1, &rollover_options,
                                             &tree, &validation, &search,
                                             states, sizeof states,
                                             &pending_check, &evidence),
                                         ==, pending_result);
                        if (pending_result != TC_TLV_OK)
                          munit_assert_memory_equal(sizeof evidence, &evidence,
                                                    &empty);
                        else {
                          munit_assert_int(
                              tc_x509_crl_evidence_status(&evidence, &status),
                              ==, TC_TLV_OK);
                          munit_assert_int(status, ==,
                                           generation ? TC_X509_CRL_UNREVOKED
                                                      : TC_X509_CRL_REVOKED);
                        }
                        const size_t required = TRUST_WORK_BUDGET - work;
                        const tc_x509_crl_evidence expected = evidence;
                        for (unsigned short_budget = 0; short_budget < 2;
                             ++short_budget) {
                          evidence = empty;
                          work = required - short_budget;
                          munit_assert_int(
                              tc_cms_crl_point_process(
                                  &rollover_candidates, &index,
                                  TC_X509_CRL_COMPLETE_ONLY,
                                  TC_X509_CRL_ORDER_NUMBER, &query, &source, 1,
                                  &rollover_options, &tree, &validation,
                                  &search, states, sizeof states,
                                  &pending_check, &evidence),
                              ==, short_budget ? TC_TLV_LIMIT : pending_result);
                          if (short_budget)
                            munit_assert_memory_equal(sizeof evidence, &evidence,
                                                      &empty);
                          else
                            assert_evidence_equal(&evidence, &expected);
                        }
                      }
                    }
                    const TC_bytes retry_inputs[] = {
                        signer_inputs[0],
                        signer_inputs[1],
                        {alternative_der, alternative_length}};
                    const size_t retry_count =
                        sizeof retry_inputs / sizeof *retry_inputs;
                    candidate_source retry_source = {retry_inputs, retry_count,
                                                     0, TC_TLV_OK, 0};
                    const TC_X509_store_source retry_records = {
                        &retry_source, retry_count, 0, read_candidate, NULL};
                    tc_cms_candidates retry_candidates;
                    work = TRUST_WORK_BUDGET;
                    munit_assert_int(tc_cms_candidates_init(
                                         (TC_bytes){NULL, 0}, &retry_records,
                                         retry_count,
                                         retry_count * ENCODED_CAPACITY,
                                         &limits, &tree, &retry_candidates),
                                     ==, TC_TLV_OK);
                    unresolved_crl_probe unresolved = {
                        {{NULL, 0}, 1, 0, TC_X509_PATH_VALID, 0, NULL, 0},
                        signer_inputs[1],
                        TC_X509_PATH_UNSUPPORTED};
                    const tc_x509_crl_path_check retry_check = {
                        &unresolved, check_unresolved_crl_path};
                    evidence = empty;
                    work = TRUST_WORK_BUDGET;
                    munit_assert_int(
                        tc_cms_crl_point_process(
                            &retry_candidates, &index,
                            TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER,
                            &query, &source, 1, &rollover_options, &tree,
                            &validation, &search, states, sizeof states,
                            &retry_check, &evidence),
                        ==, kind == TIED ? TC_TLV_INVALID : TC_TLV_OK);
                    munit_assert_size(unresolved.path.calls, >=, retry_count);
                    if (kind == TIED)
                      munit_assert_memory_equal(sizeof evidence, &evidence,
                                                &empty);
                    else {
                      munit_assert_int(
                          tc_x509_crl_evidence_status(&evidence, &status), ==,
                          TC_TLV_OK);
                      munit_assert_int(status, ==, TC_X509_CRL_REVOKED);
                    }
                  }
                  if (kind == UNNUMBERED) {
                    work = TRUST_WORK_BUDGET;
                    munit_assert_int(tc_cms_crl_point_process(
                                         &rollover_candidates, &index,
                                         TC_X509_CRL_COMPLETE_ONLY,
                                         TC_X509_CRL_ORDER_THIS_UPDATE, &query,
                                         &source, 1, &rollover_options, &tree,
                                         &validation, &search, states,
                                         sizeof states, &check, &evidence),
                                     ==, TC_TLV_OK);
                    munit_assert_int(
                        tc_x509_crl_evidence_status(&evidence, &status), ==,
                        TC_TLV_OK);
                    munit_assert_int(status, ==, TC_X509_CRL_REVOKED);
                  }
                  TC_bytes swap = rollover_inputs[0];
                  rollover_inputs[0] = rollover_inputs[1];
                  rollover_inputs[1] = swap;
                }
              }
              {
                enum { OLD_COMPLETE, NEW_COMPLETE, NEW_DELTA, RECORDS };
                static const unsigned orders[][RECORDS] = {
                    {OLD_COMPLETE, NEW_COMPLETE, NEW_DELTA},
                    {OLD_COMPLETE, NEW_DELTA, NEW_COMPLETE},
                    {NEW_COMPLETE, OLD_COMPLETE, NEW_DELTA},
                    {NEW_COMPLETE, NEW_DELTA, OLD_COMPLETE},
                    {NEW_DELTA, OLD_COMPLETE, NEW_COMPLETE},
                    {NEW_DELTA, NEW_COMPLETE, OLD_COMPLETE}};
                static const TC_X509_crl_delta_policy policies[] = {
                    TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_DELTA_IF_AVAILABLE,
                    TC_X509_CRL_DELTA_REQUIRED};
                uint8_t pair_der[2][ENCODED_CAPACITY],
                    conflict_der[ENCODED_CAPACITY];
                X509_CRL *conflicting = make_partition_crl(
                    crl, generated, TC_X509_CRL_ALL_REASONS, 1);
                const int conflict_length = i2d_X509_CRL(conflicting, NULL);
                munit_assert_int(conflict_length, >, 0);
                munit_assert_size((size_t)conflict_length, <=,
                                  sizeof conflict_der);
                unsigned char *conflict_destination = conflict_der;
                munit_assert_int(
                    i2d_X509_CRL(conflicting, &conflict_destination), ==,
                    conflict_length);
                X509_CRL_free(conflicting);
                TC_bytes inputs[RECORDS] = {rollover_inputs[0]};
                for (unsigned member = 0; member < 2; ++member) {
                  X509_CRL *variant =
                      member ? X509_CRL_dup(newest)
                             : make_partition_crl(crl, other_key,
                                                  TC_X509_CRL_ALL_REASONS, 0);
                  ASN1_INTEGER *number = ASN1_INTEGER_new();
                  ASN1_TIME *update = ASN1_TIME_new();
                  munit_assert_not_null(variant);
                  munit_assert_not_null(number);
                  munit_assert_not_null(update);
                  if (!member) {
                    AUTHORITY_KEYID *authority = X509_CRL_get_ext_d2i(
                        newest, NID_authority_key_identifier, NULL, NULL);
                    munit_assert_not_null(authority);
                    munit_assert_int(X509_CRL_add1_ext_i2d(
                                         variant, NID_authority_key_identifier,
                                         authority, 0, X509V3_ADD_REPLACE),
                                     ==, 1);
                    AUTHORITY_KEYID_free(authority);
                  }
                  munit_assert_int(ASN1_INTEGER_set(number, member ? 3 : 2), ==,
                                   1);
                  munit_assert_int(X509_CRL_add1_ext_i2d(variant,
                                                         NID_crl_number, number,
                                                         0, X509V3_ADD_REPLACE),
                                   ==, 1);
                  if (member) {
                    munit_assert_int(ASN1_INTEGER_set(number, 2), ==, 1);
                    munit_assert_int(X509_CRL_add1_ext_i2d(
                                         variant, NID_delta_crl, number, 1, 0),
                                     ==, 1);
                  }
                  munit_assert_int(
                      ASN1_TIME_set_string(update, member ? "260103000000Z"
                                                          : "260102000000Z"),
                      ==, 1);
                  munit_assert_int(X509_CRL_set1_lastUpdate(variant, update),
                                   ==, 1);
                  munit_assert_int(
                      X509_CRL_sign(variant, other_key, EVP_sha256()), >, 0);
                  const int length = i2d_X509_CRL(variant, NULL);
                  munit_assert_int(length, >, 0);
                  munit_assert_size((size_t)length, <=,
                                    sizeof pair_der[member]);
                  unsigned char *destination = pair_der[member];
                  munit_assert_int(i2d_X509_CRL(variant, &destination), ==,
                                   length);
                  inputs[member ? NEW_DELTA : NEW_COMPLETE] =
                      (TC_bytes){pair_der[member], (size_t)length};
                  ASN1_INTEGER_free(number);
                  ASN1_TIME_free(update);
                  X509_CRL_free(variant);
                }
                rollover_options.at.day = 3;
                for (size_t order = 0; order < sizeof orders / sizeof *orders;
                     ++order) {
                  TC_bytes ordered[RECORDS];
                  for (unsigned i = 0; i < RECORDS; ++i)
                    ordered[i] = inputs[orders[order][i]];
                  candidate_source pair_source = {ordered, RECORDS, 0,
                                                  TC_TLV_OK, 0};
                  const tc_pki_record_source pair_records = {
                      &pair_source, RECORDS, read_candidate};
                  tc_cms_candidates pair_candidates;
                  tc_cms_revocations pair_reader;
                  TC_X509_crl_record rows[RECORDS];
                  TC_X509_crl_index index;
                  uint8_t states[RECORDS];
                  work = TRUST_WORK_BUDGET;
                  munit_assert_int(
                      tc_cms_candidates_init((TC_bytes){NULL, 0},
                                             &signer_records, PARTITIONS,
                                             PARTITIONS * ENCODED_CAPACITY,
                                             &limits, &tree, &pair_candidates),
                      ==, TC_TLV_OK);
                  munit_assert_int(tc_cms_revocations_init(
                                       (TC_bytes){NULL, 0}, &pair_records,
                                       RECORDS, RECORDS * ENCODED_CAPACITY,
                                       &limits, &tree, &pair_reader),
                                   ==, TC_TLV_OK);
                  munit_assert_int(tc_cms_crl_index_init(&pair_reader, &tree,
                                                         oids,
                                                         EXTENSION_CAPACITY,
                                                         rows, RECORDS, &index),
                                   ==, TC_TLV_OK);
                  selected_crl_probe probe = {
                      {{NULL, 0}, 1, 0, TC_X509_PATH_VALID, 0, NULL, 0},
                      inputs[NEW_COMPLETE],
                      inputs[NEW_DELTA],
                      0};
                  const tc_x509_crl_path_check check = {
                      &probe, check_selected_crl_path};
                  for (size_t policy = 0;
                       policy < sizeof policies / sizeof *policies; ++policy) {
                    probe.pairs = 0;
                    evidence = (tc_x509_crl_evidence){0};
                    work = TRUST_WORK_BUDGET;
                    munit_assert_int(
                        tc_cms_crl_point_process(
                            &pair_candidates, &index, policies[policy],
                            TC_X509_CRL_ORDER_NUMBER, &query, &source, 1,
                            &rollover_options, &tree, &validation, &search,
                            states, sizeof states, &check, &evidence),
                        ==, TC_TLV_OK);
                    munit_assert_int(
                        tc_x509_crl_evidence_status(&evidence, &status), ==,
                        TC_TLV_OK);
                    munit_assert_int(status, ==,
                                     policies[policy] ==
                                             TC_X509_CRL_COMPLETE_ONLY
                                         ? TC_X509_CRL_UNREVOKED
                                         : TC_X509_CRL_REVOKED);
                    munit_assert_size(probe.pairs, ==,
                                      policies[policy] ==
                                              TC_X509_CRL_COMPLETE_ONLY
                                          ? 0
                                          : PARTITIONS);
                    /* A damaged delta cannot supply the revocation entry. */
                    const size_t signature_end = inputs[NEW_DELTA].length - 1;
                    pair_der[1][signature_end] ^= 1;
                    const tc_x509_crl_evidence empty = {0};
                    probe.pairs = 0;
                    evidence = empty;
                    work = TRUST_WORK_BUDGET;
                    munit_assert_int(
                        tc_cms_crl_point_process(
                            &pair_candidates, &index, policies[policy],
                            TC_X509_CRL_ORDER_NUMBER, &query, &source, 1,
                            &rollover_options, &tree, &validation, &search,
                            states, sizeof states, &check, &evidence),
                        ==,
                        policies[policy] == TC_X509_CRL_DELTA_REQUIRED
                            ? TC_TLV_INVALID
                            : TC_TLV_OK);
                    munit_assert_size(probe.pairs, ==, 0);
                    if (policies[policy] == TC_X509_CRL_DELTA_REQUIRED) {
                      munit_assert_memory_equal(sizeof evidence, &evidence,
                                                &empty);
                    } else {
                      munit_assert_int(
                          tc_x509_crl_evidence_status(&evidence, &status), ==,
                          TC_TLV_OK);
                      munit_assert_int(status, ==, TC_X509_CRL_UNREVOKED);
                    }
                    pair_der[1][signature_end] ^= 1;
                  }
                  /* The newer complete CRL supersedes the old key's conflict.
                   */
                  for (unsigned i = 0; i < RECORDS; ++i) {
                    if (orders[order][i] == NEW_DELTA)
                      ordered[i] =
                          (TC_bytes){conflict_der, (size_t)conflict_length};
                  }
                  work = TRUST_WORK_BUDGET;
                  munit_assert_int(tc_cms_crl_index_init(&pair_reader, &tree,
                                                         oids,
                                                         EXTENSION_CAPACITY,
                                                         rows, RECORDS, &index),
                                   ==, TC_TLV_OK);
                  for (unsigned damaged = 0; damaged < 2; ++damaged) {
                    const tc_x509_crl_evidence empty = {0};
                    evidence = empty;
                    work = TRUST_WORK_BUDGET;
                    if (damaged)
                      pair_der[0][inputs[NEW_COMPLETE].length - 1] ^= 1;
                    munit_assert_int(
                        tc_cms_crl_point_process(
                            &pair_candidates, &index, TC_X509_CRL_COMPLETE_ONLY,
                            TC_X509_CRL_ORDER_NUMBER, &query, &source, 1,
                            &rollover_options, &tree, &validation, &search,
                            states, sizeof states, &check, &evidence),
                        ==, damaged ? TC_TLV_INVALID : TC_TLV_OK);
                    if (damaged) {
                      munit_assert_memory_equal(sizeof evidence, &evidence,
                                                &empty);
                      pair_der[0][inputs[NEW_COMPLETE].length - 1] ^= 1;
                    } else {
                      munit_assert_int(
                          tc_x509_crl_evidence_status(&evidence, &status), ==,
                          TC_TLV_OK);
                      munit_assert_int(status, ==, TC_X509_CRL_UNREVOKED);
                    }
                  }
                }
              }
              X509_CRL_free(newest);
            }
            {
              enum { ISSUER_SERIAL = 2, LEAF_SERIAL = 9, DEPENDENCIES = 2 };
              uint8_t issuer_der[ENCODED_CAPACITY], leaf_der[ENCODED_CAPACITY];
              uint8_t child_der[ENCODED_CAPACITY], root_der[ENCODED_CAPACITY];
              X509 *issuer =
                  make_certificate(other_key, "Delegated issuer", certificate);
              munit_assert_int(ASN1_INTEGER_set(X509_get_serialNumber(issuer),
                                                ISSUER_SERIAL),
                               ==, 1);
              add_extension(issuer, NID_basic_constraints, "critical,CA:TRUE");
              add_extension(issuer, NID_key_usage,
                            "critical,keyCertSign,cRLSign");
              add_extension(issuer, NID_subject_key_identifier, "hash");
              const size_t issuer_length =
                  encode_certificate(issuer, generated, EVP_sha256(),
                                     issuer_der, sizeof issuer_der);
              X509 *leaf = make_certificate(generated, "Target", issuer);
              munit_assert_int(
                  ASN1_INTEGER_set(X509_get_serialNumber(leaf), LEAF_SERIAL),
                  ==, 1);
              const size_t leaf_length = encode_certificate(
                  leaf, other_key, EVP_sha256(), leaf_der, sizeof leaf_der);
              X509_free(leaf);
              TC_X509_certificate leaf_view;
              munit_assert_int(TC_X509_read(leaf_der, leaf_length, &limits,
                                            &parser, &leaf_view),
                               ==, TC_TLV_OK);
              const TC_bytes chain[] = {{issuer_der, issuer_length},
                                        {leaf_der, leaf_length}};
              TC_X509_path_result validated;
              work = TRUST_WORK_BUDGET;
              munit_assert_int(tc_x509_path_validate_budget(
                                   chain, DEPENDENCIES, &anchors[1].trust,
                                   &options, &validation, &work, &validated),
                               ==, TC_X509_PATH_VALID);
              X509_CRL *child = make_partition_crl(crl, other_key,
                                                   TC_X509_CRL_ALL_REASONS, 0);
              munit_assert_int(X509_CRL_set_issuer_name(
                                   child, X509_get_subject_name(issuer)),
                               ==, 1);
              AUTHORITY_KEYID *authority = AUTHORITY_KEYID_new();
              munit_assert_not_null(authority);
              authority->keyid = X509_get_ext_d2i(
                  issuer, NID_subject_key_identifier, NULL, NULL);
              munit_assert_not_null(authority->keyid);
              munit_assert_int(
                  X509_CRL_add1_ext_i2d(child, NID_authority_key_identifier,
                                        authority, 0, X509V3_ADD_REPLACE),
                  ==, 1);
              AUTHORITY_KEYID_free(authority);
              X509_free(issuer);
              munit_assert_int(X509_CRL_sign(child, other_key, EVP_sha256()), >,
                               0);
              const int child_length = i2d_X509_CRL(child, NULL);
              munit_assert_int(child_length, >, 0);
              munit_assert_size((size_t)child_length, <=, sizeof child_der);
              unsigned char *destination = child_der;
              munit_assert_int(i2d_X509_CRL(child, &destination), ==,
                               child_length);
              X509_CRL_free(child);
              const TC_bytes signers[] = {{signer_der, (size_t)signer_length},
                                          {issuer_der, issuer_length}};
              candidate_source signer_source = {signers, DEPENDENCIES, 0,
                                                TC_TLV_OK, 0};
              dependency_source_probe dependency_source = {&signer_source, NULL,
                                                           TC_TLV_OK, 0};
              const TC_X509_store_source signer_records = {
                  &dependency_source, DEPENDENCIES, 0,
                  read_dependency_candidate, NULL};
              combined_store_source combined = {&signer_records, &source};
              const TC_X509_store_source complete_source = {
                  &combined, DEPENDENCIES, source.anchor_count,
                  combined_candidate, combined_anchor};
              tc_cms_candidates signer_reader;
              work = TRUST_WORK_BUDGET;
              munit_assert_int(
                  tc_cms_candidates_init((TC_bytes){NULL, 0}, &signer_records,
                                         DEPENDENCIES,
                                         sizeof issuer_der + sizeof signer_der,
                                         &limits, &tree, &signer_reader),
                  ==, TC_TLV_OK);
              for (unsigned rejected = 0; rejected < 2; ++rejected) {
                X509_CRL *root = make_partition_crl(
                    crl, generated, TC_X509_CRL_ALL_REASONS, (int)rejected);
                if (rejected) {
                  ASN1_INTEGER *serial = ASN1_INTEGER_new();
                  munit_assert_not_null(serial);
                  munit_assert_int(ASN1_INTEGER_set(serial, ISSUER_SERIAL), ==,
                                   1);
                  munit_assert_int(
                      X509_REVOKED_set_serialNumber(
                          sk_X509_REVOKED_value(X509_CRL_get_REVOKED(root), 0),
                          serial),
                      ==, 1);
                  ASN1_INTEGER_free(serial);
                }
                munit_assert_int(X509_CRL_sign(root, generated, EVP_sha256()),
                                 >, 0);
                const int root_length = i2d_X509_CRL(root, NULL);
                munit_assert_int(root_length, >, 0);
                munit_assert_size((size_t)root_length, <=, sizeof root_der);
                destination = root_der;
                munit_assert_int(i2d_X509_CRL(root, &destination), ==,
                                 root_length);
                X509_CRL_free(root);
                const TC_bytes inputs[] = {{child_der, (size_t)child_length},
                                           {root_der, (size_t)root_length}};
                candidate_source crls = {inputs, DEPENDENCIES, 0, TC_TLV_OK, 0};
                const tc_pki_record_source crl_records = {&crls, DEPENDENCIES,
                                                          read_candidate};
                tc_cms_revocations crl_reader;
                TC_X509_crl_record rows[DEPENDENCIES];
                TC_X509_crl_index index;
                TC_X509_revocation_node nodes[DEPENDENCIES] = {0};
                uint8_t states[DEPENDENCIES];
                work = TRUST_WORK_BUDGET;
                munit_assert_int(
                    tc_cms_revocations_init((TC_bytes){NULL, 0}, &crl_records,
                                            DEPENDENCIES,
                                            sizeof child_der + sizeof root_der,
                                            &limits, &tree, &crl_reader),
                    ==, TC_TLV_OK);
                munit_assert_int(tc_cms_crl_index_init(&crl_reader, &tree, oids,
                                                       EXTENSION_CAPACITY, rows,
                                                       DEPENDENCIES, &index),
                                 ==, TC_TLV_OK);
                const tc_cms_crl_resolution resolution = {
                    &signer_reader,
                    &index,
                    &source,
                    &options,
                    1,
                    TC_X509_CRL_COMPLETE_ONLY,
                    TC_X509_CRL_ORDER_NUMBER};
                tc_x509_crl_resolution_workspace workspace = {
                    &tree,         &validation, &search,     states,
                    sizeof states, nodes,       DEPENDENCIES};
                const tc_x509_crl_evidence empty = {0};
                TC_X509_revocation_result path_evidence, path_sentinel;
                memset(&path_sentinel, 0xa5, sizeof path_sentinel);
                TC_X509_revocation_options public_options = {
                    &index,
                    &complete_source,
                    &options,
                    1,
                    sizeof issuer_der + sizeof signer_der,
                    TC_X509_CRL_COMPLETE_ONLY,
                    TC_X509_CRL_ORDER_NUMBER};
                TC_X509_revocation_workspace public_workspace = {
                    &validation,   &search, states,
                    sizeof states, nodes,   DEPENDENCIES};
                path_evidence = path_sentinel;
                work = TRUST_WORK_BUDGET;
                munit_assert_int(TC_X509_path_check_revocation(
                                     chain, DEPENDENCIES, &public_options,
                                     &public_workspace, &work, &path_evidence),
                                 ==, TC_TLV_OK);
                munit_assert_int(path_evidence.status, ==,
                                 rejected ? TC_X509_CRL_REVOKED
                                          : TC_X509_CRL_UNREVOKED);
                munit_assert_size(path_evidence.certificate_index, ==,
                                  rejected ? 0 : SIZE_MAX);
                const size_t public_work = TRUST_WORK_BUDGET - work;
                for (unsigned short_budget = 0; short_budget < 2;
                     ++short_budget) {
                  path_evidence = path_sentinel;
                  work = public_work - short_budget;
                  munit_assert_int(TC_X509_path_check_revocation(
                                       chain, DEPENDENCIES, &public_options,
                                       &public_workspace, &work,
                                       &path_evidence),
                                   ==, short_budget ? TC_TLV_LIMIT : TC_TLV_OK);
                  if (short_budget)
                    munit_assert_memory_equal(sizeof path_evidence,
                                              &path_evidence, &path_sentinel);
                }
                const size_t saved_byte_limit =
                    public_options.max_candidate_bytes;
                public_options.max_candidate_bytes = 0;
                path_evidence = path_sentinel;
                work = TRUST_WORK_BUDGET;
                munit_assert_int(TC_X509_path_check_revocation(
                                     chain, DEPENDENCIES, &public_options,
                                     &public_workspace, &work, &path_evidence),
                                 ==, TC_TLV_LIMIT);
                munit_assert_memory_equal(sizeof path_evidence, &path_evidence,
                                          &path_sentinel);
                public_options.max_candidate_bytes = saved_byte_limit;
                /* A failed source read must not become an unrevoked decision.
                 */
                const struct {
                  TC_TLV_result returned, expected;
                } source_failures[] = {{TC_TLV_UNSUPPORTED, TC_TLV_UNSUPPORTED},
                                       {TC_TLV_INVALID, TC_TLV_ARGUMENT},
                                       {TC_TLV_LIMIT, TC_TLV_LIMIT},
                                       {TC_TLV_ARGUMENT, TC_TLV_ARGUMENT}};
                for (size_t failure = 0;
                     failure <
                     sizeof source_failures / sizeof source_failures[0];
                     ++failure) {
                  signer_source.status = source_failures[failure].returned;
                  signer_source.calls = 0;
                  path_evidence = path_sentinel;
                  work = TRUST_WORK_BUDGET;
                  munit_assert_int(TC_X509_path_check_revocation(
                                       chain, DEPENDENCIES, &public_options,
                                       &public_workspace, &work,
                                       &path_evidence),
                                   ==, source_failures[failure].expected);
                  munit_assert_size(signer_source.calls, ==, 1);
                  munit_assert_memory_equal(sizeof path_evidence,
                                            &path_evidence, &path_sentinel);
                }
                signer_source.status = TC_TLV_OK;
                signer_source.increase_work = 1;
                signer_source.calls = 0;
                path_evidence = path_sentinel;
                work = TRUST_WORK_BUDGET;
                munit_assert_int(TC_X509_path_check_revocation(
                                     chain, DEPENDENCIES, &public_options,
                                     &public_workspace, &work, &path_evidence),
                                 ==, TC_TLV_ARGUMENT);
                munit_assert_size(signer_source.calls, ==, 1);
                munit_assert_memory_equal(sizeof path_evidence, &path_evidence,
                                          &path_sentinel);
                signer_source.increase_work = 0;
                TC_X509_revocation_options missing_index = public_options;
                TC_X509_revocation_options missing_source = public_options;
                TC_X509_revocation_options missing_policy = public_options;
                TC_X509_revocation_workspace missing_validation =
                    public_workspace;
                TC_X509_revocation_workspace missing_search = public_workspace;
                missing_index.index = NULL;
                missing_source.source = NULL;
                missing_policy.signer_policy = NULL;
                missing_validation.validation = NULL;
                missing_search.search = NULL;
                const struct {
                  const TC_bytes *path;
                  size_t count;
                  const TC_X509_revocation_options *options;
                  const TC_X509_revocation_workspace *workspace;
                  size_t *budget;
                  TC_X509_revocation_result *result;
                } missing_inputs[] = {
                    {NULL, DEPENDENCIES, &public_options, &public_workspace,
                     &work, &path_evidence},
                    {chain, 0, &public_options, &public_workspace, &work,
                     &path_evidence},
                    {chain, DEPENDENCIES, NULL, &public_workspace, &work,
                     &path_evidence},
                    {chain, DEPENDENCIES, &public_options, NULL, &work,
                     &path_evidence},
                    {chain, DEPENDENCIES, &public_options, &public_workspace,
                     NULL, &path_evidence},
                    {chain, DEPENDENCIES, &public_options, &public_workspace,
                     &work, NULL},
                    {chain, DEPENDENCIES, &missing_index, &public_workspace,
                     &work, &path_evidence},
                    {chain, DEPENDENCIES, &missing_source, &public_workspace,
                     &work, &path_evidence},
                    {chain, DEPENDENCIES, &missing_policy, &public_workspace,
                     &work, &path_evidence},
                    {chain, DEPENDENCIES, &public_options, &missing_validation,
                     &work, &path_evidence},
                    {chain, DEPENDENCIES, &public_options, &missing_search,
                     &work, &path_evidence}};
                for (size_t i = 0;
                     i < sizeof missing_inputs / sizeof *missing_inputs; ++i) {
                  signer_source.calls = 0;
                  path_evidence = path_sentinel;
                  work = TRUST_WORK_BUDGET;
                  munit_assert_int(
                      TC_X509_path_check_revocation(
                          missing_inputs[i].path, missing_inputs[i].count,
                          missing_inputs[i].options,
                          missing_inputs[i].workspace, missing_inputs[i].budget,
                          missing_inputs[i].result),
                      ==, TC_TLV_ARGUMENT);
                  munit_assert_size(signer_source.calls, ==, 0);
                  munit_assert_size(work, ==, TRUST_WORK_BUDGET);
                  munit_assert_memory_equal(sizeof path_evidence,
                                            &path_evidence, &path_sentinel);
                }
                ExampleX509RevocationWorkspace example_storage;
                path_evidence = path_sentinel;
                work = TRUST_WORK_BUDGET;
                munit_assert_int(example_check_path_revocation(
                                     chain, DEPENDENCIES, &public_options,
                                     &work, &example_storage, &path_evidence),
                                 ==, TC_TLV_OK);
                munit_assert_int(path_evidence.status, ==,
                                 rejected ? TC_X509_CRL_REVOKED
                                          : TC_X509_CRL_UNREVOKED);
                munit_assert_size(path_evidence.certificate_index, ==,
                                  rejected ? 0 : SIZE_MAX);
                path_evidence = path_sentinel;
                work = TRUST_WORK_BUDGET;
                signer_source.calls = 0;
                public_workspace.states = (uint8_t *)&public_options;
                munit_assert_int(TC_X509_path_check_revocation(
                                     chain, DEPENDENCIES, &public_options,
                                     &public_workspace, &work, &path_evidence),
                                 ==, TC_TLV_ARGUMENT);
                munit_assert_size(work, ==, TRUST_WORK_BUDGET);
                munit_assert_size(signer_source.calls, ==, 0);
                munit_assert_memory_equal(sizeof path_evidence, &path_evidence,
                                          &path_sentinel);
                public_workspace.states = states;
                munit_assert_int(
                    TC_X509_path_check_revocation(
                        chain, DEPENDENCIES, &public_options, &public_workspace,
                        &public_options.max_candidate_bytes, &path_evidence),
                    ==, TC_TLV_ARGUMENT);
                munit_assert_size(public_options.max_candidate_bytes, ==,
                                  saved_byte_limit);
                munit_assert_size(signer_source.calls, ==, 0);
                path_evidence = path_sentinel;
                work = TRUST_WORK_BUDGET;
                munit_assert_int(
                    tc_cms_crl_path_resolve(chain, DEPENDENCIES, &resolution,
                                            &workspace, &path_evidence),
                    ==, TC_TLV_OK);
                munit_assert_int(path_evidence.status, ==,
                                 rejected ? TC_X509_CRL_REVOKED
                                          : TC_X509_CRL_UNREVOKED);
                munit_assert_size(path_evidence.certificate_index, ==,
                                  rejected ? 0 : SIZE_MAX);
                munit_assert_ptr_equal(nodes[0].certificate.data, issuer_der);
                if (!rejected) {
                  munit_assert_ptr_equal(nodes[1].certificate.data, leaf_der);
                  munit_assert_int(nodes[0].status, ==, TC_X509_CRL_UNREVOKED);
                  munit_assert_int(nodes[1].status, ==, TC_X509_CRL_UNREVOKED);
                }
                const size_t path_work = TRUST_WORK_BUDGET - work;
                for (unsigned short_budget = 0; short_budget < 2;
                     ++short_budget) {
                  path_evidence = path_sentinel;
                  work = path_work - short_budget;
                  munit_assert_int(
                      tc_cms_crl_path_resolve(chain, DEPENDENCIES, &resolution,
                                              &workspace, &path_evidence),
                      ==, short_budget ? TC_TLV_LIMIT : TC_TLV_OK);
                  if (short_budget)
                    munit_assert_memory_equal(sizeof path_evidence,
                                              &path_evidence, &path_sentinel);
                }
                memcpy(search.path, chain, sizeof chain);
                path_evidence = path_sentinel;
                work = TRUST_WORK_BUDGET;
                munit_assert_int(tc_cms_crl_path_resolve(
                                     search.path, DEPENDENCIES, &resolution,
                                     &workspace, &path_evidence),
                                 ==, TC_TLV_ARGUMENT);
                munit_assert_size(work, ==, TRUST_WORK_BUDGET);
                munit_assert_memory_equal(sizeof path_evidence, &path_evidence,
                                          &path_sentinel);
                munit_assert_memory_equal(sizeof chain, search.path, chain);
                const struct {
                  const TC_bytes *chain;
                  size_t count;
                  const tc_cms_crl_resolution *resolution;
                  const tc_x509_crl_resolution_workspace *workspace;
                  TC_X509_revocation_result *out;
                } invalid_paths[] = {
                    {NULL, DEPENDENCIES, &resolution, &workspace,
                     &path_evidence},
                    {chain, 0, &resolution, &workspace, &path_evidence},
                    {chain, SIZE_MAX, &resolution, &workspace, &path_evidence},
                    {chain, DEPENDENCIES, NULL, &workspace, &path_evidence},
                    {chain, DEPENDENCIES, &resolution, NULL, &path_evidence},
                    {chain, DEPENDENCIES, &resolution, &workspace, NULL}};
                for (size_t invalid = 0;
                     invalid < sizeof invalid_paths / sizeof *invalid_paths;
                     ++invalid) {
                  path_evidence = path_sentinel;
                  work = TRUST_WORK_BUDGET;
                  munit_assert_int(
                      tc_cms_crl_path_resolve(invalid_paths[invalid].chain,
                                              invalid_paths[invalid].count,
                                              invalid_paths[invalid].resolution,
                                              invalid_paths[invalid].workspace,
                                              invalid_paths[invalid].out),
                      ==, TC_TLV_ARGUMENT);
                  munit_assert_size(work, ==, TRUST_WORK_BUDGET);
                  munit_assert_memory_equal(sizeof path_evidence,
                                            &path_evidence, &path_sentinel);
                }
                const TC_bytes invalid_members[] = {
                    {NULL, 1},
                    {leaf_der, 0},
                    {states, sizeof states},
                    {(const uint8_t *)&path_evidence, sizeof path_evidence}};
                for (size_t invalid = 0;
                     invalid < sizeof invalid_members / sizeof *invalid_members;
                     ++invalid) {
                  const TC_bytes held[] = {chain[0], invalid_members[invalid]};
                  uint8_t saved_nodes[sizeof nodes];
                  memcpy(saved_nodes, nodes, sizeof nodes);
                  path_evidence = path_sentinel;
                  work = TRUST_WORK_BUDGET;
                  munit_assert_int(
                      tc_cms_crl_path_resolve(held, DEPENDENCIES, &resolution,
                                              &workspace, &path_evidence),
                      ==, TC_TLV_ARGUMENT);
                  munit_assert_size(work, ==, TRUST_WORK_BUDGET);
                  munit_assert_memory_equal(sizeof path_evidence,
                                            &path_evidence, &path_sentinel);
                  munit_assert_memory_equal(sizeof nodes, nodes, saved_nodes);
                }
                union {
                  TC_X509_revocation_result result;
                  TC_X509_revocation_node nodes[DEPENDENCIES];
                } overlapping;
                uint8_t saved_overlap[sizeof overlapping];
                memset(&overlapping, 0xa5, sizeof overlapping);
                memcpy(saved_overlap, &overlapping, sizeof overlapping);
                tc_x509_crl_resolution_workspace overlap_workspace = workspace;
                overlap_workspace.nodes = overlapping.nodes;
                work = TRUST_WORK_BUDGET;
                munit_assert_int(tc_cms_crl_path_resolve(
                                     chain, DEPENDENCIES, &resolution,
                                     &overlap_workspace, &overlapping.result),
                                 ==, TC_TLV_ARGUMENT);
                munit_assert_size(work, ==, TRUST_WORK_BUDGET);
                munit_assert_memory_equal(sizeof overlapping, &overlapping,
                                          saved_overlap);
                evidence = empty;
                work = TRUST_WORK_BUDGET;
                munit_assert_int(tc_cms_crl_resolve(&leaf_view, &resolution,
                                                    &workspace, &evidence),
                                 ==, rejected ? TC_TLV_INVALID : TC_TLV_OK);
                munit_assert_ptr_equal(nodes[1].certificate.data, issuer_der);
                munit_assert_int(nodes[1].status, ==,
                                 rejected ? TC_X509_CRL_REVOKED
                                          : TC_X509_CRL_UNREVOKED);
                const size_t required = TRUST_WORK_BUDGET - work;
                const tc_x509_crl_evidence expected_evidence = evidence;
                if (rejected)
                  munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
                else {
                  munit_assert_int(
                      tc_x509_crl_evidence_status(&evidence, &status), ==,
                      TC_TLV_OK);
                  munit_assert_int(status, ==, TC_X509_CRL_UNREVOKED);
                }
                for (unsigned short_budget = 0; short_budget < 2;
                     ++short_budget) {
                  evidence = empty;
                  work = required - short_budget;
                  munit_assert_int(tc_cms_crl_resolve(&leaf_view, &resolution,
                                                      &workspace, &evidence),
                                   ==,
                                   short_budget ? TC_TLV_LIMIT
                                   : rejected   ? TC_TLV_INVALID
                                                : TC_TLV_OK);
                  if (short_budget)
                    munit_assert_memory_equal(sizeof evidence, &evidence,
                                              &empty);
                  else
                    assert_evidence_equal(&evidence, &expected_evidence);
                }
                signer_source.status = TC_TLV_UNSUPPORTED;
                signer_source.calls = 0;
                evidence = empty;
                work = TRUST_WORK_BUDGET;
                munit_assert_int(tc_cms_crl_resolve(&leaf_view, &resolution,
                                                    &workspace, &evidence),
                                 ==, TC_TLV_UNSUPPORTED);
                munit_assert_size(signer_source.calls, ==, 1);
                munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
                signer_source.status = TC_TLV_OK;
                for (size_t failure = 0;
                     failure < sizeof source_failures / sizeof *source_failures;
                     ++failure) {
                  memset(nodes, 0, sizeof nodes);
                  dependency_source.dependency = &nodes[1];
                  dependency_source.failure = source_failures[failure].returned;
                  dependency_source.failures = 0;
                  evidence = empty;
                  work = TRUST_WORK_BUDGET;
                  munit_assert_int(tc_cms_crl_resolve(&leaf_view, &resolution,
                                                      &workspace, &evidence),
                                   ==, source_failures[failure].expected);
                  munit_assert_size(dependency_source.failures, ==, 1);
                  munit_assert_int(nodes[1].status, ==,
                                   rejected ? TC_X509_CRL_REVOKED
                                            : TC_X509_CRL_UNREVOKED);
                  munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
                }
                dependency_source.dependency = NULL;
                /* Neither side of the dependency can establish the target
                 * alone. */
                for (size_t available = 0; available < DEPENDENCIES;
                     ++available) {
                  const TC_X509_crl_index partial = {&rows[available], 1, 0};
                  tc_cms_crl_resolution incomplete = resolution;
                  incomplete.index = &partial;
                  if (!rejected) {
                    path_evidence = path_sentinel;
                    work = TRUST_WORK_BUDGET;
                    munit_assert_int(tc_cms_crl_path_resolve(
                                         chain, DEPENDENCIES, &incomplete,
                                         &workspace, &path_evidence),
                                     ==, TC_TLV_UNSUPPORTED);
                    munit_assert_memory_equal(sizeof path_evidence,
                                              &path_evidence, &path_sentinel);
                  }
                  memset(nodes, 0, sizeof nodes);
                  evidence = empty;
                  work = TRUST_WORK_BUDGET;
                  munit_assert_int(tc_cms_crl_resolve(&leaf_view, &incomplete,
                                                      &workspace, &evidence),
                                   ==, TC_TLV_UNSUPPORTED);
                  munit_assert_int(nodes[0].status, ==,
                                   TC_X509_CRL_UNDETERMINED);
                  munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
                  if (!available) {
                    munit_assert_ptr_equal(nodes[1].certificate.data,
                                           issuer_der);
                    munit_assert_int(nodes[1].status, ==,
                                     TC_X509_CRL_UNDETERMINED);
                  }
                }
                const TC_X509_crl_record swap = rows[0];
                rows[0] = rows[1];
                rows[1] = swap;
                evidence = empty;
                work = TRUST_WORK_BUDGET;
                munit_assert_int(tc_cms_crl_resolve(&leaf_view, &resolution,
                                                    &workspace, &evidence),
                                 ==, rejected ? TC_TLV_INVALID : TC_TLV_OK);
                if (rejected)
                  munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
                else {
                  int equal;
                  munit_assert_int(tc_x509_crl_evidence_equal(
                                       &evidence, &expected_evidence, &equal),
                                   ==, TC_TLV_OK);
                  munit_assert_true(equal);
                }
                if (!rejected) {
                  const unsigned char *input = child_der;
                  X509_CRL *template = d2i_X509_CRL(NULL, &input, child_length);
                  munit_assert_not_null(template);
                  X509_CRL *revoked_leaf = make_partition_crl(
                      template, other_key, TC_X509_CRL_ALL_REASONS, 1);
                  X509_CRL_free(template);
                  uint8_t revoked_der[ENCODED_CAPACITY];
                  const int length = i2d_X509_CRL(revoked_leaf, NULL);
                  munit_assert_int(length, >, 0);
                  munit_assert_size((size_t)length, <=, sizeof revoked_der);
                  unsigned char *output = revoked_der;
                  munit_assert_int(i2d_X509_CRL(revoked_leaf, &output), ==,
                                   length);
                  X509_CRL_free(revoked_leaf);
                  TC_X509_crl_record revoked_rows[] = {rows[0], rows[1]};
                  work = TRUST_WORK_BUDGET;
                  munit_assert_int(
                      tc_x509_crl_read((TC_bytes){revoked_der, (size_t)length},
                                       &limits, &tree, &revoked_rows[1].crl),
                      ==, TC_TLV_OK);
                  munit_assert_int(tc_x509_crl_extension_info_read(
                                       revoked_rows[1].crl.extensions, &limits,
                                       &tree, oids, EXTENSION_CAPACITY,
                                       &revoked_rows[1].extensions),
                                   ==, TC_TLV_OK);
                  revoked_rows[1].policy =
                      tc_x509_crl_extension_policy(&revoked_rows[1].extensions);
                  const TC_X509_crl_index revoked_index = {revoked_rows,
                                                           DEPENDENCIES, 0};
                  tc_cms_crl_resolution leaf_resolution = resolution;
                  leaf_resolution.index = &revoked_index;
                  path_evidence = path_sentinel;
                  work = TRUST_WORK_BUDGET;
                  munit_assert_int(tc_cms_crl_path_resolve(
                                       chain, DEPENDENCIES, &leaf_resolution,
                                       &workspace, &path_evidence),
                                   ==, TC_TLV_OK);
                  munit_assert_int(path_evidence.status, ==,
                                   TC_X509_CRL_REVOKED);
                  munit_assert_size(path_evidence.certificate_index, ==,
                                    DEPENDENCIES - 1);
                  munit_assert_int(tc_x509_crl_evidence_status(
                                       &path_evidence.evidence, &status),
                                   ==, TC_TLV_OK);
                  munit_assert_int(status, ==, TC_X509_CRL_REVOKED);
                  munit_assert_uint(path_evidence.evidence.revocation.reason,
                                    ==, CRL_REASON_KEY_COMPROMISE);
                  int order;
                  munit_assert_int(
                      TC_X509_time_compare(
                          &path_evidence.evidence.revocation.revoked_at,
                          &revoked_rows[1].crl.this_update, &order),
                      ==, TC_TLV_OK);
                  munit_assert_int(order, ==, 0);
                  public_options.index = &revoked_index;
                  path_evidence = path_sentinel;
                  work = TRUST_WORK_BUDGET;
                  munit_assert_int(TC_X509_path_check_revocation(
                                       chain, DEPENDENCIES, &public_options,
                                       &public_workspace, &work,
                                       &path_evidence),
                                   ==, TC_TLV_OK);
                  munit_assert_int(path_evidence.status, ==,
                                   TC_X509_CRL_REVOKED);
                  munit_assert_size(path_evidence.certificate_index, ==,
                                    DEPENDENCIES - 1);
                  munit_assert_uint(path_evidence.evidence.revocation.reason,
                                    ==, CRL_REASON_KEY_COMPROMISE);
                  public_options.index = &index;
                }
                workspace.node_capacity = 1;
                evidence = empty;
                work = TRUST_WORK_BUDGET;
                munit_assert_int(tc_cms_crl_resolve(&leaf_view, &resolution,
                                                    &workspace, &evidence),
                                 ==, TC_TLV_LIMIT);
                munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
              }
            }
            const uint16_t masks[PARTITIONS] = {KEY_COMPROMISE_MASK,
                                                TC_X509_CRL_ALL_REASONS &
                                                    ~KEY_COMPROMISE_MASK};
            for (unsigned listed = 0; listed < 2; ++listed) {
              for (unsigned bad_signature = 0; bad_signature < 2;
                   ++bad_signature) {
                uint8_t partition_der[PARTITIONS][ENCODED_CAPACITY],
                    states[PARTITIONS];
                TC_bytes partition_inputs[PARTITIONS];
                for (unsigned partition = 0; partition < PARTITIONS;
                     ++partition) {
                  X509_CRL *variant = make_partition_crl(
                      crl, bad_signature && partition ? other_key : generated,
                      masks[partition], listed && !partition);
                  const int length = i2d_X509_CRL(variant, NULL);
                  munit_assert_int(length, >, 0);
                  munit_assert_size((size_t)length, <=,
                                    sizeof partition_der[partition]);
                  unsigned char *destination = partition_der[partition];
                  munit_assert_int(i2d_X509_CRL(variant, &destination), ==,
                                   length);
                  partition_inputs[partition] =
                      (TC_bytes){partition_der[partition], (size_t)length};
                  X509_CRL_free(variant);
                }
                candidate_source partition_source = {
                    partition_inputs, PARTITIONS, 0, TC_TLV_OK, 0};
                const tc_pki_record_source partition_records = {
                    &partition_source, PARTITIONS, read_candidate};
                for (unsigned order = 0; order < PARTITIONS; ++order) {
                  tc_cms_revocations partition_reader;
                  TC_X509_crl_record partition_rows[PARTITIONS];
                  TC_X509_crl_index partitions;
                  work = TRUST_WORK_BUDGET;
                  munit_assert_int(tc_cms_revocations_init(
                                       (TC_bytes){NULL, 0}, &partition_records,
                                       PARTITIONS, sizeof partition_der,
                                       &limits, &tree, &partition_reader),
                                   ==, TC_TLV_OK);
                  munit_assert_int(
                      tc_cms_crl_index_init(&partition_reader, &tree, oids,
                                            EXTENSION_CAPACITY, partition_rows,
                                            PARTITIONS, &partitions),
                      ==, TC_TLV_OK);
                  evidence = (tc_x509_crl_evidence){0};
                  status = TC_X509_CRL_UNDETERMINED;
                  uint16_t covered = 0;
                  work = TRUST_WORK_BUDGET;
                  for (unsigned reference = 0; reference < PARTITIONS;
                       ++reference) {
                    const unsigned partition =
                        order ? PARTITIONS - 1 - reference : reference;
                    const int terminal = status != TC_X509_CRL_UNDETERMINED;
                    const TC_TLV_result expected_result =
                        terminal                     ? TC_TLV_END
                        : bad_signature && partition ? TC_TLV_INVALID
                                                     : TC_TLV_OK;
                    const tc_x509_crl_evidence previous = evidence;
                    candidates =
                        (candidate_source){records, 4, 0, TC_TLV_OK, 0};
                    found = saved;
                    const size_t before_work = work;
                    munit_assert_int(
                        tc_cms_crl_scope_process(
                            &reader, &partitions, reference,
                            TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER,
                            &query, &source, 1, &options, &tree, &validation,
                            &search, states, sizeof states, &evidence, &found),
                        ==, expected_result);
                    if (expected_result == TC_TLV_OK)
                      covered |= masks[partition];
                    else {
                      munit_assert_memory_equal(sizeof evidence, &evidence,
                                                &previous);
                      munit_assert_memory_equal(sizeof found, &found, &saved);
                    }
                    if (terminal)
                      munit_assert_size(work, ==, before_work);
                    munit_assert_uint(evidence.reasons, ==, covered);
                    munit_assert_int(
                        tc_x509_crl_evidence_status(&evidence, &status), ==,
                        TC_TLV_OK);
                    if (!reference && expected_result == TC_TLV_OK &&
                        (!listed || partition))
                      munit_assert_int(status, ==, TC_X509_CRL_UNDETERMINED);
                    munit_assert_memory_equal(sizeof reader, &reader, &before);
                  }
                  munit_assert_int(status, ==,
                                   listed          ? TC_X509_CRL_REVOKED
                                   : bad_signature ? TC_X509_CRL_UNDETERMINED
                                                   : TC_X509_CRL_UNREVOKED);
                  const tc_x509_crl_evidence empty = {0};
                  crl_path_probe probe = {{signer_der, (size_t)signer_length},
                                          1,
                                          0,
                                          TC_X509_PATH_VALID,
                                          0,
                                          NULL,
                                          0};
                  const tc_x509_crl_path_check check = {&probe, check_crl_path};
                  candidates = (candidate_source){records, 4, 0, TC_TLV_OK, 0};
                  evidence = empty;
                  work = TRUST_WORK_BUDGET;
                  const TC_TLV_result run_result =
                      bad_signature && !listed ? TC_TLV_INVALID : TC_TLV_OK;
                  munit_assert_int(
                      tc_cms_crl_point_process(
                          &reader, &partitions, TC_X509_CRL_COMPLETE_ONLY,
                          TC_X509_CRL_ORDER_NUMBER, &query, &source, 1,
                          &options, &tree, &validation, &search, states,
                          sizeof states, &check, &evidence),
                      ==, run_result);
                  munit_assert_size(
                      probe.calls, ==,
                      (listed && !order) || bad_signature ? 1 : PARTITIONS);
                  if (run_result == TC_TLV_OK) {
                    munit_assert_int(
                        tc_x509_crl_evidence_status(&evidence, &status), ==,
                        TC_TLV_OK);
                    munit_assert_int(status, ==,
                                     listed ? TC_X509_CRL_REVOKED
                                            : TC_X509_CRL_UNREVOKED);
                    const size_t run_work = TRUST_WORK_BUDGET - work;
                    evidence = empty;
                    work = run_work - 1;
                    munit_assert_int(
                        tc_cms_crl_point_process(
                            &reader, &partitions, TC_X509_CRL_COMPLETE_ONLY,
                            TC_X509_CRL_ORDER_NUMBER, &query, &source, 1,
                            &options, &tree, &validation, &search, states,
                            sizeof states, &check, &evidence),
                        ==, TC_TLV_LIMIT);
                    munit_assert_memory_equal(sizeof evidence, &evidence,
                                              &empty);
                    work = run_work;
                    munit_assert_int(
                        tc_cms_crl_point_process(
                            &reader, &partitions, TC_X509_CRL_COMPLETE_ONLY,
                            TC_X509_CRL_ORDER_NUMBER, &query, &source, 1,
                            &options, &tree, &validation, &search, states,
                            sizeof states, &check, &evidence),
                        ==, TC_TLV_OK);
                    munit_assert_size(work, ==, 0);
                  } else
                    munit_assert_memory_equal(sizeof evidence, &evidence,
                                              &empty);
                  if (!listed && !bad_signature) {
                    if (!order) {
                      enum {
                        ALTERNATIVE,
                        LISTED,
                        REVOKED_TARGET,
                        WRONG_NAME,
                        NOT_CA,
                        DUPLICATE,
                        BAD_ALT,
                        BAD_DP,
                        CERT_CASES
                      };
                      enum {
                        DER_TRUE = 0xff,
                        FULL_NAME = 0,
                        REVOKED_SERIAL = 9,
                        UNLISTED_SERIAL = 10
                      };
                      static const char locator[] =
                          "https://issuer.example/crl";
                      uint8_t named_der[ENCODED_CAPACITY],
                          target_der[ENCODED_CAPACITY],
                          extension_der[ENCODED_CAPACITY];
                      X509_CRL *named = make_partition_crl(
                          crl, generated, TC_X509_CRL_ALL_REASONS, 1);
                      ISSUING_DIST_POINT *idp = ISSUING_DIST_POINT_new();
                      GENERAL_NAME *location = GENERAL_NAME_new();
                      ASN1_IA5STRING *uri = ASN1_IA5STRING_new();
                      munit_assert_not_null(named);
                      munit_assert_not_null(idp);
                      munit_assert_not_null(location);
                      munit_assert_not_null(uri);
                      idp->onlyCA = DER_TRUE;
                      idp->distpoint = DIST_POINT_NAME_new();
                      munit_assert_not_null(idp->distpoint);
                      idp->distpoint->type = FULL_NAME;
                      idp->distpoint->name.fullname =
                          sk_GENERAL_NAME_new_null();
                      munit_assert_not_null(idp->distpoint->name.fullname);
                      munit_assert_int(
                          ASN1_STRING_set(uri, locator, sizeof locator - 1), ==,
                          1);
                      GENERAL_NAME_set0_value(location, GEN_URI, uri);
                      munit_assert_int(
                          sk_GENERAL_NAME_push(idp->distpoint->name.fullname,
                                               location),
                          >, 0);
                      munit_assert_int(
                          X509_CRL_add1_ext_i2d(named,
                                                NID_issuing_distribution_point,
                                                idp, 1, X509V3_ADD_REPLACE),
                          ==, 1);
                      ISSUING_DIST_POINT_free(idp);
                      munit_assert_int(
                          X509_CRL_sign(named, generated, EVP_sha256()), >, 0);
                      const int named_length = i2d_X509_CRL(named, NULL);
                      munit_assert_int(named_length, >, 0);
                      munit_assert_size((size_t)named_length, <=,
                                        sizeof named_der);
                      unsigned char *destination = named_der;
                      munit_assert_int(i2d_X509_CRL(named, &destination), ==,
                                       named_length);
                      X509_CRL_free(named);
                      const TC_bytes named_input = {named_der,
                                                    (size_t)named_length};
                      candidate_source named_source = {&named_input, 1, 0,
                                                       TC_TLV_OK, 0};
                      const tc_pki_record_source named_records = {
                          &named_source, 1, read_candidate};
                      tc_cms_revocations named_reader;
                      TC_X509_crl_record named_row;
                      TC_X509_crl_index named_index;
                      work = TRUST_WORK_BUDGET;
                      munit_assert_int(tc_cms_revocations_init(
                                           (TC_bytes){NULL, 0}, &named_records,
                                           1, sizeof named_der, &limits, &tree,
                                           &named_reader),
                                       ==, TC_TLV_OK);
                      munit_assert_int(
                          tc_cms_crl_index_init(&named_reader, &tree, oids,
                                                EXTENSION_CAPACITY, &named_row,
                                                1, &named_index),
                          ==, TC_TLV_OK);
                      for (unsigned kind = ALTERNATIVE; kind < CERT_CASES;
                           ++kind) {
                        X509 *cert =
                            make_certificate(other_key, "Target", certificate);
                        munit_assert_int(
                            ASN1_INTEGER_set(X509_get_serialNumber(cert),
                                             kind == REVOKED_TARGET
                                                 ? REVOKED_SERIAL
                                                 : UNLISTED_SERIAL),
                            ==, 1);
                        add_extension(cert, NID_basic_constraints,
                                      kind == NOT_CA ? "critical,CA:FALSE"
                                                     : "critical,CA:TRUE");
                        if (kind == LISTED)
                          add_extension(cert, NID_crl_distribution_points,
                                        "URI:https://issuer.example/crl");
                        else if (kind != BAD_ALT)
                          add_extension(cert, NID_issuer_alt_name,
                                        kind == WRONG_NAME
                                            ? "URI:https://other.example/crl"
                                            : "URI:https://issuer.example/crl");
                        if (kind == DUPLICATE)
                          add_extension(cert, NID_issuer_alt_name,
                                        "URI:https://issuer.example/crl");
                        if (kind == BAD_ALT || kind == BAD_DP) {
                          const uint8_t empty_sequence[] = {0x30, 0};
                          ASN1_OCTET_STRING *value = ASN1_OCTET_STRING_new();
                          munit_assert_not_null(value);
                          munit_assert_int(
                              ASN1_OCTET_STRING_set(value, empty_sequence,
                                                    sizeof empty_sequence),
                              ==, 1);
                          X509_EXTENSION *extension =
                              X509_EXTENSION_create_by_NID(
                                  NULL,
                                  kind == BAD_ALT ? NID_issuer_alt_name
                                                  : NID_crl_distribution_points,
                                  0, value);
                          munit_assert_not_null(extension);
                          munit_assert_int(X509_add_ext(cert, extension, -1),
                                           ==, 1);
                          X509_EXTENSION_free(extension);
                          ASN1_OCTET_STRING_free(value);
                        }
                        const size_t length =
                            encode_certificate(cert, generated, EVP_sha256(),
                                               target_der, sizeof target_der);
                        const int extension_length = i2d_X509_EXTENSIONS(
                            X509_get0_extensions(cert), NULL);
                        munit_assert_int(extension_length, >, 0);
                        munit_assert_size((size_t)extension_length, <=,
                                          sizeof extension_der);
                        unsigned char *extension_destination = extension_der;
                        munit_assert_int(
                            i2d_X509_EXTENSIONS(X509_get0_extensions(cert),
                                                &extension_destination),
                            ==, extension_length);
                        X509_free(cert);
                        TC_X509_certificate target_view;
                        const int rejected_at_read =
                            kind == DUPLICATE || kind == BAD_ALT;
                        munit_assert_int(
                            TC_X509_read(target_der, length, &limits, &parser,
                                         &target_view),
                            ==, rejected_at_read ? TC_TLV_INVALID : TC_TLV_OK);
                        if (rejected_at_read) {
                          /* Exercise the private driver's parsed-view checks
                           * too. */
                          target_view = target;
                          target_view.encoded = (TC_bytes){target_der, length};
                          target_view.extensions = (TC_bytes){
                              extension_der, (size_t)extension_length};
                        } else if (kind < DUPLICATE) {
                          work = TRUST_WORK_BUDGET;
                          munit_assert_int(tc_x509_path_build_work(
                                               target_view.encoded, &source,
                                               &options, &validation, &search,
                                               &work, &found),
                                           ==, TC_X509_PATH_VALID);
                          munit_assert_size(found.anchor_index, ==, 1);
                        }
                        const TC_TLV_result expected =
                            kind >= DUPLICATE ? TC_TLV_INVALID
                            : kind == WRONG_NAME || kind == NOT_CA ? TC_TLV_END
                                                                   : TC_TLV_OK;
                        evidence = empty;
                        work = TRUST_WORK_BUDGET;
                        probe.calls = 0;
                        munit_assert_int(
                            tc_cms_crl_certificate_process(
                                &reader, &named_index,
                                TC_X509_CRL_COMPLETE_ONLY,
                                TC_X509_CRL_ORDER_NUMBER, &target_view, &source,
                                1, &options, &tree, &validation, &search,
                                states, sizeof states, &check, &evidence),
                            ==, expected);
                        if (expected == TC_TLV_OK) {
                          munit_assert_size(probe.calls, ==, 1);
                          munit_assert_int(
                              tc_x509_crl_evidence_status(&evidence, &status),
                              ==, TC_TLV_OK);
                          munit_assert_int(status, ==,
                                           kind == REVOKED_TARGET
                                               ? TC_X509_CRL_REVOKED
                                               : TC_X509_CRL_UNREVOKED);
                        } else {
                          munit_assert_size(probe.calls, ==, 0);
                          munit_assert_memory_equal(sizeof evidence, &evidence,
                                                    &empty);
                        }
                        const size_t required = TRUST_WORK_BUDGET - work;
                        const tc_x509_crl_evidence expected_evidence = evidence;
                        munit_assert_size(required, >, 0);
                        for (unsigned short_budget = 0; short_budget < 2;
                             ++short_budget) {
                          evidence = empty;
                          work = required - short_budget;
                          munit_assert_int(
                              tc_cms_crl_certificate_process(
                                  &reader, &named_index,
                                  TC_X509_CRL_COMPLETE_ONLY,
                                  TC_X509_CRL_ORDER_NUMBER, &target_view,
                                  &source, 1, &options, &tree, &validation,
                                  &search, states, sizeof states, &check,
                                  &evidence),
                              ==, short_budget ? TC_TLV_LIMIT : expected);
                          if (short_budget)
                            munit_assert_memory_equal(sizeof evidence, &evidence,
                                                      &empty);
                          else
                            assert_evidence_equal(&evidence,
                                                  &expected_evidence);
                        }
                        TC_X509_revocation_node dependencies[PATH_CAPACITY];
                        const tc_cms_crl_resolution resolution = {
                            &reader,
                            &named_index,
                            &source,
                            &options,
                            1,
                            TC_X509_CRL_COMPLETE_ONLY,
                            TC_X509_CRL_ORDER_NUMBER};
                        tc_x509_crl_resolution_workspace resolve_workspace = {
                            &tree,         &validation,  &search,      states,
                            sizeof states, dependencies, PATH_CAPACITY};
                        evidence = empty;
                        work = TRUST_WORK_BUDGET;
                        const TC_TLV_result resolved_result =
                            expected == TC_TLV_END ? TC_TLV_UNSUPPORTED
                                                   : expected;
                        munit_assert_int(
                            tc_cms_crl_resolve(&target_view, &resolution,
                                               &resolve_workspace, &evidence),
                            ==, resolved_result);
                        if (resolved_result == TC_TLV_OK) {
                          int equal;
                          munit_assert_int(
                              tc_x509_crl_evidence_equal(
                                  &evidence, &expected_evidence, &equal),
                              ==, TC_TLV_OK);
                          munit_assert_true(equal);
                          munit_assert_int(dependencies[0].status, ==,
                                           kind == REVOKED_TARGET
                                               ? TC_X509_CRL_REVOKED
                                               : TC_X509_CRL_UNREVOKED);
                        } else
                          munit_assert_memory_equal(sizeof evidence, &evidence,
                                                    &empty);
                        const size_t resolve_work = TRUST_WORK_BUDGET - work;
                        for (unsigned short_budget = 0; short_budget < 2;
                             ++short_budget) {
                          evidence = empty;
                          work = resolve_work - short_budget;
                          munit_assert_int(
                              tc_cms_crl_resolve(&target_view, &resolution,
                                                 &resolve_workspace, &evidence),
                              ==,
                              short_budget ? TC_TLV_LIMIT : resolved_result);
                          if (short_budget || resolved_result != TC_TLV_OK)
                            munit_assert_memory_equal(sizeof evidence,
                                                      &evidence, &empty);
                        }
                        resolve_workspace.states = (uint8_t *)dependencies;
                        uint8_t saved_dependencies[sizeof dependencies];
                        memcpy(saved_dependencies, dependencies,
                               sizeof dependencies);
                        evidence = empty;
                        work = TRUST_WORK_BUDGET;
                        munit_assert_int(
                            tc_cms_crl_resolve(&target_view, &resolution,
                                               &resolve_workspace, &evidence),
                            ==, TC_TLV_ARGUMENT);
                        munit_assert_size(work, ==, TRUST_WORK_BUDGET);
                        munit_assert_memory_equal(sizeof evidence, &evidence,
                                                  &empty);
                        munit_assert_memory_equal(sizeof dependencies,
                                                  dependencies,
                                                  saved_dependencies);
                        target_view.extensions = (TC_bytes){states, 1};
                        evidence = empty;
                        work = TRUST_WORK_BUDGET;
                        munit_assert_int(
                            tc_cms_crl_certificate_process(
                                &reader, &named_index,
                                TC_X509_CRL_COMPLETE_ONLY,
                                TC_X509_CRL_ORDER_NUMBER, &target_view, &source,
                                1, &options, &tree, &validation, &search,
                                states, sizeof states, &check, &evidence),
                            ==, TC_TLV_ARGUMENT);
                        munit_assert_size(work, ==, TRUST_WORK_BUDGET);
                        munit_assert_memory_equal(sizeof evidence, &evidence,
                                                  &empty);
                      }
                    }
                    static const uint8_t split_points[] = {
                        0x30, 27,   0x30, 11,   0xa0, 5,    0xa0, 3,
                        0x86, 1,    'a',  0x81, 2,    6,    0x40, 0x30,
                        12,   0xa0, 5,    0xa0, 3,    0x86, 1,    'a',
                        0x81, 3,    7,    0x3f, 0x80};
                    static const uint8_t first_point[] = {
                        0x30, 13, 0x30, 11,   0xa0, 5, 0xa0, 3,
                        0x86, 1,  'a',  0x81, 2,    6, 0x40};
                    uint8_t malformed[sizeof split_points + 2];
                    memcpy(malformed, split_points, sizeof split_points);
                    malformed[1] += 2;
                    malformed[sizeof split_points] = 0x30;
                    malformed[sizeof split_points + 1] = 0;
                    const TC_bytes point_lists[] = {
                        {NULL, 0},
                        {split_points, sizeof split_points},
                        {first_point, sizeof first_point},
                        {malformed, sizeof malformed}};
                    for (size_t list = 0;
                         list < sizeof point_lists / sizeof *point_lists;
                         ++list) {
                      const int invalid = point_lists[list].data == malformed;
                      evidence = empty;
                      work = TRUST_WORK_BUDGET;
                      probe.calls = 0;
                      munit_assert_int(
                          tc_cms_crl_points_process(
                              &reader, &partitions, TC_X509_CRL_COMPLETE_ONLY,
                              TC_X509_CRL_ORDER_NUMBER, &query,
                              point_lists[list], &source, 1, &options, &tree,
                              &validation, &search, states, sizeof states,
                              &check, &evidence),
                          ==, invalid ? TC_TLV_INVALID : TC_TLV_OK);
                      if (invalid) {
                        munit_assert_size(probe.calls, ==, 0);
                        munit_assert_memory_equal(sizeof evidence, &evidence,
                                                  &empty);
                      } else {
                        munit_assert_size(probe.calls, ==, PARTITIONS);
                        munit_assert_int(
                            tc_x509_crl_evidence_status(&evidence, &status), ==,
                            TC_TLV_OK);
                        munit_assert_int(status, ==, TC_X509_CRL_UNREVOKED);
                        const size_t required = TRUST_WORK_BUDGET - work;
                        for (unsigned short_budget = 0; short_budget < 2;
                             ++short_budget) {
                          evidence = empty;
                          work = required - short_budget;
                          munit_assert_int(
                              tc_cms_crl_points_process(
                                  &reader, &partitions,
                                  TC_X509_CRL_COMPLETE_ONLY,
                                  TC_X509_CRL_ORDER_NUMBER, &query,
                                  point_lists[list], &source, 1, &options,
                                  &tree, &validation, &search, states,
                                  sizeof states, &check, &evidence),
                              ==, short_budget ? TC_TLV_LIMIT : TC_TLV_OK);
                          if (short_budget)
                            munit_assert_memory_equal(sizeof evidence,
                                                      &evidence, &empty);
                        }
                      }
                    }
                    evidence = empty;
                    work = TRUST_WORK_BUDGET;
                    munit_assert_int(
                        tc_cms_crl_points_process(
                            &reader, &partitions, TC_X509_CRL_COMPLETE_ONLY,
                            TC_X509_CRL_ORDER_NUMBER, &query,
                            (TC_bytes){states, 1}, &source, 1, &options, &tree,
                            &validation, &search, states, sizeof states, &check,
                            &evidence),
                        ==, TC_TLV_ARGUMENT);
                    munit_assert_size(work, ==, TRUST_WORK_BUDGET);
                    munit_assert_memory_equal(sizeof evidence, &evidence,
                                              &empty);
                    for (unsigned source_failure = 0; source_failure < 2;
                         ++source_failure) {
                      probe.result = TC_X509_PATH_INVALID;
                      probe.accept_calls = 1;
                      probe.calls = 0;
                      probe.source_status =
                          source_failure ? &candidates.status : NULL;
                      evidence = empty;
                      work = TRUST_WORK_BUDGET;
                      munit_assert_int(
                          tc_cms_crl_points_process(
                              &reader, &partitions, TC_X509_CRL_COMPLETE_ONLY,
                              TC_X509_CRL_ORDER_NUMBER, &query,
                              (TC_bytes){split_points, sizeof split_points},
                              &source, 1, &options, &tree, &validation, &search,
                              states, sizeof states, &check, &evidence),
                          ==,
                          source_failure ? TC_TLV_UNSUPPORTED : TC_TLV_INVALID);
                      munit_assert_memory_equal(sizeof evidence, &evidence,
                                                &empty);
                      if (source_failure)
                        munit_assert_size(probe.calls, ==, 1);
                      else
                        munit_assert_size(probe.calls, >=, 2);
                      probe.source_status = NULL;
                      candidates.status = TC_TLV_OK;
                    }
                    probe.accept_calls = 0;
                    probe.result = TC_X509_PATH_VALID;
                    const TC_X509_path_status rejected[] = {
                        TC_X509_PATH_INVALID, TC_X509_PATH_UNSUPPORTED,
                        TC_X509_PATH_LIMIT, TC_X509_PATH_ERROR};
                    for (size_t rejection = 0;
                         rejection < sizeof rejected / sizeof *rejected;
                         ++rejection) {
                      probe.result = rejected[rejection];
                      probe.calls = 0;
                      evidence = empty;
                      work = TRUST_WORK_BUDGET;
                      munit_assert_int(
                          tc_cms_crl_point_process(
                              &reader, &partitions, TC_X509_CRL_COMPLETE_ONLY,
                              TC_X509_CRL_ORDER_NUMBER, &query, &source, 1,
                              &options, &tree, &validation, &search, states,
                              sizeof states, &check, &evidence),
                          ==, tc_x509_path_result_status(probe.result));
                      munit_assert_memory_equal(sizeof evidence, &evidence,
                                                &empty);
                      munit_assert_size(probe.calls, >, 0);
                    }
                    probe.result = TC_X509_PATH_INVALID;
                    probe.accept_calls = 1;
                    probe.calls = 0;
                    evidence = empty;
                    work = TRUST_WORK_BUDGET;
                    munit_assert_int(
                        tc_cms_crl_point_process(
                            &reader, &partitions, TC_X509_CRL_COMPLETE_ONLY,
                            TC_X509_CRL_ORDER_NUMBER, &query, &source, 1,
                            &options, &tree, &validation, &search, states,
                            sizeof states, &check, &evidence),
                        ==, TC_TLV_INVALID);
                    munit_assert_memory_equal(sizeof evidence, &evidence,
                                              &empty);
                    munit_assert_size(probe.calls, >, 1);
                    probe.accept_calls = 0;
                    probe.result = TC_X509_PATH_VALID;
                    probe.calls = 0;
                    probe.source_status = &candidates.status;
                    work = TRUST_WORK_BUDGET;
                    munit_assert_int(
                        tc_cms_crl_point_process(
                            &reader, &partitions, TC_X509_CRL_COMPLETE_ONLY,
                            TC_X509_CRL_ORDER_NUMBER, &query, &source, 1,
                            &options, &tree, &validation, &search, states,
                            sizeof states, &check, &evidence),
                        ==, TC_TLV_UNSUPPORTED);
                    munit_assert_memory_equal(sizeof evidence, &evidence,
                                              &empty);
                    munit_assert_size(probe.calls, ==, 1);
                    probe.source_status = NULL;
                    candidates.status = TC_TLV_OK;
                    probe.increase_work = 1;
                    evidence = empty;
                    work = TRUST_WORK_BUDGET;
                    munit_assert_int(
                        tc_cms_crl_point_process(
                            &reader, &partitions, TC_X509_CRL_COMPLETE_ONLY,
                            TC_X509_CRL_ORDER_NUMBER, &query, &source, 1,
                            &options, &tree, &validation, &search, states,
                            sizeof states, &check, &evidence),
                        ==, TC_TLV_ARGUMENT);
                    munit_assert_memory_equal(sizeof evidence, &evidence,
                                              &empty);
                    munit_assert_size(work, ==, 0);
                    probe.increase_work = 0;
                    probe.calls = 0;
                    candidates.status = TC_TLV_UNSUPPORTED;
                    candidates.calls = 0;
                    work = TRUST_WORK_BUDGET;
                    munit_assert_int(
                        tc_cms_crl_point_process(
                            &reader, &partitions, TC_X509_CRL_COMPLETE_ONLY,
                            TC_X509_CRL_ORDER_NUMBER, &query, &source, 1,
                            &options, &tree, &validation, &search, states,
                            sizeof states, &check, &evidence),
                        ==, TC_TLV_UNSUPPORTED);
                    munit_assert_memory_equal(sizeof evidence, &evidence,
                                              &empty);
                    munit_assert_size(candidates.calls, ==, 1);
                    munit_assert_size(probe.calls, ==, 0);
                    candidates.status = TC_TLV_OK;
                    const TC_X509_crl_index partial = {partition_rows, 1, 0};
                    work = TRUST_WORK_BUDGET;
                    munit_assert_int(
                        tc_cms_crl_point_process(
                            &reader, &partial, TC_X509_CRL_COMPLETE_ONLY,
                            TC_X509_CRL_ORDER_NUMBER, &query, &source, 1,
                            &options, &tree, &validation, &search, states,
                            sizeof states, &check, &evidence),
                        ==, TC_TLV_OK);
                    munit_assert_int(
                        tc_x509_crl_evidence_status(&evidence, &status), ==,
                        TC_TLV_OK);
                    munit_assert_int(status, ==, TC_X509_CRL_UNDETERMINED);
                    munit_assert_uint(evidence.reasons, ==, masks[order]);
                    evidence = empty;
                    work = TRUST_WORK_BUDGET;
                    probe.calls = 0;
                    const TC_X509_crl_index no_records = {NULL, 0, 0};
                    munit_assert_int(
                        tc_cms_crl_point_process(
                            &reader, &no_records, TC_X509_CRL_COMPLETE_ONLY,
                            TC_X509_CRL_ORDER_NUMBER, &query, &source, 1,
                            &options, &tree, &validation, &search, NULL, 0,
                            &check, &evidence),
                        ==, TC_TLV_END);
                    munit_assert_memory_equal(sizeof evidence, &evidence,
                                              &empty);
                    munit_assert_size(probe.calls, ==, 0);
                    work = TRUST_WORK_BUDGET;
                    munit_assert_int(
                        tc_cms_crl_point_process(
                            &reader, &partitions, TC_X509_CRL_COMPLETE_ONLY,
                            TC_X509_CRL_ORDER_NUMBER, &query, &source, 1,
                            &options, &tree, &validation, &search, states,
                            sizeof states, NULL, &evidence),
                        ==, TC_TLV_ARGUMENT);
                    munit_assert_size(work, ==, TRUST_WORK_BUDGET);
                    munit_assert_int(
                        tc_cms_crl_point_process(
                            &reader, &partitions, TC_X509_CRL_COMPLETE_ONLY,
                            TC_X509_CRL_ORDER_NUMBER, &query, &source, 1,
                            &options, &tree, &validation, &search,
                            (uint8_t *)&check, sizeof check, &check, &evidence),
                        ==, TC_TLV_ARGUMENT);
                    munit_assert_size(work, ==, TRUST_WORK_BUDGET);
                    munit_assert_memory_equal(sizeof evidence, &evidence,
                                              &empty);
                    munit_assert_size(probe.calls, ==, 0);
                  }
                  TC_bytes swap = partition_inputs[0];
                  partition_inputs[0] = partition_inputs[1];
                  partition_inputs[1] = swap;
                }
              }
            }
            candidates = (candidate_source){records, 4, 0, TC_TLV_OK, 0};
          }
        }
      }
      work = WORK_BUDGET;
    }
    if (check_selection) {
      const uint8_t serial = 9;
      TC_X509_certificate target = {0};
      target.serial = (TC_bytes){&serial, 1};
      target.issuer = parsed.issuer;
      tc_x509_crl_selected selected = {&parsed, &crl_info, NULL, NULL};
      tc_x509_crl_match match, saved;
      memset(&saved, 0xa5, sizeof saved);
      work = WORK_BUDGET;
      munit_assert_int(tc_x509_crl_selected_find(
                           &selected, &signer, &target, &provider, &limits,
                           &tree, &names, oids, EXTENSION_CAPACITY, &match),
                       ==, TC_TLV_OK);
      munit_assert_int(match.found, ==, revoked);
      tc_pki_distribution_point point = {0};
      tc_x509_crl_query query = {&target, &point, 0};
      {
        enum { KEY_COMPROMISE_REASONS = 1u << 1 };
        tc_x509_crl_evidence evidence = {0};
        tc_x509_crl_status status;
        TC_X509_search_result trusted, unchanged;
        signature_retry_probe probe = {provider, 0, 0, TC_X509_SIGNATURE_ERROR};
        TC_X509_path_options checked = options;
        checked.signatures =
            (TC_X509_signature_provider){retry_signature, &probe, NULL};
        memset(&unchanged, 0xa5, sizeof unchanged);
        work = TRUST_WORK_BUDGET;
        munit_assert_int(tc_x509_crl_process(
                             &selected, &signer, &query, &source, 1, &checked,
                             &validation, &search, &work, &evidence, &trusted),
                         ==, TC_TLV_OK);
        munit_assert_size(probe.calls, ==, 2);
        const size_t required = TRUST_WORK_BUDGET - work;
        munit_assert_size(trusted.validation.work_used, ==, required);
        munit_assert_size(trusted.anchor_index, ==, 1);
        munit_assert_ptr_equal(trusted.path[0].data, signer_der);
        munit_assert_int(tc_x509_crl_evidence_status(&evidence, &status), ==,
                         TC_TLV_OK);
        munit_assert_int(status, ==,
                         revoked ? TC_X509_CRL_REVOKED : TC_X509_CRL_UNREVOKED);
        const tc_x509_crl_evidence terminal = evidence;
        trusted = unchanged;
        munit_assert_int(tc_x509_crl_process(
                             &selected, &signer, &query, &source, 1, &checked,
                             &validation, &search, &work, &evidence, &trusted),
                         ==, TC_TLV_END);
        munit_assert_memory_equal(sizeof evidence, &evidence, &terminal);
        munit_assert_memory_equal(sizeof trusted, &trusted, &unchanged);
        munit_assert_size(probe.calls, ==, 2);
        evidence = (tc_x509_crl_evidence){0};
        work = required;
        munit_assert_int(tc_x509_crl_process(
                             &selected, &signer, &query, &source, 1, &options,
                             &validation, &search, &work, &evidence, &trusted),
                         ==, TC_TLV_OK);
        munit_assert_size(work, ==, 0);
        enum {
          FUTURE,
          STALE,
          NO_NEXT,
          WRONG_ISSUER,
          WRONG_ANCHOR,
          NO_PROVIDER,
          SHORT_WORK,
          REQUIRE_KU,
          CRITICAL,
          BAD_STATE,
          FAILURE_COUNT
        };
        for (unsigned failure = 0; failure < FAILURE_COUNT; ++failure) {
          tc_x509_crl copy = parsed;
          tc_x509_crl_extension_info info = crl_info;
          tc_x509_crl_selected rejected = {&copy, &info, NULL, NULL};
          TC_X509_certificate query_certificate = target;
          tc_x509_crl_query rejected_query = {&query_certificate, &point, 0};
          TC_X509_path_options rejected_options = options;
          size_t anchor_index = 1;
          TC_TLV_result expected_result = TC_TLV_INVALID;
          work = TRUST_WORK_BUDGET;
          evidence = (tc_x509_crl_evidence){0};
          evidence.reasons = KEY_COMPROMISE_REASONS;
          if (failure == FUTURE) {
            rejected_options.at.year = 2025;
            expected_result = TC_TLV_END;
          }
          if (failure == STALE) {
            rejected_options.at = parsed.next_update;
            expected_result = TC_TLV_END;
          }
          if (failure == NO_NEXT) {
            copy.has_next_update = 0;
            expected_result = TC_TLV_END;
          }
          if (failure == WRONG_ISSUER) {
            query_certificate.issuer =
                (TC_bytes){(const uint8_t *)"\x30\x00", 2};
            expected_result = TC_TLV_END;
          }
          if (failure == WRONG_ANCHOR)
            anchor_index = 0;
          if (failure == NO_PROVIDER) {
            rejected_options.signatures.verify = NULL;
            expected_result = TC_TLV_UNSUPPORTED;
          }
          if (failure == SHORT_WORK) {
            work = required - 1;
            expected_result = TC_TLV_LIMIT;
          }
          if (failure == REQUIRE_KU)
            rejected_options.flags = TC_X509_PATH_REQUIRE_KEY_USAGE;
          if (failure == CRITICAL) {
            info.unknown_critical_oid = target.serial;
            expected_result = TC_TLV_UNSUPPORTED;
          }
          if (failure == BAD_STATE) {
            evidence.reasons = 1;
            expected_result = TC_TLV_ARGUMENT;
          }
          const tc_x509_crl_evidence before = evidence;
          trusted = unchanged;
          munit_assert_int(
              tc_x509_crl_process(&rejected, &signer, &rejected_query, &source,
                                  anchor_index, &rejected_options, &validation,
                                  &search, &work, &evidence, &trusted),
              ==, expected_result);
          munit_assert_memory_equal(sizeof evidence, &evidence, &before);
          munit_assert_memory_equal(sizeof trusted, &trusted, &unchanged);
        }
        point.has_reasons = 1;
        point.reasons = KEY_COMPROMISE_REASONS;
        evidence = (tc_x509_crl_evidence){0};
        work = TRUST_WORK_BUDGET;
        munit_assert_int(tc_x509_crl_process(
                             &selected, &signer, &query, &source, 1, &options,
                             &validation, &search, &work, &evidence, &trusted),
                         ==, TC_TLV_OK);
        munit_assert_int(tc_x509_crl_evidence_status(&evidence, &status), ==,
                         TC_TLV_OK);
        munit_assert_int(status, ==,
                         revoked ? TC_X509_CRL_REVOKED
                                 : TC_X509_CRL_UNDETERMINED);
        trusted = unchanged;
        munit_assert_int(tc_x509_crl_process(
                             &selected, &signer, &query, &source, 1, &options,
                             &validation, &search, &work, &evidence, &trusted),
                         ==, TC_TLV_END);
        munit_assert_memory_equal(sizeof trusted, &trusted, &unchanged);
        if (!revoked) {
          point.reasons = TC_X509_CRL_ALL_REASONS & ~KEY_COMPROMISE_REASONS;
          work = TRUST_WORK_BUDGET;
          munit_assert_int(tc_x509_crl_process(&selected, &signer, &query,
                                               &source, 1, &options,
                                               &validation, &search, &work,
                                               &evidence, &trusted),
                           ==, TC_TLV_OK);
          munit_assert_int(tc_x509_crl_evidence_status(&evidence, &status), ==,
                           TC_TLV_OK);
          munit_assert_int(status, ==, TC_X509_CRL_UNREVOKED);
        }
        point = (tc_pki_distribution_point){0};
      }
      work = WORK_BUDGET;
      match = saved;
      munit_assert_int(tc_x509_crl_selected_find(
                           &selected, &signer, &target, NULL, &limits, &tree,
                           &names, oids, EXTENSION_CAPACITY, &match),
                       ==, TC_TLV_UNSUPPORTED);
      munit_assert_memory_equal(sizeof match, &match, &saved);
      const size_t signature_offset = (size_t)(parsed.signature.data - encoded);
      encoded[signature_offset] ^= 1;
      work = WORK_BUDGET;
      munit_assert_int(tc_x509_crl_selected_find(
                           &selected, &signer, &target, &provider, &limits,
                           &tree, &names, oids, EXTENSION_CAPACITY, &match),
                       ==, TC_TLV_INVALID);
      munit_assert_memory_equal(sizeof match, &match, &saved);
      encoded[signature_offset] ^= 1;
      enum { DELTA_FALLBACK = 2 };
      const unsigned reasons[] = {1, 8, 0};
      for (size_t i = 0; i < sizeof reasons / sizeof reasons[0]; ++i) {
        uint8_t delta_der[sizeof encoded];
        X509_CRL *delta_crl = X509_CRL_dup(crl);
        ASN1_INTEGER *number = ASN1_INTEGER_new();
        munit_assert_not_null(delta_crl);
        munit_assert_not_null(number);
        ASN1_TIME *delta_next = ASN1_TIME_new();
        munit_assert_not_null(delta_next);
        munit_assert_int(ASN1_TIME_set_string(delta_next, "280101000000Z"), ==,
                         1);
        munit_assert_int(X509_CRL_set1_lastUpdate(delta_crl, next_date), ==, 1);
        munit_assert_int(X509_CRL_set1_nextUpdate(delta_crl, delta_next), ==,
                         1);
        ASN1_TIME_free(delta_next);
        munit_assert_int(ASN1_INTEGER_set(number, 2), ==, 1);
        munit_assert_int(X509_CRL_add1_ext_i2d(delta_crl, NID_crl_number,
                                               number, 0, X509V3_ADD_REPLACE),
                         ==, 1);
        munit_assert_int(ASN1_INTEGER_set(number, 1), ==, 1);
        munit_assert_int(
            X509_CRL_add1_ext_i2d(delta_crl, NID_delta_crl, number, 1, 0), ==,
            1);
        ASN1_INTEGER_free(number);
        if (revoked && i == DELTA_FALLBACK) {
          /* A delta entry for another certificate does not replace this one. */
          ASN1_INTEGER *other_serial = ASN1_INTEGER_new();
          munit_assert_not_null(other_serial);
          munit_assert_int(ASN1_INTEGER_set(other_serial, 10), ==, 1);
          X509_REVOKED *item =
              sk_X509_REVOKED_value(X509_CRL_get_REVOKED(delta_crl), 0);
          munit_assert_int(X509_REVOKED_set_serialNumber(item, other_serial),
                           ==, 1);
          ASN1_INTEGER_free(other_serial);
        } else if (revoked) {
          ASN1_ENUMERATED *reason = ASN1_ENUMERATED_new();
          munit_assert_not_null(reason);
          munit_assert_int(ASN1_ENUMERATED_set(reason, reasons[i]), ==, 1);
          X509_REVOKED *item =
              sk_X509_REVOKED_value(X509_CRL_get_REVOKED(delta_crl), 0);
          munit_assert_int(
              X509_REVOKED_add1_ext_i2d(item, NID_crl_reason, reason, 0, 0), ==,
              1);
          ASN1_ENUMERATED_free(reason);
        }
        /* Equal metadata cannot substitute for verification with the base key.
         */
        for (unsigned wrong_key = 0; wrong_key < 2; ++wrong_key) {
          tc_x509_crl delta;
          tc_x509_crl_extension_info delta_info;
          munit_assert_int(X509_CRL_sign(delta_crl,
                                         wrong_key ? other_key : generated,
                                         EVP_sha256()),
                           >, 0);
          int delta_length = i2d_X509_CRL(delta_crl, NULL);
          munit_assert_int(delta_length, >, 0);
          munit_assert_size((size_t)delta_length, <=, sizeof delta_der);
          cursor = delta_der;
          munit_assert_int(i2d_X509_CRL(delta_crl, &cursor), ==, delta_length);
          work = WORK_BUDGET;
          munit_assert_int(
              tc_x509_crl_read((TC_bytes){delta_der, (size_t)delta_length},
                               &limits, &tree, &delta),
              ==, TC_TLV_OK);
          munit_assert_int(tc_x509_crl_extension_info_read(
                               delta.extensions, &limits, &tree, oids,
                               EXTENSION_CAPACITY, &delta_info),
                           ==, TC_TLV_OK);
          selected.delta = &delta;
          selected.delta_info = &delta_info;
          {
            tc_x509_crl_evidence evidence = {0}, empty = {0};
            TC_X509_search_result trusted, unchanged;
            TC_X509_path_options updated = options;
            signature_retry_probe probe = {provider, 0, 0,
                                           TC_X509_SIGNATURE_ERROR};
            updated.signatures =
                (TC_X509_signature_provider){retry_signature, &probe, NULL};
            updated.at = delta.this_update;
            memset(&unchanged, 0xa5, sizeof unchanged);
            trusted = unchanged;
            tc_cms_candidates candidate_reader;
            work = TRUST_WORK_BUDGET;
            munit_assert_int(tc_cms_candidates_init(container.certificates,
                                                    NULL, 1, sizeof encoded,
                                                    &limits, &tree,
                                                    &candidate_reader),
                             ==, TC_TLV_OK);
            const tc_cms_candidates before_search = candidate_reader;
            const TC_bytes crl_records[] = {parsed.encoded, delta.encoded};
            candidate_source crl_source = {crl_records, 2, 0, TC_TLV_OK, 0};
            const tc_pki_record_source records = {&crl_source, 2,
                                                  read_candidate};
            tc_cms_revocations revocations;
            TC_X509_crl_record indexed_records[2];
            TC_X509_crl_index crl_index;
            tc_x509_crl_selected indexed_pair;
            size_t delta_cursor = 0;
            work = TRUST_WORK_BUDGET;
            munit_assert_int(
                tc_cms_revocations_init((TC_bytes){NULL, 0}, &records, 2,
                                        sizeof encoded + sizeof delta_der,
                                        &limits, &tree, &revocations),
                ==, TC_TLV_OK);
            munit_assert_int(tc_cms_crl_index_init(
                                 &revocations, &tree, oids, EXTENSION_CAPACITY,
                                 indexed_records, 2, &crl_index),
                             ==, TC_TLV_OK);
            munit_assert_size(crl_source.calls, ==, 2);
            munit_assert_int(
                tc_x509_crl_delta_next(&crl_index, 0, &delta_cursor, &limits,
                                       &tree, &names, &indexed_pair),
                ==, TC_TLV_OK);
            munit_assert_ptr_equal(indexed_pair.base->encoded.data,
                                   parsed.encoded.data);
            munit_assert_ptr_equal(indexed_pair.delta->encoded.data,
                                   delta.encoded.data);
            tc_x509_crl_selected preferred, untouched;
            const tc_x509_crl_selected complete = {
                indexed_pair.base, indexed_pair.base_info, NULL, NULL};
            work = TRUST_WORK_BUDGET;
            munit_assert_int(tc_x509_crl_selected_validate(
                                 &complete, &signer, &source, 1, &updated,
                                 &validation, &search, &work, &trusted),
                             ==, TC_TLV_OK);
            memset(&untouched, 0xa5, sizeof untouched);
            preferred = untouched;
            {
              uint8_t states[2] = {0xa5, 0xa5};
              tc_x509_crl_signature_cache cache, saved_cache;
              memset(&saved_cache, 0xa5, sizeof saved_cache);
              cache = saved_cache;
              work = TRUST_WORK_BUDGET;
              munit_assert_int(tc_x509_crl_signature_cache_init(
                                   &crl_index, &signer, &updated.signatures,
                                   &limits, &names, states, 1, &work, &cache),
                               ==, TC_TLV_LIMIT);
              munit_assert_memory_equal(sizeof cache, &cache, &saved_cache);
              munit_assert_uint(states[0], ==, 0xa5);
              work = 1;
              munit_assert_int(tc_x509_crl_signature_cache_init(
                                   &crl_index, &signer, &updated.signatures,
                                   &limits, &names, states, 2, &work, &cache),
                               ==, TC_TLV_LIMIT);
              munit_assert_memory_equal(sizeof cache, &cache, &saved_cache);
              munit_assert_uint(states[0], ==, 0xa5);
              work = 2;
              munit_assert_int(tc_x509_crl_signature_cache_init(
                                   &crl_index, &signer, &updated.signatures,
                                   &limits, &names, states, 2, &work, &cache),
                               ==, TC_TLV_OK);
              munit_assert_size(work, ==, 0);
              const size_t calls = probe.calls;
              munit_assert_int(tc_x509_crl_signature_cached(&cache, 1, &work),
                               ==, TC_TLV_LIMIT);
              munit_assert_size(probe.calls, ==, calls);
              for (unsigned repeat = 0; repeat < 2; ++repeat) {
                tc_x509_crl_selected cached_pair = untouched;
                work = TRUST_WORK_BUDGET;
                munit_assert_int(
                    tc_x509_crl_delta_select_cached(&cache, 0, &updated.at,
                                                    &tree, &cached_pair),
                    ==, wrong_key ? TC_TLV_END : TC_TLV_OK);
                munit_assert_size(probe.calls, ==, calls + 1);
                if (wrong_key)
                  munit_assert_memory_equal(sizeof cached_pair, &cached_pair,
                                            &untouched);
                else
                  munit_assert_ptr_equal(cached_pair.delta, indexed_pair.delta);
              }
              const TC_X509_crl_delta_policy selection_modes[] = {
                  TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_DELTA_IF_AVAILABLE,
                  TC_X509_CRL_DELTA_REQUIRED};
              for (unsigned period = 0; period < 2; ++period)
                for (size_t mode = 0;
                     mode < sizeof selection_modes / sizeof selection_modes[0];
                     ++mode) {
                  const TC_X509_time *at =
                      period ? &delta.this_update : &parsed.this_update;
                  const int available =
                      period
                          ? !wrong_key && selection_modes[mode] !=
                                              TC_X509_CRL_COMPLETE_ONLY
                          : selection_modes[mode] != TC_X509_CRL_DELTA_REQUIRED;
                  size_t position = 0;
                  tc_x509_crl_selected effective = untouched;
                  work = TRUST_WORK_BUDGET;
                  munit_assert_int(
                      tc_x509_crl_effective_next(&cache, 0, &position,
                                                 selection_modes[mode], at,
                                                 &tree, &effective),
                      ==, available ? TC_TLV_OK : TC_TLV_END);
                  munit_assert_size(probe.calls, ==, calls + 2);
                  if (available) {
                    munit_assert_size(position, ==, 1);
                    munit_assert_ptr_equal(effective.base, indexed_pair.base);
                    munit_assert_ptr_equal(effective.delta,
                                           period ? indexed_pair.delta : NULL);
                    const tc_x509_crl_selected prior = effective;
                    munit_assert_int(
                        tc_x509_crl_effective_next(&cache, 0, &position,
                                                   selection_modes[mode], at,
                                                   &tree, &effective),
                        ==, TC_TLV_END);
                    munit_assert_memory_equal(sizeof effective, &effective,
                                              &prior);
                  } else {
                    munit_assert_size(position, ==, 0);
                    munit_assert_memory_equal(sizeof effective, &effective,
                                              &untouched);
                  }
                }
              {
                size_t position = 0;
                tc_x509_crl_selected effective;
                work = TRUST_WORK_BUDGET;
                munit_assert_int(tc_x509_crl_effective_next(
                                     &cache, 0, &position,
                                     TC_X509_CRL_COMPLETE_ONLY,
                                     &parsed.this_update, &tree, &effective),
                                 ==, TC_TLV_OK);
                const size_t required = TRUST_WORK_BUDGET - work;
                for (size_t budget = 0; budget <= required; ++budget) {
                  position = 0;
                  work = budget;
                  effective = untouched;
                  munit_assert_int(
                      tc_x509_crl_effective_next(
                          &cache, 0, &position, TC_X509_CRL_COMPLETE_ONLY,
                          &parsed.this_update, &tree, &effective),
                      ==, budget == required ? TC_TLV_OK : TC_TLV_LIMIT);
                  if (budget < required) {
                    munit_assert_size(position, ==, 0);
                    munit_assert_memory_equal(sizeof effective, &effective,
                                              &untouched);
                  }
                }
                munit_assert_size(probe.calls, ==, calls + 2);
              }
              const TC_X509_signature_result failures[] = {
                  TC_X509_SIGNATURE_UNSUPPORTED, TC_X509_SIGNATURE_LIMIT,
                  TC_X509_SIGNATURE_ERROR};
              const TC_TLV_result errors[] = {TC_TLV_UNSUPPORTED, TC_TLV_LIMIT,
                                              TC_TLV_ARGUMENT};
              for (size_t failure = 0;
                   failure < sizeof failures / sizeof failures[0]; ++failure) {
                signature_retry_probe retry = {provider, 0, 1,
                                               failures[failure]};
                const TC_X509_signature_provider failing = {retry_signature,
                                                            &retry, NULL};
                work = TRUST_WORK_BUDGET;
                munit_assert_int(tc_x509_crl_signature_cache_init(
                                     &crl_index, &signer, &failing, &limits,
                                     &names, states, 2, &work, &cache),
                                 ==, TC_TLV_OK);
                const uint8_t unchecked = states[1];
                munit_assert_int(tc_x509_crl_signature_cached(&cache, 1, &work),
                                 ==, errors[failure]);
                munit_assert_uint(states[1], ==, unchecked);
                for (unsigned repeat = 0; repeat < 2; ++repeat) {
                  work = TRUST_WORK_BUDGET;
                  munit_assert_int(
                      tc_x509_crl_signature_cached(&cache, 1, &work), ==,
                      wrong_key ? TC_TLV_INVALID : TC_TLV_OK);
                  munit_assert_size(retry.calls, ==, 2);
                }
              }
            }
            work = TRUST_WORK_BUDGET;
            munit_assert_int(tc_x509_crl_delta_select(
                                 &crl_index, 0, &signer, &updated.at, &provider,
                                 &limits, &tree, &names, &preferred),
                             ==, wrong_key ? TC_TLV_END : TC_TLV_OK);
            if (wrong_key)
              munit_assert_memory_equal(sizeof preferred, &preferred,
                                        &untouched);
            else {
              const size_t required = TRUST_WORK_BUDGET - work;
              munit_assert_ptr_equal(preferred.delta, indexed_pair.delta);
              work = required - 1;
              preferred = untouched;
              munit_assert_int(tc_x509_crl_delta_select(&crl_index, 0, &signer,
                                                        &updated.at, &provider,
                                                        &limits, &tree, &names,
                                                        &preferred),
                               ==, TC_TLV_LIMIT);
              munit_assert_memory_equal(sizeof preferred, &preferred,
                                        &untouched);
              work = required;
              munit_assert_int(tc_x509_crl_delta_select(&crl_index, 0, &signer,
                                                        &updated.at, &provider,
                                                        &limits, &tree, &names,
                                                        &preferred),
                               ==, TC_TLV_OK);
              munit_assert_size(work, ==, 0);
              tc_x509_crl_evidence applied = {0};
              tc_x509_crl_status applied_status;
              const size_t signature_calls = probe.calls;
              work = TRUST_WORK_BUDGET;
              munit_assert_int(tc_x509_crl_apply(&preferred, &query,
                                                 &updated.at, &limits, &tree,
                                                 &names, oids,
                                                 EXTENSION_CAPACITY, &applied),
                               ==, TC_TLV_OK);
              const size_t apply_work = TRUST_WORK_BUDGET - work;
              munit_assert_size(probe.calls, ==, signature_calls);
              munit_assert_int(
                  tc_x509_crl_evidence_status(&applied, &applied_status), ==,
                  TC_TLV_OK);
              munit_assert_int(applied_status, ==,
                               revoked && reasons[i] != 8
                                   ? TC_X509_CRL_REVOKED
                                   : TC_X509_CRL_UNREVOKED);
              const tc_x509_crl_evidence completed = applied;
              munit_assert_int(tc_x509_crl_apply(&preferred, &query,
                                                 &updated.at, &limits, &tree,
                                                 &names, oids,
                                                 EXTENSION_CAPACITY, &applied),
                               ==, TC_TLV_END);
              munit_assert_memory_equal(sizeof applied, &applied, &completed);
              applied = empty;
              work = apply_work - 1;
              munit_assert_int(tc_x509_crl_apply(&preferred, &query,
                                                 &updated.at, &limits, &tree,
                                                 &names, oids,
                                                 EXTENSION_CAPACITY, &applied),
                               ==, TC_TLV_LIMIT);
              munit_assert_memory_equal(sizeof applied, &applied, &empty);
              work = apply_work;
              munit_assert_int(tc_x509_crl_apply(&preferred, &query,
                                                 &updated.at, &limits, &tree,
                                                 &names, oids,
                                                 EXTENSION_CAPACITY, &applied),
                               ==, TC_TLV_OK);
              munit_assert_size(work, ==, 0);
              applied = empty;
              work = TRUST_WORK_BUDGET;
              munit_assert_int(tc_x509_crl_apply(&preferred, &query,
                                                 &delta.next_update, &limits,
                                                 &tree, &names, oids,
                                                 EXTENSION_CAPACITY, &applied),
                               ==, TC_TLV_END);
              munit_assert_memory_equal(sizeof applied, &applied, &empty);
            }
            if (!wrong_key && i == 0) {
              uint8_t extra_der[2][sizeof encoded];
              TC_bytes extended[] = {
                  parsed.encoded, delta.encoded, {NULL, 0}, {NULL, 0}};
              for (size_t extra = 0; extra < 2; ++extra) {
                X509_CRL *variant = X509_CRL_dup(delta_crl);
                ASN1_INTEGER *variant_number = ASN1_INTEGER_new();
                munit_assert_not_null(variant);
                munit_assert_not_null(variant_number);
                munit_assert_int(
                    ASN1_INTEGER_set(variant_number, (long)(3 + extra)), ==, 1);
                munit_assert_int(X509_CRL_add1_ext_i2d(variant, NID_crl_number,
                                                       variant_number, 0,
                                                       X509V3_ADD_REPLACE),
                                 ==, 1);
                ASN1_INTEGER_free(variant_number);
                munit_assert_int(X509_CRL_sign(variant,
                                               extra ? other_key : generated,
                                               EVP_sha256()),
                                 >, 0);
                const int length = i2d_X509_CRL(variant, NULL);
                munit_assert_int(length, >, 0);
                munit_assert_size((size_t)length, <=, sizeof extra_der[extra]);
                unsigned char *destination = extra_der[extra];
                munit_assert_int(i2d_X509_CRL(variant, &destination), ==,
                                 length);
                extended[extra + 2] =
                    (TC_bytes){extra_der[extra], (size_t)length};
                X509_CRL_free(variant);
              }
              candidate_source mixed_source = {extended, 4, 0, TC_TLV_OK, 0};
              const tc_pki_record_source mixed_records = {&mixed_source, 4,
                                                          read_candidate};
              TC_X509_crl_record mixed_rows[4];
              TC_X509_crl_index mixed_index;
              for (unsigned order = 0; order < 2; ++order) {
                work = TRUST_WORK_BUDGET;
                munit_assert_int(
                    tc_cms_revocations_init((TC_bytes){NULL, 0}, &mixed_records,
                                            4, 4 * sizeof encoded, &limits,
                                            &tree, &revocations),
                    ==, TC_TLV_OK);
                munit_assert_int(tc_cms_crl_index_init(&revocations, &tree,
                                                       oids, EXTENSION_CAPACITY,
                                                       mixed_rows, 4,
                                                       &mixed_index),
                                 ==, TC_TLV_OK);
                munit_assert_int(
                    tc_x509_crl_delta_select(&mixed_index, 0, &signer,
                                             &updated.at, &provider, &limits,
                                             &tree, &names, &preferred),
                    ==, TC_TLV_OK);
                munit_assert_ptr_equal(preferred.delta->encoded.data,
                                       extra_der[0]);
                TC_bytes swap = extended[1];
                extended[1] = extended[3];
                extended[3] = swap;
              }
              preferred = untouched;
              work = TRUST_WORK_BUDGET;
              munit_assert_int(
                  tc_x509_crl_delta_select(&mixed_index, 0, &signer,
                                           &delta.next_update, &provider,
                                           &limits, &tree, &names, &preferred),
                  ==, TC_TLV_END);
              munit_assert_memory_equal(sizeof preferred, &preferred,
                                        &untouched);
              work = TRUST_WORK_BUDGET;
              munit_assert_int(tc_x509_crl_delta_select(
                                   &mixed_index, 0, &signer, &updated.at, NULL,
                                   &limits, &tree, &names, &preferred),
                               ==, TC_TLV_UNSUPPORTED);
              munit_assert_memory_equal(sizeof preferred, &preferred,
                                        &untouched);
              for (long collision = 2; collision <= 3; ++collision) {
                X509_CRL *variant = X509_CRL_dup(delta_crl);
                ASN1_INTEGER *variant_number = ASN1_INTEGER_new();
                ASN1_TIME *variant_next = ASN1_TIME_new();
                munit_assert_not_null(variant);
                munit_assert_not_null(variant_number);
                munit_assert_not_null(variant_next);
                munit_assert_int(ASN1_INTEGER_set(variant_number, collision),
                                 ==, 1);
                munit_assert_int(X509_CRL_add1_ext_i2d(variant, NID_crl_number,
                                                       variant_number, 0,
                                                       X509V3_ADD_REPLACE),
                                 ==, 1);
                munit_assert_int(
                    ASN1_TIME_set_string(variant_next, "280101000001Z"), ==, 1);
                munit_assert_int(
                    X509_CRL_set1_nextUpdate(variant, variant_next), ==, 1);
                ASN1_INTEGER_free(variant_number);
                ASN1_TIME_free(variant_next);
                munit_assert_int(
                    X509_CRL_sign(variant, generated, EVP_sha256()), >, 0);
                const int length = i2d_X509_CRL(variant, NULL);
                munit_assert_int(length, >, 0);
                munit_assert_size((size_t)length, <=, sizeof extra_der[1]);
                unsigned char *destination = extra_der[1];
                munit_assert_int(i2d_X509_CRL(variant, &destination), ==,
                                 length);
                X509_CRL_free(variant);
                extended[3] = (TC_bytes){extra_der[1], (size_t)length};
                for (unsigned order = 0; order < 2; ++order) {
                  work = TRUST_WORK_BUDGET;
                  preferred = untouched;
                  munit_assert_int(tc_cms_revocations_init(
                                       (TC_bytes){NULL, 0}, &mixed_records, 4,
                                       4 * sizeof encoded, &limits, &tree,
                                       &revocations),
                                   ==, TC_TLV_OK);
                  munit_assert_int(
                      tc_cms_crl_index_init(&revocations, &tree, oids,
                                            EXTENSION_CAPACITY, mixed_rows, 4,
                                            &mixed_index),
                      ==, TC_TLV_OK);
                  munit_assert_int(
                      tc_x509_crl_delta_select(&mixed_index, 0, &signer,
                                               &updated.at, &provider, &limits,
                                               &tree, &names, &preferred),
                      ==, collision == 3 ? TC_TLV_INVALID : TC_TLV_OK);
                  if (collision == 3)
                    munit_assert_memory_equal(sizeof preferred, &preferred,
                                              &untouched);
                  else
                    munit_assert_ptr_equal(preferred.delta->encoded.data,
                                           extra_der[0]);
                  TC_bytes swap = extended[2];
                  extended[2] = extended[3];
                  extended[3] = swap;
                }
              }
            }
            trusted = unchanged;
            probe.calls = 0;
            work = TRUST_WORK_BUDGET;
            munit_assert_int(tc_x509_crl_selected_validate(
                                 &indexed_pair, &signer, &source, 1, &updated,
                                 &validation, &search, &work, &trusted),
                             ==, wrong_key ? TC_TLV_INVALID : TC_TLV_OK);
            if (wrong_key)
              munit_assert_memory_equal(sizeof trusted, &trusted, &unchanged);
            else {
              const size_t required = TRUST_WORK_BUDGET - work;
              munit_assert_size(trusted.validation.work_used, ==, required);
              munit_assert_size(trusted.anchor_index, ==, 1);
              munit_assert_size(probe.calls, ==, 3);
              trusted = unchanged;
              work = required - 1;
              munit_assert_int(tc_x509_crl_selected_validate(
                                   &indexed_pair, &signer, &source, 1, &updated,
                                   &validation, &search, &work, &trusted),
                               ==, TC_TLV_LIMIT);
              munit_assert_memory_equal(sizeof trusted, &trusted, &unchanged);
              work = required;
              munit_assert_int(tc_x509_crl_selected_validate(
                                   &indexed_pair, &signer, &source, 1, &updated,
                                   &validation, &search, &work, &trusted),
                               ==, TC_TLV_OK);
              munit_assert_size(work, ==, 0);
            }
            const TC_X509_crl_delta_policy policies[] = {
                TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_DELTA_IF_AVAILABLE,
                TC_X509_CRL_DELTA_REQUIRED};
            for (unsigned period = 0; period < 2; ++period) {
              TC_X509_path_options indexed_options = updated;
              indexed_options.at =
                  period ? delta.this_update : parsed.this_update;
              for (size_t policy = 0;
                   policy < sizeof policies / sizeof policies[0]; ++policy) {
                const TC_TLV_result expected =
                    period ? (!wrong_key && policies[policy] !=
                                                TC_X509_CRL_COMPLETE_ONLY
                                  ? TC_TLV_OK
                                  : TC_TLV_END)
                           : (policies[policy] == TC_X509_CRL_DELTA_REQUIRED
                                  ? TC_TLV_END
                                  : TC_TLV_OK);
                tc_x509_crl_evidence indexed_evidence = {0};
                trusted = unchanged;
                probe.calls = 0;
                work = TRUST_WORK_BUDGET;
                munit_assert_int(tc_cms_crl_index_process(
                                     &candidate_reader, &crl_index, 0,
                                     policies[policy], &query, &source, 1,
                                     &indexed_options, &tree, &validation,
                                     &search, &indexed_evidence, &trusted),
                                 ==, expected);
                munit_assert_memory_equal(sizeof candidate_reader,
                                          &candidate_reader, &before_search);
                munit_assert_size(
                    probe.calls, ==,
                    period ? (policies[policy] == TC_X509_CRL_COMPLETE_ONLY ? 0
                                                                            : 3)
                           : 2);
                if (expected == TC_TLV_OK) {
                  const size_t required = TRUST_WORK_BUDGET - work;
                  tc_x509_crl_status indexed_status;
                  munit_assert_size(trusted.validation.work_used, ==, required);
                  munit_assert_int(tc_x509_crl_evidence_status(
                                       &indexed_evidence, &indexed_status),
                                   ==, TC_TLV_OK);
                  munit_assert_int(indexed_status, ==,
                                   revoked && (!period || reasons[i] != 8)
                                       ? TC_X509_CRL_REVOKED
                                       : TC_X509_CRL_UNREVOKED);
                  indexed_evidence = empty;
                  trusted = unchanged;
                  work = required - 1;
                  munit_assert_int(tc_cms_crl_index_process(
                                       &candidate_reader, &crl_index, 0,
                                       policies[policy], &query, &source, 1,
                                       &indexed_options, &tree, &validation,
                                       &search, &indexed_evidence, &trusted),
                                   ==, TC_TLV_LIMIT);
                  munit_assert_memory_equal(sizeof indexed_evidence,
                                            &indexed_evidence, &empty);
                  munit_assert_memory_equal(sizeof trusted, &trusted,
                                            &unchanged);
                  work = required;
                  munit_assert_int(tc_cms_crl_index_process(
                                       &candidate_reader, &crl_index, 0,
                                       policies[policy], &query, &source, 1,
                                       &indexed_options, &tree, &validation,
                                       &search, &indexed_evidence, &trusted),
                                   ==, TC_TLV_OK);
                  munit_assert_size(work, ==, 0);
                } else {
                  munit_assert_memory_equal(sizeof indexed_evidence,
                                            &indexed_evidence, &empty);
                  munit_assert_memory_equal(sizeof trusted, &trusted,
                                            &unchanged);
                }
                uint8_t scope_states[2];
                indexed_evidence = empty;
                trusted = unchanged;
                probe.calls = 0;
                work = TRUST_WORK_BUDGET;
                munit_assert_int(tc_cms_crl_scope_process(
                                     &candidate_reader, &crl_index, 0,
                                     policies[policy], TC_X509_CRL_ORDER_NUMBER,
                                     &query, &source, 1, &indexed_options,
                                     &tree, &validation, &search, scope_states,
                                     sizeof scope_states, &indexed_evidence,
                                     &trusted),
                                 ==, expected);
                munit_assert_memory_equal(sizeof candidate_reader,
                                          &candidate_reader, &before_search);
                munit_assert_size(probe.calls, ==,
                                  period && policies[policy] !=
                                                TC_X509_CRL_COMPLETE_ONLY
                                      ? 3
                                      : 2);
                if (expected == TC_TLV_OK) {
                  tc_x509_crl_status scope_status;
                  munit_assert_size(trusted.validation.work_used, ==,
                                    TRUST_WORK_BUDGET - work);
                  munit_assert_int(tc_x509_crl_evidence_status(
                                       &indexed_evidence, &scope_status),
                                   ==, TC_TLV_OK);
                  munit_assert_int(scope_status, ==,
                                   revoked && (!period || reasons[i] != 8)
                                       ? TC_X509_CRL_REVOKED
                                       : TC_X509_CRL_UNREVOKED);
                } else {
                  munit_assert_memory_equal(sizeof indexed_evidence,
                                            &indexed_evidence, &empty);
                  munit_assert_memory_equal(sizeof trusted, &trusted,
                                            &unchanged);
                }
              }
            }
            {
              uint8_t current_base_der[sizeof encoded];
              X509_CRL *current_base = X509_CRL_dup(crl);
              munit_assert_not_null(current_base);
              munit_assert_int(
                  X509_CRL_set1_nextUpdate(current_base,
                                           X509_CRL_get0_nextUpdate(delta_crl)),
                  ==, 1);
              munit_assert_int(
                  X509_CRL_sign(current_base, generated, EVP_sha256()), >, 0);
              const int length = i2d_X509_CRL(current_base, NULL);
              munit_assert_int(length, >, 0);
              munit_assert_size((size_t)length, <=, sizeof current_base_der);
              unsigned char *destination = current_base_der;
              munit_assert_int(i2d_X509_CRL(current_base, &destination), ==,
                               length);
              const TC_bytes overlap_records[] = {
                  {current_base_der, (size_t)length}, delta.encoded};
              candidate_source overlap_source = {overlap_records, 2, 0,
                                                 TC_TLV_OK, 0};
              const tc_pki_record_source overlap_input = {&overlap_source, 2,
                                                          read_candidate};
              TC_X509_crl_record overlap_rows[2];
              TC_X509_crl_index overlap_index;
              work = TRUST_WORK_BUDGET;
              munit_assert_int(
                  tc_cms_revocations_init((TC_bytes){NULL, 0}, &overlap_input,
                                          2, 2 * sizeof encoded, &limits, &tree,
                                          &revocations),
                  ==, TC_TLV_OK);
              munit_assert_int(tc_cms_crl_index_init(&revocations, &tree, oids,
                                                     EXTENSION_CAPACITY,
                                                     overlap_rows, 2,
                                                     &overlap_index),
                               ==, TC_TLV_OK);
              tc_x509_crl_freshness freshness;
              for (size_t record = 0; record < overlap_index.count; ++record) {
                munit_assert_int(tc_x509_crl_fresh_at(&overlap_rows[record].crl,
                                                      &updated.at, &freshness),
                                 ==, TC_TLV_OK);
                munit_assert_int(freshness, ==, TC_X509_CRL_CURRENT);
              }
              for (size_t policy = 0;
                   policy < sizeof policies / sizeof policies[0]; ++policy) {
                tc_x509_crl_evidence overlap_evidence = {0};
                const int required_missing =
                    wrong_key && policies[policy] == TC_X509_CRL_DELTA_REQUIRED;
                const int use_delta =
                    !wrong_key && policies[policy] != TC_X509_CRL_COMPLETE_ONLY;
                work = TRUST_WORK_BUDGET;
                trusted = unchanged;
                probe.calls = 0;
                munit_assert_int(tc_cms_crl_index_process(
                                     &candidate_reader, &overlap_index, 0,
                                     policies[policy], &query, &source, 1,
                                     &updated, &tree, &validation, &search,
                                     &overlap_evidence, &trusted),
                                 ==, required_missing ? TC_TLV_END : TC_TLV_OK);
                munit_assert_size(
                    probe.calls, ==,
                    policies[policy] == TC_X509_CRL_COMPLETE_ONLY ? 2 : 3);
                if (required_missing) {
                  munit_assert_memory_equal(sizeof overlap_evidence,
                                            &overlap_evidence, &empty);
                  munit_assert_memory_equal(sizeof trusted, &trusted,
                                            &unchanged);
                } else {
                  tc_x509_crl_status overlap_status;
                  munit_assert_int(tc_x509_crl_evidence_status(
                                       &overlap_evidence, &overlap_status),
                                   ==, TC_TLV_OK);
                  munit_assert_int(overlap_status, ==,
                                   revoked && (!use_delta || reasons[i] != 8)
                                       ? TC_X509_CRL_REVOKED
                                       : TC_X509_CRL_UNREVOKED);
                }
              }
              if (!wrong_key && i == 0) {
                enum { NEWER_NUMBER = 3, RECORDS = 4 };
                uint8_t newer_der[sizeof encoded],
                    conflicting_der[sizeof encoded], states[RECORDS];
                TC_X509_crl_record rows[RECORDS];
                TC_X509_crl_index index;
                tc_x509_crl_signature_cache cache;
                TC_X509_time selection_at = updated.at;
                munit_assert_uint(selection_at.second, ==, 0);
                ++selection_at.second;
                ASN1_TIME *newer_update = ASN1_TIME_new();
                munit_assert_not_null(newer_update);
                munit_assert_int(
                    ASN1_TIME_set_string(newer_update, "270101000001Z"), ==, 1);
                munit_assert_int(
                    X509_CRL_set1_lastUpdate(current_base, newer_update), ==,
                    1);
                /* Two signed deltas disagree at number 2; complete number 3
                 * supersedes both. */
                X509_CRL *conflicting = X509_CRL_dup(delta_crl);
                munit_assert_not_null(conflicting);
                munit_assert_int(
                    X509_CRL_set1_lastUpdate(conflicting, newer_update), ==, 1);
                munit_assert_int(
                    X509_CRL_sign(conflicting, generated, EVP_sha256()), >, 0);
                const int conflicting_size = i2d_X509_CRL(conflicting, NULL);
                munit_assert_int(conflicting_size, >, 0);
                munit_assert_size((size_t)conflicting_size, <=,
                                  sizeof conflicting_der);
                unsigned char *conflicting_next = conflicting_der;
                munit_assert_int(i2d_X509_CRL(conflicting, &conflicting_next),
                                 ==, conflicting_size);
                X509_CRL_free(conflicting);
                ASN1_TIME_free(newer_update);
                ASN1_INTEGER *number = ASN1_INTEGER_new();
                munit_assert_not_null(number);
                munit_assert_int(ASN1_INTEGER_set(number, NEWER_NUMBER), ==, 1);
                munit_assert_int(X509_CRL_add1_ext_i2d(current_base,
                                                       NID_crl_number, number,
                                                       0, X509V3_ADD_REPLACE),
                                 ==, 1);
                ASN1_INTEGER_free(number);
                if (revoked) {
                  STACK_OF(X509_REVOKED) *entries =
                      X509_CRL_get_REVOKED(current_base);
                  munit_assert_int(sk_X509_REVOKED_num(entries), ==, 1);
                  ASN1_ENUMERATED *reason = ASN1_ENUMERATED_new();
                  munit_assert_not_null(reason);
                  munit_assert_int(ASN1_ENUMERATED_set(reason, 2), ==, 1);
                  munit_assert_int(X509_REVOKED_add1_ext_i2d(
                                       sk_X509_REVOKED_value(entries, 0),
                                       NID_crl_reason, reason, 0,
                                       X509V3_ADD_REPLACE),
                                   ==, 1);
                  ASN1_ENUMERATED_free(reason);
                }
                for (int numbered = 1; numbered >= 0; --numbered) {
                  if (!numbered) {
                    const int extension = X509_CRL_get_ext_by_NID(
                        current_base, NID_crl_number, -1);
                    munit_assert_int(extension, >=, 0);
                    X509_EXTENSION_free(
                        X509_CRL_delete_ext(current_base, extension));
                  }
                  munit_assert_int(
                      X509_CRL_sign(current_base, generated, EVP_sha256()), >,
                      0);
                  const int size = i2d_X509_CRL(current_base, NULL);
                  munit_assert_int(size, >, 0);
                  munit_assert_size((size_t)size, <=, sizeof newer_der);
                  unsigned char *next = newer_der;
                  munit_assert_int(i2d_X509_CRL(current_base, &next), ==, size);
                  TC_bytes inputs[] = {
                      overlap_records[0],
                      delta.encoded,
                      {conflicting_der, (size_t)conflicting_size},
                      {newer_der, (size_t)size}};
                  candidate_source input_source = {inputs, RECORDS, 0,
                                                   TC_TLV_OK, 0};
                  const tc_pki_record_source input_records = {
                      &input_source, RECORDS, read_candidate};
                  const TC_bytes sentinel = delta.signature;
                  for (unsigned order = 0; order < 2; ++order) {
                    work = TRUST_WORK_BUDGET;
                    probe.calls = 0;
                    munit_assert_int(tc_cms_revocations_init(
                                         (TC_bytes){NULL, 0}, &input_records,
                                         RECORDS, RECORDS * sizeof encoded,
                                         &limits, &tree, &revocations),
                                     ==, TC_TLV_OK);
                    munit_assert_int(
                        tc_cms_crl_index_init(&revocations, &tree, oids,
                                              EXTENSION_CAPACITY, rows, RECORDS,
                                              &index),
                        ==, TC_TLV_OK);
                    munit_assert_int(tc_x509_crl_signature_cache_init(
                                         &index, &signer, &updated.signatures,
                                         &limits, &names, states, RECORDS,
                                         &work, &cache),
                                     ==, TC_TLV_OK);
                    TC_bytes latest = sentinel;
                    munit_assert_int(
                        tc_x509_crl_latest_number(
                            &cache, 0, TC_X509_CRL_DELTA_IF_AVAILABLE,
                            &selection_at, &tree, &latest),
                        ==, numbered ? TC_TLV_OK : TC_TLV_UNSUPPORTED);
                    if (numbered) {
                      munit_assert_size(latest.length, ==, 1);
                      munit_assert_uint(latest.data[0], ==, NEWER_NUMBER);
                      munit_assert_size(probe.calls, ==, RECORDS);
                      work = TRUST_WORK_BUDGET;
                      munit_assert_int(tc_x509_crl_latest_number(
                                           &cache, 0,
                                           TC_X509_CRL_DELTA_IF_AVAILABLE,
                                           &selection_at, &tree, &latest),
                                       ==, TC_TLV_OK);
                      const size_t required = TRUST_WORK_BUDGET - work;
                      latest = sentinel;
                      work = required - 1;
                      munit_assert_int(tc_x509_crl_latest_number(
                                           &cache, 0,
                                           TC_X509_CRL_DELTA_IF_AVAILABLE,
                                           &selection_at, &tree, &latest),
                                       ==, TC_TLV_LIMIT);
                      munit_assert_memory_equal(sizeof latest, &latest,
                                                &sentinel);
                      work = required;
                      munit_assert_int(tc_x509_crl_latest_number(
                                           &cache, 0,
                                           TC_X509_CRL_DELTA_IF_AVAILABLE,
                                           &selection_at, &tree, &latest),
                                       ==, TC_TLV_OK);
                      munit_assert_size(work, ==, 0);
                      munit_assert_size(probe.calls, ==, RECORDS);
                      tc_x509_crl_evidence selected_evidence = {0};
                      tc_x509_crl_status selected_status;
                      work = TRUST_WORK_BUDGET;
                      munit_assert_int(
                          tc_x509_crl_scope_apply(
                              &cache, 0, TC_X509_CRL_DELTA_IF_AVAILABLE,
                              TC_X509_CRL_ORDER_NUMBER, &query, &selection_at,
                              &tree, oids, EXTENSION_CAPACITY,
                              &selected_evidence),
                          ==, TC_TLV_OK);
                      munit_assert_int(
                          tc_x509_crl_evidence_status(&selected_evidence,
                                                      &selected_status),
                          ==, TC_TLV_OK);
                      munit_assert_int(selected_status, ==,
                                       revoked ? TC_X509_CRL_REVOKED
                                               : TC_X509_CRL_UNREVOKED);
                      if (revoked)
                        munit_assert_uint(selected_evidence.revocation.reason,
                                          ==, 2);
                      munit_assert_size(probe.calls, ==, RECORDS);
                    } else
                      munit_assert_memory_equal(sizeof latest, &latest,
                                                &sentinel);
                    tc_x509_crl_evidence legacy_evidence = {0};
                    tc_x509_crl_status legacy_status;
                    work = TRUST_WORK_BUDGET;
                    munit_assert_int(tc_x509_crl_scope_apply(
                                         &cache, 0, TC_X509_CRL_COMPLETE_ONLY,
                                         TC_X509_CRL_ORDER_THIS_UPDATE, &query,
                                         &selection_at, &tree, oids,
                                         EXTENSION_CAPACITY, &legacy_evidence),
                                     ==, TC_TLV_OK);
                    munit_assert_int(tc_x509_crl_evidence_status(
                                         &legacy_evidence, &legacy_status),
                                     ==, TC_TLV_OK);
                    munit_assert_int(legacy_status, ==,
                                     revoked ? TC_X509_CRL_REVOKED
                                             : TC_X509_CRL_UNREVOKED);
                    if (revoked)
                      munit_assert_uint(legacy_evidence.revocation.reason, ==,
                                        2);
                    const size_t calls = probe.calls;
                    legacy_evidence = empty;
                    work = TRUST_WORK_BUDGET;
                    munit_assert_int(tc_x509_crl_scope_apply(
                                         &cache, 0, TC_X509_CRL_COMPLETE_ONLY,
                                         TC_X509_CRL_ORDER_THIS_UPDATE, &query,
                                         &selection_at, &tree, oids,
                                         EXTENSION_CAPACITY, &legacy_evidence),
                                     ==, TC_TLV_OK);
                    const size_t legacy_work = TRUST_WORK_BUDGET - work;
                    legacy_evidence = empty;
                    work = legacy_work - 1;
                    munit_assert_int(tc_x509_crl_scope_apply(
                                         &cache, 0, TC_X509_CRL_COMPLETE_ONLY,
                                         TC_X509_CRL_ORDER_THIS_UPDATE, &query,
                                         &selection_at, &tree, oids,
                                         EXTENSION_CAPACITY, &legacy_evidence),
                                     ==, TC_TLV_LIMIT);
                    munit_assert_memory_equal(sizeof legacy_evidence,
                                              &legacy_evidence, &empty);
                    work = legacy_work;
                    munit_assert_int(tc_x509_crl_scope_apply(
                                         &cache, 0, TC_X509_CRL_COMPLETE_ONLY,
                                         TC_X509_CRL_ORDER_THIS_UPDATE, &query,
                                         &selection_at, &tree, oids,
                                         EXTENSION_CAPACITY, &legacy_evidence),
                                     ==, TC_TLV_OK);
                    munit_assert_size(work, ==, 0);
                    munit_assert_size(probe.calls, ==, calls);
                    legacy_evidence = empty;
                    work = TRUST_WORK_BUDGET;
                    munit_assert_int(tc_x509_crl_scope_apply(
                                         &cache, 0, TC_X509_CRL_COMPLETE_ONLY,
                                         (TC_X509_crl_order_policy)-1, &query,
                                         &selection_at, &tree, oids,
                                         EXTENSION_CAPACITY, &legacy_evidence),
                                     ==, TC_TLV_ARGUMENT);
                    munit_assert_memory_equal(sizeof legacy_evidence,
                                              &legacy_evidence, &empty);
                    munit_assert_size(work, ==, TRUST_WORK_BUDGET);
                    TC_X509_path_options scope_options = updated;
                    scope_options.at = selection_at;
                    const TC_X509_crl_delta_policy scope_delta =
                        numbered ? TC_X509_CRL_DELTA_IF_AVAILABLE
                                 : TC_X509_CRL_COMPLETE_ONLY;
                    const TC_X509_crl_order_policy scope_order =
                        numbered ? TC_X509_CRL_ORDER_NUMBER
                                 : TC_X509_CRL_ORDER_THIS_UPDATE;
                    legacy_evidence = empty;
                    trusted = unchanged;
                    work = TRUST_WORK_BUDGET;
                    probe.calls = 0;
                    munit_assert_int(tc_cms_crl_scope_process(
                                         &candidate_reader, &index, 0,
                                         scope_delta, scope_order, &query,
                                         &source, 1, &scope_options, &tree,
                                         &validation, &search, states, RECORDS,
                                         &legacy_evidence, &trusted),
                                     ==, TC_TLV_OK);
                    const size_t scope_work = TRUST_WORK_BUDGET - work;
                    munit_assert_size(trusted.validation.work_used, ==,
                                      scope_work);
                    munit_assert_size(trusted.anchor_index, ==, 1);
                    munit_assert_size(probe.calls, ==,
                                      numbered ? RECORDS + 1 : 3);
                    munit_assert_int(tc_x509_crl_evidence_status(
                                         &legacy_evidence, &legacy_status),
                                     ==, TC_TLV_OK);
                    munit_assert_int(legacy_status, ==,
                                     revoked ? TC_X509_CRL_REVOKED
                                             : TC_X509_CRL_UNREVOKED);
                    if (revoked)
                      munit_assert_uint(legacy_evidence.revocation.reason, ==,
                                        2);
                    munit_assert_memory_equal(sizeof candidate_reader,
                                              &candidate_reader,
                                              &before_search);
                    legacy_evidence = empty;
                    trusted = unchanged;
                    work = scope_work - 1;
                    munit_assert_int(tc_cms_crl_scope_process(
                                         &candidate_reader, &index, 0,
                                         scope_delta, scope_order, &query,
                                         &source, 1, &scope_options, &tree,
                                         &validation, &search, states, RECORDS,
                                         &legacy_evidence, &trusted),
                                     ==, TC_TLV_LIMIT);
                    munit_assert_memory_equal(sizeof legacy_evidence,
                                              &legacy_evidence, &empty);
                    munit_assert_memory_equal(sizeof trusted, &trusted,
                                              &unchanged);
                    work = scope_work;
                    munit_assert_int(tc_cms_crl_scope_process(
                                         &candidate_reader, &index, 0,
                                         scope_delta, scope_order, &query,
                                         &source, 1, &scope_options, &tree,
                                         &validation, &search, states, RECORDS,
                                         &legacy_evidence, &trusted),
                                     ==, TC_TLV_OK);
                    munit_assert_size(work, ==, 0);
                    legacy_evidence = empty;
                    trusted = unchanged;
                    work = TRUST_WORK_BUDGET;
                    munit_assert_int(
                        tc_cms_crl_scope_process(
                            &candidate_reader, &index, 0, scope_delta,
                            scope_order, &query, &source, 1, &scope_options,
                            &tree, &validation, &search, states, RECORDS - 1,
                            &legacy_evidence, &trusted),
                        ==, TC_TLV_LIMIT);
                    munit_assert_size(work, ==, TRUST_WORK_BUDGET);
                    munit_assert_memory_equal(sizeof legacy_evidence,
                                              &legacy_evidence, &empty);
                    munit_assert_memory_equal(sizeof trusted, &trusted,
                                              &unchanged);
                    munit_assert_int(tc_cms_crl_scope_process(
                                         &candidate_reader, &index, 0,
                                         scope_delta, scope_order, &query,
                                         &source, 0, &scope_options, &tree,
                                         &validation, &search, states, RECORDS,
                                         &legacy_evidence, &trusted),
                                     ==, TC_TLV_INVALID);
                    munit_assert_memory_equal(sizeof legacy_evidence,
                                              &legacy_evidence, &empty);
                    munit_assert_memory_equal(sizeof trusted, &trusted,
                                              &unchanged);
                    if (numbered) {
                      work = TRUST_WORK_BUDGET;
                      probe.calls = 0;
                      munit_assert_int(tc_cms_crl_scope_process(
                                           &candidate_reader, &index, 1,
                                           scope_delta, scope_order, &query,
                                           &source, 1, &scope_options, &tree,
                                           &validation, &search, states,
                                           RECORDS, &legacy_evidence, &trusted),
                                       ==, TC_TLV_OK);
                      munit_assert_size(probe.calls, ==, RECORDS + 1);
                      munit_assert_int(tc_x509_crl_evidence_status(
                                           &legacy_evidence, &legacy_status),
                                       ==, TC_TLV_OK);
                      munit_assert_int(legacy_status, ==,
                                       revoked ? TC_X509_CRL_REVOKED
                                               : TC_X509_CRL_UNREVOKED);
                      if (revoked)
                        munit_assert_uint(legacy_evidence.revocation.reason, ==,
                                          2);
                      const tc_x509_crl_evidence completed = legacy_evidence;
                      trusted = unchanged;
                      work = TRUST_WORK_BUDGET;
                      probe.calls = 0;
                      munit_assert_int(tc_cms_crl_scope_process(
                                           &candidate_reader, &index, 1,
                                           scope_delta, scope_order, &query,
                                           &source, 1, &scope_options, &tree,
                                           &validation, &search, states,
                                           RECORDS, &legacy_evidence, &trusted),
                                       ==, TC_TLV_END);
                      munit_assert_memory_equal(sizeof legacy_evidence,
                                                &legacy_evidence, &completed);
                      munit_assert_memory_equal(sizeof trusted, &trusted,
                                                &unchanged);
                      munit_assert_size(work, ==, TRUST_WORK_BUDGET);
                      munit_assert_size(probe.calls, ==, 0);
                    }
                    TC_bytes swap = inputs[0];
                    inputs[0] = inputs[RECORDS - 1];
                    inputs[RECORDS - 1] = swap;
                  }
                }
                TC_bytes conflicting_inputs[] = {
                    overlap_records[0],
                    delta.encoded,
                    {conflicting_der, (size_t)conflicting_size}};
                enum { CONFLICT_RECORDS = 3 };
                candidate_source conflict_source = {
                    conflicting_inputs, CONFLICT_RECORDS, 0, TC_TLV_OK, 0};
                const tc_pki_record_source conflict_records = {
                    &conflict_source, CONFLICT_RECORDS, read_candidate};
                for (unsigned order = 0; order < 2; ++order) {
                  work = TRUST_WORK_BUDGET;
                  probe.calls = 0;
                  munit_assert_int(tc_cms_revocations_init(
                                       (TC_bytes){NULL, 0}, &conflict_records,
                                       CONFLICT_RECORDS,
                                       CONFLICT_RECORDS * sizeof encoded,
                                       &limits, &tree, &revocations),
                                   ==, TC_TLV_OK);
                  munit_assert_int(tc_cms_crl_index_init(&revocations, &tree,
                                                         oids,
                                                         EXTENSION_CAPACITY,
                                                         rows, RECORDS, &index),
                                   ==, TC_TLV_OK);
                  munit_assert_int(tc_x509_crl_signature_cache_init(
                                       &index, &signer, &updated.signatures,
                                       &limits, &names, states, RECORDS, &work,
                                       &cache),
                                   ==, TC_TLV_OK);
                  TC_bytes latest = delta.signature;
                  munit_assert_int(
                      tc_x509_crl_latest_number(&cache, 0,
                                                TC_X509_CRL_DELTA_IF_AVAILABLE,
                                                &selection_at, &tree, &latest),
                      ==, TC_TLV_INVALID);
                  munit_assert_memory_equal(sizeof latest, &latest,
                                            &delta.signature);
                  tc_x509_crl_evidence rejected = {0};
                  work = TRUST_WORK_BUDGET;
                  munit_assert_int(
                      tc_x509_crl_scope_apply(
                          &cache, 0, TC_X509_CRL_DELTA_IF_AVAILABLE,
                          TC_X509_CRL_ORDER_NUMBER, &query, &selection_at,
                          &tree, oids, EXTENSION_CAPACITY, &rejected),
                      ==, TC_TLV_INVALID);
                  munit_assert_memory_equal(sizeof rejected, &rejected, &empty);
                  munit_assert_size(probe.calls, ==, CONFLICT_RECORDS);
                  TC_bytes swap = conflicting_inputs[0];
                  conflicting_inputs[0] =
                      conflicting_inputs[CONFLICT_RECORDS - 1];
                  conflicting_inputs[CONFLICT_RECORDS - 1] = swap;
                }
              }
              if (!wrong_key && i == 0) {
                enum { TIED_RECORDS = 3 };
                enum { CONSISTENT, DIFFERENT_REASON, DIFFERENT_UPDATE };
                TC_X509_time tie_at = updated.at;
                ++tie_at.second;
                for (unsigned fault = CONSISTENT; fault <= DIFFERENT_UPDATE;
                     ++fault) {
                  if (!revoked && fault == DIFFERENT_REASON)
                    continue;
                  X509_CRL *tied = X509_CRL_dup(delta_crl);
                  munit_assert_not_null(tied);
                  const int extension =
                      X509_CRL_get_ext_by_NID(tied, NID_delta_crl, -1);
                  munit_assert_int(extension, >=, 0);
                  X509_EXTENSION_free(X509_CRL_delete_ext(tied, extension));
                  if (fault == DIFFERENT_REASON) {
                    ASN1_ENUMERATED *reason = ASN1_ENUMERATED_new();
                    munit_assert_not_null(reason);
                    munit_assert_int(ASN1_ENUMERATED_set(reason, 2), ==, 1);
                    X509_REVOKED *entry =
                        sk_X509_REVOKED_value(X509_CRL_get_REVOKED(tied), 0);
                    munit_assert_not_null(entry);
                    munit_assert_int(
                        X509_REVOKED_add1_ext_i2d(entry, NID_crl_reason, reason,
                                                  0, X509V3_ADD_REPLACE),
                        ==, 1);
                    ASN1_ENUMERATED_free(reason);
                  } else if (fault == DIFFERENT_UPDATE) {
                    ASN1_TIME *changed = ASN1_TIME_new();
                    munit_assert_not_null(changed);
                    munit_assert_int(
                        ASN1_TIME_set_string(changed, "270101000001Z"), ==, 1);
                    munit_assert_int(X509_CRL_set1_lastUpdate(tied, changed),
                                     ==, 1);
                    ASN1_TIME_free(changed);
                  }
                  uint8_t tied_der[sizeof encoded], states[TIED_RECORDS];
                  munit_assert_int(X509_CRL_sign(tied, generated, EVP_sha256()),
                                   >, 0);
                  const int size = i2d_X509_CRL(tied, NULL);
                  munit_assert_int(size, >, 0);
                  munit_assert_size((size_t)size, <=, sizeof tied_der);
                  unsigned char *next = tied_der;
                  munit_assert_int(i2d_X509_CRL(tied, &next), ==, size);
                  X509_CRL_free(tied);
                  TC_bytes inputs[] = {overlap_records[0],
                                       delta.encoded,
                                       {tied_der, (size_t)size}};
                  candidate_source input_source = {inputs, TIED_RECORDS, 0,
                                                   TC_TLV_OK, 0};
                  const tc_pki_record_source input_records = {
                      &input_source, TIED_RECORDS, read_candidate};
                  TC_X509_crl_record rows[TIED_RECORDS];
                  TC_X509_crl_index index;
                  tc_x509_crl_signature_cache cache;
                  for (unsigned order = 0; order < 2; ++order) {
                    work = TRUST_WORK_BUDGET;
                    probe.calls = 0;
                    munit_assert_int(
                        tc_cms_revocations_init((TC_bytes){NULL, 0},
                                                &input_records, TIED_RECORDS,
                                                TIED_RECORDS * sizeof encoded,
                                                &limits, &tree, &revocations),
                        ==, TC_TLV_OK);
                    munit_assert_int(
                        tc_cms_crl_index_init(&revocations, &tree, oids,
                                              EXTENSION_CAPACITY, rows,
                                              TIED_RECORDS, &index),
                        ==, TC_TLV_OK);
                    munit_assert_int(tc_x509_crl_signature_cache_init(
                                         &index, &signer, &updated.signatures,
                                         &limits, &names, states, TIED_RECORDS,
                                         &work, &cache),
                                     ==, TC_TLV_OK);
                    tc_x509_crl_evidence scope_evidence = {0};
                    munit_assert_int(
                        tc_x509_crl_scope_apply(
                            &cache, 0, TC_X509_CRL_DELTA_IF_AVAILABLE,
                            TC_X509_CRL_ORDER_NUMBER, &query, &tie_at, &tree,
                            oids, EXTENSION_CAPACITY, &scope_evidence),
                        ==, fault == CONSISTENT ? TC_TLV_OK : TC_TLV_INVALID);
                    munit_assert_size(probe.calls, ==, TIED_RECORDS);
                    if (fault == CONSISTENT) {
                      tc_x509_crl_status scope_status;
                      munit_assert_int(tc_x509_crl_evidence_status(
                                           &scope_evidence, &scope_status),
                                       ==, TC_TLV_OK);
                      munit_assert_int(scope_status, ==,
                                       revoked ? TC_X509_CRL_REVOKED
                                               : TC_X509_CRL_UNREVOKED);
                      scope_evidence = empty;
                      work = TRUST_WORK_BUDGET;
                      munit_assert_int(
                          tc_x509_crl_scope_apply(
                              &cache, 0, TC_X509_CRL_DELTA_IF_AVAILABLE,
                              TC_X509_CRL_ORDER_NUMBER, &query, &tie_at, &tree,
                              oids, EXTENSION_CAPACITY, &scope_evidence),
                          ==, TC_TLV_OK);
                      const size_t required = TRUST_WORK_BUDGET - work;
                      scope_evidence = empty;
                      work = required - 1;
                      munit_assert_int(
                          tc_x509_crl_scope_apply(
                              &cache, 0, TC_X509_CRL_DELTA_IF_AVAILABLE,
                              TC_X509_CRL_ORDER_NUMBER, &query, &tie_at, &tree,
                              oids, EXTENSION_CAPACITY, &scope_evidence),
                          ==, TC_TLV_LIMIT);
                      munit_assert_memory_equal(sizeof scope_evidence,
                                                &scope_evidence, &empty);
                      work = required;
                      munit_assert_int(
                          tc_x509_crl_scope_apply(
                              &cache, 0, TC_X509_CRL_DELTA_IF_AVAILABLE,
                              TC_X509_CRL_ORDER_NUMBER, &query, &tie_at, &tree,
                              oids, EXTENSION_CAPACITY, &scope_evidence),
                          ==, TC_TLV_OK);
                      munit_assert_size(work, ==, 0);
                      munit_assert_size(probe.calls, ==, TIED_RECORDS);
                    } else
                      munit_assert_memory_equal(sizeof scope_evidence,
                                                &scope_evidence, &empty);
                    scope_evidence = empty;
                    work = TRUST_WORK_BUDGET;
                    munit_assert_int(
                        tc_x509_crl_scope_apply(
                            &cache, 0, TC_X509_CRL_DELTA_IF_AVAILABLE,
                            TC_X509_CRL_ORDER_THIS_UPDATE, &query, &tie_at,
                            &tree, oids, EXTENSION_CAPACITY, &scope_evidence),
                        ==,
                        fault == DIFFERENT_REASON ? TC_TLV_INVALID : TC_TLV_OK);
                    if (fault == DIFFERENT_REASON)
                      munit_assert_memory_equal(sizeof scope_evidence,
                                                &scope_evidence, &empty);
                    else {
                      tc_x509_crl_status scope_status;
                      munit_assert_int(tc_x509_crl_evidence_status(
                                           &scope_evidence, &scope_status),
                                       ==, TC_TLV_OK);
                      munit_assert_int(scope_status, ==,
                                       revoked ? TC_X509_CRL_REVOKED
                                               : TC_X509_CRL_UNREVOKED);
                    }
                    munit_assert_size(probe.calls, ==, TIED_RECORDS);
                    TC_bytes swap = inputs[0];
                    inputs[0] = inputs[2];
                    inputs[2] = swap;
                  }
                }
              }
              X509_CRL_free(current_base);
            }
            trusted = unchanged;
            probe.calls = 0;
            work = TRUST_WORK_BUDGET;
            munit_assert_int(tc_cms_crl_process(&candidate_reader,
                                                &indexed_pair, &query, &source,
                                                1, &updated, &tree, &validation,
                                                &search, &evidence, &trusted),
                             ==, wrong_key ? TC_TLV_INVALID : TC_TLV_OK);
            munit_assert_memory_equal(sizeof candidate_reader,
                                      &candidate_reader, &before_search);
            if (wrong_key) {
              munit_assert_memory_equal(sizeof trusted, &trusted, &unchanged);
              munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
            } else {
              tc_x509_crl_status status;
              munit_assert_size(probe.calls, ==, 3);
              munit_assert_size(trusted.validation.work_used, ==,
                                TRUST_WORK_BUDGET - work);
              munit_assert_int(tc_x509_crl_evidence_status(&evidence, &status),
                               ==, TC_TLV_OK);
              munit_assert_int(status, ==,
                               revoked && reasons[i] != 8
                                   ? TC_X509_CRL_REVOKED
                                   : TC_X509_CRL_UNREVOKED);
              /* The complete CRL is stale; the current delta supplies its
               * update interval. */
              tc_x509_crl_freshness freshness;
              munit_assert_int(
                  tc_x509_crl_fresh_at(&parsed, &updated.at, &freshness), ==,
                  TC_TLV_OK);
              munit_assert_int(freshness, ==, TC_X509_CRL_STALE);
              for (unsigned boundary = 0; boundary < 2; ++boundary) {
                updated.at = boundary ? delta.next_update : parsed.this_update;
                work = TRUST_WORK_BUDGET;
                evidence = empty;
                trusted = unchanged;
                munit_assert_int(
                    tc_x509_crl_process(&selected, &signer, &query, &source, 1,
                                        &updated, &validation, &search, &work,
                                        &evidence, &trusted),
                    ==, TC_TLV_END);
                munit_assert_memory_equal(sizeof trusted, &trusted, &unchanged);
                munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
              }
              munit_assert_size(probe.calls, ==, 3);
            }
          }
          work = WORK_BUDGET;
          match = saved;
          munit_assert_int(tc_x509_crl_selected_find(
                               &selected, &signer, &target, &provider, &limits,
                               &tree, &names, oids, EXTENSION_CAPACITY, &match),
                           ==, wrong_key ? TC_TLV_INVALID : TC_TLV_OK);
          if (wrong_key)
            munit_assert_memory_equal(sizeof match, &match, &saved);
          else {
            munit_assert_int(match.found, ==, revoked && reasons[i] != 8);
            munit_assert_uint(match.reason, ==, match.found ? reasons[i] : 0);
            const size_t required = WORK_BUDGET - work;
            const size_t short_budgets[] = {0, required / 2, required - 1};
            for (size_t j = 0;
                 j < sizeof short_budgets / sizeof short_budgets[0]; ++j) {
              work = short_budgets[j];
              match = saved;
              munit_assert_int(
                  tc_x509_crl_selected_find(&selected, &signer, &target,
                                            &provider, &limits, &tree, &names,
                                            oids, EXTENSION_CAPACITY, &match),
                  ==, TC_TLV_LIMIT);
              munit_assert_memory_equal(sizeof match, &match, &saved);
            }
            work = required;
            munit_assert_int(
                tc_x509_crl_selected_find(&selected, &signer, &target,
                                          &provider, &limits, &tree, &names,
                                          oids, EXTENSION_CAPACITY, &match),
                ==, TC_TLV_OK);
            munit_assert_size(work, ==, 0);
            delta_info.number = crl_info.number;
            work = WORK_BUDGET;
            match = saved;
            munit_assert_int(
                tc_x509_crl_selected_find(&selected, &signer, &target,
                                          &provider, &limits, &tree, &names,
                                          oids, EXTENSION_CAPACITY, &match),
                ==, TC_TLV_INVALID);
            munit_assert_memory_equal(sizeof match, &match, &saved);
          }
          selected.delta_info = NULL;
          work = WORK_BUDGET;
          match = saved;
          munit_assert_int(tc_x509_crl_selected_find(
                               &selected, &signer, &target, &provider, &limits,
                               &tree, &names, oids, EXTENSION_CAPACITY, &match),
                           ==, TC_TLV_ARGUMENT);
          munit_assert_memory_equal(sizeof match, &match, &saved);
        }
        X509_CRL_free(delta_crl);
      }
    }
    work = WORK_BUDGET;
    munit_assert_int(
        tc_x509_crl_entries_init(parsed.revoked, &limits, &tree, &entries), ==,
        TC_TLV_OK);
    if (revoked) {
      munit_assert_int(
          tc_x509_crl_entry_next(&entries, parsed.version, &tree, &entry), ==,
          TC_TLV_OK);
      munit_assert_size(entry.serial.length, ==, 1);
      munit_assert_uint(entry.serial.data[0], ==, 9);
    }
    munit_assert_int(
        tc_x509_crl_entry_next(&entries, parsed.version, &tree, &entry), ==,
        TC_TLV_END);
    munit_assert_int(TC_X509_signature_verify_message(
                         &parsed.tbs, 1, &parsed.signature_algorithm,
                         parsed.signature, &key, &provider, &work),
                     ==, TC_X509_SIGNATURE_VALID);
    work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_signer_check(&parsed, &signer, &provider,
                                              &limits, &names, &work),
                     ==, TC_X509_SIGNATURE_VALID);
    work = 0;
    munit_assert_int(tc_x509_crl_signer_check(&parsed, &signer, &provider,
                                              &limits, &names, &work),
                     ==, TC_X509_SIGNATURE_LIMIT);
    work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_signer_check(&parsed, &signer, NULL, &limits,
                                              &names, &work),
                     ==, TC_X509_SIGNATURE_UNSUPPORTED);
    {
      /* A matching name alone does not authorize CRL signing. */
      static const uint8_t digital_signature_only[] = {
          0x30, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d,
          0x0f, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80};
      static const uint8_t crl_sign_only[] = {0x30, 0x0d, 0x30, 0x0b, 0x06,
                                              0x03, 0x55, 0x1d, 0x0f, 0x04,
                                              0x04, 0x03, 0x02, 0x01, 0x02};
      TC_X509_certificate denied = signer;
      int authorized;
      denied.subject = (TC_bytes){(const uint8_t *)"\x30\x00", 2};
      munit_assert_int(tc_x509_crl_signer_check(&parsed, &denied, &provider,
                                                &limits, &names, &work),
                       ==, TC_X509_SIGNATURE_INVALID);
      denied = signer;
      denied.extensions =
          (TC_bytes){digital_signature_only, sizeof digital_signature_only};
      work = WORK_BUDGET;
      munit_assert_int(
          tc_x509_crl_signer_usage(&denied, &limits, &work, &authorized), ==,
          TC_TLV_OK);
      munit_assert_false(authorized);
      munit_assert_int(tc_x509_crl_signer_check(&parsed, &denied, &provider,
                                                &limits, &names, &work),
                       ==, TC_X509_SIGNATURE_INVALID);
      denied.extensions = (TC_bytes){crl_sign_only, sizeof crl_sign_only};
      work = WORK_BUDGET;
      munit_assert_int(tc_x509_crl_signer_check(&parsed, &denied, &provider,
                                                &limits, &names, &work),
                       ==, TC_X509_SIGNATURE_VALID);
    }
    if (revoked) {
      /* An unsupported entry is examined only after the signer path passes. */
      uint8_t entry_der[ENCODED_CAPACITY];
      X509_CRL *entry_crl = X509_CRL_dup(crl);
      ASN1_OBJECT *oid = OBJ_txt2obj("1.2.3.4", 1);
      ASN1_OCTET_STRING *value = ASN1_OCTET_STRING_new();
      static const uint8_t null_value[] = {0x05, 0x00};
      munit_assert_not_null(entry_crl);
      munit_assert_not_null(oid);
      munit_assert_not_null(value);
      munit_assert_int(
          ASN1_OCTET_STRING_set(value, null_value, sizeof null_value), ==, 1);
      X509_EXTENSION *extension =
          X509_EXTENSION_create_by_OBJ(NULL, oid, 1, value);
      munit_assert_not_null(extension);
      X509_REVOKED *item =
          sk_X509_REVOKED_value(X509_CRL_get_REVOKED(entry_crl), 0);
      munit_assert_int(X509_REVOKED_add_ext(item, extension, -1), ==, 1);
      X509_EXTENSION_free(extension);
      ASN1_OCTET_STRING_free(value);
      ASN1_OBJECT_free(oid);
      munit_assert_int(X509_CRL_sign(entry_crl, generated, EVP_sha256()), >, 0);
      int entry_length = i2d_X509_CRL(entry_crl, NULL);
      munit_assert_int(entry_length, >, 0);
      munit_assert_size((size_t)entry_length, <=, sizeof entry_der);
      cursor = entry_der;
      munit_assert_int(i2d_X509_CRL(entry_crl, &cursor), ==, entry_length);
      tc_x509_crl entry_view;
      tc_x509_crl_extension_info entry_info;
      TC_X509_certificate expired;
      work = TRUST_WORK_BUDGET;
      munit_assert_int(
          tc_x509_crl_read((TC_bytes){entry_der, (size_t)entry_length}, &limits,
                           &tree, &entry_view),
          ==, TC_TLV_OK);
      munit_assert_int(tc_x509_crl_extension_info_read(
                           entry_view.extensions, &limits, &tree, oids,
                           EXTENSION_CAPACITY, &entry_info),
                       ==, TC_TLV_OK);
      munit_assert_int(
          TC_X509_read(expired_der, expired_length, &limits, &parser, &expired),
          ==, TC_TLV_OK);
      const uint8_t serial = 9;
      TC_X509_certificate target = {0};
      target.serial = (TC_bytes){&serial, 1};
      target.issuer = entry_view.issuer;
      const tc_x509_crl_selected selected = {&entry_view, &entry_info, NULL,
                                             NULL};
      const tc_pki_distribution_point point = {0};
      const tc_x509_crl_query query = {&target, &point, 0};
      tc_x509_crl_evidence initial = {0}, evidence;
      initial.reasons = 1u << 1;
      TC_X509_search_result found, saved;
      memset(&saved, 0xa5, sizeof saved);
      enum { WRONG_ANCHOR, TRUSTED, EXPIRED, CASE_COUNT };
      for (unsigned scenario = 0; scenario < CASE_COUNT; ++scenario) {
        TC_X509_path_options checked = options;
        signature_retry_probe probe = {provider, 0, 0, TC_X509_SIGNATURE_ERROR};
        checked.signatures =
            (TC_X509_signature_provider){retry_signature, &probe, NULL};
        evidence = initial;
        found = saved;
        work = TRUST_WORK_BUDGET;
        munit_assert_int(
            tc_x509_crl_process(
                &selected, scenario == EXPIRED ? &expired : &signer, &query,
                &source, scenario == WRONG_ANCHOR ? 0 : 1, &checked,
                &validation, &search, &work, &evidence, &found),
            ==, scenario == TRUSTED ? TC_TLV_UNSUPPORTED : TC_TLV_INVALID);
        munit_assert_size(probe.calls, ==, scenario == EXPIRED ? 1 : 2);
        munit_assert_memory_equal(sizeof evidence, &evidence, &initial);
        munit_assert_memory_equal(sizeof found, &found, &saved);
      }
      X509_CRL_free(entry_crl);
    }
    encoded[(size_t)(parsed.signature.data - encoded) +
            parsed.signature.length - 1] ^= 1;
    work = WORK_BUDGET;
    munit_assert_int(TC_X509_signature_verify_message(
                         &parsed.tbs, 1, &parsed.signature_algorithm,
                         parsed.signature, &key, &provider, &work),
                     ==, TC_X509_SIGNATURE_INVALID);
    work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_signer_check(&parsed, &signer, &provider,
                                              &limits, &names, &work),
                     ==, TC_X509_SIGNATURE_INVALID);
    CMS_ContentInfo_free(cms);
    BIO_free(content);
    X509_CRL_free(crl);
  }
  ASN1_TIME_free(date);
  ASN1_TIME_free(next_date);
  X509_free(certificate);
  EVP_PKEY_free(generated);
  EVP_PKEY_free(other_key);
  return MUNIT_OK;
}

static MunitResult embedded_path(const MunitParameter params[], void *user) {
  enum {
    CERT_CAPACITY = 1024,
    CMS_CAPACITY = 4096,
    FRAME_CAPACITY = 16,
    POLICY_CAPACITY = 16,
    NAME_SCALARS = 128,
    PATH_CAPACITY = 3,
    INDEX_CAPACITY = 2,
    RSA_BITS = 2048,
    SIGNATURE_CAPACITY = RSA_BITS / 8,
    WORK_BUDGET = 1000000
  };
  uint8_t root_der[CERT_CAPACITY], intermediate_der[CERT_CAPACITY],
      leaf_der[CERT_CAPACITY];
  uint8_t encoded[CMS_CAPACITY], name_flags[POLICY_CAPACITY];
  uint32_t left[NAME_SCALARS], right[NAME_SCALARS];
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_bytes oids[POLICY_CAPACITY], policies[POLICY_CAPACITY],
      path[PATH_CAPACITY], index[INDEX_CAPACITY];
  TC_X509_policy_node nodes[POLICY_CAPACITY];
  TC_X509_policy_edge edges[POLICY_CAPACITY];
  TC_X509_policy_expected expected[POLICY_CAPACITY];
  TC_X509_policy_mapping mappings[POLICY_CAPACITY];
  TC_X509_search_frame search_frames[PATH_CAPACITY];
  TC_X509_path_workspace validation =
      TC_X509_PATH_WORKSPACE_INIT(frames, oids, left, right, name_flags, nodes,
                                  edges, expected, mappings, policies);
  TC_X509_search_workspace search = {path, search_frames, PATH_CAPACITY};
  TC_X509_workspace parser = {frames, FRAME_CAPACITY, oids, POLICY_CAPACITY};
  const TC_TLV_limits limits = {CMS_CAPACITY, CMS_CAPACITY, 256,
                                FRAME_CAPACITY};
  TC_ECDSA_workspace ec;
  TC_RSA_word rsa_words[TC_RSA_VERIFY_WORKSPACE_WORDS(RSA_BITS)];
  const TC_RSA_workspace rsa = {rsa_words,
                                sizeof rsa_words / sizeof *rsa_words};
  TC_X509_native_workspace native = {&ec, &rsa,
                                     TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  TC_X509_path_options options = {0};
  TC_X509_certificate parsed_root;
  TC_X509_search_result found;
  size_t work = WORK_BUDGET;
  const tc_pki_tree_workspace tree = {frames, FRAME_CAPACITY, &work};
  tc_cms_signed_data container;
  tc_cms_candidates candidates;
  tc_cms_path_source context;
  TC_X509_store_source indexed;
  EVP_PKEY *root_key = EVP_EC_gen("prime256v1");
  EVP_PKEY *intermediate_key = EVP_EC_gen("prime256v1");
  const int rsa_signer = !strcmp(munit_parameters_get(params, "key"), "rsa");
  EVP_PKEY *leaf_key =
      rsa_signer ? EVP_RSA_gen(RSA_BITS) : EVP_EC_gen("prime256v1");
  munit_assert_not_null(root_key);
  munit_assert_not_null(intermediate_key);
  munit_assert_not_null(leaf_key);
  X509 *root = make_certificate(root_key, "Root", NULL);
  X509 *intermediate = make_certificate(intermediate_key, "Intermediate", root);
  X509 *leaf = make_certificate(leaf_key, "Leaf", intermediate);
  add_extension(intermediate, NID_basic_constraints,
                "critical,CA:TRUE,pathlen:0");
  add_extension(intermediate, NID_key_usage, "critical,keyCertSign,cRLSign");
  add_extension(leaf, NID_key_usage, "critical,digitalSignature,cRLSign");
  add_extension(leaf, NID_subject_key_identifier, "hash");
  size_t root_length = encode_certificate(root, root_key, EVP_sha256(),
                                          root_der, sizeof root_der);
  size_t intermediate_length =
      encode_certificate(intermediate, root_key, EVP_sha256(), intermediate_der,
                         sizeof intermediate_der);
  size_t leaf_length = encode_certificate(leaf, intermediate_key, EVP_sha256(),
                                          leaf_der, sizeof leaf_der);
  const char *content_kind = munit_parameters_get(params, "content");
  static const uint8_t message[] = {'p', 'a', 't', 'h'};
  const size_t message_length =
      content_kind && !strncmp(content_kind, "empty-", 6) ? 0 : sizeof message;
  const int detached = content_kind && strstr(content_kind, "detached");
  const TC_bytes detached_input = {detached ? message : NULL,
                                   detached ? message_length : 0};
  BIO *content = BIO_new_mem_buf(message, (int)message_length);
  munit_assert_not_null(content);
  const char *identifier = munit_parameters_get(params, "identifier");
  unsigned cms_flags = CMS_BINARY | CMS_NOSMIMECAP;
  if (identifier && !strcmp(identifier, "key-id"))
    cms_flags |= CMS_USE_KEYID;
  if (detached)
    cms_flags |= CMS_DETACHED;
  CMS_ContentInfo *cms = CMS_sign(leaf, leaf_key, NULL, content, cms_flags);
  munit_assert_not_null(cms);
  munit_assert_int(CMS_add1_cert(cms, intermediate), ==, 1);
  X509_CRL *crl = X509_CRL_new();
  munit_assert_not_null(crl);
  munit_assert_int(X509_CRL_set_version(crl, 1), ==, 1);
  munit_assert_int(X509_CRL_set_issuer_name(crl, X509_get_subject_name(leaf)),
                   ==, 1);
  munit_assert_int(X509_CRL_set1_lastUpdate(crl, X509_get0_notBefore(leaf)), ==,
                   1);
  munit_assert_int(X509_CRL_set1_nextUpdate(crl, X509_get0_notAfter(leaf)), ==,
                   1);
  munit_assert_int(X509_CRL_sign(crl, leaf_key, EVP_sha256()), >, 0);
  munit_assert_int(CMS_add1_crl(cms, crl), ==, 1);
  int length = i2d_CMS_ContentInfo(cms, NULL);
  munit_assert_int(length, >, 0);
  munit_assert_size((size_t)length, <=, sizeof encoded);
  unsigned char *cursor = encoded;
  munit_assert_int(i2d_CMS_ContentInfo(cms, &cursor), ==, length);
  munit_assert_int(
      TC_X509_read(root_der, root_length, &limits, &parser, &parsed_root), ==,
      TC_TLV_OK);
  TC_X509_store_anchor anchor = {{parsed_root.subject, parsed_root.public_key},
                                 {{NULL, 0}, {NULL, 0}}};
  const TC_X509_store_source external = {&anchor, 0, 1, NULL, crl_trust_anchor};
  options.at = (TC_X509_time){2026, 1, 1, 0, 0, 0};
  options.parsing = limits;
  options.max_certificates = PATH_CAPACITY;
  options.max_input = CMS_CAPACITY;
  options.max_work = WORK_BUDGET;
  options.signatures = TC_X509_native_provider(&native);
  const TC_bytes target = {leaf_der, leaf_length};
  munit_assert_int(TC_X509_path_build(target, &external, &options, &validation,
                                      &search, &found),
                   ==, TC_X509_PATH_INVALID);
  munit_assert_int(tc_cms_signed_data_read((TC_bytes){encoded, (size_t)length},
                                           &limits, frames, FRAME_CAPACITY,
                                           &work, &container),
                   ==, TC_TLV_OK);
  munit_assert_int(tc_cms_candidates_init(container.certificates, &external,
                                          INDEX_CAPACITY, CMS_CAPACITY, &limits,
                                          &tree, &candidates),
                   ==, TC_TLV_OK);
  munit_assert_int(tc_cms_path_source_init(&candidates, &tree, index,
                                           INDEX_CAPACITY, &context, &indexed),
                   ==, TC_TLV_OK);
  munit_assert_size(indexed.candidate_count, ==, INDEX_CAPACITY);
  munit_assert_size(indexed.anchor_count, ==, external.anchor_count);
  munit_assert_int(TC_X509_path_build(target, &indexed, &options, &validation,
                                      &search, &found),
                   ==, TC_X509_PATH_VALID);
  munit_assert_size(found.count, ==, 2);
  munit_assert_size(found.anchor_index, ==, 0);
  munit_assert_size(found.path[0].length, ==, intermediate_length);
  munit_assert_memory_equal(intermediate_length, found.path[0].data,
                            intermediate_der);
  munit_assert_true((uintptr_t)found.path[0].data >= (uintptr_t)encoded &&
                    (uintptr_t)found.path[0].data <
                        (uintptr_t)(encoded + sizeof encoded));
  {
    TC_TLV_reader signers;
    TC_CMS_signer_info signer;
    TC_X509_search_result saved;
    uint8_t digest[TC_SHA256_DIGESTLEN];
    const TC_CMS_signature_workspace signature = {frames, FRAME_CAPACITY, NULL,
                                                  0};
    const TC_bytes content_digest = {digest, sizeof digest};
    work = WORK_BUDGET;
    munit_assert_int(TC_CMS_signers_init(container.signers, &limits, frames,
                                         FRAME_CAPACITY, &work, &signers),
                     ==, TC_TLV_OK);
    munit_assert_int(
        TC_CMS_signer_next(&signers, frames, FRAME_CAPACITY, &work, &signer),
        ==, TC_TLV_OK);
    if (container.has_content) {
      munit_assert_int(TC_CMS_content_digest(container.content, TC_HASH_SHA256,
                                             &limits, frames, FRAME_CAPACITY,
                                             &work, digest, sizeof digest),
                       ==, TC_TLV_OK);
    } else {
      unsigned digest_length;
      munit_assert_int(EVP_Digest(message, message_length, digest,
                                  &digest_length, EVP_sha256(), NULL),
                       ==, 1);
      munit_assert_size(digest_length, ==, sizeof digest);
    }
    memset(&saved, 0xa5, sizeof saved);
    memcpy(&found, &saved, sizeof found);
    work = WORK_BUDGET;
    munit_assert_int(tc_cms_signer_find(&candidates, &signer,
                                        container.content_type, content_digest,
                                        TC_CMS_ATTRIBUTES_DER, &indexed,
                                        &options, &tree, &signature,
                                        &validation, &search, &found),
                     ==, TC_X509_PATH_VALID);
    munit_assert_size(found.count, ==, 2);
    munit_assert_size(found.anchor_index, ==, 0);
    munit_assert_memory_equal(intermediate_length, found.path[0].data,
                              intermediate_der);
    munit_assert_memory_equal(leaf_length, found.path[1].data, leaf_der);
    const size_t required = WORK_BUDGET - work;
    munit_assert_size(found.validation.work_used, ==, required);
    work = required;
    munit_assert_int(tc_cms_signer_find(&candidates, &signer,
                                        container.content_type, content_digest,
                                        TC_CMS_ATTRIBUTES_DER, &indexed,
                                        &options, &tree, &signature,
                                        &validation, &search, &found),
                     ==, TC_X509_PATH_VALID);
    munit_assert_size(work, ==, 0);
    {
      uint8_t signature_bytes[SIGNATURE_CAPACITY];
      TC_CMS_path_options settings = {options, INDEX_CAPACITY, CMS_CAPACITY,
                                      TC_CMS_ATTRIBUTES_DER,
                                      TC_CMS_RSA_PARAMETERS_NULL};
      TC_CMS_path_workspace workspace = {
          validation,     search,          index,
          INDEX_CAPACITY, signature_bytes, sizeof signature_bytes};
      const TC_bytes envelope = {encoded, (size_t)length};
      {
        ExampleCMSCredentialWorkspace credential;
        const TC_bytes certificates[] = {
            {root_der, root_length},
            {intermediate_der, intermediate_length},
            {leaf_der, leaf_length}};
        candidate_source supplied = {certificates, 3, 0, TC_TLV_OK, 0};
        const TC_X509_store_source certificate_source = {&supplied, 3, 0,
                                                         read_candidate, NULL};
        combined_store_source combined = {&certificate_source, &external};
        const TC_X509_store_source complete = {
            &combined, 3, 1, combined_candidate, combined_anchor};
        TC_CMS_path_options credential_settings = settings;
        credential_settings.max_candidates += complete.candidate_count;
        TC_X509_store_snapshot slot = {0}, *held = NULL;
        TC_X509_store store = {0};
        const TC_X509_crl_index no_crls = {NULL, 0, 0};
        TC_CMS_revocation_policy revocation = {&no_crls, &options, CMS_CAPACITY,
                                               TC_X509_CRL_COMPLETE_ONLY,
                                               TC_X509_CRL_ORDER_NUMBER};
        {
          const TC_CMS_revocation_policy cms_revocation = {
              revocation.index, revocation.signer_policy,
              revocation.max_candidate_bytes, revocation.delta_policy,
              revocation.order_policy};
          union {
            TC_CMS_validation_request request;
            TC_bytes path[EXAMPLE_X509_PATH_CAPACITY];
          } aliased;
          const TC_CMS_validation_request request = {envelope,
                                                     0,
                                                     container.content_type,
                                                     detached ? &detached_input
                                                              : NULL,
                                                     detached ? 1u : 0u,
                                                     {NULL, 0}};
          const TC_CMS_credential_workspace scratch = {
              &workspace,
              aliased.path,
              EXAMPLE_X509_PATH_CAPACITY,
              credential.crl_states,
              sizeof credential.crl_states,
              credential.nodes,
              EXAMPLE_CMS_REVOCATION_NODES};
          uint8_t saved[sizeof aliased];
          memset(&aliased, 0, sizeof aliased);
          aliased.request = request;
          memcpy(saved, &aliased, sizeof saved);
          work = WORK_BUDGET;
          munit_assert_int(
              TC_CMS_credential_validate(NULL, &complete, &credential_settings,
                                         &cms_revocation, &scratch, &work),
              ==, TC_CREDENTIAL_ERROR);
          munit_assert_size(work, ==, WORK_BUDGET);
          munit_assert_int(
              TC_CMS_credential_validate(&aliased.request, &complete,
                                         &credential_settings, &cms_revocation,
                                         &scratch, &work),
              ==, TC_CREDENTIAL_ERROR);
          munit_assert_size(work, ==, WORK_BUDGET);
          munit_assert_memory_equal(sizeof saved, &aliased, saved);
          for (unsigned area = 0; area < 2; ++area) {
            TC_CMS_validation_request overlap = request;
            overlap.signer_certificate = (TC_bytes){
                area ? credential.crl_states : (const uint8_t *)aliased.path,
                1};
            work = WORK_BUDGET;
            munit_assert_int(TC_CMS_credential_validate(
                                 &overlap, &complete, &credential_settings,
                                 &cms_revocation, &scratch, &work),
                             ==, TC_CREDENTIAL_ERROR);
            munit_assert_size(work, ==, WORK_BUDGET);
            munit_assert_memory_equal(sizeof saved, &aliased, saved);
          }
        }
        work = WORK_BUDGET;
        const TC_CMS_validation_request request = {envelope,
                                                   0,
                                                   container.content_type,
                                                   detached ? &detached_input
                                                            : NULL,
                                                   detached ? 1u : 0u,
                                                   {NULL, 0}};
        munit_assert_int(example_validate_cms_from_store(
                             &request, &store, &credential_settings,
                             &revocation, &work, &credential),
                         ==, TC_CREDENTIAL_UNAVAILABLE);
        munit_assert_size(work, ==, WORK_BUDGET);
        munit_assert_int(TC_X509_store_prepare(&slot, &complete), ==,
                         TC_TLV_OK);
        munit_assert_int(TC_X509_store_publish(&store, 0, &slot), ==,
                         TC_TLV_OK);
        munit_assert_int(TC_X509_store_acquire(&store, &held), ==, TC_TLV_OK);
        {
          enum {
            MISSING_INDEX,
            MISSING_RECORDS,
            BAD_DELTA,
            BAD_ORDER,
            TOO_MANY_CRLS,
            CASE_COUNT
          };
          TC_X509_crl_record extra_records[EXAMPLE_CMS_CRL_CAPACITY + 1];
          for (unsigned kind = 0; kind < CASE_COUNT; ++kind) {
            TC_X509_crl_index bad_index = {NULL, 0, 0};
            TC_CMS_revocation_policy bad = revocation;
            bad.index = &bad_index;
            if (kind == MISSING_INDEX)
              bad.index = NULL;
            else if (kind == MISSING_RECORDS)
              bad_index.count = 1;
            else if (kind == BAD_DELTA)
              bad.delta_policy = (TC_X509_crl_delta_policy)-1;
            else if (kind == BAD_ORDER)
              bad.order_policy = (TC_X509_crl_order_policy)-1;
            else {
              bad_index.records = extra_records;
              bad_index.count = sizeof extra_records / sizeof extra_records[0];
            }
            work = WORK_BUDGET;
            munit_assert_int(example_validate_cms_from_store(
                                 &request, &store, &credential_settings, &bad,
                                 &work, &credential),
                             ==,
                             kind == TOO_MANY_CRLS ? TC_CREDENTIAL_LIMIT
                                                   : TC_CREDENTIAL_ERROR);
            munit_assert_size(work, ==, WORK_BUDGET);
            munit_assert_size(slot.readers, ==, 1);
          }
        }
        work = WORK_BUDGET;
        /* A valid CMS path still requires revocation evidence. */
        munit_assert_int(example_validate_cms_credential(
                             &request, held, &credential_settings, &revocation,
                             &work, &credential),
                         ==, TC_CREDENTIAL_UNSUPPORTED);
        work = 0;
        munit_assert_int(example_validate_cms_credential(
                             &request, held, &credential_settings, &revocation,
                             &work, &credential),
                         ==, TC_CREDENTIAL_LIMIT);
        TC_X509_path_options different_time = options;
        different_time.at.year++;
        revocation.signer_policy = &different_time;
        work = WORK_BUDGET;
        munit_assert_int(example_validate_cms_credential(
                             &request, held, &credential_settings, &revocation,
                             &work, &credential),
                         ==, TC_CREDENTIAL_ERROR);
        munit_assert_size(work, ==, WORK_BUDGET);
        revocation.signer_policy = &options;
        for (unsigned revoked = 0; revoked < 3; ++revoked) {
          uint8_t issuer_crl[CERT_CAPACITY], root_crl[CERT_CAPACITY];
          const TC_bytes crls[] = {
              {issuer_crl, encode_issuer_crl(intermediate, intermediate_key,
                                             revoked == 1 ? leaf : NULL,
                                             issuer_crl, sizeof issuer_crl)},
              {root_crl, encode_issuer_crl(root, root_key,
                                           revoked == 2 ? intermediate : NULL,
                                           root_crl, sizeof root_crl)}};
          TC_X509_crl_record records[2];
          TC_X509_crl_index crl_index;
          work = WORK_BUDGET;
          munit_assert_int(TC_X509_crl_index_init(crls, 2, &limits, &parser,
                                                  &work, records, 2,
                                                  &crl_index),
                           ==, TC_TLV_OK);
          munit_assert_int(records[0].policy, ==, TC_TLV_OK);
          munit_assert_int(records[1].policy, ==, TC_TLV_OK);
          revocation.index = &crl_index;
          {
            TC_X509_certificate target_certificates[3];
            const TC_bytes target_der[] = {
                {leaf_der, leaf_length},
                {intermediate_der, intermediate_length},
                {root_der, root_length}};
            TC_X509_crl_target targets[3];
            for (size_t target = 0; target < 3; ++target) {
              munit_assert_int(TC_X509_read(target_der[target].data,
                                            target_der[target].length, &limits,
                                            &parser,
                                            &target_certificates[target]),
                               ==, TC_TLV_OK);
              targets[target] =
                  (TC_X509_crl_target){target_certificates[target].serial,
                                       target_certificates[target].issuer};
            }
            TC_X509_crl_storage job_storage[2][256];
            TC_X509_crl_job *jobs[2];
            uint8_t metadata[2][CERT_CAPACITY], window[64], entry[256],
                issuer_storage[256];
            TC_X509_crl_match matches[2][3];
            TC_X509_crl_record prepared_records[2];
            for (size_t record = 0; record < 2; ++record) {
              TC_bytes bytes = crls[record];
              const TC_source source = {tc_source_memory_read, &bytes,
                                        bytes.length};
              const TC_X509_crl_prepare_options preparation_options = {
                  limits, bytes.length, bytes.length * 4 + 1024, 4096, 128};
              const TC_X509_crl_prepare_workspace preparation = {
                  {(uint8_t *)job_storage[record], sizeof job_storage[record]},
                  {window, sizeof window},
                  {metadata[record], sizeof metadata[record]},
                  {entry, sizeof entry},
                  {issuer_storage, sizeof issuer_storage},
                  parser,
                  validation.names,
                  matches[record],
                  3};
              work = 60000;
              munit_assert_int(TC_X509_crl_prepare_begin(
                                   &source, targets, 3, &preparation_options,
                                   &preparation, &work, &jobs[record]),
                               ==, TC_TLV_OK);
              int complete = 0;
              while (!complete) {
                work = 60000;
                munit_assert_int(TC_X509_crl_prepare_step(jobs[record], 4, 128,
                                                          &work, &complete),
                                 ==, TC_TLV_OK);
              }
              munit_assert_int(TC_X509_crl_prepare_finish(
                                   jobs[record], &prepared_records[record]),
                               ==, TC_TLV_OK);
            }
            const TC_X509_crl_index prepared_index = {prepared_records, 2, 0};
            TC_CMS_revocation_policy prepared_policy = revocation;
            prepared_policy.index = &prepared_index;
            work = WORK_BUDGET;
            munit_assert_int(
                example_validate_cms_credential(
                    &request, held, &credential_settings, &prepared_policy,
                    &work, &credential),
                ==, revoked ? TC_CREDENTIAL_REVOKED : TC_CREDENTIAL_VALID);
            for (size_t record = 0; record < 2; ++record)
              TC_X509_crl_prepare_clear(jobs[record]);
          }
          /* Explicit signer selection must retain identity and revocation
           * checks. */
          for (unsigned choice = 0; choice < 5; ++choice) {
            TC_CMS_validation_request selected = request;
            uint8_t certificate_free[CMS_CAPACITY];
            selected.signer_certificate =
                choice == 1 ? (TC_bytes){intermediate_der, intermediate_length}
                            : (TC_bytes){leaf_der, leaf_length};
            if (choice == 2)
              selected.signer_certificate.data = NULL;
            if (choice == 3)
              selected.signer_certificate.length = 0;
            if (choice == 4) {
              BIO *input = BIO_new_mem_buf(message, (int)message_length);
              munit_assert_not_null(input);
              CMS_ContentInfo *omitted = CMS_sign(leaf, leaf_key, NULL, input,
                                                  cms_flags | CMS_NOCERTS);
              munit_assert_not_null(omitted);
              int encoded_length = i2d_CMS_ContentInfo(omitted, NULL);
              munit_assert_int(encoded_length, >, 0);
              munit_assert_size((size_t)encoded_length, <=,
                                sizeof certificate_free);
              unsigned char *output = certificate_free;
              munit_assert_int(i2d_CMS_ContentInfo(omitted, &output), ==,
                               encoded_length);
              selected.encoded =
                  (TC_bytes){certificate_free, (size_t)encoded_length};
              CMS_ContentInfo_free(omitted);
              BIO_free(input);
            }
            work = WORK_BUDGET;
            munit_assert_int(example_validate_cms_credential(
                                 &selected, held, &credential_settings,
                                 &revocation, &work, &credential),
                             ==,
                             (choice == 2 || choice == 3) ? TC_CREDENTIAL_ERROR
                             : choice == 1 ? TC_CREDENTIAL_INVALID
                             : revoked     ? TC_CREDENTIAL_REVOKED
                                           : TC_CREDENTIAL_VALID);
            if (choice == 2 || choice == 3)
              munit_assert_size(work, ==, WORK_BUDGET);
          }
          if (rsa_signer) {
            uint8_t without_null[CMS_CAPACITY];
            const TC_bytes compatible_input = {
                without_null, omit_cms_rsa_parameters(envelope, without_null,
                                                      sizeof without_null)};
            for (unsigned variant = 0; variant < 4; ++variant) {
              const int allow = variant == 1, invalid_policy = variant >= 2;
              TC_CMS_path_options policy = credential_settings;
              policy.rsa_parameters = allow ? TC_CMS_RSA_PARAMETERS_ALLOW_ABSENT
                                            : TC_CMS_RSA_PARAMETERS_NULL;
              if (variant == 2)
                policy.rsa_parameters = (TC_CMS_rsa_parameters)-1;
              if (variant == 3)
                policy.attributes = (TC_CMS_attribute_encoding)-1;
              work = WORK_BUDGET;
              memset(&found, 0xa5, sizeof found);
              TC_X509_search_result preserved;
              memcpy(&preserved, &found, sizeof found);
              munit_assert_int(TC_CMS_signed_data_path_build(
                                   compatible_input, 0, container.content_type,
                                   detached_input, &external, &policy,
                                   &workspace, &work, &found),
                               ==,
                               invalid_policy ? TC_X509_PATH_ERROR
                               : allow        ? TC_X509_PATH_VALID
                                              : TC_X509_PATH_INVALID);
              if (!allow)
                munit_assert_memory_equal(sizeof found, &found, &preserved);
              if (invalid_policy)
                munit_assert_size(work, ==, WORK_BUDGET);
              work = WORK_BUDGET;
              TC_CMS_validation_request compatible = request;
              compatible.encoded = compatible_input;
              munit_assert_int(example_validate_cms_from_store(
                                   &compatible, &store, &policy, &revocation,
                                   &work, &credential),
                               ==,
                               invalid_policy ? TC_CREDENTIAL_ERROR
                               : !allow       ? TC_CREDENTIAL_INVALID
                               : revoked      ? TC_CREDENTIAL_REVOKED
                                              : TC_CREDENTIAL_VALID);
              if (invalid_policy)
                munit_assert_size(work, ==, WORK_BUDGET);
              munit_assert_size(slot.readers, ==, 1);
            }
          }
          const size_t split = message_length / 2;
          const TC_bytes parts[] = {{message, split},
                                    {NULL, 0},
                                    {message + split, message_length - split}};
          const TC_CMS_validation_request fragmented = {envelope,
                                                        0,
                                                        container.content_type,
                                                        detached ? parts : NULL,
                                                        detached ? 3u : 0u,
                                                        {NULL, 0}};
          work = WORK_BUDGET;
          munit_assert_int(
              example_validate_cms_credential(&fragmented, held,
                                              &credential_settings, &revocation,
                                              &work, &credential),
              ==, revoked ? TC_CREDENTIAL_REVOKED : TC_CREDENTIAL_VALID);
          work = WORK_BUDGET;
          munit_assert_int(
              example_validate_cms_from_store(&request, &store,
                                              &credential_settings, &revocation,
                                              &work, &credential),
              ==, revoked ? TC_CREDENTIAL_REVOKED : TC_CREDENTIAL_VALID);
          munit_assert_size(slot.readers, ==, 1);
          work = WORK_BUDGET;
          munit_assert_int(
              example_validate_cms_from_store(&fragmented, &store,
                                              &credential_settings, &revocation,
                                              &work, &credential),
              ==, revoked ? TC_CREDENTIAL_REVOKED : TC_CREDENTIAL_VALID);
          munit_assert_size(slot.readers, ==, 1);
          if (!revoked) {
            const size_t credential_work = WORK_BUDGET - work;
            munit_assert_size(credential_work, >, 0);
            for (unsigned short_budget = 0; short_budget < 2; ++short_budget) {
              work = credential_work - short_budget;
              munit_assert_int(
                  example_validate_cms_from_store(
                      &fragmented, &store, &credential_settings, &revocation,
                      &work, &credential),
                  ==, short_budget ? TC_CREDENTIAL_LIMIT : TC_CREDENTIAL_VALID);
              if (!short_budget)
                munit_assert_size(work, ==, 0);
              munit_assert_size(slot.readers, ==, 1);
            }
            enum {
              CRL_RECORDS,
              CMS_SCRATCH,
              HELD_PATH,
              CRL_STATES,
              CRL_NODES,
              ALIAS_COUNT
            };
            for (unsigned alias = 0; alias < ALIAS_COUNT; ++alias) {
              TC_X509_crl_record aliased_record = records[0];
              TC_X509_crl_index aliased_index = {&aliased_record, 1, 0};
              TC_CMS_revocation_policy aliased_policy = revocation;
              uint8_t saved_storage[sizeof credential];
              const void *overlapping = &credential.cms;
              if (alias == HELD_PATH)
                overlapping = credential.held_path;
              if (alias == CRL_STATES)
                overlapping = credential.crl_states;
              if (alias == CRL_NODES)
                overlapping = credential.nodes;
              if (alias == CRL_RECORDS)
                aliased_index.records =
                    (const TC_X509_crl_record *)&credential.cms;
              else
                aliased_record.crl.encoded = (TC_bytes){overlapping, 1};
              aliased_policy.index = &aliased_index;
              memcpy(saved_storage, &credential, sizeof credential);
              work = WORK_BUDGET;
              munit_assert_int(example_validate_cms_from_store(
                                   &fragmented, &store, &credential_settings,
                                   &aliased_policy, &work, &credential),
                               ==, TC_CREDENTIAL_ERROR);
              munit_assert_size(work, ==, WORK_BUDGET);
              munit_assert_size(slot.readers, ==, 1);
              munit_assert_memory_equal(sizeof credential, &credential,
                                        saved_storage);
            }
            {
              const void *targets[] = {&credential.cms, credential.held_path,
                                       credential.crl_states, credential.nodes};
              for (size_t alias = 0; alias < sizeof targets / sizeof *targets;
                   ++alias) {
                const TC_bytes returned = {targets[alias], 1};
                candidate_source aliased = {&returned, 1, 0, TC_TLV_OK, 0};
                const TC_X509_store_source candidates = {&aliased, 1, 0,
                                                         read_candidate, NULL};
                combined_store_source combined_alias = {&candidates, &external};
                const TC_X509_store_source source_alias = {
                    &combined_alias, 1, 1, combined_candidate, combined_anchor};
                TC_X509_store alias_store = {0};
                TC_X509_store_snapshot alias_slot = {0};
                munit_assert_int(
                    TC_X509_store_prepare(&alias_slot, &source_alias), ==,
                    TC_TLV_OK);
                munit_assert_int(
                    TC_X509_store_publish(&alias_store, 0, &alias_slot), ==,
                    TC_TLV_OK);
                work = WORK_BUDGET;
                munit_assert_int(example_validate_cms_from_store(
                                     &fragmented, &alias_store,
                                     &credential_settings, &revocation, &work,
                                     &credential),
                                 ==, TC_CREDENTIAL_ERROR);
                munit_assert_size(aliased.calls, ==, 1);
                munit_assert_size(alias_slot.readers, ==, 0);
              }
            }
            TC_X509_certificate wrong_key;
            munit_assert_int(TC_X509_read(intermediate_der, intermediate_length,
                                          &limits, &parser, &wrong_key),
                             ==, TC_TLV_OK);
            TC_X509_store_anchor wrong_anchor = anchor;
            wrong_anchor.trust.public_key = wrong_key.public_key;
            const TC_X509_store_source wrong_trust = {&wrong_anchor, 0, 1, NULL,
                                                      crl_trust_anchor};
            combined_store_source wrong_combined = {&certificate_source,
                                                    &wrong_trust};
            TC_X509_store_source wrong_source = {
                &wrong_combined, 3, 1, combined_candidate, combined_anchor};
            for (unsigned missing_anchor = 0; missing_anchor < 2;
                 ++missing_anchor) {
              TC_X509_store rejected_store = {0};
              TC_X509_store_snapshot rejected_slot = {0},
                                     *rejected_snapshot = NULL;
              wrong_source.anchor_count = missing_anchor ? 0 : 1;
              munit_assert_int(
                  TC_X509_store_prepare(&rejected_slot, &wrong_source), ==,
                  TC_TLV_OK);
              munit_assert_int(
                  TC_X509_store_publish(&rejected_store, 0, &rejected_slot), ==,
                  TC_TLV_OK);
              munit_assert_int(
                  TC_X509_store_acquire(&rejected_store, &rejected_snapshot),
                  ==, TC_TLV_OK);
              work = WORK_BUDGET;
              munit_assert_int(example_validate_cms_credential(
                                   &request, rejected_snapshot,
                                   &credential_settings, &revocation, &work,
                                   &credential),
                               ==, TC_CREDENTIAL_INVALID);
              munit_assert_int(TC_X509_store_release(rejected_snapshot), ==,
                               TC_TLV_OK);
            }
            enum {
              WRONG_USAGE,
              EXPIRED,
              TAMPERED_SIGNATURE,
              ABSENT_SIGNER,
              FAILURE_COUNT
            };
            for (unsigned failure = 0; failure < FAILURE_COUNT; ++failure) {
              TC_CMS_path_options rejected = credential_settings;
              TC_X509_path_options crl_policy = options;
              TC_bytes input = envelope;
              size_t signer_index = 0;
              uint8_t changed[CMS_CAPACITY];
              if (failure == WRONG_USAGE) {
                rejected.path.flags |= TC_X509_PATH_REQUIRE_KEY_USAGE;
                rejected.path.key_usage = TC_KEY_USAGE_KEY_ENCIPHERMENT;
              } else if (failure == EXPIRED) {
                rejected.path.at.year = 2040;
                crl_policy.at = rejected.path.at;
              } else if (failure == TAMPERED_SIGNATURE) {
                memcpy(changed, encoded, (size_t)length);
                const size_t end = (size_t)(signer.signature.data - encoded) +
                                   signer.signature.length;
                munit_assert_size(end, >, 0);
                munit_assert_size(end, <=, (size_t)length);
                changed[end - 1] ^= 1;
                input.data = changed;
              } else {
                signer_index = SIZE_MAX;
              }
              revocation.signer_policy = &crl_policy;
              TC_CMS_validation_request rejected_request = request;
              rejected_request.encoded = input;
              rejected_request.signer_index = signer_index;
              work = WORK_BUDGET;
              munit_assert_int(example_validate_cms_credential(
                                   &rejected_request, held, &rejected,
                                   &revocation, &work, &credential),
                               ==, TC_CREDENTIAL_INVALID);
              work = WORK_BUDGET;
              munit_assert_int(example_validate_cms_from_store(
                                   &rejected_request, &store, &rejected,
                                   &revocation, &work, &credential),
                               ==, TC_CREDENTIAL_INVALID);
              munit_assert_size(slot.readers, ==, 1);
            }
            revocation.signer_policy = &options;
          }
        }
        revocation.index = &no_crls;
        munit_assert_int(TC_X509_store_release(held), ==, TC_TLV_OK);
        revocation.signer_policy = &options;
        munit_assert_int(example_validate_cms_credential(&request, &slot,
                                                         &settings, &revocation,
                                                         &work, &credential),
                         ==, TC_CREDENTIAL_ERROR);
      }
      work = WORK_BUDGET;
      munit_assert_int(TC_CMS_signed_data_path_build(
                           envelope, 0, container.content_type, detached_input,
                           &external, &settings, &workspace, &work, &found),
                       ==, TC_X509_PATH_VALID);
      munit_assert_size(found.count, ==, 2);
      munit_assert_memory_equal(leaf_length, found.path[1].data, leaf_der);
      const size_t envelope_work = WORK_BUDGET - work;
      munit_assert_size(found.validation.work_used, ==, envelope_work);
      work = envelope_work;
      munit_assert_int(TC_CMS_signed_data_path_build(
                           envelope, 0, container.content_type, detached_input,
                           &external, &settings, &workspace, &work, &found),
                       ==, TC_X509_PATH_VALID);
      munit_assert_size(work, ==, 0);
      {
        const size_t split = message_length / 2;
        TC_bytes parts[] = {{message, split},
                            {NULL, 0},
                            {message + split, message_length - split}};
        work = WORK_BUDGET;
        munit_assert_int(TC_CMS_signed_data_path_build_parts(
                             envelope, 0, container.content_type,
                             detached ? parts : NULL, detached ? 3 : 0,
                             &external, &settings, &workspace, &work, &found),
                         ==, TC_X509_PATH_VALID);
        const size_t parts_work = WORK_BUDGET - work;
        munit_assert_size(found.validation.work_used, ==, parts_work);
        work = parts_work;
        munit_assert_int(TC_CMS_signed_data_path_build_parts(
                             envelope, 0, container.content_type,
                             detached ? parts : NULL, detached ? 3 : 0,
                             &external, &settings, &workspace, &work, &found),
                         ==, TC_X509_PATH_VALID);
        munit_assert_size(work, ==, 0);
        for (unsigned failure = 0; failure < 6; ++failure) {
          const TC_bytes *supplied = parts;
          size_t count = 3;
          work = WORK_BUDGET;
          memcpy(&found, &saved, sizeof found);
          if (failure == 0) {
            supplied = NULL;
            count = 1;
          }
          if (failure == 1)
            supplied = (const TC_bytes *)&found;
          if (failure == 2)
            parts[0] = (TC_bytes){NULL, 1};
          if (failure == 3) {
            parts[0] = (TC_bytes){message, split};
            supplied = detached ? parts : NULL;
            count = detached ? 3 : 0;
            work = parts_work - 1;
          }
          if (failure == 4)
            count = SIZE_MAX;
          if (failure == 5)
            parts[0] = (TC_bytes){(const uint8_t *)&found, 1};
          munit_assert_int(
              TC_CMS_signed_data_path_build_parts(
                  envelope, 0, container.content_type, supplied, count,
                  &external, &settings, &workspace, &work, &found),
              ==, failure == 3 ? TC_X509_PATH_LIMIT : TC_X509_PATH_ERROR);
          munit_assert_memory_equal(sizeof found, &found, &saved);
          if (failure != 3)
            munit_assert_size(work, ==, WORK_BUDGET);
        }
        parts[0] = (TC_bytes){message, split};
        if (!detached) {
          work = WORK_BUDGET;
          munit_assert_int(TC_CMS_signed_data_path_build_parts(
                               envelope, 0, container.content_type, parts, 3,
                               &external, &settings, &workspace, &work, &found),
                           ==, TC_X509_PATH_ERROR);
        } else {
          static const uint8_t extra_byte = 0xff;
          parts[1] = (TC_bytes){&extra_byte, 1};
          work = WORK_BUDGET;
          memcpy(&found, &saved, sizeof found);
          munit_assert_int(TC_CMS_signed_data_path_build_parts(
                               envelope, 0, container.content_type, parts, 3,
                               &external, &settings, &workspace, &work, &found),
                           ==, TC_X509_PATH_INVALID);
          munit_assert_memory_equal(sizeof found, &found, &saved);
          TC_CMS_path_options bounded = settings;
          bounded.path.parsing.max_input = envelope.length;
          const TC_bytes oversized[] = {envelope, envelope};
          work = WORK_BUDGET;
          munit_assert_int(TC_CMS_signed_data_path_build_parts(
                               envelope, 0, container.content_type, oversized,
                               2, &external, &bounded, &workspace, &work,
                               &found),
                           ==, TC_X509_PATH_LIMIT);
          munit_assert_memory_equal(sizeof found, &found, &saved);
        }
      }
      for (unsigned failure = 0; failure < 5; ++failure) {
        static const uint8_t other_type[] = {42, 3}, bad_content[] = {0xff};
        TC_bytes type = container.content_type, supplied = detached_input;
        size_t selected = 0;
        work = WORK_BUDGET;
        memcpy(&found, &saved, sizeof found);
        if (failure == 0)
          work = envelope_work - 1;
        if (failure == 1)
          selected = 1;
        if (failure == 2)
          selected = SIZE_MAX;
        if (failure == 3)
          type = (TC_bytes){other_type, sizeof other_type};
        if (failure == 4)
          supplied = (TC_bytes){bad_content, sizeof bad_content};
        munit_assert_int(TC_CMS_signed_data_path_build(
                             envelope, selected, type, supplied, &external,
                             &settings, &workspace, &work, &found),
                         ==,
                         failure == 0                ? TC_X509_PATH_LIMIT
                         : failure == 4 && !detached ? TC_X509_PATH_ERROR
                                                     : TC_X509_PATH_INVALID);
        munit_assert_memory_equal(sizeof found, &found, &saved);
      }
      {
        static const uint8_t absent[] = {0x31, 13, 0x30, 11, 6, 9, 0x60, 0x86,
                                         0x48, 1,  0x65, 3,  4, 2, 1};
        static const uint8_t null[] = {0x31, 15,   0x30, 13, 6,    9,
                                       0x60, 0x86, 0x48, 1,  0x65, 3,
                                       4,    2,    1,    5,  0};
        static const uint8_t long_null[] = {0x31, 16,   0x30, 14, 6,    9,
                                            0x60, 0x86, 0x48, 1,  0x65, 3,
                                            4,    2,    1,    5,  0x81, 0};
        static const uint8_t invalid[] = {0x31, 15,   0x30, 13, 6,    9,
                                          0x60, 0x86, 0x48, 1,  0x65, 3,
                                          4,    2,    1,    4,  0};
        static const uint8_t wrong[] = {0x31, 13, 0x30, 11, 6, 9, 0x60, 0x86,
                                        0x48, 1,  0x65, 3,  4, 2, 2};
        static const uint8_t empty[] = {0x31, 0};
        static const uint8_t extra[] = {0x31, 18,   0x30, 3, 6,    1,    42,
                                        0x30, 11,   6,    9, 0x60, 0x86, 0x48,
                                        1,    0x65, 3,    4, 2,    1};
        const struct {
          TC_bytes algorithms;
          TC_X509_path_status status;
        } variants[] = {{{absent, sizeof absent}, TC_X509_PATH_VALID},
                        {{null, sizeof null}, TC_X509_PATH_VALID},
                        {{long_null, sizeof long_null}, TC_X509_PATH_VALID},
                        {{extra, sizeof extra}, TC_X509_PATH_VALID},
                        {{invalid, sizeof invalid}, TC_X509_PATH_INVALID},
                        {{wrong, sizeof wrong}, TC_X509_PATH_INVALID},
                        {{empty, sizeof empty}, TC_X509_PATH_INVALID}};
        uint8_t rewritten[CMS_CAPACITY];
        for (size_t i = 0; i < sizeof variants / sizeof *variants; ++i) {
          const size_t rewritten_length = test_cms_encode_envelope(
              &container, variants[i].algorithms, container.signers, rewritten,
              sizeof rewritten);
          work = WORK_BUDGET;
          memcpy(&found, &saved, sizeof found);
          munit_assert_int(TC_CMS_signed_data_path_build(
                               (TC_bytes){rewritten, rewritten_length}, 0,
                               container.content_type, detached_input,
                               &external, &settings, &workspace, &work, &found),
                           ==, variants[i].status);
          if (variants[i].status != TC_X509_PATH_VALID)
            munit_assert_memory_equal(sizeof found, &found, &saved);
        }
        /* A caller can select the second signer even if the first signature
         * fails. */
        uint8_t two_signers[CMS_CAPACITY];
        munit_assert_size(2 * signer.encoded.length + 4, <=,
                          sizeof two_signers);
        two_signers[0] = 0x31;
        two_signers[1] = 0x80;
        memcpy(two_signers + 2, signer.encoded.data, signer.encoded.length);
        memcpy(two_signers + 2 + signer.encoded.length, signer.encoded.data,
               signer.encoded.length);
        memset(two_signers + 2 + 2 * signer.encoded.length, 0, 2);
        const size_t bad_signature_offset =
            2 + (size_t)(signer.signature.data - signer.encoded.data) +
            signer.signature.length - 1;
        two_signers[bad_signature_offset] ^= 1;
        size_t rewritten_length = test_cms_encode_envelope(
            &container, container.digest_algorithms,
            (TC_bytes){two_signers, 2 * signer.encoded.length + 4}, rewritten,
            sizeof rewritten);
        for (size_t selected = 0; selected < 3; ++selected) {
          work = WORK_BUDGET;
          memcpy(&found, &saved, sizeof found);
          munit_assert_int(
              TC_CMS_signed_data_path_build(
                  (TC_bytes){rewritten, rewritten_length}, selected,
                  container.content_type, detached_input, &external, &settings,
                  &workspace, &work, &found),
              ==, selected == 1 ? TC_X509_PATH_VALID : TC_X509_PATH_INVALID);
          if (selected != 1)
            munit_assert_memory_equal(sizeof found, &found, &saved);
        }
      }
      work = WORK_BUDGET;
      munit_assert_int(TC_CMS_signer_path_build(
                           &signer, container.content_type, content_digest,
                           container.certificates, &external, &settings,
                           &workspace, &work, &found),
                       ==, TC_X509_PATH_VALID);
      munit_assert_size(found.count, ==, 2);
      munit_assert_size(found.anchor_index, ==, 0);
      munit_assert_memory_equal(leaf_length, found.path[1].data, leaf_der);
      const size_t total = WORK_BUDGET - work;
      munit_assert_size(found.validation.work_used, ==, total);
      ExampleCMSPathWorkspace example;
      munit_assert_int(example_check_cms_signed_data(
                           envelope, 0, container.content_type, detached_input,
                           &external, &settings, WORK_BUDGET, &example, &found),
                       ==, TC_X509_PATH_VALID);
      munit_assert_size(found.count, ==, 2);
      munit_assert_memory_equal(leaf_length, found.path[1].data, leaf_der);
      munit_assert_int(example_find_cms_signer_path(
                           &signer, container.content_type, content_digest,
                           container.certificates, &external, &settings,
                           WORK_BUDGET, &example, &found),
                       ==, TC_X509_PATH_VALID);
      munit_assert_size(found.count, ==, 2);
      munit_assert_memory_equal(leaf_length, found.path[1].data, leaf_der);
      work = total;
      munit_assert_int(TC_CMS_signer_path_build(
                           &signer, container.content_type, content_digest,
                           container.certificates, &external, &settings,
                           &workspace, &work, &found),
                       ==, TC_X509_PATH_VALID);
      munit_assert_size(work, ==, 0);
      for (unsigned failure = 0; failure < 4; ++failure) {
        TC_CMS_path_options short_settings = settings;
        TC_CMS_path_workspace short_workspace = workspace;
        work = WORK_BUDGET;
        memcpy(&found, &saved, sizeof found);
        if (failure == 0)
          work = total - 1;
        if (failure == 1)
          short_settings.max_candidates = INDEX_CAPACITY - 1;
        if (failure == 2)
          short_settings.max_candidate_bytes =
              container.certificates.length - 1;
        if (failure == 3)
          short_workspace.certificate_capacity = INDEX_CAPACITY - 1;
        munit_assert_int(TC_CMS_signer_path_build(
                             &signer, container.content_type, content_digest,
                             container.certificates, &external, &short_settings,
                             &short_workspace, &work, &found),
                         ==, TC_X509_PATH_LIMIT);
        munit_assert_memory_equal(sizeof found, &found, &saved);
      }
      TC_bytes writes[TC_X509_PATH_STORAGE_COUNT + 6];
      munit_assert_int(tc_x509_path_storage_writes(&validation, writes), ==,
                       TC_TLV_OK);
      size_t n = TC_X509_PATH_STORAGE_COUNT;
      writes[n++] = (TC_bytes){(const uint8_t *)path, sizeof path};
      writes[n++] =
          (TC_bytes){(const uint8_t *)search_frames, sizeof search_frames};
      writes[n++] = (TC_bytes){(const uint8_t *)index, sizeof index};
      writes[n++] = (TC_bytes){signature_bytes, sizeof signature_bytes};
      writes[n++] = (TC_bytes){(const uint8_t *)&found, sizeof found};
      writes[n++] = (TC_bytes){(const uint8_t *)&work, sizeof work};
      for (size_t i = 0; i < n; ++i) {
        work = WORK_BUDGET;
        memcpy(&found, &saved, sizeof found);
        void *before = munit_malloc(writes[i].length);
        memcpy(before, writes[i].data, writes[i].length);
        const TC_bytes aliased = {writes[i].data, 1};
        munit_assert_int(
            TC_CMS_signer_path_build(&signer, container.content_type, aliased,
                                     container.certificates, &external,
                                     &settings, &workspace, &work, &found),
            ==, TC_X509_PATH_ERROR);
        munit_assert_memory_equal(writes[i].length, writes[i].data, before);
        munit_assert_size(work, ==, WORK_BUDGET);
        munit_assert_memory_equal(sizeof found, &found, &saved);
        munit_assert_int(TC_CMS_signed_data_path_build(
                             envelope, 0, aliased, detached_input, &external,
                             &settings, &workspace, &work, &found),
                         ==, TC_X509_PATH_ERROR);
        munit_assert_memory_equal(writes[i].length, writes[i].data, before);
        munit_assert_size(work, ==, WORK_BUDGET);
        munit_assert_memory_equal(sizeof found, &found, &saved);
        free(before);
      }
      settings.path.max_work = WORK_BUDGET;
      munit_assert_int(TC_CMS_signer_path_build(
                           &signer, container.content_type, content_digest,
                           container.certificates, &external, &settings,
                           &workspace, &settings.path.max_work, &found),
                       ==, TC_X509_PATH_ERROR);
      munit_assert_size(settings.path.max_work, ==, WORK_BUDGET);
      /* Indexing checks external bytes before writing even the first span. */
      const TC_bytes aliased_record = {(const uint8_t *)index, sizeof index};
      candidate_source record_context = {&aliased_record, 1, 0, TC_TLV_OK, 0};
      TC_X509_store_source aliased_source = {&record_context, 1, 0,
                                             read_candidate, NULL};
      TC_bytes saved_index[INDEX_CAPACITY];
      memcpy(saved_index, index, sizeof index);
      work = WORK_BUDGET;
      munit_assert_int(TC_CMS_signer_path_build(
                           &signer, container.content_type, content_digest,
                           (TC_bytes){NULL, 0}, &aliased_source, &settings,
                           &workspace, &work, &found),
                       ==, TC_X509_PATH_ERROR);
      munit_assert_memory_equal(sizeof index, index, saved_index);
      munit_assert_memory_equal(sizeof found, &found, &saved);
    }
    enum {
      SHORT_WORK,
      MISSING_INTERMEDIATE,
      NO_ANCHOR,
      EXPIRED,
      BAD_CONTENT,
      BAD_SIGNATURE,
      WRONG_IDENTIFIER,
      MISSING_DIGEST_PROVIDER,
      MISSING_PATH_PROVIDER
    };
    const struct {
      unsigned kind;
      TC_X509_path_status status;
    } failures[] = {{SHORT_WORK, TC_X509_PATH_LIMIT},
                    {MISSING_INTERMEDIATE, TC_X509_PATH_INVALID},
                    {NO_ANCHOR, TC_X509_PATH_INVALID},
                    {EXPIRED, TC_X509_PATH_INVALID},
                    {BAD_CONTENT, TC_X509_PATH_INVALID},
                    {BAD_SIGNATURE, TC_X509_PATH_INVALID},
                    {WRONG_IDENTIFIER, TC_X509_PATH_INVALID},
                    {MISSING_DIGEST_PROVIDER, TC_X509_PATH_UNSUPPORTED},
                    {MISSING_PATH_PROVIDER, TC_X509_PATH_UNSUPPORTED}};
    for (size_t i = 0; i < sizeof failures / sizeof *failures; ++i) {
      TC_X509_path_options checked = options;
      TC_X509_store_source source = indexed;
      TC_CMS_signer_info proposed = signer;
      static const uint8_t wrong_serial[] = {0x7f};
      static const uint8_t wrong_key_id[] = {0x80, 1, 0xff};
      work = WORK_BUDGET;
      memcpy(&found, &saved, sizeof found);
      switch (failures[i].kind) {
      case SHORT_WORK:
        work = required - 1;
        break;
      case MISSING_INTERMEDIATE:
        source = external;
        break;
      case NO_ANCHOR:
        source.anchor_count = 0;
        break;
      case EXPIRED:
        checked.at.year = 2029;
        break;
      case BAD_CONTENT:
        digest[0] ^= 1;
        break;
      case BAD_SIGNATURE:
        encoded[(size_t)(signer.signature.data - encoded) +
                signer.signature.length - 1] ^= 1;
        break;
      case WRONG_IDENTIFIER:
        if (proposed.version == 3)
          proposed.subject_key_id =
              (TC_bytes){wrong_key_id, sizeof wrong_key_id};
        else
          proposed.serial = (TC_bytes){wrong_serial, sizeof wrong_serial};
        break;
      case MISSING_DIGEST_PROVIDER:
        checked.signatures.verify_digest = NULL;
        break;
      case MISSING_PATH_PROVIDER:
        checked.signatures.verify = NULL;
        break;
      }
      munit_assert_int(tc_cms_signer_find(&candidates, &proposed,
                                          container.content_type,
                                          content_digest, TC_CMS_ATTRIBUTES_DER,
                                          &source, &checked, &tree, &signature,
                                          &validation, &search, &found),
                       ==, failures[i].status);
      munit_assert_memory_equal(sizeof found, &found, &saved);
      if (failures[i].kind == BAD_CONTENT)
        digest[0] ^= 1;
      if (failures[i].kind == BAD_SIGNATURE)
        encoded[(size_t)(signer.signature.data - encoded) +
                signer.signature.length - 1] ^= 1;
    }
    /* Retry both content-verification and path failures with another candidate.
     */
    const TC_bytes records[] = {target, target};
    candidate_source records_context = {records, 2, 0, TC_TLV_OK, 0};
    const TC_X509_store_source records_source = {&records_context, 2, 0,
                                                 read_candidate, NULL};
    tc_cms_candidates retries, before;
    work = WORK_BUDGET;
    munit_assert_int(
        tc_cms_candidates_init((TC_bytes){NULL, 0}, &records_source, 2,
                               2 * CERT_CAPACITY, &limits, &tree, &retries),
        ==, TC_TLV_OK);
    memcpy(&before, &retries, sizeof before);
    const TC_X509_signature_result retry_results[] = {
        TC_X509_SIGNATURE_INVALID, TC_X509_SIGNATURE_UNSUPPORTED,
        TC_X509_SIGNATURE_LIMIT, TC_X509_SIGNATURE_ERROR};
    for (size_t call = 1; call <= 2; ++call) {
      for (size_t i = 0; i < sizeof retry_results / sizeof *retry_results;
           ++i) {
        signature_retry_probe probe = {options.signatures, 0, call,
                                       retry_results[i]};
        TC_X509_path_options checked = options;
        checked.signatures =
            (TC_X509_signature_provider){retry_signature, &probe, retry_digest};
        work = WORK_BUDGET;
        records_context.calls = 0;
        memcpy(&found, &saved, sizeof found);
        munit_assert_int(
            tc_cms_signer_find(&retries, &signer, container.content_type,
                               content_digest, TC_CMS_ATTRIBUTES_DER, &indexed,
                               &checked, &tree, &signature, &validation,
                               &search, &found),
            ==,
            retry_results[i] == TC_X509_SIGNATURE_ERROR ? TC_X509_PATH_ERROR
                                                        : TC_X509_PATH_VALID);
        munit_assert_memory_equal(sizeof retries, &retries, &before);
        if (retry_results[i] == TC_X509_SIGNATURE_ERROR) {
          munit_assert_memory_equal(sizeof found, &found, &saved);
          munit_assert_size(records_context.calls, ==, 1);
        } else {
          munit_assert_size(records_context.calls, ==, 2);
          munit_assert_ptr_equal(found.path[found.count - 1].data, leaf_der);
        }
      }
    }
  }
  {
    tc_cms_revocations revocations;
    tc_cms_revocation_choice record;
    tc_x509_crl parsed_crl;
    tc_x509_crl_extension_info extensions;
    TC_X509_search_result saved;
    work = WORK_BUDGET;
    munit_assert_int(tc_cms_revocations_init(container.revocations, NULL, 1,
                                             CMS_CAPACITY, &limits, &tree,
                                             &revocations),
                     ==, TC_TLV_OK);
    munit_assert_int(tc_cms_revocations_next(&revocations, &tree, &record), ==,
                     TC_TLV_OK);
    munit_assert_int(record.kind, ==, TC_CMS_REVOCATION_CRL);
    munit_assert_int(tc_cms_revocations_next(&revocations, &tree, &record), ==,
                     TC_TLV_END);
    {
      const TC_bytes external_crl = record.encoded;
      candidate_source context = {&external_crl, 1, 0, TC_TLV_OK, 0};
      const tc_pki_record_source source = {&context, 1, read_candidate};
      munit_assert_int(tc_cms_revocations_init(container.revocations, &source,
                                               2, 2 * CMS_CAPACITY, &limits,
                                               &tree, &revocations),
                       ==, TC_TLV_OK);
      munit_assert_int(tc_cms_revocations_next(&revocations, &tree, &record),
                       ==, TC_TLV_OK);
      munit_assert_size(context.calls, ==, 0);
      munit_assert_int(tc_cms_revocations_next(&revocations, &tree, &record),
                       ==, TC_TLV_OK);
      munit_assert_size(context.calls, ==, 1);
      munit_assert_ptr_equal(record.encoded.data, external_crl.data);
      munit_assert_int(tc_cms_revocations_next(&revocations, &tree, &record),
                       ==, TC_TLV_END);
    }
    munit_assert_int(
        tc_x509_crl_read(record.encoded, &limits, &tree, &parsed_crl), ==,
        TC_TLV_OK);
    munit_assert_int(
        tc_x509_crl_extension_info_read(parsed_crl.extensions, &limits, &tree,
                                        oids, POLICY_CAPACITY, &extensions),
        ==, TC_TLV_OK);
    memset(&saved, 0xa5, sizeof saved);
    memcpy(&found, &saved, sizeof found);
    work = WORK_BUDGET;
    munit_assert_int(tc_cms_crl_signer_find(
                         &candidates, &parsed_crl, &extensions, &external, 0,
                         &options, &tree, &validation, &search, &found),
                     ==, TC_X509_PATH_INVALID);
    munit_assert_memory_equal(sizeof found, &found, &saved);
    work = WORK_BUDGET;
    munit_assert_int(tc_cms_crl_signer_find(
                         &candidates, &parsed_crl, &extensions, &indexed, 0,
                         &options, &tree, &validation, &search, &found),
                     ==, TC_X509_PATH_VALID);
    munit_assert_size(found.count, ==, 2);
    munit_assert_size(found.anchor_index, ==, 0);
    munit_assert_memory_equal(intermediate_length, found.path[0].data,
                              intermediate_der);
    munit_assert_size(found.path[1].length, ==, leaf_length);
    munit_assert_memory_equal(leaf_length, found.path[1].data, leaf_der);
    const size_t signature_offset =
        (size_t)(found.path[0].data - encoded) + found.path[0].length - 1;
    encoded[signature_offset] ^= 1;
    memcpy(&found, &saved, sizeof found);
    work = WORK_BUDGET;
    munit_assert_int(tc_cms_crl_signer_find(
                         &candidates, &parsed_crl, &extensions, &indexed, 0,
                         &options, &tree, &validation, &search, &found),
                     ==, TC_X509_PATH_INVALID);
    munit_assert_memory_equal(sizeof found, &found, &saved);
    encoded[signature_offset] ^= 1;
  }
  {
    const TC_CMS_path_options settings = {options, INDEX_CAPACITY, CMS_CAPACITY,
                                          TC_CMS_ATTRIBUTES_DER,
                                          TC_CMS_RSA_PARAMETERS_NULL};
    const TC_CMS_path_workspace workspace = {validation,     search, index,
                                             INDEX_CAPACITY, NULL,   0};
    static const uint8_t id_data[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                      0x0d, 1,    7,    1};
    for (unsigned wrong_name = 0; wrong_name < 2; ++wrong_name) {
      CMS_ContentInfo *named =
          CMS_sign(leaf, leaf_key, NULL, NULL, cms_flags | CMS_PARTIAL);
      BIO *named_content = BIO_new_mem_buf(message, (int)message_length);
      munit_assert_not_null(named);
      munit_assert_not_null(named_content);
      set_cms_signer_name(named,
                          X509_get_subject_name(wrong_name ? root : leaf));
      munit_assert_int(CMS_add1_cert(named, intermediate), ==, 1);
      munit_assert_int(CMS_final(named, named_content, NULL, cms_flags), ==, 1);
      munit_assert_int(CMS_SignerInfo_verify(sk_CMS_SignerInfo_value(
                           CMS_get0_SignerInfos(named), 0)),
                       ==, 1);
      length = i2d_CMS_ContentInfo(named, NULL);
      munit_assert_int(length, >, 0);
      munit_assert_size((size_t)length, <=, sizeof encoded);
      cursor = encoded;
      munit_assert_int(i2d_CMS_ContentInfo(named, &cursor), ==, length);
      work = WORK_BUDGET;
      TC_X509_search_result saved;
      memset(&saved, 0xa5, sizeof saved);
      memcpy(&found, &saved, sizeof found);
      munit_assert_int(TC_CMS_signed_data_path_build(
                           (TC_bytes){encoded, (size_t)length}, 0,
                           (TC_bytes){id_data, sizeof id_data}, detached_input,
                           &external, &settings, &workspace, &work, &found),
                       ==,
                       wrong_name ? TC_X509_PATH_INVALID : TC_X509_PATH_VALID);
      if (wrong_name)
        munit_assert_memory_equal(sizeof found, &found, &saved);
      BIO_free(named_content);
      CMS_ContentInfo_free(named);
    }
  }
  X509_CRL_free(crl);
  CMS_ContentInfo_free(cms);
  BIO_free(content);
  X509_free(leaf);
  X509_free(intermediate);
  X509_free(root);
  EVP_PKEY_free(leaf_key);
  EVP_PKEY_free(intermediate_key);
  EVP_PKEY_free(root_key);
  (void)params;
  (void)user;
  return MUNIT_OK;
}

typedef struct {
  EVP_PKEY *key;
  const TC_X509_signature_provider *provider;
  TC_TWIC_CCL_store *ccl_store;
  TC_TWIC_CCL_snapshot *replacement_ccl;
  int tamper;
  unsigned calls;
  ExampleCredentialCardKey expected_key;
} workflow_proof;

static TC_status
workflow_card_proof(void *context, TC_PIV_card_profile profile,
                    ExampleCredentialCardKey key_reference,
                    const TC_X509_public_key *key,
                    const TC_key_challenge_options *challenge) {
  workflow_proof *proof = context;
  munit_assert_true(profile == TC_PIV_CARD || profile == TC_TWIC_LEGACY_CARD ||
                    profile == TC_TWIC_NEXGEN_CARD);
  munit_assert_int(key_reference, ==, proof->expected_key);
  uint8_t digest[48], signature[384];
  const size_t digest_length =
      challenge->signature.hash == TC_HASH_SHA384 ? 48 : 32;
  const EVP_MD *digest_method =
      digest_length == 48 ? EVP_sha384() : EVP_sha256();
  size_t length = sizeof signature, work = 1000000;
  munit_assert_int(RAND_bytes(digest, (int)digest_length), ==, 1);
  EVP_PKEY_CTX *signing = EVP_PKEY_CTX_new(proof->key, NULL);
  munit_assert_not_null(signing);
  munit_assert_int(EVP_PKEY_sign_init(signing), ==, 1);
  const int rsa = EVP_PKEY_base_id(proof->key) == EVP_PKEY_RSA;
  const int pss = challenge->signature.scheme == TC_SIGNATURE_RSA_PSS;
  if (rsa) {
    munit_assert_true(pss ||
                      challenge->signature.scheme == TC_SIGNATURE_RSA_V15);
    munit_assert_int(
        EVP_PKEY_CTX_set_rsa_padding(signing, pss ? RSA_PKCS1_PSS_PADDING
                                                  : RSA_PKCS1_PADDING),
        ==, 1);
  } else {
    munit_assert_int(EVP_PKEY_base_id(proof->key), ==, EVP_PKEY_EC);
    munit_assert_int(challenge->signature.scheme, ==, TC_SIGNATURE_ECDSA);
  }
  munit_assert_int(EVP_PKEY_CTX_set_signature_md(signing, digest_method), ==,
                   1);
  if (pss) {
    munit_assert_int(EVP_PKEY_CTX_set_rsa_mgf1_md(signing, EVP_sha256()), ==,
                     1);
    munit_assert_int(EVP_PKEY_CTX_set_rsa_pss_saltlen(
                         signing, (int)challenge->signature.salt_length),
                     ==, 1);
  }
  munit_assert_int(
      EVP_PKEY_sign(signing, signature, &length, digest, digest_length), ==, 1);
  EVP_PKEY_CTX_free(signing);
  signature[0] ^= (uint8_t)proof->tamper;
  ++proof->calls;
  TC_X509_signature_result status = TC_X509_signature_verify_digest(
      (TC_bytes){digest, digest_length}, &challenge->signature,
      (TC_bytes){signature, length}, key, proof->provider, &work);
  TC_secure_zero(digest, sizeof digest);
  TC_secure_zero(signature, sizeof signature);
  if (status == TC_X509_SIGNATURE_VALID && proof->replacement_ccl) {
    munit_assert_int(
        TC_TWIC_CCL_store_publish(proof->ccl_store, 1, proof->replacement_ccl),
        ==, TC_TWIC_CCL_OK);
    proof->replacement_ccl = NULL;
  }
  return status == TC_X509_SIGNATURE_VALID     ? TC_OK
         : status == TC_X509_SIGNATURE_INVALID ? TC_MISMATCH
                                               : TC_ERROR;
}

static void credential_public_workflow(
    X509 *root, EVP_PKEY *root_key, X509 *signer, EVP_PKEY *signer_key,
    TC_PIV_card_profile profile, unsigned ec_bits, TC_bytes chuid,
    TC_bytes security, const TC_PIV_security_data *inventory,
    size_t inventory_count, TC_bytes unsigned_chuid, TC_bytes printed,
    const TC_validation_context *content) {
  enum { OBJECT_BYTES = 4096, ARENA_UNITS = 1024, WORK = 2000000 };
  static TC_validation_storage arena[ARENA_UNITS];
  uint8_t certificate_bytes[OBJECT_BYTES], biometric[OBJECT_BYTES],
      face_biometric[OBJECT_BYTES], lds_content[OBJECT_BYTES];
  EVP_PKEY *private_key = ec_bits == 256   ? EVP_EC_gen("prime256v1")
                          : ec_bits == 384 ? EVP_EC_gen("secp384r1")
                                           : EVP_RSA_gen(2048);
  munit_assert_not_null(private_key);
  X509 *certificate = make_certificate(private_key, "Synthetic card", root);
  add_extension(certificate, NID_basic_constraints, "critical,CA:FALSE");
  add_extension(certificate, NID_key_usage, "critical,digitalSignature");
  add_extension(certificate, NID_ext_key_usage,
                profile == TC_PIV_CARD ? "2.16.840.1.101.3.6.8"
                                       : "1.3.6.1.4.1.29138.6.8");
  add_card_identifiers(certificate,
                       (TC_bytes){test_card_fascn, sizeof test_card_fascn},
                       "urn:uuid:91be2094-f6dc-5349-8000-4090e49e505c");
  const TC_bytes card = {certificate_bytes,
                         encode_certificate(certificate, root_key, EVP_sha256(),
                                            certificate_bytes,
                                            sizeof certificate_bytes)};
  uint8_t alternate_eku_bytes[OBJECT_BYTES];
  X509 *alternate_eku_certificate = X509_dup(certificate);
  munit_assert_not_null(alternate_eku_certificate);
  const int eku_position =
      X509_get_ext_by_NID(alternate_eku_certificate, NID_ext_key_usage, -1);
  munit_assert_int(eku_position, >=, 0);
  X509_EXTENSION_free(X509_delete_ext(alternate_eku_certificate, eku_position));
  add_extension(alternate_eku_certificate, NID_ext_key_usage,
                profile == TC_PIV_CARD ? "1.3.6.1.4.1.29138.6.8"
                                       : "2.16.840.1.101.3.6.8");
  const TC_bytes alternate_eku_card = {
      alternate_eku_bytes,
      encode_certificate(alternate_eku_certificate, root_key, EVP_sha256(),
                         alternate_eku_bytes, sizeof alternate_eku_bytes)};
  X509_free(alternate_eku_certificate);
  uint8_t piv_auth_bytes[OBJECT_BYTES];
  X509 *piv_auth_certificate = X509_dup(certificate);
  munit_assert_not_null(piv_auth_certificate);
  GENERAL_NAMES *piv_auth_names =
      X509_get_ext_d2i(piv_auth_certificate, NID_subject_alt_name, NULL, NULL);
  GENERAL_NAME *cardholder_name = GENERAL_NAME_new();
  ASN1_IA5STRING *cardholder_uri = ASN1_IA5STRING_new();
  static const char cardholder_uuid[] =
      "urn:uuid:10213243-5465-4768-899a-abbccddeeff0";
  munit_assert_not_null(piv_auth_names);
  munit_assert_not_null(cardholder_name);
  munit_assert_not_null(cardholder_uri);
  munit_assert_int(ASN1_STRING_set(cardholder_uri, cardholder_uuid,
                                   (int)strlen(cardholder_uuid)),
                   ==, 1);
  GENERAL_NAME_set0_value(cardholder_name, GEN_URI, cardholder_uri);
  munit_assert_int(sk_GENERAL_NAME_push(piv_auth_names, cardholder_name), >, 0);
  munit_assert_int(X509_add1_ext_i2d(piv_auth_certificate, NID_subject_alt_name,
                                     piv_auth_names, 0, X509V3_ADD_REPLACE),
                   ==, 1);
  GENERAL_NAMES_free(piv_auth_names);
  const TC_bytes piv_auth_card = {
      piv_auth_bytes,
      encode_certificate(piv_auth_certificate, root_key, EVP_sha256(),
                         piv_auth_bytes, sizeof piv_auth_bytes)};
  X509_free(piv_auth_certificate);
  uint8_t absent_uuid_bytes[OBJECT_BYTES], expired_card_bytes[OBJECT_BYTES],
      wrong_identity_bytes[OBJECT_BYTES];
  X509 *absent_uuid_certificate = X509_dup(certificate);
  munit_assert_not_null(absent_uuid_certificate);
  GENERAL_NAMES *names = X509_get_ext_d2i(absent_uuid_certificate,
                                          NID_subject_alt_name, NULL, NULL);
  munit_assert_not_null(names);
  for (int i = sk_GENERAL_NAME_num(names) - 1; i >= 0; --i)
    if (sk_GENERAL_NAME_value(names, i)->type == GEN_URI)
      GENERAL_NAME_free(sk_GENERAL_NAME_delete(names, i));
  munit_assert_int(X509_add1_ext_i2d(absent_uuid_certificate,
                                     NID_subject_alt_name, names, 0,
                                     X509V3_ADD_REPLACE),
                   ==, 1);
  GENERAL_NAMES_free(names);
  const TC_bytes absent_uuid_card = {
      absent_uuid_bytes,
      encode_certificate(absent_uuid_certificate, root_key, EVP_sha256(),
                         absent_uuid_bytes, sizeof absent_uuid_bytes)};
  X509_free(absent_uuid_certificate);
  X509 *expired_certificate = X509_dup(certificate);
  munit_assert_not_null(expired_certificate);
  munit_assert_int(
      ASN1_TIME_set_string_X509(X509_getm_notAfter(expired_certificate),
                                "20250101000000Z"),
      ==, 1);
  const TC_bytes expired_card = {
      expired_card_bytes,
      encode_certificate(expired_certificate, root_key, EVP_sha256(),
                         expired_card_bytes, sizeof expired_card_bytes)};
  X509_free(expired_certificate);
  X509 *wrong_identity_certificate = X509_dup(certificate);
  munit_assert_not_null(wrong_identity_certificate);
  const int san_position =
      X509_get_ext_by_NID(wrong_identity_certificate, NID_subject_alt_name, -1);
  munit_assert_int(san_position, >=, 0);
  X509_EXTENSION_free(
      X509_delete_ext(wrong_identity_certificate, san_position));
  uint8_t wrong_fascn[sizeof test_card_fascn];
  memcpy(wrong_fascn, test_card_fascn, sizeof wrong_fascn);
  wrong_fascn[0] ^= 1;
  add_card_identifiers(wrong_identity_certificate,
                       (TC_bytes){wrong_fascn, sizeof wrong_fascn},
                       "urn:uuid:91be2094-f6dc-5349-8000-4090e49e505c");
  const TC_bytes wrong_identity_card = {
      wrong_identity_bytes,
      encode_certificate(wrong_identity_certificate, root_key, EVP_sha256(),
                         wrong_identity_bytes, sizeof wrong_identity_bytes)};
  X509_free(wrong_identity_certificate);
  uint8_t revoked_crl_bytes[OBJECT_BYTES];
  const TC_bytes revoked_crl = {revoked_crl_bytes,
                                encode_issuer_crl(root, root_key, certificate,
                                                  revoked_crl_bytes,
                                                  sizeof revoked_crl_bytes)};
  TC_TLV_frame crl_frames[16];
  TC_bytes crl_oids[16];
  TC_X509_workspace crl_parser = {crl_frames, 16, crl_oids, 16};
  TC_X509_crl_record revoked_record;
  TC_X509_crl_index revoked_index;
  size_t crl_work = WORK;
  munit_assert_int(TC_X509_crl_index_init(
                       &revoked_crl, 1, &content->options->parsing, &crl_parser,
                       &crl_work, &revoked_record, 1, &revoked_index),
                   ==, TC_TLV_OK);
  EVP_PKEY *wrong_root_key = EVP_EC_gen("prime256v1");
  munit_assert_not_null(wrong_root_key);
  X509 *wrong_root = X509_dup(root);
  munit_assert_not_null(wrong_root);
  munit_assert_int(X509_set_pubkey(wrong_root, wrong_root_key), ==, 1);
  uint8_t wrong_root_bytes[OBJECT_BYTES];
  const size_t wrong_root_length =
      encode_certificate(wrong_root, wrong_root_key, EVP_sha256(),
                         wrong_root_bytes, sizeof wrong_root_bytes);
  TC_X509_certificate parsed_wrong_root;
  munit_assert_int(TC_X509_read(wrong_root_bytes, wrong_root_length,
                                &content->options->parsing, &crl_parser,
                                &parsed_wrong_root),
                   ==, TC_TLV_OK);
  TC_X509_store_anchor wrong_anchor = {
      {parsed_wrong_root.subject, parsed_wrong_root.public_key},
      {{NULL, 0}, {NULL, 0}}};
  const TC_X509_store_source wrong_trust = {&wrong_anchor, 0, 1, NULL,
                                            crl_trust_anchor};
  X509_free(wrong_root);
  TC_PIV_CHUID parsed;
  munit_assert_int(TC_PIV_CHUID_read_profile(
                       chuid.data, chuid.length, TC_PIV_CHUID_CONTENTS,
                       profile == TC_PIV_CARD ? TC_CHUID_PROFILE_PIV
                                              : TC_CHUID_PROFILE_TWIC_SIGNED,
                       &parsed),
                   ==, TC_TLV_OK);
  const size_t biometric_length =
      encode_biometric(signer, signer_key, 0, parsed.fascn, parsed.card_uuid,
                       biometric, sizeof biometric);
  static const uint8_t piv_face_record[] = {
      'F',  'A', 'C', 0, '0', '1', '0', 0,    0,    0,    0,   50,   0,
      1,    0,   0,   0, 36,  0,   0,   0,    0,    0,    0,   0,    0,
      0,    1,   0,   0, 0,   0,   0,   0,    1,    0,    1,   0xa5, 2,
      0x58, 1,   2,   0, 0,   0,   0,   0xff, 0xd8, 0xff, 0xd9};
  uint8_t face_record[sizeof piv_face_record];
  memcpy(face_record, piv_face_record, sizeof face_record);
  if (profile != TC_PIV_CARD) {
    face_record[26] = face_record[27] = 0;
    face_record[34] = 0;
    face_record[36] = 1;
    face_record[37] = 18;
  }
  const size_t face_length = encode_biometric_record_parameters(
      signer, signer_key, 0, 0, parsed.fascn, parsed.card_uuid,
      (TC_bytes){face_record, sizeof face_record}, 0x0501, 2, 0x20,
      face_biometric, sizeof face_biometric);
  TC_validation_capacity capacity;
  TC_validation_workspace workspace;
  munit_assert_int(TC_validation_capacity_init(TC_VALIDATION_MICRO, &capacity),
                   ==, TC_RESULT_OK);
  munit_assert_int(
      TC_validation_workspace_init(
          &capacity, (TC_buffer){(uint8_t *)arena, sizeof arena}, &workspace),
      ==, TC_RESULT_OK);
  TC_validation_options card_options = *content->options;
  static const uint8_t piv_purpose[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 6, 8};
  static const uint8_t twic_purpose[] = {0x2b, 6,    1,    4, 1,
                                         0x81, 0xe3, 0x52, 6, 8};
  card_options.certificate.purpose =
      profile == TC_PIV_CARD ? (TC_bytes){piv_purpose, sizeof piv_purpose}
                             : (TC_bytes){twic_purpose, sizeof twic_purpose};
  TC_validation_options content_options = *content->options;
  content_options.certificate.purpose = (TC_bytes){NULL, 0};
  TC_validation_context card_context, content_context;
  munit_assert_int(TC_validation_context_init(&content->trust, &card_options,
                                              &workspace.credential,
                                              &card_context),
                   ==, TC_RESULT_OK);
  munit_assert_int(TC_validation_context_init(&content->trust, &content_options,
                                              &workspace.credential,
                                              &content_context),
                   ==, TC_RESULT_OK);
  int64_t now;
  munit_assert_int(TC_X509_time_to_unix(&card_options.at, &now), ==, TC_TLV_OK);
  workflow_proof proof = {
      private_key, &card_options.signatures, NULL, NULL, 0, 0, 0};
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
      EXAMPLE_CREDENTIAL_UNSUPPORTED, EXAMPLE_CREDENTIAL_VALID,
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
    const TC_TWIC_CCL_metadata metadata = {(uint64_t)now - 2,
                                           (uint64_t)now - 1};
    munit_assert_int(TC_TWIC_CCL_index_from_memory(&packed, 1, &index), ==,
                     TC_TWIC_CCL_OK);
    munit_assert_int(TC_TWIC_CCL_store_prepare(&slot, &index, &metadata), ==,
                     TC_TWIC_CCL_OK);
    munit_assert_int(TC_TWIC_CCL_store_publish(&store, 0, &slot), ==,
                     TC_TWIC_CCL_OK);
    munit_assert_int(TC_TWIC_CCL_store_acquire(&store, &held), ==,
                     TC_TWIC_CCL_OK);
    if (variant == SUPERSEDED_CCL) {
      munit_assert_int(
          TC_TWIC_CCL_store_prepare(&replacement, &index, &metadata), ==,
          TC_TWIC_CCL_OK);
      proof.ccl_store = &store;
      proof.replacement_ccl = &replacement;
    }
    ExampleCredentialValidationRequest request = {0};
    request.profile = profile;
    request.certificate = variant == ABSENT_UUID          ? absent_uuid_card
                          : variant == EXPIRED_CARD       ? expired_card
                          : variant == WRONG_IDENTITY     ? wrong_identity_card
                          : variant == ALTERNATE_EKU      ? alternate_eku_card
                          : variant == PIV_AUTHENTICATION ? piv_auth_card
                          : variant == PIV_AUTHENTICATION_TWIC_READER
                              ? absent_uuid_card
                              : card;
    request.chuid = chuid;
    request.chuid_encoding = TC_PIV_CHUID_CONTENTS;
    request.chuid_profile = profile == TC_PIV_CARD
                                ? TC_CHUID_PROFILE_PIV
                                : TC_CHUID_PROFILE_TWIC_SIGNED;
    if (variant == PIV_AUTHENTICATION ||
        variant == PIV_AUTHENTICATION_TWIC_READER)
      request.card_key = EXAMPLE_CREDENTIAL_PIV_AUTHENTICATION;
    if (variant == PIV_AUTHENTICATION_TWIC_READER ||
        variant == CARD_AUTHENTICATION_TWIC_READER)
      request.twic_reader_policy = 1;
    proof.expected_key = request.card_key;
    if (profile != TC_PIV_CARD) {
      request.ccl = held;
      request.freshness = (TC_TWIC_CCL_freshness_policy){
          (uint64_t)now, variant == STALE ? 0 : 60, 0};
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
    request.rsa_padding =
        variant == RSA_PSS ? EXAMPLE_CARD_RSA_PSS : EXAMPLE_CARD_RSA_V15;
    request.security =
        (ExampleCredentialSecurityInput){security,
                                         TC_PIV_SECURITY_CONTENTS,
                                         inventory,
                                         inventory_count,
                                         unsigned_chuid,
                                         TC_PIV_CHUID_CONTENTS,
                                         {lds_content, sizeof lds_content},
                                         printed};
    const ExampleCredentialBiometricInput biometric_inputs[] = {
        {{biometric, biometric_length},
         TC_PIV_CMS_BIOMETRIC,
         TC_PIV_CBEFF_FINGERPRINT_TEMPLATE,
         0},
        {{face_biometric, face_length},
         TC_PIV_CMS_BIOMETRIC,
         TC_PIV_CBEFF_FACE_IMAGE,
         0}};
    request.biometrics = biometric_inputs;
    request.biometric_count =
        sizeof biometric_inputs / sizeof *biometric_inputs;
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
            ? (profile == TC_PIV_CARD ? EXAMPLE_CREDENTIAL_INVALID
                                      : EXAMPLE_CREDENTIAL_VALID)
            : expected[variant];
    munit_assert_int(example_credential_validate(&request, &card_context,
                                                 &content_context, &work,
                                                 &result),
                     ==, wanted);
    const int accepted_variant =
        variant == VALID || variant == ABSENT_UUID || variant == RSA_PSS ||
        variant == PIV_AUTHENTICATION ||
        variant == PIV_AUTHENTICATION_TWIC_READER ||
        (variant == ALTERNATE_EKU && profile != TC_PIV_CARD);
    if (accepted_variant) {
      munit_assert_ptr_equal(result.card.certificate.encoded.data,
                             request.certificate.data);
      if (variant == ABSENT_UUID)
        munit_assert_size(result.identifiers.uuid_urn.length, ==, 0);
      munit_assert_true(result.has_security);
      munit_assert_ptr_equal(result.security.objects, inventory);
      munit_assert_int(result.has_printed, ==, printed.length != 0);
      if (printed.length)
        munit_assert_ptr_equal(result.printed.name.data, printed.data + 2);
      memset(arena, 0, sizeof arena);
      munit_assert_memory_equal(parsed.fascn.length,
                                result.chuid.object.fascn.data,
                                parsed.fascn.data);
      if (variant == VALID) {
        const unsigned calls = proof.calls;
        request.biometric_count = 4;
        work = WORK;
        munit_assert_int(example_credential_validate(&request, &card_context,
                                                     &content_context, &work,
                                                     &unchanged),
                         ==, EXAMPLE_CREDENTIAL_ERROR);
        request.biometric_count = 2;
        request.biometrics = NULL;
        munit_assert_int(example_credential_validate(&request, &card_context,
                                                     &content_context, &work,
                                                     &unchanged),
                         ==, EXAMPLE_CREDENTIAL_ERROR);
        const ExampleCredentialBiometricInput duplicates[] = {
            biometric_inputs[0], biometric_inputs[0]};
        request.biometrics = duplicates;
        munit_assert_int(example_credential_validate(&request, &card_context,
                                                     &content_context, &work,
                                                     &unchanged),
                         ==, EXAMPLE_CREDENTIAL_ERROR);
        request.biometrics = biometric_inputs;
        const TC_PIV_security_data *security_objects = request.security.objects;
        request.security.objects = NULL;
        work = WORK;
        munit_assert_int(example_credential_validate(&request, &card_context,
                                                     &content_context, &work,
                                                     &unchanged),
                         ==, EXAMPLE_CREDENTIAL_ERROR);
        request.security.objects = security_objects;
        request.required_objects |= 1u << 31;
        work = WORK;
        munit_assert_int(example_credential_validate(&request, &card_context,
                                                     &content_context, &work,
                                                     &unchanged),
                         ==, EXAMPLE_CREDENTIAL_ERROR);
        request.required_objects &= ~(1u << 31);
        request.required_objects |= EXAMPLE_CREDENTIAL_REQUIRE_IRIS;
        work = WORK;
        munit_assert_int(example_credential_validate(&request, &card_context,
                                                     &content_context, &work,
                                                     &unchanged),
                         ==, EXAMPLE_CREDENTIAL_UNAVAILABLE);
        request.required_objects &= ~EXAMPLE_CREDENTIAL_REQUIRE_IRIS;
        munit_assert_uint(proof.calls, ==, calls);
        if (profile != TC_PIV_CARD) {
          request.profile = TC_TWIC_LEGACY_CARD;
          work = WORK;
          munit_assert_int(example_credential_validate(&request, &card_context,
                                                       &content_context, &work,
                                                       &unchanged),
                           ==, EXAMPLE_CREDENTIAL_INVALID);
        }
      }
    } else
      munit_assert_memory_equal(sizeof result, &result, &unchanged);
    if (variant == CANCELLED || variant == STALE || variant == EXHAUSTED ||
        variant == MISSING_CRL || variant == REVOKED_CARD ||
        variant == EXPIRED_CARD || variant == WRONG_IDENTITY ||
        variant == WRONG_ROOT || variant == MISSING_REQUIRED ||
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

static MunitResult chuid_signature(const MunitParameter params[], void *user) {
  enum {
    OBJECT_BYTES = 4096,
    CERT_BYTES = 1024,
    PREFIX_BYTES = 55,
    CMS_HEADER_BYTES = 4,
    FRAME_COUNT = 16,
    OID_COUNT = 16,
    WORK = 100000
  };
  uint8_t encoded[OBJECT_BYTES] = {0x30, 25}, certificate_bytes[CERT_BYTES],
          root_bytes[CERT_BYTES];
  memcpy(encoded + 2, test_card_fascn, sizeof test_card_fascn);
  uint8_t content[PREFIX_BYTES + 2], digest[TC_SHA256_DIGESTLEN];
  static const uint8_t content_type[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 6, 1};
  TC_TLV_frame frames[FRAME_COUNT];
  TC_bytes oids[OID_COUNT];
  const TC_TLV_limits limits = {OBJECT_BYTES, OBJECT_BYTES, 256, FRAME_COUNT};
  TC_X509_workspace parser = {frames, FRAME_COUNT, oids, OID_COUNT};
  TC_ECDSA_workspace ec;
  TC_RSA_word rsa_words[TC_RSA_VERIFY_WORKSPACE_WORDS(3072)];
  const TC_RSA_workspace rsa = {rsa_words,
                                sizeof rsa_words / sizeof *rsa_words};
  const TC_X509_native_workspace native = {
      &ec, &rsa, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  const TC_X509_signature_provider provider = TC_X509_native_provider(&native);
  const TC_CMS_signature_workspace verification = {frames, FRAME_COUNT, NULL,
                                                   0};
  EVP_PKEY *key = EVP_EC_gen("prime256v1");
  EVP_PKEY *root_key = EVP_EC_gen("prime256v1");
  munit_assert_not_null(key);
  munit_assert_not_null(root_key);
  X509 *root = make_certificate(root_key, "CHUID root", NULL);
  add_extension(root, NID_basic_constraints, "critical,CA:TRUE");
  add_extension(root, NID_key_usage, "critical,keyCertSign,cRLSign");
  const TC_bytes root_der = {root_bytes,
                             encode_certificate(root, root_key, EVP_sha256(),
                                                root_bytes, sizeof root_bytes)};
  X509 *certificate = make_certificate(key, "CHUID signer", root);
  add_extension(certificate, NID_basic_constraints, "critical,CA:FALSE");
  add_extension(certificate, NID_key_usage, "critical,digitalSignature");
  const char *signer_profile = munit_parameters_get(params, "signer-profile");
  const int twic_purpose = !strcmp(signer_profile, "twic");
  const int wrong_signer_name = !strcmp(signer_profile, "wrong-name");
  add_extension(certificate, NID_ext_key_usage,
                twic_purpose ? "1.3.6.1.4.1.29138.6.7"
                             : "2.16.840.1.101.3.6.7");
  const char *signing_policy = munit_parameters_get(params, "policy");
  if (strcmp(signing_policy, "absent"))
    add_extension(certificate, NID_certificate_policies,
                  !strcmp(signing_policy, "required")
                      ? "2.16.840.1.101.3.2.1.3.39"
                  : !strcmp(signing_policy, "any") ? "2.5.29.32.0"
                                                   : "1.2.3.4");
  size_t certificate_length =
      encode_certificate(certificate, root_key, EVP_sha256(), certificate_bytes,
                         sizeof certificate_bytes);
  TC_X509_certificate signer_certificate;
  munit_assert_int(TC_X509_read(certificate_bytes, certificate_length, &limits,
                                &parser, &signer_certificate),
                   ==, TC_TLV_OK);
  encoded[27] = 0x34;
  encoded[28] = 16;
  static const uint8_t card_guid[] = {0x91, 0xbe, 0x20, 0x94, 0xf6, 0xdc,
                                      0x53, 0x49, 0x80, 0,    0x40, 0x90,
                                      0xe4, 0x9e, 0x50, 0x5c};
  memcpy(encoded + 29, card_guid, sizeof card_guid);
  encoded[45] = 0x35;
  encoded[46] = 8;
  memcpy(encoded + 47, "20260101", 8);
  memcpy(content, encoded, PREFIX_BYTES);
  content[PREFIX_BYTES] = 0xfe;
  content[PREFIX_BYTES + 1] = 0;
  const unsigned flags = CMS_BINARY | CMS_NOSMIMECAP | CMS_DETACHED;
  CMS_ContentInfo *cms =
      CMS_sign(certificate, key, NULL, NULL, flags | CMS_PARTIAL);
  BIO *input = BIO_new_mem_buf(content, sizeof content);
  ASN1_OBJECT *oid = OBJ_txt2obj("2.16.840.1.101.3.6.1", 1);
  munit_assert_not_null(cms);
  munit_assert_not_null(input);
  munit_assert_not_null(oid);
  munit_assert_int(CMS_set1_eContentType(cms, oid), ==, 1);
  set_cms_signer_name(
      cms, X509_get_subject_name(wrong_signer_name ? root : certificate));
  const char *fascn_namespace = munit_parameters_get(params, "fascn");
  const int has_fascn = strcmp(fascn_namespace, "absent") != 0;
  const int has_uuid =
      strcmp(munit_parameters_get(params, "uuid"), "present") == 0;
  if (has_fascn)
    add_cms_octet_attribute(cms,
                            strcmp(fascn_namespace, "twic") == 0
                                ? "1.3.6.1.4.1.29138.6.6"
                                : "2.16.840.1.101.3.6.6",
                            encoded + 2, encoded[1]);
  if (has_uuid)
    add_cms_octet_attribute(cms, "1.3.6.1.1.16.4", encoded + 29, encoded[28]);
  munit_assert_int(CMS_final(cms, input, NULL, flags), ==, 1);
  int cms_length = i2d_CMS_ContentInfo(cms, NULL);
  munit_assert_int(cms_length, >, 0);
  munit_assert_size((size_t)cms_length, <=,
                    sizeof encoded - PREFIX_BYTES - CMS_HEADER_BYTES - 2);
  encoded[PREFIX_BYTES] = 0x3e;
  encoded[PREFIX_BYTES + 1] = 0x82;
  encoded[PREFIX_BYTES + 2] = (uint8_t)((unsigned)cms_length >> 8);
  encoded[PREFIX_BYTES + 3] = (uint8_t)cms_length;
  unsigned char *cursor = encoded + PREFIX_BYTES + CMS_HEADER_BYTES;
  munit_assert_int(i2d_CMS_ContentInfo(cms, &cursor), ==, cms_length);
  *cursor++ = 0xfe;
  *cursor++ = 0;
  const size_t length = (size_t)(cursor - encoded);
  for (unsigned profile = TC_CHUID_PROFILE_PIV;
       profile <= TC_CHUID_PROFILE_TWIC_SIGNED; ++profile) {
    TC_PIV_CHUID chuid;
    TC_PIV_CMS_object object;
    size_t work = WORK;
    munit_assert_int(
        TC_PIV_CHUID_read_profile(encoded, length, TC_PIV_CHUID_CONTENTS,
                                  (TC_PIV_CHUID_profile)profile, &chuid),
        ==, TC_TLV_OK);
    munit_assert_int(TC_PIV_CMS_read(chuid.signature, TC_PIV_CMS_CHUID,
                                     TC_PIV_OIDS_TWIC_COMPATIBLE,
                                     TC_CMS_ATTRIBUTES_DER, &limits, frames,
                                     FRAME_COUNT, &work, &object),
                     ==, TC_TLV_OK);
    TC_CMS_signer_info signer = object.signer;
    TC_CMS_signed_attributes attributes = object.attributes;
    munit_assert_size(object.certificate.length, ==, certificate_length);
    munit_assert_memory_equal(certificate_length, object.certificate.data,
                              certificate_bytes);
    /* Authenticate the detached object and check its content signer's CRL. */
    {
      enum {
        CLEAR,
        REVOKED,
        WRONG_ROOT,
        ALTERED_CONTENT,
        TRUST_CASES,
        TRUST_WORK = 1000000
      };
      static const uint8_t content_signing[] = {0x60, 0x86, 0x48, 1,
                                                0x65, 3,    6,    7};
      static const uint8_t twic_content_signing[] = {0x2b, 6,    1,    4, 1,
                                                     0x81, 0xe3, 0x52, 6, 7};
      TC_X509_certificate parsed_root;
      munit_assert_int(TC_X509_read(root_der.data, root_der.length, &limits,
                                    &parser, &parsed_root),
                       ==, TC_TLV_OK);
      TC_X509_store_anchor anchor = {
          {parsed_root.subject, parsed_root.public_key},
          {{NULL, 0}, {NULL, 0}}};
      const TC_X509_store_source anchors = {&anchor, 0, 1, NULL,
                                            crl_trust_anchor};
      candidate_source supplied = {&root_der, 1, 0, TC_TLV_OK, 0};
      const TC_X509_store_source issuers = {&supplied, 1, 0, read_candidate,
                                            NULL};
      combined_store_source combined = {&issuers, &anchors};
      const TC_X509_store_source source = {&combined, 1, 1, combined_candidate,
                                           combined_anchor};
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
      options.path.purpose =
          twic_purpose
              ? (TC_bytes){twic_content_signing, sizeof twic_content_signing}
              : (TC_bytes){content_signing, sizeof content_signing};
      options.path.key_usage = TC_KEY_USAGE_DIGITAL_SIGNATURE;
      options.path.flags = TC_X509_PATH_REQUIRE_KEY_USAGE |
                           TC_X509_PATH_REQUIRE_EXTENDED_KEY_USAGE |
                           TC_X509_PATH_INHIBIT_ANY_PURPOSE;
      options.max_candidates = EXAMPLE_CMS_CERTIFICATE_CAPACITY;
      options.max_candidate_bytes = OBJECT_BYTES;
      options.attributes = TC_CMS_ATTRIBUTES_DER;
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
        const TC_bytes crl = {
            crl_bytes,
            encode_issuer_crl(root, root_key,
                              variant == REVOKED ? certificate : NULL,
                              crl_bytes, sizeof crl_bytes)};
        TC_X509_crl_record record;
        TC_X509_crl_index index;
        work = TRUST_WORK;
        munit_assert_int(TC_X509_crl_index_init(&crl, 1, &limits, &parser,
                                                &work, &record, 1, &index),
                         ==, TC_TLV_OK);
        const TC_CMS_revocation_policy revocation = {
            &index, &crl_policy, OBJECT_BYTES, TC_X509_CRL_COMPLETE_ONLY,
            TC_X509_CRL_ORDER_NUMBER};
        if (variant == WRONG_ROOT)
          anchor.trust.public_key = signer_certificate.public_key;
        if (variant == ALTERED_CONTENT)
          encoded[29] ^= 1;
        work = TRUST_WORK;
        munit_assert_int(example_validate_cms_from_store(&request, &store,
                                                         &options, &revocation,
                                                         &work, &storage),
                         ==,
                         wrong_signer_name    ? TC_CREDENTIAL_INVALID
                         : variant == CLEAR   ? TC_CREDENTIAL_VALID
                         : variant == REVOKED ? TC_CREDENTIAL_REVOKED
                                              : TC_CREDENTIAL_INVALID);
        munit_assert_size(slot.readers, ==, 0);
        TC_X509_store_snapshot *held;
        munit_assert_int(TC_X509_store_acquire(&store, &held), ==, TC_TLV_OK);
        static const uint8_t uuid_urn[] =
            "urn:uuid:91be2094-f6dc-5349-8000-4090e49e505c";
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
        TC_CMS_path_workspace object_path =
            example_cms_path_workspace(&storage.cms);
        const TC_CMS_credential_workspace object_workspace =
            example_cms_credential_workspace(&storage, &object_path);
        TC_validation_options object_options;
        munit_assert_int(
            example_validation_options(&options, &revocation, &object_options),
            ==, TC_RESULT_OK);
        const TC_validation_trust object_trust = {&held->source,
                                                  revocation.index};
        TC_validation_context object_context;
        munit_assert_int(
            TC_validation_context_init(&object_trust, &object_options,
                                       &object_workspace, &object_context),
            ==, TC_RESULT_OK);
        TC_PIV_CHUID_result accepted_chuid;
        memset(&accepted_chuid, 0xa5, sizeof accepted_chuid);
        TC_PIV_CHUID_result saved_chuid;
        memcpy(&saved_chuid, &accepted_chuid, sizeof saved_chuid);
        work = TRUST_WORK;
        const int profile_rejected = profile == TC_CHUID_PROFILE_PIV &&
                                     (!strcmp(fascn_namespace, "twic") ||
                                      strcmp(signing_policy, "required"));
        const int purpose_rejected =
            profile == TC_CHUID_PROFILE_PIV && twic_purpose;
        memset(&storage, 0xa5, sizeof storage);
        const uint8_t *wiped = (const uint8_t *)&storage;
        munit_assert_int(TC_PIV_CHUID_validate(&object_request, &object_context,
                                               &work, &accepted_chuid),
                         ==,
                         purpose_rejected ? TC_CREDENTIAL_ERROR
                         : profile_rejected || wrong_signer_name
                             ? TC_CREDENTIAL_INVALID
                         : variant == CLEAR   ? TC_CREDENTIAL_VALID
                         : variant == REVOKED ? TC_CREDENTIAL_REVOKED
                                              : TC_CREDENTIAL_INVALID);
        if (purpose_rejected)
          munit_assert_size(work, ==, TRUST_WORK);
        if (!purpose_rejected && !profile_rejected && !wrong_signer_name &&
            variant == CLEAR) {
          munit_assert_ptr_equal(accepted_chuid.object.fascn.data,
                                 chuid.fascn.data);
          munit_assert_size(accepted_chuid.signer.length, ==,
                            object.certificate.length);
          munit_assert_memory_equal(accepted_chuid.signer.length,
                                    accepted_chuid.signer.data,
                                    object.certificate.data);
          munit_assert_int(accepted_chuid.profile, ==, object_request.profile);
          TC_X509_validation_result signer_result;
          size_t certificate_work = TRUST_WORK;
          munit_assert_int(TC_X509_validate(accepted_chuid.signer,
                                            &object_context, &certificate_work,
                                            &signer_result),
                           ==, TC_CREDENTIAL_VALID);
          munit_assert_ptr_equal(signer_result.certificate.encoded.data,
                                 accepted_chuid.signer.data);
          munit_assert_int(signer_result.at.year, ==, object_options.at.year);
          if (object_request.profile != TC_PIV_CARD) {
            TC_validation_options alias_options = object_options;
            alias_options.certificate.purpose =
                twic_purpose
                    ? (TC_bytes){content_signing, sizeof content_signing}
                    : (TC_bytes){twic_content_signing,
                                 sizeof twic_content_signing};
            TC_validation_context alias_context;
            munit_assert_int(
                TC_validation_context_init(&object_trust, &alias_options,
                                           &object_workspace, &alias_context),
                ==, TC_RESULT_OK);
            TC_PIV_CHUID_result alias_result;
            size_t alias_work = TRUST_WORK;
            munit_assert_int(TC_PIV_CHUID_validate(&object_request,
                                                   &alias_context, &alias_work,
                                                   &alias_result),
                             ==, TC_CREDENTIAL_VALID);
          }
          memset(&storage, 0, sizeof storage);
          munit_assert_memory_equal(accepted_chuid.signer.length,
                                    accepted_chuid.signer.data,
                                    object.certificate.data);
        } else
          munit_assert_memory_equal(sizeof saved_chuid, &saved_chuid,
                                    &accepted_chuid);
        if (variant == CLEAR && !strcmp(fascn_namespace, "piv") && has_uuid &&
            !strcmp(signing_policy, "required") &&
            !strcmp(signer_profile, "piv")) {
          const size_t chuid_work = work;
          {
            uint8_t security[OBJECT_BYTES];
            uint8_t unsigned_chuid[PREFIX_BYTES + 2];
            memcpy(unsigned_chuid, encoded, PREFIX_BYTES);
            unsigned_chuid[PREFIX_BYTES] = 0xfe;
            unsigned_chuid[PREFIX_BYTES + 1] = 0;
            const TC_bytes contents[] = {
                {encoded, length}, {unsigned_chuid, sizeof unsigned_chuid}};
            /* GET DATA's response wrapper is outside the stored object content.
             */
            const uint8_t response_header[] = {
                0x53, 0x82, (uint8_t)(length >> 8), (uint8_t)length};
            const TC_bytes wrapped[] = {
                {response_header, sizeof response_header}, contents[0]};
            const TC_bytes without_check = {unsigned_chuid, PREFIX_BYTES};
            const size_t security_length = encode_security_object(
                certificate, key, contents, security, sizeof security);
            ExampleSecurityData inventory[] = {{0x3000, &contents[0], 1},
                                               {0x3002, &contents[1], 1}};
            ExampleSecurityRequest security_request = {
                {security, security_length},
                TC_PIV_SECURITY_CONTENTS,
                object_request.profile,
                object.certificate,
                &card_expiration,
                inventory,
                2};
            ExampleSecurityWorkspace security_storage;
            work = TRUST_WORK;
            munit_assert_int(example_validate_security(
                                 &security_request, held, &options, &revocation,
                                 &work, &security_storage),
                             ==, TC_CREDENTIAL_VALID);
            const uint8_t *cleared = (const uint8_t *)&security_storage;
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
              uint8_t printed_cipher[64], biometric_cipher[34],
                  mixed_security[OBJECT_BYTES];
              memcpy(printed_cipher, printed, sizeof printed);
              memcpy(biometric_cipher + 2, record, sizeof record);
              size_t printed_length, biometric_length;
              munit_assert_int(TC_TWIC_object_encrypt(
                                   &privacy_key, printed_cipher, sizeof printed,
                                   sizeof printed_cipher, &printed_length),
                               ==, TC_OK);
              munit_assert_int(TC_TWIC_object_encrypt(
                                   &privacy_key, biometric_cipher + 2,
                                   sizeof record, sizeof biometric_cipher - 2,
                                   &biometric_length),
                               ==, TC_OK);
              biometric_cipher[0] = 0xbc;
              biometric_cipher[1] = (uint8_t)biometric_length;
              const uint16_t containers[] = {0x3001, 0x2003};
              const TC_bytes selected[] = {
                  {printed, sizeof printed},
                  {biometric_cipher, biometric_length + 2}};
              const size_t mixed_length = encode_security_inventory(
                  certificate, key, containers, selected, 2, mixed_security,
                  sizeof mixed_security);
              TC_bytes supplied[] = {selected[0], selected[1]};
              ExampleSecurityData mixed_inventory[] = {
                  {containers[0], &supplied[0], 1},
                  {containers[1], &supplied[1], 1}};
              ExampleSecurityRequest mixed_request = {
                  {mixed_security, mixed_length},
                  TC_PIV_SECURITY_CONTENTS,
                  TC_TWIC_NEXGEN_CARD,
                  object.certificate,
                  &card_expiration,
                  mixed_inventory,
                  2};
              for (unsigned choice = 0; choice < 3; ++choice) {
                supplied[0] = choice == 1
                                  ? (TC_bytes){printed_cipher, printed_length}
                                  : selected[0];
                supplied[1] = choice == 2 ? (TC_bytes){record, sizeof record}
                                          : selected[1];
                work = TRUST_WORK;
                munit_assert_int(
                    example_validate_security(&mixed_request, held, &options,
                                              &revocation, &work,
                                              &security_storage),
                    ==,
                    choice == 0 ? TC_CREDENTIAL_VALID : TC_CREDENTIAL_INVALID);
              }
              const uint16_t full_containers[] = {0x3000, 0x3002, 0x3001};
              const TC_bytes full_contents[] = {
                  contents[0], contents[1], {printed, sizeof printed}};
              const size_t full_length = encode_security_inventory(
                  certificate, key, full_containers, full_contents, 3,
                  mixed_security, sizeof mixed_security);
              ExampleSecurityData full_inventory[] = {
                  {full_containers[0], &full_contents[0], 1},
                  {full_containers[1], &full_contents[1], 1},
                  {full_containers[2], &full_contents[2], 1}};
              credential_public_workflow(
                  root, root_key, certificate, key, TC_TWIC_NEXGEN_CARD, 0,
                  contents[0], (TC_bytes){mixed_security, full_length},
                  full_inventory, 3, contents[1], full_contents[2],
                  &object_context);
            }
            if (object_request.profile != TC_PIV_CARD) {
              TC_CMS_path_workspace security_path =
                  example_cms_path_workspace(&security_storage.credential.cms);
              const TC_CMS_credential_workspace security_credential =
                  example_cms_credential_workspace(&security_storage.credential,
                                                   &security_path);
              const TC_PIV_security_validation_workspace security_workspace = {
                  security_storage.content, sizeof security_storage.content};
              TC_validation_context security_context;
              const TC_TWIC_unsigned_CHUID_validation_request unsigned_request =
                  {contents[1], TC_PIV_CHUID_CONTENTS, object_request.profile,
                   &card};
              munit_assert_int(TC_validation_context_init(
                                   &object_trust, &object_options,
                                   &security_credential, &security_context),
                               ==, TC_RESULT_OK);
              work = TRUST_WORK;
              TC_PIV_security_result accepted_security;
              munit_assert_int(
                  TC_PIV_security_validate(&security_request, &security_context,
                                           &security_workspace, &work,
                                           &accepted_security),
                  ==, TC_CREDENTIAL_VALID);
              munit_assert_int(TC_TWIC_unsigned_CHUID_validate(
                                   &unsigned_request, &accepted_security,
                                   &security_context, &work),
                               ==, TC_CREDENTIAL_VALID);
              munit_assert_ptr_equal(accepted_security.objects, inventory);
              memset(&security_storage, 0, sizeof security_storage);
              munit_assert_int(TC_TWIC_unsigned_CHUID_validate(
                                   &unsigned_request, &accepted_security,
                                   &security_context, &work),
                               ==, TC_CREDENTIAL_VALID);
              /* Counter aliases must leave the retained evidence unchanged. */
              TC_TWIC_unsigned_CHUID_validation_request overlapping_request =
                  unsigned_request;
              const size_t encoded_length = overlapping_request.encoded.length;
              munit_assert_int(TC_TWIC_unsigned_CHUID_validate(
                                   &overlapping_request, &accepted_security,
                                   &security_context,
                                   &overlapping_request.encoded.length),
                               ==, TC_CREDENTIAL_ERROR);
              munit_assert_size(overlapping_request.encoded.length, ==,
                                encoded_length);
              const size_t part_length = contents[1].length;
              munit_assert_int(TC_TWIC_unsigned_CHUID_validate(
                                   &unsigned_request, &accepted_security,
                                   &security_context,
                                   (size_t *)&contents[1].length),
                               ==, TC_CREDENTIAL_ERROR);
              munit_assert_size(contents[1].length, ==, part_length);
              const size_t signer_length = accepted_security.signer.length;
              munit_assert_int(TC_TWIC_unsigned_CHUID_validate(
                                   &unsigned_request, &accepted_security,
                                   &security_context,
                                   &accepted_security.signer.length),
                               ==, TC_CREDENTIAL_ERROR);
              munit_assert_size(accepted_security.signer.length, ==,
                                signer_length);
              const size_t input_limit = object_options.parsing.max_input;
              munit_assert_int(TC_TWIC_unsigned_CHUID_validate(
                                   &unsigned_request, &accepted_security,
                                   &security_context,
                                   &object_options.parsing.max_input),
                               ==, TC_CREDENTIAL_ERROR);
              munit_assert_size(object_options.parsing.max_input, ==,
                                input_limit);
              TC_validation_options next_time = object_options;
              next_time.at.second = 1;
              TC_validation_context later_context = security_context;
              later_context.options = &next_time;
              munit_assert_int(TC_TWIC_unsigned_CHUID_validate(
                                   &unsigned_request, &accepted_security,
                                   &later_context, &work),
                               ==, TC_CREDENTIAL_ERROR);
              const size_t before_overlap = work;
              munit_assert_int(
                  TC_PIV_security_validate(
                      &security_request, &security_context, &security_workspace,
                      &work,
                      (TC_PIV_security_result *)security_storage.content),
                  ==, TC_CREDENTIAL_ERROR);
              munit_assert_size(work, ==, before_overlap);
              credential_public_workflow(
                  root, root_key, certificate, key, object_request.profile, 0,
                  contents[0], (TC_bytes){security, security_length}, inventory,
                  2, contents[1], (TC_bytes){0}, &object_context);
            }
            if (object_request.profile == TC_PIV_CARD)
              credential_public_workflow(
                  root, root_key, certificate, key, TC_PIV_CARD, 0, contents[0],
                  (TC_bytes){security, security_length}, inventory, 2,
                  (TC_bytes){0}, (TC_bytes){0}, &object_context);
            if (object_request.profile == TC_PIV_CARD)
              credential_public_workflow(
                  root, root_key, certificate, key, TC_PIV_CARD, 256,
                  contents[0], (TC_bytes){security, security_length}, inventory,
                  2, (TC_bytes){0}, (TC_bytes){0}, &object_context);
            if (object_request.profile == TC_PIV_CARD)
              credential_public_workflow(
                  root, root_key, certificate, key, TC_PIV_CARD, 384,
                  contents[0], (TC_bytes){security, security_length}, inventory,
                  2, (TC_bytes){0}, (TC_bytes){0}, &object_context);
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
              inventory[1].parts =
                  failure == WRONG_BYTES ? &contents[0] : &contents[1];
              inventory[0].parts =
                  failure == RESPONSE_WRAPPER ? wrapped : &contents[0];
              inventory[0].count = failure == RESPONSE_WRAPPER ? 2 : 1;
              if (failure == EMPTY_PARTS)
                inventory[0].count = 0;
              if (failure == OMITTED_CHECK)
                inventory[1].parts = &without_check;
              security_request.chuid_signer =
                  failure == WRONG_SIGNER ? root_der : object.certificate;
              if (failure == WRONG_MAP)
                security[4] = 1;
              work = failure == NO_WORK ? 0 : TRUST_WORK;
              munit_assert_int(
                  example_validate_security(&security_request, held, &options,
                                            &revocation, &work,
                                            &security_storage),
                  ==,
                  failure == NO_WORK       ? TC_CREDENTIAL_LIMIT
                  : failure == EMPTY_PARTS ? TC_CREDENTIAL_ERROR
                                           : TC_CREDENTIAL_INVALID);
              if (failure == MISSING || failure == DUPLICATE ||
                  failure == EMPTY_PARTS)
                munit_assert_size(work, ==, TRUST_WORK);
              security[4] = 0;
            }
            work = TRUST_WORK;
            uint8_t revoked_crl_bytes[CERT_BYTES];
            const TC_bytes revoked_crl = {
                revoked_crl_bytes,
                encode_issuer_crl(root, root_key, certificate,
                                  revoked_crl_bytes, sizeof revoked_crl_bytes)};
            TC_X509_crl_record revoked_record;
            TC_X509_crl_index revoked_index;
            munit_assert_int(
                TC_X509_crl_index_init(&revoked_crl, 1, &limits, &parser, &work,
                                       &revoked_record, 1, &revoked_index),
                ==, TC_TLV_OK);
            TC_CMS_revocation_policy revoked_options = revocation;
            revoked_options.index = &revoked_index;
            work = TRUST_WORK;
            munit_assert_int(example_validate_security(
                                 &security_request, held, &options,
                                 &revoked_options, &work, &security_storage),
                             ==, TC_CREDENTIAL_REVOKED);
          }
          uint8_t biometric[OBJECT_BYTES];
          const size_t biometric_length =
              encode_biometric(certificate, key, 0, chuid.fascn,
                               chuid.card_uuid, biometric, sizeof biometric);
          ExampleBiometricRequest biometric_request = {
              {biometric, biometric_length},
              object_request.profile,
              chuid.fascn,
              chuid.card_uuid,
              object.certificate,
              &card_expiration,
              TC_PIV_CMS_BIOMETRIC,
              TC_PIV_CBEFF_FINGERPRINT_TEMPLATE,
              0};
          {
            uint8_t encrypted[OBJECT_BYTES], recovered[OBJECT_BYTES];
            const TC_TWIC_tpk privacy_key = {
                {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}};
            EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();
            munit_assert_not_null(cipher);
            munit_assert_int(EVP_EncryptInit_ex(cipher, EVP_aes_128_ecb(), NULL,
                                                privacy_key.key, NULL),
                             ==, 1);
            int written, tail;
            munit_assert_int(EVP_EncryptUpdate(cipher, encrypted, &written,
                                               biometric,
                                               (int)biometric_length),
                             ==, 1);
            munit_assert_int(
                EVP_EncryptFinal_ex(cipher, encrypted + written, &tail), ==, 1);
            const size_t encrypted_length = (size_t)written + (size_t)tail;
            EVP_CIPHER_CTX_free(cipher);
            for (unsigned wrong_key = 0; wrong_key < 2; ++wrong_key) {
              TC_TWIC_tpk selected_key = privacy_key;
              selected_key.key[0] ^= (uint8_t)wrong_key;
              memcpy(recovered, encrypted, encrypted_length);
              size_t plaintext_length = 0;
              TC_credential_status authenticated = TC_CREDENTIAL_INVALID;
              if (TC_TWIC_object_decrypt(&selected_key, recovered,
                                         encrypted_length,
                                         &plaintext_length) == TC_OK) {
                ExampleBiometricRequest decrypted = biometric_request;
                decrypted.encoded = (TC_bytes){recovered, plaintext_length};
                work = TRUST_WORK;
                authenticated = example_validate_biometric(
                    &decrypted, held, &options, &revocation, &work, &storage);
              }
              if (wrong_key)
                munit_assert_int(authenticated, !=, TC_CREDENTIAL_VALID);
              else {
                munit_assert_int(authenticated, ==, TC_CREDENTIAL_VALID);
                munit_assert_size(plaintext_length, ==, biometric_length);
                munit_assert_memory_equal(biometric_length, recovered,
                                          biometric);
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
            uint8_t other_guid[16];
            memcpy(other_guid, chuid.card_uuid.data, sizeof other_guid);
            other_guid[0] ^= 1;
            if (check == BIO_RECORD)
              biometric[88] ^= 1;
            if (check == BIO_HEADER)
              biometric[59] ^= 1;
            if (check == BIO_GUID)
              changed.guid = (TC_bytes){other_guid, sizeof other_guid};
            if (check == BIO_SIGNER)
              changed.chuid_signer = root_der;
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
              biometric_crl_policy.at = biometric_options.path.at;
              biometric_revocation.signer_policy = &biometric_crl_policy;
            }
            work = check == BIO_WORK ? 0 : TRUST_WORK;
            memset(&storage, 0xa5, sizeof storage);
            munit_assert_int(
                example_validate_biometric(&changed, held, &biometric_options,
                                           &biometric_revocation, &work,
                                           &storage),
                ==,
                check == BIO_PROFILE ? TC_CREDENTIAL_ERROR
                : check == BIO_IRIS  ? TC_CREDENTIAL_UNSUPPORTED
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
                attributes & 2 ? chuid.card_uuid : empty, biometric,
                sizeof biometric);
            for (unsigned selected = 0; selected < 2; ++selected) {
              legacy.signature_profile =
                  selected ? TC_PIV_CMS_BIOMETRIC_LEGACY : TC_PIV_CMS_BIOMETRIC;
              work = TRUST_WORK;
              munit_assert_int(
                  example_validate_biometric(&legacy, held, &options,
                                             &revocation, &work, &storage),
                  ==,
                  (attributes & 1) && (selected || (attributes & 2))
                      ? TC_CREDENTIAL_VALID
                      : TC_CREDENTIAL_INVALID);
            }
          }
          EVP_PKEY *biometric_key = EVP_EC_gen("prime256v1");
          munit_assert_not_null(biometric_key);
          X509 *biometric_signer =
              make_certificate(biometric_key, "Biometric signer", root);
          munit_assert_int(
              ASN1_INTEGER_set(X509_get_serialNumber(biometric_signer), 2), ==,
              1);
          add_extension(biometric_signer, NID_basic_constraints,
                        "critical,CA:FALSE");
          add_extension(biometric_signer, NID_key_usage,
                        "critical,digitalSignature");
          add_extension(biometric_signer, NID_ext_key_usage,
                        "2.16.840.1.101.3.6.7");
          add_extension(biometric_signer, NID_certificate_policies,
                        "2.16.840.1.101.3.2.1.3.39");
          uint8_t biometric_certificate[CERT_BYTES];
          /* Reissued certificates still carry the same mathematical key. */
          for (unsigned reissued = 0; reissued < 3; ++reissued) {
            X509 *redundant = reissued ? biometric_signer : certificate;
            if (reissued) {
              munit_assert_int(
                  EVP_PKEY_set_utf8_string_param(
                      key, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                      reissued == 2 ? "compressed" : "uncompressed"),
                  ==, 1);
              munit_assert_int(X509_set_pubkey(redundant, key), ==, 1);
              const size_t redundant_length = encode_certificate(
                  redundant, root_key, EVP_sha256(), biometric_certificate,
                  sizeof biometric_certificate);
              TC_X509_certificate redundant_view;
              munit_assert_int(TC_X509_read(biometric_certificate,
                                            redundant_length, &limits, &parser,
                                            &redundant_view),
                               ==, TC_TLV_OK);
              munit_assert_size(redundant_view.public_key.key.length, ==,
                                reissued == 2 ? 33 : 65);
            }
            biometric_request.encoded.length =
                encode_biometric(redundant, key, 1, chuid.fascn,
                                 chuid.card_uuid, biometric, sizeof biometric);
            work = TRUST_WORK;
            munit_assert_int(
                example_validate_biometric(&biometric_request, held, &options,
                                           &revocation, &work, &storage),
                ==, TC_CREDENTIAL_INVALID);
          }
          munit_assert_int(EVP_PKEY_set_utf8_string_param(
                               key, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                               "uncompressed"),
                           ==, 1);
          munit_assert_int(X509_set_pubkey(biometric_signer, biometric_key), ==,
                           1);
          (void)encode_certificate(biometric_signer, root_key, EVP_sha256(),
                                   biometric_certificate,
                                   sizeof biometric_certificate);
          biometric_request.encoded.length =
              encode_biometric(biometric_signer, biometric_key, 1, chuid.fascn,
                               chuid.card_uuid, biometric, sizeof biometric);
          work = TRUST_WORK;
          munit_assert_int(example_validate_biometric(&biometric_request, held,
                                                      &options, &revocation,
                                                      &work, &storage),
                           ==, TC_CREDENTIAL_VALID);
          const size_t biometric_work = TRUST_WORK - work;
          work = biometric_work - 1;
          munit_assert_int(example_validate_biometric(&biometric_request, held,
                                                      &options, &revocation,
                                                      &work, &storage),
                           ==, TC_CREDENTIAL_LIMIT);
          TC_CMS_path_options bounded = options;
          bounded.path.parsing.max_input = biometric_request.encoded.length - 1;
          work = TRUST_WORK;
          munit_assert_int(example_validate_biometric(&biometric_request, held,
                                                      &bounded, &revocation,
                                                      &work, &storage),
                           ==, TC_CREDENTIAL_LIMIT);
          {
            uint8_t revoked_bytes[CERT_BYTES];
            const TC_bytes revoked_crl = {
                revoked_bytes,
                encode_issuer_crl(root, root_key, biometric_signer,
                                  revoked_bytes, sizeof revoked_bytes)};
            TC_X509_crl_record revoked_record;
            TC_X509_crl_index revoked_index;
            work = TRUST_WORK;
            munit_assert_int(
                TC_X509_crl_index_init(&revoked_crl, 1, &limits, &parser, &work,
                                       &revoked_record, 1, &revoked_index),
                ==, TC_TLV_OK);
            TC_CMS_revocation_policy revoked_options = revocation;
            revoked_options.index = &revoked_index;
            work = TRUST_WORK;
            munit_assert_int(
                example_validate_biometric(&biometric_request, held, &options,
                                           &revoked_options, &work, &storage),
                ==, TC_CREDENTIAL_REVOKED);
          }
          /* Omission with a different signing key must fail CHUID signer
           * selection. */
          biometric_request.encoded.length =
              encode_biometric(biometric_signer, biometric_key, 0, chuid.fascn,
                               chuid.card_uuid, biometric, sizeof biometric);
          work = TRUST_WORK;
          munit_assert_int(example_validate_biometric(&biometric_request, held,
                                                      &options, &revocation,
                                                      &work, &storage),
                           ==, TC_CREDENTIAL_INVALID);
          EVP_PKEY_free(biometric_key);
          static const unsigned rsa_sizes[] = {1024, 2048, 3072};
          for (size_t size = 0; size < sizeof rsa_sizes / sizeof *rsa_sizes;
               ++size) {
            EVP_PKEY *rsa_key = EVP_RSA_gen(rsa_sizes[size]);
            munit_assert_not_null(rsa_key);
            munit_assert_int(X509_set_pubkey(biometric_signer, rsa_key), ==, 1);
            const size_t rsa_certificate_length = encode_certificate(
                biometric_signer, root_key, EVP_sha256(), biometric_certificate,
                sizeof biometric_certificate);
            const TC_bytes rsa_certificate = {biometric_certificate,
                                              rsa_certificate_length};
            biometric_request.chuid_signer = object.certificate;
            biometric_request.encoded.length =
                encode_biometric(biometric_signer, rsa_key, 1, chuid.fascn,
                                 chuid.card_uuid, biometric, sizeof biometric);
            work = TRUST_WORK;
            munit_assert_int(
                example_validate_biometric(&biometric_request, held, &options,
                                           &revocation, &work, &storage),
                ==, TC_CREDENTIAL_VALID);
            biometric_request.chuid_signer = rsa_certificate;
            work = TRUST_WORK;
            munit_assert_int(
                example_validate_biometric(&biometric_request, held, &options,
                                           &revocation, &work, &storage),
                ==, TC_CREDENTIAL_INVALID);
            biometric_request.encoded.length =
                encode_biometric(biometric_signer, rsa_key, 0, chuid.fascn,
                                 chuid.card_uuid, biometric, sizeof biometric);
            work = TRUST_WORK;
            munit_assert_int(
                example_validate_biometric(&biometric_request, held, &options,
                                           &revocation, &work, &storage),
                ==, TC_CREDENTIAL_VALID);
            EVP_PKEY_free(rsa_key);
          }
          X509_free(biometric_signer);
          work = chuid_work;
        }
        if (variant == CLEAR && !purpose_rejected && !profile_rejected &&
            !wrong_signer_name) {
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
              changed.encoded =
                  (TC_bytes){unsigned_chuid, sizeof unsigned_chuid};
              munit_assert_int(TC_PIV_CHUID_read_profile(
                                   unsigned_chuid, sizeof unsigned_chuid,
                                   TC_PIV_CHUID_CONTENTS,
                                   TC_CHUID_PROFILE_TWIC_UNSIGNED,
                                   &unsigned_view),
                               ==, TC_TLV_OK);
            }
            TC_PIV_card_identifiers other_card = card;
            uint8_t other_fascn[25];
            memcpy(other_fascn, chuid.fascn.data, sizeof other_fascn);
            other_fascn[0] ^= 1;
            static const uint8_t other_uuid[] =
                "urn:uuid:91be2094-f6dc-5349-8000-000000005678";
            const TC_X509_time later = {2029, 1, 1, 0, 0, 0};
            TC_CMS_path_options changed_options = options;
            TC_X509_path_options changed_crl_policy = crl_policy;
            TC_CMS_revocation_policy changed_revocation = revocation;
            changed.card = &other_card;
            if (check == WRONG_FASCN)
              other_card.fascn = (TC_bytes){other_fascn, sizeof other_fascn};
            if (check == WRONG_UUID)
              other_card.uuid_urn =
                  (TC_bytes){other_uuid, sizeof other_uuid - 1};
            if (check == LATE_CARD_EXPIRATION)
              changed.card_expiration = &later;
            if (check == LAST_SECOND)
              changed_options.path.at = (TC_X509_time){2026, 1, 1, 23, 59, 59};
            if (check == EXPIRED_DATE)
              changed_options.path.at.day = 2;
            changed_crl_policy.at = changed_options.path.at;
            changed_revocation.signer_policy = &changed_crl_policy;
            TC_validation_options changed_validation;
            munit_assert_int(example_validation_options(&changed_options,
                                                        &changed_revocation,
                                                        &changed_validation),
                             ==, TC_RESULT_OK);
            TC_validation_context changed_context;
            munit_assert_int(
                TC_validation_context_init(&object_trust, &changed_validation,
                                           &object_workspace, &changed_context),
                ==, TC_RESULT_OK);
            work = check == ZERO_WORK    ? 0
                   : check == SHORT_WORK ? required_work - 1
                                         : TRUST_WORK;
            const TC_credential_status expected =
                check == ZERO_WORK || check == SHORT_WORK ? TC_CREDENTIAL_LIMIT
                : check == LAST_SECOND || (check == LATE_CARD_EXPIRATION &&
                                           profile != TC_CHUID_PROFILE_PIV)
                    ? TC_CREDENTIAL_VALID
                    : TC_CREDENTIAL_INVALID;
            munit_assert_int(TC_PIV_CHUID_validate(&changed, &changed_context,
                                                   &work, &accepted_chuid),
                             ==, expected);
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
    munit_assert_int(TC_PIV_CMS_identifiers_match(&object, TC_PIV_CMS_CHUID,
                                                  chuid.fascn, chuid.card_uuid,
                                                  &limits, frames, FRAME_COUNT,
                                                  &work, &identifiers_match),
                     ==, TC_TLV_OK);
    munit_assert_int(identifiers_match, ==, 1);
    size_t identifier_values[2] = {0, 0};
    const TC_bytes identifiers[] = {attributes.fascn_octets,
                                    attributes.entry_uuid_octets};
    const TC_bytes expected[] = {chuid.fascn, chuid.card_uuid};
    for (size_t i = 0; i < sizeof identifiers / sizeof *identifiers; ++i) {
      if (!identifiers[i].data)
        continue;
      TC_TLV_reader octets;
      TC_TLV_element element;
      munit_assert_int(TC_TLV_reader_init(&octets, identifiers[i].data,
                                          identifiers[i].length, TC_TLV_DER,
                                          &limits),
                       ==, TC_TLV_OK);
      munit_assert_int(TC_TLV_next(&octets, &element), ==, TC_TLV_OK);
      munit_assert_size(element.value.length, ==, expected[i].length);
      munit_assert_memory_equal(expected[i].length, element.value.data,
                                expected[i].data);
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
        munit_assert_int(TC_SHA256_update(&hash, chuid.signed_content[i].data,
                                          chuid.signed_content[i].length),
                         ==, TC_OK);
      munit_assert_int(TC_SHA256_final(&hash, digest), ==, TC_OK);
      work = WORK;
      munit_assert_int(
          TC_CMS_signer_verify_digest(
              &signer, (TC_bytes){content_type, sizeof content_type},
              (TC_bytes){digest, sizeof digest}, TC_CMS_ATTRIBUTES_DER,
              &signer_certificate.public_key, &provider, &limits, &verification,
              &work),
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
  (void)params;
  (void)user;
  return MUNIT_OK;
}

static MunitResult legacy_chuid_key_map_signature(const MunitParameter params[],
                                                  void *user) {
  enum {
    CAPACITY = 2048,
    CERTIFICATE_BYTES = 1024,
    FRAMES = 16,
    OIDS = 16,
    WORK = 100000
  };
  uint8_t encoded[CAPACITY], certificate_bytes[CERTIFICATE_BYTES];
  static const uint8_t signed_content[] = {
      0x30, 25,   0xd4, 0xe7, 0x39, 0xda, 0x73, 0x9c, 0xed, 0x39, 0xce,
      0x73, 0x9d, 0x83, 0x68, 0x58, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21,
      0xc8, 0x42, 0x10, 0xc3, 0xeb, 0x34, 16,   0x91, 0xbe, 0x20, 0x94,
      0xf6, 0xdc, 0x53, 0x49, 0x80, 0x00, 0x40, 0x90, 0xe4, 0x9e, 0x50,
      0x5c, 0x35, 8,    '2',  '0',  '2',  '6',  '0',  '1',  '0',  '1',
      0x3d, 3,    0x01, 0x02, 0x03, 0xfe, 0};
  static const uint8_t content_type[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 6, 1};
  EVP_PKEY *key = EVP_EC_gen("prime256v1");
  munit_assert_not_null(key);
  X509 *certificate = make_certificate(key, "Legacy CHUID signer", NULL);
  add_extension(certificate, NID_basic_constraints, "critical,CA:FALSE");
  add_extension(certificate, NID_key_usage, "critical,digitalSignature");
  const size_t certificate_length =
      encode_certificate(certificate, key, EVP_sha256(), certificate_bytes,
                         sizeof certificate_bytes);
  const unsigned flags = CMS_BINARY | CMS_NOSMIMECAP | CMS_DETACHED;
  CMS_ContentInfo *cms =
      CMS_sign(certificate, key, NULL, NULL, flags | CMS_PARTIAL);
  BIO *input = BIO_new_mem_buf(signed_content, sizeof signed_content);
  ASN1_OBJECT *oid = OBJ_txt2obj("2.16.840.1.101.3.6.1", 1);
  munit_assert_not_null(cms);
  munit_assert_not_null(input);
  munit_assert_not_null(oid);
  munit_assert_int(CMS_set1_eContentType(cms, oid), ==, 1);
  set_cms_signer_name(cms, X509_get_subject_name(certificate));
  add_cms_octet_attribute(cms, "2.16.840.1.101.3.6.6", signed_content + 2,
                          signed_content[1]);
  add_cms_octet_attribute(cms, "1.3.6.1.1.16.4", signed_content + 29,
                          signed_content[28]);
  munit_assert_int(CMS_final(cms, input, NULL, flags), ==, 1);
  const int cms_length = i2d_CMS_ContentInfo(cms, NULL);
  munit_assert_int(cms_length, >, 0);
  const size_t prefix_length = sizeof signed_content - 2;
  munit_assert_size(prefix_length + 4 + (size_t)cms_length + 2, <=,
                    sizeof encoded);
  memcpy(encoded, signed_content, prefix_length);
  encoded[prefix_length] = 0x3e;
  encoded[prefix_length + 1] = 0x82;
  encoded[prefix_length + 2] = (uint8_t)((unsigned)cms_length >> 8);
  encoded[prefix_length + 3] = (uint8_t)cms_length;
  unsigned char *cursor = encoded + prefix_length + 4;
  munit_assert_int(i2d_CMS_ContentInfo(cms, &cursor), ==, cms_length);
  *cursor++ = 0xfe;
  *cursor++ = 0;
  const size_t encoded_length = (size_t)(cursor - encoded);

  TC_PIV_CHUID chuid;
  munit_assert_int(
      TC_PIV_CHUID_read_profile(encoded, encoded_length, TC_PIV_CHUID_CONTENTS,
                                TC_CHUID_PROFILE_LEGACY_KEY_MAP, &chuid),
      ==, TC_TLV_OK);
  TC_PIV_CHUID unchanged;
  memset(&unchanged, 0xa5, sizeof unchanged);
  TC_PIV_CHUID strict = unchanged;
  munit_assert_int(TC_PIV_CHUID_read_profile(encoded, encoded_length,
                                             TC_PIV_CHUID_CONTENTS,
                                             TC_CHUID_PROFILE_PIV, &strict),
                   !=, TC_TLV_OK);
  munit_assert_memory_equal(sizeof strict, &strict, &unchanged);

  TC_TLV_frame frames[FRAMES];
  const TC_TLV_limits limits = {CAPACITY, CAPACITY, 256, FRAMES};
  TC_PIV_CMS_object object;
  size_t work = WORK;
  munit_assert_int(TC_PIV_CMS_read(chuid.signature, TC_PIV_CMS_CHUID,
                                   TC_PIV_OIDS_ONLY, TC_CMS_ATTRIBUTES_DER,
                                   &limits, frames, FRAMES, &work, &object),
                   ==, TC_TLV_OK);
  TC_bytes oids[OIDS];
  TC_X509_workspace parser = {frames, FRAMES, oids, OIDS};
  TC_X509_certificate parsed_certificate;
  munit_assert_int(TC_X509_read(certificate_bytes, certificate_length, &limits,
                                &parser, &parsed_certificate),
                   ==, TC_TLV_OK);
  TC_ECDSA_workspace ec;
  const TC_X509_native_workspace native = {
      &ec, NULL, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  const TC_X509_signature_provider provider = TC_X509_native_provider(&native);
  const TC_CMS_signature_workspace signature = {frames, FRAMES, NULL, 0};
  for (unsigned changed = 0; changed < 2; ++changed) {
    uint8_t digest[TC_SHA256_DIGESTLEN];
    struct TC_SHA256_ctx hash;
    if (changed)
      encoded[prefix_length - 3] ^= 1;
    munit_assert_int(TC_SHA256_init(&hash), ==, TC_OK);
    for (size_t i = 0; i < 2; ++i)
      munit_assert_int(TC_SHA256_update(&hash, chuid.signed_content[i].data,
                                        chuid.signed_content[i].length),
                       ==, TC_OK);
    munit_assert_int(TC_SHA256_final(&hash, digest), ==, TC_OK);
    work = WORK;
    munit_assert_int(
        TC_CMS_signer_verify_digest(
            &object.signer, (TC_bytes){content_type, sizeof content_type},
            (TC_bytes){digest, sizeof digest}, TC_CMS_ATTRIBUTES_DER,
            &parsed_certificate.public_key, &provider, &limits, &signature,
            &work),
        ==, changed ? TC_X509_SIGNATURE_INVALID : TC_X509_SIGNATURE_VALID);
  }
  ASN1_OBJECT_free(oid);
  BIO_free(input);
  CMS_ContentInfo_free(cms);
  X509_free(certificate);
  EVP_PKEY_free(key);
  (void)params;
  (void)user;
  return MUNIT_OK;
}

static MunitResult security_profile(const MunitParameter params[], void *user) {
  enum { CAPACITY = 4096, FRAMES = 16, WORK = 100000 };
  static const uint8_t content[] = {0x30, 0};
  uint8_t encoded[CAPACITY], certificate_bytes[CAPACITY];
  TC_TLV_frame frames[FRAMES];
  TC_bytes oids[FRAMES];
  const TC_TLV_limits limits = {CAPACITY, CAPACITY, 256, FRAMES};
  TC_X509_workspace parser = {frames, FRAMES, oids, FRAMES};
  EVP_PKEY *key = EVP_EC_gen("prime256v1");
  munit_assert_not_null(key);
  X509 *certificate =
      make_certificate(key, "Synthetic security-object signer", NULL);
  add_extension(certificate, NID_subject_key_identifier, "hash");
  const size_t certificate_length = encode_certificate(
      certificate, key, EVP_sha256(), certificate_bytes, CAPACITY);
  TC_X509_certificate parsed_certificate;
  munit_assert_int(TC_X509_read(certificate_bytes, certificate_length, &limits,
                                &parser, &parsed_certificate),
                   ==, TC_TLV_OK);
  TC_ECDSA_workspace ec;
  const TC_X509_native_workspace native = {
      &ec, NULL, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  const TC_X509_signature_provider provider = TC_X509_native_provider(&native);
  const TC_CMS_signature_workspace signature = {frames, FRAMES, NULL, 0};
  enum {
    VALID,
    DETACHED,
    EMBEDDED_CERTIFICATE,
    WRONG_TYPE,
    MRTD_TYPE,
    NO_ATTRIBUTES,
    VARIANTS
  };
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
      CMS_ContentInfo *cms =
          CMS_sign(certificate, key, NULL, NULL, flags | CMS_PARTIAL);
      ASN1_OBJECT *oid = OBJ_txt2obj(variant == WRONG_TYPE  ? "1.2.3.4"
                                     : variant == MRTD_TYPE ? "2.23.136.1.1.1"
                                                            : "1.3.27.1.1.1",
                                     1);
      BIO *input = BIO_new_mem_buf(content, sizeof content);
      munit_assert_not_null(cms);
      munit_assert_not_null(oid);
      munit_assert_not_null(input);
      munit_assert_int(CMS_set1_eContentType(cms, oid), ==, 1);
      munit_assert_int(CMS_final(cms, input, NULL, flags), ==, 1);
      const int length = i2d_CMS_ContentInfo(cms, NULL);
      munit_assert_int(length, >, 0);
      munit_assert_int(length, <=, CAPACITY);
      unsigned char *cursor = encoded;
      munit_assert_int(i2d_CMS_ContentInfo(cms, &cursor), ==, length);
      TC_PIV_CMS_object object, preserved;
      memset(&preserved, 0xa5, sizeof preserved);
      object = preserved;
      size_t work = WORK;
      const TC_TLV_result result = TC_PIV_CMS_read(
          (TC_bytes){encoded, (size_t)length}, TC_PIV_CMS_SECURITY,
          TC_PIV_OIDS_TWIC_COMPATIBLE, TC_CMS_ATTRIBUTES_DER, &limits, frames,
          FRAMES, &work, &object);
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
              TC_PIV_CMS_read((TC_bytes){encoded, (size_t)length},
                              TC_PIV_CMS_SECURITY, TC_PIV_OIDS_ONLY,
                              TC_CMS_ATTRIBUTES_DER, &limits, frames, FRAMES,
                              &work, &budget_object),
              ==, budget == required ? TC_TLV_OK : TC_TLV_LIMIT);
          if (budget < required)
            munit_assert_memory_equal(sizeof budget_object, &budget_object,
                                      &preserved);
        }
        work = WORK;
        munit_assert_int(TC_CMS_signer_verify_content(
                             &object.signer, object.envelope.content_type,
                             object.envelope.content, TC_CMS_CONTENT_BER_OCTETS,
                             TC_CMS_ATTRIBUTES_DER,
                             &parsed_certificate.public_key, &provider, &limits,
                             &signature, &work),
                         ==, TC_X509_SIGNATURE_VALID);
        const size_t changed =
            (size_t)(object.envelope.content.data - encoded) +
            object.envelope.content.length - 1;
        encoded[changed] ^= 1;
        work = WORK;
        munit_assert_int(TC_CMS_signer_verify_content(
                             &object.signer, object.envelope.content_type,
                             object.envelope.content, TC_CMS_CONTENT_BER_OCTETS,
                             TC_CMS_ATTRIBUTES_DER,
                             &parsed_certificate.public_key, &provider, &limits,
                             &signature, &work),
                         ==, TC_X509_SIGNATURE_INVALID);
        encoded[changed] ^= 1;
        /* The profile leaves LDS schema validation to TC_LDS_read. */
        for (size_t prefix = 0; prefix < (size_t)length; ++prefix) {
          work = WORK;
          object = preserved;
          munit_assert_int(
              TC_PIV_CMS_read((TC_bytes){encoded, prefix}, TC_PIV_CMS_SECURITY,
                              TC_PIV_OIDS_ONLY, TC_CMS_ATTRIBUTES_DER, &limits,
                              frames, FRAMES, &work, &object),
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
  (void)params;
  (void)user;
  return MUNIT_OK;
}

int main(int argc, char **argv) {
  static char *fascn_namespaces[] = {"absent", "piv", "twic", NULL};
  static char *uuid_presence[] = {"absent", "present", NULL};
  static char *signing_policies[] = {"required", "absent", "any", "other",
                                     NULL};
  static char *signer_profiles[] = {"piv", "wrong-name", "twic", NULL};
  static MunitParameterEnum fascn_params[] = {
      {"fascn", fascn_namespaces},
      {"uuid", uuid_presence},
      {"policy", signing_policies},
      {"signer-profile", signer_profiles},
      {NULL, NULL}};
  static char *identifiers[] = {"issuer-serial", "key-id", NULL};
  static char *contents[] = {"attached", "detached", "empty-attached",
                             "empty-detached", NULL};
  static char *key_types[] = {"ec", "rsa", NULL};
  static MunitParameterEnum identifier_params[] = {{"identifier", identifiers},
                                                   {"content", contents},
                                                   {"key", key_types},
                                                   {NULL, NULL}};
  static char *crl_groups[] = {"signer", "discovery", "selection", NULL};
  static char *crl_outcomes[] = {"clear", "revoked", NULL};
  static MunitParameterEnum revocation_params[] = {
      {"group", crl_groups}, {"outcome", crl_outcomes}, {NULL, NULL}};
  MunitTest tests[] = {
      {"/content-signature", content_signature, NULL, NULL,
       MUNIT_TEST_OPTION_NONE, NULL},
      {"/rsa-signature", rsa_signature, NULL, NULL, MUNIT_TEST_OPTION_NONE,
       NULL},
      {"/signed-data", signed_data, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/revocations", revocations, NULL, NULL, MUNIT_TEST_OPTION_NONE,
       revocation_params},
      {"/embedded-path", embedded_path, NULL, NULL, MUNIT_TEST_OPTION_NONE,
       identifier_params},
      {"/chuid-signature", chuid_signature, NULL, NULL, MUNIT_TEST_OPTION_NONE,
       fascn_params},
      {"/legacy-chuid-key-map-signature", legacy_chuid_key_map_signature, NULL,
       NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/security-profile", security_profile, NULL, NULL,
       MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/cms/native", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
