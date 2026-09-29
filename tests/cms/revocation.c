/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Signed CRL handling with the native provider: CRL signer checks, signer
 * discovery through CMS certificates and trust paths, CRL scope processing
 * and complete/delta CRL selection. OpenSSL generates the CRLs and CMS. */
#include "../../examples/x509_revocation.h"
#include "../../src/cms_internal.h"
#include "../../src/pki_identifier_internal.h"
#include "../../src/pki_tree_internal.h"
#include "../../src/x509_crl_internal.h"
#include "../x509/openssl_fixture.h"
#include "cms_crl_harness.h"
#include "munit.h"
#include "native_support.h"
#include "openssl_fixture.h"
#include "source.h"
#include "x509_crl_harness.h"
#include <tiny_crypto/x509_crypto.h>
#include <openssl/cms.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <stdlib.h>
#include <string.h>

static void assert_evidence_equal(const TC_X509_crl_evidence* left,
                                  const TC_X509_crl_evidence* right)
{
  int equal = 0;
  munit_assert_int(tc_x509_crl_evidence_equal(left, right, &equal), ==, TC_TLV_OK);
  munit_assert_true(equal);
}

typedef struct {
  candidate_source* source;
  const TC_X509_revocation_node* dependency;
  TC_TLV_result failure;
  size_t failures;
} dependency_source_probe;

static TC_TLV_result read_dependency_candidate(void* context, size_t index, size_t* work,
                                               TC_bytes* out)
{
  dependency_source_probe* probe = context;
  if (probe->dependency && probe->dependency->certificate.data &&
      probe->dependency->status != TC_X509_REVOCATION_UNDETERMINED) {
    ++probe->failures;
    return probe->failure;
  }
  return read_candidate(probe->source, index, work, out);
}

typedef struct {
  TC_TLV_result result;
  int matched, increase_work;
} candidate_filter_probe;

static TC_TLV_result probe_candidate_filter(const void* context,
                                            const TC_X509_certificate* candidate,
                                            const TC_TLV_limits* limits,
                                            const tc_pki_tree_workspace* tree, int* matched)
{
  const candidate_filter_probe* probe = context;
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
  TC_TLV_result* source_status;
  size_t accept_calls;
} crl_path_probe;

static TC_X509_path_status check_crl_path(void* context, const TC_X509_search_result* path,
                                          const tc_x509_crl_selected* selected, size_t* work)
{
  crl_path_probe* probe = context;
  ++probe->calls;
  munit_assert_size(path->count, >, 0);
  munit_assert_size(path->anchor_index, ==, probe->anchor);
  if (selected) {
    munit_assert_not_null(selected->base);
    munit_assert_not_null(selected->base_info);
    munit_assert_false(selected->base_info->present & TC_X509_CRL_EXT_DELTA);
    munit_assert_int(!!selected->delta, ==, !!selected->delta_info);
    if (selected->delta)
      munit_assert_true(selected->delta_info->present & TC_X509_CRL_EXT_DELTA);
  }
  if (probe->signer.data) {
    munit_assert_size(path->path[path->count - 1].length, ==, probe->signer.length);
    munit_assert_memory_equal(probe->signer.length, path->path[path->count - 1].data,
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
  return probe->calls <= probe->accept_calls ? TC_X509_PATH_VALID : probe->result;
}

typedef struct {
  crl_path_probe path;
  TC_bytes base, delta;
  size_t pairs;
} selected_crl_probe;

static TC_X509_path_status check_selected_crl_path(void* context, const TC_X509_search_result* path,
                                                   const tc_x509_crl_selected* selected,
                                                   size_t* work)
{
  selected_crl_probe* probe = context;
  TC_X509_path_status result = check_crl_path(&probe->path, path, selected, work);
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

static TC_X509_path_status check_unresolved_crl_path(void* context,
                                                     const TC_X509_search_result* path,
                                                     const tc_x509_crl_selected* selected,
                                                     size_t* work)
{
  unresolved_crl_probe* probe = context;
  TC_X509_path_status result = check_crl_path(&probe->path, path, selected, work);
  if (result != TC_X509_PATH_VALID)
    return result;
  const TC_bytes signer = path->path[path->count - 1];
  return signer.length == probe->signer.length &&
                 !memcmp(signer.data, probe->signer.data, signer.length)
             ? probe->result
             : TC_X509_PATH_VALID;
}

/* Check one CRL record through the shipped scope executor. The only CRL
 * signer candidate is signer. Signer paths come from trust->source. */
static TC_TLV_result crl_signer_scope(const TC_X509_crl_record* record, TC_bytes signer,
                                      const tc_x509_crl_query* query,
                                      const tc_x509_crl_trust* trust,
                                      TC_X509_crl_evidence* evidence, TC_X509_search_result* out)
{
  candidate_source records = {&signer, 1, 0, TC_TLV_OK, 0};
  const TC_X509_store_source external = {&records, 1, 0, read_candidate, NULL};
  tc_pki_store_candidates cursor = {&external, trust->options->parsing, 0, 1, signer.length};
  const TC_bytes metadata[] = {{(const uint8_t*)&cursor, sizeof cursor},
                               {(const uint8_t*)&external, sizeof external},
                               {(const uint8_t*)&records, sizeof records}};
  const tc_x509_crl_operation_source candidates = {
      {&cursor, &external, tc_x509_crl_store_source_search}, metadata, 3};
  const TC_X509_crl_index index = {record, 1, 0};
  uint8_t states[1];
  const tc_x509_crl_scope_processing processing = {&index,
                                                   0,
                                                   TC_X509_CRL_COMPLETE_ONLY,
                                                   TC_X509_CRL_ORDER_NUMBER,
                                                   query,
                                                   states,
                                                   sizeof states,
                                                   evidence,
                                                   NULL,
                                                   NULL,
                                                   NULL,
                                                   NULL,
                                                   NULL};
  return tc_x509_crl_scope_execute(&candidates, &processing, trust,
                                   &(tc_x509_crl_scope_selection){NULL, 0, 0}, out);
}

/* Check one indexed CRL scope through the shipped scope executor, with CMS
 * candidates as CRL signers. */
static TC_TLV_result cms_crl_scope_check(const tc_cms_candidates* reader,
                                         const TC_X509_crl_index* index, size_t reference,
                                         TC_X509_crl_delta_policy delta_policy,
                                         const tc_x509_crl_query* query,
                                         const tc_x509_crl_trust* trust,
                                         TC_X509_crl_evidence* evidence, TC_X509_search_result* out)
{
  uint8_t states[8];
  munit_assert_size(index->count, <=, sizeof states);
  return tc_cms_crl_scope_process(reader,
                                  &(tc_x509_crl_scope_processing){index, reference, delta_policy,
                                                                  TC_X509_CRL_ORDER_NUMBER, query,
                                                                  states, sizeof states, evidence,
                                                                  NULL, NULL, NULL, NULL, NULL},
                                  trust, out);
}

static X509_CRL* make_partition_crl(X509_CRL* template, EVP_PKEY* key, uint16_t reasons,
                                    int revoked)
{
  enum { KEY_COMPROMISE = 1, TARGET_SERIAL = 9, LAST_REASON_BIT = 8 };
  X509_CRL* crl = X509_CRL_dup(template);
  ISSUING_DIST_POINT* point = ISSUING_DIST_POINT_new();
  munit_assert_not_null(crl);
  munit_assert_not_null(point);
  point->onlysomereasons = ASN1_BIT_STRING_new();
  munit_assert_not_null(point->onlysomereasons);
  for (unsigned bit = KEY_COMPROMISE; bit <= LAST_REASON_BIT; ++bit)
    if (reasons & (1u << bit))
      munit_assert_int(ASN1_BIT_STRING_set_bit(point->onlysomereasons, (int)bit, 1), ==, 1);
  munit_assert_int(
      X509_CRL_add1_ext_i2d(crl, NID_issuing_distribution_point, point, 1, X509V3_ADD_REPLACE), ==,
      1);
  ISSUING_DIST_POINT_free(point);
  if (revoked) {
    X509_REVOKED* item = X509_REVOKED_new();
    ASN1_INTEGER* serial = ASN1_INTEGER_new();
    ASN1_ENUMERATED* reason = ASN1_ENUMERATED_new();
    ASN1_TIME* revoked_at = ASN1_STRING_dup(X509_CRL_get0_lastUpdate(crl));
    munit_assert_not_null(item);
    munit_assert_not_null(serial);
    munit_assert_not_null(reason);
    munit_assert_not_null(revoked_at);
    munit_assert_int(ASN1_INTEGER_set(serial, TARGET_SERIAL), ==, 1);
    munit_assert_int(ASN1_ENUMERATED_set(reason, KEY_COMPROMISE), ==, 1);
    munit_assert_int(X509_REVOKED_set_serialNumber(item, serial), ==, 1);
    munit_assert_int(X509_REVOKED_set_revocationDate(item, revoked_at), ==, 1);
    munit_assert_int(X509_REVOKED_add1_ext_i2d(item, NID_crl_reason, reason, 0, 0), ==, 1);
    munit_assert_int(X509_CRL_add0_revoked(crl, item), ==, 1);
    ASN1_TIME_free(revoked_at);
    ASN1_ENUMERATED_free(reason);
    ASN1_INTEGER_free(serial);
  }
  munit_assert_int(X509_CRL_sign(crl, key, EVP_sha256()), >, 0);
  return crl;
}

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

/* One CRL issuer that also signs a CMS SignedData carrying its CRL. The CRL
 * lists serial 9 when the outcome parameter is "revoked". denied_der lacks
 * cRLSign and expired_der expired in 2025. Each test gets a fresh fixture, and
 * every span in it borrows the fixture's own arrays. */
typedef struct {
  unsigned revoked;
  uint8_t encoded[ENCODED_CAPACITY], spki[SPKI_CAPACITY], signer_der[ENCODED_CAPACITY];
  uint8_t denied_der[ENCODED_CAPACITY], expired_der[ENCODED_CAPACITY];
  uint8_t other_spki[SPKI_CAPACITY];
  uint32_t name_left[NAME_SCALARS], name_right[NAME_SCALARS];
  uint8_t name_flags[EXTENSION_CAPACITY];
  TC_X509_name_workspace names;
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_bytes oids[EXTENSION_CAPACITY];
  TC_X509_policy_node nodes[POLICY_CAPACITY];
  TC_X509_policy_edge edges[POLICY_CAPACITY];
  TC_X509_policy_expected expected[POLICY_CAPACITY];
  TC_X509_policy_mapping mappings[POLICY_CAPACITY];
  TC_bytes policies[POLICY_CAPACITY], path[PATH_CAPACITY];
  TC_X509_search_frame search_frames[PATH_CAPACITY];
  TC_X509_certificate certificate_cache[PATH_CAPACITY];
  TC_X509_extension_summary summaries[PATH_CAPACITY];
  TC_X509_path_workspace validation;
  TC_X509_search_workspace search;
  TC_X509_workspace parser;
  TC_X509_certificate signer;
  TC_TLV_limits limits;
  TC_ECDSA_workspace ec;
  TC_X509_native_workspace native;
  TC_X509_signature_provider provider;
  TC_X509_public_key key, other_public;
  EVP_PKEY *generated, *other_key;
  X509* certificate;
  ASN1_TIME *date, *next_date;
  int signer_length;
  size_t denied_length, expired_length;
  TC_X509_store_anchor anchors[2];
  TC_X509_store_source source;
  TC_X509_path_options options;
  X509_CRL* crl;
  BIO* content;
  CMS_ContentInfo* cms;
  TC_CMS_signed_data container;
  TC_X509_crl parsed;
  TC_X509_crl_extensions crl_info;
} revocation_fixture;

static size_t encode_public_key(EVP_PKEY* key, uint8_t* out, size_t capacity)
{
  unsigned char* cursor = out;
  const int length = i2d_PUBKEY(key, NULL);
  munit_assert_int(length, >, 0);
  munit_assert_size((size_t)length, <=, capacity);
  munit_assert_int(i2d_PUBKEY(key, &cursor), ==, length);
  return (size_t)length;
}

/* Sign the fixture CRL and a CMS SignedData that carries it, then parse the
 * CRL from the CMS revocations field. */
static void revocation_fixture_crl(revocation_fixture* f)
{
  X509_CRL* crl = X509_CRL_new();
  unsigned char* cursor;
  size_t work;
  const tc_pki_tree_workspace tree = {f->frames, FRAME_CAPACITY, &work};
  TC_TLV_reader records;
  TC_TLV_element record;
  munit_assert_not_null(crl);
  f->content = BIO_new_mem_buf("crl", 3);
  munit_assert_not_null(f->content);
  munit_assert_int(X509_CRL_set_version(crl, 1), ==, 1);
  munit_assert_int(X509_CRL_set_issuer_name(crl, X509_get_subject_name(f->certificate)), ==, 1);
  munit_assert_int(X509_CRL_set1_lastUpdate(crl, f->date), ==, 1);
  munit_assert_int(X509_CRL_set1_nextUpdate(crl, f->next_date), ==, 1);
  {
    ASN1_INTEGER* number = ASN1_INTEGER_new();
    munit_assert_not_null(number);
    munit_assert_int(ASN1_INTEGER_set(number, 1), ==, 1);
    munit_assert_int(X509_CRL_add1_ext_i2d(crl, NID_crl_number, number, 0, 0), ==, 1);
    ASN1_INTEGER_free(number);
  }
  {
    AUTHORITY_KEYID* authority = AUTHORITY_KEYID_new();
    munit_assert_not_null(authority);
    authority->keyid = X509_get_ext_d2i(f->certificate, NID_subject_key_identifier, NULL, NULL);
    munit_assert_not_null(authority->keyid);
    munit_assert_int(X509_CRL_add1_ext_i2d(crl, NID_authority_key_identifier, authority, 0, 0), ==,
                     1);
    AUTHORITY_KEYID_free(authority);
  }
  if (f->revoked) {
    X509_REVOKED* item = X509_REVOKED_new();
    ASN1_INTEGER* serial = ASN1_INTEGER_new();
    munit_assert_not_null(item);
    munit_assert_not_null(serial);
    munit_assert_int(ASN1_INTEGER_set(serial, 9), ==, 1);
    munit_assert_int(X509_REVOKED_set_serialNumber(item, serial), ==, 1);
    munit_assert_int(X509_REVOKED_set_revocationDate(item, f->date), ==, 1);
    munit_assert_int(X509_CRL_add0_revoked(crl, item), ==, 1);
    ASN1_INTEGER_free(serial);
  }
  munit_assert_int(X509_CRL_sign(crl, f->generated, EVP_sha256()), >, 0);
  f->crl = crl;
  f->cms = CMS_sign(f->certificate, f->generated, NULL, f->content, CMS_BINARY | CMS_NOSMIMECAP);
  munit_assert_not_null(f->cms);
  munit_assert_int(CMS_add1_crl(f->cms, crl), ==, 1);
  const int length = i2d_CMS_ContentInfo(f->cms, NULL);
  munit_assert_int(length, >, 0);
  munit_assert_size((size_t)length, <=, sizeof f->encoded);
  cursor = f->encoded;
  munit_assert_int(i2d_CMS_ContentInfo(f->cms, &cursor), ==, length);
  work = WORK_BUDGET;
  munit_assert_int(tc_cms_signed_data_read((TC_bytes){f->encoded, (size_t)length}, TC_TLV_BER,
                                           &f->limits, (TC_TLV_frames){f->frames, FRAME_CAPACITY},
                                           &work, &f->container),
                   ==, TC_TLV_OK);
  munit_assert_int(tc_cms_signed_data_version_check(&f->container, TC_TLV_BER, &f->limits, &tree),
                   ==, TC_TLV_OK);
  munit_assert_int(
      tc_pki_tree_open(f->container.revocations, 0xa1, TC_TLV_BER, &f->limits, &tree, &records), ==,
      TC_TLV_OK);
  munit_assert_int(tc_pki_tree_next(&records, &tree, &record), ==, TC_TLV_OK);
  munit_assert_true(tc_pki_end(&records));
  munit_assert_int(tc_x509_crl_read(record.encoded, &f->limits, &tree, &f->parsed), ==, TC_TLV_OK);
  munit_assert_int(
      tc_x509_crl_extensions_check(&f->parsed, &f->limits, &tree, f->oids, EXTENSION_CAPACITY), ==,
      TC_TLV_OK);
  munit_assert_int(tc_x509_crl_extension_info_read(f->parsed.extensions, &f->limits, &tree, f->oids,
                                                   EXTENSION_CAPACITY, &f->crl_info),
                   ==, TC_TLV_OK);
  munit_assert_uint(f->parsed.version, ==, 2);
}

static void* revocation_setup(const MunitParameter params[], void* user)
{
  const char* outcome = munit_parameters_get(params, "outcome");
  revocation_fixture* f = calloc(1, sizeof *f);
  unsigned char* cursor;
  (void)user;
  munit_assert_not_null(f);
  munit_assert_not_null(outcome);
  munit_assert_true(strcmp(outcome, "clear") == 0 || strcmp(outcome, "revoked") == 0);
  f->revoked = strcmp(outcome, "revoked") == 0;
  f->names = (TC_X509_name_workspace){f->name_left, f->name_right, NAME_SCALARS, f->name_flags,
                                      EXTENSION_CAPACITY};
  f->validation = (TC_X509_path_workspace)TC_X509_PATH_WORKSPACE_INIT(
      f->frames, f->oids, f->name_left, f->name_right, f->name_flags, f->nodes, f->edges,
      f->expected, f->mappings, f->policies, f->certificate_cache, f->summaries);
  f->search = (TC_X509_search_workspace){f->path, f->search_frames, PATH_CAPACITY};
  f->parser = (TC_X509_workspace){{f->frames, FRAME_CAPACITY}, f->oids, EXTENSION_CAPACITY};
  f->limits = (TC_TLV_limits){ENCODED_CAPACITY, ENCODED_CAPACITY, 256, FRAME_CAPACITY};
  f->native = (TC_X509_native_workspace){&f->ec, NULL, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  f->provider = TC_X509_native_provider(&f->native);
  f->generated = EVP_EC_gen("prime256v1");
  f->other_key = EVP_EC_gen("prime256v1");
  f->date = ASN1_TIME_new();
  f->next_date = ASN1_TIME_new();
  munit_assert_not_null(f->generated);
  munit_assert_not_null(f->other_key);
  munit_assert_not_null(f->date);
  munit_assert_not_null(f->next_date);
  munit_assert_int(ASN1_TIME_set_string(f->date, "260101000000Z"), ==, 1);
  munit_assert_int(ASN1_TIME_set_string(f->next_date, "270101000000Z"), ==, 1);
  const size_t other_length = encode_public_key(f->other_key, f->other_spki, sizeof f->other_spki);
  munit_assert_int(
      TC_X509_subject_public_key((TC_bytes){f->other_spki, other_length}, &f->other_public), ==,
      TC_TLV_OK);

  f->certificate = make_certificate(f->generated, "CRL issuer", NULL);
  add_extension(f->certificate, NID_subject_key_identifier, "hash");
  add_extension(f->certificate, NID_key_usage, "critical,cRLSign");
  munit_assert_int(X509_sign(f->certificate, f->generated, EVP_sha256()), >, 0);
  f->signer_length = i2d_X509(f->certificate, NULL);
  munit_assert_int(f->signer_length, >, 0);
  munit_assert_size((size_t)f->signer_length, <=, sizeof f->signer_der);
  cursor = f->signer_der;
  munit_assert_int(i2d_X509(f->certificate, &cursor), ==, f->signer_length);
  munit_assert_int(TC_X509_read((TC_bytes){f->signer_der, (size_t)f->signer_length}, &f->limits,
                                &f->parser, &f->signer),
                   ==, TC_TLV_OK);

  X509* denied_certificate = X509_dup(f->certificate);
  munit_assert_not_null(denied_certificate);
  const int denied_usage = X509_get_ext_by_NID(denied_certificate, NID_key_usage, -1);
  munit_assert_int(denied_usage, >=, 0);
  X509_EXTENSION_free(X509_delete_ext(denied_certificate, denied_usage));
  add_extension(denied_certificate, NID_key_usage, "critical,digitalSignature");
  f->denied_length = encode_certificate(denied_certificate, f->generated, EVP_sha256(),
                                        f->denied_der, sizeof f->denied_der);
  X509_free(denied_certificate);
  X509* expired_certificate = X509_dup(f->certificate);
  munit_assert_not_null(expired_certificate);
  munit_assert_int(
      ASN1_TIME_set_string_X509(X509_getm_notAfter(expired_certificate), "20250101000000Z"), ==, 1);
  f->expired_length = encode_certificate(expired_certificate, f->generated, EVP_sha256(),
                                         f->expired_der, sizeof f->expired_der);
  X509_free(expired_certificate);

  const size_t spki_length = encode_public_key(f->generated, f->spki, sizeof f->spki);
  munit_assert_int(TC_X509_subject_public_key((TC_bytes){f->spki, spki_length}, &f->key), ==,
                   TC_TLV_OK);
  f->anchors[0].trust = (TC_X509_trust_anchor){f->signer.subject, f->other_public};
  f->anchors[1].trust = (TC_X509_trust_anchor){f->signer.subject, f->signer.public_key};
  f->source = (TC_X509_store_source){f->anchors, 0, 2, NULL, crl_trust_anchor};
  f->options.at = (TC_X509_time){2026, 1, 1, 0, 0, 0};
  f->options.parsing = f->limits;
  f->options.max_certificates = PATH_CAPACITY;
  f->options.max_input = ENCODED_CAPACITY;
  f->options.signatures = f->provider;
  revocation_fixture_crl(f);
  return f;
}

enum { PARTITIONS = 2, KEY_COMPROMISE_MASK = 1u << 1 };

/* CRL signer candidates from an external store (an expired and a denied
 * certificate before two copies of the signer) and a query for serial 9. */
typedef struct {
  TC_bytes records[4];
  candidate_source candidates;
  TC_X509_store_source external;
  tc_cms_candidates reader, before;
  uint8_t serial;
  TC_X509_certificate target;
  tc_pki_distribution_point point;
  TC_X509_crl_record indexed_record;
  TC_X509_crl_index crl_index;
  TC_X509_crl_evidence initial;
  TC_X509_search_result found, saved;
} crl_scope_context;

static void crl_scope_init(revocation_fixture* f, const tc_pki_tree_workspace* tree,
                           crl_scope_context* scope)
{
  memset(scope, 0, sizeof *scope);
  scope->records[0] = (TC_bytes){f->expired_der, f->expired_length};
  scope->records[1] = (TC_bytes){f->denied_der, f->denied_length};
  scope->records[2] = (TC_bytes){f->signer_der, (size_t)f->signer_length};
  scope->records[3] = scope->records[2];
  scope->candidates = (candidate_source){scope->records, 4, 0, TC_TLV_OK, 0};
  scope->external =
      (TC_X509_store_source){&scope->candidates, scope->candidates.count, 0, read_candidate, NULL};
  *tree->work = TRUST_WORK_BUDGET;
  munit_assert_int(tc_cms_candidates_init((TC_bytes){NULL, 0}, &scope->external,
                                          scope->candidates.count, 4 * ENCODED_CAPACITY, &f->limits,
                                          tree, &scope->reader),
                   ==, TC_TLV_OK);
  memcpy(&scope->before, &scope->reader, sizeof scope->before);
  scope->serial = 9;
  scope->target.serial = (TC_bytes){&scope->serial, 1};
  scope->target.issuer = f->parsed.issuer;
  scope->indexed_record = (TC_X509_crl_record){f->parsed, f->crl_info, TC_TLV_OK};
  scope->crl_index = (TC_X509_crl_index){&scope->indexed_record, 1, 0};
  scope->initial.reasons = 1u << 1;
  memset(&scope->saved, 0xa5, sizeof scope->saved);
  memcpy(&scope->found, &scope->saved, sizeof scope->found);
}

/* The fixture CRL selected alone, authenticated and looked up for serial 9. */
typedef struct {
  uint8_t serial;
  TC_X509_certificate target;
  tc_x509_crl_selected selected;
  TC_X509_crl_match match, saved;
  tc_pki_distribution_point point;
} crl_selection_context;

static void crl_selection_init(revocation_fixture* f, const tc_pki_tree_workspace* tree,
                               crl_selection_context* selection)
{
  memset(selection, 0, sizeof *selection);
  selection->serial = 9;
  selection->target.serial = (TC_bytes){&selection->serial, 1};
  selection->target.issuer = f->parsed.issuer;
  selection->selected = (tc_x509_crl_selected){&f->parsed, &f->crl_info, NULL, NULL};
  memset(&selection->saved, 0xa5, sizeof selection->saved);
  *tree->work = WORK_BUDGET;
  munit_assert_int(tc_x509_crl_selected_authenticate(
                       &selection->selected, &f->signer, &f->provider,
                       &(tc_x509_crl_decode){&f->limits, tree, &f->names, NULL, 0}),
                   ==, TC_TLV_OK);
  TC_bytes oids[EXTENSION_CAPACITY];
  munit_assert_int(tc_x509_crl_selected_lookup(
                       &selection->selected, &selection->target,
                       &(tc_x509_crl_decode){&f->limits, tree, &f->names, oids, EXTENSION_CAPACITY},
                       &selection->match),
                   ==, TC_TLV_OK);
  munit_assert_int(selection->match.found, ==, f->revoked);
}

static void revocation_teardown(void* fixture)
{
  revocation_fixture* f = fixture;
  CMS_ContentInfo_free(f->cms);
  BIO_free(f->content);
  X509_CRL_free(f->crl);
  ASN1_TIME_free(f->date);
  ASN1_TIME_free(f->next_date);
  X509_free(f->certificate);
  EVP_PKEY_free(f->generated);
  EVP_PKEY_free(f->other_key);
  free(f);
}

/* CRL signatures checked against a trust anchor key and name, with exact
 * and short budgets, changed names and signatures and a missing provider. */
static MunitResult signer_anchor_check(const MunitParameter params[], void* user)
{
  revocation_fixture* f = user;
  TC_X509_store_anchor* const anchors = f->anchors;
  const TC_X509_name_workspace names = f->names;
  const TC_TLV_limits limits = f->limits;
  TC_X509_signature_provider provider = f->provider;
  TC_X509_crl parsed = f->parsed;
  size_t work = 0;
  (void)params;
  {
    work = WORK_BUDGET;
    munit_assert_int(
        tc_x509_crl_anchor_check(&parsed, &anchors[1].trust, &provider, &limits, &names, &work), ==,
        TC_X509_SIGNATURE_VALID);
    const size_t required = WORK_BUDGET - work;
    munit_assert_size(required, >, 0);
    for (unsigned short_budget = 0; short_budget < 2; ++short_budget) {
      work = required - short_budget;
      munit_assert_int(
          tc_x509_crl_anchor_check(&parsed, &anchors[1].trust, &provider, &limits, &names, &work),
          ==, short_budget ? TC_X509_SIGNATURE_LIMIT : TC_X509_SIGNATURE_VALID);
    }
    work = WORK_BUDGET;
    munit_assert_int(
        tc_x509_crl_anchor_check(&parsed, &anchors[0].trust, &provider, &limits, &names, &work), ==,
        TC_X509_SIGNATURE_INVALID);
    uint8_t changed_name[ENCODED_CAPACITY], signature[SPKI_CAPACITY];
    munit_assert_size(anchors[1].trust.name.length, <=, sizeof changed_name);
    memcpy(changed_name, anchors[1].trust.name.data, anchors[1].trust.name.length);
    changed_name[anchors[1].trust.name.length - 1] = 'x';
    TC_X509_trust_anchor other = anchors[1].trust;
    other.name.data = changed_name;
    work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_anchor_check(&parsed, &other, &provider, &limits, &names, &work),
                     ==, TC_X509_SIGNATURE_INVALID);
    munit_assert_size(parsed.signature.length, <=, sizeof signature);
    memcpy(signature, parsed.signature.data, parsed.signature.length);
    signature[parsed.signature.length - 1] ^= 1;
    TC_X509_crl damaged = parsed;
    damaged.signature.data = signature;
    work = WORK_BUDGET;
    munit_assert_int(
        tc_x509_crl_anchor_check(&damaged, &anchors[1].trust, &provider, &limits, &names, &work),
        ==, TC_X509_SIGNATURE_INVALID);
    work = WORK_BUDGET;
    munit_assert_int(
        tc_x509_crl_anchor_check(&parsed, &anchors[1].trust, NULL, &limits, &names, &work), ==,
        TC_X509_SIGNATURE_UNSUPPORTED);
    munit_assert_int(tc_x509_crl_anchor_check(&parsed, NULL, &provider, &limits, &names, &work), ==,
                     TC_X509_SIGNATURE_ERROR);
  }
  return MUNIT_OK;
}

/* The CRL authority key identifier matches the signer certificate. */
static MunitResult signer_authority_match(const MunitParameter params[], void* user)
{
  revocation_fixture* f = user;
  const TC_X509_name_workspace names = f->names;
  TC_X509_certificate signer = f->signer;
  const TC_TLV_limits limits = f->limits;
  TC_X509_crl_extensions crl_info = f->crl_info;
  size_t work = 0;
  const tc_pki_tree_workspace tree = {f->frames, FRAME_CAPACITY, &work};
  (void)params;
  {
    work = WORK_BUDGET;
    int matched;
    munit_assert_true(crl_info.present & TC_X509_CRL_EXT_AUTHORITY);
    munit_assert_int(
        tc_pki_authority_matches(&crl_info.authority, &signer, &limits, &tree, &names, &matched),
        ==, TC_TLV_OK);
    munit_assert_true(matched);
  }
  return MUNIT_OK;
}

/* CRL signer candidates from CMS certificates and an external store,
 * with retries after LIMIT, authority mismatches and filter failures. */
static MunitResult signer_candidates(const MunitParameter params[], void* user)
{
  revocation_fixture* f = user;
  uint8_t* const signer_der = f->signer_der;
  uint8_t* const denied_der = f->denied_der;
  const TC_X509_name_workspace names = f->names;
  TC_X509_workspace parser = f->parser;
  const TC_TLV_limits limits = f->limits;
  TC_X509_signature_provider provider = f->provider;
  const int signer_length = f->signer_length;
  const size_t denied_length = f->denied_length;
  TC_CMS_signed_data container = f->container;
  TC_X509_crl parsed = f->parsed;
  TC_X509_crl_extensions crl_info = f->crl_info;
  size_t work = 0;
  const tc_pki_tree_workspace tree = {f->frames, FRAME_CAPACITY, &work};
  (void)params;
  {
    const TC_bytes candidates[] = {{denied_der, denied_length},
                                   {signer_der, (size_t)signer_length}};
    candidate_source source = {candidates, 2, 0, TC_TLV_OK, 0};
    TC_X509_store_source external = {&source, source.count, 0, read_candidate, NULL};
    tc_cms_candidates reader, start, saved;
    TC_X509_certificate candidate;
    TC_bytes selected = {NULL, 0}, previous;
    work = WORK_BUDGET;
    munit_assert_int(tc_cms_candidates_init(container.certificates, &external, 3,
                                            ENCODED_CAPACITY + ENCODED_CAPACITY + ENCODED_CAPACITY,
                                            &limits, &tree, &reader),
                     ==, TC_TLV_OK);
    start = reader;
    work = WORK_BUDGET;
    munit_assert_int(tc_cms_crl_signer_candidate_next(&reader, &parsed, &crl_info, &names, &tree,
                                                      &parser, &candidate, &selected),
                     ==, TC_TLV_OK);
    const size_t required = WORK_BUDGET - work;
    munit_assert_size(selected.length, ==, (size_t)signer_length);
    munit_assert_memory_equal(selected.length, selected.data, signer_der);
    munit_assert_int(
        tc_x509_crl_signer_check(&parsed, &candidate, &provider, &limits, &names, &work), ==,
        TC_X509_SIGNATURE_VALID);
    reader = start;
    work = 0;
    previous = selected;
    memcpy(&saved, &reader, sizeof saved);
    munit_assert_int(tc_cms_crl_signer_candidate_next(&reader, &parsed, &crl_info, &names, &tree,
                                                      &parser, &candidate, &selected),
                     ==, TC_TLV_LIMIT);
    munit_assert_memory_equal(sizeof reader, &reader, &saved);
    munit_assert_ptr_equal(selected.data, previous.data);
    munit_assert_size(selected.length, ==, previous.length);
    work = required;
    munit_assert_int(tc_cms_crl_signer_candidate_next(&reader, &parsed, &crl_info, &names, &tree,
                                                      &parser, &candidate, &selected),
                     ==, TC_TLV_OK);
    munit_assert_size(work, ==, 0);
    work = WORK_BUDGET;
    munit_assert_int(tc_cms_crl_signer_candidate_next(&reader, &parsed, &crl_info, &names, &tree,
                                                      &parser, &candidate, &selected),
                     ==, TC_TLV_OK);
    munit_assert_ptr_equal(selected.data, signer_der);
    munit_assert_size(source.calls, ==, source.count);
    previous = selected;
    munit_assert_int(tc_cms_crl_signer_candidate_next(&reader, &parsed, &crl_info, &names, &tree,
                                                      &parser, &candidate, &selected),
                     ==, TC_TLV_END);
    munit_assert_ptr_equal(selected.data, previous.data);
    munit_assert_size(selected.length, ==, previous.length);
    {
      TC_X509_crl_extensions wrong = crl_info;
      static const uint8_t unknown_key[] = {0};
      wrong.authority.key_identifier = (TC_bytes){unknown_key, sizeof unknown_key};
      reader = start;
      work = WORK_BUDGET;
      munit_assert_int(tc_cms_crl_signer_candidate_next(&reader, &parsed, &wrong, &names, &tree,
                                                        &parser, &candidate, &selected),
                       ==, TC_TLV_END);
      munit_assert_ptr_equal(selected.data, previous.data);
      munit_assert_size(selected.length, ==, previous.length);
    }
    {
      const candidate_filter_probe failures[] = {{TC_TLV_OK, -1, 0},   {TC_TLV_OK, 2, 0},
                                                 {TC_TLV_END, 0, 0},   {TC_TLV_OK, 1, 1},
                                                 {TC_TLV_LIMIT, 1, 0}, {TC_TLV_UNSUPPORTED, 1, 0}};
      for (size_t i = 0; i < sizeof failures / sizeof failures[0]; ++i) {
        reader = start;
        work = WORK_BUDGET;
        memcpy(&saved, &reader, sizeof saved);
        const TC_TLV_result expected =
            failures[i].result == TC_TLV_LIMIT || failures[i].result == TC_TLV_UNSUPPORTED
                ? failures[i].result
                : TC_TLV_ARGUMENT;
        munit_assert_int(tc_cms_x509_candidate_next(&reader, probe_candidate_filter, &failures[i],
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
  return MUNIT_OK;
}

/* CRL signer path validation against the trust source, with wrong anchors,
 * expiry, key usage, short budgets, changed signatures and missing providers. */
static MunitResult discovery_signer_validate(const MunitParameter params[], void* user)
{
  revocation_fixture* f = user;
  uint8_t* const encoded = f->encoded;
  uint8_t* const signer_der = f->signer_der;
  uint8_t* const denied_der = f->denied_der;
  TC_X509_path_workspace validation = f->validation;
  TC_X509_search_workspace search = f->search;
  TC_X509_workspace parser = f->parser;
  TC_X509_certificate signer = f->signer;
  const TC_TLV_limits limits = f->limits;
  const TC_X509_store_source source = f->source;
  TC_X509_path_options options = f->options;
  const size_t denied_length = f->denied_length;
  TC_X509_crl parsed = f->parsed;
  size_t work = 0;
  (void)params;
  {
    TC_X509_search_result found, saved;
    memset(&saved, 0xa5, sizeof saved);
    memcpy(&found, &saved, sizeof found);
    work = TRUST_WORK_BUDGET;
    munit_assert_int(
        tc_x509_crl_signer_validate(
            &parsed, &signer,
            &(tc_x509_crl_trust){
                &source, 1, &options,
                &(tc_pki_tree_workspace){validation.frames.data, validation.frames.capacity, &work},
                &validation, &search, &(TC_X509_revocation_time){(&options)->at, 0, 0}},
            &found),
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
      if (failure == 2) {
        rejected.flags |= TC_X509_PATH_REQUIRE_KEY_USAGE;
        rejected.key_usage = TC_KEY_USAGE_CERT_SIGN;
      }
      if (failure == 3)
        work = required - 1;
      if (failure == 4)
        encoded[(size_t)(parsed.signature.data - encoded) + parsed.signature.length - 1] ^= 1;
      memcpy(&found, &saved, sizeof found);
      munit_assert_int(
          tc_x509_crl_signer_validate(
              &parsed, &signer,
              &(tc_x509_crl_trust){&source, anchor_index, &rejected,
                                   &(tc_pki_tree_workspace){validation.frames.data,
                                                            validation.frames.capacity, &work},
                                   &validation, &search,
                                   &(TC_X509_revocation_time){(&rejected)->at, 0, 0}},
              &found),
          ==, failure == 3 ? TC_X509_PATH_LIMIT : TC_X509_PATH_INVALID);
      munit_assert_memory_equal(sizeof found, &found, &saved);
      if (failure == 4)
        encoded[(size_t)(parsed.signature.data - encoded) + parsed.signature.length - 1] ^= 1;
    }
    work = required;
    munit_assert_int(
        tc_x509_crl_signer_validate(
            &parsed, &signer,
            &(tc_x509_crl_trust){
                &source, 1, &options,
                &(tc_pki_tree_workspace){validation.frames.data, validation.frames.capacity, &work},
                &validation, &search, &(TC_X509_revocation_time){(&options)->at, 0, 0}},
            &found),
        ==, TC_X509_PATH_VALID);
    munit_assert_size(work, ==, 0);
    {
      TC_X509_certificate denied_signer;
      munit_assert_int(
          TC_X509_read((TC_bytes){denied_der, denied_length}, &limits, &parser, &denied_signer), ==,
          TC_TLV_OK);
      work = TRUST_WORK_BUDGET;
      memcpy(&found, &saved, sizeof found);
      munit_assert_int(
          tc_x509_crl_signer_validate(
              &parsed, &denied_signer,
              &(tc_x509_crl_trust){&source, 1, &options,
                                   &(tc_pki_tree_workspace){validation.frames.data,
                                                            validation.frames.capacity, &work},
                                   &validation, &search,
                                   &(TC_X509_revocation_time){(&options)->at, 0, 0}},
              &found),
          ==, TC_X509_PATH_INVALID);
      munit_assert_memory_equal(sizeof found, &found, &saved);
      work = TRUST_WORK_BUDGET;
      munit_assert_int(
          tc_x509_crl_signer_validate(
              &parsed, &signer,
              &(tc_x509_crl_trust){&source, source.anchor_count, &options,
                                   &(tc_pki_tree_workspace){validation.frames.data,
                                                            validation.frames.capacity, &work},
                                   &validation, &search,
                                   &(TC_X509_revocation_time){(&options)->at, 0, 0}},
              &found),
          ==, TC_X509_PATH_ERROR);
      munit_assert_memory_equal(sizeof found, &found, &saved);
      munit_assert_size(work, ==, TRUST_WORK_BUDGET);
      options.signatures.verify = NULL;
      munit_assert_int(
          tc_x509_crl_signer_validate(
              &parsed, &signer,
              &(tc_x509_crl_trust){&source, 1, &options,
                                   &(tc_pki_tree_workspace){validation.frames.data,
                                                            validation.frames.capacity, &work},
                                   &validation, &search,
                                   &(TC_X509_revocation_time){(&options)->at, 0, 0}},
              &found),
          ==, TC_X509_PATH_UNSUPPORTED);
      munit_assert_memory_equal(sizeof found, &found, &saved);
    }
  }
  return MUNIT_OK;
}

/* CRL signer search and scope processing with store candidates: exact and
 * short budgets, retries, reason filters, source failures and overlaps. */
static MunitResult discovery_scope(const MunitParameter params[], void* user)
{
  revocation_fixture* f = user;
  uint8_t* const signer_der = f->signer_der;
  uint8_t* const denied_der = f->denied_der;
  uint8_t* const expired_der = f->expired_der;
  uint32_t* const name_left = f->name_left;
  uint32_t* const name_right = f->name_right;
  uint8_t* const name_flags = f->name_flags;
  TC_TLV_frame* const frames = f->frames;
  TC_bytes* const oids = f->oids;
  TC_X509_policy_node* const nodes = f->nodes;
  TC_X509_policy_edge* const edges = f->edges;
  TC_X509_policy_expected* const expected = f->expected;
  TC_X509_policy_mapping* const mappings = f->mappings;
  TC_bytes* const policies = f->policies;
  TC_bytes* const path = f->path;
  TC_X509_search_frame* const search_frames = f->search_frames;
  TC_X509_store_anchor* const anchors = f->anchors;
  const unsigned revoked = f->revoked;
  TC_X509_path_workspace validation = f->validation;
  TC_X509_search_workspace search = f->search;
  const TC_TLV_limits limits = f->limits;
  TC_X509_signature_provider provider = f->provider;
  const TC_X509_store_source source = f->source;
  TC_X509_path_options options = f->options;
  const int signer_length = f->signer_length;
  const size_t denied_length = f->denied_length;
  const size_t expired_length = f->expired_length;
  TC_X509_crl parsed = f->parsed;
  TC_X509_crl_extensions crl_info = f->crl_info;
  size_t work = 0;
  const tc_pki_tree_workspace tree = {f->frames, FRAME_CAPACITY, &work};
  (void)params;
  {
    TC_X509_search_result found, saved;
    memset(&saved, 0xa5, sizeof saved);
    memcpy(&found, &saved, sizeof found);
    {
      const TC_bytes records[] = {{expired_der, expired_length},
                                  {denied_der, denied_length},
                                  {signer_der, (size_t)signer_length},
                                  {signer_der, (size_t)signer_length}};
      candidate_source candidates = {records, 4, 0, TC_TLV_OK, 0};
      const TC_X509_store_source external = {&candidates, candidates.count, 0, read_candidate,
                                             NULL};
      tc_cms_candidates reader, before;
      options.signatures = provider;
      work = TRUST_WORK_BUDGET;
      munit_assert_int(
          tc_cms_candidates_init((TC_bytes){NULL, 0}, &external, candidates.count,
                                 ENCODED_CAPACITY + ENCODED_CAPACITY + 2 * ENCODED_CAPACITY,
                                 &limits, &tree, &reader),
          ==, TC_TLV_OK);
      memcpy(&before, &reader, sizeof before);
      work = TRUST_WORK_BUDGET;
      munit_assert_int(tc_cms_crl_signer_find(
                           &reader, &parsed, &crl_info,
                           &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                                &(TC_X509_revocation_time){(&options)->at, 0, 0}},
                           &found),
                       ==, TC_X509_PATH_VALID);
      munit_assert_size(candidates.calls, ==, 3);
      munit_assert_ptr_equal(found.path[found.count - 1].data, signer_der);
      munit_assert_memory_equal(sizeof reader, &reader, &before);
      const size_t search_work = TRUST_WORK_BUDGET - work;
      munit_assert_size(found.validation.work_used, ==, search_work);
      work = search_work - 1;
      memcpy(&found, &saved, sizeof found);
      munit_assert_int(tc_cms_crl_signer_find(
                           &reader, &parsed, &crl_info,
                           &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                                &(TC_X509_revocation_time){(&options)->at, 0, 0}},
                           &found),
                       ==, TC_X509_PATH_LIMIT);
      munit_assert_memory_equal(sizeof found, &found, &saved);
      munit_assert_size(work, ==, 0);
      work = search_work;
      munit_assert_int(tc_cms_crl_signer_find(
                           &reader, &parsed, &crl_info,
                           &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                                &(TC_X509_revocation_time){(&options)->at, 0, 0}},
                           &found),
                       ==, TC_X509_PATH_VALID);
      munit_assert_size(work, ==, 0);
      signature_retry_probe probe = {provider, 0, 2, TC_X509_SIGNATURE_UNSUPPORTED};
      options.signatures = (TC_X509_signature_provider){retry_signature, &probe, NULL};
      work = TRUST_WORK_BUDGET;
      candidates.calls = 0;
      munit_assert_int(tc_cms_crl_signer_find(
                           &reader, &parsed, &crl_info,
                           &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                                &(TC_X509_revocation_time){(&options)->at, 0, 0}},
                           &found),
                       ==, TC_X509_PATH_VALID);
      munit_assert_size(candidates.calls, ==, candidates.count);
      munit_assert_size(probe.calls, ==, 4);
      probe.calls = 0;
      probe.failure = TC_X509_SIGNATURE_ERROR;
      work = TRUST_WORK_BUDGET;
      candidates.calls = 0;
      memcpy(&found, &saved, sizeof found);
      munit_assert_int(tc_cms_crl_signer_find(
                           &reader, &parsed, &crl_info,
                           &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                                &(TC_X509_revocation_time){(&options)->at, 0, 0}},
                           &found),
                       ==, TC_X509_PATH_ERROR);
      munit_assert_size(candidates.calls, ==, 3);
      munit_assert_memory_equal(sizeof found, &found, &saved);
      options.signatures.verify = NULL;
      work = TRUST_WORK_BUDGET;
      memcpy(&found, &saved, sizeof found);
      munit_assert_int(tc_cms_crl_signer_find(
                           &reader, &parsed, &crl_info,
                           &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                                &(TC_X509_revocation_time){(&options)->at, 0, 0}},
                           &found),
                       ==, TC_X509_PATH_UNSUPPORTED);
      munit_assert_memory_equal(sizeof found, &found, &saved);
      options.signatures = provider;
      work = TRUST_WORK_BUDGET;
      munit_assert_int(tc_cms_crl_signer_find(
                           &reader, &parsed, &crl_info,
                           &(tc_x509_crl_trust){&source, 0, &options, &tree, &validation, &search,
                                                &(TC_X509_revocation_time){(&options)->at, 0, 0}},
                           &found),
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
        const TC_X509_crl_record indexed_record = {parsed, crl_info, TC_TLV_OK};
        const TC_X509_crl_index crl_index = {&indexed_record, 1, 0};
        TC_X509_crl_evidence evidence = {0}, initial = {0};
        TC_X509_revocation_status status;
        initial.reasons = 1u << 1;
        evidence = initial;
        work = TRUST_WORK_BUDGET;
        candidates.calls = 0;
        munit_assert_int(cms_crl_scope_check(
                             &reader, &crl_index, 0, TC_X509_CRL_DELTA_IF_AVAILABLE, &query,
                             &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                                  &(TC_X509_revocation_time){(&options)->at, 0, 0}},
                             &evidence, &found),
                         ==, TC_TLV_OK);
        const size_t required = TRUST_WORK_BUDGET - work;
        munit_assert_size(found.validation.work_used, ==, required);
        munit_assert_size(candidates.calls, ==, 3);
        munit_assert_ptr_equal(found.path[found.count - 1].data, signer_der);
        munit_assert_int(tc_x509_crl_evidence_status(&evidence, &status), ==, TC_TLV_OK);
        munit_assert_int(status, ==,
                         revoked ? TC_X509_REVOCATION_REVOKED : TC_X509_REVOCATION_GOOD);
        const TC_X509_crl_evidence terminal = evidence;
        work = 0;
        memcpy(&found, &saved, sizeof found);
        munit_assert_int(cms_crl_scope_check(
                             &reader, &crl_index, 0, TC_X509_CRL_DELTA_IF_AVAILABLE, &query,
                             &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                                  &(TC_X509_revocation_time){(&options)->at, 0, 0}},
                             &evidence, &found),
                         ==, TC_TLV_END);
        munit_assert_memory_equal(sizeof evidence, &evidence, &terminal);
        munit_assert_memory_equal(sizeof found, &found, &saved);
        munit_assert_size(candidates.calls, ==, 3);
        evidence = initial;
        work = required;
        munit_assert_int(cms_crl_scope_check(
                             &reader, &crl_index, 0, TC_X509_CRL_DELTA_IF_AVAILABLE, &query,
                             &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                                  &(TC_X509_revocation_time){(&options)->at, 0, 0}},
                             &evidence, &found),
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
        } cases[] = {{SHORT, TC_TLV_LIMIT},          {ANCHOR, TC_TLV_INVALID},
                     {PROVIDER, TC_TLV_UNSUPPORTED}, {SOURCE_ERROR, TC_TLV_UNSUPPORTED},
                     {MALFORMED, TC_TLV_INVALID},    {INCREASE_WORK, TC_TLV_ARGUMENT},
                     {NO_MATCH, TC_TLV_INVALID},     {STALE, TC_TLV_END},
                     {RETRY_UNSUPPORTED, TC_TLV_OK}, {RETRY_ERROR, TC_TLV_ARGUMENT}};
        static const uint8_t malformed[] = {0x31, 0};
        const TC_bytes bad_records[] = {{malformed, sizeof malformed}};
        const TC_bytes denied_records[] = {{denied_der, denied_length},
                                           {denied_der, denied_length},
                                           {denied_der, denied_length},
                                           {denied_der, denied_length}};
        uint8_t signature_states[1];
        evidence = initial;
        work = TRUST_WORK_BUDGET;
        munit_assert_int(tc_cms_crl_scope_process(
                             &reader,
                             &(tc_x509_crl_scope_processing){
                                 &crl_index, 0, TC_X509_CRL_DELTA_IF_AVAILABLE,
                                 TC_X509_CRL_ORDER_NUMBER, &query, signature_states,
                                 sizeof signature_states, &evidence, NULL, NULL, NULL, NULL, NULL},
                             &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                                  &(TC_X509_revocation_time){(&options)->at, 0, 0}},
                             &found),
                         ==, TC_TLV_OK);
        const size_t scope_required = TRUST_WORK_BUDGET - work;
        evidence = initial;
        work = scope_required;
        munit_assert_int(tc_cms_crl_scope_process(
                             &reader,
                             &(tc_x509_crl_scope_processing){
                                 &crl_index, 0, TC_X509_CRL_DELTA_IF_AVAILABLE,
                                 TC_X509_CRL_ORDER_NUMBER, &query, signature_states,
                                 sizeof signature_states, &evidence, NULL, NULL, NULL, NULL, NULL},
                             &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                                  &(TC_X509_revocation_time){(&options)->at, 0, 0}},
                             &found),
                         ==, TC_TLV_OK);
        munit_assert_size(work, ==, 0);
        enum { COVERED_REASONS, OTHER_ISSUER, FILTER_CASES };
        static const uint8_t other_issuer[] = {0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06,
                                               0x03, 0x55, 0x04, 0x03, 0x0c, 0x01, 'x'};
        for (unsigned filter = COVERED_REASONS; filter < FILTER_CASES; ++filter) {
          TC_X509_certificate filtered_target = target;
          tc_pki_distribution_point filtered_point = point;
          if (filter == COVERED_REASONS) {
            filtered_point.has_reasons = 1;
            filtered_point.reasons = initial.reasons;
          } else
            filtered_target.issuer = (TC_bytes){other_issuer, sizeof other_issuer};
          const tc_x509_crl_query filtered_query = {&filtered_target, &filtered_point, 0};
          TC_X509_path_options filtered_options = options;
          filtered_options.signatures.verify = NULL;
          candidates = (candidate_source){records, 4, 0, TC_TLV_UNSUPPORTED, 0};
          evidence = initial;
          found = saved;
          work = TRUST_WORK_BUDGET;
          signature_states[0] = 0xa5;
          munit_assert_int(
              tc_cms_crl_scope_process(
                  &reader,
                  &(tc_x509_crl_scope_processing){&crl_index, 0, TC_X509_CRL_DELTA_IF_AVAILABLE,
                                                  TC_X509_CRL_ORDER_NUMBER, &filtered_query,
                                                  signature_states, sizeof signature_states,
                                                  &evidence, NULL, NULL, NULL, NULL, NULL},
                  &(tc_x509_crl_trust){&source, 1, &filtered_options, &tree, &validation, &search,
                                       &(TC_X509_revocation_time){(&filtered_options)->at, 0, 0}},
                  &found),
              ==, TC_TLV_END);
          const size_t filter_work = TRUST_WORK_BUDGET - work;
          munit_assert_memory_equal(sizeof evidence, &evidence, &initial);
          munit_assert_memory_equal(sizeof found, &found, &saved);
          munit_assert_size(candidates.calls, ==, 0);
          munit_assert_uint(signature_states[0], ==, 0xa5);
          work = filter_work - 1;
          munit_assert_int(
              tc_cms_crl_scope_process(
                  &reader,
                  &(tc_x509_crl_scope_processing){&crl_index, 0, TC_X509_CRL_DELTA_IF_AVAILABLE,
                                                  TC_X509_CRL_ORDER_NUMBER, &filtered_query,
                                                  signature_states, sizeof signature_states,
                                                  &evidence, NULL, NULL, NULL, NULL, NULL},
                  &(tc_x509_crl_trust){&source, 1, &filtered_options, &tree, &validation, &search,
                                       &(TC_X509_revocation_time){(&filtered_options)->at, 0, 0}},
                  &found),
              ==, TC_TLV_LIMIT);
          munit_assert_memory_equal(sizeof evidence, &evidence, &initial);
          munit_assert_memory_equal(sizeof found, &found, &saved);
          work = filter_work;
          munit_assert_int(
              tc_cms_crl_scope_process(
                  &reader,
                  &(tc_x509_crl_scope_processing){&crl_index, 0, TC_X509_CRL_DELTA_IF_AVAILABLE,
                                                  TC_X509_CRL_ORDER_NUMBER, &filtered_query,
                                                  signature_states, sizeof signature_states,
                                                  &evidence, NULL, NULL, NULL, NULL, NULL},
                  &(tc_x509_crl_trust){&source, 1, &filtered_options, &tree, &validation, &search,
                                       &(TC_X509_revocation_time){(&filtered_options)->at, 0, 0}},
                  &found),
              ==, TC_TLV_END);
          munit_assert_size(work, ==, 0);
          munit_assert_size(candidates.calls, ==, 0);
          munit_assert_uint(signature_states[0], ==, 0xa5);
        }
        for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
          TC_X509_path_options checked = options;
          size_t anchor_index = 1;
          signature_retry_probe retry = {provider, 0, 2, TC_X509_SIGNATURE_UNSUPPORTED};
          candidates = (candidate_source){records, 4, 0, TC_TLV_OK, 0};
          evidence = initial;
          work = TRUST_WORK_BUDGET;
          memcpy(&found, &saved, sizeof found);
          switch (cases[i].kind) {
          case SHORT:
            work = scope_required - 1;
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
            checked.signatures = (TC_X509_signature_provider){retry_signature, &retry, NULL};
            break;
          }
          TC_TLV_result result = tc_cms_crl_scope_process(
              &reader,
              &(tc_x509_crl_scope_processing){&crl_index, 0, TC_X509_CRL_DELTA_IF_AVAILABLE,
                                              TC_X509_CRL_ORDER_NUMBER, &query, signature_states,
                                              sizeof signature_states, &evidence, NULL, NULL, NULL,
                                              NULL, NULL},
              &(tc_x509_crl_trust){&source, anchor_index, &checked, &tree, &validation, &search,
                                   &(TC_X509_revocation_time){(&checked)->at, 0, 0}},
              &found);
          munit_assert_int(result, ==, cases[i].result);
          munit_assert_memory_equal(sizeof reader, &reader, &before);
          if (cases[i].result != TC_TLV_OK) {
            munit_assert_memory_equal(sizeof evidence, &evidence, &initial);
            munit_assert_memory_equal(sizeof found, &found, &saved);
          } else {
            munit_assert_size(candidates.calls, ==, 4);
            munit_assert_size(retry.calls, ==, 4);
            munit_assert_size(found.validation.work_used, ==, TRUST_WORK_BUDGET - work);
            munit_assert_int(tc_x509_crl_evidence_status(&evidence, &status), ==, TC_TLV_OK);
            munit_assert_int(status, ==,
                             revoked ? TC_X509_REVOCATION_REVOKED : TC_X509_REVOCATION_GOOD);
          }
          if (cases[i].kind == SOURCE_ERROR || cases[i].kind == MALFORMED ||
              cases[i].kind == INCREASE_WORK)
            munit_assert_size(candidates.calls, ==, 1);
          /* Freshness waits for delta selection, which follows the signer
             * path. The signer is the third record. */
          if (cases[i].kind == RETRY_ERROR || cases[i].kind == STALE)
            munit_assert_size(candidates.calls, ==, 3);
        }
        const void* state_overlaps[] = {&options,
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
        for (size_t overlap = 0; overlap < sizeof state_overlaps / sizeof *state_overlaps;
             ++overlap) {
          candidates = (candidate_source){records, 4, 0, TC_TLV_OK, 0};
          evidence = initial;
          found = saved;
          work = TRUST_WORK_BUDGET;
          munit_assert_int(
              tc_cms_crl_scope_process(
                  &reader,
                  &(tc_x509_crl_scope_processing){&crl_index, 0, TC_X509_CRL_DELTA_IF_AVAILABLE,
                                                  TC_X509_CRL_ORDER_NUMBER, &query,
                                                  (uint8_t*)state_overlaps[overlap], 1, &evidence,
                                                  NULL, NULL, NULL, NULL, NULL},
                  &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                       &(TC_X509_revocation_time){(&options)->at, 0, 0}},
                  &found),
              ==, TC_TLV_ARGUMENT);
          munit_assert_memory_equal(sizeof evidence, &evidence, &initial);
          munit_assert_memory_equal(sizeof found, &found, &saved);
          munit_assert_size(work, ==, TRUST_WORK_BUDGET);
          munit_assert_size(candidates.calls, ==, 0);
        }
        const void* returned_overlaps[] = {frames,           oids,      name_left, name_right,
                                           name_flags,       nodes,     edges,     expected,
                                           mappings,         policies,  path,      search_frames,
                                           signature_states, &evidence, &found,    &work};
        for (size_t overlap = 0; overlap < sizeof returned_overlaps / sizeof *returned_overlaps;
             ++overlap) {
          const TC_bytes returned = {returned_overlaps[overlap], 1};
          candidates = (candidate_source){&returned, 1, 0, TC_TLV_OK, 0};
          evidence = initial;
          found = saved;
          work = TRUST_WORK_BUDGET;
          munit_assert_int(
              tc_cms_crl_scope_process(
                  &reader,
                  &(tc_x509_crl_scope_processing){&crl_index, 0, TC_X509_CRL_DELTA_IF_AVAILABLE,
                                                  TC_X509_CRL_ORDER_NUMBER, &query,
                                                  signature_states, sizeof signature_states,
                                                  &evidence, NULL, NULL, NULL, NULL, NULL},
                  &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                       &(TC_X509_revocation_time){(&options)->at, 0, 0}},
                  &found),
              ==, TC_TLV_ARGUMENT);
          munit_assert_memory_equal(sizeof evidence, &evidence, &initial);
          munit_assert_memory_equal(sizeof found, &found, &saved);
          munit_assert_size(candidates.calls, ==, 1);
        }
        const TC_bytes anchor_name = anchors[1].trust.name;
        for (size_t overlap = 0; overlap < sizeof returned_overlaps / sizeof *returned_overlaps;
             ++overlap) {
          candidates = (candidate_source){records, 4, 0, TC_TLV_OK, 0};
          anchors[1].trust.name = (TC_bytes){returned_overlaps[overlap], 1};
          evidence = initial;
          found = saved;
          work = TRUST_WORK_BUDGET;
          munit_assert_int(
              tc_cms_crl_scope_process(
                  &reader,
                  &(tc_x509_crl_scope_processing){&crl_index, 0, TC_X509_CRL_DELTA_IF_AVAILABLE,
                                                  TC_X509_CRL_ORDER_NUMBER, &query,
                                                  signature_states, sizeof signature_states,
                                                  &evidence, NULL, NULL, NULL, NULL, NULL},
                  &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                       &(TC_X509_revocation_time){(&options)->at, 0, 0}},
                  &found),
              ==, TC_TLV_ARGUMENT);
          munit_assert_memory_equal(sizeof evidence, &evidence, &initial);
          munit_assert_memory_equal(sizeof found, &found, &saved);
        }
        anchors[1].trust.name = anchor_name;
        candidates = (candidate_source){records, 4, 0, TC_TLV_OK, 0};
        const tc_pki_tree_workspace partial_tree = {frames + 1, FRAME_CAPACITY - 1, &work};
        evidence = initial;
        found = saved;
        work = TRUST_WORK_BUDGET;
        munit_assert_int(
            tc_cms_crl_scope_process(
                &reader,
                &(tc_x509_crl_scope_processing){&crl_index, 0, TC_X509_CRL_DELTA_IF_AVAILABLE,
                                                TC_X509_CRL_ORDER_NUMBER, &query, signature_states,
                                                sizeof signature_states, &evidence, NULL, NULL,
                                                NULL, NULL, NULL},
                &(tc_x509_crl_trust){&source, 1, &options, &partial_tree, &validation, &search,
                                     &(TC_X509_revocation_time){(&options)->at, 0, 0}},
                &found),
            ==, TC_TLV_ARGUMENT);
        munit_assert_memory_equal(sizeof evidence, &evidence, &initial);
        munit_assert_memory_equal(sizeof found, &found, &saved);
        munit_assert_size(work, ==, TRUST_WORK_BUDGET);
        munit_assert_size(candidates.calls, ==, 0);
      }
    }
  }
  return MUNIT_OK;
}

/* CRLs from a replacement issuer key and alternative signers, with CRL
 * number rollover across partitions. */
static MunitResult discovery_issuer_rollover(const MunitParameter params[], void* user)
{
  revocation_fixture* f = user;
  uint8_t* const signer_der = f->signer_der;
  TC_bytes* const oids = f->oids;
  TC_X509_path_workspace validation = f->validation;
  TC_X509_search_workspace search = f->search;
  TC_X509_workspace parser = f->parser;
  TC_X509_certificate signer = f->signer;
  const TC_TLV_limits limits = f->limits;
  const TC_X509_store_source source = f->source;
  TC_X509_path_options options = f->options;
  EVP_PKEY* generated = f->generated;
  EVP_PKEY* other_key = f->other_key;
  X509* certificate = f->certificate;
  const int signer_length = f->signer_length;
  X509_CRL* crl = f->crl;
  size_t work = 0;
  const tc_pki_tree_workspace tree = {f->frames, FRAME_CAPACITY, &work};
  crl_scope_context scope;
  crl_scope_init(f, &tree, &scope);
  const tc_x509_crl_query query = {&scope.target, &scope.point, 0};
  TC_X509_crl_evidence evidence = scope.initial;
  TC_X509_revocation_status status;
  (void)params;
  {
    {
      uint8_t replacement_der[ENCODED_CAPACITY], alternative_der[ENCODED_CAPACITY];
      uint8_t rollover_der[PARTITIONS][ENCODED_CAPACITY];
      X509* replacement = make_certificate(other_key, "CRL issuer", certificate);
      munit_assert_int(ASN1_INTEGER_set(X509_get_serialNumber(replacement), 2), ==, 1);
      add_extension(replacement, NID_subject_key_identifier, "hash");
      add_extension(replacement, NID_key_usage, "critical,cRLSign");
      const size_t replacement_length = encode_certificate(replacement, generated, EVP_sha256(),
                                                           replacement_der, sizeof replacement_der);
      TC_X509_certificate replacement_view;
      work = TRUST_WORK_BUDGET;
      munit_assert_int(TC_X509_read((TC_bytes){replacement_der, replacement_length}, &limits,
                                    &parser, &replacement_view),
                       ==, TC_TLV_OK);
      TC_bytes rollover_inputs[PARTITIONS];
      X509_CRL* newest = NULL;
      for (unsigned generation = 0; generation < PARTITIONS; ++generation) {
        X509_CRL* variant = make_partition_crl(crl, generation ? other_key : generated,
                                               TC_X509_CRL_ALL_REASONS, (int)generation);
        if (generation) {
          ASN1_INTEGER* number = ASN1_INTEGER_new();
          ASN1_TIME* update = ASN1_TIME_new();
          AUTHORITY_KEYID* authority = AUTHORITY_KEYID_new();
          munit_assert_not_null(number);
          munit_assert_not_null(update);
          munit_assert_not_null(authority);
          munit_assert_int(ASN1_INTEGER_set(number, 2), ==, 1);
          munit_assert_int(ASN1_TIME_set_string(update, "260102000000Z"), ==, 1);
          authority->keyid = X509_get_ext_d2i(replacement, NID_subject_key_identifier, NULL, NULL);
          munit_assert_not_null(authority->keyid);
          munit_assert_int(
              X509_CRL_add1_ext_i2d(variant, NID_crl_number, number, 0, X509V3_ADD_REPLACE), ==, 1);
          munit_assert_int(X509_CRL_add1_ext_i2d(variant, NID_authority_key_identifier, authority,
                                                 0, X509V3_ADD_REPLACE),
                           ==, 1);
          munit_assert_int(X509_CRL_set1_lastUpdate(variant, update), ==, 1);
          munit_assert_int(X509_CRL_sign(variant, other_key, EVP_sha256()), >, 0);
          AUTHORITY_KEYID_free(authority);
          ASN1_TIME_free(update);
          ASN1_INTEGER_free(number);
        }
        const int length = i2d_X509_CRL(variant, NULL);
        munit_assert_int(length, >, 0);
        munit_assert_size((size_t)length, <=, sizeof rollover_der[generation]);
        unsigned char* destination = rollover_der[generation];
        munit_assert_int(i2d_X509_CRL(variant, &destination), ==, length);
        rollover_inputs[generation] = (TC_bytes){rollover_der[generation], (size_t)length};
        if (generation)
          newest = variant;
        else
          X509_CRL_free(variant);
      }
      munit_assert_int(ASN1_INTEGER_set(X509_get_serialNumber(replacement), 3), ==, 1);
      const size_t alternative_length = encode_certificate(replacement, generated, EVP_sha256(),
                                                           alternative_der, sizeof alternative_der);
      X509_free(replacement);
      const TC_bytes signer_inputs[] = {{signer_der, (size_t)signer_length},
                                        {replacement_der, replacement_length}};
      candidate_source signer_source = {signer_inputs, PARTITIONS, 0, TC_TLV_OK, 0};
      const TC_X509_store_source signer_records = {&signer_source, PARTITIONS, 0, read_candidate,
                                                   NULL};
      candidate_source rollover_source = {rollover_inputs, PARTITIONS, 0, TC_TLV_OK, 0};
      const tc_pki_record_source rollover_records = {&rollover_source, PARTITIONS, read_candidate};
      TC_X509_path_options rollover_options = options;
      rollover_options.at.day = 2;
      enum { NEWER, TIED, BAD_SIGNATURE, UNNUMBERED, ROLLOVER_CASES };
      for (unsigned kind = NEWER; kind < ROLLOVER_CASES; ++kind) {
        ASN1_INTEGER* number = ASN1_INTEGER_new();
        ASN1_TIME* update = ASN1_TIME_new();
        munit_assert_not_null(number);
        munit_assert_not_null(update);
        munit_assert_int(ASN1_INTEGER_set(number, kind == TIED ? 1 : 2), ==, 1);
        munit_assert_int(
            ASN1_TIME_set_string(update, kind == TIED ? "260101000000Z" : "260102000000Z"), ==, 1);
        munit_assert_int(
            X509_CRL_add1_ext_i2d(newest, NID_crl_number, number, 0, X509V3_ADD_REPLACE), ==, 1);
        munit_assert_int(X509_CRL_set1_lastUpdate(newest, update), ==, 1);
        ASN1_TIME_free(update);
        ASN1_INTEGER_free(number);
        if (kind == UNNUMBERED) {
          const int extension = X509_CRL_get_ext_by_NID(newest, NID_crl_number, -1);
          munit_assert_int(extension, >=, 0);
          X509_EXTENSION_free(X509_CRL_delete_ext(newest, extension));
        }
        munit_assert_int(X509_CRL_sign(newest, other_key, EVP_sha256()), >, 0);
        const int length = i2d_X509_CRL(newest, NULL);
        munit_assert_int(length, >, 0);
        munit_assert_size((size_t)length, <=, sizeof rollover_der[1]);
        unsigned char* destination = rollover_der[1];
        munit_assert_int(i2d_X509_CRL(newest, &destination), ==, length);
        if (kind == BAD_SIGNATURE)
          rollover_der[1][length - 1] ^= 1;
        rollover_inputs[1] = (TC_bytes){rollover_der[1], (size_t)length};
        for (unsigned order = 0; order < PARTITIONS; ++order) {
          tc_cms_candidates rollover_candidates;
          tc_cms_revocations rollover_reader;
          TC_X509_crl_record rows[PARTITIONS];
          TC_X509_crl_index index;
          uint8_t states[PARTITIONS];
          work = TRUST_WORK_BUDGET;
          munit_assert_int(tc_cms_candidates_init((TC_bytes){NULL, 0}, &signer_records, PARTITIONS,
                                                  PARTITIONS * ENCODED_CAPACITY, &limits, &tree,
                                                  &rollover_candidates),
                           ==, TC_TLV_OK);
          munit_assert_int(tc_cms_revocations_init((TC_bytes){NULL, 0}, &rollover_records,
                                                   PARTITIONS, sizeof rollover_der, &limits, &tree,
                                                   &rollover_reader),
                           ==, TC_TLV_OK);
          munit_assert_int(tc_cms_crl_index_init(&rollover_reader, &tree, oids, EXTENSION_CAPACITY,
                                                 rows, PARTITIONS, &index),
                           ==, TC_TLV_OK);
          for (unsigned reference = 0; reference < PARTITIONS; ++reference) {
            const unsigned generation = order ? PARTITIONS - 1 - reference : reference;
            munit_assert_int(tc_x509_crl_signer_validate(
                                 &rows[reference].crl, generation ? &replacement_view : &signer,
                                 &(tc_x509_crl_trust){
                                     &source, 1, &rollover_options,
                                     &(tc_pki_tree_workspace){validation.frames.data,
                                                              validation.frames.capacity, &work},
                                     &validation, &search,
                                     &(TC_X509_revocation_time){(&rollover_options)->at, 0, 0}},
                                 &scope.found),
                             ==,
                             generation && kind == BAD_SIGNATURE ? TC_X509_PATH_INVALID
                                                                 : TC_X509_PATH_VALID);
          }
          crl_path_probe probe = {{NULL, 0}, 1, 0, TC_X509_PATH_VALID, 0, NULL, 0};
          const tc_x509_crl_path_check check = {&probe, check_crl_path};
          evidence = (TC_X509_crl_evidence){0};
          work = TRUST_WORK_BUDGET;
          const TC_X509_crl_evidence empty = {0};
          const TC_TLV_result expected_result = kind == TIED         ? TC_TLV_INVALID
                                                : kind == UNNUMBERED ? TC_TLV_UNSUPPORTED
                                                                     : TC_TLV_OK;
          munit_assert_int(
              tc_cms_crl_point_process(
                  &rollover_candidates,
                  &(tc_x509_crl_scope_processing){
                      &index, 0, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER, &query,
                      states, sizeof states, &evidence, &check, NULL, NULL, NULL, NULL},
                  &(tc_x509_crl_trust){&source, 1, &rollover_options, &tree, &validation, &search,
                                       &(TC_X509_revocation_time){(&rollover_options)->at, 0, 0}}),
              ==, expected_result);
          munit_assert_size(probe.calls, ==, kind == BAD_SIGNATURE ? 1 : PARTITIONS);
          if (expected_result == TC_TLV_OK) {
            munit_assert_int(tc_x509_crl_evidence_status(&evidence, &status), ==, TC_TLV_OK);
            munit_assert_int(status, ==,
                             kind == BAD_SIGNATURE ? TC_X509_REVOCATION_GOOD
                                                   : TC_X509_REVOCATION_REVOKED);
            if (kind == NEWER)
              munit_assert_uint(evidence.revocation.reason, ==, 1);
          } else
            munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
          const size_t required_work = TRUST_WORK_BUDGET - work;
          const TC_X509_crl_evidence expected_evidence = evidence;
          munit_assert_size(required_work, >, 0);
          for (unsigned short_budget = 0; short_budget < 2; ++short_budget) {
            evidence = empty;
            probe.calls = 0;
            work = required_work - short_budget;
            munit_assert_int(
                tc_cms_crl_point_process(
                    &rollover_candidates,
                    &(tc_x509_crl_scope_processing){
                        &index, 0, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER, &query,
                        states, sizeof states, &evidence, &check, NULL, NULL, NULL, NULL},
                    &(tc_x509_crl_trust){
                        &source, 1, &rollover_options, &tree, &validation, &search,
                        &(TC_X509_revocation_time){(&rollover_options)->at, 0, 0}}),
                ==, short_budget ? TC_TLV_LIMIT : expected_result);
            if (short_budget)
              munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
            else
              assert_evidence_equal(&evidence, &expected_evidence);
          }
          if (kind == NEWER || kind == TIED) {
            if (kind == NEWER) {
              TC_X509_revocation_node nodes[1];
              const tc_cms_crl_resolution resolution = {
                  &rollover_candidates,    &index, &source,
                  &rollover_options,       1,      TC_X509_CRL_COMPLETE_ONLY,
                  TC_X509_CRL_ORDER_NUMBER};
              const tc_x509_crl_resolution_workspace workspace = {
                  &tree, &validation, &search, states, sizeof states, nodes, 1, 0, NULL, 0, NULL};
              evidence = empty;
              work = TRUST_WORK_BUDGET;
              munit_assert_int(
                  tc_cms_crl_resolve(&replacement_view, &resolution, &workspace, &evidence), ==,
                  TC_TLV_UNSUPPORTED);
              munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
              munit_assert_int(nodes[0].status, ==, TC_X509_REVOCATION_UNDETERMINED);
            }
            for (unsigned generation = 0; generation < PARTITIONS; ++generation) {
              for (unsigned rejected = 0; rejected < 2; ++rejected) {
                unresolved_crl_probe unresolved = {
                    {{NULL, 0}, 1, 0, TC_X509_PATH_VALID, 0, NULL, 0},
                    signer_inputs[generation],
                    rejected ? TC_X509_PATH_INVALID : TC_X509_PATH_UNSUPPORTED};
                const tc_x509_crl_path_check pending_check = {&unresolved,
                                                              check_unresolved_crl_path};
                const TC_TLV_result pending_result =
                    !rejected && (generation || kind == TIED) ? TC_TLV_UNSUPPORTED : TC_TLV_OK;
                evidence = empty;
                work = TRUST_WORK_BUDGET;
                munit_assert_int(
                    tc_cms_crl_point_process(
                        &rollover_candidates,
                        &(tc_x509_crl_scope_processing){&index, 0, TC_X509_CRL_COMPLETE_ONLY,
                                                        TC_X509_CRL_ORDER_NUMBER, &query, states,
                                                        sizeof states, &evidence, &pending_check,
                                                        NULL, NULL, NULL, NULL},
                        &(tc_x509_crl_trust){
                            &source, 1, &rollover_options, &tree, &validation, &search,
                            &(TC_X509_revocation_time){(&rollover_options)->at, 0, 0}}),
                    ==, pending_result);
                if (pending_result != TC_TLV_OK)
                  munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
                else {
                  munit_assert_int(tc_x509_crl_evidence_status(&evidence, &status), ==, TC_TLV_OK);
                  munit_assert_int(status, ==,
                                   generation ? TC_X509_REVOCATION_GOOD
                                              : TC_X509_REVOCATION_REVOKED);
                }
                const size_t required = TRUST_WORK_BUDGET - work;
                const TC_X509_crl_evidence expected = evidence;
                for (unsigned short_budget = 0; short_budget < 2; ++short_budget) {
                  evidence = empty;
                  work = required - short_budget;
                  munit_assert_int(
                      tc_cms_crl_point_process(
                          &rollover_candidates,
                          &(tc_x509_crl_scope_processing){&index, 0, TC_X509_CRL_COMPLETE_ONLY,
                                                          TC_X509_CRL_ORDER_NUMBER, &query, states,
                                                          sizeof states, &evidence, &pending_check,
                                                          NULL, NULL, NULL, NULL},
                          &(tc_x509_crl_trust){
                              &source, 1, &rollover_options, &tree, &validation, &search,
                              &(TC_X509_revocation_time){(&rollover_options)->at, 0, 0}}),
                      ==, short_budget ? TC_TLV_LIMIT : pending_result);
                  if (short_budget)
                    munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
                  else
                    assert_evidence_equal(&evidence, &expected);
                }
              }
            }
            const TC_bytes retry_inputs[] = {
                signer_inputs[0], signer_inputs[1], {alternative_der, alternative_length}};
            const size_t retry_count = sizeof retry_inputs / sizeof *retry_inputs;
            candidate_source retry_source = {retry_inputs, retry_count, 0, TC_TLV_OK, 0};
            const TC_X509_store_source retry_records = {&retry_source, retry_count, 0,
                                                        read_candidate, NULL};
            tc_cms_candidates retry_candidates;
            work = TRUST_WORK_BUDGET;
            munit_assert_int(tc_cms_candidates_init((TC_bytes){NULL, 0}, &retry_records,
                                                    retry_count, retry_count * ENCODED_CAPACITY,
                                                    &limits, &tree, &retry_candidates),
                             ==, TC_TLV_OK);
            unresolved_crl_probe unresolved = {{{NULL, 0}, 1, 0, TC_X509_PATH_VALID, 0, NULL, 0},
                                               signer_inputs[1],
                                               TC_X509_PATH_UNSUPPORTED};
            const tc_x509_crl_path_check retry_check = {&unresolved, check_unresolved_crl_path};
            evidence = empty;
            work = TRUST_WORK_BUDGET;
            munit_assert_int(
                tc_cms_crl_point_process(
                    &retry_candidates,
                    &(tc_x509_crl_scope_processing){
                        &index, 0, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER, &query,
                        states, sizeof states, &evidence, &retry_check, NULL, NULL, NULL, NULL},
                    &(tc_x509_crl_trust){
                        &source, 1, &rollover_options, &tree, &validation, &search,
                        &(TC_X509_revocation_time){(&rollover_options)->at, 0, 0}}),
                ==, kind == TIED ? TC_TLV_INVALID : TC_TLV_OK);
            munit_assert_size(unresolved.path.calls, >=, retry_count);
            if (kind == TIED)
              munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
            else {
              munit_assert_int(tc_x509_crl_evidence_status(&evidence, &status), ==, TC_TLV_OK);
              munit_assert_int(status, ==, TC_X509_REVOCATION_REVOKED);
            }
          }
          if (kind == UNNUMBERED) {
            work = TRUST_WORK_BUDGET;
            munit_assert_int(
                tc_cms_crl_point_process(
                    &rollover_candidates,
                    &(tc_x509_crl_scope_processing){
                        &index, 0, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_THIS_UPDATE, &query,
                        states, sizeof states, &evidence, &check, NULL, NULL, NULL, NULL},
                    &(tc_x509_crl_trust){
                        &source, 1, &rollover_options, &tree, &validation, &search,
                        &(TC_X509_revocation_time){(&rollover_options)->at, 0, 0}}),
                ==, TC_TLV_OK);
            munit_assert_int(tc_x509_crl_evidence_status(&evidence, &status), ==, TC_TLV_OK);
            munit_assert_int(status, ==, TC_X509_REVOCATION_REVOKED);
          }
          TC_bytes swap = rollover_inputs[0];
          rollover_inputs[0] = rollover_inputs[1];
          rollover_inputs[1] = swap;
        }
      }
      {
        enum { OLD_COMPLETE, NEW_COMPLETE, NEW_DELTA, RECORDS };
        static const unsigned orders[][RECORDS] = {
            {OLD_COMPLETE, NEW_COMPLETE, NEW_DELTA}, {OLD_COMPLETE, NEW_DELTA, NEW_COMPLETE},
            {NEW_COMPLETE, OLD_COMPLETE, NEW_DELTA}, {NEW_COMPLETE, NEW_DELTA, OLD_COMPLETE},
            {NEW_DELTA, OLD_COMPLETE, NEW_COMPLETE}, {NEW_DELTA, NEW_COMPLETE, OLD_COMPLETE}};
        static const TC_X509_crl_delta_policy policies[] = {
            TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_DELTA_IF_AVAILABLE, TC_X509_CRL_DELTA_REQUIRED};
        uint8_t pair_der[2][ENCODED_CAPACITY], conflict_der[ENCODED_CAPACITY];
        X509_CRL* conflicting = make_partition_crl(crl, generated, TC_X509_CRL_ALL_REASONS, 1);
        const int conflict_length = i2d_X509_CRL(conflicting, NULL);
        munit_assert_int(conflict_length, >, 0);
        munit_assert_size((size_t)conflict_length, <=, sizeof conflict_der);
        unsigned char* conflict_destination = conflict_der;
        munit_assert_int(i2d_X509_CRL(conflicting, &conflict_destination), ==, conflict_length);
        X509_CRL_free(conflicting);
        TC_bytes inputs[RECORDS] = {rollover_inputs[0]};
        for (unsigned member = 0; member < 2; ++member) {
          X509_CRL* variant = member
                                  ? X509_CRL_dup(newest)
                                  : make_partition_crl(crl, other_key, TC_X509_CRL_ALL_REASONS, 0);
          ASN1_INTEGER* number = ASN1_INTEGER_new();
          ASN1_TIME* update = ASN1_TIME_new();
          munit_assert_not_null(variant);
          munit_assert_not_null(number);
          munit_assert_not_null(update);
          if (!member) {
            AUTHORITY_KEYID* authority =
                X509_CRL_get_ext_d2i(newest, NID_authority_key_identifier, NULL, NULL);
            munit_assert_not_null(authority);
            munit_assert_int(X509_CRL_add1_ext_i2d(variant, NID_authority_key_identifier, authority,
                                                   0, X509V3_ADD_REPLACE),
                             ==, 1);
            AUTHORITY_KEYID_free(authority);
          }
          munit_assert_int(ASN1_INTEGER_set(number, member ? 3 : 2), ==, 1);
          munit_assert_int(
              X509_CRL_add1_ext_i2d(variant, NID_crl_number, number, 0, X509V3_ADD_REPLACE), ==, 1);
          if (member) {
            munit_assert_int(ASN1_INTEGER_set(number, 2), ==, 1);
            munit_assert_int(X509_CRL_add1_ext_i2d(variant, NID_delta_crl, number, 1, 0), ==, 1);
          }
          munit_assert_int(ASN1_TIME_set_string(update, member ? "260103000000Z" : "260102000000Z"),
                           ==, 1);
          munit_assert_int(X509_CRL_set1_lastUpdate(variant, update), ==, 1);
          munit_assert_int(X509_CRL_sign(variant, other_key, EVP_sha256()), >, 0);
          const int length = i2d_X509_CRL(variant, NULL);
          munit_assert_int(length, >, 0);
          munit_assert_size((size_t)length, <=, sizeof pair_der[member]);
          unsigned char* destination = pair_der[member];
          munit_assert_int(i2d_X509_CRL(variant, &destination), ==, length);
          inputs[member ? NEW_DELTA : NEW_COMPLETE] = (TC_bytes){pair_der[member], (size_t)length};
          ASN1_INTEGER_free(number);
          ASN1_TIME_free(update);
          X509_CRL_free(variant);
        }
        rollover_options.at.day = 3;
        for (size_t order = 0; order < sizeof orders / sizeof *orders; ++order) {
          TC_bytes ordered[RECORDS];
          for (unsigned i = 0; i < RECORDS; ++i)
            ordered[i] = inputs[orders[order][i]];
          candidate_source pair_source = {ordered, RECORDS, 0, TC_TLV_OK, 0};
          const tc_pki_record_source pair_records = {&pair_source, RECORDS, read_candidate};
          tc_cms_candidates pair_candidates;
          tc_cms_revocations pair_reader;
          TC_X509_crl_record rows[RECORDS];
          TC_X509_crl_index index;
          uint8_t states[RECORDS];
          work = TRUST_WORK_BUDGET;
          munit_assert_int(tc_cms_candidates_init((TC_bytes){NULL, 0}, &signer_records, PARTITIONS,
                                                  PARTITIONS * ENCODED_CAPACITY, &limits, &tree,
                                                  &pair_candidates),
                           ==, TC_TLV_OK);
          munit_assert_int(tc_cms_revocations_init((TC_bytes){NULL, 0}, &pair_records, RECORDS,
                                                   RECORDS * ENCODED_CAPACITY, &limits, &tree,
                                                   &pair_reader),
                           ==, TC_TLV_OK);
          munit_assert_int(tc_cms_crl_index_init(&pair_reader, &tree, oids, EXTENSION_CAPACITY,
                                                 rows, RECORDS, &index),
                           ==, TC_TLV_OK);
          selected_crl_probe probe = {{{NULL, 0}, 1, 0, TC_X509_PATH_VALID, 0, NULL, 0},
                                      inputs[NEW_COMPLETE],
                                      inputs[NEW_DELTA],
                                      0};
          const tc_x509_crl_path_check check = {&probe, check_selected_crl_path};
          for (size_t policy = 0; policy < sizeof policies / sizeof *policies; ++policy) {
            probe.pairs = 0;
            evidence = (TC_X509_crl_evidence){0};
            work = TRUST_WORK_BUDGET;
            munit_assert_int(tc_cms_crl_point_process(
                                 &pair_candidates,
                                 &(tc_x509_crl_scope_processing){&index, 0, policies[policy],
                                                                 TC_X509_CRL_ORDER_NUMBER, &query,
                                                                 states, sizeof states, &evidence,
                                                                 &check, NULL, NULL, NULL, NULL},
                                 &(tc_x509_crl_trust){
                                     &source, 1, &rollover_options, &tree, &validation, &search,
                                     &(TC_X509_revocation_time){(&rollover_options)->at, 0, 0}}),
                             ==, TC_TLV_OK);
            munit_assert_int(tc_x509_crl_evidence_status(&evidence, &status), ==, TC_TLV_OK);
            munit_assert_int(status, ==,
                             policies[policy] == TC_X509_CRL_COMPLETE_ONLY
                                 ? TC_X509_REVOCATION_GOOD
                                 : TC_X509_REVOCATION_REVOKED);
            munit_assert_size(probe.pairs, ==,
                              policies[policy] == TC_X509_CRL_COMPLETE_ONLY ? 0 : PARTITIONS);
            /* A damaged delta cannot supply the revocation entry. */
            const size_t signature_end = inputs[NEW_DELTA].length - 1;
            pair_der[1][signature_end] ^= 1;
            const TC_X509_crl_evidence empty = {0};
            probe.pairs = 0;
            evidence = empty;
            work = TRUST_WORK_BUDGET;
            munit_assert_int(
                tc_cms_crl_point_process(
                    &pair_candidates,
                    &(tc_x509_crl_scope_processing){
                        &index, 0, policies[policy], TC_X509_CRL_ORDER_NUMBER, &query, states,
                        sizeof states, &evidence, &check, NULL, NULL, NULL, NULL},
                    &(tc_x509_crl_trust){
                        &source, 1, &rollover_options, &tree, &validation, &search,
                        &(TC_X509_revocation_time){(&rollover_options)->at, 0, 0}}),
                ==, policies[policy] == TC_X509_CRL_DELTA_REQUIRED ? TC_TLV_INVALID : TC_TLV_OK);
            munit_assert_size(probe.pairs, ==, 0);
            if (policies[policy] == TC_X509_CRL_DELTA_REQUIRED) {
              munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
            } else {
              munit_assert_int(tc_x509_crl_evidence_status(&evidence, &status), ==, TC_TLV_OK);
              munit_assert_int(status, ==, TC_X509_REVOCATION_GOOD);
            }
            pair_der[1][signature_end] ^= 1;
          }
          /* The newer complete CRL supersedes the old key's conflict.
                   */
          for (unsigned i = 0; i < RECORDS; ++i) {
            if (orders[order][i] == NEW_DELTA)
              ordered[i] = (TC_bytes){conflict_der, (size_t)conflict_length};
          }
          work = TRUST_WORK_BUDGET;
          munit_assert_int(tc_cms_crl_index_init(&pair_reader, &tree, oids, EXTENSION_CAPACITY,
                                                 rows, RECORDS, &index),
                           ==, TC_TLV_OK);
          for (unsigned damaged = 0; damaged < 2; ++damaged) {
            const TC_X509_crl_evidence empty = {0};
            evidence = empty;
            work = TRUST_WORK_BUDGET;
            if (damaged)
              pair_der[0][inputs[NEW_COMPLETE].length - 1] ^= 1;
            munit_assert_int(
                tc_cms_crl_point_process(
                    &pair_candidates,
                    &(tc_x509_crl_scope_processing){
                        &index, 0, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER, &query,
                        states, sizeof states, &evidence, &check, NULL, NULL, NULL, NULL},
                    &(tc_x509_crl_trust){
                        &source, 1, &rollover_options, &tree, &validation, &search,
                        &(TC_X509_revocation_time){(&rollover_options)->at, 0, 0}}),
                ==, damaged ? TC_TLV_INVALID : TC_TLV_OK);
            if (damaged) {
              munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
              pair_der[0][inputs[NEW_COMPLETE].length - 1] ^= 1;
            } else {
              munit_assert_int(tc_x509_crl_evidence_status(&evidence, &status), ==, TC_TLV_OK);
              munit_assert_int(status, ==, TC_X509_REVOCATION_GOOD);
            }
          }
        }
      }
      X509_CRL_free(newest);
    }
  }
  return MUNIT_OK;
}

/* Delegated CRL issuers whose own revocation status is a dependency, with
 * dependency limits, source failures and resolution. */
static MunitResult discovery_dependencies(const MunitParameter params[], void* user)
{
  revocation_fixture* f = user;
  uint8_t* const signer_der = f->signer_der;
  TC_bytes* const oids = f->oids;
  TC_X509_store_anchor* const anchors = f->anchors;
  TC_X509_path_workspace validation = f->validation;
  TC_X509_search_workspace search = f->search;
  TC_X509_workspace parser = f->parser;
  TC_X509_certificate signer = f->signer;
  const TC_TLV_limits limits = f->limits;
  TC_X509_signature_provider provider = f->provider;
  const TC_X509_store_source source = f->source;
  TC_X509_path_options options = f->options;
  EVP_PKEY* generated = f->generated;
  EVP_PKEY* other_key = f->other_key;
  X509* certificate = f->certificate;
  const int signer_length = f->signer_length;
  X509_CRL* crl = f->crl;
  size_t work = 0;
  const tc_pki_tree_workspace tree = {f->frames, FRAME_CAPACITY, &work};
  crl_scope_context scope;
  crl_scope_init(f, &tree, &scope);
  TC_X509_crl_evidence evidence = scope.initial;
  TC_X509_revocation_status status;
  (void)params;
  {
    {
      enum { ISSUER_SERIAL = 2, LEAF_SERIAL = 9, DEPENDENCIES = 2 };
      uint8_t issuer_der[ENCODED_CAPACITY], leaf_der[ENCODED_CAPACITY];
      uint8_t child_der[ENCODED_CAPACITY], root_der[ENCODED_CAPACITY];
      X509* issuer = make_certificate(other_key, "Delegated issuer", certificate);
      munit_assert_int(ASN1_INTEGER_set(X509_get_serialNumber(issuer), ISSUER_SERIAL), ==, 1);
      add_extension(issuer, NID_basic_constraints, "critical,CA:TRUE");
      add_extension(issuer, NID_key_usage, "critical,keyCertSign,cRLSign");
      add_extension(issuer, NID_subject_key_identifier, "hash");
      const size_t issuer_length =
          encode_certificate(issuer, generated, EVP_sha256(), issuer_der, sizeof issuer_der);
      X509* leaf = make_certificate(generated, "Target", issuer);
      munit_assert_int(ASN1_INTEGER_set(X509_get_serialNumber(leaf), LEAF_SERIAL), ==, 1);
      const size_t leaf_length =
          encode_certificate(leaf, other_key, EVP_sha256(), leaf_der, sizeof leaf_der);
      X509_free(leaf);
      TC_X509_certificate leaf_view;
      munit_assert_int(
          TC_X509_read((TC_bytes){leaf_der, leaf_length}, &limits, &parser, &leaf_view), ==,
          TC_TLV_OK);
      const TC_bytes chain[] = {{issuer_der, issuer_length}, {leaf_der, leaf_length}};
      TC_X509_path_result validated;
      work = TRUST_WORK_BUDGET;
      munit_assert_int(tc_x509_path_validate_budget(chain, DEPENDENCIES, &anchors[1].trust,
                                                    &options, &validation, &work, &validated),
                       ==, TC_X509_PATH_VALID);
      X509_CRL* child = make_partition_crl(crl, other_key, TC_X509_CRL_ALL_REASONS, 0);
      munit_assert_int(X509_CRL_set_issuer_name(child, X509_get_subject_name(issuer)), ==, 1);
      AUTHORITY_KEYID* authority = AUTHORITY_KEYID_new();
      munit_assert_not_null(authority);
      authority->keyid = X509_get_ext_d2i(issuer, NID_subject_key_identifier, NULL, NULL);
      munit_assert_not_null(authority->keyid);
      munit_assert_int(X509_CRL_add1_ext_i2d(child, NID_authority_key_identifier, authority, 0,
                                             X509V3_ADD_REPLACE),
                       ==, 1);
      AUTHORITY_KEYID_free(authority);
      X509_free(issuer);
      munit_assert_int(X509_CRL_sign(child, other_key, EVP_sha256()), >, 0);
      const int child_length = i2d_X509_CRL(child, NULL);
      munit_assert_int(child_length, >, 0);
      munit_assert_size((size_t)child_length, <=, sizeof child_der);
      unsigned char* destination = child_der;
      munit_assert_int(i2d_X509_CRL(child, &destination), ==, child_length);
      X509_CRL_free(child);
      const TC_bytes signers[] = {{signer_der, (size_t)signer_length}, {issuer_der, issuer_length}};
      candidate_source signer_source = {signers, DEPENDENCIES, 0, TC_TLV_OK, 0};
      dependency_source_probe dependency_source = {&signer_source, NULL, TC_TLV_OK, 0};
      const TC_X509_store_source signer_records = {&dependency_source, DEPENDENCIES, 0,
                                                   read_dependency_candidate, NULL};
      combined_store_source combined = {&signer_records, &source};
      const TC_X509_store_source complete_source = {&combined, DEPENDENCIES, source.anchor_count,
                                                    combined_candidate, combined_anchor};
      tc_cms_candidates signer_reader;
      work = TRUST_WORK_BUDGET;
      munit_assert_int(tc_cms_candidates_init((TC_bytes){NULL, 0}, &signer_records, DEPENDENCIES,
                                              sizeof issuer_der + ENCODED_CAPACITY, &limits, &tree,
                                              &signer_reader),
                       ==, TC_TLV_OK);
      for (unsigned rejected = 0; rejected < 2; ++rejected) {
        X509_CRL* root = make_partition_crl(crl, generated, TC_X509_CRL_ALL_REASONS, (int)rejected);
        if (rejected) {
          ASN1_INTEGER* serial = ASN1_INTEGER_new();
          munit_assert_not_null(serial);
          munit_assert_int(ASN1_INTEGER_set(serial, ISSUER_SERIAL), ==, 1);
          munit_assert_int(X509_REVOKED_set_serialNumber(
                               sk_X509_REVOKED_value(X509_CRL_get_REVOKED(root), 0), serial),
                           ==, 1);
          ASN1_INTEGER_free(serial);
        }
        munit_assert_int(X509_CRL_sign(root, generated, EVP_sha256()), >, 0);
        const int root_length = i2d_X509_CRL(root, NULL);
        munit_assert_int(root_length, >, 0);
        munit_assert_size((size_t)root_length, <=, sizeof root_der);
        destination = root_der;
        munit_assert_int(i2d_X509_CRL(root, &destination), ==, root_length);
        X509_CRL_free(root);
        const TC_bytes inputs[] = {{child_der, (size_t)child_length},
                                   {root_der, (size_t)root_length}};
        candidate_source crls = {inputs, DEPENDENCIES, 0, TC_TLV_OK, 0};
        const tc_pki_record_source crl_records = {&crls, DEPENDENCIES, read_candidate};
        tc_cms_revocations crl_reader;
        TC_X509_crl_record rows[DEPENDENCIES];
        TC_X509_crl_index index;
        TC_X509_revocation_node nodes[DEPENDENCIES] = {0};
        TC_X509_revocation_scope scopes[DEPENDENCIES];
        TC_bytes signer_path[PATH_CAPACITY], signer_policies[POLICY_CAPACITY];
        uint8_t states[DEPENDENCIES];
        work = TRUST_WORK_BUDGET;
        munit_assert_int(tc_cms_revocations_init((TC_bytes){NULL, 0}, &crl_records, DEPENDENCIES,
                                                 sizeof child_der + sizeof root_der, &limits, &tree,
                                                 &crl_reader),
                         ==, TC_TLV_OK);
        munit_assert_int(tc_cms_crl_index_init(&crl_reader, &tree, oids, EXTENSION_CAPACITY, rows,
                                               DEPENDENCIES, &index),
                         ==, TC_TLV_OK);
        const tc_cms_crl_resolution resolution = {
            &signer_reader,          &index, &source, &options, 1, TC_X509_CRL_COMPLETE_ONLY,
            TC_X509_CRL_ORDER_NUMBER};
        tc_x509_crl_resolution_workspace workspace = {
            &tree,        &validation, &search, states, sizeof states, nodes,
            DEPENDENCIES, 0,           NULL,    0,      NULL};
        const TC_X509_crl_evidence empty = {0};
        TC_X509_revocation_result path_evidence, path_sentinel;
        memset(&path_sentinel, 0xa5, sizeof path_sentinel);
        TC_X509_revocation_options public_options = {&index,
                                                     &complete_source,
                                                     &options,
                                                     1,
                                                     sizeof issuer_der + ENCODED_CAPACITY,
                                                     TC_X509_CRL_COMPLETE_ONLY,
                                                     TC_X509_CRL_ORDER_NUMBER,
                                                     {options.at, 0, 0},
                                                     {NULL, 0, 0, 0}};
        if (!rejected) {
          TC_X509_certificate issuer_view;
          munit_assert_int(
              TC_X509_read((TC_bytes){issuer_der, issuer_length}, &limits, &parser, &issuer_view),
              ==, TC_TLV_OK);
          signature_retry_probe signature_count = {provider, 0, 0, TC_X509_SIGNATURE_ERROR};
          TC_X509_path_options counted = options;
          counted.signatures =
              (TC_X509_signature_provider){retry_signature, &signature_count, retry_digest};
          const tc_x509_crl_trust trusted = {&complete_source,
                                             1,
                                             &counted,
                                             &tree,
                                             &validation,
                                             &search,
                                             &(TC_X509_revocation_time){(&counted)->at, 0, 0}};
          const tc_pki_distribution_point fallback = {0};
          const tc_x509_crl_query query = {&issuer_view, &fallback, 0};
          TC_X509_crl_evidence evidence = {0};
          tc_x509_crl_signer_cache signer_cache = {
              {0}, {0}, signer_path, PATH_CAPACITY, signer_policies, POLICY_CAPACITY, 0};
          tc_x509_crl_scope_processing attempt = {&index,
                                                  1,
                                                  TC_X509_CRL_COMPLETE_ONLY,
                                                  TC_X509_CRL_ORDER_NUMBER,
                                                  &query,
                                                  states,
                                                  sizeof states,
                                                  &evidence,
                                                  NULL,
                                                  NULL,
                                                  NULL,
                                                  NULL,
                                                  &signer_cache};
          TC_X509_search_result first, second;
          work = TRUST_WORK_BUDGET;
          munit_assert_int(tc_x509_crl_scope_attempt(&attempt, &signer, &trusted, &first), ==,
                           TC_TLV_OK);
          munit_assert_int(signer_cache.valid, ==, 1);
          munit_assert_size(signature_count.calls, >, 0);
          const size_t verified = signature_count.calls;
          const size_t first_work = TRUST_WORK_BUDGET - work;
          evidence = (TC_X509_crl_evidence){0};
          work = TRUST_WORK_BUDGET;
          munit_assert_int(tc_x509_crl_scope_attempt(&attempt, &signer, &trusted, &second), ==,
                           TC_TLV_OK);
          munit_assert_size(signature_count.calls, ==, verified);
          munit_assert_size(TRUST_WORK_BUDGET - work, <, first_work);
          munit_assert_ptr_equal(second.path, signer_path);
          munit_assert_size(second.count, ==, first.count);
        }
        TC_X509_revocation_workspace public_workspace = {
            &validation, &search,       states,          sizeof states,
            nodes,       DEPENDENCIES,  scopes,          DEPENDENCIES,
            signer_path, PATH_CAPACITY, signer_policies, POLICY_CAPACITY};
        public_workspace.scope_capacity = 1;
        work = TRUST_WORK_BUDGET;
        path_evidence = path_sentinel;
        munit_assert_int(TC_X509_path_check_revocation(chain, DEPENDENCIES, &public_options,
                                                       &public_workspace, &work, &path_evidence),
                         ==, TC_TLV_LIMIT);
        munit_assert_memory_equal(sizeof path_evidence, &path_evidence, &path_sentinel);
        public_workspace.scope_capacity = DEPENDENCIES;
        public_workspace.signer_path_capacity = 1;
        munit_assert_int(TC_X509_path_check_revocation(chain, DEPENDENCIES, &public_options,
                                                       &public_workspace, &work, &path_evidence),
                         ==, TC_TLV_LIMIT);
        public_workspace.signer_path_capacity = PATH_CAPACITY;
        public_workspace.signer_policy_capacity = 1;
        munit_assert_int(TC_X509_path_check_revocation(chain, DEPENDENCIES, &public_options,
                                                       &public_workspace, &work, &path_evidence),
                         ==, TC_TLV_LIMIT);
        public_workspace.signer_policy_capacity = POLICY_CAPACITY;
        path_evidence = path_sentinel;
        work = TRUST_WORK_BUDGET;
        munit_assert_int(TC_X509_path_check_revocation(chain, DEPENDENCIES, &public_options,
                                                       &public_workspace, &work, &path_evidence),
                         ==, TC_TLV_OK);
        munit_assert_int(path_evidence.status, ==,
                         rejected ? TC_X509_REVOCATION_REVOKED : TC_X509_REVOCATION_GOOD);
        munit_assert_size(path_evidence.certificate_index, ==, rejected ? 0 : SIZE_MAX);
        const size_t public_work = TRUST_WORK_BUDGET - work;
        if (!rejected) {
          /* One storage preflight covers the whole path. Each padding
                   * record adds preflight work, so a second member must cost
                   * far less extra than the padding adds to the first. */
          enum { PADDING = 16, PADDED = DEPENDENCIES + PADDING };
          TC_X509_crl_record padded_rows[PADDED] = {0};
          memcpy(padded_rows, rows, sizeof rows);
          for (size_t pad = DEPENDENCIES; pad < PADDED; ++pad)
            padded_rows[pad].policy = TC_TLV_UNSUPPORTED;
          const TC_X509_crl_index padded = {padded_rows, PADDED, 0};
          uint8_t padded_states[PADDED];
          TC_X509_revocation_scope padded_scopes[PADDED];
          TC_X509_revocation_options padded_options = public_options;
          padded_options.index = &padded;
          TC_X509_revocation_workspace padded_workspace = public_workspace;
          padded_workspace.states = padded_states;
          padded_workspace.state_capacity = PADDED;
          padded_workspace.scopes = padded_scopes;
          padded_workspace.scope_capacity = PADDED;
          size_t cost[2][2];
          for (size_t members = 1; members <= DEPENDENCIES; ++members)
            for (unsigned pad = 0; pad < 2; ++pad) {
              path_evidence = path_sentinel;
              work = TRUST_WORK_BUDGET;
              munit_assert_int(TC_X509_path_check_revocation(
                                   chain, members, pad ? &padded_options : &public_options,
                                   pad ? &padded_workspace : &public_workspace, &work,
                                   &path_evidence),
                               ==, TC_TLV_OK);
              munit_assert_int(path_evidence.status, ==, TC_X509_REVOCATION_GOOD);
              cost[members - 1][pad] = TRUST_WORK_BUDGET - work;
            }
          const size_t first = cost[0][1] - cost[0][0];
          const size_t second = cost[1][1] - cost[1][0];
          munit_assert_size(first, >, 0);
          munit_assert_size(second, >=, first);
          munit_assert_size(second - first, <, first / 2);
        }
        {
          /* Every candidate CRL failing as invalid data gives INVALID,
                   * with the result unchanged. */
          uint8_t* signatures[DEPENDENCIES];
          for (size_t row = 0; row < DEPENDENCIES; ++row) {
            const TC_bytes signature = rows[row].crl.signature;
            signatures[row] = (uint8_t*)signature.data + signature.length - 1;
            *signatures[row] ^= 1;
          }
          path_evidence = path_sentinel;
          work = TRUST_WORK_BUDGET;
          munit_assert_int(TC_X509_path_check_revocation(chain, DEPENDENCIES, &public_options,
                                                         &public_workspace, &work, &path_evidence),
                           ==, TC_TLV_INVALID);
          munit_assert_int(path_evidence.status, ==, path_sentinel.status);
          munit_assert_size(path_evidence.certificate_index, ==, path_sentinel.certificate_index);
          munit_assert_uint(path_evidence.evidence.reasons, ==, path_sentinel.evidence.reasons);
          munit_assert_int(path_evidence.evidence.revocation.found, ==,
                           path_sentinel.evidence.revocation.found);
          /* An unsupported candidate takes precedence over invalid ones. */
          TC_X509_crl_record unsupported_rows[DEPENDENCIES + 1] = {0};
          memcpy(unsupported_rows, rows, sizeof rows);
          unsupported_rows[DEPENDENCIES].policy = TC_TLV_UNSUPPORTED;
          const TC_X509_crl_index unsupported_index = {unsupported_rows, DEPENDENCIES + 1, 0};
          uint8_t unsupported_states[DEPENDENCIES + 1];
          TC_X509_revocation_scope unsupported_scopes[DEPENDENCIES + 1];
          TC_X509_revocation_options unsupported_options = public_options;
          unsupported_options.index = &unsupported_index;
          TC_X509_revocation_workspace unsupported_workspace = public_workspace;
          unsupported_workspace.states = unsupported_states;
          unsupported_workspace.state_capacity = DEPENDENCIES + 1;
          unsupported_workspace.scopes = unsupported_scopes;
          unsupported_workspace.scope_capacity = DEPENDENCIES + 1;
          path_evidence = path_sentinel;
          work = TRUST_WORK_BUDGET;
          munit_assert_int(TC_X509_path_check_revocation(chain, DEPENDENCIES, &unsupported_options,
                                                         &unsupported_workspace, &work,
                                                         &path_evidence),
                           ==, TC_TLV_UNSUPPORTED);
          munit_assert_int(path_evidence.status, ==, path_sentinel.status);
          munit_assert_size(path_evidence.certificate_index, ==, path_sentinel.certificate_index);
          for (size_t row = 0; row < DEPENDENCIES; ++row)
            *signatures[row] ^= 1;
        }
        for (unsigned short_budget = 0; short_budget < 2; ++short_budget) {
          path_evidence = path_sentinel;
          work = public_work - short_budget;
          munit_assert_int(TC_X509_path_check_revocation(chain, DEPENDENCIES, &public_options,
                                                         &public_workspace, &work, &path_evidence),
                           ==, short_budget ? TC_TLV_LIMIT : TC_TLV_OK);
          if (short_budget)
            munit_assert_memory_equal(sizeof path_evidence, &path_evidence, &path_sentinel);
        }
        const size_t saved_byte_limit = public_options.max_candidate_bytes;
        public_options.max_candidate_bytes = 0;
        path_evidence = path_sentinel;
        work = TRUST_WORK_BUDGET;
        munit_assert_int(TC_X509_path_check_revocation(chain, DEPENDENCIES, &public_options,
                                                       &public_workspace, &work, &path_evidence),
                         ==, TC_TLV_LIMIT);
        munit_assert_memory_equal(sizeof path_evidence, &path_evidence, &path_sentinel);
        public_options.max_candidate_bytes = saved_byte_limit;
        /* A failed source read must not become an unrevoked decision.
                 */
        const struct {
          TC_TLV_result returned, expected;
        } source_failures[] = {{TC_TLV_UNSUPPORTED, TC_TLV_UNSUPPORTED},
                               {TC_TLV_INVALID, TC_TLV_ARGUMENT},
                               {TC_TLV_LIMIT, TC_TLV_LIMIT},
                               {TC_TLV_ARGUMENT, TC_TLV_ARGUMENT}};
        for (size_t failure = 0; failure < sizeof source_failures / sizeof source_failures[0];
             ++failure) {
          signer_source.status = source_failures[failure].returned;
          signer_source.calls = 0;
          path_evidence = path_sentinel;
          work = TRUST_WORK_BUDGET;
          munit_assert_int(TC_X509_path_check_revocation(chain, DEPENDENCIES, &public_options,
                                                         &public_workspace, &work, &path_evidence),
                           ==, source_failures[failure].expected);
          munit_assert_size(signer_source.calls, ==, 1);
          munit_assert_memory_equal(sizeof path_evidence, &path_evidence, &path_sentinel);
        }
        signer_source.status = TC_TLV_OK;
        signer_source.increase_work = 1;
        signer_source.calls = 0;
        path_evidence = path_sentinel;
        work = TRUST_WORK_BUDGET;
        munit_assert_int(TC_X509_path_check_revocation(chain, DEPENDENCIES, &public_options,
                                                       &public_workspace, &work, &path_evidence),
                         ==, TC_TLV_ARGUMENT);
        munit_assert_size(signer_source.calls, ==, 1);
        munit_assert_memory_equal(sizeof path_evidence, &path_evidence, &path_sentinel);
        signer_source.increase_work = 0;
        TC_X509_revocation_options missing_index = public_options;
        TC_X509_revocation_options missing_source = public_options;
        TC_X509_revocation_options missing_policy = public_options;
        TC_X509_revocation_workspace missing_validation = public_workspace;
        TC_X509_revocation_workspace missing_search = public_workspace;
        missing_index.index = NULL;
        missing_source.source = NULL;
        missing_policy.signer_policy = NULL;
        missing_validation.validation = NULL;
        missing_search.search = NULL;
        const struct {
          const TC_bytes* path;
          size_t count;
          const TC_X509_revocation_options* options;
          const TC_X509_revocation_workspace* workspace;
          size_t* budget;
          TC_X509_revocation_result* result;
        } missing_inputs[] = {
            {NULL, DEPENDENCIES, &public_options, &public_workspace, &work, &path_evidence},
            {chain, 0, &public_options, &public_workspace, &work, &path_evidence},
            {chain, DEPENDENCIES, NULL, &public_workspace, &work, &path_evidence},
            {chain, DEPENDENCIES, &public_options, NULL, &work, &path_evidence},
            {chain, DEPENDENCIES, &public_options, &public_workspace, NULL, &path_evidence},
            {chain, DEPENDENCIES, &public_options, &public_workspace, &work, NULL},
            {chain, DEPENDENCIES, &missing_index, &public_workspace, &work, &path_evidence},
            {chain, DEPENDENCIES, &missing_source, &public_workspace, &work, &path_evidence},
            {chain, DEPENDENCIES, &missing_policy, &public_workspace, &work, &path_evidence},
            {chain, DEPENDENCIES, &public_options, &missing_validation, &work, &path_evidence},
            {chain, DEPENDENCIES, &public_options, &missing_search, &work, &path_evidence}};
        for (size_t i = 0; i < sizeof missing_inputs / sizeof *missing_inputs; ++i) {
          signer_source.calls = 0;
          path_evidence = path_sentinel;
          work = TRUST_WORK_BUDGET;
          munit_assert_int(
              TC_X509_path_check_revocation(missing_inputs[i].path, missing_inputs[i].count,
                                            missing_inputs[i].options, missing_inputs[i].workspace,
                                            missing_inputs[i].budget, missing_inputs[i].result),
              ==, TC_TLV_ARGUMENT);
          munit_assert_size(signer_source.calls, ==, 0);
          munit_assert_size(work, ==, TRUST_WORK_BUDGET);
          munit_assert_memory_equal(sizeof path_evidence, &path_evidence, &path_sentinel);
        }
        ExampleX509RevocationWorkspace example_storage;
        path_evidence = path_sentinel;
        work = TRUST_WORK_BUDGET;
        munit_assert_int(example_check_path_revocation(chain, DEPENDENCIES, &public_options, &work,
                                                       &example_storage, &path_evidence),
                         ==, TC_TLV_OK);
        munit_assert_int(path_evidence.status, ==,
                         rejected ? TC_X509_REVOCATION_REVOKED : TC_X509_REVOCATION_GOOD);
        munit_assert_size(path_evidence.certificate_index, ==, rejected ? 0 : SIZE_MAX);
        path_evidence = path_sentinel;
        work = TRUST_WORK_BUDGET;
        signer_source.calls = 0;
        public_workspace.states = (uint8_t*)&public_options;
        munit_assert_int(TC_X509_path_check_revocation(chain, DEPENDENCIES, &public_options,
                                                       &public_workspace, &work, &path_evidence),
                         ==, TC_TLV_ARGUMENT);
        munit_assert_size(work, ==, TRUST_WORK_BUDGET);
        munit_assert_size(signer_source.calls, ==, 0);
        munit_assert_memory_equal(sizeof path_evidence, &path_evidence, &path_sentinel);
        public_workspace.states = states;
        munit_assert_int(
            TC_X509_path_check_revocation(chain, DEPENDENCIES, &public_options, &public_workspace,
                                          &public_options.max_candidate_bytes, &path_evidence),
            ==, TC_TLV_ARGUMENT);
        munit_assert_size(public_options.max_candidate_bytes, ==, saved_byte_limit);
        munit_assert_size(signer_source.calls, ==, 0);
        path_evidence = path_sentinel;
        work = TRUST_WORK_BUDGET;
        munit_assert_int(
            tc_cms_crl_path_resolve(chain, DEPENDENCIES, &resolution, &workspace, &path_evidence),
            ==, TC_TLV_OK);
        munit_assert_int(path_evidence.status, ==,
                         rejected ? TC_X509_REVOCATION_REVOKED : TC_X509_REVOCATION_GOOD);
        munit_assert_size(path_evidence.certificate_index, ==, rejected ? 0 : SIZE_MAX);
        munit_assert_ptr_equal(nodes[0].certificate.data, issuer_der);
        if (!rejected) {
          munit_assert_ptr_equal(nodes[1].certificate.data, leaf_der);
          munit_assert_int(nodes[0].status, ==, TC_X509_REVOCATION_GOOD);
          munit_assert_int(nodes[1].status, ==, TC_X509_REVOCATION_GOOD);
        }
        const size_t path_work = TRUST_WORK_BUDGET - work;
        for (unsigned short_budget = 0; short_budget < 2; ++short_budget) {
          path_evidence = path_sentinel;
          work = path_work - short_budget;
          munit_assert_int(
              tc_cms_crl_path_resolve(chain, DEPENDENCIES, &resolution, &workspace, &path_evidence),
              ==, short_budget ? TC_TLV_LIMIT : TC_TLV_OK);
          if (short_budget)
            munit_assert_memory_equal(sizeof path_evidence, &path_evidence, &path_sentinel);
        }
        memcpy(search.path, chain, sizeof chain);
        path_evidence = path_sentinel;
        work = TRUST_WORK_BUDGET;
        munit_assert_int(tc_cms_crl_path_resolve(search.path, DEPENDENCIES, &resolution, &workspace,
                                                 &path_evidence),
                         ==, TC_TLV_ARGUMENT);
        munit_assert_size(work, ==, TRUST_WORK_BUDGET);
        munit_assert_memory_equal(sizeof path_evidence, &path_evidence, &path_sentinel);
        munit_assert_memory_equal(sizeof chain, search.path, chain);
        const struct {
          const TC_bytes* chain;
          size_t count;
          const tc_cms_crl_resolution* resolution;
          const tc_x509_crl_resolution_workspace* workspace;
          TC_X509_revocation_result* out;
        } invalid_paths[] = {{NULL, DEPENDENCIES, &resolution, &workspace, &path_evidence},
                             {chain, 0, &resolution, &workspace, &path_evidence},
                             {chain, SIZE_MAX, &resolution, &workspace, &path_evidence},
                             {chain, DEPENDENCIES, NULL, &workspace, &path_evidence},
                             {chain, DEPENDENCIES, &resolution, NULL, &path_evidence},
                             {chain, DEPENDENCIES, &resolution, &workspace, NULL}};
        for (size_t invalid = 0; invalid < sizeof invalid_paths / sizeof *invalid_paths;
             ++invalid) {
          path_evidence = path_sentinel;
          work = TRUST_WORK_BUDGET;
          munit_assert_int(
              tc_cms_crl_path_resolve(invalid_paths[invalid].chain, invalid_paths[invalid].count,
                                      invalid_paths[invalid].resolution,
                                      invalid_paths[invalid].workspace, invalid_paths[invalid].out),
              ==, TC_TLV_ARGUMENT);
          munit_assert_size(work, ==, TRUST_WORK_BUDGET);
          munit_assert_memory_equal(sizeof path_evidence, &path_evidence, &path_sentinel);
        }
        const TC_bytes invalid_members[] = {{NULL, 1},
                                            {leaf_der, 0},
                                            {states, sizeof states},
                                            {(const uint8_t*)&path_evidence, sizeof path_evidence}};
        for (size_t invalid = 0; invalid < sizeof invalid_members / sizeof *invalid_members;
             ++invalid) {
          const TC_bytes held[] = {chain[0], invalid_members[invalid]};
          uint8_t saved_nodes[sizeof nodes];
          memcpy(saved_nodes, nodes, sizeof nodes);
          path_evidence = path_sentinel;
          work = TRUST_WORK_BUDGET;
          munit_assert_int(
              tc_cms_crl_path_resolve(held, DEPENDENCIES, &resolution, &workspace, &path_evidence),
              ==, TC_TLV_ARGUMENT);
          munit_assert_size(work, ==, TRUST_WORK_BUDGET);
          munit_assert_memory_equal(sizeof path_evidence, &path_evidence, &path_sentinel);
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
        munit_assert_int(tc_cms_crl_path_resolve(chain, DEPENDENCIES, &resolution,
                                                 &overlap_workspace, &overlapping.result),
                         ==, TC_TLV_ARGUMENT);
        munit_assert_size(work, ==, TRUST_WORK_BUDGET);
        munit_assert_memory_equal(sizeof overlapping, &overlapping, saved_overlap);
        evidence = empty;
        work = TRUST_WORK_BUDGET;
        munit_assert_int(tc_cms_crl_resolve(&leaf_view, &resolution, &workspace, &evidence), ==,
                         rejected ? TC_TLV_INVALID : TC_TLV_OK);
        munit_assert_ptr_equal(nodes[1].certificate.data, issuer_der);
        munit_assert_int(nodes[1].status, ==,
                         rejected ? TC_X509_REVOCATION_REVOKED : TC_X509_REVOCATION_GOOD);
        const size_t required = TRUST_WORK_BUDGET - work;
        const TC_X509_crl_evidence expected_evidence = evidence;
        if (rejected)
          munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
        else {
          munit_assert_int(tc_x509_crl_evidence_status(&evidence, &status), ==, TC_TLV_OK);
          munit_assert_int(status, ==, TC_X509_REVOCATION_GOOD);
        }
        for (unsigned short_budget = 0; short_budget < 2; ++short_budget) {
          evidence = empty;
          work = required - short_budget;
          munit_assert_int(tc_cms_crl_resolve(&leaf_view, &resolution, &workspace, &evidence), ==,
                           short_budget ? TC_TLV_LIMIT
                           : rejected   ? TC_TLV_INVALID
                                        : TC_TLV_OK);
          if (short_budget)
            munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
          else
            assert_evidence_equal(&evidence, &expected_evidence);
        }
        signer_source.status = TC_TLV_UNSUPPORTED;
        signer_source.calls = 0;
        evidence = empty;
        work = TRUST_WORK_BUDGET;
        munit_assert_int(tc_cms_crl_resolve(&leaf_view, &resolution, &workspace, &evidence), ==,
                         TC_TLV_UNSUPPORTED);
        munit_assert_size(signer_source.calls, ==, 1);
        munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
        signer_source.status = TC_TLV_OK;
        for (size_t failure = 0; failure < sizeof source_failures / sizeof *source_failures;
             ++failure) {
          memset(nodes, 0, sizeof nodes);
          dependency_source.dependency = &nodes[1];
          dependency_source.failure = source_failures[failure].returned;
          dependency_source.failures = 0;
          evidence = empty;
          work = TRUST_WORK_BUDGET;
          munit_assert_int(tc_cms_crl_resolve(&leaf_view, &resolution, &workspace, &evidence), ==,
                           source_failures[failure].expected);
          munit_assert_size(dependency_source.failures, ==, 1);
          munit_assert_int(nodes[1].status, ==,
                           rejected ? TC_X509_REVOCATION_REVOKED : TC_X509_REVOCATION_GOOD);
          munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
        }
        dependency_source.dependency = NULL;
        /* Neither side of the dependency can establish the scope.target
                 * alone. */
        for (size_t available = 0; available < DEPENDENCIES; ++available) {
          const TC_X509_crl_index partial = {&rows[available], 1, 0};
          tc_cms_crl_resolution incomplete = resolution;
          incomplete.index = &partial;
          if (!rejected) {
            path_evidence = path_sentinel;
            work = TRUST_WORK_BUDGET;
            munit_assert_int(tc_cms_crl_path_resolve(chain, DEPENDENCIES, &incomplete, &workspace,
                                                     &path_evidence),
                             ==, TC_TLV_UNSUPPORTED);
            munit_assert_memory_equal(sizeof path_evidence, &path_evidence, &path_sentinel);
          }
          memset(nodes, 0, sizeof nodes);
          evidence = empty;
          work = TRUST_WORK_BUDGET;
          munit_assert_int(tc_cms_crl_resolve(&leaf_view, &incomplete, &workspace, &evidence), ==,
                           TC_TLV_UNSUPPORTED);
          munit_assert_int(nodes[0].status, ==, TC_X509_REVOCATION_UNDETERMINED);
          munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
          if (!available) {
            munit_assert_ptr_equal(nodes[1].certificate.data, issuer_der);
            munit_assert_int(nodes[1].status, ==, TC_X509_REVOCATION_UNDETERMINED);
          }
        }
        const TC_X509_crl_record swap = rows[0];
        rows[0] = rows[1];
        rows[1] = swap;
        evidence = empty;
        work = TRUST_WORK_BUDGET;
        munit_assert_int(tc_cms_crl_resolve(&leaf_view, &resolution, &workspace, &evidence), ==,
                         rejected ? TC_TLV_INVALID : TC_TLV_OK);
        if (rejected)
          munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
        else {
          int equal;
          munit_assert_int(tc_x509_crl_evidence_equal(&evidence, &expected_evidence, &equal), ==,
                           TC_TLV_OK);
          munit_assert_true(equal);
        }
        if (!rejected) {
          const unsigned char* input = child_der;
          X509_CRL* template = d2i_X509_CRL(NULL, &input, child_length);
          munit_assert_not_null(template);
          X509_CRL* revoked_leaf =
              make_partition_crl(template, other_key, TC_X509_CRL_ALL_REASONS, 1);
          X509_CRL_free(template);
          uint8_t revoked_der[ENCODED_CAPACITY];
          const int length = i2d_X509_CRL(revoked_leaf, NULL);
          munit_assert_int(length, >, 0);
          munit_assert_size((size_t)length, <=, sizeof revoked_der);
          unsigned char* output = revoked_der;
          munit_assert_int(i2d_X509_CRL(revoked_leaf, &output), ==, length);
          X509_CRL_free(revoked_leaf);
          TC_X509_crl_record revoked_rows[] = {rows[0], rows[1]};
          work = TRUST_WORK_BUDGET;
          munit_assert_int(tc_x509_crl_read((TC_bytes){revoked_der, (size_t)length}, &limits, &tree,
                                            &revoked_rows[1].crl),
                           ==, TC_TLV_OK);
          munit_assert_int(tc_x509_crl_extension_info_read(revoked_rows[1].crl.extensions, &limits,
                                                           &tree, oids, EXTENSION_CAPACITY,
                                                           &revoked_rows[1].extensions),
                           ==, TC_TLV_OK);
          revoked_rows[1].policy = tc_x509_crl_extension_policy(&revoked_rows[1].extensions);
          const TC_X509_crl_index revoked_index = {revoked_rows, DEPENDENCIES, 0};
          tc_cms_crl_resolution leaf_resolution = resolution;
          leaf_resolution.index = &revoked_index;
          path_evidence = path_sentinel;
          work = TRUST_WORK_BUDGET;
          munit_assert_int(tc_cms_crl_path_resolve(chain, DEPENDENCIES, &leaf_resolution,
                                                   &workspace, &path_evidence),
                           ==, TC_TLV_OK);
          munit_assert_int(path_evidence.status, ==, TC_X509_REVOCATION_REVOKED);
          munit_assert_size(path_evidence.certificate_index, ==, DEPENDENCIES - 1);
          munit_assert_int(tc_x509_crl_evidence_status(&path_evidence.evidence, &status), ==,
                           TC_TLV_OK);
          munit_assert_int(status, ==, TC_X509_REVOCATION_REVOKED);
          munit_assert_uint(path_evidence.evidence.revocation.reason, ==,
                            CRL_REASON_KEY_COMPROMISE);
          int order;
          munit_assert_int(TC_X509_time_compare(&path_evidence.evidence.revocation.revoked_at,
                                                &revoked_rows[1].crl.this_update, &order),
                           ==, TC_TLV_OK);
          munit_assert_int(order, ==, 0);
          public_options.index = &revoked_index;
          path_evidence = path_sentinel;
          work = TRUST_WORK_BUDGET;
          munit_assert_int(TC_X509_path_check_revocation(chain, DEPENDENCIES, &public_options,
                                                         &public_workspace, &work, &path_evidence),
                           ==, TC_TLV_OK);
          munit_assert_int(path_evidence.status, ==, TC_X509_REVOCATION_REVOKED);
          munit_assert_size(path_evidence.certificate_index, ==, DEPENDENCIES - 1);
          munit_assert_uint(path_evidence.evidence.revocation.reason, ==,
                            CRL_REASON_KEY_COMPROMISE);
          public_options.index = &index;
        }
        workspace.node_capacity = 1;
        evidence = empty;
        work = TRUST_WORK_BUDGET;
        munit_assert_int(tc_cms_crl_resolve(&leaf_view, &resolution, &workspace, &evidence), ==,
                         TC_TLV_LIMIT);
        munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
      }
    }
  }
  return MUNIT_OK;
}

/* Reason-partitioned CRLs, listed and unlisted targets and bad partition
 * signatures, in both partition orders. */
static MunitResult discovery_partitions(const MunitParameter params[], void* user)
{
  revocation_fixture* f = user;
  uint8_t* const signer_der = f->signer_der;
  TC_bytes* const oids = f->oids;
  TC_X509_path_workspace validation = f->validation;
  TC_X509_search_workspace search = f->search;
  TC_X509_workspace parser = f->parser;
  const TC_TLV_limits limits = f->limits;
  const TC_X509_store_source source = f->source;
  TC_X509_path_options options = f->options;
  EVP_PKEY* generated = f->generated;
  EVP_PKEY* other_key = f->other_key;
  X509* certificate = f->certificate;
  const int signer_length = f->signer_length;
  X509_CRL* crl = f->crl;
  size_t work = 0;
  const tc_pki_tree_workspace tree = {f->frames, FRAME_CAPACITY, &work};
  crl_scope_context scope;
  crl_scope_init(f, &tree, &scope);
  const tc_x509_crl_query query = {&scope.target, &scope.point, 0};
  TC_X509_crl_evidence evidence = scope.initial;
  TC_X509_revocation_status status;
  (void)params;
  {
    const uint16_t masks[PARTITIONS] = {KEY_COMPROMISE_MASK,
                                        TC_X509_CRL_ALL_REASONS & ~KEY_COMPROMISE_MASK};
    for (unsigned listed = 0; listed < 2; ++listed) {
      for (unsigned bad_signature = 0; bad_signature < 2; ++bad_signature) {
        uint8_t partition_der[PARTITIONS][ENCODED_CAPACITY], states[PARTITIONS];
        TC_bytes partition_inputs[PARTITIONS];
        for (unsigned partition = 0; partition < PARTITIONS; ++partition) {
          X509_CRL* variant =
              make_partition_crl(crl, bad_signature && partition ? other_key : generated,
                                 masks[partition], listed && !partition);
          const int length = i2d_X509_CRL(variant, NULL);
          munit_assert_int(length, >, 0);
          munit_assert_size((size_t)length, <=, sizeof partition_der[partition]);
          unsigned char* destination = partition_der[partition];
          munit_assert_int(i2d_X509_CRL(variant, &destination), ==, length);
          partition_inputs[partition] = (TC_bytes){partition_der[partition], (size_t)length};
          X509_CRL_free(variant);
        }
        candidate_source partition_source = {partition_inputs, PARTITIONS, 0, TC_TLV_OK, 0};
        const tc_pki_record_source partition_records = {&partition_source, PARTITIONS,
                                                        read_candidate};
        for (unsigned order = 0; order < PARTITIONS; ++order) {
          tc_cms_revocations partition_reader;
          TC_X509_crl_record partition_rows[PARTITIONS];
          TC_X509_crl_index partitions;
          work = TRUST_WORK_BUDGET;
          munit_assert_int(tc_cms_revocations_init((TC_bytes){NULL, 0}, &partition_records,
                                                   PARTITIONS, sizeof partition_der, &limits, &tree,
                                                   &partition_reader),
                           ==, TC_TLV_OK);
          munit_assert_int(tc_cms_crl_index_init(&partition_reader, &tree, oids, EXTENSION_CAPACITY,
                                                 partition_rows, PARTITIONS, &partitions),
                           ==, TC_TLV_OK);
          evidence = (TC_X509_crl_evidence){0};
          status = TC_X509_REVOCATION_UNDETERMINED;
          uint16_t covered = 0;
          work = TRUST_WORK_BUDGET;
          for (unsigned reference = 0; reference < PARTITIONS; ++reference) {
            const unsigned partition = order ? PARTITIONS - 1 - reference : reference;
            const int terminal = status != TC_X509_REVOCATION_UNDETERMINED;
            const TC_TLV_result expected_result = terminal                     ? TC_TLV_END
                                                  : bad_signature && partition ? TC_TLV_INVALID
                                                                               : TC_TLV_OK;
            const TC_X509_crl_evidence previous = evidence;
            scope.candidates = (candidate_source){scope.records, 4, 0, TC_TLV_OK, 0};
            scope.found = scope.saved;
            const size_t before_work = work;
            munit_assert_int(
                tc_cms_crl_scope_process(
                    &scope.reader,
                    &(tc_x509_crl_scope_processing){
                        &partitions, reference, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER,
                        &query, states, sizeof states, &evidence, NULL, NULL, NULL, NULL, NULL},
                    &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                         &(TC_X509_revocation_time){(&options)->at, 0, 0}},
                    &scope.found),
                ==, expected_result);
            if (expected_result == TC_TLV_OK)
              covered |= masks[partition];
            else {
              munit_assert_memory_equal(sizeof evidence, &evidence, &previous);
              munit_assert_memory_equal(sizeof scope.found, &scope.found, &scope.saved);
            }
            if (terminal)
              munit_assert_size(work, ==, before_work);
            munit_assert_uint(evidence.reasons, ==, covered);
            munit_assert_int(tc_x509_crl_evidence_status(&evidence, &status), ==, TC_TLV_OK);
            if (!reference && expected_result == TC_TLV_OK && (!listed || partition))
              munit_assert_int(status, ==, TC_X509_REVOCATION_UNDETERMINED);
            munit_assert_memory_equal(sizeof scope.reader, &scope.reader, &scope.before);
          }
          munit_assert_int(status, ==,
                           listed          ? TC_X509_REVOCATION_REVOKED
                           : bad_signature ? TC_X509_REVOCATION_UNDETERMINED
                                           : TC_X509_REVOCATION_GOOD);
          const TC_X509_crl_evidence empty = {0};
          crl_path_probe probe = {
              {signer_der, (size_t)signer_length}, 1, 0, TC_X509_PATH_VALID, 0, NULL, 0};
          const tc_x509_crl_path_check check = {&probe, check_crl_path};
          scope.candidates = (candidate_source){scope.records, 4, 0, TC_TLV_OK, 0};
          evidence = empty;
          work = TRUST_WORK_BUDGET;
          const TC_TLV_result run_result = bad_signature && !listed ? TC_TLV_INVALID : TC_TLV_OK;
          munit_assert_int(
              tc_cms_crl_point_process(
                  &scope.reader,
                  &(tc_x509_crl_scope_processing){
                      &partitions, 0, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER, &query,
                      states, sizeof states, &evidence, &check, NULL, NULL, NULL, NULL},
                  &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                       &(TC_X509_revocation_time){(&options)->at, 0, 0}}),
              ==, run_result);
          munit_assert_size(probe.calls, ==, (listed && !order) || bad_signature ? 1 : PARTITIONS);
          if (run_result == TC_TLV_OK) {
            munit_assert_int(tc_x509_crl_evidence_status(&evidence, &status), ==, TC_TLV_OK);
            munit_assert_int(status, ==,
                             listed ? TC_X509_REVOCATION_REVOKED : TC_X509_REVOCATION_GOOD);
            const size_t run_work = TRUST_WORK_BUDGET - work;
            evidence = empty;
            work = run_work - 1;
            munit_assert_int(
                tc_cms_crl_point_process(
                    &scope.reader,
                    &(tc_x509_crl_scope_processing){
                        &partitions, 0, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER, &query,
                        states, sizeof states, &evidence, &check, NULL, NULL, NULL, NULL},
                    &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                         &(TC_X509_revocation_time){(&options)->at, 0, 0}}),
                ==, TC_TLV_LIMIT);
            munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
            work = run_work;
            munit_assert_int(
                tc_cms_crl_point_process(
                    &scope.reader,
                    &(tc_x509_crl_scope_processing){
                        &partitions, 0, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER, &query,
                        states, sizeof states, &evidence, &check, NULL, NULL, NULL, NULL},
                    &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                         &(TC_X509_revocation_time){(&options)->at, 0, 0}}),
                ==, TC_TLV_OK);
            munit_assert_size(work, ==, 0);
          } else
            munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
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
              enum { DER_TRUE = 0xff, FULL_NAME = 0, REVOKED_SERIAL = 9, UNLISTED_SERIAL = 10 };
              static const char locator[] = "https://issuer.example/crl";
              uint8_t named_der[ENCODED_CAPACITY], target_der[ENCODED_CAPACITY],
                  extension_der[ENCODED_CAPACITY];
              X509_CRL* named = make_partition_crl(crl, generated, TC_X509_CRL_ALL_REASONS, 1);
              ISSUING_DIST_POINT* idp = ISSUING_DIST_POINT_new();
              GENERAL_NAME* location = GENERAL_NAME_new();
              ASN1_IA5STRING* uri = ASN1_IA5STRING_new();
              munit_assert_not_null(named);
              munit_assert_not_null(idp);
              munit_assert_not_null(location);
              munit_assert_not_null(uri);
              idp->onlyCA = DER_TRUE;
              idp->distpoint = DIST_POINT_NAME_new();
              munit_assert_not_null(idp->distpoint);
              idp->distpoint->type = FULL_NAME;
              idp->distpoint->name.fullname = sk_GENERAL_NAME_new_null();
              munit_assert_not_null(idp->distpoint->name.fullname);
              munit_assert_int(ASN1_STRING_set(uri, locator, sizeof locator - 1), ==, 1);
              GENERAL_NAME_set0_value(location, GEN_URI, uri);
              munit_assert_int(sk_GENERAL_NAME_push(idp->distpoint->name.fullname, location), >, 0);
              munit_assert_int(X509_CRL_add1_ext_i2d(named, NID_issuing_distribution_point, idp, 1,
                                                     X509V3_ADD_REPLACE),
                               ==, 1);
              ISSUING_DIST_POINT_free(idp);
              munit_assert_int(X509_CRL_sign(named, generated, EVP_sha256()), >, 0);
              const int named_length = i2d_X509_CRL(named, NULL);
              munit_assert_int(named_length, >, 0);
              munit_assert_size((size_t)named_length, <=, sizeof named_der);
              unsigned char* destination = named_der;
              munit_assert_int(i2d_X509_CRL(named, &destination), ==, named_length);
              X509_CRL_free(named);
              const TC_bytes named_input = {named_der, (size_t)named_length};
              candidate_source named_source = {&named_input, 1, 0, TC_TLV_OK, 0};
              const tc_pki_record_source named_records = {&named_source, 1, read_candidate};
              tc_cms_revocations named_reader;
              TC_X509_crl_record named_row;
              TC_X509_crl_index named_index;
              work = TRUST_WORK_BUDGET;
              munit_assert_int(tc_cms_revocations_init((TC_bytes){NULL, 0}, &named_records, 1,
                                                       sizeof named_der, &limits, &tree,
                                                       &named_reader),
                               ==, TC_TLV_OK);
              munit_assert_int(tc_cms_crl_index_init(&named_reader, &tree, oids, EXTENSION_CAPACITY,
                                                     &named_row, 1, &named_index),
                               ==, TC_TLV_OK);
              for (unsigned kind = ALTERNATIVE; kind < CERT_CASES; ++kind) {
                X509* cert = make_certificate(other_key, "Target", certificate);
                munit_assert_int(
                    ASN1_INTEGER_set(X509_get_serialNumber(cert),
                                     kind == REVOKED_TARGET ? REVOKED_SERIAL : UNLISTED_SERIAL),
                    ==, 1);
                add_extension(cert, NID_basic_constraints,
                              kind == NOT_CA ? "critical,CA:FALSE" : "critical,CA:TRUE");
                if (kind == LISTED)
                  add_extension(cert, NID_crl_distribution_points,
                                "URI:https://issuer.example/crl");
                else if (kind != BAD_ALT)
                  add_extension(cert, NID_issuer_alt_name,
                                kind == WRONG_NAME ? "URI:https://other.example/crl"
                                                   : "URI:https://issuer.example/crl");
                if (kind == DUPLICATE)
                  add_extension(cert, NID_issuer_alt_name, "URI:https://issuer.example/crl");
                if (kind == BAD_ALT || kind == BAD_DP) {
                  const uint8_t empty_sequence[] = {0x30, 0};
                  ASN1_OCTET_STRING* value = ASN1_OCTET_STRING_new();
                  munit_assert_not_null(value);
                  munit_assert_int(
                      ASN1_OCTET_STRING_set(value, empty_sequence, sizeof empty_sequence), ==, 1);
                  X509_EXTENSION* extension = X509_EXTENSION_create_by_NID(
                      NULL, kind == BAD_ALT ? NID_issuer_alt_name : NID_crl_distribution_points, 0,
                      value);
                  munit_assert_not_null(extension);
                  munit_assert_int(X509_add_ext(cert, extension, -1), ==, 1);
                  X509_EXTENSION_free(extension);
                  ASN1_OCTET_STRING_free(value);
                }
                const size_t length = encode_certificate(cert, generated, EVP_sha256(), target_der,
                                                         sizeof target_der);
                const int extension_length = i2d_X509_EXTENSIONS(X509_get0_extensions(cert), NULL);
                munit_assert_int(extension_length, >, 0);
                munit_assert_size((size_t)extension_length, <=, sizeof extension_der);
                unsigned char* extension_destination = extension_der;
                munit_assert_int(
                    i2d_X509_EXTENSIONS(X509_get0_extensions(cert), &extension_destination), ==,
                    extension_length);
                X509_free(cert);
                TC_X509_certificate target_view;
                const int rejected_at_read = kind == DUPLICATE || kind == BAD_ALT;
                munit_assert_int(
                    TC_X509_read((TC_bytes){target_der, length}, &limits, &parser, &target_view),
                    ==, rejected_at_read ? TC_TLV_INVALID : TC_TLV_OK);
                if (rejected_at_read) {
                  /* Exercise the private driver's parsed-view checks
                           * too. */
                  target_view = scope.target;
                  target_view.encoded = (TC_bytes){target_der, length};
                  target_view.extensions = (TC_bytes){extension_der, (size_t)extension_length};
                } else if (kind < DUPLICATE) {
                  work = TRUST_WORK_BUDGET;
                  munit_assert_int(tc_x509_path_build_work(target_view.encoded, &source, &options,
                                                           &validation, &search, &work,
                                                           &scope.found),
                                   ==, TC_X509_PATH_VALID);
                  munit_assert_size(scope.found.anchor_index, ==, 1);
                }
                const TC_TLV_result expected = kind >= DUPLICATE ? TC_TLV_INVALID
                                               : kind == WRONG_NAME || kind == NOT_CA ? TC_TLV_END
                                                                                      : TC_TLV_OK;
                evidence = empty;
                work = TRUST_WORK_BUDGET;
                probe.calls = 0;
                munit_assert_int(
                    tc_cms_crl_certificate_process(
                        &scope.reader,
                        &(tc_x509_crl_scope_processing){
                            &named_index, 0, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER,
                            NULL, states, sizeof states, &evidence, &check, NULL, NULL, NULL, NULL},
                        &target_view,
                        &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                             &(TC_X509_revocation_time){(&options)->at, 0, 0}}),
                    ==, expected);
                if (expected == TC_TLV_OK) {
                  munit_assert_size(probe.calls, ==, 1);
                  munit_assert_int(tc_x509_crl_evidence_status(&evidence, &status), ==, TC_TLV_OK);
                  munit_assert_int(status, ==,
                                   kind == REVOKED_TARGET ? TC_X509_REVOCATION_REVOKED
                                                          : TC_X509_REVOCATION_GOOD);
                } else {
                  munit_assert_size(probe.calls, ==, 0);
                  munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
                }
                const size_t required = TRUST_WORK_BUDGET - work;
                const TC_X509_crl_evidence expected_evidence = evidence;
                munit_assert_size(required, >, 0);
                for (unsigned short_budget = 0; short_budget < 2; ++short_budget) {
                  evidence = empty;
                  work = required - short_budget;
                  munit_assert_int(
                      tc_cms_crl_certificate_process(
                          &scope.reader,
                          &(tc_x509_crl_scope_processing){
                              &named_index, 0, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER,
                              NULL, states, sizeof states, &evidence, &check, NULL, NULL, NULL,
                              NULL},
                          &target_view,
                          &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                               &(TC_X509_revocation_time){(&options)->at, 0, 0}}),
                      ==, short_budget ? TC_TLV_LIMIT : expected);
                  if (short_budget)
                    munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
                  else
                    assert_evidence_equal(&evidence, &expected_evidence);
                }
                TC_X509_revocation_node dependencies[PATH_CAPACITY];
                const tc_cms_crl_resolution resolution = {&scope.reader,
                                                          &named_index,
                                                          &source,
                                                          &options,
                                                          1,
                                                          TC_X509_CRL_COMPLETE_ONLY,
                                                          TC_X509_CRL_ORDER_NUMBER};
                tc_x509_crl_resolution_workspace resolve_workspace = {
                    &tree,         &validation, &search, states, sizeof states, dependencies,
                    PATH_CAPACITY, 0,           NULL,    0,      NULL};
                evidence = empty;
                work = TRUST_WORK_BUDGET;
                const TC_TLV_result resolved_result =
                    expected == TC_TLV_END ? TC_TLV_UNSUPPORTED : expected;
                munit_assert_int(
                    tc_cms_crl_resolve(&target_view, &resolution, &resolve_workspace, &evidence),
                    ==, resolved_result);
                if (resolved_result == TC_TLV_OK) {
                  int equal;
                  munit_assert_int(
                      tc_x509_crl_evidence_equal(&evidence, &expected_evidence, &equal), ==,
                      TC_TLV_OK);
                  munit_assert_true(equal);
                  munit_assert_int(dependencies[0].status, ==,
                                   kind == REVOKED_TARGET ? TC_X509_REVOCATION_REVOKED
                                                          : TC_X509_REVOCATION_GOOD);
                } else
                  munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
                const size_t resolve_work = TRUST_WORK_BUDGET - work;
                for (unsigned short_budget = 0; short_budget < 2; ++short_budget) {
                  evidence = empty;
                  work = resolve_work - short_budget;
                  munit_assert_int(
                      tc_cms_crl_resolve(&target_view, &resolution, &resolve_workspace, &evidence),
                      ==, short_budget ? TC_TLV_LIMIT : resolved_result);
                  if (short_budget || resolved_result != TC_TLV_OK)
                    munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
                }
                resolve_workspace.states = (uint8_t*)dependencies;
                uint8_t saved_dependencies[sizeof dependencies];
                memcpy(saved_dependencies, dependencies, sizeof dependencies);
                evidence = empty;
                work = TRUST_WORK_BUDGET;
                munit_assert_int(
                    tc_cms_crl_resolve(&target_view, &resolution, &resolve_workspace, &evidence),
                    ==, TC_TLV_ARGUMENT);
                munit_assert_size(work, ==, TRUST_WORK_BUDGET);
                munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
                munit_assert_memory_equal(sizeof dependencies, dependencies, saved_dependencies);
                target_view.extensions = (TC_bytes){states, 1};
                evidence = empty;
                work = TRUST_WORK_BUDGET;
                munit_assert_int(
                    tc_cms_crl_certificate_process(
                        &scope.reader,
                        &(tc_x509_crl_scope_processing){
                            &named_index, 0, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER,
                            NULL, states, sizeof states, &evidence, &check, NULL, NULL, NULL, NULL},
                        &target_view,
                        &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                             &(TC_X509_revocation_time){(&options)->at, 0, 0}}),
                    ==, TC_TLV_ARGUMENT);
                munit_assert_size(work, ==, TRUST_WORK_BUDGET);
                munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
              }
            }
            static const uint8_t split_points[] = {
                0x30, 27, 0x30, 11, 0xa0, 5, 0xa0, 3, 0x86, 1,    'a', 0x81, 2,    6,   0x40,
                0x30, 12, 0xa0, 5,  0xa0, 3, 0x86, 1, 'a',  0x81, 3,   7,    0x3f, 0x80};
            static const uint8_t first_point[] = {0x30, 13, 0x30, 11,   0xa0, 5, 0xa0, 3,
                                                  0x86, 1,  'a',  0x81, 2,    6, 0x40};
            uint8_t malformed[sizeof split_points + 2];
            memcpy(malformed, split_points, sizeof split_points);
            malformed[1] += 2;
            malformed[sizeof split_points] = 0x30;
            malformed[sizeof split_points + 1] = 0;
            const TC_bytes point_lists[] = {{NULL, 0},
                                            {split_points, sizeof split_points},
                                            {first_point, sizeof first_point},
                                            {malformed, sizeof malformed}};
            for (size_t list = 0; list < sizeof point_lists / sizeof *point_lists; ++list) {
              const int invalid = point_lists[list].data == malformed;
              evidence = empty;
              work = TRUST_WORK_BUDGET;
              probe.calls = 0;
              munit_assert_int(
                  tc_cms_crl_points_process(
                      &scope.reader,
                      &(tc_x509_crl_scope_processing){
                          &partitions, 0, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER,
                          &query, states, sizeof states, &evidence, &check, NULL, NULL, NULL, NULL},
                      point_lists[list],
                      &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                           &(TC_X509_revocation_time){(&options)->at, 0, 0}}),
                  ==, invalid ? TC_TLV_INVALID : TC_TLV_OK);
              if (invalid) {
                munit_assert_size(probe.calls, ==, 0);
                munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
              } else {
                munit_assert_size(probe.calls, ==, PARTITIONS);
                munit_assert_int(tc_x509_crl_evidence_status(&evidence, &status), ==, TC_TLV_OK);
                munit_assert_int(status, ==, TC_X509_REVOCATION_GOOD);
                const size_t required = TRUST_WORK_BUDGET - work;
                for (unsigned short_budget = 0; short_budget < 2; ++short_budget) {
                  evidence = empty;
                  work = required - short_budget;
                  munit_assert_int(
                      tc_cms_crl_points_process(
                          &scope.reader,
                          &(tc_x509_crl_scope_processing){&partitions, 0, TC_X509_CRL_COMPLETE_ONLY,
                                                          TC_X509_CRL_ORDER_NUMBER, &query, states,
                                                          sizeof states, &evidence, &check, NULL,
                                                          NULL, NULL, NULL},
                          point_lists[list],
                          &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                               &(TC_X509_revocation_time){(&options)->at, 0, 0}}),
                      ==, short_budget ? TC_TLV_LIMIT : TC_TLV_OK);
                  if (short_budget)
                    munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
                }
              }
            }
            evidence = empty;
            work = TRUST_WORK_BUDGET;
            munit_assert_int(
                tc_cms_crl_points_process(
                    &scope.reader,
                    &(tc_x509_crl_scope_processing){
                        &partitions, 0, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER, &query,
                        states, sizeof states, &evidence, &check, NULL, NULL, NULL, NULL},
                    (TC_bytes){states, 1},
                    &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                         &(TC_X509_revocation_time){(&options)->at, 0, 0}}),
                ==, TC_TLV_ARGUMENT);
            munit_assert_size(work, ==, TRUST_WORK_BUDGET);
            munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
            for (unsigned source_failure = 0; source_failure < 2; ++source_failure) {
              probe.result = TC_X509_PATH_INVALID;
              probe.accept_calls = 1;
              probe.calls = 0;
              probe.source_status = source_failure ? &scope.candidates.status : NULL;
              evidence = empty;
              work = TRUST_WORK_BUDGET;
              munit_assert_int(
                  tc_cms_crl_points_process(
                      &scope.reader,
                      &(tc_x509_crl_scope_processing){
                          &partitions, 0, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER,
                          &query, states, sizeof states, &evidence, &check, NULL, NULL, NULL, NULL},
                      (TC_bytes){split_points, sizeof split_points},
                      &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                           &(TC_X509_revocation_time){(&options)->at, 0, 0}}),
                  ==, source_failure ? TC_TLV_UNSUPPORTED : TC_TLV_INVALID);
              munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
              if (source_failure)
                munit_assert_size(probe.calls, ==, 1);
              else
                munit_assert_size(probe.calls, >=, 2);
              probe.source_status = NULL;
              scope.candidates.status = TC_TLV_OK;
            }
            probe.accept_calls = 0;
            probe.result = TC_X509_PATH_VALID;
            const TC_X509_path_status rejected[] = {TC_X509_PATH_INVALID, TC_X509_PATH_UNSUPPORTED,
                                                    TC_X509_PATH_LIMIT, TC_X509_PATH_ERROR};
            for (size_t rejection = 0; rejection < sizeof rejected / sizeof *rejected;
                 ++rejection) {
              probe.result = rejected[rejection];
              probe.calls = 0;
              evidence = empty;
              work = TRUST_WORK_BUDGET;
              munit_assert_int(
                  tc_cms_crl_point_process(
                      &scope.reader,
                      &(tc_x509_crl_scope_processing){
                          &partitions, 0, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER,
                          &query, states, sizeof states, &evidence, &check, NULL, NULL, NULL, NULL},
                      &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                           &(TC_X509_revocation_time){(&options)->at, 0, 0}}),
                  ==, tc_x509_path_result_status(probe.result));
              munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
              munit_assert_size(probe.calls, >, 0);
            }
            probe.result = TC_X509_PATH_INVALID;
            probe.accept_calls = 1;
            probe.calls = 0;
            evidence = empty;
            work = TRUST_WORK_BUDGET;
            munit_assert_int(
                tc_cms_crl_point_process(
                    &scope.reader,
                    &(tc_x509_crl_scope_processing){
                        &partitions, 0, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER, &query,
                        states, sizeof states, &evidence, &check, NULL, NULL, NULL, NULL},
                    &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                         &(TC_X509_revocation_time){(&options)->at, 0, 0}}),
                ==, TC_TLV_INVALID);
            munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
            munit_assert_size(probe.calls, >, 1);
            probe.accept_calls = 0;
            probe.result = TC_X509_PATH_VALID;
            probe.calls = 0;
            probe.source_status = &scope.candidates.status;
            work = TRUST_WORK_BUDGET;
            munit_assert_int(
                tc_cms_crl_point_process(
                    &scope.reader,
                    &(tc_x509_crl_scope_processing){
                        &partitions, 0, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER, &query,
                        states, sizeof states, &evidence, &check, NULL, NULL, NULL, NULL},
                    &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                         &(TC_X509_revocation_time){(&options)->at, 0, 0}}),
                ==, TC_TLV_UNSUPPORTED);
            munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
            munit_assert_size(probe.calls, ==, 1);
            probe.source_status = NULL;
            scope.candidates.status = TC_TLV_OK;
            probe.increase_work = 1;
            evidence = empty;
            work = TRUST_WORK_BUDGET;
            munit_assert_int(
                tc_cms_crl_point_process(
                    &scope.reader,
                    &(tc_x509_crl_scope_processing){
                        &partitions, 0, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER, &query,
                        states, sizeof states, &evidence, &check, NULL, NULL, NULL, NULL},
                    &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                         &(TC_X509_revocation_time){(&options)->at, 0, 0}}),
                ==, TC_TLV_ARGUMENT);
            munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
            munit_assert_size(work, ==, 0);
            probe.increase_work = 0;
            probe.calls = 0;
            scope.candidates.status = TC_TLV_UNSUPPORTED;
            scope.candidates.calls = 0;
            work = TRUST_WORK_BUDGET;
            munit_assert_int(
                tc_cms_crl_point_process(
                    &scope.reader,
                    &(tc_x509_crl_scope_processing){
                        &partitions, 0, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER, &query,
                        states, sizeof states, &evidence, &check, NULL, NULL, NULL, NULL},
                    &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                         &(TC_X509_revocation_time){(&options)->at, 0, 0}}),
                ==, TC_TLV_UNSUPPORTED);
            munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
            munit_assert_size(scope.candidates.calls, ==, 1);
            munit_assert_size(probe.calls, ==, 0);
            scope.candidates.status = TC_TLV_OK;
            const TC_X509_crl_index partial = {partition_rows, 1, 0};
            work = TRUST_WORK_BUDGET;
            munit_assert_int(
                tc_cms_crl_point_process(
                    &scope.reader,
                    &(tc_x509_crl_scope_processing){
                        &partial, 0, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER, &query,
                        states, sizeof states, &evidence, &check, NULL, NULL, NULL, NULL},
                    &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                         &(TC_X509_revocation_time){(&options)->at, 0, 0}}),
                ==, TC_TLV_OK);
            munit_assert_int(tc_x509_crl_evidence_status(&evidence, &status), ==, TC_TLV_OK);
            munit_assert_int(status, ==, TC_X509_REVOCATION_UNDETERMINED);
            munit_assert_uint(evidence.reasons, ==, masks[order]);
            evidence = empty;
            work = TRUST_WORK_BUDGET;
            probe.calls = 0;
            const TC_X509_crl_index no_records = {NULL, 0, 0};
            munit_assert_int(
                tc_cms_crl_point_process(
                    &scope.reader,
                    &(tc_x509_crl_scope_processing){&no_records, 0, TC_X509_CRL_COMPLETE_ONLY,
                                                    TC_X509_CRL_ORDER_NUMBER, &query, NULL, 0,
                                                    &evidence, &check, NULL, NULL, NULL, NULL},
                    &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                         &(TC_X509_revocation_time){(&options)->at, 0, 0}}),
                ==, TC_TLV_END);
            munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
            munit_assert_size(probe.calls, ==, 0);
            work = TRUST_WORK_BUDGET;
            munit_assert_int(
                tc_cms_crl_point_process(
                    &scope.reader,
                    &(tc_x509_crl_scope_processing){
                        &partitions, 0, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER, &query,
                        states, sizeof states, &evidence, NULL, NULL, NULL, NULL, NULL},
                    &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                         &(TC_X509_revocation_time){(&options)->at, 0, 0}}),
                ==, TC_TLV_ARGUMENT);
            munit_assert_size(work, ==, TRUST_WORK_BUDGET);
            munit_assert_int(
                tc_cms_crl_point_process(
                    &scope.reader,
                    &(tc_x509_crl_scope_processing){
                        &partitions, 0, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER, &query,
                        (uint8_t*)&check, sizeof check, &evidence, &check, NULL, NULL, NULL, NULL},
                    &(tc_x509_crl_trust){&source, 1, &options, &tree, &validation, &search,
                                         &(TC_X509_revocation_time){(&options)->at, 0, 0}}),
                ==, TC_TLV_ARGUMENT);
            munit_assert_size(work, ==, TRUST_WORK_BUDGET);
            munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
            munit_assert_size(probe.calls, ==, 0);
          }
          TC_bytes swap = partition_inputs[0];
          partition_inputs[0] = partition_inputs[1];
          partition_inputs[1] = swap;
        }
      }
    }
    scope.candidates = (candidate_source){scope.records, 4, 0, TC_TLV_OK, 0};
  }
  return MUNIT_OK;
}

/* Selected complete CRL authentication and lookup with scope evidence,
 * a missing provider and a changed signature. */
static MunitResult selection_lookup(const MunitParameter params[], void* user)
{
  revocation_fixture* f = user;
  uint8_t* const encoded = f->encoded;
  uint8_t* const signer_der = f->signer_der;
  const unsigned revoked = f->revoked;
  const TC_X509_name_workspace names = f->names;
  TC_X509_path_workspace validation = f->validation;
  TC_X509_search_workspace search = f->search;
  TC_X509_certificate signer = f->signer;
  const TC_TLV_limits limits = f->limits;
  TC_X509_signature_provider provider = f->provider;
  const TC_X509_store_source source = f->source;
  TC_X509_path_options options = f->options;
  TC_X509_crl parsed = f->parsed;
  TC_X509_crl_extensions crl_info = f->crl_info;
  size_t work = 0;
  const tc_pki_tree_workspace tree = {f->frames, FRAME_CAPACITY, &work};
  crl_selection_context selection;
  crl_selection_init(f, &tree, &selection);
  tc_x509_crl_query query = {&selection.target, &selection.point, 0};
  const TC_X509_crl_record selected_record = {f->parsed, f->crl_info, TC_TLV_OK};
  (void)params;
  {
    {
      enum { KEY_COMPROMISE_REASONS = 1u << 1 };
      TC_X509_crl_evidence evidence = {0};
      TC_X509_revocation_status status;
      TC_X509_search_result trusted, unchanged;
      signature_retry_probe probe = {provider, 0, 0, TC_X509_SIGNATURE_ERROR};
      TC_X509_path_options checked = options;
      checked.signatures = (TC_X509_signature_provider){retry_signature, &probe, NULL};
      memset(&unchanged, 0xa5, sizeof unchanged);
      work = TRUST_WORK_BUDGET;
      munit_assert_int(
          crl_signer_scope(
              &selected_record, signer.encoded, &query,
              &(tc_x509_crl_trust){&source, 1, &checked,
                                   &(tc_pki_tree_workspace){validation.frames.data,
                                                            validation.frames.capacity, &work},
                                   &validation, &search,
                                   &(TC_X509_revocation_time){(&checked)->at, 0, 0}},
              &evidence, &trusted),
          ==, TC_TLV_OK);
      munit_assert_size(probe.calls, ==, 2);
      const size_t required = TRUST_WORK_BUDGET - work;
      munit_assert_size(trusted.validation.work_used, ==, required);
      munit_assert_size(trusted.anchor_index, ==, 1);
      munit_assert_ptr_equal(trusted.path[0].data, signer_der);
      munit_assert_int(tc_x509_crl_evidence_status(&evidence, &status), ==, TC_TLV_OK);
      munit_assert_int(status, ==, revoked ? TC_X509_REVOCATION_REVOKED : TC_X509_REVOCATION_GOOD);
      const TC_X509_crl_evidence terminal = evidence;
      trusted = unchanged;
      munit_assert_int(
          crl_signer_scope(
              &selected_record, signer.encoded, &query,
              &(tc_x509_crl_trust){&source, 1, &checked,
                                   &(tc_pki_tree_workspace){validation.frames.data,
                                                            validation.frames.capacity, &work},
                                   &validation, &search,
                                   &(TC_X509_revocation_time){(&checked)->at, 0, 0}},
              &evidence, &trusted),
          ==, TC_TLV_END);
      munit_assert_memory_equal(sizeof evidence, &evidence, &terminal);
      munit_assert_memory_equal(sizeof trusted, &trusted, &unchanged);
      munit_assert_size(probe.calls, ==, 2);
      evidence = (TC_X509_crl_evidence){0};
      work = required;
      munit_assert_int(
          crl_signer_scope(
              &selected_record, signer.encoded, &query,
              &(tc_x509_crl_trust){&source, 1, &options,
                                   &(tc_pki_tree_workspace){validation.frames.data,
                                                            validation.frames.capacity, &work},
                                   &validation, &search,
                                   &(TC_X509_revocation_time){(&options)->at, 0, 0}},
              &evidence, &trusted),
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
        TC_X509_crl copy = parsed;
        TC_X509_crl_extensions info = crl_info;
        TC_X509_certificate query_certificate = selection.target;
        tc_x509_crl_query rejected_query = {&query_certificate, &selection.point, 0};
        TC_X509_path_options rejected_options = options;
        size_t anchor_index = 1;
        TC_TLV_result expected_result = TC_TLV_INVALID;
        work = TRUST_WORK_BUDGET;
        evidence = (TC_X509_crl_evidence){0};
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
          query_certificate.issuer = (TC_bytes){(const uint8_t*)"\x30\x00", 2};
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
        if (failure == REQUIRE_KU) {
          rejected_options.flags = TC_X509_PATH_REQUIRE_KEY_USAGE;
          rejected_options.key_usage = TC_KEY_USAGE_CERT_SIGN;
        }
        if (failure == CRITICAL) {
          info.unknown_critical_oid = selection.target.serial;
          expected_result = TC_TLV_UNSUPPORTED;
        }
        if (failure == BAD_STATE) {
          evidence.reasons = 1;
          expected_result = TC_TLV_ARGUMENT;
        }
        const TC_X509_crl_evidence before = evidence;
        const TC_X509_crl_record rejected_record = {copy, info, TC_TLV_OK};
        trusted = unchanged;
        munit_assert_int(
            crl_signer_scope(
                &rejected_record, signer.encoded, &rejected_query,
                &(tc_x509_crl_trust){&source, anchor_index, &rejected_options,
                                     &(tc_pki_tree_workspace){validation.frames.data,
                                                              validation.frames.capacity, &work},
                                     &validation, &search,
                                     &(TC_X509_revocation_time){(&rejected_options)->at, 0, 0}},
                &evidence, &trusted),
            ==, expected_result);
        munit_assert_memory_equal(sizeof evidence, &evidence, &before);
        munit_assert_memory_equal(sizeof trusted, &trusted, &unchanged);
      }
      selection.point.has_reasons = 1;
      selection.point.reasons = KEY_COMPROMISE_REASONS;
      evidence = (TC_X509_crl_evidence){0};
      work = TRUST_WORK_BUDGET;
      munit_assert_int(
          crl_signer_scope(
              &selected_record, signer.encoded, &query,
              &(tc_x509_crl_trust){&source, 1, &options,
                                   &(tc_pki_tree_workspace){validation.frames.data,
                                                            validation.frames.capacity, &work},
                                   &validation, &search,
                                   &(TC_X509_revocation_time){(&options)->at, 0, 0}},
              &evidence, &trusted),
          ==, TC_TLV_OK);
      munit_assert_int(tc_x509_crl_evidence_status(&evidence, &status), ==, TC_TLV_OK);
      munit_assert_int(status, ==,
                       revoked ? TC_X509_REVOCATION_REVOKED : TC_X509_REVOCATION_UNDETERMINED);
      trusted = unchanged;
      munit_assert_int(
          crl_signer_scope(
              &selected_record, signer.encoded, &query,
              &(tc_x509_crl_trust){&source, 1, &options,
                                   &(tc_pki_tree_workspace){validation.frames.data,
                                                            validation.frames.capacity, &work},
                                   &validation, &search,
                                   &(TC_X509_revocation_time){(&options)->at, 0, 0}},
              &evidence, &trusted),
          ==, TC_TLV_END);
      munit_assert_memory_equal(sizeof trusted, &trusted, &unchanged);
      if (!revoked) {
        selection.point.reasons = TC_X509_CRL_ALL_REASONS & ~KEY_COMPROMISE_REASONS;
        work = TRUST_WORK_BUDGET;
        munit_assert_int(
            crl_signer_scope(
                &selected_record, signer.encoded, &query,
                &(tc_x509_crl_trust){&source, 1, &options,
                                     &(tc_pki_tree_workspace){validation.frames.data,
                                                              validation.frames.capacity, &work},
                                     &validation, &search,
                                     &(TC_X509_revocation_time){(&options)->at, 0, 0}},
                &evidence, &trusted),
            ==, TC_TLV_OK);
        munit_assert_int(tc_x509_crl_evidence_status(&evidence, &status), ==, TC_TLV_OK);
        munit_assert_int(status, ==, TC_X509_REVOCATION_GOOD);
      }
      selection.point = (tc_pki_distribution_point){0};
    }
    work = WORK_BUDGET;
    selection.match = selection.saved;
    munit_assert_int(
        tc_x509_crl_selected_authenticate(&selection.selected, &signer, NULL,
                                          &(tc_x509_crl_decode){&limits, &tree, &names, NULL, 0}),
        ==, TC_TLV_UNSUPPORTED);
    const size_t signature_offset = (size_t)(parsed.signature.data - encoded);
    encoded[signature_offset] ^= 1;
    work = WORK_BUDGET;
    munit_assert_int(
        tc_x509_crl_selected_authenticate(&selection.selected, &signer, &provider,
                                          &(tc_x509_crl_decode){&limits, &tree, &names, NULL, 0}),
        ==, TC_TLV_INVALID);
    encoded[signature_offset] ^= 1;
  }
  return MUNIT_OK;
}

/* Delta CRLs over the complete CRL for each reason, with wrong keys,
 * incompatible numbers and fallback to the complete CRL. */
static MunitResult selection_delta(const MunitParameter params[], void* user)
{
  revocation_fixture* f = user;
  TC_bytes* const oids = f->oids;
  const unsigned revoked = f->revoked;
  const TC_X509_name_workspace names = f->names;
  TC_X509_path_workspace validation = f->validation;
  TC_X509_search_workspace search = f->search;
  TC_X509_certificate signer = f->signer;
  const TC_TLV_limits limits = f->limits;
  TC_X509_signature_provider provider = f->provider;
  const TC_X509_store_source source = f->source;
  TC_X509_path_options options = f->options;
  EVP_PKEY* generated = f->generated;
  EVP_PKEY* other_key = f->other_key;
  ASN1_TIME* next_date = f->next_date;
  X509_CRL* crl = f->crl;
  TC_CMS_signed_data container = f->container;
  TC_X509_crl parsed = f->parsed;
  TC_X509_crl_extensions crl_info = f->crl_info;
  size_t work = 0;
  const tc_pki_tree_workspace tree = {f->frames, FRAME_CAPACITY, &work};
  unsigned char* cursor;
  crl_selection_context selection;
  crl_selection_init(f, &tree, &selection);
  tc_x509_crl_query query = {&selection.target, &selection.point, 0};
  (void)params;
  {
    enum { DELTA_FALLBACK = 2 };
    const unsigned reasons[] = {1, 8, 0};
    for (size_t i = 0; i < sizeof reasons / sizeof reasons[0]; ++i) {
      uint8_t delta_der[ENCODED_CAPACITY];
      X509_CRL* delta_crl = X509_CRL_dup(crl);
      ASN1_INTEGER* number = ASN1_INTEGER_new();
      munit_assert_not_null(delta_crl);
      munit_assert_not_null(number);
      ASN1_TIME* delta_next = ASN1_TIME_new();
      munit_assert_not_null(delta_next);
      munit_assert_int(ASN1_TIME_set_string(delta_next, "280101000000Z"), ==, 1);
      munit_assert_int(X509_CRL_set1_lastUpdate(delta_crl, next_date), ==, 1);
      munit_assert_int(X509_CRL_set1_nextUpdate(delta_crl, delta_next), ==, 1);
      ASN1_TIME_free(delta_next);
      munit_assert_int(ASN1_INTEGER_set(number, 2), ==, 1);
      munit_assert_int(
          X509_CRL_add1_ext_i2d(delta_crl, NID_crl_number, number, 0, X509V3_ADD_REPLACE), ==, 1);
      munit_assert_int(ASN1_INTEGER_set(number, 1), ==, 1);
      munit_assert_int(X509_CRL_add1_ext_i2d(delta_crl, NID_delta_crl, number, 1, 0), ==, 1);
      ASN1_INTEGER_free(number);
      if (revoked && i == DELTA_FALLBACK) {
        /* A delta entry for another certificate does not replace this one. */
        ASN1_INTEGER* other_serial = ASN1_INTEGER_new();
        munit_assert_not_null(other_serial);
        munit_assert_int(ASN1_INTEGER_set(other_serial, 10), ==, 1);
        X509_REVOKED* item = sk_X509_REVOKED_value(X509_CRL_get_REVOKED(delta_crl), 0);
        munit_assert_int(X509_REVOKED_set_serialNumber(item, other_serial), ==, 1);
        ASN1_INTEGER_free(other_serial);
      } else if (revoked) {
        ASN1_ENUMERATED* reason = ASN1_ENUMERATED_new();
        munit_assert_not_null(reason);
        munit_assert_int(ASN1_ENUMERATED_set(reason, reasons[i]), ==, 1);
        X509_REVOKED* item = sk_X509_REVOKED_value(X509_CRL_get_REVOKED(delta_crl), 0);
        munit_assert_int(X509_REVOKED_add1_ext_i2d(item, NID_crl_reason, reason, 0, 0), ==, 1);
        ASN1_ENUMERATED_free(reason);
      }
      /* Equal metadata cannot substitute for verification with the base key.
         */
      for (unsigned wrong_key = 0; wrong_key < 2; ++wrong_key) {
        TC_X509_crl delta;
        TC_X509_crl_extensions delta_info;
        munit_assert_int(X509_CRL_sign(delta_crl, wrong_key ? other_key : generated, EVP_sha256()),
                         >, 0);
        int delta_length = i2d_X509_CRL(delta_crl, NULL);
        munit_assert_int(delta_length, >, 0);
        munit_assert_size((size_t)delta_length, <=, sizeof delta_der);
        cursor = delta_der;
        munit_assert_int(i2d_X509_CRL(delta_crl, &cursor), ==, delta_length);
        work = WORK_BUDGET;
        munit_assert_int(
            tc_x509_crl_read((TC_bytes){delta_der, (size_t)delta_length}, &limits, &tree, &delta),
            ==, TC_TLV_OK);
        munit_assert_int(tc_x509_crl_extension_info_read(delta.extensions, &limits, &tree, oids,
                                                         EXTENSION_CAPACITY, &delta_info),
                         ==, TC_TLV_OK);
        selection.selected.delta = &delta;
        selection.selected.delta_info = &delta_info;
        {
          TC_X509_crl_evidence evidence = {0}, empty = {0};
          TC_X509_search_result trusted, unchanged;
          TC_X509_path_options updated = options;
          signature_retry_probe probe = {provider, 0, 0, TC_X509_SIGNATURE_ERROR};
          updated.signatures = (TC_X509_signature_provider){retry_signature, &probe, NULL};
          updated.at = delta.this_update;
          memset(&unchanged, 0xa5, sizeof unchanged);
          trusted = unchanged;
          tc_cms_candidates candidate_reader;
          work = TRUST_WORK_BUDGET;
          munit_assert_int(tc_cms_candidates_init(container.certificates, NULL, 1, ENCODED_CAPACITY,
                                                  &limits, &tree, &candidate_reader),
                           ==, TC_TLV_OK);
          const tc_cms_candidates before_search = candidate_reader;
          const TC_bytes crl_records[] = {parsed.encoded, delta.encoded};
          candidate_source crl_source = {crl_records, 2, 0, TC_TLV_OK, 0};
          const tc_pki_record_source records = {&crl_source, 2, read_candidate};
          tc_cms_revocations revocations;
          TC_X509_crl_record indexed_records[2];
          TC_X509_crl_index crl_index;
          tc_x509_crl_selected indexed_pair;
          size_t delta_cursor = 0;
          work = TRUST_WORK_BUDGET;
          munit_assert_int(tc_cms_revocations_init((TC_bytes){NULL, 0}, &records, 2,
                                                   ENCODED_CAPACITY + sizeof delta_der, &limits,
                                                   &tree, &revocations),
                           ==, TC_TLV_OK);
          munit_assert_int(tc_cms_crl_index_init(&revocations, &tree, oids, EXTENSION_CAPACITY,
                                                 indexed_records, 2, &crl_index),
                           ==, TC_TLV_OK);
          munit_assert_size(crl_source.calls, ==, 2);
          munit_assert_int(tc_x509_crl_delta_next(&crl_index, 0, &delta_cursor, &limits, &tree,
                                                  &names, &indexed_pair),
                           ==, TC_TLV_OK);
          munit_assert_ptr_equal(indexed_pair.base->encoded.data, parsed.encoded.data);
          munit_assert_ptr_equal(indexed_pair.delta->encoded.data, delta.encoded.data);
          tc_x509_crl_selected preferred, untouched;
          const tc_x509_crl_selected complete = {indexed_pair.base, indexed_pair.base_info, NULL,
                                                 NULL};
          work = TRUST_WORK_BUDGET;
          munit_assert_int(
              tc_x509_crl_signer_validate(
                  complete.base, &signer,
                  &(tc_x509_crl_trust){&source, 1, &updated,
                                       &(tc_pki_tree_workspace){validation.frames.data,
                                                                validation.frames.capacity, &work},
                                       &validation, &search,
                                       &(TC_X509_revocation_time){(&updated)->at, 0, 0}},
                  &trusted),
              ==, TC_X509_PATH_VALID);
          memset(&untouched, 0xa5, sizeof untouched);
          preferred = untouched;
          {
            uint8_t states[2] = {0xa5, 0xa5};
            tc_x509_crl_signature_cache cache, saved_cache;
            memset(&saved_cache, 0xa5, sizeof saved_cache);
            cache = saved_cache;
            work = TRUST_WORK_BUDGET;
            munit_assert_int(
                tc_x509_crl_signature_cache_init(&crl_index, &signer, &updated.signatures, &limits,
                                                 &names, (TC_buffer){states, 1}, &work, &cache),
                ==, TC_TLV_LIMIT);
            munit_assert_memory_equal(sizeof cache, &cache, &saved_cache);
            munit_assert_uint(states[0], ==, 0xa5);
            work = 1;
            munit_assert_int(
                tc_x509_crl_signature_cache_init(&crl_index, &signer, &updated.signatures, &limits,
                                                 &names, (TC_buffer){states, 2}, &work, &cache),
                ==, TC_TLV_LIMIT);
            munit_assert_memory_equal(sizeof cache, &cache, &saved_cache);
            munit_assert_uint(states[0], ==, 0xa5);
            work = 2;
            munit_assert_int(
                tc_x509_crl_signature_cache_init(&crl_index, &signer, &updated.signatures, &limits,
                                                 &names, (TC_buffer){states, 2}, &work, &cache),
                ==, TC_TLV_OK);
            munit_assert_size(work, ==, 0);
            const size_t calls = probe.calls;
            munit_assert_int(tc_x509_crl_signature_cached(&cache, 1, &work), ==, TC_TLV_LIMIT);
            munit_assert_size(probe.calls, ==, calls);
            for (unsigned repeat = 0; repeat < 2; ++repeat) {
              tc_x509_crl_selected cached_pair = untouched;
              work = TRUST_WORK_BUDGET;
              munit_assert_int(
                  tc_x509_crl_delta_select(&cache, 0, &(TC_X509_revocation_time){updated.at, 0, 0},
                                           &tree, NULL, &cached_pair),
                  ==, wrong_key ? TC_TLV_END : TC_TLV_OK);
              munit_assert_size(probe.calls, ==, calls + 1);
              if (wrong_key)
                munit_assert_memory_equal(sizeof cached_pair, &cached_pair, &untouched);
              else
                munit_assert_ptr_equal(cached_pair.delta, indexed_pair.delta);
            }
            const TC_X509_crl_delta_policy selection_modes[] = {TC_X509_CRL_COMPLETE_ONLY,
                                                                TC_X509_CRL_DELTA_IF_AVAILABLE,
                                                                TC_X509_CRL_DELTA_REQUIRED};
            for (unsigned period = 0; period < 2; ++period)
              for (size_t mode = 0; mode < sizeof selection_modes / sizeof selection_modes[0];
                   ++mode) {
                const TC_X509_time* at = period ? &delta.this_update : &parsed.this_update;
                const int available =
                    period ? !wrong_key && selection_modes[mode] != TC_X509_CRL_COMPLETE_ONLY
                           : selection_modes[mode] != TC_X509_CRL_DELTA_REQUIRED;
                size_t position = 0;
                tc_x509_crl_selected effective = untouched;
                work = TRUST_WORK_BUDGET;
                munit_assert_int(tc_x509_crl_effective_next(
                                     &(tc_x509_crl_scope_context){
                                         &cache, selection_modes[mode], TC_X509_CRL_ORDER_NUMBER,
                                         &(TC_X509_revocation_time){*(at), 0, 0}, &tree, NULL, 0},
                                     0, &position, NULL, &effective),
                                 ==, available ? TC_TLV_OK : TC_TLV_END);
                munit_assert_size(probe.calls, ==, calls + 2);
                if (available) {
                  munit_assert_size(position, ==, 1);
                  munit_assert_ptr_equal(effective.base, indexed_pair.base);
                  munit_assert_ptr_equal(effective.delta, period ? indexed_pair.delta : NULL);
                  const tc_x509_crl_selected prior = effective;
                  munit_assert_int(tc_x509_crl_effective_next(
                                       &(tc_x509_crl_scope_context){
                                           &cache, selection_modes[mode], TC_X509_CRL_ORDER_NUMBER,
                                           &(TC_X509_revocation_time){*(at), 0, 0}, &tree, NULL, 0},
                                       0, &position, NULL, &effective),
                                   ==, TC_TLV_END);
                  munit_assert_memory_equal(sizeof effective, &effective, &prior);
                } else {
                  munit_assert_size(position, ==, 0);
                  munit_assert_memory_equal(sizeof effective, &effective, &untouched);
                }
              }
            {
              size_t position = 0;
              tc_x509_crl_selected effective;
              work = TRUST_WORK_BUDGET;
              munit_assert_int(
                  tc_x509_crl_effective_next(
                      &(tc_x509_crl_scope_context){
                          &cache, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER,
                          &(TC_X509_revocation_time){*(&parsed.this_update), 0, 0}, &tree, NULL, 0},
                      0, &position, NULL, &effective),
                  ==, TC_TLV_OK);
              const size_t required = TRUST_WORK_BUDGET - work;
              for (size_t budget = 0; budget <= required; ++budget) {
                position = 0;
                work = budget;
                effective = untouched;
                munit_assert_int(
                    tc_x509_crl_effective_next(
                        &(tc_x509_crl_scope_context){
                            &cache, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_NUMBER,
                            &(TC_X509_revocation_time){*(&parsed.this_update), 0, 0}, &tree, NULL,
                            0},
                        0, &position, NULL, &effective),
                    ==, budget == required ? TC_TLV_OK : TC_TLV_LIMIT);
                if (budget < required) {
                  munit_assert_size(position, ==, 0);
                  munit_assert_memory_equal(sizeof effective, &effective, &untouched);
                }
              }
              munit_assert_size(probe.calls, ==, calls + 2);
            }
            const TC_X509_signature_result failures[] = {
                TC_X509_SIGNATURE_UNSUPPORTED, TC_X509_SIGNATURE_LIMIT, TC_X509_SIGNATURE_ERROR};
            const TC_TLV_result errors[] = {TC_TLV_UNSUPPORTED, TC_TLV_LIMIT, TC_TLV_ARGUMENT};
            for (size_t failure = 0; failure < sizeof failures / sizeof failures[0]; ++failure) {
              signature_retry_probe retry = {provider, 0, 1, failures[failure]};
              const TC_X509_signature_provider failing = {retry_signature, &retry, NULL};
              work = TRUST_WORK_BUDGET;
              munit_assert_int(
                  tc_x509_crl_signature_cache_init(&crl_index, &signer, &failing, &limits, &names,
                                                   (TC_buffer){states, 2}, &work, &cache),
                  ==, TC_TLV_OK);
              const uint8_t unchecked = states[1];
              munit_assert_int(tc_x509_crl_signature_cached(&cache, 1, &work), ==, errors[failure]);
              munit_assert_uint(states[1], ==, unchecked);
              for (unsigned repeat = 0; repeat < 2; ++repeat) {
                work = TRUST_WORK_BUDGET;
                munit_assert_int(tc_x509_crl_signature_cached(&cache, 1, &work), ==,
                                 wrong_key ? TC_TLV_INVALID : TC_TLV_OK);
                munit_assert_size(retry.calls, ==, 2);
              }
            }
          }
          work = TRUST_WORK_BUDGET;
          munit_assert_int(tc_x509_crl_delta_select(
                               &(tc_x509_crl_signature_cache){&crl_index, &signer, &provider,
                                                              &limits, &names, NULL, 0, NULL},
                               0, &(TC_X509_revocation_time){updated.at, 0, 0}, &tree, NULL,
                               &preferred),
                           ==, wrong_key ? TC_TLV_END : TC_TLV_OK);
          if (wrong_key)
            munit_assert_memory_equal(sizeof preferred, &preferred, &untouched);
          else {
            const size_t required = TRUST_WORK_BUDGET - work;
            munit_assert_ptr_equal(preferred.delta, indexed_pair.delta);
            work = required - 1;
            preferred = untouched;
            munit_assert_int(tc_x509_crl_delta_select(
                                 &(tc_x509_crl_signature_cache){&crl_index, &signer, &provider,
                                                                &limits, &names, NULL, 0, NULL},
                                 0, &(TC_X509_revocation_time){updated.at, 0, 0}, &tree, NULL,
                                 &preferred),
                             ==, TC_TLV_LIMIT);
            munit_assert_memory_equal(sizeof preferred, &preferred, &untouched);
            work = required;
            munit_assert_int(tc_x509_crl_delta_select(
                                 &(tc_x509_crl_signature_cache){&crl_index, &signer, &provider,
                                                                &limits, &names, NULL, 0, NULL},
                                 0, &(TC_X509_revocation_time){updated.at, 0, 0}, &tree, NULL,
                                 &preferred),
                             ==, TC_TLV_OK);
            munit_assert_size(work, ==, 0);
            TC_X509_crl_evidence applied = {0};
            TC_X509_revocation_status applied_status;
            const size_t signature_calls = probe.calls;
            work = TRUST_WORK_BUDGET;
            munit_assert_int(tc_x509_crl_apply(&preferred, &query,
                                               &(TC_X509_revocation_time){updated.at, 0, 0},
                                               &(tc_x509_crl_decode){&limits, &tree, &names, oids,
                                                                     EXTENSION_CAPACITY},
                                               &applied),
                             ==, TC_TLV_OK);
            const size_t apply_work = TRUST_WORK_BUDGET - work;
            munit_assert_size(probe.calls, ==, signature_calls);
            munit_assert_int(tc_x509_crl_evidence_status(&applied, &applied_status), ==, TC_TLV_OK);
            munit_assert_int(applied_status, ==,
                             revoked && reasons[i] != 8 ? TC_X509_REVOCATION_REVOKED
                                                        : TC_X509_REVOCATION_GOOD);
            const TC_X509_crl_evidence completed = applied;
            munit_assert_int(tc_x509_crl_apply(&preferred, &query,
                                               &(TC_X509_revocation_time){updated.at, 0, 0},
                                               &(tc_x509_crl_decode){&limits, &tree, &names, oids,
                                                                     EXTENSION_CAPACITY},
                                               &applied),
                             ==, TC_TLV_END);
            munit_assert_memory_equal(sizeof applied, &applied, &completed);
            applied = empty;
            work = apply_work - 1;
            munit_assert_int(tc_x509_crl_apply(&preferred, &query,
                                               &(TC_X509_revocation_time){updated.at, 0, 0},
                                               &(tc_x509_crl_decode){&limits, &tree, &names, oids,
                                                                     EXTENSION_CAPACITY},
                                               &applied),
                             ==, TC_TLV_LIMIT);
            munit_assert_memory_equal(sizeof applied, &applied, &empty);
            work = apply_work;
            munit_assert_int(tc_x509_crl_apply(&preferred, &query,
                                               &(TC_X509_revocation_time){updated.at, 0, 0},
                                               &(tc_x509_crl_decode){&limits, &tree, &names, oids,
                                                                     EXTENSION_CAPACITY},
                                               &applied),
                             ==, TC_TLV_OK);
            munit_assert_size(work, ==, 0);
            applied = empty;
            work = TRUST_WORK_BUDGET;
            munit_assert_int(tc_x509_crl_apply(&preferred, &query,
                                               &(TC_X509_revocation_time){delta.next_update, 0, 0},
                                               &(tc_x509_crl_decode){&limits, &tree, &names, oids,
                                                                     EXTENSION_CAPACITY},
                                               &applied),
                             ==, TC_TLV_END);
            munit_assert_memory_equal(sizeof applied, &applied, &empty);
          }
          if (!wrong_key && i == 0) {
            uint8_t extra_der[2][ENCODED_CAPACITY];
            TC_bytes extended[] = {parsed.encoded, delta.encoded, {NULL, 0}, {NULL, 0}};
            for (size_t extra = 0; extra < 2; ++extra) {
              X509_CRL* variant = X509_CRL_dup(delta_crl);
              ASN1_INTEGER* variant_number = ASN1_INTEGER_new();
              munit_assert_not_null(variant);
              munit_assert_not_null(variant_number);
              munit_assert_int(ASN1_INTEGER_set(variant_number, (long)(3 + extra)), ==, 1);
              munit_assert_int(X509_CRL_add1_ext_i2d(variant, NID_crl_number, variant_number, 0,
                                                     X509V3_ADD_REPLACE),
                               ==, 1);
              ASN1_INTEGER_free(variant_number);
              munit_assert_int(X509_CRL_sign(variant, extra ? other_key : generated, EVP_sha256()),
                               >, 0);
              const int length = i2d_X509_CRL(variant, NULL);
              munit_assert_int(length, >, 0);
              munit_assert_size((size_t)length, <=, sizeof extra_der[extra]);
              unsigned char* destination = extra_der[extra];
              munit_assert_int(i2d_X509_CRL(variant, &destination), ==, length);
              extended[extra + 2] = (TC_bytes){extra_der[extra], (size_t)length};
              X509_CRL_free(variant);
            }
            candidate_source mixed_source = {extended, 4, 0, TC_TLV_OK, 0};
            const tc_pki_record_source mixed_records = {&mixed_source, 4, read_candidate};
            TC_X509_crl_record mixed_rows[4];
            TC_X509_crl_index mixed_index;
            for (unsigned order = 0; order < 2; ++order) {
              work = TRUST_WORK_BUDGET;
              munit_assert_int(tc_cms_revocations_init((TC_bytes){NULL, 0}, &mixed_records, 4,
                                                       4 * ENCODED_CAPACITY, &limits, &tree,
                                                       &revocations),
                               ==, TC_TLV_OK);
              munit_assert_int(tc_cms_crl_index_init(&revocations, &tree, oids, EXTENSION_CAPACITY,
                                                     mixed_rows, 4, &mixed_index),
                               ==, TC_TLV_OK);
              munit_assert_int(tc_x509_crl_delta_select(
                                   &(tc_x509_crl_signature_cache){&mixed_index, &signer, &provider,
                                                                  &limits, &names, NULL, 0, NULL},
                                   0, &(TC_X509_revocation_time){updated.at, 0, 0}, &tree, NULL,
                                   &preferred),
                               ==, TC_TLV_OK);
              munit_assert_ptr_equal(preferred.delta->encoded.data, extra_der[0]);
              TC_bytes swap = extended[1];
              extended[1] = extended[3];
              extended[3] = swap;
            }
            preferred = untouched;
            work = TRUST_WORK_BUDGET;
            munit_assert_int(tc_x509_crl_delta_select(
                                 &(tc_x509_crl_signature_cache){&mixed_index, &signer, &provider,
                                                                &limits, &names, NULL, 0, NULL},
                                 0, &(TC_X509_revocation_time){delta.next_update, 0, 0}, &tree,
                                 NULL, &preferred),
                             ==, TC_TLV_END);
            munit_assert_memory_equal(sizeof preferred, &preferred, &untouched);
            work = TRUST_WORK_BUDGET;
            munit_assert_int(tc_x509_crl_delta_select(
                                 &(tc_x509_crl_signature_cache){&mixed_index, &signer, NULL,
                                                                &limits, &names, NULL, 0, NULL},
                                 0, &(TC_X509_revocation_time){updated.at, 0, 0}, &tree, NULL,
                                 &preferred),
                             ==, TC_TLV_UNSUPPORTED);
            munit_assert_memory_equal(sizeof preferred, &preferred, &untouched);
            for (long collision = 2; collision <= 3; ++collision) {
              X509_CRL* variant = X509_CRL_dup(delta_crl);
              ASN1_INTEGER* variant_number = ASN1_INTEGER_new();
              ASN1_TIME* variant_next = ASN1_TIME_new();
              munit_assert_not_null(variant);
              munit_assert_not_null(variant_number);
              munit_assert_not_null(variant_next);
              munit_assert_int(ASN1_INTEGER_set(variant_number, collision), ==, 1);
              munit_assert_int(X509_CRL_add1_ext_i2d(variant, NID_crl_number, variant_number, 0,
                                                     X509V3_ADD_REPLACE),
                               ==, 1);
              munit_assert_int(ASN1_TIME_set_string(variant_next, "280101000001Z"), ==, 1);
              munit_assert_int(X509_CRL_set1_nextUpdate(variant, variant_next), ==, 1);
              ASN1_INTEGER_free(variant_number);
              ASN1_TIME_free(variant_next);
              munit_assert_int(X509_CRL_sign(variant, generated, EVP_sha256()), >, 0);
              const int length = i2d_X509_CRL(variant, NULL);
              munit_assert_int(length, >, 0);
              munit_assert_size((size_t)length, <=, sizeof extra_der[1]);
              unsigned char* destination = extra_der[1];
              munit_assert_int(i2d_X509_CRL(variant, &destination), ==, length);
              X509_CRL_free(variant);
              extended[3] = (TC_bytes){extra_der[1], (size_t)length};
              for (unsigned order = 0; order < 2; ++order) {
                work = TRUST_WORK_BUDGET;
                preferred = untouched;
                munit_assert_int(tc_cms_revocations_init((TC_bytes){NULL, 0}, &mixed_records, 4,
                                                         4 * ENCODED_CAPACITY, &limits, &tree,
                                                         &revocations),
                                 ==, TC_TLV_OK);
                munit_assert_int(tc_cms_crl_index_init(&revocations, &tree, oids,
                                                       EXTENSION_CAPACITY, mixed_rows, 4,
                                                       &mixed_index),
                                 ==, TC_TLV_OK);
                munit_assert_int(
                    tc_x509_crl_delta_select(
                        &(tc_x509_crl_signature_cache){&mixed_index, &signer, &provider, &limits,
                                                       &names, NULL, 0, NULL},
                        0, &(TC_X509_revocation_time){updated.at, 0, 0}, &tree, NULL, &preferred),
                    ==, collision == 3 ? TC_TLV_INVALID : TC_TLV_OK);
                if (collision == 3)
                  munit_assert_memory_equal(sizeof preferred, &preferred, &untouched);
                else
                  munit_assert_ptr_equal(preferred.delta->encoded.data, extra_der[0]);
                TC_bytes swap = extended[2];
                extended[2] = extended[3];
                extended[3] = swap;
              }
            }
          }
          /* A pair authenticates under one key before its base signer path. */
          probe.calls = 0;
          work = TRUST_WORK_BUDGET;
          munit_assert_int(tc_x509_crl_selected_authenticate(
                               &indexed_pair, &signer, &updated.signatures,
                               &(tc_x509_crl_decode){&limits, &tree, &names, NULL, 0}),
                           ==, wrong_key ? TC_TLV_INVALID : TC_TLV_OK);
          if (!wrong_key) {
            munit_assert_size(probe.calls, ==, 2);
            const tc_x509_crl_trust signer_trust = {
                &source,
                1,
                &updated,
                &(tc_pki_tree_workspace){validation.frames.data, validation.frames.capacity, &work},
                &validation,
                &search,
                &(TC_X509_revocation_time){(&updated)->at, 0, 0}};
            trusted = unchanged;
            probe.calls = 0;
            work = TRUST_WORK_BUDGET;
            munit_assert_int(
                tc_x509_crl_signer_validate(indexed_pair.base, &signer, &signer_trust, &trusted),
                ==, TC_X509_PATH_VALID);
            const size_t required = TRUST_WORK_BUDGET - work;
            munit_assert_size(trusted.validation.work_used, ==, required);
            munit_assert_size(trusted.anchor_index, ==, 1);
            munit_assert_size(probe.calls, ==, 2);
            trusted = unchanged;
            work = required - 1;
            munit_assert_int(
                tc_x509_crl_signer_validate(indexed_pair.base, &signer, &signer_trust, &trusted),
                ==, TC_X509_PATH_LIMIT);
            munit_assert_memory_equal(sizeof trusted, &trusted, &unchanged);
            work = required;
            munit_assert_int(
                tc_x509_crl_signer_validate(indexed_pair.base, &signer, &signer_trust, &trusted),
                ==, TC_X509_PATH_VALID);
            munit_assert_size(work, ==, 0);
          }
          const TC_X509_crl_delta_policy policies[] = {TC_X509_CRL_COMPLETE_ONLY,
                                                       TC_X509_CRL_DELTA_IF_AVAILABLE,
                                                       TC_X509_CRL_DELTA_REQUIRED};
          for (unsigned period = 0; period < 2; ++period) {
            TC_X509_path_options indexed_options = updated;
            indexed_options.at = period ? delta.this_update : parsed.this_update;
            for (size_t policy = 0; policy < sizeof policies / sizeof policies[0]; ++policy) {
              const TC_TLV_result expected =
                  period
                      ? (!wrong_key && policies[policy] != TC_X509_CRL_COMPLETE_ONLY ? TC_TLV_OK
                                                                                     : TC_TLV_END)
                      : (policies[policy] == TC_X509_CRL_DELTA_REQUIRED ? TC_TLV_END : TC_TLV_OK);
              TC_X509_crl_evidence indexed_evidence = {0};
              uint8_t scope_states[2];
              indexed_evidence = empty;
              trusted = unchanged;
              probe.calls = 0;
              work = TRUST_WORK_BUDGET;
              munit_assert_int(tc_cms_crl_scope_process(
                                   &candidate_reader,
                                   &(tc_x509_crl_scope_processing){
                                       &crl_index, 0, policies[policy], TC_X509_CRL_ORDER_NUMBER,
                                       &query, scope_states, sizeof scope_states, &indexed_evidence,
                                       NULL, NULL, NULL, NULL, NULL},
                                   &(tc_x509_crl_trust){
                                       &source, 1, &indexed_options, &tree, &validation, &search,
                                       &(TC_X509_revocation_time){(&indexed_options)->at, 0, 0}},
                                   &trusted),
                               ==, expected);
              munit_assert_memory_equal(sizeof candidate_reader, &candidate_reader, &before_search);
              munit_assert_size(probe.calls, ==,
                                period && policies[policy] != TC_X509_CRL_COMPLETE_ONLY ? 3 : 2);
              if (expected == TC_TLV_OK) {
                TC_X509_revocation_status scope_status;
                const size_t required = TRUST_WORK_BUDGET - work;
                munit_assert_size(trusted.validation.work_used, ==, required);
                munit_assert_int(tc_x509_crl_evidence_status(&indexed_evidence, &scope_status), ==,
                                 TC_TLV_OK);
                munit_assert_int(scope_status, ==,
                                 revoked && (!period || reasons[i] != 8)
                                     ? TC_X509_REVOCATION_REVOKED
                                     : TC_X509_REVOCATION_GOOD);
                /* One unit short fails with LIMIT. The exact budget succeeds. */
                for (unsigned attempt = 0; attempt < 2; ++attempt) {
                  const unsigned short_work = attempt == 0;
                  indexed_evidence = empty;
                  trusted = unchanged;
                  work = required - short_work;
                  munit_assert_int(
                      cms_crl_scope_check(
                          &candidate_reader, &crl_index, 0, policies[policy], &query,
                          &(tc_x509_crl_trust){
                              &source, 1, &indexed_options, &tree, &validation, &search,
                              &(TC_X509_revocation_time){(&indexed_options)->at, 0, 0}},
                          &indexed_evidence, &trusted),
                      ==, short_work ? TC_TLV_LIMIT : TC_TLV_OK);
                  if (short_work) {
                    munit_assert_uint(indexed_evidence.reasons, ==, 0);
                    munit_assert_int(indexed_evidence.revocation.found, ==, 0);
                    munit_assert_ptr_equal(trusted.path, unchanged.path);
                    munit_assert_size(trusted.count, ==, unchanged.count);
                    munit_assert_size(trusted.anchor_index, ==, unchanged.anchor_index);
                    munit_assert_size(trusted.validation.work_used, ==,
                                      unchanged.validation.work_used);
                  } else
                    munit_assert_size(work, ==, 0);
                }
              } else {
                munit_assert_memory_equal(sizeof indexed_evidence, &indexed_evidence, &empty);
                munit_assert_memory_equal(sizeof trusted, &trusted, &unchanged);
              }
            }
          }
          {
            uint8_t current_base_der[ENCODED_CAPACITY];
            X509_CRL* current_base = X509_CRL_dup(crl);
            munit_assert_not_null(current_base);
            munit_assert_int(
                X509_CRL_set1_nextUpdate(current_base, X509_CRL_get0_nextUpdate(delta_crl)), ==, 1);
            munit_assert_int(X509_CRL_sign(current_base, generated, EVP_sha256()), >, 0);
            const int length = i2d_X509_CRL(current_base, NULL);
            munit_assert_int(length, >, 0);
            munit_assert_size((size_t)length, <=, sizeof current_base_der);
            unsigned char* destination = current_base_der;
            munit_assert_int(i2d_X509_CRL(current_base, &destination), ==, length);
            const TC_bytes overlap_records[] = {{current_base_der, (size_t)length}, delta.encoded};
            candidate_source overlap_source = {overlap_records, 2, 0, TC_TLV_OK, 0};
            const tc_pki_record_source overlap_input = {&overlap_source, 2, read_candidate};
            TC_X509_crl_record overlap_rows[2];
            TC_X509_crl_index overlap_index;
            work = TRUST_WORK_BUDGET;
            munit_assert_int(tc_cms_revocations_init((TC_bytes){NULL, 0}, &overlap_input, 2,
                                                     2 * ENCODED_CAPACITY, &limits, &tree,
                                                     &revocations),
                             ==, TC_TLV_OK);
            munit_assert_int(tc_cms_crl_index_init(&revocations, &tree, oids, EXTENSION_CAPACITY,
                                                   overlap_rows, 2, &overlap_index),
                             ==, TC_TLV_OK);
            tc_x509_freshness freshness;
            for (size_t record = 0; record < overlap_index.count; ++record) {
              munit_assert_int(tc_x509_crl_fresh_at(&overlap_rows[record].crl,
                                                    &(TC_X509_revocation_time){updated.at, 0, 0},
                                                    &freshness),
                               ==, TC_TLV_OK);
              munit_assert_int(freshness, ==, TC_X509_FRESH_CURRENT);
            }
            for (size_t policy = 0; policy < sizeof policies / sizeof policies[0]; ++policy) {
              TC_X509_crl_evidence overlap_evidence = {0};
              const int required_missing =
                  wrong_key && policies[policy] == TC_X509_CRL_DELTA_REQUIRED;
              const int use_delta = !wrong_key && policies[policy] != TC_X509_CRL_COMPLETE_ONLY;
              work = TRUST_WORK_BUDGET;
              trusted = unchanged;
              probe.calls = 0;
              munit_assert_int(
                  cms_crl_scope_check(
                      &candidate_reader, &overlap_index, 0, policies[policy], &query,
                      &(tc_x509_crl_trust){&source, 1, &updated, &tree, &validation, &search,
                                           &(TC_X509_revocation_time){(&updated)->at, 0, 0}},
                      &overlap_evidence, &trusted),
                  ==, required_missing ? TC_TLV_END : TC_TLV_OK);
              munit_assert_size(probe.calls, ==,
                                policies[policy] == TC_X509_CRL_COMPLETE_ONLY ? 2 : 3);
              if (required_missing) {
                munit_assert_memory_equal(sizeof overlap_evidence, &overlap_evidence, &empty);
                munit_assert_memory_equal(sizeof trusted, &trusted, &unchanged);
              } else {
                TC_X509_revocation_status overlap_status;
                munit_assert_int(tc_x509_crl_evidence_status(&overlap_evidence, &overlap_status),
                                 ==, TC_TLV_OK);
                munit_assert_int(overlap_status, ==,
                                 revoked && (!use_delta || reasons[i] != 8)
                                     ? TC_X509_REVOCATION_REVOKED
                                     : TC_X509_REVOCATION_GOOD);
              }
            }
            if (!wrong_key && i == 0) {
              enum { NEWER_NUMBER = 3, RECORDS = 4 };
              uint8_t newer_der[ENCODED_CAPACITY], conflicting_der[ENCODED_CAPACITY],
                  states[RECORDS];
              TC_X509_crl_record rows[RECORDS];
              TC_X509_crl_index index;
              tc_x509_crl_signature_cache cache;
              TC_X509_time selection_at = updated.at;
              munit_assert_uint(selection_at.second, ==, 0);
              ++selection_at.second;
              ASN1_TIME* newer_update = ASN1_TIME_new();
              munit_assert_not_null(newer_update);
              munit_assert_int(ASN1_TIME_set_string(newer_update, "270101000001Z"), ==, 1);
              munit_assert_int(X509_CRL_set1_lastUpdate(current_base, newer_update), ==, 1);
              /* Two signed deltas disagree at number 2. Complete number 3
                 * supersedes both. */
              X509_CRL* conflicting = X509_CRL_dup(delta_crl);
              munit_assert_not_null(conflicting);
              munit_assert_int(X509_CRL_set1_lastUpdate(conflicting, newer_update), ==, 1);
              munit_assert_int(X509_CRL_sign(conflicting, generated, EVP_sha256()), >, 0);
              const int conflicting_size = i2d_X509_CRL(conflicting, NULL);
              munit_assert_int(conflicting_size, >, 0);
              munit_assert_size((size_t)conflicting_size, <=, sizeof conflicting_der);
              unsigned char* conflicting_next = conflicting_der;
              munit_assert_int(i2d_X509_CRL(conflicting, &conflicting_next), ==, conflicting_size);
              X509_CRL_free(conflicting);
              ASN1_TIME_free(newer_update);
              ASN1_INTEGER* number = ASN1_INTEGER_new();
              munit_assert_not_null(number);
              munit_assert_int(ASN1_INTEGER_set(number, NEWER_NUMBER), ==, 1);
              munit_assert_int(X509_CRL_add1_ext_i2d(current_base, NID_crl_number, number, 0,
                                                     X509V3_ADD_REPLACE),
                               ==, 1);
              ASN1_INTEGER_free(number);
              if (revoked) {
                STACK_OF(X509_REVOKED)* entries = X509_CRL_get_REVOKED(current_base);
                munit_assert_int(sk_X509_REVOKED_num(entries), ==, 1);
                ASN1_ENUMERATED* reason = ASN1_ENUMERATED_new();
                munit_assert_not_null(reason);
                munit_assert_int(ASN1_ENUMERATED_set(reason, 2), ==, 1);
                munit_assert_int(X509_REVOKED_add1_ext_i2d(sk_X509_REVOKED_value(entries, 0),
                                                           NID_crl_reason, reason, 0,
                                                           X509V3_ADD_REPLACE),
                                 ==, 1);
                ASN1_ENUMERATED_free(reason);
              }
              for (int numbered = 1; numbered >= 0; --numbered) {
                if (!numbered) {
                  const int extension = X509_CRL_get_ext_by_NID(current_base, NID_crl_number, -1);
                  munit_assert_int(extension, >=, 0);
                  X509_EXTENSION_free(X509_CRL_delete_ext(current_base, extension));
                }
                munit_assert_int(X509_CRL_sign(current_base, generated, EVP_sha256()), >, 0);
                const int size = i2d_X509_CRL(current_base, NULL);
                munit_assert_int(size, >, 0);
                munit_assert_size((size_t)size, <=, sizeof newer_der);
                unsigned char* next = newer_der;
                munit_assert_int(i2d_X509_CRL(current_base, &next), ==, size);
                TC_bytes inputs[] = {overlap_records[0],
                                     delta.encoded,
                                     {conflicting_der, (size_t)conflicting_size},
                                     {newer_der, (size_t)size}};
                candidate_source input_source = {inputs, RECORDS, 0, TC_TLV_OK, 0};
                const tc_pki_record_source input_records = {&input_source, RECORDS, read_candidate};
                const TC_bytes sentinel = delta.signature;
                for (unsigned order = 0; order < 2; ++order) {
                  work = TRUST_WORK_BUDGET;
                  probe.calls = 0;
                  munit_assert_int(tc_cms_revocations_init((TC_bytes){NULL, 0}, &input_records,
                                                           RECORDS, RECORDS * ENCODED_CAPACITY,
                                                           &limits, &tree, &revocations),
                                   ==, TC_TLV_OK);
                  munit_assert_int(tc_cms_crl_index_init(&revocations, &tree, oids,
                                                         EXTENSION_CAPACITY, rows, RECORDS, &index),
                                   ==, TC_TLV_OK);
                  munit_assert_int(tc_x509_crl_signature_cache_init(
                                       &index, &signer, &updated.signatures, &limits, &names,
                                       (TC_buffer){states, RECORDS}, &work, &cache),
                                   ==, TC_TLV_OK);
                  TC_bytes latest = sentinel;
                  munit_assert_int(
                      tc_x509_crl_latest_number(
                          &(tc_x509_crl_scope_context){
                              &cache, TC_X509_CRL_DELTA_IF_AVAILABLE, TC_X509_CRL_ORDER_NUMBER,
                              &(TC_X509_revocation_time){*(&selection_at), 0, 0}, &tree, NULL, 0},
                          0, &latest),
                      ==, numbered ? TC_TLV_OK : TC_TLV_UNSUPPORTED);
                  if (numbered) {
                    munit_assert_size(latest.length, ==, 1);
                    munit_assert_uint(latest.data[0], ==, NEWER_NUMBER);
                    munit_assert_size(probe.calls, ==, RECORDS);
                    work = TRUST_WORK_BUDGET;
                    munit_assert_int(
                        tc_x509_crl_latest_number(
                            &(tc_x509_crl_scope_context){
                                &cache, TC_X509_CRL_DELTA_IF_AVAILABLE, TC_X509_CRL_ORDER_NUMBER,
                                &(TC_X509_revocation_time){*(&selection_at), 0, 0}, &tree, NULL, 0},
                            0, &latest),
                        ==, TC_TLV_OK);
                    const size_t required = TRUST_WORK_BUDGET - work;
                    latest = sentinel;
                    work = required - 1;
                    munit_assert_int(
                        tc_x509_crl_latest_number(
                            &(tc_x509_crl_scope_context){
                                &cache, TC_X509_CRL_DELTA_IF_AVAILABLE, TC_X509_CRL_ORDER_NUMBER,
                                &(TC_X509_revocation_time){*(&selection_at), 0, 0}, &tree, NULL, 0},
                            0, &latest),
                        ==, TC_TLV_LIMIT);
                    munit_assert_memory_equal(sizeof latest, &latest, &sentinel);
                    work = required;
                    munit_assert_int(
                        tc_x509_crl_latest_number(
                            &(tc_x509_crl_scope_context){
                                &cache, TC_X509_CRL_DELTA_IF_AVAILABLE, TC_X509_CRL_ORDER_NUMBER,
                                &(TC_X509_revocation_time){*(&selection_at), 0, 0}, &tree, NULL, 0},
                            0, &latest),
                        ==, TC_TLV_OK);
                    munit_assert_size(work, ==, 0);
                    munit_assert_size(probe.calls, ==, RECORDS);
                    TC_X509_crl_evidence selected_evidence = {0};
                    TC_X509_revocation_status selected_status;
                    work = TRUST_WORK_BUDGET;
                    munit_assert_int(
                        tc_x509_crl_scope_evaluate(
                            &(tc_x509_crl_scope_context){
                                &cache, TC_X509_CRL_DELTA_IF_AVAILABLE, TC_X509_CRL_ORDER_NUMBER,
                                &(TC_X509_revocation_time){*(&selection_at), 0, 0}, &tree, oids,
                                EXTENSION_CAPACITY},
                            0, &query, &selected_evidence, NULL),
                        ==, TC_TLV_OK);
                    munit_assert_int(
                        tc_x509_crl_evidence_status(&selected_evidence, &selected_status), ==,
                        TC_TLV_OK);
                    munit_assert_int(selected_status, ==,
                                     revoked ? TC_X509_REVOCATION_REVOKED
                                             : TC_X509_REVOCATION_GOOD);
                    if (revoked)
                      munit_assert_uint(selected_evidence.revocation.reason, ==, 2);
                    munit_assert_size(probe.calls, ==, RECORDS);
                  } else
                    munit_assert_memory_equal(sizeof latest, &latest, &sentinel);
                  TC_X509_crl_evidence legacy_evidence = {0};
                  TC_X509_revocation_status legacy_status;
                  work = TRUST_WORK_BUDGET;
                  munit_assert_int(
                      tc_x509_crl_scope_evaluate(
                          &(tc_x509_crl_scope_context){
                              &cache, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_THIS_UPDATE,
                              &(TC_X509_revocation_time){*(&selection_at), 0, 0}, &tree, oids,
                              EXTENSION_CAPACITY},
                          0, &query, &legacy_evidence, NULL),
                      ==, TC_TLV_OK);
                  munit_assert_int(tc_x509_crl_evidence_status(&legacy_evidence, &legacy_status),
                                   ==, TC_TLV_OK);
                  munit_assert_int(legacy_status, ==,
                                   revoked ? TC_X509_REVOCATION_REVOKED : TC_X509_REVOCATION_GOOD);
                  if (revoked)
                    munit_assert_uint(legacy_evidence.revocation.reason, ==, 2);
                  const size_t calls = probe.calls;
                  legacy_evidence = empty;
                  work = TRUST_WORK_BUDGET;
                  munit_assert_int(
                      tc_x509_crl_scope_evaluate(
                          &(tc_x509_crl_scope_context){
                              &cache, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_THIS_UPDATE,
                              &(TC_X509_revocation_time){*(&selection_at), 0, 0}, &tree, oids,
                              EXTENSION_CAPACITY},
                          0, &query, &legacy_evidence, NULL),
                      ==, TC_TLV_OK);
                  const size_t legacy_work = TRUST_WORK_BUDGET - work;
                  legacy_evidence = empty;
                  work = legacy_work - 1;
                  munit_assert_int(
                      tc_x509_crl_scope_evaluate(
                          &(tc_x509_crl_scope_context){
                              &cache, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_THIS_UPDATE,
                              &(TC_X509_revocation_time){*(&selection_at), 0, 0}, &tree, oids,
                              EXTENSION_CAPACITY},
                          0, &query, &legacy_evidence, NULL),
                      ==, TC_TLV_LIMIT);
                  munit_assert_memory_equal(sizeof legacy_evidence, &legacy_evidence, &empty);
                  work = legacy_work;
                  munit_assert_int(
                      tc_x509_crl_scope_evaluate(
                          &(tc_x509_crl_scope_context){
                              &cache, TC_X509_CRL_COMPLETE_ONLY, TC_X509_CRL_ORDER_THIS_UPDATE,
                              &(TC_X509_revocation_time){*(&selection_at), 0, 0}, &tree, oids,
                              EXTENSION_CAPACITY},
                          0, &query, &legacy_evidence, NULL),
                      ==, TC_TLV_OK);
                  munit_assert_size(work, ==, 0);
                  munit_assert_size(probe.calls, ==, calls);
                  legacy_evidence = empty;
                  work = TRUST_WORK_BUDGET;
                  munit_assert_int(
                      tc_x509_crl_scope_evaluate(
                          &(tc_x509_crl_scope_context){
                              &cache, TC_X509_CRL_COMPLETE_ONLY, (TC_X509_crl_order_policy)-1,
                              &(TC_X509_revocation_time){*(&selection_at), 0, 0}, &tree, oids,
                              EXTENSION_CAPACITY},
                          0, &query, &legacy_evidence, NULL),
                      ==, TC_TLV_ARGUMENT);
                  munit_assert_memory_equal(sizeof legacy_evidence, &legacy_evidence, &empty);
                  munit_assert_size(work, ==, TRUST_WORK_BUDGET);
                  TC_X509_path_options scope_options = updated;
                  scope_options.at = selection_at;
                  const TC_X509_crl_delta_policy scope_delta =
                      numbered ? TC_X509_CRL_DELTA_IF_AVAILABLE : TC_X509_CRL_COMPLETE_ONLY;
                  const TC_X509_crl_order_policy scope_order =
                      numbered ? TC_X509_CRL_ORDER_NUMBER : TC_X509_CRL_ORDER_THIS_UPDATE;
                  legacy_evidence = empty;
                  trusted = unchanged;
                  work = TRUST_WORK_BUDGET;
                  probe.calls = 0;
                  munit_assert_int(tc_cms_crl_scope_process(
                                       &candidate_reader,
                                       &(tc_x509_crl_scope_processing){
                                           &index, 0, scope_delta, scope_order, &query, states,
                                           RECORDS, &legacy_evidence, NULL, NULL, NULL, NULL, NULL},
                                       &(tc_x509_crl_trust){
                                           &source, 1, &scope_options, &tree, &validation, &search,
                                           &(TC_X509_revocation_time){(&scope_options)->at, 0, 0}},
                                       &trusted),
                                   ==, TC_TLV_OK);
                  const size_t scope_work = TRUST_WORK_BUDGET - work;
                  munit_assert_size(trusted.validation.work_used, ==, scope_work);
                  munit_assert_size(trusted.anchor_index, ==, 1);
                  munit_assert_size(probe.calls, ==, numbered ? RECORDS + 1 : 3);
                  munit_assert_int(tc_x509_crl_evidence_status(&legacy_evidence, &legacy_status),
                                   ==, TC_TLV_OK);
                  munit_assert_int(legacy_status, ==,
                                   revoked ? TC_X509_REVOCATION_REVOKED : TC_X509_REVOCATION_GOOD);
                  if (revoked)
                    munit_assert_uint(legacy_evidence.revocation.reason, ==, 2);
                  munit_assert_memory_equal(sizeof candidate_reader, &candidate_reader,
                                            &before_search);
                  legacy_evidence = empty;
                  trusted = unchanged;
                  work = scope_work - 1;
                  munit_assert_int(tc_cms_crl_scope_process(
                                       &candidate_reader,
                                       &(tc_x509_crl_scope_processing){
                                           &index, 0, scope_delta, scope_order, &query, states,
                                           RECORDS, &legacy_evidence, NULL, NULL, NULL, NULL, NULL},
                                       &(tc_x509_crl_trust){
                                           &source, 1, &scope_options, &tree, &validation, &search,
                                           &(TC_X509_revocation_time){(&scope_options)->at, 0, 0}},
                                       &trusted),
                                   ==, TC_TLV_LIMIT);
                  munit_assert_memory_equal(sizeof legacy_evidence, &legacy_evidence, &empty);
                  munit_assert_memory_equal(sizeof trusted, &trusted, &unchanged);
                  work = scope_work;
                  munit_assert_int(tc_cms_crl_scope_process(
                                       &candidate_reader,
                                       &(tc_x509_crl_scope_processing){
                                           &index, 0, scope_delta, scope_order, &query, states,
                                           RECORDS, &legacy_evidence, NULL, NULL, NULL, NULL, NULL},
                                       &(tc_x509_crl_trust){
                                           &source, 1, &scope_options, &tree, &validation, &search,
                                           &(TC_X509_revocation_time){(&scope_options)->at, 0, 0}},
                                       &trusted),
                                   ==, TC_TLV_OK);
                  munit_assert_size(work, ==, 0);
                  legacy_evidence = empty;
                  trusted = unchanged;
                  work = TRUST_WORK_BUDGET;
                  munit_assert_int(
                      tc_cms_crl_scope_process(
                          &candidate_reader,
                          &(tc_x509_crl_scope_processing){
                              &index, 0, scope_delta, scope_order, &query, states, RECORDS - 1,
                              &legacy_evidence, NULL, NULL, NULL, NULL, NULL},
                          &(tc_x509_crl_trust){
                              &source, 1, &scope_options, &tree, &validation, &search,
                              &(TC_X509_revocation_time){(&scope_options)->at, 0, 0}},
                          &trusted),
                      ==, TC_TLV_LIMIT);
                  munit_assert_size(work, ==, TRUST_WORK_BUDGET);
                  munit_assert_memory_equal(sizeof legacy_evidence, &legacy_evidence, &empty);
                  munit_assert_memory_equal(sizeof trusted, &trusted, &unchanged);
                  munit_assert_int(tc_cms_crl_scope_process(
                                       &candidate_reader,
                                       &(tc_x509_crl_scope_processing){
                                           &index, 0, scope_delta, scope_order, &query, states,
                                           RECORDS, &legacy_evidence, NULL, NULL, NULL, NULL, NULL},
                                       &(tc_x509_crl_trust){
                                           &source, 0, &scope_options, &tree, &validation, &search,
                                           &(TC_X509_revocation_time){(&scope_options)->at, 0, 0}},
                                       &trusted),
                                   ==, TC_TLV_INVALID);
                  munit_assert_memory_equal(sizeof legacy_evidence, &legacy_evidence, &empty);
                  munit_assert_memory_equal(sizeof trusted, &trusted, &unchanged);
                  if (numbered) {
                    work = TRUST_WORK_BUDGET;
                    probe.calls = 0;
                    munit_assert_int(
                        tc_cms_crl_scope_process(
                            &candidate_reader,
                            &(tc_x509_crl_scope_processing){
                                &index, 1, scope_delta, scope_order, &query, states, RECORDS,
                                &legacy_evidence, NULL, NULL, NULL, NULL, NULL},
                            &(tc_x509_crl_trust){
                                &source, 1, &scope_options, &tree, &validation, &search,
                                &(TC_X509_revocation_time){(&scope_options)->at, 0, 0}},
                            &trusted),
                        ==, TC_TLV_OK);
                    munit_assert_size(probe.calls, ==, RECORDS + 1);
                    munit_assert_int(tc_x509_crl_evidence_status(&legacy_evidence, &legacy_status),
                                     ==, TC_TLV_OK);
                    munit_assert_int(legacy_status, ==,
                                     revoked ? TC_X509_REVOCATION_REVOKED
                                             : TC_X509_REVOCATION_GOOD);
                    if (revoked)
                      munit_assert_uint(legacy_evidence.revocation.reason, ==, 2);
                    const TC_X509_crl_evidence completed = legacy_evidence;
                    trusted = unchanged;
                    work = TRUST_WORK_BUDGET;
                    probe.calls = 0;
                    munit_assert_int(
                        tc_cms_crl_scope_process(
                            &candidate_reader,
                            &(tc_x509_crl_scope_processing){
                                &index, 1, scope_delta, scope_order, &query, states, RECORDS,
                                &legacy_evidence, NULL, NULL, NULL, NULL, NULL},
                            &(tc_x509_crl_trust){
                                &source, 1, &scope_options, &tree, &validation, &search,
                                &(TC_X509_revocation_time){(&scope_options)->at, 0, 0}},
                            &trusted),
                        ==, TC_TLV_END);
                    munit_assert_memory_equal(sizeof legacy_evidence, &legacy_evidence, &completed);
                    munit_assert_memory_equal(sizeof trusted, &trusted, &unchanged);
                    munit_assert_size(work, ==, TRUST_WORK_BUDGET);
                    munit_assert_size(probe.calls, ==, 0);
                  }
                  TC_bytes swap = inputs[0];
                  inputs[0] = inputs[RECORDS - 1];
                  inputs[RECORDS - 1] = swap;
                }
              }
              TC_bytes conflicting_inputs[] = {
                  overlap_records[0], delta.encoded, {conflicting_der, (size_t)conflicting_size}};
              enum { CONFLICT_RECORDS = 3 };
              candidate_source conflict_source = {conflicting_inputs, CONFLICT_RECORDS, 0,
                                                  TC_TLV_OK, 0};
              const tc_pki_record_source conflict_records = {&conflict_source, CONFLICT_RECORDS,
                                                             read_candidate};
              for (unsigned order = 0; order < 2; ++order) {
                work = TRUST_WORK_BUDGET;
                probe.calls = 0;
                munit_assert_int(tc_cms_revocations_init((TC_bytes){NULL, 0}, &conflict_records,
                                                         CONFLICT_RECORDS,
                                                         CONFLICT_RECORDS * ENCODED_CAPACITY,
                                                         &limits, &tree, &revocations),
                                 ==, TC_TLV_OK);
                munit_assert_int(tc_cms_crl_index_init(&revocations, &tree, oids,
                                                       EXTENSION_CAPACITY, rows, RECORDS, &index),
                                 ==, TC_TLV_OK);
                munit_assert_int(tc_x509_crl_signature_cache_init(
                                     &index, &signer, &updated.signatures, &limits, &names,
                                     (TC_buffer){states, RECORDS}, &work, &cache),
                                 ==, TC_TLV_OK);
                TC_bytes latest = delta.signature;
                munit_assert_int(
                    tc_x509_crl_latest_number(
                        &(tc_x509_crl_scope_context){
                            &cache, TC_X509_CRL_DELTA_IF_AVAILABLE, TC_X509_CRL_ORDER_NUMBER,
                            &(TC_X509_revocation_time){*(&selection_at), 0, 0}, &tree, NULL, 0},
                        0, &latest),
                    ==, TC_TLV_INVALID);
                munit_assert_memory_equal(sizeof latest, &latest, &delta.signature);
                TC_X509_crl_evidence rejected = {0};
                work = TRUST_WORK_BUDGET;
                munit_assert_int(
                    tc_x509_crl_scope_evaluate(
                        &(tc_x509_crl_scope_context){
                            &cache, TC_X509_CRL_DELTA_IF_AVAILABLE, TC_X509_CRL_ORDER_NUMBER,
                            &(TC_X509_revocation_time){*(&selection_at), 0, 0}, &tree, oids,
                            EXTENSION_CAPACITY},
                        0, &query, &rejected, NULL),
                    ==, TC_TLV_INVALID);
                munit_assert_memory_equal(sizeof rejected, &rejected, &empty);
                munit_assert_size(probe.calls, ==, CONFLICT_RECORDS);
                TC_bytes swap = conflicting_inputs[0];
                conflicting_inputs[0] = conflicting_inputs[CONFLICT_RECORDS - 1];
                conflicting_inputs[CONFLICT_RECORDS - 1] = swap;
              }
            }
            if (!wrong_key && i == 0) {
              enum { TIED_RECORDS = 3 };
              enum { CONSISTENT, DIFFERENT_REASON, DIFFERENT_UPDATE };
              TC_X509_time tie_at = updated.at;
              ++tie_at.second;
              for (unsigned fault = CONSISTENT; fault <= DIFFERENT_UPDATE; ++fault) {
                if (!revoked && fault == DIFFERENT_REASON)
                  continue;
                X509_CRL* tied = X509_CRL_dup(delta_crl);
                munit_assert_not_null(tied);
                const int extension = X509_CRL_get_ext_by_NID(tied, NID_delta_crl, -1);
                munit_assert_int(extension, >=, 0);
                X509_EXTENSION_free(X509_CRL_delete_ext(tied, extension));
                if (fault == DIFFERENT_REASON) {
                  ASN1_ENUMERATED* reason = ASN1_ENUMERATED_new();
                  munit_assert_not_null(reason);
                  munit_assert_int(ASN1_ENUMERATED_set(reason, 2), ==, 1);
                  X509_REVOKED* entry = sk_X509_REVOKED_value(X509_CRL_get_REVOKED(tied), 0);
                  munit_assert_not_null(entry);
                  munit_assert_int(X509_REVOKED_add1_ext_i2d(entry, NID_crl_reason, reason, 0,
                                                             X509V3_ADD_REPLACE),
                                   ==, 1);
                  ASN1_ENUMERATED_free(reason);
                } else if (fault == DIFFERENT_UPDATE) {
                  ASN1_TIME* changed = ASN1_TIME_new();
                  munit_assert_not_null(changed);
                  munit_assert_int(ASN1_TIME_set_string(changed, "270101000001Z"), ==, 1);
                  munit_assert_int(X509_CRL_set1_lastUpdate(tied, changed), ==, 1);
                  ASN1_TIME_free(changed);
                }
                uint8_t tied_der[ENCODED_CAPACITY], states[TIED_RECORDS];
                munit_assert_int(X509_CRL_sign(tied, generated, EVP_sha256()), >, 0);
                const int size = i2d_X509_CRL(tied, NULL);
                munit_assert_int(size, >, 0);
                munit_assert_size((size_t)size, <=, sizeof tied_der);
                unsigned char* next = tied_der;
                munit_assert_int(i2d_X509_CRL(tied, &next), ==, size);
                X509_CRL_free(tied);
                TC_bytes inputs[] = {overlap_records[0], delta.encoded, {tied_der, (size_t)size}};
                candidate_source input_source = {inputs, TIED_RECORDS, 0, TC_TLV_OK, 0};
                const tc_pki_record_source input_records = {&input_source, TIED_RECORDS,
                                                            read_candidate};
                TC_X509_crl_record rows[TIED_RECORDS];
                TC_X509_crl_index index;
                tc_x509_crl_signature_cache cache;
                for (unsigned order = 0; order < 2; ++order) {
                  work = TRUST_WORK_BUDGET;
                  probe.calls = 0;
                  munit_assert_int(tc_cms_revocations_init((TC_bytes){NULL, 0}, &input_records,
                                                           TIED_RECORDS,
                                                           TIED_RECORDS * ENCODED_CAPACITY, &limits,
                                                           &tree, &revocations),
                                   ==, TC_TLV_OK);
                  munit_assert_int(tc_cms_crl_index_init(&revocations, &tree, oids,
                                                         EXTENSION_CAPACITY, rows, TIED_RECORDS,
                                                         &index),
                                   ==, TC_TLV_OK);
                  munit_assert_int(tc_x509_crl_signature_cache_init(
                                       &index, &signer, &updated.signatures, &limits, &names,
                                       (TC_buffer){states, TIED_RECORDS}, &work, &cache),
                                   ==, TC_TLV_OK);
                  TC_X509_crl_evidence scope_evidence = {0};
                  munit_assert_int(
                      tc_x509_crl_scope_evaluate(
                          &(tc_x509_crl_scope_context){&cache, TC_X509_CRL_DELTA_IF_AVAILABLE,
                                                       TC_X509_CRL_ORDER_NUMBER,
                                                       &(TC_X509_revocation_time){*(&tie_at), 0, 0},
                                                       &tree, oids, EXTENSION_CAPACITY},
                          0, &query, &scope_evidence, NULL),
                      ==, fault == CONSISTENT ? TC_TLV_OK : TC_TLV_INVALID);
                  munit_assert_size(probe.calls, ==, TIED_RECORDS);
                  if (fault == CONSISTENT) {
                    TC_X509_revocation_status scope_status;
                    munit_assert_int(tc_x509_crl_evidence_status(&scope_evidence, &scope_status),
                                     ==, TC_TLV_OK);
                    munit_assert_int(scope_status, ==,
                                     revoked ? TC_X509_REVOCATION_REVOKED
                                             : TC_X509_REVOCATION_GOOD);
                    scope_evidence = empty;
                    work = TRUST_WORK_BUDGET;
                    munit_assert_int(
                        tc_x509_crl_scope_evaluate(
                            &(tc_x509_crl_scope_context){
                                &cache, TC_X509_CRL_DELTA_IF_AVAILABLE, TC_X509_CRL_ORDER_NUMBER,
                                &(TC_X509_revocation_time){*(&tie_at), 0, 0}, &tree, oids,
                                EXTENSION_CAPACITY},
                            0, &query, &scope_evidence, NULL),
                        ==, TC_TLV_OK);
                    const size_t required = TRUST_WORK_BUDGET - work;
                    scope_evidence = empty;
                    work = required - 1;
                    munit_assert_int(
                        tc_x509_crl_scope_evaluate(
                            &(tc_x509_crl_scope_context){
                                &cache, TC_X509_CRL_DELTA_IF_AVAILABLE, TC_X509_CRL_ORDER_NUMBER,
                                &(TC_X509_revocation_time){*(&tie_at), 0, 0}, &tree, oids,
                                EXTENSION_CAPACITY},
                            0, &query, &scope_evidence, NULL),
                        ==, TC_TLV_LIMIT);
                    munit_assert_memory_equal(sizeof scope_evidence, &scope_evidence, &empty);
                    work = required;
                    munit_assert_int(
                        tc_x509_crl_scope_evaluate(
                            &(tc_x509_crl_scope_context){
                                &cache, TC_X509_CRL_DELTA_IF_AVAILABLE, TC_X509_CRL_ORDER_NUMBER,
                                &(TC_X509_revocation_time){*(&tie_at), 0, 0}, &tree, oids,
                                EXTENSION_CAPACITY},
                            0, &query, &scope_evidence, NULL),
                        ==, TC_TLV_OK);
                    munit_assert_size(work, ==, 0);
                    munit_assert_size(probe.calls, ==, TIED_RECORDS);
                  } else
                    munit_assert_memory_equal(sizeof scope_evidence, &scope_evidence, &empty);
                  scope_evidence = empty;
                  work = TRUST_WORK_BUDGET;
                  munit_assert_int(
                      tc_x509_crl_scope_evaluate(
                          &(tc_x509_crl_scope_context){&cache, TC_X509_CRL_DELTA_IF_AVAILABLE,
                                                       TC_X509_CRL_ORDER_THIS_UPDATE,
                                                       &(TC_X509_revocation_time){*(&tie_at), 0, 0},
                                                       &tree, oids, EXTENSION_CAPACITY},
                          0, &query, &scope_evidence, NULL),
                      ==, fault == DIFFERENT_REASON ? TC_TLV_INVALID : TC_TLV_OK);
                  if (fault == DIFFERENT_REASON)
                    munit_assert_memory_equal(sizeof scope_evidence, &scope_evidence, &empty);
                  else {
                    TC_X509_revocation_status scope_status;
                    munit_assert_int(tc_x509_crl_evidence_status(&scope_evidence, &scope_status),
                                     ==, TC_TLV_OK);
                    munit_assert_int(scope_status, ==,
                                     revoked ? TC_X509_REVOCATION_REVOKED
                                             : TC_X509_REVOCATION_GOOD);
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
          if (!wrong_key) {
            /* The complete CRL is stale. The current delta supplies its
               * update interval, and a required delta outside that interval
               * leaves the scope without evidence. */
            tc_x509_freshness freshness;
            munit_assert_int(tc_x509_crl_fresh_at(
                                 &parsed, &(TC_X509_revocation_time){updated.at, 0, 0}, &freshness),
                             ==, TC_TLV_OK);
            munit_assert_int(freshness, ==, TC_X509_FRESH_STALE);
            for (unsigned boundary = 0; boundary < 2; ++boundary) {
              updated.at = boundary ? delta.next_update : parsed.this_update;
              work = TRUST_WORK_BUDGET;
              evidence = empty;
              trusted = unchanged;
              munit_assert_int(
                  cms_crl_scope_check(
                      &candidate_reader, &crl_index, 0, TC_X509_CRL_DELTA_REQUIRED, &query,
                      &(tc_x509_crl_trust){&source, 1, &updated, &tree, &validation, &search,
                                           &(TC_X509_revocation_time){(&updated)->at, 0, 0}},
                      &evidence, &trusted),
                  ==, TC_TLV_END);
              munit_assert_memory_equal(sizeof trusted, &trusted, &unchanged);
              munit_assert_memory_equal(sizeof evidence, &evidence, &empty);
            }
          }
        }
        /* Authenticate the pair under one key, then resolve its entries. */
        work = WORK_BUDGET;
        munit_assert_int(tc_x509_crl_selected_authenticate(
                             &selection.selected, &signer, &provider,
                             &(tc_x509_crl_decode){&limits, &tree, &names, NULL, 0}),
                         ==, wrong_key ? TC_TLV_INVALID : TC_TLV_OK);
        if (!wrong_key) {
          const tc_x509_crl_decode lookup = {&limits, &tree, &names, oids, EXTENSION_CAPACITY};
          selection.match = selection.saved;
          work = WORK_BUDGET;
          munit_assert_int(tc_x509_crl_selected_lookup(&selection.selected, &selection.target,
                                                       &lookup, &selection.match),
                           ==, TC_TLV_OK);
          munit_assert_int(selection.match.found, ==, revoked && reasons[i] != 8);
          munit_assert_uint(selection.match.reason, ==, selection.match.found ? reasons[i] : 0);
          const size_t required = WORK_BUDGET - work;
          const size_t short_budgets[] = {0, required / 2, required - 1};
          /* Scanning empty entry lists costs no work. */
          munit_assert_true(required || !revoked);
          for (size_t j = 0; required && j < sizeof short_budgets / sizeof short_budgets[0]; ++j) {
            work = short_budgets[j];
            selection.match = selection.saved;
            munit_assert_int(tc_x509_crl_selected_lookup(&selection.selected, &selection.target,
                                                         &lookup, &selection.match),
                             ==, TC_TLV_LIMIT);
            munit_assert_memory_equal(sizeof selection.match, &selection.match, &selection.saved);
          }
          work = required;
          munit_assert_int(tc_x509_crl_selected_lookup(&selection.selected, &selection.target,
                                                       &lookup, &selection.match),
                           ==, TC_TLV_OK);
          munit_assert_size(work, ==, 0);
          /* A delta must carry a later CRL number than its base. */
          delta_info.number = crl_info.number;
          work = WORK_BUDGET;
          munit_assert_int(tc_x509_crl_selected_authenticate(
                               &selection.selected, &signer, &provider,
                               &(tc_x509_crl_decode){&limits, &tree, &names, NULL, 0}),
                           ==, TC_TLV_INVALID);
        }
      }
      X509_CRL_free(delta_crl);
    }
  }
  return MUNIT_OK;
}

/* CRL entries, signer checks and key usage, unsupported entry extensions
 * and a changed CRL signature. */
static MunitResult entries_and_signer(const MunitParameter params[], void* user)
{
  revocation_fixture* f = user;
  uint8_t* const encoded = f->encoded;
  uint8_t* const expired_der = f->expired_der;
  TC_bytes* const oids = f->oids;
  const unsigned revoked = f->revoked;
  const TC_X509_name_workspace names = f->names;
  TC_X509_path_workspace validation = f->validation;
  TC_X509_search_workspace search = f->search;
  TC_X509_workspace parser = f->parser;
  TC_X509_certificate signer = f->signer;
  const TC_TLV_limits limits = f->limits;
  TC_X509_signature_provider provider = f->provider;
  TC_X509_public_key key = f->key;
  const TC_X509_store_source source = f->source;
  TC_X509_path_options options = f->options;
  EVP_PKEY* generated = f->generated;
  const size_t expired_length = f->expired_length;
  X509_CRL* crl = f->crl;
  TC_X509_crl parsed = f->parsed;
  size_t work = 0;
  const tc_pki_tree_workspace tree = {f->frames, FRAME_CAPACITY, &work};
  unsigned char* cursor;
  TC_TLV_reader entries;
  tc_x509_crl_entry entry;
  (void)params;
  {
    work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_entries_init(parsed.revoked, &limits, &tree, &entries), ==,
                     TC_TLV_OK);
    if (revoked) {
      munit_assert_int(tc_x509_crl_entry_next(&entries, parsed.version, &tree, &entry), ==,
                       TC_TLV_OK);
      munit_assert_size(entry.serial.length, ==, 1);
      munit_assert_uint(entry.serial.data[0], ==, 9);
    }
    munit_assert_int(tc_x509_crl_entry_next(&entries, parsed.version, &tree, &entry), ==,
                     TC_TLV_END);
    munit_assert_int(TC_X509_signature_verify_message(&parsed.tbs, 1, &parsed.signature_algorithm,
                                                      parsed.signature, &key, &provider, &work),
                     ==, TC_X509_SIGNATURE_VALID);
    work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_signer_check(&parsed, &signer, &provider, &limits, &names, &work),
                     ==, TC_X509_SIGNATURE_VALID);
    work = 0;
    munit_assert_int(tc_x509_crl_signer_check(&parsed, &signer, &provider, &limits, &names, &work),
                     ==, TC_X509_SIGNATURE_LIMIT);
    work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_signer_check(&parsed, &signer, NULL, &limits, &names, &work), ==,
                     TC_X509_SIGNATURE_UNSUPPORTED);
    {
      /* A matching name alone does not authorize CRL signing. */
      static const uint8_t digital_signature_only[] = {
          0x30, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80};
      static const uint8_t crl_sign_only[] = {0x30, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d,
                                              0x0f, 0x04, 0x04, 0x03, 0x02, 0x01, 0x02};
      TC_X509_certificate denied = signer;
      int authorized;
      denied.subject = (TC_bytes){(const uint8_t*)"\x30\x00", 2};
      munit_assert_int(
          tc_x509_crl_signer_check(&parsed, &denied, &provider, &limits, &names, &work), ==,
          TC_X509_SIGNATURE_INVALID);
      denied = signer;
      denied.extensions = (TC_bytes){digital_signature_only, sizeof digital_signature_only};
      work = WORK_BUDGET;
      munit_assert_int(tc_x509_crl_signer_usage(&denied, &limits, &work, &authorized), ==,
                       TC_TLV_OK);
      munit_assert_false(authorized);
      munit_assert_int(
          tc_x509_crl_signer_check(&parsed, &denied, &provider, &limits, &names, &work), ==,
          TC_X509_SIGNATURE_INVALID);
      denied.extensions = (TC_bytes){crl_sign_only, sizeof crl_sign_only};
      work = WORK_BUDGET;
      munit_assert_int(
          tc_x509_crl_signer_check(&parsed, &denied, &provider, &limits, &names, &work), ==,
          TC_X509_SIGNATURE_VALID);
    }
    if (revoked) {
      /* An unsupported entry is examined only after the signer path passes. */
      uint8_t entry_der[ENCODED_CAPACITY];
      X509_CRL* entry_crl = X509_CRL_dup(crl);
      ASN1_OBJECT* oid = OBJ_txt2obj("1.2.3.4", 1);
      ASN1_OCTET_STRING* value = ASN1_OCTET_STRING_new();
      static const uint8_t null_value[] = {0x05, 0x00};
      munit_assert_not_null(entry_crl);
      munit_assert_not_null(oid);
      munit_assert_not_null(value);
      munit_assert_int(ASN1_OCTET_STRING_set(value, null_value, sizeof null_value), ==, 1);
      X509_EXTENSION* extension = X509_EXTENSION_create_by_OBJ(NULL, oid, 1, value);
      munit_assert_not_null(extension);
      X509_REVOKED* item = sk_X509_REVOKED_value(X509_CRL_get_REVOKED(entry_crl), 0);
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
      TC_X509_crl entry_view;
      TC_X509_crl_extensions entry_info;
      TC_X509_certificate expired;
      work = TRUST_WORK_BUDGET;
      munit_assert_int(tc_x509_crl_read((TC_bytes){entry_der, (size_t)entry_length}, &limits, &tree,
                                        &entry_view),
                       ==, TC_TLV_OK);
      munit_assert_int(tc_x509_crl_extension_info_read(entry_view.extensions, &limits, &tree, oids,
                                                       EXTENSION_CAPACITY, &entry_info),
                       ==, TC_TLV_OK);
      munit_assert_int(
          TC_X509_read((TC_bytes){expired_der, expired_length}, &limits, &parser, &expired), ==,
          TC_TLV_OK);
      const uint8_t serial = 9;
      TC_X509_certificate target = {0};
      target.serial = (TC_bytes){&serial, 1};
      target.issuer = entry_view.issuer;
      const TC_X509_crl_record entry_record = {entry_view, entry_info, TC_TLV_OK};
      const tc_pki_distribution_point point = {0};
      const tc_x509_crl_query query = {&target, &point, 0};
      TC_X509_crl_evidence initial = {0}, evidence;
      initial.reasons = 1u << 1;
      TC_X509_search_result found, saved;
      memset(&saved, 0xa5, sizeof saved);
      enum { WRONG_ANCHOR, TRUSTED, EXPIRED, CASE_COUNT };
      for (unsigned scenario = 0; scenario < CASE_COUNT; ++scenario) {
        TC_X509_path_options checked = options;
        signature_retry_probe probe = {provider, 0, 0, TC_X509_SIGNATURE_ERROR};
        checked.signatures = (TC_X509_signature_provider){retry_signature, &probe, NULL};
        evidence = initial;
        found = saved;
        work = TRUST_WORK_BUDGET;
        munit_assert_int(
            crl_signer_scope(
                &entry_record, scenario == EXPIRED ? expired.encoded : signer.encoded, &query,
                &(tc_x509_crl_trust){&source, scenario == WRONG_ANCHOR ? 0 : 1, &checked,
                                     &(tc_pki_tree_workspace){validation.frames.data,
                                                              validation.frames.capacity, &work},
                                     &validation, &search,
                                     &(TC_X509_revocation_time){(&checked)->at, 0, 0}},
                &evidence, &found),
            ==, scenario == TRUSTED ? TC_TLV_UNSUPPORTED : TC_TLV_INVALID);
        munit_assert_size(probe.calls, ==, scenario == EXPIRED ? 1 : 2);
        munit_assert_memory_equal(sizeof evidence, &evidence, &initial);
        munit_assert_memory_equal(sizeof found, &found, &saved);
      }
      X509_CRL_free(entry_crl);
    }
    encoded[(size_t)(parsed.signature.data - encoded) + parsed.signature.length - 1] ^= 1;
    work = WORK_BUDGET;
    munit_assert_int(TC_X509_signature_verify_message(&parsed.tbs, 1, &parsed.signature_algorithm,
                                                      parsed.signature, &key, &provider, &work),
                     ==, TC_X509_SIGNATURE_INVALID);
    work = WORK_BUDGET;
    munit_assert_int(tc_x509_crl_signer_check(&parsed, &signer, &provider, &limits, &names, &work),
                     ==, TC_X509_SIGNATURE_INVALID);
  }
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  static char* outcomes[] = {"clear", "revoked", NULL};
  static char* clear[] = {"clear", NULL};
  static MunitParameterEnum outcome_params[] = {{"outcome", outcomes}, {NULL, NULL}};
  static MunitParameterEnum clear_params[] = {{"outcome", clear}, {NULL, NULL}};
  MunitTest tests[] = {{"/signer/anchor-check", signer_anchor_check, revocation_setup,
                        revocation_teardown, MUNIT_TEST_OPTION_NONE, outcome_params},
                       {"/signer/authority-match", signer_authority_match, revocation_setup,
                        revocation_teardown, MUNIT_TEST_OPTION_NONE, outcome_params},
                       {"/signer/candidates", signer_candidates, revocation_setup,
                        revocation_teardown, MUNIT_TEST_OPTION_NONE, outcome_params},
                       {"/discovery/signer-validate", discovery_signer_validate, revocation_setup,
                        revocation_teardown, MUNIT_TEST_OPTION_NONE, outcome_params},
                       {"/discovery/scope", discovery_scope, revocation_setup, revocation_teardown,
                        MUNIT_TEST_OPTION_NONE, outcome_params},
                       {"/discovery/issuer-rollover", discovery_issuer_rollover, revocation_setup,
                        revocation_teardown, MUNIT_TEST_OPTION_NONE, clear_params},
                       {"/discovery/dependencies", discovery_dependencies, revocation_setup,
                        revocation_teardown, MUNIT_TEST_OPTION_NONE, clear_params},
                       {"/discovery/partitions", discovery_partitions, revocation_setup,
                        revocation_teardown, MUNIT_TEST_OPTION_NONE, clear_params},
                       {"/selection/lookup", selection_lookup, revocation_setup,
                        revocation_teardown, MUNIT_TEST_OPTION_NONE, outcome_params},
                       {"/selection/delta", selection_delta, revocation_setup, revocation_teardown,
                        MUNIT_TEST_OPTION_NONE, outcome_params},
                       {"/entries-and-signer", entries_and_signer, revocation_setup,
                        revocation_teardown, MUNIT_TEST_OPTION_NONE, outcome_params},
                       {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/cms/revocation", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
