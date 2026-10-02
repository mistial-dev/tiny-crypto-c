/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_TEST_OCSP_FIXTURE_H_
#define TC_TEST_OCSP_FIXTURE_H_

#include <tiny_crypto/x509_ocsp.h>
#include <tiny_crypto/x509_revocation.h>
#include <tiny_crypto/x509_store.h>
#include <tiny_crypto/x509_crypto.h>
#include "munit.h"
#include <stdio.h>
#include <string.h>

enum {
  OCSP_FILE_CAPACITY = 8192,
  OCSP_FRAME_CAPACITY = 64,
  OCSP_OID_CAPACITY = 32,
  OCSP_NAME_CAPACITY = 128,
  OCSP_POLICY_CAPACITY = 16,
  OCSP_PATH_CAPACITY = 4
};

/* Scratch and native signature verification shared by the OCSP tests. The
 * provider points into the fixture, so the fixture must stay in place. The
 * path workspace also validates delegated responders and short paths. */
typedef struct {
  TC_TLV_limits limits;
  TC_TLV_frame frames[OCSP_FRAME_CAPACITY];
  TC_bytes oids[OCSP_OID_CAPACITY];
  uint32_t left[OCSP_NAME_CAPACITY], right[OCSP_NAME_CAPACITY];
  uint8_t matched[OCSP_OID_CAPACITY];
  TC_X509_policy_node nodes[OCSP_POLICY_CAPACITY];
  TC_X509_policy_edge edges[OCSP_POLICY_CAPACITY];
  TC_X509_policy_expected expected[OCSP_POLICY_CAPACITY];
  TC_X509_policy_mapping mappings[OCSP_POLICY_CAPACITY];
  TC_bytes policies[OCSP_POLICY_CAPACITY];
  TC_X509_certificate certificates[OCSP_PATH_CAPACITY];
  TC_X509_extension_summary summaries[OCSP_PATH_CAPACITY];
  TC_X509_workspace parser;
  TC_X509_path_workspace workspace;
  TC_ECDSA_workspace ec;
  TC_RSA_word words[TC_RSA_VERIFY_WORKSPACE_WORDS(4096)];
  TC_RSA_workspace rsa;
  TC_X509_native_workspace native;
  TC_X509_signature_provider signatures;
} ocsp_fixture;

static inline void ocsp_fixture_init(ocsp_fixture* fixture)
{
  fixture->limits =
      (TC_TLV_limits){OCSP_FILE_CAPACITY, OCSP_FILE_CAPACITY, 512, OCSP_FRAME_CAPACITY};
  fixture->parser =
      (TC_X509_workspace){{fixture->frames, OCSP_FRAME_CAPACITY}, fixture->oids, OCSP_OID_CAPACITY};
  fixture->workspace = (TC_X509_path_workspace)TC_X509_PATH_WORKSPACE_INIT(
      fixture->frames, fixture->oids, fixture->left, fixture->right, fixture->matched,
      fixture->nodes, fixture->edges, fixture->expected, fixture->mappings, fixture->policies,
      fixture->certificates, fixture->summaries);
  fixture->rsa = (TC_RSA_workspace){fixture->words, sizeof fixture->words / sizeof *fixture->words};
  fixture->native = (TC_X509_native_workspace){&fixture->ec, &fixture->rsa,
                                               TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  fixture->signatures = TC_X509_native_provider(&fixture->native);
}

static inline TC_bytes ocsp_read_path(const char* path, uint8_t bytes[OCSP_FILE_CAPACITY])
{
  FILE* file = fopen(path, "rb");
  munit_assert_not_null(file);
  size_t length = fread(bytes, 1, OCSP_FILE_CAPACITY, file);
  munit_assert_false(ferror(file));
  munit_assert_true(feof(file));
  munit_assert_int(fclose(file), ==, 0);
  munit_assert_size(length, >, 0);
  return (TC_bytes){bytes, length};
}

/* Read a trusted issuer certificate into an anchor that borrows bytes. */
static inline TC_X509_trust_anchor ocsp_read_anchor(ocsp_fixture* fixture, const char* path,
                                                    uint8_t bytes[OCSP_FILE_CAPACITY])
{
  const TC_bytes encoded = ocsp_read_path(path, bytes);
  TC_X509_certificate issuer;
  munit_assert_int(TC_X509_read(encoded, &fixture->limits, &fixture->parser, &issuer), ==,
                   TC_TLV_OK);
  return (TC_X509_trust_anchor){issuer.subject, issuer.public_key};
}

/* A request with the freshness and count limits used by the captured cases. */
static inline TC_X509_ocsp_verify_request ocsp_request(const ocsp_fixture* fixture,
                                                       TC_bytes response, TC_bytes certificate,
                                                       const TC_X509_trust_anchor* issuer,
                                                       TC_X509_time at)
{
  TC_X509_ocsp_verify_request request = {0};
  request.response = response;
  request.certificate = certificate;
  request.issuer = issuer;
  request.time = (TC_X509_revocation_time){at, 300, 172800};
  request.max_responses = 16;
  request.max_certificates = 4;
  request.parsing = &fixture->limits;
  request.signatures = &fixture->signatures;
  return request;
}

/* Failures after the argument checks zero the result. */
static inline void ocsp_assert_wiped(const TC_X509_ocsp_report* result)
{
  TC_X509_ocsp_report zero;
  memset(&zero, 0, sizeof zero);
  munit_assert_memory_equal(sizeof *result, result, &zero);
}

/* Entry argument errors leave a result filled with 0x5a unchanged. The
 * check reads bytes, so padding needs no struct copy. */
static inline void ocsp_assert_untouched(const TC_X509_ocsp_report* result)
{
  const uint8_t* bytes = (const uint8_t*)result;
  for (size_t i = 0; i < sizeof *result; ++i)
    munit_assert_uint8(bytes[i], ==, 0x5a);
}

static inline int ocsp_span_within(TC_bytes inner, TC_bytes outer)
{
  return inner.data && inner.length && inner.data >= outer.data && inner.length <= outer.length &&
         (size_t)(inner.data - outer.data) <= outer.length - inner.length;
}

enum { OCSP_CRL_CAPACITY = 2, OCSP_REVOCATION_NODES = 8 };

/* Storage for TC_X509_path_check_revocation. The anchor comes from one
 * certificate. CRL signers and OCSP delegates are found among the
 * candidates. The spans borrow caller bytes that stay unchanged. */
typedef struct {
  TC_bytes crls[OCSP_CRL_CAPACITY];
  TC_X509_crl_record records[OCSP_CRL_CAPACITY];
  TC_X509_crl_index index;
  TC_X509_store_anchor anchor;
  TC_bytes candidates[OCSP_PATH_CAPACITY];
  TC_X509_store_array array;
  TC_X509_store_source source;
  TC_X509_path_options signer;
  TC_bytes search_path[OCSP_PATH_CAPACITY];
  TC_X509_search_frame search_frames[OCSP_PATH_CAPACITY];
  TC_X509_search_workspace search;
  uint8_t states[OCSP_CRL_CAPACITY];
  TC_X509_revocation_node nodes[OCSP_REVOCATION_NODES];
  TC_X509_revocation_scope scopes[OCSP_CRL_CAPACITY];
  TC_bytes signer_path[OCSP_PATH_CAPACITY];
  TC_bytes signer_policies[OCSP_POLICY_CAPACITY];
  TC_X509_revocation_workspace workspace;
} ocsp_revocation;

/* Index crls, publish the anchor and candidates and set a CRL signer policy
 * at the evaluation time. fixture must already be initialized. */
static inline void ocsp_revocation_init(ocsp_revocation* revocation, ocsp_fixture* fixture,
                                        TC_bytes anchor, const TC_bytes* candidates,
                                        size_t candidate_count, const TC_bytes* crls,
                                        size_t crl_count, TC_X509_time at)
{
  munit_assert_size(candidate_count, <=, OCSP_PATH_CAPACITY);
  munit_assert_size(crl_count, <=, OCSP_CRL_CAPACITY);
  memset(revocation, 0, sizeof *revocation);
  TC_X509_certificate anchor_view;
  munit_assert_int(TC_X509_read(anchor, &fixture->limits, &fixture->parser, &anchor_view), ==,
                   TC_TLV_OK);
  munit_assert_int(TC_X509_store_anchor_from_certificate(&anchor_view, &fixture->limits,
                                                         &fixture->parser, &revocation->anchor),
                   ==, TC_TLV_OK);
  for (size_t i = 0; i < crl_count; ++i)
    revocation->crls[i] = crls[i];
  size_t work = 20000000;
  munit_assert_int(TC_X509_crl_index_init(revocation->crls, crl_count, &fixture->limits,
                                          &fixture->parser, &work, revocation->records,
                                          OCSP_CRL_CAPACITY, &revocation->index),
                   ==, TC_TLV_OK);
  for (size_t i = 0; i < candidate_count; ++i)
    revocation->candidates[i] = candidates[i];
  revocation->array =
      (TC_X509_store_array){revocation->candidates, candidate_count, &revocation->anchor, 1};
  munit_assert_int(TC_X509_store_array_source(&revocation->array, &revocation->source), ==,
                   TC_TLV_OK);
  revocation->signer.at = at;
  revocation->signer.parsing = fixture->limits;
  revocation->signer.max_certificates = OCSP_PATH_CAPACITY;
  revocation->signer.max_input = OCSP_PATH_CAPACITY * OCSP_FILE_CAPACITY;
  revocation->signer.max_work = 20000000;
  revocation->signer.signatures = fixture->signatures;
  revocation->search = (TC_X509_search_workspace){revocation->search_path,
                                                  revocation->search_frames, OCSP_PATH_CAPACITY};
  revocation->workspace = (TC_X509_revocation_workspace){
      &fixture->workspace, &revocation->search,         revocation->states,
      OCSP_CRL_CAPACITY,   revocation->nodes,           OCSP_REVOCATION_NODES,
      revocation->scopes,  OCSP_CRL_CAPACITY,           revocation->signer_path,
      OCSP_PATH_CAPACITY,  revocation->signer_policies, OCSP_POLICY_CAPACITY};
}

/* Complete CRLs in thisUpdate order, 300 s of skew and one OCSP span per
 * path member. responses may be NULL for CRLs only. */
static inline TC_X509_revocation_options ocsp_revocation_options(const ocsp_revocation* revocation,
                                                                 TC_X509_time at,
                                                                 const TC_bytes* responses,
                                                                 size_t count)
{
  const TC_X509_revocation_options options = {&revocation->index,
                                              &revocation->source,
                                              &revocation->signer,
                                              0,
                                              4 * OCSP_FILE_CAPACITY,
                                              TC_X509_CRL_COMPLETE_ONLY,
                                              TC_X509_CRL_ORDER_THIS_UPDATE,
                                              {at, 300, 0},
                                              {responses, responses ? count : 0, 16, 4}};
  return options;
}

#endif
