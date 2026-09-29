/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "ocsp_fixture.h"
#include <tiny_crypto/x509_revocation.h>

/* TC_X509_time has padding, so compare its fields. */
static void assert_time_equal(const TC_X509_time* actual, const TC_X509_time* expected)
{
  munit_assert_uint(actual->year, ==, expected->year);
  munit_assert_uint(actual->month, ==, expected->month);
  munit_assert_uint(actual->day, ==, expected->day);
  munit_assert_uint(actual->hour, ==, expected->hour);
  munit_assert_uint(actual->minute, ==, expected->minute);
  munit_assert_uint(actual->second, ==, expected->second);
}

static const TC_X509_time content_signer_at = {2026, 9, 28, 9, 0, 0};
static const TC_X509_time card_at = {2026, 9, 29, 10, 0, 0};

static ocsp_fixture fixture;
static uint8_t issuer_bytes[OCSP_FILE_CAPACITY], response_bytes[OCSP_FILE_CAPACITY];
static uint8_t certificate_bytes[OCSP_FILE_CAPACITY], signer_bytes[OCSP_FILE_CAPACITY];

static TC_X509_trust_anchor read_issuer(void)
{
  return ocsp_read_anchor(&fixture, TC_ICAM_OCSP_ROOT "/issuer.der", issuer_bytes);
}

/* The embedded OCSP Valid Signer gen3 signs every content signer response.
 * An authenticated unknown status gives no decision and is UNSUPPORTED, as
 * is an unsigned tryLater response (RFC 6960 4.2.1). */
static MunitResult content_signer(const MunitParameter params[], void* user)
{
  const char* suffixes[] = {"good", "revoked", "unknown"};
  (void)params;
  (void)user;
  ocsp_fixture_init(&fixture);
  const TC_X509_trust_anchor anchor = read_issuer();
  const TC_bytes certificate = ocsp_read_path(TC_ICAM_OCSP_ROOT "/target.der", certificate_bytes);
  for (size_t i = 0; i < 3; ++i) {
    char path[512];
    munit_assert_int(
        snprintf(path, sizeof path, "%s/content_signer_%s.der", TC_ICAM_OCSP_ROOT, suffixes[i]), >,
        0);
    TC_bytes response = ocsp_read_path(path, response_bytes);
    TC_X509_ocsp_verify_request request =
        ocsp_request(&fixture, response, certificate, &anchor, content_signer_at);
    size_t work = 20000000;
    TC_X509_ocsp_result result;
    memset(&result, 0x5a, sizeof result);
    if (i == 2) {
      munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result),
                       ==, TC_TLV_UNSUPPORTED);
      ocsp_assert_wiped(&result);
      continue;
    }
    munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result), ==,
                     TC_TLV_OK);
    munit_assert_int(result.status, ==,
                     i == 1 ? TC_X509_REVOCATION_REVOKED : TC_X509_REVOCATION_GOOD);
    /* The OpenSSL index recorded no reason for the revoked serial. */
    munit_assert_false(result.has_reason);
    if (i == 1) {
      const TC_X509_time revoked = {2024, 1, 1, 0, 0, 0};
      assert_time_equal(&result.revocation_time, &revoked);
    }
    /* The embedded OCSP Valid Signer gen3 has no id-pkix-ocsp-nocheck. */
    munit_assert_true(ocsp_span_within(result.responder_certificate, response));
    munit_assert_false(result.responder_nocheck);
    if (i == 0) {
      response_bytes[response.length - 1] ^= 1;
      work = 20000000;
      munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result),
                       ==, TC_TLV_INVALID);
      ocsp_assert_wiped(&result);
      response_bytes[response.length - 1] ^= 1;
      const uint8_t unavailable[] = {0x30, 0x03, 0x0a, 0x01, 0x03};
      request.response = (TC_bytes){unavailable, sizeof unavailable};
      work = 20000000;
      memset(&result, 0x5a, sizeof result);
      munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result),
                       ==, TC_TLV_UNSUPPORTED);
      ocsp_assert_wiped(&result);
    }
  }
  return MUNIT_OK;
}

static TC_X509_ocsp_result verify_card(unsigned card, const char* response_name,
                                       const TC_X509_trust_anchor* anchor,
                                       const TC_X509_store_source* store, TC_TLV_result expected)
{
  char path[512];
  munit_assert_int(
      snprintf(path, sizeof path, "%s/card%u_piv_auth_cert.der", TC_ICAM_OCSP_ROOT, card), >, 0);
  const TC_bytes certificate = ocsp_read_path(path, certificate_bytes);
  munit_assert_int(snprintf(path, sizeof path, "%s/%s.der", TC_ICAM_OCSP_ROOT, response_name), >,
                   0);
  const TC_bytes response = ocsp_read_path(path, response_bytes);
  TC_X509_ocsp_verify_request request =
      ocsp_request(&fixture, response, certificate, anchor, card_at);
  request.certificates = store;
  size_t work = 20000000;
  TC_X509_ocsp_result result;
  memset(&result, 0x5a, sizeof result);
  munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result), ==,
                   expected);
  if (expected != TC_TLV_OK) {
    ocsp_assert_wiped(&result);
    return result;
  }
  munit_assert_int(result.status, ==, TC_X509_REVOCATION_GOOD);
  return result;
}

/* RFC 6960 4.2.2.2.1: a delegate's own revocation status is established by
 * id-pkix-ocsp-nocheck or by separate evidence. ICAM cards 43 and 44 carry
 * the two delegate forms. The result reports which one signed. */
static MunitResult delegate_nocheck(const MunitParameter params[], void* user)
{
  (void)params;
  (void)user;
  ocsp_fixture_init(&fixture);
  const TC_X509_trust_anchor anchor = read_issuer();

  TC_X509_ocsp_result result = verify_card(43, "card43_delegate_nocheck", &anchor, NULL, TC_TLV_OK);
  munit_assert_true(ocsp_span_within(result.responder_certificate,
                                     (TC_bytes){response_bytes, sizeof response_bytes}));
  munit_assert_true(result.responder_nocheck);

  result = verify_card(44, "card44_delegate", &anchor, NULL, TC_TLV_OK);
  munit_assert_true(ocsp_span_within(result.responder_certificate,
                                     (TC_bytes){response_bytes, sizeof response_bytes}));
  munit_assert_false(result.responder_nocheck);
  /* The reported span is the complete delegate certificate. */
  TC_X509_certificate delegate;
  munit_assert_int(TC_X509_read(result.responder_certificate.data,
                                result.responder_certificate.length, &fixture.limits,
                                &fixture.parser, &delegate),
                   ==, TC_TLV_OK);
  munit_assert_size(delegate.encoded.length, ==, result.responder_certificate.length);
  return MUNIT_OK;
}

/* A delegate supplied through the store is reported from the store record.
 * max_certificates counts every delegate candidate, and zero examines none. */
static MunitResult store_delegate(const MunitParameter params[], void* user)
{
  (void)params;
  (void)user;
  ocsp_fixture_init(&fixture);
  const TC_X509_trust_anchor anchor = read_issuer();
  const TC_bytes signer =
      ocsp_read_path(TC_ICAM_OCSP_ROOT "/card44_delegate_signer.der", signer_bytes);
  const TC_X509_store_array array = {&signer, 1, NULL, 0};
  TC_X509_store_source store;
  munit_assert_int(TC_X509_store_array_source(&array, &store), ==, TC_TLV_OK);

  TC_X509_ocsp_result result =
      verify_card(44, "card44_delegate_no_certs", &anchor, &store, TC_TLV_OK);
  munit_assert_ptr_equal(result.responder_certificate.data, signer.data);
  munit_assert_size(result.responder_certificate.length, ==, signer.length);
  munit_assert_false(result.responder_nocheck);
  verify_card(44, "card44_delegate_no_certs", &anchor, NULL, TC_TLV_INVALID);

  char path[512];
  munit_assert_int(snprintf(path, sizeof path, "%s/card44_piv_auth_cert.der", TC_ICAM_OCSP_ROOT), >,
                   0);
  const TC_bytes certificate = ocsp_read_path(path, certificate_bytes);
  const TC_bytes response =
      ocsp_read_path(TC_ICAM_OCSP_ROOT "/card44_delegate_no_certs.der", response_bytes);
  TC_X509_ocsp_verify_request request =
      ocsp_request(&fixture, response, certificate, &anchor, card_at);
  request.certificates = &store;
  request.max_certificates = 0;
  size_t work = 20000000;
  munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result), ==,
                   TC_TLV_LIMIT);
  ocsp_assert_wiped(&result);
  return MUNIT_OK;
}

static TC_TLV_result failing_candidate(void* context, size_t index, size_t* work, TC_bytes* out)
{
  (void)context;
  (void)index;
  (void)work;
  (void)out;
  return TC_TLV_INVALID;
}

/* Run one card 44 store-delegate verification that must fail with ARGUMENT.
 * An entry failure (expected_work nonzero) leaves work and out unchanged. A
 * later store failure zeroes out. */
static void verify_argument(const TC_X509_trust_anchor* anchor, const TC_X509_store_source* store,
                            size_t expected_work)
{
  const TC_bytes certificate =
      ocsp_read_path(TC_ICAM_OCSP_ROOT "/card44_piv_auth_cert.der", certificate_bytes);
  const TC_bytes response =
      ocsp_read_path(TC_ICAM_OCSP_ROOT "/card44_delegate_no_certs.der", response_bytes);
  TC_X509_ocsp_verify_request request =
      ocsp_request(&fixture, response, certificate, anchor, card_at);
  request.certificates = store;
  size_t work = 20000000;
  TC_X509_ocsp_result result;
  memset(&result, 0x5a, sizeof result);
  const TC_X509_ocsp_result saved = result;
  munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result), ==,
                   TC_TLV_ARGUMENT);
  if (expected_work) {
    munit_assert_memory_equal(sizeof result, &result, &saved);
    munit_assert_size(work, ==, expected_work);
  } else
    ocsp_assert_wiped(&result);
}

/* An incomplete issuer or store is an argument error found at entry. A store
 * callback failure other than LIMIT or UNSUPPORTED is ARGUMENT, as the store
 * contract requires. */
static MunitResult source_arguments(const MunitParameter params[], void* user)
{
  (void)params;
  (void)user;
  ocsp_fixture_init(&fixture);
  const TC_X509_trust_anchor anchor = read_issuer();
  TC_X509_trust_anchor incomplete = anchor;
  incomplete.name = (TC_bytes){NULL, 0};
  verify_argument(&incomplete, NULL, 20000000);
  incomplete = anchor;
  incomplete.public_key.key = (TC_bytes){NULL, 0};
  verify_argument(&incomplete, NULL, 20000000);

  TC_X509_store_source store = {NULL, 1, 0, NULL, NULL};
  verify_argument(&anchor, &store, 20000000);
  store.candidate = failing_candidate;
  verify_argument(&anchor, &store, 0);
  return MUNIT_OK;
}

/* A response signed by the issuer needs no certificates, so max_certificates
 * may be zero. The byKey ResponderID is the SHA-1 key hash (RFC 6960 4.2.1). */
static MunitResult issuer_signed(const MunitParameter params[], void* user)
{
  (void)params;
  (void)user;
  ocsp_fixture_init(&fixture);
  const TC_X509_trust_anchor anchor = read_issuer();
  char path[512];
  munit_assert_int(snprintf(path, sizeof path, "%s/card43_piv_auth_cert.der", TC_ICAM_OCSP_ROOT), >,
                   0);
  const TC_bytes certificate = ocsp_read_path(path, certificate_bytes);
  const TC_bytes response =
      ocsp_read_path(TC_ICAM_OCSP_ROOT "/card43_issuer_by_key.der", response_bytes);
  TC_X509_ocsp_verify_request request =
      ocsp_request(&fixture, response, certificate, &anchor, card_at);
  request.max_certificates = 0;
  size_t work = 20000000;
  TC_X509_ocsp_result result;
  memset(&result, 0x5a, sizeof result);
  munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result), ==,
                   TC_TLV_OK);
  munit_assert_int(result.status, ==, TC_X509_REVOCATION_GOOD);
  munit_assert_null(result.responder_certificate.data);
  munit_assert_size(result.responder_certificate.length, ==, 0);
  munit_assert_false(result.responder_nocheck);
  return MUNIT_OK;
}

/* The BasicOCSPResponse sits inside an OCTET STRING, so the outer walk does
 * not reach it. Its elements and nesting must still respect the caller limits.
 * The response is 127 elements deep 8 levels, while the target and delegate
 * certificates need at most 82 elements and 5 levels. */
static MunitResult bounded_inner_response(const MunitParameter params[], void* user)
{
  (void)params;
  (void)user;
  ocsp_fixture_init(&fixture);
  const TC_X509_trust_anchor anchor = read_issuer();
  const TC_bytes certificate = ocsp_read_path(TC_ICAM_OCSP_ROOT "/target.der", certificate_bytes);
  const TC_bytes response =
      ocsp_read_path(TC_ICAM_OCSP_ROOT "/content_signer_good.der", response_bytes);
  const TC_TLV_limits few_elements = {OCSP_FILE_CAPACITY, OCSP_FILE_CAPACITY, 100,
                                      OCSP_FRAME_CAPACITY};
  const TC_TLV_limits shallow = {OCSP_FILE_CAPACITY, OCSP_FILE_CAPACITY, 512, 7};
  const TC_TLV_limits* limits[] = {&few_elements, &shallow};
  for (size_t i = 0; i < 2; ++i) {
    TC_X509_ocsp_verify_request request =
        ocsp_request(&fixture, response, certificate, &anchor, content_signer_at);
    request.parsing = limits[i];
    size_t work = 20000000;
    TC_X509_ocsp_result result;
    memset(&result, 0x5a, sizeof result);
    munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result), ==,
                     TC_TLV_LIMIT);
    ocsp_assert_wiped(&result);
  }
  return MUNIT_OK;
}

#define TC_LOCAL_OCSP_ROOT TC_ICAM_OCSP_ROOT "/../local"
#define TC_ICAM_CA_ROOT TC_ICAM_OCSP_ROOT "/../../icam/ca"
#define TC_ICAM_GEN3_CRL TC_ICAM_CA_ROOT "/crls/ICAMTestCardGen3SigningCA.crl"
#define TC_ICAM_ROOT_CRL TC_ICAM_CA_ROOT "/crls/ICAMTestCardRootCA.crl"
#define TC_ICAM_ROOT_CA TC_ICAM_OCSP_ROOT "/root.der"

static const TC_X509_time local_at = {2026, 9, 30, 0, 0, 0};

/* CA-signed local responses: the revocationReason is reported (RFC 6960
 * 4.2.1). A response without nextUpdate needs a nonzero max_age_seconds. */
static MunitResult local_responses(const MunitParameter params[], void* user)
{
  (void)params;
  (void)user;
  ocsp_fixture_init(&fixture);
  const TC_X509_trust_anchor anchor =
      ocsp_read_anchor(&fixture, TC_LOCAL_OCSP_ROOT "/ca.der", issuer_bytes);
  const TC_bytes certificate = ocsp_read_path(TC_LOCAL_OCSP_ROOT "/target.der", certificate_bytes);
  TC_bytes response =
      ocsp_read_path(TC_LOCAL_OCSP_ROOT "/revoked_key_compromise.der", response_bytes);
  TC_X509_ocsp_verify_request request =
      ocsp_request(&fixture, response, certificate, &anchor, local_at);
  request.max_certificates = 0;
  size_t work = 20000000;
  TC_X509_ocsp_result result;
  memset(&result, 0x5a, sizeof result);
  munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result), ==,
                   TC_TLV_OK);
  munit_assert_int(result.status, ==, TC_X509_REVOCATION_REVOKED);
  munit_assert_true(result.has_reason);
  munit_assert_uint(result.reason, ==, 1);
  const TC_X509_time revoked = {2026, 9, 1, 0, 0, 0};
  assert_time_equal(&result.revocation_time, &revoked);
  munit_assert_null(result.responder_certificate.data);

  response = ocsp_read_path(TC_LOCAL_OCSP_ROOT "/good_no_next_update.der", response_bytes);
  request.response = response;
  work = 20000000;
  munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result), ==,
                   TC_TLV_OK);
  munit_assert_int(result.status, ==, TC_X509_REVOCATION_GOOD);
  munit_assert_false(result.has_next_update);
  munit_assert_false(result.has_reason);
  /* thisUpdate is 2026-09-29 10:13:36, 49284 s before local_at - 300 s. */
  request.time.max_age_seconds = 49284;
  work = 20000000;
  munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result), ==,
                   TC_TLV_OK);
  request.time.max_age_seconds = 49283;
  work = 20000000;
  munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result), ==,
                   TC_TLV_INVALID);
  ocsp_assert_wiped(&result);
  request.time.max_age_seconds = 0;
  work = 20000000;
  memset(&result, 0x5a, sizeof result);
  munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result), ==,
                   TC_TLV_INVALID);
  ocsp_assert_wiped(&result);
  /* Clock skew applies to thisUpdate and producedAt on the early side. */
  request.time = (TC_X509_revocation_time){{2026, 9, 29, 10, 13, 30}, 5, 3600};
  work = 20000000;
  munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result), ==,
                   TC_TLV_INVALID);
  request.time.clock_skew_seconds = 6;
  work = 20000000;
  munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result), ==,
                   TC_TLV_OK);
  return MUNIT_OK;
}

/* Storage for TC_X509_path_check_revocation over the ICAM path Root CA ->
 * Signing CA (issuer.der) -> member. The Root CA is the anchor. CRL signers
 * are found among the candidates, so both CA certificates are candidates. */
typedef struct {
  uint8_t root_bytes[OCSP_FILE_CAPACITY];
  uint8_t crl_bytes[2][OCSP_FILE_CAPACITY];
  TC_bytes crls[2];
  TC_X509_crl_record records[2];
  TC_X509_crl_index index;
  TC_X509_store_anchor anchor;
  TC_bytes candidates[2];
  TC_X509_store_array array;
  TC_X509_store_source source;
  TC_X509_path_options signer;
  TC_bytes search_path[OCSP_PATH_CAPACITY];
  TC_X509_search_frame search_frames[OCSP_PATH_CAPACITY];
  TC_X509_search_workspace search;
  uint8_t states[2];
  TC_X509_revocation_node nodes[8];
  TC_X509_revocation_scope scopes[2];
  TC_bytes signer_path[OCSP_PATH_CAPACITY];
  TC_bytes signer_policies[OCSP_POLICY_CAPACITY];
  TC_X509_revocation_workspace workspace;
} revocation_fixture;

static revocation_fixture revocation;

/* The Root CA CRL is always indexed. with_crl adds the Signing CA's Gen3
 * CRL, which is signed by issuer.der, lists no revoked certificates and has
 * no CRL number. Neither CRL lists a certificate. */
static void revocation_init(int with_crl, TC_X509_time at)
{
  ocsp_fixture_init(&fixture);
  memset(&revocation, 0, sizeof revocation);
  const TC_bytes root = ocsp_read_path(TC_ICAM_ROOT_CA, revocation.root_bytes);
  const TC_bytes issuer = ocsp_read_path(TC_ICAM_OCSP_ROOT "/issuer.der", issuer_bytes);
  TC_X509_certificate root_view;
  munit_assert_int(
      TC_X509_read(root.data, root.length, &fixture.limits, &fixture.parser, &root_view), ==,
      TC_TLV_OK);
  munit_assert_int(TC_X509_store_anchor_from_certificate(&root_view, &fixture.limits,
                                                         &fixture.parser, &revocation.anchor),
                   ==, TC_TLV_OK);
  revocation.crls[0] = ocsp_read_path(TC_ICAM_ROOT_CRL, revocation.crl_bytes[0]);
  if (with_crl)
    revocation.crls[1] = ocsp_read_path(TC_ICAM_GEN3_CRL, revocation.crl_bytes[1]);
  size_t work = 20000000;
  munit_assert_int(TC_X509_crl_index_init(revocation.crls, with_crl ? 2 : 1, &fixture.limits,
                                          &fixture.parser, &work, revocation.records, 2,
                                          &revocation.index),
                   ==, TC_TLV_OK);
  revocation.candidates[0] = root;
  revocation.candidates[1] = issuer;
  revocation.array = (TC_X509_store_array){revocation.candidates, 2, &revocation.anchor, 1};
  munit_assert_int(TC_X509_store_array_source(&revocation.array, &revocation.source), ==,
                   TC_TLV_OK);
  revocation.signer.at = at;
  revocation.signer.parsing = fixture.limits;
  revocation.signer.max_certificates = OCSP_PATH_CAPACITY;
  revocation.signer.max_input = OCSP_PATH_CAPACITY * OCSP_FILE_CAPACITY;
  revocation.signer.max_work = 20000000;
  revocation.signer.signatures = fixture.signatures;
  revocation.search = (TC_X509_search_workspace){revocation.search_path, revocation.search_frames,
                                                 OCSP_PATH_CAPACITY};
  revocation.workspace =
      (TC_X509_revocation_workspace){&fixture.workspace,         &revocation.search,
                                     revocation.states,          2,
                                     revocation.nodes,           8,
                                     revocation.scopes,          2,
                                     revocation.signer_path,     OCSP_PATH_CAPACITY,
                                     revocation.signer_policies, OCSP_POLICY_CAPACITY};
}

static TC_X509_revocation_options revocation_options(TC_X509_time at, const TC_bytes* responses)
{
  const TC_X509_revocation_options options = {&revocation.index,
                                              &revocation.source,
                                              &revocation.signer,
                                              0,
                                              4 * OCSP_FILE_CAPACITY,
                                              TC_X509_CRL_COMPLETE_ONLY,
                                              TC_X509_CRL_ORDER_THIS_UPDATE,
                                              {at, 300, 0},
                                              {responses, responses ? 2 : 0, 16, 4}};
  return options;
}

/* Check the path Signing CA -> member. responses[0] is empty, so the
 * Signing CA always uses the Root CA CRL. */
static TC_TLV_result check_member(const char* certificate_name, const char* response_name,
                                  int with_crl, TC_X509_time at, TC_X509_revocation_result* out)
{
  char path[512];
  revocation_init(with_crl, at);
  munit_assert_int(snprintf(path, sizeof path, "%s/%s.der", TC_ICAM_OCSP_ROOT, certificate_name), >,
                   0);
  const TC_bytes chain[] = {revocation.candidates[1], ocsp_read_path(path, certificate_bytes)};
  TC_bytes responses[2] = {{NULL, 0}, {NULL, 0}};
  if (response_name) {
    munit_assert_int(snprintf(path, sizeof path, "%s/%s.der", TC_ICAM_OCSP_ROOT, response_name), >,
                     0);
    responses[1] = ocsp_read_path(path, response_bytes);
  }
  const TC_X509_revocation_options options =
      revocation_options(at, response_name ? responses : NULL);
  size_t work = 20000000;
  memset(out, 0xa5, sizeof *out);
  return TC_X509_path_check_revocation(chain, 2, &options, &revocation.workspace, &work, out);
}

static void assert_unchanged(const TC_X509_revocation_result* result)
{
  TC_X509_revocation_result sentinel;
  memset(&sentinel, 0xa5, sizeof sentinel);
  munit_assert_memory_equal(sizeof *result, result, &sentinel);
}

/* TC_X509_path_check_revocation uses a member's OCSP response first. A
 * delegate without id-pkix-ocsp-nocheck counts only when the CRL index shows
 * it unrevoked (RFC 6960 4.2.2.2.1). Other outcomes fall back to CRLs. */
static MunitResult path_ocsp(const MunitParameter params[], void* user)
{
  TC_X509_revocation_result result;
  (void)params;
  (void)user;
  /* Card 43's delegate carries nocheck, so OCSP alone decides. */
  munit_assert_int(
      check_member("card43_piv_auth_cert", "card43_delegate_nocheck", 0, card_at, &result), ==,
      TC_TLV_OK);
  munit_assert_int(result.status, ==, TC_X509_REVOCATION_GOOD);
  munit_assert_size(result.certificate_index, ==, SIZE_MAX);
  /* Card 44's delegate lacks nocheck. Without CRL evidence the check fails
   * closed, and the CRL for the card itself is missing too. */
  munit_assert_int(check_member("card44_piv_auth_cert", "card44_delegate", 0, card_at, &result), ==,
                   TC_TLV_UNSUPPORTED);
  assert_unchanged(&result);
  munit_assert_int(check_member("card44_piv_auth_cert", "card44_delegate", 1, card_at, &result), ==,
                   TC_TLV_OK);
  munit_assert_int(result.status, ==, TC_X509_REVOCATION_GOOD);

  /* The CRL lists nothing, so REVOKED can only come from the OCSP response,
   * accepted after the CRL showed its delegate unrevoked. */
  munit_assert_int(check_member("target", "content_signer_revoked", 1, content_signer_at, &result),
                   ==, TC_TLV_OK);
  munit_assert_int(result.status, ==, TC_X509_REVOCATION_REVOKED);
  munit_assert_size(result.certificate_index, ==, 1);
  munit_assert_true(result.evidence.revocation.found);
  munit_assert_uint(result.evidence.revocation.reason, ==, 0);
  munit_assert_uint(result.evidence.revocation.revoked_at.year, ==, 2024);
  munit_assert_int(check_member("target", "content_signer_revoked", 0, content_signer_at, &result),
                   ==, TC_TLV_UNSUPPORTED);
  assert_unchanged(&result);

  /* An authenticated unknown status and a stale response fall back to CRLs. */
  munit_assert_int(check_member("target", "content_signer_unknown", 1, content_signer_at, &result),
                   ==, TC_TLV_OK);
  munit_assert_int(result.status, ==, TC_X509_REVOCATION_GOOD);
  munit_assert_int(check_member("target", "content_signer_unknown", 0, content_signer_at, &result),
                   ==, TC_TLV_UNSUPPORTED);
  const TC_X509_time later = {2026, 10, 5, 0, 0, 0};
  munit_assert_int(check_member("target", "content_signer_revoked", 1, later, &result), ==,
                   TC_TLV_OK);
  munit_assert_int(result.status, ==, TC_X509_REVOCATION_GOOD);
  return MUNIT_OK;
}

/* The OCSP evidence runs under the caller's limits and argument rules. */
static MunitResult path_ocsp_arguments(const MunitParameter params[], void* user)
{
  (void)params;
  (void)user;
  revocation_init(1, card_at);
  const TC_bytes chain[] = {
      revocation.candidates[1],
      ocsp_read_path(TC_ICAM_OCSP_ROOT "/card44_piv_auth_cert.der", certificate_bytes)};
  const TC_bytes responses[] = {
      {NULL, 0}, ocsp_read_path(TC_ICAM_OCSP_ROOT "/card44_delegate.der", response_bytes)};
  TC_X509_revocation_options options = revocation_options(card_at, responses);
  TC_X509_revocation_result result;
  size_t work = 20000000;
  memset(&result, 0xa5, sizeof result);

  options.ocsp.count = 1;
  munit_assert_int(
      TC_X509_path_check_revocation(chain, 2, &options, &revocation.workspace, &work, &result), ==,
      TC_TLV_ARGUMENT);
  options.ocsp.count = 2;
  options.ocsp.max_responses = 0;
  munit_assert_int(
      TC_X509_path_check_revocation(chain, 2, &options, &revocation.workspace, &work, &result), ==,
      TC_TLV_ARGUMENT);
  options.ocsp.max_responses = 16;
  options.time.at.month = 13;
  munit_assert_int(
      TC_X509_path_check_revocation(chain, 2, &options, &revocation.workspace, &work, &result), ==,
      TC_TLV_ARGUMENT);
  options.time.at = card_at;
  /* CRL signer paths and freshness must use one evaluation time. */
  revocation.signer.at.second = 1;
  munit_assert_int(
      TC_X509_path_check_revocation(chain, 2, &options, &revocation.workspace, &work, &result), ==,
      TC_TLV_ARGUMENT);
  revocation.signer.at = card_at;
  munit_assert_size(work, ==, 20000000);
  assert_unchanged(&result);
  /* A response inside validation scratch is rejected before use. */
  const TC_bytes inside[] = {{NULL, 0}, {(const uint8_t*)fixture.frames, 16}};
  options.ocsp.responses = inside;
  munit_assert_int(
      TC_X509_path_check_revocation(chain, 2, &options, &revocation.workspace, &work, &result), ==,
      TC_TLV_ARGUMENT);
  assert_unchanged(&result);
  options.ocsp.responses = responses;

  /* Every work budget below the full cost is LIMIT, never a decision. */
  munit_assert_int(
      TC_X509_path_check_revocation(chain, 2, &options, &revocation.workspace, &work, &result), ==,
      TC_TLV_OK);
  const size_t required = 20000000 - work;
  for (size_t budget = required - 64; budget < required; ++budget) {
    work = budget;
    memset(&result, 0xa5, sizeof result);
    munit_assert_int(
        TC_X509_path_check_revocation(chain, 2, &options, &revocation.workspace, &work, &result),
        ==, TC_TLV_LIMIT);
    assert_unchanged(&result);
  }
  work = 0;
  munit_assert_int(
      TC_X509_path_check_revocation(chain, 2, &options, &revocation.workspace, &work, &result), ==,
      TC_TLV_LIMIT);
  return MUNIT_OK;
}

/* CRL freshness applies the revocation clock skew and max_age. The Gen3 CRL
 * has thisUpdate 2020-04-07 21:50:52, the Root CA CRL 2018-05-27 00:00:00,
 * and both have nextUpdate in December 2032. */
static MunitResult path_crl_time(const MunitParameter params[], void* user)
{
  const TC_X509_time early = {2020, 4, 7, 21, 50, 42};
  (void)params;
  (void)user;
  revocation_init(1, early);
  const TC_bytes chain[] = {
      revocation.candidates[1],
      ocsp_read_path(TC_ICAM_OCSP_ROOT "/card44_piv_auth_cert.der", certificate_bytes)};
  TC_X509_revocation_options options = revocation_options(early, NULL);
  TC_X509_revocation_result result;
  size_t work = 20000000;
  options.time.clock_skew_seconds = 9;
  munit_assert_int(
      TC_X509_path_check_revocation(chain, 2, &options, &revocation.workspace, &work, &result), ==,
      TC_TLV_UNSUPPORTED);
  options.time.clock_skew_seconds = 10;
  work = 20000000;
  munit_assert_int(
      TC_X509_path_check_revocation(chain, 2, &options, &revocation.workspace, &work, &result), ==,
      TC_TLV_OK);
  munit_assert_int(result.status, ==, TC_X509_REVOCATION_GOOD);

  /* The Root CA CRL is the older one: thisUpdate 2018-05-27 00:00:00 is
   * 263296800 s before 2026-09-29 10:00, less 300 s of skew. */
  options.time = (TC_X509_revocation_time){card_at, 300, 263296500};
  revocation.signer.at = card_at;
  work = 20000000;
  munit_assert_int(
      TC_X509_path_check_revocation(chain, 2, &options, &revocation.workspace, &work, &result), ==,
      TC_TLV_OK);
  options.time.max_age_seconds = 263296499;
  work = 20000000;
  munit_assert_int(
      TC_X509_path_check_revocation(chain, 2, &options, &revocation.workspace, &work, &result), ==,
      TC_TLV_UNSUPPORTED);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
      {"/content-signer", content_signer, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/delegate-nocheck", delegate_nocheck, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/store-delegate", store_delegate, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/source-arguments", source_arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/issuer-signed", issuer_signed, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/bounded-inner-response", bounded_inner_response, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/local-responses", local_responses, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/path-ocsp", path_ocsp, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/path-ocsp-arguments", path_ocsp_arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/path-crl-time", path_crl_time, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/x509/ocsp/icam", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
