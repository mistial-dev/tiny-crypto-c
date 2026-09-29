/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "ocsp_fixture.h"

static const TC_X509_time content_signer_at = {2026, 9, 28, 9, 0, 0};
static const TC_X509_time card_at = {2026, 9, 29, 10, 0, 0};

static ocsp_fixture fixture;
static uint8_t issuer_bytes[OCSP_FILE_CAPACITY], response_bytes[OCSP_FILE_CAPACITY];
static uint8_t certificate_bytes[OCSP_FILE_CAPACITY], signer_bytes[OCSP_FILE_CAPACITY];

static TC_X509_trust_anchor read_issuer(void)
{
  return ocsp_read_anchor(&fixture, TC_ICAM_OCSP_ROOT "/issuer.der", issuer_bytes);
}

static MunitResult content_signer(const MunitParameter params[], void* user)
{
  const char* suffixes[] = {"good", "revoked", "unknown"};
  const TC_OCSP_status statuses[] = {TC_OCSP_GOOD, TC_OCSP_REVOKED, TC_OCSP_UNKNOWN};
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
    TC_OCSP_verify_request request =
        ocsp_request(&fixture, response, certificate, &anchor, content_signer_at);
    size_t work = 20000000;
    TC_OCSP_result result = {0};
    munit_assert_int(TC_OCSP_response_verify(&request, &fixture.workspace, &work, &result), ==,
                     TC_TLV_OK);
    munit_assert_int(result.status, ==, statuses[i]);
    munit_assert_int(result.has_revocation_time, ==, i == 1);
    /* The embedded OCSP Valid Signer gen3 has no id-pkix-ocsp-nocheck. */
    munit_assert_true(ocsp_span_within(result.responder_certificate, response));
    munit_assert_false(result.responder_nocheck);
    if (i == 0) {
      const TC_OCSP_result saved = result;
      response_bytes[response.length - 1] ^= 1;
      work = 20000000;
      munit_assert_int(TC_OCSP_response_verify(&request, &fixture.workspace, &work, &result), ==,
                       TC_TLV_INVALID);
      munit_assert_memory_equal(sizeof result, &result, &saved);
      response_bytes[response.length - 1] ^= 1;
      const uint8_t unavailable[] = {0x30, 0x03, 0x0a, 0x01, 0x03};
      request.response = (TC_bytes){unavailable, sizeof unavailable};
      work = 20000000;
      munit_assert_int(TC_OCSP_response_verify(&request, &fixture.workspace, &work, &result), ==,
                       TC_TLV_OK);
      munit_assert_int(result.status, ==, TC_OCSP_UNAVAILABLE);
    }
  }
  return MUNIT_OK;
}

static TC_OCSP_result verify_card(unsigned card, const char* response_name,
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
  TC_OCSP_verify_request request = ocsp_request(&fixture, response, certificate, anchor, card_at);
  request.certificates = store;
  size_t work = 20000000;
  TC_OCSP_result result;
  memset(&result, 0x5a, sizeof result);
  const TC_OCSP_result saved = result;
  munit_assert_int(TC_OCSP_response_verify(&request, &fixture.workspace, &work, &result), ==,
                   expected);
  if (expected != TC_TLV_OK) {
    munit_assert_memory_equal(sizeof result, &result, &saved);
    return result;
  }
  munit_assert_int(result.status, ==, TC_OCSP_GOOD);
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

  TC_OCSP_result result = verify_card(43, "card43_delegate_nocheck", &anchor, NULL, TC_TLV_OK);
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

  TC_OCSP_result result = verify_card(44, "card44_delegate_no_certs", &anchor, &store, TC_TLV_OK);
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
  TC_OCSP_verify_request request = ocsp_request(&fixture, response, certificate, &anchor, card_at);
  request.certificates = &store;
  request.max_certificates = 0;
  size_t work = 20000000;
  TC_OCSP_result saved = result;
  munit_assert_int(TC_OCSP_response_verify(&request, &fixture.workspace, &work, &result), ==,
                   TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof result, &result, &saved);
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

/* Run one card 44 store-delegate verification that must fail with ARGUMENT
 * and leave work and out unchanged. */
static void verify_argument(const TC_X509_trust_anchor* anchor, const TC_X509_store_source* store,
                            size_t expected_work)
{
  const TC_bytes certificate =
      ocsp_read_path(TC_ICAM_OCSP_ROOT "/card44_piv_auth_cert.der", certificate_bytes);
  const TC_bytes response =
      ocsp_read_path(TC_ICAM_OCSP_ROOT "/card44_delegate_no_certs.der", response_bytes);
  TC_OCSP_verify_request request = ocsp_request(&fixture, response, certificate, anchor, card_at);
  request.certificates = store;
  size_t work = 20000000;
  TC_OCSP_result result;
  memset(&result, 0x5a, sizeof result);
  const TC_OCSP_result saved = result;
  munit_assert_int(TC_OCSP_response_verify(&request, &fixture.workspace, &work, &result), ==,
                   TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof result, &result, &saved);
  if (expected_work)
    munit_assert_size(work, ==, expected_work);
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
  TC_OCSP_verify_request request = ocsp_request(&fixture, response, certificate, &anchor, card_at);
  request.max_certificates = 0;
  size_t work = 20000000;
  TC_OCSP_result result;
  memset(&result, 0x5a, sizeof result);
  munit_assert_int(TC_OCSP_response_verify(&request, &fixture.workspace, &work, &result), ==,
                   TC_TLV_OK);
  munit_assert_int(result.status, ==, TC_OCSP_GOOD);
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
    TC_OCSP_verify_request request =
        ocsp_request(&fixture, response, certificate, &anchor, content_signer_at);
    request.parsing = limits[i];
    size_t work = 20000000;
    TC_OCSP_result result;
    memset(&result, 0x5a, sizeof result);
    const TC_OCSP_result saved = result;
    munit_assert_int(TC_OCSP_response_verify(&request, &fixture.workspace, &work, &result), ==,
                     TC_TLV_LIMIT);
    munit_assert_memory_equal(sizeof result, &result, &saved);
  }
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
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/x509/ocsp/icam", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
