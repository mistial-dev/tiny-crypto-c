/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "ocsp_fixture.h"

static const TC_X509_time captured_at = {2026, 9, 28, 6, 0, 0};

static TC_bytes read_fixture(const char* root, unsigned card, const char* suffix,
                             uint8_t bytes[OCSP_FILE_CAPACITY])
{
  char path[512];
  munit_assert_int(snprintf(path, sizeof path, "%s/card%02u_%s.der", root, card, suffix), >, 0);
  return ocsp_read_path(path, bytes);
}

static ocsp_fixture fixture;
static uint8_t issuer_bytes[OCSP_FILE_CAPACITY], response_bytes[OCSP_FILE_CAPACITY];
static uint8_t certificate_bytes[OCSP_FILE_CAPACITY], expected_bytes[OCSP_FILE_CAPACITY];

static MunitResult captured_responses(const MunitParameter params[], void* user)
{
  const unsigned cards[] = {1, 2, 3, 4, 10};
  uint8_t request_bytes[512];
  (void)params;
  (void)user;
  ocsp_fixture_init(&fixture);

  for (size_t i = 0; i < sizeof cards / sizeof *cards; ++i) {
    const unsigned card = cards[i];
    char path[512];
    munit_assert_int(snprintf(path, sizeof path, "%s/card%02u_issuer.der", TC_SD33_OCSP_ROOT, card),
                     >, 0);
    const TC_X509_trust_anchor anchor = ocsp_read_anchor(&fixture, path, issuer_bytes);
    const TC_bytes response = read_fixture(TC_SD33_OCSP_ROOT, card, "response", response_bytes);
    for (unsigned role = 0; role < 2; ++role) {
      TC_bytes certificate = read_fixture(
          TC_SD33_CERT_ROOT, card, role ? "card_auth_cert" : "piv_auth_cert", certificate_bytes);
      TC_X509_ocsp_verify_request request =
          ocsp_request(&fixture, response, certificate, &anchor, captured_at);
      if (card == 1 && role == 0) {
        const TC_hash_algorithm hashes[] = {TC_HASH_SHA1, TC_HASH_SHA256};
        const char* names[] = {"request_sha1", "request_sha256"};
        for (size_t j = 0; j < 2; ++j) {
          TC_bytes expected = read_fixture(TC_SD33_OCSP_ROOT, card, names[j], expected_bytes);
          size_t request_work = 20000000, request_length = 0;
          const TC_X509_ocsp_encode_request encode = {certificate, &anchor, hashes[j],
                                                      (TC_bytes){NULL, 0}, &fixture.limits};
          munit_assert_int(TC_X509_ocsp_request_encode(
                               &encode, &fixture.workspace, &request_work,
                               (TC_buffer){request_bytes, sizeof request_bytes}, &request_length),
                           ==, TC_TLV_OK);
          munit_assert_size(request_length, ==, expected.length);
          munit_assert_memory_equal(request_length, request_bytes, expected.data);
        }
      }
      size_t work = 20000000;
      TC_X509_ocsp_result result = {0};
      munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result),
                       ==, TC_TLV_OK);
      munit_assert_int(result.status, ==, TC_X509_REVOCATION_GOOD);
      munit_assert_true(result.has_next_update);
      /* The SD 33 responders are delegates whose certificates are embedded. */
      munit_assert_true(ocsp_span_within(result.responder_certificate, response));
      request.max_responses = 1;
      work = 20000000;
      munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result),
                       ==, TC_TLV_LIMIT);
      ocsp_assert_wiped(&result);
      request.max_responses = 16;
      request.max_certificates = 0;
      work = 20000000;
      munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result),
                       ==, TC_TLV_LIMIT);
      ocsp_assert_wiped(&result);
      request.max_certificates = 4;
      request.time.at = (TC_X509_time){2026, 10, 1, 6, 0, 0};
      work = 20000000;
      munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result),
                       ==, TC_TLV_INVALID);
      ocsp_assert_wiped(&result);
      request.time.at = captured_at;
      uint8_t nonce[32] = {0};
      request.expected_nonce = (TC_bytes){nonce, sizeof nonce};
      work = 20000000;
      munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result),
                       ==, TC_TLV_INVALID);
      ocsp_assert_wiped(&result);
      request.expected_nonce = (TC_bytes){NULL, 0};
      work = 0;
      munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result),
                       ==, TC_TLV_LIMIT);
      ocsp_assert_wiped(&result);
      if (card == 1 && role == 0) {
        TC_X509_certificate changed;
        munit_assert_int(TC_X509_read(certificate, &fixture.limits, &fixture.parser, &changed), ==,
                         TC_TLV_OK);
        uint8_t* serial = (uint8_t*)changed.serial.data;
        serial[changed.serial.length - 1] ^= 1;
        work = 20000000;
        munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result),
                         ==, TC_TLV_INVALID);
        ocsp_assert_wiped(&result);
        serial[changed.serial.length - 1] ^= 1;
      }
    }
  }
  return MUNIT_OK;
}

/* The evaluation time is checked at entry, before any response field is
 * read. An unsuccessful responseStatus has no time fields, so it would expose
 * a late check. That response is UNSUPPORTED and zeroes the result. */
static MunitResult time_arguments(const MunitParameter params[], void* user)
{
  static const uint8_t unavailable[] = {0x30, 0x03, 0x0a, 0x01, 0x03};
  (void)params;
  (void)user;
  ocsp_fixture_init(&fixture);
  char path[512];
  munit_assert_int(snprintf(path, sizeof path, "%s/card01_issuer.der", TC_SD33_OCSP_ROOT), >, 0);
  const TC_X509_trust_anchor anchor = ocsp_read_anchor(&fixture, path, issuer_bytes);
  const TC_bytes certificate =
      read_fixture(TC_SD33_CERT_ROOT, 1, "piv_auth_cert", certificate_bytes);
  TC_X509_ocsp_verify_request request = ocsp_request(
      &fixture, (TC_bytes){unavailable, sizeof unavailable}, certificate, &anchor, captured_at);
  TC_X509_ocsp_result result, saved;
  memset(&result, 0x5a, sizeof result);
  saved = result;
  size_t work = 20000000;

  request.time.at = (TC_X509_time){2026, 13, 1, 0, 0, 0};
  munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result), ==,
                   TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof result, &result, &saved);
  munit_assert_size(work, ==, 20000000);
  request.time.at = captured_at;
  munit_assert_int(TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result), ==,
                   TC_TLV_UNSUPPORTED);
  ocsp_assert_wiped(&result);
  return MUNIT_OK;
}

/* A short buffer, including an empty size query, reports the exact length. */
static MunitResult request_sizing(const MunitParameter params[], void* user)
{
  uint8_t encoded[512], nonce[32];
  (void)params;
  (void)user;
  ocsp_fixture_init(&fixture);
  char path[512];
  munit_assert_int(snprintf(path, sizeof path, "%s/card01_issuer.der", TC_SD33_OCSP_ROOT), >, 0);
  const TC_X509_trust_anchor anchor = ocsp_read_anchor(&fixture, path, issuer_bytes);
  const TC_bytes certificate =
      read_fixture(TC_SD33_CERT_ROOT, 1, "piv_auth_cert", certificate_bytes);
  const TC_bytes expected = read_fixture(TC_SD33_OCSP_ROOT, 1, "request_sha1", expected_bytes);
  for (size_t i = 0; i < sizeof nonce; ++i)
    nonce[i] = (uint8_t)(0xa0 + i);
  TC_X509_ocsp_encode_request request = {
      certificate, &anchor, TC_HASH_SHA1, {NULL, 0}, &fixture.limits};
  size_t work = 20000000, length = 1;

  munit_assert_int(TC_X509_ocsp_request_encode(&request, &fixture.workspace, &work,
                                               (TC_buffer){NULL, 0}, &length),
                   ==, TC_TLV_LIMIT);
  munit_assert_size(length, ==, expected.length);
  memset(encoded, 0xa5, sizeof encoded);
  length = 0;
  munit_assert_int(TC_X509_ocsp_request_encode(&request, &fixture.workspace, &work,
                                               (TC_buffer){encoded, expected.length - 1}, &length),
                   ==, TC_TLV_LIMIT);
  munit_assert_size(length, ==, expected.length);
  for (size_t i = 0; i < sizeof encoded; ++i)
    munit_assert_uint8(encoded[i], ==, 0xa5);
  munit_assert_int(TC_X509_ocsp_request_encode(&request, &fixture.workspace, &work,
                                               (TC_buffer){encoded, expected.length}, &length),
                   ==, TC_TLV_OK);
  munit_assert_size(length, ==, expected.length);
  munit_assert_memory_equal(length, encoded, expected.data);

  /* The nonce extension adds [2] { Extension { id-pkix-ocsp-nonce, OCTET STRING
   * { OCTET STRING nonce } } } after requestList (RFC 6960 4.1.1, RFC 9654 2.1). */
  request.nonce = (TC_bytes){nonce, sizeof nonce};
  size_t required = 0;
  munit_assert_int(TC_X509_ocsp_request_encode(&request, &fixture.workspace, &work,
                                               (TC_buffer){NULL, 0}, &required),
                   ==, TC_TLV_LIMIT);
  munit_assert_size(required, ==, expected.length + 2 + 2 + 2 + 11 + 2 + 2 + sizeof nonce);
  munit_assert_int(TC_X509_ocsp_request_encode(&request, &fixture.workspace, &work,
                                               (TC_buffer){encoded, required - 1}, &length),
                   ==, TC_TLV_LIMIT);
  munit_assert_size(length, ==, required);
  munit_assert_int(TC_X509_ocsp_request_encode(&request, &fixture.workspace, &work,
                                               (TC_buffer){encoded, required}, &length),
                   ==, TC_TLV_OK);
  munit_assert_size(length, ==, required);
  munit_assert_memory_equal(sizeof nonce, encoded + length - sizeof nonce, nonce);

  /* Argument errors leave length unchanged. A later failure clears it. */
  request.nonce = (TC_bytes){nonce, 31};
  length = 77;
  munit_assert_int(TC_X509_ocsp_request_encode(&request, &fixture.workspace, &work,
                                               (TC_buffer){encoded, sizeof encoded}, &length),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_size(length, ==, 77);
  request.nonce = (TC_bytes){nonce, sizeof nonce};
  length = 77;
  munit_assert_int(TC_X509_ocsp_request_encode(&request, &fixture.workspace, &work,
                                               (TC_buffer){certificate_bytes, sizeof encoded},
                                               &length),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_size(length, ==, 77);
  munit_assert_int(TC_X509_ocsp_request_encode(&request, &fixture.workspace, &work,
                                               (TC_buffer){nonce + 8, sizeof encoded}, &length),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_size(length, ==, 77);
  request.hash = TC_HASH_SHA384;
  munit_assert_int(TC_X509_ocsp_request_encode(&request, &fixture.workspace, &work,
                                               (TC_buffer){encoded, sizeof encoded}, &length),
                   ==, TC_TLV_UNSUPPORTED);
  munit_assert_size(length, ==, 0);
  request.hash = TC_HASH_SHA1;
  length = 77;
  work = 0;
  munit_assert_int(TC_X509_ocsp_request_encode(&request, &fixture.workspace, &work,
                                               (TC_buffer){encoded, sizeof encoded}, &length),
                   ==, TC_TLV_LIMIT);
  munit_assert_size(length, ==, 0);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
      {"/captured-responses", captured_responses, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/time-arguments", time_arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/request-sizing", request_sizing, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/x509/ocsp/sd33", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
