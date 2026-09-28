/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/x509_ocsp.h>
#include <tiny_crypto/x509_crypto.h>
#include "munit.h"
#include <stdio.h>
#include <string.h>

enum { FILE_CAPACITY = 8192, FRAME_CAPACITY = 64, OID_CAPACITY = 32 };

static TC_bytes read_path(const char* path, uint8_t bytes[FILE_CAPACITY])
{
  FILE* file = fopen(path, "rb");
  munit_assert_not_null(file);
  size_t length = fread(bytes, 1, FILE_CAPACITY, file);
  munit_assert_false(ferror(file));
  munit_assert_true(feof(file));
  munit_assert_int(fclose(file), ==, 0);
  munit_assert_size(length, >, 0);
  return (TC_bytes){bytes, length};
}

static TC_bytes read_fixture(const char* root, unsigned card, const char* suffix,
                             uint8_t bytes[FILE_CAPACITY])
{
  char path[512];
  munit_assert_int(snprintf(path, sizeof path, "%s/card%02u_%s.der", root, card, suffix), >, 0);
  return read_path(path, bytes);
}

static MunitResult captured_responses(const MunitParameter params[], void* user)
{
  const unsigned cards[] = {1, 2, 3, 4, 10};
  const TC_TLV_limits limits = {FILE_CAPACITY, FILE_CAPACITY, 512, FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_bytes oids[OID_CAPACITY];
  uint32_t left[128], right[128];
  uint8_t matched[OID_CAPACITY];
  TC_X509_workspace parser = {frames, FRAME_CAPACITY, oids, OID_CAPACITY};
  TC_OCSP_workspace scratch = {
      frames, FRAME_CAPACITY, oids, OID_CAPACITY, {left, right, 128, matched, OID_CAPACITY}};
  TC_ECDSA_workspace ec;
  TC_RSA_word words[TC_RSA_VERIFY_WORKSPACE_WORDS(4096)];
  TC_RSA_workspace rsa = {words, sizeof words / sizeof *words};
  TC_X509_native_workspace native = {&ec, &rsa, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  TC_X509_signature_provider signatures = TC_X509_native_provider(&native);
  uint8_t issuer_bytes[FILE_CAPACITY], response_bytes[FILE_CAPACITY];
  uint8_t certificate_bytes[FILE_CAPACITY];
  uint8_t request_bytes[512], expected_bytes[FILE_CAPACITY];
  (void)params;
  (void)user;

  for (size_t i = 0; i < sizeof cards / sizeof *cards; ++i) {
    const unsigned card = cards[i];
    TC_bytes issuer_der = read_fixture(TC_SD33_OCSP_ROOT, card, "issuer", issuer_bytes);
    TC_bytes response = read_fixture(TC_SD33_OCSP_ROOT, card, "response", response_bytes);
    TC_X509_certificate issuer;
    munit_assert_int(TC_X509_read(issuer_der.data, issuer_der.length, &limits, &parser, &issuer),
                     ==, TC_TLV_OK);
    TC_X509_trust_anchor anchor = {issuer.subject, issuer.public_key};
    for (unsigned role = 0; role < 2; ++role) {
      TC_bytes certificate = read_fixture(
          TC_SD33_CERT_ROOT, card, role ? "card_auth_cert" : "piv_auth_cert", certificate_bytes);
      TC_OCSP_verify_request request = {0};
      request.response = response;
      request.certificate = certificate;
      request.issuer = &anchor;
      request.at = (TC_X509_time){2026, 9, 28, 6, 0, 0};
      request.max_age_seconds = 172800;
      request.clock_skew_seconds = 300;
      request.max_response_bytes = FILE_CAPACITY;
      request.max_responses = 16;
      request.max_certificates = 4;
      request.parsing = &limits;
      request.signatures = &signatures;
      if (card == 1 && role == 0) {
        const TC_hash_algorithm hashes[] = {TC_HASH_SHA1, TC_HASH_SHA256};
        const char* names[] = {"request_sha1", "request_sha256"};
        for (size_t j = 0; j < 2; ++j) {
          TC_bytes expected = read_fixture(TC_SD33_OCSP_ROOT, card, names[j], expected_bytes);
          size_t request_work = 20000000, request_length = 0;
          munit_assert_int(TC_OCSP_request_encode(
                               certificate, &anchor, hashes[j], (TC_bytes){NULL, 0}, &limits,
                               &scratch, &request_work,
                               (TC_buffer){request_bytes, sizeof request_bytes}, &request_length),
                           ==, TC_TLV_OK);
          munit_assert_size(request_length, ==, expected.length);
          munit_assert_memory_equal(request_length, request_bytes, expected.data);
        }
      }
      size_t work = 20000000;
      TC_OCSP_result result = {0};
      munit_assert_int(TC_OCSP_response_verify(&request, &scratch, &work, &result), ==, TC_TLV_OK);
      munit_assert_int(result.status, ==, TC_OCSP_GOOD);
      munit_assert_true(result.has_next_update);
      const TC_OCSP_result saved = result;
      request.max_responses = 1;
      work = 20000000;
      munit_assert_int(TC_OCSP_response_verify(&request, &scratch, &work, &result), ==,
                       TC_TLV_LIMIT);
      munit_assert_memory_equal(sizeof result, &result, &saved);
      request.max_responses = 16;
      request.at = (TC_X509_time){2026, 10, 1, 6, 0, 0};
      work = 20000000;
      munit_assert_int(TC_OCSP_response_verify(&request, &scratch, &work, &result), ==,
                       TC_TLV_INVALID);
      munit_assert_memory_equal(sizeof result, &result, &saved);
      request.at = (TC_X509_time){2026, 9, 28, 6, 0, 0};
      uint8_t nonce[32] = {0};
      request.expected_nonce = (TC_bytes){nonce, sizeof nonce};
      work = 20000000;
      munit_assert_int(TC_OCSP_response_verify(&request, &scratch, &work, &result), ==,
                       TC_TLV_INVALID);
      munit_assert_memory_equal(sizeof result, &result, &saved);
      request.expected_nonce = (TC_bytes){NULL, 0};
      work = 0;
      munit_assert_int(TC_OCSP_response_verify(&request, &scratch, &work, &result), ==,
                       TC_TLV_LIMIT);
      munit_assert_memory_equal(sizeof result, &result, &saved);
      if (card == 1 && role == 0) {
        TC_X509_certificate changed;
        munit_assert_int(
            TC_X509_read(certificate.data, certificate.length, &limits, &parser, &changed), ==,
            TC_TLV_OK);
        uint8_t* serial = (uint8_t*)changed.serial.data;
        serial[changed.serial.length - 1] ^= 1;
        work = 20000000;
        munit_assert_int(TC_OCSP_response_verify(&request, &scratch, &work, &result), ==,
                         TC_TLV_INVALID);
        munit_assert_memory_equal(sizeof result, &result, &saved);
        serial[changed.serial.length - 1] ^= 1;
      }
    }
  }
  const char* suffixes[] = {"good", "revoked", "unknown"};
  const TC_OCSP_status statuses[] = {TC_OCSP_GOOD, TC_OCSP_REVOKED, TC_OCSP_UNKNOWN};
  TC_bytes issuer_der = read_path(TC_ICAM_OCSP_ROOT "/issuer.der", issuer_bytes);
  TC_bytes certificate = read_path(TC_ICAM_OCSP_ROOT "/target.der", certificate_bytes);
  TC_X509_certificate issuer;
  munit_assert_int(TC_X509_read(issuer_der.data, issuer_der.length, &limits, &parser, &issuer), ==,
                   TC_TLV_OK);
  TC_X509_trust_anchor anchor = {issuer.subject, issuer.public_key};
  for (size_t i = 0; i < 3; ++i) {
    char path[512];
    munit_assert_int(
        snprintf(path, sizeof path, "%s/content_signer_%s.der", TC_ICAM_OCSP_ROOT, suffixes[i]), >,
        0);
    TC_bytes response = read_path(path, response_bytes);
    TC_OCSP_verify_request request = {0};
    request.response = response;
    request.certificate = certificate;
    request.issuer = &anchor;
    request.at = (TC_X509_time){2026, 9, 28, 9, 0, 0};
    request.max_age_seconds = 172800;
    request.clock_skew_seconds = 300;
    request.max_response_bytes = FILE_CAPACITY;
    request.max_responses = 16;
    request.max_certificates = 4;
    request.parsing = &limits;
    request.signatures = &signatures;
    size_t work = 20000000;
    TC_OCSP_result result = {0};
    munit_assert_int(TC_OCSP_response_verify(&request, &scratch, &work, &result), ==, TC_TLV_OK);
    munit_assert_int(result.status, ==, statuses[i]);
    munit_assert_int(result.has_revocation_time, ==, i == 1);
    if (i == 0) {
      const TC_OCSP_result saved = result;
      response_bytes[response.length - 1] ^= 1;
      work = 20000000;
      munit_assert_int(TC_OCSP_response_verify(&request, &scratch, &work, &result), ==,
                       TC_TLV_INVALID);
      munit_assert_memory_equal(sizeof result, &result, &saved);
      response_bytes[response.length - 1] ^= 1;
      const uint8_t unavailable[] = {0x30, 0x03, 0x0a, 0x01, 0x03};
      request.response = (TC_bytes){unavailable, sizeof unavailable};
      work = 20000000;
      munit_assert_int(TC_OCSP_response_verify(&request, &scratch, &work, &result), ==, TC_TLV_OK);
      munit_assert_int(result.status, ==, TC_OCSP_UNAVAILABLE);
    }
  }
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
      {"/captured-responses", captured_responses, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/x509/ocsp/sd33", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
