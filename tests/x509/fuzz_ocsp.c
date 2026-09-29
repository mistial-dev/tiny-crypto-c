/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * libFuzzer target for OCSP response verification and request encoding.
 * The issuer, targets and a store delegate are the ICAM fixtures in
 * TC_OCSP_FUZZ_ROOT. The evaluation time lies inside their validity, so the
 * captured responses reach delegate path validation and signature checks. */
#include "ocsp_fixture.h"
#include <stdlib.h>

enum { TARGETS = 3, WORK_LIMIT = 20000000 };

static const char* const target_names[TARGETS] = {"target.der", "card43_piv_auth_cert.der",
                                                  "card44_piv_auth_cert.der"};
static const TC_X509_time fuzz_at = {2026, 9, 29, 10, 0, 0};

static ocsp_fixture fixture;
static uint8_t issuer_bytes[OCSP_FILE_CAPACITY], delegate_bytes[OCSP_FILE_CAPACITY];
static uint8_t target_bytes[TARGETS][OCSP_FILE_CAPACITY];
static TC_bytes targets[TARGETS], delegate;
static TC_X509_trust_anchor issuer;
static TC_X509_store_array store_array;
static TC_X509_store_source store;

static TC_bytes read_fixture(const char* name, uint8_t bytes[OCSP_FILE_CAPACITY])
{
  char path[512];
  if (snprintf(path, sizeof path, "%s/%s", TC_OCSP_FUZZ_ROOT, name) >= (int)sizeof path)
    abort();
  FILE* file = fopen(path, "rb");
  if (!file)
    abort();
  const size_t length = fread(bytes, 1, OCSP_FILE_CAPACITY, file);
  if (ferror(file) || !feof(file) || fclose(file) || !length)
    abort();
  return (TC_bytes){bytes, length};
}

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
  (void)argc;
  (void)argv;
  ocsp_fixture_init(&fixture);
  TC_X509_certificate view;
  const TC_bytes encoded = read_fixture("issuer.der", issuer_bytes);
  if (TC_X509_read(encoded, &fixture.limits, &fixture.parser, &view) != TC_TLV_OK)
    abort();
  issuer = (TC_X509_trust_anchor){view.subject, view.public_key};
  for (size_t i = 0; i < TARGETS; ++i)
    targets[i] = read_fixture(target_names[i], target_bytes[i]);
  delegate = read_fixture("card44_delegate_signer.der", delegate_bytes);
  store_array = (TC_X509_store_array){&delegate, 1, NULL, 0};
  if (TC_X509_store_array_source(&store_array, &store) != TC_TLV_OK)
    abort();
  return 0;
}

static int all_zero(const void* bytes, size_t length)
{
  const uint8_t* cursor = bytes;
  for (size_t i = 0; i < length; ++i)
    if (cursor[i])
      return 0;
  return 1;
}

static int span_within(TC_bytes inner, TC_bytes outer)
{
  return inner.data >= outer.data && inner.length <= outer.length &&
         (size_t)(inner.data - outer.data) <= outer.length - inner.length;
}

/* Received data never produces ARGUMENT. Failures zero the result. OK
 * reports a decision and a delegate from the response or the store. */
static void check_verify(TC_bytes response, TC_bytes certificate, size_t budget)
{
  TC_X509_ocsp_verify_request request =
      ocsp_request(&fixture, response, certificate, &issuer, fuzz_at);
  request.certificates = &store;
  TC_X509_ocsp_result result;
  memset(&result, 0x5a, sizeof result);
  size_t work = budget;
  const TC_TLV_result status =
      TC_X509_ocsp_response_verify(&request, &fixture.workspace, &work, &result);
  if (status == TC_TLV_ARGUMENT || work > budget)
    abort();
  if (status != TC_TLV_OK) {
    if (!all_zero(&result, sizeof result))
      abort();
    return;
  }
  if (result.status != TC_X509_REVOCATION_GOOD && result.status != TC_X509_REVOCATION_REVOKED)
    abort();
  if (result.has_reason && (result.status != TC_X509_REVOCATION_REVOKED || result.reason > 10 ||
                            result.reason == 7 || result.reason == 8))
    abort();
  if (!result.responder_certificate.data) {
    if (result.responder_certificate.length || result.responder_nocheck)
      abort();
  } else if (!span_within(result.responder_certificate, response) &&
             (result.responder_certificate.data != delegate.data ||
              result.responder_certificate.length != delegate.length))
    abort();
}

/* The input as a certificate. OK writes DER within capacity. A short buffer
 * reports the required size. Every other result reports no encoding. */
static void check_encode(TC_bytes certificate, size_t capacity, size_t budget)
{
  static const uint8_t nonce[32] = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
                                    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
  uint8_t encoded[512];
  memset(encoded, 0xa5, sizeof encoded);
  const TC_X509_ocsp_encode_request request = {certificate, &issuer, TC_HASH_SHA256,
                                               (TC_bytes){nonce, sizeof nonce}, &fixture.limits};
  size_t work = budget, length = SIZE_MAX;
  const TC_TLV_result status = TC_X509_ocsp_request_encode(&request, &fixture.workspace, &work,
                                                           (TC_buffer){encoded, capacity}, &length);
  if (status == TC_TLV_ARGUMENT || work > budget)
    abort();
  size_t untouched = 0;
  if (status == TC_TLV_OK) {
    if (length > capacity || TC_TLV_walk(encoded, length, TC_TLV_DER, &fixture.limits,
                                         fixture.workspace.frames, NULL, NULL) != TC_TLV_OK)
      abort();
    untouched = length;
  } else if (!(status == TC_TLV_LIMIT && length > capacity) && length)
    abort();
  for (size_t i = untouched; i < sizeof encoded; ++i)
    if (encoded[i] != 0xa5)
      abort();
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  const TC_bytes input = {size ? data : (const uint8_t*)"", size};
  /* The first byte also selects a small budget and capacity, so LIMIT paths
   * run on complete inputs. */
  const size_t selector = size ? data[0] : 0;
  for (size_t i = 0; i < TARGETS; ++i)
    check_verify(input, targets[i], WORK_LIMIT);
  check_verify(input, targets[selector % TARGETS], selector * 2048);
  check_encode(input, 512, WORK_LIMIT);
  check_encode(input, selector * 2, selector * 64);
  return 0;
}
