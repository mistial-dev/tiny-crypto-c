/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_TEST_OCSP_FIXTURE_H_
#define TC_TEST_OCSP_FIXTURE_H_

#include <tiny_crypto/x509_ocsp.h>
#include <tiny_crypto/x509_crypto.h>
#include "munit.h"
#include <stdio.h>
#include <string.h>

enum {
  OCSP_FILE_CAPACITY = 8192,
  OCSP_FRAME_CAPACITY = 64,
  OCSP_OID_CAPACITY = 32,
  OCSP_NAME_CAPACITY = 128
};

/* Scratch and native signature verification shared by the OCSP tests. The
 * provider points into the fixture, so the fixture must stay in place. */
typedef struct {
  TC_TLV_limits limits;
  TC_TLV_frame frames[OCSP_FRAME_CAPACITY];
  TC_bytes oids[OCSP_OID_CAPACITY];
  uint32_t left[OCSP_NAME_CAPACITY], right[OCSP_NAME_CAPACITY];
  uint8_t matched[OCSP_OID_CAPACITY];
  TC_X509_workspace parser;
  TC_OCSP_workspace workspace;
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
      (TC_X509_workspace){fixture->frames, OCSP_FRAME_CAPACITY, fixture->oids, OCSP_OID_CAPACITY};
  fixture->workspace = (TC_OCSP_workspace){
      fixture->frames,
      OCSP_FRAME_CAPACITY,
      fixture->oids,
      OCSP_OID_CAPACITY,
      {fixture->left, fixture->right, OCSP_NAME_CAPACITY, fixture->matched, OCSP_OID_CAPACITY}};
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
  munit_assert_int(
      TC_X509_read(encoded.data, encoded.length, &fixture->limits, &fixture->parser, &issuer), ==,
      TC_TLV_OK);
  return (TC_X509_trust_anchor){issuer.subject, issuer.public_key};
}

/* A request with the freshness and count limits used by the captured cases. */
static inline TC_OCSP_verify_request ocsp_request(const ocsp_fixture* fixture, TC_bytes response,
                                                  TC_bytes certificate,
                                                  const TC_X509_trust_anchor* issuer,
                                                  TC_X509_time at)
{
  TC_OCSP_verify_request request = {0};
  request.response = response;
  request.certificate = certificate;
  request.issuer = issuer;
  request.at = at;
  request.max_age_seconds = 172800;
  request.clock_skew_seconds = 300;
  request.max_responses = 16;
  request.max_certificates = 4;
  request.parsing = &fixture->limits;
  request.signatures = &fixture->signatures;
  return request;
}

static inline int ocsp_span_within(TC_bytes inner, TC_bytes outer)
{
  return inner.data && inner.length && inner.data >= outer.data && inner.length <= outer.length &&
         (size_t)(inner.data - outer.data) <= outer.length - inner.length;
}

#endif
