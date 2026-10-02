/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Validation context over vendored certificates and CRLs for the credential
 * tests. Anchor certificates, untrusted candidates and an optional CRL
 * index feed a TC_validation_context with the native signature provider.
 * The fixture points into itself, so keep it in place (a static object). */
#ifndef TC_TEST_CREDENTIAL_VALIDATION_FIXTURE_H_
#define TC_TEST_CREDENTIAL_VALIDATION_FIXTURE_H_

#include <tiny_crypto/credential.h>
#include <tiny_crypto/x509_crypto.h>
#include <tiny_crypto/x509_store.h>
#include "munit.h"
#include "test_io.h"
#include <string.h>

enum {
  FIXTURE_FILE_BYTES = 16384,
  FIXTURE_FRAMES = 32,
  FIXTURE_OIDS = 64,
  FIXTURE_CANDIDATES = 4,
  FIXTURE_CRLS = 4,
  FIXTURE_ANCHORS = 2,
  FIXTURE_ARENA_BYTES = 1024 * 1024,
  FIXTURE_WORK = 200000000
};

typedef struct {
  TC_TLV_limits limits;
  TC_TLV_frame frames[FIXTURE_FRAMES];
  TC_bytes oids[FIXTURE_OIDS];
  TC_X509_workspace parser;
  TC_ECDSA_workspace ec;
  TC_RSA_word words[TC_RSA_VERIFY_WORKSPACE_WORDS(4096)];
  TC_RSA_workspace rsa;
  TC_X509_native_workspace native;
  TC_validation_storage arena[FIXTURE_ARENA_BYTES / sizeof(TC_validation_storage)];
  TC_validation_workspace workspace;
  TC_X509_store_anchor anchors[FIXTURE_ANCHORS];
  TC_bytes candidates[FIXTURE_CANDIDATES];
  TC_X509_store_array array;
  TC_X509_store_source source;
  TC_bytes crls[FIXTURE_CRLS];
  TC_X509_crl_record records[FIXTURE_CRLS];
  TC_X509_crl_index index;
  TC_validation_options options;
  TC_validation_context context;
} validation_fixture;

/* Read a DER file into bytes. */
static inline TC_bytes fixture_read(const char* path, uint8_t bytes[FIXTURE_FILE_BYTES])
{
  FILE* file = tc_test_fopen(path, "rb");
  munit_assert_not_null(file);
  const size_t length = fread(bytes, 1, FIXTURE_FILE_BYTES, file);
  munit_assert_true(feof(file));
  munit_assert_int(fclose(file), ==, 0);
  munit_assert_size(length, >, 0);
  return (TC_bytes){bytes, length};
}

/* The trust inputs of a fixture: trusted anchors, untrusted candidate
 * issuers and indexed CRLs. */
typedef struct {
  const TC_bytes* anchors;
  size_t anchor_count;
  const TC_bytes* candidates;
  size_t candidate_count;
  const TC_bytes* crls;
  size_t crl_count;
} validation_fixture_trust;

/* Build the context from trust. CRL signer searches read only candidates,
 * so list an anchor certificate among them when it signs a CRL. All spans
 * borrow caller bytes that stay unchanged. */
static inline void validation_fixture_init_trust(validation_fixture* fixture,
                                                 const validation_fixture_trust* trust_inputs,
                                                 TC_X509_time at,
                                                 TC_validation_revocation revocation)
{
  const TC_bytes* candidates = trust_inputs->candidates;
  const size_t candidate_count = trust_inputs->candidate_count;
  const TC_bytes* crls = trust_inputs->crls;
  const size_t crl_count = trust_inputs->crl_count;
  munit_assert_size(trust_inputs->anchor_count, >=, 1);
  munit_assert_size(trust_inputs->anchor_count, <=, FIXTURE_ANCHORS);
  munit_assert_size(candidate_count, <=, FIXTURE_CANDIDATES);
  munit_assert_size(crl_count, <=, FIXTURE_CRLS);
  fixture->limits = (TC_TLV_limits){FIXTURE_FILE_BYTES, FIXTURE_FILE_BYTES, 512, FIXTURE_FRAMES};
  fixture->parser =
      (TC_X509_workspace){{fixture->frames, FIXTURE_FRAMES}, fixture->oids, FIXTURE_OIDS};
  fixture->rsa = (TC_RSA_workspace){fixture->words, sizeof fixture->words / sizeof *fixture->words};
  fixture->native = (TC_X509_native_workspace){&fixture->ec, &fixture->rsa,
                                               TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};

  TC_validation_capacity capacity;
  munit_assert_int(TC_validation_capacity_init(TC_VALIDATION_DESKTOP, &capacity), ==, TC_RESULT_OK);
  munit_assert_int(TC_validation_workspace_init(
                       &capacity, (TC_buffer){(uint8_t*)fixture->arena, sizeof fixture->arena},
                       &fixture->workspace),
                   ==, TC_RESULT_OK);

  for (size_t i = 0; i < trust_inputs->anchor_count; ++i) {
    TC_X509_certificate view;
    munit_assert_int(
        TC_X509_read(trust_inputs->anchors[i], &fixture->limits, &fixture->parser, &view), ==,
        TC_TLV_OK);
    munit_assert_int(TC_X509_store_anchor_from_certificate(&view, &fixture->limits,
                                                           &fixture->parser, &fixture->anchors[i]),
                     ==, TC_TLV_OK);
  }
  for (size_t i = 0; i < candidate_count; ++i)
    fixture->candidates[i] = candidates[i];
  fixture->array = (TC_X509_store_array){fixture->candidates, candidate_count, fixture->anchors,
                                         trust_inputs->anchor_count};
  munit_assert_int(TC_X509_store_array_source(&fixture->array, &fixture->source), ==, TC_TLV_OK);
  for (size_t i = 0; i < crl_count; ++i)
    fixture->crls[i] = crls[i];
  size_t work = FIXTURE_WORK;
  munit_assert_int(TC_X509_crl_index_init(fixture->crls, crl_count, &fixture->limits,
                                          &fixture->parser, &work, fixture->records, FIXTURE_CRLS,
                                          &fixture->index),
                   ==, TC_TLV_OK);

  memset(&fixture->options, 0, sizeof fixture->options);
  fixture->options.at = at;
  fixture->options.signatures = TC_X509_native_provider(&fixture->native);
  fixture->options.parsing = fixture->limits;
  fixture->options.max_certificates = 8;
  fixture->options.max_input = 8 * FIXTURE_FILE_BYTES;
  fixture->options.max_candidates = FIXTURE_CANDIDATES;
  fixture->options.max_candidate_bytes = FIXTURE_CANDIDATES * FIXTURE_FILE_BYTES;
  fixture->options.revocation = revocation;
  const TC_validation_trust trust = {&fixture->source, &fixture->index};
  munit_assert_int(TC_validation_context_init(&trust, &fixture->options,
                                              &fixture->workspace.credential, &fixture->context),
                   ==, TC_RESULT_OK);
}

/* Build the context with one anchor. */
static inline void validation_fixture_init(validation_fixture* fixture, TC_bytes anchor,
                                           const TC_bytes* candidates, size_t candidate_count,
                                           const TC_bytes* crls, size_t crl_count, TC_X509_time at,
                                           TC_validation_revocation revocation)
{
  const validation_fixture_trust trust = {&anchor, 1, candidates, candidate_count, crls, crl_count};
  validation_fixture_init_trust(fixture, &trust, at, revocation);
}

/* Read the card identifiers from the subjectAltName of a validated Card
 * Authentication certificate (SP 800-73-5 Part 1 section 3.1.4). */
static inline void fixture_card_identifiers(const validation_fixture* fixture,
                                            const TC_X509_certificate* card,
                                            TC_PIV_card_identifiers* out)
{
  static const uint8_t san_oid[] = {0x55, 0x1d, 17};
  TC_TLV_reader extensions;
  TC_X509_extension extension;
  size_t work = FIXTURE_WORK;
  int found = 0;
  munit_assert_int(TC_X509_extensions_init(&extensions, card->extensions, &fixture->limits), ==,
                   TC_TLV_OK);
  while (TC_X509_extension_next(&extensions, &extension) == TC_TLV_OK) {
    if (extension.oid.length != sizeof san_oid ||
        memcmp(extension.oid.data, san_oid, sizeof san_oid))
      continue;
    TC_TLV_frame frames[FIXTURE_FRAMES];
    munit_assert_int(TC_PIV_card_identifiers_read(extension.value, TC_PIV_CARD, &fixture->limits,
                                                  (TC_TLV_frames){frames, FIXTURE_FRAMES}, &work,
                                                  out),
                     ==, TC_TLV_OK);
    found = 1;
  }
  munit_assert_true(found);
}

#endif
