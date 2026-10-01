/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The composed card check on the SD 33 card 2 and card 4 simulators. The
 * SD 33 root is unavailable, so the issuing CAs are pinned: card 2 has its
 * card certificates and CHUID signer under the RSA 3072 CA and its secure
 * messaging signer under the ECC P-384 CA, card 4 has all of them under the
 * ECC P-256 CA. The vendored CRLs and OCSP responses are evaluated at
 * 2026-09-29T18:00:00Z. The PIN and pairing code come from the fixtures. */
#include <tiny_crypto/piv_card_check.h>
#include <tiny_crypto/piv_sm_apdu.h>
#include <tiny_crypto/piv_vci.h>
#include "../credential/validation_fixture.h"
#include "card_simulator.h"
#include "source_internal.h"
#include "test_util.h"
#include <tiny_crypto/x509_crl_source.h>
#include <stdio.h>
#include <string.h>

#ifndef TC_CARD_FIXTURE_DIR
#error "TC_CARD_FIXTURE_DIR must name the capture fixture directory"
#endif
#ifndef TC_VECTOR_DIR
#error "TC_VECTOR_DIR must name tests/vectors"
#endif

enum {
  POOL_BYTES = TC_PIV_INVENTORY_POOL_BYTES,
  RESPONSE_BYTES = 1024,
  COPY_BYTES = 4096,
  SM_SCRATCH_BYTES = 1024,
  EXCHANGES = 4096,
  CATALOG = TC_PIV_CATALOG_PIV_OBJECTS,
  CERTIFICATE_BYTES = 16384,
  LDS_BYTES = 4096,
  CVC_BYTES = 512,
  CHECK_WORK = 400000000
};

static const TC_X509_time at = {2026, 9, 29, 18, 0, 0};

/* The captured card 2 PKCS #1 v1.5 encoded messages end in these digests
 * (tests/piv/key_proof.c). */
static const uint8_t card2_digest_9a[32] = {
    0x1e, 0x7a, 0x86, 0x02, 0x3c, 0x89, 0xbc, 0x32, 0x6c, 0xcf, 0x96, 0x86, 0x9f, 0x61, 0x21, 0x36,
    0x7b, 0x2f, 0x43, 0x6a, 0xd6, 0x19, 0xa9, 0x34, 0x55, 0xd9, 0x8c, 0xe9, 0x81, 0x1a, 0x51, 0xe0};
static const uint8_t card2_digest_9e[32] = {
    0x63, 0x7a, 0xe3, 0x80, 0x2f, 0xbe, 0xd7, 0xef, 0x1f, 0xb1, 0xed, 0xaa, 0x53, 0x66, 0xeb, 0x56,
    0xb7, 0xa8, 0x0c, 0x29, 0x14, 0xa4, 0x86, 0x2d, 0xbf, 0x80, 0xff, 0xb6, 0x86, 0x91, 0x36, 0x37};

static tc_card_fixture fixture;
static tc_card_simulator card;
static TC_PIV_link link;
static uint8_t scratch[TC_APDU_SHORT_COMMAND_MAX_BYTES];
static uint8_t sm_scratch[SM_SCRATCH_BYTES];
static uint8_t response_bytes[RESPONSE_BYTES];
static uint8_t copy_bytes[COPY_BYTES];
static uint8_t pool[POOL_BYTES];
static TC_PIV_object objects[CATALOG];
static TC_PIV_inventory inventory;
static TC_PIV_SM session;
static TC_PIV_SM_workspace sm_workspace;
static uint8_t card_cvc[CVC_BYTES];
static TC_bytes sm_card_cvc;
static TC_PIV_object plain_copy;
static const tc_card_session* recorded;

static validation_fixture card_trust, content_trust;
static uint8_t issuer_bytes[3][FIXTURE_FILE_BYTES];
static uint8_t crl_bytes[3][FIXTURE_FILE_BYTES];
static uint8_t ocsp_bytes[FIXTURE_FILE_BYTES];
static TC_PIV_card_check_ocsp ocsp;
static TC_PIV_card_check_workspace workspace;
static uint8_t certificate_storage[CERTIFICATE_BYTES];
static uint8_t lds_storage[LDS_BYTES];
static TC_PIV_card_report report;
static uint8_t override_bytes[16384];

static TC_PIV_key_proof_workspace proof_workspace;
static TC_ECDSA_workspace proof_ec;
static TC_RSA_word proof_words[TC_RSA_VERIFY_WORKSPACE_WORDS(3072)];

/* ---- Card and link ---- */

static void load(const char* name)
{
  char path[512];
  munit_assert_int(snprintf(path, sizeof path, "%s/%s.txt", TC_CARD_FIXTURE_DIR, name), >, 0);
  munit_assert_long(tc_card_fixture_load(&fixture, path), ==, 0);
}

static TC_buffer response_buffer(void)
{
  return (TC_buffer){response_bytes, sizeof response_bytes};
}

static void link_open(TC_PIV_interface interface)
{
  const TC_PIV_link_options options = {{TC_APDU_SHORT, 0, EXCHANGES, 0, 0}, interface, 0};
  TC_PIV_application application;
  tc_card_simulator_init(&card, &fixture, interface);
  munit_assert_int(TC_PIV_link_init(&link, tc_card_simulator_transport(&card), &options,
                                    (TC_buffer){scratch, sizeof scratch}),
                   ==, TC_PIV_OK);
  munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 0, response_buffer(), &application),
                   ==, TC_PIV_OK);
  sm_card_cvc = (TC_bytes){NULL, 0};
}

/* The PIN or pairing code of reference as ASCII digits. */
static TC_bytes secret(uint8_t reference, uint8_t out[8])
{
  const tc_card_reference* data = tc_card_fixture_reference(&fixture, reference);
  munit_assert_not_null(data);
  size_t length = 0;
  while (length < 8 && data->value[length] != 0xff)
    ++length;
  memcpy(out, data->value, length);
  return (TC_bytes){out, length};
}

static void pin_verify(void)
{
  uint8_t pin[8];
  TC_PIV_reference_status status;
  munit_assert_int(TC_PIV_pin_verify(&link, 0x80, secret(0x80, pin), 3, &status), ==, TC_PIV_OK);
}

static TC_status recorded_scalar(void* context, uint8_t* output, size_t length)
{
  (void)context;
  munit_assert_size(length, ==, recorded->scalar.length);
  memcpy(output, recorded->scalar.data, length);
  return TC_OK;
}

/* Read 5FC122 plain, as the inventory's copy under secure messaging must
 * match it (COPY_MATCH). */
static void plain_copy_read(void)
{
  static const uint8_t tag[] = {0x5f, 0xc1, 0x22};
  TC_PIV_data_object object;
  munit_assert_int(TC_PIV_get_data(&link, (TC_bytes){tag, sizeof tag},
                                   (TC_buffer){copy_bytes, COPY_BYTES}, &object),
                   ==, TC_PIV_OK);
  memset(&plain_copy, 0, sizeof plain_copy);
  plain_copy.info =
      TC_PIV_catalog_find(TC_PIV_APPLICATION_PIV, TC_PIV_CARD, (TC_bytes){tag, sizeof tag});
  plain_copy.encoded = object.encoded;
  plain_copy.value = object.value;
  plain_copy.status = object.status;
  plain_copy.state = TC_PIV_OBJECT_PRESENT;
}

/* Secure the contactless link with the recorded key establishment, keep the
 * card CVC and establish the VCI with the pairing code. */
static void link_secure_vci(void)
{
  TC_PIV_SM_peer peer;
  TC_PIV_CVC cvc;
  TC_PIV_discovery discovery;
  TC_PIV_vci_mode mode;
  uint8_t pairing[8];
  recorded = &fixture.sessions[0];
  memset(&session, 0, sizeof session);
  munit_assert_int(TC_PIV_SM_key_request(&link, &session, (TC_PIV_SM_suite)recorded->suite,
                                         recorded->host_id.data,
                                         (TC_random_source){recorded_scalar, NULL},
                                         response_buffer(), &peer, &sm_workspace),
                   ==, TC_PIV_OK);
  munit_assert_size(peer.certificate.length, <=, sizeof card_cvc);
  memcpy(card_cvc, peer.certificate.data, peer.certificate.length);
  sm_card_cvc = (TC_bytes){card_cvc, peer.certificate.length};
  munit_assert_int(TC_PIV_CVC_read(peer.certificate, &cvc), ==, TC_TLV_OK);
  munit_assert_int(TC_PIV_SM_finish(&session, &peer, cvc.public_key, &sm_workspace), ==, TC_OK);
  munit_assert_int(
      TC_PIV_link_secure(&link, &sm_workspace, (TC_buffer){sm_scratch, sizeof sm_scratch}), ==,
      TC_PIV_OK);
  munit_assert_int(TC_PIV_discovery_get(&link, TC_PIV_DISCOVERY_PIV, response_buffer(), &discovery),
                   ==, TC_PIV_OK);
  munit_assert_int(TC_PIV_vci_establish(&link, &discovery, secret(0x98, pairing), &mode), ==,
                   TC_PIV_OK);
}

static void inventory_read(void)
{
  memset(&inventory, 0, sizeof inventory);
  inventory.objects = objects;
  inventory.capacity = CATALOG;
  size_t work = SIZE_MAX;
  munit_assert_int(
      TC_PIV_inventory_read(&link, NULL, (TC_buffer){pool, sizeof pool}, &work, &inventory), ==,
      TC_PIV_OK);
}

/* ---- Trust ---- */

static TC_bytes vector(const char* name, uint8_t bytes[FIXTURE_FILE_BYTES])
{
  char path[512];
  munit_assert_int(snprintf(path, sizeof path, "%s/%s", TC_VECTOR_DIR, name), >, 0);
  return fixture_read(path, bytes);
}

typedef enum { EVIDENCE_NONE, EVIDENCE_OCSP, EVIDENCE_CRLS, EVIDENCE_ALL } evidence_kind;

/* Card 2: the RSA 3072 CA pins the card certificates and the CHUID signer,
 * the ECC P-384 CA the secure messaging signer. */
static void card2_trust(evidence_kind evidence, TC_validation_revocation policy)
{
  const TC_bytes rsa = vector("x509/ocsp/sd33/card01_issuer.der", issuer_bytes[0]);
  const TC_bytes p384 = vector("x509/ocsp/sd33/card04_issuer.der", issuer_bytes[1]);
  const TC_bytes crls[] = {vector("x509/crl/sd33/RSA3072IssuingCA.crl", crl_bytes[0]),
                           vector("x509/crl/sd33/ECCP384IssuingCA.crl", crl_bytes[1])};
  const int with_crls = evidence == EVIDENCE_CRLS || evidence == EVIDENCE_ALL;
  const TC_bytes card_anchors[] = {rsa};
  const validation_fixture_trust card_inputs = {card_anchors,     1, card_anchors, 1, crls,
                                                with_crls ? 1 : 0};
  validation_fixture_init_trust(&card_trust, &card_inputs, at, policy);
  const TC_bytes content_anchors[] = {rsa, p384};
  const validation_fixture_trust content_inputs = {content_anchors,  2, content_anchors, 2, crls,
                                                   with_crls ? 2 : 0};
  validation_fixture_init_trust(&content_trust, &content_inputs, at, policy);
  memset(&ocsp, 0, sizeof ocsp);
  ocsp.max_responses = 16;
  ocsp.max_certificates = 4;
  if (evidence == EVIDENCE_OCSP || evidence == EVIDENCE_ALL) {
    /* One response covers both card certificates of the issuer. */
    const TC_bytes response = vector("x509/ocsp/sd33/card01_response.der", ocsp_bytes);
    ocsp.responses[TC_PIV_CARD_SLOT_PIV_AUTHENTICATION] = response;
    ocsp.responses[TC_PIV_CARD_SLOT_CARD_AUTHENTICATION] = response;
  }
}

/* Card 4: the ECC P-256 CA pins everything. */
static void card4_trust(void)
{
  const TC_bytes p256 = vector("x509/ocsp/sd33/card03_issuer.der", issuer_bytes[2]);
  const TC_bytes crl = vector("x509/crl/sd33/ECCP256IssuingCA.crl", crl_bytes[2]);
  const validation_fixture_trust inputs = {&p256, 1, &p256, 1, &crl, 1};
  validation_fixture_init_trust(&card_trust, &inputs, at, TC_VALIDATION_REVOCATION_REQUIRED);
  validation_fixture_init_trust(&content_trust, &inputs, at, TC_VALIDATION_REVOCATION_REQUIRED);
  memset(&ocsp, 0, sizeof ocsp);
  ocsp.max_responses = 16;
  ocsp.max_certificates = 4;
  const TC_bytes response = vector("x509/ocsp/sd33/card03_response.der", ocsp_bytes);
  ocsp.responses[TC_PIV_CARD_SLOT_PIV_AUTHENTICATION] = response;
  ocsp.responses[TC_PIV_CARD_SLOT_CARD_AUTHENTICATION] = response;
}

/* ---- Check runs ---- */

static TC_PIV_card_check_request check_request(void)
{
  TC_PIV_card_check_request request;
  memset(&request, 0, sizeof request);
  request.inventory = &inventory;
  request.link = &link;
  request.profile = TC_PIV_CARD;
  request.card = &card_trust.context;
  request.content = &content_trust.context;
  request.ocsp = &ocsp;
  request.sm_card_cvc = sm_card_cvc;
  return request;
}

static TC_PIV_result check_run(const TC_PIV_card_check_request* request)
{
  workspace.certificates = (TC_buffer){certificate_storage, sizeof certificate_storage};
  workspace.lds_content = (TC_buffer){lds_storage, sizeof lds_storage};
  size_t work = CHECK_WORK;
  memset(&report, 0xa5, sizeof report);
  return TC_PIV_card_check(request, &workspace, &work, &report);
}

static const TC_PIV_check* find(uint8_t kind, uint16_t container, uint8_t key)
{
  const TC_PIV_check_requirement requirement = {kind, key, container};
  return TC_PIV_card_report_find(&report, &requirement);
}

static void expect(uint8_t kind, uint16_t container, uint8_t outcome, uint8_t reason)
{
  const TC_PIV_check* check = find(kind, container, 0);
  if (!check)
    munit_errorf("no check kind %u container %04x", kind, container);
  if (check->outcome != outcome || check->reason != reason)
    munit_errorf("check kind %u container %04x: outcome %u reason %u status %d, expected %u %u",
                 kind, container, check->outcome, check->reason, (int)check->status, outcome,
                 reason);
}

static void expect_passed(uint8_t kind, uint16_t container)
{
  expect(kind, container, TC_PIV_CHECK_PASSED, TC_PIV_REASON_NONE);
}

/* 1 when the entry is one of exceptions. */
static int excepted(const TC_PIV_check* check, const TC_PIV_check_requirement* exceptions,
                    size_t count)
{
  for (size_t i = 0; i < count; ++i)
    if (check->kind == exceptions[i].kind && check->container == exceptions[i].container)
      return 1;
  return 0;
}

/* Every entry PASSED except those listed. */
static void expect_all_passed(const TC_PIV_check_requirement* exceptions, size_t count)
{
  munit_assert_size(report.count, >, 0);
  for (size_t i = 0; i < report.count; ++i) {
    const TC_PIV_check* check = &report.checks[i];
    if (excepted(check, exceptions, count))
      continue;
    /* The captured SD 33 cards omit the present BIT group from the Security
     * Object. Its unauthenticated bytes cannot establish consistency. */
    if (check->kind == TC_PIV_CHECK_DISCOVERY_CONSISTENCY && check->container == 0x6050 &&
        check->outcome == TC_PIV_CHECK_NOT_CHECKABLE && check->reason == TC_PIV_REASON_DEPENDENCY)
      continue;
    if (check->outcome != TC_PIV_CHECK_PASSED)
      munit_errorf("check %zu kind %u container %04x key %02x: outcome %u reason %u status %d", i,
                   check->kind, check->container, check->key_reference, check->outcome,
                   check->reason, (int)check->status);
  }
}

/* Mapped containers of the card 2 Security Object. */
static const uint16_t card2_mapped[] = {0xdb00, 0x3000, 0x6010, 0x3001, 0x6030, 0x6050, 0x6060};

static const TC_PIV_check_requirement iris_only[] = {{TC_PIV_CHECK_BIOMETRIC, 0, 0x1015},
                                                     {TC_PIV_CHECK_SM_CVC, 0, 0x1017}};
static const TC_PIV_check_requirement card2_exceptions[] = {
    {TC_PIV_CHECK_BIOMETRIC, 0, 0x1015},
    {TC_PIV_CHECK_SM_CVC, 0, 0x1017},
    {TC_PIV_CHECK_DISCOVERY_CONSISTENCY, 0, 0x6050}};

static void expect_card2_complete(void)
{
  static const uint16_t mandatory[] = {0xdb00, 0x3000, 0x0101, 0x6010, 0x9000, 0x6030, 0x0500};
  for (size_t i = 0; i < sizeof mandatory / sizeof *mandatory; ++i)
    expect_passed(TC_PIV_CHECK_MANDATORY_OBJECT, mandatory[i]);
  static const uint16_t certificates[] = {0x0500, 0x0101, 0x0100, 0x0102};
  for (size_t i = 0; i < 4; ++i) {
    expect_passed(TC_PIV_CHECK_CERTIFICATE_PATH, certificates[i]);
    expect_passed(TC_PIV_CHECK_REVOCATION, certificates[i]);
  }
  expect_passed(TC_PIV_CHECK_CERTIFICATE_IDENTIFIERS, 0x0500);
  expect_passed(TC_PIV_CHECK_CERTIFICATE_IDENTIFIERS, 0x0101);
  expect_passed(TC_PIV_CHECK_CHUID, 0x3000);
  expect_passed(TC_PIV_CHECK_REVOCATION, 0x3000);
  expect_passed(TC_PIV_CHECK_SECURITY_SIGNATURE, 0x9000);
  expect_passed(TC_PIV_CHECK_REVOCATION, 0x9000);
  for (size_t i = 0; i < sizeof card2_mapped / sizeof *card2_mapped; ++i)
    expect_passed(TC_PIV_CHECK_SECURITY_DIGEST, card2_mapped[i]);
  expect_passed(TC_PIV_CHECK_BIOMETRIC, 0x6010);
  expect_passed(TC_PIV_CHECK_BIOMETRIC, 0x6030);
  expect(TC_PIV_CHECK_BIOMETRIC, 0x1015, TC_PIV_CHECK_NOT_CHECKABLE, TC_PIV_REASON_UNSUPPORTED);
  expect_passed(TC_PIV_CHECK_PRINTED_EXPIRATION, 0x3001);
  /* The card's Security Object hashes Discovery but omits the present BIT
   * group, so consistency cannot rely on the BIT bytes. */
  expect(TC_PIV_CHECK_DISCOVERY_CONSISTENCY, 0x6050, TC_PIV_CHECK_NOT_CHECKABLE,
         TC_PIV_REASON_DEPENDENCY);
  expect_passed(TC_PIV_CHECK_SM_SIGNER, 0x1017);
  expect_passed(TC_PIV_CHECK_REVOCATION, 0x1017);
  for (size_t i = 0; i < TC_PIV_CARD_CERTIFICATES; ++i)
    munit_assert_uint8(report.certificate_valid[i], ==, 1);
  munit_assert_uint8(report.has_card, ==, 1);
  munit_assert_uint8(report.has_chuid, ==, 1);
  munit_assert_uint8(report.has_security, ==, 1);
  munit_assert_int(report.profile, ==, TC_PIV_CARD);
  munit_assert_int(report.application, ==, TC_PIV_APPLICATION_PIV);
  expect_all_passed(card2_exceptions, 3);
}

/* ---- Key proofs ---- */

/* Digests the random source returns in order. */
static struct {
  const uint8_t* digests[3];
  size_t lengths[3], count, calls;
} entropy;

static TC_status queued_digest(void* context, uint8_t* output, size_t length)
{
  (void)context;
  munit_assert_size(entropy.calls, <, entropy.count);
  munit_assert_size(length, ==, entropy.lengths[entropy.calls]);
  memcpy(output, entropy.digests[entropy.calls], length);
  ++entropy.calls;
  return TC_OK;
}

static TC_X509_signature_provider native_provider(void)
{
  static TC_RSA_workspace rsa;
  static TC_X509_native_workspace native;
  rsa = (TC_RSA_workspace){proof_words, sizeof proof_words / sizeof *proof_words};
  native = (TC_X509_native_workspace){&proof_ec, &rsa, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  return TC_X509_native_provider(&native);
}

/* Prove 9A then 9E on card 2 with the recorded challenges. */
static TC_PIV_result card2_prove(unsigned keys)
{
  memset(&entropy, 0, sizeof entropy);
  if (keys & TC_PIV_CARD_PROVE_PIV_AUTHENTICATION) {
    entropy.digests[entropy.count] = card2_digest_9a;
    entropy.lengths[entropy.count++] = 32;
  }
  if (keys & TC_PIV_CARD_PROVE_CARD_AUTHENTICATION) {
    entropy.digests[entropy.count] = card2_digest_9e;
    entropy.lengths[entropy.count++] = 32;
  }
  const TC_X509_signature_provider provider = native_provider();
  const TC_PIV_card_proof_request request = {
      keys, {TC_PIV_CARD, at, TC_PIV_RSA_PKCS1_V15, 0}, {queued_digest, NULL}, &provider};
  TC_work_budget work = {UINT32_MAX};
  return TC_PIV_card_prove_keys(&link, &request, &proof_workspace, &work, &report);
}

/* ---- Tests ---- */

/* Card 2 on contact with the PIN and full evidence: every check passes
 * except iris, and SM_CVC has no session. Both proofs pass, and the
 * baseline requirements accept the card. */
TC_TEST(card2_contact)
{
  load("sd33_card2");
  card2_trust(EVIDENCE_ALL, TC_VALIDATION_REVOCATION_REQUIRED);
  link_open(TC_PIV_CONTACT);
  pin_verify();
  inventory_read();
  const TC_PIV_card_check_request request = check_request();
  munit_assert_int(check_run(&request), ==, TC_PIV_OK);
  expect_card2_complete();
  expect(TC_PIV_CHECK_SM_CVC, 0x1017, TC_PIV_CHECK_NOT_CHECKABLE, TC_PIV_REASON_NOT_REQUESTED);
  munit_assert_int(
      card2_prove(TC_PIV_CARD_PROVE_PIV_AUTHENTICATION | TC_PIV_CARD_PROVE_CARD_AUTHENTICATION), ==,
      TC_PIV_OK);
  munit_assert_size(entropy.calls, ==, 2);
  const TC_PIV_check_requirement baseline[] = {{TC_PIV_CHECK_CERTIFICATE_PATH, 0x9e, 0},
                                               {TC_PIV_CHECK_REVOCATION, 0, 0x0500},
                                               {TC_PIV_CHECK_KEY_PROOF, 0x9e, 0},
                                               {TC_PIV_CHECK_KEY_PROOF, 0x9a, 0},
                                               {TC_PIV_CHECK_CHUID, 0, 0},
                                               {TC_PIV_CHECK_SECURITY_DIGEST, 0, 0}};
  munit_assert_int(TC_PIV_card_report_accepts(&report, baseline, 6), ==, 1);
  /* SM_CVC is NOT_CHECKABLE on contact. */
  const TC_PIV_check_requirement sm[] = {{TC_PIV_CHECK_SM_CVC, 0, 0}};
  munit_assert_int(TC_PIV_card_report_accepts(&report, sm, 1), ==, 0);
  /* Every entry matches kind 0 with any container, and iris fails it. */
  const TC_PIV_check_requirement biometrics[] = {{TC_PIV_CHECK_BIOMETRIC, 0, 0}};
  munit_assert_int(TC_PIV_card_report_accepts(&report, biometrics, 1), ==, 0);
  munit_assert_size(card.violations, ==, 0);
  TC_PIV_inventory_clear(&inventory);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* Card 2 on contactless under secure messaging with the VCI and the PIN:
 * SM_CVC and COPY_MATCH pass. After unsecure, SM_CVC is RESTRICTED. A
 * changed CVC byte fails SM_CVC only. */
TC_TEST(card2_contactless)
{
  load("sd33_card2");
  card2_trust(EVIDENCE_ALL, TC_VALIDATION_REVOCATION_REQUIRED);
  link_open(TC_PIV_CONTACTLESS);
  plain_copy_read();
  link_secure_vci();
  pin_verify();
  inventory_read();
  TC_PIV_card_check_request request = check_request();
  request.plain_copies = &plain_copy;
  request.plain_copy_count = 1;
  munit_assert_int(check_run(&request), ==, TC_PIV_OK);
  expect_card2_complete();
  expect_passed(TC_PIV_CHECK_SM_CVC, 0x1017);
  expect_passed(TC_PIV_CHECK_COPY_MATCH, 0x1017);
  munit_assert_int(
      card2_prove(TC_PIV_CARD_PROVE_PIV_AUTHENTICATION | TC_PIV_CARD_PROVE_CARD_AUTHENTICATION), ==,
      TC_PIV_OK);
  const TC_PIV_check_requirement secured[] = {{TC_PIV_CHECK_SM_SIGNER, 0, 0},
                                              {TC_PIV_CHECK_SM_CVC, 0, 0},
                                              {TC_PIV_CHECK_COPY_MATCH, 0, 0},
                                              {TC_PIV_CHECK_KEY_PROOF, 0, 0}};
  munit_assert_int(TC_PIV_card_report_accepts(&report, secured, 4), ==, 1);

  card_cvc[sm_card_cvc.length - 1] ^= 1;
  munit_assert_int(check_run(&request), ==, TC_PIV_OK);
  expect(TC_PIV_CHECK_SM_CVC, 0x1017, TC_PIV_CHECK_FAILED, TC_PIV_REASON_NONE);
  expect_card2_complete();
  card_cvc[sm_card_cvc.length - 1] ^= 1;

  /* A different plain copy fails COPY_MATCH. */
  copy_bytes[plain_copy.encoded.length - 1] ^= 1;
  munit_assert_int(check_run(&request), ==, TC_PIV_OK);
  expect(TC_PIV_CHECK_COPY_MATCH, 0x1017, TC_PIV_CHECK_FAILED, TC_PIV_REASON_NONE);
  copy_bytes[plain_copy.encoded.length - 1] ^= 1;

  TC_PIV_link_unsecure(&link);
  munit_assert_int(check_run(&request), ==, TC_PIV_OK);
  expect(TC_PIV_CHECK_SM_CVC, 0x1017, TC_PIV_CHECK_NOT_CHECKABLE, TC_PIV_REASON_RESTRICTED);
  /* Without the VCI the link refuses 9A on contactless before drawing a
   * challenge (Part 1 Table 5), and 9E still proves in plaintext. The
   * retained certificates stay usable. */
  munit_assert_int(card2_prove(TC_PIV_CARD_PROVE_PIV_AUTHENTICATION), ==, TC_PIV_OK);
  munit_assert_size(entropy.calls, ==, 0);
  expect(TC_PIV_CHECK_KEY_PROOF, 0x0101, TC_PIV_CHECK_NOT_CHECKABLE, TC_PIV_REASON_RESTRICTED);
  munit_assert_int(card2_prove(TC_PIV_CARD_PROVE_CARD_AUTHENTICATION), ==, TC_PIV_OK);
  munit_assert_size(entropy.calls, ==, 1);
  expect_passed(TC_PIV_CHECK_KEY_PROOF, 0x0500);
  const TC_PIV_check_requirement card_auth[] = {{TC_PIV_CHECK_KEY_PROOF, 0x9e, 0}};
  munit_assert_int(TC_PIV_card_report_accepts(&report, card_auth, 1), ==, 1);
  const TC_PIV_check_requirement piv_auth[] = {{TC_PIV_CHECK_KEY_PROOF, 0x9a, 0}};
  munit_assert_int(TC_PIV_card_report_accepts(&report, piv_auth, 1), ==, 0);
  request.link = NULL;
  munit_assert_int(check_run(&request), ==, TC_PIV_OK);
  expect(TC_PIV_CHECK_SM_CVC, 0x1017, TC_PIV_CHECK_NOT_CHECKABLE, TC_PIV_REASON_RESTRICTED);
  munit_assert_size(card.violations, ==, 0);
  TC_PIV_inventory_clear(&inventory);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* Without the PIN the PIN-gated objects are RESTRICTED: their digests,
 * biometrics and the printed check are NOT_CHECKABLE, while the CHUID, the
 * signature and the other digests pass. A 9E requirement still accepts. */
TC_TEST(card2_without_pin)
{
  static const uint16_t gated[] = {0x6010, 0x3001, 0x6030};
  load("sd33_card2");
  card2_trust(EVIDENCE_ALL, TC_VALIDATION_REVOCATION_REQUIRED);
  link_open(TC_PIV_CONTACT);
  inventory_read();
  const TC_PIV_card_check_request request = check_request();
  munit_assert_int(check_run(&request), ==, TC_PIV_OK);
  expect_passed(TC_PIV_CHECK_CHUID, 0x3000);
  expect_passed(TC_PIV_CHECK_SECURITY_SIGNATURE, 0x9000);
  for (size_t i = 0; i < sizeof card2_mapped / sizeof *card2_mapped; ++i) {
    int restricted = 0;
    for (size_t j = 0; j < sizeof gated / sizeof *gated; ++j)
      restricted |= card2_mapped[i] == gated[j];
    if (restricted)
      expect(TC_PIV_CHECK_SECURITY_DIGEST, card2_mapped[i], TC_PIV_CHECK_NOT_CHECKABLE,
             TC_PIV_REASON_RESTRICTED);
    else
      expect_passed(TC_PIV_CHECK_SECURITY_DIGEST, card2_mapped[i]);
  }
  for (size_t i = 0; i < sizeof gated / sizeof *gated; ++i)
    if (gated[i] != 0x3001)
      expect(TC_PIV_CHECK_MANDATORY_OBJECT, gated[i], TC_PIV_CHECK_NOT_CHECKABLE,
             TC_PIV_REASON_RESTRICTED);
  expect(TC_PIV_CHECK_BIOMETRIC, 0x6010, TC_PIV_CHECK_NOT_CHECKABLE, TC_PIV_REASON_RESTRICTED);
  expect(TC_PIV_CHECK_BIOMETRIC, 0x6030, TC_PIV_CHECK_NOT_CHECKABLE, TC_PIV_REASON_RESTRICTED);
  expect(TC_PIV_CHECK_PRINTED_EXPIRATION, 0x3001, TC_PIV_CHECK_NOT_CHECKABLE,
         TC_PIV_REASON_RESTRICTED);
  munit_assert_int(card2_prove(TC_PIV_CARD_PROVE_CARD_AUTHENTICATION), ==, TC_PIV_OK);
  const TC_PIV_check_requirement card_auth[] = {{TC_PIV_CHECK_KEY_PROOF, 0x9e, 0},
                                                {TC_PIV_CHECK_CERTIFICATE_PATH, 0x9e, 0},
                                                {TC_PIV_CHECK_CHUID, 0, 0}};
  munit_assert_int(TC_PIV_card_report_accepts(&report, card_auth, 3), ==, 1);
  const TC_PIV_check_requirement face[] = {{TC_PIV_CHECK_BIOMETRIC, 0, 0x6030}};
  munit_assert_int(TC_PIV_card_report_accepts(&report, face, 1), ==, 0);
  TC_PIV_inventory_clear(&inventory);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* Missing evidence. Without CRLs under REQUIRED, OCSP still covers the card
 * certificates, the CHUID signer has no evidence and the signed objects
 * depend on the CHUID. Under WHEN_AVAILABLE they pass and REVOCATION says
 * NO_EVIDENCE. With no evidence at all, REQUIRED stops at 9E. */
TC_TEST(card2_evidence)
{
  load("sd33_card2");
  link_open(TC_PIV_CONTACT);
  pin_verify();
  inventory_read();
  const TC_PIV_card_check_request request = check_request();

  card2_trust(EVIDENCE_OCSP, TC_VALIDATION_REVOCATION_REQUIRED);
  munit_assert_int(check_run(&request), ==, TC_PIV_OK);
  expect_passed(TC_PIV_CHECK_CERTIFICATE_PATH, 0x0500);
  expect_passed(TC_PIV_CHECK_REVOCATION, 0x0500);
  expect_passed(TC_PIV_CHECK_CERTIFICATE_IDENTIFIERS, 0x0500);
  expect(TC_PIV_CHECK_REVOCATION, 0x0100, TC_PIV_CHECK_NOT_CHECKABLE, TC_PIV_REASON_NO_EVIDENCE);
  munit_assert_uint8(report.certificate_valid[TC_PIV_CARD_SLOT_DIGITAL_SIGNATURE], ==, 0);
  munit_assert_uint8(report.certificate_valid[TC_PIV_CARD_SLOT_CARD_AUTHENTICATION], ==, 1);
  expect(TC_PIV_CHECK_CHUID, 0x3000, TC_PIV_CHECK_NOT_CHECKABLE, TC_PIV_REASON_NO_EVIDENCE);
  expect(TC_PIV_CHECK_REVOCATION, 0x3000, TC_PIV_CHECK_NOT_CHECKABLE, TC_PIV_REASON_NO_EVIDENCE);
  expect(TC_PIV_CHECK_SECURITY_SIGNATURE, 0x9000, TC_PIV_CHECK_NOT_CHECKABLE,
         TC_PIV_REASON_DEPENDENCY);
  expect(TC_PIV_CHECK_SECURITY_DIGEST, 0x6010, TC_PIV_CHECK_NOT_CHECKABLE,
         TC_PIV_REASON_DEPENDENCY);
  expect(TC_PIV_CHECK_BIOMETRIC, 0x6030, TC_PIV_CHECK_NOT_CHECKABLE, TC_PIV_REASON_DEPENDENCY);
  expect(TC_PIV_CHECK_CERTIFICATE_IDENTIFIERS, 0x0101, TC_PIV_CHECK_NOT_CHECKABLE,
         TC_PIV_REASON_DEPENDENCY);
  expect(TC_PIV_CHECK_SM_SIGNER, 0x1017, TC_PIV_CHECK_NOT_CHECKABLE, TC_PIV_REASON_NO_EVIDENCE);
  munit_assert_uint8(report.has_chuid, ==, 0);

  card2_trust(EVIDENCE_NONE, TC_VALIDATION_REVOCATION_WHEN_AVAILABLE);
  munit_assert_int(check_run(&request), ==, TC_PIV_OK);
  static const TC_PIV_check_requirement unchecked[] = {
      {TC_PIV_CHECK_REVOCATION, 0, 0x0500}, {TC_PIV_CHECK_REVOCATION, 0, 0x0101},
      {TC_PIV_CHECK_REVOCATION, 0, 0x0100}, {TC_PIV_CHECK_REVOCATION, 0, 0x0102},
      {TC_PIV_CHECK_REVOCATION, 0, 0x3000}, {TC_PIV_CHECK_REVOCATION, 0, 0x9000},
      {TC_PIV_CHECK_REVOCATION, 0, 0x1017}, {TC_PIV_CHECK_BIOMETRIC, 0, 0x1015},
      {TC_PIV_CHECK_SM_CVC, 0, 0x1017}};
  for (size_t i = 0; i < 7; ++i)
    expect(TC_PIV_CHECK_REVOCATION, unchecked[i].container, TC_PIV_CHECK_NOT_CHECKABLE,
           TC_PIV_REASON_NO_EVIDENCE);
  expect_all_passed(unchecked, sizeof unchecked / sizeof *unchecked);
  munit_assert_uint8(report.certificate_valid[TC_PIV_CARD_SLOT_DIGITAL_SIGNATURE], ==, 1);
  const TC_PIV_check_requirement revocation[] = {{TC_PIV_CHECK_REVOCATION, 0, 0}};
  munit_assert_int(TC_PIV_card_report_accepts(&report, revocation, 1), ==, 0);

  card2_trust(EVIDENCE_NONE, TC_VALIDATION_REVOCATION_REQUIRED);
  munit_assert_int(check_run(&request), ==, TC_PIV_OK);
  expect_passed(TC_PIV_CHECK_CERTIFICATE_PATH, 0x0500);
  expect(TC_PIV_CHECK_REVOCATION, 0x0500, TC_PIV_CHECK_NOT_CHECKABLE, TC_PIV_REASON_NO_EVIDENCE);
  expect(TC_PIV_CHECK_CERTIFICATE_IDENTIFIERS, 0x0500, TC_PIV_CHECK_NOT_CHECKABLE,
         TC_PIV_REASON_DEPENDENCY);
  expect(TC_PIV_CHECK_CHUID, 0x3000, TC_PIV_CHECK_NOT_CHECKABLE, TC_PIV_REASON_DEPENDENCY);
  munit_assert_uint8(report.has_card, ==, 0);
  munit_assert_int(card2_prove(TC_PIV_CARD_PROVE_CARD_AUTHENTICATION), ==, TC_PIV_OK);
  expect(TC_PIV_CHECK_KEY_PROOF, 0, TC_PIV_CHECK_NOT_CHECKABLE, TC_PIV_REASON_DEPENDENCY);
  munit_assert_size(entropy.calls, ==, 0);
  TC_PIV_inventory_clear(&inventory);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* A TWIC reader may use either listed PIV/TWIC OID pair from either card
 * application (TWIC Part 2 v5 section 6). Keep this OCSP case separate from
 * the PIV policy case above so the TWIC-compatible EKU policy is exercised
 * with authenticated revocation evidence. */
TC_TEST(card2_twic_ocsp_policy)
{
  load("sd33_card2");
  link_open(TC_PIV_CONTACT);
  pin_verify();
  inventory_read();
  card2_trust(EVIDENCE_OCSP, TC_VALIDATION_REVOCATION_REQUIRED);
  TC_PIV_card_check_request request = check_request();
  request.profile = TC_TWIC_LEGACY_CARD;
  munit_assert_int(check_run(&request), ==, TC_PIV_OK);
  expect_passed(TC_PIV_CHECK_CERTIFICATE_PATH, 0x0500);
  expect_passed(TC_PIV_CHECK_REVOCATION, 0x0500);
  /* This PIV sample's identifier values do not satisfy the TWIC card profile;
   * that independent check must not erase the valid path and OCSP result. */
  expect(TC_PIV_CHECK_CERTIFICATE_IDENTIFIERS, 0x0500, TC_PIV_CHECK_FAILED, TC_PIV_REASON_NONE);
  munit_assert_uint8(report.certificate_valid[TC_PIV_CARD_SLOT_CARD_AUTHENTICATION], ==, 1);
  munit_assert_uint8(report.has_card, ==, 0);
  munit_assert_int(report.profile, ==, TC_TWIC_LEGACY_CARD);
  munit_assert_int(report.application, ==, TC_PIV_APPLICATION_PIV);
  TC_PIV_inventory_clear(&inventory);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* Copy fixture object tag into override storage and flip one byte at
 * offset from its end. */
static TC_bytes tampered_object(uint32_t tag, size_t offset)
{
  const tc_card_object* object = tc_card_fixture_object(&fixture, tag);
  munit_assert_not_null(object);
  munit_assert_size(object->data.length, <=, sizeof override_bytes);
  memcpy(override_bytes, object->data.data, object->data.length);
  override_bytes[object->data.length - offset] ^= 1;
  return (TC_bytes){override_bytes, object->data.length};
}

static void card2_contact_inventory(void)
{
  pin_verify();
  inventory_read();
}

/* Card answers and changed bytes fail only the checks that cover them. */
TC_TEST(card2_failures)
{
  load("sd33_card2");
  card2_trust(EVIDENCE_ALL, TC_VALIDATION_REVOCATION_REQUIRED);
  const TC_PIV_card_check_request request = check_request();

  /* A mapped mandatory object answers 6A82: the object and its digest
   * fail, and the biometric has nothing to check. */
  link_open(TC_PIV_CONTACT);
  munit_assert_int(tc_card_simulator_override(&card, 0x5fc108, 0x6a82, (TC_bytes){NULL, 0}), ==, 1);
  card2_contact_inventory();
  munit_assert_int(check_run(&request), ==, TC_PIV_OK);
  expect(TC_PIV_CHECK_MANDATORY_OBJECT, 0x6030, TC_PIV_CHECK_FAILED, TC_PIV_REASON_ABSENT);
  munit_assert_uint16(find(TC_PIV_CHECK_MANDATORY_OBJECT, 0x6030, 0)->card_status, ==, 0x6a82);
  expect(TC_PIV_CHECK_SECURITY_DIGEST, 0x6030, TC_PIV_CHECK_FAILED, TC_PIV_REASON_ABSENT);
  expect(TC_PIV_CHECK_BIOMETRIC, 0x6030, TC_PIV_CHECK_NOT_CHECKABLE, TC_PIV_REASON_ABSENT);
  const TC_PIV_check_requirement face[] = {{TC_PIV_CHECK_MANDATORY_OBJECT, 0, 0x6030},
                                           {TC_PIV_CHECK_SECURITY_DIGEST, 0, 0x6030},
                                           {TC_PIV_CHECK_BIOMETRIC, 0, 0x6030},
                                           iris_only[0],
                                           iris_only[1]};
  expect_all_passed(face, 5);
  TC_PIV_inventory_clear(&inventory);

  /* A changed facial image byte fails its digest and its signature. */
  link_open(TC_PIV_CONTACT);
  munit_assert_int(
      tc_card_simulator_override(&card, 0x5fc108, 0x9000, tampered_object(0x5fc108, 40)), ==, 1);
  card2_contact_inventory();
  munit_assert_int(check_run(&request), ==, TC_PIV_OK);
  expect_passed(TC_PIV_CHECK_MANDATORY_OBJECT, 0x6030);
  expect(TC_PIV_CHECK_SECURITY_DIGEST, 0x6030, TC_PIV_CHECK_FAILED, TC_PIV_REASON_NONE);
  expect(TC_PIV_CHECK_BIOMETRIC, 0x6030, TC_PIV_CHECK_FAILED, TC_PIV_REASON_NONE);
  expect_all_passed(face + 1, 4);
  TC_PIV_inventory_clear(&inventory);

  /* A changed fingerprint byte fails its digest and its signature. */
  link_open(TC_PIV_CONTACT);
  munit_assert_int(
      tc_card_simulator_override(&card, 0x5fc103, 0x9000, tampered_object(0x5fc103, 600)), ==, 1);
  card2_contact_inventory();
  munit_assert_int(check_run(&request), ==, TC_PIV_OK);
  expect_passed(TC_PIV_CHECK_MANDATORY_OBJECT, 0x6010);
  expect(TC_PIV_CHECK_SECURITY_DIGEST, 0x6010, TC_PIV_CHECK_FAILED, TC_PIV_REASON_NONE);
  expect(TC_PIV_CHECK_BIOMETRIC, 0x6010, TC_PIV_CHECK_FAILED, TC_PIV_REASON_NONE);
  expect_passed(TC_PIV_CHECK_BIOMETRIC, 0x6030);
  const TC_PIV_check_requirement fingerprints[] = {{TC_PIV_CHECK_SECURITY_DIGEST, 0, 0x6010},
                                                   {TC_PIV_CHECK_BIOMETRIC, 0, 0x6010},
                                                   iris_only[0],
                                                   iris_only[1]};
  expect_all_passed(fingerprints, 4);
  TC_PIV_inventory_clear(&inventory);

  /* A changed CHUID fails the CHUID and its digest. The checks that need an
   * accepted CHUID depend on it. */
  link_open(TC_PIV_CONTACT);
  munit_assert_int(
      tc_card_simulator_override(&card, 0x5fc102, 0x9000, tampered_object(0x5fc102, 3)), ==, 1);
  card2_contact_inventory();
  munit_assert_int(check_run(&request), ==, TC_PIV_OK);
  expect(TC_PIV_CHECK_CHUID, 0x3000, TC_PIV_CHECK_FAILED, TC_PIV_REASON_NONE);
  expect(TC_PIV_CHECK_SECURITY_SIGNATURE, 0x9000, TC_PIV_CHECK_NOT_CHECKABLE,
         TC_PIV_REASON_DEPENDENCY);
  expect_passed(TC_PIV_CHECK_CERTIFICATE_PATH, 0x0500);
  expect_passed(TC_PIV_CHECK_SM_SIGNER, 0x1017);
  TC_PIV_inventory_clear(&inventory);

  /* An absent mandatory object that the map does not name fails only its
   * presence and the checks on it. */
  link_open(TC_PIV_CONTACT);
  munit_assert_int(tc_card_simulator_override(&card, 0x5fc105, 0x6a82, (TC_bytes){NULL, 0}), ==, 1);
  card2_contact_inventory();
  munit_assert_int(check_run(&request), ==, TC_PIV_OK);
  expect(TC_PIV_CHECK_MANDATORY_OBJECT, 0x0101, TC_PIV_CHECK_FAILED, TC_PIV_REASON_ABSENT);
  expect(TC_PIV_CHECK_CERTIFICATE_PATH, 0x0101, TC_PIV_CHECK_NOT_CHECKABLE, TC_PIV_REASON_ABSENT);
  munit_assert_uint8(report.certificate_valid[TC_PIV_CARD_SLOT_PIV_AUTHENTICATION], ==, 0);
  expect_passed(TC_PIV_CHECK_CHUID, 0x3000);
  munit_assert_int(card2_prove(TC_PIV_CARD_PROVE_PIV_AUTHENTICATION), ==, TC_PIV_OK);
  expect(TC_PIV_CHECK_KEY_PROOF, 0, TC_PIV_CHECK_NOT_CHECKABLE, TC_PIV_REASON_DEPENDENCY);
  TC_PIV_inventory_clear(&inventory);

  /* A nonempty BIT group omitted from the Security Object cannot be used to
   * decide Discovery consistency. */
  static const uint8_t bit_group[] = {0x7f, 0x61, 0x08, 0x02, 0x01, 0x01,
                                      0x7f, 0x60, 0x02, 0x01, 0x02};
  link_open(TC_PIV_CONTACT);
  munit_assert_int(
      tc_card_simulator_override(&card, 0x7f61, 0x9000, (TC_bytes){bit_group, sizeof bit_group}),
      ==, 1);
  card2_contact_inventory();
  munit_assert_int(check_run(&request), ==, TC_PIV_OK);
  expect(TC_PIV_CHECK_DISCOVERY_CONSISTENCY, 0x6050, TC_PIV_CHECK_NOT_CHECKABLE,
         TC_PIV_REASON_DEPENDENCY);
  TC_PIV_inventory_clear(&inventory);

  /* Without an authenticated Security Object the Discovery Object and the
   * BIT group have no integrity, so their consistency depends on it
   * (Part 1 sections 3.3.2 and 3.3.6). */
  link_open(TC_PIV_CONTACT);
  munit_assert_int(tc_card_simulator_override(&card, 0x5fc106, 0x6a82, (TC_bytes){NULL, 0}), ==, 1);
  card2_contact_inventory();
  munit_assert_int(check_run(&request), ==, TC_PIV_OK);
  expect(TC_PIV_CHECK_MANDATORY_OBJECT, 0x9000, TC_PIV_CHECK_FAILED, TC_PIV_REASON_ABSENT);
  expect(TC_PIV_CHECK_DISCOVERY_CONSISTENCY, 0x6050, TC_PIV_CHECK_NOT_CHECKABLE,
         TC_PIV_REASON_DEPENDENCY);
  expect(TC_PIV_CHECK_PRINTED_EXPIRATION, 0x3001, TC_PIV_CHECK_NOT_CHECKABLE,
         TC_PIV_REASON_DEPENDENCY);
  expect_passed(TC_PIV_CHECK_CHUID, 0x3000);
  TC_PIV_inventory_clear(&inventory);

  /* The PIV application of a TWIC card refuses contactless reads (TWIC Part 2
   * v5 4.2), so a denied mandatory object is NOT_CHECKABLE under a TWIC
   * profile and FAILED under the PIV profile. */
  link_open(TC_PIV_CONTACTLESS);
  munit_assert_int(tc_card_simulator_override(&card, 0x5fc102, 0x6982, (TC_bytes){NULL, 0}), ==, 1);
  inventory_read();
  TC_PIV_card_check_request twic = check_request();
  munit_assert_int(check_run(&twic), ==, TC_PIV_OK);
  expect(TC_PIV_CHECK_MANDATORY_OBJECT, 0x3000, TC_PIV_CHECK_FAILED, TC_PIV_REASON_DENIED);
  twic.profile = TC_TWIC_NEXGEN_CARD;
  munit_assert_int(check_run(&twic), ==, TC_PIV_OK);
  expect(TC_PIV_CHECK_MANDATORY_OBJECT, 0x3000, TC_PIV_CHECK_NOT_CHECKABLE, TC_PIV_REASON_DENIED);
  munit_assert_int(report.profile, ==, TC_TWIC_NEXGEN_CARD);
  expect(TC_PIV_CHECK_MANDATORY_OBJECT, 0x0101, TC_PIV_CHECK_NOT_CHECKABLE,
         TC_PIV_REASON_RESTRICTED);
  TC_PIV_inventory_clear(&inventory);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

static TC_status card4_digest(void* context, uint8_t* output, size_t length)
{
  const uint8_t* key = context;
  for (size_t i = 0; i < fixture.authentication_count; ++i) {
    const tc_card_authentication* entry = &fixture.authentications[i];
    if (entry->algorithm == TC_PIV_ALGORITHM_ECC_P256 && entry->key == *key && entry->tag == 0x81) {
      munit_assert_size(length, ==, entry->input.length);
      memcpy(output, entry->input.data, length);
      return TC_OK;
    }
  }
  return TC_ERROR;
}

/* Card 4 (CS2, P-256) on contactless under secure messaging with the VCI
 * and the PIN. */
TC_TEST(card4_contactless)
{
  load("sd33_card4");
  card4_trust();
  link_open(TC_PIV_CONTACTLESS);
  link_secure_vci();
  pin_verify();
  inventory_read();
  const TC_PIV_card_check_request request = check_request();
  munit_assert_int(check_run(&request), ==, TC_PIV_OK);
  expect_passed(TC_PIV_CHECK_CHUID, 0x3000);
  expect_passed(TC_PIV_CHECK_SECURITY_SIGNATURE, 0x9000);
  expect_passed(TC_PIV_CHECK_SM_SIGNER, 0x1017);
  expect_passed(TC_PIV_CHECK_SM_CVC, 0x1017);
  expect_all_passed(iris_only, 1);
  /* 9E with the recorded ECDSA input. */
  static const uint8_t key = 0x9e;
  const TC_X509_signature_provider provider = native_provider();
  const TC_PIV_card_proof_request proof = {TC_PIV_CARD_PROVE_CARD_AUTHENTICATION,
                                           {TC_PIV_CARD, at, TC_PIV_RSA_PKCS1_V15, 0},
                                           {card4_digest, (void*)&key},
                                           &provider};
  TC_work_budget work = {UINT32_MAX};
  munit_assert_int(TC_PIV_card_prove_keys(&link, &proof, &proof_workspace, &work, &report), ==,
                   TC_PIV_OK);
  expect_passed(TC_PIV_CHECK_KEY_PROOF, 0);
  munit_assert_true(tc_test_all_zero(&proof_workspace, sizeof proof_workspace));
  munit_assert_size(card.violations, ==, 0);
  TC_PIV_inventory_clear(&inventory);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* More entries than TC_PIV_CARD_CHECKS_MAX return LIMIT with the report
 * wiped. */
TC_TEST(report_limit)
{
  static TC_PIV_object copies[TC_PIV_CARD_CHECKS_MAX];
  load("sd33_card2");
  card2_trust(EVIDENCE_ALL, TC_VALIDATION_REVOCATION_REQUIRED);
  link_open(TC_PIV_CONTACT);
  inventory_read();
  const TC_PIV_object* ccc = TC_PIV_inventory_find(&inventory, 0xdb00);
  for (size_t i = 0; i < TC_PIV_CARD_CHECKS_MAX; ++i)
    copies[i] = *ccc;
  TC_PIV_card_check_request request = check_request();
  request.plain_copies = copies;
  request.plain_copy_count = 40;
  munit_assert_int(check_run(&request), ==, TC_PIV_OK);
  expect_passed(TC_PIV_CHECK_COPY_MATCH, 0xdb00);
  request.plain_copy_count = TC_PIV_CARD_CHECKS_MAX;
  munit_assert_int(check_run(&request), ==, TC_PIV_LIMIT);
  munit_assert_true(tc_test_all_zero(&report, sizeof report));
  TC_PIV_inventory_clear(&inventory);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* Exhausted work makes the checks that need it NOT_CHECKABLE/LIMIT and the
 * checks after them dependent. The report stays complete, and nothing
 * passes that needs a validator. */
TC_TEST(work_limit)
{
  load("sd33_card2");
  card2_trust(EVIDENCE_ALL, TC_VALIDATION_REVOCATION_REQUIRED);
  link_open(TC_PIV_CONTACT);
  pin_verify();
  inventory_read();
  const TC_PIV_card_check_request request = check_request();
  workspace.certificates = (TC_buffer){certificate_storage, sizeof certificate_storage};
  workspace.lds_content = (TC_buffer){lds_storage, sizeof lds_storage};
  size_t work = CHECK_WORK;
  munit_assert_int(TC_PIV_card_check(&request, &workspace, &work, &report), ==, TC_PIV_OK);
  const size_t used = CHECK_WORK - work;
  const size_t budgets[] = {0, used / 8, used / 2, used - 1};
  for (size_t b = 0; b < sizeof budgets / sizeof *budgets; ++b) {
    work = budgets[b];
    memset(&report, 0xa5, sizeof report);
    munit_assert_int(TC_PIV_card_check(&request, &workspace, &work, &report), ==, TC_PIV_OK);
    munit_assert_size(work, <=, budgets[b]);
    size_t limited = 0;
    for (size_t i = 0; i < report.count; ++i) {
      const TC_PIV_check* check = &report.checks[i];
      limited += check->reason == TC_PIV_REASON_LIMIT;
      if (check->outcome == TC_PIV_CHECK_FAILED)
        munit_errorf("budget %zu check %zu kind %u container %04x failed", budgets[b], i,
                     check->kind, check->container);
    }
    munit_assert_size(limited, >, 0);
    if (!budgets[b]) {
      expect(TC_PIV_CHECK_CERTIFICATE_PATH, 0x0500, TC_PIV_CHECK_NOT_CHECKABLE,
             TC_PIV_REASON_LIMIT);
      expect(TC_PIV_CHECK_CHUID, 0x3000, TC_PIV_CHECK_NOT_CHECKABLE, TC_PIV_REASON_DEPENDENCY);
      expect(TC_PIV_CHECK_SECURITY_SIGNATURE, 0x9000, TC_PIV_CHECK_NOT_CHECKABLE,
             TC_PIV_REASON_DEPENDENCY);
      expect_passed(TC_PIV_CHECK_MANDATORY_OBJECT, 0x9000);
      munit_assert_uint8(report.has_card, ==, 0);
    }
  }
  TC_PIV_inventory_clear(&inventory);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* Argument errors leave the report, the work counter and the workspace
 * unchanged. */
TC_TEST(arguments)
{
  TC_PIV_CHUID_profile chuid_profile = TC_CHUID_PROFILE_PIV;
  munit_assert_int(TC_PIV_card_chuid_profile(TC_PIV_APPLICATION_PIV, TC_PIV_CARD, &chuid_profile),
                   ==, TC_TLV_OK);
  munit_assert_int(chuid_profile, ==, TC_CHUID_PROFILE_PIV);
  munit_assert_int(
      TC_PIV_card_chuid_profile(TC_PIV_APPLICATION_PIV, TC_TWIC_LEGACY_CARD, &chuid_profile), ==,
      TC_TLV_OK);
  munit_assert_int(chuid_profile, ==, TC_CHUID_PROFILE_LEGACY_KEY_MAP);
  munit_assert_int(
      TC_PIV_card_chuid_profile(TC_PIV_APPLICATION_PIV, TC_TWIC_NEXGEN_CARD, &chuid_profile), ==,
      TC_TLV_OK);
  munit_assert_int(chuid_profile, ==, TC_CHUID_PROFILE_LEGACY_KEY_MAP);
  munit_assert_int(
      TC_PIV_card_chuid_profile(TC_PIV_APPLICATION_TWIC, TC_TWIC_NEXGEN_CARD, &chuid_profile), ==,
      TC_TLV_OK);
  munit_assert_int(chuid_profile, ==, TC_CHUID_PROFILE_TWIC_SIGNED);
  munit_assert_int(TC_PIV_card_chuid_profile(TC_PIV_APPLICATION_TWIC, TC_PIV_CARD, &chuid_profile),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_card_chuid_profile(TC_PIV_APPLICATION_PIV, TC_PIV_CARD, NULL), ==,
                   TC_TLV_ARGUMENT);
  load("sd33_card2");
  card2_trust(EVIDENCE_ALL, TC_VALIDATION_REVOCATION_REQUIRED);
  link_open(TC_PIV_CONTACT);
  inventory_read();
  workspace.certificates = (TC_buffer){certificate_storage, sizeof certificate_storage};
  workspace.lds_content = (TC_buffer){lds_storage, sizeof lds_storage};
  memset(&report, 0xa5, sizeof report);
  size_t work = CHECK_WORK;
  TC_PIV_card_check_request request = check_request();
  munit_assert_int(TC_PIV_card_check(NULL, &workspace, &work, &report), ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_card_check(&request, NULL, &work, &report), ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_card_check(&request, &workspace, NULL, &report), ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_card_check(&request, &workspace, &work, NULL), ==, TC_PIV_ARGUMENT);
  request.card = NULL;
  munit_assert_int(TC_PIV_card_check(&request, &workspace, &work, &report), ==, TC_PIV_ARGUMENT);
  request = check_request();
  request.profile = (TC_PIV_card_profile)7;
  munit_assert_int(TC_PIV_card_check(&request, &workspace, &work, &report), ==, TC_PIV_ARGUMENT);
  request = check_request();
  request.plain_copy_count = 1;
  munit_assert_int(TC_PIV_card_check(&request, &workspace, &work, &report), ==, TC_PIV_ARGUMENT);
  /* The contexts use different times. */
  request = check_request();
  content_trust.options.at.hour = 19;
  munit_assert_int(TC_PIV_card_check(&request, &workspace, &work, &report), ==, TC_PIV_ARGUMENT);
  content_trust.options.at.hour = 18;
  /* A TWIC application inventory under another profile. */
  TC_PIV_inventory twic = inventory;
  twic.link.application = TC_PIV_APPLICATION_TWIC;
  twic.link.profile = TC_TWIC_LEGACY_CARD;
  request.inventory = &twic;
  request.profile = TC_TWIC_NEXGEN_CARD;
  munit_assert_int(TC_PIV_card_check(&request, &workspace, &work, &report), ==, TC_PIV_ARGUMENT);
  request = check_request();
  twic = inventory;
  twic.count = 0;
  request.inventory = &twic;
  munit_assert_int(TC_PIV_card_check(&request, &workspace, &work, &report), ==, TC_PIV_ARGUMENT);
  twic = inventory;
  --twic.count;
  request.inventory = &twic;
  munit_assert_int(TC_PIV_card_check(&request, &workspace, &work, &report), ==, TC_PIV_ARGUMENT);
  TC_PIV_object altered[CATALOG];
  memcpy(altered, inventory.objects, sizeof altered);
  TC_PIV_object swapped = altered[0];
  altered[0] = altered[1];
  altered[1] = swapped;
  twic = inventory;
  twic.objects = altered;
  request.inventory = &twic;
  munit_assert_int(TC_PIV_card_check(&request, &workspace, &work, &report), ==, TC_PIV_ARGUMENT);
  memcpy(altered, inventory.objects, sizeof altered);
  TC_PIV_object_info forged = *altered[0].info;
  altered[0].info = &forged;
  request.inventory = &twic;
  munit_assert_int(TC_PIV_card_check(&request, &workspace, &work, &report), ==, TC_PIV_ARGUMENT);
  /* The report inside the inventory pool. */
  request = check_request();
  munit_assert_int(
      TC_PIV_card_check(&request, &workspace, &work, (TC_PIV_card_report*)(void*)(pool + 64)), ==,
      TC_PIV_ARGUMENT);
  /* The report over the link, a plain copy's bytes or an OCSP response. */
  static uint8_t overlap[sizeof(TC_PIV_card_report) + sizeof(TC_PIV_link)];
  TC_PIV_link* moved = (TC_PIV_link*)(void*)overlap;
  *moved = link;
  static uint8_t overlap_before[sizeof overlap];
  memcpy(overlap_before, overlap, sizeof overlap);
  request.link = moved;
  munit_assert_int(
      TC_PIV_card_check(&request, &workspace, &work, (TC_PIV_card_report*)(void*)overlap), ==,
      TC_PIV_ARGUMENT);
  request = check_request();
  TC_PIV_object copy = *TC_PIV_inventory_find(&inventory, 0xdb00);
  copy.encoded = (TC_bytes){overlap, 16};
  request.plain_copies = &copy;
  request.plain_copy_count = 1;
  munit_assert_int(
      TC_PIV_card_check(&request, &workspace, &work, (TC_PIV_card_report*)(void*)overlap), ==,
      TC_PIV_ARGUMENT);
  request = check_request();
  TC_PIV_card_check_ocsp inside = ocsp;
  inside.responses[0] = (TC_bytes){overlap + 8, 8};
  request.ocsp = &inside;
  munit_assert_int(
      TC_PIV_card_check(&request, &workspace, &work, (TC_PIV_card_report*)(void*)overlap), ==,
      TC_PIV_ARGUMENT);
  munit_assert_memory_equal(sizeof overlap, overlap, overlap_before);
  request = check_request();
  /* The LDS buffer inside the certificate buffer. */
  workspace.lds_content = (TC_buffer){certificate_storage + 64, 1024};
  munit_assert_int(TC_PIV_card_check(&request, &workspace, &work, &report), ==, TC_PIV_ARGUMENT);
  workspace.lds_content = (TC_buffer){lds_storage, sizeof lds_storage};
  munit_assert_size(work, ==, CHECK_WORK);
  munit_assert_true(tc_test_all_value(&report, sizeof report, 0xa5));

  /* Key proof arguments. */
  munit_assert_int(check_run(&request), ==, TC_PIV_OK);
  const TC_PIV_card_report before = report;
  const TC_X509_signature_provider provider = native_provider();
  TC_PIV_card_proof_request proof = {
      0, {TC_PIV_CARD, at, TC_PIV_RSA_PKCS1_V15, 0}, {queued_digest, NULL}, &provider};
  TC_work_budget budget = {UINT32_MAX};
  munit_assert_int(TC_PIV_card_prove_keys(&link, &proof, &proof_workspace, &budget, &report), ==,
                   TC_PIV_ARGUMENT);
  proof.keys = 1u << 5;
  munit_assert_int(TC_PIV_card_prove_keys(&link, &proof, &proof_workspace, &budget, &report), ==,
                   TC_PIV_ARGUMENT);
  proof.keys = TC_PIV_CARD_PROVE_CARD_AUTHENTICATION;
  proof.policy.profile = TC_TWIC_LEGACY_CARD;
  munit_assert_int(TC_PIV_card_prove_keys(&link, &proof, &proof_workspace, &budget, &report), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_card_prove_keys(NULL, &proof, &proof_workspace, &budget, &report), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_size(report.count, ==, before.count);
  for (size_t i = 0; i < before.count; ++i) {
    munit_assert_int(report.checks[i].status, ==, before.checks[i].status);
    munit_assert_uint16(report.checks[i].container, ==, before.checks[i].container);
    munit_assert_uint8(report.checks[i].kind, ==, before.checks[i].kind);
    munit_assert_uint8(report.checks[i].outcome, ==, before.checks[i].outcome);
  }
  munit_assert_uint32(budget.remaining, ==, UINT32_MAX);
  TC_PIV_inventory_clear(&inventory);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* Find and acceptance on a report written by hand. */
TC_TEST(accepts)
{
  memset(&report, 0, sizeof report);
  const TC_PIV_check passed = {
      TC_CREDENTIAL_VALID, 0x0500, 0, TC_PIV_CHECK_KEY_PROOF, TC_PIV_CHECK_PASSED,
      TC_PIV_REASON_NONE,  0x9e};
  const TC_PIV_check restricted = {
      TC_CREDENTIAL_UNAVAILABLE, 0x0101, 0, TC_PIV_CHECK_KEY_PROOF, TC_PIV_CHECK_NOT_CHECKABLE,
      TC_PIV_REASON_RESTRICTED,  0x9a};
  report.checks[0] = passed;
  report.checks[1] = restricted;
  report.count = 2;
  const TC_PIV_check_requirement card_auth = {TC_PIV_CHECK_KEY_PROOF, 0x9e, 0};
  const TC_PIV_check_requirement piv_auth = {TC_PIV_CHECK_KEY_PROOF, 0x9a, 0};
  const TC_PIV_check_requirement any = {TC_PIV_CHECK_KEY_PROOF, 0, 0};
  const TC_PIV_check_requirement container = {TC_PIV_CHECK_KEY_PROOF, 0, 0x0500};
  const TC_PIV_check_requirement missing = {TC_PIV_CHECK_CHUID, 0, 0};
  munit_assert_ptr_equal(TC_PIV_card_report_find(&report, &card_auth), &report.checks[0]);
  munit_assert_ptr_equal(TC_PIV_card_report_find(&report, &piv_auth), &report.checks[1]);
  munit_assert_ptr_equal(TC_PIV_card_report_find(&report, &container), &report.checks[0]);
  munit_assert_null(TC_PIV_card_report_find(&report, &missing));
  munit_assert_null(TC_PIV_card_report_find(NULL, &missing));
  munit_assert_null(TC_PIV_card_report_find(&report, NULL));
  munit_assert_int(TC_PIV_card_report_accepts(&report, &card_auth, 1), ==, 1);
  munit_assert_int(TC_PIV_card_report_accepts(&report, &container, 1), ==, 1);
  munit_assert_int(TC_PIV_card_report_accepts(&report, &piv_auth, 1), ==, 0);
  munit_assert_int(TC_PIV_card_report_accepts(&report, &any, 1), ==, 0);
  munit_assert_int(TC_PIV_card_report_accepts(&report, &missing, 1), ==, 0);
  munit_assert_int(TC_PIV_card_report_accepts(&report, &card_auth, 0), ==, 0);
  munit_assert_int(TC_PIV_card_report_accepts(&report, NULL, 1), ==, 0);
  munit_assert_int(TC_PIV_card_report_accepts(NULL, &card_auth, 1), ==, 0);
  report.count = TC_PIV_CARD_CHECKS_MAX + 1;
  munit_assert_int(TC_PIV_card_report_accepts(&report, &card_auth, 1), ==, 0);
  munit_assert_null(TC_PIV_card_report_find(&report, &card_auth));
  return MUNIT_OK;
}

/* The certificate check of retained objects: 9E with its identifiers and
 * 9A against the CHUID GUID. */
TC_TEST(card_certificate)
{
  static uint8_t der[2][FIXTURE_FILE_BYTES];
  load("sd33_card2");
  card2_trust(EVIDENCE_CRLS, TC_VALIDATION_REVOCATION_REQUIRED);
  const TC_bytes card_auth = vector("x509/piv/sd33/card01_card_auth_cert.der", der[0]);
  const TC_bytes piv_auth = vector("x509/piv/sd33/card01_piv_auth_cert.der", der[1]);
  TC_PIV_card_certificate_request request = {card_auth, TC_PIV_CARD, 0x9e, 0, {NULL, 0}};
  TC_PIV_card_certificate_report result, unchanged;
  size_t work = CHECK_WORK;
  munit_assert_int(TC_PIV_card_certificate_validate(&request, &card_trust.context, &work, &result),
                   ==, TC_CREDENTIAL_VALID);
  munit_assert_uint8(result.certificate.revocation_checked, ==, 1);
  munit_assert_size(result.identifiers.fascn.length, ==, 25);
  munit_assert_ptr(result.identifiers.fascn.data, >=, card_auth.data);

  const tc_card_object* chuid_object = tc_card_fixture_object(&fixture, 0x5fc102);
  TC_PIV_CHUID chuid;
  munit_assert_int(
      TC_PIV_CHUID_read(chuid_object->data, TC_PIV_CHUID_CONTAINER, TC_CHUID_PROFILE_PIV, &chuid),
      ==, TC_TLV_OK);
  request = (TC_PIV_card_certificate_request){piv_auth, TC_PIV_CARD, 0x9a, 0, chuid.card_uuid};
  work = CHECK_WORK;
  munit_assert_int(TC_PIV_card_certificate_validate(&request, &card_trust.context, &work, &result),
                   ==, TC_CREDENTIAL_VALID);
  /* The PIV Authentication certificate has no card authentication EKU, so
   * it fails the 9E purpose. */
  memset(&unchanged, 0xa5, sizeof unchanged);
  request = (TC_PIV_card_certificate_request){piv_auth, TC_PIV_CARD, 0x9e, 0, {NULL, 0}};
  munit_assert_int(
      TC_PIV_card_certificate_validate(&request, &card_trust.context, &work, &unchanged), ==,
      TC_CREDENTIAL_INVALID);
  /* Argument errors. */
  work = CHECK_WORK;
  request.key_reference = 0x9c;
  munit_assert_int(
      TC_PIV_card_certificate_validate(&request, &card_trust.context, &work, &unchanged), ==,
      TC_CREDENTIAL_ERROR);
  request = (TC_PIV_card_certificate_request){card_auth, TC_PIV_CARD, 0x9e, 1, {NULL, 0}};
  munit_assert_int(
      TC_PIV_card_certificate_validate(&request, &card_trust.context, &work, &unchanged), ==,
      TC_CREDENTIAL_ERROR);
  request =
      (TC_PIV_card_certificate_request){piv_auth, TC_TWIC_NEXGEN_CARD, 0x9a, 0, chuid.card_uuid};
  munit_assert_int(
      TC_PIV_card_certificate_validate(&request, &card_trust.context, &work, &unchanged), ==,
      TC_CREDENTIAL_ERROR);
  request = (TC_PIV_card_certificate_request){piv_auth, TC_PIV_CARD, 0x9a, 0, {NULL, 0}};
  munit_assert_int(
      TC_PIV_card_certificate_validate(&request, &card_trust.context, &work, &unchanged), ==,
      TC_CREDENTIAL_ERROR);
  munit_assert_int(TC_PIV_card_certificate_validate(NULL, &card_trust.context, &work, &unchanged),
                   ==, TC_CREDENTIAL_ERROR);
  munit_assert_size(work, ==, CHECK_WORK);
  munit_assert_true(tc_test_all_value(&unchanged, sizeof unchanged, 0xa5));
  return MUNIT_OK;
}

/* ---- CRL targets ---- */

enum { TARGETS = 32, CRL_JOB_UNITS = 256, CRL_METADATA_BYTES = 4096, CRL_WINDOW_BYTES = 1024 };

static TC_X509_crl_target targets[TARGETS];
static uint8_t target_certificates[CERTIFICATE_BYTES];
static TC_PIV_crl_target_workspace target_workspace;

static TC_PIV_result targets_list(size_t capacity, size_t* work, size_t* count)
{
  target_workspace.certificates = (TC_buffer){target_certificates, sizeof target_certificates};
  target_workspace.parsing = card_trust.parser;
  return TC_PIV_card_crl_targets(&inventory, &card_trust.limits, &target_workspace, work, targets,
                                 capacity, count);
}

static int target_listed(TC_bytes serial, TC_bytes issuer, size_t count)
{
  for (size_t i = 0; i < count; ++i)
    if (targets[i].serial.length == serial.length && targets[i].issuer.length == issuer.length &&
        !memcmp(targets[i].serial.data, serial.data, serial.length) &&
        !memcmp(targets[i].issuer.data, issuer.data, issuer.length))
      return 1;
  return 0;
}

/* Card 2 on contact with the PIN: the targets cover every card certificate
 * and every content signer, and CRLs prepared through the source path for
 * them satisfy every revocation check of the REQUIRED policy. */
TC_TEST(crl_targets)
{
  load("sd33_card2");
  card2_trust(EVIDENCE_CRLS, TC_VALIDATION_REVOCATION_REQUIRED);
  link_open(TC_PIV_CONTACT);
  pin_verify();
  inventory_read();
  size_t work = CHECK_WORK, count = 0;
  munit_assert_int(targets_list(TARGETS, &work, &count), ==, TC_PIV_OK);
  munit_assert_size(count, >=, 5);
  /* Each pair is listed once. */
  for (size_t i = 0; i < count; ++i)
    for (size_t j = i + 1; j < count; ++j)
      munit_assert_false(
          targets[i].serial.length == targets[j].serial.length &&
          !memcmp(targets[i].serial.data, targets[j].serial.data, targets[i].serial.length) &&
          targets[i].issuer.length == targets[j].issuer.length &&
          !memcmp(targets[i].issuer.data, targets[j].issuer.data, targets[i].issuer.length));

  /* The buffer-backed check names the certificates the targets must cover. */
  TC_PIV_card_check_request request = check_request();
  request.ocsp = NULL;
  munit_assert_int(check_run(&request), ==, TC_PIV_OK);
  for (size_t slot = 0; slot < TC_PIV_CARD_CERTIFICATES; ++slot)
    munit_assert_true(
        target_listed(report.certificates[slot].serial, report.certificates[slot].issuer, count));
  TC_X509_certificate signer;
  munit_assert_int(
      TC_X509_read(report.chuid.signer, &card_trust.limits, &card_trust.parser, &signer), ==,
      TC_TLV_OK);
  munit_assert_true(target_listed(signer.serial, signer.issuer, count));

  /* Prepare both issuer CRLs for the targets only and index them. */
  static TC_X509_crl_storage state[2][CRL_JOB_UNITS];
  static TC_X509_crl_match matches[2][TARGETS];
  static uint8_t metadata[2][CRL_METADATA_BYTES], window[CRL_WINDOW_BYTES],
      entry[CRL_METADATA_BYTES], issuer[CRL_METADATA_BYTES];
  static TC_X509_crl_record records[2];
  TC_X509_crl_job* jobs[2];
  for (size_t i = 0; i < 2; ++i) {
    TC_bytes bytes = content_trust.crls[i];
    const TC_source source = {tc_source_memory_read, &bytes, bytes.length};
    const TC_X509_crl_prepare_options options = {content_trust.limits, bytes.length,
                                                 bytes.length * 4 + 1024, 4096, 1024};
    const TC_X509_crl_prepare_workspace preparation = {
        {(uint8_t*)state[i], sizeof state[i]},
        {window, sizeof window},
        {metadata[i], sizeof metadata[i]},
        {entry, sizeof entry},
        {issuer, sizeof issuer},
        content_trust.parser,
        content_trust.workspace.path.validation.names,
        matches[i],
        TARGETS};
    size_t budget = 60000;
    munit_assert_int(TC_X509_crl_prepare_begin(&source, targets, count, &options, &preparation,
                                               &budget, &jobs[i]),
                     ==, TC_TLV_OK);
    int complete = 0;
    while (!complete) {
      budget = 60000;
      munit_assert_int(TC_X509_crl_prepare_step(jobs[i], 16, 1024, &budget, &complete), ==,
                       TC_TLV_OK);
    }
    munit_assert_int(TC_X509_crl_prepare_finish(jobs[i], &records[i]), ==, TC_TLV_OK);
  }
  const TC_X509_crl_index card_index = {records, 1, 0}, content_index = {records, 2, 0};
  const TC_validation_trust card_sources = {&card_trust.source, &card_index};
  const TC_validation_trust content_sources = {&content_trust.source, &content_index};
  munit_assert_int(TC_validation_context_init(&card_sources, &card_trust.options,
                                              &card_trust.workspace.credential,
                                              &card_trust.context),
                   ==, TC_RESULT_OK);
  munit_assert_int(TC_validation_context_init(&content_sources, &content_trust.options,
                                              &content_trust.workspace.credential,
                                              &content_trust.context),
                   ==, TC_RESULT_OK);
  request = check_request();
  request.ocsp = NULL;
  munit_assert_int(check_run(&request), ==, TC_PIV_OK);
  expect_card2_complete();
  for (size_t i = 0; i < 2; ++i)
    TC_X509_crl_prepare_clear(jobs[i]);

  /* One slot short is LIMIT with count unchanged. Work runs out the same
   * way. */
  size_t limited = 77;
  work = CHECK_WORK;
  munit_assert_int(targets_list(count - 1, &work, &limited), ==, TC_PIV_LIMIT);
  munit_assert_size(limited, ==, 77);
  work = 16;
  munit_assert_int(targets_list(TARGETS, &work, &limited), ==, TC_PIV_LIMIT);
  munit_assert_size(limited, ==, 77);
  /* Argument errors leave the outputs unchanged. */
  work = CHECK_WORK;
  munit_assert_int(TC_PIV_card_crl_targets(NULL, &card_trust.limits, &target_workspace, &work,
                                           targets, TARGETS, &limited),
                   ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_card_crl_targets(&inventory, &card_trust.limits, &target_workspace, &work,
                                           NULL, TARGETS, &limited),
                   ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_card_crl_targets(&inventory, &card_trust.limits, &target_workspace, &work,
                                           targets, TARGETS, (size_t*)(void*)targets),
                   ==, TC_PIV_ARGUMENT);
  munit_assert_size(limited, ==, 77);
  munit_assert_size(work, ==, CHECK_WORK);
  TC_PIV_inventory_clear(&inventory);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
      {"/crl-targets", crl_targets, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/card2-contact", card2_contact, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/card2-contactless", card2_contactless, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/card2-without-pin", card2_without_pin, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/card2-evidence", card2_evidence, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/card2-twic-ocsp-policy", card2_twic_ocsp_policy, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/card2-failures", card2_failures, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/card4-contactless", card4_contactless, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/report-limit", report_limit, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/work-limit", work_limit, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/arguments", arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/accepts", accepts, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/card-certificate", card_certificate, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/piv/card-check", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
