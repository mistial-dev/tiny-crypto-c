/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The library against one PIV card, in the scenario order of
 * docs/testing.md ("PIV card hardware tests"). card_config.h lists the
 * environment and card_backend.h the card. Every command passes the guard
 * of guard.h. The scenarios share one card connection and run without
 * forking, and a scenario whose prerequisites are missing skips.
 *
 * Scenarios 1 to 9 open with SELECT. From the VCI on the session continues,
 * since a SELECT ends the link's VCI and PIN state. The run makes at most
 * one PIN submission and proves 9C directly after it, since
 * TC_PIV_pin_verify submits only while the card reports the PIN unverified
 * (SP 800-73-5 Part 2 3.2.1) and 9C needs a PIN verified immediately
 * before each use (Part 1 Table 5). The output holds labels and counts. */
#include "../../../examples/piv_inspect_trust.h"
#include "../../../examples/pki_input.h"
#include "card_backend.h"
#include "card_fixture.h"
#include "test_util.h"
#include <tiny_crypto/hash.h>
#include <tiny_crypto/piv_biometric.h>
#include <tiny_crypto/piv_card_objects.h>
#include <tiny_crypto/piv_cms.h>
#include <tiny_crypto/piv_printed.h>
#include <tiny_crypto/piv_security.h>
#include <tiny_crypto/piv_sm_apdu.h>
#include <tiny_crypto/piv_sm_authenticate.h>
#include <tiny_crypto/piv_vci.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#ifndef TC_VECTOR_DIR
#error "TC_VECTOR_DIR must name tests/vectors"
#endif
#ifndef TC_CARD_FIXTURE_DIR
#error "TC_CARD_FIXTURE_DIR must name the capture fixture directory"
#endif

/* CTest SKIP_RETURN_CODE. */
#define SKIP_STATUS 77

#define COMMAND_SCRATCH_BYTES                                                                      \
  (TC_APDU_EXTENDED_COMMAND_BYTES(TC_PIV_COMMAND_MAX_NC) > TC_APDU_SHORT_COMMAND_MAX_BYTES         \
       ? TC_APDU_EXTENDED_COMMAND_BYTES(TC_PIV_COMMAND_MAX_NC)                                     \
       : TC_APDU_SHORT_COMMAND_MAX_BYTES)

enum {
  EXCHANGES = 8192,     /* C-RP budget of each link */
  COPY_BYTES = 4096,    /* one plain object answer or decoded certificate */
  OBJECT_BYTES = 16384, /* the largest object, the facial image */
  FILE_BYTES = 16384,
  CHUNK_BYTES = 256, /* data bytes of one short answer */
  VALIDATION_WORK = 200000000,
  CHECK_WORK = 400000000
};

static const uint8_t piv_aid[] = {0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00};

/* One plain copy: the answer buffer and the object it holds. */
typedef struct {
  uint8_t bytes[COPY_BYTES];
  TC_PIV_data_object object;
  int present;
} Copy;

enum { COPY_CHUID, COPY_CARD_CERTIFICATE, COPY_SIGNER, COPY_DISCOVERY, COPIES };

static struct {
  tc_piv_card_config config;
  tc_card_fixture expected; /* the TC_PIV_CARD_EXPECT fixture */
  tc_piv_guard guard;
  tc_piv_card_backend backend;
  int opened;
  /* Trust */
  uint8_t files[2 * TC_PIV_CARD_TRUST_FILES][FILE_BYTES];
  TC_bytes anchors[TC_PIV_CARD_TRUST_FILES], crls[TC_PIV_CARD_TRUST_FILES];
  ExamplePIVInspectOptions trust_inputs;
  ExamplePIVInspectTrust trust;
  /* The vendored CRLs are small, so they are indexed from memory. */
  TC_X509_crl_record crl_records[TC_PIV_CARD_TRUST_FILES];
  TC_X509_crl_index crl_index;
  /* Link */
  TC_PIV_link link, extended;
  uint8_t command_scratch[COMMAND_SCRATCH_BYTES], extended_scratch[COMMAND_SCRATCH_BYTES];
  uint8_t sm_scratch[TC_PIV_SM_COMMAND_DATA_BYTES(TC_PIV_COMMAND_MAX_NC)];
  uint8_t select_response[512];
  TC_PIV_application application;
  /* Plain copies and what they gave */
  Copy copies[COPIES];
  TC_PIV_CHUID chuid;
  int has_chuid;
  uint8_t signer_der[COPY_BYTES];
  TC_PIV_certificate signer;
  TC_X509_validation_result signer_result;
  TC_GZIP_workspace gzip;
  /* Secure messaging and the VCI */
  TC_PIV_SM session;
  TC_PIV_SM_workspace sm_workspace;
  TC_PIV_SM_authentication_workspace authentication;
  uint8_t key_response[TC_PIV_SM_KEY_RESPONSE_BYTES];
  TC_bytes card_cvc;
  TC_PIV_discovery discovery;
  int secured, has_discovery, vci, pin_verified;
  /* Objects, certificates and proofs */
  uint8_t response[TC_PIV_RESPONSE_BYTES(OBJECT_BYTES)];
  uint8_t certificate_der[COPY_BYTES];
  TC_PIV_key_proof_workspace proof;
  /* Inventory and report */
  uint8_t pool[TC_PIV_INVENTORY_POOL_BYTES];
  TC_PIV_object objects[TC_PIV_CATALOG_PIV_OBJECTS];
  TC_PIV_inventory inventory;
  TC_PIV_object plain_copies[2];
  TC_PIV_card_check_workspace check;
  uint8_t certificates[16384], lds[4096];
  TC_PIV_card_report report;
} run;

/* A label and counts on stdout, which munit leaves uncaptured. */
static void note(const char* format, ...)
{
  va_list arguments;
  va_start(arguments, format);
  fputs("  ", stdout);
  vfprintf(stdout, format, arguments);
  fputc('\n', stdout);
  fflush(stdout);
  va_end(arguments);
}

static TC_bytes tag_bytes(uint32_t tag, uint8_t storage[3])
{
  storage[0] = (uint8_t)(tag >> 16);
  storage[1] = (uint8_t)(tag >> 8);
  storage[2] = (uint8_t)tag;
  const size_t length = tag > 0xffff ? 3 : tag > 0xff ? 2 : 1;
  return (TC_bytes){storage + 3 - length, length};
}

/* GET DATA of tag on link into buffer. */
static TC_PIV_result read_on(TC_PIV_link* link, uint32_t tag, TC_buffer buffer,
                             TC_PIV_data_object* out)
{
  uint8_t storage[3];
  memset(out, 0, sizeof *out);
  return TC_PIV_get_data(link, tag_bytes(tag, storage), buffer, out);
}

static TC_PIV_result read_object(uint32_t tag, TC_buffer buffer, TC_PIV_data_object* out)
{
  return read_on(&run.link, tag, buffer, out);
}

static TC_buffer response_buffer(void)
{
  return (TC_buffer){run.response, sizeof run.response};
}

/* Read tag plain into its copy. */
static void read_copy(uint32_t tag, size_t index)
{
  Copy* copy = &run.copies[index];
  copy->present = 0;
  munit_assert_int(read_object(tag, (TC_buffer){copy->bytes, sizeof copy->bytes}, &copy->object),
                   ==, TC_PIV_OK);
  copy->present = 1;
}

static void expect_same(TC_bytes actual, TC_bytes expected)
{
  munit_assert_size(actual.length, ==, expected.length);
  munit_assert_memory_equal(actual.length, actual.data, expected.data);
}

/* With TC_PIV_CARD_EXPECT, encoded equals the fixture's copy of tag. */
static void expect_object(uint32_t tag, TC_bytes encoded)
{
  if (!run.config.expect)
    return;
  const tc_card_object* object = tc_card_fixture_object(&run.expected, tag);
  munit_assert_not_null(object);
  expect_same(encoded, object->data);
}

/* The guard refused nothing so far. */
static void expect_guard_clean(void)
{
  if (run.guard.counts.refusals)
    munit_errorf("guard refused: %s", run.guard.counts.refusal);
}

static void link_start(TC_PIV_link* link, TC_APDU_length_format format, uint8_t* scratch,
                       size_t capacity)
{
  const TC_PIV_link_options options = {{format, 0, EXCHANGES, 0, 0},
                                       run.backend.interface,
                                       format == TC_APDU_EXTENDED ? (uint32_t)TC_APDU_MAX_NE : 0};
  munit_assert_int(
      TC_PIV_link_init(link, run.backend.transport, &options, (TC_buffer){scratch, capacity}), ==,
      TC_PIV_OK);
}

static void select_piv(void)
{
  memset(&run.application, 0, sizeof run.application);
  munit_assert_int(TC_PIV_select(&run.link, TC_PIV_APPLICATION_PIV, 0,
                                 (TC_buffer){run.select_response, sizeof run.select_response},
                                 &run.application),
                   ==, TC_PIV_OK);
}

/* Decode a certificate container into certificate_der. */
static TC_PIV_certificate certificate_decode(TC_bytes encoded, TC_PIV_certificate_profile profile,
                                             uint8_t* der)
{
  TC_PIV_certificate certificate;
  size_t work = VALIDATION_WORK;
  munit_assert_int(TC_PIV_certificate_decode(encoded, profile, COPY_BYTES, &run.gzip, &work,
                                             (TC_buffer){der, COPY_BYTES}, &certificate),
                   ==, TC_TLV_OK);
  return certificate;
}

/* The library reader of each plain object. */
static void decode(uint32_t tag, TC_bytes encoded)
{
  switch (tag) {
  case 0x5fc102:
    munit_assert_int(
        TC_PIV_CHUID_read(encoded, TC_PIV_CHUID_CONTAINER, TC_CHUID_PROFILE_PIV, &run.chuid), ==,
        TC_TLV_OK);
    run.has_chuid = run.chuid.card_uuid.length == 16;
    break;
  case 0x5fc101:
  case 0x5fc105:
    (void)certificate_decode(encoded, TC_PIV_CERTIFICATE_SLOT, run.certificate_der);
    break;
  case 0x5fc122:
    run.signer = certificate_decode(encoded, TC_PIV_CERTIFICATE_SM_SIGNER, run.signer_der);
    break;
  case 0x7f61: {
    TC_PIV_bit_group bits;
    munit_assert_int(TC_PIV_bit_group_read(encoded, &bits), ==, TC_TLV_OK);
    break;
  }
  case 0x5fc107: {
    TC_PIV_CCC ccc;
    munit_assert_int(TC_PIV_CCC_read(encoded, TC_PIV_CONTAINER, &ccc), ==, TC_TLV_OK);
    break;
  }
  case 0x5fc106: {
    TC_PIV_security_object security;
    munit_assert_int(TC_PIV_security_read(encoded, TC_PIV_SECURITY_CONTAINER, &security), ==,
                     TC_TLV_OK);
    break;
  }
  case 0x5fc10c: {
    TC_PIV_key_history history;
    munit_assert_int(TC_PIV_key_history_read(encoded, TC_PIV_CONTAINER, &history), ==, TC_TLV_OK);
    break;
  }
  default:
    munit_errorf("no reader for %06x", (unsigned)tag);
  }
}

/* End a secure messaging session that failed, then fail. */
static void secure_failed(const char* step, int result)
{
  TC_PIV_link_unsecure(&run.link);
  TC_PIV_SM_clear(&run.session);
  run.secured = 0;
  munit_errorf("%s: %d", step, result);
}

/* ---- 1 to 7: plain commands ---- */

/* SELECT with the complete AID: the template names the AID, the algorithms
 * with 06 01 00, and the DO 7F66 limits reach the channel (Part 2 3.1.1
 * Tables 3 to 5, ISO/IEC 7816-4 12.8.1). */
TC_TEST(select_piv_scenario)
{
  link_start(&run.link, TC_APDU_SHORT, run.command_scratch, sizeof run.command_scratch);
  select_piv();
  expect_same(run.application.aid, (TC_bytes){piv_aid, sizeof piv_aid});
  munit_assert_size(run.application.algorithms.length, >, 0);
  if (run.config.expect)
    munit_assert_uint8(run.application.sm_suite, ==, run.expected.sessions[0].suite);
  if (run.application.max_command_bytes) {
    munit_assert_size(run.link.channel.max_command_bytes, ==, run.application.max_command_bytes);
    munit_assert_size(run.link.channel.max_response_bytes, <=, run.application.max_response_bytes);
  }
  note("select_piv: suite %02x, limits %zu/%zu", run.application.sm_suite,
       run.application.max_command_bytes, run.application.max_response_bytes);
  expect_guard_clean();
  return MUNIT_OK;
}

/* SELECT with the 9-byte AID prefix answers the complete AID (Part 2
 * 3.1.1). */
TC_TEST(select_truncated)
{
  TC_APDU_channel channel;
  uint8_t scratch[TC_APDU_SHORT_COMMAND_MAX_BYTES];
  const TC_APDU_channel_options options = {TC_APDU_SHORT, TC_APDU_GET_RESPONSE_PLAIN_CLA, 4, 0, 0};
  munit_assert_int(TC_APDU_channel_init(&channel, run.backend.transport, &options,
                                        (TC_buffer){scratch, sizeof scratch}),
                   ==, TC_APDU_OK);
  const TC_APDU_command command = {{piv_aid, 9}, 256, 0x00, 0xa4, 0x04, 0x00};
  TC_APDU_response answer;
  const TC_APDU_result result = TC_APDU_transceive(&channel, &command, response_buffer(), &answer);
  TC_APDU_channel_clear(&channel);
  munit_assert_int(result, ==, TC_APDU_OK);
  munit_assert_uint16(answer.sw, ==, 0x9000);
  TC_PIV_application application;
  munit_assert_int(TC_PIV_application_read(answer.data, TC_PIV_APPLICATION_PIV, 0, &application),
                   ==, TC_TLV_OK);
  expect_same(application.aid, (TC_bytes){piv_aid, sizeof piv_aid});
  select_piv();
  expect_guard_clean();
  return MUNIT_OK;
}

/* The Discovery Object read plain on contact (Part 1 3.3.6). */
TC_TEST(discovery_plain)
{
  if (run.backend.interface != TC_PIV_CONTACT)
    return MUNIT_SKIP;
  select_piv();
  read_copy(0x7e, COPY_DISCOVERY);
  TC_PIV_discovery discovery;
  munit_assert_int(TC_PIV_discovery_read(run.copies[COPY_DISCOVERY].object.encoded,
                                         TC_PIV_DISCOVERY_PIV, &discovery),
                   ==, TC_TLV_OK);
  expect_object(0x7e, run.copies[COPY_DISCOVERY].object.encoded);
  note("discovery_plain: policy %02x %02x", discovery.policy, discovery.preference);
  expect_guard_clean();
  return MUNIT_OK;
}

/* The objects readable plain, decoded by the library readers and compared
 * with the capture fixture. The CHUID and the Card Authentication
 * certificate bind the card identity for the guard. */
TC_TEST(plain_objects)
{
  static const struct {
    uint32_t tag;
    int copy;
  } always[] = {{0x5fc102, COPY_CHUID},
                {0x5fc101, COPY_CARD_CERTIFICATE},
                {0x7f61, -1},
                {0x5fc122, COPY_SIGNER}};
  static const uint32_t contact[] = {0x5fc107, 0x5fc105, 0x5fc106, 0x5fc10c};
  select_piv();
  size_t count = 0;
  for (size_t i = 0; i < sizeof always / sizeof *always; ++i) {
    TC_PIV_data_object object;
    if (always[i].copy >= 0) {
      read_copy(always[i].tag, (size_t)always[i].copy);
      object = run.copies[always[i].copy].object;
    } else {
      munit_assert_int(read_object(always[i].tag, response_buffer(), &object), ==, TC_PIV_OK);
    }
    decode(always[i].tag, object.encoded);
    expect_object(always[i].tag, object.encoded);
    ++count;
  }
  for (size_t i = 0;
       run.backend.interface == TC_PIV_CONTACT && i < sizeof contact / sizeof *contact; ++i) {
    TC_PIV_data_object object;
    munit_assert_int(read_object(contact[i], response_buffer(), &object), ==, TC_PIV_OK);
    decode(contact[i], object.encoded);
    expect_object(contact[i], object.encoded);
    ++count;
  }
  if (run.config.expect)
    munit_assert_int(tc_piv_guard_identity_bound(&run.guard), ==, 1);
  note("plain_objects: %zu objects, identity %s", count,
       tc_piv_guard_identity_bound(&run.guard) ? "bound" : "unbound");
  expect_guard_clean();
  return MUNIT_OK;
}

/* A SHORT CHUID read collects its answer with GET RESPONSE CLA 00 and
 * Le = SW2 (ISO/IEC 7816-4 5.3.4, Part 2 4.2.6). One byte less than the
 * answer and its status returns LIMIT with the buffer wiped, and the channel
 * stays usable. */
TC_TEST(get_response_chain)
{
  select_piv();
  const size_t before = run.guard.counts.get_responses;
  const size_t mismatches = run.guard.counts.get_response_le_mismatches;
  TC_PIV_data_object object;
  munit_assert_int(read_object(0x5fc102, response_buffer(), &object), ==, TC_PIV_OK);
  const size_t length = object.encoded.length;
  const size_t steps = run.guard.counts.get_responses - before;
  munit_assert_size(steps, >=, (length - 1) / CHUNK_BYTES);
  munit_assert_size(run.guard.counts.get_response_le_mismatches, ==, mismatches);
  if (run.copies[COPY_CHUID].present)
    expect_same(object.encoded, run.copies[COPY_CHUID].object.encoded);
  memset(run.response, 0xa5, length + 1);
  munit_assert_int(read_object(0x5fc102, (TC_buffer){run.response, length + 1}, &object), ==,
                   TC_PIV_LIMIT);
  munit_assert_true(tc_test_all_zero(run.response, length + 1));
  select_piv();
  munit_assert_int(read_object(0x5fc102, (TC_buffer){run.response, length + 2}, &object), ==,
                   TC_PIV_OK);
  note("get_response_chain: %zu bytes, %zu GET RESPONSE", length, steps);
  expect_guard_clean();
  return MUNIT_OK;
}

/* An EXTENDED link reads the same CHUID within the DO 7F66 limits. */
TC_TEST(extended)
{
  if (!run.config.extended || !run.application.max_command_bytes)
    return MUNIT_SKIP;
  link_start(&run.extended, TC_APDU_EXTENDED, run.extended_scratch, sizeof run.extended_scratch);
  TC_PIV_application application;
  TC_PIV_data_object object = {0};
  TC_PIV_result result =
      TC_PIV_select(&run.extended, TC_PIV_APPLICATION_PIV, 0,
                    (TC_buffer){run.select_response, sizeof run.select_response}, &application);
  if (result == TC_PIV_OK)
    result = read_on(&run.extended, 0x5fc102, response_buffer(), &object);
  TC_PIV_link_clear(&run.extended);
  munit_assert_int(result, ==, TC_PIV_OK);
  if (run.copies[COPY_CHUID].present)
    expect_same(object.encoded, run.copies[COPY_CHUID].object.encoded);
  munit_assert_size(run.guard.counts.max_command_bytes, <=, application.max_command_bytes);
  munit_assert_size(run.guard.counts.max_answer_bytes, <=, application.max_response_bytes);
  select_piv();
  note("extended: largest command %zu, largest answer %zu", run.guard.counts.max_command_bytes,
       run.guard.counts.max_answer_bytes);
  expect_guard_clean();
  return MUNIT_OK;
}

static const TC_PIV_object* inventory_object(uint32_t tag)
{
  uint8_t storage[3];
  const TC_bytes name = tag_bytes(tag, storage);
  for (size_t i = 0; i < run.inventory.count; ++i) {
    const TC_PIV_object* object = &run.inventory.objects[i];
    if (object->info->tag_length == name.length &&
        !memcmp(object->info->tag, name.data, name.length))
      return object;
  }
  return NULL;
}

static void inventory_read(void)
{
  TC_PIV_inventory_clear(&run.inventory);
  memset(&run.inventory, 0, sizeof run.inventory);
  run.inventory.objects = run.objects;
  run.inventory.capacity = TC_PIV_CATALOG_PIV_OBJECTS;
  size_t work = CHECK_WORK;
  munit_assert_int(TC_PIV_inventory_read(&run.link, NULL, (TC_buffer){run.pool, sizeof run.pool},
                                         &work, &run.inventory),
                   ==, TC_PIV_OK);
}

/* The iris images and retired certificate 20 are absent (6A82) or empty
 * (53 00), and the iris images need the PIN (6982 before it). On
 * contactless without the VCI their rule is unmet (Part 1 Table 2), so the
 * inventory sends nothing for them, and a direct GET DATA may answer
 * 6982. */
TC_TEST(not_found)
{
  static const uint32_t tags[] = {0x5fc121, 0x5fc120};
  select_piv();
  if (run.backend.interface == TC_PIV_CONTACTLESS) {
    inventory_read();
    for (size_t i = 0; i < sizeof tags / sizeof *tags; ++i) {
      const TC_PIV_object* object = inventory_object(tags[i]);
      munit_assert_not_null(object);
      munit_assert_uint8(object->state, ==, TC_PIV_OBJECT_RESTRICTED);
    }
    TC_PIV_inventory_clear(&run.inventory);
  }
  for (size_t i = 0; i < sizeof tags / sizeof *tags; ++i) {
    TC_PIV_data_object object;
    const TC_PIV_result result = read_object(tags[i], response_buffer(), &object);
    const uint16_t status = TC_PIV_link_status(&run.link);
    if (result == TC_PIV_OK)
      munit_assert_size(object.value.length, ==, 0);
    else
      munit_assert_true(result == TC_PIV_CARD_STATUS && (status == 0x6a82 || status == 0x6982));
    note("not_found: %06x %s %04x", (unsigned)tags[i], result == TC_PIV_OK ? "empty" : "status",
         status);
  }
  expect_guard_clean();
  return MUNIT_OK;
}

/* ---- 8 to 13: secure messaging, VCI, PIN and proofs ---- */

/* Key establishment under the content signer of 5FC122 with the CHUID GUID
 * (Part 1 3.3.7, Part 2 4.1). The SM reads equal the plain copies. */
TC_TEST(sm_establish)
{
  if (!run.application.sm_suite || !run.copies[COPY_SIGNER].present || !run.has_chuid)
    return MUNIT_SKIP;
  select_piv();
  size_t work = VALIDATION_WORK;
  const TC_credential_status signer = TC_PIV_content_signer_validate(
      run.signer.certificate, TC_PIV_CARD, &run.trust.context, &work, &run.signer_result);
  munit_assert_int(signer, ==, TC_CREDENTIAL_VALID);
  TC_PIV_SM_peer peer;
  memset(&peer, 0, sizeof peer);
  TC_PIV_result result = TC_PIV_SM_key_request(
      &run.link, &run.session, (TC_PIV_SM_suite)run.application.sm_suite, run.backend.host_id,
      run.backend.random, (TC_buffer){run.key_response, sizeof run.key_response}, &peer,
      &run.sm_workspace);
  if (result != TC_PIV_OK)
    secure_failed("key establishment", result);
  const TC_PIV_SM_authentication authentication = {peer,
                                                   run.signer.intermediate_cvc,
                                                   run.chuid.card_uuid,
                                                   &run.signer_result.certificate,
                                                   &run.trust.options.parsing,
                                                   &run.trust.options.signatures};
  const TC_credential_status card =
      TC_PIV_SM_authenticate_response(&run.session, &authentication, &work, &run.authentication);
  if (card != TC_CREDENTIAL_VALID)
    secure_failed("card authentication", card);
  result = TC_PIV_link_secure(&run.link, &run.sm_workspace,
                              (TC_buffer){run.sm_scratch, sizeof run.sm_scratch});
  if (result != TC_PIV_OK)
    secure_failed("link secure", result);
  run.secured = 1;
  run.card_cvc = peer.certificate;
  const size_t protected_before = run.guard.counts.protected_commands;
  static const struct {
    uint32_t tag;
    int copy;
  } reads[] = {{0x7e, COPY_DISCOVERY}, {0x5fc102, COPY_CHUID}, {0x5fc122, COPY_SIGNER}};
  for (size_t i = 0; i < sizeof reads / sizeof *reads; ++i) {
    TC_PIV_data_object object;
    munit_assert_int(read_object(reads[i].tag, response_buffer(), &object), ==, TC_PIV_OK);
    if (run.copies[reads[i].copy].present)
      expect_same(object.encoded, run.copies[reads[i].copy].object.encoded);
  }
  munit_assert_int(
      TC_PIV_discovery_get(&run.link, TC_PIV_DISCOVERY_PIV, response_buffer(), &run.discovery), ==,
      TC_PIV_OK);
  munit_assert_uint8(run.discovery.secured, ==, 1);
  run.has_discovery = 1;
  munit_assert_size(run.guard.counts.protected_commands - protected_before, ==, 4);
  note("sm_establish: suite %02x, discovery policy %02x %02x", run.application.sm_suite,
       run.discovery.policy, run.discovery.preference);
  expect_guard_clean();
  return MUNIT_OK;
}

/* The VCI with the pairing code on contactless (Part 1 5.5). Before it the
 * library refuses the PIN query and sends nothing. After it the PIV
 * Authentication certificate is readable. */
TC_TEST(vci)
{
  if (run.backend.interface != TC_PIV_CONTACTLESS || !run.secured || !run.has_discovery ||
      !(run.discovery.policy & TC_PIV_POLICY_VCI))
    return MUNIT_SKIP;
  const int pairing = !(run.discovery.policy & TC_PIV_POLICY_VCI_WITHOUT_PAIRING);
  if (pairing && (!run.config.pairing_code.length || !run.config.expect))
    return MUNIT_SKIP;
  select_piv();
  const size_t sent = run.guard.counts.exchanges;
  TC_PIV_reference_status status;
  munit_assert_int(
      TC_PIV_verify_status(&run.link, TC_PIV_discovery_pin_reference(&run.discovery), &status), ==,
      TC_PIV_REFUSED);
  munit_assert_size(run.guard.counts.exchanges, ==, sent);
  TC_PIV_vci_mode mode = TC_PIV_VCI_PAIRED;
  const TC_PIV_result result =
      TC_PIV_vci_establish(&run.link, &run.discovery, run.config.pairing_code, &mode);
  if (result != TC_PIV_OK) {
    TC_PIV_link_info info;
    TC_PIV_link_info_get(&run.link, &info);
    if (info.sm_lost)
      secure_failed("VCI with the session lost", result);
    munit_errorf("VCI: %d, status %04x", result, TC_PIV_link_status(&run.link));
  }
  run.vci = 1;
  TC_PIV_data_object object;
  munit_assert_int(read_object(0x5fc105, response_buffer(), &object), ==, TC_PIV_OK);
  decode(0x5fc105, object.encoded);
  expect_object(0x5fc105, object.encoded);
  note("vci: %s", mode == TC_PIV_VCI_PAIRED ? "paired" : "without pairing");
  expect_guard_clean();
  return MUNIT_OK;
}

static uint8_t pin_reference(void)
{
  return run.has_discovery ? TC_PIV_discovery_pin_reference(&run.discovery) : 0x80;
}

/* The data-less VERIFY (Part 2 3.2.1): plain on contact, under SM after the
 * VCI on contactless. Without the VCI on contactless the library refuses it
 * and sends nothing. */
TC_TEST(retry_query)
{
  const size_t sent = run.guard.counts.exchanges;
  TC_PIV_reference_status status;
  const TC_PIV_result result = TC_PIV_verify_status(&run.link, pin_reference(), &status);
  if (run.backend.interface == TC_PIV_CONTACTLESS && !run.vci) {
    munit_assert_int(result, ==, TC_PIV_REFUSED);
    munit_assert_size(run.guard.counts.exchanges, ==, sent);
    note("retry_query: refused without the VCI");
    return MUNIT_OK;
  }
  munit_assert_int(result, ==, TC_PIV_OK);
  munit_assert_true(status.verified || status.retries_known);
  note("retry_query: %02x %s, %u tries", pin_reference(),
       status.verified ? "verified" : "unverified", status.retries);
  expect_guard_clean();
  return MUNIT_OK;
}

/* The BC value of a biometric container value (Part 1 Tables 13 and 14). */
static TC_bytes biometric_record(TC_bytes value)
{
  const TC_TLV_limits limits = {value.length, value.length, 8, 1};
  TC_TLV_reader reader;
  TC_TLV_element element;
  munit_assert_int(TC_TLV_reader_init(&reader, value, TC_TLV_ISO7816, &limits), ==, TC_TLV_OK);
  int found = 0;
  TC_PIV_CBEFF cbeff;
  while (!found && TC_TLV_next(&reader, &element) == TC_TLV_OK)
    if (element.header.tag_length == 1 && element.header.tag[0] == 0xbc) {
      munit_assert_int(TC_PIV_CBEFF_read(element.value, &cbeff), ==, TC_TLV_OK);
      found = 1;
    }
  munit_assert_true(found);
  return cbeff.record;
}

/* A validated certificate view of a card certificate container. */
static void certificate_validate(TC_bytes encoded, uint8_t key, TC_X509_validation_result* out)
{
  const TC_PIV_certificate certificate =
      certificate_decode(encoded, TC_PIV_CERTIFICATE_SLOT, run.certificate_der);
  size_t work = VALIDATION_WORK;
  TC_credential_status status;
  if (key == 0x9c) {
    status = TC_X509_validate(certificate.certificate, &run.trust.context, &work, out);
  } else {
    const TC_PIV_card_certificate_request request = {certificate.certificate, TC_PIV_CARD, key, 0,
                                                     key == 0x9a ? run.chuid.card_uuid
                                                                 : (TC_bytes){NULL, 0}};
    TC_PIV_card_certificate_result result;
    status = TC_PIV_card_certificate_validate(&request, &run.trust.context, &work, &result);
    if (status == TC_CREDENTIAL_VALID)
      *out = result.certificate;
  }
  if (status != TC_CREDENTIAL_VALID)
    munit_errorf("certificate %02x: %d", key, status);
}

static void prove(uint8_t key, const TC_X509_validation_result* certificate)
{
  tc_piv_card_backend_proofs(&run.backend, &key, 1);
  const TC_PIV_key_proof_request request = {
      &certificate->certificate, {TC_PIV_CARD, run.backend.at, TC_PIV_RSA_PKCS1_V15, 0}, key};
  TC_work_budget budget = {UINT32_MAX};
  munit_assert_int(TC_PIV_key_prove(&run.link, &request, run.backend.random,
                                    &run.trust.options.signatures, &run.proof, &budget),
                   ==, TC_PIV_OK);
}

/* The one PIN submission, then 9C directly after it, then the PIN-gated
 * objects: fingerprints, the facial image (about 12 KB, plain GET RESPONSE
 * after an SM command, decrypted in place) and printed information. */
TC_TEST(pin)
{
  if (!run.config.pin.length || !run.config.expect ||
      (run.backend.interface == TC_PIV_CONTACTLESS && !run.vci))
    return MUNIT_SKIP;
  if (!tc_piv_guard_identity_bound(&run.guard))
    munit_error("the card identity did not match, so no PIN is sent");
  int sign = run.backend.signature_proofs;
  TC_X509_validation_result signing;
  memset(&signing, 0, sizeof signing);
  if (sign) {
    TC_PIV_data_object object;
    munit_assert_int(read_object(0x5fc10a, response_buffer(), &object), ==, TC_PIV_OK);
    expect_object(0x5fc10a, object.encoded);
    certificate_validate(object.encoded, 0x9c, &signing);
  }
  TC_PIV_reference_status status = {0, 0, 0, 0};
  const TC_PIV_result result = TC_PIV_pin_verify(&run.link, pin_reference(), run.config.pin,
                                                 run.config.minimum_retries, &status);
  if (result != TC_PIV_OK || !status.verified)
    munit_errorf("PIN: %d, status %04x", result, TC_PIV_link_status(&run.link));
  run.pin_verified = 1;
  /* A PIN left verified by an earlier session gets no submission, and 9C
   * then lacks the PIN Always condition. */
  sign = sign && status.submitted;
  if (sign) {
    prove(0x9c, &signing);
    munit_assert_size(run.guard.counts.signatures, ==, 1);
  }
  TC_PIV_data_object object;
  munit_assert_int(read_object(0x5fc103, response_buffer(), &object), ==, TC_PIV_OK);
  expect_object(0x5fc103, object.encoded);
  TC_PIV_fingerprint_record fingerprints;
  munit_assert_int(TC_PIV_fingerprint_read(biometric_record(object.value), &fingerprints), ==,
                   TC_TLV_OK);
  const size_t before = run.guard.counts.get_responses;
  munit_assert_int(read_object(0x5fc108, response_buffer(), &object), ==, TC_PIV_OK);
  expect_object(0x5fc108, object.encoded);
  const size_t steps = run.guard.counts.get_responses - before;
  const size_t face_bytes = object.encoded.length;
  TC_PIV_face_record face;
  munit_assert_int(TC_PIV_face_read(biometric_record(object.value), TC_PIV_FACE_PROFILE_PIV, &face),
                   ==, TC_TLV_OK);
  munit_assert_int(read_object(0x5fc109, response_buffer(), &object), ==, TC_PIV_OK);
  expect_object(0x5fc109, object.encoded);
  TC_PIV_printed printed;
  munit_assert_int(TC_PIV_printed_read(object.encoded, TC_PIV_PRINTED_CONTAINER,
                                       TC_PIV_PRINTED_PROFILE_PIV, &printed),
                   ==, TC_TLV_OK);
  note("pin: submitted %u, 9C %s, facial image %zu bytes in %zu GET RESPONSE", status.submitted,
       sign ? "proved" : "skipped", face_bytes, steps);
  expect_guard_clean();
  return MUNIT_OK;
}

/* 9E against the validated 5FC101 without a PIN, and 9A after the PIN
 * (Part 1 Table 5). */
TC_TEST(key_proofs)
{
  if (!run.copies[COPY_CARD_CERTIFICATE].present)
    return MUNIT_SKIP;
  TC_X509_validation_result certificate;
  certificate_validate(run.copies[COPY_CARD_CERTIFICATE].object.encoded, 0x9e, &certificate);
  prove(0x9e, &certificate);
  if (run.pin_verified) {
    TC_PIV_data_object object;
    munit_assert_int(read_object(0x5fc105, response_buffer(), &object), ==, TC_PIV_OK);
    certificate_validate(object.encoded, 0x9a, &certificate);
    prove(0x9a, &certificate);
  }
  note("key_proofs: 9E proved, 9A %s", run.pin_verified ? "proved" : "skipped");
  expect_guard_clean();
  return MUNIT_OK;
}

/* Write each present object that holds no secret to DIR/<tag>.bin. */
static void dump_objects(const char* directory)
{
  for (size_t i = 0; i < run.inventory.count; ++i) {
    const TC_PIV_object* object = &run.inventory.objects[i];
    if (object->state != TC_PIV_OBJECT_PRESENT || object->info->flags & TC_PIV_OBJECT_SECRET)
      continue;
    char path[TC_PIV_CARD_PATH_BYTES];
    int length = snprintf(path, sizeof path, "%s/", directory);
    for (size_t j = 0; length > 0 && j < object->info->tag_length; ++j)
      length += snprintf(path + length, sizeof path - (size_t)length, "%02x", object->info->tag[j]);
    munit_assert_true(length > 0 && (size_t)length + 5 <= sizeof path);
    memcpy(path + length, ".bin", 5);
    const int file = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    munit_assert_int(file, >=, 0);
    const ssize_t written = write(file, object->encoded.data, object->encoded.length);
    munit_assert_int(close(file), ==, 0);
    munit_assert_true(written == (ssize_t)object->encoded.length);
  }
}

/* The inventory over the whole catalog, the composed card check with the
 * pinned trust points and CRLs, and the 9E and 9A proofs. 9C is left out,
 * since the PIN budget is spent. */
TC_TEST(inventory_and_report)
{
  inventory_read();
  if (run.config.dump_dir)
    dump_objects(run.config.dump_dir);
  size_t copies = 0;
  if (run.secured) {
    static const int sources[] = {COPY_SIGNER, COPY_CHUID};
    static const uint32_t tags[] = {0x5fc122, 0x5fc102};
    for (size_t i = 0; i < 2; ++i) {
      const Copy* copy = &run.copies[sources[i]];
      uint8_t storage[3];
      TC_PIV_object* object = &run.plain_copies[copies];
      memset(object, 0, sizeof *object);
      object->info =
          TC_PIV_catalog_find(TC_PIV_APPLICATION_PIV, TC_PIV_CARD, tag_bytes(tags[i], storage));
      object->encoded = copy->object.encoded;
      object->value = copy->object.value;
      object->status = copy->object.status;
      object->state = TC_PIV_OBJECT_PRESENT;
      copies += copy->present && object->info;
    }
  }
  const TC_PIV_card_check_request request = {&run.inventory,
                                             &run.link,
                                             TC_PIV_CARD,
                                             &run.trust.context,
                                             &run.trust.context,
                                             NULL,
                                             run.card_cvc,
                                             copies ? run.plain_copies : NULL,
                                             copies};
  run.check.certificates = (TC_buffer){run.certificates, sizeof run.certificates};
  run.check.lds_content = (TC_buffer){run.lds, sizeof run.lds};
  size_t work = CHECK_WORK;
  munit_assert_int(TC_PIV_card_check(&request, &run.check, &work, &run.report), ==, TC_PIV_OK);
  const uint8_t order[] = {0x9a, 0x9e};
  const unsigned keys = TC_PIV_CARD_PROVE_CARD_AUTHENTICATION |
                        (run.pin_verified ? TC_PIV_CARD_PROVE_PIV_AUTHENTICATION : 0u);
  tc_piv_card_backend_proofs(&run.backend, run.pin_verified ? order : order + 1,
                             run.pin_verified ? 2 : 1);
  const TC_PIV_card_proof_request proofs = {keys,
                                            {TC_PIV_CARD, run.backend.at, TC_PIV_RSA_PKCS1_V15, 0},
                                            run.backend.random,
                                            &run.trust.options.signatures};
  TC_work_budget budget = {UINT32_MAX};
  munit_assert_int(TC_PIV_card_prove_keys(&run.link, &proofs, &run.proof, &budget, &run.report), ==,
                   TC_PIV_OK);
  size_t outcomes[3] = {0, 0, 0};
  for (size_t i = 0; i < run.report.count; ++i) {
    const TC_PIV_check* check = &run.report.checks[i];
    if (check->outcome == TC_PIV_CHECK_FAILED)
      note("FAILED kind %u container %04x key %02x", check->kind, check->container,
           check->key_reference);
    if (check->outcome < 3)
      ++outcomes[check->outcome];
  }
  note("inventory_and_report: %zu objects, %zu passed, %zu failed, %zu not checkable",
       run.inventory.count, outcomes[TC_PIV_CHECK_PASSED], outcomes[TC_PIV_CHECK_FAILED],
       outcomes[TC_PIV_CHECK_NOT_CHECKABLE]);
  munit_assert_size(outcomes[TC_PIV_CHECK_FAILED], ==, 0);
  if (run.config.expect) {
    /* The card authentication path, the CHUID and 9E. Revocation may lack
     * evidence once the vendored CRLs expire, so it stays unrequired. The
     * secure messaging signer, CVC and plain copies once SM is up, the
     * Security Object signature on contact or with the VCI, and with the PIN
     * the PIV Authentication path, 9A and every signed digest. */
    static const TC_PIV_check_requirement always[] = {{TC_PIV_CHECK_CERTIFICATE_PATH, 0x9e, 0},
                                                      {TC_PIV_CHECK_CHUID, 0, 0},
                                                      {TC_PIV_CHECK_KEY_PROOF, 0x9e, 0}};
    static const TC_PIV_check_requirement secured[] = {{TC_PIV_CHECK_SM_SIGNER, 0, 0},
                                                       {TC_PIV_CHECK_SM_CVC, 0, 0},
                                                       {TC_PIV_CHECK_COPY_MATCH, 0, 0}};
    static const TC_PIV_check_requirement signed_map[] = {{TC_PIV_CHECK_SECURITY_SIGNATURE, 0, 0}};
    static const TC_PIV_check_requirement pin_gated[] = {{TC_PIV_CHECK_CERTIFICATE_PATH, 0x9a, 0},
                                                         {TC_PIV_CHECK_KEY_PROOF, 0x9a, 0},
                                                         {TC_PIV_CHECK_SECURITY_DIGEST, 0, 0}};
    munit_assert_true(
        TC_PIV_card_report_accepts(&run.report, always, sizeof always / sizeof *always));
    munit_assert_true(!run.secured || TC_PIV_card_report_accepts(&run.report, secured,
                                                                 sizeof secured / sizeof *secured));
    munit_assert_true((run.backend.interface == TC_PIV_CONTACTLESS && !run.vci) ||
                      TC_PIV_card_report_accepts(&run.report, signed_map, 1));
    munit_assert_true(
        !run.pin_verified ||
        TC_PIV_card_report_accepts(&run.report, pin_gated, sizeof pin_gated / sizeof *pin_gated));
  }
  expect_guard_clean();
  return MUNIT_OK;
}

/* ---- Setup ---- */

/* 1 when the SHA-256 of bytes is the hex text expected, in either case. */
static int digest_matches(TC_bytes bytes, const char* expected)
{
  uint8_t digest[TC_SHA256_DIGESTLEN];
  char text[2 * TC_SHA256_DIGESTLEN + 1];
  struct TC_SHA256_ctx hash;
  if (TC_SHA256_init(&hash) != TC_OK || TC_SHA256_update(&hash, bytes) != TC_OK ||
      TC_SHA256_final(&hash, digest) != TC_OK)
    return 0;
  for (size_t i = 0; i < sizeof digest; ++i)
    snprintf(text + 2 * i, 3, "%02x", digest[i]);
  return !strcasecmp(text, expected);
}

/* The pinned trust points and CRLs in one validation context. */
static const char* trust_load(void)
{
  const tc_piv_card_trust_paths* paths = &run.config.trust;
  size_t file = 0;
  for (size_t i = 0; i < paths->anchor_count; ++i, ++file)
    if (!example_read_file(paths->anchors[i], run.files[file], FILE_BYTES, &run.anchors[i]) ||
        !digest_matches(run.anchors[i], paths->anchor_sha256[i]))
      return "a trust anchor is unreadable or differs from its pin";
  for (size_t i = 0; i < paths->crl_count; ++i, ++file)
    if (!example_read_file(paths->crls[i], run.files[file], FILE_BYTES, &run.crls[i]))
      return "a CRL is unreadable";
  memset(&run.trust_inputs, 0, sizeof run.trust_inputs);
  run.trust_inputs.anchors = run.anchors;
  run.trust_inputs.anchor_count = paths->anchor_count;
  run.trust_inputs.revocation = run.config.revocation;
  run.trust_inputs.at = run.backend.at;
  if (!example_piv_inspect_trust_init(&run.trust, &run.trust_inputs))
    return "a trust anchor is malformed";
  size_t work = SIZE_MAX;
  static const TC_bytes no_crl = {NULL, 0};
  if (TC_X509_crl_index_init(paths->crl_count ? run.crls : &no_crl, paths->crl_count,
                             &run.trust.options.parsing, &run.trust.parser, &work, run.crl_records,
                             TC_PIV_CARD_TRUST_FILES, &run.crl_index) != TC_TLV_OK ||
      !example_piv_inspect_trust_revocation(&run.trust, &run.crl_index))
    return "a CRL is malformed";
  return NULL;
}

/* The guard policy: reference data and 9C only with a known identity. */
static const char* guard_start(void)
{
  tc_piv_guard_policy policy;
  memset(&policy, 0, sizeof policy);
  policy.minimum_retries = run.config.minimum_retries;
  if (run.config.expect) {
    char path[512];
    if (snprintf(path, sizeof path, "%s/%s.txt", TC_CARD_FIXTURE_DIR, run.config.expect->fixture) <=
            0 ||
        tc_card_fixture_load(&run.expected, path))
      return "unable to load the expected card fixture";
    const tc_card_object* chuid = tc_card_fixture_object(&run.expected, 0x5fc102);
    const tc_card_object* certificate = tc_card_fixture_object(&run.expected, 0x5fc101);
    if (!chuid || !certificate || !run.expected.session_count)
      return "the expected card fixture lacks the CHUID or 5FC101";
    policy.identity[TC_PIV_GUARD_CHUID] = chuid->data;
    policy.identity[TC_PIV_GUARD_CARD_CERTIFICATE] = certificate->data;
    policy.pin_submissions = run.config.pin.length ? 1 : 0;
    policy.pairing_submissions = run.config.pairing_code.length ? 1 : 0;
    policy.signatures = policy.pin_submissions;
  }
  return tc_piv_guard_init(&run.guard, &policy) ? NULL : "invalid guard policy";
}

static const char* setup(void)
{
  const char* failure = guard_start();
  if (failure)
    return failure;
  failure = tc_piv_card_backend_open(&run.backend, &run.config, &run.guard);
  if (failure)
    return failure;
  run.opened = 1;
  return trust_load();
}

/* Clear every session and the card state, and wipe the run. */
static int teardown(int status)
{
  TC_PIV_inventory_clear(&run.inventory);
  TC_PIV_link_clear(&run.extended);
  TC_PIV_link_clear(&run.link);
  TC_PIV_SM_clear(&run.session);
  if (run.opened && !tc_piv_card_backend_close(&run.backend))
    status = EXIT_FAILURE;
  TC_secure_zero(&run, sizeof run);
  return status;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
      {"/01-select-piv", select_piv_scenario, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/02-select-truncated", select_truncated, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/03-discovery-plain", discovery_plain, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/04-plain-objects", plain_objects, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/05-get-response-chain", get_response_chain, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/06-extended", extended, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/07-not-found", not_found, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/08-sm-establish", sm_establish, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/09-vci", vci, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/10-retry-query", retry_query, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/11-pin", pin, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/12-key-proofs", key_proofs, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/13-inventory-and-report", inventory_and_report, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/piv/card", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  const char* malformed = tc_piv_card_config_read(&run.config, TC_VECTOR_DIR);
  if (malformed) {
    fprintf(stderr, "piv_card: %s is malformed\n", malformed);
    return EXIT_FAILURE;
  }
  const char* skip = tc_piv_card_backend_skip(&run.config);
  if (skip) {
    fprintf(stderr, "piv_card: skipped, %s\n", skip);
    return SKIP_STATUS;
  }
  /* The scenarios share the card connection, so munit runs them in this
   * process. */
  char* arguments[64];
  if (argc < 1 || (size_t)argc >= sizeof arguments / sizeof *arguments)
    return EXIT_FAILURE;
  for (int i = 0; i < argc; ++i)
    arguments[i] = argv[i];
  static char no_fork[] = "--no-fork";
  arguments[argc] = no_fork;
  arguments[argc + 1] = NULL;
  const char* failure = setup();
  int status = EXIT_FAILURE;
  if (failure) {
    fprintf(stderr, "piv_card: %s\n", failure);
  } else {
    status = munit_suite_main(&suite, NULL, argc + 1, arguments);
    if (run.guard.counts.refusals) {
      fprintf(stderr, "piv_card: the guard refused %zu commands, first: %s\n",
              run.guard.counts.refusals, run.guard.counts.refusal);
      status = EXIT_FAILURE;
    }
  }
  return teardown(status);
}
