/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* PIV virtual contact interface: the Discovery Object read over the link and
 * the pairing-code VERIFY under secure messaging (SP 800-73-5 Part 1 section
 * 5.5 and Table 2 footnote 9, Part 2 sections 3.2.1.3 and A.6). Secured
 * links use the synthetic tools/sm_fixtures.py handshakes with
 * tests/support/sm_card.c as the card. Plain links use the scripted
 * transport. The pairing code 65135275 is the Part 2 Table 25 example. */
#include <tiny_crypto/piv_vci.h>
#include "cavp.h"
#include "munit.h"
#include "scripted_transport.h"
#include "sm_card.h"
#include "test_util.h"
#include <string.h>
#if TC_TEST_SM_FIXTURES
#include "sm_fixtures.h"
#endif

#define STEP(command, response) {command, response, {0}, {0}, TC_OK, 0}

/* SD 33 card 2 application property template. */
#define PIV_SELECT "00A404000BA00000030800001000010000"
#define PIV_APT(suite)                                                                             \
  "612A4F0BA00000030800001000010079074F05A000000308500A49442D4F6E6520504956AC068001" suite         \
  "0601007F6608020203F802027FFF9000"
/* Synthetic TWIC NEXGEN SELECT and answer (TWIC Part 2 v5 5.1). */
#define TWIC_SELECT "00A4040009A0000003672000000100"
#define TWIC_APT "61144F0BA00000036720000001010379054F03A000007F660802020400020208009000"
#define GET_DISCOVERY "00CB3FFF035C017E00"
/* 7E 12 {4F 0B PIV AID} {5F2F 02 policy 00}. */
#define DISCOVERY(policy)                                                                          \
  "7E124F0BA000000308000010000100"                                                                 \
  "5F2F02" policy "00"

enum { RESPONSE_BYTES = 512, SM_SCRATCH_BYTES = 256, EXCHANGES = 64 };

static const uint8_t pairing_code[] = {'6', '5', '1', '3', '5', '2', '7', '5'};
static const uint8_t host_id[8] = {0};

static tc_sm_card card;
static tc_script script;
static uint8_t scratch[TC_APDU_SHORT_COMMAND_MAX_BYTES];
static uint8_t sm_scratch[SM_SCRATCH_BYTES];
static uint8_t response_bytes[RESPONSE_BYTES];
static uint8_t select_bytes[64], key_bytes[512];
static TC_PIV_SM session;
static TC_PIV_SM_workspace workspace;

static size_t hex(const char* text, uint8_t* out, size_t capacity)
{
  size_t length = 0;
  munit_assert_true(tc_test_hex_decode(text, TC_TEST_HEX_SEPARATED, out, capacity, &length));
  return length;
}

static TC_buffer response_buffer(void)
{
  memset(response_bytes, 0xee, sizeof response_bytes);
  return (TC_buffer){response_bytes, sizeof response_bytes};
}

static TC_PIV_link_info link_info(const TC_PIV_link* link)
{
  TC_PIV_link_info info;
  memset(&info, 0xa5, sizeof info);
  TC_PIV_link_info_get(link, &info);
  return info;
}

/* A plain link over the scripted transport with the PIV application
 * selected. */
static void plain_link(TC_PIV_link* link, const tc_script_step* steps, size_t count,
                       TC_PIV_interface interface)
{
  const TC_PIV_link_options options = {{TC_APDU_SHORT, 0, EXCHANGES, 0, 0}, interface, 0};
  TC_PIV_application application;
  tc_script_init(&script, steps, count);
  munit_assert_int(TC_PIV_link_init(link, tc_script_transport(&script), &options,
                                    (TC_buffer){scratch, sizeof scratch}),
                   ==, TC_PIV_OK);
  munit_assert_int(TC_PIV_select(link, TC_PIV_APPLICATION_PIV, 0, response_buffer(), &application),
                   ==, TC_PIV_OK);
}

/* A discovery the caller parsed itself, which never counts as read under
 * secure messaging. */
static TC_PIV_discovery parsed_discovery(const char* text, TC_PIV_discovery_profile profile)
{
  static uint8_t encoded[32];
  TC_PIV_discovery discovery;
  const size_t length = hex(text, encoded, sizeof encoded);
  munit_assert_int(TC_PIV_discovery_read((TC_bytes){encoded, length}, profile, &discovery), ==,
                   TC_TLV_OK);
  return discovery;
}

/* A plain contact read records secured 0, and the object borrows the
 * response. */
TC_TEST(discovery_plain)
{
  static const tc_script_step steps[] = {STEP(PIV_SELECT, PIV_APT("2E")),
                                         STEP(GET_DISCOVERY, DISCOVERY("48") "9000")};
  TC_PIV_link link;
  TC_PIV_discovery discovery;
  memset(&discovery, 0xa5, sizeof discovery);
  plain_link(&link, steps, 2, TC_PIV_CONTACT);
  munit_assert_int(TC_PIV_discovery_get(&link, TC_PIV_DISCOVERY_PIV, response_buffer(), &discovery),
                   ==, TC_PIV_OK);
  munit_assert_uint8(discovery.policy, ==, TC_PIV_POLICY_PIV_PIN | TC_PIV_POLICY_VCI);
  munit_assert_uint8(discovery.preference, ==, 0);
  munit_assert_uint8(discovery.profile, ==, TC_PIV_DISCOVERY_PIV);
  munit_assert_uint8(discovery.secured, ==, 0);
  munit_assert_ptr_equal(discovery.aid.data, response_bytes + 4);
  munit_assert_size(discovery.aid.length, ==, 11);
  munit_assert_size(script.mismatch, ==, 0);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* Answers outside the Discovery Object rules: a card status, an object
 * outside the profile, other framing and an empty TWIC form. Each wipes the
 * response and leaves out unchanged. */
TC_TEST(discovery_failures)
{
  static const struct {
    const char* answer;
    TC_PIV_discovery_profile profile;
    TC_PIV_result result;
  } cases[] = {
      {"6A82", TC_PIV_DISCOVERY_PIV, TC_PIV_CARD_STATUS},
      {DISCOVERY("04") "9000", TC_PIV_DISCOVERY_PIV, TC_PIV_INVALID},
      {"7E134F0BA000000308000010000100"
       "5F2F03480000"
       "9000",
       TC_PIV_DISCOVERY_PIV, TC_PIV_INVALID},
      {"7E027F009000", TC_PIV_DISCOVERY_PIV, TC_PIV_INVALID},
  };
  for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
    const tc_script_step steps[] = {STEP(PIV_SELECT, PIV_APT("2E")),
                                    STEP(GET_DISCOVERY, cases[i].answer)};
    TC_PIV_link link;
    TC_PIV_discovery discovery;
    memset(&discovery, 0xa5, sizeof discovery);
    plain_link(&link, steps, 2, TC_PIV_CONTACT);
    munit_assert_int(TC_PIV_discovery_get(&link, cases[i].profile, response_buffer(), &discovery),
                     ==, cases[i].result);
    munit_assert_true(tc_test_all_zero(response_bytes, sizeof response_bytes));
    munit_assert_uint8(discovery.policy, ==, 0xa5);
    TC_PIV_link_clear(&link);
  }
  return MUNIT_OK;
}

/* The TWIC application may wrap the object in 53 (TWIC Part 2 v5 4.7.5),
 * and its empty forms mean the card announces no policy. */
TC_TEST(discovery_twic)
{
  static const tc_script_step wrapped[] = {STEP(TWIC_SELECT, TWIC_APT),
                                           STEP(GET_DISCOVERY, "5314" DISCOVERY("04") "9000"),
                                           STEP(GET_DISCOVERY, "53009000")};
  TC_PIV_link link;
  TC_PIV_discovery discovery;
  TC_PIV_application application;
  const TC_PIV_link_options options = {{TC_APDU_SHORT, 0, EXCHANGES, 0, 0}, TC_PIV_CONTACT, 0};
  tc_script_init(&script, wrapped, 3);
  munit_assert_int(TC_PIV_link_init(&link, tc_script_transport(&script), &options,
                                    (TC_buffer){scratch, sizeof scratch}),
                   ==, TC_PIV_OK);
  munit_assert_int(
      TC_PIV_select(&link, TC_PIV_APPLICATION_TWIC, 0, response_buffer(), &application), ==,
      TC_PIV_OK);
  munit_assert_int(
      TC_PIV_discovery_get(&link, TC_PIV_DISCOVERY_TWIC, response_buffer(), &discovery), ==,
      TC_PIV_OK);
  munit_assert_uint8(discovery.policy, ==, TC_PIV_POLICY_VCI_WITHOUT_PAIRING);
  munit_assert_uint8(discovery.profile, ==, TC_PIV_DISCOVERY_TWIC);
  munit_assert_ptr_equal(discovery.aid.data, response_bytes + 6);
  memset(&discovery, 0xa5, sizeof discovery);
  munit_assert_int(
      TC_PIV_discovery_get(&link, TC_PIV_DISCOVERY_TWIC, response_buffer(), &discovery), ==,
      TC_PIV_UNSUPPORTED);
  munit_assert_uint8(discovery.policy, ==, 0xa5);
  munit_assert_true(tc_test_all_zero(response_bytes, sizeof response_bytes));
  munit_assert_size(script.mismatch, ==, 0);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* Argument errors change nothing and send nothing. */
TC_TEST(discovery_arguments)
{
  static const tc_script_step steps[] = {STEP(PIV_SELECT, PIV_APT("2E"))};
  TC_PIV_link link, cleared;
  TC_PIV_discovery discovery;
  memset(&cleared, 0, sizeof cleared);
  memset(&discovery, 0xa5, sizeof discovery);
  plain_link(&link, steps, 1, TC_PIV_CONTACT);
  const TC_buffer response = response_buffer();
  munit_assert_int(TC_PIV_discovery_get(NULL, TC_PIV_DISCOVERY_PIV, response, &discovery), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_discovery_get(&cleared, TC_PIV_DISCOVERY_PIV, response, &discovery), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_discovery_get(&link, TC_PIV_DISCOVERY_PIV, response, NULL), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_discovery_get(&link, (TC_PIV_discovery_profile)7, response, &discovery),
                   ==, TC_PIV_ARGUMENT);
  munit_assert_int(
      TC_PIV_discovery_get(&link, TC_PIV_DISCOVERY_PIV, (TC_buffer){response_bytes, 1}, &discovery),
      ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_discovery_get(&link, TC_PIV_DISCOVERY_PIV,
                                        (TC_buffer){scratch, sizeof scratch}, &discovery),
                   ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_discovery_get(&link, TC_PIV_DISCOVERY_PIV,
                                        (TC_buffer){(uint8_t*)&discovery, sizeof discovery},
                                        &discovery),
                   ==, TC_PIV_ARGUMENT);
  munit_assert_uint8(discovery.policy, ==, 0xa5);
  munit_assert_size(script.next, ==, 1);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* No VCI without secure messaging: a plain contactless link is refused
 * before anything is sent, and so is a discovery read without it. */
TC_TEST(unsecured)
{
  static const tc_script_step steps[] = {STEP(PIV_SELECT, PIV_APT("2E"))};
  TC_PIV_link link;
  TC_PIV_vci_mode mode = (TC_PIV_vci_mode)7;
  const TC_PIV_discovery discovery = parsed_discovery(DISCOVERY("4C"), TC_PIV_DISCOVERY_PIV);
  plain_link(&link, steps, 1, TC_PIV_CONTACTLESS);
  munit_assert_int(TC_PIV_vci_establish(&link, &discovery, (TC_bytes){NULL, 0}, &mode), ==,
                   TC_PIV_REFUSED);
  munit_assert_int(
      TC_PIV_vci_establish(&link, &discovery, (TC_bytes){pairing_code, sizeof pairing_code}, &mode),
      ==, TC_PIV_REFUSED);
  munit_assert_int(mode, ==, 7);
  munit_assert_uint8(link_info(&link).vci, ==, 0);
  munit_assert_size(script.next, ==, 1);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

#if TC_TEST_SM_FIXTURES
static const struct tc_sm_fixture* fixture(void)
{
  const struct tc_sm_fixture* found = NULL;
  for (size_t i = 0; i < sizeof sm_fixtures / sizeof *sm_fixtures && !found; ++i)
    if (!sm_fixtures[i].intermediate.length &&
        (sm_fixtures[i].suite == TC_PIV_SM_CS2 ? TC_PIV_SM_ENABLE_CS2 : TC_PIV_SM_ENABLE_CS7))
      found = &sm_fixtures[i];
  munit_assert_not_null(found);
  return found;
}

static TC_status scalar_one(void* context, uint8_t* output, size_t length)
{
  (void)context;
  memset(output, 0, length);
  output[length - 1] = 1;
  return TC_OK;
}

/* Run key establishment with the fixture handshake and secure the link. */
static void link_secure(TC_PIV_link* link)
{
  const struct tc_sm_fixture* f = fixture();
  TC_PIV_SM_peer peer;
  memcpy(key_bytes, f->response.data, f->response.length);
  key_bytes[f->response.length] = 0x90;
  key_bytes[f->response.length + 1] = 0x00;
  card.key_command = f->request;
  card.key_answer = (TC_bytes){key_bytes, f->response.length + 2};
  munit_assert_int(TC_PIV_SM_key_request(link, &session, f->suite, host_id,
                                         (TC_random_source){scalar_one, NULL}, response_buffer(),
                                         &peer, &workspace),
                   ==, TC_PIV_OK);
  munit_assert_int(TC_PIV_SM_finish(&session, &peer, f->public_key, &workspace), ==, TC_OK);
  tc_sm_card_keys(&card, f->material);
  munit_assert_int(TC_PIV_link_secure(link, &workspace, (TC_buffer){sm_scratch, sizeof sm_scratch}),
                   ==, TC_PIV_OK);
}

/* A secured contactless link to the card model with the PIV application
 * selected. */
static void secured_link(TC_PIV_link* link, TC_PIV_interface interface)
{
  char apt[160];
  const TC_PIV_link_options options = {{TC_APDU_SHORT, 0, EXCHANGES, 0, 0}, interface, 0};
  TC_PIV_application application;
  tc_sm_card_init(&card);
  memcpy(apt, PIV_APT("00"), sizeof PIV_APT("00"));
  memcpy(strstr(apt, "AC068001") + 8, fixture()->suite == TC_PIV_SM_CS2 ? "27" : "2E", 2);
  card.select_answer = (TC_bytes){select_bytes, hex(apt, select_bytes, sizeof select_bytes)};
  memset(&session, 0, sizeof session);
  munit_assert_int(TC_PIV_link_init(link, tc_sm_card_transport(&card), &options,
                                    (TC_buffer){scratch, sizeof scratch}),
                   ==, TC_PIV_OK);
  munit_assert_int(TC_PIV_select(link, TC_PIV_APPLICATION_PIV, 0, response_buffer(), &application),
                   ==, TC_PIV_OK);
  link_secure(link);
}

/* Offset of the first policy byte in the Discovery Object. */
enum { POLICY_OFFSET = 18 };

/* Read the Discovery Object under secure messaging with policy byte policy. */
static TC_PIV_discovery secured_discovery(TC_PIV_link* link, uint8_t policy)
{
  TC_PIV_discovery discovery;
  card.answer_length = hex(DISCOVERY("48"), card.answer, sizeof card.answer);
  card.answer[POLICY_OFFSET] = policy;
  card.inner_sw = 0x9000;
  munit_assert_int(TC_PIV_discovery_get(link, TC_PIV_DISCOVERY_PIV, response_buffer(), &discovery),
                   ==, TC_PIV_OK);
  munit_assert_true(card.mac_valid);
  munit_assert_uint8(discovery.secured, ==, 1);
  munit_assert_uint8(discovery.policy, ==, policy);
  return discovery;
}

/* The default configuration: VERIFY 98 with the pairing code under secure
 * messaging (Part 2 Table 25), then a contactless PIN is allowed. */
TC_TEST(paired)
{
  static const uint8_t pin[] = {'1', '4', '1', '5', '9', '2'};
  TC_PIV_link link;
  TC_PIV_vci_mode mode = (TC_PIV_vci_mode)7;
  TC_PIV_reference_status status;
  secured_link(&link, TC_PIV_CONTACTLESS);
  const TC_PIV_discovery discovery = secured_discovery(&link, 0x48);
  munit_assert_int(TC_PIV_pin_verify(&link, 0x80, (TC_bytes){pin, sizeof pin}, 3, &status), ==,
                   TC_PIV_REFUSED);
  card.answer_length = 0;
  munit_assert_int(
      TC_PIV_vci_establish(&link, &discovery, (TC_bytes){pairing_code, sizeof pairing_code}, &mode),
      ==, TC_PIV_OK);
  munit_assert_int(mode, ==, TC_PIV_VCI_PAIRED);
  munit_assert_memory_equal(3, card.header, "\x20\x00\x98");
  munit_assert_size(card.plain_length, ==, sizeof pairing_code);
  munit_assert_memory_equal(sizeof pairing_code, card.plain, pairing_code);
  munit_assert_int(card.plain_le, ==, 0);
  munit_assert_size(card.plain_commands, ==, 0);
  munit_assert_true(tc_test_all_zero(sm_scratch, sizeof sm_scratch));
  munit_assert_true(tc_test_all_zero(scratch, sizeof scratch));
  munit_assert_uint8(link_info(&link).vci, ==, 1);
  munit_assert_uint16(TC_PIV_link_status(&link), ==, 0x9000);
  card.inner_sw = 0x63c5;
  munit_assert_int(TC_PIV_verify_status(&link, 0x80, &status), ==, TC_PIV_OK);
  munit_assert_uint(status.retries, ==, 5);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* Policy bit 3: the VCI follows from secure messaging alone, and nothing is
 * sent. A code may be passed and stays unused. */
TC_TEST(without_pairing)
{
  TC_PIV_link link;
  TC_PIV_vci_mode mode = (TC_PIV_vci_mode)7;
  secured_link(&link, TC_PIV_CONTACTLESS);
  const TC_PIV_discovery discovery = secured_discovery(&link, 0x4c);
  const size_t transmits = card.transmits;
  munit_assert_int(TC_PIV_vci_establish(&link, &discovery, (TC_bytes){NULL, 0}, &mode), ==,
                   TC_PIV_OK);
  munit_assert_int(mode, ==, TC_PIV_VCI_WITHOUT_PAIRING);
  munit_assert_size(card.transmits, ==, transmits);
  munit_assert_uint8(link_info(&link).vci, ==, 1);
  mode = (TC_PIV_vci_mode)7;
  munit_assert_int(
      TC_PIV_vci_establish(&link, &discovery, (TC_bytes){pairing_code, sizeof pairing_code}, &mode),
      ==, TC_PIV_OK);
  munit_assert_int(mode, ==, TC_PIV_VCI_WITHOUT_PAIRING);
  munit_assert_size(card.transmits, ==, transmits);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* A rejected code is CARD_STATUS with the session kept and the VCI clear
 * (Part 2 3.2.1.3). A later correct code establishes it. */
TC_TEST(rejected)
{
  static const uint16_t statuses[] = {0x6300, 0x6a80, 0x6a88};
  for (size_t i = 0; i < sizeof statuses / sizeof statuses[0]; ++i) {
    TC_PIV_link link;
    TC_PIV_vci_mode mode = (TC_PIV_vci_mode)7;
    secured_link(&link, TC_PIV_CONTACTLESS);
    const TC_PIV_discovery discovery = secured_discovery(&link, 0x48);
    card.answer_length = 0;
    munit_assert_int(TC_PIV_vci_establish(&link, &discovery,
                                          (TC_bytes){pairing_code, sizeof pairing_code}, &mode),
                     ==, TC_PIV_OK);
    card.inner_sw = statuses[i];
    munit_assert_int(TC_PIV_vci_establish(&link, &discovery,
                                          (TC_bytes){pairing_code, sizeof pairing_code}, &mode),
                     ==, TC_PIV_CARD_STATUS);
    munit_assert_int(mode, ==, TC_PIV_VCI_PAIRED);
    munit_assert_uint16(TC_PIV_link_status(&link), ==, statuses[i]);
    const TC_PIV_link_info info = link_info(&link);
    munit_assert_uint8(info.vci, ==, 0);
    munit_assert_uint8(info.secured, ==, 1);
    munit_assert_int(TC_PIV_SM_get_state(&session), ==, TC_PIV_SM_READY);
    card.inner_sw = 0x9000;
    munit_assert_int(TC_PIV_vci_establish(&link, &discovery,
                                          (TC_bytes){pairing_code, sizeof pairing_code}, &mode),
                     ==, TC_PIV_OK);
    munit_assert_uint8(link_info(&link).vci, ==, 1);
    TC_PIV_link_clear(&link);
  }
  return MUNIT_OK;
}

/* A secure messaging failure on the pairing VERIFY ends the session (Part 2
 * 4.3, footnote 25): an outer status is CARD_STATUS with that status, a bad
 * response MAC is INVALID. Both clear the VCI and wipe the SM scratch, and
 * the mode stays unchanged. */
TC_TEST(session_lost)
{
  static const struct {
    tc_sm_card_fault fault;
    TC_PIV_result result;
    uint16_t status;
  } cases[] = {{TC_SM_CARD_OUTER_STATUS, TC_PIV_CARD_STATUS, 0x6988},
               {TC_SM_CARD_BAD_MAC, TC_PIV_INVALID, 0}};
  for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
    TC_PIV_link link;
    TC_PIV_vci_mode mode = (TC_PIV_vci_mode)7;
    secured_link(&link, TC_PIV_CONTACTLESS);
    const TC_PIV_discovery discovery = secured_discovery(&link, 0x48);
    card.answer_length = 0;
    card.fault = cases[i].fault;
    card.outer_sw = 0x6988;
    munit_assert_int(TC_PIV_vci_establish(&link, &discovery,
                                          (TC_bytes){pairing_code, sizeof pairing_code}, &mode),
                     ==, cases[i].result);
    munit_assert_int(mode, ==, 7);
    munit_assert_uint16(TC_PIV_link_status(&link), ==, cases[i].status);
    const TC_PIV_link_info info = link_info(&link);
    munit_assert_uint8(info.vci, ==, 0);
    munit_assert_uint8(info.secured, ==, 0);
    munit_assert_uint8(info.sm_lost, ==, 1);
    munit_assert_true(tc_test_all_zero(sm_scratch, sizeof sm_scratch));
    munit_assert_true(tc_test_all_zero(scratch, sizeof scratch));
    /* A lost session refuses the next attempt before sending. */
    const size_t transmits = card.transmits;
    card.fault = TC_SM_CARD_ANSWER;
    munit_assert_int(TC_PIV_vci_establish(&link, &discovery,
                                          (TC_bytes){pairing_code, sizeof pairing_code}, &mode),
                     ==, TC_PIV_REFUSED);
    munit_assert_size(card.transmits, ==, transmits);
    TC_PIV_link_clear(&link);
  }
  return MUNIT_OK;
}

/* Cards without a VCI, the TWIC profile and a discovery parsed outside the
 * link are turned away before anything is sent. */
TC_TEST(unavailable)
{
  TC_PIV_link link;
  TC_PIV_vci_mode mode = (TC_PIV_vci_mode)7;
  const TC_bytes code = {pairing_code, sizeof pairing_code};
  secured_link(&link, TC_PIV_CONTACTLESS);
  const TC_PIV_discovery no_vci = secured_discovery(&link, 0x40);
  const size_t transmits = card.transmits;
  munit_assert_int(TC_PIV_vci_establish(&link, &no_vci, code, &mode), ==, TC_PIV_UNSUPPORTED);
  TC_PIV_discovery twic = parsed_discovery(DISCOVERY("04"), TC_PIV_DISCOVERY_TWIC);
  twic.secured = 1;
  munit_assert_int(TC_PIV_vci_establish(&link, &twic, code, &mode), ==, TC_PIV_UNSUPPORTED);
  const TC_PIV_discovery plain = parsed_discovery(DISCOVERY("48"), TC_PIV_DISCOVERY_PIV);
  munit_assert_int(TC_PIV_vci_establish(&link, &plain, code, &mode), ==, TC_PIV_REFUSED);
  munit_assert_int(mode, ==, 7);
  munit_assert_size(card.transmits, ==, transmits);
  munit_assert_uint8(link_info(&link).vci, ==, 0);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* Malformed codes, missing pointers and overlap are argument errors that
 * leave the mode and the link unchanged. */
TC_TEST(arguments)
{
  static const uint8_t short_code[] = {'1', '2', '3', '4', '5', '6', '7'};
  static const uint8_t letter[] = {'1', '2', '3', '4', '5', '6', '7', 'A'};
  TC_PIV_link link, cleared;
  TC_PIV_vci_mode mode = (TC_PIV_vci_mode)7;
  const TC_bytes code = {pairing_code, sizeof pairing_code};
  memset(&cleared, 0, sizeof cleared);
  secured_link(&link, TC_PIV_CONTACTLESS);
  const TC_PIV_discovery discovery = secured_discovery(&link, 0x48);
  const size_t transmits = card.transmits;
  munit_assert_int(TC_PIV_vci_establish(NULL, &discovery, code, &mode), ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_vci_establish(&cleared, &discovery, code, &mode), ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_vci_establish(&link, NULL, code, &mode), ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_vci_establish(&link, &discovery, code, NULL), ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_vci_establish(&link, &discovery, (TC_bytes){NULL, 8}, &mode), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_vci_establish(&link, &discovery, (TC_bytes){NULL, 0}, &mode), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(
      TC_PIV_vci_establish(&link, &discovery, (TC_bytes){short_code, sizeof short_code}, &mode), ==,
      TC_PIV_ARGUMENT);
  munit_assert_int(
      TC_PIV_vci_establish(&link, &discovery, (TC_bytes){letter, sizeof letter}, &mode), ==,
      TC_PIV_ARGUMENT);
  memcpy(sm_scratch, pairing_code, sizeof pairing_code);
  munit_assert_int(TC_PIV_vci_establish(&link, &discovery, (TC_bytes){sm_scratch, 8}, &mode), ==,
                   TC_PIV_ARGUMENT);
  memset(sm_scratch, 0, sizeof sm_scratch);
  const TC_PIV_discovery no_vci = {discovery.aid, 0x40, 0, TC_PIV_DISCOVERY_PIV, 1};
  munit_assert_int(TC_PIV_vci_establish(&link, &no_vci, (TC_bytes){letter, sizeof letter}, &mode),
                   ==, TC_PIV_ARGUMENT);
  munit_assert_int(mode, ==, 7);
  munit_assert_size(card.transmits, ==, transmits);
  munit_assert_uint8(link_info(&link).vci, ==, 0);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* The VCI ends with the session state it depends on: SELECT, unsecure, a
 * session loss and a new key request (Part 2 4.3). */
TC_TEST(cleared)
{
  for (int event = 0; event < 4; ++event) {
    TC_PIV_link link;
    TC_PIV_vci_mode mode;
    TC_PIV_application application;
    TC_PIV_data_object object;
    TC_PIV_SM_peer peer;
    static const uint8_t tag[] = {0x7e};
    secured_link(&link, TC_PIV_CONTACTLESS);
    const TC_PIV_discovery discovery = secured_discovery(&link, 0x4c);
    munit_assert_int(TC_PIV_vci_establish(&link, &discovery, (TC_bytes){NULL, 0}, &mode), ==,
                     TC_PIV_OK);
    munit_assert_uint8(link_info(&link).vci, ==, 1);
    switch (event) {
    case 0:
      munit_assert_int(
          TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 0, response_buffer(), &application), ==,
          TC_PIV_OK);
      break;
    case 1:
      TC_PIV_link_unsecure(&link);
      break;
    case 2:
      card.fault = TC_SM_CARD_BAD_MAC;
      munit_assert_int(
          TC_PIV_get_data(&link, (TC_bytes){tag, sizeof tag}, response_buffer(), &object), ==,
          TC_PIV_INVALID);
      munit_assert_uint8(link_info(&link).sm_lost, ==, 1);
      break;
    default:
      TC_PIV_link_unsecure(&link);
      munit_assert_uint8(link_info(&link).vci, ==, 0);
      munit_assert_int(TC_PIV_SM_key_request(&link, &session, fixture()->suite, host_id,
                                             (TC_random_source){scalar_one, NULL},
                                             response_buffer(), &peer, &workspace),
                       ==, TC_PIV_OK);
      break;
    }
    munit_assert_uint8(link_info(&link).vci, ==, 0);
    /* Establishing again needs the session and a fresh read. */
    munit_assert_int(TC_PIV_vci_establish(&link, &discovery, (TC_bytes){NULL, 0}, &mode), ==,
                     event == 0 ? TC_PIV_OK : TC_PIV_REFUSED);
    TC_PIV_link_clear(&link);
  }
  return MUNIT_OK;
}

/* The contact interface accepts the call (Part 1 Table 4 footnote 11). */
TC_TEST(contact)
{
  TC_PIV_link link;
  TC_PIV_vci_mode mode;
  secured_link(&link, TC_PIV_CONTACT);
  const TC_PIV_discovery discovery = secured_discovery(&link, 0x48);
  card.answer_length = 0;
  munit_assert_int(
      TC_PIV_vci_establish(&link, &discovery, (TC_bytes){pairing_code, sizeof pairing_code}, &mode),
      ==, TC_PIV_OK);
  munit_assert_int(mode, ==, TC_PIV_VCI_PAIRED);
  munit_assert_uint8(link_info(&link).vci, ==, 1);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}
#endif

static MunitTest tests[] = {
    {"/discovery-plain", discovery_plain, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/discovery-failures", discovery_failures, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/discovery-twic", discovery_twic, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/discovery-arguments", discovery_arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/unsecured", unsecured, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#if TC_TEST_SM_FIXTURES
    {"/paired", paired, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/without-pairing", without_pairing, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/rejected", rejected, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/session-lost", session_lost, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/unavailable", unavailable, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/arguments", arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/cleared", cleared, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/contact", contact, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
static const MunitSuite suite = {"/piv-vci", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[])
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
