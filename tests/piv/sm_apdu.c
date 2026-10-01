/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* PIV secure messaging on a card link: key establishment framing (SP
 * 800-73-5 Part 2 4.1.1, 4.1.8), protected commands and responses (4.2.2 to
 * 4.2.7) and the session-loss rule (4.3, footnote 25). Sessions use the
 * synthetic tools/sm_fixtures.py handshakes, and tests/support/sm_card.c
 * plays the card. The recorded key establishment comes from NIST SD 33 card
 * 2 (tests/vectors/piv/sm_captures/nist_special_database_33_card_2.json,
 * exchange 49). */
#include <tiny_crypto/piv_sm_apdu.h>
#include "cavp.h"
#include "munit.h"
#include "piv_link_internal.h"
#include "sm_card.h"
#include "test_util.h"
#include <string.h>
#if TC_TEST_SM_FIXTURES
#include "sm_fixtures.h"
#endif

enum { RESPONSE_BYTES = 4096, SM_SCRATCH_BYTES = 1024, EXCHANGES = 1000 };

/* SD 33 card 2 application property template with the suite byte replaced. */
#define APT(suite)                                                                                 \
  "612A4F0BA00000030800001000010079074F05A000000308500A49442D4F6E6520504956AC068001" suite         \
  "0601007F6608020203F802027FFF9000"

static tc_sm_card card;
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

static TC_buffer response_buffer(size_t capacity)
{
  memset(response_bytes, 0xee, sizeof response_bytes);
  return (TC_buffer){response_bytes, capacity};
}

static TC_status scalar_one(void* context, uint8_t* output, size_t length)
{
  (void)context;
  memset(output, 0, length);
  output[length - 1] = 1;
  return TC_OK;
}

static TC_status failing_random(void* context, uint8_t* output, size_t length)
{
  (void)context;
  (void)output;
  (void)length;
  return TC_ERROR;
}

static const uint8_t host_id[8] = {0};

/* Open a link to the card model and select the PIV application announcing
 * suite (27 or 2E). */
static void link_open(TC_PIV_link* link, TC_PIV_interface interface, TC_APDU_length_format format,
                      size_t exchanges, const char* suite)
{
  char apt[160];
  const TC_PIV_link_options options = {{format, 0, exchanges, 0, 0}, interface, 0};
  TC_PIV_application application;
  tc_sm_card_init(&card);
  memcpy(apt, APT("00"), sizeof APT("00"));
  memcpy(strstr(apt, "AC068001") + 8, suite, 2);
  card.select_answer = (TC_bytes){select_bytes, hex(apt, select_bytes, sizeof select_bytes)};
  memset(sm_scratch, 0, sizeof sm_scratch);
  memset(&session, 0, sizeof session);
  munit_assert_int(TC_PIV_link_init(link, tc_sm_card_transport(&card), &options,
                                    (TC_buffer){scratch, sizeof scratch}),
                   ==, TC_PIV_OK);
  munit_assert_int(
      TC_PIV_select(link, TC_PIV_APPLICATION_PIV, 0, response_buffer(RESPONSE_BYTES), &application),
      ==, TC_PIV_OK);
}

static void link_info(const TC_PIV_link* link, TC_PIV_link_info* info)
{
  memset(info, 0xa5, sizeof *info);
  TC_PIV_link_info_get(link, info);
}

#if TC_TEST_SM_FIXTURES
static const struct tc_sm_fixture* fixture_for(TC_PIV_SM_suite suite)
{
  const struct tc_sm_fixture* found = NULL;
  for (size_t i = 0; i < sizeof sm_fixtures / sizeof *sm_fixtures && !found; ++i)
    if (sm_fixtures[i].suite == suite && !sm_fixtures[i].intermediate.length)
      found = &sm_fixtures[i];
  munit_assert_not_null(found);
  return found;
}

static const char* suite_hex(TC_PIV_SM_suite suite)
{
  return suite == TC_PIV_SM_CS2 ? "27" : "2E";
}

/* Establish and bind a session with the fixture handshake: the card model
 * answers the key establishment and takes the derived keys. */
static void key_answer_set(const struct tc_sm_fixture* fixture)
{
  memcpy(key_bytes, fixture->response.data, fixture->response.length);
  key_bytes[fixture->response.length] = 0x90;
  key_bytes[fixture->response.length + 1] = 0x00;
  card.key_command = fixture->request;
  card.key_answer = (TC_bytes){key_bytes, fixture->response.length + 2};
}

static void link_secure(TC_PIV_link* link, const struct tc_sm_fixture* fixture)
{
  TC_PIV_SM_peer peer;
  key_answer_set(fixture);
  munit_assert_int(TC_PIV_SM_key_request(link, &session, fixture->suite, host_id,
                                         (TC_random_source){scalar_one, NULL},
                                         response_buffer(RESPONSE_BYTES), &peer, &workspace),
                   ==, TC_PIV_OK);
  munit_assert_false(card.broken);
  munit_assert_int(TC_PIV_SM_get_state(&session), ==, TC_PIV_SM_ESTABLISHING);
  munit_assert_int(TC_PIV_SM_finish(&session, &peer, fixture->public_key, &workspace), ==, TC_OK);
  tc_sm_card_keys(&card, fixture->material);
  munit_assert_int(TC_PIV_link_secure(link, &workspace, (TC_buffer){sm_scratch, sizeof sm_scratch}),
                   ==, TC_PIV_OK);
}

static void secured_link(TC_PIV_link* link, TC_PIV_SM_suite suite, TC_PIV_interface interface)
{
  link_open(link, interface, TC_APDU_SHORT, EXCHANGES, suite_hex(suite));
  link_secure(link, fixture_for(suite));
}

static const TC_PIV_SM_suite suites[] = {
#if TC_PIV_SM_ENABLE_CS2
    TC_PIV_SM_CS2,
#endif
#if TC_PIV_SM_ENABLE_CS7
    TC_PIV_SM_CS7,
#endif
};
#define SUITE_COUNT (sizeof suites / sizeof suites[0])

/* Send any protected command through the link dispatch. */
static TC_PIV_result send(TC_PIV_link* link, uint8_t ins, TC_bytes data, uint32_t ne,
                          size_t capacity, TC_APDU_response* out)
{
  const TC_APDU_command command = {data, ne, 0x00, ins, 0x07, 0x9a};
  return tc_piv_link_transceive(link, TC_PIV_COMMAND_GENERAL_AUTHENTICATE, &command,
                                response_buffer(capacity), out);
}

static void assert_lost(const TC_PIV_link* link, uint16_t status)
{
  TC_PIV_link_info info;
  link_info(link, &info);
  munit_assert_uint8(info.secured, ==, 0);
  munit_assert_uint8(info.sm_lost, ==, 1);
  munit_assert_uint8(info.vci, ==, 0);
  munit_assert_uint8(info.pin_verified, ==, 0);
  munit_assert_uint16(TC_PIV_link_status(link), ==, status);
  munit_assert_int(TC_PIV_SM_get_state(&session), ==, TC_PIV_SM_IDLE);
  munit_assert_true(tc_test_all_zero(&session, sizeof session));
  munit_assert_true(tc_test_all_zero(sm_scratch, sizeof sm_scratch));
}

/* The first protected command is the VERIFY retry query of the fixture:
 * 0C 20 00 80 0A 8E 08 tag 00 (4.2.4). The model's answer matches the
 * fixture reply, which cross-checks the model. */
TC_TEST(verify_query)
{
  for (size_t s = 0; s < SUITE_COUNT; ++s) {
    const struct tc_sm_fixture* fixture = fixture_for(suites[s]);
    TC_PIV_link link;
    TC_PIV_reference_status status;
    uint8_t expected[32] = {0x0c, 0x20, 0x00, 0x80, 0x0a};
    secured_link(&link, suites[s], TC_PIV_CONTACT);
    munit_assert_int(TC_PIV_verify_status(&link, 0x80, &status), ==, TC_PIV_OK);
    munit_assert_uint8(status.verified, ==, 1);
    munit_assert_uint16(TC_PIV_link_status(&link), ==, 0x9000);
    munit_assert_size(fixture->command.length, ==, 10);
    memcpy(expected + 5, fixture->command.data, 10);
    munit_assert_size(card.first_command_length, ==, 16);
    munit_assert_memory_equal(16, card.first_command, expected);
    munit_assert_memory_equal(fixture->reply.length, card.previous, fixture->reply.data);
    munit_assert_size(card.plain_length, ==, 0);
    munit_assert_int(card.plain_le, ==, 0);
    munit_assert_size(card.plain_commands, ==, 0);
    TC_PIV_link_clear(&link);
    munit_assert_true(tc_test_all_zero(&session, sizeof session));
  }
  return MUNIT_OK;
}

/* GET DATA under SM: 87 11 01 with one block, 97 01 00, and the plaintext
 * decrypted in place in the response buffer. */
TC_TEST(get_data)
{
  static const uint8_t tag[] = {0x5f, 0xc1, 0x02};
  static const uint8_t object[] = {0x53, 0x04, 0x30, 0x02, 0x01, 0x02};
  static const uint8_t plain_command[] = {0x5c, 0x03, 0x5f, 0xc1, 0x02};
  for (size_t s = 0; s < SUITE_COUNT; ++s) {
    TC_PIV_link link;
    TC_PIV_data_object out;
    secured_link(&link, suites[s], TC_PIV_CONTACTLESS);
    memcpy(card.answer, object, sizeof object);
    card.answer_length = sizeof object;
    munit_assert_int(
        TC_PIV_get_data(&link, (TC_bytes){tag, sizeof tag}, response_buffer(RESPONSE_BYTES), &out),
        ==, TC_PIV_OK);
    munit_assert_true(card.mac_valid);
    munit_assert_int(card.plain_le, ==, 1);
    munit_assert_memory_equal(sizeof plain_command, card.plain, plain_command);
    /* 0C CB 3F FF 20 {87 11 01 ct(16), 97 01 00, 8E 08 tag} 00 */
    munit_assert_size(card.last_fragment_length, ==, 38);
    munit_assert_uint8(card.last_fragment[4], ==, 0x20);
    munit_assert_memory_equal(3, card.last_fragment + 5, "\x87\x11\x01");
    munit_assert_memory_equal(3, card.last_fragment + 24, "\x97\x01\x00");
    munit_assert_size(out.encoded.length, ==, sizeof object);
    munit_assert_memory_equal(sizeof object, out.encoded.data, object);
    /* The plaintext follows the 87 header inside the response buffer. */
    munit_assert_ptr_equal(out.encoded.data, response_bytes + 3);
    munit_assert_uint16(TC_PIV_link_status(&link), ==, 0x9000);
    TC_PIV_link_clear(&link);
  }
  return MUNIT_OK;
}

/* 87 lengths of one, two and three octets, and SM data fields above 255
 * bytes as 1C fragments of 255 bytes on SHORT and EXTENDED links (4.2.4). */
TC_TEST(lengths)
{
  static const struct {
    size_t nc, fragments;
    uint8_t length_octets[3];
  } cases[] = {{111, 1, {0x71}},
               {112, 1, {0x81, 0x81}},
               {239, 2, {0x81, 0xf1}},
               {240, 2, {0x82, 0x01, 0x01}},
               {600, 3, {0x82, 0x02, 0x61}}};
  static uint8_t data[600];
  tc_test_fill_incrementing(data, sizeof data);
  for (size_t s = 0; s < SUITE_COUNT; ++s)
    for (size_t format = 0; format < 2; ++format)
      for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        TC_PIV_link link;
        TC_APDU_response out;
        link_open(&link, TC_PIV_CONTACT, format ? TC_APDU_EXTENDED : TC_APDU_SHORT, EXCHANGES,
                  suite_hex(suites[s]));
        link_secure(&link, fixture_for(suites[s]));
        card.answer_length = 0;
        card.inner_sw = 0x9000;
        munit_assert_int(
            send(&link, 0x87, (TC_bytes){data, cases[i].nc}, 256, RESPONSE_BYTES, &out), ==,
            TC_PIV_OK);
        munit_assert_false(card.broken);
        munit_assert_size(card.fragments, ==, cases[i].fragments);
        munit_assert_size(card.plain_length, ==, cases[i].nc);
        munit_assert_memory_equal(cases[i].nc, card.plain, data);
        munit_assert_uint8(card.field[0], ==, 0x87);
        const size_t octets = cases[i].length_octets[0] < 0x80 ? 1 : cases[i].length_octets[0] & 3;
        munit_assert_memory_equal(octets == 1 ? 1 : octets + 1, card.field + 1,
                                  cases[i].length_octets);
        munit_assert_uint8(card.last_fragment[0], ==, 0x0c);
        munit_assert_uint8(card.last_fragment[card.last_fragment_length - 1], ==, 0x00);
        munit_assert_size(out.data.length, ==, 0);
        munit_assert_uint16(out.sw, ==, 0x9000);
        TC_PIV_link_clear(&link);
      }
  return MUNIT_OK;
}

/* A long answer arrives in 256-byte chunks with plain GET RESPONSE 00 C0,
 * which leaves the counter (4.2.2, 4.2.6). */
TC_TEST(response_chaining)
{
  for (size_t s = 0; s < SUITE_COUNT; ++s) {
    TC_PIV_link link;
    TC_APDU_response out;
    secured_link(&link, suites[s], TC_PIV_CONTACT);
    tc_test_fill_incrementing(card.answer, 1000);
    card.answer_length = 1000;
    munit_assert_int(
        send(&link, 0xcb, (TC_bytes){(const uint8_t*)"\x5c\x01\x7e", 3}, 256, RESPONSE_BYTES, &out),
        ==, TC_PIV_OK);
    munit_assert_size(card.get_responses, ==, 4);
    munit_assert_false(card.broken);
    munit_assert_size(out.data.length, ==, 1000);
    munit_assert_memory_equal(1000, out.data.data, card.answer);
    /* The next command authenticates, so the counters agree. */
    card.answer_length = 0;
    munit_assert_int(
        send(&link, 0xcb, (TC_bytes){(const uint8_t*)"\x5c\x01\x7e", 3}, 256, RESPONSE_BYTES, &out),
        ==, TC_PIV_OK);
    munit_assert_true(card.mac_valid);
    TC_PIV_link_clear(&link);
  }
  return MUNIT_OK;
}

/* An authenticated inner status other than 9000 keeps the session (the
 * recorded 6982 before the PIN). */
TC_TEST(inner_status)
{
  static const uint8_t tag[] = {0x5f, 0xc1, 0x08};
  for (size_t s = 0; s < SUITE_COUNT; ++s) {
    TC_PIV_link link;
    TC_PIV_data_object out;
    TC_PIV_link_info info;
    secured_link(&link, suites[s], TC_PIV_CONTACTLESS);
    card.inner_sw = 0x6982;
    munit_assert_int(
        TC_PIV_get_data(&link, (TC_bytes){tag, sizeof tag}, response_buffer(RESPONSE_BYTES), &out),
        ==, TC_PIV_CARD_STATUS);
    munit_assert_uint16(TC_PIV_link_status(&link), ==, 0x6982);
    link_info(&link, &info);
    munit_assert_uint8(info.secured, ==, 1);
    munit_assert_uint8(info.sm_lost, ==, 0);
    munit_assert_int(TC_PIV_SM_get_state(&session), ==, TC_PIV_SM_READY);
    card.inner_sw = 0x9000;
    card.answer[0] = 0x53;
    card.answer[1] = 0x00;
    card.answer_length = 2;
    munit_assert_int(
        TC_PIV_get_data(&link, (TC_bytes){tag, sizeof tag}, response_buffer(RESPONSE_BYTES), &out),
        ==, TC_PIV_OK);
    TC_PIV_link_clear(&link);
  }
  return MUNIT_OK;
}

/* An outer status other than 9000 is an SM error: the session ends, the link
 * records sm_lost and refuses protected commands until TC_PIV_link_unsecure
 * (4.2.7, 4.3, footnote 25). 6CXX is never corrected under SM. */
TC_TEST(outer_status)
{
  static const uint16_t statuses[] = {0x6882, 0x6987, 0x6988, 0x6982, 0x6c10, 0x6700};
  static const uint8_t tag[] = {0x7e};
  for (size_t s = 0; s < SUITE_COUNT; ++s)
    for (size_t i = 0; i < sizeof statuses / sizeof statuses[0]; ++i) {
      TC_PIV_link link;
      TC_PIV_data_object out;
      TC_PIV_reference_status status;
      secured_link(&link, suites[s], TC_PIV_CONTACTLESS);
      link.flags |= TC_PIV_LINK_VCI | TC_PIV_LINK_PIN_VERIFIED;
      card.fault = TC_SM_CARD_OUTER_STATUS;
      card.outer_sw = statuses[i];
      munit_assert_int(TC_PIV_get_data(&link, (TC_bytes){tag, sizeof tag},
                                       response_buffer(RESPONSE_BYTES), &out),
                       ==, TC_PIV_CARD_STATUS);
      assert_lost(&link, statuses[i]);
      munit_assert_true(tc_test_all_zero(response_bytes, RESPONSE_BYTES));
      munit_assert_size(card.transmits, ==, 3);
      /* Nothing protected goes out, and nothing falls back to plaintext. */
      munit_assert_int(TC_PIV_get_data(&link, (TC_bytes){tag, sizeof tag},
                                       response_buffer(RESPONSE_BYTES), &out),
                       ==, TC_PIV_REFUSED);
      munit_assert_int(TC_PIV_verify_status(&link, 0x98, &status), ==, TC_PIV_REFUSED);
      munit_assert_int(TC_PIV_SM_key_request(&link, &session, suites[s], host_id,
                                             (TC_random_source){scalar_one, NULL},
                                             response_buffer(RESPONSE_BYTES), NULL, &workspace),
                       ==, TC_PIV_ARGUMENT);
      {
        TC_PIV_SM_peer peer;
        munit_assert_int(TC_PIV_SM_key_request(&link, &session, suites[s], host_id,
                                               (TC_random_source){scalar_one, NULL},
                                               response_buffer(RESPONSE_BYTES), &peer, &workspace),
                         ==, TC_PIV_REFUSED);
      }
      munit_assert_size(card.transmits, ==, 3);
      munit_assert_uint16(TC_PIV_link_status(&link), ==, statuses[i]);
      TC_PIV_link_unsecure(&link);
      munit_assert_int(TC_PIV_get_data(&link, (TC_bytes){tag, sizeof tag},
                                       response_buffer(RESPONSE_BYTES), &out),
                       ==, TC_PIV_CARD_STATUS);
      munit_assert_size(card.plain_commands, ==, 1);
      TC_PIV_link_clear(&link);
    }
  return MUNIT_OK;
}

/* Malformed SM DOs, a failed R-MAC and bad padding end the session with
 * INVALID and link status 0 (4.2.5 to 4.2.7). */
TC_TEST(malformed)
{
  static const tc_sm_card_fault faults[] = {
      TC_SM_CARD_STALE,       TC_SM_CARD_BAD_INDICATOR, TC_SM_CARD_PARTIAL_BLOCK,
      TC_SM_CARD_BAD_PADDING, TC_SM_CARD_MAC_LENGTH,    TC_SM_CARD_NO_STATUS,
      TC_SM_CARD_NO_MAC,      TC_SM_CARD_TRAILING,      TC_SM_CARD_BAD_MAC};
  static const uint8_t tag[] = {0x7e};
  for (size_t s = 0; s < SUITE_COUNT; ++s) {
    for (size_t i = 0; i < sizeof faults / sizeof faults[0]; ++i) {
      TC_PIV_link link;
      TC_PIV_data_object out;
      secured_link(&link, suites[s], TC_PIV_CONTACT);
      memcpy(card.answer, "\x7e\x01\x00", 3);
      card.answer_length = 3;
      if (faults[i] == TC_SM_CARD_STALE)
        /* A recorded answer to an earlier command fails the chained R-MAC. */
        munit_assert_int(TC_PIV_get_data(&link, (TC_bytes){tag, sizeof tag},
                                         response_buffer(RESPONSE_BYTES), &out),
                         ==, TC_PIV_OK);
      card.fault = faults[i];
      munit_assert_int(TC_PIV_get_data(&link, (TC_bytes){tag, sizeof tag},
                                       response_buffer(RESPONSE_BYTES), &out),
                       ==, TC_PIV_INVALID);
      assert_lost(&link, 0);
      munit_assert_true(tc_test_all_zero(response_bytes, RESPONSE_BYTES));
      TC_PIV_link_clear(&link);
    }
    /* A VERIFY answer carries no 87 (4.2.6). */
    TC_PIV_link link;
    TC_APDU_response answer;
    secured_link(&link, suites[s], TC_PIV_CONTACT);
    card.fault = TC_SM_CARD_CRYPTOGRAM_ALWAYS;
    munit_assert_int(send(&link, 0x20, (TC_bytes){NULL, 0}, 0, RESPONSE_BYTES, &answer), ==,
                     TC_PIV_INVALID);
    assert_lost(&link, 0);
    TC_PIV_link_clear(&link);
  }
  return MUNIT_OK;
}

/* A 1C fragment answered other than 9000 ends the chain and the session. */
TC_TEST(chain_status)
{
  static uint8_t data[400];
  for (size_t s = 0; s < SUITE_COUNT; ++s) {
    TC_PIV_link link;
    TC_APDU_response out;
    secured_link(&link, suites[s], TC_PIV_CONTACT);
    card.fault = TC_SM_CARD_CHAIN_STATUS;
    card.outer_sw = 0x6883;
    munit_assert_int(send(&link, 0x87, (TC_bytes){data, sizeof data}, 256, RESPONSE_BYTES, &out),
                     ==, TC_PIV_CARD_STATUS);
    munit_assert_size(card.fragments, ==, 1);
    assert_lost(&link, 0x6883);
    TC_PIV_link_clear(&link);
  }
  return MUNIT_OK;
}

static TC_status failing_transmit(void* context, TC_bytes command, TC_buffer response,
                                  size_t* length)
{
  (void)context;
  (void)command;
  (void)response;
  (void)length;
  return TC_ERROR;
}

/* A transport failure ends a bound session, whether it hits a protected
 * command or a plain one such as SELECT. The stopped link keeps no keys. */
TC_TEST(transport_failure)
{
  static const uint8_t tag[] = {0x7e};
  for (size_t s = 0; s < SUITE_COUNT; ++s) {
    TC_PIV_link link;
    TC_PIV_data_object out;
    TC_PIV_application application;
    secured_link(&link, suites[s], TC_PIV_CONTACTLESS);
    link.flags |= TC_PIV_LINK_VCI | TC_PIV_LINK_PIN_VERIFIED;
    link.channel.transport.transmit = failing_transmit;
    munit_assert_int(
        TC_PIV_get_data(&link, (TC_bytes){tag, sizeof tag}, response_buffer(RESPONSE_BYTES), &out),
        ==, TC_PIV_ERROR);
    assert_lost(&link, 0);
    munit_assert_true(tc_test_all_zero(response_bytes, RESPONSE_BYTES));
    TC_PIV_link_clear(&link);

    secured_link(&link, suites[s], TC_PIV_CONTACTLESS);
    link.flags |= TC_PIV_LINK_VCI | TC_PIV_LINK_PIN_VERIFIED;
    link.channel.transport.transmit = failing_transmit;
    munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 0,
                                   response_buffer(RESPONSE_BYTES), &application),
                     ==, TC_PIV_ERROR);
    assert_lost(&link, 0);
    munit_assert_int(
        TC_PIV_get_data(&link, (TC_bytes){tag, sizeof tag}, response_buffer(RESPONSE_BYTES), &out),
        ==, TC_PIV_REFUSED);
    TC_PIV_link_clear(&link);
  }
  return MUNIT_OK;
}

/* LIMIT before protection keeps the session. LIMIT during the exchange ends
 * it, since the counters then disagree. */
TC_TEST(limits)
{
  static uint8_t data[TC_PIV_SM_MAX_PLAIN_NC + 1];
  for (size_t s = 0; s < SUITE_COUNT; ++s) {
    TC_PIV_link link;
    TC_APDU_response out;
    TC_PIV_link_info info;
    /* The answer outgrows the response buffer during GET RESPONSE. */
    secured_link(&link, suites[s], TC_PIV_CONTACT);
    card.answer_length = 600;
    munit_assert_int(send(&link, 0xcb, (TC_bytes){data, 3}, 256, 300, &out), ==, TC_PIV_LIMIT);
    assert_lost(&link, 0);
    munit_assert_true(tc_test_all_zero(response_bytes, 300));
    TC_PIV_link_clear(&link);

    /* The SM scratch is too small: nothing is protected or sent. */
    secured_link(&link, suites[s], TC_PIV_CONTACT);
    const size_t sent = card.transmits;
    munit_assert_int(
        send(&link, 0x87, (TC_bytes){data, SM_SCRATCH_BYTES}, 256, RESPONSE_BYTES, &out), ==,
        TC_PIV_LIMIT);
    munit_assert_int(
        send(&link, 0x87, (TC_bytes){data, TC_PIV_SM_MAX_PLAIN_NC}, 256, RESPONSE_BYTES, &out), ==,
        TC_PIV_LIMIT);
    munit_assert_int(
        send(&link, 0x87, (TC_bytes){data, TC_PIV_SM_MAX_PLAIN_NC + 1}, 256, RESPONSE_BYTES, &out),
        ==, TC_PIV_ARGUMENT);
    munit_assert_size(card.transmits, ==, sent);
    link_info(&link, &info);
    munit_assert_uint8(info.secured, ==, 1);
    munit_assert_int(TC_PIV_SM_get_state(&session), ==, TC_PIV_SM_READY);
    munit_assert_int(send(&link, 0x87, (TC_bytes){data, 16}, 256, RESPONSE_BYTES, &out), ==,
                     TC_PIV_OK);
    munit_assert_true(card.mac_valid);
    TC_PIV_link_clear(&link);

    /* The budget covers SELECT, key establishment and two fragments. */
    link_open(&link, TC_PIV_CONTACT, TC_APDU_SHORT, 4, suite_hex(suites[s]));
    link_secure(&link, fixture_for(suites[s]));
    munit_assert_int(send(&link, 0x87, (TC_bytes){data, 600}, 256, RESPONSE_BYTES, &out), ==,
                     TC_PIV_LIMIT);
    munit_assert_int(TC_PIV_SM_get_state(&session), ==, TC_PIV_SM_READY);
    munit_assert_size(card.transmits, ==, 2);
    /* A GET RESPONSE step past the budget ends the session. */
    card.answer_length = 600;
    munit_assert_int(send(&link, 0xcb, (TC_bytes){data, 3}, 256, RESPONSE_BYTES, &out), ==,
                     TC_PIV_LIMIT);
    assert_lost(&link, 0);
    TC_PIV_link_clear(&link);
  }
  return MUNIT_OK;
}

/* The PIN reaches a contactless card only under SM with the VCI (Part 1
 * Table 4, Part 2 3.2.1). The VCI bit stands in for piv_vci.h here. */
TC_TEST(pin_contactless)
{
  static const uint8_t pin[] = "123456";
  static const uint8_t padded[] = {'1', '2', '3', '4', '5', '6', 0xff, 0xff};
  for (size_t s = 0; s < SUITE_COUNT; ++s) {
    TC_PIV_link link;
    TC_PIV_reference_status status;
    link_open(&link, TC_PIV_CONTACTLESS, TC_APDU_SHORT, EXCHANGES, suite_hex(suites[s]));
    munit_assert_int(TC_PIV_pin_verify(&link, 0x80, (TC_bytes){pin, 6}, 3, &status), ==,
                     TC_PIV_REFUSED);
    link_secure(&link, fixture_for(suites[s]));
    munit_assert_int(TC_PIV_pin_verify(&link, 0x80, (TC_bytes){pin, 6}, 3, &status), ==,
                     TC_PIV_REFUSED);
    link.flags |= TC_PIV_LINK_VCI;
    card.inner_sw = 0x63c5;
    munit_assert_int(TC_PIV_verify_status(&link, 0x80, &status), ==, TC_PIV_OK);
    munit_assert_uint(status.retries, ==, 5);
    munit_assert_size(card.plain_length, ==, 0);
    /* Query, then submission, both protected. */
    card.inner_sw = 0x63c5;
    munit_assert_int(TC_PIV_pin_verify(&link, 0x80, (TC_bytes){pin, 6}, 3, &status), ==,
                     TC_PIV_CARD_STATUS);
    munit_assert_uint16(TC_PIV_link_status(&link), ==, 0x63c5);
    munit_assert_size(card.plain_length, ==, sizeof padded);
    munit_assert_memory_equal(sizeof padded, card.plain, padded);
    munit_assert_size(card.plain_commands, ==, 0);
    munit_assert_true(tc_test_all_zero(sm_scratch, sizeof sm_scratch));
    TC_PIV_link_clear(&link);
  }
  return MUNIT_OK;
}

/* Secure messaging belongs to the PIV application: reselecting it keeps the
 * session and selecting TWIC ends it. Unsecure and clear wipe the session
 * and the SM scratch. */
TC_TEST(unbind)
{
  for (size_t s = 0; s < SUITE_COUNT; ++s) {
    TC_PIV_link link;
    TC_PIV_link_info info;
    TC_PIV_application application;
    TC_PIV_data_object out;
    static const uint8_t tag[] = {0x7e};
    secured_link(&link, suites[s], TC_PIV_CONTACT);
    munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 0,
                                   response_buffer(RESPONSE_BYTES), &application),
                     ==, TC_PIV_OK);
    link_info(&link, &info);
    munit_assert_uint8(info.secured, ==, 1);
    /* The model answers the TWIC SELECT with the PIV template, which fails. */
    munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_TWIC, 0,
                                   response_buffer(RESPONSE_BYTES), &application),
                     ==, TC_PIV_INVALID);
    link_info(&link, &info);
    munit_assert_uint8(info.secured, ==, 0);
    munit_assert_uint8(info.sm_lost, ==, 0);
    munit_assert_true(tc_test_all_zero(&session, sizeof session));
    TC_PIV_link_clear(&link);

    secured_link(&link, suites[s], TC_PIV_CONTACT);
    card.answer_length = 0;
    munit_assert_int(
        TC_PIV_get_data(&link, (TC_bytes){tag, sizeof tag}, response_buffer(RESPONSE_BYTES), &out),
        ==, TC_PIV_INVALID);
    TC_PIV_link_unsecure(&link);
    TC_PIV_link_unsecure(&link);
    TC_PIV_link_unsecure(NULL);
    link_info(&link, &info);
    munit_assert_uint8(info.secured, ==, 0);
    munit_assert_uint8(info.sm_lost, ==, 0);
    munit_assert_int(
        TC_PIV_get_data(&link, (TC_bytes){tag, sizeof tag}, response_buffer(RESPONSE_BYTES), &out),
        ==, TC_PIV_CARD_STATUS);
    munit_assert_size(card.plain_commands, ==, 1);
    TC_PIV_link_clear(&link);

    secured_link(&link, suites[s], TC_PIV_CONTACT);
    sm_scratch[0] = 1;
    TC_PIV_link_clear(&link);
    munit_assert_true(tc_test_all_zero(&session, sizeof session));
    munit_assert_true(tc_test_all_zero(sm_scratch, sizeof sm_scratch));
  }
  return MUNIT_OK;
}

/* Size of the one-byte-tag TLV header at offset, whose length field ends
 * with the byte a test adjusts. */
static size_t header_bytes(const uint8_t* encoded, size_t offset)
{
  const uint8_t first = encoded[offset + 1];
  return first < 0x80 ? 2u : 2u + (first & 0x7fu);
}

/* Key establishment arguments, refusals, card statuses and answer framing
 * (4.1.8, Table 19). */
TC_TEST(key_request)
{
  for (size_t s = 0; s < SUITE_COUNT; ++s) {
    const struct tc_sm_fixture* fixture = fixture_for(suites[s]);
    const TC_random_source random = {scalar_one, NULL};
    TC_PIV_link link;
    TC_PIV_SM_peer peer, saved;
    memset(&peer, 0xa5, sizeof peer);
    saved = peer;
    link_open(&link, TC_PIV_CONTACT, TC_APDU_SHORT, EXCHANGES, suite_hex(suites[s]));
    key_answer_set(fixture);
    const TC_buffer response = {response_bytes, RESPONSE_BYTES};
    munit_assert_int(TC_PIV_SM_key_request(NULL, &session, suites[s], host_id, random, response,
                                           &peer, &workspace),
                     ==, TC_PIV_ARGUMENT);
    munit_assert_int(
        TC_PIV_SM_key_request(&link, NULL, suites[s], host_id, random, response, &peer, &workspace),
        ==, TC_PIV_ARGUMENT);
    munit_assert_int(TC_PIV_SM_key_request(&link, &session, suites[s], NULL, random, response,
                                           &peer, &workspace),
                     ==, TC_PIV_ARGUMENT);
    munit_assert_int(TC_PIV_SM_key_request(&link, &session, suites[s], host_id,
                                           (TC_random_source){NULL, NULL}, response, &peer,
                                           &workspace),
                     ==, TC_PIV_ARGUMENT);
    munit_assert_int(TC_PIV_SM_key_request(&link, &session, (TC_PIV_SM_suite)0x28, host_id, random,
                                           response, &peer, &workspace),
                     ==, TC_PIV_ARGUMENT);
    munit_assert_int(TC_PIV_SM_key_request(&link, &session, suites[s], host_id, random,
                                           (TC_buffer){(uint8_t*)&session, sizeof session}, &peer,
                                           &workspace),
                     ==, TC_PIV_ARGUMENT);
    munit_assert_int(TC_PIV_SM_key_request(&link, &session, suites[s], host_id, random,
                                           (TC_buffer){scratch, sizeof scratch}, &peer, &workspace),
                     ==, TC_PIV_ARGUMENT);
    munit_assert_int(TC_PIV_SM_key_request(&link, &session, suites[s], (const uint8_t*)&workspace,
                                           random, response, &peer, &workspace),
                     ==, TC_PIV_ARGUMENT);
    /* The template announced the other suite, or the build lacks it. */
    munit_assert_int(
        TC_PIV_SM_key_request(&link, &session,
                              suites[s] == TC_PIV_SM_CS2 ? TC_PIV_SM_CS7 : TC_PIV_SM_CS2, host_id,
                              random, response, &peer, &workspace),
        ==, TC_PIV_UNSUPPORTED);
    munit_assert_size(card.transmits, ==, 1);
    munit_assert_memory_equal(sizeof peer, &peer, &saved);
    /* A failed random source sends nothing. */
    munit_assert_int(TC_PIV_SM_key_request(&link, &session, suites[s], host_id,
                                           (TC_random_source){failing_random, NULL}, response,
                                           &peer, &workspace),
                     ==, TC_PIV_ERROR);
    munit_assert_size(card.transmits, ==, 1);
    munit_assert_true(tc_test_all_zero(&session, sizeof session));

    /* A card status ends the attempt. */
    static const uint8_t refused[] = {0x6a, 0x80};
    card.key_answer = (TC_bytes){refused, sizeof refused};
    munit_assert_int(TC_PIV_SM_key_request(&link, &session, suites[s], host_id, random, response,
                                           &peer, &workspace),
                     ==, TC_PIV_CARD_STATUS);
    munit_assert_uint16(TC_PIV_link_status(&link), ==, 0x6a80);
    munit_assert_true(tc_test_all_zero(&session, sizeof session));
    munit_assert_true(tc_test_all_zero(&workspace, sizeof workspace));
    munit_assert_true(tc_test_all_zero(response_bytes, RESPONSE_BYTES));
    munit_assert_memory_equal(sizeof peer, &peer, &saved);

    /* Framing: outer tag, C_ICC tag and a trailing byte. The fixture answer
     * is 7C L 82 L CB N cryptogram 7F21 ... */
    const size_t length = fixture->response.length;
    for (int variant = 0; variant < 4; ++variant) {
      key_answer_set(fixture);
      size_t answer_length = length + 2;
      if (variant == 0)
        key_bytes[0] = 0x7d;
      if (variant == 1) {
        /* The first C_ICC byte follows 7C L 82 L and the fixed fields. */
        const size_t inner = header_bytes(key_bytes, 0);
        const size_t prefix = inner + header_bytes(key_bytes, inner) + 1 +
                              (suites[s] == TC_PIV_SM_CS2 ? 16u : 24u) + 16;
        munit_assert_uint8(key_bytes[prefix], ==, 0x7f);
        key_bytes[prefix] = 0x7e;
      }
      if (variant == 2) {
        /* A truncated nonce. */
        static const uint8_t short_answer[] = {0x7c, 0x05, 0x82, 0x03, 0x00,
                                               0x01, 0x02, 0x90, 0x00};
        memcpy(key_bytes, short_answer, sizeof short_answer);
        answer_length = sizeof short_answer;
      }
      if (variant == 3) {
        /* A byte after C_ICC inside 82. */
        const size_t inner = header_bytes(key_bytes, 0);
        key_bytes[inner - 1] = (uint8_t)(key_bytes[inner - 1] + 1);
        key_bytes[inner + header_bytes(key_bytes, inner) - 1]++;
        key_bytes[length] = 0x00;
        key_bytes[length + 1] = 0x90;
        key_bytes[length + 2] = 0x00;
        answer_length = length + 3;
      }
      card.key_answer = (TC_bytes){key_bytes, answer_length};
      munit_assert_int(TC_PIV_SM_key_request(&link, &session, suites[s], host_id, random, response,
                                             &peer, &workspace),
                       ==, TC_PIV_INVALID);
      munit_assert_uint16(TC_PIV_link_status(&link), ==, 0);
      munit_assert_true(tc_test_all_zero(&session, sizeof session));
      munit_assert_memory_equal(sizeof peer, &peer, &saved);
    }

    /* Only the PIV application runs key establishment, and a secured link
     * needs TC_PIV_link_unsecure first. */
    key_answer_set(fixture);
    link_secure(&link, fixture);
    munit_assert_int(TC_PIV_SM_key_request(&link, &session, suites[s], host_id, random, response,
                                           &peer, &workspace),
                     ==, TC_PIV_REFUSED);
    TC_PIV_link_unsecure(&link);
    munit_assert_int(TC_PIV_SM_key_request(&link, &session, suites[s], host_id, random, response,
                                           &peer, &workspace),
                     ==, TC_PIV_OK);
    /* Establishing again with the bound session replaces it. */
    munit_assert_int(TC_PIV_SM_key_request(&link, &session, suites[s], host_id, random, response,
                                           &peer, &workspace),
                     ==, TC_PIV_OK);
    TC_PIV_link_clear(&link);
    munit_assert_true(tc_test_all_zero(&session, sizeof session));
    tc_sm_card_init(&card);
    const TC_PIV_link_options options = {{TC_APDU_SHORT, 0, EXCHANGES, 0, 0}, TC_PIV_CONTACT, 0};
    munit_assert_int(TC_PIV_link_init(&link, tc_sm_card_transport(&card), &options,
                                      (TC_buffer){scratch, sizeof scratch}),
                     ==, TC_PIV_OK);
    munit_assert_int(TC_PIV_SM_key_request(&link, &session, suites[s], host_id, random, response,
                                           &peer, &workspace),
                     ==, TC_PIV_REFUSED);
    munit_assert_size(card.transmits, ==, 0);
    TC_PIV_link_clear(&link);
  }
  return MUNIT_OK;
}

/* The advertised minimum command scratch of an EXTENDED link carries key
 * establishment for every built suite (Part 2 4.1.8). */
TC_TEST(minimum_scratch)
{
  static uint8_t minimum[TC_PIV_EXTENDED_SCRATCH_BYTES];
  for (size_t s = 0; s < sizeof suites / sizeof *suites; ++s) {
    const struct tc_sm_fixture* fixture = fixture_for(suites[s]);
    char apt[160];
    tc_sm_card_init(&card);
    memcpy(apt, APT("00"), sizeof APT("00"));
    memcpy(strstr(apt, "AC068001") + 8, suite_hex(suites[s]), 2);
    card.select_answer = (TC_bytes){select_bytes, hex(apt, select_bytes, sizeof select_bytes)};
    const TC_PIV_link_options options = {{TC_APDU_EXTENDED, 0, EXCHANGES, 0, 0}, TC_PIV_CONTACT, 0};
    TC_PIV_link link;
    TC_PIV_application application;
    TC_PIV_SM_peer peer;
    munit_assert_int(TC_PIV_link_init(&link, tc_sm_card_transport(&card), &options,
                                      (TC_buffer){minimum, sizeof minimum}),
                     ==, TC_PIV_OK);
    munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 0,
                                   response_buffer(RESPONSE_BYTES), &application),
                     ==, TC_PIV_OK);
    key_answer_set(fixture);
    munit_assert_int(TC_PIV_SM_key_request(&link, &session, fixture->suite, host_id,
                                           (TC_random_source){scalar_one, NULL},
                                           response_buffer(RESPONSE_BYTES), &peer, &workspace),
                     ==, TC_PIV_OK);
    TC_PIV_link_clear(&link);
  }
  return MUNIT_OK;
}

/* TC_PIV_link_secure needs the READY session bound by the key request. */
TC_TEST(secure_arguments)
{
  for (size_t s = 0; s < SUITE_COUNT; ++s) {
    const struct tc_sm_fixture* fixture = fixture_for(suites[s]);
    const TC_buffer sm = {sm_scratch, sizeof sm_scratch};
    TC_PIV_link link;
    TC_PIV_SM_peer peer;
    link_open(&link, TC_PIV_CONTACT, TC_APDU_SHORT, EXCHANGES, suite_hex(suites[s]));
    munit_assert_int(TC_PIV_link_secure(&link, &workspace, sm), ==, TC_PIV_ARGUMENT);
    key_answer_set(fixture);
    munit_assert_int(TC_PIV_SM_key_request(&link, &session, suites[s], host_id,
                                           (TC_random_source){scalar_one, NULL},
                                           response_buffer(RESPONSE_BYTES), &peer, &workspace),
                     ==, TC_PIV_OK);
    /* ESTABLISHING until the peer is authenticated. */
    munit_assert_int(TC_PIV_link_secure(&link, &workspace, sm), ==, TC_PIV_ARGUMENT);
    munit_assert_int(TC_PIV_SM_finish(&session, &peer, fixture->public_key, &workspace), ==, TC_OK);
    munit_assert_int(TC_PIV_link_secure(NULL, &workspace, sm), ==, TC_PIV_ARGUMENT);
    munit_assert_int(TC_PIV_link_secure(&link, NULL, sm), ==, TC_PIV_ARGUMENT);
    munit_assert_int(
        TC_PIV_link_secure(
            &link, &workspace,
            (TC_buffer){sm_scratch, TC_PIV_SM_COMMAND_DATA_BYTES(TC_PIV_COMMAND_MAX_NC) - 1}),
        ==, TC_PIV_ARGUMENT);
    munit_assert_int(TC_PIV_link_secure(&link, &workspace, (TC_buffer){scratch, sizeof scratch}),
                     ==, TC_PIV_ARGUMENT);
    munit_assert_int(
        TC_PIV_link_secure(&link, &workspace, (TC_buffer){(uint8_t*)&session, sizeof session}), ==,
        TC_PIV_ARGUMENT);
    munit_assert_int(TC_PIV_link_secure(&link, (TC_PIV_SM_workspace*)sm_scratch, sm), ==,
                     TC_PIV_ARGUMENT);
    TC_PIV_link_info info;
    link_info(&link, &info);
    munit_assert_uint8(info.secured, ==, 0);
    munit_assert_int(TC_PIV_link_secure(&link, &workspace,
                                        (TC_buffer){sm_scratch, TC_PIV_SM_COMMAND_DATA_BYTES(
                                                                    TC_PIV_COMMAND_MAX_NC)}),
                     ==, TC_PIV_OK);
    munit_assert_int(TC_PIV_link_secure(&link, &workspace, sm), ==, TC_PIV_ARGUMENT);
    link_info(&link, &info);
    munit_assert_uint8(info.secured, ==, 1);
    /* A response buffer inside the SM scratch is an overlap. */
    TC_PIV_data_object out;
    static const uint8_t tag[] = {0x7e};
    munit_assert_int(
        TC_PIV_get_data(&link, (TC_bytes){tag, sizeof tag}, (TC_buffer){sm_scratch, 64}, &out), ==,
        TC_PIV_ARGUMENT);
    TC_PIV_link_clear(&link);
  }
  return MUNIT_OK;
}
#endif

/* SD 33 card 2 CS7 key establishment, byte for byte: the 118-byte command
 * and the answer 7C 82 01 40 {82 82 01 3C {CB, N (24), cryptogram, C_ICC of
 * 275 bytes}}. */
#if TC_PIV_SM_ENABLE_CS7
static const char recorded_scalar[] =
    "ffe98ef96aaea84a2ab29de9b7aeb64a1b5621d4e3513c3c82fd8d9f8c357f91957553d3dd2f1954c99bff89"
    "ede83fb3";
static const char recorded_key_command[] =
    "00872e04707c6e816a00000000000000000004c3b4e0f47185086019d2982cb22c6889f1a7dc3d3838b8c4a5"
    "d0a00a9405e8febcfe8174805988df4251365bf9944c7057e964c94946718e93a9ec045a92096a354c6ef394"
    "b3db55b8dff0535d65f29c79f8b9aedb4ffeb8fbd07bf6cb8a8d78820000";
static const char recorded_key_answer[] =
    "7c8201408282013c004a2b00dbd3f39cb3a1337478bb56bc3975892f3b9aeba0c868764622c47a0d51d5329a"
    "64cb1538927f2182010e5f2901804208b6103792270fbd085f201044be53852e86434db45eb3e09fcc0dca7f"
    "496a06052b8104002286610417c9775bb3f0bf1444374eb6551d73b30783c442b533aa5dc6553792cfd4923f"
    "ca21252fba1a1664d35dd5af170e8e2d3fbec25455222780a735015e60abc68f51a35a1455f892f40b4b0c7f"
    "4b8da6695175a45e61f2330509c97536176e44015f4c01005f37793077300a06082a8648ce3d040303036900"
    "3066023100b7832d62d9a868359e8c82c669c75854fee9be575d3be4c949060d57cf908e54f1428d3e4e2ee5"
    "0b0700bffb5938a93e0231009948a32275150e148c9e025181954c1d53c9952c56d318303a9e5408416f769d"
    "592c6abb39b1c87709e72189fa8d5d249000";

static const uint8_t* recorded_scalar_bytes;

static TC_status recorded_random(void* context, uint8_t* output, size_t length)
{
  (void)context;
  memcpy(output, recorded_scalar_bytes, length);
  return TC_OK;
}
#endif

TC_TEST(key_request_recorded)
{
#if TC_PIV_SM_ENABLE_CS7
  static uint8_t scalar[48], command[128], answer[400];
  TC_PIV_link link;
  TC_PIV_SM_peer peer;
  munit_assert_size(hex(recorded_scalar, scalar, sizeof scalar), ==, 48);
  recorded_scalar_bytes = scalar;
  link_open(&link, TC_PIV_CONTACTLESS, TC_APDU_SHORT, EXCHANGES, "2E");
  card.key_command = (TC_bytes){command, hex(recorded_key_command, command, sizeof command)};
  card.key_answer = (TC_bytes){answer, hex(recorded_key_answer, answer, sizeof answer)};
  munit_assert_size(card.key_command.length, ==, 118);
  munit_assert_size(card.key_answer.length, ==, TC_PIV_SM_KEY_RESPONSE_BYTES);
  munit_assert_int(TC_PIV_SM_key_request(&link, &session, TC_PIV_SM_CS7, host_id,
                                         (TC_random_source){recorded_random, NULL},
                                         response_buffer(TC_PIV_SM_KEY_RESPONSE_BYTES), &peer,
                                         &workspace),
                   ==, TC_PIV_OK);
  munit_assert_false(card.broken);
  munit_assert_uint8(peer.card_control, ==, 0);
  munit_assert_size(peer.nonce.length, ==, 24);
  munit_assert_size(peer.cryptogram.length, ==, 16);
  munit_assert_size(peer.certificate.length, ==, TC_PIV_SM_CARD_CVC_MAX_BYTES);
  munit_assert_ptr_equal(peer.nonce.data, response_bytes + 9);
  munit_assert_uint8(peer.certificate.data[0], ==, 0x7f);
  TC_PIV_link_clear(&link);

  /* A C_ICC above 275 bytes is INVALID: grow 7F21 by one byte. */
  link_open(&link, TC_PIV_CONTACTLESS, TC_APDU_SHORT, EXCHANGES, "2E");
  card.key_command = (TC_bytes){command, 118};
  const size_t length = hex(recorded_key_answer, answer, sizeof answer) - 2;
  answer[3] = (uint8_t)(answer[3] + 1); /* 7C 82 01 41 */
  answer[7] = (uint8_t)(answer[7] + 1); /* 82 82 01 3D */
  const size_t cvc = 8 + 1 + 24 + 16;
  answer[cvc + 4] = (uint8_t)(answer[cvc + 4] + 1); /* 7F21 82 01 10 */
  answer[length] = 0x00;
  answer[length + 1] = 0x90;
  answer[length + 2] = 0x00;
  card.key_answer = (TC_bytes){answer, length + 3};
  munit_assert_int(TC_PIV_SM_key_request(&link, &session, TC_PIV_SM_CS7, host_id,
                                         (TC_random_source){recorded_random, NULL},
                                         response_buffer(RESPONSE_BYTES), &peer, &workspace),
                   ==, TC_PIV_INVALID);
  munit_assert_true(tc_test_all_zero(&session, sizeof session));
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
#else
  return MUNIT_SKIP;
#endif
}

static MunitTest tests[] = {
#if TC_TEST_SM_FIXTURES
    {"/verify-query", verify_query, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/get-data", get_data, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/lengths", lengths, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/response-chaining", response_chaining, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/inner-status", inner_status, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/outer-status", outer_status, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/malformed", malformed, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/chain-status", chain_status, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/transport-failure", transport_failure, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/limits", limits, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/pin-contactless", pin_contactless, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/unbind", unbind, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/key-request", key_request, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/minimum-scratch", minimum_scratch, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/secure-arguments", secure_arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
    {"/key-request-recorded", key_request_recorded, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
static const MunitSuite suite = {"/piv-sm-apdu", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[])
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
