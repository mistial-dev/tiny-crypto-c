/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* The card simulator of tests/support/card_simulator.c on the SD 33 card
 * fixtures. Every recorded session replays byte for byte against the
 * simulator, which checks its card-side secure messaging against real card
 * answers. The library then drives the simulator on both interfaces, and raw
 * APDUs exercise the card rules the library never breaks (SP 800-73-5 Part 1
 * Tables 2, 4 and 5, Part 2 3.1 to 3.2 and 4.2 to 4.3). The library runs
 * take the PIN and pairing code from the fixtures. */
#include <tiny_crypto/piv_cvc.h>
#include <tiny_crypto/piv_sm_apdu.h>
#include <tiny_crypto/piv_vci.h>
#include "card_simulator.h"
#include "cavp.h"
#include "munit.h"
#include "test_io.h"
#include "test_util.h"
#include <string.h>

enum {
  RESPONSE_BYTES = 16384,
  SM_SCRATCH_BYTES = 1024,
  EXCHANGES = 4096,
  WIRE_BYTES = 300,
  FACIAL_IMAGE_BYTES = 12141,
  RAW_COMMAND_BYTES = 512
};

static tc_card_fixture fixture;
static tc_card_simulator card;
static uint8_t scratch[TC_APDU_SHORT_COMMAND_MAX_BYTES];
static uint8_t sm_scratch[SM_SCRATCH_BYTES];
static uint8_t response_bytes[RESPONSE_BYTES];
static TC_PIV_SM session;
static TC_PIV_SM_workspace workspace;
static const tc_card_session* recorded;

static const uint8_t tag_ccc[] = {0x5f, 0xc1, 0x07};
static const uint8_t tag_chuid[] = {0x5f, 0xc1, 0x02};
static const uint8_t tag_piv_certificate[] = {0x5f, 0xc1, 0x05};
static const uint8_t tag_facial_image[] = {0x5f, 0xc1, 0x08};

static void load(const char* name)
{
  char path[512];
  snprintf(path, sizeof path, "%s/%s.txt", TC_CARD_FIXTURE_DIR, name);
  munit_assert_long(tc_card_fixture_load(&fixture, path), ==, 0);
}

static TC_buffer response_buffer(void)
{
  memset(response_bytes, 0xee, sizeof response_bytes);
  return (TC_buffer){response_bytes, sizeof response_bytes};
}

static uint32_t tag_value(const uint8_t tag[3])
{
  return (uint32_t)tag[0] << 16 | (uint32_t)tag[1] << 8 | tag[2];
}

/* Send one command APDU and return SW1 SW2. */
static uint16_t send(const uint8_t* command, size_t length, size_t* data_length)
{
  size_t answer = 0;
  const TC_APDU_transport transport = tc_card_simulator_transport(&card);
  munit_assert_int(transport.transmit(transport.context, (TC_bytes){command, length},
                                      (TC_buffer){response_bytes, sizeof response_bytes}, &answer),
                   ==, TC_OK);
  munit_assert_size(answer, >=, 2);
  if (data_length)
    *data_length = answer - 2;
  return (uint16_t)(response_bytes[answer - 2] << 8 | response_bytes[answer - 1]);
}

/* Send one raw APDU given as hex and return SW1 SW2. */
static uint16_t raw(const char* hex, size_t* data_length)
{
  uint8_t command[RAW_COMMAND_BYTES];
  size_t length = 0;
  munit_assert_true(
      tc_test_hex_decode(hex, TC_TEST_HEX_SEPARATED, command, sizeof command, &length));
  return send(command, length, data_length);
}

/* The PIN or pairing code of reference as ASCII digits. */
static TC_bytes secret(uint8_t reference, uint8_t out[8])
{
  const tc_card_reference* data = tc_card_fixture_reference(&fixture, reference);
  munit_assert_not_null(data);
  munit_assert_true(data->value_known);
  size_t length = 0;
  while (length < 8 && data->value[length] != 0xff)
    ++length;
  memcpy(out, data->value, length);
  return (TC_bytes){out, length};
}

static void link_open(TC_PIV_link* link, TC_PIV_interface interface)
{
  const TC_PIV_link_options options = {{TC_APDU_SHORT, 0, EXCHANGES, 0, 0}, interface, 0};
  TC_PIV_application application;
  tc_card_simulator_init(&card, &fixture, interface);
  munit_assert_int(TC_PIV_link_init(link, tc_card_simulator_transport(&card), &options,
                                    (TC_buffer){scratch, sizeof scratch}),
                   ==, TC_PIV_OK);
  munit_assert_int(TC_PIV_select(link, TC_PIV_APPLICATION_PIV, 0, response_buffer(), &application),
                   ==, TC_PIV_OK);
}

static TC_status recorded_scalar(void* context, uint8_t* output, size_t length)
{
  (void)context;
  munit_assert_size(length, ==, recorded->scalar.length);
  memcpy(output, recorded->scalar.data, length);
  return TC_OK;
}

/* Key establishment with a recorded host scalar, key confirmation with the
 * card CVC key and the secured link. */
static void link_secure(TC_PIV_link* link)
{
  TC_PIV_SM_peer peer;
  TC_PIV_CVC cvc;
  recorded = &fixture.sessions[0];
  memset(&session, 0, sizeof session);
  munit_assert_int(TC_PIV_SM_key_request(link, &session, (TC_PIV_SM_suite)recorded->suite,
                                         recorded->host_id.data,
                                         (TC_random_source){recorded_scalar, NULL},
                                         response_buffer(), &peer, &workspace),
                   ==, TC_PIV_OK);
  munit_assert_int(TC_PIV_CVC_read(peer.certificate, &cvc), ==, TC_TLV_OK);
  munit_assert_int(TC_PIV_SM_finish(&session, &peer, cvc.public_key, &workspace), ==, TC_OK);
  munit_assert_int(TC_PIV_link_secure(link, &workspace, (TC_buffer){sm_scratch, sizeof sm_scratch}),
                   ==, TC_PIV_OK);
  munit_assert_true(card.session_active);
}

static TC_PIV_link_info link_info(const TC_PIV_link* link)
{
  TC_PIV_link_info info;
  TC_PIV_link_info_get(link, &info);
  return info;
}

/* Read tag and check the answer equals the fixture container. */
static void read_matches(TC_PIV_link* link, const uint8_t tag[3])
{
  TC_PIV_data_object object;
  const tc_card_object* expected = tc_card_fixture_object(&fixture, tag_value(tag));
  munit_assert_not_null(expected);
  munit_assert_int(TC_PIV_get_data(link, (TC_bytes){tag, 3}, response_buffer(), &object), ==,
                   TC_PIV_OK);
  munit_assert_size(object.encoded.length, ==, expected->data.length);
  munit_assert_memory_equal(expected->data.length, object.encoded.data, expected->data.data);
}

static void read_denied(TC_PIV_link* link, const uint8_t tag[3])
{
  TC_PIV_data_object object;
  munit_assert_int(TC_PIV_get_data(link, (TC_bytes){tag, 3}, response_buffer(), &object), ==,
                   TC_PIV_CARD_STATUS);
  munit_assert_uint16(TC_PIV_link_status(link), ==, 0x6982);
}

/* Both fixtures load with the facts the captures record. */
TC_TEST(fixture_load)
{
  load("sd33_card2");
  munit_assert_string_equal(fixture.name, "sd33_card2");
  munit_assert_size(fixture.select.length, ==, 55);
  const tc_card_object* chuid = tc_card_fixture_object(&fixture, 0x5fc102);
  munit_assert_not_null(chuid);
  munit_assert_size(chuid->data.length, ==, 2880);
  munit_assert_not_null(tc_card_fixture_object(&fixture, 0x7e));
  munit_assert_not_null(tc_card_fixture_object(&fixture, 0x5fc123));
  munit_assert_null(tc_card_fixture_object(&fixture, 0x5fc104));
  const tc_card_reference* pin = tc_card_fixture_reference(&fixture, 0x80);
  munit_assert_not_null(pin);
  munit_assert_uint8(pin->retries, ==, 7);
  munit_assert_true(pin->value_known);
  munit_assert_uint8(tc_card_fixture_reference(&fixture, 0x98)->retries, ==,
                     TC_CARD_FIXTURE_DEFAULT_RETRIES);
  munit_assert_size(fixture.session_count, ==, 3);
  munit_assert_size(fixture.replay_count, ==, 3);
  munit_assert_int(tc_card_fixture_replay(&fixture, "vci_vectors_card01")->interface, ==,
                   TC_PIV_CONTACT);
  munit_assert_size(fixture.authentication_count, ==, 8);

  load("sd33_card4");
  const tc_card_reference* global = tc_card_fixture_reference(&fixture, 0x00);
  munit_assert_not_null(global);
  munit_assert_false(global->value_known);
  munit_assert_uint8(global->retries, ==, 6);
  munit_assert_size(fixture.session_count, ==, 1);
  munit_assert_uint8(fixture.sessions[0].suite, ==, 0x27);
  munit_assert_null(tc_card_fixture_object(&fixture, 0x5fc123));
  return MUNIT_OK;
}

/* A missing file and malformed records name the failure. */
TC_TEST(fixture_errors)
{
  static const char* const bad[] = {
      "card bad\nsurprise 00\n",
      "card bad\nobject 5fc102 5\n",
      "card bad\nwire 00 9000\n",
      "card bad\nreference 80 3132 7\n",
  };
  munit_assert_long(tc_card_fixture_load(&fixture, "missing-card-fixture.txt"), ==, -1);
  for (size_t i = 0; i < sizeof bad / sizeof *bad; ++i) {
    FILE* file = tc_test_fopen("card-fixture-bad.txt", "w");
    munit_assert_not_null(file);
    fputs(bad[i], file);
    fclose(file);
    munit_assert_long(tc_card_fixture_load(&fixture, "card-fixture-bad.txt"), ==, 2);
  }
  remove("card-fixture-bad.txt");
  return MUNIT_OK;
}

/* Every recorded session, from card reset, gets the recorded answers byte
 * for byte, protected answers included. */
static void replay_all(const char* name)
{
  load(name);
  munit_assert_size(fixture.replay_count, >, 0);
  for (size_t r = 0; r < fixture.replay_count; ++r) {
    const tc_card_replay* replay = &fixture.replays[r];
    const TC_APDU_transport transport = tc_card_simulator_transport(&card);
    tc_card_simulator_init(&card, &fixture, replay->interface);
    for (size_t i = replay->first; i < replay->first + replay->count; ++i) {
      const tc_card_exchange* exchange = &fixture.exchanges[i];
      size_t length = 0;
      munit_assert_int(transport.transmit(transport.context, exchange->command,
                                          (TC_buffer){response_bytes, WIRE_BYTES}, &length),
                       ==, TC_OK);
      if (length != exchange->answer.length ||
          memcmp(response_bytes, exchange->answer.data, length))
        munit_errorf("%s exchange %zu differs", replay->name, i - replay->first);
    }
    munit_assert_size(card.violations, ==, 0);
    munit_assert_size(card.protected_commands, >, 0);
  }
}

TC_TEST(replay_card2)
{
  replay_all("sd33_card2");
  return MUNIT_OK;
}

TC_TEST(replay_card4)
{
  replay_all("sd33_card4");
  return MUNIT_OK;
}

/* Contact: Always objects plain, PIN objects after a plaintext PIN, long
 * answers in 256-byte chunks. */
TC_TEST(library_contact)
{
  TC_PIV_link link;
  TC_PIV_reference_status status;
  uint8_t pin[8];
  load("sd33_card2");
  link_open(&link, TC_PIV_CONTACT);
  read_matches(&link, tag_ccc);
  read_matches(&link, tag_piv_certificate);
  read_denied(&link, tag_facial_image);
  munit_assert_int(TC_PIV_pin_verify(&link, 0x80, secret(0x80, pin), 3, &status), ==, TC_PIV_OK);
  munit_assert_uint8(status.submitted, ==, 1);
  const size_t before = card.get_responses;
  read_matches(&link, tag_facial_image);
  munit_assert_size(card.get_responses - before, ==, FACIAL_IMAGE_BYTES / 256);
  munit_assert_size(card.pin_submissions, ==, 1);
  munit_assert_size(card.violations, ==, 0);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* Contactless: Always objects plain, VCI objects refused until the paired
 * secure messaging session, PIN objects after the protected PIN. */
TC_TEST(library_contactless)
{
  TC_PIV_link link;
  TC_PIV_discovery discovery;
  TC_PIV_vci_mode mode;
  TC_PIV_reference_status status;
  uint8_t pin[8], pairing[8];
  load("sd33_card2");
  link_open(&link, TC_PIV_CONTACTLESS);
  read_matches(&link, tag_chuid);
  read_denied(&link, tag_piv_certificate);
  link_secure(&link);
  read_denied(&link, tag_piv_certificate);
  munit_assert_true(link_info(&link).secured);
  munit_assert_int(TC_PIV_discovery_get(&link, TC_PIV_DISCOVERY_PIV, response_buffer(), &discovery),
                   ==, TC_PIV_OK);
  munit_assert_int(TC_PIV_vci_establish(&link, &discovery, secret(0x98, pairing), &mode), ==,
                   TC_PIV_OK);
  munit_assert_int(mode, ==, TC_PIV_VCI_PAIRED);
  munit_assert_true(card.pairing_verified);
  read_matches(&link, tag_piv_certificate);
  read_denied(&link, tag_facial_image);
  munit_assert_true(link_info(&link).secured);
  munit_assert_int(TC_PIV_pin_verify(&link, 0x80, secret(0x80, pin), 3, &status), ==, TC_PIV_OK);
  read_matches(&link, tag_facial_image);
  munit_assert_size(tc_card_simulator_sent(&card, 0xcb, tag_value(tag_facial_image)), ==, 2);
  for (size_t i = 0; i < card.log_count; ++i)
    if (card.log[i].ins == 0x20 && card.log[i].data_bytes)
      munit_assert_uint8(card.log[i].secured, ==, 1);
  munit_assert_size(card.violations, ==, 0);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* VERIFY counters, the query, P1 FF and blocking (Part 2 3.2.1). */
TC_TEST(verify_rules)
{
  load("sd33_card2");
  tc_card_simulator_init(&card, &fixture, TC_PIV_CONTACT);
  munit_assert_uint16(raw("00A4040009A00000030800001000", NULL), ==, 0x9000);
  munit_assert_uint16(raw("00200080", NULL), ==, 0x63c7);
  munit_assert_uint16(raw("0020008008303030303030FFFF", NULL), ==, 0x63c6);
  munit_assert_uint16(raw("00200080", NULL), ==, 0x63c6);
  munit_assert_uint16(raw("0020008008313233343536FFFF", NULL), ==, 0x9000);
  munit_assert_uint16(raw("00200080", NULL), ==, 0x9000);
  munit_assert_uint16(raw("0020FF80", NULL), ==, 0x9000);
  munit_assert_uint16(raw("00200080", NULL), ==, 0x63c7);
  munit_assert_uint16(raw("00200081", NULL), ==, 0x6a88);
  munit_assert_uint16(raw("002000800431323334", NULL), ==, 0x6a80);
  for (unsigned left = 6; left > 0; --left)
    munit_assert_uint16(raw("0020008008303030303030FFFF", NULL), ==, (uint16_t)(0x63c0 | left));
  munit_assert_uint16(raw("0020008008303030303030FFFF", NULL), ==, 0x63c0);
  munit_assert_uint16(raw("0020008008303030303030FFFF", NULL), ==, 0x6983);
  munit_assert_uint16(raw("0020008008313233343536FFFF", NULL), ==, 0x6983);
  munit_assert_uint16(raw("00200080", NULL), ==, 0x6983);
  munit_assert_size(card.pin_submissions, ==, 12);
  munit_assert_size(card.violations, ==, 0);
  return MUNIT_OK;
}

/* Contactless VERIFY in plaintext is refused and counted as a violation,
 * and so is the pairing code without secure messaging (Part 1 Table 4). */
TC_TEST(contactless_plain_verify)
{
  load("sd33_card2");
  tc_card_simulator_init(&card, &fixture, TC_PIV_CONTACTLESS);
  munit_assert_uint16(raw("00A404000BA00000030800001000010000", NULL), ==, 0x9000);
  munit_assert_uint16(raw("0020008008313233343536FFFF", NULL), ==, 0x6982);
  munit_assert_uint16(raw("00200098083030303030303032", NULL), ==, 0x6982);
  munit_assert_uint16(raw("00200080", NULL), ==, 0x6982);
  munit_assert_false(card.verified[0]);
  munit_assert_false(card.pairing_verified);
  munit_assert_size(card.violations, ==, 2);
  munit_assert_not_null(card.violation);
  return MUNIT_OK;
}

/* GET DATA answers, SELECT forms and host protocol errors. */
TC_TEST(card_answers)
{
  size_t length = 0;
  load("sd33_card2");
  tc_card_simulator_init(&card, &fixture, TC_PIV_CONTACT);
  munit_assert_uint16(raw("00CB3FFF055C035FC10200", NULL), ==, 0x6985);
  munit_assert_uint16(raw("00A4040005A000000308", NULL), ==, 0x6a82);
  munit_assert_uint16(raw("00A404000BA00000030800001000010000", &length), ==, 0x9000);
  munit_assert_size(length, ==, fixture.select.length);
  munit_assert_uint16(raw("00A4040005A000000399", NULL), ==, 0x6a82);
  munit_assert_true(card.selected);
  munit_assert_uint16(raw("00CB3FFF055C035FC10400", NULL), ==, 0x6a82);
  munit_assert_uint16(raw("00CB3FFF055C035FC12000", &length), ==, 0x9000);
  munit_assert_size(length, ==, 2);
  munit_assert_uint16(raw("00CB3FFF03FF0000", NULL), ==, 0x6a80);
  munit_assert_uint16(raw("00CB3FFE055C035FC10200", NULL), ==, 0x6a86);
  /* Le 50 gets the first 80 bytes, as SD 33 card 2 answers. */
  munit_assert_uint16(raw("00CB3FFF055C035FC10250", &length), ==, 0x9000);
  munit_assert_size(length, ==, 0x50);
  munit_assert_uint16(raw("00CB3FFF055C035FC10200", &length), ==, 0x6100);
  munit_assert_size(length, ==, 256);
  munit_assert_uint16(raw("00C0000010", &length), ==, 0x6100);
  munit_assert_size(length, ==, 16);
  munit_assert_uint16(raw("00DA3FFF00", NULL), ==, 0x6d00);
  munit_assert_size(card.violations, ==, 0);
  /* Host errors. */
  munit_assert_uint16(raw("00C0000000", NULL), ==, 0x6985);
  munit_assert_uint16(raw("80CA000000", NULL), ==, 0x6e00);
  munit_assert_uint16(raw("0CCB3FFF0A8E08000000000000000000", NULL), ==, 0x6982);
  munit_assert_uint16(raw("00CB3FFF", NULL), ==, 0x6a80);
  munit_assert_size(card.violations, ==, 2);
  return MUNIT_OK;
}

/* Key rules: 9E Always, 9A with the PIN, 9C with a PIN submission right
 * before it (Part 1 Table 5), unrecorded input 6A80. */
TC_TEST(authenticate_rules)
{
  char command[700];
  const tc_card_authentication* signing = NULL;
  const tc_card_authentication* card_key = NULL;
  size_t length = 0;
  load("sd33_card2");
  for (size_t i = 0; i < fixture.authentication_count; ++i) {
    if (fixture.authentications[i].key == 0x9c)
      signing = &fixture.authentications[i];
    if (fixture.authentications[i].key == 0x9e)
      card_key = &fixture.authentications[i];
  }
  munit_assert_not_null(signing);
  munit_assert_not_null(card_key);
  tc_card_simulator_init(&card, &fixture, TC_PIV_CONTACT);
  munit_assert_uint16(raw("00A404000BA00000030800001000010000", NULL), ==, 0x9000);
  /* 7C 82 01 06 {82 00, 81 82 01 00 input} as an extended command. */
  for (size_t k = 0; k < 2; ++k) {
    const tc_card_authentication* entry = k ? signing : card_key;
    /* Each append is checked before the next one uses its length. */
    int at =
        snprintf(command, sizeof command, "0087%02X%02X00010A7C8201068200818201", 7, entry->key);
    munit_assert_true(at > 0 && (size_t)at < sizeof command);
    at += snprintf(command + at, sizeof command - (size_t)at, "00");
    munit_assert_true((size_t)at < sizeof command);
    for (size_t i = 0; i < entry->input.length; ++i) {
      at += snprintf(command + at, sizeof command - (size_t)at, "%02X", entry->input.data[i]);
      munit_assert_true((size_t)at < sizeof command);
    }
    at += snprintf(command + at, sizeof command - (size_t)at, "0000");
    munit_assert_true((size_t)at < sizeof command);
    if (!k) {
      munit_assert_uint16(raw(command, &length), ==, 0x9000);
      munit_assert_size(length, ==, entry->answer.length);
      munit_assert_memory_equal(length, response_bytes, entry->answer.data);
      char* digit = &command[strlen(command) - 6];
      *digit = *digit == '0' ? '1' : '0';
      munit_assert_uint16(raw(command, NULL), ==, 0x6a80);
      continue;
    }
    munit_assert_uint16(raw(command, NULL), ==, 0x6982);
    munit_assert_uint16(raw("0020008008313233343536FFFF", NULL), ==, 0x9000);
    munit_assert_uint16(raw("00200080", NULL), ==, 0x9000);
    munit_assert_uint16(raw(command, NULL), ==, 0x6982);
    munit_assert_uint16(raw("0020008008313233343536FFFF", NULL), ==, 0x9000);
    munit_assert_uint16(raw(command, &length), ==, 0x9000);
    munit_assert_memory_equal(length, response_bytes, entry->answer.data);
    munit_assert_uint16(raw(command, NULL), ==, 0x6982);
  }
  munit_assert_uint16(raw("0087079B00", NULL), ==, 0x6a86);
  munit_assert_size(card.violations, ==, 0);
  return MUNIT_OK;
}

/* Plain command chaining with CLA 10 (ISO/IEC 7816-4 5.3.3): fragments
 * answer 9000, the last one runs the command. A fragment with another
 * header breaks the chain. */
TC_TEST(chain_rules)
{
  uint8_t command[RAW_COMMAND_BYTES];
  const tc_card_authentication* card_key = NULL;
  size_t length = 0;
  load("sd33_card2");
  for (size_t i = 0; i < fixture.authentication_count && !card_key; ++i)
    if (fixture.authentications[i].key == 0x9e)
      card_key = &fixture.authentications[i];
  munit_assert_not_null(card_key);
  munit_assert_size(card_key->input.length, ==, 256);
  tc_card_simulator_init(&card, &fixture, TC_PIV_CONTACT);
  munit_assert_uint16(raw("00A404000BA00000030800001000010000", NULL), ==, 0x9000);
  /* 7C 82 01 06 {82 00, 81 82 01 00 input}: 266 bytes in fragments of
   * 255 and 11. */
  static const uint8_t template_header[] = {0x7c, 0x82, 0x01, 0x06, 0x82,
                                            0x00, 0x81, 0x82, 0x01, 0x00};
  uint8_t field[266];
  memcpy(field, template_header, sizeof template_header);
  memcpy(field + sizeof template_header, card_key->input.data, 256);
  const uint8_t first[] = {0x10, 0x87, 0x07, 0x9e, 0xff};
  memcpy(command, first, sizeof first);
  memcpy(command + 5, field, 255);
  munit_assert_uint16(send(command, 260, &length), ==, 0x9000);
  munit_assert_size(length, ==, 0);
  const uint8_t last[] = {0x00, 0x87, 0x07, 0x9e, 11};
  memcpy(command, last, sizeof last);
  memcpy(command + 5, field + 255, 11);
  command[16] = 0x00;
  munit_assert_uint16(send(command, 17, &length), ==, 0x6108);
  munit_assert_size(length, ==, 256);
  munit_assert_memory_equal(256, response_bytes, card_key->answer.data);
  munit_assert_uint16(raw("00C0000008", &length), ==, 0x9000);
  munit_assert_memory_equal(8, response_bytes, card_key->answer.data + 256);
  munit_assert_size(card.fragments, ==, 1);
  munit_assert_size(tc_card_simulator_sent(&card, 0x87, 0), ==, 1);
  munit_assert_size(card.violations, ==, 0);
  /* The last fragment names another key. */
  command[0] = 0x10;
  command[4] = 0x05;
  munit_assert_uint16(send(command, 10, NULL), ==, 0x9000);
  munit_assert_uint16(raw("0087079A03010203", NULL), ==, 0x6883);
  munit_assert_size(card.violations, ==, 1);
  /* A chained fragment with Le, and GET RESPONSE under an SM CLA. */
  munit_assert_uint16(raw("1087079E0301020300", NULL), ==, 0x6883);
  munit_assert_uint16(raw("0CC0000000", NULL), ==, 0x6985);
  munit_assert_size(card.violations, ==, 3);
  /* Card 2 has no Global PIN (Discovery Object policy 48 00). */
  munit_assert_uint16(raw("00200000", NULL), ==, 0x6a88);
  return MUNIT_OK;
}

/* Overrides replace container answers, and reset clears the security
 * status and the session. */
TC_TEST(override_and_reset)
{
  static const uint8_t empty[] = {0x53, 0x00};
  TC_PIV_link link;
  TC_PIV_data_object object;
  TC_PIV_reference_status status;
  uint8_t pin[8];
  load("sd33_card2");
  link_open(&link, TC_PIV_CONTACT);
  munit_assert_true(tc_card_simulator_override(&card, 0x5fc102, 0x6982, (TC_bytes){NULL, 0}));
  munit_assert_true(tc_card_simulator_override(&card, 0x5fc107, 0x9000, (TC_bytes){empty, 2}));
  munit_assert_true(tc_card_simulator_override(&card, 0x5fc105, 0x6a82, (TC_bytes){NULL, 0}));
  read_denied(&link, tag_chuid);
  munit_assert_int(TC_PIV_get_data(&link, (TC_bytes){tag_ccc, 3}, response_buffer(), &object), ==,
                   TC_PIV_OK);
  munit_assert_size(object.value.length, ==, 0);
  munit_assert_int(
      TC_PIV_get_data(&link, (TC_bytes){tag_piv_certificate, 3}, response_buffer(), &object), ==,
      TC_PIV_CARD_STATUS);
  munit_assert_uint16(TC_PIV_link_status(&link), ==, 0x6a82);
  munit_assert_int(TC_PIV_pin_verify(&link, 0x80, secret(0x80, pin), 3, &status), ==, TC_PIV_OK);
  munit_assert_true(card.verified[0]);
  tc_card_simulator_reset(&card);
  munit_assert_false(card.verified[0]);
  munit_assert_false(card.selected);
  for (size_t i = 0; i < TC_CARD_SIMULATOR_OVERRIDES; ++i)
    tc_card_simulator_override(&card, 0x5fc10c, 0x9000, (TC_bytes){empty, 2});
  munit_assert_false(tc_card_simulator_override(&card, 0x5fc10c, 0x9000, (TC_bytes){empty, 2}));
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* A protected command with a bad C-MAC answers 6988 and ends the session
 * (Part 2 4.3), so the next protected command answers 6982. */
TC_TEST(session_errors)
{
  TC_PIV_link link;
  load("sd33_card2");
  link_open(&link, TC_PIV_CONTACTLESS);
  link_secure(&link);
  munit_assert_uint16(raw("0CCB3FFF0A8E08000000000000000000", NULL), ==, 0x6988);
  munit_assert_false(card.session_active);
  munit_assert_size(card.violations, ==, 1);
  munit_assert_uint16(raw("0CCB3FFF0A8E08000000000000000000", NULL), ==, 0x6982);
  /* Extended length secure messaging (footnote 22). */
  munit_assert_uint16(raw("0CCB3FFF00000A8E0800000000000000000000", NULL), ==, 0x6700);
  munit_assert_size(card.violations, ==, 2);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* Any SM status other than 9000 or 61XX ends the session (Part 2 4.3
 * footnote 25), and so does a key establishment request, even one the card
 * rejects. */
TC_TEST(session_destruction)
{
  TC_PIV_link link;
  load("sd33_card2");
  link_open(&link, TC_PIV_CONTACTLESS);
  link_secure(&link);
  munit_assert_uint16(raw("0CCB3FFF00000A8E0800000000000000000000", NULL), ==, 0x6700);
  munit_assert_false(card.session_active);
  TC_PIV_link_clear(&link);

  /* A protected command that does not parse, here Lc 0A with two data
   * bytes, is an SM error before any other check. */
  link_open(&link, TC_PIV_CONTACTLESS);
  link_secure(&link);
  munit_assert_uint16(raw("0CCB3FFF0A8E08", NULL), ==, 0x6700);
  munit_assert_false(card.session_active);
  munit_assert_uint16(raw("0CCB3FFF0A8E08000000000000000000", NULL), ==, 0x6982);
  TC_PIV_link_clear(&link);

  /* A malformed plain APDU inside a protected chain breaks that chain. */
  link_open(&link, TC_PIV_CONTACTLESS);
  link_secure(&link);
  munit_assert_uint16(raw("1CCB3FFF0A8E080000000000000000", NULL), ==, 0x9000);
  munit_assert_uint16(raw("00CB3FFF0A5C", NULL), ==, 0x6700);
  munit_assert_false(card.session_active);
  TC_PIV_link_clear(&link);

  /* Outside a protected chain a malformed plain APDU is no SM error. */
  link_open(&link, TC_PIV_CONTACTLESS);
  link_secure(&link);
  munit_assert_uint16(raw("00CB3FFF0A5C", NULL), ==, 0x6700);
  munit_assert_true(card.session_active);
  TC_PIV_link_clear(&link);

  link_open(&link, TC_PIV_CONTACTLESS);
  link_secure(&link);
  /* A protected chain broken by a plaintext command. */
  munit_assert_uint16(raw("1CCB3FFF0A8E080000000000000000", NULL), ==, 0x9000);
  munit_assert_true(card.session_active);
  munit_assert_uint16(raw("00CB3FFF055C035FC10200", NULL), ==, 0x6883);
  munit_assert_false(card.session_active);
  TC_PIV_link_clear(&link);

  link_open(&link, TC_PIV_CONTACTLESS);
  link_secure(&link);
  munit_assert_uint16(raw("00872704047C02820000", NULL), ==, 0x6a80);
  munit_assert_false(card.session_active);
  munit_assert_uint16(raw("0CCB3FFF0A8E08000000000000000000", NULL), ==, 0x6982);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* The VCI condition and the verifiable references follow the Discovery
 * Object the card answers, overrides included (Part 1 5.5, Part 2 3.2.1). */
TC_TEST(discovery_override)
{
  static const uint8_t without_pairing[] = {0x7e, 0x12, 0x4f, 0x0b, 0xa0, 0x00, 0x00,
                                            0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01,
                                            0x00, 0x5f, 0x2f, 0x02, 0x4c, 0x00};
  TC_PIV_link link;
  load("sd33_card2");
  link_open(&link, TC_PIV_CONTACTLESS);
  munit_assert_true(tc_card_simulator_override(
      &card, 0x7e, 0x9000, (TC_bytes){without_pairing, sizeof without_pairing}));
  link_secure(&link);
  read_matches(&link, tag_piv_certificate);
  munit_assert_size(card.pairing_submissions, ==, 0);
  TC_PIV_link_clear(&link);

  tc_card_simulator_init(&card, &fixture, TC_PIV_CONTACT);
  munit_assert_true(tc_card_simulator_override(&card, 0x7e, 0x6a82, (TC_bytes){NULL, 0}));
  munit_assert_uint16(raw("00A404000BA00000030800001000010000", NULL), ==, 0x9000);
  munit_assert_uint16(raw("00200098", NULL), ==, 0x6a88);
  munit_assert_uint16(raw("00200080", NULL), ==, 0x63c7);
  return MUNIT_OK;
}

/* A full command log counts as a violation, so a test that counts sent
 * commands never reads a truncated log. */
TC_TEST(log_limit)
{
  load("sd33_card2");
  tc_card_simulator_init(&card, &fixture, TC_PIV_CONTACT);
  for (size_t i = 0; i < TC_CARD_SIMULATOR_LOG; ++i)
    munit_assert_uint16(raw("00A404000BA00000030800001000010000", NULL), ==, 0x9000);
  munit_assert_size(card.violations, ==, 0);
  munit_assert_uint16(raw("00A404000BA00000030800001000010000", NULL), ==, 0x9000);
  munit_assert_size(card.violations, ==, 1);
  munit_assert_size(card.log_count, ==, TC_CARD_SIMULATOR_LOG);
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/fixture/load", fixture_load, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/fixture/errors", fixture_errors, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/replay/card2", replay_card2, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/replay/card4", replay_card4, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/library/contact", library_contact, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/library/contactless", library_contactless, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/verify/rules", verify_rules, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/verify/contactless-plain", contactless_plain_verify, NULL, NULL, MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/card/answers", card_answers, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/authenticate/rules", authenticate_rules, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/chain/rules", chain_rules, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/override-reset", override_and_reset, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/session/errors", session_errors, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/session/destruction", session_destruction, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/discovery/override", discovery_override, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/card/log-limit", log_limit, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
static const MunitSuite suite = {"/card-simulator", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[])
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
