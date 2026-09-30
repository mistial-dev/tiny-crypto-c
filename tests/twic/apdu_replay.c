/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* The synthetic TWIC APDU replays of tests/twic/apdu_replay.py through the
 * library: TWIC SELECT and the TWIC application inventory (TWIC Part 2 v5
 * 4.5 and 5), the observed absent and denied objects, the PIV application
 * of the card, its PIN and GENERAL AUTHENTICATE through an APDU channel on
 * the same transport. Every command must equal the replay byte for byte. */
#include <tiny_crypto/piv_catalog.h>
#include "munit.h"
#include "test_util.h"
#include <stdio.h>
#include <string.h>

#ifndef TC_TWIC_VECTOR_DIR
#error "TC_TWIC_VECTOR_DIR must name the synthetic TWIC corpus"
#endif

enum {
  MAX_OBJECT = 20000,
  RESPONSE_SIZE = MAX_OBJECT + 32,
  POOL_SIZE = 120000,
  LINE_SIZE = 1200,
  WIRE_SIZE = 300,
  EXCHANGES = 1000,
  TWIC_OBJECTS = 12
};

/* The replay transport. With empty_tag set, GET DATA of that tag answers
 * 53 00 and the recorded GET RESPONSE steps of its answer are skipped. */
typedef struct {
  FILE* file;
  size_t exchanges;
  uint8_t empty_tag[3];
  int skip_get_response;
} Replay;

static int nibble(char value)
{
  if (value >= '0' && value <= '9')
    return value - '0';
  if (value >= 'a' && value <= 'f')
    return value - 'a' + 10;
  return -1;
}

static size_t decode(const char* value, uint8_t* bytes, size_t capacity)
{
  size_t length = 0;
  while (value[0] && value[0] != '\n' && value[0] != '\r' && value[0] != ' ') {
    munit_assert_size(length, <, capacity);
    const int high = nibble(value[0]);
    const int low = nibble(value[1]);
    munit_assert_int(high, >=, 0);
    munit_assert_int(low, >=, 0);
    bytes[length++] = (uint8_t)(high * 16 + low);
    value += 2;
  }
  return length;
}

static char* next_line(FILE* file, char* line, size_t capacity)
{
  while (fgets(line, (int)capacity, file)) {
    const size_t length = strlen(line);
    munit_assert_true(length && (line[length - 1] == '\n' || feof(file)));
    if (line[0] != '#')
      return line;
  }
  return NULL;
}

static TC_status transmit(void* context, TC_bytes command, TC_buffer response, size_t* length)
{
  Replay* replay = context;
  char line[LINE_SIZE];
  uint8_t expected_command[WIRE_SIZE], expected_response[WIRE_SIZE];
  char* separator = NULL;
  size_t command_size = 0;
  do {
    munit_assert_not_null(next_line(replay->file, line, sizeof line));
    separator = strchr(line, ' ');
    munit_assert_not_null(separator);
    command_size = decode(line, expected_command, sizeof expected_command);
  } while (replay->skip_get_response && expected_command[1] == 0xc0 && command.data[1] != 0xc0);
  replay->skip_get_response = 0;
  const size_t response_size = decode(separator + 1, expected_response, sizeof expected_response);
  munit_assert_size(command.length, ==, command_size);
  munit_assert_memory_equal(command_size, command.data, expected_command);
  ++replay->exchanges;
  if (command_size == 11 && command.data[1] == 0xcb && replay->empty_tag[0] &&
      !memcmp(command.data + 7, replay->empty_tag, 3)) {
    static const uint8_t empty[] = {0x53, 0, 0x90, 0};
    munit_assert_size(sizeof empty, <=, response.capacity);
    memcpy(response.data, empty, sizeof empty);
    *length = sizeof empty;
    replay->skip_get_response = 1;
    return TC_OK;
  }
  munit_assert_size(response_size, <=, response.capacity);
  memcpy(response.data, expected_response, response_size);
  *length = response_size;
  return TC_OK;
}

static void fixture_path(char* path, size_t capacity, const char* profile, const char* name)
{
  const int result = snprintf(path, capacity, "%s/%s/%s", TC_TWIC_VECTOR_DIR, profile, name);
  munit_assert_int(result, >, 0);
  munit_assert_size((size_t)result, <, capacity);
}

static size_t fixture_read(const char* profile, const char* name, uint8_t* bytes, size_t capacity)
{
  char path[512];
  fixture_path(path, sizeof path, profile, name);
  FILE* file = fopen(path, "rb");
  munit_assert_not_null(file);
  const size_t length = fread(bytes, 1, capacity, file);
  munit_assert_int(ferror(file), ==, 0);
  munit_assert_int(fgetc(file), ==, EOF);
  munit_assert_int(fclose(file), ==, 0);
  return length;
}

static uint8_t scratch[TC_APDU_SHORT_COMMAND_MAX_BYTES];
static uint8_t response[RESPONSE_SIZE];
static uint8_t pool[POOL_SIZE];
static TC_PIV_object objects[TWIC_OBJECTS];
static uint8_t expected[MAX_OBJECT];

/* An empty inventory over the objects array. */
static TC_PIV_inventory inventory_start(void)
{
  TC_PIV_inventory inventory;
  memset(&inventory, 0, sizeof inventory);
  inventory.objects = objects;
  inventory.capacity = TWIC_OBJECTS;
  return inventory;
}

static TC_buffer response_buffer(void)
{
  return (TC_buffer){response, sizeof response};
}

static FILE* replay_open(const char* profile, const char* name)
{
  char path[512];
  fixture_path(path, sizeof path, profile, name);
  FILE* file = fopen(path, "rb");
  munit_assert_not_null(file);
  return file;
}

static void link_open(TC_PIV_link* link, Replay* replay, TC_PIV_interface interface)
{
  const TC_PIV_link_options options = {{TC_APDU_SHORT, 0, EXCHANGES, 0, 0}, interface, 0};
  munit_assert_int(TC_PIV_link_init(link, (TC_APDU_transport){transmit, replay}, &options,
                                    (TC_buffer){scratch, sizeof scratch}),
                   ==, TC_PIV_OK);
}

static void select_application(TC_PIV_link* link, TC_PIV_application_id id,
                               TC_PIV_card_profile profile)
{
  TC_PIV_application application;
  munit_assert_int(TC_PIV_select(link, id, 0, response_buffer(), &application), ==, TC_PIV_OK);
  munit_assert_int(application.profile, ==, profile);
  munit_assert_size(application.max_command_bytes, ==, 0x400);
  munit_assert_size(application.max_response_bytes, ==, 0x800);
}

/* GET DATA of tag answers the fixture object named name. */
static void read_object(TC_PIV_link* link, const char* profile, const char* name, TC_bytes tag)
{
  TC_PIV_data_object object;
  const size_t length = fixture_read(profile, name, expected, sizeof expected);
  munit_assert_int(TC_PIV_get_data(link, tag, response_buffer(), &object), ==, TC_PIV_OK);
  munit_assert_size(object.encoded.length, ==, length);
  munit_assert_memory_equal(length, object.encoded.data, expected);
}

/* GET DATA of tag is answered with sw alone. */
static void read_status(TC_PIV_link* link, TC_bytes tag, uint16_t sw)
{
  TC_PIV_data_object object;
  munit_assert_int(TC_PIV_get_data(link, tag, response_buffer(), &object), ==, TC_PIV_CARD_STATUS);
  munit_assert_uint16(TC_PIV_link_status(link), ==, sw);
}

static void read_status_tags(TC_PIV_link* link, const uint8_t prefix[2], const uint8_t* last,
                             size_t count, uint16_t sw)
{
  for (size_t i = 0; i < count; ++i) {
    const uint8_t tag[] = {prefix[0], prefix[1], last[i]};
    read_status(link, (TC_bytes){tag, sizeof tag}, sw);
  }
}

static void read_e_stickers(TC_PIV_link* link)
{
  for (unsigned tag = 0xe1; tag <= 0xfd; ++tag) {
    if (tag > 0xea && tag < 0xfa)
      continue;
    const uint8_t encoded = (uint8_t)tag;
    read_status(link, (TC_bytes){&encoded, 1}, 0x6a82);
  }
}

/* Every present TWIC object equals its fixture. The TWIC Privacy Key reads
 * on contact only (TWIC Part 2 v5 4.5). */
static void check_twic_inventory(const TC_PIV_inventory* inventory, const char* profile,
                                 TC_PIV_interface interface)
{
  static const struct {
    const char* name;
    uint16_t container;
  } names[] = {{"card-auth-cert.bin", 0x0500},
               {"signed-chuid.bin", 0x3000},
               {"unsigned-chuid.bin", 0x3002},
               {"discovery.bin", 0x6050},
               {"personal.bin", 0x6011},
               {"handwritten.bin", 0x6012},
               {"tpk.bin", 0x2001},
               {"fingerprint.bin", 0x2003},
               {"face.bin", 0x6030},
               {"printed.bin", 0x3001},
               {"security.bin", 0x9000},
               {"iris.bin", 0x1015}};
  const int nexgen = strcmp(profile, "legacy") != 0;
  munit_assert_size(inventory->count, ==, nexgen ? 12 : 5);
  munit_assert_int(inventory->link.application, ==, TC_PIV_APPLICATION_TWIC);
  for (size_t i = 0; i < sizeof names / sizeof *names; ++i) {
    const TC_PIV_object* object = TC_PIV_inventory_find(inventory, names[i].container);
    if (!nexgen && !object)
      continue;
    munit_assert_not_null(object);
    if (names[i].container == 0x2001 && interface == TC_PIV_CONTACTLESS) {
      munit_assert_int(object->state, ==, TC_PIV_OBJECT_RESTRICTED);
      continue;
    }
    const size_t length = fixture_read(profile, names[i].name, expected, sizeof expected);
    munit_assert_int(object->state, ==, length == 2 ? TC_PIV_OBJECT_EMPTY : TC_PIV_OBJECT_PRESENT);
    munit_assert_size(object->encoded.length, ==, length);
    munit_assert_memory_equal(length, object->encoded.data, expected);
  }
}

/* GENERAL AUTHENTICATE 9E with the fixture challenge (SP 800-73-5 Part 2
 * A.4.1): 7C {82 00, 81 challenge} in a SHORT chain, answered with
 * 7C {82 signature} over GET RESPONSE. */
static void authenticate(Replay* replay, const char* profile, int invalid)
{
  uint8_t challenge[256], signature[256], request[266];
  TC_APDU_channel channel;
  TC_APDU_response answer;
  uint8_t channel_scratch[TC_APDU_SHORT_COMMAND_MAX_BYTES];
  munit_assert_size(fixture_read(profile, "ga-challenge.bin", challenge, sizeof challenge), ==,
                    sizeof challenge);
  munit_assert_size(fixture_read(profile, "ga-signature.bin", signature, sizeof signature), ==,
                    sizeof signature);
  if (invalid)
    signature[sizeof signature - 1] ^= 1;
  static const uint8_t header[] = {0x7c, 0x82, 0x01, 0x06, 0x82, 0x00, 0x81, 0x82, 0x01, 0x00};
  memcpy(request, header, sizeof header);
  memcpy(request + sizeof header, challenge, sizeof challenge);
  const TC_APDU_channel_options options = {TC_APDU_SHORT, TC_APDU_GET_RESPONSE_PLAIN_CLA, 8, 0, 0};
  munit_assert_int(TC_APDU_channel_init(&channel, (TC_APDU_transport){transmit, replay}, &options,
                                        (TC_buffer){channel_scratch, sizeof channel_scratch}),
                   ==, TC_APDU_OK);
  const TC_APDU_command command = {{request, sizeof request}, 256, 0x00, 0x87, 0x07, 0x9e};
  munit_assert_int(TC_APDU_transceive(&channel, &command, response_buffer(), &answer), ==,
                   TC_APDU_OK);
  TC_APDU_channel_clear(&channel);
  munit_assert_uint16(answer.sw, ==, 0x9000);
  munit_assert_size(answer.data.length, ==, 264);
  static const uint8_t prefix[] = {0x7c, 0x82, 0x01, 0x04, 0x82, 0x82, 0x01, 0x00};
  munit_assert_memory_equal(sizeof prefix, answer.data.data, prefix);
  munit_assert_memory_equal(sizeof signature, answer.data.data + sizeof prefix, signature);
}

static void twic_application(TC_PIV_link* link, const char* profile, TC_PIV_interface interface)
{
  static const uint8_t tag_privacy_key[] = {0xdf, 0xc1, 0x01};
  const int legacy = !strcmp(profile, "legacy");
  TC_PIV_inventory inventory = inventory_start();
  size_t work = POOL_SIZE;
  select_application(link, TC_PIV_APPLICATION_TWIC,
                     legacy ? TC_TWIC_LEGACY_CARD : TC_TWIC_NEXGEN_CARD);
  munit_assert_int(
      TC_PIV_inventory_read(link, NULL, (TC_buffer){pool, sizeof pool}, &work, &inventory), ==,
      TC_PIV_OK);
  check_twic_inventory(&inventory, profile, interface);
  TC_PIV_inventory_clear(&inventory);
  /* The observed contactless refusal of the TWIC Privacy Key. */
  if (interface == TC_PIV_CONTACTLESS)
    read_status(link, (TC_bytes){tag_privacy_key, sizeof tag_privacy_key},
                legacy ? 0x6a81 : 0x6982);
  if (legacy) {
    static const uint8_t pivs[] = {0x01}, twics[] = {0x08, 0x09};
    static const uint8_t piv_prefix[] = {0x5f, 0xc1}, twic_prefix[] = {0xdf, 0xc1};
    read_status_tags(link, piv_prefix, pivs, sizeof pivs, 0x6a82);
    read_status_tags(link, twic_prefix, twics, sizeof twics, 0x6a82);
    if (interface == TC_PIV_CONTACTLESS) {
      static const uint8_t discovery = 0x7e, iris[] = {0x21}, personal[] = {0x01, 0x02};
      static const uint8_t personal_prefix[] = {0xdf, 0xc0};
      read_status(link, (TC_bytes){&discovery, 1}, 0x6a82);
      read_status_tags(link, twic_prefix, iris, sizeof iris, 0x6a82);
      read_status_tags(link, personal_prefix, personal, sizeof personal, 0x6a82);
      read_e_stickers(link);
    }
  } else {
    read_e_stickers(link);
  }
}

static void piv_application(TC_PIV_link* link, Replay* replay, const char* profile,
                            TC_PIV_interface interface)
{
  static const uint8_t piv_prefix[] = {0x5f, 0xc1};
  static const uint8_t tag_chuid[] = {0x5f, 0xc1, 0x02}, tag_card_auth[] = {0x5f, 0xc1, 0x01};
  static const uint8_t discovery = 0x7e;
  const int legacy = !strcmp(profile, "legacy");
  const int contact = interface == TC_PIV_CONTACT;
  select_application(link, TC_PIV_APPLICATION_PIV, TC_PIV_CARD);
  read_object(link, profile, "piv-signed-chuid.bin", (TC_bytes){tag_chuid, sizeof tag_chuid});
  read_object(link, profile, "piv-card-auth-cert.bin",
              (TC_bytes){tag_card_auth, sizeof tag_card_auth});
  authenticate(replay, profile, 0);
  static const struct {
    const char* name;
    uint8_t last;
  } certificates[] = {{"piv-auth-cert.bin", 0x05},
                      {"piv-discovery.bin", 0x07},
                      {"piv-sign-cert.bin", 0x0a},
                      {"piv-key-management-cert.bin", 0x0b}};
  if (legacy && contact) {
    for (size_t i = 0; i < sizeof certificates / sizeof *certificates; ++i) {
      const uint8_t tag[] = {0x5f, 0xc1, certificates[i].last};
      read_object(link, profile, certificates[i].name, (TC_bytes){tag, sizeof tag});
    }
  } else if (legacy) {
    static const uint8_t denied[] = {0x05, 0x07, 0x0a, 0x0b}, absent[] = {0x0c, 0x0d, 0x0e, 0x0f};
    read_status_tags(link, piv_prefix, denied, sizeof denied, 0x6a81);
    read_status_tags(link, piv_prefix, absent, sizeof absent, 0x6a82);
    read_status(link, (TC_bytes){&discovery, 1}, 0x6a82);
    return;
  }
  if (legacy)
    return;
  if (contact)
    for (size_t i = 0; i < 2; ++i) {
      const uint8_t tag[] = {0x5f, 0xc1, certificates[i].last};
      read_object(link, profile, certificates[i].name, (TC_bytes){tag, sizeof tag});
    }
  read_object(link, profile, "piv-twic-discovery.bin", (TC_bytes){&discovery, 1});
  if (!contact) {
    static const uint8_t denied[] = {0x05, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    read_status_tags(link, piv_prefix, denied, sizeof denied, 0x6982);
    return;
  }
  /* Query 63C3, then one submission of the invented PIN (Part 2 3.2.1). */
  static const uint8_t invented_pin[] = "31415926";
  TC_PIV_reference_status status;
  munit_assert_int(TC_PIV_pin_verify(link, 0x80, (TC_bytes){invented_pin, 8}, 3, &status), ==,
                   TC_PIV_OK);
  munit_assert_uint8(status.submitted, ==, 1);
  static const struct {
    const char* name;
    uint8_t last;
  } gated[] = {{"piv-fingerprint.bin", 0x03}, {"piv-face.bin", 0x08},   {"piv-security.bin", 0x06},
               {"piv-printed.bin", 0x09},     {"piv-5fc10a.bin", 0x0a}, {"piv-5fc10b.bin", 0x0b},
               {"piv-5fc10c.bin", 0x0c},      {"piv-5fc10d.bin", 0x0d}, {"piv-5fc10e.bin", 0x0e},
               {"piv-5fc10f.bin", 0x0f}};
  for (size_t i = 0; i < sizeof gated / sizeof *gated; ++i) {
    const uint8_t tag[] = {0x5f, 0xc1, gated[i].last};
    read_object(link, profile, gated[i].name, (TC_bytes){tag, sizeof tag});
  }
}

static MunitResult replay_profile(const char* profile, TC_PIV_interface interface)
{
  Replay replay = {replay_open(profile, interface == TC_PIV_CONTACT ? "apdu-contact.txt"
                                                                    : "apdu-contactless.txt"),
                   0,
                   {0},
                   0};
  TC_PIV_link link;
  link_open(&link, &replay, interface);
  twic_application(&link, profile, interface);
  piv_application(&link, &replay, profile, interface);
  char tail[LINE_SIZE];
  munit_assert_null(next_line(replay.file, tail, sizeof tail));
  munit_assert_int(fclose(replay.file), ==, 0);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

TC_TEST(legacy_contact)
{
  return replay_profile("legacy", TC_PIV_CONTACT);
}
TC_TEST(legacy_contactless)
{
  return replay_profile("legacy", TC_PIV_CONTACTLESS);
}
TC_TEST(nexgen_contact)
{
  return replay_profile("nexgen", TC_PIV_CONTACT);
}
TC_TEST(nexgen_contactless)
{
  return replay_profile("nexgen", TC_PIV_CONTACTLESS);
}

/* A mandatory NEXGEN object answered 53 00 reads as EMPTY. The inventory
 * completes, and the card check reports the missing content. */
TC_TEST(required_empty)
{
  static const struct {
    uint8_t tag[3];
    uint16_t container;
  } required[] = {
      {{0x5f, 0xc1, 0x02}, 0x3000}, {{0xdf, 0xc1, 0x03}, 0x2003}, {{0xdf, 0xc1, 0x0f}, 0x9000}};
  for (size_t i = 0; i < sizeof required / sizeof *required; ++i) {
    Replay replay = {replay_open("nexgen", "apdu-contact.txt"), 0, {0}, 0};
    memcpy(replay.empty_tag, required[i].tag, 3);
    TC_PIV_link link;
    TC_PIV_inventory inventory = inventory_start();
    size_t work = POOL_SIZE;
    link_open(&link, &replay, TC_PIV_CONTACT);
    select_application(&link, TC_PIV_APPLICATION_TWIC, TC_TWIC_NEXGEN_CARD);
    munit_assert_int(
        TC_PIV_inventory_read(&link, NULL, (TC_buffer){pool, sizeof pool}, &work, &inventory), ==,
        TC_PIV_OK);
    const TC_PIV_object* object = TC_PIV_inventory_find(&inventory, required[i].container);
    munit_assert_int(object->state, ==, TC_PIV_OBJECT_EMPTY);
    munit_assert_int(object->info->requirement, ==, TC_PIV_MANDATORY);
    TC_PIV_inventory_clear(&inventory);
    TC_PIV_link_clear(&link);
    munit_assert_int(fclose(replay.file), ==, 0);
  }
  return MUNIT_OK;
}

/* A flipped signature travels unchanged. Verification belongs to the key
 * proof. */
TC_TEST(invalid_legacy_proof)
{
  Replay replay = {replay_open("legacy", "apdu-ga-invalid.txt"), 0, {0}, 0};
  TC_PIV_link link;
  link_open(&link, &replay, TC_PIV_CONTACT);
  TC_PIV_application application;
  munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 0, response_buffer(), &application),
                   ==, TC_PIV_OK);
  authenticate(&replay, "legacy", 1);
  char tail[LINE_SIZE];
  munit_assert_null(next_line(replay.file, tail, sizeof tail));
  munit_assert_int(fclose(replay.file), ==, 0);
  munit_assert_size(replay.exchanges, ==, 4);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
      {"/legacy-contact", legacy_contact, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/legacy-contactless", legacy_contactless, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/nexgen-contact", nexgen_contact, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/nexgen-contactless", nexgen_contactless, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/required-empty", required_empty, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/invalid-legacy-proof", invalid_legacy_proof, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/twic-apdu-replay", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
