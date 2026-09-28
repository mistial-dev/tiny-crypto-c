/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../examples/credential_io.h"
#include "munit.h"
#include <stdio.h>
#include <string.h>

#ifndef TC_TWIC_VECTOR_DIR
#error "TC_TWIC_VECTOR_DIR must name the synthetic TWIC corpus"
#endif

enum { MAX_OBJECT = 20000, POOL_SIZE = 120000, LINE_SIZE = 1200 };
typedef struct {
  FILE* file;
  size_t exchanges;
  uint8_t empty_tag[3];
} Replay;

static int nibble(char value)
{
  if (value >= '0' && value <= '9')
    return value - '0';
  if (value >= 'a' && value <= 'f')
    return value - 'a' + 10;
  return -1;
}

static size_t decode(char* value, uint8_t* bytes, size_t capacity)
{
  size_t length = 0;
  while (value[0] && value[0] != '\n' && value[0] != '\r') {
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

static int transmit(void* context, const uint8_t* command, size_t command_length, uint8_t* response,
                    size_t capacity, size_t* length)
{
  Replay* replay = context;
  char line[LINE_SIZE];
  uint8_t expected_command[300], expected_response[300];
  munit_assert_not_null(next_line(replay->file, line, sizeof line));
  char* separator = strchr(line, ' ');
  munit_assert_not_null(separator);
  *separator++ = 0;
  const size_t command_size = decode(line, expected_command, sizeof expected_command);
  const size_t response_size = decode(separator, expected_response, sizeof expected_response);
  munit_assert_size(command_length, ==, command_size);
  munit_assert_memory_equal(command_size, command, expected_command);
  if (command_size == 11 && command[1] == 0xcb && replay->empty_tag[0] &&
      !memcmp(command + 7, replay->empty_tag, 3)) {
    static const uint8_t empty[] = {0x53, 0, 0x90, 0};
    munit_assert_size(sizeof empty, <=, capacity);
    memcpy(response, empty, sizeof empty);
    *length = sizeof empty;
    ++replay->exchanges;
    return 1;
  }
  munit_assert_size(response_size, <=, capacity);
  memcpy(response, expected_response, response_size);
  *length = response_size;
  ++replay->exchanges;
  return 1;
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

static void compare_inventory(const char* profile, const ExampleTWICInventory* inventory)
{
  static const char* const objects[] = {"signed-chuid.bin", "unsigned-chuid.bin", "fingerprint.bin",
                                        "face.bin",         "printed.bin",        "iris.bin",
                                        "personal.bin",     "handwritten.bin"};
  uint8_t bytes[MAX_OBJECT];
  const size_t required = strcmp(profile, "legacy") ? 8 : 3;
  munit_assert_size(inventory->count, ==, required);
  const TC_TLV_limits limits = {MAX_OBJECT, MAX_OBJECT, 1, 1};
  for (size_t i = 0; i < required; ++i) {
    const size_t length = fixture_read(profile, objects[i], bytes, sizeof bytes);
    TC_TLV_element field;
    munit_assert_int(TC_TLV_read(bytes, length, TC_TLV_ISO7816, &limits, &field), ==, TC_TLV_OK);
    munit_assert_size(field.encoded.length, ==, length);
    munit_assert_uint(field.header.tag[0], ==, 0x53);
    munit_assert_size(inventory->objects[i].contents.length, ==, field.value.length);
    munit_assert_memory_equal(field.value.length, inventory->objects[i].contents.data,
                              field.value.data);
  }
  const size_t security_length = fixture_read(profile, "security.bin", bytes, sizeof bytes);
  munit_assert_size(inventory->security.length, ==, security_length);
  munit_assert_memory_equal(security_length, inventory->security.data, bytes);
}

static void authenticate(ExampleCardIO* io, const char* profile, int invalid, uint8_t* buffer,
                         size_t capacity)
{
  uint8_t challenge[256], signature[256];
  munit_assert_size(fixture_read(profile, "ga-challenge.bin", challenge, sizeof challenge), ==,
                    sizeof challenge);
  munit_assert_size(fixture_read(profile, "ga-signature.bin", signature, sizeof signature), ==,
                    sizeof signature);
  if (invalid)
    signature[sizeof signature - 1] ^= 1;
  ExampleCardResponse response = {0};
  munit_assert_int(example_card_authenticate(
                       io, EXAMPLE_CARD_ALGORITHM_RSA_2048, EXAMPLE_CARD_KEY_CARD_AUTHENTICATION,
                       (TC_bytes){challenge, sizeof challenge}, buffer, capacity, &response),
                   ==, EXAMPLE_CARD_OK);
  munit_assert_uint(response.status, ==, 0x9000);
  munit_assert_size(response.length, ==, 264);
  static const uint8_t prefix[] = {0x7c, 0x82, 0x01, 0x04, 0x82, 0x82, 0x01, 0x00};
  munit_assert_memory_equal(sizeof prefix, buffer, prefix);
  munit_assert_memory_equal(sizeof signature, buffer + sizeof prefix, signature);
}

static MunitResult replay_profile(const char* profile, const char* interface)
{
  char path[512], name[64];
  const int size = snprintf(name, sizeof name, "apdu-%s.txt", interface);
  munit_assert_int(size, >, 0);
  munit_assert_size((size_t)size, <, sizeof name);
  fixture_path(path, sizeof path, profile, name);
  FILE* file = fopen(path, "rb");
  munit_assert_not_null(file);
  Replay replay = {file, 0, {0}};
  ExampleCardIO io = {transmit, &replay, 1000, 0};
  static uint8_t pool[POOL_SIZE], buffer[MAX_OBJECT + EXAMPLE_CARD_STATUS_BYTES];
  ExampleTWICInventory inventory;
  size_t work = sizeof pool;
  const ExampleCardModel model =
      strcmp(profile, "legacy") ? EXAMPLE_CARD_MODEL_TWIC_NEXGEN : EXAMPLE_CARD_MODEL_TWIC_LEGACY;
  munit_assert_int(example_twic_inventory_read(&io, model, EXAMPLE_CARD_READ_SHORT, pool,
                                               sizeof pool, MAX_OBJECT, &work, &inventory),
                   ==, EXAMPLE_CARD_OK);
  compare_inventory(profile, &inventory);

  const uint8_t tpk_tag[] = {0xdf, 0xc1, 0x01};
  ExampleCardResponse response = {0};
  const ExampleCardResult result = example_card_object_read(
      &io, EXAMPLE_CARD_READ_SHORT, tpk_tag, sizeof tpk_tag, buffer, sizeof buffer, &response);
  if (!strcmp(interface, "contact")) {
    uint8_t tpk[MAX_OBJECT];
    const size_t length = fixture_read(profile, "tpk.bin", tpk, sizeof tpk);
    munit_assert_int(result, ==, EXAMPLE_CARD_OK);
    munit_assert_size(response.length, ==, length);
    munit_assert_memory_equal(length, buffer, tpk);
  } else {
    munit_assert_int(result, ==, EXAMPLE_CARD_STATUS);
    munit_assert_uint(response.status, ==, strcmp(profile, "legacy") ? 0x6982 : 0x6a81);
    munit_assert_size(response.length, ==, 0);
  }
  if (!strcmp(profile, "legacy")) {
    static const uint8_t absent[][3] = {{0x5f, 0xc1, 0x01}, {0xdf, 0xc1, 0x08}, {0xdf, 0xc1, 0x09}};
    for (size_t i = 0; i < sizeof absent / sizeof *absent; ++i) {
      munit_assert_int(example_card_object_read(&io, EXAMPLE_CARD_READ_SHORT, absent[i],
                                                sizeof absent[i], buffer, sizeof buffer, &response),
                       ==, EXAMPLE_CARD_STATUS);
      munit_assert_uint(response.status, ==, 0x6a82);
      munit_assert_size(response.length, ==, 0);
    }
    if (!strcmp(interface, "contactless")) {
      static const struct {
        uint8_t tag[3];
        size_t length;
      } absent_rf[] = {{{0x7e, 0, 0}, 1},
                       {{0xdf, 0xc1, 0x21}, 3},
                       {{0xdf, 0xc0, 0x01}, 3},
                       {{0xdf, 0xc0, 0x02}, 3}};
      for (size_t i = 0; i < sizeof absent_rf / sizeof *absent_rf; ++i) {
        munit_assert_int(example_card_object_read(&io, EXAMPLE_CARD_READ_SHORT, absent_rf[i].tag,
                                                  absent_rf[i].length, buffer, sizeof buffer,
                                                  &response),
                         ==, EXAMPLE_CARD_STATUS);
        munit_assert_uint(response.status, ==, 0x6a82);
      }
      for (unsigned tag = 0xe1; tag <= 0xfd; ++tag) {
        if (tag > 0xea && tag < 0xfa)
          continue;
        const uint8_t encoded = (uint8_t)tag;
        munit_assert_int(example_card_object_read(&io, EXAMPLE_CARD_READ_SHORT, &encoded, 1, buffer,
                                                  sizeof buffer, &response),
                         ==, EXAMPLE_CARD_STATUS);
        munit_assert_uint(response.status, ==, 0x6a82);
      }
    }
  } else if (!strcmp(profile, "nexgen")) {
    static const struct {
      const char* name;
      uint8_t tag[3];
      size_t tag_length;
    } objects[] = {{"card-auth-cert.bin", {0x5f, 0xc1, 0x01}, 3},
                   {"discovery.bin", {0x7e, 0, 0}, 1}};
    for (size_t i = 0; i < sizeof objects / sizeof *objects; ++i) {
      uint8_t expected[MAX_OBJECT];
      const size_t length = fixture_read(profile, objects[i].name, expected, sizeof expected);
      const ExampleCardResult status =
          objects[i].tag[0] == 0x7e
              ? example_card_read(&io, objects[i].tag, objects[i].tag_length, buffer, sizeof buffer,
                                  &response)
              : example_card_object_read(&io, EXAMPLE_CARD_READ_SHORT, objects[i].tag,
                                         objects[i].tag_length, buffer, sizeof buffer, &response);
      munit_assert_int(status, ==, EXAMPLE_CARD_OK);
      munit_assert_size(response.length, ==, length);
      munit_assert_memory_equal(length, buffer, expected);
    }
    for (unsigned tag = 0xe1; tag <= 0xfd; ++tag) {
      if (tag > 0xea && tag < 0xfa)
        continue;
      const uint8_t encoded = (uint8_t)tag;
      munit_assert_int(example_card_object_read(&io, EXAMPLE_CARD_READ_SHORT, &encoded, 1, buffer,
                                                sizeof buffer, &response),
                       ==, EXAMPLE_CARD_STATUS);
      munit_assert_uint(response.status, ==, 0x6a82);
      munit_assert_size(response.length, ==, 0);
    }
  }
  {
    munit_assert_int(example_card_select(&io, EXAMPLE_CARD_PIV, buffer, sizeof buffer, &response),
                     ==, EXAMPLE_CARD_OK);
    ExampleCardModel piv_model = EXAMPLE_CARD_MODEL_TWIC_LEGACY;
    munit_assert_int(
        example_card_identity((TC_bytes){buffer, response.length}, EXAMPLE_CARD_PIV, &piv_model),
        ==, TC_TLV_OK);
    munit_assert_int(piv_model, ==, EXAMPLE_CARD_MODEL_PIV);
    static const struct {
      const char* name;
      uint8_t tag[3];
    } piv_objects[] = {{"piv-signed-chuid.bin", {0x5f, 0xc1, 0x02}},
                       {"piv-card-auth-cert.bin", {0x5f, 0xc1, 0x01}}};
    for (size_t i = 0; i < sizeof piv_objects / sizeof *piv_objects; ++i) {
      uint8_t expected[MAX_OBJECT];
      const size_t length = fixture_read(profile, piv_objects[i].name, expected, sizeof expected);
      munit_assert_int(example_card_object_read(&io, EXAMPLE_CARD_READ_SHORT, piv_objects[i].tag,
                                                sizeof piv_objects[i].tag, buffer, sizeof buffer,
                                                &response),
                       ==, EXAMPLE_CARD_OK);
      munit_assert_size(response.length, ==, length);
      munit_assert_memory_equal(length, buffer, expected);
    }
    authenticate(&io, profile, 0, buffer, sizeof buffer);
    if (!strcmp(profile, "legacy")) {
      if (!strcmp(interface, "contact")) {
        static const struct {
          const char* name;
          uint8_t tag[3];
        } legacy_certs[] = {{"piv-auth-cert.bin", {0x5f, 0xc1, 0x05}},
                            {"piv-discovery.bin", {0x5f, 0xc1, 0x07}},
                            {"piv-sign-cert.bin", {0x5f, 0xc1, 0x0a}},
                            {"piv-key-management-cert.bin", {0x5f, 0xc1, 0x0b}}};
        for (size_t i = 0; i < sizeof legacy_certs / sizeof *legacy_certs; ++i) {
          uint8_t expected[MAX_OBJECT];
          const size_t length =
              fixture_read(profile, legacy_certs[i].name, expected, sizeof expected);
          munit_assert_int(example_card_object_read(&io, EXAMPLE_CARD_READ_SHORT,
                                                    legacy_certs[i].tag, sizeof legacy_certs[i].tag,
                                                    buffer, sizeof buffer, &response),
                           ==, EXAMPLE_CARD_OK);
          munit_assert_size(response.length, ==, length);
          munit_assert_memory_equal(length, buffer, expected);
        }
      } else {
        static const uint8_t restricted[] = {0x05, 0x07, 0x0a, 0x0b};
        for (size_t i = 0; i < sizeof restricted; ++i) {
          const uint8_t tag[] = {0x5f, 0xc1, restricted[i]};
          munit_assert_int(example_card_object_read(&io, EXAMPLE_CARD_READ_SHORT, tag, sizeof tag,
                                                    buffer, sizeof buffer, &response),
                           ==, EXAMPLE_CARD_STATUS);
          munit_assert_uint(response.status, ==, 0x6a81);
        }
        for (unsigned last = 0x0c; last <= 0x0f; ++last) {
          const uint8_t tag[] = {0x5f, 0xc1, (uint8_t)last};
          munit_assert_int(example_card_object_read(&io, EXAMPLE_CARD_READ_SHORT, tag, sizeof tag,
                                                    buffer, sizeof buffer, &response),
                           ==, EXAMPLE_CARD_STATUS);
          munit_assert_uint(response.status, ==, 0x6a82);
        }
        const uint8_t discovery = 0x7e;
        munit_assert_int(example_card_object_read(&io, EXAMPLE_CARD_READ_SHORT, &discovery, 1,
                                                  buffer, sizeof buffer, &response),
                         ==, EXAMPLE_CARD_STATUS);
        munit_assert_uint(response.status, ==, 0x6a82);
      }
    }
    if (!strcmp(profile, "nexgen")) {
      static const struct {
        const char* name;
        uint8_t tag[3];
        size_t tag_length;
      } extra[] = {{"piv-auth-cert.bin", {0x5f, 0xc1, 0x05}, 3},
                   {"piv-discovery.bin", {0x5f, 0xc1, 0x07}, 3},
                   {"piv-twic-discovery.bin", {0x7e, 0, 0}, 1}};
      for (size_t i = 0; i < sizeof extra / sizeof *extra; ++i) {
        if (strcmp(interface, "contact") && i < 2)
          continue;
        uint8_t expected[MAX_OBJECT];
        const size_t length = fixture_read(profile, extra[i].name, expected, sizeof expected);
        const ExampleCardResult status =
            extra[i].tag[0] == 0x7e
                ? example_card_read(&io, extra[i].tag, extra[i].tag_length, buffer, sizeof buffer,
                                    &response)
                : example_card_object_read(&io, EXAMPLE_CARD_READ_SHORT, extra[i].tag,
                                           extra[i].tag_length, buffer, sizeof buffer, &response);
        munit_assert_int(status, ==, EXAMPLE_CARD_OK);
        munit_assert_size(response.length, ==, length);
        munit_assert_memory_equal(length, buffer, expected);
      }
      if (!strcmp(interface, "contact")) {
        static const uint8_t invented_pin[] = "31415926";
        ExampleCardPIN guard = {0};
        uint16_t pin_status = 0;
        munit_assert_int(example_card_verify_pin(&io, &guard, invented_pin, 8, &pin_status), ==,
                         EXAMPLE_CARD_OK);
        munit_assert_uint(pin_status, ==, 0x9000);
        munit_assert_int(guard.used, ==, 1);
        static const struct {
          const char* name;
          uint8_t tag[3];
        } gated[] = {{"piv-fingerprint.bin", {0x5f, 0xc1, 0x03}},
                     {"piv-face.bin", {0x5f, 0xc1, 0x08}},
                     {"piv-security.bin", {0x5f, 0xc1, 0x06}},
                     {"piv-printed.bin", {0x5f, 0xc1, 0x09}}};
        for (size_t i = 0; i < sizeof gated / sizeof *gated; ++i) {
          uint8_t expected[MAX_OBJECT];
          const size_t length = fixture_read(profile, gated[i].name, expected, sizeof expected);
          munit_assert_int(example_card_object_read(&io, EXAMPLE_CARD_READ_SHORT, gated[i].tag,
                                                    sizeof gated[i].tag, buffer, sizeof buffer,
                                                    &response),
                           ==, EXAMPLE_CARD_OK);
          munit_assert_size(response.length, ==, length);
          munit_assert_memory_equal(length, buffer, expected);
        }
        for (unsigned last = 0x0a; last <= 0x0f; ++last) {
          char object_file[] = "piv-5fc100.bin";
          const char digits[] = "0123456789abcdef";
          object_file[8] = digits[last >> 4];
          object_file[9] = digits[last & 15];
          uint8_t expected[MAX_OBJECT];
          const size_t length = fixture_read(profile, object_file, expected, sizeof expected);
          const uint8_t tag[] = {0x5f, 0xc1, (uint8_t)last};
          munit_assert_int(example_card_object_read(&io, EXAMPLE_CARD_READ_SHORT, tag, sizeof tag,
                                                    buffer, sizeof buffer, &response),
                           ==, EXAMPLE_CARD_OK);
          munit_assert_size(response.length, ==, length);
          munit_assert_memory_equal(length, buffer, expected);
        }
      } else {
        static const uint8_t denied[] = {0x05, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
        for (size_t i = 0; i < sizeof denied; ++i) {
          const uint8_t tag[] = {0x5f, 0xc1, denied[i]};
          munit_assert_int(example_card_object_read(&io, EXAMPLE_CARD_READ_SHORT, tag, sizeof tag,
                                                    buffer, sizeof buffer, &response),
                           ==, EXAMPLE_CARD_STATUS);
          munit_assert_uint(response.status, ==, 0x6982);
          munit_assert_size(response.length, ==, 0);
        }
      }
    }
  }
  char tail[LINE_SIZE];
  munit_assert_null(next_line(file, tail, sizeof tail));
  munit_assert_int(fclose(file), ==, 0);
  munit_assert_int(io.stopped, ==, 0);
  munit_assert_size(replay.exchanges, >, inventory.count + 2);
  return MUNIT_OK;
}

static MunitResult legacy_contact(const MunitParameter params[], void* context)
{
  (void)params;
  (void)context;
  return replay_profile("legacy", "contact");
}
static MunitResult legacy_contactless(const MunitParameter params[], void* context)
{
  (void)params;
  (void)context;
  return replay_profile("legacy", "contactless");
}
static MunitResult nexgen_contact(const MunitParameter params[], void* context)
{
  (void)params;
  (void)context;
  return replay_profile("nexgen", "contact");
}
static MunitResult nexgen_contactless(const MunitParameter params[], void* context)
{
  (void)params;
  (void)context;
  return replay_profile("nexgen", "contactless");
}

static MunitResult required_nonempty(const MunitParameter params[], void* context)
{
  static const uint8_t required[][3] = {{0x5f, 0xc1, 0x02}, {0xdf, 0xc1, 0x03}, {0xdf, 0xc1, 0x0f}};
  char path[512];
  fixture_path(path, sizeof path, "nexgen", "apdu-contact.txt");
  static uint8_t pool[POOL_SIZE];
  for (size_t i = 0; i < sizeof required / sizeof *required; ++i) {
    FILE* file = fopen(path, "rb");
    munit_assert_not_null(file);
    Replay replay = {file, 0, {0}};
    memcpy(replay.empty_tag, required[i], 3);
    ExampleCardIO io = {transmit, &replay, 1000, 0};
    ExampleTWICInventory inventory, preserved;
    memset(&inventory, 0xa5, sizeof inventory);
    preserved = inventory;
    memset(pool, 0xa5, sizeof pool);
    size_t work = sizeof pool;
    munit_assert_int(example_twic_inventory_read(&io, EXAMPLE_CARD_MODEL_TWIC_NEXGEN,
                                                 EXAMPLE_CARD_READ_SHORT, pool, sizeof pool,
                                                 MAX_OBJECT, &work, &inventory),
                     ==, EXAMPLE_CARD_PROTOCOL);
    munit_assert_int(io.stopped, ==, 1);
    munit_assert_memory_equal(sizeof inventory, &inventory, &preserved);
    for (size_t n = 0; n < sizeof pool; ++n)
      munit_assert_uint(pool[n], ==, 0);
    munit_assert_int(fclose(file), ==, 0);
  }
  (void)params;
  (void)context;
  return MUNIT_OK;
}

static MunitResult invalid_legacy_proof(const MunitParameter params[], void* context)
{
  char path[512];
  fixture_path(path, sizeof path, "legacy", "apdu-ga-invalid.txt");
  FILE* file = fopen(path, "rb");
  munit_assert_not_null(file);
  Replay replay = {file, 0, {0}};
  ExampleCardIO io = {transmit, &replay, 8, 0};
  static uint8_t buffer[MAX_OBJECT + EXAMPLE_CARD_STATUS_BYTES];
  ExampleCardResponse selected = {0};
  munit_assert_int(example_card_select(&io, EXAMPLE_CARD_PIV, buffer, sizeof buffer, &selected), ==,
                   EXAMPLE_CARD_OK);
  authenticate(&io, "legacy", 1, buffer, sizeof buffer);
  char tail[LINE_SIZE];
  munit_assert_null(next_line(file, tail, sizeof tail));
  munit_assert_int(fclose(file), ==, 0);
  munit_assert_size(replay.exchanges, ==, 4);
  (void)params;
  (void)context;
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
      {"/legacy-contact", legacy_contact, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/legacy-contactless", legacy_contactless, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/nexgen-contact", nexgen_contact, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/nexgen-contactless", nexgen_contactless, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/required-nonempty", required_nonempty, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/invalid-legacy-proof", invalid_legacy_proof, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/twic-apdu-replay", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
