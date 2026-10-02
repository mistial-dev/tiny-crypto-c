/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Command APDU encoding: ISO/IEC 7816-4:2020 5.2 cases 1, 2S, 3S, 4S, 2E, 3E
 * and 4E, the CLA rules of 5.4.1 and recorded NIST SP 800-73-5 commands. */
#include <tiny_crypto/apdu.h>
#include "cavp.h"
#include "munit.h"
#include "test_util.h"
#include <string.h>

static uint8_t data_bytes[TC_APDU_MAX_NC];

static TC_APDU_command command_of(uint8_t cla, uint8_t ins, size_t nc, uint32_t ne)
{
  TC_APDU_command command = {{data_bytes, nc}, ne, cla, ins, 0x12, 0x34};
  return command;
}

/* Encode and compare with expected hex. */
static void check_encoding(const TC_APDU_command* command, TC_APDU_length_format format,
                           const char* expected_hex)
{
  static uint8_t expected[TC_APDU_EXTENDED_COMMAND_BYTES(TC_APDU_MAX_NC)];
  static uint8_t encoded[TC_APDU_EXTENDED_COMMAND_BYTES(TC_APDU_MAX_NC)];
  size_t expected_length = 0, size = 0, written = 0;
  munit_assert_true(tc_test_hex_decode(expected_hex, TC_TEST_HEX_SEPARATED, expected,
                                       sizeof expected, &expected_length));
  munit_assert_int(TC_APDU_command_size(command, format, &size), ==, TC_APDU_OK);
  munit_assert_size(size, ==, expected_length);
  munit_assert_int(TC_APDU_command_encode(command, format, (TC_buffer){encoded, size}, &written),
                   ==, TC_APDU_OK);
  munit_assert_size(written, ==, expected_length);
  munit_assert_memory_equal(written, encoded, expected);
}

TC_TEST(short_cases)
{
  memset(data_bytes, 0xa5, 3);
  TC_APDU_command command = command_of(0x00, 0xb0, 0, 0);
  check_encoding(&command, TC_APDU_SHORT, "00 b0 12 34");
  command.ne = 1;
  check_encoding(&command, TC_APDU_SHORT, "00 b0 12 34 01");
  command.ne = 255;
  check_encoding(&command, TC_APDU_SHORT, "00 b0 12 34 ff");
  command.ne = 256;
  check_encoding(&command, TC_APDU_SHORT, "00 b0 12 34 00");
  command = command_of(0x0c, 0xd6, 3, 0);
  check_encoding(&command, TC_APDU_SHORT, "0c d6 12 34 03 a5 a5 a5");
  command.ne = 256;
  check_encoding(&command, TC_APDU_SHORT, "0c d6 12 34 03 a5 a5 a5 00");
  return MUNIT_OK;
}

TC_TEST(extended_cases)
{
  static char hex[2 * TC_APDU_EXTENDED_COMMAND_BYTES(300) + 1];
  memset(data_bytes, 0x5a, 300);
  /* Short-encodable commands keep the short form in EXTENDED. */
  TC_APDU_command command = command_of(0x00, 0xb0, 3, 256);
  check_encoding(&command, TC_APDU_EXTENDED, "00 b0 12 34 03 5a 5a 5a 00");
  command = command_of(0x00, 0xb0, 0, 257);
  check_encoding(&command, TC_APDU_EXTENDED, "00 b0 12 34 00 01 01");
  command.ne = 65535;
  check_encoding(&command, TC_APDU_EXTENDED, "00 b0 12 34 00 ff ff");
  command.ne = 65536;
  check_encoding(&command, TC_APDU_EXTENDED, "00 b0 12 34 00 00 00");
  /* Case 3E and 4E with Nc 256: 2-byte Le after the extended Lc. */
  command = command_of(0x00, 0xd6, 256, 0);
  size_t used = (size_t)snprintf(hex, sizeof hex, "00d61234000100");
  for (size_t i = 0; i < 256; ++i)
    used += (size_t)snprintf(hex + used, sizeof hex - used, "5a");
  check_encoding(&command, TC_APDU_EXTENDED, hex);
  command.ne = 1;
  snprintf(hex + used, sizeof hex - used, "0001");
  check_encoding(&command, TC_APDU_EXTENDED, hex);
  command.ne = 65536;
  snprintf(hex + used, sizeof hex - used, "0000");
  check_encoding(&command, TC_APDU_EXTENDED, hex);
  /* Nc 255 with Ne 257 needs the extended form for both fields. */
  command = command_of(0x00, 0xd6, 255, 257);
  size_t size = 0;
  munit_assert_int(TC_APDU_command_size(&command, TC_APDU_EXTENDED, &size), ==, TC_APDU_OK);
  munit_assert_size(size, ==, 4 + 3 + 255 + 2);
  command = command_of(0x00, 0xd6, TC_APDU_MAX_NC, TC_APDU_MAX_NE);
  munit_assert_int(TC_APDU_command_size(&command, TC_APDU_EXTENDED, &size), ==, TC_APDU_OK);
  munit_assert_size(size, ==, TC_APDU_EXTENDED_COMMAND_BYTES(TC_APDU_MAX_NC));
  return MUNIT_OK;
}

/* Recorded NIST SD 33 card 2 commands (SP 800-73-5 Part 2 3.1.1, 3.1.2,
 * 3.2.1, 3.2.4). The GENERAL AUTHENTICATE is exchange 57 of the
 * nist_sd_33_vectors_v2 card 2 capture: plain, extended Lc 010A, Le 0100. */
TC_TEST(recorded_commands)
{
  static const uint8_t aid[] = {0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0, 1, 0};
  static const uint8_t discovery[] = {0x5c, 1, 0x7e};
  static const uint8_t chuid[] = {0x5c, 3, 0x5f, 0xc1, 2};
  static const char authenticate[] =
      "0087079E00010A7C82010681820100B35D278F8541DDF720ECAE09FB9CAEBC91FB1043D9026C86E286CD03C3"
      "A43B18D96D86FA6C80C2C1A321D428FD6486F3F27EA84C14E6E92F9F6850909695812E134323A22362F74C71"
      "12CF93099D09F874AF7CC65DC512B5934A1FF31A4B0328D7AFB6C0A55321C71A2C817E8300F87342DB931D31"
      "3930AD0E8BF82CEDA215F5F3DC6CD31AB7A628AF6E68058290D87F48075409380DE7E1AB748D2FF535342B1D"
      "26CBAD6D3BF96B1B30336C1284453D952034C5E397BEF540A9F59DA9AFAE8B3A0EE2C18EF423B4403806AA4B"
      "A522467501D585004FEC5E080137D7AC3C1746CBAA0DEC9DDB7A2FF3BB71A1E3FC2BD90D0A2147982D80E6C2"
      "EE8F5A409619FE82000100";
  static uint8_t template_bytes[266];
  TC_APDU_command select = {{aid, sizeof aid}, 256, 0x00, 0xa4, 0x04, 0x00};
  check_encoding(&select, TC_APDU_SHORT, "00A404000BA00000030800001000010000");
  TC_APDU_command get_data = {{discovery, sizeof discovery}, 256, 0x00, 0xcb, 0x3f, 0xff};
  check_encoding(&get_data, TC_APDU_SHORT, "00CB3FFF035C017E00");
  get_data.data = (TC_bytes){chuid, sizeof chuid};
  check_encoding(&get_data, TC_APDU_EXTENDED, "00CB3FFF055C035FC10200");
  TC_APDU_command verify = {{NULL, 0}, 0, 0x00, 0x20, 0x00, 0x80};
  check_encoding(&verify, TC_APDU_SHORT, "00200080");
  /* Data field of the recorded command: after the 7-byte header and Lc. */
  uint8_t whole[275];
  size_t length = tc_test_hex(authenticate, whole, sizeof whole);
  munit_assert_size(length, ==, sizeof whole);
  memcpy(template_bytes, whole + 7, sizeof template_bytes);
  TC_APDU_command general = {{template_bytes, sizeof template_bytes}, 256, 0x00, 0x87, 0x07, 0x9e};
  check_encoding(&general, TC_APDU_EXTENDED, authenticate);
  return MUNIT_OK;
}

TC_TEST(argument_errors)
{
  uint8_t out[16];
  size_t size = 77, written = 77;
  TC_APDU_command command = command_of(0x00, 0xb0, 0, 0);
  memset(out, 0xee, sizeof out);
  munit_assert_int(TC_APDU_command_size(NULL, TC_APDU_SHORT, &size), ==, TC_APDU_ARGUMENT);
  munit_assert_int(TC_APDU_command_size(&command, TC_APDU_SHORT, NULL), ==, TC_APDU_ARGUMENT);
  munit_assert_int(TC_APDU_command_size(&command, (TC_APDU_length_format)2, &size), ==,
                   TC_APDU_ARGUMENT);
  command.data = (TC_bytes){NULL, 1};
  munit_assert_int(TC_APDU_command_size(&command, TC_APDU_SHORT, &size), ==, TC_APDU_ARGUMENT);
  /* SHORT bounds: Nc 256 and Ne 257. */
  command = command_of(0x00, 0xb0, 256, 0);
  munit_assert_int(TC_APDU_command_size(&command, TC_APDU_SHORT, &size), ==, TC_APDU_ARGUMENT);
  command = command_of(0x00, 0xb0, 0, 257);
  munit_assert_int(TC_APDU_command_size(&command, TC_APDU_SHORT, &size), ==, TC_APDU_ARGUMENT);
  /* Every format: Ne 65537. */
  command.ne = TC_APDU_MAX_NE + 1;
  munit_assert_int(TC_APDU_command_size(&command, TC_APDU_EXTENDED, &size), ==, TC_APDU_ARGUMENT);
  /* The channel owns CLA b5. */
  command = command_of(0x10, 0xb0, 0, 0);
  munit_assert_int(TC_APDU_command_size(&command, TC_APDU_SHORT, &size), ==, TC_APDU_ARGUMENT);
  munit_assert_int(
      TC_APDU_command_encode(&command, TC_APDU_SHORT, (TC_buffer){out, sizeof out}, &written), ==,
      TC_APDU_ARGUMENT);
  command = command_of(0x00, 0xb0, 0, 0);
  munit_assert_int(TC_APDU_command_encode(&command, TC_APDU_SHORT, (TC_buffer){NULL, 4}, &written),
                   ==, TC_APDU_ARGUMENT);
  munit_assert_int(
      TC_APDU_command_encode(&command, TC_APDU_SHORT, (TC_buffer){out, sizeof out}, NULL), ==,
      TC_APDU_ARGUMENT);
  /* The output overlaps the command data. */
  memset(out, 0, sizeof out);
  command.data = (TC_bytes){out + 4, 4};
  munit_assert_int(
      TC_APDU_command_encode(&command, TC_APDU_SHORT, (TC_buffer){out, sizeof out}, &written), ==,
      TC_APDU_ARGUMENT);
  munit_assert_size(size, ==, 77);
  munit_assert_size(written, ==, 77);
  munit_assert_true(tc_test_all_zero(out, sizeof out));
  return MUNIT_OK;
}

/* ISO/IEC 7816-4 5.4.1: 001x xxxx is RFU, 01xx xxxx the further interindustry
 * values and b8 the proprietary class. */
TC_TEST(class_bytes)
{
  static const uint8_t unsupported[] = {0x20, 0x3f, 0x40, 0x7f, 0x80, 0x90, 0xa0, 0xff};
  static const uint8_t accepted[] = {0x00, 0x01, 0x03, 0x04, 0x08, 0x0c, 0x0f};
  size_t size = 0;
  for (size_t i = 0; i < sizeof unsupported; ++i) {
    TC_APDU_command command = command_of(unsupported[i], 0xb0, 0, 0);
    munit_assert_int(TC_APDU_command_size(&command, TC_APDU_SHORT, &size), ==, TC_APDU_UNSUPPORTED);
  }
  for (size_t i = 0; i < sizeof accepted; ++i) {
    TC_APDU_command command = command_of(accepted[i], 0xb0, 0, 0);
    munit_assert_int(TC_APDU_command_size(&command, TC_APDU_SHORT, &size), ==, TC_APDU_OK);
  }
  return MUNIT_OK;
}

TC_TEST(short_output)
{
  uint8_t out[9];
  size_t written = 55;
  memset(data_bytes, 0x11, 3);
  TC_APDU_command command = command_of(0x00, 0xd6, 3, 256);
  memset(out, 0xcc, sizeof out);
  munit_assert_int(TC_APDU_command_encode(&command, TC_APDU_SHORT, (TC_buffer){out, 8}, &written),
                   ==, TC_APDU_LIMIT);
  munit_assert_size(written, ==, 55);
  munit_assert_true(tc_test_all_value(out, sizeof out, 0xcc));
  munit_assert_int(TC_APDU_command_encode(&command, TC_APDU_SHORT, (TC_buffer){out, 9}, &written),
                   ==, TC_APDU_OK);
  munit_assert_size(written, ==, 9);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  static MunitTest tests[] = {
      {"/short-cases", short_cases, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/extended-cases", extended_cases, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/recorded-commands", recorded_commands, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/argument-errors", argument_errors, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/class-bytes", class_bytes, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/short-output", short_output, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  static const MunitSuite suite = {"/apdu/encode", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
