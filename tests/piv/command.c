/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* PIV card commands: SELECT and the application property template (SP
 * 800-73-5 Part 2 3.1.1, TWIC Part 2 v5 5.1), GET DATA framing (Part 2 3.1.2,
 * TWIC Part 2 v5 3.3.6 and 5.2), VERIFY (Part 2 3.2.1), status meanings (Part
 * 1 Table 7) and the dynamic authentication template (Part 2 Table 7).
 * Recorded bytes come from NIST SD 33 card 2 (nist_sd_33_vectors_v2,
 * exchanges 0 and 1). */
#include <tiny_crypto/piv_command.h>
#include "cavp.h"
#include "munit.h"
#include "piv_link_internal.h"
#include "piv_template_internal.h"
#include "scripted_transport.h"
#include "test_util.h"
#include <string.h>

#define STEP(command, response) {command, response, {0}, {0}, TC_OK, 0}
#define FAILED_STEP(command) {command, NULL, {0}, {0}, TC_ERROR, 0}

/* SD 33 card 2: SELECT with the complete PIV AID, and its answer. */
#define PIV_SELECT "00A404000BA00000030800001000010000"
#define PIV_APT                                                                                    \
  "612A4F0BA00000030800001000010079074F05A000000308500A49442D4F6E6520504956AC0680012E06010"        \
  "07F6608020203F802027FFF"
#define TWIC_SELECT                                                                                \
  "00A4040009A00000036720000001"                                                                   \
  "00"
/* Synthetic TWIC answers: 61 {4F AID 01 xx, 79 {4F RID}} 7F66 {02 0400, 02 0800}. */
#define TWIC_APT(subversion)                                                                       \
  "61144F0BA00000036720000001"                                                                     \
  "010" subversion "79054F03A00000"                                                                \
  "7F660802020400020208"                                                                           \
  "00"

enum { RESPONSE_BYTES = 600 };

static tc_script script;
static uint8_t scratch[TC_APDU_SHORT_COMMAND_MAX_BYTES];
static uint8_t response_bytes[RESPONSE_BYTES];

static TC_buffer response_buffer(size_t capacity)
{
  return (TC_buffer){response_bytes, capacity};
}

static void link_start_options(TC_PIV_link* link, const tc_script_step* steps, size_t count,
                               const TC_PIV_link_options* options)
{
  tc_script_init(&script, steps, count);
  script.scratch = scratch;
  script.scratch_length = sizeof scratch;
  memset(scratch, 0, sizeof scratch);
  memset(response_bytes, 0xee, sizeof response_bytes);
  munit_assert_int(TC_PIV_link_init(link, tc_script_transport(&script), options,
                                    (TC_buffer){scratch, sizeof scratch}),
                   ==, TC_PIV_OK);
}

static void link_start(TC_PIV_link* link, const tc_script_step* steps, size_t count,
                       TC_PIV_interface interface)
{
  const TC_PIV_link_options options = {{TC_APDU_SHORT, 0, 32, 0, 0}, interface, 0};
  link_start_options(link, steps, count, &options);
}

static void select_application(TC_PIV_link* link, TC_PIV_application_id application)
{
  TC_PIV_application out;
  munit_assert_int(TC_PIV_select(link, application, 0, response_buffer(RESPONSE_BYTES), &out), ==,
                   TC_PIV_OK);
}

static void assert_script_done(void)
{
  munit_assert_size(script.mismatch, ==, 0);
  munit_assert_size(script.next, ==, script.count);
  munit_assert_false(script.scratch_dirty);
  munit_assert_true(tc_test_all_zero(scratch, sizeof scratch));
}

static size_t hex(const char* text, uint8_t* output, size_t capacity)
{
  size_t length = 0;
  munit_assert_true(tc_test_hex_decode(text, TC_TEST_HEX_SEPARATED, output, capacity, &length));
  return length;
}

static TC_bytes span(const uint8_t* data, size_t length)
{
  return (TC_bytes){data, length};
}

/* The recorded card 2 template: suite 2E, AC 80 2E 06 01 00, and the 7F66
 * limits 1016 and 32767 installed in the channel (ISO/IEC 7816-4 12.8.1). */
TC_TEST(select_recorded)
{
  const tc_script_step steps[] = {STEP(PIV_SELECT, PIV_APT "9000")};
  TC_PIV_link link;
  link_start(&link, steps, 1, TC_PIV_CONTACT);
  TC_PIV_link_info info;
  TC_PIV_link_info_get(&link, &info);
  munit_assert_int(info.application, ==, TC_PIV_APPLICATION_NONE);
  munit_assert_uint16(TC_PIV_link_status(&link), ==, 0);
  TC_PIV_application out;
  munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 0, response_buffer(100), &out), ==,
                   TC_PIV_OK);
  uint8_t aid[11], algorithms[6];
  hex("A0000003080000100001 00", aid, sizeof aid);
  hex("80012E060100", algorithms, sizeof algorithms);
  munit_assert_ptr_equal(out.aid.data, response_bytes + 4);
  munit_assert_size(out.aid.length, ==, 11);
  munit_assert_memory_equal(11, out.aid.data, aid);
  munit_assert_size(out.label.length, ==, 10);
  munit_assert_memory_equal(10, out.label.data, "ID-One PIV");
  munit_assert_size(out.url.length, ==, 0);
  munit_assert_size(out.algorithms.length, ==, sizeof algorithms);
  munit_assert_memory_equal(sizeof algorithms, out.algorithms.data, algorithms);
  munit_assert_size(out.max_command_bytes, ==, 1016);
  munit_assert_size(out.max_response_bytes, ==, 32767);
  munit_assert_int(out.profile, ==, TC_PIV_CARD);
  munit_assert_uint8(out.version[0], ==, 1);
  munit_assert_uint8(out.version[1], ==, 0);
  munit_assert_uint8(out.sm_suite, ==, 0x2e);
  TC_PIV_link_info_get(&link, &info);
  munit_assert_int(info.interface, ==, TC_PIV_CONTACT);
  munit_assert_int(info.application, ==, TC_PIV_APPLICATION_PIV);
  munit_assert_int(info.profile, ==, TC_PIV_CARD);
  munit_assert_uint8(info.sm_suite, ==, 0x2e);
  munit_assert_uint8(info.secured, ==, 0);
  munit_assert_uint8(info.vci, ==, 0);
  munit_assert_uint8(info.pin_verified, ==, 0);
  munit_assert_uint16(TC_PIV_link_status(&link), ==, 0x9000);
  munit_assert_size(link.channel.max_command_bytes, ==, 1016);
  munit_assert_size(link.channel.max_response_bytes, ==, 32767);
  munit_assert_uint(link.channel.flags, ==, TC_APDU_GET_RESPONSE_PLAIN_CLA);
  /* The trailing status bytes are wiped. */
  munit_assert_true(tc_test_all_zero(response_bytes + 0x2c + 11, 2));
  assert_script_done();
  TC_PIV_link_clear(&link);
  munit_assert_true(tc_test_all_zero(&link, sizeof link));
  TC_PIV_link_clear(NULL);
  return MUNIT_OK;
}

static TC_TLV_result read_hex(const char* text, TC_PIV_application_id expected, unsigned flags,
                              TC_PIV_application* out)
{
  static uint8_t encoded[256];
  const size_t length = hex(text, encoded, sizeof encoded);
  return TC_PIV_application_read(span(encoded, length), expected, flags, out);
}

static void assert_read(const char* text, TC_PIV_application_id expected, TC_TLV_result result)
{
  TC_PIV_application out, preserved;
  memset(&out, 0xa5, sizeof out);
  preserved = out;
  munit_assert_int(read_hex(text, expected, 0, &out), ==, result);
  if (result != TC_TLV_OK)
    munit_assert_memory_equal(sizeof out, &out, &preserved);
}

/* Table 3, 4 and 5 structure. */
TC_TEST(application_rules)
{
  assert_read(PIV_APT, TC_PIV_APPLICATION_PIV, TC_TLV_OK);
  assert_read(PIV_APT, TC_PIV_APPLICATION_TWIC, TC_TLV_INVALID);
  /* Without 7F66 and without AC. */
  assert_read("61154F0BA000000308000010000100 79064F04A0000003", TC_PIV_APPLICATION_PIV, TC_TLV_OK);
  /* A proprietary top-level DO and an unknown DO inside 61 are skipped. */
  assert_read("61194F0BA000000308000010000100 79064F04A0000003 C0020102 C10100",
              TC_PIV_APPLICATION_PIV, TC_TLV_OK);
  /* AC: 06 with value 00 (Table 5), each 80 one byte, one suite at most. */
  assert_read("611D4F0BA000000308000010000100 79064F04A0000003 AC0680012E060101",
              TC_PIV_APPLICATION_PIV, TC_TLV_INVALID);
  assert_read("611C4F0BA000000308000010000100 79064F04A0000003 AC0580012E0600",
              TC_PIV_APPLICATION_PIV, TC_TLV_INVALID);
  assert_read("61204F0BA000000308000010000100 79064F04A0000003 AC0980012E060100060100",
              TC_PIV_APPLICATION_PIV, TC_TLV_INVALID);
  assert_read("611A4F0BA000000308000010000100 79064F04A0000003 AC0380012E", TC_PIV_APPLICATION_PIV,
              TC_TLV_INVALID);
  assert_read("611A4F0BA000000308000010000100 79064F04A0000003 AC03060100", TC_PIV_APPLICATION_PIV,
              TC_TLV_INVALID);
  assert_read("611E4F0BA000000308000010000100 79064F04A0000003 AC078002112E060100",
              TC_PIV_APPLICATION_PIV, TC_TLV_INVALID);
  assert_read("61204F0BA000000308000010000100 79064F04A0000003 AC0980012780012E060100",
              TC_PIV_APPLICATION_PIV, TC_TLV_INVALID);
  TC_PIV_application out;
  munit_assert_int(read_hex("61204F0BA000000308000010000100 79064F04A0000003 "
                            "AC098001118001140601 00",
                            TC_PIV_APPLICATION_PIV, 0, &out),
                   ==, TC_TLV_OK);
  munit_assert_uint8(out.sm_suite, ==, 0);
  munit_assert_int(read_hex("61234F0BA000000308000010000100 79064F04A0000003 "
                            "AC0C800111800127060100C10100",
                            TC_PIV_APPLICATION_PIV, 0, &out),
                   ==, TC_TLV_OK);
  munit_assert_uint8(out.sm_suite, ==, 0x27);
  /* 4F and 79 are mandatory and single. */
  assert_read("61084F06A00000030800 ", TC_PIV_APPLICATION_PIV, TC_TLV_INVALID);
  assert_read("610D4F0BA000000308000010000100", TC_PIV_APPLICATION_PIV, TC_TLV_INVALID);
  assert_read("61114F0BA000000308000010000100 79024F00", TC_PIV_APPLICATION_PIV, TC_TLV_INVALID);
  assert_read("61114F0BA000000308000010000100 79020000", TC_PIV_APPLICATION_PIV, TC_TLV_INVALID);
  assert_read("61134F0BA000000308000010000100 7904C0020102", TC_PIV_APPLICATION_PIV,
              TC_TLV_INVALID);
  assert_read("61224F0BA000000308000010000100 4F0BA000000308000010000100 79064F04A0000003",
              TC_PIV_APPLICATION_PIV, TC_TLV_INVALID);
  assert_read("611D4F0BA000000308000010000100 79064F04A0000003 79064F04A0000003",
              TC_PIV_APPLICATION_PIV, TC_TLV_INVALID);
  assert_read("61194F0BA000000308000010000100 79064F04A0000003 50020102", TC_PIV_APPLICATION_PIV,
              TC_TLV_OK);
  assert_read("611D4F0BA000000308000010000100 79064F04A0000003 5002010250020102",
              TC_PIV_APPLICATION_PIV, TC_TLV_INVALID);
  assert_read("61214F0BA000000308000010000100 79064F04A0000003 5F5003010203 5F5003010203",
              TC_PIV_APPLICATION_PIV, TC_TLV_INVALID);
  /* A foreign or shortened AID. */
  assert_read("61154F0BA000000308000010010100 79064F04A0000003", TC_PIV_APPLICATION_PIV,
              TC_TLV_INVALID);
  assert_read("61144F0AA0000003080000100001 79064F04A0000003", TC_PIV_APPLICATION_PIV,
              TC_TLV_INVALID);
  /* One 61 template, first at top level. */
  assert_read("61154F0BA000000308000010000100 79064F04A0000003 "
              "61154F0BA000000308000010000100 79064F04A0000003",
              TC_PIV_APPLICATION_PIV, TC_TLV_INVALID);
  assert_read("C00100 61154F0BA000000308000010000100 79064F04A0000003", TC_PIV_APPLICATION_PIV,
              TC_TLV_INVALID);
  assert_read("", TC_PIV_APPLICATION_PIV, TC_TLV_INVALID);
  /* 7F66: two positive 02 integers of at least 4 and 3 (12.8.1). */
  static const char* const limits[] = {"7F6606020104020103",      "7F66070202040002 0100",
                                       "7F660402020400",          "7F660C020204000202040002020400",
                                       "7F6608810201008202 0100", "7F66070201030202 0400",
                                       "7F660702020400 020102",   "7F6608020280000202 0400",
                                       "7F6606020104020103"};
  static const TC_TLV_result expected[] = {TC_TLV_OK,      TC_TLV_INVALID, TC_TLV_INVALID,
                                           TC_TLV_INVALID, TC_TLV_INVALID, TC_TLV_INVALID,
                                           TC_TLV_INVALID, TC_TLV_INVALID, TC_TLV_OK};
  for (size_t i = 0; i < sizeof limits / sizeof *limits; ++i) {
    char text[200] = "61154F0BA000000308000010000100 79064F04A0000003 ";
    strcat(text, limits[i]);
    if (i == 8)
      strcat(text, limits[i]);
    assert_read(text, TC_PIV_APPLICATION_PIV, i == 8 ? TC_TLV_INVALID : expected[i]);
  }
  /* A leading zero keeps a large limit positive. Leading zeros beyond that
   * are non-minimal. */
  munit_assert_int(
      read_hex("61154F0BA000000308000010000100 79064F04A0000003 7F660902020400020300FFFF",
               TC_PIV_APPLICATION_PIV, 0, &out),
      ==, TC_TLV_OK);
  munit_assert_size(out.max_command_bytes, ==, 0x400);
  munit_assert_size(out.max_response_bytes, ==, 0xffff);
  assert_read("61154F0BA000000308000010000100 79064F04A0000003 7F660902030004000202 0400",
              TC_PIV_APPLICATION_PIV, TC_TLV_INVALID);
  munit_assert_int(read_hex("61154F0BA000000308000010000100 79064F04A0000003 "
                            "7F66100202040002 0A01000000000000000000",
                            TC_PIV_APPLICATION_PIV, 0, &out),
                   ==, TC_TLV_OK);
  munit_assert_size(out.max_response_bytes, ==, SIZE_MAX);
  /* Every truncation of the recorded template is rejected. */
  uint8_t encoded[128];
  const size_t length = hex(PIV_APT, encoded, sizeof encoded);
  for (size_t n = 0; n < length; ++n) {
    memset(&out, 0x5a, sizeof out);
    const TC_TLV_result result =
        TC_PIV_application_read(span(encoded, n), TC_PIV_APPLICATION_PIV, 0, &out);
    /* Cutting exactly before 7F66 leaves a complete template. */
    munit_assert_int(result, ==, n == 0x2c ? TC_TLV_OK : TC_TLV_INVALID);
  }
  /* Versions other than 01 00 are unsupported. */
  assert_read("61154F0BA000000308000010000101 79064F04A0000003", TC_PIV_APPLICATION_PIV,
              TC_TLV_UNSUPPORTED);
  assert_read("61154F0BA000000308000010000200 79064F04A0000003", TC_PIV_APPLICATION_PIV,
              TC_TLV_UNSUPPORTED);
  /* Framing limits: depth 4 and 64 elements. */
  assert_read("611D4F0BA000000308000010000100 79064F04A0000003 E206E304E402E500",
              TC_PIV_APPLICATION_PIV, TC_TLV_LIMIT);
  /* Arguments. */
  munit_assert_int(TC_PIV_application_read(span(encoded, length), TC_PIV_APPLICATION_NONE, 0, &out),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_application_read(span(encoded, length), TC_PIV_APPLICATION_PIV, 2, &out),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_application_read(span(encoded, length), TC_PIV_APPLICATION_PIV, 0, NULL),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_application_read(span(NULL, 3), TC_PIV_APPLICATION_PIV, 0, &out), ==,
                   TC_TLV_ARGUMENT);
  TC_PIV_application* inside = (TC_PIV_application*)(void*)response_bytes;
  memcpy(response_bytes, encoded, length);
  munit_assert_int(
      TC_PIV_application_read(span(response_bytes, length), TC_PIV_APPLICATION_PIV, 0, inside), ==,
      TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

/* TWIC Part 2 v5 4.1: version 01 with sub-version 01 (Legacy) or 03
 * (NEXGEN). Other sub-versions need the explicit compatibility flag (TWIC
 * Part 3 v4 D.3). */
TC_TEST(application_twic)
{
  TC_PIV_application out;
  munit_assert_int(read_hex(TWIC_APT("1"), TC_PIV_APPLICATION_TWIC, 0, &out), ==, TC_TLV_OK);
  munit_assert_int(out.profile, ==, TC_TWIC_LEGACY_CARD);
  munit_assert_size(out.max_command_bytes, ==, 0x400);
  munit_assert_size(out.max_response_bytes, ==, 0x800);
  munit_assert_size(out.algorithms.length, ==, 0);
  munit_assert_uint8(out.sm_suite, ==, 0);
  munit_assert_int(read_hex(TWIC_APT("3"), TC_PIV_APPLICATION_TWIC, 0, &out), ==, TC_TLV_OK);
  munit_assert_int(out.profile, ==, TC_TWIC_NEXGEN_CARD);
  munit_assert_int(read_hex(TWIC_APT("3"), TC_PIV_APPLICATION_PIV, 0, &out), ==, TC_TLV_INVALID);
  assert_read(TWIC_APT("2"), TC_PIV_APPLICATION_TWIC, TC_TLV_UNSUPPORTED);
  assert_read(TWIC_APT("4"), TC_PIV_APPLICATION_TWIC, TC_TLV_UNSUPPORTED);
  munit_assert_int(read_hex(TWIC_APT("4"), TC_PIV_APPLICATION_TWIC,
                            TC_PIV_SELECT_TWIC_SUBVERSION_COMPATIBLE, &out),
                   ==, TC_TLV_OK);
  munit_assert_int(out.profile, ==, TC_TWIC_LEGACY_CARD);
  munit_assert_uint8(out.version[1], ==, 4);
  /* Version 02 and the test bit stay unsupported with the flag. */
  static const char* const versions[] = {
      "61144F0BA00000036720000001020179054F03A000007F66080202040002020800",
      "61144F0BA00000036720000001810179054F03A000007F66080202040002020800"};
  for (size_t i = 0; i < 2; ++i) {
    memset(&out, 0x5a, sizeof out);
    munit_assert_int(read_hex(versions[i], TC_PIV_APPLICATION_TWIC,
                              TC_PIV_SELECT_TWIC_SUBVERSION_COMPATIBLE, &out),
                     ==, TC_TLV_UNSUPPORTED);
  }
  return MUNIT_OK;
}

/* TWIC SELECT uses the 9-byte partial AID with Le 00 and installs the TWIC
 * GET RESPONSE flags (TWIC Part 2 v5 5.1, 5.2 note 3a). */
TC_TEST(select_twic)
{
  const tc_script_step steps[] = {STEP(TWIC_SELECT, TWIC_APT("3") "9000")};
  TC_PIV_link link;
  link_start(&link, steps, 1, TC_PIV_CONTACTLESS);
  TC_PIV_application out;
  munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_TWIC, 0, response_buffer(64), &out), ==,
                   TC_PIV_OK);
  munit_assert_int(out.profile, ==, TC_TWIC_NEXGEN_CARD);
  TC_PIV_link_info info;
  TC_PIV_link_info_get(&link, &info);
  munit_assert_int(info.application, ==, TC_PIV_APPLICATION_TWIC);
  munit_assert_int(info.profile, ==, TC_TWIC_NEXGEN_CARD);
  munit_assert_int(info.interface, ==, TC_PIV_CONTACTLESS);
  munit_assert_uint(link.channel.flags, ==,
                    TC_APDU_GET_RESPONSE_PLAIN_CLA | TC_APDU_GET_RESPONSE_LE_FF);
  munit_assert_size(link.channel.max_command_bytes, ==, 0x400);
  munit_assert_size(link.channel.max_response_bytes, ==, 0x800);
  assert_script_done();
  return MUNIT_OK;
}

/* A failed SELECT leaves no application selected and wipes the response. */
TC_TEST(select_failures)
{
  const tc_script_step steps[] = {
      STEP(PIV_SELECT, PIV_APT "9000"),
      STEP(TWIC_SELECT, "6A82"),
      STEP(PIV_SELECT, PIV_APT "9000"),
      STEP(PIV_SELECT, "61154F0BA000000308000010000200 79064F04A0000003 9000"),
      STEP(PIV_SELECT, "6112"),
      FAILED_STEP(PIV_SELECT)};
  TC_PIV_link link;
  link_start(&link, steps, 6, TC_PIV_CONTACT);
  TC_PIV_application out, preserved;
  memset(&out, 0x5a, sizeof out);
  preserved = out;
  TC_PIV_link_info info;
  select_application(&link, TC_PIV_APPLICATION_PIV);
  link.flags |= TC_PIV_LINK_PIN_VERIFIED;
  memset(response_bytes, 0xee, sizeof response_bytes);
  munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_TWIC, 0, response_buffer(64), &out), ==,
                   TC_PIV_CARD_STATUS);
  munit_assert_uint16(TC_PIV_link_status(&link), ==, 0x6a82);
  munit_assert_int(
      TC_PIV_status_classify(0x6a82, TC_PIV_COMMAND_SELECT, TC_PIV_APPLICATION_TWIC, NULL), ==,
      TC_PIV_SW_NOT_FOUND);
  munit_assert_memory_equal(sizeof out, &out, &preserved);
  munit_assert_true(tc_test_all_zero(response_bytes, 64));
  TC_PIV_link_info_get(&link, &info);
  munit_assert_int(info.application, ==, TC_PIV_APPLICATION_NONE);
  munit_assert_uint8(info.pin_verified, ==, 0);
  /* A good SELECT, then one with an unsupported version. */
  select_application(&link, TC_PIV_APPLICATION_PIV);
  munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 0, response_buffer(64), &out), ==,
                   TC_PIV_UNSUPPORTED);
  munit_assert_uint16(TC_PIV_link_status(&link), ==, 0);
  munit_assert_true(tc_test_all_zero(response_bytes, 64));
  TC_PIV_link_info_get(&link, &info);
  munit_assert_int(info.application, ==, TC_PIV_APPLICATION_NONE);
  /* A 61XX that needs more room than offered is LIMIT. */
  munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 0, response_buffer(8), &out), ==,
                   TC_PIV_LIMIT);
  munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 0, response_buffer(64), &out), ==,
                   TC_PIV_ERROR);
  munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 0, response_buffer(64), &out), ==,
                   TC_PIV_ERROR);
  munit_assert_memory_equal(sizeof out, &out, &preserved);
  assert_script_done();
  return MUNIT_OK;
}

TC_TEST(select_arguments)
{
  TC_PIV_link link;
  link_start(&link, NULL, 0, TC_PIV_CONTACT);
  TC_PIV_application out, preserved;
  memset(&out, 0x5a, sizeof out);
  preserved = out;
  munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_NONE, 0, response_buffer(64), &out), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 2, response_buffer(64), &out), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 0, response_buffer(1), &out), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 0, (TC_buffer){NULL, 64}, &out), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 0, response_buffer(64), NULL), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_select(NULL, TC_PIV_APPLICATION_PIV, 0, response_buffer(64), &out), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 0,
                                 (TC_buffer){(uint8_t*)&out, sizeof out}, &out),
                   ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 0,
                                 (TC_buffer){(uint8_t*)&link, sizeof link}, &preserved),
                   ==, TC_PIV_ARGUMENT);
  munit_assert_memory_equal(sizeof out, &out, &preserved);
  TC_PIV_link_clear(&link);
  munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 0, response_buffer(64), &out), ==,
                   TC_PIV_ARGUMENT);
  assert_script_done();
  return MUNIT_OK;
}

static TC_PIV_result get_data_hex(TC_PIV_link* link, const char* tag_hex, size_t capacity,
                                  TC_PIV_data_object* out)
{
  static uint8_t tag[4];
  const size_t length = hex(tag_hex, tag, sizeof tag);
  return TC_PIV_get_data(link, span(tag, length), response_buffer(capacity), out);
}

/* PIV application answers (Part 2 3.1.2, Part 1 4.1.1). */
TC_TEST(get_data_piv)
{
  const tc_script_step steps[] = {
      STEP(PIV_SELECT, PIV_APT "9000"),
      STEP("00CB3FFF035C017E00", "7E124F0BA0000003080000100001005F2F0248009000"),
      STEP("00CB3FFF055C035FC10200", "5303010203 9000"),
      STEP("00CB3FFF055C035FC10500", "5300 9000"),
      STEP("00CB3FFF045C027F6100", "7F6103020100 9000"),
      STEP("00CB3FFF055C035FC10200", "53010762 82"),
      STEP("00CB3FFF055C035FC10200", "9000"),
      STEP("00CB3FFF035C017E00", "7E00 9000"),
      STEP("00CB3FFF035C017E00", "5302AABB 9000"),
      STEP("00CB3FFF055C035FC10200", "5302AABB00 9000"),
      STEP("00CB3FFF055C035FC10200", "5302AA 9000"),
      STEP("00CB3FFF055C035FC10200", "5402AABB 9000"),
      STEP("00CB3FFF055C035FC10200", "53020762 82"),
      STEP("00CB3FFF055C035FC10200", "6282"),
      STEP("00CB3FFF055C035FC10200", "6A82"),
      STEP("00CB3FFF055C035FC10200", "6982"),
      STEP("00CB3FFF055C035FC10200", "6A88")};
  TC_PIV_link link;
  link_start(&link, steps, sizeof steps / sizeof *steps, TC_PIV_CONTACT);
  select_application(&link, TC_PIV_APPLICATION_PIV);
  TC_PIV_data_object out;
  munit_assert_int(get_data_hex(&link, "7E", 64, &out), ==, TC_PIV_OK);
  munit_assert_int(out.form, ==, TC_PIV_FORM_TEMPLATE);
  munit_assert_ptr_equal(out.encoded.data, response_bytes);
  munit_assert_size(out.encoded.length, ==, 0x14);
  munit_assert_ptr_equal(out.value.data, response_bytes + 2);
  munit_assert_size(out.value.length, ==, 0x12);
  munit_assert_uint16(out.status, ==, 0x9000);
  munit_assert_true(tc_test_all_zero(response_bytes + 0x14, 2));
  munit_assert_int(get_data_hex(&link, "5FC102", 64, &out), ==, TC_PIV_OK);
  munit_assert_int(out.form, ==, TC_PIV_FORM_CONTAINER);
  munit_assert_size(out.value.length, ==, 3);
  munit_assert_uint8(out.value.data[2], ==, 3);
  munit_assert_int(get_data_hex(&link, "5FC105", 64, &out), ==, TC_PIV_OK);
  munit_assert_int(out.form, ==, TC_PIV_FORM_CONTAINER);
  munit_assert_size(out.encoded.length, ==, 2);
  munit_assert_size(out.value.length, ==, 0);
  munit_assert_int(get_data_hex(&link, "7F61", 64, &out), ==, TC_PIV_OK);
  munit_assert_int(out.form, ==, TC_PIV_FORM_TEMPLATE);
  munit_assert_size(out.value.length, ==, 3);
  /* 6282 with exact framing. */
  munit_assert_int(get_data_hex(&link, "5FC102", 64, &out), ==, TC_PIV_OK);
  munit_assert_uint16(out.status, ==, 0x6282);
  munit_assert_uint16(TC_PIV_link_status(&link), ==, 0x6282);
  munit_assert_int(
      TC_PIV_status_classify(0x6282, TC_PIV_COMMAND_GET_DATA, TC_PIV_APPLICATION_PIV, NULL), ==,
      TC_PIV_SW_END_OF_OBJECT);
  /* Malformed answers: bare 9000, empty 7E, 53 for 7E, trailing bytes,
   * truncation, a foreign tag, inexact 6282 and 6282 without data. */
  TC_PIV_data_object preserved;
  memset(&out, 0x5a, sizeof out);
  preserved = out;
  static const char* const tags[] = {"5FC102", "7E",     "7E",     "5FC102",
                                     "5FC102", "5FC102", "5FC102", "5FC102"};
  for (size_t i = 0; i < sizeof tags / sizeof *tags; ++i) {
    memset(response_bytes, 0xee, sizeof response_bytes);
    munit_assert_int(get_data_hex(&link, tags[i], 64, &out), ==, TC_PIV_INVALID);
    munit_assert_memory_equal(sizeof out, &out, &preserved);
    munit_assert_true(tc_test_all_zero(response_bytes, 64));
    munit_assert_uint16(TC_PIV_link_status(&link), ==, 0);
  }
  /* Card statuses. */
  static const uint16_t statuses[] = {0x6a82, 0x6982, 0x6a88};
  static const TC_PIV_status meanings[] = {TC_PIV_SW_NOT_FOUND, TC_PIV_SW_SECURITY_STATUS,
                                           TC_PIV_SW_REFERENCE_NOT_FOUND};
  for (size_t i = 0; i < 3; ++i) {
    munit_assert_int(get_data_hex(&link, "5FC102", 64, &out), ==, TC_PIV_CARD_STATUS);
    munit_assert_uint16(TC_PIV_link_status(&link), ==, statuses[i]);
    munit_assert_int(TC_PIV_status_classify(TC_PIV_link_status(&link), TC_PIV_COMMAND_GET_DATA,
                                            TC_PIV_APPLICATION_PIV, NULL),
                     ==, meanings[i]);
    munit_assert_memory_equal(sizeof out, &out, &preserved);
  }
  assert_script_done();
  return MUNIT_OK;
}

/* TWIC application answers (TWIC Part 2 v5 3.3.6, 4.5 and 5.2). */
TC_TEST(get_data_twic)
{
  const tc_script_step steps[] = {STEP(TWIC_SELECT, TWIC_APT("1") "9000"),
                                  STEP("00CB3FFF055C03DFC10100", "5300 9000"),
                                  STEP("00CB3FFF055C03DFC10100", "DFC10100 9000"),
                                  STEP("00CB3FFF035C017E00", "7E028000 9000"),
                                  STEP("00CB3FFF055C03DFC10100", "DFC10102AABB 9000"),
                                  STEP("00CB3FFF055C03DFC10100", "DFC101028000 9000"),
                                  STEP("00CB3FFF055C03DFC10100", "9000"),
                                  STEP("00CB3FFF055C03DFC10100", "DFC10202AABB 9000"),
                                  STEP("00CB3FFF055C03DFC10100", "6A88")};
  TC_PIV_link link;
  link_start(&link, steps, sizeof steps / sizeof *steps, TC_PIV_CONTACT);
  select_application(&link, TC_PIV_APPLICATION_TWIC);
  TC_PIV_data_object out;
  munit_assert_int(get_data_hex(&link, "DFC101", 64, &out), ==, TC_PIV_OK);
  munit_assert_int(out.form, ==, TC_PIV_FORM_CONTAINER);
  munit_assert_size(out.value.length, ==, 0);
  munit_assert_int(get_data_hex(&link, "DFC101", 64, &out), ==, TC_PIV_OK);
  munit_assert_int(out.form, ==, TC_PIV_FORM_TEMPLATE);
  munit_assert_size(out.encoded.length, ==, 4);
  munit_assert_size(out.value.length, ==, 0);
  /* TAG 02 80 00 is empty for a constructed tag. */
  munit_assert_int(get_data_hex(&link, "7E", 64, &out), ==, TC_PIV_OK);
  munit_assert_int(out.form, ==, TC_PIV_FORM_TEMPLATE);
  munit_assert_size(out.encoded.length, ==, 4);
  munit_assert_size(out.value.length, ==, 0);
  munit_assert_int(get_data_hex(&link, "DFC101", 64, &out), ==, TC_PIV_OK);
  munit_assert_size(out.value.length, ==, 2);
  /* DFC101 is primitive, so 80 00 is its value. */
  munit_assert_int(get_data_hex(&link, "DFC101", 64, &out), ==, TC_PIV_OK);
  munit_assert_size(out.value.length, ==, 2);
  munit_assert_int(get_data_hex(&link, "DFC101", 64, &out), ==, TC_PIV_OK);
  munit_assert_int(out.form, ==, TC_PIV_FORM_NONE);
  munit_assert_size(out.encoded.length, ==, 0);
  munit_assert_size(out.value.length, ==, 0);
  munit_assert_uint16(out.status, ==, 0x9000);
  munit_assert_int(get_data_hex(&link, "DFC101", 64, &out), ==, TC_PIV_INVALID);
  munit_assert_int(get_data_hex(&link, "DFC101", 64, &out), ==, TC_PIV_CARD_STATUS);
  munit_assert_int(TC_PIV_status_classify(TC_PIV_link_status(&link), TC_PIV_COMMAND_GET_DATA,
                                          TC_PIV_APPLICATION_TWIC, NULL),
                   ==, TC_PIV_SW_NOT_FOUND);
  assert_script_done();
  return MUNIT_OK;
}

/* Response chaining through the channel: 6CXX correction and GET RESPONSE
 * with CLA 00 and Le = SW2 (ported from the example card reader). */
TC_TEST(get_data_chained)
{
  const tc_script_step steps[] = {
      STEP(PIV_SELECT, PIV_APT "9000"), STEP("00CB3FFF055C035FC10200", "6C06"),
      STEP("00CB3FFF055C035FC10206", "53066104 6104"), STEP("00C0000004", "01020304 9000")};
  TC_PIV_link link;
  link_start(&link, steps, 4, TC_PIV_CONTACT);
  select_application(&link, TC_PIV_APPLICATION_PIV);
  TC_PIV_data_object out;
  munit_assert_int(get_data_hex(&link, "5FC102", 300, &out), ==, TC_PIV_OK);
  munit_assert_size(out.encoded.length, ==, 8);
  munit_assert_size(out.value.length, ==, 6);
  munit_assert_memory_equal(6, out.value.data, "\x61\x04\x01\x02\x03\x04");
  munit_assert_true(tc_test_all_zero(response_bytes + 8, 2));
  munit_assert_size(TC_APDU_channel_exchanges_left(&link.channel), ==, 28);
  assert_script_done();
  return MUNIT_OK;
}

/* EXTENDED links request up to 65536 bytes (ISO/IEC 7816-4 5.2). */
TC_TEST(get_data_extended)
{
  static uint8_t large[TC_APDU_RESPONSE_BYTES(65536)];
  static const uint8_t tag[] = {0x5f, 0xc1, 0x02};
  /* The card limit 32767 lowers Ne to 32765. */
  const tc_script_step steps[] = {STEP(PIV_SELECT, PIV_APT "9000"),
                                  STEP("00CB3FFF0000055C035FC1027FFD", "5300 9000")};
  const TC_PIV_link_options options = {{TC_APDU_EXTENDED, 0, 4, 0, 0}, TC_PIV_CONTACT, 65536};
  TC_PIV_link link;
  link_start_options(&link, steps, 2, &options);
  select_application(&link, TC_PIV_APPLICATION_PIV);
  TC_PIV_data_object out;
  munit_assert_int(TC_PIV_get_data(&link, span(tag, 3), (TC_buffer){large, sizeof large}, &out), ==,
                   TC_PIV_OK);
  munit_assert_size(out.encoded.length, ==, 2);
  munit_assert_size(script.offered[1], ==, sizeof large);
  assert_script_done();
  TC_PIV_link_clear(&link);
  /* Without a card limit Ne 65536 encodes 0000. */
  const tc_script_step full[] = {STEP("00CB3FFF0000055C035FC1020000", "5300 9000")};
  link_start_options(&link, full, 1, &options);
  link.application = TC_PIV_APPLICATION_PIV;
  munit_assert_int(TC_PIV_get_data(&link, span(tag, 3), (TC_buffer){large, sizeof large}, &out), ==,
                   TC_PIV_OK);
  assert_script_done();
  return MUNIT_OK;
}

TC_TEST(get_data_arguments)
{
  const tc_script_step steps[] = {STEP(PIV_SELECT, PIV_APT "9000")};
  TC_PIV_link link;
  link_start(&link, steps, 1, TC_PIV_CONTACT);
  TC_PIV_data_object out, preserved;
  memset(&out, 0x5a, sizeof out);
  preserved = out;
  munit_assert_int(get_data_hex(&link, "7E", 64, &out), ==, TC_PIV_REFUSED);
  select_application(&link, TC_PIV_APPLICATION_PIV);
  static const char* const tags[] = {"",     "5FC1020A", "5F", "5FC1", "5F80",
                                     "7E01", "00",       "FF", "1F"};
  for (size_t i = 0; i < sizeof tags / sizeof *tags; ++i)
    munit_assert_int(get_data_hex(&link, tags[i], 64, &out), ==, TC_PIV_ARGUMENT);
  munit_assert_int(get_data_hex(&link, "7E", 1, &out), ==, TC_PIV_ARGUMENT);
  munit_assert_int(get_data_hex(&link, "7E", 64, NULL), ==, TC_PIV_ARGUMENT);
  static const uint8_t tag = 0x7e;
  munit_assert_int(TC_PIV_get_data(NULL, span(&tag, 1), response_buffer(64), &out), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_get_data(&link, span(NULL, 1), response_buffer(64), &out), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(
      TC_PIV_get_data(&link, span(&tag, 1), (TC_buffer){(uint8_t*)&out, sizeof out}, &out), ==,
      TC_PIV_ARGUMENT);
  munit_assert_int(
      TC_PIV_get_data(&link, span(&tag, 1), (TC_buffer){(uint8_t*)&link, sizeof link}, &preserved),
      ==, TC_PIV_ARGUMENT);
  response_bytes[10] = 0x7e;
  munit_assert_int(TC_PIV_get_data(&link, span(response_bytes + 10, 1), response_buffer(64), &out),
                   ==, TC_PIV_ARGUMENT);
  munit_assert_memory_equal(sizeof out, &out, &preserved);
  assert_script_done();
  return MUNIT_OK;
}

/* VERIFY without data (Part 2 3.2.1). */
TC_TEST(verify_status)
{
  const tc_script_step steps[] = {STEP(PIV_SELECT, PIV_APT "9000"), STEP("00200080", "63C7"),
                                  STEP("00200000", "9000"),         STEP("00200080", "6983"),
                                  STEP("00200098", "6300"),         STEP("00200080", "9000")};
  TC_PIV_link link;
  link_start(&link, steps, sizeof steps / sizeof *steps, TC_PIV_CONTACT);
  TC_PIV_reference_status out, preserved;
  memset(&out, 0x5a, sizeof out);
  preserved = out;
  munit_assert_int(TC_PIV_verify_status(&link, 0x80, &out), ==, TC_PIV_REFUSED);
  select_application(&link, TC_PIV_APPLICATION_PIV);
  munit_assert_int(TC_PIV_verify_status(&link, 0x80, &out), ==, TC_PIV_OK);
  munit_assert_uint8(out.verified, ==, 0);
  munit_assert_uint8(out.submitted, ==, 0);
  munit_assert_uint8(out.retries_known, ==, 1);
  munit_assert_uint(out.retries, ==, 7);
  TC_PIV_link_info info;
  TC_PIV_link_info_get(&link, &info);
  munit_assert_uint8(info.pin_verified, ==, 0);
  munit_assert_int(TC_PIV_verify_status(&link, 0x00, &out), ==, TC_PIV_OK);
  munit_assert_uint8(out.verified, ==, 1);
  munit_assert_uint8(out.retries_known, ==, 0);
  TC_PIV_link_info_get(&link, &info);
  munit_assert_uint8(info.pin_verified, ==, 1);
  memset(&out, 0x5a, sizeof out);
  munit_assert_int(TC_PIV_verify_status(&link, 0x80, &out), ==, TC_PIV_CARD_STATUS);
  munit_assert_uint16(TC_PIV_link_status(&link), ==, 0x6983);
  munit_assert_memory_equal(sizeof out, &out, &preserved);
  munit_assert_int(
      TC_PIV_status_classify(0x6983, TC_PIV_COMMAND_VERIFY, TC_PIV_APPLICATION_PIV, NULL), ==,
      TC_PIV_SW_BLOCKED);
  /* The pairing code has no retry counter (Part 2 footnote 7). */
  munit_assert_int(TC_PIV_verify_status(&link, 0x98, &out), ==, TC_PIV_OK);
  munit_assert_uint8(out.verified, ==, 0);
  munit_assert_uint8(out.retries_known, ==, 0);
  /* References outside 80, 00 and 98. */
  memset(&out, 0x5a, sizeof out);
  munit_assert_int(TC_PIV_verify_status(&link, 0x96, &out), ==, TC_PIV_UNSUPPORTED);
  munit_assert_int(TC_PIV_verify_status(&link, 0x97, &out), ==, TC_PIV_UNSUPPORTED);
  munit_assert_int(TC_PIV_verify_status(&link, 0x81, &out), ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_verify_status(&link, 0x9a, &out), ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_verify_status(&link, 0x80, NULL), ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_verify_status(NULL, 0x80, &out), ==, TC_PIV_ARGUMENT);
  munit_assert_memory_equal(sizeof out, &out, &preserved);
  munit_assert_int(TC_PIV_verify_status(&link, 0x80, &out), ==, TC_PIV_OK);
  assert_script_done();
  return MUNIT_OK;
}

/* Part 2 3.2.1: VERIFY 80 or 00 fails outside the contact interface and the
 * VCI, and 98 without secure messaging on contactless. The library refuses
 * those commands before sending. */
TC_TEST(verify_contactless)
{
  const tc_script_step steps[] = {STEP(PIV_SELECT, PIV_APT "9000"), STEP("00200080", "6983"),
                                  STEP("00200098", "6300")};
  TC_PIV_link link;
  link_start(&link, steps, 3, TC_PIV_CONTACTLESS);
  select_application(&link, TC_PIV_APPLICATION_PIV);
  TC_PIV_reference_status out;
  static const uint8_t pin[] = "123456";
  munit_assert_int(TC_PIV_verify_status(&link, 0x80, &out), ==, TC_PIV_REFUSED);
  munit_assert_int(TC_PIV_verify_status(&link, 0x00, &out), ==, TC_PIV_REFUSED);
  munit_assert_int(TC_PIV_verify_status(&link, 0x98, &out), ==, TC_PIV_REFUSED);
  munit_assert_int(TC_PIV_pin_verify(&link, 0x80, span(pin, 6), 3, &out), ==, TC_PIV_REFUSED);
  munit_assert_size(script.next, ==, 1);
  munit_assert_uint16(TC_PIV_link_status(&link), ==, 0x9000);
  /* With the VCI the retry query goes out. A contactless intermediate
   * retry value answers 6983 (Part 2 3.2.1). */
  link.flags |= TC_PIV_LINK_VCI;
  munit_assert_int(TC_PIV_verify_status(&link, 0x80, &out), ==, TC_PIV_CARD_STATUS);
  munit_assert_uint16(TC_PIV_link_status(&link), ==, 0x6983);
  link.flags = TC_PIV_LINK_SECURED;
  munit_assert_int(TC_PIV_verify_status(&link, 0x80, &out), ==, TC_PIV_REFUSED);
  munit_assert_int(TC_PIV_verify_status(&link, 0x98, &out), ==, TC_PIV_OK);
  assert_script_done();
  return MUNIT_OK;
}

/* The TWIC application defines no VERIFY (TWIC Part 2 v5 5). */
TC_TEST(verify_twic)
{
  const tc_script_step steps[] = {STEP(TWIC_SELECT, TWIC_APT("3") "9000")};
  TC_PIV_link link;
  link_start(&link, steps, 1, TC_PIV_CONTACT);
  select_application(&link, TC_PIV_APPLICATION_TWIC);
  TC_PIV_reference_status out;
  static const uint8_t pin[] = "123456";
  munit_assert_int(TC_PIV_verify_status(&link, 0x80, &out), ==, TC_PIV_UNSUPPORTED);
  munit_assert_int(TC_PIV_pin_verify(&link, 0x80, span(pin, 6), 3, &out), ==, TC_PIV_UNSUPPORTED);
  assert_script_done();
  return MUNIT_OK;
}

/* Part 2 2.4.3 and 3.2.1.1: query, then one submission padded with FF. */
TC_TEST(pin_verify)
{
  static const uint8_t pin[] = "12345678";
  const tc_script_step steps[] = {STEP(PIV_SELECT, PIV_APT "9000"), STEP("00200080", "63C3"),
                                  STEP("0020008008313233343536FFFF", "9000")};
  TC_PIV_link link;
  link_start(&link, steps, 3, TC_PIV_CONTACT);
  select_application(&link, TC_PIV_APPLICATION_PIV);
  TC_PIV_reference_status out;
  munit_assert_int(TC_PIV_pin_verify(&link, 0x80, span(pin, 6), 3, &out), ==, TC_PIV_OK);
  munit_assert_uint8(out.verified, ==, 1);
  munit_assert_uint8(out.submitted, ==, 1);
  /* Success resets the counter, so no count is reported. */
  munit_assert_uint8(out.retries_known, ==, 0);
  TC_PIV_link_info info;
  TC_PIV_link_info_get(&link, &info);
  munit_assert_uint8(info.pin_verified, ==, 1);
  munit_assert_uint16(TC_PIV_link_status(&link), ==, 0x9000);
  /* The PIN passed through the scratch buffer, which is wiped. */
  assert_script_done();
  munit_assert_memory_equal(13, script.sent[2],
                            "\x00\x20\x00\x80\x08"
                            "123456\xff\xff");
  /* A new SELECT resets the PIN status. */
  const tc_script_step again[] = {STEP(PIV_SELECT, PIV_APT "9000")};
  script.steps = again;
  script.count = 1;
  script.next = 0;
  select_application(&link, TC_PIV_APPLICATION_PIV);
  TC_PIV_link_info_get(&link, &info);
  munit_assert_uint8(info.pin_verified, ==, 0);
  return MUNIT_OK;
}

/* Every 63CX below the floor refuses, and nothing more is sent. */
TC_TEST(pin_verify_floor)
{
  static const uint8_t pin[] = "123456";
  for (unsigned retries = 0; retries <= 15; ++retries) {
    char query[5] = "63C0";
    query[3] = "0123456789ABCDEF"[retries];
    const tc_script_step steps[] = {STEP("00200000", query),
                                    STEP("00200000083132333435 36FFFF", "9000")};
    TC_PIV_link link;
    link_start(&link, steps, 2, TC_PIV_CONTACT);
    link.application = TC_PIV_APPLICATION_PIV;
    TC_PIV_reference_status out;
    memset(&out, 0x5a, sizeof out);
    const TC_PIV_result result = TC_PIV_pin_verify(&link, 0x00, span(pin, 6), 4, &out);
    munit_assert_int(result, ==, retries >= 4 ? TC_PIV_OK : TC_PIV_REFUSED);
    munit_assert_size(script.next, ==, retries >= 4 ? 2 : 1);
    munit_assert_size(script.mismatch, ==, 0);
    munit_assert_uint16(TC_PIV_link_status(&link), ==,
                        (uint16_t)(retries >= 4 ? 0x9000 : 0x63c0 + retries));
    TC_PIV_link_info info;
    TC_PIV_link_info_get(&link, &info);
    munit_assert_uint8(info.pin_verified, ==, retries >= 4);
  }
  return MUNIT_OK;
}

TC_TEST(pin_verify_outcomes)
{
  static const uint8_t pin[] = "12345678";
  /* Already verified: nothing is submitted. */
  const tc_script_step verified[] = {STEP("00200080", "9000")};
  TC_PIV_link link;
  link_start(&link, verified, 1, TC_PIV_CONTACT);
  link.application = TC_PIV_APPLICATION_PIV;
  TC_PIV_reference_status out, preserved;
  munit_assert_int(TC_PIV_pin_verify(&link, 0x80, span(pin, 8), 2, &out), ==, TC_PIV_OK);
  munit_assert_uint8(out.verified, ==, 1);
  munit_assert_uint8(out.submitted, ==, 0);
  assert_script_done();
  memset(&out, 0x5a, sizeof out);
  preserved = out;
  /* A blocked or unknown counter stops before the PIN. */
  static const char* const queries[] = {"6983", "6300", "6A88"};
  static const TC_PIV_result query_results[] = {TC_PIV_CARD_STATUS, TC_PIV_REFUSED,
                                                TC_PIV_CARD_STATUS};
  for (size_t i = 0; i < 3; ++i) {
    const tc_script_step steps[] = {STEP("00200080", queries[i])};
    link_start(&link, steps, 1, TC_PIV_CONTACT);
    link.application = TC_PIV_APPLICATION_PIV;
    munit_assert_int(TC_PIV_pin_verify(&link, 0x80, span(pin, 8), 2, &out), ==, query_results[i]);
    munit_assert_memory_equal(sizeof out, &out, &preserved);
    assert_script_done();
  }
  /* A failed submission is reported once. The card is never retried. */
  static const char* const answers[] = {"63C2", "6983", "6A80"};
  for (size_t i = 0; i < 3; ++i) {
    const tc_script_step steps[] = {STEP("00200080", "63C5"),
                                    STEP("00200080083132333435363738", answers[i])};
    link_start(&link, steps, 2, TC_PIV_CONTACT);
    link.application = TC_PIV_APPLICATION_PIV;
    munit_assert_int(TC_PIV_pin_verify(&link, 0x80, span(pin, 8), 2, &out), ==, TC_PIV_CARD_STATUS);
    munit_assert_memory_equal(sizeof out, &out, &preserved);
    TC_PIV_link_info info;
    TC_PIV_link_info_get(&link, &info);
    munit_assert_uint8(info.pin_verified, ==, 0);
    assert_script_done();
  }
  unsigned retries = 99;
  munit_assert_int(
      TC_PIV_status_classify(0x63c2, TC_PIV_COMMAND_VERIFY, TC_PIV_APPLICATION_PIV, &retries), ==,
      TC_PIV_SW_VERIFY_FAILED);
  munit_assert_uint(retries, ==, 2);
  /* A transport failure on the submission stops the link. */
  const tc_script_step lost[] = {STEP("00200080", "63C5"),
                                 FAILED_STEP("00200080083132333435363738")};
  link_start(&link, lost, 2, TC_PIV_CONTACT);
  link.application = TC_PIV_APPLICATION_PIV;
  munit_assert_int(TC_PIV_pin_verify(&link, 0x80, span(pin, 8), 2, &out), ==, TC_PIV_ERROR);
  munit_assert_int(TC_PIV_pin_verify(&link, 0x80, span(pin, 8), 2, &out), ==, TC_PIV_ERROR);
  munit_assert_memory_equal(sizeof out, &out, &preserved);
  assert_script_done();
  /* The budget covers the query only. */
  const tc_script_step budget[] = {STEP("00200080", "63C5")};
  const TC_PIV_link_options options = {{TC_APDU_SHORT, 0, 1, 0, 0}, TC_PIV_CONTACT, 0};
  link_start_options(&link, budget, 1, &options);
  link.application = TC_PIV_APPLICATION_PIV;
  munit_assert_int(TC_PIV_pin_verify(&link, 0x80, span(pin, 8), 2, &out), ==, TC_PIV_LIMIT);
  assert_script_done();
  return MUNIT_OK;
}

TC_TEST(pin_verify_arguments)
{
  TC_PIV_link link;
  link_start(&link, NULL, 0, TC_PIV_CONTACT);
  link.application = TC_PIV_APPLICATION_PIV;
  TC_PIV_reference_status out, preserved;
  memset(&out, 0x5a, sizeof out);
  preserved = out;
  static const uint8_t digits[] = "123456789";
  static const uint8_t letters[] = "12345x";
  munit_assert_int(TC_PIV_pin_verify(&link, 0x80, span(digits, 5), 3, &out), ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_pin_verify(&link, 0x80, span(digits, 9), 3, &out), ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_pin_verify(&link, 0x80, span(letters, 6), 3, &out), ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_pin_verify(&link, 0x80, span(NULL, 6), 3, &out), ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_pin_verify(&link, 0x80, span(digits, 6), 1, &out), ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_pin_verify(&link, 0x80, span(digits, 6), 16, &out), ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_pin_verify(&link, 0x98, span(digits, 8), 3, &out), ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_pin_verify(&link, 0x96, span(digits, 8), 3, &out), ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_pin_verify(&link, 0x80, span(digits, 6), 3, NULL), ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_pin_verify(NULL, 0x80, span(digits, 6), 3, &out), ==, TC_PIV_ARGUMENT);
  munit_assert_memory_equal(sizeof out, &out, &preserved);
  link.application = TC_PIV_APPLICATION_NONE;
  munit_assert_int(TC_PIV_pin_verify(&link, 0x80, span(digits, 6), 3, &out), ==, TC_PIV_REFUSED);
  assert_script_done();
  return MUNIT_OK;
}

/* A PIN reference answering other than 9000 is unverified on the card (Part 2
 * 3.2.1.1), so the link drops its PIN status. */
TC_TEST(pin_status_tracking)
{
  static const uint8_t pin[] = "123456";
  const tc_script_step steps[] = {
      STEP("00200080", "9000"), STEP("00200080", "63C9"),
      STEP("00200000", "9000"), STEP("00200000", "6983"),
      STEP("00200080", "63C5"), STEP("00200080083132333435 36FFFF", "63C4"),
      STEP("00200098", "6300")};
  TC_PIV_link link;
  link_start(&link, steps, sizeof steps / sizeof *steps, TC_PIV_CONTACT);
  link.application = TC_PIV_APPLICATION_PIV;
  TC_PIV_reference_status out;
  TC_PIV_link_info info;
  munit_assert_int(TC_PIV_verify_status(&link, 0x80, &out), ==, TC_PIV_OK);
  TC_PIV_link_info_get(&link, &info);
  munit_assert_uint8(info.pin_verified, ==, 1);
  /* The card reports the PIN unverified again, for example after a PIN
   * Always key used it. */
  munit_assert_int(TC_PIV_verify_status(&link, 0x80, &out), ==, TC_PIV_OK);
  TC_PIV_link_info_get(&link, &info);
  munit_assert_uint8(info.pin_verified, ==, 0);
  munit_assert_int(TC_PIV_verify_status(&link, 0x00, &out), ==, TC_PIV_OK);
  munit_assert_int(TC_PIV_verify_status(&link, 0x00, &out), ==, TC_PIV_CARD_STATUS);
  TC_PIV_link_info_get(&link, &info);
  munit_assert_uint8(info.pin_verified, ==, 0);
  /* A rejected submission leaves the reference FALSE. */
  link.flags |= TC_PIV_LINK_PIN_VERIFIED;
  munit_assert_int(TC_PIV_pin_verify(&link, 0x80, span(pin, 6), 3, &out), ==, TC_PIV_CARD_STATUS);
  TC_PIV_link_info_get(&link, &info);
  munit_assert_uint8(info.pin_verified, ==, 0);
  /* The pairing code is a separate reference. */
  link.flags |= TC_PIV_LINK_PIN_VERIFIED;
  munit_assert_int(TC_PIV_verify_status(&link, 0x98, &out), ==, TC_PIV_OK);
  TC_PIV_link_info_get(&link, &info);
  munit_assert_uint8(info.pin_verified, ==, 1);
  assert_script_done();
  return MUNIT_OK;
}

/* Buffers inside the command scratch would be wiped after the first
 * transmit, so the calls reject them before sending and keep the link
 * state. */
TC_TEST(scratch_overlap)
{
  const tc_script_step steps[] = {STEP(PIV_SELECT, PIV_APT "9000")};
  TC_PIV_link link;
  link_start(&link, steps, 1, TC_PIV_CONTACT);
  select_application(&link, TC_PIV_APPLICATION_PIV);
  link.flags |= TC_PIV_LINK_PIN_VERIFIED;
  const TC_buffer inside = {scratch + 8, 64};
  TC_PIV_application application;
  munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 0, inside, &application), ==,
                   TC_PIV_ARGUMENT);
  static const uint8_t tag[] = {0x5f, 0xc1, 0x02};
  TC_PIV_data_object object;
  munit_assert_int(TC_PIV_get_data(&link, span(tag, 3), inside, &object), ==, TC_PIV_ARGUMENT);
  /* A PIN in the scratch would reach the card as zeros after the query. */
  memcpy(scratch + 8, "123456", 6);
  TC_PIV_reference_status out;
  munit_assert_int(TC_PIV_pin_verify(&link, 0x80, span(scratch + 8, 6), 3, &out), ==,
                   TC_PIV_ARGUMENT);
  memset(scratch, 0, sizeof scratch);
  TC_PIV_link_info info;
  TC_PIV_link_info_get(&link, &info);
  munit_assert_int(info.application, ==, TC_PIV_APPLICATION_PIV);
  munit_assert_uint8(info.pin_verified, ==, 1);
  munit_assert_uint16(TC_PIV_link_status(&link), ==, 0x9000);
  assert_script_done();
  return MUNIT_OK;
}

/* Part 1 Table 7 with the per-command 6A88 and 63XX meanings. */
TC_TEST(status_classify)
{
  static const struct {
    uint16_t sw;
    TC_PIV_command command;
    TC_PIV_application_id application;
    TC_PIV_status status;
  } cases[] = {
      {0x9000, TC_PIV_COMMAND_GET_DATA, TC_PIV_APPLICATION_PIV, TC_PIV_SW_SUCCESS},
      {0x6282, TC_PIV_COMMAND_GET_DATA, TC_PIV_APPLICATION_TWIC, TC_PIV_SW_END_OF_OBJECT},
      {0x6282, TC_PIV_COMMAND_VERIFY, TC_PIV_APPLICATION_PIV, TC_PIV_SW_OTHER},
      {0x6300, TC_PIV_COMMAND_VERIFY, TC_PIV_APPLICATION_PIV, TC_PIV_SW_VERIFY_FAILED},
      {0x63c9, TC_PIV_COMMAND_VERIFY, TC_PIV_APPLICATION_PIV, TC_PIV_SW_VERIFY_FAILED},
      {0x63c9, TC_PIV_COMMAND_GET_DATA, TC_PIV_APPLICATION_PIV, TC_PIV_SW_OTHER},
      {0x6301, TC_PIV_COMMAND_VERIFY, TC_PIV_APPLICATION_PIV, TC_PIV_SW_OTHER},
      {0x6882, TC_PIV_COMMAND_GET_DATA, TC_PIV_APPLICATION_PIV, TC_PIV_SW_SM_UNSUPPORTED},
      {0x6982, TC_PIV_COMMAND_GENERAL_AUTHENTICATE, TC_PIV_APPLICATION_PIV,
       TC_PIV_SW_SECURITY_STATUS},
      {0x6983, TC_PIV_COMMAND_VERIFY, TC_PIV_APPLICATION_PIV, TC_PIV_SW_BLOCKED},
      {0x6987, TC_PIV_COMMAND_GET_DATA, TC_PIV_APPLICATION_PIV, TC_PIV_SW_SM_MISSING},
      {0x6988, TC_PIV_COMMAND_GET_DATA, TC_PIV_APPLICATION_PIV, TC_PIV_SW_SM_INCORRECT},
      {0x6a80, TC_PIV_COMMAND_VERIFY, TC_PIV_APPLICATION_PIV, TC_PIV_SW_WRONG_DATA},
      {0x6a81, TC_PIV_COMMAND_GET_DATA, TC_PIV_APPLICATION_PIV, TC_PIV_SW_NOT_SUPPORTED},
      {0x6a82, TC_PIV_COMMAND_GET_DATA, TC_PIV_APPLICATION_PIV, TC_PIV_SW_NOT_FOUND},
      {0x6a82, TC_PIV_COMMAND_SELECT, TC_PIV_APPLICATION_TWIC, TC_PIV_SW_NOT_FOUND},
      {0x6a84, TC_PIV_COMMAND_GET_DATA, TC_PIV_APPLICATION_PIV, TC_PIV_SW_NO_MEMORY},
      {0x6a86, TC_PIV_COMMAND_VERIFY, TC_PIV_APPLICATION_PIV, TC_PIV_SW_WRONG_P1P2},
      {0x6a88, TC_PIV_COMMAND_VERIFY, TC_PIV_APPLICATION_PIV, TC_PIV_SW_REFERENCE_NOT_FOUND},
      {0x6a88, TC_PIV_COMMAND_GENERAL_AUTHENTICATE, TC_PIV_APPLICATION_TWIC,
       TC_PIV_SW_REFERENCE_NOT_FOUND},
      {0x6a88, TC_PIV_COMMAND_GET_DATA, TC_PIV_APPLICATION_PIV, TC_PIV_SW_REFERENCE_NOT_FOUND},
      {0x6a88, TC_PIV_COMMAND_GET_DATA, TC_PIV_APPLICATION_TWIC, TC_PIV_SW_NOT_FOUND},
      {0x6110, TC_PIV_COMMAND_GET_DATA, TC_PIV_APPLICATION_PIV, TC_PIV_SW_OTHER},
      {0x6d00, TC_PIV_COMMAND_GET_DATA, TC_PIV_APPLICATION_PIV, TC_PIV_SW_OTHER},
      {0x0000, TC_PIV_COMMAND_GET_DATA, TC_PIV_APPLICATION_NONE, TC_PIV_SW_OTHER}};
  for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
    unsigned retries = 99;
    munit_assert_int(
        TC_PIV_status_classify(cases[i].sw, cases[i].command, cases[i].application, &retries), ==,
        cases[i].status);
    munit_assert_uint(retries, ==,
                      cases[i].sw == 0x63c9 && cases[i].command == TC_PIV_COMMAND_VERIFY ? 9 : 99);
  }
  munit_assert_int(
      TC_PIV_status_classify(0x63c4, TC_PIV_COMMAND_VERIFY, TC_PIV_APPLICATION_PIV, NULL), ==,
      TC_PIV_SW_VERIFY_FAILED);
  return MUNIT_OK;
}

TC_TEST(link_init)
{
  static uint8_t small[TC_APDU_SHORT_COMMAND_MAX_BYTES - 1];
  TC_PIV_link link, preserved;
  memset(&link, 0x5a, sizeof link);
  preserved = link;
  tc_script_init(&script, NULL, 0);
  const TC_APDU_transport transport = tc_script_transport(&script);
  const TC_buffer scratch_buffer = {scratch, sizeof scratch};
  TC_PIV_link_options options = {{TC_APDU_SHORT, 0, 4, 0, 0}, TC_PIV_CONTACT, 0};
  munit_assert_int(TC_PIV_link_init(&link, transport, &options, (TC_buffer){small, sizeof small}),
                   ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_link_init(NULL, transport, &options, scratch_buffer), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_link_init(&link, transport, NULL, scratch_buffer), ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_link_init(&link, transport, &options, (TC_buffer){NULL, 300}), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(
      TC_PIV_link_init(&link, (TC_APDU_transport){NULL, NULL}, &options, scratch_buffer), ==,
      TC_PIV_ARGUMENT);
  options.interface = (TC_PIV_interface)2;
  munit_assert_int(TC_PIV_link_init(&link, transport, &options, scratch_buffer), ==,
                   TC_PIV_ARGUMENT);
  options.interface = TC_PIV_CONTACTLESS;
  options.response_ne = 257;
  munit_assert_int(TC_PIV_link_init(&link, transport, &options, scratch_buffer), ==,
                   TC_PIV_ARGUMENT);
  options.response_ne = 256;
  options.channel.exchanges = 0;
  munit_assert_int(TC_PIV_link_init(&link, transport, &options, scratch_buffer), ==,
                   TC_PIV_ARGUMENT);
  options.channel.exchanges = 4;
  options.channel.format = TC_APDU_EXTENDED;
  options.response_ne = 65537;
  munit_assert_int(TC_PIV_link_init(&link, transport, &options, scratch_buffer), ==,
                   TC_PIV_ARGUMENT);
  options.response_ne = 65536;
  /* EXTENDED needs room for the largest command, or the card limit. */
  munit_assert_int(
      TC_PIV_link_init(
          &link, transport, &options,
          (TC_buffer){scratch, TC_APDU_EXTENDED_COMMAND_BYTES(TC_PIV_COMMAND_MAX_NC) - 1}),
      ==, TC_PIV_ARGUMENT);
  munit_assert_memory_equal(sizeof link, &link, &preserved);
  munit_assert_int(
      TC_PIV_link_init(&link, transport, &options,
                       (TC_buffer){scratch, TC_APDU_EXTENDED_COMMAND_BYTES(TC_PIV_COMMAND_MAX_NC)}),
      ==, TC_PIV_OK);
  options.channel.max_command_bytes = 20;
  munit_assert_int(TC_PIV_link_init(&link, transport, &options, (TC_buffer){scratch, 20}), ==,
                   TC_PIV_OK);
  munit_assert_int(TC_PIV_link_init(&link, transport, &options, (TC_buffer){scratch, 19}), ==,
                   TC_PIV_ARGUMENT);
  /* Scratch inside the link or the options. */
  munit_assert_int(
      TC_PIV_link_init(&link, transport, &options, (TC_buffer){(uint8_t*)&link, sizeof link}), ==,
      TC_PIV_ARGUMENT);
  munit_assert_int(
      TC_PIV_link_init(&link, transport, &options, (TC_buffer){(uint8_t*)&options, sizeof options}),
      ==, TC_PIV_ARGUMENT);
  TC_PIV_link_info info;
  memset(&info, 0x5a, sizeof info);
  TC_PIV_link_info_get(&link, &info);
  munit_assert_int(info.interface, ==, TC_PIV_CONTACTLESS);
  munit_assert_int(info.application, ==, TC_PIV_APPLICATION_NONE);
  munit_assert_uint8(info.secured, ==, 0);
  munit_assert_uint8(info.sm_lost, ==, 0);
  munit_assert_uint8(info.sm_suite, ==, 0);
  TC_PIV_link_info_get(NULL, &info);
  TC_PIV_link_info_get(&link, NULL);
  munit_assert_uint16(TC_PIV_link_status(NULL), ==, 0);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* The 7C template of GENERAL AUTHENTICATE (Part 2 Table 7, A.4.1): request
 * 7C {82 00, 81 L challenge} and response 7C {82 L signature}. */
TC_TEST(template)
{
  uint8_t challenge[256];
  for (size_t i = 0; i < sizeof challenge; ++i)
    challenge[i] = (uint8_t)i;
  const tc_piv_template_item items[] = {{TC_PIV_TEMPLATE_RESPONSE, {NULL, 0}},
                                        {TC_PIV_TEMPLATE_CHALLENGE, {challenge, 256}}};
  munit_assert_size(tc_piv_template_size(items, 2), ==, 4 + 2 + 4 + 256);
  uint8_t out[300];
  memset(out, 0xee, sizeof out);
  const uint8_t* end = tc_piv_template_write(out, items, 2);
  munit_assert_ptr_equal(end, out + 266);
  munit_assert_memory_equal(10, out, "\x7c\x82\x01\x06\x82\x00\x81\x82\x01\x00");
  munit_assert_memory_equal(256, out + 10, challenge);
  munit_assert_uint8(out[266], ==, 0xee);
  const uint8_t tags[] = {TC_PIV_TEMPLATE_RESPONSE, TC_PIV_TEMPLATE_CHALLENGE};
  TC_bytes values[2] = {{NULL, 7}, {NULL, 7}};
  munit_assert_int(tc_piv_template_read(span(out, 266), tags, 2, values), ==, TC_TLV_OK);
  munit_assert_size(values[0].length, ==, 0);
  munit_assert_ptr_equal(values[1].data, out + 10);
  munit_assert_size(values[1].length, ==, 256);
  /* Order, count, trailing bytes, other templates and truncation. */
  const uint8_t reversed[] = {TC_PIV_TEMPLATE_CHALLENGE, TC_PIV_TEMPLATE_RESPONSE};
  TC_bytes preserved[2] = {{NULL, 7}, {NULL, 7}};
  memcpy(values, preserved, sizeof values);
  munit_assert_int(tc_piv_template_read(span(out, 266), reversed, 2, values), ==, TC_TLV_INVALID);
  munit_assert_int(tc_piv_template_read(span(out, 266), tags, 1, values), ==, TC_TLV_INVALID);
  munit_assert_int(tc_piv_template_read(span(out, 267), tags, 2, values), ==, TC_TLV_INVALID);
  munit_assert_int(tc_piv_template_read(span(out, 265), tags, 2, values), ==, TC_TLV_INVALID);
  static const uint8_t other[] = {0x7d, 0x02, 0x82, 0x00};
  munit_assert_int(tc_piv_template_read(span(other, 4), tags, 1, values), ==, TC_TLV_INVALID);
  static const uint8_t repeated[] = {0x7c, 0x04, 0x82, 0x00, 0x82, 0x00};
  munit_assert_int(tc_piv_template_read(span(repeated, 6), tags, 1, values), ==, TC_TLV_INVALID);
  munit_assert_true(values[0].data == NULL && values[0].length == 7);
  static const uint8_t single[] = {0x7c, 0x03, 0x82, 0x01, 0xaa};
  munit_assert_int(tc_piv_template_read(span(single, 5), tags, 1, values), ==, TC_TLV_OK);
  munit_assert_size(values[0].length, ==, 1);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
      {"/select/recorded", select_recorded, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/select/twic", select_twic, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/select/failures", select_failures, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/select/arguments", select_arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/application/rules", application_rules, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/application/twic", application_twic, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/get-data/piv", get_data_piv, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/get-data/twic", get_data_twic, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/get-data/chained", get_data_chained, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/get-data/extended", get_data_extended, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/get-data/arguments", get_data_arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/verify/status", verify_status, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/verify/contactless", verify_contactless, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/verify/twic", verify_twic, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/pin/verify", pin_verify, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/pin/floor", pin_verify_floor, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/pin/outcomes", pin_verify_outcomes, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/pin/arguments", pin_verify_arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/pin/status-tracking", pin_status_tracking, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/link/scratch-overlap", scratch_overlap, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/status/classify", status_classify, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/link/init", link_init, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/template", template, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/piv/command", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
