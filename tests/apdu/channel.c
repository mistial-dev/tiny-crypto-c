/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Exchange channel: ISO/IEC 7816-4:2020 5.3.3 command chaining, 5.3.4
 * response chaining, 5.6 GET RESPONSE and 6CXX handling, 12.8.1 card limits,
 * the transport contract and the exchange budget. */
#include <tiny_crypto/apdu.h>
#include "munit.h"
#include "scripted_transport.h"
#include "test_util.h"
#include <stdio.h>
#include <string.h>

enum { SCRATCH_BYTES = TC_APDU_EXTENDED_COMMAND_BYTES(600), RESPONSE_BYTES = 600 };
/* Hex text of a scripted command: repeat() output plus a header and Le. */
enum { HEX_BYTES = 2 * 600 + 64 };

static tc_script script;
static uint8_t scratch[SCRATCH_BYTES];
static uint8_t response_bytes[RESPONSE_BYTES];
static uint8_t data_bytes[600];

static TC_APDU_channel start_options(const tc_script_step* steps, size_t count,
                                     const TC_APDU_channel_options* options)
{
  TC_APDU_channel channel;
  tc_script_init(&script, steps, count);
  script.scratch = scratch;
  script.scratch_length = sizeof scratch;
  memset(scratch, 0, sizeof scratch);
  memset(response_bytes, 0xee, sizeof response_bytes);
  munit_assert_int(TC_APDU_channel_init(&channel, tc_script_transport(&script), options,
                                        (TC_buffer){scratch, sizeof scratch}),
                   ==, TC_APDU_OK);
  return channel;
}

static TC_APDU_channel start(const tc_script_step* steps, size_t count,
                             TC_APDU_length_format format, unsigned flags)
{
  const TC_APDU_channel_options options = {format, flags, 16, 0, 0};
  return start_options(steps, count, &options);
}

static TC_APDU_command get_data(uint8_t cla, uint32_t ne)
{
  static const uint8_t tag[] = {0x5c, 3, 0x5f, 0xc1, 2};
  TC_APDU_command command = {{tag, sizeof tag}, ne, cla, 0xcb, 0x3f, 0xff};
  return command;
}

static TC_APDU_result run(TC_APDU_channel* channel, const TC_APDU_command* command, size_t capacity,
                          TC_APDU_response* out)
{
  return TC_APDU_transceive(channel, command, (TC_buffer){response_bytes, capacity}, out);
}

static void assert_script_done(void)
{
  munit_assert_size(script.mismatch, ==, 0);
  munit_assert_size(script.next, ==, script.count);
  munit_assert_false(script.scratch_dirty);
  munit_assert_true(tc_test_all_zero(scratch, sizeof scratch));
}

/* Hex of count copies of byte. */
static const char* repeat(uint8_t byte, size_t count)
{
  static char text[2 * 600 + 1];
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < count; ++i) {
    text[2 * i] = digits[byte >> 4];
    text[2 * i + 1] = digits[byte & 15];
  }
  text[2 * count] = 0;
  return text;
}

/* SW2 gives the remaining bytes. Each chunk is appended, and GET RESPONSE
 * uses the command CLA and Le = SW2 (5.3.4, 5.6). */
TC_TEST(response_chaining)
{
  static char first[80], second[80];
  memcpy(first, repeat(0xa1, 16), 33);
  strcat(first, "6110");
  memcpy(second, repeat(0xa2, 16), 33);
  strcat(second, "9000");
  const tc_script_step steps[] = {{"00cb3fff055c035fc10200", first, {0}, {0}, TC_OK, 0},
                                  {"00c0000010", second, {0}, {0}, TC_OK, 0}};
  TC_APDU_channel channel = start(steps, 2, TC_APDU_SHORT, 0);
  TC_APDU_command command = get_data(0x00, 256);
  TC_APDU_response out;
  munit_assert_int(run(&channel, &command, 64, &out), ==, TC_APDU_OK);
  munit_assert_ptr_equal(out.data.data, response_bytes);
  munit_assert_size(out.data.length, ==, 32);
  munit_assert_uint16(out.sw, ==, 0x9000);
  munit_assert_true(tc_test_all_value(response_bytes, 16, 0xa1));
  munit_assert_true(tc_test_all_value(response_bytes + 16, 16, 0xa2));
  /* The trailing status bytes are wiped. The rest was never written. */
  munit_assert_true(tc_test_all_zero(response_bytes + 32, 2));
  munit_assert_true(tc_test_all_value(response_bytes + 34, 30, 0xee));
  munit_assert_size(script.offered[0], ==, 64);
  munit_assert_size(script.offered[1], ==, 48);
  munit_assert_size(TC_APDU_channel_exchanges_left(&channel), ==, 14);
  assert_script_done();
  return MUNIT_OK;
}

/* 61 00 requests 256 bytes, or FF with TC_APDU_GET_RESPONSE_LE_FF. */
TC_TEST(get_response_le)
{
  static char full[2 * 258 + 1];
  memcpy(full, repeat(0x33, 256), 513);
  strcat(full, "9000");
  const tc_script_step plain[] = {{NULL, "6100", {0}, {0}, TC_OK, 0},
                                  {"00c0000000", full, {0}, {0}, TC_OK, 0}};
  TC_APDU_channel channel = start(plain, 2, TC_APDU_SHORT, 0);
  TC_APDU_command command = get_data(0x00, 256);
  TC_APDU_response out;
  munit_assert_int(run(&channel, &command, 258, &out), ==, TC_APDU_OK);
  munit_assert_size(out.data.length, ==, 256);
  assert_script_done();

  const tc_script_step twic[] = {{NULL, "6100", {0}, {0}, TC_OK, 0},
                                 {"00c00000ff", full, {0}, {0}, TC_OK, 0}};
  channel = start(twic, 2, TC_APDU_SHORT, TC_APDU_GET_RESPONSE_LE_FF);
  munit_assert_int(run(&channel, &command, 258, &out), ==, TC_APDU_OK);
  munit_assert_size(out.data.length, ==, 256);
  assert_script_done();

  /* 61 00 needs room for 256 bytes and SW1 SW2. */
  channel = start(plain, 2, TC_APDU_SHORT, 0);
  munit_assert_int(run(&channel, &command, 257, &out), ==, TC_APDU_LIMIT);
  munit_assert_size(script.next, ==, 1);
  munit_assert_true(tc_test_all_zero(response_bytes, 257));
  return MUNIT_OK;
}

/* ISO/IEC 7816-4 5.6 permits the same CLA. SP 800-73-5 Part 2 4.2.6 uses 00,
 * selected with TC_APDU_GET_RESPONSE_PLAIN_CLA. Logical channel bits stay. */
TC_TEST(get_response_class)
{
  const tc_script_step same[] = {{"0ccb3fff055c035fc10200", "0102610a", {0}, {0}, TC_OK, 0},
                                 {"0cc000000a", "9000", {0}, {0}, TC_OK, 0}};
  TC_APDU_channel channel = start(same, 2, TC_APDU_SHORT, 0);
  TC_APDU_command command = get_data(0x0c, 256);
  TC_APDU_response out;
  munit_assert_int(run(&channel, &command, 64, &out), ==, TC_APDU_OK);
  munit_assert_size(out.data.length, ==, 2);
  assert_script_done();

  const tc_script_step plain[] = {{"0ccb3fff055c035fc10200", "610a", {0}, {0}, TC_OK, 0},
                                  {"00c000000a", "9000", {0}, {0}, TC_OK, 0}};
  channel = start(plain, 2, TC_APDU_SHORT, TC_APDU_GET_RESPONSE_PLAIN_CLA);
  munit_assert_int(run(&channel, &command, 64, &out), ==, TC_APDU_OK);
  assert_script_done();

  const tc_script_step logical[] = {{"0fcb3fff055c035fc10200", "610a", {0}, {0}, TC_OK, 0},
                                    {"03c000000a", "9000", {0}, {0}, TC_OK, 0}};
  channel = start(logical, 2, TC_APDU_SHORT, TC_APDU_GET_RESPONSE_PLAIN_CLA);
  command = get_data(0x0f, 256);
  munit_assert_int(run(&channel, &command, 64, &out), ==, TC_APDU_OK);
  assert_script_done();
  return MUNIT_OK;
}

/* 6CXX re-issues the same step once with Le = SW2 (5.6). */
TC_TEST(wrong_length_correction)
{
  static char body[80];
  memcpy(body, repeat(0x44, 16), 33);
  strcat(body, "9000");
  const tc_script_step corrected[] = {{"00cb3fff055c035fc10200", "6c10", {0}, {0}, TC_OK, 0},
                                      {"00cb3fff055c035fc10210", body, {0}, {0}, TC_OK, 0}};
  TC_APDU_channel channel = start(corrected, 2, TC_APDU_SHORT, 0);
  TC_APDU_command command = get_data(0x00, 256);
  TC_APDU_response out;
  munit_assert_int(run(&channel, &command, 64, &out), ==, TC_APDU_OK);
  munit_assert_size(out.data.length, ==, 16);
  munit_assert_uint16(out.sw, ==, 0x9000);
  assert_script_done();

  /* A second 6CXX on the same step is returned. */
  const tc_script_step twice[] = {{NULL, "6c10", {0}, {0}, TC_OK, 0},
                                  {"00cb3fff055c035fc10210", "6c08", {0}, {0}, TC_OK, 0}};
  channel = start(twice, 2, TC_APDU_SHORT, 0);
  munit_assert_int(run(&channel, &command, 64, &out), ==, TC_APDU_OK);
  munit_assert_size(out.data.length, ==, 0);
  munit_assert_uint16(out.sw, ==, 0x6c08);
  assert_script_done();

  /* GET RESPONSE steps get their own correction after each 61XX, and
   * 6C00 requests 256 bytes. */
  static char chunk[80];
  memcpy(chunk, repeat(0x55, 8), 17);
  strcat(chunk, "6120");
  const tc_script_step chained[] = {{NULL, "6c00", {0}, {0}, TC_OK, 0},
                                    {"00cb3fff055c035fc10200", chunk, {0}, {0}, TC_OK, 0},
                                    {"00c0000020", "6c04", {0}, {0}, TC_OK, 0},
                                    {"00c0000004", "010203049000", {0}, {0}, TC_OK, 0}};
  channel = start(chained, 4, TC_APDU_SHORT, 0);
  munit_assert_int(run(&channel, &command, 300, &out), ==, TC_APDU_OK);
  munit_assert_size(out.data.length, ==, 12);
  munit_assert_uint8(response_bytes[11], ==, 4);
  assert_script_done();
  return MUNIT_OK;
}

/* No correction under SM (SP 800-73-5 Part 2 footnote 25) or on a chained
 * command. */
TC_TEST(wrong_length_reported)
{
  const tc_script_step sm[] = {{NULL, "6c10", {0}, {0}, TC_OK, 0}};
  TC_APDU_channel channel = start(sm, 1, TC_APDU_SHORT, TC_APDU_GET_RESPONSE_PLAIN_CLA);
  TC_APDU_command command = get_data(0x0c, 256);
  TC_APDU_response out;
  munit_assert_int(run(&channel, &command, 64, &out), ==, TC_APDU_OK);
  munit_assert_uint16(out.sw, ==, 0x6c10);
  assert_script_done();

  /* Plain GET RESPONSE after an SM command keeps the SM rule. */
  const tc_script_step sm_chunks[] = {{NULL, "0102610a", {0}, {0}, TC_OK, 0},
                                      {"00c000000a", "6c04", {0}, {0}, TC_OK, 0}};
  channel = start(sm_chunks, 2, TC_APDU_SHORT, TC_APDU_GET_RESPONSE_PLAIN_CLA);
  munit_assert_int(run(&channel, &command, 64, &out), ==, TC_APDU_OK);
  munit_assert_uint16(out.sw, ==, 0x6c04);
  assert_script_done();

  const tc_script_step chain[] = {{NULL, "9000", {0}, {0}, TC_OK, 0},
                                  {NULL, "6c10", {0}, {0}, TC_OK, 0}};
  channel = start(chain, 2, TC_APDU_SHORT, 0);
  memset(data_bytes, 0x77, 256);
  TC_APDU_command long_command = {{data_bytes, 256}, 256, 0x00, 0xdb, 0x3f, 0xff};
  munit_assert_int(run(&channel, &long_command, 64, &out), ==, TC_APDU_OK);
  munit_assert_uint16(out.sw, ==, 0x6c10);
  assert_script_done();
  return MUNIT_OK;
}

/* A command without Le expects no data. 6CXX there is returned unchanged,
 * so a VERIFY and its PIN digits are sent once. */
TC_TEST(wrong_length_without_le)
{
  static const uint8_t pin[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xff, 0xff};
  const tc_script_step steps[] = {{"0020008008313233343536ffff", "6c10", {0}, {0}, TC_OK, 0}};
  TC_APDU_channel channel = start(steps, 1, TC_APDU_SHORT, 0);
  TC_APDU_command verify = {{pin, sizeof pin}, 0, 0x00, 0x20, 0x00, 0x80};
  TC_APDU_response out;
  munit_assert_int(run(&channel, &verify, 64, &out), ==, TC_APDU_OK);
  munit_assert_uint16(out.sw, ==, 0x6c10);
  munit_assert_size(out.data.length, ==, 0);
  assert_script_done();
  return MUNIT_OK;
}

/* A chain that the scratch, the card limit or the budget cannot carry to its
 * last fragment returns LIMIT before its first transmit (5.3.3). */
TC_TEST(chain_preflight)
{
  static uint8_t small_scratch[TC_APDU_SHORT_COMMAND_MAX_BYTES - 1];
  const tc_script_step steps[] = {{NULL, "9000", {0}, {0}, TC_OK, 0},
                                  {NULL, "9000", {0}, {0}, TC_OK, 0}};
  memset(data_bytes, 0x66, sizeof data_bytes);
  /* 255 + 255 bytes: the last fragment carries Le and needs 261 bytes. */
  const TC_APDU_command command = {{data_bytes, 510}, 256, 0x00, 0xdb, 0x3f, 0xff};
  const TC_APDU_channel_options options = {TC_APDU_SHORT, 0, 16, 0, 0};
  TC_APDU_response out;
  TC_APDU_channel channel;
  tc_script_init(&script, steps, 2);
  munit_assert_int(TC_APDU_channel_init(&channel, tc_script_transport(&script), &options,
                                        (TC_buffer){small_scratch, sizeof small_scratch}),
                   ==, TC_APDU_OK);
  memset(response_bytes, 0xee, sizeof response_bytes);
  munit_assert_int(run(&channel, &command, 64, &out), ==, TC_APDU_LIMIT);
  munit_assert_size(script.next, ==, 0);
  munit_assert_size(TC_APDU_channel_exchanges_left(&channel), ==, 16);

  const TC_APDU_channel_options limited = {TC_APDU_SHORT, 0, 16, 260, 0};
  channel = start_options(steps, 2, &limited);
  munit_assert_int(run(&channel, &command, 64, &out), ==, TC_APDU_LIMIT);
  munit_assert_size(script.next, ==, 0);

  /* Two fragments need two exchanges. */
  const TC_APDU_channel_options budget = {TC_APDU_SHORT, 0, 1, 0, 0};
  channel = start_options(steps, 2, &budget);
  munit_assert_int(run(&channel, &command, 64, &out), ==, TC_APDU_LIMIT);
  munit_assert_size(script.next, ==, 0);
  munit_assert_size(TC_APDU_channel_exchanges_left(&channel), ==, 1);

  /* Without Le the last fragment fits 260 bytes. */
  const TC_APDU_command no_le = {{data_bytes, 510}, 0, 0x00, 0xdb, 0x3f, 0xff};
  channel = start_options(steps, 2, &limited);
  munit_assert_int(run(&channel, &no_le, 64, &out), ==, TC_APDU_OK);
  assert_script_done();
  return MUNIT_OK;
}

/* 255-byte fragments with CLA b5 and no Le, then the last fragment with Le
 * (5.3.3, SP 800-73-5 Part 2 4.2.4). */
TC_TEST(command_chaining)
{
  static char first[HEX_BYTES], last[64];
  memset(data_bytes, 0x66, sizeof data_bytes);
  snprintf(first, sizeof first, "10dbffffff%s", repeat(0x66, 255));
  snprintf(last, sizeof last, "00dbffff01%s00", repeat(0x66, 1));
  const tc_script_step steps[] = {{first, "9000", {0}, {0}, TC_OK, 0},
                                  {last, "9000", {0}, {0}, TC_OK, 0}};
  TC_APDU_channel channel = start(steps, 2, TC_APDU_SHORT, 0);
  TC_APDU_command command = {{data_bytes, 256}, 256, 0x00, 0xdb, 0xff, 0xff};
  TC_APDU_response out;
  munit_assert_int(run(&channel, &command, 64, &out), ==, TC_APDU_OK);
  munit_assert_uint16(out.sw, ==, 0x9000);
  assert_script_done();

  /* 510 bytes: two full fragments. Logical channel 3 stays in every CLA. */
  static char second[HEX_BYTES];
  snprintf(first, sizeof first, "13dbffffff%s", repeat(0x66, 255));
  snprintf(second, sizeof second, "03dbffffff%s", repeat(0x66, 255));
  const tc_script_step two[] = {{first, "9000", {0}, {0}, TC_OK, 0},
                                {second, "01029000", {0}, {0}, TC_OK, 0}};
  channel = start(two, 2, TC_APDU_SHORT, 0);
  command = (TC_APDU_command){{data_bytes, 510}, 0, 0x03, 0xdb, 0xff, 0xff};
  munit_assert_int(run(&channel, &command, 64, &out), ==, TC_APDU_OK);
  munit_assert_size(out.data.length, ==, 2);
  assert_script_done();
  return MUNIT_OK;
}

/* An intermediate answer other than 9000 ends the chain. Warnings and data
 * are prohibited there (5.6). */
TC_TEST(chain_answers)
{
  static const char* const ending[] = {"6883", "6884", "6982", "6a80"};
  static const uint16_t ending_sw[] = {0x6883, 0x6884, 0x6982, 0x6a80};
  static const char* const invalid[] = {"6282", "63c1", "019000", "6000"};
  memset(data_bytes, 0x66, 300);
  TC_APDU_command command = {{data_bytes, 300}, 256, 0x00, 0xdb, 0xff, 0xff};
  TC_APDU_response out;
  for (size_t i = 0; i < 4; ++i) {
    const tc_script_step steps[] = {{NULL, ending[i], {0}, {0}, TC_OK, 0}};
    TC_APDU_channel channel = start(steps, 1, TC_APDU_SHORT, 0);
    munit_assert_int(run(&channel, &command, 64, &out), ==, TC_APDU_OK);
    munit_assert_size(out.data.length, ==, 0);
    munit_assert_uint16(out.sw, ==, ending_sw[i]);
    assert_script_done();
  }
  for (size_t i = 0; i < 4; ++i) {
    const tc_script_step steps[] = {{NULL, invalid[i], {0}, {0}, TC_OK, 0}};
    TC_APDU_channel channel = start(steps, 1, TC_APDU_SHORT, 0);
    out.sw = 0x1234;
    munit_assert_int(run(&channel, &command, 64, &out), ==, TC_APDU_INVALID);
    munit_assert_uint16(out.sw, ==, 0x1234);
    munit_assert_true(tc_test_all_zero(response_bytes, 64));
    assert_script_done();
  }
  return MUNIT_OK;
}

/* A short response buffer returns LIMIT, wipes it and keeps the channel. The
 * card may return more than Ne bytes (TWIC Part 2 v5 5.2 note 2). */
TC_TEST(capacity_limit)
{
  static char overdelivered[80];
  memcpy(overdelivered, repeat(0x21, 10), 21);
  strcat(overdelivered, "9000");
  static char chunk[80];
  memcpy(chunk, repeat(0x22, 16), 33);
  strcat(chunk, "6110");
  const tc_script_step steps[] = {{"00cb3fff055c035fc10204", overdelivered, {0}, {0}, TC_OK, 0},
                                  {NULL, chunk, {0}, {0}, TC_OK, 0},
                                  {"00a4040000", "9000", {0}, {0}, TC_OK, 0}};
  TC_APDU_channel channel = start(steps, 3, TC_APDU_SHORT, 0);
  TC_APDU_command command = get_data(0x00, 4);
  TC_APDU_response out;
  munit_assert_int(run(&channel, &command, 20, &out), ==, TC_APDU_OK);
  munit_assert_size(out.data.length, ==, 10);
  /* 16 bytes arrive with 61 10, and 16 + 2 more do not fit in 20. */
  munit_assert_int(run(&channel, &command, 20, &out), ==, TC_APDU_LIMIT);
  munit_assert_true(tc_test_all_zero(response_bytes, 20));
  munit_assert_size(script.next, ==, 2);
  TC_APDU_command select = {{NULL, 0}, 256, 0x00, 0xa4, 0x04, 0x00};
  munit_assert_int(run(&channel, &select, 20, &out), ==, TC_APDU_OK);
  munit_assert_uint16(out.sw, ==, 0x9000);
  assert_script_done();
  return MUNIT_OK;
}

/* Each transmit consumes one exchange. An exhausted budget returns LIMIT
 * before transmit. */
TC_TEST(exchange_budget)
{
  const tc_script_step steps[] = {{NULL, "6110", {0}, {0}, TC_OK, 0}};
  const TC_APDU_channel_options options = {TC_APDU_SHORT, 0, 1, 0, 0};
  TC_APDU_channel channel = start_options(steps, 1, &options);
  TC_APDU_command command = get_data(0x00, 256);
  TC_APDU_response out;
  munit_assert_int(run(&channel, &command, 64, &out), ==, TC_APDU_LIMIT);
  munit_assert_size(TC_APDU_channel_exchanges_left(&channel), ==, 0);
  munit_assert_int(run(&channel, &command, 64, &out), ==, TC_APDU_LIMIT);
  assert_script_done();
  munit_assert_size(TC_APDU_channel_exchanges_left(NULL), ==, 0);
  return MUNIT_OK;
}

/* Transport failures and broken length reports stop the channel. */
TC_TEST(transport_failures)
{
  const tc_script_step failed[] = {{NULL, NULL, {0}, {0}, TC_ERROR, 0}};
  const tc_script_step long_report[] = {{NULL, "9000", {0}, {0}, TC_OK, 65}};
  const tc_script_step short_report[] = {{NULL, "019000", {0}, {0}, TC_OK, 1}};
  const tc_script_step* const cases[] = {failed, long_report, short_report};
  TC_APDU_command command = get_data(0x00, 256);
  TC_APDU_response out = {{NULL, 0}, 0x4444};
  for (size_t i = 0; i < 3; ++i) {
    TC_APDU_channel channel = start(cases[i], 1, TC_APDU_SHORT, 0);
    munit_assert_int(run(&channel, &command, 64, &out), ==, TC_APDU_ERROR);
    munit_assert_true(tc_test_all_zero(response_bytes, 64));
    memset(response_bytes, 0xee, 64);
    /* A stopped channel sends nothing and leaves the buffer unchanged. */
    munit_assert_int(run(&channel, &command, 64, &out), ==, TC_APDU_ERROR);
    munit_assert_true(tc_test_all_value(response_bytes, 64, 0xee));
    munit_assert_int(TC_APDU_channel_restrict(&channel, 0, 0, 0), ==, TC_APDU_ERROR);
    munit_assert_uint16(out.sw, ==, 0x4444);
    assert_script_done();
  }
  return MUNIT_OK;
}

/* EXTENDED sends one command with extended Lc and respects DO 7F66 limits
 * (12.8.1). */
TC_TEST(extended_channel)
{
  memset(data_bytes, 0x99, 300);
  static char command_hex[HEX_BYTES];
  snprintf(command_hex, sizeof command_hex, "00db3fff00012c%s0000", repeat(0x99, 300));
  const tc_script_step steps[] = {{command_hex, "9000", {0}, {0}, TC_OK, 0}};
  TC_APDU_channel channel = start(steps, 1, TC_APDU_EXTENDED, 0);
  TC_APDU_command command = {{data_bytes, 300}, TC_APDU_MAX_NE, 0x00, 0xdb, 0x3f, 0xff};
  TC_APDU_response out;
  munit_assert_int(run(&channel, &command, 64, &out), ==, TC_APDU_OK);
  assert_script_done();

  /* 309 encoded bytes exceed max_command_bytes 308. */
  const TC_APDU_channel_options limited = {TC_APDU_EXTENDED, 0, 4, 308, 0};
  channel = start_options(steps, 1, &limited);
  munit_assert_int(run(&channel, &command, 64, &out), ==, TC_APDU_LIMIT);
  munit_assert_size(script.next, ==, 0);

  /* Ne above max_response_bytes - 2 is lowered. */
  const tc_script_step clamped[] = {{"00cb3fff055c035fc10264", "9000", {0}, {0}, TC_OK, 0}};
  const TC_APDU_channel_options responses = {TC_APDU_EXTENDED, 0, 4, 0, 102};
  channel = start_options(clamped, 1, &responses);
  command = get_data(0x00, TC_APDU_MAX_NE);
  munit_assert_int(run(&channel, &command, 64, &out), ==, TC_APDU_OK);
  assert_script_done();
  return MUNIT_OK;
}

/* restrict only tightens limits and replaces the flags. */
TC_TEST(restrict_limits)
{
  memset(data_bytes, 0x99, 300);
  const tc_script_step steps[] = {{NULL, "9000", {0}, {0}, TC_OK, 0},
                                  {"0ccb3fff055c035fc10200", "610a", {0}, {0}, TC_OK, 0},
                                  {"00c000000a", "9000", {0}, {0}, TC_OK, 0}};
  const TC_APDU_channel_options options = {TC_APDU_EXTENDED, 0, 8, 400, 0};
  TC_APDU_channel channel = start_options(steps, 3, &options);
  TC_APDU_command command = {{data_bytes, 300}, 0, 0x00, 0xdb, 0x3f, 0xff};
  TC_APDU_response out;
  munit_assert_int(TC_APDU_channel_restrict(&channel, 1000, 0, 0), ==, TC_APDU_OK);
  munit_assert_int(run(&channel, &command, 64, &out), ==, TC_APDU_OK);
  munit_assert_int(TC_APDU_channel_restrict(&channel, 300, 0, TC_APDU_GET_RESPONSE_PLAIN_CLA), ==,
                   TC_APDU_OK);
  munit_assert_int(TC_APDU_channel_restrict(&channel, 0, 0, TC_APDU_GET_RESPONSE_PLAIN_CLA), ==,
                   TC_APDU_OK);
  munit_assert_int(run(&channel, &command, 64, &out), ==, TC_APDU_LIMIT);
  TC_APDU_command sm = get_data(0x0c, 256);
  munit_assert_int(run(&channel, &sm, 64, &out), ==, TC_APDU_OK);
  assert_script_done();

  munit_assert_int(TC_APDU_channel_restrict(NULL, 0, 0, 0), ==, TC_APDU_ARGUMENT);
  munit_assert_int(TC_APDU_channel_restrict(&channel, 0, 0, 4), ==, TC_APDU_ARGUMENT);
  munit_assert_int(TC_APDU_channel_restrict(&channel, 3, 0, 0), ==, TC_APDU_ARGUMENT);
  munit_assert_int(TC_APDU_channel_restrict(&channel, 0, 2, 0), ==, TC_APDU_ARGUMENT);
  return MUNIT_OK;
}

TC_TEST(init_arguments)
{
  const tc_script_step steps[] = {{NULL, "9000", {0}, {0}, TC_OK, 0}};
  tc_script_init(&script, steps, 1);
  const TC_APDU_transport transport = tc_script_transport(&script);
  const TC_APDU_transport missing = {NULL, &script};
  const TC_buffer buffer = {scratch, sizeof scratch};
  TC_APDU_channel channel;
  memset(&channel, 0x5a, sizeof channel);
  const TC_APDU_channel_options good = {TC_APDU_SHORT, 0, 1, 0, 0};
  const TC_APDU_channel_options bad[] = {{(TC_APDU_length_format)2, 0, 1, 0, 0},
                                         {TC_APDU_SHORT, 4, 1, 0, 0},
                                         {TC_APDU_SHORT, 0, 0, 0, 0},
                                         {TC_APDU_SHORT, 0, 1, 3, 0},
                                         {TC_APDU_SHORT, 0, 1, 0, 2}};
  munit_assert_int(TC_APDU_channel_init(NULL, transport, &good, buffer), ==, TC_APDU_ARGUMENT);
  munit_assert_int(TC_APDU_channel_init(&channel, transport, NULL, buffer), ==, TC_APDU_ARGUMENT);
  munit_assert_int(TC_APDU_channel_init(&channel, missing, &good, buffer), ==, TC_APDU_ARGUMENT);
  munit_assert_int(TC_APDU_channel_init(&channel, transport, &good, (TC_buffer){NULL, 8}), ==,
                   TC_APDU_ARGUMENT);
  munit_assert_int(TC_APDU_channel_init(&channel, transport, &good, (TC_buffer){scratch, 3}), ==,
                   TC_APDU_ARGUMENT);
  munit_assert_int(TC_APDU_channel_init(&channel, transport, &good,
                                        (TC_buffer){(uint8_t*)&channel, sizeof channel}),
                   ==, TC_APDU_ARGUMENT);
  for (size_t i = 0; i < sizeof bad / sizeof *bad; ++i)
    munit_assert_int(TC_APDU_channel_init(&channel, transport, &bad[i], buffer), ==,
                     TC_APDU_ARGUMENT);
  size_t pattern;
  memset(&pattern, 0x5a, sizeof pattern);
  munit_assert_size(channel.exchanges_left, ==, pattern);
  munit_assert_size(channel.scratch_capacity, ==, pattern);
  munit_assert_uint8(channel.stopped, ==, 0x5a);
  return MUNIT_OK;
}

TC_TEST(transceive_arguments)
{
  const tc_script_step steps[] = {{NULL, "9000", {0}, {0}, TC_OK, 0}};
  TC_APDU_channel channel = start(steps, 1, TC_APDU_SHORT, 0);
  TC_APDU_command command = get_data(0x00, 256);
  TC_APDU_response out = {{NULL, 0}, 0x4444};
  const TC_buffer response = {response_bytes, 64};
  munit_assert_int(TC_APDU_transceive(NULL, &command, response, &out), ==, TC_APDU_ARGUMENT);
  munit_assert_int(TC_APDU_transceive(&channel, NULL, response, &out), ==, TC_APDU_ARGUMENT);
  munit_assert_int(TC_APDU_transceive(&channel, &command, response, NULL), ==, TC_APDU_ARGUMENT);
  munit_assert_int(TC_APDU_transceive(&channel, &command, (TC_buffer){NULL, 64}, &out), ==,
                   TC_APDU_ARGUMENT);
  munit_assert_int(TC_APDU_transceive(&channel, &command, (TC_buffer){response_bytes, 1}, &out), ==,
                   TC_APDU_ARGUMENT);
  /* The response overlaps the scratch, and the command data overlaps the
   * response or the scratch. */
  munit_assert_int(TC_APDU_transceive(&channel, &command, (TC_buffer){scratch, 64}, &out), ==,
                   TC_APDU_ARGUMENT);
  TC_APDU_command aliased = command;
  aliased.data = (TC_bytes){response_bytes + 8, 4};
  munit_assert_int(TC_APDU_transceive(&channel, &aliased, response, &out), ==, TC_APDU_ARGUMENT);
  aliased.data = (TC_bytes){scratch + 8, 4};
  munit_assert_int(TC_APDU_transceive(&channel, &aliased, response, &out), ==, TC_APDU_ARGUMENT);
  aliased = command;
  aliased.cla = 0x10;
  munit_assert_int(TC_APDU_transceive(&channel, &aliased, response, &out), ==, TC_APDU_ARGUMENT);
  aliased.cla = 0x80;
  munit_assert_int(TC_APDU_transceive(&channel, &aliased, response, &out), ==, TC_APDU_UNSUPPORTED);
  aliased = command;
  aliased.ne = 257;
  munit_assert_int(TC_APDU_transceive(&channel, &aliased, response, &out), ==, TC_APDU_ARGUMENT);
  munit_assert_true(tc_test_all_value(response_bytes, 64, 0xee));
  munit_assert_uint16(out.sw, ==, 0x4444);
  munit_assert_size(script.next, ==, 0);
  munit_assert_int(TC_APDU_transceive(&channel, &command, response, &out), ==, TC_APDU_OK);
  assert_script_done();

  /* clear wipes the scratch and leaves an unusable channel. */
  memset(scratch, 0x42, sizeof scratch);
  TC_APDU_channel_clear(&channel);
  TC_APDU_channel_clear(NULL);
  munit_assert_true(tc_test_all_zero(scratch, sizeof scratch));
  munit_assert_true(channel.transport.transmit == NULL);
  munit_assert_null(channel.scratch);
  munit_assert_size(channel.scratch_capacity, ==, 0);
  munit_assert_size(TC_APDU_channel_exchanges_left(&channel), ==, 0);
  munit_assert_int(TC_APDU_transceive(&channel, &command, response, &out), ==, TC_APDU_ARGUMENT);
  munit_assert_int(TC_APDU_channel_restrict(&channel, 0, 0, 0), ==, TC_APDU_ARGUMENT);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  static MunitTest tests[] = {
      {"/response-chaining", response_chaining, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/get-response-le", get_response_le, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/get-response-class", get_response_class, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/wrong-length-correction", wrong_length_correction, NULL, NULL, MUNIT_TEST_OPTION_NONE,
       NULL},
      {"/wrong-length-reported", wrong_length_reported, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/wrong-length-without-le", wrong_length_without_le, NULL, NULL, MUNIT_TEST_OPTION_NONE,
       NULL},
      {"/chain-preflight", chain_preflight, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/command-chaining", command_chaining, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/chain-answers", chain_answers, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/capacity-limit", capacity_limit, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/exchange-budget", exchange_budget, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/transport-failures", transport_failures, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/extended-channel", extended_channel, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/restrict-limits", restrict_limits, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/init-arguments", init_arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/transceive-arguments", transceive_arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  static const MunitSuite suite = {"/apdu/channel", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
