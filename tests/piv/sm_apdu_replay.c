/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Byte-exact wire replay of PIV secure messaging sessions through the
 * library link (SP 800-73-5 Part 2 4.1 and 4.2). tests/piv/sm_corpus.py and
 * tests/piv/synthetic_sm.py write the transcript, one record per line:
 *
 *   select COMMAND ANSWER            plain SELECT and its answer with SW
 *   begin SUITE SCALAR HOST COMMAND  key establishment inputs and the
 *                                    expected GENERAL AUTHENTICATE command
 *   finish ANSWER MATERIAL           its answer data and the derived keys
 *   state COUNTER CMD_MCV RESP_MCV   session state, - for an unknown field
 *   command INS P1 P2 NE DATA ANSWER SW
 *                                    one logical command: plain data, the
 *                                    expected plaintext answer and inner SW
 *   wire COMMAND ANSWER              one expected APDU of that command
 *   end                              run the logical command
 *
 * Hex fields use - for empty. The transport fails on any byte that differs
 * from the next wire record. */
#include <tiny_crypto/piv_cvc.h>
#include <tiny_crypto/piv_sm_apdu.h>
#include "cavp.h"
#include "munit.h"
#include "piv_link_internal.h"
#include "test_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
  WIRE_MAX = 96,
  WIRE_BYTES = 300,
  DATA_BYTES = 16384,
  SM_SCRATCH_BYTES = 1024,
  RESPONSE_BYTES = 16384,
  FIELDS_MAX = 9
};

typedef struct {
  uint8_t command[WIRE_BYTES], answer[WIRE_BYTES];
  size_t command_length, answer_length;
} wire_record;

/* The expected exchanges of one logical command, or of SELECT and key
 * establishment when those records are active. */
typedef struct {
  wire_record records[WIRE_MAX];
  size_t count, next, mismatch;
  const uint8_t* plain_command;
  size_t plain_command_length;
  const uint8_t* plain_answer;
  size_t plain_answer_length;
} replay_transport;

static const char* transcript_path;
static replay_transport transport;
static uint8_t scalar[48];
static char line[131072];

static TC_status replay_transmit(void* context, TC_bytes command, TC_buffer response,
                                 size_t* length)
{
  replay_transport* replay = context;
  if (replay->plain_command) {
    /* SELECT or key establishment: one exchange. */
    const int same = command.length == replay->plain_command_length &&
                     !memcmp(command.data, replay->plain_command, command.length);
    replay->plain_command = NULL;
    if (!same || replay->plain_answer_length > response.capacity) {
      replay->mismatch = 1;
      return TC_ERROR;
    }
    memcpy(response.data, replay->plain_answer, replay->plain_answer_length);
    *length = replay->plain_answer_length;
    return TC_OK;
  }
  if (replay->next >= replay->count) {
    replay->mismatch = replay->next + 1;
    return TC_ERROR;
  }
  const wire_record* record = &replay->records[replay->next++];
  if (command.length != record->command_length ||
      memcmp(command.data, record->command, command.length) ||
      record->answer_length > response.capacity) {
    replay->mismatch = replay->next;
    return TC_ERROR;
  }
  memcpy(response.data, record->answer, record->answer_length);
  *length = record->answer_length;
  return TC_OK;
}

static size_t decode(const char* hex, uint8_t* output, size_t capacity)
{
  size_t length = 0;
  if (!strcmp(hex, "-"))
    return 0;
  munit_assert_true(tc_test_hex_decode(hex, TC_TEST_HEX_FIELD, output, capacity, &length));
  return length;
}

static TC_status recorded_random(void* context, uint8_t* output, size_t length)
{
  (void)context;
  memcpy(output, scalar, length);
  return TC_OK;
}

static void state_check(const TC_PIV_SM* session, char* const* fields)
{
  const uint8_t* values[] = {session->data.traffic.counter, session->data.traffic.command_mcv,
                             session->data.traffic.response_mcv};
  for (size_t i = 0; i < 3; ++i) {
    uint8_t expected[16];
    if (!strcmp(fields[i], "-"))
      continue;
    munit_assert_size(decode(fields[i], expected, sizeof expected), ==, 16);
    munit_assert_memory_equal(16, values[i], expected);
  }
}

/* Replay state across the records of one transcript. */
typedef struct {
  TC_PIV_link link;
  TC_PIV_SM session;
  TC_PIV_SM_workspace workspace;
  TC_PIV_SM_suite suite;
  uint8_t host[8];
  uint8_t key_command[128];
  size_t key_command_length;
  uint8_t data[DATA_BYTES], answer[DATA_BYTES], response[RESPONSE_BYTES];
  uint8_t scratch[TC_APDU_SHORT_COMMAND_MAX_BYTES], sm_scratch[SM_SCRATCH_BYTES];
  TC_APDU_command command;
  size_t answer_length;
  uint16_t inner_sw;
  size_t commands;
} replay_state;

static void replay_select(replay_state* state, char* const* fields)
{
  static const TC_PIV_link_options options = {{TC_APDU_SHORT, 0, 100000, 0, 0}, TC_PIV_CONTACT, 0};
  TC_PIV_application application;
  const size_t command_length = decode(fields[0], state->data, sizeof state->data);
  const size_t answer_length = decode(fields[1], state->answer, sizeof state->answer);
  munit_assert_int(TC_PIV_link_init(&state->link, (TC_APDU_transport){replay_transmit, &transport},
                                    &options, (TC_buffer){state->scratch, sizeof state->scratch}),
                   ==, TC_PIV_OK);
  transport.plain_command = state->data;
  transport.plain_command_length = command_length;
  transport.plain_answer = state->answer;
  transport.plain_answer_length = answer_length;
  munit_assert_int(TC_PIV_select(&state->link, TC_PIV_APPLICATION_PIV, 0,
                                 (TC_buffer){state->response, sizeof state->response},
                                 &application),
                   ==, TC_PIV_OK);
  munit_assert_size(transport.mismatch, ==, 0);
}

static void replay_begin(replay_state* state, char* const* fields)
{
  state->suite = (TC_PIV_SM_suite)strtoul(fields[0], NULL, 16);
  munit_assert_size(decode(fields[1], scalar, sizeof scalar), ==,
                    state->suite == TC_PIV_SM_CS2 ? 32 : 48);
  munit_assert_size(decode(fields[2], state->host, sizeof state->host), ==, 8);
  state->key_command_length = decode(fields[3], state->key_command, sizeof state->key_command);
}

/* Key establishment through the link, then key confirmation with the CVC
 * key and the link secured. */
static void replay_finish(replay_state* state, char* const* fields)
{
  uint8_t material[128];
  TC_PIV_SM_peer peer;
  TC_PIV_CVC cvc;
  size_t length = decode(fields[0], state->answer, sizeof state->answer - 2);
  const size_t key_bytes = state->suite == TC_PIV_SM_CS2 ? 16 : 32;
  state->answer[length++] = 0x90;
  state->answer[length++] = 0x00;
  munit_assert_size(decode(fields[1], material, sizeof material), ==, 4 * key_bytes);
  transport.plain_command = state->key_command;
  transport.plain_command_length = state->key_command_length;
  transport.plain_answer = state->answer;
  transport.plain_answer_length = length;
  munit_assert_int(TC_PIV_SM_key_request(&state->link, &state->session, state->suite, state->host,
                                         (TC_random_source){recorded_random, NULL},
                                         (TC_buffer){state->response, sizeof state->response},
                                         &peer, &state->workspace),
                   ==, TC_PIV_OK);
  munit_assert_size(transport.mismatch, ==, 0);
  munit_assert_int(TC_PIV_CVC_read(peer.certificate, &cvc), ==, TC_TLV_OK);
  munit_assert_int(TC_PIV_SM_finish(&state->session, &peer, cvc.public_key, &state->workspace), ==,
                   TC_OK);
  munit_assert_memory_equal(key_bytes, state->session.data.traffic.mac_key, material + key_bytes);
  munit_assert_memory_equal(key_bytes, state->session.data.traffic.enc_key,
                            material + 2 * key_bytes);
  munit_assert_memory_equal(key_bytes, state->session.data.traffic.rmac_key,
                            material + 3 * key_bytes);
  munit_assert_int(TC_PIV_link_secure(&state->link, &state->workspace,
                                      (TC_buffer){state->sm_scratch, sizeof state->sm_scratch}),
                   ==, TC_PIV_OK);
}

static void replay_command(replay_state* state, char* const* fields)
{
  const uint32_t ne = (uint32_t)strtoul(fields[3], NULL, 10);
  state->command = (TC_APDU_command){{state->data, decode(fields[4], state->data, DATA_BYTES)},
                                     ne,
                                     0x00,
                                     (uint8_t)strtoul(fields[0], NULL, 16),
                                     (uint8_t)strtoul(fields[1], NULL, 16),
                                     (uint8_t)strtoul(fields[2], NULL, 16)};
  state->answer_length = decode(fields[5], state->answer, sizeof state->answer);
  state->inner_sw = (uint16_t)strtoul(fields[6], NULL, 16);
  transport.count = transport.next = transport.mismatch = 0;
}

static void replay_wire(char* const* fields)
{
  munit_assert_size(transport.count, <, WIRE_MAX);
  wire_record* record = &transport.records[transport.count++];
  record->command_length = decode(fields[0], record->command, sizeof record->command);
  record->answer_length = decode(fields[1], record->answer, sizeof record->answer);
}

static void replay_end(replay_state* state)
{
  TC_APDU_response out;
  const TC_PIV_command kind = state->command.ins == 0xcb   ? TC_PIV_COMMAND_GET_DATA
                              : state->command.ins == 0x20 ? TC_PIV_COMMAND_VERIFY
                                                           : TC_PIV_COMMAND_GENERAL_AUTHENTICATE;
  munit_assert_int(tc_piv_link_transceive(&state->link, kind, &state->command,
                                          (TC_buffer){state->response, sizeof state->response},
                                          &out),
                   ==, TC_PIV_OK);
  munit_assert_size(transport.mismatch, ==, 0);
  munit_assert_size(transport.next, ==, transport.count);
  munit_assert_uint16(out.sw, ==, state->inner_sw);
  munit_assert_size(out.data.length, ==, state->answer_length);
  munit_assert_memory_equal(state->answer_length, out.data.data, state->answer);
  ++state->commands;
}

static int split(char* text, char** fields)
{
  int count = 0;
  for (char* token = strtok(text, " \t\r\n"); token; token = strtok(NULL, " \t\r\n")) {
    munit_assert_int(count, <, FIELDS_MAX);
    fields[count++] = token;
  }
  return count;
}

TC_TEST(replay)
{
  static replay_state state;
  if (!transcript_path)
    return MUNIT_SKIP;
  FILE* file = fopen(transcript_path, "r");
  munit_assert_not_null(file);
  memset(&state, 0, sizeof state);
  while (fgets(line, sizeof line, file)) {
    char* fields[FIELDS_MAX];
    const int count = split(line, fields);
    munit_assert_int(count, >, 0);
    const char* kind = fields[0];
    if (!strcmp(kind, "select") && count == 3)
      replay_select(&state, fields + 1);
    else if (!strcmp(kind, "begin") && count == 5)
      replay_begin(&state, fields + 1);
    else if (!strcmp(kind, "finish") && count == 3)
      replay_finish(&state, fields + 1);
    else if (!strcmp(kind, "state") && count == 4)
      state_check(&state.session, fields + 1);
    else if (!strcmp(kind, "command") && count == 8)
      replay_command(&state, fields + 1);
    else if (!strcmp(kind, "wire") && count == 3)
      replay_wire(fields + 1);
    else if (!strcmp(kind, "end") && count == 1)
      replay_end(&state);
    else
      munit_errorf("Unknown transcript record %s with %d fields", kind, count);
  }
  munit_assert_int(ferror(file), ==, 0);
  fclose(file);
  munit_assert_size(state.commands, >, 0);
  TC_PIV_link_clear(&state.link);
  munit_assert_true(tc_test_all_zero(&state.session, sizeof state.session));
  printf("%zu protected commands replayed\n", state.commands);
  return MUNIT_OK;
}

static MunitTest tests[] = {{"/replay", replay, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                            {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
static const MunitSuite suite = {"/piv-sm-apdu", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[])
{
  if (argc == 3 && strcmp(argv[1], "--transcript") == 0) {
    char* args[] = {argv[0], (char*)"/piv-sm-apdu/replay", NULL};
    transcript_path = argv[2];
    return munit_suite_main(&suite, NULL, 2, args);
  }
  return munit_suite_main(&suite, NULL, argc, argv);
}
