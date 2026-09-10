/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/piv_sm.h>
#include "../../examples/piv_sm_wire.h"
#include "munit.h"
#include "test_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { uint8_t scalar[48]; unsigned calls, zeros, fail; } random_state;
static const char* transcript_path;

static TC_status fixed_random(void* user, uint8_t* output, size_t length)
{
  random_state* state = (random_state*)user;
  ++state->calls;
  if (state->fail) return TC_ERROR;
  if (state->calls <= state->zeros) memset(output, 0, length);
  else memcpy(output, state->scalar, length);
  return TC_OK;
}

static MunitResult begin_failures(const MunitParameter params[], void* user)
{
  TC_PIV_SM session = {0}, saved;
  TC_PIV_SM_workspace w;
  random_state random = {{0}, 0, 0, 0};
  uint8_t request[118], expected[118], host[8] = {0};
  size_t written = 999;
#if TC_PIV_SM_ENABLE_CS2
  const TC_PIV_SM_suite selected = TC_PIV_SM_CS2;
  const size_t scalar_length = 32, request_length = 86;
#else
  const TC_PIV_SM_suite selected = TC_PIV_SM_CS7;
  const size_t scalar_length = 48, request_length = 118;
#endif
  (void)params; (void)user;
  memset(request, 0xa5, sizeof request); memcpy(expected, request, sizeof expected);
  random.scalar[scalar_length - 1] = 1;
  saved = session;
  munit_assert_int(example_piv_sm_begin(&session, selected, host, fixed_random, &random,
                                  request, request_length - 1, &written, &w), ==, TC_ERROR);
  munit_assert_uint(random.calls, ==, 0);
  munit_assert_size(written, ==, 999);
  munit_assert_memory_equal(sizeof session, &session, &saved);
  munit_assert_memory_equal(sizeof request, request, expected);
#if !TC_PIV_SM_ENABLE_CS2 || !TC_PIV_SM_ENABLE_CS7
  {
    const TC_PIV_SM_suite disabled = selected == TC_PIV_SM_CS2 ? TC_PIV_SM_CS7 : TC_PIV_SM_CS2;
    munit_assert_int(example_piv_sm_begin(&session, disabled, host, fixed_random, &random,
                                    request, sizeof request, &written, &w), ==, TC_ERROR);
    munit_assert_uint(random.calls, ==, 0);
    munit_assert_size(written, ==, 999);
    munit_assert_memory_equal(sizeof session, &session, &saved);
    munit_assert_memory_equal(sizeof request, request, expected);
  }
#endif
  random.zeros = 16;
  munit_assert_int(example_piv_sm_begin(&session, selected, host, fixed_random, &random,
                                  request, sizeof request, &written, &w), ==, TC_ERROR);
  munit_assert_uint(random.calls, ==, 16);
  munit_assert_true(tc_test_all_zero(&session, sizeof session));
  munit_assert_true(tc_test_all_zero(&w, sizeof w));
  munit_assert_memory_equal(sizeof request, request, expected);
  random.calls = 0; random.zeros = 1;
  munit_assert_int(example_piv_sm_begin(&session, selected, host, fixed_random, &random,
                                  request, sizeof request, &written, &w), ==, TC_OK);
  munit_assert_uint(random.calls, ==, 2);
  munit_assert_size(written, ==, request_length);
  munit_assert_uint(session.state, ==, TC_PIV_SM_ESTABLISHING);
  random.fail = 1;
  munit_assert_int(example_piv_sm_begin(&session, selected, host, fixed_random, &random,
                                  request, sizeof request, &written, &w), ==, TC_ERROR);
  munit_assert_true(tc_test_all_zero(&session, sizeof session));
  TC_PIV_SM_clear(NULL);
  return MUNIT_OK;
}

static size_t decode(const char* hex, uint8_t* output, size_t capacity)
{
  size_t length;
  if (strcmp(hex, "-") == 0) return 0;
  length = tc_test_decode_hex(hex, output, capacity);
  munit_assert_size(length, ==, strlen(hex) / 2);
  munit_assert_size(strlen(hex) % 2, ==, 0);
  return length;
}

static void pending_session(TC_PIV_SM* session, TC_PIV_SM_suite suite)
{
  TC_PIV_SM_workspace w;
  const ExamplePIVSMCommand command = {{NULL, 0}, 0x20, 0, 0x80, 0};
  uint8_t output[16];
  size_t written;
  memset(session, 0, sizeof *session);
  session->suite = (uint8_t)suite; session->state = TC_PIV_SM_READY;
  session->data.traffic.counter[15] = 1;
  munit_assert_int(example_piv_sm_protect(session, &command, output, sizeof output, &written, &w), ==, TC_OK);
  munit_assert_size(written, ==, 10);
}

static size_t make_response(const TC_PIV_SM* session, size_t plain_length, int bad_padding, uint8_t* output)
{
  TC_AES_dynamic_key key;
  TC_AES_dynamic_CMAC mac;
  uint8_t iv[16] = {0x80}, tag[16];
  size_t i, padded = plain_length + 16 - plain_length % 16, at;
  const size_t key_length = session->suite == TC_PIV_SM_CS2 ? 16 : 32;
  iv[15] = 1;
  output[0] = 0x87; output[1] = (uint8_t)(padded + 1); output[2] = 1;
  for (i = 0; i < plain_length; ++i) output[3 + i] = (uint8_t)i;
  output[3 + plain_length] = bad_padding ? 0x81 : 0x80;
  memset(output + 4 + plain_length, 0, padded - plain_length - 1);
  munit_assert_int(TC_AES_dynamic_key_init(&key, session->data.traffic.enc_key, key_length), ==, TC_OK);
  munit_assert_int(TC_AES_dynamic_encrypt(&key, iv), ==, TC_OK);
  munit_assert_int(TC_AES_dynamic_CBC_encrypt(&key, iv, output + 3, padded), ==, TC_OK);
  TC_AES_dynamic_key_clear(&key);
  at = 3 + padded;
  output[at++] = 0x99; output[at++] = 2; output[at++] = 0x90; output[at++] = 0;
  munit_assert_int(TC_AES_dynamic_CMAC_init(&mac, session->data.traffic.rmac_key, key_length), ==, TC_OK);
  munit_assert_int(TC_AES_dynamic_CMAC_update(&mac, session->data.traffic.response_mcv, 16), ==, TC_OK);
  munit_assert_int(TC_AES_dynamic_CMAC_update(&mac, output, at), ==, TC_OK);
  munit_assert_int(TC_AES_dynamic_CMAC_final(&mac, tag), ==, TC_OK);
  output[at++] = 0x8e; output[at++] = 8;
  memcpy(output + at, tag, 8);
  return at + 8;
}

static MunitResult response_failures(const MunitParameter params[], void* user)
{
  static const size_t lengths[] = {0, 1, 15, 16, 17, 31, 32};
  const TC_PIV_SM_suite suites[] = {
#if TC_PIV_SM_ENABLE_CS2
    TC_PIV_SM_CS2,
#endif
#if TC_PIV_SM_ENABLE_CS7
    TC_PIV_SM_CS7,
#endif
  };
  TC_PIV_SM session, saved;
  TC_PIV_SM_workspace w;
  ExamplePIVSMResult result, saved_result;
  uint8_t response[128], output[64], expected[64], plain[64];
  size_t s, i, j, length;
  (void)params; (void)user;
  tc_test_fill_incrementing(plain, sizeof plain);
  memset(expected, 0xa5, sizeof expected);
  memset(&saved_result, 0xa5, sizeof saved_result);
  for (s = 0; s < sizeof suites / sizeof suites[0]; ++s) {
    for (i = 0; i < sizeof lengths / sizeof lengths[0]; ++i) {
      pending_session(&session, suites[s]); saved = session;
      length = make_response(&session, lengths[i], 0, response);
      memcpy(output, expected, sizeof output); result = saved_result;
      if (lengths[i]) {
        munit_assert_int(example_piv_sm_unprotect(&session, (TC_bytes){response,length}, 0x9000,
                                          output, lengths[i] - 1, &result, &w), ==, TC_ERROR);
        munit_assert_memory_equal(sizeof session, &session, &saved);
        munit_assert_memory_equal(sizeof result, &result, &saved_result);
        munit_assert_memory_equal(sizeof output, output, expected);
      }
      munit_assert_int(example_piv_sm_unprotect(&session, (TC_bytes){response,length}, 0x9000,
                                        output, lengths[i], &result, &w), ==, TC_OK);
      munit_assert_size(result.length, ==, lengths[i]);
      munit_assert_uint(result.status, ==, 0x9000);
      munit_assert_memory_equal(lengths[i], output, plain);
      munit_assert_uint8(output[lengths[i]], ==, 0xa5);
      munit_assert_true(tc_test_all_zero(&w, sizeof w));
    }
    pending_session(&session, suites[s]); saved = session;
    length = make_response(&session, 17, 0, response);
    memcpy(output, expected, sizeof output);
    for (i = 0; i < 64; ++i) {
      session = saved; result = saved_result;
      response[length - 8 + i / 8] ^= (uint8_t)(1u << (i % 8));
      munit_assert_int(example_piv_sm_unprotect(&session, (TC_bytes){response,length}, 0x9000,
                                        output, sizeof output, &result, &w), ==, TC_MISMATCH);
      response[length - 8 + i / 8] ^= (uint8_t)(1u << (i % 8));
      munit_assert_true(tc_test_all_zero(&session, sizeof session));
      munit_assert_true(tc_test_all_zero(&w, sizeof w));
      munit_assert_memory_equal(sizeof output, output, expected);
      munit_assert_memory_equal(sizeof result, &result, &saved_result);
    }
    for (j = 0; j < length; ++j) {
      session = saved; result = saved_result;
      munit_assert_int(example_piv_sm_unprotect(&session, (TC_bytes){response,j}, 0x9000,
                                        output, sizeof output, &result, &w), ==, TC_ERROR);
      munit_assert_true(tc_test_all_zero(&session, sizeof session));
      munit_assert_memory_equal(sizeof output, output, expected);
      munit_assert_memory_equal(sizeof result, &result, &saved_result);
    }
    session = saved;
    munit_assert_int(example_piv_sm_unprotect(&session, (TC_bytes){response,length}, 0x6988,
                                      output, sizeof output, &result, &w), ==, TC_ERROR);
    munit_assert_true(tc_test_all_zero(&session, sizeof session));
    session = saved;
    length = make_response(&session, 17, 1, response);
    munit_assert_int(example_piv_sm_unprotect(&session, (TC_bytes){response,length}, 0x9000,
                                      output, sizeof output, &result, &w), ==, TC_ERROR);
    munit_assert_true(tc_test_all_zero(&session, sizeof session));
    munit_assert_memory_equal(sizeof output, output, expected);
    session = saved;
    {
      const ExamplePIVSMCommand command = {{NULL, 0}, 0x20, 0, 0x80, 0};
      size_t written = 999;
      munit_assert_int(example_piv_sm_protect(&session, &command, output, sizeof output, &written, &w), ==, TC_ERROR);
      munit_assert_memory_equal(sizeof session, &session, &saved);
      munit_assert_size(written, ==, 999);
      session.state = TC_PIV_SM_READY; session.data.traffic.counter[0] = 1;
      munit_assert_int(example_piv_sm_protect(&session, &command, output, sizeof output, &written, &w), ==, TC_ERROR);
      munit_assert_true(tc_test_all_zero(&session, sizeof session));
      munit_assert_memory_equal(sizeof output, output, expected);
    }
  }
  return MUNIT_OK;
}

static MunitResult replay(const MunitParameter params[], void* user)
{
  static char line[131072];
  static uint8_t data[32768], expected[32768], output[32768];
  TC_PIV_SM session = {0};
  TC_PIV_SM_workspace w;
  random_state random = {{0}, 0, 0, 0};
  FILE* file;
  size_t lines = 0;
  (void)params; (void)user;
  if (!transcript_path) return MUNIT_SKIP;
  file = fopen(transcript_path, "r");
  munit_assert_not_null(file);
  while (fgets(line, sizeof line, file)) {
    char* fields[8];
    size_t count = 0, length, expected_length, written = 0;
    char* token = strtok(line, " \t\r\n");
    while (token) {
      munit_assert_size(count, <, 8);
      fields[count++] = token;
      token = strtok(NULL, " \t\r\n");
    }
    munit_assert_size(count, >, 0);
    ++lines;
    if (strcmp(fields[0], "begin") == 0) {
      uint8_t host[8];
      TC_PIV_SM_suite suite;
      munit_assert_size(count, ==, 5);
      suite = (TC_PIV_SM_suite)strtoul(fields[1], NULL, 16);
      length = decode(fields[2], random.scalar, sizeof random.scalar);
      munit_assert_size(length, ==, suite == TC_PIV_SM_CS2 ? 32 : 48);
      munit_assert_size(decode(fields[3], host, sizeof host), ==, 8);
      expected_length = decode(fields[4], expected, sizeof expected);
      munit_assert_int(example_piv_sm_begin(&session, suite, host, fixed_random, &random,
                                      output, sizeof output, &written, &w), ==, TC_OK);
      munit_assert_size(written, ==, expected_length);
      munit_assert_memory_equal(written, output, expected);
    } else if (strcmp(fields[0], "finish") == 0) {
      ExamplePIVSMResponse parsed;
      uint8_t material[128];
      size_t key_length = session.suite == TC_PIV_SM_CS2 ? 16 : 32;
      munit_assert_size(count, ==, 3);
      length = decode(fields[1], data, sizeof data);
      munit_assert_size(decode(fields[2], material, sizeof material), ==, 4 * key_length);
      munit_assert_int(example_piv_sm_response_read((TC_PIV_SM_suite)session.suite,
        (TC_bytes){data,length},&parsed), ==, TC_OK);
      {
        TC_PIV_SM trial;
        ExamplePIVSMResponse probe, unchanged;
        uint8_t wrong_key[97];
        TC_bytes authenticated = {wrong_key, parsed.cvc.public_key.length};
        size_t prefix, cryptogram = (size_t)(parsed.peer.cryptogram.data - data);
        memset(&unchanged, 0xa5, sizeof unchanged);
        for (prefix = 0; prefix < length; ++prefix) {
          probe = unchanged;
          munit_assert_int(example_piv_sm_response_read((TC_PIV_SM_suite)session.suite,
            (TC_bytes){data,prefix},&probe), ==, TC_ERROR);
          munit_assert_memory_equal(sizeof probe, &probe, &unchanged);
        }
        memcpy(wrong_key, parsed.cvc.public_key.data, authenticated.length);
        wrong_key[1] ^= 1;
        trial = session;
        munit_assert_int(example_piv_sm_finish(&trial,(TC_bytes){data,length},0x9000,authenticated,&w), ==, TC_MISMATCH);
        munit_assert_true(tc_test_all_zero(&trial, sizeof trial));
        trial = session;
        data[cryptogram] ^= 1;
        munit_assert_int(example_piv_sm_finish(&trial,(TC_bytes){data,length},0x9000,parsed.cvc.public_key,&w), ==, TC_MISMATCH);
        data[cryptogram] ^= 1;
        munit_assert_true(tc_test_all_zero(&trial, sizeof trial));
        trial = session;
        munit_assert_int(example_piv_sm_finish(&trial,(TC_bytes){data,length},0x6988,parsed.cvc.public_key,&w), ==, TC_ERROR);
        munit_assert_true(tc_test_all_zero(&trial, sizeof trial));
      }
      munit_assert_int(example_piv_sm_finish(&session,(TC_bytes){data,length},0x9000,parsed.cvc.public_key,&w), ==, TC_OK);
      munit_assert_uint(session.state, ==, TC_PIV_SM_READY);
      munit_assert_memory_equal(key_length, session.data.traffic.mac_key, material + key_length);
      munit_assert_memory_equal(key_length, session.data.traffic.enc_key, material + 2 * key_length);
      munit_assert_memory_equal(key_length, session.data.traffic.rmac_key, material + 3 * key_length);
    } else if (strcmp(fields[0], "command") == 0) {
      ExamplePIVSMCommand command;
      munit_assert_size(count, ==, 7);
      command.ins = (uint8_t)strtoul(fields[1], NULL, 16);
      command.p1 = (uint8_t)strtoul(fields[2], NULL, 16);
      command.p2 = (uint8_t)strtoul(fields[3], NULL, 16);
      command.has_le = (uint8_t)strtoul(fields[4], NULL, 16);
      command.data.data = data; command.data.length = decode(fields[5], data, sizeof data);
      expected_length = decode(fields[6], expected, sizeof expected);
      munit_assert_int(example_piv_sm_protect(&session,&command,output,sizeof output,&written,&w), ==, TC_OK);
      munit_assert_uint(session.state, ==, TC_PIV_SM_PENDING);
      munit_assert_size(written, ==, expected_length);
      munit_assert_memory_equal(written, output, expected);
    } else if (strcmp(fields[0], "response") == 0) {
      ExamplePIVSMResult result;
      uint16_t transport;
      munit_assert_size(count, ==, 5);
      transport = (uint16_t)strtoul(fields[1], NULL, 16);
      length = decode(fields[2], data, sizeof data);
      expected_length = decode(fields[3], expected, sizeof expected);
      munit_assert_int(example_piv_sm_unprotect(&session,(TC_bytes){data,length},transport,
                                       output, sizeof output, &result, &w), ==, TC_OK);
      munit_assert_size(result.length, ==, expected_length);
      munit_assert_uint(result.status, ==, strtoul(fields[4], NULL, 16));
      munit_assert_memory_equal(result.length, output, expected);
      munit_assert_uint(session.state, ==, TC_PIV_SM_READY);
    } else if (strcmp(fields[0], "state") == 0) {
      munit_assert_size(count, ==, 4);
      munit_assert_size(decode(fields[1], expected, sizeof expected), ==, 16);
      munit_assert_memory_equal(16, session.data.traffic.counter, expected);
      munit_assert_size(decode(fields[2], expected, sizeof expected), ==, 16);
      munit_assert_memory_equal(16, session.data.traffic.command_mcv, expected);
      munit_assert_size(decode(fields[3], expected, sizeof expected), ==, 16);
      munit_assert_memory_equal(16, session.data.traffic.response_mcv, expected);
    } else munit_errorf("Unknown transcript operation %s", fields[0]);
    munit_assert_true(tc_test_all_zero(&w, sizeof w));
  }
  munit_assert_int(ferror(file), ==, 0);
  fclose(file);
  munit_assert_size(lines, >, 1);
  TC_PIV_SM_clear(&session);
  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/begin-failures", begin_failures, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/response-failures", response_failures, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/replay", replay, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};
static const MunitSuite suite = {"/piv-sm", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{
  if (argc == 3 && strcmp(argv[1], "--transcript") == 0) {
    char* args[] = {argv[0], (char*)"/piv-sm/replay", NULL};
    transcript_path = argv[2];
    return munit_suite_main(&suite, NULL, 2, args);
  }
  return munit_suite_main(&suite, NULL, argc, argv);
}
