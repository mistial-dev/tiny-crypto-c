/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* PIV secure messaging session: key establishment failures, ciphertext
 * sizing, response authentication and in-place decryption (SP 800-73-5
 * Part 2 sections 4.1 and 4.2). The APDU framing tests are in sm_apdu.c. */
#include <tiny_crypto/piv_sm.h>
#include "munit.h"
#include "test_util.h"
#include <string.h>

typedef struct {
  uint8_t scalar[48];
  unsigned calls, zeros, fail;
} random_state;

static TC_status fixed_random(void* user, uint8_t* output, size_t length)
{
  random_state* state = (random_state*)user;
  ++state->calls;
  if (state->fail)
    return TC_ERROR;
  if (state->calls <= state->zeros)
    memset(output, 0, length);
  else
    memcpy(output, state->scalar, length);
  return TC_OK;
}

TC_TEST(begin_failures)
{
  TC_PIV_SM session = {0};
  TC_PIV_SM_workspace w;
  TC_PIV_SM_handshake handshake, saved_handshake;
  random_state random = {{0}, 0, 0, 0};
  uint8_t host[8] = {0};
#if TC_PIV_SM_ENABLE_CS2
  const TC_PIV_SM_suite selected = TC_PIV_SM_CS2;
  const size_t scalar_length = 32, public_length = 65;
#else
  const TC_PIV_SM_suite selected = TC_PIV_SM_CS7;
  const size_t scalar_length = 48, public_length = 97;
#endif
  memset(&handshake, 0xa5, sizeof handshake);
  saved_handshake = handshake;
  random.scalar[scalar_length - 1] = 1;
#if !TC_PIV_SM_ENABLE_CS2 || !TC_PIV_SM_ENABLE_CS7
  {
    const TC_PIV_SM saved = session;
    const TC_PIV_SM_suite disabled = selected == TC_PIV_SM_CS2 ? TC_PIV_SM_CS7 : TC_PIV_SM_CS2;
    munit_assert_int(TC_PIV_SM_begin(&session, disabled, host,
                                     (TC_random_source){fixed_random, &random}, &handshake, &w),
                     ==, TC_ERROR);
    munit_assert_uint(random.calls, ==, 0);
    munit_assert_memory_equal(sizeof session, &session, &saved);
    munit_assert_memory_equal(sizeof handshake, &handshake, &saved_handshake);
  }
#endif
  random.zeros = 16;
  munit_assert_int(TC_PIV_SM_begin(&session, selected, host,
                                   (TC_random_source){fixed_random, &random}, &handshake, &w),
                   ==, TC_ERROR);
  munit_assert_uint(random.calls, ==, 16);
  munit_assert_true(tc_test_all_zero(&session, sizeof session));
  munit_assert_true(tc_test_all_zero(&w, sizeof w));
  munit_assert_memory_equal(sizeof handshake, &handshake, &saved_handshake);
  random.calls = 0;
  random.zeros = 1;
  munit_assert_int(TC_PIV_SM_begin(&session, selected, host,
                                   (TC_random_source){fixed_random, &random}, &handshake, &w),
                   ==, TC_OK);
  munit_assert_uint(random.calls, ==, 2);
  munit_assert_size(handshake.public_key.length, ==, public_length);
  munit_assert_int(TC_PIV_SM_get_state(&session), ==, TC_PIV_SM_ESTABLISHING);
  random.fail = 1;
  munit_assert_int(TC_PIV_SM_begin(&session, selected, host,
                                   (TC_random_source){fixed_random, &random}, &handshake, &w),
                   ==, TC_ERROR);
  munit_assert_true(tc_test_all_zero(&session, sizeof session));
  munit_assert_int(TC_PIV_SM_get_state(&session), ==, TC_PIV_SM_IDLE);
  munit_assert_int(TC_PIV_SM_get_state(NULL), ==, TC_PIV_SM_IDLE);
  TC_PIV_SM_clear(NULL);
  return MUNIT_OK;
}

TC_TEST(ciphertext_size)
{
  static const struct {
    size_t plaintext, ciphertext;
  } sizes[] = {{0, 0},   {1, 16},  {15, 16}, {16, 32},
               {17, 32}, {31, 32}, {32, 48}, {SIZE_MAX - 16, SIZE_MAX - 15}};
  static const size_t overflow[] = {SIZE_MAX - 15, SIZE_MAX - 1, SIZE_MAX};
  size_t i, length;
  for (i = 0; i < sizeof sizes / sizeof sizes[0]; ++i) {
    length = 999;
    munit_assert_int(TC_PIV_SM_ciphertext_size(sizes[i].plaintext, &length), ==, TC_OK);
    munit_assert_size(length, ==, sizes[i].ciphertext);
  }
  for (i = 0; i < sizeof overflow / sizeof overflow[0]; ++i) {
    length = 999;
    munit_assert_int(TC_PIV_SM_ciphertext_size(overflow[i], &length), ==, TC_ERROR);
    munit_assert_size(length, ==, 999);
  }
  munit_assert_int(TC_PIV_SM_ciphertext_size(16, NULL), ==, TC_ERROR);
  return MUNIT_OK;
}

/* Protect a VERIFY retry query on a synthetic READY session: the MAC input is
 * the header block alone (Part 2 section 4.2.3). */
static void pending_session(TC_PIV_SM* session, TC_PIV_SM_suite suite)
{
  TC_PIV_SM_workspace w;
  static const uint8_t header[16] = {0x0c, 0x20, 0x00, 0x80, 0x80};
  const TC_bytes authenticated[] = {{header, sizeof header}};
  const TC_PIV_SM_protect_request request = {{NULL, 0}, NULL, 0, authenticated, 1};
  uint8_t tag[8];
  size_t written = 99;
  memset(session, 0, sizeof *session);
  session->suite = (uint8_t)suite;
  session->state = TC_PIV_SM_READY;
  session->data.traffic.counter[15] = 1;
  munit_assert_int(TC_PIV_SM_protect(session, &request, &written, tag, &w), ==, TC_OK);
  munit_assert_size(written, ==, 0);
}

static size_t make_response(const TC_PIV_SM* session, size_t plain_length, int bad_padding,
                            uint8_t* output)
{
  TC_AES_dynamic_key key;
  TC_AES_dynamic_CMAC mac;
  uint8_t iv[16] = {0x80}, tag[16];
  size_t i, padded = plain_length + 16 - plain_length % 16, at;
  const size_t key_length = session->suite == TC_PIV_SM_CS2 ? 16 : 32;
  iv[15] = 1;
  output[0] = 0x87;
  output[1] = (uint8_t)(padded + 1);
  output[2] = 1;
  for (i = 0; i < plain_length; ++i)
    output[3 + i] = (uint8_t)i;
  output[3 + plain_length] = bad_padding ? 0x81 : 0x80;
  memset(output + 4 + plain_length, 0, padded - plain_length - 1);
  munit_assert_int(TC_AES_dynamic_key_init(&key, session->data.traffic.enc_key, key_length), ==,
                   TC_OK);
  munit_assert_int(TC_AES_dynamic_encrypt(&key, iv), ==, TC_OK);
  munit_assert_int(TC_AES_dynamic_CBC_encrypt(&key, iv, output + 3, padded), ==, TC_OK);
  TC_AES_dynamic_key_clear(&key);
  at = 3 + padded;
  output[at++] = 0x99;
  output[at++] = 2;
  output[at++] = 0x90;
  output[at++] = 0;
  munit_assert_int(TC_AES_dynamic_CMAC_init(&mac, session->data.traffic.rmac_key, key_length), ==,
                   TC_OK);
  munit_assert_int(TC_AES_dynamic_CMAC_update(&mac, session->data.traffic.response_mcv, 16), ==,
                   TC_OK);
  munit_assert_int(TC_AES_dynamic_CMAC_update(&mac, output, at), ==, TC_OK);
  munit_assert_int(TC_AES_dynamic_CMAC_final(&mac, tag), ==, TC_OK);
  output[at++] = 0x8e;
  output[at++] = 8;
  memcpy(output + at, tag, 8);
  return at + 8;
}

/* The spans of a make_response answer: 87 L 01 ciphertext 99 02 SW 8E 08 tag. */
static TC_PIV_SM_unprotect_request response_request(const uint8_t* response, size_t length,
                                                    TC_bytes* authenticated)
{
  const size_t ciphertext = length - 3 - 14;
  *authenticated = (TC_bytes){response, length - 10};
  const TC_PIV_SM_unprotect_request request = {
      {response + 3, ciphertext}, {response + length - 8, 8}, authenticated, 1};
  return request;
}

static TC_status unprotect_response(TC_PIV_SM* session, const uint8_t* response, size_t length,
                                    uint8_t* output, size_t capacity, size_t* plain_length,
                                    TC_PIV_SM_workspace* w)
{
  TC_bytes authenticated;
  const TC_PIV_SM_unprotect_request request = response_request(response, length, &authenticated);
  return TC_PIV_SM_unprotect(session, &request, output, capacity, plain_length, w);
}

static const TC_PIV_SM_suite suites[] = {
#if TC_PIV_SM_ENABLE_CS2
    TC_PIV_SM_CS2,
#endif
#if TC_PIV_SM_ENABLE_CS7
    TC_PIV_SM_CS7,
#endif
};

TC_TEST(response_failures)
{
  static const size_t lengths[] = {1, 15, 16, 17, 31, 32};
  TC_PIV_SM session, saved;
  TC_PIV_SM_workspace w;
  uint8_t response[128], output[64], expected[64], plain[64];
  size_t s, i, length, plain_length;
  tc_test_fill_incrementing(plain, sizeof plain);
  memset(expected, 0xa5, sizeof expected);
  for (s = 0; s < sizeof suites / sizeof suites[0]; ++s) {
    for (i = 0; i < sizeof lengths / sizeof lengths[0]; ++i) {
      pending_session(&session, suites[s]);
      saved = session;
      length = make_response(&session, lengths[i], 0, response);
      memcpy(output, expected, sizeof output);
      plain_length = 999;
      munit_assert_int(
          unprotect_response(&session, response, length, output, lengths[i] - 1, &plain_length, &w),
          ==, TC_ERROR);
      munit_assert_int(TC_PIV_SM_get_state(&session), ==, TC_PIV_SM_PENDING);
      munit_assert_memory_equal(sizeof session, &session, &saved);
      munit_assert_size(plain_length, ==, 999);
      munit_assert_memory_equal(sizeof output, output, expected);
      munit_assert_int(
          unprotect_response(&session, response, length, output, lengths[i], &plain_length, &w), ==,
          TC_OK);
      munit_assert_size(plain_length, ==, lengths[i]);
      munit_assert_int(TC_PIV_SM_get_state(&session), ==, TC_PIV_SM_READY);
      munit_assert_memory_equal(lengths[i], output, plain);
      munit_assert_uint8(output[lengths[i]], ==, 0xa5);
      munit_assert_true(tc_test_all_zero(&w, sizeof w));
    }
    pending_session(&session, suites[s]);
    saved = session;
    length = make_response(&session, 17, 0, response);
    memcpy(output, expected, sizeof output);
    for (i = 0; i < 64; ++i) {
      session = saved;
      plain_length = 999;
      response[length - 8 + i / 8] ^= (uint8_t)(1u << (i % 8));
      munit_assert_int(
          unprotect_response(&session, response, length, output, sizeof output, &plain_length, &w),
          ==, TC_MISMATCH);
      response[length - 8 + i / 8] ^= (uint8_t)(1u << (i % 8));
      munit_assert_int(TC_PIV_SM_get_state(&session), ==, TC_PIV_SM_IDLE);
      munit_assert_true(tc_test_all_zero(&session, sizeof session));
      munit_assert_true(tc_test_all_zero(&w, sizeof w));
      munit_assert_memory_equal(sizeof output, output, expected);
      munit_assert_size(plain_length, ==, 999);
    }
    {
      /* An argument error in PENDING leaves the request retryable. */
      const TC_PIV_SM_unprotect_request request = {{NULL, 0}, {response + length - 8, 7}, NULL, 0};
      plain_length = 999;
      session = saved;
      memset(&w, 0x5a, sizeof w);
      munit_assert_int(
          TC_PIV_SM_unprotect(&session, &request, output, sizeof output, &plain_length, &w), ==,
          TC_ERROR);
      munit_assert_int(TC_PIV_SM_get_state(&session), ==, TC_PIV_SM_PENDING);
      munit_assert_memory_equal(sizeof session, &session, &saved);
      munit_assert_size(plain_length, ==, 999);
      munit_assert_uint8(((const uint8_t*)&w)[0], ==, 0x5a);
      munit_assert_memory_equal(sizeof output, output, expected);
    }
    session = saved;
    length = make_response(&session, 17, 1, response);
    munit_assert_int(
        unprotect_response(&session, response, length, output, sizeof output, &plain_length, &w),
        ==, TC_ERROR);
    munit_assert_true(tc_test_all_zero(&session, sizeof session));
    munit_assert_memory_equal(sizeof output, output, expected);
    session = saved;
    {
      static const uint8_t header[16] = {0x0c, 0x20, 0x00, 0x80, 0x80};
      const TC_bytes authenticated[] = {{header, sizeof header}};
      const TC_PIV_SM_protect_request request = {{NULL, 0}, NULL, 0, authenticated, 1};
      uint8_t tag[8];
      size_t written = 999;
      /* One protected command may be pending. */
      munit_assert_int(TC_PIV_SM_protect(&session, &request, &written, tag, &w), ==, TC_ERROR);
      munit_assert_memory_equal(sizeof session, &session, &saved);
      munit_assert_size(written, ==, 999);
      /* The counter stops before the low 120 bits repeat. */
      session.state = TC_PIV_SM_READY;
      session.data.traffic.counter[0] = 1;
      munit_assert_int(TC_PIV_SM_protect(&session, &request, &written, tag, &w), ==, TC_ERROR);
      munit_assert_true(tc_test_all_zero(&session, sizeof session));
      munit_assert_size(written, ==, 999);
    }
  }
  return MUNIT_OK;
}

/* Exact-alias decryption: the plaintext replaces the ciphertext after the
 * response MAC is checked, so no second buffer is needed. */
TC_TEST(in_place)
{
  static const size_t lengths[] = {1, 15, 16, 17, 31, 32};
  TC_PIV_SM session, saved;
  TC_PIV_SM_workspace w;
  uint8_t response[128], original[128], plain[64];
  size_t s, i, length, plain_length;
  tc_test_fill_incrementing(plain, sizeof plain);
  for (s = 0; s < sizeof suites / sizeof suites[0]; ++s) {
    for (i = 0; i < sizeof lengths / sizeof lengths[0]; ++i) {
      pending_session(&session, suites[s]);
      saved = session;
      length = make_response(&session, lengths[i], 0, response);
      memcpy(original, response, length);
      TC_bytes authenticated;
      const TC_PIV_SM_unprotect_request request =
          response_request(response, length, &authenticated);
      uint8_t* ciphertext = response + 3;
      const size_t ciphertext_length = request.ciphertext.length;
      /* A capacity past the ciphertext and a shifted start are overlaps. */
      plain_length = 999;
      munit_assert_int(TC_PIV_SM_unprotect(&session, &request, ciphertext, ciphertext_length + 1,
                                           &plain_length, &w),
                       ==, TC_ERROR);
      munit_assert_int(TC_PIV_SM_unprotect(&session, &request, ciphertext + 1,
                                           ciphertext_length - 1, &plain_length, &w),
                       ==, TC_ERROR);
      munit_assert_int(TC_PIV_SM_unprotect(&session, &request, ciphertext - 1, ciphertext_length,
                                           &plain_length, &w),
                       ==, TC_ERROR);
      munit_assert_int(
          TC_PIV_SM_unprotect(&session, &request, response + length - 8, 8, &plain_length, &w), ==,
          TC_ERROR);
      munit_assert_memory_equal(sizeof session, &session, &saved);
      munit_assert_size(plain_length, ==, 999);
      munit_assert_memory_equal(length, response, original);
      /* A capacity below the plaintext keeps the session PENDING. */
      munit_assert_int(
          TC_PIV_SM_unprotect(&session, &request, ciphertext, lengths[i] - 1, &plain_length, &w),
          ==, TC_ERROR);
      munit_assert_memory_equal(sizeof session, &session, &saved);
      munit_assert_memory_equal(length, response, original);
      munit_assert_int(
          TC_PIV_SM_unprotect(&session, &request, ciphertext, ciphertext_length, &plain_length, &w),
          ==, TC_OK);
      munit_assert_size(plain_length, ==, lengths[i]);
      munit_assert_memory_equal(lengths[i], ciphertext, plain);
      munit_assert_int(TC_PIV_SM_get_state(&session), ==, TC_PIV_SM_READY);
      /* Bytes after the plaintext keep their ciphertext value. */
      munit_assert_memory_equal(length - 3 - lengths[i], ciphertext + lengths[i],
                                original + 3 + lengths[i]);
      munit_assert_true(tc_test_all_zero(&w, sizeof w));
    }
    /* A MAC failure leaves the ciphertext untouched. */
    pending_session(&session, suites[s]);
    length = make_response(&session, 20, 0, response);
    response[length - 1] ^= 1;
    memcpy(original, response, length);
    munit_assert_int(
        unprotect_response(&session, response, length, response + 3, 32, &plain_length, &w), ==,
        TC_MISMATCH);
    munit_assert_memory_equal(length, response, original);
    munit_assert_int(TC_PIV_SM_get_state(&session), ==, TC_PIV_SM_IDLE);
    /* Malformed padding ends the session before any byte is written. */
    pending_session(&session, suites[s]);
    length = make_response(&session, 20, 1, response);
    memcpy(original, response, length);
    munit_assert_int(
        unprotect_response(&session, response, length, response + 3, 32, &plain_length, &w), ==,
        TC_ERROR);
    munit_assert_memory_equal(length, response, original);
    munit_assert_int(TC_PIV_SM_get_state(&session), ==, TC_PIV_SM_IDLE);
  }
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/begin-failures", begin_failures, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/ciphertext-size", ciphertext_size, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/response-failures", response_failures, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/in-place", in_place, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
static const MunitSuite suite = {"/piv-sm", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
