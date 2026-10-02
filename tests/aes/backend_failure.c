/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "aes_internal.h"
#include <tiny_crypto/aes_kw.h>
#include "munit.h"
#include "test_util.h"
#include <string.h>

#undef tc_aes_cipher_rounds
#undef tc_aes_inverse_rounds
TC_status tc_aes_cipher_rounds(state_t*, const uint8_t*, uint8_t);
TC_status tc_aes_inverse_rounds(state_t*, const uint8_t*, uint8_t);

static unsigned calls, fail_at;

TC_status tc_test_cipher_rounds(state_t* state, const uint8_t* key, uint8_t rounds)
{
  ++calls;
  if (calls == fail_at) {
    memset(state, 0xa5, sizeof *state); /* A failed device may modify scratch. */
    return TC_ERROR;
  }
  return tc_aes_cipher_rounds(state, key, rounds);
}

TC_status tc_test_inverse_rounds(state_t* state, const uint8_t* key, uint8_t rounds)
{
  ++calls;
  if (calls == fail_at) {
    memset(state, 0xa5, sizeof *state);
    return TC_ERROR;
  }
  return tc_aes_inverse_rounds(state, key, rounds);
}

TC_status tc_test_cipher(state_t* state, const uint8_t* key)
{
  return tc_test_cipher_rounds(state, key, TC_AES_FIXED_ROUNDS);
}

TC_TEST(failures)
{
  uint8_t key[16] = {0}, data[33] = {0}, tag[16], expected[16];
  struct TC_AES_CMAC_ctx fixed;
  struct TC_AES_CMAC_ctx failed_fixed;
  TC_AES_dynamic_CMAC dynamic;
  unsigned stage;
  memset(expected, 0x5a, sizeof expected);
  memset(&failed_fixed, 0, sizeof failed_fixed);
  for (stage = 1; stage <= 4; ++stage) {
    TC_status status;
    calls = 0;
    fail_at = stage;
    memcpy(tag, expected, sizeof tag);
    status = TC_AES_CMAC_init(&fixed, (TC_bytes){key, TC_AES_KEYLEN});
    if (status == TC_OK)
      status = TC_AES_CMAC_update(&fixed, (TC_bytes){data, sizeof data});
    if (status == TC_OK)
      status = TC_AES_CMAC_final(&fixed, (TC_buffer){tag, TC_AES_CMAC_TAG_MAX});
    munit_assert_int(status, ==, TC_ERROR);
    munit_assert_memory_equal(sizeof fixed, &fixed, &failed_fixed);
    munit_assert_memory_equal(sizeof tag, tag, expected);
    munit_assert_int(TC_AES_CMAC_update(&fixed, (TC_bytes){data, 1}), ==, TC_ERROR);
    munit_assert_int(TC_AES_CMAC_final(&fixed, (TC_buffer){tag, TC_AES_CMAC_TAG_MAX}), ==,
                     TC_ERROR);
    munit_assert_memory_equal(sizeof tag, tag, expected);

    calls = 0;
    status = TC_AES_dynamic_CMAC_init(&dynamic, (TC_bytes){key, sizeof key});
    if (status == TC_OK)
      status = TC_AES_dynamic_CMAC_update(&dynamic, (TC_bytes){data, sizeof data});
    if (status == TC_OK)
      status = TC_AES_dynamic_CMAC_final(&dynamic, (TC_buffer){tag, TC_AES_BLOCKLEN});
    munit_assert_int(status, ==, TC_ERROR);
    munit_assert_true(tc_test_all_zero(&dynamic, sizeof dynamic));
    munit_assert_memory_equal(sizeof tag, tag, expected);
    munit_assert_int(TC_AES_dynamic_CMAC_update(&dynamic, (TC_bytes){data, 1}), ==, TC_ERROR);
    munit_assert_int(TC_AES_dynamic_CMAC_final(&dynamic, (TC_buffer){tag, TC_AES_BLOCKLEN}), ==,
                     TC_ERROR);
    munit_assert_memory_equal(sizeof tag, tag, expected);
  }
  fail_at = 0;
  munit_assert_int(TC_AES_CMAC_init(&fixed, (TC_bytes){key, TC_AES_KEYLEN}), ==, TC_OK);
  munit_assert_int(TC_AES_CMAC_final(&fixed, (TC_buffer){tag, TC_AES_CMAC_TAG_MAX}), ==, TC_OK);
  munit_assert_int(TC_AES_dynamic_CMAC_init(&dynamic, (TC_bytes){key, sizeof key}), ==, TC_OK);
  munit_assert_int(TC_AES_dynamic_CMAC_final(&dynamic, (TC_buffer){tag, TC_AES_BLOCKLEN}), ==,
                   TC_OK);
  return MUNIT_OK;
}

TC_TEST(siv_failures)
{
  const size_t lengths[] = {0, 1, 16, 33};
  uint8_t key[2 * TC_AES_KEYLEN] = {0}, plain[33] = {0};
  uint8_t ciphertext[33], output[33], tag[16], failed_tag[16], sentinel[16];
  const TC_bytes ad[] = {{NULL, 0}, {plain, sizeof plain}};
  size_t index;
  memset(sentinel, 0x5a, sizeof sentinel);
  for (index = 0; index < sizeof lengths / sizeof lengths[0]; ++index) {
    unsigned total, stage;
    size_t length = lengths[index];
    calls = 0;
    fail_at = 0;
    munit_assert_int(TC_AES_SIV_encrypt((TC_bytes){key, sizeof key}, ad, 2,
                                        (TC_bytes){plain, length}, (TC_buffer){tag, sizeof tag},
                                        (TC_buffer){ciphertext, length}),
                     ==, TC_OK);
    total = calls;
    for (stage = 1; stage <= total; ++stage) {
      calls = 0;
      fail_at = stage;
      memset(output, 0x5a, sizeof output);
      memcpy(failed_tag, sentinel, sizeof failed_tag);
      munit_assert_int(TC_AES_SIV_encrypt(
                           (TC_bytes){key, sizeof key}, ad, 2, (TC_bytes){plain, length},
                           (TC_buffer){failed_tag, sizeof failed_tag}, (TC_buffer){output, length}),
                       ==, TC_ERROR);
      munit_assert_memory_equal(sizeof failed_tag, failed_tag, sentinel);
      munit_assert_true(tc_test_all_zero(output, length));

      calls = 0;
      memset(output, 0x5a, sizeof output);
      munit_assert_int(
          TC_AES_SIV_decrypt((TC_bytes){key, sizeof key}, ad, 2, (TC_bytes){tag, sizeof tag},
                             (TC_bytes){ciphertext, length}, (TC_buffer){output, length}),
          ==, TC_ERROR);
      munit_assert_true(tc_test_all_zero(output, length));

      calls = 0;
      memcpy(output, ciphertext, length);
      munit_assert_int(TC_AES_SIV_decrypt((TC_bytes){key, sizeof key}, ad, 2,
                                          (TC_bytes){tag, sizeof tag}, (TC_bytes){output, length},
                                          (TC_buffer){output, length}),
                       ==, TC_ERROR);
      munit_assert_true(tc_test_all_zero(output, length));
    }
  }
  fail_at = 0;
  return MUNIT_OK;
}

static TC_status eax_operation(int prime, int decrypt, const uint8_t* key, const uint8_t* header,
                               const uint8_t* input, size_t length, uint8_t* output, uint8_t* tag)
{
  if (prime) {
    if (decrypt)
      return TC_AES_EAX_PRIME_decrypt(
          (TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){header, 33}, (TC_bytes){input, length},
          (TC_bytes){tag, TC_AES_EAX_PRIME_TAG_LEN}, (TC_buffer){output, length});
    return TC_AES_EAX_PRIME_encrypt((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){header, 33},
                                    (TC_bytes){input, length}, (TC_buffer){output, length},
                                    (TC_buffer){tag, TC_AES_EAX_PRIME_TAG_LEN});
  }
  if (decrypt)
    return TC_AES_EAX_decrypt((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){header, 33},
                              (TC_bytes){header, 33}, (TC_bytes){input, length},
                              (TC_bytes){tag, 16}, (TC_buffer){output, length});
  return TC_AES_EAX_encrypt((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){header, 33},
                            (TC_bytes){header, 33}, (TC_bytes){input, length},
                            (TC_buffer){output, length}, (TC_buffer){tag, 16});
}

TC_TEST(eax_failures)
{
  const size_t lengths[] = {0, 1, 16, 33};
  uint8_t key[TC_AES_KEYLEN] = {0}, plain[33] = {0}, ciphertext[33];
  uint8_t output[33], tag[16], failed_tag[16], sentinel[16];
  int prime;
  size_t index;
  memset(sentinel, 0x5a, sizeof sentinel);
  for (prime = 0; prime <= 1; ++prime) {
    for (index = 0; index < sizeof lengths / sizeof lengths[0]; ++index) {
      unsigned total, stage;
      size_t length = lengths[index];
      calls = 0;
      fail_at = 0;
      memset(tag, 0, sizeof tag);
      munit_assert_int(eax_operation(prime, 0, key, plain, plain, length, ciphertext, tag), ==,
                       TC_OK);
      total = calls;
      for (stage = 1; stage <= total; ++stage) {
        calls = 0;
        fail_at = stage;
        memset(output, 0x5a, sizeof output);
        memcpy(failed_tag, sentinel, sizeof failed_tag);
        munit_assert_int(eax_operation(prime, 0, key, plain, plain, length, output, failed_tag), ==,
                         TC_ERROR);
        munit_assert_memory_equal(sizeof failed_tag, failed_tag, sentinel);
        munit_assert_true(tc_test_all_zero(output, length));
        calls = 0;
        memset(output, 0x5a, sizeof output);
        munit_assert_int(eax_operation(prime, 1, key, plain, ciphertext, length, output, tag), ==,
                         TC_ERROR);
        munit_assert_true(tc_test_all_zero(output, length));
        calls = 0;
        memcpy(output, ciphertext, length);
        munit_assert_int(eax_operation(prime, 1, key, plain, output, length, output, tag), ==,
                         TC_ERROR);
        munit_assert_true(tc_test_all_zero(output, length));
      }
    }
  }
  fail_at = 0;
  return MUNIT_OK;
}

TC_TEST(ccm_failures)
{
  const size_t lengths[] = {0, 1, 16, 33};
  uint8_t key[TC_AES_KEYLEN] = {0}, plain[33] = {0}, nonce[13] = {0};
  uint8_t ciphertext[33], output[33], tag[16], failed_tag[16], sentinel[16];
  size_t index;
  memset(sentinel, 0x5a, sizeof sentinel);
  for (index = 0; index < sizeof lengths / sizeof lengths[0]; ++index) {
    unsigned total, stage;
    size_t length = lengths[index];
    calls = 0;
    fail_at = 0;
    munit_assert_int(
        TC_AES_CCM_encrypt((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){nonce, sizeof nonce},
                           (TC_bytes){plain, sizeof plain}, (TC_bytes){plain, length},
                           (TC_buffer){ciphertext, length}, (TC_buffer){tag, sizeof tag}),
        ==, TC_OK);
    total = calls;
    for (stage = 1; stage <= total; ++stage) {
      calls = 0;
      fail_at = stage;
      memcpy(failed_tag, sentinel, sizeof failed_tag);
      memset(output, 0x5a, sizeof output);
      munit_assert_int(TC_AES_CCM_encrypt(
                           (TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){nonce, sizeof nonce},
                           (TC_bytes){plain, sizeof plain}, (TC_bytes){plain, length},
                           (TC_buffer){output, length}, (TC_buffer){failed_tag, sizeof failed_tag}),
                       ==, TC_ERROR);
      munit_assert_memory_equal(sizeof failed_tag, failed_tag, sentinel);
      munit_assert_true(tc_test_all_zero(output, length));
    }
    calls = 0;
    fail_at = 0;
    munit_assert_int(
        TC_AES_CCM_decrypt((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){nonce, sizeof nonce},
                           (TC_bytes){plain, sizeof plain}, (TC_bytes){ciphertext, length},
                           (TC_bytes){tag, sizeof tag}, (TC_buffer){output, length}),
        ==, TC_OK);
    total = calls;
    for (stage = 1; stage <= total; ++stage) {
      calls = 0;
      fail_at = stage;
      memset(output, 0x5a, sizeof output);
      munit_assert_int(
          TC_AES_CCM_decrypt((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){nonce, sizeof nonce},
                             (TC_bytes){plain, sizeof plain}, (TC_bytes){ciphertext, length},
                             (TC_bytes){tag, sizeof tag}, (TC_buffer){output, length}),
          ==, TC_ERROR);
      munit_assert_true(tc_test_all_zero(output, length));
      calls = 0;
      memcpy(output, ciphertext, length);
      munit_assert_int(
          TC_AES_CCM_decrypt((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){nonce, sizeof nonce},
                             (TC_bytes){plain, sizeof plain}, (TC_bytes){output, length},
                             (TC_bytes){tag, sizeof tag}, (TC_buffer){output, length}),
          ==, TC_ERROR);
      munit_assert_true(tc_test_all_zero(output, length));
    }
  }
  fail_at = 0;
  return MUNIT_OK;
}

TC_TEST(gcm_failures)
{
  uint8_t key[TC_AES_KEYLEN] = {0}, plain[33] = {0}, iv[12] = {0};
  uint8_t ciphertext[33], output[33], tag[16], failed_tag[16], sentinel[16];
  struct TC_AES_GCM_ctx ctx;
  unsigned stage;
  memset(sentinel, 0x5a, sizeof sentinel);
  calls = 0;
  fail_at = 0;
  munit_assert_int(
      TC_AES_GCM_encrypt((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){iv, sizeof iv},
                         (TC_bytes){plain, sizeof plain}, (TC_bytes){plain, sizeof plain},
                         (TC_buffer){ciphertext, sizeof plain}, (TC_buffer){tag, sizeof tag}),
      ==, TC_OK);
  /* H, three counter blocks and the tag mask. */
  munit_assert_uint(calls, ==, 5);
  for (stage = 1; stage <= 5; ++stage) {
    TC_status status;
    calls = 0;
    fail_at = stage;
    memcpy(failed_tag, sentinel, sizeof failed_tag);
    memset(output, 0x5a, sizeof output);
    munit_assert_int(TC_AES_GCM_encrypt((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){iv, sizeof iv},
                                        (TC_bytes){plain, sizeof plain},
                                        (TC_bytes){plain, sizeof plain},
                                        (TC_buffer){output, sizeof plain},
                                        (TC_buffer){failed_tag, sizeof failed_tag}),
                     ==, TC_ERROR);
    munit_assert_memory_equal(sizeof failed_tag, failed_tag, sentinel);
    munit_assert_true(tc_test_all_zero(output, sizeof output));
    calls = 0;
    memset(output, 0x5a, sizeof output);
    munit_assert_int(TC_AES_GCM_decrypt(
                         (TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){iv, sizeof iv},
                         (TC_bytes){plain, sizeof plain}, (TC_bytes){ciphertext, sizeof ciphertext},
                         (TC_bytes){tag, sizeof tag}, (TC_buffer){output, sizeof ciphertext}),
                     ==, TC_ERROR);
    munit_assert_true(tc_test_all_zero(output, sizeof output));
    calls = 0;
    memcpy(output, ciphertext, sizeof output);
    munit_assert_int(
        TC_AES_GCM_decrypt((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){iv, sizeof iv},
                           (TC_bytes){plain, sizeof plain}, (TC_bytes){output, sizeof output},
                           (TC_bytes){tag, sizeof tag}, (TC_buffer){output, sizeof output}),
        ==, TC_ERROR);
    munit_assert_true(tc_test_all_zero(output, sizeof output));

    calls = 0;
    memcpy(output, plain, sizeof output);
    status =
        TC_AES_GCM_init(&ctx, (TC_bytes){key, sizeof key}, (TC_bytes){iv, sizeof iv}, sizeof tag);
    if (status == TC_OK)
      status = TC_AES_GCM_encrypt_update(&ctx, (TC_buffer){output, sizeof output});
    if (status == TC_OK)
      status = TC_AES_GCM_encrypt_finish(&ctx, (TC_buffer){failed_tag, sizeof failed_tag});
    munit_assert_int(status, ==, TC_ERROR);
    munit_assert_true(tc_test_all_zero(&ctx.key, sizeof ctx.key));
    munit_assert_memory_equal(sizeof failed_tag, failed_tag, sentinel);
    munit_assert_int(TC_AES_GCM_encrypt_update(&ctx, (TC_buffer){output, 1}), ==, TC_ERROR);
    munit_assert_int(TC_AES_GCM_aad_update(&ctx, (TC_bytes){output, 1}), ==, TC_ERROR);
    munit_assert_int(TC_AES_GCM_encrypt_finish(&ctx, (TC_buffer){failed_tag, sizeof failed_tag}),
                     ==, TC_ERROR);
  }
  fail_at = 0;
  return MUNIT_OK;
}

/* Fail every block call of each key wrap entry in turn: the KWP single-block
 * paths, the first and middle W steps and the last W^-1 step before the
 * integrity check. Each failure returns TC_ERROR, wipes the written region
 * and leaves the KWP length unchanged. */
TC_TEST(kw_failures)
{
  static const struct {
    int padded;
    size_t length;
  } cases[] = {{0, 16}, {0, 24}, {1, 7}, {1, 20}};
  uint8_t kek[16] = {0}, key_data[24], wrapped[32], output[40];
  size_t index;
  memset(key_data, 0x3c, sizeof key_data);
  for (index = 0; index < sizeof cases / sizeof cases[0]; ++index) {
    const int padded = cases[index].padded;
    const TC_bytes k = {kek, sizeof kek};
    const TC_bytes data = {key_data, cases[index].length};
    const size_t wrapped_length =
        padded ? TC_AES_KWP_WRAPPED_BYTES(data.length) : TC_AES_KW_WRAPPED_BYTES(data.length);
    const size_t area = wrapped_length - 8u;
    unsigned wrap_total, unwrap_total, stage;
    size_t length = 0;
    calls = 0;
    fail_at = 0;
    munit_assert_int(padded ? TC_AES_KWP_wrap(k, data, (TC_buffer){wrapped, wrapped_length})
                            : TC_AES_KW_wrap(k, data, (TC_buffer){wrapped, wrapped_length}),
                     ==, TC_OK);
    wrap_total = calls;
    calls = 0;
    munit_assert_int(padded ? TC_AES_KWP_unwrap(k, (TC_bytes){wrapped, wrapped_length},
                                                (TC_buffer){output, area}, &length)
                            : TC_AES_KW_unwrap(k, (TC_bytes){wrapped, wrapped_length},
                                               (TC_buffer){output, area}),
                     ==, TC_OK);
    unwrap_total = calls;
    /* One block for two semiblocks, 6(n - 1) otherwise. */
    munit_assert_uint(wrap_total, ==, wrapped_length == 16 ? 1u : 6u * (unsigned)(area / 8u));
    munit_assert_uint(unwrap_total, ==, wrap_total);
    for (stage = 1; stage <= wrap_total; ++stage) {
      calls = 0;
      fail_at = stage;
      memset(output, 0x5a, sizeof output);
      munit_assert_int(padded ? TC_AES_KWP_wrap(k, data, (TC_buffer){output, wrapped_length})
                              : TC_AES_KW_wrap(k, data, (TC_buffer){output, wrapped_length}),
                       ==, TC_ERROR);
      munit_assert_true(tc_test_all_zero(output, wrapped_length));
      munit_assert_true(
          tc_test_all_value(output + wrapped_length, sizeof output - wrapped_length, 0x5a));

      calls = 0;
      length = SIZE_MAX;
      memset(output, 0x5a, sizeof output);
      munit_assert_int(padded ? TC_AES_KWP_unwrap(k, (TC_bytes){wrapped, wrapped_length},
                                                  (TC_buffer){output, area}, &length)
                              : TC_AES_KW_unwrap(k, (TC_bytes){wrapped, wrapped_length},
                                                 (TC_buffer){output, area}),
                       ==, TC_ERROR);
      munit_assert_true(tc_test_all_zero(output, area));
      munit_assert_true(tc_test_all_value(output + area, sizeof output - area, 0x5a));
      munit_assert_size(length, ==, SIZE_MAX);

      /* In place, the caller loses the wrapped input. */
      calls = 0;
      memcpy(output, wrapped, wrapped_length);
      munit_assert_int(padded ? TC_AES_KWP_unwrap(k, (TC_bytes){output, wrapped_length},
                                                  (TC_buffer){output, area}, &length)
                              : TC_AES_KW_unwrap(k, (TC_bytes){output, wrapped_length},
                                                 (TC_buffer){output, area}),
                       ==, TC_ERROR);
      munit_assert_true(tc_test_all_zero(output, area));
      munit_assert_size(length, ==, SIZE_MAX);
    }
  }
  fail_at = 0;
  return MUNIT_OK;
}

static MunitTest tests[] = {{"/cmac", failures, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                            {"/siv", siv_failures, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                            {"/eax", eax_failures, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                            {"/ccm", ccm_failures, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                            {"/gcm", gcm_failures, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                            {"/kw", kw_failures, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                            {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};

int main(int argc, char** argv)
{
  MunitSuite suite = {"/aes-backend", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
