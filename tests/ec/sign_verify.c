/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/ec.h>
#include "munit.h"
#include "test_util.h"
#include <string.h>

/* Test seam in src/ec.c, compiled with TC_TEST_ECDSA_FAULT. */
extern void (*tc_test_ecdsa_fault)(uint8_t* signature, size_t length);

static void flip_bit(uint8_t* signature, size_t length)
{
  signature[length - 1] ^= 1u;
}

static TC_status counter_random(void* context, uint8_t* output, size_t length)
{
  unsigned* counter = context;
  memset(output, 0, length);
  output[length - 1] = (uint8_t)++*counter;
  return TC_OK;
}

/* A faulted signature is withheld when TC_ECDSA_SIGN_VERIFY is set and
 * released otherwise. A public key from another key pair is also caught. */
TC_TEST(fault_detection)
{
  TC_EC_workspace key_workspace;
  TC_ECDSA_workspace workspace;
  uint8_t private_key[32], public_key[65], other_private[32], other_public[65];
  uint8_t digest[32] = {1, 2, 3}, signature[64];
  unsigned counter = 0;
  TC_EC_execution execution = {{counter_random, &counter}, 8, {UINT32_MAX}};
  munit_assert_int(TC_EC_generate_key_pair(TC_EC_P256, (TC_buffer){private_key, 32},
                                           (TC_buffer){public_key, 65}, &key_workspace, &execution),
                   ==, TC_EC_OK);
  munit_assert_int(TC_EC_generate_key_pair(TC_EC_P256, (TC_buffer){other_private, 32},
                                           (TC_buffer){other_public, 65}, &key_workspace,
                                           &execution),
                   ==, TC_EC_OK);
  const TC_bytes key = {private_key, 32}, point = {public_key, 65}, message = {digest, 32};
  munit_assert_int(TC_ECDSA_sign_digest(TC_EC_P256, key, point, message, (TC_buffer){signature, 64},
                                        &workspace, &execution),
                   ==, TC_EC_OK);
  tc_test_ecdsa_fault = flip_bit;
  memset(signature, 0xa5, sizeof signature);
  const TC_EC_result faulted = TC_ECDSA_sign_digest(
      TC_EC_P256, key, point, message, (TC_buffer){signature, 64}, &workspace, &execution);
  tc_test_ecdsa_fault = NULL;
#if TC_ECDSA_SIGN_VERIFY
  munit_assert_int(faulted, ==, TC_EC_ERROR);
  for (size_t i = 0; i < sizeof signature; ++i)
    munit_assert_uint(signature[i], ==, 0xa5);
  munit_assert_int(TC_ECDSA_sign_digest(TC_EC_P256, key, (TC_bytes){other_public, 65}, message,
                                        (TC_buffer){signature, 64}, &workspace, &execution),
                   ==, TC_EC_ERROR);
#else
  munit_assert_int(faulted, ==, TC_EC_OK);
  TC_work_budget work = {UINT32_MAX};
  munit_assert_int(TC_ECDSA_verify_digest(TC_EC_P256, point, message, (TC_bytes){signature, 64},
                                          &workspace, &work),
                   ==, TC_EC_INVALID);
#endif
  return MUNIT_OK;
}

/* Every operation checks its documented cost before it starts. */
TC_TEST(work_limits)
{
  TC_EC_workspace workspace;
  TC_ECDSA_workspace signing;
  uint8_t scalar[32] = {0}, public_key[65], digest[32] = {0}, signature[64];
  unsigned counter = 0;
  scalar[31] = 1;
  const uint32_t cost = TC_EC_operation_work(TC_EC_P256, TC_EC_OPERATION_PUBLIC_KEY);
  munit_assert_uint32(cost, ==, 512);
  TC_work_budget work = {cost - 1};
  munit_assert_int(TC_EC_public_key(TC_EC_P256, (TC_bytes){scalar, 32}, (TC_buffer){public_key, 65},
                                    &workspace, &work),
                   ==, TC_EC_LIMIT);
  munit_assert_uint32(work.remaining, ==, cost - 1);
  work.remaining = cost;
  munit_assert_int(TC_EC_public_key(TC_EC_P256, (TC_bytes){scalar, 32}, (TC_buffer){public_key, 65},
                                    &workspace, &work),
                   ==, TC_EC_OK);
  munit_assert_uint32(work.remaining, ==, 0);
  const uint32_t sign = TC_EC_operation_work(TC_EC_P256, TC_EC_OPERATION_SIGN);
  TC_EC_execution execution = {{counter_random, &counter}, 1, {sign - 1}};
  munit_assert_int(TC_ECDSA_sign_digest(TC_EC_P256, (TC_bytes){scalar, 32},
                                        (TC_bytes){public_key, 65}, (TC_bytes){digest, 32},
                                        (TC_buffer){signature, 64}, &signing, &execution),
                   ==, TC_EC_LIMIT);
  munit_assert_uint(counter, ==, 0);
  execution.work.remaining = sign;
  munit_assert_int(TC_ECDSA_sign_digest(TC_EC_P256, (TC_bytes){scalar, 32},
                                        (TC_bytes){public_key, 65}, (TC_bytes){digest, 32},
                                        (TC_buffer){signature, 64}, &signing, &execution),
                   ==, TC_EC_OK);
  munit_assert_uint32(execution.work.remaining, ==, 0);
  munit_assert_uint32(TC_EC_operation_work((TC_EC_curve)0, TC_EC_OPERATION_SIGN), ==, 0);
  return MUNIT_OK;
}

int main(int argc, char* argv[])
{
  MunitTest tests[] = {
      {"/fault-detection", fault_detection, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/work-limits", work_limits, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/ec/sign-verify", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
