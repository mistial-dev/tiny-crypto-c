/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/ec.h>
#include "cavp.h"
#include "munit.h"
#include "test_util.h"
#include <string.h>

TC_TEST(pinned_answers)
{
  static const struct {
    TC_EC_curve curve;
    TC_hash_algorithm hash;
    size_t width;
    const char *key, *digest, *signature;
  } answers[] = {{TC_EC_P256, TC_HASH_SHA256, 32,
                  "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
                  "AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF",
                  "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"
                  "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"},
                 {TC_EC_P384, TC_HASH_SHA384, 48,
                  "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8"
                  "96D5724E4C70A825F872C9EA60D2EDF5",
                  "9A9083505BC92276AEC4BE312696EF7BF3BF603F4BBD381196A029F340585312"
                  "313BCA4A9B5B890EFEE42C77B1EE25FE",
                  "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C"
                  "81A648152E44ACF96E36DD1E80FABE46"
                  "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94F"
                  "A329C145786E679E7B82C71A38628AC8"}};
  uint8_t key[48], digest[48], public_key[97], signature[96], expected[96];
  TC_EC_workspace key_workspace;
  TC_ECDSA_workspace sign_workspace;
  for (size_t i = 0; i < sizeof answers / sizeof answers[0]; ++i) {
    const size_t width = answers[i].width;
    munit_assert_size(tc_test_hex(answers[i].key, key, sizeof key), ==, width);
    munit_assert_size(tc_test_hex(answers[i].digest, digest, sizeof digest), ==, width);
    munit_assert_size(tc_test_hex(answers[i].signature, expected, sizeof expected), ==, 2 * width);
    TC_work_budget key_work = {UINT32_MAX};
    munit_assert_int(TC_EC_public_key(answers[i].curve, TC_APPROVED_ONLY, (TC_bytes){key, width},
                                      (TC_buffer){public_key, 1 + 2 * width}, &key_workspace,
                                      &key_work),
                     ==, TC_EC_OK);
    TC_work_budget sign_work = {UINT32_MAX};
    const TC_ECDSA_sign_options options = {answers[i].hash, 4, TC_APPROVED_ONLY};
    munit_assert_int(
        TC_ECDSA_sign_digest(answers[i].curve, &options, (TC_bytes){key, width},
                             (TC_bytes){public_key, 1 + 2 * width}, (TC_bytes){digest, width},
                             (TC_buffer){signature, 2 * width}, &sign_workspace, &sign_work),
        ==, TC_EC_OK);
    munit_assert_memory_equal(2 * width, signature, expected);
    munit_assert_true(tc_test_all_zero(&sign_workspace, sizeof sign_workspace));

    /* NULL spans are argument errors found before any RFC 6979 work, with the
     * signature and work unchanged. */
    memset(signature, 0xa5, sizeof signature);
    sign_work.remaining = UINT32_MAX;
    munit_assert_int(
        TC_ECDSA_sign_digest(answers[i].curve, &options, (TC_bytes){key, width},
                             (TC_bytes){public_key, 1 + 2 * width}, (TC_bytes){NULL, width},
                             (TC_buffer){signature, 2 * width}, &sign_workspace, &sign_work),
        ==, TC_EC_ARGUMENT);
    munit_assert_int(
        TC_ECDSA_sign_digest(answers[i].curve, &options, (TC_bytes){NULL, width},
                             (TC_bytes){public_key, 1 + 2 * width}, (TC_bytes){digest, width},
                             (TC_buffer){signature, 2 * width}, &sign_workspace, &sign_work),
        ==, TC_EC_ARGUMENT);
    munit_assert_true(tc_test_all_value(signature, sizeof signature, 0xa5));
    munit_assert_uint32(sign_work.remaining, ==, UINT32_MAX);
  }
  return MUNIT_OK;
}

/* RFC 6979 appendix A.2.3, P-192 with SHA-256 over "sample". SP 800-186
 * section 3.2.1.1 excludes P-192 signing, so signing needs
 * options.approval = TC_PERMIT_DISALLOWED. */
TC_TEST(disallowed_p192)
{
  uint8_t key[24], digest[32], public_key[49], signature[48], expected[48];
  TC_EC_workspace key_workspace;
  TC_ECDSA_workspace sign_workspace;
  munit_assert_size(
      tc_test_hex("6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4", key, sizeof key), ==, 24);
  munit_assert_size(tc_test_hex("AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF",
                                digest, sizeof digest),
                    ==, 32);
  munit_assert_size(tc_test_hex("4B0B8CE98A92866A2820E20AA6B75B56382E0F9BFD5ECB55"
                                "CCDB006926EA9565CBADC840829D8C384E06DE1F1E381B85",
                                expected, sizeof expected),
                    ==, 48);
  TC_work_budget work = {UINT32_MAX};
  munit_assert_int(TC_EC_public_key(TC_EC_P192, TC_PERMIT_DISALLOWED, (TC_bytes){key, sizeof key},
                                    (TC_buffer){public_key, sizeof public_key}, &key_workspace,
                                    &work),
                   ==, TC_EC_OK);
  TC_ECDSA_sign_options options = {TC_HASH_SHA256, 4, TC_APPROVED_ONLY};
  TC_work_budget sign_work = {UINT32_MAX};
  memset(signature, 0xa5, sizeof signature);
  munit_assert_int(TC_ECDSA_sign_digest(
                       TC_EC_P192, &options, (TC_bytes){key, sizeof key},
                       (TC_bytes){public_key, sizeof public_key}, (TC_bytes){digest, sizeof digest},
                       (TC_buffer){signature, sizeof signature}, &sign_workspace, &sign_work),
                   ==, TC_EC_UNSUPPORTED);
  munit_assert_uint32(sign_work.remaining, ==, UINT32_MAX);
  munit_assert_true(tc_test_all_value(signature, sizeof signature, 0xa5));
  options.approval = TC_PERMIT_DISALLOWED;
  munit_assert_int(TC_ECDSA_sign_digest(
                       TC_EC_P192, &options, (TC_bytes){key, sizeof key},
                       (TC_bytes){public_key, sizeof public_key}, (TC_bytes){digest, sizeof digest},
                       (TC_buffer){signature, sizeof signature}, &sign_workspace, &sign_work),
                   ==, TC_EC_OK);
  munit_assert_memory_equal(sizeof expected, signature, expected);
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/pinned-answers", pinned_answers, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/disallowed-p192", disallowed_p192, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
static const MunitSuite suite = {"/ec/rfc6979", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char** argv)
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
