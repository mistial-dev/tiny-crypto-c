/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * SP 800-108 KBKDF test suite for tiny-crypto-c using µunit (munit).
 * Sub-tests live in kbkdf_test.c (known answers, API edge cases) and cavp.c
 * (NIST KBKDFVS response files, TC_KDF_CAVP=1 only).
 */

#include "munit.h"

/* Provided by kbkdf_test.c (return MUNIT_SKIP when the KDF is disabled). */
MunitResult test_kbkdf_known(const MunitParameter params[], void* data);
MunitResult test_kbkdf_counter_encoding(const MunitParameter params[], void* data);
MunitResult test_kbkdf_cmac_first_block(const MunitParameter params[], void* data);
MunitResult test_kbkdf_generated(const MunitParameter params[], void* data);
MunitResult test_kbkdf_fixed_input(const MunitParameter params[], void* data);
MunitResult test_kbkdf_api(const MunitParameter params[], void* data);
MunitResult test_kbkdf_limits(const MunitParameter params[], void* data);
MunitResult test_kbkdf_truncation(const MunitParameter params[], void* data);

/* Provided by cavp.c (return MUNIT_SKIP when TC_KDF_CAVP is 0). */
MunitResult test_kbkdf_cavp_counter(const MunitParameter params[], void* data);
MunitResult test_kbkdf_cavp_feedback(const MunitParameter params[], void* data);
MunitResult test_kbkdf_cavp_pipeline(const MunitParameter params[], void* data);

static MunitTest test_suite_tests[] = {
  { "/kbkdf/known",            test_kbkdf_known,            NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/kbkdf/counter-encoding", test_kbkdf_counter_encoding, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/kbkdf/cmac-first-block", test_kbkdf_cmac_first_block, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/kbkdf/generated",        test_kbkdf_generated,        NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/kbkdf/fixed-input",      test_kbkdf_fixed_input,      NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/kbkdf/api",              test_kbkdf_api,              NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/kbkdf/limits",           test_kbkdf_limits,           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/kbkdf/truncation",       test_kbkdf_truncation,       NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/cavp/counter",           test_kbkdf_cavp_counter,     NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/cavp/feedback",          test_kbkdf_cavp_feedback,    NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/cavp/pipeline",          test_kbkdf_cavp_pipeline,    NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

static const MunitSuite test_suite = {
  "/tiny-crypto-c",
  test_suite_tests,
  NULL,
  1,
  MUNIT_SUITE_OPTION_NONE
};

int main(int argc, char* argv[])
{
  return munit_suite_main(&test_suite, NULL, argc, argv);
}
