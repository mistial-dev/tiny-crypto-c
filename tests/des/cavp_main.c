/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "munit.h"

MunitResult test_cavp_kat(const MunitParameter params[], void* data);
MunitResult test_cavp_mmt(const MunitParameter params[], void* data);
MunitResult test_cavp_mct_ecb(const MunitParameter params[], void* data);
MunitResult test_cavp_mct_cbc(const MunitParameter params[], void* data);
MunitResult test_cavp_mct_cfb1(const MunitParameter params[], void* data);
MunitResult test_cavp_mct_cfb8(const MunitParameter params[], void* data);
MunitResult test_cavp_mct_cfb64(const MunitParameter params[], void* data);
MunitResult test_cavp_mct_ofb(const MunitParameter params[], void* data);

static MunitTest tests[] = {
  { "/kat", test_cavp_kat, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/mmt", test_cavp_mmt, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/mct-ecb", test_cavp_mct_ecb, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/mct-cbc", test_cavp_mct_cbc, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/mct-cfb1", test_cavp_mct_cfb1, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/mct-cfb8", test_cavp_mct_cfb8, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/mct-cfb64", test_cavp_mct_cfb64, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/mct-ofb", test_cavp_mct_ofb, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

static const MunitSuite suite = {
  "/tiny-des-cavp", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE
};

int main(int argc, char* argv[])
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
