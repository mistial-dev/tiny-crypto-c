/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../examples/credential_system.h"
#include "munit.h"
#include <string.h>

static MunitResult host_services(const MunitParameter params[], void* context)
{
  TC_X509_time now;
  int64_t seconds;
  munit_assert_true(example_card_now(&now));
  munit_assert_int(TC_X509_time_to_unix(&now,&seconds), ==, TC_TLV_OK);
  munit_assert_int64(seconds, >=, 0);
  munit_assert_false(example_card_now(NULL));
  uint8_t entropy[48];
  memset(entropy,0xa5,sizeof entropy);
  munit_assert_int(example_card_random(NULL,NULL,sizeof entropy), ==, TC_ERROR);
  munit_assert_int(example_card_random(NULL,entropy,0), ==, TC_ERROR);
  for (size_t i = 0; i < sizeof entropy; ++i) munit_assert_uint(entropy[i], ==, 0xa5);
  munit_assert_int(example_card_random(NULL,entropy,sizeof entropy), ==, TC_OK);
  TC_secure_zero(entropy,sizeof entropy);
  (void)params; (void)context;
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/host-services",host_services,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/credential/system",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
