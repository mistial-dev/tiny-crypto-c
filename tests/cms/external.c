/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../src/cms_internal.h"
#include "source.h"
#include "munit.h"

static MunitResult external_collections(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  enum { FRAME_CAPACITY = 4, WORK_BUDGET = 128 };
  /* Collection iteration returns records; schema parsing follows separately. */
  const uint8_t sequence[] = {0x30,0};
  const TC_bytes inputs[] = {{sequence,sizeof sequence}};
  candidate_source records = {inputs,1,0,TC_TLV_OK,0};
  const TC_X509_store_source certificates = {&records,1,0,read_candidate,NULL};
  const tc_pki_record_source crls = {&records,1,read_candidate};
  const TC_TLV_limits limits = {16,16,8,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  size_t work = WORK_BUDGET;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  tc_cms_candidates candidates;
  tc_cms_certificate_choice certificate;
  munit_assert_int(tc_cms_candidates_init((TC_bytes){NULL,0},&certificates,1,sizeof sequence,
      &limits,&tree,&candidates), ==, TC_TLV_OK);
  munit_assert_int(tc_cms_candidates_next(&candidates,&tree,&certificate), ==, TC_TLV_OK);
  munit_assert_int(certificate.kind, ==, TC_CMS_CERT_X509);
  munit_assert_ptr_equal(certificate.encoded.data,sequence);
  munit_assert_size(certificate.encoded.length, ==, sizeof sequence);
  munit_assert_int(tc_cms_candidates_next(&candidates,&tree,&certificate), ==, TC_TLV_END);
  munit_assert_size(records.calls, ==, 1);

  tc_cms_revocations revocations;
  tc_cms_revocation_choice revocation;
  work = WORK_BUDGET; records.calls = 0;
  munit_assert_int(tc_cms_revocations_init((TC_bytes){NULL,0},&crls,1,sizeof sequence,
      &limits,&tree,&revocations), ==, TC_TLV_OK);
  munit_assert_int(tc_cms_revocations_next(&revocations,&tree,&revocation), ==, TC_TLV_OK);
  munit_assert_int(revocation.kind, ==, TC_CMS_REVOCATION_CRL);
  munit_assert_ptr_equal(revocation.encoded.data,sequence);
  munit_assert_int(tc_cms_revocations_next(&revocations,&tree,&revocation), ==, TC_TLV_END);
  munit_assert_size(records.calls, ==, 1);

  const uint8_t embedded_certificates[] = {0xa0,0}, embedded_crls[] = {0xa1,0};
  work = WORK_BUDGET; records.calls = 0;
  munit_assert_int(tc_cms_candidates_init((TC_bytes){embedded_certificates,sizeof embedded_certificates},
      &certificates,1,16,&limits,&tree,&candidates), ==, TC_TLV_OK);
  munit_assert_int(tc_cms_candidates_next(&candidates,&tree,&certificate), ==, TC_TLV_OK);
  munit_assert_ptr_equal(certificate.encoded.data,sequence);
  munit_assert_int(tc_cms_candidates_next(&candidates,&tree,&certificate), ==, TC_TLV_END);
  munit_assert_size(records.calls, ==, 1);
  work = WORK_BUDGET; records.calls = 0;
  munit_assert_int(tc_cms_revocations_init((TC_bytes){embedded_crls,sizeof embedded_crls},
      &crls,1,16,&limits,&tree,&revocations), ==, TC_TLV_OK);
  munit_assert_int(tc_cms_revocations_next(&revocations,&tree,&revocation), ==, TC_TLV_OK);
  munit_assert_ptr_equal(revocation.encoded.data,sequence);
  munit_assert_int(tc_cms_revocations_next(&revocations,&tree,&revocation), ==, TC_TLV_END);
  munit_assert_size(records.calls, ==, 1);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/external-collections",external_collections,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/pki/der",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
