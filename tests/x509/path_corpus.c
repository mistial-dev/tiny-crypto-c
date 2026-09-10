/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/x509_crypto.h>
#include <tiny_crypto/x509_revocation.h>
#include "munit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { MAX_CERTIFICATES = 16, MAX_CRLS = 16, WORK_BUDGET = 4000000 };

typedef struct {
  TC_bytes candidates[MAX_CERTIFICATES];
  TC_X509_store_anchor anchors[MAX_CERTIFICATES];
  size_t candidate_count, anchor_count, candidate_calls, anchor_calls;
} corpus_source;

static TC_TLV_result read_candidate(void* context, size_t index, size_t* work, TC_bytes* out)
{
  corpus_source* source = context;
  if (index >= source->candidate_count) return TC_TLV_END;
  if (!*work) return TC_TLV_LIMIT;
  --*work; ++source->candidate_calls; *out = source->candidates[index];
  return TC_TLV_OK;
}

static TC_TLV_result read_anchor(void* context, size_t index, size_t* work,
    TC_X509_store_anchor* out)
{
  corpus_source* source = context;
  if (index >= source->anchor_count) return TC_TLV_END;
  if (!*work) return TC_TLV_LIMIT;
  --*work; ++source->anchor_calls; *out = source->anchors[index];
  return TC_TLV_OK;
}

static TC_bytes load_file(const char* name)
{
  FILE* file = fopen(name,"rb");
  long length;
  uint8_t* data;
  munit_assert_not_null(file);
  munit_assert_int(fseek(file,0,SEEK_END), ==, 0);
  length = ftell(file);
  munit_assert_int(length, >, 0);
  munit_assert_int(fseek(file,0,SEEK_SET), ==, 0);
  data = malloc((size_t)length);
  munit_assert_not_null(data);
  munit_assert_size(fread(data,1,(size_t)length,file), ==, (size_t)length);
  munit_assert_int(fclose(file), ==, 0);
  return (TC_bytes){data,(size_t)length};
}

static size_t load_numbered(const char* prefix, TC_bytes* out, size_t capacity)
{
  char variable[64];
  size_t count = 0;
  while (count < capacity) {
    munit_assert_int(snprintf(variable,sizeof variable,"%s_%zu",prefix,count), >, 0);
    const char* path = getenv(variable);
    if (!path) break;
    out[count++] = load_file(path);
  }
  return count;
}

static void free_bytes(TC_bytes* values, size_t count)
{
  for (size_t i = 0; i < count; ++i) free((void*)values[i].data);
}

static TC_X509_path_options path_options(const TC_X509_signature_provider* signatures)
{
  TC_X509_path_options options;
  memset(&options,0,sizeof options);
  options.at = (TC_X509_time){2024,1,1,0,0,0};
  const char* configured = getenv("TC_X509_AT");
  if (configured) {
    unsigned year, month, day, hour, minute, second;
    int consumed = 0, order;
    munit_assert_int(sscanf(configured,"%4u%2u%2u%2u%2u%2u%n",
        &year,&month,&day,&hour,&minute,&second,&consumed), ==, 6);
    munit_assert_int(consumed, ==, 14);
    munit_assert_char(configured[consumed], ==, '\0');
    options.at = (TC_X509_time){year,(uint8_t)month,(uint8_t)day,
      (uint8_t)hour,(uint8_t)minute,(uint8_t)second};
    munit_assert_int(TC_X509_time_compare(&options.at,&options.at,&order), ==, TC_TLV_OK);
  }
  options.parsing = (TC_TLV_limits){65536,65536,4096,32};
  options.max_certificates = MAX_CERTIFICATES;
  options.max_input = 512 * 1024;
  options.max_work = WORK_BUDGET;
  options.signatures = *signatures;
  return options;
}

static MunitResult corpus_case(const MunitParameter params[], void* user)
{
  const char* target_path = getenv("TC_X509_TARGET");
  const char* expected_path = getenv("TC_X509_EXPECT_PATH");
  TC_bytes target;
  TC_bytes anchor_bytes[MAX_CERTIFICATES], crls[MAX_CRLS];
  corpus_source records = {0}, revocation_records = {0};
  TC_X509_store_source source = {&records,0,0,read_candidate,read_anchor};
  TC_X509_store_source revocation_source = {&revocation_records,0,0,
    read_candidate,read_anchor};
  TC_TLV_frame parse_frames[32], path_frames[32];
  TC_bytes parse_oids[32], path_oids[32];
  TC_X509_workspace parser = {parse_frames,32,parse_oids,32};
  uint32_t left[256], right[256];
  uint8_t matched[32], states[MAX_CRLS];
  TC_X509_policy_node nodes[64];
  TC_X509_policy_edge edges[128];
  TC_X509_policy_expected expected[64];
  TC_X509_policy_mapping mappings[32];
  TC_bytes policies[64], path[MAX_CERTIFICATES], held[MAX_CERTIFICATES];
  TC_X509_search_frame search_frames[MAX_CERTIFICATES];
  TC_X509_path_workspace validation = TC_X509_PATH_WORKSPACE_INIT(path_frames,path_oids,
      left,right,matched,nodes,edges,expected,mappings,policies);
  TC_X509_search_workspace search = {path,search_frames,MAX_CERTIFICATES};
  TC_X509_revocation_node dependencies[MAX_CERTIFICATES];
  TC_X509_crl_record crl_records[MAX_CRLS];
  TC_X509_crl_index crl_index;
  TC_ECDSA_workspace ec;
  TC_RSA_word rsa_words[TC_RSA_VERIFY_WORKSPACE_WORDS(4096)];
  TC_RSA_workspace rsa = {rsa_words,sizeof rsa_words / sizeof *rsa_words};
  TC_X509_native_workspace native = {&ec,&rsa,TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  TC_X509_signature_provider signatures = TC_X509_native_provider(&native);
  TC_X509_path_options options = path_options(&signatures);
  TC_X509_search_result result;
  size_t crl_count, anchor_count, work;
  (void)params; (void)user;

  munit_assert_not_null(target_path);
  munit_assert_not_null(expected_path);
  target = load_file(target_path);

  records.candidate_count = load_numbered("TC_X509_CANDIDATE",records.candidates,MAX_CERTIFICATES);
  anchor_count = load_numbered("TC_X509_ANCHOR",anchor_bytes,MAX_CERTIFICATES);
  crl_count = load_numbered("TC_X509_CRL",crls,MAX_CRLS);
  munit_assert_size(anchor_count, >, 0);
  for (size_t i = 0; i < anchor_count; ++i) {
    TC_X509_certificate parsed;
    munit_assert_int(TC_X509_read(anchor_bytes[i].data,anchor_bytes[i].length,
        &options.parsing,&parser,&parsed), ==, TC_TLV_OK);
    records.anchors[i].trust = (TC_X509_trust_anchor){parsed.subject,parsed.public_key};
  }
  records.anchor_count = source.anchor_count = anchor_count;
  source.candidate_count = records.candidate_count;
  TC_X509_path_status path_status = TC_X509_path_build(target,&source,&options,
      &validation,&search,&result);
  if (strcmp(expected_path,"valid") == 0) {
    munit_assert_int(path_status, ==, TC_X509_PATH_VALID);
  } else if (strcmp(expected_path,"limit") == 0) {
    munit_assert_int(path_status, ==, TC_X509_PATH_LIMIT);
  } else {
    munit_assert_string_equal(expected_path,"invalid");
    munit_assert_int(path_status, ==, TC_X509_PATH_INVALID);
  }
  munit_assert_size(records.anchor_calls, >, 0);
  munit_assert_size(records.candidate_calls, <=, WORK_BUDGET);
  munit_assert_size(records.anchor_calls, <=, WORK_BUDGET);

  if (path_status == TC_X509_PATH_VALID && getenv("TC_X509_EXPECT_REVOCATION")) {
    const char* expected_revocation = getenv("TC_X509_EXPECT_REVOCATION");
    munit_assert_size(result.count, <=, MAX_CERTIFICATES);
    /* CRL signer discovery needs encoded certificates so it can enforce the
     * signer's certificate constraints. Trust anchors carry only name/key trust. */
    munit_assert_size(records.candidate_count, <=, MAX_CERTIFICATES - anchor_count);
    for (size_t i = 0; i < records.candidate_count; ++i)
      revocation_records.candidates[revocation_records.candidate_count++] = records.candidates[i];
    for (size_t i = 0; i < anchor_count; ++i) {
      revocation_records.candidates[revocation_records.candidate_count++] = anchor_bytes[i];
      revocation_records.anchors[i] = records.anchors[i];
    }
    revocation_records.anchor_count = revocation_source.anchor_count = anchor_count;
    revocation_source.candidate_count = revocation_records.candidate_count;
    memcpy(held,result.path,result.count * sizeof *held);
    work = WORK_BUDGET;
    munit_assert_int(TC_X509_crl_index_init(crls,crl_count,&options.parsing,&parser,&work,
        crl_records,MAX_CRLS,&crl_index), ==, TC_TLV_OK);
    const char* delta = getenv("TC_X509_DELTA");
    TC_X509_revocation_options revocation = {&crl_index,&revocation_source,&options,result.anchor_index,
      512 * 1024,delta ? TC_X509_CRL_DELTA_IF_AVAILABLE : TC_X509_CRL_COMPLETE_ONLY,
      TC_X509_CRL_ORDER_NUMBER};
    TC_X509_revocation_workspace workspace = {&validation,&search,states,sizeof states,
      dependencies,MAX_CERTIFICATES};
    TC_X509_revocation_result evidence, saved_evidence;
    TC_TLV_result expected_checked;
    if (strcmp(expected_revocation,"unsupported") == 0) expected_checked = TC_TLV_UNSUPPORTED;
    else if (strcmp(expected_revocation,"invalid") == 0) expected_checked = TC_TLV_INVALID;
    else {
      munit_assert_true(strcmp(expected_revocation,"revoked") == 0 ||
          strcmp(expected_revocation,"unrevoked") == 0);
      expected_checked = TC_TLV_OK;
    }
    memset(states,0,sizeof states);
    memset(dependencies,0,sizeof dependencies);
    memset(&saved_evidence,0xa5,sizeof saved_evidence);
    evidence = saved_evidence;
    work = WORK_BUDGET;
    TC_TLV_result checked = TC_X509_path_check_revocation(held,result.count,&revocation,
        &workspace,&work,&evidence);
    munit_assert_int(checked, ==, expected_checked);
    if (checked == TC_TLV_OK) {
      munit_assert_int(evidence.status, ==, strcmp(expected_revocation,"revoked") == 0 ?
          TC_X509_CRL_REVOKED : TC_X509_CRL_UNREVOKED);
    } else munit_assert_memory_equal(sizeof evidence,&evidence,&saved_evidence);
    const size_t required = WORK_BUDGET - work;
    munit_assert_size(required, >, 0);
    memset(states,0,sizeof states);
    memset(dependencies,0,sizeof dependencies);
    evidence = saved_evidence;
    work = required;
    munit_assert_int(TC_X509_path_check_revocation(held,result.count,&revocation,
        &workspace,&work,&evidence), ==, expected_checked);
    munit_assert_size(work, ==, 0);
    if (expected_checked != TC_TLV_OK)
      munit_assert_memory_equal(sizeof evidence,&evidence,&saved_evidence);
    memset(states,0,sizeof states);
    memset(dependencies,0,sizeof dependencies);
    evidence = saved_evidence;
    work = required - 1;
    munit_assert_int(TC_X509_path_check_revocation(held,result.count,&revocation,
        &workspace,&work,&evidence), ==, TC_TLV_LIMIT);
    munit_assert_memory_equal(sizeof evidence,&evidence,&saved_evidence);
    munit_assert_size(revocation_records.candidate_calls, <=, WORK_BUDGET);
    munit_assert_size(revocation_records.anchor_calls, <=, WORK_BUDGET);
  }
  free((void*)target.data);
  free_bytes(records.candidates,records.candidate_count);
  free_bytes(anchor_bytes,anchor_count);
  free_bytes(crls,crl_count);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {{"/case",corpus_case,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}};
  MunitSuite suite = {"/x509/path-corpus",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
