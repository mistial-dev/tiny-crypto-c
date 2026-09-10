/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/validation.h>
#include "munit.h"
#include <string.h>

enum { ARENA_UNITS = 4096 };
static TC_validation_storage arena[ARENA_UNITS];

static MunitResult profiles(const MunitParameter params[], void* context)
{
  size_t previous = 0;
  for (int profile = TC_VALIDATION_MICRO; profile <= TC_VALIDATION_DESKTOP; ++profile) {
    TC_validation_capacity capacity;
    TC_validation_workspace workspace;
    size_t bytes = 0;
    munit_assert_int(TC_validation_capacity_init((TC_validation_profile)profile,&capacity),
        ==,TC_RESULT_OK);
    munit_assert_int(TC_validation_workspace_size(&capacity,&bytes),==,TC_RESULT_OK);
    munit_assert_size(bytes,>,previous);
    munit_assert_size(bytes,<=,sizeof arena);
    memset(arena,0xa5,sizeof arena);
    munit_assert_int(TC_validation_workspace_init(&capacity,
        (TC_buffer){(uint8_t*)arena,bytes},&workspace),==,TC_RESULT_OK);
    munit_assert_ptr_equal(workspace.credential.path,&workspace.path);
    munit_assert_size(workspace.path.search.capacity,==,capacity.path);
    munit_assert_size(workspace.credential.path_capacity,==,capacity.path);
    munit_assert_size(workspace.path.validation.names.scalar_capacity,==,capacity.name_scalars);
    const void* starts[] = {workspace.path.validation.frames,
      workspace.path.validation.oids,workspace.path.validation.names.left,
      workspace.path.validation.names.right,workspace.path.validation.names.matched,
      workspace.path.validation.nodes,workspace.path.validation.edges,
      workspace.path.validation.expected,workspace.path.validation.mappings,
      workspace.path.validation.policies,workspace.path.search.path,
      workspace.path.search.frames,workspace.path.certificates,workspace.path.signature,
      workspace.credential.held_path,workspace.credential.crl_states,workspace.credential.nodes};
    uintptr_t last = (uintptr_t)arena;
    for (size_t i = 0; i < sizeof starts / sizeof *starts; ++i) {
      munit_assert_true((uintptr_t)starts[i] >= last);
      munit_assert_true((uintptr_t)starts[i] < (uintptr_t)arena + bytes);
      munit_assert_size((uintptr_t)starts[i] % TC_validation_workspace_alignment(),==,0);
      last = (uintptr_t)starts[i] + 1;
    }
    for (size_t i = 0; i < sizeof arena; ++i)
      munit_assert_uint8(((uint8_t*)arena)[i],==,0xa5);
    previous = bytes;
  }
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult invalid_storage(const MunitParameter params[], void* context)
{
  TC_validation_capacity capacity;
  TC_validation_workspace workspace, saved;
  size_t bytes;
  munit_assert_int(TC_validation_capacity_init(TC_VALIDATION_MICRO,&capacity),==,TC_RESULT_OK);
  munit_assert_int(TC_validation_workspace_size(&capacity,&bytes),==,TC_RESULT_OK);
  memset(&workspace,0xa5,sizeof workspace);
  memcpy(&saved,&workspace,sizeof saved);
  munit_assert_int(TC_validation_workspace_init(&capacity,
      (TC_buffer){(uint8_t*)arena,bytes - 1},&workspace),==,TC_RESULT_LIMIT);
  munit_assert_memory_equal(sizeof saved,&workspace,&saved);
  munit_assert_int(TC_validation_workspace_init(&capacity,
      (TC_buffer){(uint8_t*)arena + 1,bytes},&workspace),==,TC_RESULT_ARGUMENT);
  munit_assert_int(TC_validation_workspace_init(&capacity,
      (TC_buffer){(uint8_t*)&workspace,sizeof workspace},&workspace),==,TC_RESULT_ARGUMENT);
  munit_assert_int(TC_validation_workspace_init(&capacity,
      (TC_buffer){(uint8_t*)arena,SIZE_MAX},&workspace),==,TC_RESULT_ARGUMENT);
  capacity.frames = SIZE_MAX;
  size_t untouched = 123;
  munit_assert_int(TC_validation_workspace_size(&capacity,&untouched),==,TC_RESULT_LIMIT);
  munit_assert_size(untouched,==,123);
  capacity.frames = 0;
  munit_assert_int(TC_validation_workspace_size(&capacity,&untouched),==,TC_RESULT_ARGUMENT);
  munit_assert_memory_equal(sizeof saved,&workspace,&saved);
  munit_assert_int(TC_validation_capacity_init((TC_validation_profile)99,&capacity),
      ==,TC_RESULT_ARGUMENT);
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult context_setup(const MunitParameter params[], void* user)
{
  TC_validation_capacity capacity;
  TC_validation_workspace workspace;
  TC_validation_context context, saved;
  TC_X509_store_source source = {0};
  TC_X509_crl_index crls = {0};
  TC_validation_trust trust = {&source,&crls};
  TC_validation_options options = {0};
  options.at = (TC_X509_time){2026,1,1,0,0,0};
  options.max_certificates = 4;
  options.max_candidates = 8;
  options.max_input = options.max_candidate_bytes = 65536;
  munit_assert_int(TC_validation_capacity_init(TC_VALIDATION_MICRO,&capacity),==,TC_RESULT_OK);
  munit_assert_int(TC_validation_workspace_init(&capacity,
      (TC_buffer){(uint8_t*)arena,sizeof arena},&workspace),==,TC_RESULT_OK);
  munit_assert_int(TC_validation_context_init(&trust,&options,&workspace.credential,&context),
      ==,TC_RESULT_OK);
  munit_assert_ptr_equal(context.options,&options);
  munit_assert_ptr_equal(context.trust.crls,&crls);
  static const uint8_t empty_sequence[] = {0x30,0};
  const TC_CMS_validation_request cms_request = {
    .encoded = {empty_sequence,sizeof empty_sequence},
    .expected_type = {empty_sequence,sizeof empty_sequence}
  };
  size_t work = 10000;
  munit_assert_size(workspace.path.signature_capacity,>=,sizeof context);
  TC_validation_context* alias_context = (TC_validation_context*)workspace.path.signature;
  *alias_context = context;
  munit_assert_int(TC_CMS_validate(&cms_request,alias_context,&work),==,TC_CREDENTIAL_ERROR);
  munit_assert_size(work,==,10000);
  munit_assert_size(workspace.path.signature_capacity,>=,sizeof options);
  TC_validation_options* alias_options = (TC_validation_options*)workspace.path.signature;
  *alias_options = options;
  TC_validation_context alias_options_context = context;
  alias_options_context.options = alias_options;
  munit_assert_int(TC_CMS_validate(&cms_request,&alias_options_context,&work),
      ==,TC_CREDENTIAL_ERROR);
  munit_assert_size(work,==,10000);
  memcpy(&saved,&context,sizeof saved);
  union {
    TC_X509_store_source source;
    TC_validation_context context;
  } source_alias = {0};
  trust.certificates = &source_alias.source;
  munit_assert_int(TC_validation_context_init(&trust,&options,&workspace.credential,
      &source_alias.context),==,TC_RESULT_ARGUMENT);
  trust.certificates = &source;
  union {
    TC_X509_crl_index crls;
    TC_validation_context context;
  } crl_alias = {0};
  trust.crls = &crl_alias.crls;
  munit_assert_int(TC_validation_context_init(&trust,&options,&workspace.credential,
      &crl_alias.context),==,TC_RESULT_ARGUMENT);
  trust.crls = &crls;
  union {
    TC_CMS_path_workspace path;
    TC_validation_context context;
  } path_alias = {0};
  TC_CMS_credential_workspace credential = workspace.credential;
  credential.path = &path_alias.path;
  munit_assert_int(TC_validation_context_init(&trust,&options,&credential,
      &path_alias.context),==,TC_RESULT_ARGUMENT);
  options.at.month = 13;
  munit_assert_int(TC_validation_context_init(&trust,&options,&workspace.credential,&context),
      ==,TC_RESULT_ARGUMENT);
  munit_assert_memory_equal(sizeof saved,&saved,&context);
  options.at.month = 1;
  options.attributes = (TC_CMS_attribute_encoding)99;
  munit_assert_int(TC_validation_context_init(&trust,&options,&workspace.credential,&context),
      ==,TC_RESULT_ARGUMENT);
  options.attributes = TC_CMS_ATTRIBUTES_DER;
  TC_X509_validation_result result, unchanged;
  memset(&result,0xa5,sizeof result);
  memcpy(&unchanged,&result,sizeof result);
  work = 0;
  munit_assert_int(TC_X509_validate((TC_bytes){empty_sequence,sizeof empty_sequence},
      &context,&work,&result),==,TC_CREDENTIAL_LIMIT);
  munit_assert_memory_equal(sizeof result,&unchanged,&result);
  work = 10000;
  munit_assert_int(TC_X509_validate((TC_bytes){empty_sequence,sizeof empty_sequence},
      &context,&work,(TC_X509_validation_result*)arena),==,TC_CREDENTIAL_ERROR);
  munit_assert_size(work,==,10000);
  (void)params; (void)user;
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/profiles",profiles,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/invalid-storage",invalid_storage,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/context",context_setup,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/validation/workspace",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
