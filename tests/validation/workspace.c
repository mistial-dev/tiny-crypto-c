/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/validation.h>
#include "../../src/credential_status_internal.h"
#include "munit.h"
#include "test_util.h"
#include <string.h>

enum { ARENA_UNITS = 4096 };
static TC_validation_storage arena[ARENA_UNITS];

TC_TEST(status_mapping)
{
  munit_assert_int(tc_credential_signature_status(TC_X509_SIGNATURE_VALID), ==,
                   TC_CREDENTIAL_VALID);
  munit_assert_int(tc_credential_signature_status(TC_X509_SIGNATURE_INVALID), ==,
                   TC_CREDENTIAL_INVALID);
  munit_assert_int(tc_credential_signature_status(TC_X509_SIGNATURE_LIMIT), ==,
                   TC_CREDENTIAL_LIMIT);
  munit_assert_int(tc_credential_signature_status(TC_X509_SIGNATURE_UNSUPPORTED), ==,
                   TC_CREDENTIAL_UNSUPPORTED);
  munit_assert_int(tc_credential_signature_status((TC_X509_signature_result)127), ==,
                   TC_CREDENTIAL_ERROR);
  munit_assert_int(tc_credential_tlv_status(TC_TLV_OK, &tc_credential_tlv_validation), ==,
                   TC_CREDENTIAL_VALID);
  /* A failed storage source is a source failure under both policies. */
  munit_assert_int(tc_credential_tlv_status(TC_TLV_IO, &tc_credential_tlv_validation), ==,
                   TC_CREDENTIAL_ERROR);
  munit_assert_int(tc_credential_tlv_status((TC_TLV_result)127, &tc_credential_tlv_validation), ==,
                   TC_CREDENTIAL_INVALID);
  munit_assert_int(tc_credential_tlv_status(TC_TLV_OK, &tc_credential_tlv_cms), ==,
                   TC_CREDENTIAL_ERROR);
  munit_assert_int(tc_credential_tlv_status(TC_TLV_IO, &tc_credential_tlv_cms), ==,
                   TC_CREDENTIAL_ERROR);
  munit_assert_int(tc_credential_tlv_status((TC_TLV_result)127, &tc_credential_tlv_cms), ==,
                   TC_CREDENTIAL_ERROR);
  return MUNIT_OK;
}

TC_TEST(profiles)
{
  size_t previous = 0;
  for (int profile = TC_VALIDATION_MICRO; profile <= TC_VALIDATION_DESKTOP; ++profile) {
    TC_validation_capacity capacity;
    TC_validation_workspace workspace;
    size_t bytes = 0;
    munit_assert_int(TC_validation_capacity_init((TC_validation_profile)profile, &capacity), ==,
                     TC_RESULT_OK);
    munit_assert_int(TC_validation_workspace_size(&capacity, &bytes), ==, TC_RESULT_OK);
    munit_assert_size(bytes, >, previous);
    munit_assert_size(bytes, <=, sizeof arena);
    memset(arena, 0xa5, sizeof arena);
    munit_assert_int(
        TC_validation_workspace_init(&capacity, (TC_buffer){(uint8_t*)arena, bytes}, &workspace),
        ==, TC_RESULT_OK);
    munit_assert_ptr_equal(workspace.credential.path, &workspace.path);
    munit_assert_size(workspace.path.search.capacity, ==, capacity.path);
    munit_assert_size(workspace.path.validation.certificate_capacity, ==, capacity.path);
    munit_assert_size(workspace.credential.path_capacity, ==, capacity.path);
    munit_assert_size(workspace.path.validation.names.scalar_capacity, ==, capacity.name_scalars);
    const void* starts[] = {workspace.path.validation.frames.data,
                            workspace.path.validation.oids,
                            workspace.path.validation.names.left,
                            workspace.path.validation.names.right,
                            workspace.path.validation.names.matched,
                            workspace.path.validation.nodes,
                            workspace.path.validation.edges,
                            workspace.path.validation.expected,
                            workspace.path.validation.mappings,
                            workspace.path.validation.policies,
                            workspace.path.validation.certificates,
                            workspace.path.search.path,
                            workspace.path.search.frames,
                            workspace.path.certificates,
                            workspace.path.signature,
                            workspace.credential.held_path,
                            workspace.credential.crl_states,
                            workspace.credential.nodes};
    uintptr_t last = (uintptr_t)arena;
    for (size_t i = 0; i < sizeof starts / sizeof *starts; ++i) {
      munit_assert_true((uintptr_t)starts[i] >= last);
      munit_assert_true((uintptr_t)starts[i] < (uintptr_t)arena + bytes);
      munit_assert_size((uintptr_t)starts[i] % TC_validation_workspace_alignment(), ==, 0);
      last = (uintptr_t)starts[i] + 1;
    }
    for (size_t i = 0; i < sizeof arena; ++i)
      munit_assert_uint8(((uint8_t*)arena)[i], ==, 0xa5);
    previous = bytes;
  }
  return MUNIT_OK;
}

static TC_X509_path_capacity path_capacity(const TC_validation_capacity* c)
{
  TC_X509_path_capacity path = {
      c->frames,       c->oids,         c->name_scalars,    c->name_attributes,
      c->policy_nodes, c->policy_edges, c->policy_expected, c->policy_mappings,
      c->policies,     c->path};
  return path;
}

/* The validation arena starts with the TC_X509_path_workspace_init layout for
 * the same counts, followed by the CMS search and revocation arrays. */
TC_TEST(shared_path_layout)
{
  TC_validation_capacity capacities[4];
  for (int profile = TC_VALIDATION_MICRO; profile <= TC_VALIDATION_DESKTOP; ++profile)
    munit_assert_int(
        TC_validation_capacity_init((TC_validation_profile)profile, &capacities[profile]), ==,
        TC_RESULT_OK);
  /* Minimum counts, zero policy arrays and an odd signature size. */
  capacities[3] = (TC_validation_capacity){.frames = 1,
                                           .oids = 1,
                                           .name_scalars = 1,
                                           .name_attributes = 1,
                                           .path = 1,
                                           .certificates = 1,
                                           .signature_bytes = 3,
                                           .crls = 1};
  /* Exact sizes for LP64 hosts with 8-byte alignment. */
  static const size_t lp64_bytes[4] = {9232, 18592, 68480, 776};
  for (size_t i = 0; i < 4; ++i) {
    const TC_validation_capacity* capacity = &capacities[i];
    const TC_X509_path_capacity path = path_capacity(capacity);
    TC_validation_workspace workspace;
    TC_X509_path_workspace expected;
    size_t bytes = 0, path_bytes = 0;
    munit_assert_int(TC_validation_workspace_size(capacity, &bytes), ==, TC_RESULT_OK);
    munit_assert_int(TC_X509_path_workspace_size(&path, &path_bytes), ==, TC_RESULT_OK);
    munit_assert_size(bytes, >, path_bytes);
    munit_assert_size(TC_validation_workspace_alignment() % TC_X509_path_workspace_alignment(), ==,
                      0);
    if (sizeof(void*) == 8 && sizeof(size_t) == 8 && TC_validation_workspace_alignment() == 8)
      munit_assert_size(bytes, ==, lp64_bytes[i]);
    munit_assert_int(
        TC_validation_workspace_init(capacity, (TC_buffer){(uint8_t*)arena, bytes}, &workspace), ==,
        TC_RESULT_OK);
    munit_assert_int(
        TC_X509_path_workspace_init(&path, (TC_buffer){(uint8_t*)arena, path_bytes}, &expected), ==,
        TC_RESULT_OK);
    const TC_X509_path_workspace* actual = &workspace.path.validation;
    munit_assert_ptr_equal(actual->frames.data, expected.frames.data);
    munit_assert_ptr_equal(actual->oids, expected.oids);
    munit_assert_ptr_equal(actual->names.left, expected.names.left);
    munit_assert_ptr_equal(actual->names.right, expected.names.right);
    munit_assert_ptr_equal(actual->names.matched, expected.names.matched);
    munit_assert_ptr_equal(actual->nodes, expected.nodes);
    munit_assert_ptr_equal(actual->edges, expected.edges);
    munit_assert_ptr_equal(actual->expected, expected.expected);
    munit_assert_ptr_equal(actual->mappings, expected.mappings);
    munit_assert_ptr_equal(actual->policies, expected.policies);
    munit_assert_ptr_equal(actual->certificates, expected.certificates);
    munit_assert_ptr_equal(actual->summaries, expected.summaries);
    munit_assert_size(actual->frames.capacity, ==, expected.frames.capacity);
    munit_assert_size(actual->oid_capacity, ==, expected.oid_capacity);
    munit_assert_size(actual->names.scalar_capacity, ==, expected.names.scalar_capacity);
    munit_assert_size(actual->names.attribute_capacity, ==, expected.names.attribute_capacity);
    munit_assert_size(actual->node_capacity, ==, expected.node_capacity);
    munit_assert_size(actual->edge_capacity, ==, expected.edge_capacity);
    munit_assert_size(actual->expected_capacity, ==, expected.expected_capacity);
    munit_assert_size(actual->mapping_capacity, ==, expected.mapping_capacity);
    munit_assert_size(actual->policy_capacity, ==, expected.policy_capacity);
    munit_assert_size(actual->certificate_capacity, ==, expected.certificate_capacity);
    munit_assert_size(actual->summary_capacity, ==, expected.summary_capacity);
    /* The remaining arrays follow the path layout in declaration order. */
    const struct {
      const void* start;
      size_t bytes;
    } tail[] = {
        {workspace.path.search.path, capacity->path * sizeof(TC_bytes)},
        {workspace.path.search.frames, capacity->path * sizeof(TC_X509_search_frame)},
        {workspace.path.certificates, capacity->certificates * sizeof(TC_bytes)},
        {workspace.path.signature, capacity->signature_bytes},
        {workspace.path.signed_digest, TC_CMS_SIGNED_DIGEST_BYTES},
        {workspace.credential.held_path, capacity->path * sizeof(TC_bytes)},
        {workspace.credential.crl_states, capacity->crls},
        {workspace.credential.nodes, capacity->revocation_nodes * sizeof(TC_X509_revocation_node)},
        {workspace.credential.scopes, capacity->crls * sizeof(TC_X509_revocation_scope)},
        {workspace.credential.signer_path, capacity->path * sizeof(TC_bytes)},
        {workspace.credential.signer_policies, capacity->policies * sizeof(TC_bytes)}};
    uintptr_t end = (uintptr_t)arena + path_bytes;
    for (size_t t = 0; t < sizeof tail / sizeof *tail; ++t) {
      if (!tail[t].bytes) {
        munit_assert_null(tail[t].start);
        continue;
      }
      munit_assert_size((uintptr_t)tail[t].start % TC_validation_workspace_alignment(), ==, 0);
      munit_assert_true((uintptr_t)tail[t].start >= end);
      end = (uintptr_t)tail[t].start + tail[t].bytes;
    }
    munit_assert_true(end <= (uintptr_t)arena + bytes);
    munit_assert_true((uintptr_t)arena + bytes - end < TC_validation_workspace_alignment() ||
                      end == (uintptr_t)arena + bytes);
  }
  return MUNIT_OK;
}

/* A short arena, or a count that overflows in the path part or in the CMS and
 * revocation part, returns LIMIT with the workspace and arena unchanged. */
TC_TEST(limits_leave_outputs_unchanged)
{
  for (int profile = TC_VALIDATION_MICRO; profile <= TC_VALIDATION_DESKTOP; ++profile) {
    TC_validation_capacity capacity;
    TC_validation_workspace workspace, saved;
    size_t bytes = 0;
    munit_assert_int(TC_validation_capacity_init((TC_validation_profile)profile, &capacity), ==,
                     TC_RESULT_OK);
    munit_assert_int(TC_validation_workspace_size(&capacity, &bytes), ==, TC_RESULT_OK);
    memset(arena, 0x5a, sizeof arena);
    memset(&workspace, 0xa5, sizeof workspace);
    memcpy(&saved, &workspace, sizeof saved);
    munit_assert_int(TC_validation_workspace_init(
                         &capacity, (TC_buffer){(uint8_t*)arena, bytes - 1}, &workspace),
                     ==, TC_RESULT_LIMIT);
    munit_assert_memory_equal(sizeof saved, &workspace, &saved);
    for (size_t i = 0; i < sizeof arena; ++i)
      munit_assert_uint8(((uint8_t*)arena)[i], ==, 0x5a);
  }
  for (int field = 0; field < 5; ++field) {
    TC_validation_capacity capacity;
    TC_validation_workspace workspace, saved;
    size_t untouched = 123;
    munit_assert_int(TC_validation_capacity_init(TC_VALIDATION_MICRO, &capacity), ==, TC_RESULT_OK);
    switch (field) {
    case 0:
      capacity.policy_mappings = SIZE_MAX / 2;
      break;
    case 1:
      capacity.certificates = SIZE_MAX / 2;
      break;
    case 2:
      capacity.signature_bytes = SIZE_MAX - 8;
      break;
    case 3:
      capacity.revocation_nodes = SIZE_MAX / 2;
      break;
    default:
      capacity.crls = SIZE_MAX / 2;
      break;
    }
    munit_assert_int(TC_validation_workspace_size(&capacity, &untouched), ==, TC_RESULT_LIMIT);
    munit_assert_size(untouched, ==, 123);
    memset(&workspace, 0xa5, sizeof workspace);
    memcpy(&saved, &workspace, sizeof saved);
    munit_assert_int(TC_validation_workspace_init(
                         &capacity, (TC_buffer){(uint8_t*)arena, sizeof arena}, &workspace),
                     ==, TC_RESULT_LIMIT);
    munit_assert_memory_equal(sizeof saved, &workspace, &saved);
  }
  return MUNIT_OK;
}

TC_TEST(invalid_storage)
{
  TC_validation_capacity capacity;
  TC_validation_workspace workspace, saved;
  size_t bytes;
  munit_assert_int(TC_validation_capacity_init(TC_VALIDATION_MICRO, &capacity), ==, TC_RESULT_OK);
  munit_assert_int(TC_validation_workspace_size(&capacity, &bytes), ==, TC_RESULT_OK);
  memset(&workspace, 0xa5, sizeof workspace);
  memcpy(&saved, &workspace, sizeof saved);
  munit_assert_int(
      TC_validation_workspace_init(&capacity, (TC_buffer){(uint8_t*)arena, bytes - 1}, &workspace),
      ==, TC_RESULT_LIMIT);
  munit_assert_memory_equal(sizeof saved, &workspace, &saved);
  munit_assert_int(
      TC_validation_workspace_init(&capacity, (TC_buffer){(uint8_t*)arena + 1, bytes}, &workspace),
      ==, TC_RESULT_ARGUMENT);
  munit_assert_int(TC_validation_workspace_init(
                       &capacity, (TC_buffer){(uint8_t*)&workspace, sizeof workspace}, &workspace),
                   ==, TC_RESULT_ARGUMENT);
  munit_assert_int(
      TC_validation_workspace_init(&capacity, (TC_buffer){(uint8_t*)arena, SIZE_MAX}, &workspace),
      ==, TC_RESULT_ARGUMENT);
  capacity.frames = SIZE_MAX;
  size_t untouched = 123;
  munit_assert_int(TC_validation_workspace_size(&capacity, &untouched), ==, TC_RESULT_LIMIT);
  munit_assert_size(untouched, ==, 123);
  capacity.frames = 0;
  munit_assert_int(TC_validation_workspace_size(&capacity, &untouched), ==, TC_RESULT_ARGUMENT);
  munit_assert_memory_equal(sizeof saved, &workspace, &saved);
  munit_assert_int(TC_validation_capacity_init((TC_validation_profile)99, &capacity), ==,
                   TC_RESULT_ARGUMENT);
  return MUNIT_OK;
}

TC_TEST(context_setup)
{
  TC_validation_capacity capacity;
  TC_validation_workspace workspace;
  TC_validation_context context, saved;
  TC_X509_store_source source = {0};
  TC_X509_crl_index crls = {0};
  TC_validation_trust trust = {&source, &crls};
  TC_validation_options options = {0};
  options.at = (TC_X509_time){2026, 1, 1, 0, 0, 0};
  options.max_certificates = 4;
  options.max_candidates = 8;
  options.max_input = options.max_candidate_bytes = 65536;
  munit_assert_int(TC_validation_capacity_init(TC_VALIDATION_MICRO, &capacity), ==, TC_RESULT_OK);
  munit_assert_int(TC_validation_workspace_init(
                       &capacity, (TC_buffer){(uint8_t*)arena, sizeof arena}, &workspace),
                   ==, TC_RESULT_OK);
  munit_assert_int(TC_validation_context_init(&trust, &options, &workspace.credential, &context),
                   ==, TC_RESULT_OK);
  munit_assert_ptr_equal(context.options, &options);
  munit_assert_ptr_equal(context.trust.crls, &crls);
  static const uint8_t empty_sequence[] = {0x30, 0};
  const TC_CMS_validation_request cms_request = {
      .encoded = {empty_sequence, sizeof empty_sequence},
      .expected_type = {empty_sequence, sizeof empty_sequence}};
  size_t work = 10000;
  munit_assert_size(workspace.path.signature_capacity, >=, sizeof context);
  TC_validation_context* alias_context = (TC_validation_context*)workspace.path.signature;
  *alias_context = context;
  munit_assert_int(TC_CMS_validate(&cms_request, alias_context, &work, NULL), ==,
                   TC_CREDENTIAL_ERROR);
  munit_assert_size(work, ==, 10000);
  munit_assert_size(workspace.path.signature_capacity, >=, sizeof options);
  TC_validation_options* alias_options = (TC_validation_options*)workspace.path.signature;
  *alias_options = options;
  TC_validation_context alias_options_context = context;
  alias_options_context.options = alias_options;
  munit_assert_int(TC_CMS_validate(&cms_request, &alias_options_context, &work, NULL), ==,
                   TC_CREDENTIAL_ERROR);
  munit_assert_size(work, ==, 10000);
  memcpy(&saved, &context, sizeof saved);
  union {
    TC_X509_store_source source;
    TC_validation_context context;
  } source_alias = {0};
  trust.certificates = &source_alias.source;
  munit_assert_int(
      TC_validation_context_init(&trust, &options, &workspace.credential, &source_alias.context),
      ==, TC_RESULT_ARGUMENT);
  trust.certificates = &source;
  union {
    TC_X509_crl_index crls;
    TC_validation_context context;
  } crl_alias = {0};
  trust.crls = &crl_alias.crls;
  munit_assert_int(
      TC_validation_context_init(&trust, &options, &workspace.credential, &crl_alias.context), ==,
      TC_RESULT_ARGUMENT);
  trust.crls = &crls;
  union {
    TC_CMS_path_workspace path;
    TC_validation_context context;
  } path_alias = {0};
  TC_CMS_credential_workspace credential = workspace.credential;
  credential.path = &path_alias.path;
  munit_assert_int(TC_validation_context_init(&trust, &options, &credential, &path_alias.context),
                   ==, TC_RESULT_ARGUMENT);
  options.at.month = 13;
  munit_assert_int(TC_validation_context_init(&trust, &options, &workspace.credential, &context),
                   ==, TC_RESULT_ARGUMENT);
  munit_assert_memory_equal(sizeof saved, &saved, &context);
  options.at.month = 1;
  options.verification.attributes = (TC_CMS_attribute_encoding)99;
  munit_assert_int(TC_validation_context_init(&trust, &options, &workspace.credential, &context),
                   ==, TC_RESULT_ARGUMENT);
  options.verification.attributes = TC_CMS_ATTRIBUTES_DER;
  /* Every policy enum rejects values on both sides of its range. */
  for (int bad = -1; bad <= 1; bad += 2) {
    TC_validation_options changed = options;
    changed.verification.rsa_parameters =
        (TC_CMS_rsa_parameters)(bad < 0 ? bad : TC_CMS_RSA_PARAMETERS_ALLOW_ABSENT + bad);
    munit_assert_int(TC_validation_context_init(&trust, &changed, &workspace.credential, &context),
                     ==, TC_RESULT_ARGUMENT);
    changed = options;
    changed.verification.envelope =
        (TC_CMS_envelope_encoding)(bad < 0 ? bad : TC_CMS_ENVELOPE_DER + bad);
    munit_assert_int(TC_validation_context_init(&trust, &changed, &workspace.credential, &context),
                     ==, TC_RESULT_ARGUMENT);
    changed = options;
    changed.verification.attribute_oids =
        (TC_CMS_attribute_oids)(bad < 0 ? bad : TC_CMS_ATTRIBUTE_OIDS_PIV_TWIC + bad);
    munit_assert_int(TC_validation_context_init(&trust, &changed, &workspace.credential, &context),
                     ==, TC_RESULT_ARGUMENT);
    changed = options;
    changed.verification.other_attributes =
        (TC_CMS_other_attributes)(bad < 0 ? bad : TC_CMS_OTHER_ATTRIBUTES_SKIP_ALL + bad);
    munit_assert_int(TC_validation_context_init(&trust, &changed, &workspace.credential, &context),
                     ==, TC_RESULT_ARGUMENT);
    changed = options;
    changed.delta_policy =
        (TC_X509_crl_delta_policy)(bad < 0 ? bad : TC_X509_CRL_DELTA_REQUIRED + bad);
    munit_assert_int(TC_validation_context_init(&trust, &changed, &workspace.credential, &context),
                     ==, TC_RESULT_ARGUMENT);
    changed = options;
    changed.order_policy =
        (TC_X509_crl_order_policy)(bad < 0 ? bad : TC_X509_CRL_ORDER_THIS_UPDATE + bad);
    munit_assert_int(TC_validation_context_init(&trust, &changed, &workspace.credential, &context),
                     ==, TC_RESULT_ARGUMENT);
  }
  TC_X509_validation_result result, unchanged;
  memset(&result, 0xa5, sizeof result);
  memcpy(&unchanged, &result, sizeof result);
  work = 0;
  munit_assert_int(
      TC_X509_validate((TC_bytes){empty_sequence, sizeof empty_sequence}, &context, &work, &result),
      ==, TC_CREDENTIAL_LIMIT);
  munit_assert_memory_equal(sizeof result, &unchanged, &result);
  work = 10000;
  munit_assert_int(TC_X509_validate((TC_bytes){empty_sequence, sizeof empty_sequence}, &context,
                                    &work, (TC_X509_validation_result*)arena),
                   ==, TC_CREDENTIAL_ERROR);
  munit_assert_size(work, ==, 10000);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
      {"/status-mapping", status_mapping, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/profiles", profiles, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/shared-path-layout", shared_path_layout, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/limits", limits_leave_outputs_unchanged, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/invalid-storage", invalid_storage, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/context", context_setup, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/validation/workspace", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
