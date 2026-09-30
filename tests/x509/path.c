/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../src/x509_path_internal.h"
#include "../../src/x509_path_status_internal.h"
#include "../../src/x509_policy_internal.h"
#include "munit.h"
#include "test_util.h"
#include <stddef.h>
#include <string.h>

typedef struct {
  unsigned calls;
  TC_X509_signature_result result;
} Provider;
/* Each validation clears the summary cache. Direct pass calls do the same so
 * every call summarizes the current certificate views. */
static tc_x509_path_input* fresh(tc_x509_path_input* input)
{
  memset(input->summaries, 0, input->count * sizeof *input->summaries);
  return input;
}

static TC_X509_signature_result verify(void* context, const TC_bytes* message, size_t count,
                                       const TC_DER_algorithm* algorithm, TC_bytes signature,
                                       const TC_X509_public_key* key, size_t* work)
{
  Provider* provider = (Provider*)context;
  (void)message;
  (void)count;
  (void)algorithm;
  (void)signature;
  (void)key;
  ++provider->calls;
  if (!*work)
    return TC_X509_SIGNATURE_LIMIT;
  --*work;
  return provider->result;
}

TC_TEST(basic)
{
  const uint8_t names[][14] = {{0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 0x0c, 1, 'A'},
                               {0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 0x0c, 1, 'B'},
                               {0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 0x0c, 1, 'C'},
                               {0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 0x0c, 1, 'D'}};
  const uint8_t identifiers[] = {1, 2, 3};
  const uint8_t oid[] = {0x2a, 3};
  uint8_t extensions[] = {0x30, 33, 0x30, 18,   6,  3, 0x55, 0x1d, 19, 1, 1,    0xff,
                          4,    8,  0x30, 6,    1,  1, 0xff, 2,    1,  1, 0x30, 11,
                          6,    3,  0x55, 0x1d, 15, 4, 4,    3,    2,  2, 4};
  TC_X509_certificate certificates[3], saved;
  TC_X509_trust_anchor anchor;
  const TC_X509_time at = {2026, 1, 1, 0, 0, 0};
  const TC_X509_time before = {2024, 1, 1, 0, 0, 0}, after = {2028, 1, 1, 0, 0, 0};
  const TC_TLV_limits limits = {1024, 1024, 64, 8};
  uint32_t left[32], right[32];
  uint8_t used[4];
  TC_X509_name_workspace workspace = {left, right, 32, used, 4};
  Provider state = {0, TC_X509_SIGNATURE_VALID};
  TC_X509_signature_provider signatures = {verify, &state, NULL};
  TC_X509_extension_summary summaries[3];
  tc_x509_path_input input = {certificates, 3,           3,       3,    &anchor,
                              &at,          &signatures, &limits, NULL, NULL,
                              NULL,         summaries,   0,       0,    0};
  size_t i, work = 100000, required;
  int accepted = 99;
  memset(certificates, 0, sizeof certificates);
  memset(&anchor, 0, sizeof anchor);
  anchor.name.data = names[0];
  anchor.name.length = sizeof names[0];
  anchor.public_key.algorithm.oid.data = oid;
  anchor.public_key.algorithm.oid.length = sizeof oid;
  anchor.public_key.key.data = identifiers;
  anchor.public_key.key.length = sizeof identifiers;
  for (i = 0; i < 3; ++i) {
    certificates[i].encoded.data = identifiers + i;
    certificates[i].encoded.length = 1;
    certificates[i].tbs = certificates[i].signature = certificates[i].encoded;
    certificates[i].signature_algorithm = anchor.public_key.algorithm;
    certificates[i].public_key = anchor.public_key;
    certificates[i].issuer.data = names[i];
    certificates[i].issuer.length = sizeof names[i];
    certificates[i].subject.data = names[i + 1];
    certificates[i].subject.length = sizeof names[i + 1];
    certificates[i].not_before = before;
    certificates[i].not_after = after;
    certificates[i].version = 3;
    certificates[i].extensions.data = extensions;
    certificates[i].extensions.length = sizeof extensions;
  }
  munit_assert_int(tc_x509_path_basic(fresh(&input), &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  munit_assert_uint(state.calls, ==, 3);
  required = 100000 - work;
  for (i = 0; i < required; ++i) {
    work = i;
    accepted = 99;
    munit_assert_int(tc_x509_path_basic(fresh(&input), &workspace, &work, &accepted), ==,
                     TC_TLV_LIMIT);
    munit_assert_int(accepted, ==, 99);
  }
  extensions[21] = 0;
  work = 100000;
  munit_assert_int(tc_x509_path_basic(fresh(&input), &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  certificates[1].subject = certificates[1].issuer;
  certificates[2].issuer = certificates[1].subject;
  work = 100000;
  input.has_anchor_path_len = 1;
  input.anchor_path_len = 1;
  munit_assert_int(tc_x509_path_basic(fresh(&input), &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  input.anchor_path_len = 0;
  work = 100000;
  munit_assert_int(tc_x509_path_basic(fresh(&input), &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  input.has_anchor_path_len = 0;
  certificates[1].subject.data = names[2];
  certificates[2].issuer.data = names[2];
  extensions[21] = 1;
  extensions[33] = 7;
  extensions[34] = 0x80;
  work = 100000;
  munit_assert_int(tc_x509_path_basic(fresh(&input), &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  extensions[33] = 2;
  extensions[34] = 4;
  saved = certificates[0];
  certificates[0].extensions.data = NULL;
  certificates[0].extensions.length = 0;
  work = 100000;
  munit_assert_int(tc_x509_path_basic(fresh(&input), &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  certificates[0] = saved;
  certificates[1].not_after.year = 2025;
  work = 100000;
  munit_assert_int(tc_x509_path_basic(fresh(&input), &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  certificates[1].not_after = after;
  saved = certificates[2];
  certificates[2] = certificates[1];
  work = 100000;
  state.calls = 0;
  munit_assert_int(tc_x509_path_basic(fresh(&input), &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  munit_assert_uint(state.calls, ==, 0);
  certificates[2] = saved;
  input.max_input = 2;
  work = 100000;
  accepted = 99;
  munit_assert_int(tc_x509_path_basic(fresh(&input), &workspace, &work, &accepted), ==,
                   TC_TLV_LIMIT);
  munit_assert_int(accepted, ==, 99);
  input.max_input = 3;
  input.max_certificates = 2;
  munit_assert_int(tc_x509_path_basic(fresh(&input), &workspace, &work, &accepted), ==,
                   TC_TLV_LIMIT);
  munit_assert_int(accepted, ==, 99);
  input.max_certificates = 3;
  input.signatures = NULL;
  munit_assert_int(tc_x509_path_basic(fresh(&input), &workspace, &work, &accepted), ==,
                   TC_TLV_UNSUPPORTED);
  munit_assert_int(accepted, ==, 99);
  input.signatures = &signatures;
  state.result = TC_X509_SIGNATURE_INVALID;
  munit_assert_int(tc_x509_path_basic(fresh(&input), &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  /* Clock skew widens each validity period on both sides. */
  state.result = TC_X509_SIGNATURE_VALID;
  certificates[2].not_after = (TC_X509_time){2025, 12, 31, 23, 59, 50};
  certificates[1].not_before = (TC_X509_time){2026, 1, 1, 0, 0, 10};
  static const struct {
    uint32_t skew;
    int accepted;
  } skews[] = {{0, 0}, {9, 0}, {10, 1}, {UINT32_MAX, 1}};
  for (i = 0; i < sizeof skews / sizeof *skews; ++i) {
    input.clock_skew_seconds = skews[i].skew;
    work = 100000;
    munit_assert_int(tc_x509_path_basic(fresh(&input), &workspace, &work, &accepted), ==,
                     TC_TLV_OK);
    munit_assert_int(accepted, ==, skews[i].accepted);
  }
  return MUNIT_OK;
}

TC_TEST(names)
{
  const uint8_t dn_a[] = {0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 0x0c, 1, 'A'};
  const uint8_t dn_b[] = {0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 0x0c, 1, 'B'};
  const uint8_t encoded[] = {1, 2, 3};
  uint8_t constraints[] = {0x30, 18,   0x30, 16,   6, 3,    0x55, 0x1d, 30, 4,
                           9,    0x30, 7,    0xa0, 5, 0x30, 3,    0x82, 1,  'a'};
  uint8_t narrower[sizeof constraints];
  uint8_t san[] = {0x30, 14, 0x30, 12, 6, 3, 0x55, 0x1d, 17, 4, 5, 0x30, 3, 0x82, 1, 'a'};
  TC_X509_certificate certificates[3];
  TC_TLV_limits limits = {1024, 1024, 64, 8};
  uint32_t left[32], right[32];
  uint8_t used[4];
  TC_TLV_frame frames[8];
  TC_X509_name_workspace name_workspace = {left, right, 32, used, 4};
  TC_X509_constraint_workspace workspace = {{frames, 8}, &name_workspace};
  TC_X509_extension_summary summaries[3];
  tc_x509_path_input input = {certificates, 3,    3,    3,         NULL, NULL, NULL, &limits,
                              NULL,         NULL, NULL, summaries, 0,    0,    0};
  size_t i, work = 100000, required;
  int accepted = 99;
  memset(certificates, 0, sizeof certificates);
  memcpy(narrower, constraints, sizeof narrower);
  for (i = 0; i < 3; ++i) {
    certificates[i].encoded.data = encoded + i;
    certificates[i].encoded.length = 1;
    certificates[i].subject.data = dn_b;
    certificates[i].subject.length = sizeof dn_b;
    certificates[i].issuer.data = dn_a;
    certificates[i].issuer.length = sizeof dn_a;
  }
  certificates[0].extensions.data = constraints;
  certificates[0].extensions.length = sizeof constraints;
  certificates[1].extensions.data = narrower;
  certificates[1].extensions.length = sizeof narrower;
  certificates[2].extensions.data = san;
  certificates[2].extensions.length = sizeof san;
  munit_assert_int(tc_x509_path_names(fresh(&input), &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  required = 100000 - work;
  for (i = 0; i < required; ++i) {
    work = i;
    accepted = 99;
    munit_assert_int(tc_x509_path_names(fresh(&input), &workspace, &work, &accepted), ==,
                     TC_TLV_LIMIT);
    munit_assert_int(accepted, ==, 99);
  }
  narrower[19] = 'b';
  work = 100000;
  munit_assert_int(tc_x509_path_names(fresh(&input), &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  narrower[19] = 'a';
  constraints[13] = 0xa1;
  work = 100000;
  munit_assert_int(tc_x509_path_names(fresh(&input), &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  constraints[13] = 0xa0;
  constraints[15] = 0x31;
  work = 100000;
  accepted = 99;
  munit_assert_int(tc_x509_path_names(fresh(&input), &workspace, &work, &accepted), ==,
                   TC_TLV_INVALID);
  munit_assert_int(accepted, ==, 99);
  constraints[15] = 0x30;
  /* A rollover certificate is exempt, but its child still inherits the constraint. */
  san[15] = 'b';
  certificates[1].extensions = certificates[2].extensions;
  certificates[2].extensions.data = NULL;
  certificates[2].extensions.length = 0;
  work = 100000;
  munit_assert_int(tc_x509_path_names(fresh(&input), &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  certificates[1].subject = certificates[1].issuer;
  work = 100000;
  munit_assert_int(tc_x509_path_names(fresh(&input), &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  certificates[2].extensions = certificates[1].extensions;
  certificates[2].subject = certificates[2].issuer;
  work = 100000;
  munit_assert_int(tc_x509_path_names(fresh(&input), &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  return MUNIT_OK;
}

/* Policy controls as the policy pass derives them from a certificate. */
static TC_TLV_result read_controls(const TC_X509_certificate* certificate,
                                   const TC_TLV_limits* limits, size_t* work,
                                   tc_x509_policy_controls* out)
{
  TC_X509_extension_summary summary;
  TC_TLV_result result = tc_x509_extensions_summarize(certificate, limits, work, &summary);
  if (result == TC_TLV_OK)
    tc_x509_policy_controls_from_summary(&summary, out);
  return result;
}

TC_TEST(policy_controls)
{
  uint8_t extensions[] = {0x30, 29, 0x30, 15,   6,  3, 0x55, 0x1d, 36,   4,  8, 0x30, 6, 0x80, 1, 2,
                          0x81, 1,  3,    0x30, 10, 6, 3,    0x55, 0x1d, 54, 4, 3,    2, 1,    4};
  TC_X509_certificate certificate;
  const TC_TLV_limits limits = {1024, 1024, 64, 8};
  tc_x509_policy_controls controls, saved;
  tc_x509_policy_counters counters;
  size_t work = 1000, required, i;
  unsigned target, self_issued;
  memset(&certificate, 0, sizeof certificate);
  certificate.extensions.data = extensions;
  certificate.extensions.length = sizeof extensions;
  munit_assert_int(read_controls(&certificate, &limits, &work, &controls), ==, TC_TLV_OK);
  munit_assert_int(controls.constraints.has_require_explicit_policy, ==, 1);
  munit_assert_int(controls.constraints.has_inhibit_policy_mapping, ==, 1);
  munit_assert_int(controls.has_inhibit_any, ==, 1);
  munit_assert_uint(controls.constraints.require_explicit_policy, ==, 2);
  munit_assert_uint(controls.constraints.inhibit_policy_mapping, ==, 3);
  munit_assert_uint(controls.inhibit_any, ==, 4);
  saved = controls;
  required = 1000 - work;
  for (i = 0; i < required; ++i) {
    work = i;
    munit_assert_int(read_controls(&certificate, &limits, &work, &controls), ==, TC_TLV_LIMIT);
    munit_assert_memory_equal(sizeof controls, &controls, &saved);
  }
  for (target = 0; target < 2; ++target) {
    for (self_issued = 0; self_issued < 2; ++self_issued) {
      counters.explicit_policy = counters.mapping = counters.any = 5;
      tc_x509_policy_counters_advance(&counters, &controls, self_issued, target);
      munit_assert_size(counters.explicit_policy, ==, target ? 4 : 2);
      munit_assert_size(counters.mapping, ==, target ? 5 : 3);
      munit_assert_size(counters.any, ==, target ? 5 : 4);
    }
  }
  controls.constraints.require_explicit_policy = 0;
  counters.explicit_policy = counters.mapping = counters.any = 5;
  tc_x509_policy_counters_advance(&counters, &controls, 1, 1);
  munit_assert_size(counters.explicit_policy, ==, 0);
  munit_assert_size(counters.mapping, ==, 5);
  munit_assert_size(counters.any, ==, 5);
  controls = saved;
  extensions[30] = 0xff;
  work = 1000;
  munit_assert_int(read_controls(&certificate, &limits, &work, &controls), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof controls, &controls, &saved);
  certificate.extensions.data = NULL;
  certificate.extensions.length = 0;
  work = 1000;
  munit_assert_int(read_controls(&certificate, &limits, &work, &controls), ==, TC_TLV_OK);
  munit_assert_int(controls.has_inhibit_any, ==, 0);
  munit_assert_int(controls.constraints.has_require_explicit_policy, ==, 0);
  munit_assert_int(controls.constraints.has_inhibit_policy_mapping, ==, 0);
  counters.explicit_policy = counters.mapping = counters.any = 5;
  tc_x509_policy_counters_advance(&counters, &controls, 1, 0);
  munit_assert_size(counters.explicit_policy, ==, 5);
  munit_assert_size(counters.mapping, ==, 5);
  munit_assert_size(counters.any, ==, 5);
  tc_x509_policy_counters_advance(&counters, &controls, 0, 0);
  munit_assert_size(counters.explicit_policy, ==, 4);
  munit_assert_size(counters.mapping, ==, 4);
  munit_assert_size(counters.any, ==, 4);
  counters.explicit_policy = counters.mapping = counters.any = 0;
  tc_x509_policy_counters_advance(&counters, &controls, 0, 0);
  munit_assert_size(counters.explicit_policy, ==, 0);
  munit_assert_size(counters.mapping, ==, 0);
  munit_assert_size(counters.any, ==, 0);
  return MUNIT_OK;
}

/* One intermediate certificate's policy processing: RFC 5280 section 6.1.3
 * (d)-(f) through graph_step, then section 6.1.4 (a)-(b) through graph_map. */
static TC_TLV_result policy_certificate(tc_x509_policy_graph* graph, const TC_bytes* policies,
                                        size_t policy_count, const TC_X509_policy_mapping* mappings,
                                        size_t mapping_count, int allow_mapping, size_t* work)
{
  TC_TLV_result result = tc_x509_policy_graph_step(graph, policies, policy_count, 1, work);
  if (result != TC_TLV_OK)
    return result;
  return tc_x509_policy_graph_map(graph, mappings, mapping_count, allow_mapping, work);
}

TC_TEST(policy_graph)
{
  const uint8_t oid_bytes[][2] = {{0x2a, 1}, {0x2a, 2}, {0x2a, 3}};
  const uint8_t any_bytes[] = {0x55, 0x1d, 0x20, 0};
  TC_bytes policies[] = {{oid_bytes[0], 2}, {oid_bytes[1], 2}, {oid_bytes[2], 2}};
  TC_bytes any = {any_bytes, sizeof any_bytes};
  TC_X509_policy_mapping mappings[] = {{policies[0], policies[2]}, {policies[1], policies[2]}};
  TC_X509_policy_node nodes[32];
  TC_X509_policy_edge edges[64];
  TC_X509_policy_expected expected[64];
  tc_x509_policy_graph graph = {nodes, 32, 0, edges, 64, 0, expected, 64, 0, 0};
  size_t work = 100000, required, budget, i;
  munit_assert_int(tc_x509_policy_graph_init(&graph), ==, TC_TLV_OK);
  munit_assert_int(policy_certificate(&graph, policies, 2, mappings, 2, 1, &work), ==, TC_TLV_OK);
  munit_assert_int(tc_x509_policy_graph_step(&graph, policies + 2, 1, 1, &work), ==, TC_TLV_OK);
  munit_assert_size(graph.node_count, ==, 4);
  munit_assert_size(graph.edge_count, ==, 4);
  munit_assert_size(edges[2].child, ==, 3);
  munit_assert_size(edges[3].child, ==, 3);
  munit_assert_size(edges[2].parent, ==, 1);
  munit_assert_size(edges[3].parent, ==, 2);
  for (i = 0; i < 4; ++i)
    munit_assert_int(nodes[i].alive, ==, 1);
  required = 100000 - work;
  for (budget = 0; budget < required; ++budget) {
    TC_TLV_result result;
    work = budget;
    munit_assert_int(tc_x509_policy_graph_init(&graph), ==, TC_TLV_OK);
    result = policy_certificate(&graph, policies, 2, mappings, 2, 1, &work);
    if (result == TC_TLV_OK)
      result = tc_x509_policy_graph_step(&graph, policies + 2, 1, 1, &work);
    munit_assert_int(result, ==, TC_TLV_LIMIT);
  }
  work = required;
  munit_assert_int(tc_x509_policy_graph_init(&graph), ==, TC_TLV_OK);
  munit_assert_int(policy_certificate(&graph, policies, 2, mappings, 2, 1, &work), ==, TC_TLV_OK);
  munit_assert_int(tc_x509_policy_graph_step(&graph, policies + 2, 1, 1, &work), ==, TC_TLV_OK);
  munit_assert_size(work, ==, 0);
  work = 100000;
  munit_assert_int(tc_x509_policy_graph_init(&graph), ==, TC_TLV_OK);
  munit_assert_int(policy_certificate(&graph, policies, 2, mappings, 2, 0, &work), ==, TC_TLV_OK);
  for (i = 0; i < graph.node_count; ++i)
    munit_assert_int(nodes[i].alive, ==, 0);
  munit_assert_int(tc_x509_policy_graph_step(&graph, &any, 1, 1, &work), ==, TC_TLV_OK);
  munit_assert_size(graph.node_count, ==, 3);
  munit_assert_int(tc_x509_policy_graph_init(&graph), ==, TC_TLV_OK);
  munit_assert_int(tc_x509_policy_graph_step(&graph, &any, 1, 0, &work), ==, TC_TLV_OK);
  munit_assert_int(nodes[0].alive, ==, 0);
  munit_assert_int(tc_x509_policy_graph_init(&graph), ==, TC_TLV_OK);
  munit_assert_int(policy_certificate(&graph, &any, 1, mappings, 1, 1, &work), ==, TC_TLV_OK);
  munit_assert_size(graph.node_count, ==, 3);
  munit_assert_int(tc_x509_policy_graph_step(&graph, policies + 2, 1, 1, &work), ==, TC_TLV_OK);
  munit_assert_size(graph.edge_count, ==, 3);
  munit_assert_int(nodes[1].alive, ==, 0);
  munit_assert_int(nodes[2].alive, ==, 1);
  munit_assert_size(edges[2].parent, ==, 2);
  for (i = 0; i < 3; ++i) {
    graph.node_capacity = i == 0 ? 2 : 32;
    graph.edge_capacity = i == 1 ? 1 : 64;
    graph.expected_capacity = i == 2 ? 1 : 64;
    work = 100000;
    munit_assert_int(tc_x509_policy_graph_init(&graph), ==, TC_TLV_OK);
    munit_assert_int(policy_certificate(&graph, policies, 2, mappings, 2, 1, &work), ==,
                     TC_TLV_LIMIT);
  }
  graph.node_capacity = 32;
  graph.edge_capacity = graph.expected_capacity = 64;
  work = 100000;
  munit_assert_int(tc_x509_policy_graph_init(&graph), ==, TC_TLV_OK);
  munit_assert_int(policy_certificate(&graph, policies, 2, mappings, 2, 1, &work), ==, TC_TLV_OK);
  munit_assert_int(tc_x509_policy_graph_step(&graph, &any, 1, 1, &work), ==, TC_TLV_OK);
  munit_assert_size(graph.node_count, ==, 4);
  munit_assert_size(graph.edge_count, ==, 4);
  munit_assert_memory_equal(2, nodes[3].oid.data, policies[2].data);
  {
    TC_X509_policy_mapping invalid = {any, policies[0]};
    munit_assert_int(tc_x509_policy_graph_init(&graph), ==, TC_TLV_OK);
    munit_assert_int(policy_certificate(&graph, policies, 2, &invalid, 1, 1, &work), ==,
                     TC_TLV_INVALID);
    invalid.issuer_policy = policies[0];
    invalid.subject_policy = any;
    munit_assert_int(tc_x509_policy_graph_init(&graph), ==, TC_TLV_OK);
    munit_assert_int(policy_certificate(&graph, policies, 2, &invalid, 1, 1, &work), ==,
                     TC_TLV_INVALID);
  }
  {
    TC_X509_policy_mapping cross[] = {{policies[0], policies[0]},
                                      {policies[0], policies[1]},
                                      {policies[1], policies[0]},
                                      {policies[1], policies[1]}};
    work = 1000000;
    munit_assert_int(tc_x509_policy_graph_init(&graph), ==, TC_TLV_OK);
    for (i = 0; i < 8; ++i)
      munit_assert_int(policy_certificate(&graph, policies, 2, cross, 4, 1, &work), ==, TC_TLV_OK);
    munit_assert_size(graph.node_count, ==, 17);
    munit_assert_size(graph.edge_count, ==, 30);
    munit_assert_size(graph.expected_count, ==, 32);
  }
  /* A map step without mappings changes nothing and charges no work. Each
   * certificate then pays for one prune. */
  {
    const size_t before = work = 1000;
    munit_assert_int(tc_x509_policy_graph_init(&graph), ==, TC_TLV_OK);
    munit_assert_int(tc_x509_policy_graph_step(&graph, policies, 2, 1, &work), ==, TC_TLV_OK);
    const size_t step_work = before - work;
    munit_assert_int(tc_x509_policy_graph_map(&graph, NULL, 0, 1, &work), ==, TC_TLV_OK);
    munit_assert_size(before - work, ==, step_work);
  }
  return MUNIT_OK;
}

TC_TEST(policies)
{
  const uint8_t dn[] = {0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 0x0c, 1, 'A'};
  const uint8_t oid_bytes[][2] = {{0x2a, 1}, {0x2a, 2}};
  const uint8_t any_bytes[] = {0x55, 0x1d, 0x20, 0};
  const TC_bytes initial[] = {{oid_bytes[0], 2}, {oid_bytes[1], 2}, {any_bytes, sizeof any_bytes}};
  const uint8_t issuing[] = {0x30, 38,   0x30, 15,   6,    3,  0x55, 0x1d, 32,   4,
                             8,    0x30, 6,    0x30, 4,    6,  2,    0x2a, 1,    0x30,
                             19,   6,    3,    0x55, 0x1d, 33, 4,    12,   0x30, 10,
                             0x30, 8,    6,    2,    0x2a, 1,  6,    2,    0x2a, 2};
  const uint8_t leaf[] = {0x30, 17,   0x30, 15,   6, 3, 0x55, 0x1d, 32, 4,
                          8,    0x30, 6,    0x30, 4, 6, 2,    0x2a, 2};
  TC_X509_certificate certificates[2];
  const TC_TLV_limits limits = {1024, 1024, 64, 8};
  TC_X509_extension_summary summaries[3];
  tc_x509_path_input input = {certificates, 2,    2,    2048,      NULL, NULL, NULL, &limits,
                              NULL,         NULL, NULL, summaries, 0,    0,    0};
  uint32_t left[32], right[32];
  uint8_t used[4];
  TC_X509_name_workspace names = {left, right, 32, used, 4};
  TC_X509_policy_node nodes[8];
  TC_X509_policy_edge edges[8];
  TC_X509_policy_expected expected[8];
  tc_x509_policy_graph graph = {nodes, 8, 0, edges, 8, 0, expected, 8, 0, 0};
  TC_bytes policy_scratch[4], output[4];
  TC_X509_policy_mapping mappings[4];
  TC_TLV_frame frames[8];
  tc_x509_policy_workspace workspace = {&graph, policy_scratch, 4,          mappings, 4, output,
                                        4,      &names,         {frames, 8}};
  tc_x509_policy_options options = {initial, 1, 1, 0, 0};
  size_t i, count = 99, work = 100000, required;
  int accepted = 99;
  memset(certificates, 0, sizeof certificates);
  for (i = 0; i < 2; ++i) {
    certificates[i].issuer.data = dn;
    certificates[i].issuer.length = sizeof dn;
    certificates[i].subject = certificates[i].issuer;
  }
  certificates[0].extensions.data = issuing;
  certificates[0].extensions.length = sizeof issuing;
  certificates[1].extensions.data = leaf;
  certificates[1].extensions.length = sizeof leaf;
  munit_assert_int(tc_x509_path_policies(fresh(&input), &options, (TC_bytes){NULL, 0}, &workspace,
                                         &work, &count, &accepted),
                   ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  munit_assert_size(count, ==, 1);
  munit_assert_memory_equal(2, output[0].data, initial[0].data);
  required = 100000 - work;
  for (i = 0; i < required; ++i) {
    work = i;
    count = 99;
    accepted = 99;
    munit_assert_int(tc_x509_path_policies(fresh(&input), &options, (TC_bytes){NULL, 0}, &workspace,
                                           &work, &count, &accepted),
                     ==, TC_TLV_LIMIT);
    munit_assert_size(count, ==, 99);
    munit_assert_int(accepted, ==, 99);
  }
  work = required;
  munit_assert_int(tc_x509_path_policies(fresh(&input), &options, (TC_bytes){NULL, 0}, &workspace,
                                         &work, &count, &accepted),
                   ==, TC_TLV_OK);
  munit_assert_size(work, ==, 0);
  munit_assert_int(accepted, ==, 1);
  {
    const uint8_t anchor_a[] = {0x30, 4, 6, 2, 0x2a, 1};
    const uint8_t anchor_b[] = {0x30, 4, 6, 2, 0x2a, 2};
    const TC_bytes app_with_any[] = {initial[2], initial[1]};
    work = 100000;
    munit_assert_int(tc_x509_path_policies(fresh(&input), &options,
                                           (TC_bytes){anchor_a, sizeof anchor_a}, &workspace, &work,
                                           &count, &accepted),
                     ==, TC_TLV_OK);
    munit_assert_int(accepted, ==, 1);
    munit_assert_size(count, ==, 1);
    work = 100000;
    munit_assert_int(tc_x509_path_policies(fresh(&input), &options,
                                           (TC_bytes){anchor_b, sizeof anchor_b}, &workspace, &work,
                                           &count, &accepted),
                     ==, TC_TLV_OK);
    munit_assert_int(accepted, ==, 0);
    munit_assert_size(count, ==, 0);
    options.initial = app_with_any;
    options.initial_count = 2;
    work = 100000;
    munit_assert_int(tc_x509_path_policies(fresh(&input), &options,
                                           (TC_bytes){anchor_a, sizeof anchor_a}, &workspace, &work,
                                           &count, &accepted),
                     ==, TC_TLV_OK);
    munit_assert_int(accepted, ==, 1);
    munit_assert_size(count, ==, 1);
    options.initial = initial;
    options.initial_count = 1;
  }
  options.initial = initial + 1;
  work = 100000;
  munit_assert_int(tc_x509_path_policies(fresh(&input), &options, (TC_bytes){NULL, 0}, &workspace,
                                         &work, &count, &accepted),
                   ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  munit_assert_size(count, ==, 0);
  options.initial = initial + 2;
  work = 100000;
  munit_assert_int(tc_x509_path_policies(fresh(&input), &options, (TC_bytes){NULL, 0}, &workspace,
                                         &work, &count, &accepted),
                   ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  munit_assert_size(count, ==, 1);
  munit_assert_memory_equal(2, output[0].data, initial[0].data);
  options.inhibit_mapping = 1;
  work = 100000;
  munit_assert_int(tc_x509_path_policies(fresh(&input), &options, (TC_bytes){NULL, 0}, &workspace,
                                         &work, &count, &accepted),
                   ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  options.inhibit_mapping = 0;
  workspace.output_capacity = 0;
  work = 100000;
  count = 99;
  accepted = 99;
  munit_assert_int(tc_x509_path_policies(fresh(&input), &options, (TC_bytes){NULL, 0}, &workspace,
                                         &work, &count, &accepted),
                   ==, TC_TLV_LIMIT);
  munit_assert_size(count, ==, 99);
  munit_assert_int(accepted, ==, 99);
  workspace.output_capacity = 4;
  certificates[1].extensions.data = NULL;
  certificates[1].extensions.length = 0;
  work = 100000;
  munit_assert_int(tc_x509_path_policies(fresh(&input), &options, (TC_bytes){NULL, 0}, &workspace,
                                         &work, &count, &accepted),
                   ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  munit_assert_size(count, ==, 0);
  options.require_explicit = 0;
  work = 100000;
  munit_assert_int(tc_x509_path_policies(fresh(&input), &options, (TC_bytes){NULL, 0}, &workspace,
                                         &work, &count, &accepted),
                   ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  munit_assert_size(count, ==, 0);
  return MUNIT_OK;
}

TC_TEST(qualifiers)
{
  static const struct {
    uint8_t value[24];
    size_t length;
    unsigned kind;
    TC_TLV_result result;
  } cases[] = {{{0x16, 3, 'a', ':', 'b'}, 5, 1, TC_TLV_OK},
               {{0x0c, 3, 'a', ':', 'b'}, 5, 1, TC_TLV_INVALID},
               {{0x16, 1, 0xff}, 3, 1, TC_TLV_INVALID},
               {{0x30, 0}, 2, 2, TC_TLV_OK},
               {{0x30, 3, 0x0c, 1, 'a'}, 5, 2, TC_TLV_OK},
               {{0x30, 3, 0x16, 1, 'a'}, 5, 2, TC_TLV_OK},
               {{0x30, 3, 0x1a, 1, 'a'}, 5, 2, TC_TLV_OK},
               {{0x30, 4, 0x1e, 2, 0, 'a'}, 6, 2, TC_TLV_OK},
               {{0x30, 3, 0x1a, 1, 0x1f}, 5, 2, TC_TLV_INVALID},
               {{0x30, 3, 0x1a, 1, 0x7f}, 5, 2, TC_TLV_INVALID},
               {{0x30, 3, 0x0c, 1, 0xc0}, 5, 2, TC_TLV_INVALID},
               {{0x30, 4, 0x1e, 2, 0xd8, 0}, 6, 2, TC_TLV_INVALID},
               {{0x30, 2, 0x0c, 0}, 4, 2, TC_TLV_INVALID},
               {{0x30, 3, 0x13, 1, 'a'}, 5, 2, TC_TLV_INVALID},
               {{0x30, 6, 0x0c, 1, 'a', 0x0c, 1, 'b'}, 8, 2, TC_TLV_INVALID},
               {{0x30, 7, 0x30, 5, 0x0c, 1, 'a', 0x30, 0}, 9, 2, TC_TLV_OK},
               {{0x30, 10, 0x30, 8, 0x0c, 1, 'a', 0x30, 3, 2, 1, 0xff}, 12, 2, TC_TLV_OK},
               {{0x30, 11, 0x30, 9, 0x0c, 1, 'a', 0x30, 4, 2, 2, 0, 1}, 13, 2, TC_TLV_INVALID},
               {{0x30, 7, 0x30, 5, 0x0c, 1, 'a', 0x31, 0}, 9, 2, TC_TLV_INVALID},
               {{0x30, 5, 0x30, 3, 0x0c, 1, 'a'}, 7, 2, TC_TLV_INVALID},
               {{5, 0}, 2, 3, TC_TLV_UNSUPPORTED}};
  uint8_t encoded[128] = {0x30, 0, 0x30, 0, 6, 8, 0x2b, 6, 1, 5, 5, 7, 2, 0};
  const uint8_t ordinary[] = {0x2a, 1}, wildcard[] = {0x55, 0x1d, 0x20, 0};
  TC_X509_policy policy = {{ordinary, sizeof ordinary}, {encoded, 0}};
  TC_TLV_frame frames[8];
  TC_TLV_limits limits = {1024, 1024, 64, 8};
  size_t i, budget, required, work;
  for (i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
    encoded[1] = (uint8_t)(12 + cases[i].length);
    encoded[3] = (uint8_t)(10 + cases[i].length);
    encoded[13] = (uint8_t)cases[i].kind;
    memcpy(encoded + 14, cases[i].value, cases[i].length);
    policy.qualifiers.length = 14 + cases[i].length;
    work = 10000;
    munit_assert_int(
        tc_x509_policy_qualifiers_check(&policy, 1, &limits, (TC_TLV_frames){frames, 8}, &work), ==,
        cases[i].result);
    if (cases[i].result != TC_TLV_OK)
      continue;
    required = 10000 - work;
    for (budget = 0; budget < required; ++budget) {
      work = budget;
      munit_assert_int(
          tc_x509_policy_qualifiers_check(&policy, 1, &limits, (TC_TLV_frames){frames, 8}, &work),
          ==, TC_TLV_LIMIT);
    }
    work = 10000;
    limits.max_elements = 1;
    munit_assert_int(
        tc_x509_policy_qualifiers_check(&policy, 1, &limits, (TC_TLV_frames){frames, 8}, &work), ==,
        TC_TLV_LIMIT);
    limits.max_elements = 64;
    limits.max_depth = 0;
    work = 10000;
    munit_assert_int(
        tc_x509_policy_qualifiers_check(&policy, 1, &limits, (TC_TLV_frames){frames, 8}, &work), ==,
        TC_TLV_LIMIT);
    limits.max_depth = 8;
    work = 10000;
    munit_assert_int(
        tc_x509_policy_qualifiers_check(&policy, 1, &limits, (TC_TLV_frames){NULL, 0}, &work), ==,
        TC_TLV_LIMIT);
  }
  /* The final fixture is an unknown qualifier on an ordinary policy. */
  work = 10000;
  munit_assert_int(
      tc_x509_policy_qualifiers_check(&policy, 0, &limits, (TC_TLV_frames){frames, 8}, &work), ==,
      TC_TLV_OK);
  policy.oid.data = wildcard;
  policy.oid.length = sizeof wildcard;
  work = 10000;
  munit_assert_int(
      tc_x509_policy_qualifiers_check(&policy, 0, &limits, (TC_TLV_frames){frames, 8}, &work), ==,
      TC_TLV_UNSUPPORTED);
  return MUNIT_OK;
}

TC_TEST(usage)
{
  const uint8_t dn[] = {0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 0x0c, 1, 'A'};
  const uint8_t oid[] = {0x2a, 1};
  uint8_t extensions[] = {0x30, 28, 0x30, 11, 6,    3,    0x55, 0x1d, 15, 4,    4, 3, 2, 7,    0x80,
                          0x30, 13, 6,    3,  0x55, 0x1d, 37,   4,    6,  0x30, 4, 6, 2, 0x2a, 1};
  uint8_t unknown[] = {0x30, 12, 0x30, 10, 6, 3, 0x55, 0x1d, 99, 1, 1, 0xff, 4, 0};
  const uint8_t wildcard[] = {0x30, 17,   0x30, 15, 6, 3,    0x55, 0x1d, 37, 4,
                              8,    0x30, 6,    6,  4, 0x55, 0x1d, 37,   0};
  const uint8_t combined[] = {0x30, 21, 0x30, 19,   6,    3,  0x55, 0x1d, 37, 4,    12, 0x30,
                              10,   6,  4,    0x55, 0x1d, 37, 0,    6,    2,  0x2a, 1};
  const uint8_t issuer_wildcard[] = {0x30, 31, 0x30, 12,   6,    3,    0x55, 0x1d, 19,   4,    5,
                                     0x30, 3,  1,    1,    0xff, 0x30, 15,   6,    3,    0x55, 0x1d,
                                     37,   4,  8,    0x30, 6,    6,    4,    0x55, 0x1d, 37,   0};
  TC_X509_certificate certificates[2];
  const TC_TLV_limits limits = {1024, 1024, 64, 8};
  TC_X509_extension_summary summaries[3];
  tc_x509_path_input input = {certificates, 1,    2,    2048,      NULL, NULL, NULL, &limits,
                              NULL,         NULL, NULL, summaries, 0,    0,    0};
  uint32_t left[32], right[32];
  uint8_t used[4];
  TC_TLV_frame frames[8];
  TC_bytes oids[4];
  TC_X509_name_workspace names = {left, right, 32, used, 4};
  tc_x509_extension_workspace workspace = {oids, 4, {{frames, 8}, &names}};
  tc_x509_path_usage purpose = {{oid, sizeof oid}, 1, 1, 1, 0};
  size_t i, work = 100000, required;
  int accepted = 99;
  memset(certificates, 0, sizeof certificates);
  certificates[0].subject.data = dn;
  certificates[0].subject.length = sizeof dn;
  certificates[0].issuer = certificates[0].subject;
  certificates[0].extensions.data = extensions;
  certificates[0].extensions.length = sizeof extensions;
  munit_assert_int(tc_x509_path_extensions(fresh(&input), &purpose, &workspace, &work, &accepted),
                   ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  required = 100000 - work;
  for (i = 0; i < required; ++i) {
    accepted = 99;
    work = i;
    munit_assert_int(tc_x509_path_extensions(fresh(&input), &purpose, &workspace, &work, &accepted),
                     ==, TC_TLV_LIMIT);
    munit_assert_int(accepted, ==, 99);
  }
  extensions[29] = 2;
  work = 100000;
  munit_assert_int(tc_x509_path_extensions(fresh(&input), &purpose, &workspace, &work, &accepted),
                   ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  extensions[29] = 1;
  purpose.key_usage = 2;
  work = 100000;
  munit_assert_int(tc_x509_path_extensions(fresh(&input), &purpose, &workspace, &work, &accepted),
                   ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  purpose.key_usage = 1;
  certificates[0].extensions.data = NULL;
  certificates[0].extensions.length = 0;
  work = 100000;
  munit_assert_int(tc_x509_path_extensions(fresh(&input), &purpose, &workspace, &work, &accepted),
                   ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  purpose.require_key_usage = purpose.require_extended_key_usage = 0;
  work = 100000;
  munit_assert_int(tc_x509_path_extensions(fresh(&input), &purpose, &workspace, &work, &accepted),
                   ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  certificates[0].extensions.data = unknown;
  certificates[0].extensions.length = sizeof unknown;
  work = 100000;
  accepted = 99;
  munit_assert_int(tc_x509_path_extensions(fresh(&input), &purpose, &workspace, &work, &accepted),
                   ==, TC_TLV_UNSUPPORTED);
  munit_assert_int(accepted, ==, 99);
  /* Remove the critical BOOLEAN, retaining the same unknown extension OID. */
  unknown[1] = 9;
  unknown[3] = 7;
  unknown[9] = 4;
  unknown[10] = 0;
  certificates[0].extensions.length = 11;
  work = 100000;
  munit_assert_int(tc_x509_path_extensions(fresh(&input), &purpose, &workspace, &work, &accepted),
                   ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  certificates[0].extensions.data = wildcard;
  certificates[0].extensions.length = sizeof wildcard;
  work = 100000;
  munit_assert_int(tc_x509_path_extensions(fresh(&input), &purpose, &workspace, &work, &accepted),
                   ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  certificates[1] = certificates[0];
  input.count = 2;
  purpose.inhibit_any_purpose = 1;
  work = 100000;
  munit_assert_int(tc_x509_path_extensions(fresh(&input), &purpose, &workspace, &work, &accepted),
                   ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  input.count = 1;
  certificates[0].extensions.data = extensions;
  certificates[0].extensions.length = sizeof extensions;
  work = 100000;
  munit_assert_int(tc_x509_path_extensions(fresh(&input), &purpose, &workspace, &work, &accepted),
                   ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  /* An explicit match remains usable alongside the wildcard. */
  certificates[0].extensions = (TC_bytes){combined, sizeof combined};
  work = 100000;
  munit_assert_int(tc_x509_path_extensions(fresh(&input), &purpose, &workspace, &work, &accepted),
                   ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  certificates[0].extensions = (TC_bytes){NULL, 0};
  work = 100000;
  munit_assert_int(tc_x509_path_extensions(fresh(&input), &purpose, &workspace, &work, &accepted),
                   ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  purpose.require_extended_key_usage = 1;
  work = 100000;
  munit_assert_int(tc_x509_path_extensions(fresh(&input), &purpose, &workspace, &work, &accepted),
                   ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  purpose.require_extended_key_usage = 0;
  /* Isolate the intermediate's wildcard while the leaf explicitly permits use. */
  input.count = 2;
  certificates[0].extensions = (TC_bytes){issuer_wildcard, sizeof issuer_wildcard};
  certificates[1].extensions = (TC_bytes){extensions, sizeof extensions};
  purpose.require_extended_key_usage = 1;
  for (unsigned inhibit = 0; inhibit < 2; ++inhibit) {
    purpose.inhibit_any_purpose = (int)inhibit;
    work = 100000;
    munit_assert_int(tc_x509_path_extensions(fresh(&input), &purpose, &workspace, &work, &accepted),
                     ==, TC_TLV_OK);
    munit_assert_int(accepted, ==, !inhibit);
    const size_t needed = 100000 - work;
    work = needed - 1;
    accepted = 99;
    munit_assert_int(tc_x509_path_extensions(fresh(&input), &purpose, &workspace, &work, &accepted),
                     ==, TC_TLV_LIMIT);
    munit_assert_int(accepted, ==, 99);
  }
  certificates[1].extensions = (TC_bytes){wildcard, sizeof wildcard};
  purpose.require_extended_key_usage = 0;
  purpose.inhibit_any_purpose = 0;
  input.count = 2;
  certificates[0].extensions.data = extensions;
  certificates[0].extensions.length = sizeof extensions;
  extensions[29] = 2;
  work = 100000;
  munit_assert_int(tc_x509_path_extensions(fresh(&input), &purpose, &workspace, &work, &accepted),
                   ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  return MUNIT_OK;
}

/* Invalid options are argument errors found at the entry: an invalid
 * validation time, malformed initial-policy OID contents or a malformed
 * purpose return ERROR before the storage and anchor checks charge work. */
TC_TEST(entry_option_checks)
{
  static const uint8_t certificate[] = {0x30, 0};
  static const uint8_t any_policy[] = {0x55, 0x1d, 0x20, 0};
  static const uint8_t malformed_oid[] = {0x80, 1};
  const TC_bytes chain = {certificate, sizeof certificate};
  TC_TLV_frame frames[4];
  TC_bytes oids[4], policies[4], initial[2];
  uint32_t left[8], right[8];
  uint8_t matched[4];
  TC_X509_policy_node nodes[4];
  TC_X509_policy_edge edges[4];
  TC_X509_policy_expected expected[4];
  TC_X509_policy_mapping mappings[4];
  TC_X509_certificate certificates[2];
  TC_X509_extension_summary summaries[2];
  const TC_X509_path_workspace workspace =
      TC_X509_PATH_WORKSPACE_INIT(frames, oids, left, right, matched, nodes, edges, expected,
                                  mappings, policies, certificates, summaries);
  TC_X509_trust_anchor anchor;
  TC_X509_path_options options;
  TC_X509_path_result out;
  unsigned scenario;
  memset(&anchor, 0, sizeof anchor);
  for (scenario = 0; scenario < 3; ++scenario) {
    size_t work = 100000;
    memset(&options, 0, sizeof options);
    options.at = (TC_X509_time){2026, 1, 1, 0, 0, 0};
    options.parsing = (TC_TLV_limits){1024, 1024, 64, 8};
    options.max_certificates = 2;
    options.max_input = 1024;
    initial[0] = (TC_bytes){any_policy, sizeof any_policy};
    initial[1] = (TC_bytes){malformed_oid, sizeof malformed_oid};
    if (scenario == 0)
      options.at.month = 13;
    if (scenario == 1) {
      options.initial_policies = initial;
      options.initial_policy_count = 2;
    }
    if (scenario == 2)
      options.purpose = (TC_bytes){malformed_oid, sizeof malformed_oid};
    memset(&out, 0xa5, sizeof out);
    munit_assert_int(
        tc_x509_path_validate_budget(&chain, 1, &anchor, &options, &workspace, &work, &out), ==,
        TC_X509_PATH_ERROR);
    munit_assert_size(work, ==, 100000);
    munit_assert_true(tc_test_all_value(&out, sizeof out, 0xa5));
  }
  return MUNIT_OK;
}

static TC_X509_path_storage path_arena[256];

/* A small capacity with every array present. */
static TC_X509_path_capacity arena_capacity(void)
{
  TC_X509_path_capacity capacity;
  capacity.frames = 4;
  capacity.oids = 3;
  capacity.name_scalars = 9;
  capacity.name_attributes = 3;
  capacity.policy_nodes = 5;
  capacity.policy_edges = 6;
  capacity.policy_expected = 7;
  capacity.policy_mappings = 2;
  capacity.policies = 3;
  capacity.path = 2;
  return capacity;
}

static void assert_workspace_equal(const TC_X509_path_workspace* a, const TC_X509_path_workspace* b)
{
  munit_assert_ptr_equal(a->frames.data, b->frames.data);
  munit_assert_size(a->frames.capacity, ==, b->frames.capacity);
  munit_assert_ptr_equal(a->oids, b->oids);
  munit_assert_size(a->oid_capacity, ==, b->oid_capacity);
  munit_assert_ptr_equal(a->names.left, b->names.left);
  munit_assert_ptr_equal(a->names.right, b->names.right);
  munit_assert_size(a->names.scalar_capacity, ==, b->names.scalar_capacity);
  munit_assert_ptr_equal(a->names.matched, b->names.matched);
  munit_assert_size(a->names.attribute_capacity, ==, b->names.attribute_capacity);
  munit_assert_ptr_equal(a->nodes, b->nodes);
  munit_assert_size(a->node_capacity, ==, b->node_capacity);
  munit_assert_ptr_equal(a->edges, b->edges);
  munit_assert_size(a->edge_capacity, ==, b->edge_capacity);
  munit_assert_ptr_equal(a->expected, b->expected);
  munit_assert_size(a->expected_capacity, ==, b->expected_capacity);
  munit_assert_ptr_equal(a->mappings, b->mappings);
  munit_assert_size(a->mapping_capacity, ==, b->mapping_capacity);
  munit_assert_ptr_equal(a->policies, b->policies);
  munit_assert_size(a->policy_capacity, ==, b->policy_capacity);
  munit_assert_ptr_equal(a->certificates, b->certificates);
  munit_assert_size(a->certificate_capacity, ==, b->certificate_capacity);
  munit_assert_ptr_equal(a->summaries, b->summaries);
  munit_assert_size(a->summary_capacity, ==, b->summary_capacity);
}

/* Alignment of each element type, from the offset after a leading char. */
#define ALIGNMENT_PROBE(name, type)                                                                \
  typedef struct {                                                                                 \
    char byte;                                                                                     \
    type element;                                                                                  \
  } name
ALIGNMENT_PROBE(frame_probe, TC_TLV_frame);
ALIGNMENT_PROBE(span_probe, TC_bytes);
ALIGNMENT_PROBE(scalar_probe, uint32_t);
ALIGNMENT_PROBE(node_probe, TC_X509_policy_node);
ALIGNMENT_PROBE(edge_probe, TC_X509_policy_edge);
ALIGNMENT_PROBE(expected_probe, TC_X509_policy_expected);
ALIGNMENT_PROBE(mapping_probe, TC_X509_policy_mapping);
ALIGNMENT_PROBE(certificate_probe, TC_X509_certificate);
ALIGNMENT_PROBE(summary_probe, TC_X509_extension_summary);

/* The exact size succeeds, and the twelve arrays are ordered, aligned,
 * disjoint and end at the reported size. */
TC_TEST(workspace_arena_layout)
{
  const TC_X509_path_capacity capacity = arena_capacity();
  const size_t alignment = TC_X509_path_workspace_alignment();
  const size_t element_alignments[] = {
      offsetof(frame_probe, element),   offsetof(span_probe, element),
      offsetof(scalar_probe, element),  offsetof(node_probe, element),
      offsetof(edge_probe, element),    offsetof(expected_probe, element),
      offsetof(mapping_probe, element), offsetof(certificate_probe, element),
      offsetof(summary_probe, element)};
  TC_X509_path_workspace workspace;
  size_t bytes = 0;
  munit_assert_size(alignment, >, 0);
  for (size_t i = 0; i < sizeof element_alignments / sizeof *element_alignments; ++i)
    munit_assert_size(alignment % element_alignments[i], ==, 0);
  munit_assert_int(TC_X509_path_workspace_size(&capacity, &bytes), ==, TC_RESULT_OK);
  munit_assert_size(bytes, <=, sizeof path_arena);
  memset(path_arena, 0xa5, sizeof path_arena);
  munit_assert_int(
      TC_X509_path_workspace_init(&capacity, (TC_buffer){(uint8_t*)path_arena, bytes}, &workspace),
      ==, TC_RESULT_OK);
  munit_assert_true(tc_test_all_value(path_arena, sizeof path_arena, 0xa5));
  munit_assert_size(workspace.frames.capacity, ==, capacity.frames);
  munit_assert_size(workspace.oid_capacity, ==, capacity.oids);
  munit_assert_size(workspace.names.scalar_capacity, ==, capacity.name_scalars);
  munit_assert_size(workspace.names.attribute_capacity, ==, capacity.name_attributes);
  munit_assert_size(workspace.node_capacity, ==, capacity.policy_nodes);
  munit_assert_size(workspace.edge_capacity, ==, capacity.policy_edges);
  munit_assert_size(workspace.expected_capacity, ==, capacity.policy_expected);
  munit_assert_size(workspace.mapping_capacity, ==, capacity.policy_mappings);
  munit_assert_size(workspace.policy_capacity, ==, capacity.policies);
  munit_assert_size(workspace.certificate_capacity, ==, capacity.path);
  munit_assert_size(workspace.summary_capacity, ==, capacity.path);
  {
    const struct {
      const void* start;
      size_t bytes;
    } arrays[] = {{workspace.frames.data, capacity.frames * sizeof(TC_TLV_frame)},
                  {workspace.oids, capacity.oids * sizeof(TC_bytes)},
                  {workspace.names.left, capacity.name_scalars * sizeof(uint32_t)},
                  {workspace.names.right, capacity.name_scalars * sizeof(uint32_t)},
                  {workspace.names.matched, capacity.name_attributes},
                  {workspace.nodes, capacity.policy_nodes * sizeof(TC_X509_policy_node)},
                  {workspace.edges, capacity.policy_edges * sizeof(TC_X509_policy_edge)},
                  {workspace.expected, capacity.policy_expected * sizeof(TC_X509_policy_expected)},
                  {workspace.mappings, capacity.policy_mappings * sizeof(TC_X509_policy_mapping)},
                  {workspace.policies, capacity.policies * sizeof(TC_bytes)},
                  {workspace.certificates, capacity.path * sizeof(TC_X509_certificate)},
                  {workspace.summaries, capacity.path * sizeof(TC_X509_extension_summary)}};
    uintptr_t end = (uintptr_t)path_arena;
    for (size_t i = 0; i < sizeof arrays / sizeof *arrays; ++i) {
      const uintptr_t start = (uintptr_t)arrays[i].start;
      munit_assert_not_null(arrays[i].start);
      munit_assert_size((size_t)(start % alignment), ==, 0);
      munit_assert_true(start >= end);
      munit_assert_size((size_t)(start - end), <, alignment);
      end = start + arrays[i].bytes;
    }
    munit_assert_size((size_t)(end - (uintptr_t)path_arena), ==, bytes);
  }
  return MUNIT_OK;
}

/* A short arena is LIMIT and bad storage is ARGUMENT, both leaving out
 * unchanged. Zero policy counts leave those arrays NULL. */
TC_TEST(workspace_arena_failures)
{
  TC_X509_path_capacity capacity = arena_capacity();
  const size_t alignment = TC_X509_path_workspace_alignment();
  TC_X509_path_workspace workspace, saved;
  uint8_t* base = (uint8_t*)path_arena;
  size_t bytes = 0, untouched = 123;
  munit_assert_int(TC_X509_path_workspace_size(&capacity, &bytes), ==, TC_RESULT_OK);
  memset(&workspace, 0x5a, sizeof workspace);
  saved = workspace;
  munit_assert_int(TC_X509_path_workspace_init(&capacity, (TC_buffer){base, bytes - 1}, &workspace),
                   ==, TC_RESULT_LIMIT);
  assert_workspace_equal(&workspace, &saved);
  if (alignment > 1)
    munit_assert_int(
        TC_X509_path_workspace_init(&capacity, (TC_buffer){base + 1, bytes}, &workspace), ==,
        TC_RESULT_ARGUMENT);
  munit_assert_int(TC_X509_path_workspace_init(&capacity, (TC_buffer){NULL, bytes}, &workspace), ==,
                   TC_RESULT_ARGUMENT);
  munit_assert_int(TC_X509_path_workspace_init(NULL, (TC_buffer){base, bytes}, &workspace), ==,
                   TC_RESULT_ARGUMENT);
  munit_assert_int(TC_X509_path_workspace_init(&capacity, (TC_buffer){base, bytes}, NULL), ==,
                   TC_RESULT_ARGUMENT);
  munit_assert_int(TC_X509_path_workspace_init(&capacity, (TC_buffer){base, SIZE_MAX}, &workspace),
                   ==, TC_RESULT_ARGUMENT);
  munit_assert_int(TC_X509_path_workspace_init(
                       &capacity, (TC_buffer){(uint8_t*)&workspace, sizeof workspace}, &workspace),
                   ==, TC_RESULT_ARGUMENT);
  {
    TC_X509_path_capacity* inside = (TC_X509_path_capacity*)(void*)path_arena;
    *inside = capacity;
    munit_assert_int(
        TC_X509_path_workspace_init(inside, (TC_buffer){base, sizeof path_arena}, &workspace), ==,
        TC_RESULT_ARGUMENT);
  }
  assert_workspace_equal(&workspace, &saved);

  /* Required counts. */
  for (unsigned field = 0; field < 5; ++field) {
    TC_X509_path_capacity zero = capacity;
    size_t* counts[] = {&zero.frames, &zero.oids, &zero.name_scalars, &zero.name_attributes,
                        &zero.path};
    *counts[field] = 0;
    munit_assert_int(TC_X509_path_workspace_size(&zero, &untouched), ==, TC_RESULT_ARGUMENT);
    munit_assert_int(
        TC_X509_path_workspace_init(&zero, (TC_buffer){base, sizeof path_arena}, &workspace), ==,
        TC_RESULT_ARGUMENT);
  }
  munit_assert_int(TC_X509_path_workspace_size(NULL, &untouched), ==, TC_RESULT_ARGUMENT);
  munit_assert_int(TC_X509_path_workspace_size(&capacity, NULL), ==, TC_RESULT_ARGUMENT);
  capacity.frames = SIZE_MAX;
  munit_assert_int(TC_X509_path_workspace_size(&capacity, &untouched), ==, TC_RESULT_LIMIT);
  munit_assert_int(
      TC_X509_path_workspace_init(&capacity, (TC_buffer){base, sizeof path_arena}, &workspace), ==,
      TC_RESULT_LIMIT);
  capacity.frames = 4;
  munit_assert_size(untouched, ==, 123);
  assert_workspace_equal(&workspace, &saved);

  capacity.policy_nodes = capacity.policy_edges = capacity.policy_expected = 0;
  capacity.policy_mappings = capacity.policies = 0;
  munit_assert_int(TC_X509_path_workspace_size(&capacity, &bytes), ==, TC_RESULT_OK);
  munit_assert_int(TC_X509_path_workspace_init(&capacity, (TC_buffer){base, bytes}, &workspace), ==,
                   TC_RESULT_OK);
  munit_assert_null(workspace.nodes);
  munit_assert_null(workspace.edges);
  munit_assert_null(workspace.expected);
  munit_assert_null(workspace.mappings);
  munit_assert_null(workspace.policies);
  munit_assert_size(workspace.node_capacity, ==, 0);
  munit_assert_not_null(workspace.summaries);
  return MUNIT_OK;
}

/* A storage source that failed to supply bytes is a source failure. */
TC_TEST(status_mapping)
{
  munit_assert_int(tc_x509_path_status(TC_TLV_IO), ==, TC_X509_PATH_ERROR);
  munit_assert_int(tc_x509_path_status(TC_TLV_ARGUMENT), ==, TC_X509_PATH_ERROR);
  munit_assert_int(tc_x509_path_status(TC_TLV_INVALID), ==, TC_X509_PATH_INVALID);
  munit_assert_int(tc_x509_path_status(TC_TLV_MORE), ==, TC_X509_PATH_INVALID);
  munit_assert_int(tc_x509_path_status(TC_TLV_LIMIT), ==, TC_X509_PATH_LIMIT);
  munit_assert_int(tc_x509_path_status(TC_TLV_UNSUPPORTED), ==, TC_X509_PATH_UNSUPPORTED);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
      {"/basic", basic, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/names", names, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/policy-controls", policy_controls, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/policy-graph", policy_graph, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/policies", policies, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/qualifiers", qualifiers, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/usage", usage, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/entry-option-checks", entry_option_checks, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/status-mapping", status_mapping, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/workspace-arena-layout", workspace_arena_layout, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/workspace-arena-failures", workspace_arena_failures, NULL, NULL, MUNIT_TEST_OPTION_NONE,
       NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/x509/path", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
