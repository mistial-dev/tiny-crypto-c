/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../src/x509_path_internal.h"
#include "../../src/x509_policy_internal.h"
#include "munit.h"
#include <string.h>

typedef struct { unsigned calls; TC_X509_signature_result result; } Provider;
static TC_X509_signature_result verify(void* context, const TC_bytes* message, size_t count,
    const TC_DER_algorithm* algorithm, TC_bytes signature,
    const TC_X509_public_key* key, size_t* work)
{
  Provider* provider = (Provider*)context;
  (void)message; (void)count; (void)algorithm; (void)signature; (void)key;
  ++provider->calls;
  if (!*work) return TC_X509_SIGNATURE_LIMIT;
  --*work;
  return provider->result;
}

static MunitResult basic(const MunitParameter params[], void* user)
{
  const uint8_t names[][14] = {
    {0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A'},
    {0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'B'},
    {0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'C'},
    {0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'D'}
  };
  const uint8_t identifiers[] = {1,2,3};
  const uint8_t oid[] = {0x2a,3};
  uint8_t extensions[] = {0x30,33,0x30,18,6,3,0x55,0x1d,19,1,1,0xff,4,8,0x30,6,1,1,0xff,2,1,1,
    0x30,11,6,3,0x55,0x1d,15,4,4,3,2,2,4};
  TC_X509_certificate certificates[3], saved;
  TC_X509_trust_anchor anchor;
  const TC_X509_time at = {2026,1,1,0,0,0};
  const TC_X509_time before = {2024,1,1,0,0,0}, after = {2028,1,1,0,0,0};
  const TC_TLV_limits limits = {1024,1024,64,8};
  uint32_t left[32], right[32];
  uint8_t used[4];
  TC_X509_name_workspace workspace = {left,right,32,used,4};
  Provider state = {0,TC_X509_SIGNATURE_VALID};
  TC_X509_signature_provider signatures = {verify,&state,NULL};
  tc_x509_path_input input = {certificates,3,3,3,&anchor,&at,&signatures,&limits,NULL,NULL};
  size_t i, work = 100000, required;
  int accepted = 99;
  (void)params; (void)user;
  memset(certificates, 0, sizeof certificates);
  memset(&anchor, 0, sizeof anchor);
  anchor.name.data = names[0]; anchor.name.length = sizeof names[0];
  anchor.public_key.algorithm.oid.data = oid; anchor.public_key.algorithm.oid.length = sizeof oid;
  anchor.public_key.key.data = identifiers; anchor.public_key.key.length = sizeof identifiers;
  for (i = 0; i < 3; ++i) {
    certificates[i].encoded.data = identifiers + i; certificates[i].encoded.length = 1;
    certificates[i].tbs = certificates[i].signature = certificates[i].encoded;
    certificates[i].signature_algorithm = anchor.public_key.algorithm;
    certificates[i].public_key = anchor.public_key;
    certificates[i].issuer.data = names[i]; certificates[i].issuer.length = sizeof names[i];
    certificates[i].subject.data = names[i + 1]; certificates[i].subject.length = sizeof names[i + 1];
    certificates[i].not_before = before; certificates[i].not_after = after; certificates[i].version = 3;
    certificates[i].extensions.data = extensions; certificates[i].extensions.length = sizeof extensions;
  }
  munit_assert_int(tc_x509_path_basic(&input, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1); munit_assert_uint(state.calls, ==, 3);
  required = 100000 - work;
  for (i = 0; i < required; ++i) {
    work = i; accepted = 99;
    munit_assert_int(tc_x509_path_basic(&input, &workspace, &work, &accepted), ==, TC_TLV_LIMIT);
    munit_assert_int(accepted, ==, 99);
  }
  extensions[21] = 0; work = 100000;
  munit_assert_int(tc_x509_path_basic(&input, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  certificates[1].subject = certificates[1].issuer;
  certificates[2].issuer = certificates[1].subject; work = 100000;
  munit_assert_int(tc_x509_path_basic(&input, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  certificates[1].subject.data = names[2]; certificates[2].issuer.data = names[2]; extensions[21] = 1;
  extensions[33] = 7; extensions[34] = 0x80; work = 100000;
  munit_assert_int(tc_x509_path_basic(&input, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  extensions[33] = 2; extensions[34] = 4;
  saved = certificates[0]; certificates[0].extensions.data = NULL; certificates[0].extensions.length = 0; work = 100000;
  munit_assert_int(tc_x509_path_basic(&input, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0); certificates[0] = saved;
  certificates[1].not_after.year = 2025; work = 100000;
  munit_assert_int(tc_x509_path_basic(&input, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0); certificates[1].not_after = after;
  saved = certificates[2]; certificates[2] = certificates[1]; work = 100000; state.calls = 0;
  munit_assert_int(tc_x509_path_basic(&input, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0); munit_assert_uint(state.calls, ==, 0); certificates[2] = saved;
  input.max_input = 2; work = 100000; accepted = 99;
  munit_assert_int(tc_x509_path_basic(&input, &workspace, &work, &accepted), ==, TC_TLV_LIMIT);
  munit_assert_int(accepted, ==, 99); input.max_input = 3;
  input.max_certificates = 2;
  munit_assert_int(tc_x509_path_basic(&input, &workspace, &work, &accepted), ==, TC_TLV_LIMIT);
  munit_assert_int(accepted, ==, 99); input.max_certificates = 3;
  input.signatures = NULL;
  munit_assert_int(tc_x509_path_basic(&input, &workspace, &work, &accepted), ==, TC_TLV_UNSUPPORTED);
  munit_assert_int(accepted, ==, 99); input.signatures = &signatures;
  state.result = TC_X509_SIGNATURE_INVALID;
  munit_assert_int(tc_x509_path_basic(&input, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  return MUNIT_OK;
}

static MunitResult names(const MunitParameter params[], void* user)
{
  const uint8_t dn_a[] = {0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A'};
  const uint8_t dn_b[] = {0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'B'};
  const uint8_t encoded[] = {1,2,3};
  uint8_t constraints[] = {0x30,18,0x30,16,6,3,0x55,0x1d,30,4,9,0x30,7,0xa0,5,0x30,3,0x82,1,'a'};
  uint8_t narrower[sizeof constraints];
  uint8_t san[] = {0x30,14,0x30,12,6,3,0x55,0x1d,17,4,5,0x30,3,0x82,1,'a'};
  TC_X509_certificate certificates[3];
  TC_TLV_limits limits = {1024,1024,64,8};
  uint32_t left[32], right[32];
  uint8_t used[4];
  TC_TLV_frame frames[8];
  TC_X509_name_workspace name_workspace = {left,right,32,used,4};
  TC_X509_constraint_workspace workspace = {frames,8,&name_workspace};
  tc_x509_path_input input = {certificates,3,3,3,NULL,NULL,NULL,&limits,NULL,NULL};
  size_t i, work = 100000, required;
  int accepted = 99;
  (void)params; (void)user;
  memset(certificates, 0, sizeof certificates);
  memcpy(narrower, constraints, sizeof narrower);
  for (i = 0; i < 3; ++i) {
    certificates[i].encoded.data = encoded + i; certificates[i].encoded.length = 1;
    certificates[i].subject.data = dn_b; certificates[i].subject.length = sizeof dn_b;
    certificates[i].issuer.data = dn_a; certificates[i].issuer.length = sizeof dn_a;
  }
  certificates[0].extensions.data = constraints; certificates[0].extensions.length = sizeof constraints;
  certificates[1].extensions.data = narrower; certificates[1].extensions.length = sizeof narrower;
  certificates[2].extensions.data = san; certificates[2].extensions.length = sizeof san;
  munit_assert_int(tc_x509_path_names(&input, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  required = 100000 - work;
  for (i = 0; i < required; ++i) {
    work = i; accepted = 99;
    munit_assert_int(tc_x509_path_names(&input, &workspace, &work, &accepted), ==, TC_TLV_LIMIT);
    munit_assert_int(accepted, ==, 99);
  }
  narrower[19] = 'b'; work = 100000;
  munit_assert_int(tc_x509_path_names(&input, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0); narrower[19] = 'a';
  constraints[13] = 0xa1; work = 100000;
  munit_assert_int(tc_x509_path_names(&input, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0); constraints[13] = 0xa0;
  constraints[15] = 0x31; work = 100000; accepted = 99;
  munit_assert_int(tc_x509_path_names(&input, &workspace, &work, &accepted), ==, TC_TLV_INVALID);
  munit_assert_int(accepted, ==, 99); constraints[15] = 0x30;
  /* A rollover certificate is exempt, but its child still inherits the constraint. */
  san[15] = 'b'; certificates[1].extensions = certificates[2].extensions;
  certificates[2].extensions.data = NULL; certificates[2].extensions.length = 0; work = 100000;
  munit_assert_int(tc_x509_path_names(&input, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  certificates[1].subject = certificates[1].issuer; work = 100000;
  munit_assert_int(tc_x509_path_names(&input, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  certificates[2].extensions = certificates[1].extensions;
  certificates[2].subject = certificates[2].issuer; work = 100000;
  munit_assert_int(tc_x509_path_names(&input, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  return MUNIT_OK;
}

static MunitResult policy_controls(const MunitParameter params[], void* user)
{
  uint8_t extensions[] = {0x30,29,
    0x30,15,6,3,0x55,0x1d,36,4,8,0x30,6,0x80,1,2,0x81,1,3,
    0x30,10,6,3,0x55,0x1d,54,4,3,2,1,4};
  TC_X509_certificate certificate;
  const TC_TLV_limits limits = {1024,1024,64,8};
  tc_x509_policy_controls controls, saved;
  tc_x509_policy_counters counters;
  size_t work = 1000, required, i;
  unsigned target, self_issued;
  (void)params; (void)user;
  memset(&certificate, 0, sizeof certificate);
  certificate.extensions.data = extensions; certificate.extensions.length = sizeof extensions;
  munit_assert_int(tc_x509_policy_controls_read(&certificate, &limits, &work, &controls), ==, TC_TLV_OK);
  munit_assert_int(controls.constraints.has_require_explicit_policy, ==, 1);
  munit_assert_int(controls.constraints.has_inhibit_policy_mapping, ==, 1);
  munit_assert_int(controls.has_inhibit_any, ==, 1);
  munit_assert_uint(controls.constraints.require_explicit_policy, ==, 2);
  munit_assert_uint(controls.constraints.inhibit_policy_mapping, ==, 3);
  munit_assert_uint(controls.inhibit_any, ==, 4);
  saved = controls; required = 1000 - work;
  for (i = 0; i < required; ++i) {
    work = i;
    munit_assert_int(tc_x509_policy_controls_read(&certificate, &limits, &work, &controls), ==, TC_TLV_LIMIT);
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
  munit_assert_size(counters.mapping, ==, 5); munit_assert_size(counters.any, ==, 5);
  controls = saved; extensions[30] = 0xff; work = 1000;
  munit_assert_int(tc_x509_policy_controls_read(&certificate, &limits, &work, &controls), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof controls, &controls, &saved);
  certificate.extensions.data = NULL; certificate.extensions.length = 0; work = 1000;
  munit_assert_int(tc_x509_policy_controls_read(&certificate, &limits, &work, &controls), ==, TC_TLV_OK);
  munit_assert_int(controls.has_inhibit_any, ==, 0);
  munit_assert_int(controls.constraints.has_require_explicit_policy, ==, 0);
  munit_assert_int(controls.constraints.has_inhibit_policy_mapping, ==, 0);
  counters.explicit_policy = counters.mapping = counters.any = 5;
  tc_x509_policy_counters_advance(&counters, &controls, 1, 0);
  munit_assert_size(counters.explicit_policy, ==, 5);
  munit_assert_size(counters.mapping, ==, 5); munit_assert_size(counters.any, ==, 5);
  tc_x509_policy_counters_advance(&counters, &controls, 0, 0);
  munit_assert_size(counters.explicit_policy, ==, 4);
  munit_assert_size(counters.mapping, ==, 4); munit_assert_size(counters.any, ==, 4);
  counters.explicit_policy = counters.mapping = counters.any = 0;
  tc_x509_policy_counters_advance(&counters, &controls, 0, 0);
  munit_assert_size(counters.explicit_policy, ==, 0);
  munit_assert_size(counters.mapping, ==, 0); munit_assert_size(counters.any, ==, 0);
  return MUNIT_OK;
}

static MunitResult policy_graph(const MunitParameter params[], void* user)
{
  const uint8_t oid_bytes[][2] = {{0x2a,1},{0x2a,2},{0x2a,3}};
  const uint8_t any_bytes[] = {0x55,0x1d,0x20,0};
  TC_bytes policies[] = {{oid_bytes[0],2},{oid_bytes[1],2},{oid_bytes[2],2}};
  TC_bytes any = {any_bytes,sizeof any_bytes};
  TC_X509_policy_mapping mappings[] = {{policies[0],policies[2]},{policies[1],policies[2]}};
  tc_x509_policy_node nodes[32];
  tc_x509_policy_edge edges[64];
  tc_x509_policy_expected expected[64];
  tc_x509_policy_graph graph = {nodes,32,0,edges,64,0,expected,64,0,0};
  size_t work = 100000, required, budget, i;
  (void)params; (void)user;
  munit_assert_int(tc_x509_policy_graph_init(&graph), ==, TC_TLV_OK);
  munit_assert_int(tc_x509_policy_graph_step(&graph, policies, 2, mappings, 2, 1, 1, &work), ==, TC_TLV_OK);
  munit_assert_int(tc_x509_policy_graph_step(&graph, policies + 2, 1, NULL, 0, 1, 1, &work), ==, TC_TLV_OK);
  munit_assert_size(graph.node_count, ==, 4); munit_assert_size(graph.edge_count, ==, 4);
  munit_assert_size(edges[2].child, ==, 3); munit_assert_size(edges[3].child, ==, 3);
  munit_assert_size(edges[2].parent, ==, 1); munit_assert_size(edges[3].parent, ==, 2);
  for (i = 0; i < 4; ++i) munit_assert_int(nodes[i].alive, ==, 1);
  required = 100000 - work;
  for (budget = 0; budget < required; ++budget) {
    TC_TLV_result result;
    work = budget;
    munit_assert_int(tc_x509_policy_graph_init(&graph), ==, TC_TLV_OK);
    result = tc_x509_policy_graph_step(&graph, policies, 2, mappings, 2, 1, 1, &work);
    if (result == TC_TLV_OK)
      result = tc_x509_policy_graph_step(&graph, policies + 2, 1, NULL, 0, 1, 1, &work);
    munit_assert_int(result, ==, TC_TLV_LIMIT);
  }
  work = required;
  munit_assert_int(tc_x509_policy_graph_init(&graph), ==, TC_TLV_OK);
  munit_assert_int(tc_x509_policy_graph_step(&graph, policies, 2, mappings, 2, 1, 1, &work), ==, TC_TLV_OK);
  munit_assert_int(tc_x509_policy_graph_step(&graph, policies + 2, 1, NULL, 0, 1, 1, &work), ==, TC_TLV_OK);
  munit_assert_size(work, ==, 0);
  work = 100000;
  munit_assert_int(tc_x509_policy_graph_init(&graph), ==, TC_TLV_OK);
  munit_assert_int(tc_x509_policy_graph_step(&graph, policies, 2, mappings, 2, 1, 0, &work), ==, TC_TLV_OK);
  for (i = 0; i < graph.node_count; ++i) munit_assert_int(nodes[i].alive, ==, 0);
  munit_assert_int(tc_x509_policy_graph_step(&graph, &any, 1, NULL, 0, 1, 1, &work), ==, TC_TLV_OK);
  munit_assert_size(graph.node_count, ==, 3);
  munit_assert_int(tc_x509_policy_graph_init(&graph), ==, TC_TLV_OK);
  munit_assert_int(tc_x509_policy_graph_step(&graph, &any, 1, NULL, 0, 0, 1, &work), ==, TC_TLV_OK);
  munit_assert_int(nodes[0].alive, ==, 0);
  munit_assert_int(tc_x509_policy_graph_init(&graph), ==, TC_TLV_OK);
  munit_assert_int(tc_x509_policy_graph_step(&graph, &any, 1, mappings, 1, 1, 1, &work), ==, TC_TLV_OK);
  munit_assert_size(graph.node_count, ==, 3);
  munit_assert_int(tc_x509_policy_graph_step(&graph, policies + 2, 1, NULL, 0, 1, 1, &work), ==, TC_TLV_OK);
  munit_assert_size(graph.edge_count, ==, 3);
  munit_assert_int(nodes[1].alive, ==, 0); munit_assert_int(nodes[2].alive, ==, 1);
  munit_assert_size(edges[2].parent, ==, 2);
  for (i = 0; i < 3; ++i) {
    graph.node_capacity = i == 0 ? 2 : 32;
    graph.edge_capacity = i == 1 ? 1 : 64;
    graph.expected_capacity = i == 2 ? 1 : 64;
    work = 100000;
    munit_assert_int(tc_x509_policy_graph_init(&graph), ==, TC_TLV_OK);
    munit_assert_int(tc_x509_policy_graph_step(&graph, policies, 2, mappings, 2, 1, 1, &work), ==, TC_TLV_LIMIT);
  }
  graph.node_capacity = 32; graph.edge_capacity = graph.expected_capacity = 64;
  work = 100000;
  munit_assert_int(tc_x509_policy_graph_init(&graph), ==, TC_TLV_OK);
  munit_assert_int(tc_x509_policy_graph_step(&graph, policies, 2, mappings, 2, 1, 1, &work), ==, TC_TLV_OK);
  munit_assert_int(tc_x509_policy_graph_step(&graph, &any, 1, NULL, 0, 1, 1, &work), ==, TC_TLV_OK);
  munit_assert_size(graph.node_count, ==, 4); munit_assert_size(graph.edge_count, ==, 4);
  munit_assert_memory_equal(2, nodes[3].oid.data, policies[2].data);
  {
    TC_bytes duplicate[] = {policies[0], policies[0]};
    TC_X509_policy_mapping invalid = {any, policies[0]};
    munit_assert_int(tc_x509_policy_graph_init(&graph), ==, TC_TLV_OK);
    munit_assert_int(tc_x509_policy_graph_step(&graph, duplicate, 2, NULL, 0, 1, 1, &work), ==, TC_TLV_INVALID);
    munit_assert_int(tc_x509_policy_graph_init(&graph), ==, TC_TLV_OK);
    munit_assert_int(tc_x509_policy_graph_step(&graph, policies, 2, &invalid, 1, 1, 1, &work), ==, TC_TLV_INVALID);
    invalid.issuer_policy = policies[0]; invalid.subject_policy = any;
    munit_assert_int(tc_x509_policy_graph_init(&graph), ==, TC_TLV_OK);
    munit_assert_int(tc_x509_policy_graph_step(&graph, policies, 2, &invalid, 1, 1, 1, &work), ==, TC_TLV_INVALID);
  }
  {
    TC_X509_policy_mapping cross[] = {
      {policies[0],policies[0]}, {policies[0],policies[1]},
      {policies[1],policies[0]}, {policies[1],policies[1]}
    };
    work = 1000000;
    munit_assert_int(tc_x509_policy_graph_init(&graph), ==, TC_TLV_OK);
    for (i = 0; i < 8; ++i)
      munit_assert_int(tc_x509_policy_graph_step(&graph, policies, 2, cross, 4, 1, 1, &work), ==, TC_TLV_OK);
    munit_assert_size(graph.node_count, ==, 17);
    munit_assert_size(graph.edge_count, ==, 30);
    munit_assert_size(graph.expected_count, ==, 32);
  }
  return MUNIT_OK;
}

static MunitResult policies(const MunitParameter params[], void* user)
{
  const uint8_t dn[] = {0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A'};
  const uint8_t oid_bytes[][2] = {{0x2a,1},{0x2a,2}};
  const uint8_t any_bytes[] = {0x55,0x1d,0x20,0};
  const TC_bytes initial[] = {{oid_bytes[0],2},{oid_bytes[1],2},{any_bytes,sizeof any_bytes}};
  const uint8_t issuing[] = {0x30,38,
    0x30,15,6,3,0x55,0x1d,32,4,8,0x30,6,0x30,4,6,2,0x2a,1,
    0x30,19,6,3,0x55,0x1d,33,4,12,0x30,10,0x30,8,6,2,0x2a,1,6,2,0x2a,2};
  const uint8_t leaf[] = {0x30,17,0x30,15,6,3,0x55,0x1d,32,4,8,0x30,6,0x30,4,6,2,0x2a,2};
  TC_X509_certificate certificates[2];
  const TC_TLV_limits limits = {1024,1024,64,8};
  tc_x509_path_input input = {certificates,2,2,2048,NULL,NULL,NULL,&limits,NULL,NULL};
  uint32_t left[32], right[32];
  uint8_t used[4];
  TC_X509_name_workspace names = {left,right,32,used,4};
  tc_x509_policy_node nodes[8];
  tc_x509_policy_edge edges[8];
  tc_x509_policy_expected expected[8];
  tc_x509_policy_graph graph = {nodes,8,0,edges,8,0,expected,8,0,0};
  TC_bytes policy_scratch[4], output[4];
  TC_X509_policy_mapping mappings[4];
  TC_TLV_frame frames[8];
  tc_x509_policy_workspace workspace = {&graph,policy_scratch,4,mappings,4,output,4,&names,frames,8};
  tc_x509_policy_options options = {initial,1,1,0,0};
  size_t i, count = 99, work = 100000, required;
  int accepted = 99;
  (void)params; (void)user;
  memset(certificates, 0, sizeof certificates);
  for (i = 0; i < 2; ++i) {
    certificates[i].issuer.data = dn; certificates[i].issuer.length = sizeof dn;
    certificates[i].subject = certificates[i].issuer;
  }
  certificates[0].extensions.data = issuing; certificates[0].extensions.length = sizeof issuing;
  certificates[1].extensions.data = leaf; certificates[1].extensions.length = sizeof leaf;
  munit_assert_int(tc_x509_path_policies(&input, &options, &workspace, &work, &count, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1); munit_assert_size(count, ==, 1);
  munit_assert_memory_equal(2, output[0].data, initial[0].data);
  required = 100000 - work;
  for (i = 0; i < required; ++i) {
    work = i; count = 99; accepted = 99;
    munit_assert_int(tc_x509_path_policies(&input, &options, &workspace, &work, &count, &accepted), ==, TC_TLV_LIMIT);
    munit_assert_size(count, ==, 99); munit_assert_int(accepted, ==, 99);
  }
  work = required;
  munit_assert_int(tc_x509_path_policies(&input, &options, &workspace, &work, &count, &accepted), ==, TC_TLV_OK);
  munit_assert_size(work, ==, 0); munit_assert_int(accepted, ==, 1);
  options.initial = initial + 1; work = 100000;
  munit_assert_int(tc_x509_path_policies(&input, &options, &workspace, &work, &count, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0); munit_assert_size(count, ==, 0);
  options.initial = initial + 2; work = 100000;
  munit_assert_int(tc_x509_path_policies(&input, &options, &workspace, &work, &count, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1); munit_assert_size(count, ==, 1);
  munit_assert_memory_equal(2, output[0].data, initial[0].data);
  options.inhibit_mapping = 1; work = 100000;
  munit_assert_int(tc_x509_path_policies(&input, &options, &workspace, &work, &count, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  options.inhibit_mapping = 0; workspace.output_capacity = 0; work = 100000; count = 99; accepted = 99;
  munit_assert_int(tc_x509_path_policies(&input, &options, &workspace, &work, &count, &accepted), ==, TC_TLV_LIMIT);
  munit_assert_size(count, ==, 99); munit_assert_int(accepted, ==, 99); workspace.output_capacity = 4;
  certificates[1].extensions.data = NULL; certificates[1].extensions.length = 0; work = 100000;
  munit_assert_int(tc_x509_path_policies(&input, &options, &workspace, &work, &count, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0); munit_assert_size(count, ==, 0);
  options.require_explicit = 0; work = 100000;
  munit_assert_int(tc_x509_path_policies(&input, &options, &workspace, &work, &count, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1); munit_assert_size(count, ==, 0);
  return MUNIT_OK;
}

static MunitResult qualifiers(const MunitParameter params[], void* user)
{
  static const struct {
    uint8_t value[24];
    size_t length;
    unsigned kind;
    TC_TLV_result result;
  } cases[] = {
    {{0x16,3,'a',':','b'},5,1,TC_TLV_OK},
    {{0x0c,3,'a',':','b'},5,1,TC_TLV_INVALID},
    {{0x16,1,0xff},3,1,TC_TLV_INVALID},
    {{0x30,0},2,2,TC_TLV_OK},
    {{0x30,3,0x0c,1,'a'},5,2,TC_TLV_OK},
    {{0x30,3,0x16,1,'a'},5,2,TC_TLV_OK},
    {{0x30,3,0x1a,1,'a'},5,2,TC_TLV_OK},
    {{0x30,4,0x1e,2,0,'a'},6,2,TC_TLV_OK},
    {{0x30,3,0x1a,1,0x1f},5,2,TC_TLV_INVALID},
    {{0x30,3,0x1a,1,0x7f},5,2,TC_TLV_INVALID},
    {{0x30,3,0x0c,1,0xc0},5,2,TC_TLV_INVALID},
    {{0x30,4,0x1e,2,0xd8,0},6,2,TC_TLV_INVALID},
    {{0x30,2,0x0c,0},4,2,TC_TLV_INVALID},
    {{0x30,3,0x13,1,'a'},5,2,TC_TLV_INVALID},
    {{0x30,6,0x0c,1,'a',0x0c,1,'b'},8,2,TC_TLV_INVALID},
    {{0x30,7,0x30,5,0x0c,1,'a',0x30,0},9,2,TC_TLV_OK},
    {{0x30,10,0x30,8,0x0c,1,'a',0x30,3,2,1,0xff},12,2,TC_TLV_OK},
    {{0x30,11,0x30,9,0x0c,1,'a',0x30,4,2,2,0,1},13,2,TC_TLV_INVALID},
    {{0x30,7,0x30,5,0x0c,1,'a',0x31,0},9,2,TC_TLV_INVALID},
    {{0x30,5,0x30,3,0x0c,1,'a'},7,2,TC_TLV_INVALID},
    {{5,0},2,3,TC_TLV_UNSUPPORTED}
  };
  uint8_t encoded[128] = {0x30,0,0x30,0,6,8,0x2b,6,1,5,5,7,2,0};
  const uint8_t ordinary[] = {0x2a,1}, wildcard[] = {0x55,0x1d,0x20,0};
  TC_X509_policy policy = {{ordinary,sizeof ordinary},{encoded,0}};
  TC_TLV_frame frames[8];
  TC_TLV_limits limits = {1024,1024,64,8};
  size_t i, budget, required, work;
  (void)params; (void)user;
  for (i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
    encoded[1] = (uint8_t)(12 + cases[i].length);
    encoded[3] = (uint8_t)(10 + cases[i].length);
    encoded[13] = (uint8_t)cases[i].kind;
    memcpy(encoded + 14, cases[i].value, cases[i].length);
    policy.qualifiers.length = 14 + cases[i].length; work = 10000;
    munit_assert_int(tc_x509_policy_qualifiers_check(&policy, 1, &limits, frames, 8, &work), ==, cases[i].result);
    if (cases[i].result != TC_TLV_OK) continue;
    required = 10000 - work;
    for (budget = 0; budget < required; ++budget) {
      work = budget;
      munit_assert_int(tc_x509_policy_qualifiers_check(&policy, 1, &limits, frames, 8, &work), ==, TC_TLV_LIMIT);
    }
    work = 10000; limits.max_elements = 1;
    munit_assert_int(tc_x509_policy_qualifiers_check(&policy, 1, &limits, frames, 8, &work), ==, TC_TLV_LIMIT);
    limits.max_elements = 64; limits.max_depth = 0; work = 10000;
    munit_assert_int(tc_x509_policy_qualifiers_check(&policy, 1, &limits, frames, 8, &work), ==, TC_TLV_LIMIT);
    limits.max_depth = 8; work = 10000;
    munit_assert_int(tc_x509_policy_qualifiers_check(&policy, 1, &limits, NULL, 0, &work), ==, TC_TLV_LIMIT);
  }
  /* The final fixture is an unknown qualifier on an ordinary policy. */
  work = 10000;
  munit_assert_int(tc_x509_policy_qualifiers_check(&policy, 0, &limits, frames, 8, &work), ==, TC_TLV_OK);
  policy.oid.data = wildcard; policy.oid.length = sizeof wildcard; work = 10000;
  munit_assert_int(tc_x509_policy_qualifiers_check(&policy, 0, &limits, frames, 8, &work), ==, TC_TLV_UNSUPPORTED);
  return MUNIT_OK;
}

static MunitResult usage(const MunitParameter params[], void* user)
{
  const uint8_t dn[] = {0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A'};
  const uint8_t oid[] = {0x2a,1};
  uint8_t extensions[] = {0x30,28,
    0x30,11,6,3,0x55,0x1d,15,4,4,3,2,7,0x80,
    0x30,13,6,3,0x55,0x1d,37,4,6,0x30,4,6,2,0x2a,1};
  uint8_t unknown[] = {0x30,12,0x30,10,6,3,0x55,0x1d,99,1,1,0xff,4,0};
  const uint8_t wildcard[] = {0x30,17,0x30,15,6,3,0x55,0x1d,37,4,8,0x30,6,6,4,0x55,0x1d,37,0};
  const uint8_t combined[] = {0x30,21,0x30,19,6,3,0x55,0x1d,37,4,12,
    0x30,10,6,4,0x55,0x1d,37,0,6,2,0x2a,1};
  const uint8_t issuer_wildcard[] = {0x30,31,
    0x30,12,6,3,0x55,0x1d,19,4,5,0x30,3,1,1,0xff,
    0x30,15,6,3,0x55,0x1d,37,4,8,0x30,6,6,4,0x55,0x1d,37,0};
  TC_X509_certificate certificates[2];
  const TC_TLV_limits limits = {1024,1024,64,8};
  tc_x509_path_input input = {certificates,1,2,2048,NULL,NULL,NULL,&limits,NULL,NULL};
  uint32_t left[32], right[32];
  uint8_t used[4];
  TC_TLV_frame frames[8];
  TC_bytes oids[4];
  TC_X509_name_workspace names = {left,right,32,used,4};
  tc_x509_extension_workspace workspace = {oids,4,{frames,8,&names}};
  tc_x509_path_usage purpose = {{oid,sizeof oid},1,1,1,0};
  size_t i, work = 100000, required;
  int accepted = 99;
  (void)params; (void)user;
  memset(certificates, 0, sizeof certificates);
  certificates[0].subject.data = dn; certificates[0].subject.length = sizeof dn;
  certificates[0].issuer = certificates[0].subject;
  certificates[0].extensions.data = extensions; certificates[0].extensions.length = sizeof extensions;
  munit_assert_int(tc_x509_path_extensions(&input, &purpose, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1); required = 100000 - work;
  for (i = 0; i < required; ++i) {
    accepted = 99; work = i;
    munit_assert_int(tc_x509_path_extensions(&input, &purpose, &workspace, &work, &accepted), ==, TC_TLV_LIMIT);
    munit_assert_int(accepted, ==, 99);
  }
  extensions[29] = 2; work = 100000;
  munit_assert_int(tc_x509_path_extensions(&input, &purpose, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0); extensions[29] = 1;
  purpose.key_usage = 2; work = 100000;
  munit_assert_int(tc_x509_path_extensions(&input, &purpose, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0); purpose.key_usage = 1;
  certificates[0].extensions.data = NULL; certificates[0].extensions.length = 0; work = 100000;
  munit_assert_int(tc_x509_path_extensions(&input, &purpose, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  purpose.require_key_usage = purpose.require_extended_key_usage = 0; work = 100000;
  munit_assert_int(tc_x509_path_extensions(&input, &purpose, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  certificates[0].extensions.data = unknown; certificates[0].extensions.length = sizeof unknown;
  work = 100000; accepted = 99;
  munit_assert_int(tc_x509_path_extensions(&input, &purpose, &workspace, &work, &accepted), ==, TC_TLV_UNSUPPORTED);
  munit_assert_int(accepted, ==, 99);
  /* Remove the critical BOOLEAN, retaining the same unknown extension OID. */
  unknown[1] = 9; unknown[3] = 7; unknown[9] = 4; unknown[10] = 0;
  certificates[0].extensions.length = 11; work = 100000;
  munit_assert_int(tc_x509_path_extensions(&input, &purpose, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  certificates[0].extensions.data = wildcard; certificates[0].extensions.length = sizeof wildcard;
  work = 100000;
  munit_assert_int(tc_x509_path_extensions(&input, &purpose, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  certificates[1] = certificates[0]; input.count = 2;
  purpose.inhibit_any_purpose = 1; work = 100000;
  munit_assert_int(tc_x509_path_extensions(&input, &purpose, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  input.count = 1;
  certificates[0].extensions.data = extensions; certificates[0].extensions.length = sizeof extensions;
  work = 100000;
  munit_assert_int(tc_x509_path_extensions(&input, &purpose, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  /* An explicit match remains usable alongside the wildcard. */
  certificates[0].extensions = (TC_bytes){combined,sizeof combined}; work = 100000;
  munit_assert_int(tc_x509_path_extensions(&input, &purpose, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  certificates[0].extensions = (TC_bytes){NULL,0}; work = 100000;
  munit_assert_int(tc_x509_path_extensions(&input, &purpose, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  purpose.require_extended_key_usage = 1; work = 100000;
  munit_assert_int(tc_x509_path_extensions(&input, &purpose, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  purpose.require_extended_key_usage = 0;
  /* Isolate the intermediate's wildcard while the leaf explicitly permits use. */
  input.count = 2;
  certificates[0].extensions = (TC_bytes){issuer_wildcard,sizeof issuer_wildcard};
  certificates[1].extensions = (TC_bytes){extensions,sizeof extensions};
  purpose.require_extended_key_usage = 1;
  for (unsigned inhibit = 0; inhibit < 2; ++inhibit) {
    purpose.inhibit_any_purpose = (int)inhibit; work = 100000;
    munit_assert_int(tc_x509_path_extensions(&input, &purpose, &workspace, &work, &accepted), ==, TC_TLV_OK);
    munit_assert_int(accepted, ==, !inhibit);
    const size_t needed = 100000 - work;
    work = needed - 1; accepted = 99;
    munit_assert_int(tc_x509_path_extensions(&input, &purpose, &workspace, &work, &accepted), ==, TC_TLV_LIMIT);
    munit_assert_int(accepted, ==, 99);
  }
  certificates[1].extensions = (TC_bytes){wildcard,sizeof wildcard};
  purpose.require_extended_key_usage = 0;
  purpose.inhibit_any_purpose = 0; input.count = 2;
  certificates[0].extensions.data = extensions; certificates[0].extensions.length = sizeof extensions;
  extensions[29] = 2; work = 100000;
  munit_assert_int(tc_x509_path_extensions(&input, &purpose, &workspace, &work, &accepted), ==, TC_TLV_OK);
  munit_assert_int(accepted, ==, 0);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/basic",basic,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/names",names,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/policy-controls",policy_controls,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/policy-graph",policy_graph,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/policies",policies,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/qualifiers",qualifiers,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/usage",usage,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/x509/path",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
