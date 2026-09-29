/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/x509.h>
#include "munit.h"
#include <string.h>

/* Generous limits for the single-value decoders. */
static const TC_TLV_limits value_limits = {256, 256, 32, 4};

static const uint8_t purposes[] = {0x30, 15, 6, 8, 0x2b, 6,    1,    5,   5,
                                   7,    3,  2, 6, 3,    0x55, 0x1d, 0x25};

static MunitResult eku_valid(const MunitParameter params[], void* user)
{
  TC_bytes oids[3];
  size_t count = 99;
  (void)params;
  (void)user;
  memset(oids, 0, sizeof oids);
  munit_assert_int(TC_X509_extended_key_usage_read((TC_bytes){purposes, sizeof purposes},
                                                   &value_limits, oids, 3, &count),
                   ==, TC_TLV_OK);
  munit_assert_size(count, ==, 2);
  munit_assert_ptr_equal(oids[0].data, purposes + 4);
  munit_assert_size(oids[0].length, ==, 8);
  munit_assert_ptr_equal(oids[1].data, purposes + 14);
  munit_assert_size(oids[1].length, ==, 3);
  munit_assert_null(oids[2].data);
  munit_assert_size(oids[2].length, ==, 0);
  return MUNIT_OK;
}

static MunitResult eku_invalid(const MunitParameter params[], void* user)
{
  const uint8_t empty[] = {0x30, 0};
  const uint8_t empty_oid[] = {0x30, 2, 6, 0};
  const uint8_t nonminimal[] = {0x30, 4, 6, 2, 0x80, 0x2a};
  uint8_t bad[sizeof purposes];
  TC_bytes oids[3], saved[3];
  size_t count = 99, i;
  (void)params;
  (void)user;
  memset(saved, 0xa5, sizeof saved);
  memcpy(oids, saved, sizeof oids);
  for (i = 0; i < sizeof purposes; ++i) {
    munit_assert_int(
        TC_X509_extended_key_usage_read((TC_bytes){purposes, i}, &value_limits, oids, 3, &count),
        !=, TC_TLV_OK);
    munit_assert_memory_equal(sizeof oids, oids, saved);
    munit_assert_size(count, ==, 99);
  }
  memcpy(bad, purposes, sizeof bad);
  bad[12] = 4;
  munit_assert_int(
      TC_X509_extended_key_usage_read((TC_bytes){bad, sizeof bad}, &value_limits, oids, 3, &count),
      ==, TC_TLV_INVALID);
  munit_assert_int(TC_X509_extended_key_usage_read((TC_bytes){empty, sizeof empty}, &value_limits,
                                                   oids, 3, &count),
                   ==, TC_TLV_INVALID);
  munit_assert_int(TC_X509_extended_key_usage_read((TC_bytes){empty_oid, sizeof empty_oid},
                                                   &value_limits, oids, 3, &count),
                   ==, TC_TLV_INVALID);
  munit_assert_int(TC_X509_extended_key_usage_read((TC_bytes){nonminimal, sizeof nonminimal},
                                                   &value_limits, oids, 3, &count),
                   ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof oids, oids, saved);
  munit_assert_size(count, ==, 99);
  return MUNIT_OK;
}

static MunitResult eku_storage(const MunitParameter params[], void* user)
{
  TC_bytes oids[3], saved[3];
  size_t count = 99;
  (void)params;
  (void)user;
  memset(saved, 0xa5, sizeof saved);
  memcpy(oids, saved, sizeof oids);
  munit_assert_int(TC_X509_extended_key_usage_read((TC_bytes){purposes, sizeof purposes},
                                                   &value_limits, oids, 1, &count),
                   ==, TC_TLV_LIMIT);
  munit_assert_int(TC_X509_extended_key_usage_read((TC_bytes){purposes, sizeof purposes},
                                                   &value_limits, NULL, 0, &count),
                   ==, TC_TLV_LIMIT);
  munit_assert_int(TC_X509_extended_key_usage_read((TC_bytes){purposes, sizeof purposes},
                                                   &value_limits, NULL, 1, &count),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_extended_key_usage_read((TC_bytes){purposes, sizeof purposes},
                                                   &value_limits, oids, SIZE_MAX, &count),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_extended_key_usage_read((TC_bytes){purposes, sizeof purposes},
                                                   &value_limits, oids, 3, NULL),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_int(
      TC_X509_extended_key_usage_read((TC_bytes){NULL, 1}, &value_limits, oids, 3, &count), ==,
      TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_extended_key_usage_read((TC_bytes){(const uint8_t*)oids, sizeof oids},
                                                   &value_limits, oids, 3, &count),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_extended_key_usage_read((TC_bytes){purposes, sizeof purposes},
                                                   &value_limits, oids, 3, &oids[0].length),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof oids, oids, saved);
  munit_assert_size(count, ==, 99);
  munit_assert_int(TC_X509_extended_key_usage_read((TC_bytes){purposes, sizeof purposes},
                                                   &value_limits, oids, 2, &count),
                   ==, TC_TLV_OK);
  munit_assert_size(count, ==, 2);
  return MUNIT_OK;
}

static MunitResult policy_constraints(const MunitParameter params[], void* user)
{
  const uint8_t both[] = {0x30, 6, 0x80, 1, 0, 0x81, 1, 3};
  const uint8_t one[] = {0x30, 3, 0x81, 1, 0};
  const uint8_t maximum[] = {0x30, 7, 0x80, 5, 0, 255, 255, 255, 255};
  const uint8_t overflow[] = {0x30, 7, 0x80, 5, 1, 0, 0, 0, 0};
  const uint8_t invalid[][8] = {{0x30, 0},
                                {0x30, 3, 0x80, 1, 255},
                                {0x30, 4, 0x80, 2, 0, 1},
                                {0x30, 6, 0x81, 1, 0, 0x80, 1, 0},
                                {0x30, 6, 0x80, 1, 0, 0x80, 1, 0},
                                {0x30, 3, 0xa0, 1, 0},
                                {0x30, 3, 0x82, 1, 0},
                                {0x30, 2, 0x80, 0}};
  TC_X509_policy_constraints out, saved;
  size_t i;
  (void)params;
  (void)user;
  munit_assert_int(
      TC_X509_policy_constraints_read((TC_bytes){both, sizeof both}, &value_limits, &out), ==,
      TC_TLV_OK);
  munit_assert_true(out.has_require_explicit_policy && out.has_inhibit_policy_mapping);
  munit_assert_uint32(out.require_explicit_policy, ==, 0);
  munit_assert_uint32(out.inhibit_policy_mapping, ==, 3);
  munit_assert_int(
      TC_X509_policy_constraints_read((TC_bytes){one, sizeof one}, &value_limits, &out), ==,
      TC_TLV_OK);
  munit_assert_false(out.has_require_explicit_policy);
  munit_assert_true(out.has_inhibit_policy_mapping);
  munit_assert_uint32(out.inhibit_policy_mapping, ==, 0);
  munit_assert_int(
      TC_X509_policy_constraints_read((TC_bytes){maximum, sizeof maximum}, &value_limits, &out), ==,
      TC_TLV_OK);
  munit_assert_uint32(out.require_explicit_policy, ==, UINT32_MAX);
  memset(&out, 0xa5, sizeof out);
  memset(&saved, 0xa5, sizeof saved);
  for (i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
    munit_assert_int(TC_X509_policy_constraints_read((TC_bytes){invalid[i], invalid[i][1] + 2},
                                                     &value_limits, &out),
                     ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof out, &out, &saved);
  }
  for (i = 0; i < sizeof both; ++i) {
    munit_assert_int(TC_X509_policy_constraints_read((TC_bytes){both, i}, &value_limits, &out), !=,
                     TC_TLV_OK);
    munit_assert_memory_equal(sizeof out, &out, &saved);
  }
  munit_assert_int(
      TC_X509_policy_constraints_read((TC_bytes){overflow, sizeof overflow}, &value_limits, &out),
      ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof out, &out, &saved);
  munit_assert_int(
      TC_X509_policy_constraints_read((TC_bytes){both, sizeof both}, &value_limits, NULL), ==,
      TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

/* A reader's limits cover the complete value passed to init: the outer
 * SEQUENCE and every element read beneath it, as TC_TLV_walk counts them. */
static MunitResult extension_budget(const MunitParameter params[], void* user)
{
  const uint8_t extensions[] = {0x30, 19, 0x30, 6,  6, 1, 42,   4, 1, 0, 0x30,
                                9,    6,  1,    43, 1, 1, 0xff, 4, 1, 0};
  TC_TLV_limits bounds = {sizeof extensions, sizeof extensions, 8, 2};
  TC_TLV_reader reader, saved_reader;
  TC_X509_extension out;
  (void)params;
  (void)user;
  munit_assert_int(
      TC_X509_extensions_init(&reader, (TC_bytes){extensions, sizeof extensions}, &bounds), ==,
      TC_TLV_OK);
  munit_assert_int(TC_X509_extension_next(&reader, &out), ==, TC_TLV_OK);
  munit_assert_false(out.critical);
  munit_assert_int(TC_X509_extension_next(&reader, &out), ==, TC_TLV_OK);
  munit_assert_true(out.critical);
  munit_assert_int(TC_X509_extension_next(&reader, &out), ==, TC_TLV_END);
  munit_assert_size(reader.elements, ==, 8);
  /* One element short fails on the second extension's fields. */
  bounds.max_elements = 7;
  munit_assert_int(
      TC_X509_extensions_init(&reader, (TC_bytes){extensions, sizeof extensions}, &bounds), ==,
      TC_TLV_OK);
  munit_assert_int(TC_X509_extension_next(&reader, &out), ==, TC_TLV_OK);
  saved_reader = reader;
  munit_assert_int(TC_X509_extension_next(&reader, &out), ==, TC_TLV_LIMIT);
  munit_assert_size(reader.offset, ==, saved_reader.offset);
  munit_assert_size(reader.elements, ==, saved_reader.elements);
  munit_assert_false(out.critical);
  /* The Extension SEQUENCE is the second constructed level. */
  bounds.max_elements = 8;
  bounds.max_depth = 1;
  munit_assert_int(
      TC_X509_extensions_init(&reader, (TC_bytes){extensions, sizeof extensions}, &bounds), ==,
      TC_TLV_OK);
  munit_assert_int(TC_X509_extension_next(&reader, &out), ==, TC_TLV_LIMIT);
  bounds.max_depth = 0;
  munit_assert_int(
      TC_X509_extensions_init(&reader, (TC_bytes){extensions, sizeof extensions}, &bounds), ==,
      TC_TLV_LIMIT);
  return MUNIT_OK;
}

static MunitResult policy_mapping_budget(const MunitParameter params[], void* user)
{
  const uint8_t mappings[] = {0x30, 16, 0x30, 6, 6, 1, 42, 6, 1, 42, 0x30, 6, 6, 1, 42, 6, 1, 43};
  TC_TLV_limits bounds = {sizeof mappings, sizeof mappings, 7, 2};
  TC_TLV_reader reader, saved_reader;
  TC_X509_policy_mapping out;
  (void)params;
  (void)user;
  munit_assert_int(
      TC_X509_policy_mappings_init(&reader, (TC_bytes){mappings, sizeof mappings}, &bounds), ==,
      TC_TLV_OK);
  munit_assert_int(TC_X509_policy_mapping_next(&reader, &out), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_policy_mapping_next(&reader, &out), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_policy_mapping_next(&reader, &out), ==, TC_TLV_END);
  munit_assert_size(reader.elements, ==, 7);
  bounds.max_elements = 6;
  munit_assert_int(
      TC_X509_policy_mappings_init(&reader, (TC_bytes){mappings, sizeof mappings}, &bounds), ==,
      TC_TLV_OK);
  munit_assert_int(TC_X509_policy_mapping_next(&reader, &out), ==, TC_TLV_OK);
  saved_reader = reader;
  munit_assert_int(TC_X509_policy_mapping_next(&reader, &out), ==, TC_TLV_LIMIT);
  munit_assert_size(reader.offset, ==, saved_reader.offset);
  munit_assert_size(reader.elements, ==, saved_reader.elements);
  munit_assert_uint8(out.subject_policy.data[0], ==, 42);
  bounds.max_elements = 7;
  bounds.max_depth = 1;
  munit_assert_int(
      TC_X509_policy_mappings_init(&reader, (TC_bytes){mappings, sizeof mappings}, &bounds), ==,
      TC_TLV_OK);
  munit_assert_int(TC_X509_policy_mapping_next(&reader, &out), ==, TC_TLV_LIMIT);
  return MUNIT_OK;
}

/* Single-value decoders count the outer element, every field and each
 * constructed level, and fail with LIMIT one element or level short. */
static MunitResult value_budgets(const MunitParameter params[], void* user)
{
  const uint8_t basic[] = {0x30, 6, 1, 1, 0xff, 2, 1, 3};
  const uint8_t constraints[] = {0x30, 6, 0x80, 1, 0, 0x81, 1, 3};
  const uint8_t usage[] = {3, 2, 7, 0x80};
  const uint8_t identifier[] = {0x30, 11, 0x80, 1, 7, 0xa1, 3, 0x82, 1, 'a', 0x82, 1, 1};
  TC_TLV_limits bounds = {64, 64, 3, 1};
  TC_X509_basic_constraints basic_out = {0, 0, 0};
  TC_X509_policy_constraints policy_out = {0, 0, 0, 0};
  TC_X509_authority_key_identifier key_out;
  TC_bytes oids[2];
  size_t count = 0;
  uint16_t usage_out = 0;
  (void)params;
  (void)user;
  munit_assert_int(
      TC_X509_basic_constraints_read((TC_bytes){basic, sizeof basic}, &bounds, &basic_out), ==,
      TC_TLV_OK);
  munit_assert_true(basic_out.ca);
  munit_assert_uint32(basic_out.path_length, ==, 3);
  munit_assert_int(TC_X509_policy_constraints_read((TC_bytes){constraints, sizeof constraints},
                                                   &bounds, &policy_out),
                   ==, TC_TLV_OK);
  munit_assert_uint32(policy_out.inhibit_policy_mapping, ==, 3);
  munit_assert_int(TC_X509_extended_key_usage_read((TC_bytes){purposes, sizeof purposes}, &bounds,
                                                   oids, 2, &count),
                   ==, TC_TLV_OK);
  munit_assert_size(count, ==, 2);
  bounds.max_elements = 2;
  basic_out.path_length = 99;
  munit_assert_int(
      TC_X509_basic_constraints_read((TC_bytes){basic, sizeof basic}, &bounds, &basic_out), ==,
      TC_TLV_LIMIT);
  munit_assert_uint32(basic_out.path_length, ==, 99);
  munit_assert_int(TC_X509_policy_constraints_read((TC_bytes){constraints, sizeof constraints},
                                                   &bounds, &policy_out),
                   ==, TC_TLV_LIMIT);
  count = 99;
  munit_assert_int(TC_X509_extended_key_usage_read((TC_bytes){purposes, sizeof purposes}, &bounds,
                                                   oids, 2, &count),
                   ==, TC_TLV_LIMIT);
  munit_assert_size(count, ==, 99);
  bounds.max_elements = 3;
  bounds.max_depth = 0;
  munit_assert_int(
      TC_X509_basic_constraints_read((TC_bytes){basic, sizeof basic}, &bounds, &basic_out), ==,
      TC_TLV_LIMIT);
  munit_assert_int(TC_X509_policy_constraints_read((TC_bytes){constraints, sizeof constraints},
                                                   &bounds, &policy_out),
                   ==, TC_TLV_LIMIT);
  /* KeyUsage is one primitive element. */
  munit_assert_int(TC_X509_key_usage_read((TC_bytes){usage, sizeof usage}, &bounds, &usage_out), ==,
                   TC_TLV_OK);
  munit_assert_uint(usage_out, ==, TC_KEY_USAGE_DIGITAL_SIGNATURE);
  bounds.max_elements = 0;
  usage_out = 0;
  munit_assert_int(TC_X509_key_usage_read((TC_bytes){usage, sizeof usage}, &bounds, &usage_out), ==,
                   TC_TLV_LIMIT);
  munit_assert_uint(usage_out, ==, 0);
  bounds.max_value = 1;
  bounds.max_elements = 1;
  munit_assert_int(TC_X509_key_usage_read((TC_bytes){usage, sizeof usage}, &bounds, &usage_out), ==,
                   TC_TLV_LIMIT);
  munit_assert_int(TC_X509_key_usage_read((TC_bytes){usage, sizeof usage}, NULL, &usage_out), ==,
                   TC_TLV_ARGUMENT);
  /* AuthorityKeyIdentifier: the SEQUENCE and three fields. */
  bounds = (TC_TLV_limits){64, 64, 4, 1};
  munit_assert_int(TC_X509_authority_key_identifier_read((TC_bytes){identifier, sizeof identifier},
                                                         &bounds, &key_out),
                   ==, TC_TLV_OK);
  bounds.max_elements = 3;
  munit_assert_int(TC_X509_authority_key_identifier_read((TC_bytes){identifier, sizeof identifier},
                                                         &bounds, &key_out),
                   ==, TC_TLV_LIMIT);
  return MUNIT_OK;
}

/* CertificatePolicies and qualifier readers spend one budget across the list. */
static MunitResult policy_budgets(const MunitParameter params[], void* user)
{
  const uint8_t valid[] = {0x30, 19,   0x30, 3,    6, 1, 42, 0x30, 12, 6, 1,
                           43,   0x30, 7,    0x30, 5, 6, 1,  44,   5,  0};
  TC_TLV_limits bounds = {64, 64, 6, 2};
  TC_bytes seen[2];
  TC_X509_policy_reader reader;
  TC_X509_policy policy;
  TC_TLV_reader qualifiers;
  TC_X509_policy_qualifier qualifier;
  (void)params;
  (void)user;
  munit_assert_int(
      TC_X509_policies_init(&reader, (TC_bytes){valid, sizeof valid}, &bounds, seen, 2), ==,
      TC_TLV_OK);
  munit_assert_int(TC_X509_policy_next(&reader, &policy), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_policy_next(&reader, &policy), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_policy_next(&reader, &policy), ==, TC_TLV_END);
  munit_assert_size(reader.reader.elements, ==, 6);
  bounds.max_elements = 5;
  munit_assert_int(
      TC_X509_policies_init(&reader, (TC_bytes){valid, sizeof valid}, &bounds, seen, 2), ==,
      TC_TLV_OK);
  munit_assert_int(TC_X509_policy_next(&reader, &policy), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_policy_next(&reader, &policy), ==, TC_TLV_LIMIT);
  munit_assert_size(reader.count, ==, 1);
  /* The qualifier SEQUENCE, one PolicyQualifierInfo, its OID and value. */
  bounds = (TC_TLV_limits){64, 64, 4, 2};
  munit_assert_int(TC_X509_policy_qualifiers_init(&qualifiers, (TC_bytes){valid + 12, 9}, &bounds),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_policy_qualifier_next(&qualifiers, &qualifier), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_policy_qualifier_next(&qualifiers, &qualifier), ==, TC_TLV_END);
  bounds.max_elements = 3;
  munit_assert_int(TC_X509_policy_qualifiers_init(&qualifiers, (TC_bytes){valid + 12, 9}, &bounds),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_policy_qualifier_next(&qualifiers, &qualifier), ==, TC_TLV_LIMIT);
  bounds.max_elements = 4;
  bounds.max_depth = 1;
  munit_assert_int(TC_X509_policy_qualifiers_init(&qualifiers, (TC_bytes){valid + 12, 9}, &bounds),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_policy_qualifier_next(&qualifiers, &qualifier), ==, TC_TLV_LIMIT);
  return MUNIT_OK;
}

/* Contents readers cover IMPLICIT GeneralNames such as an AKI issuer. */
static MunitResult general_names_contents(const MunitParameter params[], void* user)
{
  const uint8_t contents[] = {0x82, 1, 'a', 0x86, 1, 'b'};
  const TC_TLV_limits bounds = {64, 64, 2, 1};
  TC_TLV_limits small = bounds;
  TC_TLV_frame frames[2];
  TC_X509_general_names_reader reader;
  TC_X509_general_name name;
  (void)params;
  (void)user;
  munit_assert_int(TC_X509_general_names_contents_init(&reader,
                                                       (TC_bytes){contents, sizeof contents},
                                                       &bounds, (TC_TLV_frames){frames, 2}),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_general_name_next(&reader, &name), ==, TC_TLV_OK);
  munit_assert_uint(name.type, ==, 2);
  munit_assert_int(TC_X509_general_name_next(&reader, &name), ==, TC_TLV_OK);
  munit_assert_uint(name.type, ==, 6);
  munit_assert_int(TC_X509_general_name_next(&reader, &name), ==, TC_TLV_END);
  small.max_elements = 1;
  munit_assert_int(TC_X509_general_names_contents_init(&reader,
                                                       (TC_bytes){contents, sizeof contents},
                                                       &small, (TC_TLV_frames){frames, 2}),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_general_name_next(&reader, &name), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_general_name_next(&reader, &name), ==, TC_TLV_LIMIT);
  munit_assert_int(TC_X509_general_names_contents_init(&reader, (TC_bytes){NULL, 0}, &bounds,
                                                       (TC_TLV_frames){frames, 2}),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_general_name_next(&reader, &name), ==, TC_TLV_END);
  /* A truncated name inside complete contents is malformed. */
  munit_assert_int(TC_X509_general_names_contents_init(&reader, (TC_bytes){contents, 2}, &bounds,
                                                       (TC_TLV_frames){frames, 2}),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_general_name_next(&reader, &name), ==, TC_TLV_INVALID);
  /* The SEQUENCE form rejects contents and an empty list. */
  munit_assert_int(TC_X509_general_names_init(&reader, (TC_bytes){contents, sizeof contents},
                                              &bounds, (TC_TLV_frames){frames, 2}),
                   ==, TC_TLV_INVALID);
  munit_assert_int(TC_X509_general_names_init(&reader, (TC_bytes){(const uint8_t*)"\x30\x00", 2},
                                              &bounds, (TC_TLV_frames){frames, 2}),
                   ==, TC_TLV_INVALID);
  munit_assert_int(TC_X509_general_names_contents_init(&reader,
                                                       (TC_bytes){contents, sizeof contents},
                                                       &bounds, (TC_TLV_frames){NULL, 2}),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_int(
      TC_X509_general_names_contents_init(&reader, (TC_bytes){contents, sizeof contents}, &bounds,
                                          (TC_TLV_frames){(TC_TLV_frame*)(void*)contents, 1}),
      ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_general_name_next(NULL, &name), ==, TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

static MunitResult policy_mappings(const MunitParameter params[], void* user)
{
  const uint8_t valid[] = {0x30, 16, 0x30, 6, 6, 1, 42, 6, 1, 42, 0x30, 6, 6, 1, 42, 6, 1, 43};
  const uint8_t invalid[][16] = {{0x30, 2, 0x30, 0},
                                 {0x30, 5, 0x30, 3, 6, 1, 42},
                                 {0x30, 11, 0x30, 9, 6, 1, 42, 6, 1, 43, 6, 1, 44},
                                 {0x30, 8, 0x30, 6, 4, 1, 42, 6, 1, 43},
                                 {0x30, 8, 0x30, 6, 6, 1, 42, 4, 1, 43},
                                 {0x30, 8, 0x30, 6, 6, 1, 42, 6, 1, 128},
                                 {0x30, 8, 0x30, 6, 6, 0, 6, 2, 128, 42},
                                 {0x30, 11, 0x30, 9, 6, 4, 0x55, 0x1d, 0x20, 0, 6, 1, 42},
                                 {0x30, 11, 0x30, 9, 6, 1, 42, 6, 4, 0x55, 0x1d, 0x20, 0}};
  const uint8_t empty[] = {0x30, 0};
  TC_TLV_limits bounds = {sizeof valid, sizeof valid, 7, 2};
  uint8_t malformed_tail[sizeof valid];
  TC_TLV_reader reader, saved_reader;
  TC_X509_policy_mapping out, saved;
  size_t i;
  (void)params;
  (void)user;
  munit_assert_int(TC_X509_policy_mappings_init(&reader, (TC_bytes){valid, sizeof valid}, &bounds),
                   ==, TC_TLV_OK);
  for (i = 0; i < 2; ++i) {
    munit_assert_int(TC_X509_policy_mapping_next(&reader, &out), ==, TC_TLV_OK);
    munit_assert_ptr_equal(out.issuer_policy.data, valid + 6 + 8 * i);
    munit_assert_size(out.issuer_policy.length, ==, 1);
    munit_assert_size(out.subject_policy.data[0], ==, 42 + i);
  }
  memcpy(&saved, &out, sizeof saved);
  memcpy(&saved_reader, &reader, sizeof reader);
  munit_assert_int(TC_X509_policy_mapping_next(&reader, &out), ==, TC_TLV_END);
  munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
  munit_assert_memory_equal(sizeof out, &out, &saved);
  memcpy(malformed_tail, valid, sizeof valid);
  malformed_tail[15] = 4;
  munit_assert_int(TC_X509_policy_mappings_init(
                       &reader, (TC_bytes){malformed_tail, sizeof malformed_tail}, &bounds),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_policy_mapping_next(&reader, &out), ==, TC_TLV_OK);
  memcpy(&saved_reader, &reader, sizeof reader);
  memset(&out, 0xa5, sizeof out);
  memset(&saved, 0xa5, sizeof saved);
  munit_assert_int(TC_X509_policy_mapping_next(&reader, &out), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
  munit_assert_memory_equal(sizeof out, &out, &saved);
  for (i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
    munit_assert_int(
        TC_X509_policy_mappings_init(&reader, (TC_bytes){invalid[i], invalid[i][1] + 2}, &bounds),
        ==, TC_TLV_OK);
    memcpy(&saved_reader, &reader, sizeof reader);
    munit_assert_int(TC_X509_policy_mapping_next(&reader, &out), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
    munit_assert_memory_equal(sizeof out, &out, &saved);
  }
  for (i = 0; i < sizeof valid; ++i)
    munit_assert_int(TC_X509_policy_mappings_init(&reader, (TC_bytes){valid, i}, &bounds), !=,
                     TC_TLV_OK);
  munit_assert_int(TC_X509_policy_mappings_init(&reader, (TC_bytes){empty, sizeof empty}, &bounds),
                   ==, TC_TLV_INVALID);
  /* The outer SEQUENCE and the first mapping use four elements. */
  bounds.max_elements = 4;
  munit_assert_int(TC_X509_policy_mappings_init(&reader, (TC_bytes){valid, sizeof valid}, &bounds),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_policy_mapping_next(&reader, &out), ==, TC_TLV_OK);
  memcpy(&saved_reader, &reader, sizeof reader);
  memset(&out, 0xa5, sizeof out);
  memset(&saved, 0xa5, sizeof saved);
  munit_assert_int(TC_X509_policy_mapping_next(&reader, &out), ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
  munit_assert_memory_equal(sizeof out, &out, &saved);
  munit_assert_int(TC_X509_policy_mapping_next(NULL, &out), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_policy_mapping_next(&reader, NULL), ==, TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

static MunitResult policies(const MunitParameter params[], void* user)
{
  const uint8_t valid[] = {0x30, 19,   0x30, 3,    6, 1, 42, 0x30, 12, 6, 1,
                           43,   0x30, 7,    0x30, 5, 6, 1,  44,   5,  0};
  const uint8_t empty[] = {0x30, 0};
  const uint8_t missing_value[] = {0x30, 5, 0x30, 3, 6, 1, 42};
  const uint8_t empty_qualifiers[] = {0x30, 7, 0x30, 5, 6, 1, 42, 0x30, 0};
  TC_TLV_limits bounds = {128, 128, 8, 2};
  TC_bytes seen[2];
  TC_X509_policy_reader reader, saved_reader;
  TC_X509_policy policy, saved;
  TC_TLV_reader qualifiers;
  TC_X509_policy_qualifier qualifier;
  uint8_t duplicate[sizeof valid];
  size_t i;
  (void)params;
  (void)user;
  munit_assert_int(
      TC_X509_policies_init(&reader, (TC_bytes){valid, sizeof valid}, &bounds, seen, 2), ==,
      TC_TLV_OK);
  memcpy(&saved_reader, &reader, sizeof reader);
  munit_assert_int(TC_X509_policy_next(&reader, (TC_X509_policy*)seen), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_policy_next(&reader, (TC_X509_policy*)&reader), ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
  munit_assert_int(TC_X509_policy_next(&reader, &policy), ==, TC_TLV_OK);
  munit_assert_uint8(policy.oid.data[0], ==, 42);
  munit_assert_null(policy.qualifiers.data);
  munit_assert_int(TC_X509_policy_qualifiers_init(&qualifiers, policy.qualifiers, &bounds), ==,
                   TC_TLV_OK);
  munit_assert_int(TC_X509_policy_qualifier_next(&qualifiers, &qualifier), ==, TC_TLV_END);
  munit_assert_int(TC_X509_policy_next(&reader, &policy), ==, TC_TLV_OK);
  munit_assert_uint8(policy.oid.data[0], ==, 43);
  munit_assert_ptr_equal(policy.qualifiers.data, valid + 12);
  munit_assert_int(TC_X509_policy_qualifiers_init(&qualifiers, policy.qualifiers, &bounds), ==,
                   TC_TLV_OK);
  munit_assert_int(TC_X509_policy_qualifier_next(&qualifiers, &qualifier), ==, TC_TLV_OK);
  munit_assert_uint8(qualifier.oid.data[0], ==, 44);
  munit_assert_ptr_equal(qualifier.value.data, valid + 19);
  munit_assert_size(qualifier.value.length, ==, 2);
  munit_assert_int(TC_X509_policy_qualifier_next(&qualifiers, &qualifier), ==, TC_TLV_END);
  munit_assert_int(TC_X509_policy_next(&reader, &policy), ==, TC_TLV_END);
  memcpy(duplicate, valid, sizeof valid);
  duplicate[11] = 42;
  munit_assert_int(
      TC_X509_policies_init(&reader, (TC_bytes){duplicate, sizeof duplicate}, &bounds, seen, 2), ==,
      TC_TLV_OK);
  munit_assert_int(TC_X509_policy_next(&reader, &policy), ==, TC_TLV_OK);
  memcpy(&saved, &policy, sizeof saved);
  memcpy(&saved_reader, &reader, sizeof reader);
  munit_assert_int(TC_X509_policy_next(&reader, &policy), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof policy, &policy, &saved);
  munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
  for (i = 0; i < sizeof valid; ++i)
    munit_assert_int(TC_X509_policies_init(&reader, (TC_bytes){valid, i}, &bounds, seen, 2), !=,
                     TC_TLV_OK);
  munit_assert_int(
      TC_X509_policies_init(&reader, (TC_bytes){empty, sizeof empty}, &bounds, seen, 2), ==,
      TC_TLV_INVALID);
  munit_assert_int(
      TC_X509_policies_init(&reader, (TC_bytes){valid, sizeof valid}, &bounds, NULL, 0), ==,
      TC_TLV_OK);
  munit_assert_int(TC_X509_policy_next(&reader, &policy), ==, TC_TLV_LIMIT);
  munit_assert_int(
      TC_X509_policies_init(&reader, (TC_bytes){valid, sizeof valid}, &bounds, NULL, 1), ==,
      TC_TLV_ARGUMENT);
  munit_assert_int(
      TC_X509_policies_init(&reader, (TC_bytes){valid, sizeof valid}, &bounds, seen, SIZE_MAX), ==,
      TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_policies_init(&reader,
                                         (TC_bytes){empty_qualifiers, sizeof empty_qualifiers},
                                         &bounds, seen, 2),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_policy_next(&reader, &policy), ==, TC_TLV_INVALID);
  munit_assert_int(TC_X509_policy_qualifiers_init(
                       &qualifiers, (TC_bytes){missing_value, sizeof missing_value}, &bounds),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_policy_qualifier_next(&qualifiers, &qualifier), ==, TC_TLV_INVALID);
  return MUNIT_OK;
}

static MunitResult general_names(const MunitParameter params[], void* user)
{
  const uint8_t valid[] = {0x30, 14, 0x82, 3, 'a', '.', 'b', 0x87, 4, 127, 0, 0, 1, 0x88, 1, 42};
  const uint8_t nested[] = {0x30, 14, 0xa0, 7, 6, 1, 42, 0xa0, 2, 5, 0, 0x82, 3, 'a', '.', 'b'};
  const uint8_t invalid[][8] = {{0x30, 2, 0x82, 0},          {0x30, 3, 0x82, 1, 0},
                                {0x30, 3, 0x86, 1, ' '},     {0x30, 3, 0x81, 1, 255},
                                {0x30, 3, 0x87, 1, 0},       {0x30, 3, 0x88, 1, 128},
                                {0x30, 4, 0xa4, 2, 0x30, 0}, {0x30, 3, 0x89, 1, 42}};
  TC_TLV_limits bounds = {128, 128, 16, 4};
  TC_X509_general_names_reader reader, saved_reader;
  TC_TLV_frame frames[4];
  const TC_TLV_frames scratch = {frames, 4};
  TC_X509_general_name out, saved;
  size_t i;
  (void)params;
  (void)user;
  munit_assert_int(
      TC_X509_general_names_init(&reader, (TC_bytes){valid, sizeof valid}, &bounds, scratch), ==,
      TC_TLV_OK);
  munit_assert_int(TC_X509_general_name_next(&reader, &out), ==, TC_TLV_OK);
  munit_assert_uint(out.type, ==, 2);
  munit_assert_ptr_equal(out.value.data, valid + 4);
  munit_assert_int(TC_X509_general_name_next(&reader, &out), ==, TC_TLV_OK);
  munit_assert_uint(out.type, ==, 7);
  munit_assert_size(out.value.length, ==, 4);
  munit_assert_int(TC_X509_general_name_next(&reader, &out), ==, TC_TLV_OK);
  munit_assert_uint(out.type, ==, 8);
  munit_assert_int(TC_X509_general_name_next(&reader, &out), ==, TC_TLV_END);
  memset(&out, 0xa5, sizeof out);
  memset(&saved, 0xa5, sizeof saved);
  for (i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
    munit_assert_int(TC_X509_general_names_init(&reader, (TC_bytes){invalid[i], invalid[i][1] + 2},
                                                &bounds, scratch),
                     ==, TC_TLV_OK);
    memcpy(&saved_reader, &reader, sizeof reader);
    munit_assert_int(TC_X509_general_name_next(&reader, &out), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
    munit_assert_memory_equal(sizeof out, &out, &saved);
  }
  /* The outer SEQUENCE and the otherName tree use five elements. */
  bounds.max_elements = 5;
  munit_assert_int(
      TC_X509_general_names_init(&reader, (TC_bytes){nested, sizeof nested}, &bounds, scratch), ==,
      TC_TLV_OK);
  munit_assert_int(TC_X509_general_name_next(&reader, &out), ==, TC_TLV_OK);
  munit_assert_uint(out.type, ==, 0);
  munit_assert_size(reader.reader.elements, ==, 5);
  memcpy(&saved_reader, &reader, sizeof reader);
  memset(&out, 0xa5, sizeof out);
  memset(&saved, 0xa5, sizeof saved);
  munit_assert_int(TC_X509_general_name_next(&reader, &out), ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
  munit_assert_memory_equal(sizeof out, &out, &saved);
  return MUNIT_OK;
}

static MunitResult name_constraints(const MunitParameter params[], void* user)
{
  const uint8_t valid[] = {0x30, 21,   0xa0, 5,   0x30, 3, 0x82, 1,   'a', 0xa1, 12, 0x30,
                           10,   0x87, 8,    192, 0,    2, 0,    255, 255, 255,  0};
  const uint8_t invalid[][8] = {{0x30, 0},
                                {0x30, 2, 0xa0, 0},
                                {0x30, 2, 0xa1, 0},
                                {0x30, 3, 0x80, 1, 0},
                                {0x30, 6, 0xa1, 1, 0, 0xa0, 1, 0},
                                {0x30, 6, 0xa0, 1, 0, 0xa0, 1, 0}};
  const uint8_t distances[] = {0x30, 9, 0x82, 1, 'a', 0x80, 1, 1, 0x81, 1, 2};
  const uint8_t default_zero[] = {0x30, 6, 0x82, 1, 'a', 0x80, 1, 0};
  const uint8_t plain_ip[] = {0x30, 6, 0x87, 4, 192, 0, 2, 0};
  TC_TLV_limits bounds = {128, 128, 16, 4};
  TC_TLV_frame frames[4];
  TC_X509_general_subtrees_reader reader, saved_reader;
  TC_X509_name_constraints out, saved;
  TC_X509_general_subtree subtree, saved_subtree;
  size_t i;
  (void)params;
  (void)user;
  munit_assert_int(TC_X509_name_constraints_read((TC_bytes){valid, sizeof valid}, &bounds, &out),
                   ==, TC_TLV_OK);
  munit_assert_ptr_equal(out.permitted.data, valid + 4);
  munit_assert_ptr_equal(out.excluded.data, valid + 11);
  munit_assert_int(
      TC_X509_general_subtrees_init(&reader, (TC_bytes){out.permitted.data, out.permitted.length},
                                    &bounds, (TC_TLV_frames){frames, 4}),
      ==, TC_TLV_OK);
  munit_assert_int(TC_X509_general_subtree_next(&reader, &subtree), ==, TC_TLV_OK);
  munit_assert_uint(subtree.base.type, ==, 2);
  munit_assert_uint32(subtree.minimum, ==, 0);
  munit_assert_false(subtree.has_maximum);
  munit_assert_int(TC_X509_general_subtree_next(&reader, &subtree), ==, TC_TLV_END);
  munit_assert_int(TC_X509_general_subtrees_init(&reader,
                                                 (TC_bytes){out.excluded.data, out.excluded.length},
                                                 &bounds, (TC_TLV_frames){frames, 4}),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_general_subtree_next(&reader, &subtree), ==, TC_TLV_OK);
  munit_assert_uint(subtree.base.type, ==, 7);
  munit_assert_size(subtree.base.value.length, ==, 8);
  memcpy(&saved, &out, sizeof saved);
  for (i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
    munit_assert_int(
        TC_X509_name_constraints_read((TC_bytes){invalid[i], invalid[i][1] + 2}, &bounds, &out), ==,
        TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof out, &out, &saved);
  }
  munit_assert_int(TC_X509_general_subtrees_init(&reader, (TC_bytes){distances, sizeof distances},
                                                 &bounds, (TC_TLV_frames){frames, 4}),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_general_subtree_next(&reader, &subtree), ==, TC_TLV_OK);
  munit_assert_uint32(subtree.minimum, ==, 1);
  munit_assert_true(subtree.has_maximum);
  munit_assert_uint32(subtree.maximum, ==, 2);
  memcpy(&saved_subtree, &subtree, sizeof subtree);
  munit_assert_int(TC_X509_general_subtrees_init(&reader,
                                                 (TC_bytes){default_zero, sizeof default_zero},
                                                 &bounds, (TC_TLV_frames){frames, 4}),
                   ==, TC_TLV_OK);
  memcpy(&saved_reader, &reader, sizeof reader);
  munit_assert_int(TC_X509_general_subtree_next(&reader, &subtree), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
  munit_assert_memory_equal(sizeof subtree, &subtree, &saved_subtree);
  munit_assert_int(TC_X509_general_subtrees_init(&reader, (TC_bytes){plain_ip, sizeof plain_ip},
                                                 &bounds, (TC_TLV_frames){frames, 4}),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_general_subtree_next(&reader, &subtree), ==, TC_TLV_INVALID);
  return MUNIT_OK;
}

static MunitResult subtree_limits(const MunitParameter params[], void* user)
{
  uint8_t ipv6[36] = {0x30, 34, 0x87, 32, 0x20, 1, 0x0d, 0xb8};
  const uint8_t maximum[] = {0x30, 10, 0x82, 1, 'a', 0x81, 5, 0, 255, 255, 255, 255};
  const uint8_t overflow[] = {0x30, 10, 0x82, 1, 'a', 0x81, 5, 1, 0, 0, 0, 0};
  const uint8_t invalid[][11] = {{0x30, 9, 0x82, 1, 'a', 0x81, 1, 2, 0x80, 1, 1},
                                 {0x30, 9, 0x82, 1, 'a', 0x80, 1, 1, 0x80, 1, 1},
                                 {0x30, 9, 0x82, 1, 'a', 0x81, 1, 2, 0x81, 1, 2},
                                 {0x30, 6, 0x82, 1, 'a', 0x80, 1, 255},
                                 {0x30, 7, 0x82, 1, 'a', 0x81, 2, 0, 1},
                                 {0x30, 6, 0x82, 1, 'a', 0x82, 1, 1}};
  TC_TLV_limits bounds = {128, 128, 16, 4};
  TC_X509_general_subtrees_reader reader, saved_reader;
  TC_TLV_frame frames[4];
  TC_X509_general_subtree out, saved;
  size_t i;
  (void)params;
  (void)user;
  memset(ipv6 + 20, 255, 8);
  munit_assert_int(TC_X509_general_subtrees_init(&reader, (TC_bytes){ipv6, sizeof ipv6}, &bounds,
                                                 (TC_TLV_frames){frames, 4}),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_general_subtree_next(&reader, &out), ==, TC_TLV_OK);
  munit_assert_size(out.base.value.length, ==, 32);
  munit_assert_ptr_equal(out.base.value.data, ipv6 + 4);
  munit_assert_int(TC_X509_general_subtrees_init(&reader, (TC_bytes){maximum, sizeof maximum},
                                                 &bounds, (TC_TLV_frames){frames, 4}),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_general_subtree_next(&reader, &out), ==, TC_TLV_OK);
  munit_assert_uint32(out.maximum, ==, UINT32_MAX);
  memcpy(&saved, &out, sizeof out);
  for (i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
    munit_assert_int(TC_X509_general_subtrees_init(&reader,
                                                   (TC_bytes){invalid[i], invalid[i][1] + 2},
                                                   &bounds, (TC_TLV_frames){frames, 4}),
                     ==, TC_TLV_OK);
    memcpy(&saved_reader, &reader, sizeof reader);
    munit_assert_int(TC_X509_general_subtree_next(&reader, &out), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
    munit_assert_memory_equal(sizeof out, &out, &saved);
  }
  munit_assert_int(TC_X509_general_subtrees_init(&reader, (TC_bytes){overflow, sizeof overflow},
                                                 &bounds, (TC_TLV_frames){frames, 4}),
                   ==, TC_TLV_OK);
  memcpy(&saved_reader, &reader, sizeof reader);
  munit_assert_int(TC_X509_general_subtree_next(&reader, &out), ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
  munit_assert_memory_equal(sizeof out, &out, &saved);
  munit_assert_int(TC_X509_general_subtrees_init(&reader, (TC_bytes){ipv6, sizeof ipv6}, &bounds,
                                                 (TC_TLV_frames){frames, 0}),
                   ==, TC_TLV_OK);
  memcpy(&saved_reader, &reader, sizeof reader);
  munit_assert_int(TC_X509_general_subtree_next(&reader, &out), ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
  munit_assert_memory_equal(sizeof out, &out, &saved);
  bounds.max_depth = 0;
  munit_assert_int(TC_X509_general_subtrees_init(&reader, (TC_bytes){ipv6, sizeof ipv6}, &bounds,
                                                 (TC_TLV_frames){frames, 4}),
                   ==, TC_TLV_OK);
  memcpy(&saved_reader, &reader, sizeof reader);
  munit_assert_int(TC_X509_general_subtree_next(&reader, &out), ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
  munit_assert_memory_equal(sizeof out, &out, &saved);
  /* Argument errors leave the reader unchanged. */
  munit_assert_int(TC_X509_general_subtrees_init(NULL, (TC_bytes){ipv6, sizeof ipv6}, &bounds,
                                                 (TC_TLV_frames){frames, 4}),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_general_subtrees_init(&reader, (TC_bytes){ipv6, sizeof ipv6}, NULL,
                                                 (TC_TLV_frames){frames, 4}),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_general_subtrees_init(&reader, (TC_bytes){ipv6, sizeof ipv6}, &bounds,
                                                 (TC_TLV_frames){NULL, 4}),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
  munit_assert_int(TC_X509_general_subtree_next(NULL, &out), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_general_subtree_next(&reader, NULL), ==, TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

static MunitResult key_identifiers(const MunitParameter params[], void* user)
{
  const uint8_t all[] = {0x30, 11, 0x80, 1, 7, 0xa1, 3, 0x82, 1, 'a', 0x82, 1, 1};
  const uint8_t empty[] = {0x30, 0}, empty_key[] = {0x30, 2, 0x80, 0};
  const uint8_t ski[] = {4, 3, 1, 2, 3};
  uint8_t long_serial[30] = {0x30, 28, 0xa1, 3, 0x82, 1, 'a', 0x82, 21, 1};
  const uint8_t invalid[][12] = {{0x30, 3, 0x82, 1, 1},
                                 {0x30, 5, 0xa1, 3, 0x82, 1, 'a'},
                                 {0x30, 6, 0x80, 1, 1, 0x80, 1, 2},
                                 {0x30, 3, 0x83, 1, 1},
                                 {0x30, 8, 0x82, 1, 1, 0xa1, 3, 0x82, 1, 'a'},
                                 {0x30, 9, 0xa1, 3, 0x82, 1, 'a', 0x82, 2, 0, 1},
                                 {0x30, 7, 0xa1, 3, 0x82, 1, 'a', 0x82, 0}};
  TC_TLV_limits bounds = {128, 128, 8, 4};
  TC_X509_authority_key_identifier out, saved;
  TC_bytes key;
  size_t i;
  (void)params;
  (void)user;
  munit_assert_int(TC_X509_subject_key_identifier_read((TC_bytes){ski, sizeof ski}, &bounds, &key),
                   ==, TC_TLV_OK);
  munit_assert_ptr_equal(key.data, ski + 2);
  munit_assert_size(key.length, ==, 3);
  munit_assert_int(
      TC_X509_subject_key_identifier_read((TC_bytes){empty, sizeof empty}, &bounds, &key), ==,
      TC_TLV_INVALID);
  munit_assert_ptr_equal(key.data, ski + 2);
  munit_assert_int(
      TC_X509_authority_key_identifier_read((TC_bytes){all, sizeof all}, &bounds, &out), ==,
      TC_TLV_OK);
  munit_assert_true(out.has_key_identifier);
  munit_assert_ptr_equal(out.key_identifier.data, all + 4);
  munit_assert_ptr_equal(out.issuer.data, all + 7);
  munit_assert_ptr_equal(out.serial.data, all + 12);
  munit_assert_false(out.serial_negative);
  munit_assert_int(
      TC_X509_authority_key_identifier_read((TC_bytes){empty, sizeof empty}, &bounds, &out), ==,
      TC_TLV_OK);
  munit_assert_false(out.has_key_identifier);
  munit_assert_null(out.serial.data);
  munit_assert_int(
      TC_X509_authority_key_identifier_read((TC_bytes){empty_key, sizeof empty_key}, &bounds, &out),
      ==, TC_TLV_OK);
  munit_assert_true(out.has_key_identifier);
  munit_assert_size(out.key_identifier.length, ==, 0);
  munit_assert_int(TC_X509_authority_key_identifier_read(
                       (TC_bytes){long_serial, sizeof long_serial}, &bounds, &out),
                   ==, TC_TLV_OK);
  munit_assert_size(out.serial.length, ==, 21);
  long_serial[9] = 128;
  munit_assert_int(TC_X509_authority_key_identifier_read(
                       (TC_bytes){long_serial, sizeof long_serial}, &bounds, &out),
                   ==, TC_TLV_OK);
  munit_assert_true(out.serial_negative);
  memcpy(&saved, &out, sizeof out);
  for (i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
    munit_assert_int(TC_X509_authority_key_identifier_read(
                         (TC_bytes){invalid[i], invalid[i][1] + 2}, &bounds, &out),
                     ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof out, &out, &saved);
  }
  for (i = 0; i < sizeof all; ++i) {
    munit_assert_int(TC_X509_authority_key_identifier_read((TC_bytes){all, i}, &bounds, &out), !=,
                     TC_TLV_OK);
    munit_assert_memory_equal(sizeof out, &out, &saved);
  }
  return MUNIT_OK;
}

#include <stdio.h>

/* max_elements covers every element TC_X509_read parses, including the
 * DER inside each extnValue. fcpcag2.crt has 70 elements in its outer
 * structure and 8 more inside its extension values. */
static MunitResult element_accounting(const MunitParameter params[], void* user)
{
  static uint8_t der[4096];
  TC_TLV_frame frames[32];
  TC_bytes oids[32];
  TC_X509_workspace workspace = {{frames, 32}, oids, 32};
  TC_X509_certificate certificate;
  FILE* file = fopen(TC_FPKI_CERTIFICATE, "rb");
  (void)params;
  (void)user;
  munit_assert_not_null(file);
  const size_t length = fread(der, 1, sizeof der, file);
  munit_assert_int(fclose(file), ==, 0);
  munit_assert_size(length, >, 0);
  TC_TLV_limits limits = {sizeof der, sizeof der, 78, 32};
  munit_assert_int(TC_X509_read((TC_bytes){der, length}, &limits, &workspace, &certificate), ==,
                   TC_TLV_OK);
  limits.max_elements = 77;
  munit_assert_int(TC_X509_read((TC_bytes){der, length}, &limits, &workspace, &certificate), ==,
                   TC_TLV_LIMIT);
  return MUNIT_OK;
}

/* Optional context-tagged fields must appear once each, in schema order. */
static MunitResult optional_field_order(const MunitParameter params[], void* user)
{
  const TC_TLV_limits bounds = {256, 256, 32, 8};
  (void)params;
  (void)user;
  /* AuthorityKeyIdentifier: [0] keyIdentifier, [1] issuer, [2] serial. */
  static const uint8_t key_id_only[] = {0x30, 3, 0x80, 1, 1};
  static const uint8_t key_id_twice[] = {0x30, 6, 0x80, 1, 1, 0x80, 1, 2};
  static const uint8_t serial_first[] = {0x30, 6, 0x82, 1, 1, 0x80, 1, 1};
  static const uint8_t unknown_tag[] = {0x30, 3, 0x83, 1, 1};
  TC_X509_authority_key_identifier akid;
  munit_assert_int(TC_X509_authority_key_identifier_read(
                       (TC_bytes){key_id_only, sizeof key_id_only}, &bounds, &akid),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_authority_key_identifier_read(
                       (TC_bytes){key_id_twice, sizeof key_id_twice}, &bounds, &akid),
                   ==, TC_TLV_INVALID);
  munit_assert_int(TC_X509_authority_key_identifier_read(
                       (TC_bytes){serial_first, sizeof serial_first}, &bounds, &akid),
                   ==, TC_TLV_INVALID);
  munit_assert_int(TC_X509_authority_key_identifier_read(
                       (TC_bytes){unknown_tag, sizeof unknown_tag}, &bounds, &akid),
                   ==, TC_TLV_INVALID);
  /* NameConstraints: [0] permitted before [1] excluded. */
  static const uint8_t excluded_first[] = {0x30, 16,   0xa1, 6,    0x30, 4,    0x82, 2,   'a',
                                           'b',  0xa0, 6,    0x30, 4,    0x82, 2,    'c', 'd'};
  TC_X509_name_constraints constraints;
  munit_assert_int(TC_X509_name_constraints_read((TC_bytes){excluded_first, sizeof excluded_first},
                                                 &bounds, &constraints),
                   ==, TC_TLV_INVALID);
  /* PolicyConstraints: [0] requireExplicitPolicy before [1] inhibitMapping. */
  static const uint8_t mapping_first[] = {0x30, 6, 0x81, 1, 1, 0x80, 1, 1};
  static const uint8_t in_order[] = {0x30, 6, 0x80, 1, 1, 0x81, 1, 2};
  TC_X509_policy_constraints policy;
  munit_assert_int(TC_X509_policy_constraints_read((TC_bytes){in_order, sizeof in_order},
                                                   &value_limits, &policy),
                   ==, TC_TLV_OK);
  munit_assert_uint32(policy.inhibit_policy_mapping, ==, 2);
  munit_assert_int(TC_X509_policy_constraints_read((TC_bytes){mapping_first, sizeof mapping_first},
                                                   &value_limits, &policy),
                   ==, TC_TLV_INVALID);
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/optional-field-order", optional_field_order, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/element-accounting", element_accounting, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/key-identifiers", key_identifiers, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/subtree-limits", subtree_limits, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/name-constraints", name_constraints, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/general-names", general_names, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/policies", policies, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/value-budgets", value_budgets, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/policy-budgets", policy_budgets, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/general-names-contents", general_names_contents, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/extension-budget", extension_budget, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/policy-mapping-budget", policy_mapping_budget, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/policy-mappings", policy_mappings, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/policy-constraints", policy_constraints, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/eku-valid", eku_valid, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/eku-invalid", eku_invalid, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/eku-storage", eku_storage, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
static const MunitSuite suite = {"/x509-extensions", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
