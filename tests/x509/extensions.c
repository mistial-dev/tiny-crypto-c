/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/x509.h>
#include "munit.h"
#include <string.h>

static const uint8_t purposes[] = {
  0x30, 15, 6, 8, 0x2b, 6, 1, 5, 5, 7, 3, 2, 6, 3, 0x55, 0x1d, 0x25
};

static MunitResult eku_valid(const MunitParameter params[], void* user)
{
  TC_bytes oids[3];
  size_t count = 99;
  (void)params; (void)user;
  memset(oids, 0, sizeof oids);
  munit_assert_int(TC_X509_extended_key_usage_read(purposes, sizeof purposes, oids, 3, &count), ==, TC_TLV_OK);
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
  const uint8_t empty[] = {0x30,0};
  const uint8_t empty_oid[] = {0x30,2,6,0};
  const uint8_t nonminimal[] = {0x30,4,6,2,0x80,0x2a};
  uint8_t bad[sizeof purposes];
  TC_bytes oids[3], saved[3];
  size_t count = 99, i;
  (void)params; (void)user;
  memset(saved, 0xa5, sizeof saved);
  memcpy(oids, saved, sizeof oids);
  for (i = 0; i < sizeof purposes; ++i) {
    munit_assert_int(TC_X509_extended_key_usage_read(purposes, i, oids, 3, &count), !=, TC_TLV_OK);
    munit_assert_memory_equal(sizeof oids, oids, saved);
    munit_assert_size(count, ==, 99);
  }
  memcpy(bad, purposes, sizeof bad);
  bad[12] = 4;
  munit_assert_int(TC_X509_extended_key_usage_read(bad, sizeof bad, oids, 3, &count), ==, TC_TLV_INVALID);
  munit_assert_int(TC_X509_extended_key_usage_read(empty, sizeof empty, oids, 3, &count), ==, TC_TLV_INVALID);
  munit_assert_int(TC_X509_extended_key_usage_read(empty_oid, sizeof empty_oid, oids, 3, &count), ==, TC_TLV_INVALID);
  munit_assert_int(TC_X509_extended_key_usage_read(nonminimal, sizeof nonminimal, oids, 3, &count), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof oids, oids, saved);
  munit_assert_size(count, ==, 99);
  return MUNIT_OK;
}

static MunitResult eku_storage(const MunitParameter params[], void* user)
{
  TC_bytes oids[3], saved[3];
  size_t count = 99;
  (void)params; (void)user;
  memset(saved, 0xa5, sizeof saved);
  memcpy(oids, saved, sizeof oids);
  munit_assert_int(TC_X509_extended_key_usage_read(purposes, sizeof purposes, oids, 1, &count), ==, TC_TLV_LIMIT);
  munit_assert_int(TC_X509_extended_key_usage_read(purposes, sizeof purposes, NULL, 0, &count), ==, TC_TLV_LIMIT);
  munit_assert_int(TC_X509_extended_key_usage_read(purposes, sizeof purposes, NULL, 1, &count), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_extended_key_usage_read(purposes, sizeof purposes, oids, SIZE_MAX, &count), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_extended_key_usage_read(purposes, sizeof purposes, oids, 3, NULL), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_extended_key_usage_read(NULL, 1, oids, 3, &count), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_extended_key_usage_read((const uint8_t*)oids, sizeof oids, oids, 3, &count), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_extended_key_usage_read(purposes, sizeof purposes, oids, 3, &oids[0].length), ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof oids, oids, saved);
  munit_assert_size(count, ==, 99);
  munit_assert_int(TC_X509_extended_key_usage_read(purposes, sizeof purposes, oids, 2, &count), ==, TC_TLV_OK);
  munit_assert_size(count, ==, 2);
  return MUNIT_OK;
}

static MunitResult policy_constraints(const MunitParameter params[], void* user)
{
  const uint8_t both[] = {0x30,6,0x80,1,0,0x81,1,3};
  const uint8_t one[] = {0x30,3,0x81,1,0};
  const uint8_t maximum[] = {0x30,7,0x80,5,0,255,255,255,255};
  const uint8_t overflow[] = {0x30,7,0x80,5,1,0,0,0,0};
  const uint8_t invalid[][8] = {
    {0x30,0}, {0x30,3,0x80,1,255}, {0x30,4,0x80,2,0,1},
    {0x30,6,0x81,1,0,0x80,1,0}, {0x30,6,0x80,1,0,0x80,1,0},
    {0x30,3,0xa0,1,0}, {0x30,3,0x82,1,0}, {0x30,2,0x80,0}
  };
  TC_X509_policy_constraints out, saved;
  size_t i;
  (void)params; (void)user;
  munit_assert_int(TC_X509_policy_constraints_read(both, sizeof both, &out), ==, TC_TLV_OK);
  munit_assert_true(out.has_require_explicit_policy && out.has_inhibit_policy_mapping);
  munit_assert_uint32(out.require_explicit_policy, ==, 0);
  munit_assert_uint32(out.inhibit_policy_mapping, ==, 3);
  munit_assert_int(TC_X509_policy_constraints_read(one, sizeof one, &out), ==, TC_TLV_OK);
  munit_assert_false(out.has_require_explicit_policy);
  munit_assert_true(out.has_inhibit_policy_mapping);
  munit_assert_uint32(out.inhibit_policy_mapping, ==, 0);
  munit_assert_int(TC_X509_policy_constraints_read(maximum, sizeof maximum, &out), ==, TC_TLV_OK);
  munit_assert_uint32(out.require_explicit_policy, ==, UINT32_MAX);
  memset(&out, 0xa5, sizeof out);
  memset(&saved, 0xa5, sizeof saved);
  for (i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
    munit_assert_int(TC_X509_policy_constraints_read(invalid[i], invalid[i][1] + 2, &out), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof out, &out, &saved);
  }
  for (i = 0; i < sizeof both; ++i) {
    munit_assert_int(TC_X509_policy_constraints_read(both, i, &out), !=, TC_TLV_OK);
    munit_assert_memory_equal(sizeof out, &out, &saved);
  }
  munit_assert_int(TC_X509_policy_constraints_read(overflow, sizeof overflow, &out), ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof out, &out, &saved);
  munit_assert_int(TC_X509_policy_constraints_read(both, sizeof both, NULL), ==, TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

static MunitResult policy_mappings(const MunitParameter params[], void* user)
{
  const uint8_t valid[] = {0x30,16,0x30,6,6,1,42,6,1,42,0x30,6,6,1,42,6,1,43};
  const uint8_t invalid[][16] = {
    {0x30,2,0x30,0}, {0x30,5,0x30,3,6,1,42},
    {0x30,11,0x30,9,6,1,42,6,1,43,6,1,44},
    {0x30,8,0x30,6,4,1,42,6,1,43},
    {0x30,8,0x30,6,6,1,42,4,1,43},
    {0x30,8,0x30,6,6,1,42,6,1,128},
    {0x30,8,0x30,6,6,0,6,2,128,42},
    {0x30,11,0x30,9,6,4,0x55,0x1d,0x20,0,6,1,42},
    {0x30,11,0x30,9,6,1,42,6,4,0x55,0x1d,0x20,0}
  };
  const uint8_t empty[] = {0x30,0};
  TC_TLV_limits bounds = {sizeof valid, sizeof valid, 2, 1};
  uint8_t malformed_tail[sizeof valid];
  TC_TLV_reader reader, saved_reader;
  TC_X509_policy_mapping out, saved;
  size_t i;
  (void)params; (void)user;
  munit_assert_int(TC_X509_policy_mappings_init(&reader, valid, sizeof valid, &bounds), ==, TC_TLV_OK);
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
  munit_assert_int(TC_X509_policy_mappings_init(&reader, malformed_tail,
      sizeof malformed_tail, &bounds), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_policy_mapping_next(&reader, &out), ==, TC_TLV_OK);
  memcpy(&saved_reader, &reader, sizeof reader);
  memset(&out, 0xa5, sizeof out);
  memset(&saved, 0xa5, sizeof saved);
  munit_assert_int(TC_X509_policy_mapping_next(&reader, &out), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
  munit_assert_memory_equal(sizeof out, &out, &saved);
  for (i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
    munit_assert_int(TC_X509_policy_mappings_init(&reader, invalid[i], invalid[i][1] + 2, &bounds), ==, TC_TLV_OK);
    memcpy(&saved_reader, &reader, sizeof reader);
    munit_assert_int(TC_X509_policy_mapping_next(&reader, &out), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
    munit_assert_memory_equal(sizeof out, &out, &saved);
  }
  for (i = 0; i < sizeof valid; ++i)
    munit_assert_int(TC_X509_policy_mappings_init(&reader, valid, i, &bounds), !=, TC_TLV_OK);
  munit_assert_int(TC_X509_policy_mappings_init(&reader, empty, sizeof empty, &bounds), ==, TC_TLV_INVALID);
  bounds.max_elements = 1;
  munit_assert_int(TC_X509_policy_mappings_init(&reader, valid, sizeof valid, &bounds), ==, TC_TLV_OK);
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
  const uint8_t valid[] = {0x30,19,0x30,3,6,1,42,0x30,12,6,1,43,0x30,7,0x30,5,6,1,44,5,0};
  const uint8_t empty[] = {0x30,0};
  const uint8_t missing_value[] = {0x30,5,0x30,3,6,1,42};
  const uint8_t empty_qualifiers[] = {0x30,7,0x30,5,6,1,42,0x30,0};
  TC_TLV_limits bounds = {128,128,8,2};
  TC_bytes seen[2];
  TC_X509_policy_reader reader, saved_reader;
  TC_X509_policy policy, saved;
  TC_TLV_reader qualifiers;
  TC_X509_policy_qualifier qualifier;
  uint8_t duplicate[sizeof valid];
  size_t i;
  (void)params; (void)user;
  munit_assert_int(TC_X509_policies_init(&reader, valid, sizeof valid, &bounds, seen, 2), ==, TC_TLV_OK);
  memcpy(&saved_reader, &reader, sizeof reader);
  munit_assert_int(TC_X509_policy_next(&reader, (TC_X509_policy*)seen), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_policy_next(&reader, (TC_X509_policy*)&reader), ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
  munit_assert_int(TC_X509_policy_next(&reader, &policy), ==, TC_TLV_OK);
  munit_assert_uint8(policy.oid.data[0], ==, 42);
  munit_assert_null(policy.qualifiers.data);
  munit_assert_int(TC_X509_policy_qualifiers_init(&qualifiers, policy.qualifiers, &bounds), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_policy_qualifier_next(&qualifiers, &qualifier), ==, TC_TLV_END);
  munit_assert_int(TC_X509_policy_next(&reader, &policy), ==, TC_TLV_OK);
  munit_assert_uint8(policy.oid.data[0], ==, 43);
  munit_assert_ptr_equal(policy.qualifiers.data, valid + 12);
  munit_assert_int(TC_X509_policy_qualifiers_init(&qualifiers, policy.qualifiers, &bounds), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_policy_qualifier_next(&qualifiers, &qualifier), ==, TC_TLV_OK);
  munit_assert_uint8(qualifier.oid.data[0], ==, 44);
  munit_assert_ptr_equal(qualifier.value.data, valid + 19);
  munit_assert_size(qualifier.value.length, ==, 2);
  munit_assert_int(TC_X509_policy_qualifier_next(&qualifiers, &qualifier), ==, TC_TLV_END);
  munit_assert_int(TC_X509_policy_next(&reader, &policy), ==, TC_TLV_END);
  memcpy(duplicate, valid, sizeof valid); duplicate[11] = 42;
  munit_assert_int(TC_X509_policies_init(&reader, duplicate, sizeof duplicate, &bounds, seen, 2), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_policy_next(&reader, &policy), ==, TC_TLV_OK);
  memcpy(&saved, &policy, sizeof saved); memcpy(&saved_reader, &reader, sizeof reader);
  munit_assert_int(TC_X509_policy_next(&reader, &policy), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof policy, &policy, &saved);
  munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
  for (i = 0; i < sizeof valid; ++i)
    munit_assert_int(TC_X509_policies_init(&reader, valid, i, &bounds, seen, 2), !=, TC_TLV_OK);
  munit_assert_int(TC_X509_policies_init(&reader, empty, sizeof empty, &bounds, seen, 2), ==, TC_TLV_INVALID);
  munit_assert_int(TC_X509_policies_init(&reader, valid, sizeof valid, &bounds, NULL, 0), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_policy_next(&reader, &policy), ==, TC_TLV_LIMIT);
  munit_assert_int(TC_X509_policies_init(&reader, valid, sizeof valid, &bounds, NULL, 1), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_policies_init(&reader, valid, sizeof valid, &bounds, seen, SIZE_MAX), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_policies_init(&reader, empty_qualifiers, sizeof empty_qualifiers,
      &bounds, seen, 2), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_policy_next(&reader, &policy), ==, TC_TLV_INVALID);
  munit_assert_int(TC_X509_policy_qualifiers_init(&qualifiers,
      (TC_bytes){missing_value, sizeof missing_value}, &bounds), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_policy_qualifier_next(&qualifiers, &qualifier), ==, TC_TLV_INVALID);
  return MUNIT_OK;
}

static MunitResult general_names(const MunitParameter params[], void* user)
{
  const uint8_t valid[] = {0x30,14,0x82,3,'a','.','b',0x87,4,127,0,0,1,0x88,1,42};
  const uint8_t nested[] = {0x30,14,0xa0,7,6,1,42,0xa0,2,5,0,0x82,3,'a','.','b'};
  const uint8_t invalid[][8] = {
    {0x30,2,0x82,0}, {0x30,3,0x82,1,0}, {0x30,3,0x86,1,' '},
    {0x30,3,0x81,1,255}, {0x30,3,0x87,1,0}, {0x30,3,0x88,1,128},
    {0x30,4,0xa4,2,0x30,0}, {0x30,3,0x89,1,42}
  };
  TC_TLV_limits bounds = {128,128,16,4};
  TC_TLV_reader reader, saved_reader;
  TC_TLV_frame frames[4];
  TC_X509_general_name out, saved;
  size_t i;
  (void)params; (void)user;
  munit_assert_int(TC_X509_general_names_init(&reader, valid, sizeof valid, &bounds), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_general_name_next(&reader, frames, 4, &out), ==, TC_TLV_OK);
  munit_assert_uint(out.type, ==, 2);
  munit_assert_ptr_equal(out.value.data, valid + 4);
  munit_assert_int(TC_X509_general_name_next(&reader, frames, 4, &out), ==, TC_TLV_OK);
  munit_assert_uint(out.type, ==, 7);
  munit_assert_size(out.value.length, ==, 4);
  munit_assert_int(TC_X509_general_name_next(&reader, frames, 4, &out), ==, TC_TLV_OK);
  munit_assert_uint(out.type, ==, 8);
  munit_assert_int(TC_X509_general_name_next(&reader, frames, 4, &out), ==, TC_TLV_END);
  memset(&out, 0xa5, sizeof out);
  memset(&saved, 0xa5, sizeof saved);
  for (i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
    munit_assert_int(TC_X509_general_names_init(&reader, invalid[i], invalid[i][1] + 2, &bounds), ==, TC_TLV_OK);
    memcpy(&saved_reader, &reader, sizeof reader);
    munit_assert_int(TC_X509_general_name_next(&reader, frames, 4, &out), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
    munit_assert_memory_equal(sizeof out, &out, &saved);
  }
  bounds.max_elements = 4;
  munit_assert_int(TC_X509_general_names_init(&reader, nested, sizeof nested, &bounds), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_general_name_next(&reader, frames, 4, &out), ==, TC_TLV_OK);
  munit_assert_uint(out.type, ==, 0);
  munit_assert_size(reader.elements, ==, 4);
  memcpy(&saved_reader, &reader, sizeof reader);
  memset(&out, 0xa5, sizeof out);
  memset(&saved, 0xa5, sizeof saved);
  munit_assert_int(TC_X509_general_name_next(&reader, frames, 4, &out), ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
  munit_assert_memory_equal(sizeof out, &out, &saved);
  return MUNIT_OK;
}

static MunitResult name_constraints(const MunitParameter params[], void* user)
{
  const uint8_t valid[] = {0x30,21,0xa0,5,0x30,3,0x82,1,'a',
    0xa1,12,0x30,10,0x87,8,192,0,2,0,255,255,255,0};
  const uint8_t invalid[][8] = {
    {0x30,0}, {0x30,2,0xa0,0}, {0x30,2,0xa1,0}, {0x30,3,0x80,1,0},
    {0x30,6,0xa1,1,0,0xa0,1,0}, {0x30,6,0xa0,1,0,0xa0,1,0}
  };
  const uint8_t distances[] = {0x30,9,0x82,1,'a',0x80,1,1,0x81,1,2};
  const uint8_t default_zero[] = {0x30,6,0x82,1,'a',0x80,1,0};
  const uint8_t plain_ip[] = {0x30,6,0x87,4,192,0,2,0};
  TC_TLV_limits bounds = {128,128,16,4};
  TC_TLV_frame frames[4];
  TC_TLV_reader reader, saved_reader;
  TC_X509_name_constraints out, saved;
  TC_X509_general_subtree subtree, saved_subtree;
  size_t i;
  (void)params; (void)user;
  munit_assert_int(TC_X509_name_constraints_read(valid, sizeof valid, &bounds, &out), ==, TC_TLV_OK);
  munit_assert_ptr_equal(out.permitted.data, valid + 4);
  munit_assert_ptr_equal(out.excluded.data, valid + 11);
  munit_assert_int(TC_TLV_reader_init(&reader, out.permitted.data, out.permitted.length,
      TC_TLV_DER, &bounds), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_general_subtree_next(&reader, frames, 4, &subtree), ==, TC_TLV_OK);
  munit_assert_uint(subtree.base.type, ==, 2);
  munit_assert_uint32(subtree.minimum, ==, 0);
  munit_assert_false(subtree.has_maximum);
  munit_assert_int(TC_X509_general_subtree_next(&reader, frames, 4, &subtree), ==, TC_TLV_END);
  munit_assert_int(TC_TLV_reader_init(&reader, out.excluded.data, out.excluded.length,
      TC_TLV_DER, &bounds), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_general_subtree_next(&reader, frames, 4, &subtree), ==, TC_TLV_OK);
  munit_assert_uint(subtree.base.type, ==, 7);
  munit_assert_size(subtree.base.value.length, ==, 8);
  memcpy(&saved, &out, sizeof saved);
  for (i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
    munit_assert_int(TC_X509_name_constraints_read(invalid[i], invalid[i][1] + 2,
        &bounds, &out), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof out, &out, &saved);
  }
  munit_assert_int(TC_TLV_reader_init(&reader, distances, sizeof distances, TC_TLV_DER, &bounds), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_general_subtree_next(&reader, frames, 4, &subtree), ==, TC_TLV_OK);
  munit_assert_uint32(subtree.minimum, ==, 1);
  munit_assert_true(subtree.has_maximum);
  munit_assert_uint32(subtree.maximum, ==, 2);
  memcpy(&saved_subtree, &subtree, sizeof subtree);
  munit_assert_int(TC_TLV_reader_init(&reader, default_zero, sizeof default_zero, TC_TLV_DER, &bounds), ==, TC_TLV_OK);
  memcpy(&saved_reader, &reader, sizeof reader);
  munit_assert_int(TC_X509_general_subtree_next(&reader, frames, 4, &subtree), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
  munit_assert_memory_equal(sizeof subtree, &subtree, &saved_subtree);
  munit_assert_int(TC_TLV_reader_init(&reader, plain_ip, sizeof plain_ip, TC_TLV_DER, &bounds), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_general_subtree_next(&reader, frames, 4, &subtree), ==, TC_TLV_INVALID);
  return MUNIT_OK;
}

static MunitResult subtree_limits(const MunitParameter params[], void* user)
{
  uint8_t ipv6[36] = {0x30,34,0x87,32,0x20,1,0x0d,0xb8};
  const uint8_t maximum[] = {0x30,10,0x82,1,'a',0x81,5,0,255,255,255,255};
  const uint8_t overflow[] = {0x30,10,0x82,1,'a',0x81,5,1,0,0,0,0};
  const uint8_t invalid[][11] = {
    {0x30,9,0x82,1,'a',0x81,1,2,0x80,1,1},
    {0x30,9,0x82,1,'a',0x80,1,1,0x80,1,1},
    {0x30,9,0x82,1,'a',0x81,1,2,0x81,1,2},
    {0x30,6,0x82,1,'a',0x80,1,255},
    {0x30,7,0x82,1,'a',0x81,2,0,1},
    {0x30,6,0x82,1,'a',0x82,1,1}
  };
  TC_TLV_limits bounds = {128,128,16,4};
  TC_TLV_reader reader, saved_reader;
  TC_TLV_frame frames[4];
  TC_X509_general_subtree out, saved;
  size_t i;
  (void)params; (void)user;
  memset(ipv6 + 20, 255, 8);
  munit_assert_int(TC_TLV_reader_init(&reader, ipv6, sizeof ipv6, TC_TLV_DER, &bounds), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_general_subtree_next(&reader, frames, 4, &out), ==, TC_TLV_OK);
  munit_assert_size(out.base.value.length, ==, 32);
  munit_assert_ptr_equal(out.base.value.data, ipv6 + 4);
  munit_assert_int(TC_TLV_reader_init(&reader, maximum, sizeof maximum, TC_TLV_DER, &bounds), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_general_subtree_next(&reader, frames, 4, &out), ==, TC_TLV_OK);
  munit_assert_uint32(out.maximum, ==, UINT32_MAX);
  memcpy(&saved, &out, sizeof out);
  for (i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
    munit_assert_int(TC_TLV_reader_init(&reader, invalid[i], invalid[i][1] + 2, TC_TLV_DER, &bounds), ==, TC_TLV_OK);
    memcpy(&saved_reader, &reader, sizeof reader);
    munit_assert_int(TC_X509_general_subtree_next(&reader, frames, 4, &out), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
    munit_assert_memory_equal(sizeof out, &out, &saved);
  }
  munit_assert_int(TC_TLV_reader_init(&reader, overflow, sizeof overflow, TC_TLV_DER, &bounds), ==, TC_TLV_OK);
  memcpy(&saved_reader, &reader, sizeof reader);
  munit_assert_int(TC_X509_general_subtree_next(&reader, frames, 4, &out), ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
  munit_assert_memory_equal(sizeof out, &out, &saved);
  munit_assert_int(TC_TLV_reader_init(&reader, ipv6, sizeof ipv6, TC_TLV_DER, &bounds), ==, TC_TLV_OK);
  memcpy(&saved_reader, &reader, sizeof reader);
  munit_assert_int(TC_X509_general_subtree_next(&reader, frames, 0, &out), ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
  munit_assert_memory_equal(sizeof out, &out, &saved);
  bounds.max_depth = 0;
  munit_assert_int(TC_TLV_reader_init(&reader, ipv6, sizeof ipv6, TC_TLV_DER, &bounds), ==, TC_TLV_OK);
  memcpy(&saved_reader, &reader, sizeof reader);
  munit_assert_int(TC_X509_general_subtree_next(&reader, frames, 4, &out), ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
  munit_assert_memory_equal(sizeof out, &out, &saved);
  return MUNIT_OK;
}

static MunitResult key_identifiers(const MunitParameter params[], void* user)
{
  const uint8_t all[] = {0x30,11,0x80,1,7,0xa1,3,0x82,1,'a',0x82,1,1};
  const uint8_t empty[] = {0x30,0}, empty_key[] = {0x30,2,0x80,0};
  const uint8_t ski[] = {4,3,1,2,3};
  uint8_t long_serial[30] = {0x30,28,0xa1,3,0x82,1,'a',0x82,21,1};
  const uint8_t invalid[][12] = {
    {0x30,3,0x82,1,1}, {0x30,5,0xa1,3,0x82,1,'a'},
    {0x30,6,0x80,1,1,0x80,1,2}, {0x30,3,0x83,1,1},
    {0x30,8,0x82,1,1,0xa1,3,0x82,1,'a'},
    {0x30,9,0xa1,3,0x82,1,'a',0x82,2,0,1},
    {0x30,7,0xa1,3,0x82,1,'a',0x82,0}
  };
  TC_TLV_limits bounds = {128,128,8,4};
  TC_X509_authority_key_identifier out, saved;
  TC_bytes key;
  size_t i;
  (void)params; (void)user;
  munit_assert_int(TC_X509_subject_key_identifier_read(ski, sizeof ski, &bounds, &key), ==, TC_TLV_OK);
  munit_assert_ptr_equal(key.data, ski + 2);
  munit_assert_size(key.length, ==, 3);
  munit_assert_int(TC_X509_subject_key_identifier_read(empty, sizeof empty, &bounds, &key), ==, TC_TLV_INVALID);
  munit_assert_ptr_equal(key.data, ski + 2);
  munit_assert_int(TC_X509_authority_key_identifier_read(all, sizeof all, &bounds, &out), ==, TC_TLV_OK);
  munit_assert_true(out.has_key_identifier);
  munit_assert_ptr_equal(out.key_identifier.data, all + 4);
  munit_assert_ptr_equal(out.issuer.data, all + 7);
  munit_assert_ptr_equal(out.serial.data, all + 12);
  munit_assert_false(out.serial_negative);
  munit_assert_int(TC_X509_authority_key_identifier_read(empty, sizeof empty, &bounds, &out), ==, TC_TLV_OK);
  munit_assert_false(out.has_key_identifier);
  munit_assert_null(out.serial.data);
  munit_assert_int(TC_X509_authority_key_identifier_read(empty_key, sizeof empty_key, &bounds, &out), ==, TC_TLV_OK);
  munit_assert_true(out.has_key_identifier);
  munit_assert_size(out.key_identifier.length, ==, 0);
  munit_assert_int(TC_X509_authority_key_identifier_read(long_serial, sizeof long_serial, &bounds, &out), ==, TC_TLV_OK);
  munit_assert_size(out.serial.length, ==, 21);
  long_serial[9] = 128;
  munit_assert_int(TC_X509_authority_key_identifier_read(long_serial, sizeof long_serial, &bounds, &out), ==, TC_TLV_OK);
  munit_assert_true(out.serial_negative);
  memcpy(&saved, &out, sizeof out);
  for (i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
    munit_assert_int(TC_X509_authority_key_identifier_read(invalid[i], invalid[i][1] + 2,
        &bounds, &out), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof out, &out, &saved);
  }
  for (i = 0; i < sizeof all; ++i) {
    munit_assert_int(TC_X509_authority_key_identifier_read(all, i, &bounds, &out), !=, TC_TLV_OK);
    munit_assert_memory_equal(sizeof out, &out, &saved);
  }
  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/key-identifiers", key_identifiers, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/subtree-limits", subtree_limits, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/name-constraints", name_constraints, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/general-names", general_names, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/policies", policies, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/policy-mappings", policy_mappings, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/policy-constraints", policy_constraints, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/eku-valid", eku_valid, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/eku-invalid", eku_invalid, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/eku-storage", eku_storage, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};
static const MunitSuite suite = {"/x509-extensions", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{ return munit_suite_main(&suite, NULL, argc, argv); }
