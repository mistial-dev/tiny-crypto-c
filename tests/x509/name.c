/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/x509.h>
#include "munit.h"
#include <string.h>

static const uint8_t multi[] = {
  0x30,22,0x31,20,0x30,8,6,3,0x55,4,3,0x0c,1,'A',
  0x30,8,6,3,0x55,4,10,0x13,1,'Z'
};
static const TC_TLV_limits bounds = {1024,1024,32,3};

static MunitResult attributes(const MunitParameter params[], void* user)
{
  TC_bytes encoded = {multi,sizeof multi}, rdn;
  TC_TLV_reader name, values;
  TC_X509_name_attribute attribute;
  (void)params; (void)user;
  munit_assert_int(TC_X509_name_init(&name, encoded, &bounds), ==, TC_TLV_OK);
  munit_assert_size(name.elements, ==, 1);
  munit_assert_int(TC_X509_rdn_next(&name, &rdn), ==, TC_TLV_OK);
  munit_assert_size(name.elements, ==, 8);
  munit_assert_ptr_equal(rdn.data, multi + 4);
  munit_assert_size(rdn.length, ==, 20);
  munit_assert_int(TC_TLV_reader_init(&values, rdn.data, rdn.length, TC_TLV_DER, &bounds), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_attribute_next(&values, &attribute), ==, TC_TLV_OK);
  munit_assert_size(values.elements, ==, 3);
  munit_assert_ptr_equal(attribute.encoded.data, multi + 4);
  munit_assert_ptr_equal(attribute.oid.data, multi + 8);
  munit_assert_ptr_equal(attribute.value.data, multi + 11);
  munit_assert_int(TC_X509_attribute_next(&values, &attribute), ==, TC_TLV_OK);
  munit_assert_uint8(attribute.oid.data[2], ==, 10);
  munit_assert_int(TC_X509_attribute_next(&values, &attribute), ==, TC_TLV_END);
  munit_assert_int(TC_X509_rdn_next(&name, &rdn), ==, TC_TLV_END);
  return MUNIT_OK;
}

static MunitResult limits(const MunitParameter params[], void* user)
{
  TC_bytes encoded = {multi,sizeof multi}, rdn = {multi,1};
  TC_TLV_reader reader, saved;
  TC_TLV_limits limited = bounds;
  size_t i;
  (void)params; (void)user;
  for (i = 1; i < 8; ++i) {
    limited.max_elements = i;
    munit_assert_int(TC_X509_name_init(&reader, encoded, &limited), ==, TC_TLV_OK);
    saved = reader;
    munit_assert_int(TC_X509_rdn_next(&reader, &rdn), ==, TC_TLV_LIMIT);
    munit_assert_memory_equal(sizeof reader, &reader, &saved);
    munit_assert_ptr_equal(rdn.data, multi);
    munit_assert_size(rdn.length, ==, 1);
  }
  limited = bounds;
  for (i = 1; i < 3; ++i) {
    limited.max_depth = i;
    munit_assert_int(TC_X509_name_init(&reader, encoded, &limited), ==, TC_TLV_OK);
    saved = reader;
    munit_assert_int(TC_X509_rdn_next(&reader, &rdn), ==, TC_TLV_LIMIT);
    munit_assert_memory_equal(sizeof reader, &reader, &saved);
  }
  limited = bounds; limited.max_elements = 0;
  saved = reader;
  munit_assert_int(TC_X509_name_init(&reader, encoded, &limited), ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof reader, &reader, &saved);
  limited = bounds; limited.max_depth = 0;
  munit_assert_int(TC_X509_name_init(&reader, encoded, &limited), ==, TC_TLV_LIMIT);
  return MUNIT_OK;
}

static MunitResult invalid(const MunitParameter params[], void* user)
{
  uint8_t bad[sizeof multi];
  TC_bytes encoded = {bad,sizeof bad}, rdn = {NULL,0};
  TC_TLV_reader reader, saved;
  unsigned variant;
  (void)params; (void)user;
  for (variant = 0; variant < 4; ++variant) {
    memcpy(bad, multi, sizeof bad);
    if (variant == 0) { bad[10] = 10; bad[20] = 3; }
    if (variant == 1) bad[13] = 0xc0;
    if (variant == 2) bad[6] = 4;
    if (variant == 3) bad[11] = 4;
    munit_assert_int(TC_X509_name_init(&reader, encoded, &bounds), ==, TC_TLV_OK);
    saved = reader;
    munit_assert_int(TC_X509_rdn_next(&reader, &rdn), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof reader, &reader, &saved);
    munit_assert_null(rdn.data);
  }
  return MUNIT_OK;
}

static MunitResult matching(const MunitParameter params[], void* user)
{
  const uint8_t a[] = {0x30,22,0x31,20,
    0x30,8,6,3,0x55,4,3,0x0c,1,'b',0x30,8,6,3,0x55,4,3,0x13,1,'A'};
  uint8_t b[sizeof a];
  uint32_t first[32], second[32];
  uint8_t used[2];
  TC_X509_name_workspace workspace = {first,second,32,used,2};
  TC_bytes left = {a,sizeof a}, right = {b,sizeof b};
  size_t work = 10000;
  int equal = 99;
  (void)params; (void)user;
  memcpy(b, a, sizeof b); b[13] = 'a'; b[23] = 'B';
  munit_assert_int(TC_X509_name_equal(left, right, &bounds, &workspace, &work, &equal), ==, TC_TLV_OK);
  munit_assert_int(equal, ==, 1);
  work = 10000;
  munit_assert_int(TC_X509_name_equal(right, left, &bounds, &workspace, &work, &equal), ==, TC_TLV_OK);
  munit_assert_int(equal, ==, 1);
  b[13] = 'a'; b[23] = 'A'; work = 10000;
  munit_assert_int(TC_X509_name_equal(right, left, &bounds, &workspace, &work, &equal), ==, TC_TLV_OK);
  munit_assert_int(equal, ==, 0);
  return MUNIT_OK;
}

static MunitResult subtree(const MunitParameter params[], void* user)
{
  const uint8_t parent[] = {0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A'};
  uint8_t child[] = {0x30,24,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'a',
    0x31,10,0x30,8,6,3,0x55,4,10,0x0c,1,'Z'};
  const uint8_t empty[] = {0x30,0};
  uint32_t first[32], second[32];
  uint8_t used[2];
  TC_X509_name_workspace workspace = {first,second,32,used,2};
  TC_bytes name = {child,sizeof child}, base = {parent,sizeof parent}, root = {empty,2};
  size_t work = 10000;
  int equal = 99;
  (void)params; (void)user;
  munit_assert_int(TC_X509_name_within(name, base, &bounds, &workspace, &work, &equal), ==, TC_TLV_OK);
  munit_assert_int(equal, ==, 1);
  work = 10000;
  munit_assert_int(TC_X509_name_equal(name, base, &bounds, &workspace, &work, &equal), ==, TC_TLV_OK);
  munit_assert_int(equal, ==, 0);
  work = 10000;
  munit_assert_int(TC_X509_name_within(base, name, &bounds, &workspace, &work, &equal), ==, TC_TLV_OK);
  munit_assert_int(equal, ==, 0);
  work = 10000;
  munit_assert_int(TC_X509_name_within(name, root, &bounds, &workspace, &work, &equal), ==, TC_TLV_OK);
  munit_assert_int(equal, ==, 1);
  child[13] = 'B'; child[25] = 0xc0; work = 10000; equal = 99;
  munit_assert_int(TC_X509_name_equal(name, base, &bounds, &workspace, &work, &equal), ==, TC_TLV_INVALID);
  munit_assert_int(equal, ==, 99);
  return MUNIT_OK;
}

static MunitResult match_limits(const MunitParameter params[], void* user)
{
  TC_bytes name = {multi,sizeof multi};
  uint32_t first[32], second[32];
  uint8_t used[2];
  TC_X509_name_workspace workspace = {first,second,32,used,2};
  size_t work = 10000, required, i;
  int equal = 99;
  (void)params; (void)user;
  munit_assert_int(TC_X509_name_equal(name, name, &bounds, &workspace, &work, &equal), ==, TC_TLV_OK);
  munit_assert_int(equal, ==, 1);
  required = 10000 - work;
  for (i = 0; i < required; ++i) {
    work = i; equal = 99;
    munit_assert_int(TC_X509_name_equal(name, name, &bounds, &workspace, &work, &equal), ==, TC_TLV_LIMIT);
    munit_assert_int(equal, ==, 99);
  }
  work = 10000; workspace.attribute_capacity = 1;
  munit_assert_int(TC_X509_name_equal(name, name, &bounds, &workspace, &work, &equal), ==, TC_TLV_LIMIT);
  munit_assert_int(equal, ==, 99);
  workspace.attribute_capacity = 2; workspace.scalar_capacity = 2; work = 10000;
  munit_assert_int(TC_X509_name_equal(name, name, &bounds, &workspace, &work, &equal), ==, TC_TLV_LIMIT);
  workspace.scalar_capacity = 32; workspace.right = first; work = 10000;
  munit_assert_int(TC_X509_name_equal(name, name, &bounds, &workspace, &work, &equal), ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, 10000);
  munit_assert_int(equal, ==, 99);
  return MUNIT_OK;
}

static MunitResult matching_rules(const MunitParameter params[], void* user)
{
  uint8_t name[] = {0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x14,1,'A'};
  const uint8_t domain[] = {0x30,19,0x31,17,0x30,15,6,10,
    9,0x92,0x26,0x89,0x93,0xf2,0x2c,100,1,25,0x16,1,'A'};
  uint8_t lower[sizeof domain];
  uint32_t first[32], second[32];
  uint8_t used[2];
  TC_X509_name_workspace workspace = {first,second,32,used,2};
  TC_bytes left = {name,sizeof name}, right = left;
  size_t work = 10000;
  int equal = 99;
  (void)params; (void)user;
  munit_assert_int(TC_X509_name_equal(left, right, &bounds, &workspace, &work, &equal), ==, TC_TLV_UNSUPPORTED);
  munit_assert_int(equal, ==, 99);
  name[11] = 0x0c; name[10] = 99; work = 10000;
  munit_assert_int(TC_X509_name_equal(left, right, &bounds, &workspace, &work, &equal), ==, TC_TLV_UNSUPPORTED);
  memcpy(lower, domain, sizeof lower); lower[20] = 'a';
  left.data = domain; left.length = sizeof domain;
  right.data = lower; right.length = sizeof lower;
  work = 10000;
  munit_assert_int(TC_X509_name_equal(left, right, &bounds, &workspace, &work, &equal), ==, TC_TLV_OK);
  munit_assert_int(equal, ==, 1);
  return MUNIT_OK;
}

static MunitResult unicode_names(const MunitParameter params[], void* user)
{
  const uint8_t utf8[] = {0x30,13,0x31,11,0x30,9,6,3,0x55,4,3,0x0c,2,0xc3,0x85};
  const uint8_t bmp[] = {0x30,13,0x31,11,0x30,9,6,3,0x55,4,3,0x1e,2,0,0xe5};
  const uint8_t decomposed[] = {0x30,14,0x31,12,0x30,10,6,3,0x55,4,3,0x0c,3,'A',0xcc,0x8a};
  uint32_t first[32], second[32];
  uint8_t used[2];
  TC_X509_name_workspace workspace = {first,second,32,used,2};
  TC_bytes left = {utf8,sizeof utf8}, right = {bmp,sizeof bmp};
  size_t work = 10000;
  int equal = 99;
  (void)params; (void)user;
  munit_assert_int(TC_X509_name_equal(left, right, &bounds, &workspace, &work, &equal), ==, TC_TLV_OK);
  munit_assert_int(equal, ==, 1);
  right.data = decomposed; right.length = sizeof decomposed; work = 10000;
  munit_assert_int(TC_X509_name_equal(left, right, &bounds, &workspace, &work, &equal), ==, TC_TLV_OK);
  munit_assert_int(equal, ==, 1);
  return MUNIT_OK;
}

typedef struct { const char *name, *base; TC_TLV_result status; int match; } StringConstraint;

static void string_constraints(unsigned type, const StringConstraint* cases, size_t count)
{
  size_t i;
  for (i = 0; i < count; ++i) {
    TC_X509_general_name name = {0};
    TC_X509_general_subtree base = {0};
    uint8_t encoded[256] = {6,8,0x2b,6,1,5,5,7,8,9,0xa0,0,0x0c,0};
    size_t work = 10000, required, budget;
    int matched = 99;
    name.type = base.base.type = type;
    name.value.data = (const uint8_t*)cases[i].name; name.value.length = strlen(cases[i].name);
    base.base.value.data = (const uint8_t*)cases[i].base; base.base.value.length = strlen(cases[i].base);
    if (!type) {
      munit_assert_size(name.value.length, <=, 125);
      encoded[11] = (uint8_t)(name.value.length + 2); encoded[13] = (uint8_t)name.value.length;
      memcpy(encoded + 14, name.value.data, name.value.length);
      name.value.data = encoded; name.value.length += 14; base.base.type = 1;
    }
    munit_assert_int(TC_X509_general_name_within(&name, &base, &bounds, NULL, &work, &matched), ==, cases[i].status);
    munit_assert_int(matched, ==, cases[i].status == TC_TLV_OK ? cases[i].match : 99);
    if (cases[i].status != TC_TLV_OK) continue;
    required = 10000 - work;
    for (budget = 0; budget < required; ++budget) {
      work = budget; matched = 99;
      munit_assert_int(TC_X509_general_name_within(&name, &base, &bounds, NULL, &work, &matched), ==, TC_TLV_LIMIT);
      munit_assert_int(matched, ==, 99);
    }
  }
}

static MunitResult dns_constraints(const MunitParameter params[], void* user)
{
  static const StringConstraint cases[] = {
    {"example.com", "example.com", TC_TLV_OK, 1},
    {"A.Example.COM", "example.com", TC_TLV_OK, 1},
    {"a.b.example.com", ".example.com", TC_TLV_OK, 1},
    {"example.com", ".example.com", TC_TLV_OK, 0},
    {"badexample.com", "example.com", TC_TLV_OK, 0},
    {"example.com.evil", "example.com", TC_TLV_OK, 0},
    {"com", "example.com", TC_TLV_OK, 0},
    {"", "example.com", TC_TLV_INVALID, 0},
    {"example.com", ".", TC_TLV_INVALID, 0},
    {"a..example.com", "example.com", TC_TLV_INVALID, 0},
    {"-a.example.com", "example.com", TC_TLV_INVALID, 0},
    {"a-.example.com", "example.com", TC_TLV_INVALID, 0},
    {"example.com.", "example.com", TC_TLV_INVALID, 0},
    {"a_b.example.com", "example.com", TC_TLV_INVALID, 0},
    {"*.example.com", "example.com", TC_TLV_UNSUPPORTED, 0},
    {"example.com", "*.com", TC_TLV_UNSUPPORTED, 0}
  };
  (void)params; (void)user;
  string_constraints(2, cases, sizeof cases / sizeof cases[0]);
  return MUNIT_OK;
}

static MunitResult mail_constraints(const MunitParameter params[], void* user)
{
  static const StringConstraint cases[] = {
    {"user@example.com", "EXAMPLE.com", TC_TLV_OK, 1},
    {"User@example.com", "example.com", TC_TLV_OK, 1},
    {"user@a.example.com", "example.com", TC_TLV_OK, 0},
    {"user@a.example.com", ".example.com", TC_TLV_OK, 1},
    {"user@example.com", ".example.com", TC_TLV_OK, 0},
    {"user@badexample.com", ".example.com", TC_TLV_OK, 0},
    {"user@example.com.evil", "example.com", TC_TLV_OK, 0},
    {"a.b+tag@example.com", "example.com", TC_TLV_OK, 1},
    {"!#$%&'*+-/=?^_`{|}~@example.com", "example.com", TC_TLV_OK, 1},
    {"\"a@evil.com\"@example.com", "example.com", TC_TLV_OK, 1},
    {"\"a\\@evil.com\"@example.com", "example.com", TC_TLV_OK, 1},
    {"\"a\\\"@evil.com\"@example.com", "example.com", TC_TLV_OK, 1},
    {"\"a b\"@example.com", "example.com", TC_TLV_OK, 1},
    {"\"\"@example.com", "example.com", TC_TLV_OK, 1},
    {"user@xn--bcher-kva.example", "XN--BCHER-KVA.example", TC_TLV_OK, 1},
    {"user@example.com", "user@example.com", TC_TLV_UNSUPPORTED, 0},
    {"user@[192.0.2.1]", "example.com", TC_TLV_UNSUPPORTED, 0},
    {"user@[IPv6:2001:db8::1]", "example.com", TC_TLV_UNSUPPORTED, 0},
    {"user", "example.com", TC_TLV_INVALID, 0},
    {"@example.com", "example.com", TC_TLV_INVALID, 0},
    {"a@", "example.com", TC_TLV_INVALID, 0},
    {".a@example.com", "example.com", TC_TLV_INVALID, 0},
    {"a.@example.com", "example.com", TC_TLV_INVALID, 0},
    {"a..b@example.com", "example.com", TC_TLV_INVALID, 0},
    {"a b@example.com", "example.com", TC_TLV_INVALID, 0},
    {"a@evil@example.com", "example.com", TC_TLV_INVALID, 0},
    {"\"a\"b@example.com", "example.com", TC_TLV_INVALID, 0},
    {"\"a@example.com", "example.com", TC_TLV_INVALID, 0},
    {"\"a\\", "example.com", TC_TLV_INVALID, 0},
    {"\"a\n\"@example.com", "example.com", TC_TLV_INVALID, 0},
    {"\"a\\\n\"@example.com", "example.com", TC_TLV_INVALID, 0},
    {"\xc3\xa9@example.com", "example.com", TC_TLV_INVALID, 0},
    {"user@b\xc3\xbc" "cher.example", "example", TC_TLV_INVALID, 0},
    {"<user@example.com>", "example.com", TC_TLV_INVALID, 0},
    {"user@example.com (name)", "example.com", TC_TLV_INVALID, 0}
  };
  (void)params; (void)user;
  string_constraints(1, cases, sizeof cases / sizeof cases[0]);
  return MUNIT_OK;
}

static MunitResult uri_constraints(const MunitParameter params[], void* user)
{
  static const StringConstraint cases[] = {
    {"https://EXAMPLE.com", "example.com", TC_TLV_OK, 1},
    {"https://example.com:443/one?two=three#four", "example.com", TC_TLV_OK, 1},
    {"scheme+ext.1-2://user:pass@example.com:/a%20b?x=%2f?#a?b", "example.com", TC_TLV_OK, 1},
    {"https://evil.com@example.com", "example.com", TC_TLV_OK, 1},
    {"https://example.com@evil.com", "example.com", TC_TLV_OK, 0},
    {"https://user%40evil.com@example.com/", "example.com", TC_TLV_OK, 1},
    {"https://@example.com/", "example.com", TC_TLV_OK, 1},
    {"https://a.example.com/", "example.com", TC_TLV_OK, 0},
    {"https://a.example.com/", ".example.com", TC_TLV_OK, 1},
    {"https://example.com/", ".example.com", TC_TLV_OK, 0},
    {"https://badexample.com/", ".example.com", TC_TLV_OK, 0},
    {"https://example.com.evil/", "example.com", TC_TLV_OK, 0},
    {"https://evil.com/example.com", "example.com", TC_TLV_OK, 0},
    {"https://evil.com?host=example.com", "example.com", TC_TLV_OK, 0},
    {"https://evil.com#example.com", "example.com", TC_TLV_OK, 0},
    {"https://192.0.2.1/", "192.0.2.1", TC_TLV_INVALID, 0},
    {"https://[2001:db8::1]/", "example.com", TC_TLV_INVALID, 0},
    {"https://[v1.a]/", "example.com", TC_TLV_INVALID, 0},
    {"mailto:user@example.com", "example.com", TC_TLV_INVALID, 0},
    {"urn:example:thing", "example.com", TC_TLV_INVALID, 0},
    {"//example.com/", "example.com", TC_TLV_INVALID, 0},
    {"https:/example.com/", "example.com", TC_TLV_INVALID, 0},
    {"https:///example.com/", "example.com", TC_TLV_INVALID, 0},
    {"1https://example.com/", "example.com", TC_TLV_INVALID, 0},
    {"https://example.com:abc/", "example.com", TC_TLV_INVALID, 0},
    {"https://example.com:443:80/", "example.com", TC_TLV_INVALID, 0},
    {"https://user@evil@example.com/", "example.com", TC_TLV_INVALID, 0},
    {"https://user%4@example.com/", "example.com", TC_TLV_INVALID, 0},
    {"https://user%GG@example.com/", "example.com", TC_TLV_INVALID, 0},
    {"https://example.com/%", "example.com", TC_TLV_INVALID, 0},
    {"https://example.com/?x=%0", "example.com", TC_TLV_INVALID, 0},
    {"https://example.com/#%gg", "example.com", TC_TLV_INVALID, 0},
    {"https://example.com/#one#two", "example.com", TC_TLV_INVALID, 0},
    {"https://example.com/a b", "example.com", TC_TLV_INVALID, 0},
    {"https://example.com/\\evil", "example.com", TC_TLV_INVALID, 0},
    {"https://example.com/?[x]", "example.com", TC_TLV_INVALID, 0},
    {"https://%65xample.com/", "example.com", TC_TLV_OK, 1},
    {"https://%45xample%2ecom/", "example.com", TC_TLV_OK, 1},
    {"https://a%2eexample.com/", ".example.com", TC_TLV_OK, 1},
    {"https://a%2Eexample.com/", "example.com", TC_TLV_OK, 0},
    {"https://bad%65xample.com/", ".example.com", TC_TLV_OK, 0},
    {"https://example%2ecom.evil/", "example.com", TC_TLV_OK, 0},
    {"https://a%2Db.example.com/", ".example.com", TC_TLV_OK, 1},
    {"https://%2Da.example.com/", ".example.com", TC_TLV_INVALID, 0},
    {"https://a%2D.example.com/", ".example.com", TC_TLV_INVALID, 0},
    {"https://example.com%40evil.com/", "example.com", TC_TLV_INVALID, 0},
    {"https://example.com%2Fevil/", "example.com", TC_TLV_INVALID, 0},
    {"https://example.com%00/", "example.com", TC_TLV_INVALID, 0},
    {"https://example%252ecom/", "example.com", TC_TLV_INVALID, 0},
    {"https://%31%39%32%2e0%2e2%2e1/", "192.0.2.1", TC_TLV_INVALID, 0},
    {"https://example%2/", "example.com", TC_TLV_INVALID, 0},
    {"https://example%gg/", "example.com", TC_TLV_INVALID, 0},
    {"https://example%/", "example.com", TC_TLV_INVALID, 0}
  };
  (void)params; (void)user;
  string_constraints(6, cases, sizeof cases / sizeof cases[0]);
  return MUNIT_OK;
}

static MunitResult uri_host_lengths(const MunitParameter params[], void* user)
{
  static const size_t lengths[] = {63,64,253,254};
  uint8_t uri[800], host[254];
  size_t test, i;
  (void)params; (void)user;
  for (test = 0; test < sizeof lengths / sizeof lengths[0]; ++test) {
    TC_X509_general_name name = {0};
    TC_X509_general_subtree base = {0};
    size_t length = lengths[test], work = 10000;
    int matched = 99, valid = length == 63 || length == 253;
    memcpy(uri, "https://", 8);
    for (i = 0; i < length; ++i) {
      int dot = length > 64 && i % 64 == 63;
      host[i] = dot ? '.' : 'a';
      uri[8 + i * 3] = '%';
      uri[9 + i * 3] = dot ? '2' : '6';
      uri[10 + i * 3] = dot ? 'e' : '1';
    }
    name.type = base.base.type = 6;
    name.value.data = uri; name.value.length = 8 + length * 3;
    base.base.value.data = host; base.base.value.length = length;
    munit_assert_int(TC_X509_general_name_within(&name, &base, &bounds, NULL, &work, &matched), ==,
      valid ? TC_TLV_OK : TC_TLV_INVALID);
    munit_assert_int(matched, ==, valid ? 1 : 99);
  }
  return MUNIT_OK;
}

static MunitResult utf8_mail_constraints(const MunitParameter params[], void* user)
{
  static const StringConstraint cases[] = {
    {"\xc3\xa9@example.com", "example.com", TC_TLV_OK, 1},
    {"\xc3\xa9@example.com", "EXAMPLE.COM", TC_TLV_OK, 1},
    {"e\xcc\x81@example.com", "example.com", TC_TLV_OK, 1},
    {"\xe5\xad\xa6\xe7\x94\x9f@school.example.com", ".example.com", TC_TLV_OK, 1},
    {"\xc3\xa9@example.com", ".example.com", TC_TLV_OK, 0},
    {"\xc3\xa9@a.example.com", "example.com", TC_TLV_OK, 0},
    {"\xc3\xa9@badexample.com", ".example.com", TC_TLV_OK, 0},
    {"\xc3\xa9@xn--bcher-kva.example", "xn--bcher-kva.example", TC_TLV_OK, 1},
    {"\"\xc3\xa9@evil\"@example.com", "example.com", TC_TLV_OK, 1},
    {"\"\xc3\xa9\\@evil\"@example.com", "example.com", TC_TLV_OK, 1},
    {"\"\\\xc3\xa9\"@example.com", "example.com", TC_TLV_INVALID, 0},
    {"user@example.com", "example.com", TC_TLV_INVALID, 0},
    {"\xc3\xa9@EXAMPLE.com", "example.com", TC_TLV_INVALID, 0},
    {"\xc3\xa9@ab--cd.example", "ab--cd.example", TC_TLV_INVALID, 0},
    {"\xc3\xa9@b\xc3\xbc" "cher.example", "example", TC_TLV_INVALID, 0},
    {"\xef\xbb\xbf\xc3\xa9@example.com", "example.com", TC_TLV_INVALID, 0},
    {"\xc3\xa9\xef\xbb\xbf@example.com", "example.com", TC_TLV_INVALID, 0},
    {"\xc0\xaf@example.com", "example.com", TC_TLV_INVALID, 0},
    {"\xed\xa0\x80@example.com", "example.com", TC_TLV_INVALID, 0},
    {"\xf4\x90\x80\x80@example.com", "example.com", TC_TLV_INVALID, 0},
    {"\xc3@example.com", "example.com", TC_TLV_INVALID, 0},
    {".\xc3\xa9@example.com", "example.com", TC_TLV_INVALID, 0},
    {"\xc3\xa9..a@example.com", "example.com", TC_TLV_INVALID, 0},
    {"\xc3\xa9@example.com", "user@example.com", TC_TLV_UNSUPPORTED, 0}
  };
  (void)params; (void)user;
  string_constraints(0, cases, sizeof cases / sizeof cases[0]);
  return MUNIT_OK;
}

static MunitResult utf8_mail_structure(const MunitParameter params[], void* user)
{
  uint8_t encoded[] = {0xa0,28,6,8,0x2b,6,1,5,5,7,8,9,0xa0,16,0x0c,14,
    0xc3,0xa9,'@','e','x','a','m','p','l','e','.','c','o','m'};
  TC_TLV_reader reader;
  TC_TLV_frame frames[4];
  TC_X509_general_name name;
  TC_X509_general_subtree base = {0};
  TC_TLV_limits small = bounds;
  size_t work = 10000, length;
  int matched = 99;
  (void)params; (void)user;
  base.base.type = 1;
  base.base.value.data = (const uint8_t*)"example.com"; base.base.value.length = 11;
  munit_assert_int(TC_TLV_reader_init(&reader, encoded, sizeof encoded, TC_TLV_DER, &bounds), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_general_name_next(&reader, frames, 4, &name), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_general_name_within(&name, &base, &bounds, NULL, &work, &matched), ==, TC_TLV_OK);
  munit_assert_int(matched, ==, 1);
  {
    uint8_t permitted[] = {0x30,13,0x81,11,'e','x','a','m','p','l','e','.','c','o','m'};
    TC_X509_name_constraints constraints = {{permitted,sizeof permitted},{NULL,0}};
    TC_X509_constraint_workspace workspace = {frames,4,NULL};
    work = 10000; matched = 99;
    munit_assert_int(TC_X509_name_constraints_check(&name, &constraints, &bounds, &workspace, &work, &matched), ==, TC_TLV_OK);
    munit_assert_int(matched, ==, 1);
    permitted[4] = 'z'; work = 10000;
    munit_assert_int(TC_X509_name_constraints_check(&name, &constraints, &bounds, &workspace, &work, &matched), ==, TC_TLV_OK);
    munit_assert_int(matched, ==, 0);
    permitted[4] = 'e'; constraints.excluded = constraints.permitted; work = 10000;
    munit_assert_int(TC_X509_name_constraints_check(&name, &constraints, &bounds, &workspace, &work, &matched), ==, TC_TLV_OK);
    munit_assert_int(matched, ==, 0);
  }
  for (length = 0; length < sizeof encoded - 2; ++length) {
    name.value.length = length; work = 10000; matched = 99;
    munit_assert_int(TC_X509_general_name_within(&name, &base, &bounds, NULL, &work, &matched), !=, TC_TLV_OK);
    munit_assert_int(matched, ==, 99);
  }
  name.value.length = sizeof encoded - 2;
  encoded[14] = 0x16; work = 10000;
  munit_assert_int(TC_X509_general_name_within(&name, &base, &bounds, NULL, &work, &matched), ==, TC_TLV_INVALID);
  munit_assert_int(matched, ==, 99);
  encoded[14] = 0x0c; encoded[11] = 8; work = 10000;
  munit_assert_int(TC_X509_general_name_within(&name, &base, &bounds, NULL, &work, &matched), ==, TC_TLV_OK);
  munit_assert_int(matched, ==, 0);
  encoded[11] = 9; small.max_elements = 2; work = 10000; matched = 99;
  munit_assert_int(TC_X509_general_name_within(&name, &base, &small, NULL, &work, &matched), ==, TC_TLV_LIMIT);
  munit_assert_int(matched, ==, 99);
  small = bounds; small.max_depth = 1; work = 10000;
  munit_assert_int(TC_X509_general_name_within(&name, &base, &small, NULL, &work, &matched), ==, TC_TLV_LIMIT);
  munit_assert_int(matched, ==, 99);
  return MUNIT_OK;
}

static MunitResult constraint_lists(const MunitParameter params[], void* user)
{
  uint8_t permit[] = {0x30,13,0x82,11,'e','x','a','m','p','l','e','.','c','o','m',
    0x30,11,0x82,9,'o','t','h','e','r','.','c','o','m'};
  const uint8_t exclude[] = {0x30,17,0x82,15,'b','a','d','.','e','x','a','m','p','l','e','.','c','o','m'};
  static const struct { const char* name; int allowed; } cases[] = {
    {"example.com",1}, {"a.example.com",1}, {"other.com",1},
    {"bad.example.com",0}, {"a.bad.example.com",0}, {"unlisted.com",0}
  };
  TC_TLV_frame frames[4];
  TC_X509_constraint_workspace workspace = {frames,4,NULL};
  TC_X509_name_constraints constraints = {{permit,sizeof permit},{exclude,sizeof exclude}};
  TC_X509_general_name name = {0};
  TC_TLV_limits small = bounds;
  size_t i, work, needed, budget;
  int allowed;
  (void)params; (void)user;
  name.type = 2;
  for (i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
    name.value.data = (const uint8_t*)cases[i].name; name.value.length = strlen(cases[i].name);
    work = 10000; allowed = 99;
    munit_assert_int(TC_X509_name_constraints_check(&name, &constraints, &bounds, &workspace, &work, &allowed), ==, TC_TLV_OK);
    munit_assert_int(allowed, ==, cases[i].allowed);
    needed = 10000 - work;
    for (budget = 0; budget < needed; ++budget) {
      work = budget; allowed = 99;
      munit_assert_int(TC_X509_name_constraints_check(&name, &constraints, &bounds, &workspace, &work, &allowed), ==, TC_TLV_LIMIT);
      munit_assert_int(allowed, ==, 99);
    }
  }
  name.value.data = (const uint8_t*)"example.com"; name.value.length = 11;
  small.max_elements = 6; work = 10000;
  munit_assert_int(TC_X509_name_constraints_check(&name, &constraints, &small, &workspace, &work, &allowed), ==, TC_TLV_OK);
  small.max_elements = 5; work = 10000; allowed = 99;
  munit_assert_int(TC_X509_name_constraints_check(&name, &constraints, &small, &workspace, &work, &allowed), ==, TC_TLV_LIMIT);
  munit_assert_int(allowed, ==, 99);
  workspace.frame_capacity = 0; work = 10000;
  munit_assert_int(TC_X509_name_constraints_check(&name, &constraints, &bounds, &workspace, &work, &allowed), ==, TC_TLV_LIMIT);
  munit_assert_int(allowed, ==, 99);
  workspace.frame_capacity = 4;
  small = bounds; small.max_input = sizeof permit + sizeof exclude - 1; work = 10000;
  munit_assert_int(TC_X509_name_constraints_check(&name, &constraints, &small, &workspace, &work, &allowed), ==, TC_TLV_LIMIT);
  munit_assert_int(allowed, ==, 99);
  /* A matching first entry does not excuse a malformed later subtree. */
  permit[15] = 0x31; work = 10000;
  munit_assert_int(TC_X509_name_constraints_check(&name, &constraints, &bounds, &workspace, &work, &allowed), ==, TC_TLV_INVALID);
  munit_assert_int(allowed, ==, 99);
  permit[15] = 0x30;
  name.type = 1; name.value.data = (const uint8_t*)"user@example.com"; name.value.length = 16; work = 10000;
  munit_assert_int(TC_X509_name_constraints_check(&name, &constraints, &bounds, &workspace, &work, &allowed), ==, TC_TLV_OK);
  munit_assert_int(allowed, ==, 1);
  constraints.permitted.data = NULL; constraints.permitted.length = 0;
  constraints.excluded = constraints.permitted; work = 10000;
  munit_assert_int(TC_X509_name_constraints_check(&name, &constraints, &bounds, &workspace, &work, &allowed), ==, TC_TLV_OK);
  munit_assert_int(allowed, ==, 1);
  return MUNIT_OK;
}

static MunitResult certificate_names(const MunitParameter params[], void* user)
{
  uint8_t san[] = {0x30,37,0x30,35,6,3,0x55,0x1d,17,4,28,0x30,26,
    0x82,11,'e','x','a','m','p','l','e','.','c','o','m',
    0x82,11,'e','x','a','m','p','l','e','.','c','o','m'};
  uint8_t email[] = {0x30,33,0x31,31,0x30,29,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,9,1,
    0x16,16,'u','s','e','r','@','e','x','a','m','p','l','e','.','c','o','m'};
  uint8_t permit[] = {0x30,13,0x82,11,'e','x','a','m','p','l','e','.','c','o','m'};
  const uint8_t empty[] = {0x30,0};
  TC_X509_certificate certificate = {0};
  TC_X509_name_constraints constraints = {{permit,sizeof permit},{NULL,0}};
  TC_TLV_frame frames[4];
  TC_X509_constraint_workspace workspace = {frames,4,NULL};
  size_t work = 10000, needed, budget;
  int allowed = 99;
  (void)params; (void)user;
  certificate.subject.data = multi; certificate.subject.length = sizeof multi;
  certificate.extensions.data = san; certificate.extensions.length = sizeof san;
  munit_assert_int(TC_X509_certificate_names_check(&certificate, &constraints, &bounds, &workspace, &work, &allowed), ==, TC_TLV_OK);
  munit_assert_int(allowed, ==, 1);
  needed = 10000 - work;
  for (budget = 0; budget < needed; ++budget) {
    work = budget; allowed = 99;
    munit_assert_int(TC_X509_certificate_names_check(&certificate, &constraints, &bounds, &workspace, &work, &allowed), ==, TC_TLV_LIMIT);
    munit_assert_int(allowed, ==, 99);
  }
  san[28] = 'z'; work = 10000;
  munit_assert_int(TC_X509_certificate_names_check(&certificate, &constraints, &bounds, &workspace, &work, &allowed), ==, TC_TLV_OK);
  munit_assert_int(allowed, ==, 0);
  san[28] = 'e'; san[26] = 0x80; work = 10000; allowed = 99;
  munit_assert_int(TC_X509_certificate_names_check(&certificate, &constraints, &bounds, &workspace, &work, &allowed), ==, TC_TLV_INVALID);
  munit_assert_int(allowed, ==, 99);
  san[26] = 0x82;
  certificate.subject.data = empty; certificate.subject.length = sizeof empty; work = 10000;
  munit_assert_int(TC_X509_certificate_names_check(&certificate, &constraints, &bounds, &workspace, &work, &allowed), ==, TC_TLV_OK);
  munit_assert_int(allowed, ==, 1);
  certificate.extensions.data = NULL; certificate.extensions.length = 0; work = 10000; allowed = 99;
  munit_assert_int(TC_X509_certificate_names_check(&certificate, &constraints, &bounds, &workspace, &work, &allowed), ==, TC_TLV_INVALID);
  munit_assert_int(allowed, ==, 99);
  certificate.subject.data = email; certificate.subject.length = sizeof email;
  permit[2] = 0x81; work = 10000;
  munit_assert_int(TC_X509_certificate_names_check(&certificate, &constraints, &bounds, &workspace, &work, &allowed), ==, TC_TLV_OK);
  munit_assert_int(allowed, ==, 1);
  email[24] = 'z'; work = 10000;
  munit_assert_int(TC_X509_certificate_names_check(&certificate, &constraints, &bounds, &workspace, &work, &allowed), ==, TC_TLV_OK);
  munit_assert_int(allowed, ==, 0);
  certificate.extensions.data = san; certificate.extensions.length = sizeof san; work = 10000;
  munit_assert_int(TC_X509_certificate_names_check(&certificate, &constraints, &bounds, &workspace, &work, &allowed), ==, TC_TLV_OK);
  munit_assert_int(allowed, ==, 1);
  {
    uint8_t directory[sizeof multi + 4] = {0x30,sizeof multi + 2,0xa4,sizeof multi};
    TC_TLV_frame deep_frames[8];
    uint32_t left[32], right[32];
    uint8_t used[2];
    TC_X509_name_workspace names = {left,right,32,used,2};
    TC_X509_constraint_workspace deep_workspace = {deep_frames,8,&names};
    const TC_TLV_limits deep = {1024,1024,64,8};
    memcpy(directory + 4, multi, sizeof multi);
    constraints.permitted.data = directory; constraints.permitted.length = sizeof directory;
    certificate.subject.data = multi; certificate.subject.length = sizeof multi;
    certificate.extensions.data = NULL; certificate.extensions.length = 0; work = 10000;
    munit_assert_int(TC_X509_certificate_names_check(&certificate, &constraints, &deep, &deep_workspace, &work, &allowed), ==, TC_TLV_OK);
    munit_assert_int(allowed, ==, 1);
    directory[sizeof directory - 1] = 'Y'; work = 10000;
    munit_assert_int(TC_X509_certificate_names_check(&certificate, &constraints, &deep, &deep_workspace, &work, &allowed), ==, TC_TLV_OK);
    munit_assert_int(allowed, ==, 0);
    names.right = names.left; work = 10000; allowed = 99;
    munit_assert_int(TC_X509_certificate_names_check(&certificate, &constraints, &deep, &deep_workspace, &work, &allowed), ==, TC_TLV_ARGUMENT);
    munit_assert_int(allowed, ==, 99);
    munit_assert_size(work, ==, 10000);
  }
  return MUNIT_OK;
}

static MunitResult constraint_arguments(const MunitParameter params[], void* user)
{
  TC_X509_general_name name = {0};
  TC_X509_general_subtree base = {0};
  uint32_t first[32], second[32];
  uint8_t used[2];
  TC_X509_name_workspace workspace = {first,second,32,used,2};
  TC_TLV_limits small = bounds;
  size_t work = 10000;
  int matched = 99;
  (void)params; (void)user;
  name.type = base.base.type = 4;
  name.value.data = base.base.value.data = multi;
  name.value.length = base.base.value.length = sizeof multi;
  munit_assert_int(TC_X509_general_name_within(&name, &base, &bounds, &workspace, &work, &matched), ==, TC_TLV_OK);
  munit_assert_int(matched, ==, 1);
  work = 10000; matched = 99;
  munit_assert_int(TC_X509_general_name_within(&name, &base, &bounds, NULL, &work, &matched), ==, TC_TLV_ARGUMENT);
  munit_assert_int(matched, ==, 99);
  base.minimum = 1; work = 10000;
  munit_assert_int(TC_X509_general_name_within(&name, &base, &bounds, &workspace, &work, &matched), ==, TC_TLV_UNSUPPORTED);
  munit_assert_int(matched, ==, 99);
  base.minimum = 0; base.has_maximum = 1; work = 10000;
  munit_assert_int(TC_X509_general_name_within(&name, &base, &bounds, &workspace, &work, &matched), ==, TC_TLV_UNSUPPORTED);
  munit_assert_int(matched, ==, 99);
  base.has_maximum = 0; small.max_value = sizeof multi - 1; work = 10000;
  munit_assert_int(TC_X509_general_name_within(&name, &base, &small, &workspace, &work, &matched), ==, TC_TLV_LIMIT);
  munit_assert_int(matched, ==, 99);
  name.type = base.base.type = 8; work = 10000;
  munit_assert_int(TC_X509_general_name_within(&name, &base, &bounds, NULL, &work, &matched), ==, TC_TLV_UNSUPPORTED);
  munit_assert_int(matched, ==, 99);
  base.base.type = 2; work = 10000;
  munit_assert_int(TC_X509_general_name_within(&name, &base, &bounds, NULL, &work, &matched), ==, TC_TLV_OK);
  munit_assert_int(matched, ==, 0);
  name.type = 9; work = 10000; matched = 99;
  munit_assert_int(TC_X509_general_name_within(&name, &base, &bounds, NULL, &work, &matched), ==, TC_TLV_ARGUMENT);
  munit_assert_int(matched, ==, 99);
  return MUNIT_OK;
}

static MunitResult ip_constraints(const MunitParameter params[], void* user)
{
  uint8_t address[16], range[32];
  size_t width, prefix, i;
  (void)params; (void)user;
  for (width = 4; width <= 16; width += 12) {
    for (prefix = 0; prefix <= width * 8; ++prefix) {
      TC_X509_general_name name = {0};
      TC_X509_general_subtree base = {0};
      size_t work = 10000;
      int matched = 99;
      memset(address, 0xa5, sizeof address);
      memset(range, 0, sizeof range);
      memcpy(range, address, width);
      for (i = 0; i < prefix; ++i) range[width + i / 8] |= (uint8_t)(128u >> (i % 8));
      name.type = base.base.type = 7;
      name.value.data = address; name.value.length = width;
      base.base.value.data = range; base.base.value.length = width * 2;
      munit_assert_int(TC_X509_general_name_within(&name, &base, &bounds, NULL, &work, &matched), ==, TC_TLV_OK);
      munit_assert_int(matched, ==, 1);
      if (prefix < width * 8) {
        address[prefix / 8] ^= (uint8_t)(128u >> (prefix % 8)); work = 10000;
        munit_assert_int(TC_X509_general_name_within(&name, &base, &bounds, NULL, &work, &matched), ==, TC_TLV_OK);
        munit_assert_int(matched, ==, 1);
      }
      if (prefix) {
        address[0] ^= 128; work = 10000;
        munit_assert_int(TC_X509_general_name_within(&name, &base, &bounds, NULL, &work, &matched), ==, TC_TLV_OK);
        munit_assert_int(matched, ==, 0);
      }
      name.value.length = width == 4 ? 16 : 4; work = 10000;
      munit_assert_int(TC_X509_general_name_within(&name, &base, &bounds, NULL, &work, &matched), ==, TC_TLV_OK);
      munit_assert_int(matched, ==, 0);
      range[width] = 0x7f; work = 10000; matched = 99;
      munit_assert_int(TC_X509_general_name_within(&name, &base, &bounds, NULL, &work, &matched), ==, TC_TLV_INVALID);
      munit_assert_int(matched, ==, 99);
    }
  }
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/attributes", attributes, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/limits", limits, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/invalid", invalid, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/matching", matching, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/subtree", subtree, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/match-limits", match_limits, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/matching-rules", matching_rules, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/unicode-names", unicode_names, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/dns-constraints", dns_constraints, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/mail-constraints", mail_constraints, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/uri-constraints", uri_constraints, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/uri-host-lengths", uri_host_lengths, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/utf8-mail-constraints", utf8_mail_constraints, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/utf8-mail-structure", utf8_mail_structure, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/ip-constraints", ip_constraints, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/constraint-arguments", constraint_arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/constraint-lists", constraint_lists, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/certificate-names", certificate_names, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
  };
  MunitSuite suite = {"/x509/name", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
