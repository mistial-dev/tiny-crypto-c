/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/x509_trust_anchor.h>
#include <tiny_crypto/x509_path.h>
#include "munit.h"
#include <stdio.h>
#include <string.h>

#ifndef TC_TWIC_SYNTHETIC_ROOT
#error "A vendored synthetic trust anchor is required"
#endif

static const TC_TLV_limits limits = {8192, 8192, 128, 16};
static TC_TLV_frame frames[16];
static TC_bytes oids[32];
static TC_X509_workspace workspace = {frames, 16, oids, 32};

static size_t add(uint8_t* out, unsigned tag, const uint8_t* value, size_t length)
{
  munit_assert_size(length, <, 128);
  out[0] = (uint8_t)tag;
  out[1] = (uint8_t)length;
  memcpy(out + 2, value, length);
  return length + 2;
}

static size_t make_info(uint8_t* out, const uint8_t* flags, size_t flag_length, int policy,
                        int cert_path, int explicit_version, int bad_qualifier)
{
  static const uint8_t spki[] = {0x30, 12, 0x30, 5, 6, 3, 0x2a, 3, 4, 3, 3, 0, 1, 2};
  static const uint8_t key_id[] = {4, 1, 1};
  static const uint8_t name[] = {0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 0x0c, 1, 'A'};
  static const uint8_t policy_info[] = {0x30, 5, 6, 3, 0x2a, 3, 4};
  static const uint8_t qualified_policy[] = {0x30, 7, 6, 3, 0x2a, 3, 4, 0x30, 0};
  uint8_t controls[64], controls_tlv[66], info[128], info_tlv[130], choice[132];
  size_t n = 0, m = 0;
  if (explicit_version) {
    static const uint8_t version[] = {2, 1, 1};
    memcpy(info + m, version, sizeof version);
    m += sizeof version;
  }
  memcpy(info + m, spki, sizeof spki);
  m += sizeof spki;
  memcpy(info + m, key_id, sizeof key_id);
  m += sizeof key_id;
  if (cert_path) {
    memcpy(controls + n, name, sizeof name);
    n += sizeof name;
    if (policy)
      n += bad_qualifier ? add(controls + n, 0xa1, qualified_policy, sizeof qualified_policy)
                         : add(controls + n, 0xa1, policy_info, sizeof policy_info);
    if (flags)
      n += add(controls + n, 0x82, flags, flag_length);
    size_t controls_length = add(controls_tlv, 0x30, controls, n);
    memcpy(info + m, controls_tlv, controls_length);
    m += controls_length;
  }
  size_t info_length = add(info_tlv, 0x30, info, m);
  size_t choice_length = add(choice, 0xa2, info_tlv, info_length);
  return add(out, 0x30, choice, choice_length);
}

static MunitResult flags_and_unusable(const MunitParameter params[], void* user)
{
  (void)params;
  (void)user;
  struct {
    uint8_t data[2];
    size_t length;
    unsigned expected;
    int policy;
  } cases[] = {{{0, 0}, 1, 0, 0},
               {{7, 0x80}, 2, TC_X509_PATH_INHIBIT_MAPPING, 0},
               {{6, 0x40}, 2, TC_X509_PATH_REQUIRE_EXPLICIT_POLICY, 1},
               {{5, 0x20}, 2, TC_X509_PATH_INHIBIT_ANY_POLICY, 0},
               {{5, 0xe0},
                2,
                TC_X509_PATH_INHIBIT_MAPPING | TC_X509_PATH_REQUIRE_EXPLICIT_POLICY |
                    TC_X509_PATH_INHIBIT_ANY_POLICY,
                1}};
  for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
    uint8_t encoded[140];
    size_t length = make_info(encoded, cases[i].data, cases[i].length, cases[i].policy, 1, 0, 0);
    TC_TLV_reader reader;
    TC_X509_store_anchor anchor;
    munit_assert_int(TC_X509_trust_anchor_list_init(&reader, encoded, length, &limits, &workspace),
                     ==, TC_TLV_OK);
    munit_assert_int(TC_X509_trust_anchor_next(&reader, &limits, &workspace, &anchor), ==,
                     TC_TLV_OK);
    munit_assert_uint(anchor.policy_flags, ==, cases[i].expected);
    munit_assert_int(anchor.x509_unusable, ==, 0);
    munit_assert_int(TC_X509_trust_anchor_next(&reader, &limits, &workspace, &anchor), ==,
                     TC_TLV_END);
  }
  uint8_t encoded[140];
  size_t length = make_info(encoded, NULL, 0, 0, 0, 0, 0);
  TC_TLV_reader reader;
  TC_X509_store_anchor anchor;
  munit_assert_int(TC_X509_trust_anchor_list_init(&reader, encoded, length, &limits, &workspace),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_trust_anchor_next(&reader, &limits, &workspace, &anchor), ==, TC_TLV_OK);
  munit_assert_int(anchor.x509_unusable, ==, 1);
  munit_assert_null(anchor.trust.name.data);
  return MUNIT_OK;
}

static MunitResult malformed(const MunitParameter params[], void* user)
{
  (void)params;
  (void)user;
  uint8_t encoded[140];
  TC_TLV_reader reader;
  TC_X509_store_anchor anchor, saved;
  static const uint8_t bad_flags[][2] = {{6, 0x80}, {5, 0x21}, {4, 0x20}};
  for (size_t i = 0; i < sizeof bad_flags / sizeof *bad_flags; ++i) {
    size_t length = make_info(encoded, bad_flags[i], 2, 0, 1, 0, 0);
    munit_assert_int(TC_X509_trust_anchor_list_init(&reader, encoded, length, &limits, &workspace),
                     ==, TC_TLV_OK);
    memset(&anchor, 0xa5, sizeof anchor);
    saved = anchor;
    size_t offset = reader.offset;
    munit_assert_int(TC_X509_trust_anchor_next(&reader, &limits, &workspace, &anchor), ==,
                     TC_TLV_INVALID);
    munit_assert_size(reader.offset, ==, offset);
    munit_assert_memory_equal(sizeof anchor, &anchor, &saved);
  }
  size_t length = make_info(encoded, NULL, 0, 0, 0, 1, 0);
  munit_assert_int(TC_X509_trust_anchor_list_init(&reader, encoded, length, &limits, &workspace),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_trust_anchor_next(&reader, &limits, &workspace, &anchor), ==,
                   TC_TLV_INVALID);
  length = make_info(encoded, NULL, 0, 0, 0, 0, 0);
  munit_assert_int(
      TC_X509_trust_anchor_list_init(&reader, encoded, length - 1, &limits, &workspace), !=,
      TC_TLV_OK);
  length = make_info(encoded, NULL, 0, 1, 1, 0, 1);
  munit_assert_int(TC_X509_trust_anchor_list_init(&reader, encoded, length, &limits, &workspace),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_trust_anchor_next(&reader, &limits, &workspace, &anchor), ==,
                   TC_TLV_INVALID);
  return MUNIT_OK;
}

static size_t read_fixture(const char* file, uint8_t* out, size_t capacity)
{
  char path[512];
  munit_assert_int(snprintf(path, sizeof path, "%s/legacy/%s", TC_TWIC_SYNTHETIC_ROOT, file), >, 0);
  FILE* input = fopen(path, "rb");
  munit_assert_not_null(input);
  size_t size = fread(out, 1, capacity, input);
  munit_assert_int(ferror(input), ==, 0);
  munit_assert_int(fgetc(input), ==, EOF);
  munit_assert_int(fclose(input), ==, 0);
  return size;
}

static void grow_length(uint8_t* buffer, const TC_TLV_element* element, size_t extra)
{
  size_t offset = (size_t)(element->encoded.data - buffer);
  uint8_t marker = buffer[offset + 1];
  if (marker < 128) {
    munit_assert_size((size_t)marker + extra, <, 128);
    buffer[offset + 1] = (uint8_t)(marker + extra);
  } else {
    unsigned octets = marker & 0x7fu;
    size_t length = element->value.length + extra;
    munit_assert_uint(octets, >, 0);
    munit_assert_uint(octets, <=, 2);
    if (octets == 1)
      munit_assert_size(length, <, 256);
    else
      munit_assert_size(length, <, 65536);
    for (unsigned i = 0; i < octets; ++i)
      buffer[offset + 2 + i] = (uint8_t)(length >> (8u * (octets - i - 1u)));
  }
}

static MunitResult precedence(const MunitParameter params[], void* user)
{
  (void)params;
  (void)user;
  uint8_t encoded[8192];
  size_t length = read_fixture("trust-anchors.der", encoded, sizeof encoded);
  TC_TLV_element list, choice, info, part, controls = {0};
  TC_TLV_reader fields, reader;
  TC_X509_store_anchor anchor;
  munit_assert_int(TC_TLV_read(encoded, length, TC_TLV_DER, &limits, &list), ==, TC_TLV_OK);
  munit_assert_int(TC_TLV_read(list.value.data, list.value.length, TC_TLV_DER, &limits, &choice),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_TLV_read(choice.value.data, choice.value.length, TC_TLV_DER, &limits, &info),
                   ==, TC_TLV_OK);
  munit_assert_int(
      TC_TLV_reader_init(&fields, info.value.data, info.value.length, TC_TLV_DER, &limits), ==,
      TC_TLV_OK);
  while (TC_TLV_next(&fields, &part) == TC_TLV_OK)
    if (part.header.tag_length == 1 && part.header.tag[0] == 0x30 &&
        part.encoded.data != info.value.data) {
      controls = part;
      break;
    }
  munit_assert_not_null(controls.encoded.data);
  /* RFC 5914 CertPathControls [4] replaces embedded root pathLen=2. */
  const size_t end = (size_t)(controls.encoded.data - encoded) + controls.encoded.length;
  munit_assert_size(length + 3, <=, sizeof encoded);
  memmove(encoded + end + 3, encoded + end, length - end);
  encoded[end] = 0x84;
  encoded[end + 1] = 1;
  encoded[end + 2] = 0;
  grow_length(encoded, &list, 3);
  grow_length(encoded, &choice, 3);
  grow_length(encoded, &info, 3);
  grow_length(encoded, &controls, 3);
  length += 3;
  munit_assert_int(TC_X509_trust_anchor_list_init(&reader, encoded, length, &limits, &workspace),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_trust_anchor_next(&reader, &limits, &workspace, &anchor), ==, TC_TLV_OK);
  munit_assert_int(anchor.has_path_len, ==, 1);
  munit_assert_size(anchor.path_len, ==, 0);
  return MUNIT_OK;
}

static MunitResult choices(const MunitParameter params[], void* user)
{
  (void)params;
  (void)user;
  static uint8_t encoded[8192], root[4096], tbs_choice[4096], list[4096];
  TC_TLV_reader reader;
  TC_X509_store_anchor anchor;
  size_t length = read_fixture("trust-anchors.der", encoded, sizeof encoded);
  munit_assert_int(TC_X509_trust_anchor_list_init(&reader, encoded, length, &limits, &workspace),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_trust_anchor_next(&reader, &limits, &workspace, &anchor), ==, TC_TLV_OK);
  munit_assert_int(anchor.x509_unusable, ==, 0);
  length = read_fixture("trust-anchor-certificate.der", encoded, sizeof encoded);
  munit_assert_int(TC_X509_trust_anchor_list_init(&reader, encoded, length, &limits, &workspace),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_trust_anchor_next(&reader, &limits, &workspace, &anchor), ==, TC_TLV_OK);
  length = read_fixture("root.der", root, sizeof root);
  TC_X509_certificate certificate;
  munit_assert_int(TC_X509_read(root, length, &limits, &workspace, &certificate), ==, TC_TLV_OK);
  /* The TBSCertificate choice is explicitly wrapped. Its DER is borrowed. */
  munit_assert_size(certificate.tbs.length, <, 0x10000);
  size_t t = certificate.tbs.length;
  tbs_choice[0] = 0xa1;
  tbs_choice[1] = 0x82;
  tbs_choice[2] = (uint8_t)(t >> 8);
  tbs_choice[3] = (uint8_t)t;
  memcpy(tbs_choice + 4, certificate.tbs.data, t);
  size_t choice_length = t + 4;
  list[0] = 0x30;
  list[1] = 0x82;
  list[2] = (uint8_t)(choice_length >> 8);
  list[3] = (uint8_t)choice_length;
  memcpy(list + 4, tbs_choice, choice_length);
  munit_assert_int(
      TC_X509_trust_anchor_list_init(&reader, list, choice_length + 4, &limits, &workspace), ==,
      TC_TLV_OK);
  munit_assert_int(TC_X509_trust_anchor_next(&reader, &limits, &workspace, &anchor), ==, TC_TLV_OK);
  munit_assert_int(anchor.x509_unusable, ==, 0);
  return MUNIT_OK;
}

/* Read a TrustAnchorInfo whose exts [1] holds the given Extension list
 * contents. */
static TC_TLV_result read_with_exts(const uint8_t* list, size_t list_length)
{
  static const uint8_t spki[] = {0x30, 12, 0x30, 5, 6, 3, 0x2a, 3, 4, 3, 3, 0, 1, 2};
  static const uint8_t key_id[] = {4, 1, 1};
  static const uint8_t name[] = {0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 0x0c, 1, 'A'};
  uint8_t extensions[64], exts[66], info[128], info_tlv[130], choice[132], encoded[134];
  size_t n = 0;
  TC_TLV_reader reader;
  TC_X509_store_anchor anchor;
  munit_assert_size(list_length, <=, 60);
  size_t extensions_length = add(extensions, 0x30, list, list_length);
  size_t exts_length = add(exts, 0xa1, extensions, extensions_length);
  memcpy(info + n, spki, sizeof spki);
  n += sizeof spki;
  memcpy(info + n, key_id, sizeof key_id);
  n += sizeof key_id;
  n += add(info + n, 0x30, name, sizeof name); /* CertPathControls with taName only */
  memcpy(info + n, exts, exts_length);
  n += exts_length;
  size_t info_length = add(info_tlv, 0x30, info, n);
  size_t choice_length = add(choice, 0xa2, info_tlv, info_length);
  size_t length = add(encoded, 0x30, choice, choice_length);
  munit_assert_int(TC_X509_trust_anchor_list_init(&reader, encoded, length, &limits, &workspace),
                   ==, TC_TLV_OK);
  return TC_X509_trust_anchor_next(&reader, &limits, &workspace, &anchor);
}

/* RFC 5914 section 2.6 forbids these extensions in TrustAnchorInfo exts. */
static MunitResult forbidden_exts(const MunitParameter params[], void* user)
{
  static const unsigned ids[] = {30, 32, 36, 54, 19};
  (void)params;
  (void)user;
  for (size_t i = 0; i < sizeof ids / sizeof *ids; ++i) {
    /* basicConstraints (19) is permitted and parses; the others are not. */
    uint8_t extension[] = {0x30, 9, 6, 3, 0x55, 0x1d, (uint8_t)ids[i], 4, 2, 0x30, 0};
    munit_assert_int(read_with_exts(extension, sizeof extension), ==,
                     (ids[i] == 19 ? TC_TLV_OK : TC_TLV_INVALID));
  }
  return MUNIT_OK;
}

/* RFC 5280 section 4.2: an extension OID appears at most once. */
static MunitResult duplicate_exts(const MunitParameter params[], void* user)
{
  static const uint8_t basic[] = {0x30, 9, 6, 3, 0x55, 0x1d, 19, 4, 2, 0x30, 0};
  static const uint8_t other[] = {0x30, 9, 6, 3, 0x2a, 3, 5, 4, 2, 5, 0};
  uint8_t list[3 * sizeof basic];
  (void)params;
  (void)user;
  memcpy(list, basic, sizeof basic);
  memcpy(list + sizeof basic, other, sizeof other);
  munit_assert_int(read_with_exts(list, 2 * sizeof basic), ==, TC_TLV_OK);
  memcpy(list + 2 * sizeof basic, basic, sizeof basic);
  munit_assert_int(read_with_exts(list, sizeof list), ==, TC_TLV_INVALID);
  memcpy(list + 2 * sizeof basic, other, sizeof other);
  munit_assert_int(read_with_exts(list + sizeof basic, 2 * sizeof other), ==, TC_TLV_INVALID);
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/forbidden-exts", forbidden_exts, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/duplicate-exts", duplicate_exts, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/flags-and-unusable", flags_and_unusable, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/malformed", malformed, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/choices", choices, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/precedence", precedence, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, 0, NULL}};
static const MunitSuite suite = {"/x509-trust-anchor", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
