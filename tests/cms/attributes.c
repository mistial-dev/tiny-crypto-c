/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/cms.h>
#include "munit.h"
#include <string.h>

static const TC_CMS_verification_policy cms_policy = {.envelope = TC_CMS_ENVELOPE_BER};
static const TC_CMS_verification_policy cms_ber_order_policy = {
    .attributes = TC_CMS_ATTRIBUTES_BER_DEFINITE_ORDER};
/* Indexed by TC_CMS_attribute_encoding, with every PIV and TWIC identifier. */
static const TC_CMS_verification_policy cms_attribute_policies[] = {
    {.attributes = TC_CMS_ATTRIBUTES_DER, .attribute_oids = TC_CMS_ATTRIBUTE_OIDS_PIV_TWIC},
    {.attributes = TC_CMS_ATTRIBUTES_BER_DEFINITE_ORDER,
     .attribute_oids = TC_CMS_ATTRIBUTE_OIDS_PIV_TWIC}};

static const uint8_t encoded[] = {
    0xa0, 0x2c, 0x30, 0x10, 0x06, 9,    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1,    9,    4, 0x31,
    3,    4,    1,    0xaa, 0x30, 0x18, 0x06, 9,    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9,
    3,    0x31, 0x0b, 0x06, 9,    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1,    7,    1};

static MunitResult attributes(const MunitParameter params[], void* user)
{
  TC_TLV_limits limits = {1024, 1024, 32, 8};
  TC_TLV_frame frames[8];
  TC_CMS_signed_attributes result, saved;
  TC_bytes input = {encoded, sizeof encoded};
  size_t work = 1000, required;
  uint8_t bad[64];
  static const size_t positions[] = {0, 1, 2, 17, 35};
  static const uint8_t values[] = {0x31, 0x80, 0x31, 5, 4};
  (void)params;
  (void)user;
  munit_assert_int(TC_CMS_signed_attributes_read(input, &cms_policy, &limits,
                                                 (TC_TLV_frames){frames, 8}, &work, &result),
                   ==, TC_TLV_OK);
  required = 1000 - work;
  munit_assert_ptr_equal(result.content_type.data, encoded + 37);
  munit_assert_size(result.content_type.length, ==, 9);
  munit_assert_ptr_equal(result.message_digest.data, encoded + 19);
  munit_assert_size(result.message_digest.length, ==, 1);
  munit_assert_uint(result.signature_input[0].data[0], ==, 0x31);
  munit_assert_size(result.signature_input[0].length, ==, 1);
  munit_assert_ptr_equal(result.signature_input[1].data, encoded + 1);
  munit_assert_size(result.signature_input[1].length, ==, sizeof encoded - 1);
  munit_assert_uint(encoded[0], ==, 0xa0);
  memset(&result, 0xa5, sizeof result);
  memcpy(&saved, &result, sizeof saved);
  for (size_t budget = 0; budget < required; ++budget) {
    work = budget;
    munit_assert_int(TC_CMS_signed_attributes_read(input, &cms_policy, &limits,
                                                   (TC_TLV_frames){frames, 8}, &work, &result),
                     ==, TC_TLV_LIMIT);
    munit_assert_memory_equal(sizeof result, &result, &saved);
  }
  for (size_t i = 0; i < sizeof positions / sizeof *positions; ++i) {
    memcpy(bad, encoded, sizeof encoded);
    bad[positions[i]] = values[i];
    work = 1000;
    input = (TC_bytes){bad, sizeof encoded};
    munit_assert_int(TC_CMS_signed_attributes_read(input, &cms_policy, &limits,
                                                   (TC_TLV_frames){frames, 8}, &work, &result),
                     !=, TC_TLV_OK);
    munit_assert_memory_equal(sizeof result, &result, &saved);
  }
  /* Reverse the SET OF members without changing either attribute. */
  memcpy(bad, encoded, 2);
  memcpy(bad + 2, encoded + 20, 26);
  memcpy(bad + 28, encoded + 2, 18);
  work = 1000;
  munit_assert_int(TC_CMS_signed_attributes_read(input, &cms_policy, &limits,
                                                 (TC_TLV_frames){frames, 8}, &work, &result),
                   ==, TC_TLV_INVALID);
  memcpy(bad, encoded, 20);
  memcpy(bad + 20, encoded + 2, 18);
  memcpy(bad + 38, encoded + 20, 26);
  bad[1] = 62;
  input.length = 64;
  work = 1000;
  munit_assert_int(TC_CMS_signed_attributes_read(input, &cms_policy, &limits,
                                                 (TC_TLV_frames){frames, 8}, &work, &result),
                   ==, TC_TLV_INVALID);
  memcpy(bad, encoded, 20);
  bad[1] = 18;
  input.length = 20;
  work = 1000;
  munit_assert_int(TC_CMS_signed_attributes_read(input, &cms_policy, &limits,
                                                 (TC_TLV_frames){frames, 8}, &work, &result),
                   ==, TC_TLV_INVALID);
  memcpy(bad, encoded, sizeof encoded);
  bad[14] = 6;
  input.length = sizeof encoded;
  work = 1000;
  munit_assert_int(TC_CMS_signed_attributes_read(input, &cms_policy, &limits,
                                                 (TC_TLV_frames){frames, 8}, &work, &result),
                   ==, TC_TLV_UNSUPPORTED);
  munit_assert_memory_equal(sizeof result, &result, &saved);
  input = (TC_bytes){encoded, sizeof encoded};
  work = 1000;
  munit_assert_int(TC_CMS_signed_attributes_read(input, &cms_policy, &limits,
                                                 (TC_TLV_frames){frames, 0}, &work, &result),
                   ==, TC_TLV_LIMIT);
  limits.max_elements = 8;
  work = 1000;
  munit_assert_int(TC_CMS_signed_attributes_read(input, &cms_policy, &limits,
                                                 (TC_TLV_frames){frames, 8}, &work, &result),
                   ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof result, &result, &saved);
  return MUNIT_OK;
}

static MunitResult compatibility(const MunitParameter params[], void* user)
{
  const TC_TLV_limits limits = {1024, 1024, 64, 8};
  TC_TLV_frame frames[8];
  TC_CMS_signed_attributes result, saved;
  uint8_t input[96];
  size_t work;
  (void)params;
  (void)user;
  /* Preserve reversed members and a nonminimal outer length in signature input. */
  input[0] = 0xa0;
  input[1] = 0x81;
  input[2] = 44;
  memcpy(input + 3, encoded + 20, 26);
  memcpy(input + 29, encoded + 2, 18);
  work = 1000;
  munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input, 47}, &cms_ber_order_policy,
                                                 &limits, (TC_TLV_frames){frames, 8}, &work,
                                                 &result),
                   ==, TC_TLV_OK);
  munit_assert_ptr_equal(result.signature_input[1].data, input + 1);
  munit_assert_size(result.signature_input[1].length, ==, 46);
  munit_assert_uint(result.signature_input[1].data[0], ==, 0x81);
  memset(&result, 0xa5, sizeof result);
  memcpy(&saved, &result, sizeof saved);
  work = 1000;
  munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input, 47}, &cms_policy, &limits,
                                                 (TC_TLV_frames){frames, 8}, &work, &result),
                   !=, TC_TLV_OK);
  munit_assert_memory_equal(sizeof result, &result, &saved);
  for (unsigned kind = 0; kind < 5; ++kind) {
    size_t length = sizeof encoded;
    memcpy(input, encoded, length);
    if (kind == 0) { /* Duplicate messageDigest. */
      memcpy(input + length, encoded + 2, 18);
      length += 18;
      input[1] += 18;
    } else if (kind == 1) { /* Missing contentType. */
      length = 20;
      input[1] = 18;
    } else if (kind == 2) { /* Indefinite attribute sequence inside a definite set. */
      memmove(input + 22, input + 20, 26);
      input[3] = 0x80;
      input[20] = 0;
      input[21] = 0;
      length += 2;
      input[1] += 2;
    } else if (kind == 3) { /* Malformed OID contents. */
      input[14] = 0x80;
    } else { /* Constructed messageDigest is outside this compatibility mode. */
      input[17] = 0x24;
    }
    work = 1000;
    munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input, length}, &cms_ber_order_policy,
                                                   &limits, (TC_TLV_frames){frames, 8}, &work,
                                                   &result),
                     !=, TC_TLV_OK);
    munit_assert_memory_equal(sizeof result, &result, &saved);
  }
  work = 1000;
  munit_assert_int(TC_CMS_signed_attributes_read(
                       (TC_bytes){encoded, sizeof encoded},
                       &(TC_CMS_verification_policy){.attributes = (TC_CMS_attribute_encoding)99},
                       &limits, (TC_TLV_frames){frames, 8}, &work, &result),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, 1000);
  munit_assert_memory_equal(sizeof result, &result, &saved);
  return MUNIT_OK;
}

static MunitResult signing_time(const MunitParameter params[], void* user)
{
  static const struct {
    unsigned tag;
    const char* text;
    unsigned year;
  } cases[] = {{0x17, "491231235959Z", 2049},   {0x17, "500101000000Z", 1950},
               {0x17, "240229000000Z", 2024},   {0x17, "230229000000Z", 0},
               {0x17, "241301000000Z", 0},      {0x17, "240101000000z", 0},
               {0x17, "2401010000Z", 0},        {0x18, "20500101000000Z", 2050},
               {0x18, "19490101000000Z", 1949}, {0x18, "20260101000000Z", 0},
               {0x18, "20500101000000.0Z", 0},  {0x18, "00000101000000Z", 0}};
  const TC_TLV_limits limits = {512, 512, 64, 8};
  TC_TLV_frame frames[8];
  uint8_t input[128];
  TC_CMS_signed_attributes result, saved;
  (void)params;
  (void)user;
  for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
    size_t length = strlen(cases[i].text), work = 1000;
    uint8_t* attribute = input + sizeof encoded;
    memcpy(input, encoded, sizeof encoded);
    attribute[0] = 0x30;
    attribute[1] = (uint8_t)(length + 15);
    memcpy(attribute + 2, encoded + 22, 11);
    attribute[12] = 5;
    attribute[13] = 0x31;
    attribute[14] = (uint8_t)(length + 2);
    attribute[15] = (uint8_t)cases[i].tag;
    attribute[16] = (uint8_t)length;
    memcpy(attribute + 17, cases[i].text, length);
    input[1] = (uint8_t)(sizeof encoded - 2 + length + 17);
    memset(&result, 0xa5, sizeof result);
    memcpy(&saved, &result, sizeof saved);
    munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input, sizeof encoded + length + 17},
                                                   &cms_policy, &limits, (TC_TLV_frames){frames, 8},
                                                   &work, &result),
                     ==, cases[i].year ? TC_TLV_OK : TC_TLV_INVALID);
    if (cases[i].year) {
      munit_assert_true(result.has_signing_time);
      munit_assert_uint(result.signing_time.year, ==, cases[i].year);
      memcpy(attribute + length + 17, attribute, length + 17);
      input[1] += (uint8_t)(length + 17);
      work = 1000;
      memcpy(&result, &saved, sizeof result);
      munit_assert_int(TC_CMS_signed_attributes_read(
                           (TC_bytes){input, sizeof encoded + 2 * (length + 17)}, &cms_policy,
                           &limits, (TC_TLV_frames){frames, 8}, &work, &result),
                       ==, TC_TLV_INVALID);
      munit_assert_memory_equal(sizeof result, &result, &saved);
    } else
      munit_assert_memory_equal(sizeof result, &result, &saved);
  }
  return MUNIT_OK;
}

enum { ATTRIBUTE_BUFFER_BYTES = 256, ATTRIBUTE_BYTES = 96, MAX_EXTRA_ATTRIBUTES = 4 };

/* Encode one Attribute with one value, or two copies of it. */
static size_t make_attribute(uint8_t out[ATTRIBUTE_BYTES], TC_bytes oid, const uint8_t* value,
                             size_t length, int multiple_values)
{
  size_t value_bytes = length * (multiple_values ? 2u : 1u);
  const size_t header = 6 + oid.length;
  munit_assert_size(header + value_bytes, <=, ATTRIBUTE_BYTES);
  out[0] = 0x30;
  out[1] = (uint8_t)(header - 2 + value_bytes);
  out[2] = 6;
  out[3] = (uint8_t)oid.length;
  memcpy(out + 4, oid.data, oid.length);
  out[header - 2] = 0x31;
  out[header - 1] = (uint8_t)value_bytes;
  memcpy(out + header, value, length);
  if (multiple_values)
    memcpy(out + header + length, value, length);
  return header + value_bytes;
}

/* Encode [0] signedAttrs holding contentType, messageDigest and extra, in DER
 * SET OF order. */
static size_t attribute_set(uint8_t out[ATTRIBUTE_BUFFER_BYTES], const TC_bytes* extra,
                            size_t extra_count)
{
  TC_bytes members[2 + MAX_EXTRA_ATTRIBUTES] = {{encoded + 2, 18}, {encoded + 20, 26}};
  size_t count = 2, total = 2;
  munit_assert_size(extra_count, <=, MAX_EXTRA_ATTRIBUTES);
  for (size_t i = 0; i < extra_count; ++i)
    members[count++] = extra[i];
  for (size_t i = 1; i < count; ++i) {
    for (size_t j = i; j; --j) {
      size_t common =
          members[j].length < members[j - 1].length ? members[j].length : members[j - 1].length;
      if (memcmp(members[j].data, members[j - 1].data, common) >= 0)
        break;
      TC_bytes temporary = members[j];
      members[j] = members[j - 1];
      members[j - 1] = temporary;
    }
  }
  out[0] = 0xa0;
  for (size_t i = 0; i < count; ++i) {
    munit_assert_size(members[i].length, <, ATTRIBUTE_BUFFER_BYTES - total);
    memcpy(out + total, members[i].data, members[i].length);
    total += members[i].length;
  }
  munit_assert_size(total - 2, <=, 255);
  if (total - 2 >= 128) {
    memmove(out + 3, out + 2, total - 2);
    out[1] = 0x81;
    out[2] = (uint8_t)(total - 2);
    ++total;
  } else
    out[1] = (uint8_t)(total - 2);
  return total;
}

static size_t with_attribute(uint8_t out[ATTRIBUTE_BUFFER_BYTES], TC_bytes oid,
                             const uint8_t* value, size_t length, int duplicate,
                             int multiple_values)
{
  uint8_t attribute[ATTRIBUTE_BYTES];
  const TC_bytes member = {attribute,
                           make_attribute(attribute, oid, value, length, multiple_values)};
  const TC_bytes extra[] = {member, member};
  return attribute_set(out, extra, duplicate ? 2 : 1);
}

static MunitResult capabilities(const MunitParameter params[], void* user)
{
  static const uint8_t capability_oid[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 15};
  const TC_bytes oid = {capability_oid, sizeof capability_oid};
  static const struct {
    uint8_t bytes[16];
    size_t length;
    int valid;
  } cases[] = {{{0x30, 0}, 2, 1},
               {{0x30, 6, 0x30, 4, 6, 2, 0x2a, 3}, 8, 1},
               {{0x30, 8, 0x30, 6, 6, 2, 0x2a, 3, 5, 0}, 10, 1},
               {{0x30, 10, 0x30, 8, 6, 2, 0x2a, 3, 5, 0, 5, 0}, 12, 0},
               {{0x30, 6, 0x30, 4, 6, 2, 0x2a, 0x80}, 8, 0},
               {{0x30, 6, 0x31, 4, 6, 2, 0x2a, 3}, 8, 0},
               {{0x31, 0}, 2, 0},
               {{0x30, 2, 0x30, 0}, 4, 0},
               {{0x30, 3, 6, 1, 0x2a}, 5, 0},
               {{0x30, 0x80, 0, 0}, 4, 0}};
  const TC_TLV_limits limits = {512, 512, 64, 8};
  TC_TLV_frame frames[8];
  uint8_t input[ATTRIBUTE_BUFFER_BYTES];
  TC_CMS_signed_attributes result, saved;
  (void)params;
  (void)user;
  memset(&saved, 0xa5, sizeof saved);
  for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
    for (unsigned mode = 0; mode < 2; ++mode) {
      size_t length = with_attribute(input, oid, cases[i].bytes, cases[i].length, 0, 0);
      size_t work = 2000;
      memcpy(&result, &saved, sizeof result);
      munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input, length},
                                                     &cms_attribute_policies[mode], &limits,
                                                     (TC_TLV_frames){frames, 8}, &work, &result),
                       ==, cases[i].valid ? TC_TLV_OK : TC_TLV_INVALID);
      if (!cases[i].valid) {
        munit_assert_memory_equal(sizeof result, &result, &saved);
        continue;
      }
      munit_assert_size(result.smime_capabilities.length, ==, cases[i].length);
      munit_assert_memory_equal(cases[i].length, result.smime_capabilities.data, cases[i].bytes);
      munit_assert_true(result.smime_capabilities.data >= input);
      munit_assert_true(result.smime_capabilities.data + cases[i].length <= input + length);
      size_t required = 2000 - work;
      for (size_t budget = 0; budget < required; ++budget) {
        work = budget;
        memcpy(&result, &saved, sizeof result);
        munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input, length},
                                                       &cms_attribute_policies[mode], &limits,
                                                       (TC_TLV_frames){frames, 8}, &work, &result),
                         ==, TC_TLV_LIMIT);
        munit_assert_memory_equal(sizeof result, &result, &saved);
      }
      for (unsigned duplicate = 0; duplicate < 2; ++duplicate) {
        length = with_attribute(input, oid, cases[i].bytes, cases[i].length, duplicate, !duplicate);
        work = 2000;
        munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input, length},
                                                       &cms_attribute_policies[mode], &limits,
                                                       (TC_TLV_frames){frames, 8}, &work, &result),
                         ==, TC_TLV_INVALID);
        munit_assert_memory_equal(sizeof result, &result, &saved);
      }
    }
  }
  return MUNIT_OK;
}

static MunitResult signer_name(const MunitParameter params[], void* user)
{
  static const uint8_t name_oid[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 6, 5};
  static const uint8_t name[] = {0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 0x0c, 1, 'A'};
  const TC_bytes oid = {name_oid, sizeof name_oid};
  const TC_TLV_limits limits = {512, 512, 64, 8};
  TC_TLV_frame frames[8];
  uint8_t input[ATTRIBUTE_BUFFER_BYTES], bad_name[sizeof name];
  TC_CMS_signed_attributes result, saved;
  (void)params;
  (void)user;
  memset(&saved, 0xa5, sizeof saved);
  for (unsigned mode = 0; mode < 2; ++mode) {
    size_t length = with_attribute(input, oid, name, sizeof name, 0, 0), work = 2000;
    munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input, length},
                                                   &cms_attribute_policies[mode], &limits,
                                                   (TC_TLV_frames){frames, 8}, &work, &result),
                     ==, TC_TLV_OK);
    munit_assert_size(result.signer_name.length, ==, sizeof name);
    munit_assert_memory_equal(sizeof name, result.signer_name.data, name);
    munit_assert_true(result.signer_name.data >= input &&
                      result.signer_name.data + sizeof name <= input + length);
    size_t required = 2000 - work;
    for (size_t budget = 0; budget < required; ++budget) {
      work = budget;
      memcpy(&result, &saved, sizeof result);
      munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input, length},
                                                     &cms_attribute_policies[mode], &limits,
                                                     (TC_TLV_frames){frames, 8}, &work, &result),
                       ==, TC_TLV_LIMIT);
      munit_assert_memory_equal(sizeof result, &result, &saved);
    }
    for (unsigned variant = 0; variant < 5; ++variant) {
      memcpy(bad_name, name, sizeof name);
      if (variant == 2)
        bad_name[2] = 0x30; /* RDN requires SET OF. */
      if (variant == 3)
        bad_name[10] = 0x80; /* Unfinished OID arc. */
      if (variant == 4)
        bad_name[13] = 0xff; /* Invalid UTF-8. */
      length = with_attribute(input, oid, bad_name, sizeof bad_name, variant == 0, variant == 1);
      work = 2000;
      memcpy(&result, &saved, sizeof result);
      munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input, length},
                                                     &cms_attribute_policies[mode], &limits,
                                                     (TC_TLV_frames){frames, 8}, &work, &result),
                       ==, TC_TLV_INVALID);
      munit_assert_memory_equal(sizeof result, &result, &saved);
    }
  }
  return MUNIT_OK;
}

static MunitResult identifier_octets(const MunitParameter params[], void* user)
{
  enum { FASCN_BYTES = 25, WORK = 4000 };
  static const uint8_t piv[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 6, 6};
  static const uint8_t twic[] = {0x2b, 6, 1, 4, 1, 0x81, 0xe3, 0x52, 6, 6};
  static const uint8_t uuid[] = {0x2b, 6, 1, 1, 0x10, 4};
  const TC_bytes oids[] = {{piv, sizeof piv}, {twic, sizeof twic}, {uuid, sizeof uuid}};
  const TC_TLV_limits limits = {512, 512, 64, 8};
  TC_TLV_frame frames[8];
  uint8_t input[ATTRIBUTE_BUFFER_BYTES], value[32] = {4, FASCN_BYTES};
  TC_CMS_signed_attributes parsed, saved;
  memset(&saved, 0xa5, sizeof saved);
  for (unsigned ns = 0; ns < sizeof oids / sizeof *oids; ++ns) {
    const uint8_t bytes = ns == 2 ? 16 : FASCN_BYTES;
    for (unsigned mode = 0; mode < 2; ++mode) {
      enum {
        VALID,
        DUPLICATE,
        MULTIPLE_VALUES,
        SHORT,
        LONG,
        WRONG_TAG,
        FRAGMENTED,
        INDEFINITE,
        CASE_COUNT
      };
      for (unsigned kind = 0; kind < CASE_COUNT; ++kind) {
        memset(value, 0, sizeof value);
        value[0] = 4;
        value[1] = bytes;
        size_t value_length = bytes + 2;
        if (kind == SHORT) {
          --value[1];
          --value_length;
        }
        if (kind == LONG) {
          ++value[1];
          ++value_length;
        }
        if (kind == WRONG_TAG)
          value[0] = 0x0c;
        if (kind == FRAGMENTED) {
          value[0] = 0x24;
          value[1] = bytes + 4;
          value[2] = 4;
          value[3] = 1;
          value[5] = 4;
          value[6] = bytes - 1;
          value_length = bytes + 6;
        }
        if (kind == INDEFINITE) {
          value[0] = 0x24;
          value[1] = 0x80;
          value[2] = 4;
          value[3] = bytes;
          value_length = bytes + 6;
        }
        size_t length = with_attribute(input, oids[ns], value, value_length, kind == DUPLICATE,
                                       kind == MULTIPLE_VALUES),
               work = WORK;
        const int valid =
            kind == VALID || (kind == FRAGMENTED && mode == TC_CMS_ATTRIBUTES_BER_DEFINITE_ORDER);
        memcpy(&parsed, &saved, sizeof parsed);
        munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input, length},
                                                       &cms_attribute_policies[mode], &limits,
                                                       (TC_TLV_frames){frames, 8}, &work, &parsed),
                         ==, valid ? TC_TLV_OK : TC_TLV_INVALID);
        if (!valid) {
          munit_assert_memory_equal(sizeof parsed, &parsed, &saved);
          continue;
        }
        const TC_bytes found = ns == 2 ? parsed.entry_uuid_octets : parsed.fascn_octets;
        if (ns < 2)
          munit_assert_memory_equal(oids[ns].length, parsed.fascn_oid.data, oids[ns].data);
        munit_assert_size(found.length, ==, value_length);
        munit_assert_memory_equal(value_length, found.data, value);
        munit_assert_true(found.data >= input && found.data + value_length <= input + length);
        const size_t required = WORK - work;
        for (size_t budget = 0; budget < required; ++budget) {
          work = budget;
          memcpy(&parsed, &saved, sizeof parsed);
          munit_assert_int(TC_CMS_signed_attributes_read(
                               (TC_bytes){input, length}, &cms_attribute_policies[mode], &limits,
                               (TC_TLV_frames){frames, 8}, &work, &parsed),
                           ==, TC_TLV_LIMIT);
          munit_assert_memory_equal(sizeof parsed, &parsed, &saved);
        }
      }
      if (ns == 1) {
        /* Replace the first TWIC OID in a duplicate pair with its PIV equivalent. */
        memset(value, 0, sizeof value);
        value[0] = 4;
        value[1] = FASCN_BYTES;
        size_t length = with_attribute(input, oids[ns], value, FASCN_BYTES + 2, 1, 0);
        const size_t attribute = 3 + sizeof encoded - 2;
        const size_t oid_value = attribute + 4, removed = sizeof twic - sizeof piv;
        munit_assert_uint8(input[1], ==, 0x81);
        memcpy(input + oid_value, piv, sizeof piv);
        memmove(input + oid_value + sizeof piv, input + oid_value + sizeof twic,
                length - oid_value - sizeof twic);
        input[attribute + 1] -= (uint8_t)removed;
        input[attribute + 3] = sizeof piv;
        input[2] -= (uint8_t)removed;
        length -= removed;
        size_t work = WORK;
        memcpy(&parsed, &saved, sizeof parsed);
        munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input, length},
                                                       &cms_attribute_policies[mode], &limits,
                                                       (TC_TLV_frames){frames, 8}, &work, &parsed),
                         ==, TC_TLV_INVALID);
        munit_assert_memory_equal(sizeof parsed, &parsed, &saved);
      }
    }
  }
  (void)params;
  (void)user;
  return MUNIT_OK;
}

/* Read input under policy and check the documented result. Failures leave out
 * unchanged. Successful reads fail with LIMIT, out unchanged, at every shorter
 * work budget. */
static TC_TLV_result read_checked(TC_bytes input, const TC_CMS_verification_policy* policy,
                                  TC_TLV_result expected, TC_CMS_signed_attributes* out)
{
  enum { WORK = 4000 };
  const TC_TLV_limits limits = {512, 512, 64, 8};
  TC_TLV_frame frames[8];
  TC_CMS_signed_attributes saved;
  size_t work = WORK;
  memset(out, 0xa5, sizeof *out);
  memcpy(&saved, out, sizeof saved);
  munit_assert_int(
      TC_CMS_signed_attributes_read(input, policy, &limits, (TC_TLV_frames){frames, 8}, &work, out),
      ==, expected);
  if (expected != TC_TLV_OK) {
    munit_assert_memory_equal(sizeof saved, out, &saved);
    return expected;
  }
  const size_t required = WORK - work;
  for (size_t budget = 0; budget < required; ++budget) {
    TC_CMS_signed_attributes limited;
    memcpy(&limited, &saved, sizeof limited);
    work = budget;
    munit_assert_int(TC_CMS_signed_attributes_read(input, policy, &limits,
                                                   (TC_TLV_frames){frames, 8}, &work, &limited),
                     ==, TC_TLV_LIMIT);
    munit_assert_memory_equal(sizeof saved, &limited, &saved);
  }
  return expected;
}

static MunitResult other_attributes(const MunitParameter params[], void* user)
{
  /* RFC 6211 section 2, RFC 5035 sections 5 and 3, RFC 5652 section 11.4, and
   * a private arc. */
  static const uint8_t algorithm_protection[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 52};
  static const uint8_t signing_certificate[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                                1,    9,    16,   2,    12};
  static const uint8_t signing_certificate_v2[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                                   1,    9,    16,   2,    47};
  static const uint8_t countersignature[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 6};
  static const uint8_t private_arc[] = {0x2b, 6, 1, 4, 1, 0x86, 0x8d, 0x1f, 1};
  static const struct {
    const uint8_t* oid;
    size_t oid_length;
    int listed;
  } cases[] = {{algorithm_protection, sizeof algorithm_protection, 1},
               {signing_certificate, sizeof signing_certificate, 1},
               {signing_certificate_v2, sizeof signing_certificate_v2, 1},
               {countersignature, sizeof countersignature, 0},
               {private_arc, sizeof private_arc, 0}};
  static const uint8_t sequence[] = {0x30, 3, 2, 1, 5};
  static const uint8_t octets[] = {4, 1, 0};
  static const TC_CMS_other_attributes handling[] = {TC_CMS_OTHER_ATTRIBUTES_SKIP_LISTED,
                                                     TC_CMS_OTHER_ATTRIBUTES_REJECT,
                                                     TC_CMS_OTHER_ATTRIBUTES_SKIP_ALL};
  enum { ONE, DUPLICATE, MULTIPLE_VALUES, OCTET_VALUE, VARIANTS };
  uint8_t input[ATTRIBUTE_BUFFER_BYTES];
  TC_CMS_signed_attributes parsed;
  (void)params;
  (void)user;
  for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
    const TC_bytes oid = {cases[i].oid, cases[i].oid_length};
    for (size_t h = 0; h < sizeof handling / sizeof *handling; ++h) {
      for (unsigned mode = 0; mode < 2; ++mode) {
        const TC_CMS_verification_policy policy = {.attributes = (TC_CMS_attribute_encoding)mode,
                                                   .other_attributes = handling[h]};
        const int skipped = cases[i].listed ? handling[h] != TC_CMS_OTHER_ATTRIBUTES_REJECT
                                            : handling[h] == TC_CMS_OTHER_ATTRIBUTES_SKIP_ALL;
        for (unsigned variant = 0; variant < VARIANTS; ++variant) {
          const uint8_t* value = variant == OCTET_VALUE ? octets : sequence;
          const size_t value_length = variant == OCTET_VALUE ? sizeof octets : sizeof sequence;
          const size_t length = with_attribute(input, oid, value, value_length,
                                               variant == DUPLICATE, variant == MULTIPLE_VALUES);
          /* Listed attributes carry one SEQUENCE. Other values stay opaque. */
          const int malformed =
              variant == DUPLICATE ||
              (cases[i].listed && (variant == MULTIPLE_VALUES || variant == OCTET_VALUE));
          const TC_TLV_result expected = !skipped    ? TC_TLV_UNSUPPORTED
                                         : malformed ? TC_TLV_INVALID
                                                     : TC_TLV_OK;
          if (read_checked((TC_bytes){input, length}, &policy, expected, &parsed) != TC_TLV_OK)
            continue;
          munit_assert_ptr_equal(parsed.content_type.data, input + length - 9);
          munit_assert_size(parsed.message_digest.length, ==, 1);
          munit_assert_null(parsed.smime_capabilities.data);
          munit_assert_null(parsed.signer_name.data);
          munit_assert_null(parsed.fascn_oid.data);
        }
      }
    }
  }
  /* A repeated skipped type with a different value sorts apart from its first
   * instance. contentType and messageDigest lie between the two members. */
  uint8_t first[ATTRIBUTE_BYTES], second[ATTRIBUTE_BYTES];
  static const uint8_t null_value[] = {5, 0};
  static const uint8_t text_value[] = {0x0c, 10, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'};
  const TC_bytes oid = {private_arc, sizeof private_arc};
  const TC_bytes members[] = {
      {first, make_attribute(first, oid, null_value, sizeof null_value, 0)},
      {second, make_attribute(second, oid, text_value, sizeof text_value, 0)}};
  const TC_CMS_verification_policy skip_all = {.other_attributes =
                                                   TC_CMS_OTHER_ATTRIBUTES_SKIP_ALL};
  size_t length = attribute_set(input, members, 1);
  read_checked((TC_bytes){input, length}, &skip_all, TC_TLV_OK, &parsed);
  length = attribute_set(input, members, 2);
  munit_assert_memory_equal(members[0].length, input + 2, first);
  munit_assert_memory_equal(members[1].length, input + length - members[1].length, second);
  read_checked((TC_bytes){input, length}, &skip_all, TC_TLV_INVALID, &parsed);
  /* X.690 section 11.6: DER sorts the values of a skipped attribute. NULL
   * (05 00) before INTEGER (02 01 05) is out of order. */
  static const uint8_t unsorted[] = {5, 0, 2, 1, 5}, sorted[] = {2, 1, 5, 5, 0};
  for (unsigned order = 0; order < 2; ++order) {
    const uint8_t* values = order ? sorted : unsorted;
    for (unsigned mode = 0; mode < 2; ++mode) {
      const TC_CMS_verification_policy policy = {.attributes = (TC_CMS_attribute_encoding)mode,
                                                 .other_attributes =
                                                     TC_CMS_OTHER_ATTRIBUTES_SKIP_ALL};
      const TC_bytes member = {first, make_attribute(first, oid, values, sizeof unsorted, 0)};
      length = attribute_set(input, &member, 1);
      read_checked((TC_bytes){input, length}, &policy,
                   order || mode == TC_CMS_ATTRIBUTES_BER_DEFINITE_ORDER ? TC_TLV_OK
                                                                         : TC_TLV_INVALID,
                   &parsed);
    }
  }
  return MUNIT_OK;
}

static MunitResult identifier_namespaces(const MunitParameter params[], void* user)
{
  enum { NAME, PIV_FASCN, TWIC_FASCN, KINDS, FASCN_BYTES = 25 };
  static const uint8_t name_oid[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 6, 5};
  static const uint8_t piv_fascn[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 6, 6};
  static const uint8_t twic_fascn[] = {0x2b, 6, 1, 4, 1, 0x81, 0xe3, 0x52, 6, 6};
  static const uint8_t name[] = {0x30, 12, 0x31, 10, 0x30, 8, 6, 3, 0x55, 4, 3, 0x0c, 1, 'A'};
  static const TC_CMS_other_attributes handling[] = {TC_CMS_OTHER_ATTRIBUTES_SKIP_LISTED,
                                                     TC_CMS_OTHER_ATTRIBUTES_SKIP_ALL};
  const TC_bytes oids[KINDS] = {
      {name_oid, sizeof name_oid}, {piv_fascn, sizeof piv_fascn}, {twic_fascn, sizeof twic_fascn}};
  uint8_t fascn[FASCN_BYTES + 2] = {4, FASCN_BYTES};
  uint8_t input[ATTRIBUTE_BUFFER_BYTES];
  TC_CMS_signed_attributes parsed;
  (void)params;
  (void)user;
  for (unsigned kind = 0; kind < KINDS; ++kind) {
    const uint8_t* value = kind == NAME ? name : fascn;
    const size_t value_length = kind == NAME ? sizeof name : sizeof fascn;
    const size_t length = with_attribute(input, oids[kind], value, value_length, 0, 0);
    for (unsigned set = TC_CMS_ATTRIBUTE_OIDS_CMS; set <= TC_CMS_ATTRIBUTE_OIDS_PIV_TWIC; ++set) {
      for (size_t h = 0; h < sizeof handling / sizeof *handling; ++h) {
        const TC_CMS_verification_policy policy = {.attribute_oids = (TC_CMS_attribute_oids)set,
                                                   .other_attributes = handling[h]};
        /* TWIC Part 2 v5 section 6 pairs twicFASC-N with pivFASC-N. The PIV
         * set excludes that alias even when other attributes are skipped. */
        const int interpreted = kind == TWIC_FASCN ? set == TC_CMS_ATTRIBUTE_OIDS_PIV_TWIC
                                                   : set != TC_CMS_ATTRIBUTE_OIDS_CMS;
        const int excluded = kind == TWIC_FASCN && set == TC_CMS_ATTRIBUTE_OIDS_PIV;
        const int skipped =
            !interpreted && !excluded && handling[h] == TC_CMS_OTHER_ATTRIBUTES_SKIP_ALL;
        if (read_checked((TC_bytes){input, length}, &policy,
                         interpreted || skipped ? TC_TLV_OK : TC_TLV_UNSUPPORTED,
                         &parsed) != TC_TLV_OK)
          continue;
        if (!interpreted) {
          munit_assert_null(parsed.signer_name.data);
          munit_assert_null(parsed.fascn_oid.data);
          munit_assert_null(parsed.fascn_octets.data);
        } else if (kind == NAME) {
          munit_assert_size(parsed.signer_name.length, ==, sizeof name);
          munit_assert_memory_equal(sizeof name, parsed.signer_name.data, name);
        } else {
          munit_assert_size(parsed.fascn_oid.length, ==, oids[kind].length);
          munit_assert_memory_equal(oids[kind].length, parsed.fascn_oid.data, oids[kind].data);
          munit_assert_size(parsed.fascn_octets.length, ==, sizeof fascn);
        }
      }
    }
  }
  return MUNIT_OK;
}

static MunitResult policy_arguments(const MunitParameter params[], void* user)
{
  const TC_TLV_limits limits = {512, 512, 64, 8};
  TC_TLV_frame frames[8];
  TC_CMS_signed_attributes parsed, saved;
  const TC_bytes input = {encoded, sizeof encoded};
  size_t work = 1000;
  (void)params;
  (void)user;
  memset(&parsed, 0xa5, sizeof parsed);
  memcpy(&saved, &parsed, sizeof saved);
  munit_assert_int(TC_CMS_signed_attributes_read(input, NULL, &limits, (TC_TLV_frames){frames, 8},
                                                 &work, &parsed),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, 1000);
  munit_assert_memory_equal(sizeof parsed, &parsed, &saved);
  /* Each field rejects the values on both sides of its range. */
  for (unsigned field = 0; field < 5; ++field) {
    for (int bad = -1; bad <= 1; bad += 2) {
      TC_CMS_verification_policy policy = {0};
      if (field == 0)
        policy.envelope = (TC_CMS_envelope_encoding)(bad < 0 ? bad : TC_CMS_ENVELOPE_DER + bad);
      else if (field == 1)
        policy.attributes =
            (TC_CMS_attribute_encoding)(bad < 0 ? bad : TC_CMS_ATTRIBUTES_BER_DEFINITE_ORDER + bad);
      else if (field == 2)
        policy.rsa_parameters =
            (TC_CMS_rsa_parameters)(bad < 0 ? bad : TC_CMS_RSA_PARAMETERS_ALLOW_ABSENT + bad);
      else if (field == 3)
        policy.attribute_oids =
            (TC_CMS_attribute_oids)(bad < 0 ? bad : TC_CMS_ATTRIBUTE_OIDS_PIV_TWIC + bad);
      else
        policy.other_attributes =
            (TC_CMS_other_attributes)(bad < 0 ? bad : TC_CMS_OTHER_ATTRIBUTES_SKIP_ALL + bad);
      work = 1000;
      munit_assert_int(TC_CMS_signed_attributes_read(input, &policy, &limits,
                                                     (TC_TLV_frames){frames, 8}, &work, &parsed),
                       ==, TC_TLV_ARGUMENT);
      munit_assert_size(work, ==, 1000);
      munit_assert_memory_equal(sizeof parsed, &parsed, &saved);
    }
  }
  /* The policy is copied at entry, so it may share storage with out. */
  union {
    TC_CMS_signed_attributes attributes;
    TC_CMS_verification_policy policy;
  } shared;
  memset(&shared, 0, sizeof shared);
  work = 1000;
  munit_assert_int(TC_CMS_signed_attributes_read(input, &shared.policy, &limits,
                                                 (TC_TLV_frames){frames, 8}, &work,
                                                 &shared.attributes),
                   ==, TC_TLV_OK);
  munit_assert_size(shared.attributes.message_digest.length, ==, 1);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
      {"/required", attributes, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/compatibility", compatibility, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/signing-time", signing_time, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/capabilities", capabilities, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/signer-name", signer_name, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/identifier-octets", identifier_octets, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/other-attributes", other_attributes, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/identifier-namespaces", identifier_namespaces, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/policy-arguments", policy_arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/cms/attributes", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
