/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/piv_cms.h>
#include "munit.h"
#include <string.h>

static MunitResult cbeff(const MunitParameter params[], void* context)
{
  enum { HEADER_BYTES = 88, RECORD_BYTES = 1, SIGNATURE_BYTES = 2,
    OBJECT_BYTES = HEADER_BYTES + RECORD_BYTES + SIGNATURE_BYTES };
  uint8_t bytes[OBJECT_BYTES + 1] = {3,0x0d,0,0,0,RECORD_BYTES,0,SIGNATURE_BYTES};
  TC_PIV_CBEFF object, saved;
  const TC_bytes input = {bytes,OBJECT_BYTES};
  memset(&saved,0xa5,sizeof saved);
  munit_assert_int(TC_PIV_CBEFF_read(input,&object), ==, TC_TLV_OK);
  munit_assert_ptr_equal(object.signed_content.data,bytes);
  munit_assert_size(object.signed_content.length, ==, HEADER_BYTES + RECORD_BYTES);
  munit_assert_ptr_equal(object.record.data,bytes + HEADER_BYTES);
  munit_assert_size(object.record.length, ==, RECORD_BYTES);
  munit_assert_ptr_equal(object.signature.data,bytes + HEADER_BYTES + RECORD_BYTES);
  munit_assert_size(object.signature.length, ==, SIGNATURE_BYTES);
  munit_assert_ptr_equal(object.fascn.data,bytes + 59);
  munit_assert_size(object.fascn.length, ==, 25);
  for (size_t prefix = 0; prefix < OBJECT_BYTES; ++prefix) {
    memcpy(&object,&saved,sizeof object);
    munit_assert_int(TC_PIV_CBEFF_read((TC_bytes){bytes,prefix},&object), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof object,&object,&saved);
  }
  munit_assert_int(TC_PIV_CBEFF_read((TC_bytes){bytes,sizeof bytes},&object), ==, TC_TLV_INVALID);
  const size_t length_octets[] = {2,3,4,5,6,7};
  for (size_t i = 0; i < sizeof length_octets / sizeof *length_octets; ++i) {
    const size_t offset = length_octets[i];
    const uint8_t original = bytes[offset];
    bytes[offset] = 0xff;
    munit_assert_int(TC_PIV_CBEFF_read(input,&object), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof object,&object,&saved);
    bytes[offset] = original;
  }
  bytes[5] = 0;
  munit_assert_int(TC_PIV_CBEFF_read(input,&object), ==, TC_TLV_INVALID);
  bytes[5] = RECORD_BYTES; bytes[7] = 0;
  munit_assert_int(TC_PIV_CBEFF_read(input,&object), ==, TC_TLV_INVALID);
  bytes[7] = SIGNATURE_BYTES; bytes[0] = 4;
  munit_assert_int(TC_PIV_CBEFF_read(input,&object), ==, TC_TLV_UNSUPPORTED);
  munit_assert_memory_equal(sizeof object,&object,&saved);
  munit_assert_int(TC_PIV_CBEFF_read((TC_bytes){NULL,OBJECT_BYTES},&object), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_CBEFF_read(input,NULL), ==, TC_TLV_ARGUMENT);
  union { TC_PIV_CBEFF object; uint8_t bytes[OBJECT_BYTES]; } alias;
  memcpy(alias.bytes,bytes,OBJECT_BYTES);
  munit_assert_int(TC_PIV_CBEFF_read((TC_bytes){alias.bytes,OBJECT_BYTES},&alias.object), ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(OBJECT_BYTES,alias.bytes,bytes);
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult metadata(const MunitParameter params[], void* context)
{
  uint8_t bytes[91] = {3,0x0d,0,0,0,1,0,2,0,0x1b,2,1};
  static const uint8_t date[] = {20,24,2,29,12,30,0,'Z'};
  const TC_bytes input = {bytes,sizeof bytes};
  TC_PIV_CBEFF_metadata parsed, preserved;
  for (size_t offset = 12; offset <= 28; offset += sizeof date) memcpy(bytes + offset,date,sizeof date);
  memcpy(bytes + 41,"NIST",5);
  munit_assert_int(TC_PIV_CBEFF_metadata_read(input,&parsed), ==, TC_TLV_OK);
  munit_assert_uint(parsed.created.year, ==, 2024);
  munit_assert_uint(parsed.created.day, ==, 29);
  munit_assert_uint(parsed.format_owner, ==, 0x1b);
  munit_assert_uint(parsed.format_type, ==, 0x201);
  munit_assert_ptr_equal(parsed.creator.data,bytes + 41);
  munit_assert_size(parsed.creator.length, ==, 4);
  munit_assert_int(parsed.encrypted, ==, 0);
  bytes[1] = 0x0f;
  munit_assert_int(TC_PIV_CBEFF_metadata_read(input,&parsed), ==, TC_TLV_OK);
  munit_assert_int(parsed.encrypted, ==, 1);
  bytes[1] = 0x0d;
  static const uint8_t qualities[] = {254,255,0,100};
  static const int expected[] = {-2,-1,0,100};
  for (size_t i = 0; i < sizeof qualities; ++i) {
    bytes[40] = qualities[i];
    munit_assert_int(TC_PIV_CBEFF_metadata_read(input,&parsed), ==, TC_TLV_OK);
    munit_assert_int(parsed.quality, ==, expected[i]);
  }
  bytes[40] = 0;
  static const struct { size_t offset; uint8_t value; } invalid[] = {
    {1,0},{12,100},{13,100},{14,13},{15,30},{16,24},{17,60},{18,60},{19,'X'},
    {21,23},{29,23},{40,101},{40,253},{41,0x7f},{84,1},{87,1}
  };
  memset(&preserved,0xa5,sizeof preserved);
  for (size_t prefix = 0; prefix < sizeof bytes; ++prefix) {
    memcpy(&parsed,&preserved,sizeof parsed);
    munit_assert_int(TC_PIV_CBEFF_metadata_read((TC_bytes){bytes,prefix},&parsed), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof parsed,&parsed,&preserved);
  }
  munit_assert_int(TC_PIV_CBEFF_metadata_read((TC_bytes){NULL,sizeof bytes},&parsed), ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof parsed,&parsed,&preserved);
  munit_assert_int(TC_PIV_CBEFF_metadata_read(input,NULL), ==, TC_TLV_ARGUMENT);
  union { TC_PIV_CBEFF_metadata metadata; uint8_t bytes[sizeof bytes]; } alias;
  memcpy(alias.bytes,bytes,sizeof bytes);
  munit_assert_int(TC_PIV_CBEFF_metadata_read((TC_bytes){alias.bytes,sizeof bytes},&alias.metadata), ==, TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof bytes,alias.bytes,bytes);
  for (size_t i = 0; i < sizeof invalid / sizeof *invalid; ++i) {
    const uint8_t saved = bytes[invalid[i].offset];
    bytes[invalid[i].offset] = invalid[i].value;
    memcpy(&parsed,&preserved,sizeof parsed);
    munit_assert_int(TC_PIV_CBEFF_metadata_read(input,&parsed), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof parsed,&parsed,&preserved);
    bytes[invalid[i].offset] = saved;
  }
  memset(bytes + 41,'A',18);
  munit_assert_int(TC_PIV_CBEFF_metadata_read(input,&parsed), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof parsed,&parsed,&preserved);
  /* Creator bytes after the terminator are unspecified. */
  bytes[41] = 0;
  munit_assert_int(TC_PIV_CBEFF_metadata_read(input,&parsed), ==, TC_TLV_OK);
  munit_assert_size(parsed.creator.length, ==, 0);
  bytes[41] = 'A'; bytes[58] = 0;
  munit_assert_int(TC_PIV_CBEFF_metadata_read(input,&parsed), ==, TC_TLV_OK);
  munit_assert_size(parsed.creator.length, ==, 17);
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult formats(const MunitParameter params[], void* context)
{
  static const struct {
    uint16_t owner, type;
    uint32_t biometric;
    uint8_t processing;
    TC_PIV_CBEFF_format expected;
  } cases[] = {
    {0x001b,0x0401,0x000008,0x20,TC_PIV_CBEFF_FINGERPRINT_IMAGE},
    {0x001b,0x0201,0x000008,0x80,TC_PIV_CBEFF_FINGERPRINT_TEMPLATE},
    {0x0101,0x0009,0x000010,0x40,TC_PIV_CBEFF_IRIS_IMAGE},
    {0x001b,0x0501,0x000002,0x20,TC_PIV_CBEFF_FACE_IMAGE}
  };
  munit_assert_int(TC_PIV_CBEFF_format_identify(NULL), ==, TC_PIV_CBEFF_FORMAT_UNKNOWN);
  for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
    TC_PIV_CBEFF_metadata metadata = {0};
    metadata.format_owner = cases[i].owner;
    metadata.format_type = cases[i].type;
    metadata.biometric_type = cases[i].biometric;
    metadata.quality = -2;
    for (unsigned value = 0; value <= UINT8_MAX; ++value) {
      metadata.data_type = (uint8_t)value;
      munit_assert_int(TC_PIV_CBEFF_format_identify(&metadata), ==,
          (value & 0xe0) == cases[i].processing ? cases[i].expected : TC_PIV_CBEFF_FORMAT_UNKNOWN);
    }
    metadata.data_type = cases[i].processing;
    metadata.format_owner ^= 1;
    munit_assert_int(TC_PIV_CBEFF_format_identify(&metadata), ==, TC_PIV_CBEFF_FORMAT_UNKNOWN);
    metadata.format_owner = cases[i].owner; metadata.format_type ^= 1;
    munit_assert_int(TC_PIV_CBEFF_format_identify(&metadata), ==, TC_PIV_CBEFF_FORMAT_UNKNOWN);
    metadata.format_type = cases[i].type;
    for (unsigned bit = 0; bit < 24; ++bit) {
      metadata.biometric_type = cases[i].biometric ^ ((uint32_t)1 << bit);
      munit_assert_int(TC_PIV_CBEFF_format_identify(&metadata), ==, TC_PIV_CBEFF_FORMAT_UNKNOWN);
    }
  }
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult identifiers(const MunitParameter params[], void* context)
{
  enum { FASCN_BYTES = 25, UUID_BYTES = 16, FRAME_COUNT = 8, WORK = 8192 };
  uint8_t fascn[FASCN_BYTES], uuid[UUID_BYTES];
  uint8_t encoded_fascn[FASCN_BYTES + 2] = {4,FASCN_BYTES};
  uint8_t encoded_uuid[UUID_BYTES + 2] = {4,UUID_BYTES};
  uint8_t chunks[UUID_BYTES + 6] = {0x24,UUID_BYTES + 4,4,8};
  TC_TLV_frame frames[FRAME_COUNT];
  const TC_TLV_limits limits = {WORK,WORK,64,FRAME_COUNT};
  const TC_bytes expected_fascn = {fascn,sizeof fascn}, expected_uuid = {uuid,sizeof uuid};
  TC_PIV_CMS_object object = {0};
  for (size_t i = 0; i < sizeof fascn; ++i) fascn[i] = (uint8_t)i;
  for (size_t i = 0; i < sizeof uuid; ++i) uuid[i] = (uint8_t)(i + 32);
  memcpy(encoded_fascn + 2,fascn,sizeof fascn);
  memcpy(encoded_uuid + 2,uuid,sizeof uuid);
  memcpy(chunks + 4,uuid,8); chunks[12] = 4; chunks[13] = 8;
  memcpy(chunks + 14,uuid + 8,8);
  object.attributes.fascn_octets = (TC_bytes){encoded_fascn,sizeof encoded_fascn};
  for (unsigned fragmented = 0; fragmented < 2; ++fragmented) {
    object.attributes.entry_uuid_octets = fragmented ? (TC_bytes){chunks,sizeof chunks} :
        (TC_bytes){encoded_uuid,sizeof encoded_uuid};
    size_t required = 0;
    for (unsigned mismatch = 0; mismatch < 3; ++mismatch) {
      if (mismatch == 1) fascn[0] ^= 1;
      if (mismatch == 2) uuid[0] ^= 1;
      size_t work = WORK;
      int matched = -1;
      munit_assert_int(TC_PIV_CMS_identifiers_match(&object,TC_PIV_CMS_BIOMETRIC,expected_fascn,expected_uuid,
          &limits,frames,FRAME_COUNT,&work,&matched), ==, TC_TLV_OK);
      munit_assert_int(matched, ==, mismatch == 0);
      if (!mismatch) required = WORK - work;
      if (mismatch == 1) fascn[0] ^= 1;
      if (mismatch == 2) uuid[0] ^= 1;
    }
    for (size_t budget = 0; budget <= required; ++budget) {
      size_t work = budget;
      int matched = -1;
      munit_assert_int(TC_PIV_CMS_identifiers_match(&object,TC_PIV_CMS_BIOMETRIC,expected_fascn,expected_uuid,
          &limits,frames,FRAME_COUNT,&work,&matched), ==, budget == required ? TC_TLV_OK : TC_TLV_LIMIT);
      munit_assert_int(matched, ==, budget == required ? 1 : -1);
      if (budget == required) munit_assert_size(work, ==, 0);
    }
  }
  size_t work = WORK;
  int matched = -1;
  fascn[0] ^= 1; chunks[12] = 5;
  munit_assert_int(TC_PIV_CMS_identifiers_match(&object,TC_PIV_CMS_BIOMETRIC,expected_fascn,expected_uuid,
      &limits,frames,FRAME_COUNT,&work,&matched), ==, TC_TLV_INVALID);
  munit_assert_int(matched, ==, -1);
  fascn[0] ^= 1; chunks[12] = 4;
  TC_PIV_CMS_object preserved;
  memcpy(&preserved,&object,sizeof object);
  work = WORK;
  munit_assert_int(TC_PIV_CMS_identifiers_match(&object,TC_PIV_CMS_BIOMETRIC,expected_fascn,expected_uuid,
      &limits,frames,FRAME_COUNT,&work,&object.envelope.has_content), ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, WORK);
  munit_assert_memory_equal(sizeof object,&object,&preserved);
  work = WORK;
  munit_assert_int(TC_PIV_CMS_identifiers_match(&object,TC_PIV_CMS_BIOMETRIC,(TC_bytes){fascn,sizeof fascn - 1},expected_uuid,
      &limits,frames,FRAME_COUNT,&work,&matched), ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, WORK); munit_assert_int(matched, ==, -1);
  object.attributes.entry_uuid_octets = (TC_bytes){NULL,0};
  munit_assert_int(TC_PIV_CMS_identifiers_match(&object,TC_PIV_CMS_BIOMETRIC,expected_fascn,expected_uuid,
      &limits,frames,FRAME_COUNT,&work,&matched), ==, TC_TLV_INVALID);
  munit_assert_int(matched, ==, -1);
  for (unsigned presence = 0; presence < 4; ++presence) {
    object.attributes.fascn_octets = presence & 1 ? (TC_bytes){encoded_fascn,sizeof encoded_fascn} : (TC_bytes){NULL,0};
    object.attributes.entry_uuid_octets = presence & 2 ? (TC_bytes){chunks,sizeof chunks} : (TC_bytes){NULL,0};
    work = WORK; matched = -1;
    munit_assert_int(TC_PIV_CMS_identifiers_match(&object,TC_PIV_CMS_BIOMETRIC,expected_fascn,expected_uuid,
        &limits,frames,FRAME_COUNT,&work,&matched), ==, presence == 3 ? TC_TLV_OK : TC_TLV_INVALID);
    munit_assert_int(matched, ==, presence == 3 ? 1 : -1);
    if (presence != 3) munit_assert_size(work, ==, WORK);
    for (unsigned mismatch = 0; mismatch < 3; ++mismatch) {
      if (mismatch == 1) fascn[0] ^= 1;
      if (mismatch == 2) uuid[0] ^= 1;
      work = WORK; matched = -1;
      munit_assert_int(TC_PIV_CMS_identifiers_match(&object,TC_PIV_CMS_CHUID,expected_fascn,expected_uuid,
          &limits,frames,FRAME_COUNT,&work,&matched), ==, TC_TLV_OK);
      munit_assert_int(matched, ==, mismatch == 0 || !(presence & (1u << (mismatch - 1))));
      size_t legacy_work = WORK;
      int legacy_matched = -1;
      munit_assert_int(TC_PIV_CMS_identifiers_match(&object,TC_PIV_CMS_BIOMETRIC_LEGACY,
          expected_fascn,expected_uuid,&limits,frames,FRAME_COUNT,&legacy_work,&legacy_matched), ==,
          presence & 1 ? TC_TLV_OK : TC_TLV_INVALID);
      munit_assert_int(legacy_matched, ==, presence & 1 ? matched : -1);
      if (!(presence & 1)) munit_assert_size(legacy_work, ==, WORK);
      if (mismatch == 1) fascn[0] ^= 1;
      if (mismatch == 2) uuid[0] ^= 1;
    }
    const size_t required = WORK - work;
    for (size_t budget = 0; budget <= required; ++budget) {
      work = budget; matched = -1;
      munit_assert_int(TC_PIV_CMS_identifiers_match(&object,TC_PIV_CMS_CHUID,expected_fascn,expected_uuid,
          &limits,frames,FRAME_COUNT,&work,&matched), ==, budget == required ? TC_TLV_OK : TC_TLV_LIMIT);
      munit_assert_int(matched, ==, budget == required ? 1 : -1);
    }
  }
  work = WORK; matched = -1;
  munit_assert_int(TC_PIV_CMS_identifiers_match(&object,(TC_PIV_CMS_kind)-1,expected_fascn,expected_uuid,
      &limits,frames,FRAME_COUNT,&work,&matched), ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, WORK);
  munit_assert_int(matched, ==, -1);
  (void)params; (void)context;
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {{"/identifiers",identifiers,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/cbeff",cbeff,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/metadata",metadata,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/formats",formats,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}};
  MunitSuite suite = {"/piv/cms",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
