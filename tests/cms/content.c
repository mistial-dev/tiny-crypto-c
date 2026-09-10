/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/cms.h>
#include "../../src/pki_octets_hash_internal.h"
#include "munit.h"

static MunitResult content_binding(const MunitParameter params[], void* user)
{
  enum { WORK_BUDGET = 1024 };
  static const uint8_t type[] = {42,3};
  static const uint8_t message[] = {'a','b','c'};
  TC_CMS_signed_attributes attributes = {0};
  tc_hash_workspace scratch;
  uint8_t digest[TC_SHA512_DIGESTLEN], actual[TC_SHA512_DIGESTLEN];
  (void)params; (void)user;
  attributes.content_type = (TC_bytes){type,sizeof type};
  for (unsigned id = TC_HASH_SHA1; id <= TC_HASH_SHA512; ++id) {
    tc_hash_info info;
    const TC_hash_algorithm algorithm = (TC_hash_algorithm)id;
    const TC_bytes whole = {message,sizeof message};
    munit_assert_true(tc_hash_info_get((TC_hash_algorithm)id,&info));
    munit_assert_int(tc_hash_digest_parts((TC_hash_algorithm)id,&whole,1,digest,&scratch), ==, TC_OK);
    attributes.message_digest = (TC_bytes){digest,info.digest_length};
    for (size_t split = 0; split <= sizeof message; ++split) {
      TC_bytes parts[] = {{message,split},{NULL,0},{message + split,sizeof message - split}};
      size_t work = WORK_BUDGET;
      int matched = -1;
      const TC_bytes computed = {actual,info.digest_length};
      munit_assert_int(tc_hash_digest_parts(algorithm,parts,sizeof parts / sizeof *parts,
          actual,&scratch), ==, TC_OK);
      munit_assert_int(TC_CMS_content_digest_check(&attributes,attributes.content_type,algorithm,
          computed,&work,&matched), ==, TC_TLV_OK);
      munit_assert_int(matched, ==, 1);
      size_t required = WORK_BUDGET - work;
      for (size_t budget = 0; budget < required; ++budget) {
        work = budget; matched = -1;
        munit_assert_int(TC_CMS_content_digest_check(&attributes,attributes.content_type,algorithm,
            computed,&work,&matched), ==, TC_TLV_LIMIT);
        munit_assert_int(matched, ==, -1);
      }
      work = required;
      munit_assert_int(TC_CMS_content_digest_check(&attributes,attributes.content_type,algorithm,
          computed,&work,&matched), ==, TC_TLV_OK);
      munit_assert_int(matched, ==, 1);
      munit_assert_size(work, ==, 0);
      digest[0] ^= 1; work = WORK_BUDGET;
      munit_assert_int(TC_CMS_content_digest_check(&attributes,attributes.content_type,algorithm,
          computed,&work,&matched), ==, TC_TLV_OK);
      munit_assert_int(matched, ==, 0); digest[0] ^= 1;
      work = WORK_BUDGET;
      munit_assert_int(TC_CMS_content_digest_check(&attributes,(TC_bytes){type,1},algorithm,
          computed,&work,&matched), ==, TC_TLV_OK);
      munit_assert_int(matched, ==, 0);
      work = WORK_BUDGET; matched = -1;
      munit_assert_int(TC_CMS_content_digest_check(&attributes,attributes.content_type,algorithm,
          (TC_bytes){actual,info.digest_length - 1},&work,&matched), ==, TC_TLV_ARGUMENT);
      munit_assert_int(matched, ==, -1);
      munit_assert_int(TC_CMS_content_digest_check(&attributes,attributes.content_type,TC_HASH_UNKNOWN,
          computed,&work,&matched), ==, TC_TLV_UNSUPPORTED);
      munit_assert_int(matched, ==, -1);
      --attributes.message_digest.length; work = WORK_BUDGET;
      munit_assert_int(TC_CMS_content_digest_check(&attributes,attributes.content_type,algorithm,
          computed,&work,&matched), ==, TC_TLV_OK);
      munit_assert_int(matched, ==, 0);
      ++attributes.message_digest.length;
    }
  }
  return MUNIT_OK;
}

static MunitResult binding_storage(const MunitParameter params[], void* user)
{
  enum { ATTRIBUTES, TYPE, DIGEST, ATTRIBUTE_TYPE, ATTRIBUTE_DIGEST,
    WORK, MATCHED, SLOT_COUNT, WORK_BUDGET = 1024 };
  union slot {
    TC_CMS_signed_attributes attributes;
    uint8_t bytes[TC_SHA512_DIGESTLEN];
    size_t work;
    int matched;
  } slots[SLOT_COUNT];
  uint8_t saved[sizeof slots];
  (void)params; (void)user;
  /* Read-only ranges may alias; neither writable range may alias anything. */
  for (unsigned output = WORK; output <= MATCHED; ++output)
    for (unsigned input = 0; input < output; ++input) {
      void* pointers[SLOT_COUNT];
      memset(slots,0,sizeof slots);
      for (unsigned i = 0; i < SLOT_COUNT; ++i) pointers[i] = &slots[i];
      pointers[output] = pointers[input];
      size_t* work = pointers[WORK];
      int* matched = pointers[MATCHED];
      TC_CMS_signed_attributes* attributes = pointers[ATTRIBUTES];
      *work = WORK_BUDGET;
      *matched = -1;
      attributes->content_type = (TC_bytes){pointers[ATTRIBUTE_TYPE],2};
      attributes->message_digest = (TC_bytes){pointers[ATTRIBUTE_DIGEST],TC_SHA256_DIGESTLEN};
      memcpy(saved,slots,sizeof saved);
      munit_assert_int(TC_CMS_content_digest_check(attributes,
          (TC_bytes){pointers[TYPE],2},TC_HASH_SHA256,
          (TC_bytes){pointers[DIGEST],TC_SHA256_DIGESTLEN},work,matched), ==, TC_TLV_ARGUMENT);
      munit_assert_memory_equal(sizeof slots,slots,saved);
    }
  TC_CMS_signed_attributes attributes = {0};
  uint8_t digest[TC_SHA256_DIGESTLEN] = {0};
  attributes.content_type = (TC_bytes){digest,2};
  attributes.message_digest = (TC_bytes){digest,sizeof digest};
  size_t work = WORK_BUDGET;
  int matched = -1;
  munit_assert_int(TC_CMS_content_digest_check(&attributes,attributes.content_type,
      TC_HASH_SHA256,attributes.message_digest,&work,&matched), ==, TC_TLV_OK);
  munit_assert_int(matched, ==, 1);
  /* Reject an address range that wraps before touching either output. */
  work = WORK_BUDGET; matched = -1;
  attributes.message_digest = (TC_bytes){(const uint8_t*)(uintptr_t)(UINTPTR_MAX - 1),4};
  munit_assert_int(TC_CMS_content_digest_check(&attributes,attributes.content_type,
      TC_HASH_SHA256,(TC_bytes){digest,sizeof digest},&work,&matched), ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, WORK_BUDGET);
  munit_assert_int(matched, ==, -1);
  return MUNIT_OK;
}

static MunitResult encoded_content(const MunitParameter params[], void* user)
{
  enum { FRAME_CAPACITY = 8, WORK_BUDGET = 1024, OUTPUT_SENTINEL = 0xa5 };
  static const uint8_t message[] = {'a','b','c'};
  static const uint8_t primitive[] = {4,3,'a','b','c'};
  static const uint8_t sha256_abc[TC_SHA256_DIGESTLEN] = {
    0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
    0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
  };
  static const uint8_t definite[] = {0x24,9,4,1,'a',0x24,4,4,2,'b','c'};
  static const uint8_t indefinite[] = {0x24,0x80,4,1,'a',0x24,0x80,4,0,4,2,'b','c',0,0,0,0};
  static const uint8_t wrong_child[] = {0x24,3,2,1,0};
  static const uint8_t empty[] = {4,0};
  const TC_bytes encodings[] = {
    {primitive,sizeof primitive}, {definite,sizeof definite}, {indefinite,sizeof indefinite}
  };
  TC_TLV_limits limits = {WORK_BUDGET,WORK_BUDGET,32,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  tc_hash_workspace scratch;
  uint8_t expected[TC_SHA512_DIGESTLEN], actual[TC_SHA512_DIGESTLEN];
  const uint8_t zero_scratch[sizeof scratch] = {0};
  uint8_t untouched[sizeof actual];
  (void)params; (void)user;
  memset(untouched,OUTPUT_SENTINEL,sizeof untouched);
  for (unsigned id = TC_HASH_SHA1; id <= TC_HASH_SHA512; ++id) {
    const TC_hash_algorithm hash = (TC_hash_algorithm)id;
    const TC_bytes whole = {message,sizeof message};
    tc_hash_info info;
    munit_assert_true(tc_hash_info_get(hash,&info));
    munit_assert_int(tc_hash_digest_parts(hash,&whole,1,expected,&scratch), ==, TC_OK);
    if (hash == TC_HASH_SHA256)
      munit_assert_memory_equal(sizeof sha256_abc,expected,sha256_abc);
    for (size_t i = 0; i < sizeof encodings / sizeof *encodings; ++i) {
      size_t work = WORK_BUDGET;
      memset(actual,OUTPUT_SENTINEL,sizeof actual);
      munit_assert_int(TC_CMS_content_digest(encodings[i],hash,&limits,frames,
          FRAME_CAPACITY,&work,actual,sizeof actual), ==, TC_TLV_OK);
      munit_assert_memory_equal(info.digest_length,actual,expected);
      for (size_t spare = info.digest_length; spare < sizeof actual; ++spare)
        munit_assert_uint(actual[spare], ==, OUTPUT_SENTINEL);
      const size_t required = WORK_BUDGET - work;
      for (size_t budget = 0; budget < required; ++budget) {
        work = budget;
        memcpy(actual,untouched,sizeof actual);
        munit_assert_int(TC_CMS_content_digest(encodings[i],hash,&limits,frames,
            FRAME_CAPACITY,&work,actual,sizeof actual), ==, TC_TLV_LIMIT);
        munit_assert_memory_equal(sizeof actual,actual,untouched);
      }
      work = required;
      munit_assert_int(TC_CMS_content_digest(encodings[i],hash,&limits,frames,
          FRAME_CAPACITY,&work,actual,sizeof actual), ==, TC_TLV_OK);
      munit_assert_size(work, ==, 0);
      for (size_t capacity = 0; capacity < info.digest_length; ++capacity) {
        work = WORK_BUDGET;
        memcpy(actual,untouched,sizeof actual);
        munit_assert_int(TC_CMS_content_digest(encodings[i],hash,&limits,frames,
            FRAME_CAPACITY,&work,actual,capacity), ==, TC_TLV_LIMIT);
        munit_assert_memory_equal(sizeof actual,actual,untouched);
      }
      for (size_t length = 0; length < encodings[i].length; ++length) {
        work = WORK_BUDGET;
        memcpy(actual,untouched,sizeof actual);
        munit_assert_int(TC_CMS_content_digest((TC_bytes){encodings[i].data,length},
            hash,&limits,frames,FRAME_CAPACITY,&work,actual,sizeof actual), !=, TC_TLV_OK);
        munit_assert_memory_equal(sizeof actual,actual,untouched);
      }
    }
    size_t work = WORK_BUDGET;
    memcpy(actual,untouched,sizeof actual);
    munit_assert_int(TC_CMS_content_digest((TC_bytes){wrong_child,sizeof wrong_child},
        hash,&limits,frames,FRAME_CAPACITY,&work,actual,sizeof actual), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof actual,actual,untouched);
    work = WORK_BUDGET;
    munit_assert_int(tc_pki_octets_hash((TC_bytes){definite,sizeof definite},
        TC_TLV_DER,&limits,frames,FRAME_CAPACITY,hash,&scratch,&work,actual), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof actual,actual,untouched);
    munit_assert_memory_equal(sizeof scratch,&scratch,zero_scratch);
    munit_assert_int(tc_hash_digest_parts(hash,NULL,0,expected,&scratch), ==, TC_OK);
    work = WORK_BUDGET;
    munit_assert_int(TC_CMS_content_digest((TC_bytes){empty,sizeof empty},
        hash,&limits,frames,FRAME_CAPACITY,&work,actual,sizeof actual), ==, TC_TLV_OK);
    munit_assert_memory_equal(info.digest_length,actual,expected);
  }
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/binding",content_binding,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/storage",binding_storage,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/encoded",encoded_content,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/cms/content",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
