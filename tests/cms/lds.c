/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/lds.h>
#include "munit.h"
#include <string.h>

enum { CAPACITY = 2048, FRAMES = 8, WORK = 100000 };

static size_t field(uint8_t* out, uint8_t tag, const uint8_t* value, size_t length)
{
  if (length > CAPACITY - 4) {
    munit_error("LDS fixture field exceeds its buffer");
  }
  size_t used = 0;
  out[used++] = tag;
  if (length >= 256) { out[used++] = 0x82; out[used++] = (uint8_t)(length >> 8); }
  else if (length >= 128) out[used++] = 0x81;
  out[used++] = (uint8_t)length;
  memcpy(out + used,value,length);
  return used + length;
}

static size_t fixture(uint8_t* out, unsigned version, unsigned count, int duplicate,
    size_t digest_bytes, unsigned parameters)
{
  uint8_t body[CAPACITY], hashes[CAPACITY], entry[80];
  uint8_t algorithm[] = {6,9,0x60,0x86,0x48,1,0x65,3,4,2,1,5,0,0};
  const uint8_t version_byte = (uint8_t)version;
  size_t used = field(body,2,&version_byte,1), hash_bytes = 0;
  if (parameters == 2) { algorithm[11] = 1; algorithm[12] = 1; algorithm[13] = 0xff; }
  if (parameters == 3) algorithm[10] = 8;
  used += field(body + used,0x30,algorithm,parameters == 2 ? 14 : parameters == 1 ? 13 : 11);
  for (unsigned i = 0; i < count; ++i) {
    const uint8_t number = (uint8_t)(duplicate && i + 1 == count ? 1 : i + 1);
    size_t bytes = field(entry,2,&number,1);
    uint8_t digest[64]; memset(digest,(int)i,sizeof digest);
    bytes += field(entry + bytes,4,digest,digest_bytes);
    hash_bytes += field(hashes + hash_bytes,0x30,entry,bytes);
  }
  used += field(body + used,0x30,hashes,hash_bytes);
  if (version == 1) {
    static const uint8_t versions[] = {0x13,4,'0','1','0','8',0x13,6,'0','4','0','0','0','0'};
    used += field(body + used,0x30,versions,sizeof versions);
  }
  return field(out,0x30,body,used);
}

static MunitResult parsing(const MunitParameter params[], void* context)
{
  uint8_t encoded[CAPACITY];
  TC_TLV_frame frames[FRAMES];
  const TC_TLV_limits limits = {CAPACITY,CAPACITY,128,FRAMES};
  TC_LDS_security_object object, preserved;
  memset(&preserved,0xa5,sizeof preserved);
  for (unsigned version = 0; version < 2; ++version) {
    for (unsigned count = 2; count <= TC_LDS_MAX_GROUPS; ++count) {
      const size_t length = fixture(encoded,version,count,0,32,count & 1);
      size_t work = WORK;
      munit_assert_int(TC_LDS_read((TC_bytes){encoded,length},&limits,frames,FRAMES,&work,&object), ==, TC_TLV_OK);
      munit_assert_uint(object.version, ==, version);
      munit_assert_int(object.hash, ==, TC_HASH_SHA256);
      munit_assert_uint(object.groups, ==, (1u << count) - 1);
      munit_assert_ptr_equal(object.encoded.data,encoded);
      munit_assert_size(object.lds_version.length, ==, version ? 4 : 0);
      if (version) munit_assert_memory_equal(4,object.lds_version.data,"0108");
    }
  }
  enum { TOO_FEW, TOO_MANY, DUPLICATE, SHORT_HASH, LONG_HASH, BAD_PARAMETERS, UNKNOWN_HASH, UNKNOWN_VERSION };
  for (unsigned variant = TOO_FEW; variant <= UNKNOWN_VERSION; ++variant) {
    const size_t length = fixture(encoded,variant == UNKNOWN_VERSION ? 2 : 0,
        variant == TOO_FEW ? 1 : variant == TOO_MANY ? 17 : 2,variant == DUPLICATE,
        variant == SHORT_HASH ? 31 : variant == LONG_HASH ? 33 : 32,
        variant == BAD_PARAMETERS ? 2 : variant == UNKNOWN_HASH ? 3 : 0);
    size_t work = WORK; object = preserved;
    munit_assert_int(TC_LDS_read((TC_bytes){encoded,length},&limits,frames,FRAMES,&work,&object), ==,
        variant == UNKNOWN_HASH || variant == UNKNOWN_VERSION ? TC_TLV_UNSUPPORTED : TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof object,&object,&preserved);
  }
  for (unsigned variant = 0; variant < 7; ++variant) {
    size_t length = fixture(encoded,variant == 0 ? 0 : 1,2,0,32,0);
    size_t work = WORK;
    munit_assert_int(TC_LDS_read((TC_bytes){encoded,length},&limits,frames,FRAMES,&work,&object), ==, TC_TLV_OK);
    if (variant < 2) encoded[4] ^= 1; /* Missing or unexpected version information. */
    else if (variant == 2) encoded[(size_t)(object.lds_version.data - encoded)] = 'A';
    else if (variant == 3) encoded[(size_t)(object.unicode_version.data - encoded)] = 'X';
    else if (variant == 4) encoded[length++] = 0;
    else {
      /* Two short sequence headers and the INTEGER header precede DG1. */
      encoded[(size_t)(object.hashes.data - encoded) + 6] = variant == 5 ? 0 : 17;
    }
    work = WORK; object = preserved;
    munit_assert_int(TC_LDS_read((TC_bytes){encoded,length},&limits,frames,FRAMES,&work,&object), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof object,&object,&preserved);
  }
  size_t length = fixture(encoded,1,2,0,32,0);
  for (size_t prefix = 0; prefix < length; ++prefix) {
    size_t work = WORK; object = preserved;
    munit_assert_int(TC_LDS_read((TC_bytes){encoded,prefix},&limits,frames,FRAMES,&work,&object), !=, TC_TLV_OK);
    munit_assert_memory_equal(sizeof object,&object,&preserved);
  }
  size_t work = WORK;
  munit_assert_int(TC_LDS_read((TC_bytes){encoded,length},&limits,frames,FRAMES,&work,&object), ==, TC_TLV_OK);
  const size_t required = WORK - work;
  for (size_t budget = 0; budget <= required; ++budget) {
    work = budget; object = preserved;
    munit_assert_int(TC_LDS_read((TC_bytes){encoded,length},&limits,frames,FRAMES,&work,&object), ==,
        budget == required ? TC_TLV_OK : TC_TLV_LIMIT);
    if (budget < required) munit_assert_memory_equal(sizeof object,&object,&preserved);
  }
  work = WORK; object = preserved;
  munit_assert_int(TC_LDS_read((TC_bytes){encoded,length},&limits,NULL,0,&work,&object), ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof object,&object,&preserved);
  union { TC_LDS_security_object object; uint8_t bytes[CAPACITY]; } alias;
  memcpy(alias.bytes,encoded,length);
  work = WORK;
  munit_assert_int(TC_LDS_read((TC_bytes){alias.bytes,length},&limits,frames,FRAMES,&work,&alias.object), ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, WORK);
  munit_assert_memory_equal(length,alias.bytes,encoded);
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult lookup(const MunitParameter params[], void* context)
{
  uint8_t encoded[CAPACITY];
  TC_TLV_frame frames[FRAMES];
  const TC_TLV_limits limits = {CAPACITY,CAPACITY,128,FRAMES};
  const TC_bytes sentinel = {(const uint8_t*)"unchanged",9};
  TC_LDS_security_object object;
  for (unsigned count = 2; count <= TC_LDS_MAX_GROUPS; ++count) {
    const size_t length = fixture(encoded,1,count,0,32,0);
    size_t work = WORK;
    munit_assert_int(TC_LDS_read((TC_bytes){encoded,length},&limits,frames,FRAMES,&work,&object), ==, TC_TLV_OK);
    for (unsigned number = 0; number <= TC_LDS_MAX_GROUPS + 1; ++number) {
      TC_bytes digest = sentinel;
      work = WORK;
      const int invalid = !number || number > TC_LDS_MAX_GROUPS;
      munit_assert_int(TC_LDS_hash_find(&object,number,&limits,frames,FRAMES,&work,&digest), ==,
          invalid ? TC_TLV_ARGUMENT : number > count ? TC_TLV_END : TC_TLV_OK);
      if (invalid || number > count) {
        munit_assert_ptr_equal(digest.data,sentinel.data);
        munit_assert_size(digest.length, ==, sentinel.length);
        if (invalid) munit_assert_size(work, ==, WORK);
      } else {
        munit_assert_size(digest.length, ==, 32);
        munit_assert_true(digest.data >= encoded && digest.data + digest.length <= encoded + length);
        for (size_t i = 0; i < digest.length; ++i) munit_assert_uint(digest.data[i], ==, number - 1);
      }
    }
  }
  const size_t length = fixture(encoded,0,2,0,32,0);
  size_t work = WORK;
  TC_bytes digest;
  munit_assert_int(TC_LDS_read((TC_bytes){encoded,length},&limits,frames,FRAMES,&work,&object), ==, TC_TLV_OK);
  work = WORK;
  munit_assert_int(TC_LDS_hash_find(&object,1,&limits,frames,FRAMES,&work,&digest), ==, TC_TLV_OK);
  const size_t required = WORK - work;
  for (size_t budget = 0; budget <= required; ++budget) {
    work = budget; digest = sentinel;
    munit_assert_int(TC_LDS_hash_find(&object,1,&limits,frames,FRAMES,&work,&digest), ==,
        budget == required ? TC_TLV_OK : TC_TLV_LIMIT);
    if (budget < required) {
      munit_assert_ptr_equal(digest.data,sentinel.data);
      munit_assert_size(digest.length, ==, sentinel.length);
    }
  }
  TC_LDS_security_object preserved = object;
  work = WORK;
  munit_assert_int(TC_LDS_hash_find(&object,1,&limits,frames,FRAMES,&work,&object.hashes), ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, WORK);
  munit_assert_memory_equal(sizeof object,&object,&preserved);
  work = WORK; digest = sentinel;
  munit_assert_int(TC_LDS_hash_find(&object,1,NULL,frames,FRAMES,&work,&digest), ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, WORK);
  munit_assert_ptr_equal(digest.data,sentinel.data);
  /* A later duplicate must fail even when searching for the first group. */
  enum { SEQUENCE_HEADER_BYTES = 2, GROUP_NUMBER_OFFSET = 4,
    SHA256_GROUP_BYTES = 2 + 3 + 2 + 32 };
  const size_t second_number = (size_t)(object.hashes.data - encoded) +
      SEQUENCE_HEADER_BYTES + SHA256_GROUP_BYTES + GROUP_NUMBER_OFFSET;
  munit_assert_uint(encoded[second_number], ==, 2);
  encoded[second_number] = 1;
  work = WORK;
  munit_assert_int(TC_LDS_hash_find(&object,1,&limits,frames,FRAMES,&work,&digest), ==, TC_TLV_INVALID);
  munit_assert_ptr_equal(digest.data,sentinel.data);
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult content_read(const MunitParameter params[], void* context)
{
  uint8_t der[CAPACITY], encoded[CAPACITY], chunks[CAPACITY], buffer[CAPACITY];
  TC_TLV_frame frames[FRAMES];
  const TC_TLV_limits limits = {CAPACITY,CAPACITY,128,FRAMES};
  TC_LDS_security_object object, preserved;
  memset(&preserved,0xa5,sizeof preserved);
  const size_t length = fixture(der,0,2,0,32,0);
  size_t used = field(encoded,4,der,length), work = WORK;
  munit_assert_int(TC_LDS_read_content((TC_bytes){encoded,used},&limits,frames,FRAMES,
      &work,NULL,0,&object), ==, TC_TLV_OK);
  munit_assert_ptr_equal(object.encoded.data,encoded + used - length);
  for (size_t split = 0; split <= length; ++split) {
    size_t bytes = field(chunks,4,der,split);
    bytes += field(chunks + bytes,4,der + split,length - split);
    used = field(encoded,0x24,chunks,bytes);
    work = WORK;
    memset(buffer,0xa5,sizeof buffer);
    munit_assert_int(TC_LDS_read_content((TC_bytes){encoded,used},&limits,frames,FRAMES,
        &work,buffer,length,&object), ==, TC_TLV_OK);
    munit_assert_memory_equal(length,object.encoded.data,der);
    const int copied = split && split < length;
    if (copied) munit_assert_ptr_equal(object.encoded.data,buffer);
    else munit_assert_uint(buffer[0], ==, 0xa5);
    work = WORK; object = preserved;
    munit_assert_int(TC_LDS_read_content((TC_bytes){encoded,used},&limits,frames,FRAMES,
        &work,NULL,0,&object), ==, copied ? TC_TLV_LIMIT : TC_TLV_OK);
    if (copied) munit_assert_memory_equal(sizeof object,&object,&preserved);
  }
  /* An indefinite outer string contains a definite, fragmented inner string. */
  size_t bytes = field(chunks,4,der,1);
  bytes += field(chunks + bytes,4,der + 1,length - 1);
  encoded[0] = 0x24; encoded[1] = 0x80;
  used = 2 + field(encoded + 2,0x24,chunks,bytes);
  encoded[used++] = 0; encoded[used++] = 0;
  work = WORK;
  munit_assert_int(TC_LDS_read_content((TC_bytes){encoded,used},&limits,frames,FRAMES,
      &work,buffer,length,&object), ==, TC_TLV_OK);
  munit_assert_memory_equal(length,object.encoded.data,der);
  const size_t required = WORK - work;
  for (size_t budget = 0; budget <= required; ++budget) {
    work = budget; object = preserved;
    munit_assert_int(TC_LDS_read_content((TC_bytes){encoded,used},&limits,frames,FRAMES,
        &work,buffer,length,&object), ==, budget == required ? TC_TLV_OK : TC_TLV_LIMIT);
    if (budget < required) munit_assert_memory_equal(sizeof object,&object,&preserved);
  }
  for (size_t prefix = 0; prefix < used; ++prefix) {
    work = WORK; object = preserved;
    munit_assert_int(TC_LDS_read_content((TC_bytes){encoded,prefix},&limits,frames,FRAMES,
        &work,buffer,length,&object), !=, TC_TLV_OK);
    munit_assert_memory_equal(sizeof object,&object,&preserved);
  }
  work = WORK;
  munit_assert_int(TC_LDS_read_content((TC_bytes){encoded,used},&limits,frames,FRAMES,
      &work,buffer,length - 1,&object), ==, TC_TLV_LIMIT);
  work = WORK;
  munit_assert_int(TC_LDS_read_content((TC_bytes){encoded,used},&limits,frames,FRAMES,
      &work,encoded,sizeof encoded,&object), ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, WORK);
  munit_assert_memory_equal(sizeof object,&object,&preserved);
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult hash_check(const MunitParameter params[], void* context)
{
  /* SHA-256 of the three ASCII bytes abc. */
  static const uint8_t expected[] = {
    0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
    0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
  };
  uint8_t encoded[CAPACITY];
  TC_TLV_frame frames[FRAMES];
  const TC_TLV_limits limits = {CAPACITY,CAPACITY,128,FRAMES};
  TC_LDS_security_object object;
  TC_bytes digest;
  const size_t length = fixture(encoded,0,2,0,32,0);
  size_t work = WORK;
  munit_assert_int(TC_LDS_read((TC_bytes){encoded,length},&limits,frames,FRAMES,&work,&object), ==, TC_TLV_OK);
  munit_assert_int(TC_LDS_hash_find(&object,1,&limits,frames,FRAMES,&work,&digest), ==, TC_TLV_OK);
  memcpy(encoded + (size_t)(digest.data - encoded),expected,sizeof expected);
  work = WORK;
  munit_assert_int(TC_LDS_read((TC_bytes){encoded,length},&limits,frames,FRAMES,&work,&object), ==, TC_TLV_OK);
  TC_bytes parts[] = {{(const uint8_t*)"a",1},{NULL,0},{(const uint8_t*)"bc",2}};
  int matched = 7;
  work = WORK;
  munit_assert_int(TC_LDS_hash_check(&object,1,parts,3,&limits,frames,FRAMES,&work,&matched), ==,
      TC_ENABLE_SHA256 ? TC_TLV_OK : TC_TLV_UNSUPPORTED);
  munit_assert_int(matched, ==, TC_ENABLE_SHA256 ? 1 : 7);
#if TC_ENABLE_SHA256
  const size_t required = WORK - work;
  for (size_t budget = 0; budget <= required; ++budget) {
    work = budget; matched = 7;
    munit_assert_int(TC_LDS_hash_check(&object,1,parts,3,&limits,frames,FRAMES,&work,&matched), ==,
        budget == required ? TC_TLV_OK : TC_TLV_LIMIT);
    munit_assert_int(matched, ==, budget == required ? 1 : 7);
  }
  parts[2] = (TC_bytes){(const uint8_t*)"bd",2};
  work = WORK;
  munit_assert_int(TC_LDS_hash_check(&object,1,parts,3,&limits,frames,FRAMES,&work,&matched), ==, TC_TLV_OK);
  munit_assert_int(matched, ==, 0);
  work = WORK;
  munit_assert_int(TC_LDS_hash_check(&object,1,NULL,0,&limits,frames,FRAMES,&work,&matched), ==, TC_TLV_OK);
  munit_assert_int(matched, ==, 0);
#endif
  work = WORK; matched = 7;
  munit_assert_int(TC_LDS_hash_check(&object,3,parts,3,&limits,frames,FRAMES,&work,&matched), ==, TC_TLV_END);
  munit_assert_int(matched, ==, 7);
  parts[0] = (TC_bytes){(const uint8_t*)&matched,sizeof matched};
  work = WORK;
  munit_assert_int(TC_LDS_hash_check(&object,1,parts,3,&limits,frames,FRAMES,&work,&matched), ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, WORK);
  munit_assert_int(matched, ==, 7);
  (void)params; (void)context;
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/parsing",parsing,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/lookup",lookup,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/content",content_read,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/hash",hash_check,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/lds",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
