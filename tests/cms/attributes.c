/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/cms.h>
#include "munit.h"
#include <string.h>

static const uint8_t encoded[] = {
  0xa0,0x2c,
  0x30,0x10,0x06,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,9,4,0x31,3,4,1,0xaa,
  0x30,0x18,0x06,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,9,3,
  0x31,0x0b,0x06,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,1
};

static MunitResult attributes(const MunitParameter params[], void* user)
{
  TC_TLV_limits limits = {1024,1024,32,8};
  TC_TLV_frame frames[8];
  TC_CMS_signed_attributes result, saved;
  TC_bytes input = {encoded,sizeof encoded};
  size_t work = 1000, required;
  uint8_t bad[64];
  static const size_t positions[] = {0,1,2,17,35};
  static const uint8_t values[] = {0x31,0x80,0x31,5,4};
  (void)params; (void)user;
  munit_assert_int(TC_CMS_signed_attributes_read(input,TC_CMS_ATTRIBUTES_DER,&limits,frames,8,&work,&result), ==, TC_TLV_OK);
  required = 1000 - work;
  munit_assert_ptr_equal(result.content_type.data,encoded + 37);
  munit_assert_size(result.content_type.length, ==, 9);
  munit_assert_ptr_equal(result.message_digest.data,encoded + 19);
  munit_assert_size(result.message_digest.length, ==, 1);
  munit_assert_uint(result.signature_input[0].data[0], ==, 0x31);
  munit_assert_size(result.signature_input[0].length, ==, 1);
  munit_assert_ptr_equal(result.signature_input[1].data,encoded + 1);
  munit_assert_size(result.signature_input[1].length, ==, sizeof encoded - 1);
  munit_assert_uint(encoded[0], ==, 0xa0);
  memset(&result,0xa5,sizeof result); memcpy(&saved,&result,sizeof saved);
  for (size_t budget = 0; budget < required; ++budget) {
    work = budget;
    munit_assert_int(TC_CMS_signed_attributes_read(input,TC_CMS_ATTRIBUTES_DER,&limits,frames,8,&work,&result), ==, TC_TLV_LIMIT);
    munit_assert_memory_equal(sizeof result,&result,&saved);
  }
  for (size_t i = 0; i < sizeof positions / sizeof *positions; ++i) {
    memcpy(bad,encoded,sizeof encoded); bad[positions[i]] = values[i]; work = 1000;
    input = (TC_bytes){bad,sizeof encoded};
    munit_assert_int(TC_CMS_signed_attributes_read(input,TC_CMS_ATTRIBUTES_DER,&limits,frames,8,&work,&result), !=, TC_TLV_OK);
    munit_assert_memory_equal(sizeof result,&result,&saved);
  }
  /* Reverse the SET OF members without changing either attribute. */
  memcpy(bad,encoded,2); memcpy(bad + 2,encoded + 20,26); memcpy(bad + 28,encoded + 2,18);
  work = 1000;
  munit_assert_int(TC_CMS_signed_attributes_read(input,TC_CMS_ATTRIBUTES_DER,&limits,frames,8,&work,&result), ==, TC_TLV_INVALID);
  memcpy(bad,encoded,20); memcpy(bad + 20,encoded + 2,18); memcpy(bad + 38,encoded + 20,26);
  bad[1] = 62; input.length = 64; work = 1000;
  munit_assert_int(TC_CMS_signed_attributes_read(input,TC_CMS_ATTRIBUTES_DER,&limits,frames,8,&work,&result), ==, TC_TLV_INVALID);
  memcpy(bad,encoded,20); bad[1] = 18; input.length = 20; work = 1000;
  munit_assert_int(TC_CMS_signed_attributes_read(input,TC_CMS_ATTRIBUTES_DER,&limits,frames,8,&work,&result), ==, TC_TLV_INVALID);
  memcpy(bad,encoded,sizeof encoded); bad[14] = 6; input.length = sizeof encoded; work = 1000;
  munit_assert_int(TC_CMS_signed_attributes_read(input,TC_CMS_ATTRIBUTES_DER,&limits,frames,8,&work,&result), ==, TC_TLV_UNSUPPORTED);
  munit_assert_memory_equal(sizeof result,&result,&saved);
  input = (TC_bytes){encoded,sizeof encoded}; work = 1000;
  munit_assert_int(TC_CMS_signed_attributes_read(input,TC_CMS_ATTRIBUTES_DER,&limits,frames,0,&work,&result), ==, TC_TLV_LIMIT);
  limits.max_elements = 8; work = 1000;
  munit_assert_int(TC_CMS_signed_attributes_read(input,TC_CMS_ATTRIBUTES_DER,&limits,frames,8,&work,&result), ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof result,&result,&saved);
  return MUNIT_OK;
}

static MunitResult compatibility(const MunitParameter params[], void* user)
{
  const TC_TLV_limits limits = {1024,1024,64,8};
  TC_TLV_frame frames[8];
  TC_CMS_signed_attributes result, saved;
  uint8_t input[96];
  size_t work;
  (void)params; (void)user;
  /* Preserve reversed members and a nonminimal outer length in signature input. */
  input[0] = 0xa0; input[1] = 0x81; input[2] = 44;
  memcpy(input + 3,encoded + 20,26); memcpy(input + 29,encoded + 2,18);
  work = 1000;
  munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input,47},
      TC_CMS_ATTRIBUTES_BER_DEFINITE_ORDER,&limits,frames,8,&work,&result), ==, TC_TLV_OK);
  munit_assert_ptr_equal(result.signature_input[1].data,input + 1);
  munit_assert_size(result.signature_input[1].length, ==, 46);
  munit_assert_uint(result.signature_input[1].data[0], ==, 0x81);
  memset(&result,0xa5,sizeof result); memcpy(&saved,&result,sizeof saved);
  work = 1000;
  munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input,47},TC_CMS_ATTRIBUTES_DER,
      &limits,frames,8,&work,&result), !=, TC_TLV_OK);
  munit_assert_memory_equal(sizeof result,&result,&saved);
  for (unsigned kind = 0; kind < 5; ++kind) {
    size_t length = sizeof encoded;
    memcpy(input,encoded,length);
    if (kind == 0) { /* Duplicate messageDigest. */
      memcpy(input + length,encoded + 2,18); length += 18; input[1] += 18;
    } else if (kind == 1) { /* Missing contentType. */
      length = 20; input[1] = 18;
    } else if (kind == 2) { /* Indefinite attribute sequence inside a definite set. */
      memmove(input + 22,input + 20,26); input[3] = 0x80;
      input[20] = 0; input[21] = 0; length += 2; input[1] += 2;
    } else if (kind == 3) { /* Malformed OID contents. */
      input[14] = 0x80;
    } else { /* Constructed messageDigest is outside this compatibility mode. */
      input[17] = 0x24;
    }
    work = 1000;
    munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input,length},
        TC_CMS_ATTRIBUTES_BER_DEFINITE_ORDER,&limits,frames,8,&work,&result), !=, TC_TLV_OK);
    munit_assert_memory_equal(sizeof result,&result,&saved);
  }
  work = 1000;
  munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){encoded,sizeof encoded},
      (TC_CMS_attribute_encoding)99,&limits,frames,8,&work,&result), ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, 1000);
  munit_assert_memory_equal(sizeof result,&result,&saved);
  return MUNIT_OK;
}

static MunitResult signing_time(const MunitParameter params[], void* user)
{
  static const struct { unsigned tag; const char* text; unsigned year; } cases[] = {
    {0x17,"491231235959Z",2049}, {0x17,"500101000000Z",1950},
    {0x17,"240229000000Z",2024}, {0x17,"230229000000Z",0},
    {0x17,"241301000000Z",0}, {0x17,"240101000000z",0},
    {0x17,"2401010000Z",0}, {0x18,"20500101000000Z",2050},
    {0x18,"19490101000000Z",1949}, {0x18,"20260101000000Z",0},
    {0x18,"20500101000000.0Z",0}, {0x18,"00000101000000Z",0}
  };
  const TC_TLV_limits limits = {512,512,64,8};
  TC_TLV_frame frames[8];
  uint8_t input[128];
  TC_CMS_signed_attributes result, saved;
  (void)params; (void)user;
  for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
    size_t length = strlen(cases[i].text), work = 1000;
    uint8_t* attribute = input + sizeof encoded;
    memcpy(input,encoded,sizeof encoded);
    attribute[0] = 0x30; attribute[1] = (uint8_t)(length + 15);
    memcpy(attribute + 2,encoded + 22,11); attribute[12] = 5;
    attribute[13] = 0x31; attribute[14] = (uint8_t)(length + 2);
    attribute[15] = (uint8_t)cases[i].tag; attribute[16] = (uint8_t)length;
    memcpy(attribute + 17,cases[i].text,length);
    input[1] = (uint8_t)(sizeof encoded - 2 + length + 17);
    memset(&result,0xa5,sizeof result); memcpy(&saved,&result,sizeof saved);
    munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input,sizeof encoded + length + 17},TC_CMS_ATTRIBUTES_DER,
        &limits,frames,8,&work,&result), ==, cases[i].year ? TC_TLV_OK : TC_TLV_INVALID);
    if (cases[i].year) {
      munit_assert_true(result.has_signing_time);
      munit_assert_uint(result.signing_time.year, ==, cases[i].year);
      memcpy(attribute + length + 17,attribute,length + 17);
      input[1] += (uint8_t)(length + 17); work = 1000;
      memcpy(&result,&saved,sizeof result);
      munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input,sizeof encoded + 2 * (length + 17)},TC_CMS_ATTRIBUTES_DER,
          &limits,frames,8,&work,&result), ==, TC_TLV_INVALID);
      munit_assert_memory_equal(sizeof result,&result,&saved);
    } else munit_assert_memory_equal(sizeof result,&result,&saved);
  }
  return MUNIT_OK;
}

enum { ATTRIBUTE_BUFFER_BYTES = 256 };
static size_t with_attribute(uint8_t out[ATTRIBUTE_BUFFER_BYTES], TC_bytes oid,
    const uint8_t* value, size_t length,
    int duplicate, int multiple_values)
{
  uint8_t attribute[96];
  size_t value_bytes = length * (multiple_values ? 2u : 1u);
  const size_t header = 6 + oid.length;
  munit_assert_size(header + value_bytes, <=, sizeof attribute);
  attribute[0] = 0x30; attribute[1] = (uint8_t)(header - 2 + value_bytes);
  attribute[2] = 6; attribute[3] = (uint8_t)oid.length;
  memcpy(attribute + 4,oid.data,oid.length);
  attribute[header - 2] = 0x31; attribute[header - 1] = (uint8_t)value_bytes;
  memcpy(attribute + header,value,length);
  if (multiple_values) memcpy(attribute + header + length,value,length);
  TC_bytes members[4] = {{encoded + 2,18},{encoded + 20,26},
    {attribute,header + value_bytes},{attribute,header + value_bytes}};
  size_t count = duplicate ? 4 : 3, total = 2;
  for (size_t i = 1; i < count; ++i) {
    for (size_t j = i; j; --j) {
      size_t common = members[j].length < members[j - 1].length
        ? members[j].length : members[j - 1].length;
      if (memcmp(members[j].data,members[j - 1].data,common) >= 0) break;
      TC_bytes temporary = members[j]; members[j] = members[j - 1]; members[j - 1] = temporary;
    }
  }
  out[0] = 0xa0;
  for (size_t i = 0; i < count; ++i) {
    munit_assert_size(members[i].length, <, ATTRIBUTE_BUFFER_BYTES - total);
    memcpy(out + total,members[i].data,members[i].length); total += members[i].length;
  }
  munit_assert_size(total - 2, <=, 255);
  if (total - 2 >= 128) {
    memmove(out + 3,out + 2,total - 2);
    out[1] = 0x81; out[2] = (uint8_t)(total - 2);
    ++total;
  } else out[1] = (uint8_t)(total - 2);
  return total;
}

static MunitResult capabilities(const MunitParameter params[], void* user)
{
  static const uint8_t capability_oid[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,9,15};
  const TC_bytes oid = {capability_oid,sizeof capability_oid};
  static const struct { uint8_t bytes[16]; size_t length; int valid; } cases[] = {
    {{0x30,0},2,1},
    {{0x30,6,0x30,4,6,2,0x2a,3},8,1},
    {{0x30,8,0x30,6,6,2,0x2a,3,5,0},10,1},
    {{0x30,10,0x30,8,6,2,0x2a,3,5,0,5,0},12,0},
    {{0x30,6,0x30,4,6,2,0x2a,0x80},8,0},
    {{0x30,6,0x31,4,6,2,0x2a,3},8,0},
    {{0x31,0},2,0},
    {{0x30,2,0x30,0},4,0},
    {{0x30,3,6,1,0x2a},5,0},
    {{0x30,0x80,0,0},4,0}
  };
  const TC_TLV_limits limits = {512,512,64,8};
  TC_TLV_frame frames[8];
  uint8_t input[ATTRIBUTE_BUFFER_BYTES];
  TC_CMS_signed_attributes result, saved;
  (void)params; (void)user;
  memset(&saved,0xa5,sizeof saved);
  for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
    for (unsigned mode = 0; mode < 2; ++mode) {
      size_t length = with_attribute(input,oid,cases[i].bytes,cases[i].length,0,0);
      size_t work = 2000;
      memcpy(&result,&saved,sizeof result);
      munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input,length},
          (TC_CMS_attribute_encoding)mode,&limits,frames,8,&work,&result), ==,
          cases[i].valid ? TC_TLV_OK : TC_TLV_INVALID);
      if (!cases[i].valid) {
        munit_assert_memory_equal(sizeof result,&result,&saved);
        continue;
      }
      munit_assert_size(result.smime_capabilities.length, ==, cases[i].length);
      munit_assert_memory_equal(cases[i].length,result.smime_capabilities.data,cases[i].bytes);
      munit_assert_true(result.smime_capabilities.data >= input);
      munit_assert_true(result.smime_capabilities.data + cases[i].length <= input + length);
      size_t required = 2000 - work;
      for (size_t budget = 0; budget < required; ++budget) {
        work = budget; memcpy(&result,&saved,sizeof result);
        munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input,length},
            (TC_CMS_attribute_encoding)mode,&limits,frames,8,&work,&result), ==, TC_TLV_LIMIT);
        munit_assert_memory_equal(sizeof result,&result,&saved);
      }
      for (unsigned duplicate = 0; duplicate < 2; ++duplicate) {
        length = with_attribute(input,oid,cases[i].bytes,cases[i].length,duplicate,!duplicate);
        work = 2000;
        munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input,length},
            (TC_CMS_attribute_encoding)mode,&limits,frames,8,&work,&result), ==, TC_TLV_INVALID);
        munit_assert_memory_equal(sizeof result,&result,&saved);
      }
    }
  }
  return MUNIT_OK;
}

static MunitResult signer_name(const MunitParameter params[], void* user)
{
  static const uint8_t name_oid[] = {0x60,0x86,0x48,1,0x65,3,6,5};
  static const uint8_t name[] = {0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A'};
  const TC_bytes oid = {name_oid,sizeof name_oid};
  const TC_TLV_limits limits = {512,512,64,8};
  TC_TLV_frame frames[8];
  uint8_t input[ATTRIBUTE_BUFFER_BYTES], bad_name[sizeof name];
  TC_CMS_signed_attributes result, saved;
  (void)params; (void)user;
  memset(&saved,0xa5,sizeof saved);
  for (unsigned mode = 0; mode < 2; ++mode) {
    size_t length = with_attribute(input,oid,name,sizeof name,0,0), work = 2000;
    munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input,length},
        (TC_CMS_attribute_encoding)mode,&limits,frames,8,&work,&result), ==, TC_TLV_OK);
    munit_assert_size(result.signer_name.length, ==, sizeof name);
    munit_assert_memory_equal(sizeof name,result.signer_name.data,name);
    munit_assert_true(result.signer_name.data >= input && result.signer_name.data + sizeof name <= input + length);
    size_t required = 2000 - work;
    for (size_t budget = 0; budget < required; ++budget) {
      work = budget; memcpy(&result,&saved,sizeof result);
      munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input,length},
          (TC_CMS_attribute_encoding)mode,&limits,frames,8,&work,&result), ==, TC_TLV_LIMIT);
      munit_assert_memory_equal(sizeof result,&result,&saved);
    }
    for (unsigned variant = 0; variant < 5; ++variant) {
      memcpy(bad_name,name,sizeof name);
      if (variant == 2) bad_name[2] = 0x30; /* RDN requires SET OF. */
      if (variant == 3) bad_name[10] = 0x80; /* Unfinished OID arc. */
      if (variant == 4) bad_name[13] = 0xff; /* Invalid UTF-8. */
      length = with_attribute(input,oid,bad_name,sizeof bad_name,variant == 0,variant == 1);
      work = 2000; memcpy(&result,&saved,sizeof result);
      munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input,length},
          (TC_CMS_attribute_encoding)mode,&limits,frames,8,&work,&result), ==, TC_TLV_INVALID);
      munit_assert_memory_equal(sizeof result,&result,&saved);
    }
  }
  return MUNIT_OK;
}

static MunitResult identifier_octets(const MunitParameter params[], void* user)
{
  enum { FASCN_BYTES = 25, WORK = 4000 };
  static const uint8_t piv[] = {0x60,0x86,0x48,1,0x65,3,6,6};
  static const uint8_t twic[] = {0x2b,6,1,4,1,0x81,0xe3,0x52,6,6};
  static const uint8_t uuid[] = {0x2b,6,1,1,0x10,4};
  const TC_bytes oids[] = {{piv,sizeof piv},{twic,sizeof twic},{uuid,sizeof uuid}};
  const TC_TLV_limits limits = {512,512,64,8};
  TC_TLV_frame frames[8];
  uint8_t input[ATTRIBUTE_BUFFER_BYTES], value[32] = {4,FASCN_BYTES};
  TC_CMS_signed_attributes parsed, saved;
  memset(&saved,0xa5,sizeof saved);
  for (unsigned ns = 0; ns < sizeof oids / sizeof *oids; ++ns) {
    const uint8_t bytes = ns == 2 ? 16 : FASCN_BYTES;
    for (unsigned mode = 0; mode < 2; ++mode) {
      enum { VALID, DUPLICATE, MULTIPLE_VALUES, SHORT, LONG, WRONG_TAG, FRAGMENTED,
             INDEFINITE, CASE_COUNT };
      for (unsigned kind = 0; kind < CASE_COUNT; ++kind) {
        memset(value,0,sizeof value); value[0] = 4; value[1] = bytes;
        size_t value_length = bytes + 2;
        if (kind == SHORT) { --value[1]; --value_length; }
        if (kind == LONG) { ++value[1]; ++value_length; }
        if (kind == WRONG_TAG) value[0] = 0x0c;
        if (kind == FRAGMENTED) {
          value[0] = 0x24; value[1] = bytes + 4;
          value[2] = 4; value[3] = 1;
          value[5] = 4; value[6] = bytes - 1;
          value_length = bytes + 6;
        }
        if (kind == INDEFINITE) {
          value[0] = 0x24; value[1] = 0x80; value[2] = 4; value[3] = bytes;
          value_length = bytes + 6;
        }
        size_t length = with_attribute(input,oids[ns],value,value_length,
            kind == DUPLICATE,kind == MULTIPLE_VALUES), work = WORK;
        const int valid = kind == VALID || (kind == FRAGMENTED && mode == TC_CMS_ATTRIBUTES_BER_DEFINITE_ORDER);
        memcpy(&parsed,&saved,sizeof parsed);
        munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input,length},
            (TC_CMS_attribute_encoding)mode,&limits,frames,8,&work,&parsed), ==,
            valid ? TC_TLV_OK : TC_TLV_INVALID);
        if (!valid) { munit_assert_memory_equal(sizeof parsed,&parsed,&saved); continue; }
        const TC_bytes found = ns == 2 ? parsed.entry_uuid_octets : parsed.fascn_octets;
        if (ns < 2) munit_assert_memory_equal(oids[ns].length,parsed.fascn_oid.data,oids[ns].data);
        munit_assert_size(found.length, ==, value_length);
        munit_assert_memory_equal(value_length,found.data,value);
        munit_assert_true(found.data >= input && found.data + value_length <= input + length);
        const size_t required = WORK - work;
        for (size_t budget = 0; budget < required; ++budget) {
          work = budget; memcpy(&parsed,&saved,sizeof parsed);
          munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input,length},
              (TC_CMS_attribute_encoding)mode,&limits,frames,8,&work,&parsed), ==, TC_TLV_LIMIT);
          munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
        }
      }
      if (ns == 1) {
        /* Replace the first TWIC OID in a duplicate pair with its PIV equivalent. */
        memset(value,0,sizeof value); value[0] = 4; value[1] = FASCN_BYTES;
        size_t length = with_attribute(input,oids[ns],value,FASCN_BYTES + 2,1,0);
        const size_t attribute = 3 + sizeof encoded - 2;
        const size_t oid_value = attribute + 4, removed = sizeof twic - sizeof piv;
        munit_assert_uint8(input[1], ==, 0x81);
        memcpy(input + oid_value,piv,sizeof piv);
        memmove(input + oid_value + sizeof piv,input + oid_value + sizeof twic,
            length - oid_value - sizeof twic);
        input[attribute + 1] -= (uint8_t)removed;
        input[attribute + 3] = sizeof piv;
        input[2] -= (uint8_t)removed;
        length -= removed;
        size_t work = WORK;
        memcpy(&parsed,&saved,sizeof parsed);
        munit_assert_int(TC_CMS_signed_attributes_read((TC_bytes){input,length},
            (TC_CMS_attribute_encoding)mode,&limits,frames,8,&work,&parsed), ==, TC_TLV_INVALID);
        munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
      }
    }
  }
  (void)params; (void)user;
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/required",attributes,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/compatibility",compatibility,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/signing-time",signing_time,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/capabilities",capabilities,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/signer-name",signer_name,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/identifier-octets",identifier_octets,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/cms/attributes",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
