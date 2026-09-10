/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../src/cms_internal.h"
#include "../../src/pki_tree_internal.h"
#include "../../src/pki_extensions_internal.h"
#include "source.h"
#include "../../examples/cms_reader.h"
#include "munit.h"
#include <string.h>

static const uint8_t signer[] = {
  0x30,21,2,1,3,0x80,1,0xaa,
  0x30,4,6,2,0x2a,3,0x30,4,6,2,0x2a,3,4,1,0xbb
};

static MunitResult identifiers(const MunitParameter params[], void* user)
{
  static const uint8_t issuer_id[] = {
    0x30,17,0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A',2,1,1
  };
  const TC_TLV_limits limits = {256,256,64,8};
  TC_TLV_frame frames[8];
  tc_cms_signer_info result, saved;
  uint8_t input[64];
  size_t work = 1000;
  (void)params; (void)user;
  munit_assert_int(TC_CMS_signer_info_read((TC_bytes){signer,sizeof signer},TC_TLV_DER,
      &limits,frames,8,&work,&result), ==, TC_TLV_OK);
  munit_assert_uint(result.version, ==, 3);
  munit_assert_ptr_equal(result.encoded.data,signer);
  munit_assert_size(result.encoded.length, ==, sizeof signer);
  munit_assert_ptr_equal(result.subject_key_id.data,signer + 5);
  munit_assert_ptr_equal(result.signature.data,signer + 20);
  munit_assert_null(result.issuer.data);
  munit_assert_null(result.signed_attributes.data);
  munit_assert_null(result.unsigned_attributes.data);
  ExampleCMSWorkspace example;
  munit_assert_int(example_read_cms_signer((TC_bytes){signer,sizeof signer},1000,
      &example,&result), ==, TC_TLV_OK);
  munit_assert_ptr_equal(result.signature.data,signer + 20);
  memcpy(input,signer,5); input[1] = 37; input[4] = 1;
  memcpy(input + 5,issuer_id,sizeof issuer_id);
  memcpy(input + 24,signer + 8,sizeof signer - 8); work = 1000;
  munit_assert_int(TC_CMS_signer_info_read((TC_bytes){input,39},TC_TLV_DER,
      &limits,frames,8,&work,&result), ==, TC_TLV_OK);
  munit_assert_uint(result.version, ==, 1);
  munit_assert_ptr_equal(result.issuer.data,input + 7);
  munit_assert_size(result.issuer.length, ==, 14);
  munit_assert_ptr_equal(result.serial.data,input + 23);
  munit_assert_false(result.serial_negative);
  munit_assert_null(result.subject_key_id.data);
  memset(&result,0xa5,sizeof result); memcpy(&saved,&result,sizeof saved);
  input[4] = 3; work = 1000;
  munit_assert_int(TC_CMS_signer_info_read((TC_bytes){input,39},TC_TLV_DER,
      &limits,frames,8,&work,&result), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof result,&result,&saved);
  return MUNIT_OK;
}

static MunitResult attributes(const MunitParameter params[], void* user)
{
  /* Unknown attributes are retained here; their semantics are checked separately. */
  static const uint8_t attribute[] = {0xa0,11,0x30,9,6,2,0x2a,3,0x31,3,4,1,0xcc};
  const TC_TLV_limits limits = {256,256,64,8};
  TC_TLV_frame frames[8];
  tc_cms_signer_info result, saved;
  uint8_t input[64];
  (void)params; (void)user;
  for (unsigned mask = 0; mask < 4; ++mask) {
    size_t length = 14, signed_offset = 0, unsigned_offset = 0, work = 1000;
    memcpy(input,signer,14);
    if (mask & 1) {
      signed_offset = length;
      memcpy(input + length,attribute,sizeof attribute); length += sizeof attribute;
    }
    memcpy(input + length,signer + 14,sizeof signer - 14); length += sizeof signer - 14;
    if (mask & 2) {
      unsigned_offset = length;
      memcpy(input + length,attribute,sizeof attribute); input[length] = 0xa1;
      length += sizeof attribute;
    }
    input[1] = (uint8_t)(length - 2);
    munit_assert_int(TC_CMS_signer_info_read((TC_bytes){input,length},TC_TLV_DER,
        &limits,frames,8,&work,&result), ==, TC_TLV_OK);
    munit_assert_ptr_equal(result.signed_attributes.data,signed_offset ? input + signed_offset : NULL);
    munit_assert_ptr_equal(result.unsigned_attributes.data,unsigned_offset ? input + unsigned_offset : NULL);
    munit_assert_size(result.signed_attributes.length, ==, signed_offset ? sizeof attribute : 0);
    munit_assert_size(result.unsigned_attributes.length, ==, unsigned_offset ? sizeof attribute : 0);
    memset(&result,0xa5,sizeof result); memcpy(&saved,&result,sizeof saved);
    /* A valid field after unsignedAttrs still violates the SignerInfo schema. */
    input[length] = 5; input[length + 1] = 0; input[1] += 2; work = 1000;
    munit_assert_int(TC_CMS_signer_info_read((TC_bytes){input,length + 2},TC_TLV_DER,
        &limits,frames,8,&work,&result), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof result,&result,&saved);
    input[1] -= 2;
    if (signed_offset || unsigned_offset) {
      size_t offset = signed_offset ? signed_offset : unsigned_offset;
      input[offset] = signed_offset ? 0xa1 : 0xa0; work = 1000;
      munit_assert_int(TC_CMS_signer_info_read((TC_bytes){input,length},TC_TLV_DER,
          &limits,frames,8,&work,&result), ==, TC_TLV_INVALID);
      munit_assert_memory_equal(sizeof result,&result,&saved);
    }
  }
  return MUNIT_OK;
}

static MunitResult malformed(const MunitParameter params[], void* user)
{
  enum { WORK_BUDGET = 1024 };
  static const size_t offsets[] = {4,5,8,14,20};
  static const uint8_t replacements[] = {1,0xa0,0x31,0x31,3};
  const TC_TLV_limits limits = {256,256,64,8};
  TC_TLV_frame frames[8];
  tc_cms_signer_info result, saved;
  uint8_t input[sizeof signer];
  size_t work;
  (void)params; (void)user;
  memset(&result,0xa5,sizeof result); memcpy(&saved,&result,sizeof saved);
  for (size_t length = 0; length < sizeof signer; ++length) {
    work = 1000;
    munit_assert_int(TC_CMS_signer_info_read((TC_bytes){signer,length},TC_TLV_DER,
        &limits,frames,8,&work,&result), !=, TC_TLV_OK);
    munit_assert_memory_equal(sizeof result,&result,&saved);
  }
  for (size_t i = 0; i < sizeof offsets / sizeof *offsets; ++i) {
    memcpy(input,signer,sizeof signer); input[offsets[i]] = replacements[i]; work = 1000;
    munit_assert_int(TC_CMS_signer_info_read((TC_bytes){input,sizeof input},TC_TLV_DER,
        &limits,frames,8,&work,&result), !=, TC_TLV_OK);
    munit_assert_memory_equal(sizeof result,&result,&saved);
  }
  tc_cms_signer_info valid;
  work = WORK_BUDGET;
  munit_assert_int(TC_CMS_signer_info_read((TC_bytes){signer,sizeof signer},TC_TLV_DER,
      &limits,frames,8,&work,&valid), ==, TC_TLV_OK);
  const size_t required = WORK_BUDGET - work;
  for (size_t budget = 0; budget < required; ++budget) {
    work = budget;
    munit_assert_int(TC_CMS_signer_info_read((TC_bytes){signer,sizeof signer},TC_TLV_DER,
        &limits,frames,8,&work,&result), ==, TC_TLV_LIMIT);
    munit_assert_memory_equal(sizeof result,&result,&saved);
  }
  work = required;
  munit_assert_int(TC_CMS_signer_info_read((TC_bytes){signer,sizeof signer},TC_TLV_DER,
      &limits,frames,8,&work,&result), ==, TC_TLV_OK);
  munit_assert_size(work, ==, 0);
  return MUNIT_OK;
}

static MunitResult ber_fields(const MunitParameter params[], void* user)
{
  enum { FRAME_CAPACITY = 8, WORK_BUDGET = 4096, SKI_OFFSET = 5, SKI_CHILD_OFFSET = 7 };
  uint8_t encoded[] = {
    0x30,0x80,2,1,3,
    0xa0,0x80,4,1,0xaa,0,0,
    0x30,0x80,6,2,0x2a,3,0,0,
    0x30,0x80,6,2,0x2a,3,0,0,
    0x24,0x80,4,1,0xbb,0,0,0,0
  };
  static const uint8_t issuer[] = {
    0x30,0x80,2,1,1,
    0x30,0x80,
      0x30,0x80,0x31,0x80,0x30,0x80,6,3,0x55,4,3,0x0c,1,'A',0,0,0,0,0,0,
      2,1,1,0,0,
    0x30,0x80,6,2,0x2a,3,0,0,
    0x30,0x80,6,2,0x2a,3,0,0,
    4,1,0xbb,0,0
  };
  const TC_TLV_limits limits = {WORK_BUDGET,WORK_BUDGET,64,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  tc_cms_signer_info result, saved;
  size_t work = WORK_BUDGET;
  (void)params; (void)user;
  munit_assert_int(TC_CMS_signer_info_read((TC_bytes){encoded,sizeof encoded},TC_TLV_BER,
      &limits,frames,FRAME_CAPACITY,&work,&result), ==, TC_TLV_OK);
  munit_assert_ptr_equal(result.subject_key_id.data,encoded + SKI_OFFSET);
  munit_assert_uint(result.subject_key_id.data[0], ==, 0xa0);
  munit_assert_uint(result.signature.data[0], ==, 0x24);
  munit_assert_size(result.signature.length, ==, 7);
  munit_assert_size(result.digest_algorithm.oid.length, ==, 2);
  const size_t required = WORK_BUDGET - work;
  memset(&result,0xa5,sizeof result); memcpy(&saved,&result,sizeof saved);
  for (size_t budget = 0; budget < required; ++budget) {
    work = budget;
    munit_assert_int(TC_CMS_signer_info_read((TC_bytes){encoded,sizeof encoded},TC_TLV_BER,
        &limits,frames,FRAME_CAPACITY,&work,&result), ==, TC_TLV_LIMIT);
    munit_assert_memory_equal(sizeof result,&result,&saved);
  }
  for (size_t length = 0; length < sizeof encoded; ++length) {
    work = WORK_BUDGET;
    munit_assert_int(TC_CMS_signer_info_read((TC_bytes){encoded,length},TC_TLV_BER,
        &limits,frames,FRAME_CAPACITY,&work,&result), !=, TC_TLV_OK);
    munit_assert_memory_equal(sizeof result,&result,&saved);
  }
  work = WORK_BUDGET;
  munit_assert_int(TC_CMS_signer_info_read((TC_bytes){encoded,sizeof encoded},TC_TLV_DER,
      &limits,frames,FRAME_CAPACITY,&work,&result), ==, TC_TLV_INVALID);
  encoded[SKI_CHILD_OFFSET] = 2; work = WORK_BUDGET;
  munit_assert_int(TC_CMS_signer_info_read((TC_bytes){encoded,sizeof encoded},TC_TLV_BER,
      &limits,frames,FRAME_CAPACITY,&work,&result), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof result,&result,&saved);
  encoded[SKI_CHILD_OFFSET] = 4;
  work = required;
  munit_assert_int(TC_CMS_signer_info_read((TC_bytes){encoded,sizeof encoded},TC_TLV_BER,
      &limits,frames,FRAME_CAPACITY,&work,&result), ==, TC_TLV_OK);
  munit_assert_size(work, ==, 0);
  work = WORK_BUDGET;
  munit_assert_int(TC_CMS_signer_info_read((TC_bytes){issuer,sizeof issuer},TC_TLV_BER,
      &limits,frames,FRAME_CAPACITY,&work,&result), ==, TC_TLV_OK);
  munit_assert_uint(result.version, ==, 1);
  munit_assert_null(result.subject_key_id.data);
  munit_assert_size(result.serial.length, ==, 1);
  munit_assert_uint(result.serial.data[0], ==, 1);
  munit_assert_false(result.serial_negative);
  munit_assert_uint(result.issuer.data[0], ==, 0x30);
  munit_assert_uint(result.issuer.data[1], ==, 0x80);
  {
    enum { RDN_TAG = 9, OID_LAST = 17, VALUE_TAG = 18, VALUE_BYTE = 20 };
    uint8_t invalid[sizeof issuer];
    const size_t issuer_work = WORK_BUDGET - work;
    memcpy(&saved,&result,sizeof saved);
    for (size_t budget = 0; budget < issuer_work; ++budget) {
      work = budget;
      munit_assert_int(TC_CMS_signer_info_read((TC_bytes){issuer,sizeof issuer},TC_TLV_BER,
          &limits,frames,FRAME_CAPACITY,&work,&result), ==, TC_TLV_LIMIT);
      munit_assert_memory_equal(sizeof result,&result,&saved);
    }
    for (size_t length = 0; length < sizeof issuer; ++length) {
      work = WORK_BUDGET;
      munit_assert_int(TC_CMS_signer_info_read((TC_bytes){issuer,length},TC_TLV_BER,
          &limits,frames,FRAME_CAPACITY,&work,&result), !=, TC_TLV_OK);
      munit_assert_memory_equal(sizeof result,&result,&saved);
    }
    const struct { size_t offset; uint8_t value; } changes[] = {
      {RDN_TAG,0x30}, {OID_LAST,0x80}, {VALUE_TAG,2}, {VALUE_BYTE,0xff}
    };
    for (size_t i = 0; i < sizeof changes / sizeof changes[0]; ++i) {
      memcpy(invalid,issuer,sizeof invalid);
      invalid[changes[i].offset] = changes[i].value;
      work = WORK_BUDGET;
      munit_assert_int(TC_CMS_signer_info_read((TC_bytes){invalid,sizeof invalid},TC_TLV_BER,
          &limits,frames,FRAME_CAPACITY,&work,&result), ==, TC_TLV_INVALID);
      munit_assert_memory_equal(sizeof result,&result,&saved);
    }
  }
  return MUNIT_OK;
}

static MunitResult issuer_schema(const MunitParameter params[], void* user)
{
  enum { FRAME_CAPACITY = 8, WORK_BUDGET = 4096 };
  static const uint8_t unsorted[] = {
    0x30,22,0x31,20,
    0x30,8,6,3,0x55,4,3,0x0c,1,'B',
    0x30,8,6,3,0x55,4,3,0x0c,1,'A'
  };
  static const uint8_t empty_rdn[] = {0x30,2,0x31,0};
  static const uint8_t constructed[] = {
    0x30,14,0x31,12,0x30,10,6,3,0x55,4,3,0x2c,3,0x0c,1,'A'
  };
  TC_TLV_limits limits = {WORK_BUDGET,WORK_BUDGET,64,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  size_t work = WORK_BUDGET;
  const tc_pki_tree_workspace workspace = {frames,FRAME_CAPACITY,&work};
  (void)params; (void)user;
  munit_assert_int(tc_pki_tree_name((TC_bytes){unsorted,sizeof unsorted},TC_TLV_BER,
      &limits,&workspace), ==, TC_TLV_OK);
  work = WORK_BUDGET;
  munit_assert_int(tc_pki_tree_name((TC_bytes){unsorted,sizeof unsorted},TC_TLV_DER,
      &limits,&workspace), ==, TC_TLV_INVALID);
  work = WORK_BUDGET;
  munit_assert_int(tc_pki_tree_name((TC_bytes){empty_rdn,sizeof empty_rdn},TC_TLV_BER,
      &limits,&workspace), ==, TC_TLV_INVALID);
  work = WORK_BUDGET;
  munit_assert_int(tc_pki_tree_name((TC_bytes){constructed,sizeof constructed},TC_TLV_BER,
      &limits,&workspace), ==, TC_TLV_INVALID);
  limits.max_elements = 3; work = WORK_BUDGET;
  munit_assert_int(tc_pki_tree_name((TC_bytes){unsorted,sizeof unsorted},TC_TLV_BER,
      &limits,&workspace), ==, TC_TLV_LIMIT);
  limits.max_elements = 64; limits.max_depth = 2; work = WORK_BUDGET;
  munit_assert_int(tc_pki_tree_name((TC_bytes){unsorted,sizeof unsorted},TC_TLV_BER,
      &limits,&workspace), ==, TC_TLV_LIMIT);
  return MUNIT_OK;
}

static MunitResult issuer_matching(const MunitParameter params[], void* user)
{
  enum { FRAME_CAPACITY = 8, SCALAR_CAPACITY = 32, ATTRIBUTE_CAPACITY = 4,
    WORK_BUDGET = 16384, FIRST_VALUE = 14, LAST_VALUE = 26 };
  static const uint8_t der[] = {
    0x30,22,0x31,20,
    0x30,8,6,3,0x55,4,3,0x0c,1,'A',
    0x30,8,6,3,0x55,4,3,0x0c,1,'B'
  };
  uint8_t ber[] = {
    0x30,0x80,0x31,0x80,
    0x30,0x80,6,3,0x55,4,3,0x0c,0x81,1,'b',0,0,
    0x30,0x80,6,3,0x55,4,3,0x13,1,'A',0,0,0,0,0,0
  };
  const TC_bytes left = {der,sizeof der}, right = {ber,sizeof ber};
  const TC_TLV_limits limits = {WORK_BUDGET,WORK_BUDGET,64,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  uint32_t a[SCALAR_CAPACITY], b[SCALAR_CAPACITY];
  uint8_t flags[ATTRIBUTE_CAPACITY];
  const TC_X509_name_workspace names = {a,b,SCALAR_CAPACITY,flags,ATTRIBUTE_CAPACITY};
  size_t work = WORK_BUDGET;
  tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  int matched = -1;
  (void)params; (void)user;
  munit_assert_int(tc_pki_name_equal(left,TC_TLV_DER,right,TC_TLV_BER,
      &limits,&names,&tree,&matched), ==, TC_TLV_OK);
  munit_assert_int(matched, ==, 1);
  const size_t required = WORK_BUDGET - work;
  for (size_t budget = 0; budget < required; ++budget) {
    work = budget; matched = -1;
    munit_assert_int(tc_pki_name_equal(left,TC_TLV_DER,right,TC_TLV_BER,
        &limits,&names,&tree,&matched), ==, TC_TLV_LIMIT);
    munit_assert_int(matched, ==, -1);
  }
  work = required;
  munit_assert_int(tc_pki_name_equal(left,TC_TLV_DER,right,TC_TLV_BER,
      &limits,&names,&tree,&matched), ==, TC_TLV_OK);
  munit_assert_size(work, ==, 0);
  munit_assert_int(matched, ==, 1);
  for (size_t length = 0; length < sizeof ber; ++length) {
    work = WORK_BUDGET; matched = -1;
    munit_assert_int(tc_pki_name_equal(left,TC_TLV_DER,(TC_bytes){ber,length},TC_TLV_BER,
        &limits,&names,&tree,&matched), !=, TC_TLV_OK);
    munit_assert_int(matched, ==, -1);
  }
  work = WORK_BUDGET;
  munit_assert_int(tc_pki_name_equal(right,TC_TLV_BER,left,TC_TLV_DER,
      &limits,&names,&tree,&matched), ==, TC_TLV_OK);
  munit_assert_int(matched, ==, 1);
  work = WORK_BUDGET; matched = -1;
  munit_assert_int(tc_pki_name_equal(left,TC_TLV_DER,right,TC_TLV_DER,
      &limits,&names,&tree,&matched), ==, TC_TLV_INVALID);
  munit_assert_int(matched, ==, -1);
  ber[FIRST_VALUE] = 'a'; work = WORK_BUDGET;
  munit_assert_int(tc_pki_name_equal(left,TC_TLV_DER,right,TC_TLV_BER,
      &limits,&names,&tree,&matched), ==, TC_TLV_OK);
  munit_assert_int(matched, ==, 0);
  ber[LAST_VALUE] = 0xff; work = WORK_BUDGET; matched = -1;
  munit_assert_int(tc_pki_name_equal(left,TC_TLV_DER,right,TC_TLV_BER,
      &limits,&names,&tree,&matched), ==, TC_TLV_INVALID);
  munit_assert_int(matched, ==, -1);
  TC_X509_name_workspace aliased = names;
  aliased.left = (uint32_t*)frames; work = WORK_BUDGET;
  munit_assert_int(tc_pki_name_equal(left,TC_TLV_DER,right,TC_TLV_BER,
      &limits,&aliased,&tree,&matched), ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, WORK_BUDGET);
  munit_assert_int(matched, ==, -1);
  return MUNIT_OK;
}

static size_t chunked_name(uint8_t* output, unsigned tag, TC_bytes value, size_t split)
{
  static const uint8_t prefix[] = {0x30,0x80,0x31,0x80,0x30,0x80,6,3,0x55,4,3};
  enum { CLOSING_BYTES = 10 };
  size_t used = sizeof prefix;
  munit_assert_size(split, <=, value.length);
  munit_assert_size(value.length, <, 128);
  memcpy(output,prefix,sizeof prefix);
  output[used++] = (uint8_t)(tag | 0x20); output[used++] = 0x80;
  output[used++] = 0x24; output[used++] = 0x80;
  output[used++] = 4; output[used++] = (uint8_t)split;
  memcpy(output + used,value.data,split); used += split;
  output[used++] = 4; output[used++] = (uint8_t)(value.length - split);
  memcpy(output + used,value.data + split,value.length - split); used += value.length - split;
  memset(output + used,0,CLOSING_BYTES);
  return used + CLOSING_BYTES;
}

static MunitResult constructed_names(const MunitParameter params[], void* user)
{
  enum { ENCODED_CAPACITY = 64, FRAME_CAPACITY = 8, SCALAR_CAPACITY = 32,
    ATTRIBUTE_CAPACITY = 4, WORK_BUDGET = 16384, OID_LAST = 10, CHILD_TAG = 15 };
  static const uint8_t utf8[] = {'A',0xcc,0x8a};
  static const uint8_t bmp[] = {0,'A',3,0x0a};
  static const uint8_t universal[] = {0,0,0,'A',0,0,3,0x0a};
  static const uint8_t der[] = {0x30,13,0x31,11,0x30,9,6,3,0x55,4,3,0x0c,2,0xc3,0xa5};
  static const struct { unsigned tag; const uint8_t* bytes; size_t length; } cases[] = {
    {0x0c,utf8,sizeof utf8}, {0x1e,bmp,sizeof bmp}, {0x1c,universal,sizeof universal}
  };
  const TC_TLV_limits limits = {WORK_BUDGET,WORK_BUDGET,64,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  uint32_t a[SCALAR_CAPACITY], b[SCALAR_CAPACITY];
  uint8_t flags[ATTRIBUTE_CAPACITY], encoded[ENCODED_CAPACITY];
  const TC_X509_name_workspace names = {a,b,SCALAR_CAPACITY,flags,ATTRIBUTE_CAPACITY};
  size_t work = WORK_BUDGET;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  int matched;
  (void)params; (void)user;
  for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
    for (size_t split = 0; split <= cases[i].length; ++split) {
      const size_t length = chunked_name(encoded,cases[i].tag,
          (TC_bytes){cases[i].bytes,cases[i].length},split);
      work = WORK_BUDGET; matched = -1;
      munit_assert_int(tc_pki_name_equal((TC_bytes){der,sizeof der},TC_TLV_DER,
          (TC_bytes){encoded,length},TC_TLV_BER,&limits,&names,&tree,&matched), ==, TC_TLV_OK);
      munit_assert_int(matched, ==, 1);
      const size_t required = WORK_BUDGET - work;
      for (size_t budget = 0; budget < required; ++budget) {
        work = budget; matched = -1;
        munit_assert_int(tc_pki_name_equal((TC_bytes){der,sizeof der},TC_TLV_DER,
            (TC_bytes){encoded,length},TC_TLV_BER,&limits,&names,&tree,&matched), ==, TC_TLV_LIMIT);
        munit_assert_int(matched, ==, -1);
      }
      work = required;
      munit_assert_int(tc_pki_name_equal((TC_bytes){der,sizeof der},TC_TLV_DER,
          (TC_bytes){encoded,length},TC_TLV_BER,&limits,&names,&tree,&matched), ==, TC_TLV_OK);
      munit_assert_size(work, ==, 0);
      for (size_t prefix = 0; prefix < length; ++prefix) {
        work = WORK_BUDGET; matched = -1;
        munit_assert_int(tc_pki_name_equal((TC_bytes){der,sizeof der},TC_TLV_DER,
            (TC_bytes){encoded,prefix},TC_TLV_BER,&limits,&names,&tree,&matched), !=, TC_TLV_OK);
        munit_assert_int(matched, ==, -1);
      }
      encoded[CHILD_TAG] = (uint8_t)cases[i].tag; work = WORK_BUDGET;
      munit_assert_int(tc_pki_tree_name((TC_bytes){encoded,length},TC_TLV_BER,
          &limits,&tree), ==, TC_TLV_INVALID);
    }
  }
  {
    static const uint8_t country[] = {'U','S'};
    size_t length = chunked_name(encoded,0x13,(TC_bytes){country,sizeof country},1);
    encoded[OID_LAST] = 6; work = WORK_BUDGET;
    munit_assert_int(tc_pki_tree_name((TC_bytes){encoded,length},TC_TLV_BER,
        &limits,&tree), ==, TC_TLV_OK);
    length = chunked_name(encoded,0x13,(TC_bytes){country,1},1);
    encoded[OID_LAST] = 6; work = WORK_BUDGET;
    munit_assert_int(tc_pki_tree_name((TC_bytes){encoded,length},TC_TLV_BER,
        &limits,&tree), ==, TC_TLV_INVALID);
    length = chunked_name(encoded,0x0c,(TC_bytes){utf8,sizeof utf8 - 1},1);
    work = WORK_BUDGET;
    munit_assert_int(tc_pki_tree_name((TC_bytes){encoded,length},TC_TLV_BER,
        &limits,&tree), ==, TC_TLV_INVALID);
    length = chunked_name(encoded,0x14,(TC_bytes){country,sizeof country},1);
    work = WORK_BUDGET;
    munit_assert_int(tc_pki_tree_name((TC_bytes){encoded,length},TC_TLV_BER,
        &limits,&tree), ==, TC_TLV_OK);
    work = WORK_BUDGET; matched = -1;
    munit_assert_int(tc_pki_name_equal((TC_bytes){encoded,length},TC_TLV_BER,
        (TC_bytes){encoded,length},TC_TLV_BER,&limits,&names,&tree,&matched), ==, TC_TLV_UNSUPPORTED);
    munit_assert_int(matched, ==, -1);
  }
  {
    static const uint8_t domain_der[] = {
      0x30,19,0x31,17,0x30,15,6,10,9,0x92,0x26,0x89,0x93,0xf2,0x2c,100,1,25,0x16,1,'a'
    };
    static const uint8_t domain_ber[] = {
      0x30,0x80,0x31,0x80,0x30,0x80,6,10,9,0x92,0x26,0x89,0x93,0xf2,0x2c,100,1,25,
      0x36,0x80,4,1,'A',0,0,0,0,0,0,0,0
    };
    work = WORK_BUDGET; matched = -1;
    munit_assert_int(tc_pki_name_equal((TC_bytes){domain_der,sizeof domain_der},TC_TLV_DER,
        (TC_bytes){domain_ber,sizeof domain_ber},TC_TLV_BER,&limits,&names,&tree,&matched), ==, TC_TLV_OK);
    munit_assert_int(matched, ==, 1);
  }
  return MUNIT_OK;
}

static MunitResult certificate_ski(const MunitParameter params[], void* user)
{
  enum { WORK_BUDGET = 1024, EXTENSION_HEADER = 2 };
  static const uint8_t present[] = {0x30,12,0x30,10,6,3,0x55,0x1d,14,4,3,4,1,0xaa};
  static const uint8_t empty[] = {0x30,11,0x30,9,6,3,0x55,0x1d,14,4,2,4,0};
  const TC_bytes cases[] = {{NULL,0},{present,sizeof present},{empty,sizeof empty}};
  const TC_TLV_limits limits = {WORK_BUDGET,WORK_BUDGET,32,4};
  TC_X509_certificate certificate = {0};
  TC_bytes out, saved = {present,1};
  size_t work;
  (void)params; (void)user;
  for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
    certificate.extensions = cases[i]; work = WORK_BUDGET; out = saved;
    munit_assert_int(tc_pki_subject_key_identifier(&certificate,&limits,&work,&out), ==, TC_TLV_OK);
    if (!i) munit_assert_null(out.data);
    else {
      munit_assert_size(out.length, ==, i == 1 ? 1 : 0);
      munit_assert_ptr_equal(out.data,cases[i].data + cases[i].length - out.length);
    }
    size_t required = WORK_BUDGET - work;
    for (size_t budget = 0; budget < required; ++budget) {
      work = budget; out = saved;
      munit_assert_int(tc_pki_subject_key_identifier(&certificate,&limits,&work,&out), ==, TC_TLV_LIMIT);
      munit_assert_ptr_equal(out.data,saved.data);
      munit_assert_size(out.length, ==, saved.length);
    }
    work = required;
    munit_assert_int(tc_pki_subject_key_identifier(&certificate,&limits,&work,&out), ==, TC_TLV_OK);
    munit_assert_size(work, ==, 0);
    if (i) {
      uint8_t duplicate[2 * sizeof present];
      size_t body = cases[i].length - EXTENSION_HEADER;
      duplicate[0] = 0x30; duplicate[1] = (uint8_t)(2 * body);
      memcpy(duplicate + EXTENSION_HEADER,cases[i].data + EXTENSION_HEADER,body);
      memcpy(duplicate + EXTENSION_HEADER + body,cases[i].data + EXTENSION_HEADER,body);
      certificate.extensions = (TC_bytes){duplicate,EXTENSION_HEADER + 2 * body};
      work = WORK_BUDGET; out = saved;
      munit_assert_int(tc_pki_subject_key_identifier(&certificate,&limits,&work,&out), ==, TC_TLV_INVALID);
      munit_assert_ptr_equal(out.data,saved.data);
      munit_assert_size(out.length, ==, saved.length);
    }
  }
  {
    /* Finding the SKI does not end the extension scan. */
    uint8_t trailing[sizeof present + EXTENSION_HEADER];
    memcpy(trailing,present,sizeof present);
    trailing[1] += EXTENSION_HEADER;
    trailing[sizeof present] = 5; trailing[sizeof present + 1] = 0;
    certificate.extensions = (TC_bytes){trailing,sizeof trailing};
    work = WORK_BUDGET; out = saved;
    munit_assert_int(tc_pki_subject_key_identifier(&certificate,&limits,&work,&out), ==, TC_TLV_INVALID);
    munit_assert_ptr_equal(out.data,saved.data);
    munit_assert_size(out.length, ==, saved.length);
  }
  return MUNIT_OK;
}

static MunitResult certificate_identifiers(const MunitParameter params[], void* user)
{
  enum { FRAME_CAPACITY = 8, SCALAR_CAPACITY = 32, ATTRIBUTE_CAPACITY = 4, WORK_BUDGET = 16384 };
  static const uint8_t issuer_der[] = {0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A'};
  static const uint8_t issuer_ber[] = {
    0x30,0x80,0x31,0x80,0x30,0x80,6,3,0x55,4,3,0x0c,1,'a',0,0,0,0,0,0
  };
  static const uint8_t serial[] = {0,0x80}, other_serial[] = {0x80};
  static const uint8_t extensions[] = {0x30,12,0x30,10,6,3,0x55,0x1d,14,4,3,4,1,0xaa};
  static const uint8_t primitive[] = {0x80,1,0xaa};
  static const uint8_t constructed[] = {0xa0,0x80,4,0,0x24,0x80,4,1,0xaa,0,0,0,0};
  static const uint8_t wrong[] = {0x80,1,0xbb}, longer[] = {0x80,2,0xaa,0xbb};
  static const uint8_t malformed[] = {0xa0,0x80,4,1,0xbb,2,1,0,0,0};
  const TC_TLV_limits limits = {WORK_BUDGET,WORK_BUDGET,64,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  uint32_t a[SCALAR_CAPACITY], b[SCALAR_CAPACITY];
  uint8_t flags[ATTRIBUTE_CAPACITY];
  const TC_X509_name_workspace names = {a,b,SCALAR_CAPACITY,flags,ATTRIBUTE_CAPACITY};
  size_t work = WORK_BUDGET;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  TC_X509_certificate certificate = {0};
  tc_cms_signer_info info = {0};
  int matched;
  (void)params; (void)user;
  certificate.issuer = (TC_bytes){issuer_der,sizeof issuer_der};
  certificate.serial = (TC_bytes){serial,sizeof serial};
  certificate.extensions = (TC_bytes){extensions,sizeof extensions};
  for (unsigned variant = 0; variant < 3; ++variant) {
    memset(&info,0,sizeof info);
    if (!variant) {
      info.version = 1;
      info.issuer = (TC_bytes){issuer_ber,sizeof issuer_ber};
      info.serial = certificate.serial;
    } else {
      info.version = 3;
      info.subject_key_id = variant == 1 ? (TC_bytes){primitive,sizeof primitive} :
          (TC_bytes){constructed,sizeof constructed};
    }
    work = WORK_BUDGET; matched = -1;
    munit_assert_int(tc_cms_signer_matches(&info,TC_TLV_BER,&certificate,&limits,&names,&tree,&matched),
        ==, TC_TLV_OK);
    munit_assert_int(matched, ==, 1);
    const size_t required = WORK_BUDGET - work;
    for (size_t budget = 0; budget < required; ++budget) {
      work = budget; matched = -1;
      munit_assert_int(tc_cms_signer_matches(&info,TC_TLV_BER,&certificate,&limits,&names,&tree,&matched),
          ==, TC_TLV_LIMIT);
      munit_assert_int(matched, ==, -1);
    }
    work = required;
    munit_assert_int(tc_cms_signer_matches(&info,TC_TLV_BER,&certificate,&limits,&names,&tree,&matched),
        ==, TC_TLV_OK);
    munit_assert_int(matched, ==, 1);
    munit_assert_size(work, ==, 0);
    if (!variant) {
      certificate.serial = (TC_bytes){other_serial,sizeof other_serial};
      certificate.serial_negative = 1; work = WORK_BUDGET;
      munit_assert_int(tc_cms_signer_matches(&info,TC_TLV_BER,&certificate,&limits,&names,&tree,&matched),
          ==, TC_TLV_OK);
      munit_assert_int(matched, ==, 0);
      certificate.serial = (TC_bytes){serial,sizeof serial}; certificate.serial_negative = 0;
    }
  }
  {
    const TC_bytes failures[] = {{wrong,sizeof wrong},{longer,sizeof longer}};
    for (size_t i = 0; i < sizeof failures / sizeof failures[0]; ++i) {
      info.subject_key_id = failures[i]; work = WORK_BUDGET;
      munit_assert_int(tc_cms_signer_matches(&info,TC_TLV_BER,&certificate,&limits,NULL,&tree,&matched),
          ==, TC_TLV_OK);
      munit_assert_int(matched, ==, 0);
    }
  }
  info.subject_key_id = (TC_bytes){constructed,sizeof constructed};
  for (size_t length = 0; length < sizeof constructed; ++length) {
    info.subject_key_id.length = length; work = WORK_BUDGET; matched = -1;
    munit_assert_int(tc_cms_signer_matches(&info,TC_TLV_BER,&certificate,&limits,NULL,&tree,&matched),
        !=, TC_TLV_OK);
    munit_assert_int(matched, ==, -1);
  }
  info.subject_key_id = (TC_bytes){malformed,sizeof malformed}; work = WORK_BUDGET;
  munit_assert_int(tc_cms_signer_matches(&info,TC_TLV_BER,&certificate,&limits,NULL,&tree,&matched),
      ==, TC_TLV_INVALID);
  munit_assert_int(matched, ==, -1);
  info.subject_key_id = (TC_bytes){primitive,sizeof primitive};
  certificate.extensions = (TC_bytes){NULL,0}; work = WORK_BUDGET;
  munit_assert_int(tc_cms_signer_matches(&info,TC_TLV_BER,&certificate,&limits,NULL,&tree,&matched),
      ==, TC_TLV_OK);
  munit_assert_int(matched, ==, 0);
  {
    uint8_t duplicate[sizeof extensions * 2 - 2];
    memcpy(duplicate,extensions,sizeof extensions);
    memcpy(duplicate + sizeof extensions,extensions + 2,sizeof extensions - 2);
    duplicate[1] = (uint8_t)(sizeof duplicate - 2);
    certificate.extensions = (TC_bytes){duplicate,sizeof duplicate}; work = WORK_BUDGET; matched = -1;
    munit_assert_int(tc_cms_signer_matches(&info,TC_TLV_BER,&certificate,&limits,NULL,&tree,&matched),
        ==, TC_TLV_INVALID);
    munit_assert_int(matched, ==, -1);
  }
  return MUNIT_OK;
}

static MunitResult candidate_iteration(const MunitParameter params[], void* user)
{
  enum { FRAME_CAPACITY = 8, WORK_BUDGET = 4096, RECORD_COUNT = 3 };
  static const uint8_t embedded[] = {0xa0,0x80,0x30,0,0xa2,0,0,0};
  static const uint8_t external_record[] = {0x30,0};
  static const uint8_t wrong_choice[] = {0xa0,3,2,1,1};
  const TC_bytes records[] = {{external_record,sizeof external_record}};
  candidate_source source = {records,1,0,TC_TLV_OK,0};
  TC_X509_store_source external = {&source,source.count,0,read_candidate,NULL};
  const TC_TLV_limits limits = {WORK_BUDGET,WORK_BUDGET,64,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  size_t work = WORK_BUDGET;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  tc_cms_candidates reader, saved;
  tc_cms_certificate_choice choice, previous;
  const TC_bytes input = {embedded,sizeof embedded};
  (void)params; (void)user;
  munit_assert_int(tc_cms_candidates_init(input,&external,RECORD_COUNT,
      sizeof embedded + sizeof external_record,&limits,&tree,&reader), ==, TC_TLV_OK);
  const tc_cms_candidates start = reader;
  const size_t init_work = WORK_BUDGET - work;
  for (size_t i = 0; i < RECORD_COUNT; ++i) {
    munit_assert_int(tc_cms_candidates_next(&reader,&tree,&choice), ==, TC_TLV_OK);
    munit_assert_uint(choice.kind, ==, i == 1 ? 3 : 0);
    munit_assert_ptr_equal(choice.encoded.data,i < 2 ? embedded + 2 + i * 2 : external_record);
  }
  munit_assert_size(source.calls, ==, 1);
  munit_assert_size(reader.collection.bytes_left, ==, 0);
  munit_assert_size(reader.collection.remaining, ==, 0);
  memcpy(&previous,&choice,sizeof previous); memcpy(&saved,&reader,sizeof saved);
  munit_assert_int(tc_cms_candidates_next(&reader,&tree,&choice), ==, TC_TLV_END);
  munit_assert_memory_equal(sizeof reader,&reader,&saved);
  munit_assert_memory_equal(sizeof choice,&choice,&previous);
  const size_t next_work = WORK_BUDGET - init_work - work;
  for (size_t budget = 0; budget < next_work; ++budget) {
    reader = start; work = budget;
    TC_TLV_result result = TC_TLV_OK;
    for (size_t i = 0; i < RECORD_COUNT && result == TC_TLV_OK; ++i) {
      memcpy(&saved,&reader,sizeof saved); memcpy(&previous,&choice,sizeof previous);
      result = tc_cms_candidates_next(&reader,&tree,&choice);
    }
    munit_assert_int(result, ==, TC_TLV_LIMIT);
    munit_assert_memory_equal(sizeof reader,&reader,&saved);
    munit_assert_memory_equal(sizeof choice,&choice,&previous);
  }
  reader = start; reader.collection.remaining = RECORD_COUNT - 1; work = WORK_BUDGET; source.calls = 0;
  munit_assert_int(tc_cms_candidates_next(&reader,&tree,&choice), ==, TC_TLV_OK);
  munit_assert_int(tc_cms_candidates_next(&reader,&tree,&choice), ==, TC_TLV_OK);
  munit_assert_int(tc_cms_candidates_next(&reader,&tree,&choice), ==, TC_TLV_LIMIT);
  munit_assert_size(source.calls, ==, 0);
  for (unsigned failure = 0; failure < 3; ++failure) {
    reader = start; work = WORK_BUDGET;
    munit_assert_int(tc_cms_candidates_next(&reader,&tree,&choice), ==, TC_TLV_OK);
    munit_assert_int(tc_cms_candidates_next(&reader,&tree,&choice), ==, TC_TLV_OK);
    if (failure == 0) reader.collection.bytes_left = sizeof external_record - 1;
    source.increase_work = failure == 1;
    source.status = failure == 2 ? TC_TLV_END : TC_TLV_OK;
    memcpy(&saved,&reader,sizeof saved); memcpy(&previous,&choice,sizeof previous);
    munit_assert_int(tc_cms_candidates_next(&reader,&tree,&choice), ==,
        failure == 0 ? TC_TLV_LIMIT : TC_TLV_ARGUMENT);
    munit_assert_memory_equal(sizeof reader,&reader,&saved);
    munit_assert_memory_equal(sizeof choice,&choice,&previous);
    if (source.increase_work) munit_assert_size(work, ==, 0);
  }
  source.increase_work = 0; source.status = TC_TLV_OK;
  for (size_t length = 1; length < sizeof embedded; ++length) {
    work = WORK_BUDGET; memcpy(&saved,&reader,sizeof saved);
    munit_assert_int(tc_cms_candidates_init((TC_bytes){embedded,length},&external,
        RECORD_COUNT,WORK_BUDGET,&limits,&tree,&reader), !=, TC_TLV_OK);
    munit_assert_memory_equal(sizeof reader,&reader,&saved);
  }
  work = WORK_BUDGET;
  munit_assert_int(tc_cms_candidates_init((TC_bytes){wrong_choice,sizeof wrong_choice},NULL,
      RECORD_COUNT,WORK_BUDGET,&limits,&tree,&reader), ==, TC_TLV_OK);
  memcpy(&saved,&reader,sizeof saved); memcpy(&previous,&choice,sizeof previous);
  munit_assert_int(tc_cms_candidates_next(&reader,&tree,&choice), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof reader,&reader,&saved);
  munit_assert_memory_equal(sizeof choice,&choice,&previous);
  {
    enum { INDEX_CAPACITY = 2 };
    TC_bytes index[INDEX_CAPACITY], record, prior_record;
    TC_X509_store_source indexed, prior_source;
    tc_cms_path_source context, prior_context;
    source.calls = 0; work = WORK_BUDGET;
    munit_assert_int(tc_cms_path_source_init(&start,&tree,index,INDEX_CAPACITY,&context,&indexed), ==, TC_TLV_OK);
    const size_t required = WORK_BUDGET - work;
    munit_assert_size(indexed.candidate_count, ==, INDEX_CAPACITY);
    munit_assert_size(indexed.anchor_count, ==, 0);
    munit_assert_size(source.calls, ==, 1);
    for (size_t i = 0; i < INDEX_CAPACITY; ++i) {
      munit_assert_int(indexed.candidate(indexed.context,i,&work,&record), ==, TC_TLV_OK);
      munit_assert_ptr_equal(record.data,i ? external_record : embedded + 2);
      munit_assert_size(record.length, ==, sizeof external_record);
    }
    munit_assert_size(source.calls, ==, 1);
    prior_record = record;
    munit_assert_int(indexed.candidate(indexed.context,INDEX_CAPACITY,&work,&record), ==, TC_TLV_ARGUMENT);
    munit_assert_ptr_equal(record.data,prior_record.data);
    munit_assert_size(record.length, ==, prior_record.length);
    work = 0;
    munit_assert_int(indexed.candidate(indexed.context,0,&work,&record), ==, TC_TLV_LIMIT);
    munit_assert_ptr_equal(record.data,prior_record.data);
    munit_assert_size(record.length, ==, prior_record.length);
    memcpy(&prior_source,&indexed,sizeof indexed); memcpy(&prior_context,&context,sizeof context);
    for (size_t budget = 0; budget < required; ++budget) {
      work = budget;
      munit_assert_int(tc_cms_path_source_init(&start,&tree,index,INDEX_CAPACITY,&context,&indexed), ==, TC_TLV_LIMIT);
      munit_assert_memory_equal(sizeof indexed,&indexed,&prior_source);
      munit_assert_memory_equal(sizeof context,&context,&prior_context);
    }
    work = required;
    munit_assert_int(tc_cms_path_source_init(&start,&tree,index,INDEX_CAPACITY,&context,&indexed), ==, TC_TLV_OK);
    munit_assert_size(work, ==, 0);
    memcpy(&prior_source,&indexed,sizeof indexed); memcpy(&prior_context,&context,sizeof context);
    for (unsigned failure = 0; failure < 4; ++failure) {
      tc_cms_candidates limited = start;
      size_t capacity = INDEX_CAPACITY;
      if (failure == 0) --capacity;
      if (failure == 1) --limited.collection.remaining;
      if (failure == 2) limited.collection.bytes_left = 0;
      source.increase_work = failure == 3;
      work = WORK_BUDGET;
      munit_assert_int(tc_cms_path_source_init(&limited,&tree,index,capacity,&context,&indexed),
          ==, failure == 3 ? TC_TLV_ARGUMENT : TC_TLV_LIMIT);
      munit_assert_memory_equal(sizeof indexed,&indexed,&prior_source);
      munit_assert_memory_equal(sizeof context,&context,&prior_context);
    }
    source.increase_work = 0;
    work = WORK_BUDGET;
    munit_assert_int(tc_cms_candidates_init((TC_bytes){NULL,0},NULL,0,0,&limits,&tree,&reader), ==, TC_TLV_OK);
    munit_assert_int(tc_cms_path_source_init(&reader,&tree,NULL,0,&context,&indexed), ==, TC_TLV_OK);
    munit_assert_size(indexed.candidate_count, ==, 0);
    munit_assert_size(indexed.anchor_count, ==, 0);
  }
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/identifiers",identifiers,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/attributes",attributes,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/malformed",malformed,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/ber-fields",ber_fields,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/issuer-schema",issuer_schema,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/issuer-matching",issuer_matching,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/constructed-names",constructed_names,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/certificate-ski",certificate_ski,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/certificate-identifiers",certificate_identifiers,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/candidate-iteration",candidate_iteration,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/cms/signer-info",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
