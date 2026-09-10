/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/cms.h>
#include "../../examples/cms_reader.h"
#include "munit.h"
#include <string.h>

enum { FRAME_CAPACITY = 8, INPUT_CAPACITY = 128, WORK_BUDGET = 4096 };
static const uint8_t detached[] = {
  0x30,35,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,2,
  0xa0,22,0x30,20,2,1,1,0x31,0,0x30,11,6,9,
  0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,1,0x31,0
};

static MunitResult read_envelope(const MunitParameter params[], void* user)
{
  enum { VERSION_OFFSET = 19, CONTENT_TYPE_OFFSET = 26, SIGNERS_OFFSET = 35 };
  uint8_t encoded[sizeof detached + 2];
  TC_TLV_limits limits = {INPUT_CAPACITY,INPUT_CAPACITY,32,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_CMS_signed_data parsed, saved;
  size_t work;
  (void)params; (void)user;
  memset(&saved,0xa5,sizeof saved);
  for (unsigned indefinite = 0; indefinite < 2; ++indefinite) {
    memcpy(encoded,detached,sizeof detached);
    encoded[sizeof detached] = encoded[sizeof detached + 1] = 0;
    if (indefinite) encoded[1] = 0x80;
    const size_t length = sizeof detached + (indefinite ? 2 : 0);
    work = WORK_BUDGET;
    munit_assert_int(TC_CMS_signed_data_read((TC_bytes){encoded,length},&limits,
        frames,FRAME_CAPACITY,&work,&parsed), ==, TC_TLV_OK);
    munit_assert_ptr_equal(parsed.encoded.data,encoded);
    munit_assert_size(parsed.encoded.length, ==, length);
    munit_assert_uint(parsed.version, ==, 1);
    munit_assert_false(parsed.has_content);
    munit_assert_null(parsed.content.data);
    munit_assert_ptr_equal(parsed.content_type.data,encoded + CONTENT_TYPE_OFFSET);
    munit_assert_ptr_equal(parsed.signers.data,encoded + SIGNERS_OFFSET);
    const size_t required = WORK_BUDGET - work;
    for (size_t budget = 0; budget < required; ++budget) {
      work = budget; parsed = saved;
      munit_assert_int(TC_CMS_signed_data_read((TC_bytes){encoded,length},&limits,
          frames,FRAME_CAPACITY,&work,&parsed), ==, TC_TLV_LIMIT);
      munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
    }
    work = required;
    munit_assert_int(TC_CMS_signed_data_read((TC_bytes){encoded,length},&limits,
        frames,FRAME_CAPACITY,&work,&parsed), ==, TC_TLV_OK);
    munit_assert_size(work, ==, 0);
    ExampleCMSWorkspace example;
    munit_assert_int(example_read_cms((TC_bytes){encoded,length},WORK_BUDGET,
        &example,&parsed), ==, TC_TLV_OK);
    munit_assert_ptr_equal(parsed.encoded.data,encoded);
    munit_assert_false(parsed.has_content);
    enum { INPUT_LIMIT, VALUE_LIMIT, ELEMENT_LIMIT, DEPTH_LIMIT, FRAME_LIMIT, LIMIT_COUNT };
    for (unsigned bound = 0; bound < LIMIT_COUNT; ++bound) {
      TC_TLV_limits bounded = limits;
      size_t capacity = FRAME_CAPACITY;
      if (bound == INPUT_LIMIT) bounded.max_input = length - 1;
      if (bound == VALUE_LIMIT) bounded.max_value = 1;
      if (bound == ELEMENT_LIMIT) bounded.max_elements = 1;
      if (bound == DEPTH_LIMIT) bounded.max_depth = 1;
      if (bound == FRAME_LIMIT) capacity = 1;
      work = WORK_BUDGET; parsed = saved;
      munit_assert_int(TC_CMS_signed_data_read((TC_bytes){encoded,length},&bounded,
          frames,capacity,&work,&parsed), ==, TC_TLV_LIMIT);
      munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
    }
    for (size_t truncated = 0; truncated < length; ++truncated) {
      work = WORK_BUDGET; parsed = saved;
      munit_assert_int(TC_CMS_signed_data_read((TC_bytes){encoded,truncated},&limits,
          frames,FRAME_CAPACITY,&work,&parsed), !=, TC_TLV_OK);
      munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
    }
    encoded[VERSION_OFFSET] = 3; work = WORK_BUDGET; parsed = saved;
    munit_assert_int(TC_CMS_signed_data_read((TC_bytes){encoded,length},&limits,
        frames,FRAME_CAPACITY,&work,&parsed), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  }
  return MUNIT_OK;
}

static MunitResult embedded_content(const MunitParameter params[], void* user)
{
  enum { CONTENT_OFFSET = 35, OCTETS_OFFSET = CONTENT_OFFSET + 2,
    OUTER_LENGTH = 1, WRAPPER_LENGTH = 14, SIGNED_DATA_LENGTH = 16,
    ENCAP_LENGTH = 23, TYPE_LENGTH = 11 };
  static const uint8_t empty[] = {4,0};
  static const uint8_t primitive[] = {4,3,'a','b','c'};
  static const uint8_t constructed[] = {0x24,7,4,1,'a',4,2,'b','c'};
  const TC_bytes forms[] = {{empty,sizeof empty},{primitive,sizeof primitive},
    {constructed,sizeof constructed}};
  uint8_t encoded[INPUT_CAPACITY];
  TC_TLV_limits limits = {INPUT_CAPACITY,INPUT_CAPACITY,32,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_CMS_signed_data parsed;
  (void)params; (void)user;
  for (size_t i = 0; i < sizeof forms / sizeof forms[0]; ++i) {
    size_t length = OCTETS_OFFSET + forms[i].length;
    memcpy(encoded,detached,CONTENT_OFFSET);
    encoded[CONTENT_OFFSET] = 0xa0;
    encoded[CONTENT_OFFSET + 1] = (uint8_t)forms[i].length;
    memcpy(encoded + OCTETS_OFFSET,forms[i].data,forms[i].length);
    encoded[length++] = 0x31; encoded[length++] = 0;
    encoded[OUTER_LENGTH] = (uint8_t)(length - OUTER_LENGTH - 1);
    encoded[WRAPPER_LENGTH] = (uint8_t)(length - WRAPPER_LENGTH - 1);
    encoded[SIGNED_DATA_LENGTH] = (uint8_t)(length - SIGNED_DATA_LENGTH - 1);
    encoded[ENCAP_LENGTH] = (uint8_t)(TYPE_LENGTH + 2 + forms[i].length);
    size_t work = WORK_BUDGET;
    munit_assert_int(TC_CMS_signed_data_read((TC_bytes){encoded,length},&limits,
        frames,FRAME_CAPACITY,&work,&parsed), ==, TC_TLV_OK);
    munit_assert_true(parsed.has_content);
    munit_assert_ptr_equal(parsed.content.data,encoded + OCTETS_OFFSET);
    munit_assert_size(parsed.content.length, ==, forms[i].length);
  }
  return MUNIT_OK;
}

static MunitResult storage(const MunitParameter params[], void* user)
{
  enum { INPUT, LIMITS, FRAMES, WORK, OUTPUT, SLOT_COUNT };
  union slot {
    uint8_t input[INPUT_CAPACITY];
    TC_TLV_limits limits;
    TC_TLV_frame frames[FRAME_CAPACITY];
    size_t work;
    TC_CMS_signed_data data;
    TC_CMS_signed_attributes attributes;
    TC_CMS_signer_info signer;
    TC_TLV_reader reader;
  } slots[SLOT_COUNT];
  uint8_t saved[sizeof slots];
  (void)params; (void)user;
  enum { ENVELOPE, ATTRIBUTES, SIGNER, SIGNERS_INIT, SIGNER_NEXT, DIGEST, READER_COUNT };
  for (unsigned reader = 0; reader < READER_COUNT; ++reader)
    for (unsigned left = 0; left < SLOT_COUNT; ++left)
      for (unsigned right = left + 1; right < SLOT_COUNT; ++right) {
        void* pointers[SLOT_COUNT];
        memset(slots,0xa5,sizeof slots);
        memcpy(slots[INPUT].input,detached,sizeof detached);
        slots[LIMITS].limits = (TC_TLV_limits){INPUT_CAPACITY,INPUT_CAPACITY,32,FRAME_CAPACITY};
        slots[WORK].work = WORK_BUDGET;
        for (unsigned i = 0; i < SLOT_COUNT; ++i) pointers[i] = &slots[i];
        pointers[left] = pointers[right];
        if (reader == SIGNER_NEXT) {
          TC_TLV_reader* state = pointers[LIMITS];
          *state = (TC_TLV_reader){0};
          state->input = (TC_bytes){pointers[INPUT],sizeof detached};
          state->profile = TC_TLV_BER;
        }
        memcpy(saved,slots,sizeof slots);
        const TC_bytes input = {pointers[INPUT],sizeof detached};
        TC_TLV_result result;
        if (reader == ATTRIBUTES)
          result = TC_CMS_signed_attributes_read(input,TC_CMS_ATTRIBUTES_DER,pointers[LIMITS],
              pointers[FRAMES],FRAME_CAPACITY,pointers[WORK],pointers[OUTPUT]);
        else if (reader == SIGNER)
          result = TC_CMS_signer_info_read(input,TC_TLV_BER,pointers[LIMITS],
              pointers[FRAMES],FRAME_CAPACITY,pointers[WORK],pointers[OUTPUT]);
        else if (reader == SIGNERS_INIT)
          result = TC_CMS_signers_init(input,pointers[LIMITS],pointers[FRAMES],FRAME_CAPACITY,
              pointers[WORK],pointers[OUTPUT]);
        else if (reader == SIGNER_NEXT)
          result = TC_CMS_signer_next(pointers[LIMITS],pointers[FRAMES],FRAME_CAPACITY,
              pointers[WORK],pointers[OUTPUT]);
        else if (reader == DIGEST)
          result = TC_CMS_content_digest(input,TC_HASH_SHA256,pointers[LIMITS],pointers[FRAMES],
              FRAME_CAPACITY,pointers[WORK],pointers[OUTPUT],INPUT_CAPACITY);
        else
          result = TC_CMS_signed_data_read(input,pointers[LIMITS],pointers[FRAMES],FRAME_CAPACITY,
              pointers[WORK],pointers[OUTPUT]);
        munit_assert_int(result, ==, TC_TLV_ARGUMENT);
        munit_assert_memory_equal(sizeof slots,slots,saved);
      }
  TC_TLV_limits limits = {INPUT_CAPACITY,INPUT_CAPACITY,32,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_CMS_signed_data output, unchanged;
  memset(&unchanged,0xa5,sizeof unchanged); output = unchanged;
  size_t work = WORK_BUDGET;
  munit_assert_int(TC_CMS_signed_data_read((TC_bytes){detached,sizeof detached},&limits,
      frames,SIZE_MAX / sizeof *frames + 1,&work,&output), ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, WORK_BUDGET);
  munit_assert_memory_equal(sizeof output,&output,&unchanged);
  uint8_t digest[INPUT_CAPACITY], saved_digest[INPUT_CAPACITY];
  memset(digest,0xa5,sizeof digest); memcpy(saved_digest,digest,sizeof digest);
  work = WORK_BUDGET;
  munit_assert_int(TC_CMS_content_digest((TC_bytes){detached,sizeof detached},TC_HASH_SHA256,
      &limits,frames,FRAME_CAPACITY,&work,digest,sizeof digest), ==, TC_TLV_UNSUPPORTED);
  munit_assert_memory_equal(sizeof digest,digest,saved_digest);
  return MUNIT_OK;
}

static MunitResult signer_iteration(const MunitParameter params[], void* user)
{
  static const uint8_t record[] = {
    0x30,21,2,1,3,0x80,1,0xaa,
    0x30,4,6,2,0x2a,3,0x30,4,6,2,0x2a,3,4,1,0xbb
  };
  enum { VERSION_OFFSET = 4 };
  uint8_t encoded[INPUT_CAPACITY], saved_frames[FRAME_CAPACITY * sizeof(TC_TLV_frame)];
  const TC_TLV_limits limits = {INPUT_CAPACITY,INPUT_CAPACITY,64,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_TLV_reader reader, saved_reader;
  TC_CMS_signer_info signer, saved;
  (void)params; (void)user;
  memset(&saved,0xa5,sizeof saved);
  for (unsigned outer_indefinite = 0; outer_indefinite < 2; ++outer_indefinite)
    for (unsigned inner_indefinite = 0; inner_indefinite < 2; ++inner_indefinite) {
      size_t length = 2, offsets[2], work = WORK_BUDGET;
      for (unsigned i = 0; i < 2; ++i) {
        offsets[i] = length;
        memcpy(encoded + length,record,sizeof record);
        if (inner_indefinite) encoded[length + 1] = 0x80;
        length += sizeof record;
        if (inner_indefinite) { encoded[length++] = 0; encoded[length++] = 0; }
      }
      encoded[0] = 0x31; encoded[1] = (uint8_t)(length - 2);
      if (outer_indefinite) {
        encoded[1] = 0x80; encoded[length++] = 0; encoded[length++] = 0;
      }
      const TC_bytes input = {encoded,length};
      ExampleCMSWorkspace example;
      munit_assert_int(example_parse_cms_signers(input,WORK_BUDGET,&example), ==, TC_TLV_OK);
      munit_assert_int(TC_CMS_signers_init(input,&limits,frames,FRAME_CAPACITY,&work,&reader), ==, TC_TLV_OK);
      const size_t init_work = WORK_BUDGET - work;
      const TC_TLV_reader start = reader;
      for (size_t budget = 0; budget < init_work; ++budget) {
        reader = start; work = budget;
        munit_assert_int(TC_CMS_signers_init(input,&limits,frames,FRAME_CAPACITY,&work,&reader), ==, TC_TLV_LIMIT);
        munit_assert_memory_equal(sizeof reader,&reader,&start);
      }
      size_t total_work = init_work;
      reader = start;
      for (unsigned i = 0; i < 2; ++i) {
        saved_reader = reader; work = WORK_BUDGET;
        munit_assert_int(TC_CMS_signer_next(&reader,frames,FRAME_CAPACITY,&work,&signer), ==, TC_TLV_OK);
        munit_assert_ptr_equal(signer.encoded.data,encoded + offsets[i]);
        munit_assert_uint(signer.version, ==, 3);
        const size_t required = WORK_BUDGET - work;
        total_work += required;
        for (size_t budget = 0; budget < required; ++budget) {
          reader = saved_reader; signer = saved; work = budget;
          munit_assert_int(TC_CMS_signer_next(&reader,frames,FRAME_CAPACITY,&work,&signer), ==, TC_TLV_LIMIT);
          munit_assert_memory_equal(sizeof reader,&reader,&saved_reader);
          munit_assert_memory_equal(sizeof signer,&signer,&saved);
        }
        reader = saved_reader; work = required;
        munit_assert_int(TC_CMS_signer_next(&reader,frames,FRAME_CAPACITY,&work,&signer), ==, TC_TLV_OK);
        munit_assert_size(work, ==, 0);
      }
      saved_reader = reader; signer = saved; work = 0;
      memset(frames,0xa5,sizeof frames);
      memcpy(saved_frames,frames,sizeof frames);
      munit_assert_int(TC_CMS_signer_next(&reader,frames,FRAME_CAPACITY,&work,&signer), ==, TC_TLV_END);
      munit_assert_memory_equal(sizeof reader,&reader,&saved_reader);
      munit_assert_memory_equal(sizeof signer,&signer,&saved);
      munit_assert_memory_equal(sizeof frames,frames,saved_frames);
      munit_assert_size(work, ==, 0);
      work = total_work;
      munit_assert_int(TC_CMS_signers_init(input,&limits,frames,FRAME_CAPACITY,&work,&reader), ==, TC_TLV_OK);
      for (unsigned i = 0; i < 2; ++i)
        munit_assert_int(TC_CMS_signer_next(&reader,frames,FRAME_CAPACITY,&work,&signer), ==, TC_TLV_OK);
      munit_assert_int(TC_CMS_signer_next(&reader,frames,FRAME_CAPACITY,&work,&signer), ==, TC_TLV_END);
      munit_assert_size(work, ==, 0);
      encoded[offsets[1] + VERSION_OFFSET] = 1;
      munit_assert_int(example_parse_cms_signers(input,WORK_BUDGET,&example), ==, TC_TLV_INVALID);
      reader = start; work = WORK_BUDGET;
      munit_assert_int(TC_CMS_signer_next(&reader,frames,FRAME_CAPACITY,&work,&signer), ==, TC_TLV_OK);
      saved_reader = reader; signer = saved;
      munit_assert_int(TC_CMS_signer_next(&reader,frames,FRAME_CAPACITY,&work,&signer), ==, TC_TLV_INVALID);
      munit_assert_memory_equal(sizeof reader,&reader,&saved_reader);
      munit_assert_memory_equal(sizeof signer,&signer,&saved);
      for (unsigned invalid_state = 0; invalid_state < 2; ++invalid_state) {
        reader = start;
        if (invalid_state) reader.profile = TC_TLV_DER;
        else reader.offset = reader.input.length + 1;
        saved_reader = reader; signer = saved; work = WORK_BUDGET;
        munit_assert_int(TC_CMS_signer_next(&reader,frames,FRAME_CAPACITY,&work,&signer), ==, TC_TLV_ARGUMENT);
        munit_assert_memory_equal(sizeof reader,&reader,&saved_reader);
        munit_assert_memory_equal(sizeof signer,&signer,&saved);
        munit_assert_size(work, ==, WORK_BUDGET);
      }
    }
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/envelope",read_envelope,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/content",embedded_content,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/storage",storage,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/signers",signer_iteration,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}};
  MunitSuite suite = {"/cms/reader",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
