/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/cms.h>
#include "../../examples/cms_reader.h"
#include "munit.h"
#include "test_util.h"
#include <string.h>

static const TC_CMS_verification_policy cms_policy = {.envelope = TC_CMS_ENVELOPE_BER};

enum { FRAME_CAPACITY = 8, INPUT_CAPACITY = 128, WORK_BUDGET = 4096 };
static const uint8_t detached[] = {0x30, 35,   6,    9,    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                   1,    7,    2,    0xa0, 22,   0x30, 20,   2,    1,    1,
                                   0x31, 0,    0x30, 11,   6,    9,    0x2a, 0x86, 0x48, 0x86,
                                   0xf7, 0x0d, 1,    7,    1,    0x31, 0};

TC_TEST(read_envelope)
{
  enum { VERSION_OFFSET = 19, CONTENT_TYPE_OFFSET = 26, SIGNERS_OFFSET = 35 };
  uint8_t encoded[sizeof detached + 2];
  TC_TLV_limits limits = {INPUT_CAPACITY, INPUT_CAPACITY, 32, FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_CMS_signed_data parsed, saved;
  size_t work;
  memset(&saved, 0xa5, sizeof saved);
  for (unsigned indefinite = 0; indefinite < 2; ++indefinite) {
    memcpy(encoded, detached, sizeof detached);
    encoded[sizeof detached] = encoded[sizeof detached + 1] = 0;
    if (indefinite)
      encoded[1] = 0x80;
    const size_t length = sizeof detached + (indefinite ? 2 : 0);
    work = WORK_BUDGET;
    munit_assert_int(TC_CMS_signed_data_read((TC_bytes){encoded, length}, &cms_policy, &limits,
                                             (TC_TLV_frames){frames, FRAME_CAPACITY}, &work,
                                             &parsed),
                     ==, TC_TLV_OK);
    munit_assert_ptr_equal(parsed.encoded.data, encoded);
    munit_assert_size(parsed.encoded.length, ==, length);
    munit_assert_uint(parsed.version, ==, 1);
    munit_assert_false(parsed.has_content);
    munit_assert_null(parsed.content.data);
    munit_assert_ptr_equal(parsed.content_type.data, encoded + CONTENT_TYPE_OFFSET);
    munit_assert_ptr_equal(parsed.signers.data, encoded + SIGNERS_OFFSET);
    const size_t required = WORK_BUDGET - work;
    for (size_t budget = 0; budget < required; ++budget) {
      work = budget;
      parsed = saved;
      munit_assert_int(TC_CMS_signed_data_read((TC_bytes){encoded, length}, &cms_policy, &limits,
                                               (TC_TLV_frames){frames, FRAME_CAPACITY}, &work,
                                               &parsed),
                       ==, TC_TLV_LIMIT);
      munit_assert_memory_equal(sizeof parsed, &parsed, &saved);
    }
    work = required;
    munit_assert_int(TC_CMS_signed_data_read((TC_bytes){encoded, length}, &cms_policy, &limits,
                                             (TC_TLV_frames){frames, FRAME_CAPACITY}, &work,
                                             &parsed),
                     ==, TC_TLV_OK);
    munit_assert_size(work, ==, 0);
    ExampleCMSWorkspace example;
    munit_assert_int(example_read_cms((TC_bytes){encoded, length}, WORK_BUDGET, &example, &parsed),
                     ==, TC_TLV_OK);
    munit_assert_ptr_equal(parsed.encoded.data, encoded);
    munit_assert_false(parsed.has_content);
    enum { INPUT_LIMIT, VALUE_LIMIT, ELEMENT_LIMIT, DEPTH_LIMIT, FRAME_LIMIT, LIMIT_COUNT };
    for (unsigned bound = 0; bound < LIMIT_COUNT; ++bound) {
      TC_TLV_limits bounded = limits;
      size_t capacity = FRAME_CAPACITY;
      if (bound == INPUT_LIMIT)
        bounded.max_input = length - 1;
      if (bound == VALUE_LIMIT)
        bounded.max_value = 1;
      if (bound == ELEMENT_LIMIT)
        bounded.max_elements = 1;
      if (bound == DEPTH_LIMIT)
        bounded.max_depth = 1;
      if (bound == FRAME_LIMIT)
        capacity = 1;
      work = WORK_BUDGET;
      parsed = saved;
      munit_assert_int(TC_CMS_signed_data_read((TC_bytes){encoded, length}, &cms_policy, &bounded,
                                               (TC_TLV_frames){frames, capacity}, &work, &parsed),
                       ==, TC_TLV_LIMIT);
      munit_assert_memory_equal(sizeof parsed, &parsed, &saved);
    }
    for (size_t truncated = 0; truncated < length; ++truncated) {
      work = WORK_BUDGET;
      parsed = saved;
      munit_assert_int(TC_CMS_signed_data_read((TC_bytes){encoded, truncated}, &cms_policy, &limits,
                                               (TC_TLV_frames){frames, FRAME_CAPACITY}, &work,
                                               &parsed),
                       !=, TC_TLV_OK);
      munit_assert_memory_equal(sizeof parsed, &parsed, &saved);
    }
    encoded[VERSION_OFFSET] = 3;
    work = WORK_BUDGET;
    parsed = saved;
    munit_assert_int(TC_CMS_signed_data_read((TC_bytes){encoded, length}, &cms_policy, &limits,
                                             (TC_TLV_frames){frames, FRAME_CAPACITY}, &work,
                                             &parsed),
                     ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof parsed, &parsed, &saved);
  }
  return MUNIT_OK;
}

/* Replace the detached envelope's EncapsulatedContentInfo with one holding
 * content, an OCTET STRING in any form. Returns the encoded length. */
static size_t embed_content(uint8_t encoded[INPUT_CAPACITY], TC_bytes content)
{
  enum {
    CONTENT_OFFSET = 35,
    OCTETS_OFFSET = CONTENT_OFFSET + 2,
    OUTER_LENGTH = 1,
    WRAPPER_LENGTH = 14,
    SIGNED_DATA_LENGTH = 16,
    ENCAP_LENGTH = 23,
    TYPE_LENGTH = 11
  };
  size_t length = OCTETS_OFFSET + content.length;
  munit_assert_size(length + 2, <=, INPUT_CAPACITY);
  memcpy(encoded, detached, CONTENT_OFFSET);
  encoded[CONTENT_OFFSET] = 0xa0;
  encoded[CONTENT_OFFSET + 1] = (uint8_t)content.length;
  memcpy(encoded + OCTETS_OFFSET, content.data, content.length);
  encoded[length++] = 0x31;
  encoded[length++] = 0;
  encoded[OUTER_LENGTH] = (uint8_t)(length - OUTER_LENGTH - 1);
  encoded[WRAPPER_LENGTH] = (uint8_t)(length - WRAPPER_LENGTH - 1);
  encoded[SIGNED_DATA_LENGTH] = (uint8_t)(length - SIGNED_DATA_LENGTH - 1);
  encoded[ENCAP_LENGTH] = (uint8_t)(TYPE_LENGTH + 2 + content.length);
  return length;
}

static const uint8_t empty_content[] = {4, 0};
static const uint8_t primitive_content[] = {4, 3, 'a', 'b', 'c'};
static const uint8_t constructed_content[] = {0x24, 7, 4, 1, 'a', 4, 2, 'b', 'c'};

TC_TEST(embedded_content)
{
  enum { OCTETS_OFFSET = 37 };
  const TC_bytes forms[] = {{empty_content, sizeof empty_content},
                            {primitive_content, sizeof primitive_content},
                            {constructed_content, sizeof constructed_content}};
  uint8_t encoded[INPUT_CAPACITY];
  TC_TLV_limits limits = {INPUT_CAPACITY, INPUT_CAPACITY, 32, FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_CMS_signed_data parsed;
  for (size_t i = 0; i < sizeof forms / sizeof forms[0]; ++i) {
    const size_t length = embed_content(encoded, forms[i]);
    size_t work = WORK_BUDGET;
    munit_assert_int(TC_CMS_signed_data_read((TC_bytes){encoded, length}, &cms_policy, &limits,
                                             (TC_TLV_frames){frames, FRAME_CAPACITY}, &work,
                                             &parsed),
                     ==, TC_TLV_OK);
    munit_assert_true(parsed.has_content);
    munit_assert_ptr_equal(parsed.content.data, encoded + OCTETS_OFFSET);
    munit_assert_size(parsed.content.length, ==, forms[i].length);
  }
  return MUNIT_OK;
}

TC_TEST(der_envelope)
{
  enum { PRIMITIVE, CONSTRUCTED, INDEFINITE, LONG_LENGTH, DETACHED, EMPTY_SET, CASE_COUNT };
  static const TC_CMS_verification_policy der = {.envelope = TC_CMS_ENVELOPE_DER};
  const TC_TLV_limits limits = {INPUT_CAPACITY, INPUT_CAPACITY, 32, FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  uint8_t encoded[INPUT_CAPACITY];
  TC_CMS_signed_data parsed, saved;
  memset(&saved, 0xa5, sizeof saved);
  for (unsigned kind = 0; kind < CASE_COUNT; ++kind) {
    size_t length;
    if (kind == PRIMITIVE || kind == CONSTRUCTED)
      length = embed_content(
          encoded, kind == PRIMITIVE ? (TC_bytes){primitive_content, sizeof primitive_content}
                                     : (TC_bytes){constructed_content, sizeof constructed_content});
    else {
      memcpy(encoded, detached, sizeof detached);
      length = sizeof detached;
      if (kind == INDEFINITE) {
        encoded[1] = 0x80;
        encoded[length++] = 0;
        encoded[length++] = 0;
      } else if (kind == LONG_LENGTH) {
        /* X.690 section 10.1 requires the shortest length form. */
        memmove(encoded + 3, encoded + 2, length - 2);
        encoded[1] = 0x81;
        encoded[2] = (uint8_t)(length - 2);
        ++length;
      }
    }
    const int der_valid = kind == PRIMITIVE || kind == DETACHED || kind == EMPTY_SET;
    for (unsigned policy = 0; policy < 2; ++policy) {
      size_t work = WORK_BUDGET;
      memcpy(&parsed, &saved, sizeof parsed);
      const TC_CMS_verification_policy* selected = policy ? &der : &cms_policy;
      if (kind == EMPTY_SET) {
        TC_TLV_reader reader;
        TC_CMS_signer_info signer;
        munit_assert_int(
            TC_CMS_signers_init((TC_bytes){detached + sizeof detached - 2, 2}, selected, &limits,
                                (TC_TLV_frames){frames, FRAME_CAPACITY}, &work, &reader),
            ==, TC_TLV_OK);
        munit_assert_int(reader.profile, ==, policy ? TC_TLV_DER : TC_TLV_BER);
        munit_assert_int(
            TC_CMS_signer_next(&reader, (TC_TLV_frames){frames, FRAME_CAPACITY}, &work, &signer),
            ==, TC_TLV_END);
        continue;
      }
      munit_assert_int(TC_CMS_signed_data_read((TC_bytes){encoded, length}, selected, &limits,
                                               (TC_TLV_frames){frames, FRAME_CAPACITY}, &work,
                                               &parsed),
                       ==, !policy || der_valid ? TC_TLV_OK : TC_TLV_INVALID);
      if (policy && !der_valid)
        munit_assert_memory_equal(sizeof parsed, &parsed, &saved);
      else
        munit_assert_ptr_equal(parsed.encoded.data, encoded);
    }
  }
  /* A missing or invalid policy is an argument error before any parsing. */
  const TC_CMS_verification_policy bad = {.envelope = (TC_CMS_envelope_encoding)2};
  const TC_CMS_verification_policy* policies[] = {NULL, &bad};
  for (size_t i = 0; i < sizeof policies / sizeof *policies; ++i) {
    size_t work = WORK_BUDGET;
    TC_TLV_reader reader, saved_reader;
    TC_CMS_signer_info signer, saved_signer;
    memset(&reader, 0xa5, sizeof reader);
    memcpy(&saved_reader, &reader, sizeof reader);
    memset(&signer, 0xa5, sizeof signer);
    memcpy(&saved_signer, &signer, sizeof signer);
    memcpy(&parsed, &saved, sizeof parsed);
    munit_assert_int(TC_CMS_signed_data_read((TC_bytes){detached, sizeof detached}, policies[i],
                                             &limits, (TC_TLV_frames){frames, FRAME_CAPACITY},
                                             &work, &parsed),
                     ==, TC_TLV_ARGUMENT);
    munit_assert_int(TC_CMS_signers_init((TC_bytes){detached + sizeof detached - 2, 2}, policies[i],
                                         &limits, (TC_TLV_frames){frames, FRAME_CAPACITY}, &work,
                                         &reader),
                     ==, TC_TLV_ARGUMENT);
    munit_assert_int(TC_CMS_signer_info_read((TC_bytes){detached, sizeof detached}, policies[i],
                                             &limits, (TC_TLV_frames){frames, FRAME_CAPACITY},
                                             &work, &signer),
                     ==, TC_TLV_ARGUMENT);
    munit_assert_size(work, ==, WORK_BUDGET);
    munit_assert_memory_equal(sizeof parsed, &parsed, &saved);
    munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
    munit_assert_memory_equal(sizeof signer, &signer, &saved_signer);
  }
  return MUNIT_OK;
}

TC_TEST(storage)
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
  enum { ENVELOPE, ATTRIBUTES, SIGNER, SIGNERS_INIT, SIGNER_NEXT, DIGEST, READER_COUNT };
  for (unsigned reader = 0; reader < READER_COUNT; ++reader)
    for (unsigned left = 0; left < SLOT_COUNT; ++left)
      for (unsigned right = left + 1; right < SLOT_COUNT; ++right) {
        void* pointers[SLOT_COUNT];
        memset(slots, 0xa5, sizeof slots);
        memcpy(slots[INPUT].input, detached, sizeof detached);
        slots[LIMITS].limits = (TC_TLV_limits){INPUT_CAPACITY, INPUT_CAPACITY, 32, FRAME_CAPACITY};
        slots[WORK].work = WORK_BUDGET;
        for (unsigned i = 0; i < SLOT_COUNT; ++i)
          pointers[i] = &slots[i];
        pointers[left] = pointers[right];
        if (reader == SIGNER_NEXT) {
          TC_TLV_reader* state = pointers[LIMITS];
          *state = (TC_TLV_reader){0};
          state->input = (TC_bytes){pointers[INPUT], sizeof detached};
          state->profile = TC_TLV_BER;
        }
        memcpy(saved, slots, sizeof slots);
        const TC_bytes input = {pointers[INPUT], sizeof detached};
        TC_TLV_result result;
        if (reader == ATTRIBUTES)
          result = TC_CMS_signed_attributes_read(input, &cms_policy, pointers[LIMITS],
                                                 (TC_TLV_frames){pointers[FRAMES], FRAME_CAPACITY},
                                                 pointers[WORK], pointers[OUTPUT]);
        else if (reader == SIGNER)
          result = TC_CMS_signer_info_read(input, &cms_policy, pointers[LIMITS],
                                           (TC_TLV_frames){pointers[FRAMES], FRAME_CAPACITY},
                                           pointers[WORK], pointers[OUTPUT]);
        else if (reader == SIGNERS_INIT)
          result = TC_CMS_signers_init(input, &cms_policy, pointers[LIMITS],
                                       (TC_TLV_frames){pointers[FRAMES], FRAME_CAPACITY},
                                       pointers[WORK], pointers[OUTPUT]);
        else if (reader == SIGNER_NEXT)
          result = TC_CMS_signer_next(pointers[LIMITS],
                                      (TC_TLV_frames){pointers[FRAMES], FRAME_CAPACITY},
                                      pointers[WORK], pointers[OUTPUT]);
        else if (reader == DIGEST)
          result = TC_CMS_content_digest(input, TC_HASH_SHA256, pointers[LIMITS],
                                         (TC_TLV_frames){pointers[FRAMES], FRAME_CAPACITY},
                                         pointers[WORK], pointers[OUTPUT], INPUT_CAPACITY);
        else
          result = TC_CMS_signed_data_read(input, &cms_policy, pointers[LIMITS],
                                           (TC_TLV_frames){pointers[FRAMES], FRAME_CAPACITY},
                                           pointers[WORK], pointers[OUTPUT]);
        munit_assert_int(result, ==, TC_TLV_ARGUMENT);
        munit_assert_memory_equal(sizeof slots, slots, saved);
      }
  TC_TLV_limits limits = {INPUT_CAPACITY, INPUT_CAPACITY, 32, FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_CMS_signed_data output, unchanged;
  memset(&unchanged, 0xa5, sizeof unchanged);
  output = unchanged;
  size_t work = WORK_BUDGET;
  munit_assert_int(TC_CMS_signed_data_read(
                       (TC_bytes){detached, sizeof detached}, &cms_policy, &limits,
                       (TC_TLV_frames){frames, SIZE_MAX / sizeof *frames + 1}, &work, &output),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, WORK_BUDGET);
  munit_assert_memory_equal(sizeof output, &output, &unchanged);
  uint8_t digest[INPUT_CAPACITY], saved_digest[INPUT_CAPACITY];
  memset(digest, 0xa5, sizeof digest);
  memcpy(saved_digest, digest, sizeof digest);
  work = WORK_BUDGET;
  munit_assert_int(TC_CMS_content_digest((TC_bytes){detached, sizeof detached}, TC_HASH_SHA256,
                                         &limits, (TC_TLV_frames){frames, FRAME_CAPACITY}, &work,
                                         digest, sizeof digest),
                   ==, TC_TLV_UNSUPPORTED);
  munit_assert_memory_equal(sizeof digest, digest, saved_digest);
  return MUNIT_OK;
}

TC_TEST(signer_iteration)
{
  static const uint8_t record[] = {0x30, 21, 2,    1, 3, 0x80, 1,    0xaa, 0x30, 4, 6,   2,
                                   0x2a, 3,  0x30, 4, 6, 2,    0x2a, 3,    4,    1, 0xbb};
  enum { VERSION_OFFSET = 4 };
  uint8_t encoded[INPUT_CAPACITY], saved_frames[FRAME_CAPACITY * sizeof(TC_TLV_frame)];
  const TC_TLV_limits limits = {INPUT_CAPACITY, INPUT_CAPACITY, 64, FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_TLV_reader reader, saved_reader;
  TC_CMS_signer_info signer, saved;
  memset(&saved, 0xa5, sizeof saved);
  for (unsigned outer_indefinite = 0; outer_indefinite < 2; ++outer_indefinite)
    for (unsigned inner_indefinite = 0; inner_indefinite < 2; ++inner_indefinite) {
      size_t length = 2, offsets[2], work = WORK_BUDGET;
      for (unsigned i = 0; i < 2; ++i) {
        offsets[i] = length;
        memcpy(encoded + length, record, sizeof record);
        if (inner_indefinite)
          encoded[length + 1] = 0x80;
        length += sizeof record;
        if (inner_indefinite) {
          encoded[length++] = 0;
          encoded[length++] = 0;
        }
      }
      encoded[0] = 0x31;
      encoded[1] = (uint8_t)(length - 2);
      if (outer_indefinite) {
        encoded[1] = 0x80;
        encoded[length++] = 0;
        encoded[length++] = 0;
      }
      const TC_bytes input = {encoded, length};
      ExampleCMSWorkspace example;
      munit_assert_int(example_parse_cms_signers(input, WORK_BUDGET, &example), ==, TC_TLV_OK);
      munit_assert_int(TC_CMS_signers_init(input, &cms_policy, &limits,
                                           (TC_TLV_frames){frames, FRAME_CAPACITY}, &work, &reader),
                       ==, TC_TLV_OK);
      const size_t init_work = WORK_BUDGET - work;
      const TC_TLV_reader start = reader;
      for (size_t budget = 0; budget < init_work; ++budget) {
        reader = start;
        work = budget;
        munit_assert_int(TC_CMS_signers_init(input, &cms_policy, &limits,
                                             (TC_TLV_frames){frames, FRAME_CAPACITY}, &work,
                                             &reader),
                         ==, TC_TLV_LIMIT);
        munit_assert_memory_equal(sizeof reader, &reader, &start);
      }
      size_t total_work = init_work;
      reader = start;
      for (unsigned i = 0; i < 2; ++i) {
        saved_reader = reader;
        work = WORK_BUDGET;
        munit_assert_int(
            TC_CMS_signer_next(&reader, (TC_TLV_frames){frames, FRAME_CAPACITY}, &work, &signer),
            ==, TC_TLV_OK);
        munit_assert_ptr_equal(signer.encoded.data, encoded + offsets[i]);
        munit_assert_uint(signer.version, ==, 3);
        const size_t required = WORK_BUDGET - work;
        total_work += required;
        for (size_t budget = 0; budget < required; ++budget) {
          reader = saved_reader;
          signer = saved;
          work = budget;
          munit_assert_int(
              TC_CMS_signer_next(&reader, (TC_TLV_frames){frames, FRAME_CAPACITY}, &work, &signer),
              ==, TC_TLV_LIMIT);
          munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
          munit_assert_memory_equal(sizeof signer, &signer, &saved);
        }
        reader = saved_reader;
        work = required;
        munit_assert_int(
            TC_CMS_signer_next(&reader, (TC_TLV_frames){frames, FRAME_CAPACITY}, &work, &signer),
            ==, TC_TLV_OK);
        munit_assert_size(work, ==, 0);
      }
      saved_reader = reader;
      signer = saved;
      work = 0;
      memset(frames, 0xa5, sizeof frames);
      memcpy(saved_frames, frames, sizeof frames);
      munit_assert_int(
          TC_CMS_signer_next(&reader, (TC_TLV_frames){frames, FRAME_CAPACITY}, &work, &signer), ==,
          TC_TLV_END);
      munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
      munit_assert_memory_equal(sizeof signer, &signer, &saved);
      munit_assert_memory_equal(sizeof frames, frames, saved_frames);
      munit_assert_size(work, ==, 0);
      work = total_work;
      munit_assert_int(TC_CMS_signers_init(input, &cms_policy, &limits,
                                           (TC_TLV_frames){frames, FRAME_CAPACITY}, &work, &reader),
                       ==, TC_TLV_OK);
      for (unsigned i = 0; i < 2; ++i)
        munit_assert_int(
            TC_CMS_signer_next(&reader, (TC_TLV_frames){frames, FRAME_CAPACITY}, &work, &signer),
            ==, TC_TLV_OK);
      munit_assert_int(
          TC_CMS_signer_next(&reader, (TC_TLV_frames){frames, FRAME_CAPACITY}, &work, &signer), ==,
          TC_TLV_END);
      munit_assert_size(work, ==, 0);
      encoded[offsets[1] + VERSION_OFFSET] = 1;
      munit_assert_int(example_parse_cms_signers(input, WORK_BUDGET, &example), ==, TC_TLV_INVALID);
      reader = start;
      work = WORK_BUDGET;
      munit_assert_int(
          TC_CMS_signer_next(&reader, (TC_TLV_frames){frames, FRAME_CAPACITY}, &work, &signer), ==,
          TC_TLV_OK);
      saved_reader = reader;
      signer = saved;
      munit_assert_int(
          TC_CMS_signer_next(&reader, (TC_TLV_frames){frames, FRAME_CAPACITY}, &work, &signer), ==,
          TC_TLV_INVALID);
      munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
      munit_assert_memory_equal(sizeof signer, &signer, &saved);
      for (unsigned invalid_state = 0; invalid_state < 2; ++invalid_state) {
        reader = start;
        if (invalid_state)
          reader.profile = TC_TLV_ISO7816;
        else
          reader.offset = reader.input.length + 1;
        saved_reader = reader;
        signer = saved;
        work = WORK_BUDGET;
        munit_assert_int(
            TC_CMS_signer_next(&reader, (TC_TLV_frames){frames, FRAME_CAPACITY}, &work, &signer),
            ==, TC_TLV_ARGUMENT);
        munit_assert_memory_equal(sizeof reader, &reader, &saved_reader);
        munit_assert_memory_equal(sizeof signer, &signer, &saved);
        munit_assert_size(work, ==, WORK_BUDGET);
      }
    }
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {{"/envelope", read_envelope, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {"/content", embedded_content, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {"/der-envelope", der_envelope, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {"/storage", storage, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {"/signers", signer_iteration, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/cms/reader", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
