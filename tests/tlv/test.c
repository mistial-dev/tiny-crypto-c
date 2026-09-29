/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/tlv.h>
#include <tiny_crypto/der.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "munit.h"
#include "test_util.h"
static const TC_TLV_limits limits = {SIZE_MAX, SIZE_MAX, 4096, 16};

/* X.690 sections 8 and 10, ISO 7816-4 section 6. */
TC_TEST(headers)
{
  static const uint8_t sequence[] = {0x30, 3, 2, 1, 42};
  static const uint8_t long_tag[] = {0x5f, 0x20, 0};
  static const uint8_t nonshort[] = {4, 0x81, 1, 0xaa};
  static const uint8_t leadingzero[] = {4, 0x82, 0, 1, 0xaa};
  static const uint8_t badtags[][7] = {{0, 0},
                                       {0x1f, 0x1e, 0},
                                       {0x1f, 0x80, 0x1f, 0},
                                       {4, 0xff},
                                       {0x20, 0},
                                       {4, 0x80},
                                       {0x1f, 0x90, 0x80, 0x80, 0x80, 0, 0}};
  static const size_t badlength[] = {2, 3, 4, 2, 2, 2, 7};
  TC_TLV_element e, before;
  TC_TLV_header h, old;
  TC_TLV_limits small = limits;
  size_t i;
  memset(&e, 0xa5, sizeof e);
  before = e;
  for (i = 0; i < sizeof sequence; ++i) {
    munit_assert(TC_TLV_read((TC_bytes){sequence, i}, TC_TLV_DER, &limits, &e) == TC_TLV_MORE);
    munit_assert(memcmp(&e, &before, sizeof e) == 0);
  }
  munit_assert(TC_TLV_read((TC_bytes){sequence, sizeof sequence}, TC_TLV_DER, &limits, &e) ==
               TC_TLV_OK);
  munit_assert(e.header.number == 16 && e.header.constructed == 1 && e.header.tag_class == 0);
  munit_assert(e.value.data == sequence + 2 && e.value.length == 3 && e.encoded.length == 5);
  munit_assert(TC_TLV_read((TC_bytes){long_tag, sizeof long_tag}, TC_TLV_ISO7816, &limits, &e) ==
               TC_TLV_OK);
  munit_assert(e.header.number == 32 && e.header.tag_class == 1 && e.header.tag_length == 2);
  munit_assert(e.header.tag[0] == 0x5f && e.header.tag[1] == 0x20);
  munit_assert(TC_TLV_read((TC_bytes){nonshort, sizeof nonshort}, TC_TLV_DER, &limits, &e) ==
               TC_TLV_INVALID);
  munit_assert(TC_TLV_read((TC_bytes){nonshort, sizeof nonshort}, TC_TLV_ISO7816, &limits, &e) ==
               TC_TLV_OK);
  munit_assert(TC_TLV_read((TC_bytes){leadingzero, sizeof leadingzero}, TC_TLV_DER, &limits, &e) ==
               TC_TLV_INVALID);
  munit_assert(TC_TLV_read((TC_bytes){leadingzero, sizeof leadingzero}, TC_TLV_ISO7816, &limits,
                           &e) == TC_TLV_OK);
  for (i = 0; i < sizeof badlength / sizeof badlength[0]; ++i)
    munit_assert(TC_TLV_read((TC_bytes){badtags[i], badlength[i]}, TC_TLV_DER, &limits, &e) < 0);
  memset(&h, 0x5a, sizeof h);
  old = h;
  small.max_value = 2;
  munit_assert(TC_TLV_header_read((TC_bytes){sequence, 2}, TC_TLV_DER, &small, &h) == TC_TLV_LIMIT);
  munit_assert(memcmp(&h, &old, sizeof h) == 0);
  munit_assert(TC_TLV_header_read((TC_bytes){NULL, 1}, TC_TLV_DER, &limits, &h) == TC_TLV_ARGUMENT);
  munit_assert(TC_TLV_header_read((TC_bytes){sequence, 2}, (TC_TLV_profile)99, &limits, &h) ==
               TC_TLV_ARGUMENT);
  munit_assert(TC_TLV_header_read((TC_bytes){sequence, 2}, TC_TLV_DER, NULL, &h) ==
               TC_TLV_ARGUMENT);
  munit_assert(TC_TLV_read((TC_bytes){sequence, 5}, TC_TLV_DER, &limits, NULL) == TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

TC_TEST(lengths)
{
  static const size_t values[] = {0, 1, 127, 128, 255, 256, 1024};
  static const uint8_t expected_headers[] = {2, 2, 2, 3, 3, 4, 4};
  size_t i;
  uint8_t bytes[1028];
  TC_TLV_element e;
  for (i = 0; i < sizeof values / sizeof values[0]; ++i) {
    size_t n = values[i], h = expected_headers[i];
    memset(bytes, 0x80, sizeof bytes);
    bytes[0] = 4;
    if (n < 128)
      bytes[1] = (uint8_t)n;
    else if (n < 256) {
      bytes[1] = 0x81;
      bytes[2] = (uint8_t)n;
    } else {
      bytes[1] = 0x82;
      bytes[2] = (uint8_t)(n >> 8);
      bytes[3] = (uint8_t)n;
    }
    munit_assert(TC_TLV_read((TC_bytes){bytes, h + n}, TC_TLV_DER, &limits, &e) == TC_TLV_OK);
    munit_assert(e.header.header_length == h && e.value.length == n);
    munit_assert(TC_TLV_read((TC_bytes){bytes, h + n - 1}, TC_TLV_DER, &limits, &e) == TC_TLV_MORE);
  }
  /* The declared value can fit size_t while header + value would overflow. */
  memset(bytes, 255, sizeof bytes);
  bytes[0] = 4;
  bytes[1] = (uint8_t)(0x80 | sizeof(size_t));
  munit_assert(TC_TLV_read((TC_bytes){bytes, 2 + sizeof(size_t)}, TC_TLV_DER, &limits, &e) ==
               TC_TLV_MORE);
  bytes[1] = (uint8_t)(0x81 + sizeof(size_t));
  munit_assert(TC_TLV_read((TC_bytes){bytes, 2 + sizeof(size_t)}, TC_TLV_DER, &limits, &e) ==
               TC_TLV_LIMIT);
  return MUNIT_OK;
}

TC_TEST(cursor)
{
  static const uint8_t input[] = {0, 4, 0, 0xff, 2, 1, 42, 0};
  static const uint8_t truncated[] = {4, 2, 1};
  TC_TLV_reader r, saved;
  TC_TLV_element e, old;
  munit_assert(TC_TLV_reader_init(&r, (TC_bytes){input, sizeof input}, TC_TLV_ISO7816_PAD_ZERO_FF,
                                  &limits) == TC_TLV_OK);
  munit_assert(TC_TLV_next(&r, &e) == TC_TLV_OK && r.offset == 3);
  munit_assert(TC_TLV_next(&r, &e) == TC_TLV_OK && r.offset == 7);
  munit_assert(e.value.length == 1 && e.value.data[0] == 42);
  munit_assert(TC_TLV_next(&r, &e) == TC_TLV_END && r.offset == sizeof input);
  munit_assert(TC_TLV_reader_init(&r, (TC_bytes){truncated, sizeof truncated}, TC_TLV_DER,
                                  &limits) == TC_TLV_OK);
  saved = r;
  old = e;
  munit_assert(TC_TLV_next(&r, &e) == TC_TLV_MORE);
  munit_assert(memcmp(&r, &saved, sizeof r) == 0 && memcmp(&e, &old, sizeof e) == 0);
  munit_assert(TC_TLV_reader_init(&r, (TC_bytes){NULL, 0}, TC_TLV_DER, &limits) == TC_TLV_OK);
  munit_assert(TC_TLV_next(&r, &e) == TC_TLV_END);
  saved = r;
  munit_assert(TC_TLV_reader_init(&r, (TC_bytes){NULL, 1}, TC_TLV_DER, &limits) == TC_TLV_ARGUMENT);
  munit_assert_size(r.offset, ==, saved.offset);
  munit_assert_ptr_equal(r.input.data, saved.input.data);
  {
    /* next rewrites the reader while it reads input, so they must not alias. */
    union {
      TC_TLV_reader reader;
      uint8_t bytes[sizeof(TC_TLV_reader) + sizeof input];
    } shared;
    uint8_t original[sizeof shared];
    const size_t offsets[] = {0, 1, sizeof(TC_TLV_reader) - 1};
    size_t i;
    for (i = 0; i < sizeof offsets / sizeof *offsets; ++i) {
      memset(&shared, 0x5a, sizeof shared);
      memcpy(shared.bytes + offsets[i], input, sizeof input);
      memcpy(original, &shared, sizeof original);
      munit_assert_int(TC_TLV_reader_init(&shared.reader,
                                          (TC_bytes){shared.bytes + offsets[i], sizeof input},
                                          TC_TLV_DER, &limits),
                       ==, TC_TLV_ARGUMENT);
      munit_assert_memory_equal(sizeof original, original, &shared);
    }
    memcpy(shared.bytes + sizeof(TC_TLV_reader), input, sizeof input);
    munit_assert_int(
        TC_TLV_reader_init(&shared.reader,
                           (TC_bytes){shared.bytes + sizeof(TC_TLV_reader), sizeof input},
                           TC_TLV_DER, &limits),
        ==, TC_TLV_OK);
  }
  return MUNIT_OK;
}

/* ISO/IEC 7816-4:2020 section 6.4: a constructed template holds nested data
 * objects without padding. Padding is a root-level property of the reader. */
TC_TEST(child_reader)
{
  static const uint8_t padded[] = {0, 0x30, 3, 0, 4, 0, 0xff};
  static const uint8_t nested[] = {0x30, 4, 4, 0, 4, 0};
  static const uint8_t other[] = {0x30, 0};
  TC_TLV_reader root, child, saved;
  TC_TLV_element sequence, e, old;
  munit_assert(TC_TLV_reader_init(&root, (TC_bytes){padded, sizeof padded},
                                  TC_TLV_ISO7816_PAD_ZERO_FF, &limits) == TC_TLV_OK);
  munit_assert(TC_TLV_next(&root, &sequence) == TC_TLV_OK && sequence.value.data == padded + 3);
  munit_assert(TC_TLV_next(&root, &e) == TC_TLV_END);
  munit_assert(TC_TLV_reader_child(&child, &root, &sequence) == TC_TLV_OK);
  munit_assert(child.profile == TC_TLV_ISO7816_PAD_ZERO_FF && child.offset == 0 &&
               child.elements == 0 && child.input.data == sequence.value.data &&
               child.input.length == sequence.value.length);
  saved = child;
  memset(&e, 0xa5, sizeof e);
  old = e;
  munit_assert(TC_TLV_next(&child, &e) == TC_TLV_INVALID);
  munit_assert(memcmp(&child, &saved, sizeof child) == 0 && memcmp(&e, &old, sizeof e) == 0);

  /* Children of an unpadded template read normally and inherit limits. */
  TC_TLV_limits small = limits;
  small.max_elements = 1;
  munit_assert(TC_TLV_reader_init(&root, (TC_bytes){nested, sizeof nested}, TC_TLV_DER, &small) ==
               TC_TLV_OK);
  munit_assert(TC_TLV_next(&root, &sequence) == TC_TLV_OK);
  munit_assert(TC_TLV_reader_child(&child, &root, &sequence) == TC_TLV_OK);
  munit_assert(child.limits.max_elements == 1);
  munit_assert(TC_TLV_next(&child, &e) == TC_TLV_OK && e.value.data == nested + 4);
  munit_assert(TC_TLV_next(&child, &e) == TC_TLV_LIMIT);

  /* A child template is complete, so a truncated nested element is malformed. */
  static const uint8_t overrun[] = {0x30, 2, 4, 1};
  munit_assert(TC_TLV_reader_init(&root, (TC_bytes){overrun, sizeof overrun}, TC_TLV_DER,
                                  &limits) == TC_TLV_OK);
  munit_assert(TC_TLV_next(&root, &sequence) == TC_TLV_OK);
  munit_assert(TC_TLV_reader_init(&saved, sequence.value, TC_TLV_DER, &limits) == TC_TLV_OK);
  munit_assert(TC_TLV_next(&saved, &e) == TC_TLV_MORE);
  munit_assert(TC_TLV_reader_child(&child, &root, &sequence) == TC_TLV_OK);
  munit_assert(TC_TLV_next(&child, &e) == TC_TLV_INVALID);
  munit_assert(TC_TLV_reader_init(&root, (TC_bytes){nested, sizeof nested}, TC_TLV_DER, &small) ==
               TC_TLV_OK);
  munit_assert(TC_TLV_next(&root, &sequence) == TC_TLV_OK);
  munit_assert(TC_TLV_reader_child(&child, &root, &sequence) == TC_TLV_OK);
  munit_assert(TC_TLV_next(&child, &e) == TC_TLV_OK);

  /* Nested readers stay nonroot. */
  munit_assert(TC_TLV_reader_child(&saved, &child, &e) == TC_TLV_OK);
  munit_assert(TC_TLV_next(&saved, &e) == TC_TLV_END);

  /* The element must lie inside the parent input. Failures leave child unchanged. */
  munit_assert(TC_TLV_reader_init(&root, (TC_bytes){other, sizeof other}, TC_TLV_DER, &limits) ==
               TC_TLV_OK);
  munit_assert(TC_TLV_next(&root, &e) == TC_TLV_OK);
  memset(&child, 0x5a, sizeof child);
  saved = child;
  munit_assert(TC_TLV_reader_child(&child, &root, &sequence) == TC_TLV_ARGUMENT);
  munit_assert(TC_TLV_reader_child(NULL, &root, &e) == TC_TLV_ARGUMENT);
  munit_assert(TC_TLV_reader_child(&child, NULL, &e) == TC_TLV_ARGUMENT);
  munit_assert(TC_TLV_reader_child(&child, &root, NULL) == TC_TLV_ARGUMENT);
  munit_assert(memcmp(&child, &saved, sizeof child) == 0);
  return MUNIT_OK;
}

struct events {
  uint32_t bytes;
  size_t begins, closes, max_depth;
};
static void visit(void* user, const TC_TLV_event* e)
{
  struct events* v = (struct events*)user;
  size_t i;
  if (e->kind == TC_TLV_BEGIN)
    ++v->begins;
  if (e->kind == TC_TLV_CLOSE)
    ++v->closes;
  if (v->max_depth < e->depth)
    v->max_depth = e->depth;
  /* Hash the original bytes so every chunk partition produces the same value. */
  for (i = 0; i < e->bytes.length; ++i)
    v->bytes = v->bytes * 33 + e->bytes.data[i];
}

TC_TEST(walks)
{
  static const uint8_t definite[] = {0x30, 9, 0x30, 3, 2, 1, 42, 4, 2, 0, 0};
  static const uint8_t indefinite[] = {0x30, 0x80, 0x30, 0x80, 2, 1, 42, 0, 0, 4, 2, 0, 0, 0, 0};
  static const uint8_t escape[] = {0x30, 2, 4, 3, 1, 2, 3};
  static const uint8_t nested_padding[] = {0x30, 1, 0};
  static const uint8_t escaped_eoc[] = {0x30, 2, 0x30, 0x80, 0, 0};
  TC_TLV_frame frames[16];
  TC_TLV_limits small = limits;
  struct events expected = {0, 0, 0, 0};
  size_t i;
  uint32_t hash = 0;
  munit_assert(TC_TLV_walk((TC_bytes){definite, sizeof definite}, TC_TLV_DER, &limits,
                           (TC_TLV_frames){frames, 16}, visit, &expected) == TC_TLV_OK);
  for (i = 0; i < sizeof definite; ++i)
    hash = hash * 33 + definite[i];
  munit_assert(expected.bytes == hash && expected.begins == 4 && expected.closes == 4 &&
               expected.max_depth == 2);
  for (i = 1; i < sizeof definite; ++i)
    munit_assert(TC_TLV_walk((TC_bytes){definite, i}, TC_TLV_DER, &limits,
                             (TC_TLV_frames){frames, 16}, NULL, NULL) == TC_TLV_INVALID);
  munit_assert(TC_TLV_walk((TC_bytes){NULL, 1}, TC_TLV_DER, &limits, (TC_TLV_frames){frames, 16},
                           NULL, NULL) == TC_TLV_ARGUMENT);
  munit_assert(TC_TLV_walk((TC_bytes){escape, sizeof escape}, TC_TLV_DER, &limits,
                           (TC_TLV_frames){frames, 16}, NULL, NULL) == TC_TLV_INVALID);
  munit_assert(TC_TLV_walk((TC_bytes){nested_padding, sizeof nested_padding},
                           TC_TLV_ISO7816_PAD_ZERO, &limits, (TC_TLV_frames){frames, 16}, NULL,
                           NULL) == TC_TLV_INVALID);
  small.max_elements = 3;
  munit_assert(TC_TLV_walk((TC_bytes){definite, sizeof definite}, TC_TLV_DER, &small,
                           (TC_TLV_frames){frames, 16}, NULL, NULL) == TC_TLV_LIMIT);
  small = limits;
  small.max_depth = 1;
  munit_assert(TC_TLV_walk((TC_bytes){definite, sizeof definite}, TC_TLV_DER, &small,
                           (TC_TLV_frames){frames, 16}, NULL, NULL) == TC_TLV_LIMIT);
  munit_assert(TC_TLV_walk((TC_bytes){definite, sizeof definite}, TC_TLV_DER, &limits,
                           (TC_TLV_frames){NULL, 0}, NULL, NULL) == TC_TLV_LIMIT);
  munit_assert(TC_TLV_walk((TC_bytes){indefinite, sizeof indefinite}, TC_TLV_DER, &limits,
                           (TC_TLV_frames){frames, 16}, NULL, NULL) == TC_TLV_INVALID);
#if TC_TLV_ENABLE_BER
  munit_assert(TC_TLV_walk((TC_bytes){indefinite, sizeof indefinite}, TC_TLV_BER, &limits,
                           (TC_TLV_frames){frames, 16}, NULL, NULL) == TC_TLV_OK);
  munit_assert(TC_TLV_walk((TC_bytes){escaped_eoc, sizeof escaped_eoc}, TC_TLV_BER, &limits,
                           (TC_TLV_frames){frames, 16}, NULL, NULL) == TC_TLV_INVALID);
  small = limits;
  small.max_value = 2;
  munit_assert(TC_TLV_walk((TC_bytes){indefinite, sizeof indefinite}, TC_TLV_BER, &small,
                           (TC_TLV_frames){frames, 16}, NULL, NULL) == TC_TLV_LIMIT);
#else
  (void)escaped_eoc;
  munit_assert(TC_TLV_walk((TC_bytes){indefinite, sizeof indefinite}, TC_TLV_BER, &limits,
                           (TC_TLV_frames){frames, 16}, NULL, NULL) == TC_TLV_UNSUPPORTED);
#endif
#if TC_TLV_ENABLE_STREAM
  for (i = 0; i <= sizeof definite; ++i) {
    TC_TLV_stream s;
    struct events actual = {0, 0, 0, 0};
    TC_TLV_result r;
    munit_assert(TC_TLV_stream_init(&s, TC_TLV_DER, &limits, (TC_TLV_frames){frames, 16}) ==
                 TC_TLV_OK);
    r = TC_TLV_stream_feed(&s, (TC_bytes){definite, i}, visit, &actual);
    munit_assert(r == TC_TLV_OK || r == TC_TLV_MORE);
    munit_assert(TC_TLV_stream_feed(&s, (TC_bytes){definite + i, sizeof definite - i}, visit,
                                    &actual) == TC_TLV_OK);
    munit_assert(TC_TLV_stream_finish(&s) == TC_TLV_OK);
    munit_assert(actual.bytes == expected.bytes && actual.begins == 4 && actual.closes == 4);
    munit_assert(TC_TLV_stream_feed(&s, (TC_bytes){NULL, 0}, NULL, NULL) == TC_TLV_ARGUMENT);
    munit_assert(TC_TLV_stream_init(&s, TC_TLV_DER, &limits, (TC_TLV_frames){frames, 16}) ==
                 TC_TLV_OK);
    munit_assert(TC_TLV_stream_feed(&s, (TC_bytes){NULL, 1}, NULL, NULL) == TC_TLV_ARGUMENT);
  }
  {
    TC_TLV_stream s;
    munit_assert(TC_TLV_stream_init(&s, TC_TLV_DER, &limits, (TC_TLV_frames){frames, 16}) ==
                 TC_TLV_OK);
    munit_assert(TC_TLV_stream_feed(&s, (TC_bytes){escape, sizeof escape}, NULL, NULL) ==
                 TC_TLV_INVALID);
    munit_assert(TC_TLV_stream_feed(&s, (TC_bytes){definite, sizeof definite}, NULL, NULL) ==
                 TC_TLV_INVALID);
    munit_assert(TC_TLV_stream_finish(&s) == TC_TLV_INVALID);
  }
#if TC_TLV_ENABLE_BER
  for (i = 1; i <= sizeof indefinite; ++i) {
    TC_TLV_stream s;
    size_t p = 0;
    munit_assert(TC_TLV_stream_init(&s, TC_TLV_BER, &limits, (TC_TLV_frames){frames, 16}) ==
                 TC_TLV_OK);
    while (p < sizeof indefinite) {
      size_t n = sizeof indefinite - p;
      TC_TLV_result r;
      if (n > i)
        n = i;
      r = TC_TLV_stream_feed(&s, (TC_bytes){indefinite + p, n}, NULL, NULL);
      munit_assert(r == TC_TLV_OK || r == TC_TLV_MORE);
      p += n;
    }
    munit_assert(TC_TLV_stream_finish(&s) == TC_TLV_OK);
  }
#endif
#endif
  return MUNIT_OK;
}

struct borrowed {
  const uint8_t* input;
  size_t events, borrowed;
};
static void check_borrowed(void* user, const TC_TLV_event* e)
{
  struct borrowed* b = (struct borrowed*)user;
  if (!e->bytes.length)
    return;
  ++b->events;
  munit_assert_memory_equal(e->bytes.length, e->bytes.data, b->input + e->offset);
  /* Every walk span, including BEGIN headers and EOC markers, points into input. */
  if (e->bytes.data == b->input + e->offset)
    ++b->borrowed;
}

TC_TEST(walk_spans_borrow_input)
{
  static const uint8_t definite[] = {0x30, 9, 0x30, 3, 2, 1, 42, 4, 2, 0, 0};
  TC_TLV_frame frames[4];
  struct borrowed spans = {definite, 0, 0};
  munit_assert(TC_TLV_walk((TC_bytes){definite, sizeof definite}, TC_TLV_DER, &limits,
                           (TC_TLV_frames){frames, 4}, check_borrowed, &spans) == TC_TLV_OK);
  /* Four headers and two primitive values. */
  munit_assert_size(spans.events, ==, 6);
  munit_assert_size(spans.borrowed, ==, spans.events);
#if TC_TLV_ENABLE_STREAM
  /* The header at offset 2 straddles the two chunks and comes from stream
   * storage. Every other span borrows its fed chunk. */
  TC_TLV_stream stream;
  struct borrowed split = {definite, 0, 0};
  munit_assert(TC_TLV_stream_init(&stream, TC_TLV_DER, &limits, (TC_TLV_frames){frames, 4}) ==
               TC_TLV_OK);
  munit_assert(TC_TLV_stream_feed(&stream, (TC_bytes){definite, 3}, check_borrowed, &split) ==
               TC_TLV_MORE);
  munit_assert(TC_TLV_stream_feed(&stream, (TC_bytes){definite + 3, sizeof definite - 3},
                                  check_borrowed, &split) == TC_TLV_OK);
  munit_assert(TC_TLV_stream_finish(&stream) == TC_TLV_OK);
  munit_assert_size(split.events, ==, 6);
  munit_assert_size(split.borrowed, ==, 5);
#endif
#if TC_TLV_ENABLE_BER
  static const uint8_t indefinite[] = {0x30, 0x80, 0x30, 0x80, 2, 1, 42, 0, 0, 4, 2, 0, 0, 0, 0};
  struct borrowed ber = {indefinite, 0, 0};
  munit_assert(TC_TLV_walk((TC_bytes){indefinite, sizeof indefinite}, TC_TLV_BER, &limits,
                           (TC_TLV_frames){frames, 4}, check_borrowed, &ber) == TC_TLV_OK);
  /* Four headers, two primitive values and two EOC markers. */
  munit_assert_size(ber.events, ==, 8);
  munit_assert_size(ber.borrowed, ==, ber.events);
#endif
  return MUNIT_OK;
}

#if TC_ENABLE_DER
TC_TEST(signatures)
{
  static const uint8_t absent[] = {0x30, 3, 6, 1, 42};
  static const uint8_t null_parameter[] = {0x30, 5, 6, 1, 42, 5, 0};
  static const uint8_t extra[] = {0x30, 7, 6, 1, 42, 5, 0, 5, 0};
  static const uint8_t empty[] = {0x30, 0};
  static const uint8_t bad_child[] = {0x30, 3, 6, 2, 42};
  static const uint8_t signature[] = {0x30, 7, 2, 2, 0, 128, 2, 1, 1};
  static const uint8_t zero_r[] = {0x30, 6, 2, 1, 0, 2, 1, 1};
  static const uint8_t negative_s[] = {0x30, 6, 2, 1, 1, 2, 1, 255};
  static const uint8_t missing_s[] = {0x30, 3, 2, 1, 1};
  TC_DER_algorithm algorithm, saved_algorithm;
  TC_DER_signature_pair pair, saved_pair;
  size_t i;
  munit_assert(TC_DER_algorithm_identifier((TC_bytes){absent, sizeof absent}, &algorithm) ==
               TC_TLV_OK);
  munit_assert(algorithm.oid.length == 1 && algorithm.oid.data[0] == 42);
  munit_assert(!algorithm.parameters.data && !algorithm.parameters.length);
  munit_assert(TC_DER_algorithm_identifier((TC_bytes){null_parameter, sizeof null_parameter},
                                           &algorithm) == TC_TLV_OK);
  munit_assert(algorithm.parameters.length == 2 && algorithm.parameters.data == null_parameter + 5);
  saved_algorithm = algorithm;
  munit_assert(TC_DER_algorithm_identifier((TC_bytes){extra, sizeof extra}, &algorithm) ==
               TC_TLV_INVALID);
  munit_assert(TC_DER_algorithm_identifier((TC_bytes){empty, sizeof empty}, &algorithm) ==
               TC_TLV_INVALID);
  munit_assert(TC_DER_algorithm_identifier((TC_bytes){bad_child, sizeof bad_child}, &algorithm) ==
               TC_TLV_INVALID);
  munit_assert(memcmp(&algorithm, &saved_algorithm, sizeof algorithm) == 0);
  munit_assert(TC_DER_ecdsa_signature((TC_bytes){signature, sizeof signature}, &pair) == TC_TLV_OK);
  munit_assert(pair.r.length == 1 && pair.r.data == signature + 5 && pair.r.data[0] == 128);
  munit_assert(pair.s.length == 1 && pair.s.data == signature + 8 && pair.s.data[0] == 1);
  saved_pair = pair;
  munit_assert(TC_DER_ecdsa_signature((TC_bytes){zero_r, sizeof zero_r}, &pair) == TC_TLV_INVALID);
  munit_assert(TC_DER_ecdsa_signature((TC_bytes){negative_s, sizeof negative_s}, &pair) ==
               TC_TLV_INVALID);
  munit_assert(TC_DER_ecdsa_signature((TC_bytes){missing_s, sizeof missing_s}, &pair) ==
               TC_TLV_INVALID);
  for (i = 0; i < sizeof signature; ++i)
    munit_assert(TC_DER_ecdsa_signature((TC_bytes){signature, i}, &pair) == TC_TLV_INVALID);
  munit_assert(memcmp(&pair, &saved_pair, sizeof pair) == 0);
  munit_assert(TC_DER_ecdsa_signature((TC_bytes){signature, sizeof signature}, NULL) ==
               TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

TC_TEST(rsa_public_key)
{
  uint8_t encoded[] = {0x30, 7, 2, 2, 0, 128, 2, 1, 3};
  TC_DER_rsa_public_key key;
  munit_assert_int(TC_DER_rsa_public((TC_bytes){encoded, sizeof encoded}, &key), ==, TC_TLV_OK);
  munit_assert_ptr_equal(key.modulus.data, encoded + 5);
  munit_assert_size(key.modulus.length, ==, 1);
  munit_assert_ptr_equal(key.exponent.data, encoded + 8);
  const TC_DER_rsa_public_key saved = key;
  for (size_t end = 0; end < sizeof encoded; ++end) {
    munit_assert_int(TC_DER_rsa_public((TC_bytes){encoded, end}, &key), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof key, &key, &saved);
  }
  const uint8_t bad_exponents[] = {0, 128, 255};
  for (size_t i = 0; i < sizeof bad_exponents; ++i) {
    encoded[8] = bad_exponents[i];
    munit_assert_int(TC_DER_rsa_public((TC_bytes){encoded, sizeof encoded}, &key), ==,
                     TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof key, &key, &saved);
  }
  encoded[8] = 3;
  encoded[5] = 127;
  munit_assert_int(TC_DER_rsa_public((TC_bytes){encoded, sizeof encoded}, &key), ==,
                   TC_TLV_INVALID);
  encoded[5] = 128;
  uint8_t extra[sizeof encoded + 2];
  memcpy(extra, encoded, sizeof encoded);
  extra[sizeof encoded] = 5;
  extra[sizeof encoded + 1] = 0;
  munit_assert_int(TC_DER_rsa_public((TC_bytes){extra, sizeof extra}, &key), ==, TC_TLV_INVALID);
  extra[1] += 2;
  munit_assert_int(TC_DER_rsa_public((TC_bytes){extra, sizeof extra}, &key), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof key, &key, &saved);
  munit_assert_int(TC_DER_rsa_public((TC_bytes){encoded, sizeof encoded}, NULL), ==,
                   TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

TC_TEST(private_key_info)
{
  /* An opaque key under OID 1.2, with an empty attributes set. */
  uint8_t encoded[] = {0x30, 13, 2, 1, 0, 0x30, 3, 6, 1, 42, 4, 1, 7, 0xa0, 0};
  TC_DER_private_key key;
  munit_assert_int(TC_DER_private_key_info((TC_bytes){encoded, sizeof encoded}, &key), ==,
                   TC_TLV_OK);
  munit_assert_ptr_equal(key.algorithm.oid.data, encoded + 9);
  munit_assert_ptr_equal(key.key.data, encoded + 12);
  munit_assert_size(key.key.length, ==, 1);
  munit_assert_ptr_equal(key.attributes.data, encoded + sizeof encoded);
  munit_assert_size(key.attributes.length, ==, 0);
  TC_DER_private_key saved;
  memset(&key, 0xa5, sizeof key);
  memset(&saved, 0xa5, sizeof saved);
  for (size_t i = 0; i < sizeof encoded; ++i) {
    munit_assert_int(TC_DER_private_key_info((TC_bytes){encoded, i}, &key), ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof key, &key, &saved);
  }
  const size_t tags[] = {0, 2, 5, 7, 10, 13};
  for (size_t i = 0; i < sizeof tags / sizeof *tags; ++i) {
    const uint8_t tag = encoded[tags[i]];
    encoded[tags[i]] = 5;
    munit_assert_int(TC_DER_private_key_info((TC_bytes){encoded, sizeof encoded}, &key), !=,
                     TC_TLV_OK);
    munit_assert_memory_equal(sizeof key, &key, &saved);
    encoded[tags[i]] = tag;
  }
  encoded[4] = 2;
  munit_assert_int(TC_DER_private_key_info((TC_bytes){encoded, sizeof encoded}, &key), ==,
                   TC_TLV_UNSUPPORTED);
  munit_assert_memory_equal(sizeof key, &key, &saved);
  encoded[4] = 0;
  munit_assert_int(TC_DER_private_key_info((TC_bytes){encoded, sizeof encoded}, NULL), ==,
                   TC_TLV_ARGUMENT);
  encoded[1] -= 2;
  munit_assert_int(TC_DER_private_key_info((TC_bytes){encoded, sizeof encoded}, &key), ==,
                   TC_TLV_INVALID);
  munit_assert_int(TC_DER_private_key_info((TC_bytes){encoded, sizeof encoded - 2}, &key), ==,
                   TC_TLV_OK);
  munit_assert_null(key.attributes.data);
  munit_assert_null(key.public_key.data);
  munit_assert_uint(key.public_key_unused, ==, 0);

  uint8_t with_public[] = {0x30, 17, 2, 1, 1, 0x30, 3, 6, 1, 42, 4, 1, 7, 0xa0, 0, 0x81, 2, 0, 8};
  munit_assert_int(TC_DER_private_key_info((TC_bytes){with_public, sizeof with_public}, &key), ==,
                   TC_TLV_OK);
  munit_assert_ptr_equal(key.public_key.data, with_public + 18);
  munit_assert_size(key.public_key.length, ==, 1);
  TC_DER_private_key public_saved;
  memset(&key, 0xa5, sizeof key);
  memset(&public_saved, 0xa5, sizeof public_saved);
  for (size_t end = 0; end < sizeof with_public; ++end) {
    munit_assert_int(TC_DER_private_key_info((TC_bytes){with_public, end}, &key), ==,
                     TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof key, &key, &public_saved);
  }
  /* Version and public-key presence must agree. */
  with_public[4] = 0;
  munit_assert_int(TC_DER_private_key_info((TC_bytes){with_public, sizeof with_public}, &key), ==,
                   TC_TLV_INVALID);
  with_public[4] = 1;
  with_public[1] -= 4;
  munit_assert_int(TC_DER_private_key_info((TC_bytes){with_public, sizeof with_public - 4}, &key),
                   ==, TC_TLV_INVALID);
  with_public[1] += 4;
  with_public[17] = 4;
  munit_assert_int(TC_DER_private_key_info((TC_bytes){with_public, sizeof with_public}, &key), ==,
                   TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof key, &key, &public_saved);
  with_public[17] = 3;
  munit_assert_int(TC_DER_private_key_info((TC_bytes){with_public, sizeof with_public}, &key), ==,
                   TC_TLV_OK);
  munit_assert_uint(key.public_key_unused, ==, 3);
  /* Public key also fits directly after the private key. */
  memmove(with_public + 13, with_public + 15, 4);
  with_public[1] -= 2;
  munit_assert_int(TC_DER_private_key_info((TC_bytes){with_public, sizeof with_public - 2}, &key),
                   ==, TC_TLV_OK);
  munit_assert_null(key.attributes.data);
  with_public[17] = 0xa0;
  with_public[18] = 0;
  with_public[1] += 2;
  munit_assert_int(TC_DER_private_key_info((TC_bytes){with_public, sizeof with_public}, &key), ==,
                   TC_TLV_INVALID);
  return MUNIT_OK;
}

/* The complete-input readers report truncation as malformed input. */
TC_TEST(der_truncation)
{
  static const uint8_t integer[] = {2, 5, 0};
  static const uint8_t short_header[] = {2};
  static const uint8_t long_length[] = {4, 0x82, 1};
  static const uint8_t algorithm[] = {0x30, 5, 6, 1, 42};
  TC_bytes v = {NULL, 0};
  TC_DER_algorithm parsed;
  uint32_t n = 7;
  int sign = 3;
  unsigned unused = 5;
  munit_assert_int(TC_DER_integer((TC_bytes){integer, sizeof integer}, &v, &sign), ==,
                   TC_TLV_INVALID);
  munit_assert_int(TC_DER_integer((TC_bytes){short_header, sizeof short_header}, &v, &sign), ==,
                   TC_TLV_INVALID);
  munit_assert_int(TC_DER_integer((TC_bytes){integer, 0}, &v, &sign), ==, TC_TLV_INVALID);
  munit_assert_int(TC_DER_uint32((TC_bytes){integer, sizeof integer}, &n), ==, TC_TLV_INVALID);
  munit_assert_int(TC_DER_bit_string((TC_bytes){long_length, sizeof long_length}, &v, &unused), ==,
                   TC_TLV_INVALID);
  munit_assert_int(TC_DER_oid((TC_bytes){integer, 1}, &v), ==, TC_TLV_INVALID);
  munit_assert_int(TC_DER_boolean((TC_bytes){integer, 1}, &sign), ==, TC_TLV_INVALID);
  munit_assert_int(TC_DER_null((TC_bytes){integer, 1}), ==, TC_TLV_INVALID);
  munit_assert_int(TC_DER_sequence((TC_bytes){algorithm, 1}, &v), ==, TC_TLV_INVALID);
  munit_assert_int(TC_DER_set((TC_bytes){algorithm, 1}, &v), ==, TC_TLV_INVALID);
  munit_assert_int(TC_DER_algorithm_identifier((TC_bytes){algorithm, sizeof algorithm}, &parsed),
                   ==, TC_TLV_INVALID);
  munit_assert(!v.data && !v.length && n == 7 && sign == 3 && unused == 5);
  munit_assert_int(TC_DER_integer((TC_bytes){NULL, 3}, &v, &sign), ==, TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

/* RFC 5280 section 4.1.2.7 SubjectPublicKeyInfo. */
TC_TEST(subject_public_key)
{
  static const uint8_t valid[] = {0x30, 9, 0x30, 3, 6, 1, 42, 3, 2, 0, 7};
  static const uint8_t unused_bits[] = {0x30, 9, 0x30, 3, 6, 1, 42, 3, 2, 1, 6};
  static const uint8_t empty_key[] = {0x30, 8, 0x30, 3, 6, 1, 42, 3, 1, 0};
  static const uint8_t trailing[] = {0x30, 11, 0x30, 3, 6, 1, 42, 3, 2, 0, 7, 5, 0};
  static const uint8_t missing_key[] = {0x30, 5, 0x30, 3, 6, 1, 42};
  static const uint8_t octet_key[] = {0x30, 9, 0x30, 3, 6, 1, 42, 4, 2, 0, 7};
  static const uint8_t bad_algorithm[] = {0x30, 9, 0x30, 3, 6, 1, 0x80, 3, 2, 0, 7};
  TC_DER_public_key key, saved;
  munit_assert_int(TC_DER_subject_public_key((TC_bytes){valid, sizeof valid}, &key), ==, TC_TLV_OK);
  munit_assert_ptr_equal(key.algorithm.oid.data, valid + 6);
  munit_assert_size(key.algorithm.oid.length, ==, 1);
  munit_assert_null(key.algorithm.parameters.data);
  munit_assert_ptr_equal(key.key.data, valid + 10);
  munit_assert_size(key.key.length, ==, 1);
  saved = key;
  munit_assert_int(TC_DER_subject_public_key((TC_bytes){unused_bits, sizeof unused_bits}, &key), ==,
                   TC_TLV_INVALID);
  munit_assert_int(TC_DER_subject_public_key((TC_bytes){empty_key, sizeof empty_key}, &key), ==,
                   TC_TLV_INVALID);
  munit_assert_int(TC_DER_subject_public_key((TC_bytes){trailing, sizeof trailing}, &key), ==,
                   TC_TLV_INVALID);
  munit_assert_int(TC_DER_subject_public_key((TC_bytes){missing_key, sizeof missing_key}, &key), ==,
                   TC_TLV_INVALID);
  munit_assert_int(TC_DER_subject_public_key((TC_bytes){octet_key, sizeof octet_key}, &key), ==,
                   TC_TLV_INVALID);
  munit_assert_int(TC_DER_subject_public_key((TC_bytes){bad_algorithm, sizeof bad_algorithm}, &key),
                   ==, TC_TLV_INVALID);
  for (size_t end = 0; end < sizeof valid; ++end)
    munit_assert_int(TC_DER_subject_public_key((TC_bytes){valid, end}, &key), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof key, &key, &saved);
  munit_assert_int(TC_DER_subject_public_key((TC_bytes){valid, sizeof valid}, NULL), ==,
                   TC_TLV_ARGUMENT);
  munit_assert_int(TC_DER_subject_public_key((TC_bytes){NULL, sizeof valid}, &key), ==,
                   TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof key, &key, &saved);
  return MUNIT_OK;
}

/* X.690 section 8.19.2: base-128 subidentifiers with minimal leading octets. */
TC_TEST(oid_contents)
{
  static const uint8_t rsa[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1};
  static const uint8_t large_arc[] = {0x2a, 0xff, 0xff, 0xff, 0xff, 0xff,
                                      0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};
  static const uint8_t continuation_end[] = {0x2a, 0x81};
  static const uint8_t leading_arc[] = {0x2a, 0x80, 1};
  static const uint8_t leading_first[] = {0x80, 0x2a};
  munit_assert_int(TC_DER_oid_contents((TC_bytes){rsa, sizeof rsa}), ==, TC_TLV_OK);
  munit_assert_int(TC_DER_oid_contents((TC_bytes){rsa, 1}), ==, TC_TLV_OK);
  munit_assert_int(TC_DER_oid_contents((TC_bytes){large_arc, sizeof large_arc}), ==, TC_TLV_OK);
  munit_assert_int(TC_DER_oid_contents((TC_bytes){rsa, 0}), ==, TC_TLV_INVALID);
  munit_assert_int(TC_DER_oid_contents((TC_bytes){NULL, 0}), ==, TC_TLV_INVALID);
  munit_assert_int(TC_DER_oid_contents((TC_bytes){continuation_end, sizeof continuation_end}), ==,
                   TC_TLV_INVALID);
  munit_assert_int(TC_DER_oid_contents((TC_bytes){rsa, 2}), ==, TC_TLV_INVALID);
  munit_assert_int(TC_DER_oid_contents((TC_bytes){leading_arc, sizeof leading_arc}), ==,
                   TC_TLV_INVALID);
  munit_assert_int(TC_DER_oid_contents((TC_bytes){leading_first, sizeof leading_first}), ==,
                   TC_TLV_INVALID);
  munit_assert_int(TC_DER_oid_contents((TC_bytes){NULL, 1}), ==, TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

TC_TEST(der)
{
  static const uint8_t positive[] = {2, 2, 0, 128}, negative[] = {2, 1, 255};
  static const uint8_t nonminimal[] = {2, 2, 0, 127}, zero[] = {2, 0};
  static const uint8_t maximum[] = {2, 5, 0, 255, 255, 255, 255};
  static const uint8_t oversized[] = {2, 5, 1, 0, 0, 0, 0};
  static const uint8_t bitstring[] = {3, 2, 3, 0xa8}, badbits[] = {3, 2, 3, 0xa9};
  static const uint8_t oid[] = {6, 3, 0x88, 0x37, 3}, badoid[] = {6, 2, 0x80, 1};
  static const uint8_t hugeoid[] = {6, 8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};
  static const uint8_t yes[] = {1, 1, 255}, badbool[] = {1, 1, 1};
  static const uint8_t nil[] = {5, 0}, seq[] = {0x30, 0}, set[] = {0x31, 0};
  TC_bytes v;
  uint32_t n = 9;
  int sign;
  unsigned unused;
  munit_assert(TC_DER_integer((TC_bytes){positive, sizeof positive}, &v, &sign) == TC_TLV_OK &&
               !sign && v.length == 2);
  munit_assert(TC_DER_positive_integer((TC_bytes){positive, sizeof positive}, &v) == TC_TLV_OK);
  munit_assert(v.data == positive + sizeof positive - 1 && v.length == 1 && v.data[0] == 128);
  const TC_bytes magnitude = v;
  static const uint8_t integer_zero[] = {2, 1, 0};
  munit_assert(TC_DER_positive_integer((TC_bytes){integer_zero, sizeof integer_zero}, &v) ==
               TC_TLV_INVALID);
  munit_assert(TC_DER_positive_integer((TC_bytes){negative, sizeof negative}, &v) ==
               TC_TLV_INVALID);
  munit_assert(TC_DER_positive_integer((TC_bytes){nonminimal, sizeof nonminimal}, &v) ==
               TC_TLV_INVALID);
  munit_assert(v.data == magnitude.data && v.length == magnitude.length);
  munit_assert(TC_DER_positive_integer((TC_bytes){positive, sizeof positive}, NULL) ==
               TC_TLV_ARGUMENT);
  {
    uint8_t encoded[] = {0x30, 27, 2, 1, 0, 2, 1, 15, 2, 1, 3, 2, 1, 3, 2,
                         1,    3,  2, 1, 5, 2, 1, 1,  2, 1, 3, 2, 1, 2};
    TC_DER_rsa_private_key key;
    munit_assert(TC_DER_rsa_private((TC_bytes){encoded, sizeof encoded}, &key) == TC_TLV_OK);
    munit_assert(key.modulus.data == encoded + 7 && key.modulus.length == 1);
    munit_assert(key.coefficient.data == encoded + 28 && key.coefficient.length == 1);
    const TC_DER_rsa_private_key saved = key;
    for (size_t i = 0; i < sizeof encoded; ++i) {
      munit_assert(TC_DER_rsa_private((TC_bytes){encoded, i}, &key) == TC_TLV_INVALID);
      munit_assert_memory_equal(sizeof key, &key, &saved);
    }
    for (size_t i = 7; i < sizeof encoded; i += 3) {
      const uint8_t original = encoded[i];
      encoded[i] = 0;
      munit_assert(TC_DER_rsa_private((TC_bytes){encoded, sizeof encoded}, &key) == TC_TLV_INVALID);
      munit_assert_memory_equal(sizeof key, &key, &saved);
      encoded[i] = 0x80;
      munit_assert(TC_DER_rsa_private((TC_bytes){encoded, sizeof encoded}, &key) == TC_TLV_INVALID);
      munit_assert_memory_equal(sizeof key, &key, &saved);
      encoded[i] = original;
      uint8_t padded[sizeof encoded + 1];
      memcpy(padded, encoded, i);
      padded[i] = 0;
      memcpy(padded + i + 1, encoded + i, sizeof encoded - i);
      ++padded[1];
      ++padded[i - 1];
      munit_assert(TC_DER_rsa_private((TC_bytes){padded, sizeof padded}, &key) == TC_TLV_INVALID);
      munit_assert_memory_equal(sizeof key, &key, &saved);
      padded[i + 1] = 0x80;
      TC_DER_rsa_private_key signed_magnitude;
      munit_assert(TC_DER_rsa_private((TC_bytes){padded, sizeof padded}, &signed_magnitude) ==
                   TC_TLV_OK);
    }
    uint8_t extra[sizeof encoded + 3];
    memcpy(extra, encoded, sizeof encoded);
    extra[sizeof encoded] = 2;
    extra[sizeof encoded + 1] = 1;
    extra[sizeof encoded + 2] = 1;
    munit_assert(TC_DER_rsa_private((TC_bytes){extra, sizeof extra}, &key) == TC_TLV_INVALID);
    extra[1] += 3;
    munit_assert(TC_DER_rsa_private((TC_bytes){extra, sizeof extra}, &key) == TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof key, &key, &saved);
    /* A multi-prime key (version 1) with otherPrimeInfos is unsupported. */
    extra[4] = 1;
    munit_assert(TC_DER_rsa_private((TC_bytes){extra, sizeof extra}, &key) == TC_TLV_UNSUPPORTED);
    munit_assert_memory_equal(sizeof key, &key, &saved);
    munit_assert(TC_DER_rsa_private((TC_bytes){encoded, sizeof encoded}, NULL) == TC_TLV_ARGUMENT);
    encoded[4] = 1;
    munit_assert(TC_DER_rsa_private((TC_bytes){encoded, sizeof encoded}, &key) ==
                 TC_TLV_UNSUPPORTED);
    encoded[4] = 2;
    munit_assert(TC_DER_rsa_private((TC_bytes){encoded, sizeof encoded}, &key) == TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof key, &key, &saved);
  }
  munit_assert(TC_DER_uint32((TC_bytes){positive, sizeof positive}, &n) == TC_TLV_OK && n == 128);
  munit_assert(TC_DER_integer((TC_bytes){negative, sizeof negative}, &v, &sign) == TC_TLV_OK &&
               sign);
  munit_assert(TC_DER_uint32((TC_bytes){negative, sizeof negative}, &n) == TC_TLV_INVALID &&
               n == 128);
  munit_assert(TC_DER_integer((TC_bytes){nonminimal, sizeof nonminimal}, &v, &sign) ==
               TC_TLV_INVALID);
  munit_assert(TC_DER_integer((TC_bytes){zero, sizeof zero}, &v, &sign) == TC_TLV_INVALID);
  munit_assert(TC_DER_uint32((TC_bytes){maximum, sizeof maximum}, &n) == TC_TLV_OK &&
               n == UINT32_MAX);
  munit_assert(TC_DER_uint32((TC_bytes){oversized, sizeof oversized}, &n) == TC_TLV_LIMIT &&
               n == UINT32_MAX);
  munit_assert(TC_DER_bit_string((TC_bytes){bitstring, sizeof bitstring}, &v, &unused) ==
                   TC_TLV_OK &&
               unused == 3 && v.length == 1);
  munit_assert(TC_DER_bit_string((TC_bytes){badbits, sizeof badbits}, &v, &unused) ==
               TC_TLV_INVALID);
  munit_assert(TC_DER_oid((TC_bytes){oid, sizeof oid}, &v) == TC_TLV_OK);
  munit_assert(TC_DER_oid((TC_bytes){hugeoid, sizeof hugeoid}, &v) == TC_TLV_OK);
  munit_assert(TC_DER_oid((TC_bytes){badoid, sizeof badoid}, &v) == TC_TLV_INVALID);
  munit_assert(TC_DER_boolean((TC_bytes){yes, sizeof yes}, &sign) == TC_TLV_OK && sign);
  munit_assert(TC_DER_boolean((TC_bytes){badbool, sizeof badbool}, &sign) == TC_TLV_INVALID);
  munit_assert(TC_DER_null((TC_bytes){nil, sizeof nil}) == TC_TLV_OK);
  munit_assert(TC_DER_sequence((TC_bytes){seq, sizeof seq}, &v) == TC_TLV_OK && v.length == 0);
  munit_assert(TC_DER_set((TC_bytes){set, sizeof set}, &v) == TC_TLV_OK && v.length == 0);
  return MUNIT_OK;
}
#endif

TC_TEST(tree_reads)
{
  enum { FRAME_CAPACITY = 4 };
  static const uint8_t sequence[] = {0x30, 3, 4, 1, 42, 0xff};
  static const uint8_t primitive[] = {4, 2, 0, 0, 0xff};
  static const uint8_t empty[] = {0x30, 0, 0xff};
  static const uint8_t escaped[] = {0x30, 3, 4, 2, 42};
  static const uint8_t cut_header[] = {0x30, 1, 4, 0};
  static const uint8_t nested[] = {0x30, 2, 0x30, 0};
  const TC_bytes valid[] = {{sequence, sizeof sequence - 1},
                            {primitive, sizeof primitive - 1},
                            {empty, sizeof empty - 1}};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_TLV_element element, saved;
  TC_TLV_limits limited = limits;
  for (size_t i = 0; i < sizeof valid / sizeof *valid; ++i) {
    memset(&element, 0xa5, sizeof element);
    memcpy(&saved, &element, sizeof saved);
    for (size_t length = 0; length < valid[i].length; ++length) {
      munit_assert_int(TC_TLV_read_tree((TC_bytes){valid[i].data, length}, TC_TLV_DER, &limits,
                                        (TC_TLV_frames){frames, FRAME_CAPACITY}, &element),
                       ==, TC_TLV_MORE);
      munit_assert_memory_equal(sizeof element, &element, &saved);
    }
    munit_assert_int(TC_TLV_read_tree((TC_bytes){valid[i].data, valid[i].length + 1}, TC_TLV_DER,
                                      &limits, (TC_TLV_frames){frames, FRAME_CAPACITY}, &element),
                     ==, TC_TLV_OK);
    munit_assert_ptr_equal(element.encoded.data, valid[i].data);
    munit_assert_size(element.encoded.length, ==, valid[i].length);
    munit_assert_ptr_equal(element.value.data, valid[i].data + element.header.header_length);
    munit_assert_size(element.value.length, ==, element.header.length);
  }
  memset(&element, 0xa5, sizeof element);
  memcpy(&saved, &element, sizeof saved);
  munit_assert_int(TC_TLV_read_tree((TC_bytes){escaped, sizeof escaped}, TC_TLV_DER, &limits,
                                    (TC_TLV_frames){frames, FRAME_CAPACITY}, &element),
                   ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof element, &element, &saved);
  munit_assert_int(TC_TLV_read_tree((TC_bytes){cut_header, sizeof cut_header}, TC_TLV_DER, &limits,
                                    (TC_TLV_frames){frames, FRAME_CAPACITY}, &element),
                   ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof element, &element, &saved);
  limited.max_elements = 1;
  munit_assert_int(TC_TLV_read_tree((TC_bytes){sequence, sizeof sequence}, TC_TLV_DER, &limited,
                                    (TC_TLV_frames){frames, FRAME_CAPACITY}, &element),
                   ==, TC_TLV_LIMIT);
  limited = limits;
  limited.max_depth = 1;
  munit_assert_int(TC_TLV_read_tree((TC_bytes){nested, sizeof nested}, TC_TLV_DER, &limited,
                                    (TC_TLV_frames){frames, FRAME_CAPACITY}, &element),
                   ==, TC_TLV_LIMIT);
  munit_assert_int(TC_TLV_read_tree((TC_bytes){nested, sizeof nested}, TC_TLV_DER, &limits,
                                    (TC_TLV_frames){frames, 1}, &element),
                   ==, TC_TLV_LIMIT);
  munit_assert_memory_equal(sizeof element, &element, &saved);
  munit_assert_int(TC_TLV_read_tree((TC_bytes){NULL, 1}, TC_TLV_DER, &limits,
                                    (TC_TLV_frames){frames, FRAME_CAPACITY}, &element),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_TLV_read_tree((TC_bytes){sequence, sizeof sequence}, TC_TLV_DER, &limits,
                                    (TC_TLV_frames){NULL, FRAME_CAPACITY}, &element),
                   ==, TC_TLV_ARGUMENT);
#if TC_TLV_ENABLE_BER
  {
    static const uint8_t indefinite[] = {0x30, 0x80, 0x30, 0x80, 4, 2, 0, 0, 0, 0, 0, 0, 0xff};
    static const uint8_t empty_indefinite[] = {0x30, 0x80, 0, 0, 0xff};
    const TC_bytes objects[] = {{indefinite, sizeof indefinite - 1},
                                {empty_indefinite, sizeof empty_indefinite - 1}};
    for (size_t i = 0; i < sizeof objects / sizeof *objects; ++i) {
      memset(&element, 0xa5, sizeof element);
      memcpy(&saved, &element, sizeof saved);
      for (size_t length = 0; length < objects[i].length; ++length) {
        munit_assert_int(TC_TLV_read_tree((TC_bytes){objects[i].data, length}, TC_TLV_BER, &limits,
                                          (TC_TLV_frames){frames, FRAME_CAPACITY}, &element),
                         ==, TC_TLV_MORE);
        munit_assert_memory_equal(sizeof element, &element, &saved);
      }
      munit_assert_int(TC_TLV_read_tree((TC_bytes){objects[i].data, objects[i].length + 1},
                                        TC_TLV_BER, &limits,
                                        (TC_TLV_frames){frames, FRAME_CAPACITY}, &element),
                       ==, TC_TLV_OK);
      munit_assert_size(element.encoded.length, ==, objects[i].length);
      munit_assert_size(element.value.length, ==,
                        objects[i].length - element.header.header_length - 2);
      munit_assert_true(element.header.indefinite);
      munit_assert_int(TC_TLV_walk(element.encoded, TC_TLV_BER, &limits,
                                   (TC_TLV_frames){frames, FRAME_CAPACITY}, NULL, NULL),
                       ==, TC_TLV_OK);
    }
  }
#endif
  return MUNIT_OK;
}

#if TC_ENABLE_DER
/* The DER readers take a complete encoding, so a tag or length field wider
 * than the build parses is malformed input. A version too large for a
 * uint32_t follows the reader's rule for other unknown versions. */
TC_TEST(der_status_classes)
{
  static const uint8_t long_tag[] = {0x1f, 0x81, 0x81, 0x81, 0x81, 0x81, 0x01, 1, 0};
  static const uint8_t wide_length[] = {2, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0};
  static const uint8_t pkcs8_version[] = {0x30, 17, 2, 5,  1, 0, 0, 0,    0, 0x30,
                                          3,    6,  1, 42, 4, 1, 7, 0xa0, 0};
  static const uint8_t rsa_version[] = {0x30, 31, 2, 5, 1, 0, 0, 0, 0, 2, 1, 1, 2, 1, 1, 2, 1,
                                        1,    2,  1, 1, 2, 1, 1, 2, 1, 1, 2, 1, 1, 2, 1, 1};
  TC_bytes v = {NULL, 0};
  int sign = 3;
  TC_DER_private_key key;
  TC_DER_rsa_private_key rsa;
  memset(&key, 0xa5, sizeof key);
  memset(&rsa, 0xa5, sizeof rsa);
  munit_assert_int(TC_DER_integer((TC_bytes){long_tag, sizeof long_tag}, &v, &sign), ==,
                   TC_TLV_INVALID);
  munit_assert_int(TC_DER_integer((TC_bytes){wide_length, sizeof wide_length}, &v, &sign), ==,
                   TC_TLV_INVALID);
  munit_assert_int(TC_DER_private_key_info((TC_bytes){pkcs8_version, sizeof pkcs8_version}, &key),
                   ==, TC_TLV_UNSUPPORTED);
  munit_assert_int(TC_DER_rsa_private((TC_bytes){rsa_version, sizeof rsa_version}, &rsa), ==,
                   TC_TLV_INVALID);
  munit_assert(!v.data && !v.length && sign == 3);
  munit_assert_uint(((const uint8_t*)&key)[0], ==, 0xa5);
  munit_assert_uint(((const uint8_t*)&rsa)[0], ==, 0xa5);
  return MUNIT_OK;
}
#endif

static MunitTest tests[] = {
    {"/headers", headers, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/lengths", lengths, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/cursor", cursor, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/child-reader", child_reader, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/walks", walks, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/walk-spans-borrow-input", walk_spans_borrow_input, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/tree-reads", tree_reads, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#if TC_ENABLE_DER
    {"/signatures", signatures, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/der", der, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/der-truncation", der_truncation, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/der-status-classes", der_status_classes, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/subject-public-key", subject_public_key, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/oid-contents", oid_contents, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/private-key-info", private_key_info, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/rsa-public-key", rsa_public_key, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
static const MunitSuite suite = {"/tlv", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
