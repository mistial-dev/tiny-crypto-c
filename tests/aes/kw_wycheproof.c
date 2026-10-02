/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Reader for the Wycheproof AES-KW and AES-KWP records that tests/wycheproof.py
 * writes: "mode tcId verdict kek msg ct" per line, "-" for an empty field. */
#include <tiny_crypto/aes_kw.h>
#include "munit.h"
#include "cavp.h"
#include "test_util.h"
#include <stdio.h>
#include <string.h>

enum { KW_FIELD = 1024, KW_SENTINEL = 0xa5 };
static const char* vector_path;

static size_t decode(const char* text, uint8_t* output)
{
  size_t length;
  if (strcmp(text, "-") == 0)
    return 0;
  length = tc_test_hex(text, output, KW_FIELD);
  munit_assert_size(length, ==, strlen(text) / 2);
  return length;
}

/* True when SP 800-38F section 5.3.1 admits length bytes of key data. */
static int wrap_length_ok(int padded, size_t length)
{
  return padded ? length != 0 : length >= 16 && length % 8 == 0;
}

static TC_status wrap(int padded, TC_bytes kek, TC_bytes key_data, TC_buffer wrapped)
{
  return padded ? TC_AES_KWP_wrap(kek, key_data, wrapped) : TC_AES_KW_wrap(kek, key_data, wrapped);
}

static TC_status unwrap(int padded, TC_bytes kek, TC_bytes wrapped, TC_buffer key_data,
                        size_t* length)
{
  TC_status status;
  if (padded)
    return TC_AES_KWP_unwrap(kek, wrapped, key_data, length);
  status = TC_AES_KW_unwrap(kek, wrapped, key_data);
  if (status == TC_OK)
    *length = wrapped.length - 8u;
  return status;
}

TC_TEST(vectors)
{
  static uint8_t kek[64], msg[KW_FIELD], ct[KW_FIELD], out[KW_FIELD + 16];
  static char kek_hex[129], msg_hex[2 * KW_FIELD + 1], ct_hex[2 * KW_FIELD + 1];
  char mode[8], verdict[16];
  unsigned id, count = 0;
  FILE* file;
  int fields;
  if (!vector_path)
    return MUNIT_SKIP;
  file = fopen(vector_path, "r");
  munit_assert_not_null(file);
  while ((fields = fscanf(file, "%7s %u %15s %128s %2048s %2048s", mode, &id, verdict, kek_hex,
                          msg_hex, ct_hex)) == 6) {
    const int padded = strcmp(mode, "kwp") == 0;
    const int valid = strcmp(verdict, "valid") == 0;
    const size_t kek_length = decode(kek_hex, kek);
    const size_t msg_length = decode(msg_hex, msg);
    const size_t ct_length = decode(ct_hex, ct);
    const TC_bytes k = {kek, kek_length};
    size_t length = SIZE_MAX;
    TC_status status;
    munit_assert_true(padded || strcmp(mode, "kw") == 0);
    munit_assert_true(valid || strcmp(verdict, "invalid") == 0);
    /* Each reader receives only KEK sizes its build accepts. */
    if (!TC_AES_KW_KEK_LENGTH_SUPPORTED(kek_length))
      munit_errorf("key wrap case %u: KEK length %u is outside this build", id,
                   (unsigned)kek_length);

    memset(out, KW_SENTINEL, sizeof out);
    status = unwrap(padded, k, (TC_bytes){ct, ct_length}, (TC_buffer){out, sizeof out}, &length);
    if (valid) {
      if (status != TC_OK)
        munit_errorf("key wrap case %u: valid unwrap rejected (%d)", id, status);
      munit_assert_size(length, ==, msg_length);
      munit_assert_memory_equal(msg_length, out, msg);
      munit_assert_true(
          tc_test_all_value(out + ct_length - 8u, sizeof out - (ct_length - 8u), KW_SENTINEL));
      memset(out, KW_SENTINEL, sizeof out);
      munit_assert_int(wrap(padded, k, (TC_bytes){msg, msg_length}, (TC_buffer){out, sizeof out}),
                       ==, TC_OK);
      munit_assert_memory_equal(ct_length, out, ct);
      munit_assert_true(tc_test_all_value(out + ct_length, sizeof out - ct_length, KW_SENTINEL));
      /* In place. */
      length = 0;
      munit_assert_int(
          unwrap(padded, k, (TC_bytes){out, ct_length}, (TC_buffer){out, ct_length}, &length), ==,
          TC_OK);
      munit_assert_size(length, ==, msg_length);
      munit_assert_memory_equal(msg_length, out, msg);
    } else {
      if (status == TC_MISMATCH) {
        munit_assert_true(tc_test_all_zero(out, ct_length - 8u));
        munit_assert_true(
            tc_test_all_value(out + ct_length - 8u, sizeof out - (ct_length - 8u), KW_SENTINEL));
      } else if (status == TC_ERROR) {
        munit_assert_true(tc_test_all_value(out, sizeof out, KW_SENTINEL));
      } else {
        munit_errorf("key wrap case %u: invalid unwrap accepted", id);
      }
      munit_assert_size(length, ==, SIZE_MAX);
      /* Key data outside the wrap domain (WrongDataSize, EmptyKey, ShortKey)
       * is also rejected on wrap. */
      if (!wrap_length_ok(padded, msg_length)) {
        memset(out, KW_SENTINEL, sizeof out);
        munit_assert_int(wrap(padded, k, (TC_bytes){msg, msg_length}, (TC_buffer){out, sizeof out}),
                         ==, TC_ERROR);
        munit_assert_true(tc_test_all_value(out, sizeof out, KW_SENTINEL));
      }
    }
    ++count;
  }
  munit_assert_int(fields, ==, EOF);
  munit_assert_false(ferror(file));
  fclose(file);
  munit_assert_uint(count, >, 0);
  return MUNIT_OK;
}

static MunitTest tests[] = {{"/vectors", vectors, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                            {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
static const MunitSuite suite = {"/keywrap", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{
  if (argc == 3 && strcmp(argv[1], "--vectors") == 0) {
    char* args[] = {argv[0], (char*)"/keywrap/vectors"};
    vector_path = argv[2];
    return munit_suite_main(&suite, NULL, 2, args);
  }
  return munit_suite_main(&suite, NULL, argc, argv);
}
