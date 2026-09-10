/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_TEST_MAC_VECTORS_H
#define TC_TEST_MAC_VECTORS_H
#include "munit.h"
#include "test_util.h"
#include <stdio.h>
#include <string.h>

typedef TC_status (*tc_test_mac_fn)(const uint8_t*, size_t, const uint8_t*, size_t,
                                     uint8_t*, size_t);

static size_t tc_test_mac_hex(const char* text, uint8_t* output, size_t capacity)
{
  size_t length;
  if (strcmp(text, "-") == 0) return 0;
  length = tc_test_decode_hex(text, output, capacity);
  munit_assert_size(strlen(text) % 2, ==, 0);
  munit_assert_size(length, ==, strlen(text) / 2);
  return length;
}

static MunitResult tc_test_mac_vectors(const char* path, tc_test_mac_fn digest)
{
  FILE* file;
  char key_hex[2049], msg_hex[16385], tag_hex[2049], verdict[16];
  uint8_t key[1024], msg[8192], tag[1024], output[1024];
  unsigned id, count = 0;
  int fields;
  if (!path) return MUNIT_SKIP;
  file = fopen(path, "r");
  munit_assert_not_null(file);
  while ((fields = fscanf(file, "%u %2048s %16384s %2048s %15s",
                           &id, key_hex, msg_hex, tag_hex, verdict)) == 5) {
    size_t key_length = tc_test_mac_hex(key_hex, key, sizeof key);
    size_t msg_length = tc_test_mac_hex(msg_hex, msg, sizeof msg);
    size_t tag_length = tc_test_mac_hex(tag_hex, tag, sizeof tag);
    TC_status status;
    memset(output, 0xa5, sizeof output);
    status = digest(key, key_length, msg, msg_length, output, tag_length);
    if (strcmp(verdict, "invalid-key") == 0) {
      size_t i;
      munit_assert_int(status, ==, TC_ERROR);
      for (i = 0; i < sizeof output; ++i) munit_assert_uint(output[i], ==, 0xa5);
    } else {
      munit_assert_true(strcmp(verdict, "valid") == 0 || strcmp(verdict, "invalid") == 0);
      munit_assert_size(tag_length, >, 0);
      munit_assert_int(status, ==, TC_OK);
      if ((memcmp(output, tag, tag_length) == 0) != (strcmp(verdict, "valid") == 0))
        munit_errorf("Wycheproof MAC case %u", id);
    }
    ++count;
  }
  munit_assert_int(fields, ==, EOF);
  munit_assert_false(ferror(file));
  fclose(file);
  munit_assert_uint(count, >, 0);
  return MUNIT_OK;
}
#endif
