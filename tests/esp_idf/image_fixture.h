/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once
#include "rom/secure_boot.h"
#include <tiny_crypto/hash.h>
#include "munit.h"
#include <stdio.h>

static void read_image_fixture(const char* path, ets_secure_boot_signature_t* signatures,
    uint8_t digest[32])
{
  struct TC_SHA256_ctx hash;
  uint8_t buffer[1024];
  FILE* file = fopen(path, "rb");
  long size, remaining;
  munit_assert_not_null(file);
  munit_assert_int(fseek(file, 0, SEEK_END), ==, 0);
  size = ftell(file);
  munit_assert_long(size, >, 4096);
  munit_assert_long(size % 4096, ==, 0);
  rewind(file);
  munit_assert_int(TC_SHA256_init(&hash), ==, TC_OK);
  remaining = size - 4096;
  while (remaining) {
    size_t count = remaining < (long)sizeof buffer ? (size_t)remaining : sizeof buffer;
    munit_assert_size(fread(buffer, 1, count, file), ==, count);
    munit_assert_int(TC_SHA256_update(&hash, buffer, count), ==, TC_OK);
    remaining -= (long)count;
  }
  munit_assert_int(TC_SHA256_final(&hash, digest), ==, TC_OK);
  munit_assert_size(fread(signatures, 1, sizeof *signatures, file), ==, sizeof *signatures);
  munit_assert_int(fclose(file), ==, 0);
}
