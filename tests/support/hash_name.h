/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_TEST_HASH_NAME_H_
#define TC_TEST_HASH_NAME_H_
#include <tiny_crypto/common.h>
#include "munit.h"
#include <string.h>

static inline TC_hash_algorithm hash_algorithm(const char* name)
{
  static const struct { const char* name; TC_hash_algorithm algorithm; } hashes[] = {
    {"SHA-1",TC_HASH_SHA1}, {"SHA-224",TC_HASH_SHA224}, {"SHA-256",TC_HASH_SHA256},
    {"SHA-384",TC_HASH_SHA384}, {"SHA-512",TC_HASH_SHA512}
  };
  for (size_t i = 0; i < sizeof hashes / sizeof *hashes; ++i)
    if (!strcmp(name,hashes[i].name)) return hashes[i].algorithm;
  munit_error("Unknown fixture hash");
}
#endif
