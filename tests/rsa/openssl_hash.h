/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_TEST_RSA_OPENSSL_HASH_H_
#define TC_TEST_RSA_OPENSSL_HASH_H_
#include <tiny_crypto/rsa.h>
#include <openssl/evp.h>
#include "munit.h"
#include <string.h>

typedef struct {
  const char* name;
  TC_hash_algorithm algorithm;
  const EVP_MD* (*method)(void);
} tc_test_openssl_hash;

static const tc_test_openssl_hash* tc_test_openssl_hash_get(const char* name)
{
  static const tc_test_openssl_hash hashes[] = {
    {"SHA1",TC_HASH_SHA1,EVP_sha1}, {"SHA224",TC_HASH_SHA224,EVP_sha224},
    {"SHA256",TC_HASH_SHA256,EVP_sha256}, {"SHA384",TC_HASH_SHA384,EVP_sha384},
    {"SHA512",TC_HASH_SHA512,EVP_sha512}
  };
  for (size_t i = 0; i < sizeof hashes / sizeof *hashes; ++i)
    if (!strcmp(name,hashes[i].name)) return &hashes[i];
  munit_error("Unknown hash parameter");
  return NULL;
}
#endif
