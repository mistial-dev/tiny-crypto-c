/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_TEST_RSA_OPENSSL_KEY_H_
#define TC_TEST_RSA_OPENSSL_KEY_H_
#include <tiny_crypto/rsa.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

enum { TC_TEST_RSA_MAX_BYTES = 384 };

/* A zero width selects the minimal unsigned encoding. */
static inline size_t tc_test_rsa_component(EVP_PKEY* key, const char* name,
    uint8_t* output, size_t capacity, size_t width)
{
  BIGNUM* value = NULL;
  if (EVP_PKEY_get_bn_param(key,name,&value) != 1) { BN_clear_free(value); return 0; }
  size_t length = width ? width : (size_t)BN_num_bytes(value);
  int written = length && length <= capacity && length <= TC_TEST_RSA_MAX_BYTES ?
      BN_bn2binpad(value,output,(int)length) : -1;
  BN_clear_free(value);
  return written > 0 && (size_t)written == length ? length : 0;
}

/* Export padded private components into caller-owned test storage. */
static inline size_t tc_test_rsa_export(EVP_PKEY* key,
    uint8_t components[5][TC_TEST_RSA_MAX_BYTES], size_t width)
{
  const char* names[] = {OSSL_PKEY_PARAM_RSA_N,OSSL_PKEY_PARAM_RSA_E,OSSL_PKEY_PARAM_RSA_D,
    OSSL_PKEY_PARAM_RSA_FACTOR1,OSSL_PKEY_PARAM_RSA_FACTOR2};
  size_t exponent_length = 0;
  if (!width || width > TC_TEST_RSA_MAX_BYTES) return 0;
  for (size_t i = 0; i < sizeof names / sizeof *names; ++i) {
    size_t length = tc_test_rsa_component(key,names[i],components[i],
        TC_TEST_RSA_MAX_BYTES,i == 1 ? 0 : width);
    if (!length) return 0;
    if (i == 1) exponent_length = length;
  }
  return exponent_length;
}
#endif
