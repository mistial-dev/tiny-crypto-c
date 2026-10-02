/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_TEST_RSA_OPENSSL_KEY_H_
#define TC_TEST_RSA_OPENSSL_KEY_H_
#include <tiny_crypto/rsa.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>

enum { TC_TEST_RSA_MAX_BYTES = 512 };

/* A zero width selects the minimal unsigned encoding. */
static inline size_t tc_test_rsa_component(EVP_PKEY* key, const char* name, uint8_t* output,
                                           size_t capacity, size_t width)
{
  BIGNUM* value = NULL;
  if (EVP_PKEY_get_bn_param(key, name, &value) != 1) {
    BN_clear_free(value);
    return 0;
  }
  size_t length = width ? width : (size_t)BN_num_bytes(value);
  int written = length && length <= capacity && length <= TC_TEST_RSA_MAX_BYTES
                    ? BN_bn2binpad(value, output, (int)length)
                    : -1;
  BN_clear_free(value);
  return written > 0 && (size_t)written == length ? length : 0;
}

/* Export padded private components into caller-owned test storage. */
static inline size_t tc_test_rsa_export(EVP_PKEY* key, uint8_t components[5][TC_TEST_RSA_MAX_BYTES],
                                        size_t width)
{
  const char* names[] = {OSSL_PKEY_PARAM_RSA_N, OSSL_PKEY_PARAM_RSA_E, OSSL_PKEY_PARAM_RSA_D,
                         OSSL_PKEY_PARAM_RSA_FACTOR1, OSSL_PKEY_PARAM_RSA_FACTOR2};
  size_t exponent_length = 0;
  if (!width || width > TC_TEST_RSA_MAX_BYTES)
    return 0;
  for (size_t i = 0; i < sizeof names / sizeof *names; ++i) {
    size_t length = tc_test_rsa_component(key, names[i], components[i], TC_TEST_RSA_MAX_BYTES,
                                          i == 1 ? 0 : width);
    if (!length)
      return 0;
    if (i == 1)
      exponent_length = length;
  }
  return exponent_length;
}
/* An RSA key with d = e^-1 mod LCM(p-1, q-1), as FIPS 186-5 A.1.1 requires.
 * OpenSSL reduces d modulo (p-1)(q-1) for some sizes, so the key is rebuilt
 * from its factors. Returns NULL on failure. */
static inline EVP_PKEY* tc_test_rsa_generate(unsigned bits)
{
  EVP_PKEY* source = EVP_RSA_gen(bits);
  EVP_PKEY* key = NULL;
  BIGNUM *n = NULL, *e = NULL, *p = NULL, *q = NULL;
  BIGNUM *d = BN_new(), *p1 = BN_new(), *q1 = BN_new(), *phi = BN_new(), *g = BN_new();
  BIGNUM *lambda = BN_new(), *dp = BN_new(), *dq = BN_new(), *qinv = BN_new();
  BN_CTX* context = BN_CTX_new();
  OSSL_PARAM_BLD* build = OSSL_PARAM_BLD_new();
  OSSL_PARAM* params = NULL;
  EVP_PKEY_CTX* from = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
  if (source && context && build && from && qinv &&
      EVP_PKEY_get_bn_param(source, OSSL_PKEY_PARAM_RSA_N, &n) &&
      EVP_PKEY_get_bn_param(source, OSSL_PKEY_PARAM_RSA_E, &e) &&
      EVP_PKEY_get_bn_param(source, OSSL_PKEY_PARAM_RSA_FACTOR1, &p) &&
      EVP_PKEY_get_bn_param(source, OSSL_PKEY_PARAM_RSA_FACTOR2, &q) &&
      BN_sub(p1, p, BN_value_one()) && BN_sub(q1, q, BN_value_one()) &&
      BN_mul(phi, p1, q1, context) && BN_gcd(g, p1, q1, context) &&
      BN_div(lambda, NULL, phi, g, context) && BN_mod_inverse(d, e, lambda, context) &&
      BN_mod(dp, d, p1, context) && BN_mod(dq, d, q1, context) &&
      BN_mod_inverse(qinv, q, p, context) &&
      OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_N, n) &&
      OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_E, e) &&
      OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_D, d) &&
      OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_FACTOR1, p) &&
      OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_FACTOR2, q) &&
      OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_EXPONENT1, dp) &&
      OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_EXPONENT2, dq) &&
      OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, qinv) &&
      (params = OSSL_PARAM_BLD_to_param(build)) != NULL && EVP_PKEY_fromdata_init(from) == 1)
    (void)EVP_PKEY_fromdata(from, &key, EVP_PKEY_KEYPAIR, params);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(build);
  EVP_PKEY_CTX_free(from);
  BN_CTX_free(context);
  BN_clear_free(qinv);
  BN_clear_free(dq);
  BN_clear_free(dp);
  BN_clear_free(lambda);
  BN_clear_free(g);
  BN_clear_free(phi);
  BN_clear_free(q1);
  BN_clear_free(p1);
  BN_clear_free(d);
  BN_clear_free(q);
  BN_clear_free(p);
  BN_free(e);
  BN_free(n);
  EVP_PKEY_free(source);
  return key;
}
/* 1 when the key's d is below LCM(p-1, q-1), as FIPS 186-5 A.1.1 requires. */
static inline int tc_test_rsa_d_below_lcm(EVP_PKEY* key)
{
  BIGNUM *d = NULL, *p = NULL, *q = NULL;
  BIGNUM *p1 = BN_new(), *q1 = BN_new(), *phi = BN_new(), *g = BN_new(), *lambda = BN_new();
  BN_CTX* context = BN_CTX_new();
  int below = 0;
  if (context && lambda && EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_D, &d) &&
      EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_FACTOR1, &p) &&
      EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_FACTOR2, &q) &&
      BN_sub(p1, p, BN_value_one()) && BN_sub(q1, q, BN_value_one()) &&
      BN_mul(phi, p1, q1, context) && BN_gcd(g, p1, q1, context) &&
      BN_div(lambda, NULL, phi, g, context))
    below = BN_cmp(d, lambda) < 0;
  BN_CTX_free(context);
  BN_clear_free(lambda);
  BN_clear_free(g);
  BN_clear_free(phi);
  BN_clear_free(q1);
  BN_clear_free(p1);
  BN_clear_free(q);
  BN_clear_free(p);
  BN_clear_free(d);
  return below;
}
#endif
