/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/rsa.h>
#include "munit.h"
#include "openssl_key.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <stdlib.h>
#include <string.h>

enum { MAX_BYTES = 512, MAX_WORDS = 13 * 4096 / TC_RSA_WORD_BITS };

typedef struct {
  int fail;
  size_t calls;
} random_source;

static TC_status random_bytes(void* context, uint8_t* output, size_t length)
{
  random_source* source = context;
  ++source->calls;
  if (source->fail)
    return TC_ERROR;
  memset(output, 0, length);
  output[length - 1] = 2;
  return TC_OK;
}

static MunitResult raw_operations(const MunitParameter params[], void* user)
{
  const size_t bits = (size_t)strtoul(munit_parameters_get(params, "bits"), NULL, 10);
#if TC_RSA_SMALL
  if (bits > 1024)
    return MUNIT_SKIP;
#endif
  const size_t width = bits / 8;
  if (width == 0 || width > MAX_BYTES)
    return MUNIT_ERROR;
  uint8_t modulus[MAX_BYTES], private_exponent[MAX_BYTES];
  uint8_t representative[MAX_BYTES] = {0}, transformed[MAX_BYTES], recovered[MAX_BYTES];
  uint8_t expected[MAX_BYTES], unchanged[MAX_BYTES];
  static const uint8_t exponent[] = {1, 0, 1};
  TC_RSA_word scratch[MAX_WORDS];
  TC_RSA_workspace workspace = {scratch, MAX_WORDS};
  EVP_PKEY* generated = EVP_RSA_gen((int)bits);
  EVP_PKEY_CTX* private_context;
  EVP_PKEY_CTX* public_context;
  (void)user;
  munit_assert_not_null(generated);
  munit_assert_size(tc_test_rsa_component(generated, OSSL_PKEY_PARAM_RSA_N, modulus, width, width),
                    ==, width);
  munit_assert_size(
      tc_test_rsa_component(generated, OSSL_PKEY_PARAM_RSA_D, private_exponent, width, width), ==,
      width);
  TC_RSA_public_key key = {{modulus, width}, {exponent, sizeof exponent}};
  TC_bytes input = {representative, width};
  representative[width - 1] = 42;
  munit_assert_size(TC_RSA_workspace_words(TC_RSA_OPERATION_RAW_PUBLIC, bits), ==,
                    8 * bits / TC_RSA_WORD_BITS + 2);
  munit_assert_size(TC_RSA_workspace_words(TC_RSA_OPERATION_RAW_PRIVATE, bits), ==,
                    13 * bits / TC_RSA_WORD_BITS);
  munit_assert_size(TC_RSA_workspace_words(TC_RSA_OPERATION_RAW_PRIVATE, 4096), ==,
                    TC_RSA_RAW_PRIVATE_WORKSPACE_WORDS(4096));

  private_context = EVP_PKEY_CTX_new(generated, NULL);
  public_context = EVP_PKEY_CTX_new(generated, NULL);
  munit_assert_not_null(private_context);
  munit_assert_not_null(public_context);
  munit_assert_int(EVP_PKEY_decrypt_init(private_context), ==, 1);
  munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(private_context, RSA_NO_PADDING), ==, 1);
  munit_assert_int(EVP_PKEY_encrypt_init(public_context), ==, 1);
  munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(public_context, RSA_NO_PADDING), ==, 1);
  size_t expected_length = width;
  munit_assert_int(
      EVP_PKEY_decrypt(private_context, expected, &expected_length, representative, width), ==, 1);
  munit_assert_size(expected_length, ==, width);

  random_source source = {0, 0};
  TC_RSA_execution execution = {{random_bytes, &source}, 2, {100000}};
  memset(transformed, 0xa5, width);
  munit_assert_int(TC_RSA_raw_private(&key, (TC_bytes){private_exponent, width}, input, &workspace,
                                      (TC_buffer){transformed, width}, &execution),
                   ==, TC_RSA_OK);
  munit_assert_memory_equal(width, transformed, expected);
  munit_assert_size(source.calls, ==, 1);
  for (size_t i = 0; i < TC_RSA_workspace_words(TC_RSA_OPERATION_RAW_PRIVATE, bits); ++i)
    munit_assert_uint(scratch[i], ==, 0);

  TC_work_budget public_work = {100000};
  munit_assert_int(TC_RSA_raw_public(&key, (TC_bytes){transformed, width}, &workspace,
                                     (TC_buffer){recovered, width}, &public_work),
                   ==, TC_RSA_OK);
  munit_assert_memory_equal(width, recovered, representative);
  size_t public_length = width;
  munit_assert_int(
      EVP_PKEY_encrypt(public_context, expected, &public_length, representative, width), ==, 1);
  munit_assert_size(public_length, ==, width);
  public_work.remaining = 100000;
  munit_assert_int(
      TC_RSA_raw_public(&key, input, &workspace, (TC_buffer){recovered, width}, &public_work), ==,
      TC_RSA_OK);
  munit_assert_memory_equal(width, recovered, expected);

  memset(unchanged, 0x5a, width);
  memcpy(recovered, unchanged, width);
  public_work.remaining = 0;
  munit_assert_int(
      TC_RSA_raw_public(&key, input, &workspace, (TC_buffer){recovered, width}, &public_work), ==,
      TC_RSA_LIMIT);
  munit_assert_memory_equal(width, recovered, unchanged);
  public_work.remaining = 100000;
  munit_assert_int(
      TC_RSA_raw_public(&key, input, &workspace, (TC_buffer){representative, width}, &public_work),
      ==, TC_RSA_ARGUMENT);
  memcpy(representative, modulus, width);
  munit_assert_int(
      TC_RSA_raw_public(&key, input, &workspace, (TC_buffer){recovered, width}, &public_work), ==,
      TC_RSA_INVALID);
  munit_assert_memory_equal(width, recovered, unchanged);
  representative[0] = 0;
  representative[width - 1] = 42;
  memset(recovered, 0x5a, width);
  source.fail = 1;
  execution.work.remaining = 100000;
  munit_assert_int(TC_RSA_raw_private(&key, (TC_bytes){private_exponent, width}, input, &workspace,
                                      (TC_buffer){recovered, width}, &execution),
                   ==, TC_RSA_ERROR);
  munit_assert_memory_equal(width, recovered, unchanged);
  source.fail = 0;
  private_exponent[width - 1] ^= 2;
  execution.work.remaining = 100000;
  munit_assert_int(TC_RSA_raw_private(&key, (TC_bytes){private_exponent, width}, input, &workspace,
                                      (TC_buffer){recovered, width}, &execution),
                   ==, TC_RSA_ERROR);
  munit_assert_memory_equal(width, recovered, unchanged);

  EVP_PKEY_CTX_free(public_context);
  EVP_PKEY_CTX_free(private_context);
  EVP_PKEY_free(generated);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitParameterEnum sizes[] = {{"bits", (char*[]){"1024", "2048", "4096", NULL}}, {NULL, NULL}};
  MunitTest tests[] = {{"/operations", raw_operations, NULL, NULL, MUNIT_TEST_OPTION_NONE, sizes},
                       {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/rsa/raw", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
