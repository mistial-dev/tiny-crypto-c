/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/twic_tpk.h>
#include <tiny_crypto/aes.h>
#include "munit.h"
#include <string.h>

static MunitResult decrypt(const MunitParameter params[], void* context)
{
  TC_TWIC_tpk key = {{0}};
  struct TC_AES_key_ctx aes;
  uint8_t buffer[TC_AES_BLOCKLEN * 2], zeros[sizeof buffer] = {0};
  munit_assert_int(TC_AES_key_init(&aes,key.key), ==, TC_OK);
  for (size_t padding = 1; padding <= TC_AES_BLOCKLEN; ++padding) {
    memset(buffer,0x5a,sizeof buffer - padding);
    memset(buffer + sizeof buffer - padding,(int)padding,padding);
    for (size_t offset = 0; offset < sizeof buffer; offset += TC_AES_BLOCKLEN)
      munit_assert_int(TC_AES_ECB_encrypt(&aes,buffer + offset), ==, TC_OK);
    size_t length = SIZE_MAX;
    munit_assert_int(TC_TWIC_object_decrypt(&key,buffer,sizeof buffer,&length), ==, TC_OK);
    munit_assert_size(length, ==, sizeof buffer - padding);
    for (size_t i = 0; i < length; ++i) munit_assert_uint(buffer[i], ==, 0x5a);
    munit_assert_memory_equal(padding,buffer + length,zeros);
  }
  for (size_t bad = 0; bad < TC_AES_BLOCKLEN; ++bad) {
    memset(buffer,TC_AES_BLOCKLEN,sizeof buffer);
    buffer[sizeof buffer - 1 - bad] = 0;
    for (size_t offset = 0; offset < sizeof buffer; offset += TC_AES_BLOCKLEN)
      munit_assert_int(TC_AES_ECB_encrypt(&aes,buffer + offset), ==, TC_OK);
    size_t length = SIZE_MAX;
    munit_assert_int(TC_TWIC_object_decrypt(&key,buffer,sizeof buffer,&length), ==, TC_ERROR);
    munit_assert_size(length, ==, SIZE_MAX);
    munit_assert_memory_equal(sizeof buffer,buffer,zeros);
  }
  size_t length = SIZE_MAX;
  memset(buffer,0x5a,sizeof buffer);
  munit_assert_int(TC_TWIC_object_decrypt(&key,buffer,sizeof buffer - 1,&length), ==, TC_ERROR);
  for (size_t i = 0; i < sizeof buffer; ++i) munit_assert_uint(buffer[i], ==, 0x5a);
  munit_assert_size(length, ==, SIZE_MAX);
  TC_secure_zero(&aes,sizeof aes);
  (void)params; (void)context;
  return MUNIT_OK;
}
static MunitResult known_answers(const MunitParameter params[], void* context)
{
  /* OpenSSL enc -aes-128-ecb, PKCS#7 padding, key bytes 00 through 0f. */
  static const uint8_t ciphertext[][TC_AES_BLOCKLEN] = {
    {0x78,0xd7,0x4a,0x51,0x63,0x67,0x6a,0x2a,0xf4,0x70,0x49,0xe0,0xcd,0xa2,0x1d,0xb5},
    {0x95,0x4f,0x64,0xf2,0xe4,0xe8,0x6e,0x9e,0xee,0x82,0xd2,0x02,0x16,0x68,0x48,0x99}
  };
  static const uint8_t plaintext[] = "TWIC synthetic";
  TC_TWIC_tpk key;
  uint8_t buffer[TC_AES_BLOCKLEN], zeros[TC_AES_BLOCKLEN] = {0};
  for (size_t i = 0; i < sizeof key.key; ++i) key.key[i] = (uint8_t)i;
  for (size_t i = 0; i < sizeof ciphertext / sizeof *ciphertext; ++i) {
    size_t length = SIZE_MAX;
    memcpy(buffer,ciphertext[i],sizeof buffer);
    munit_assert_int(TC_TWIC_object_decrypt(&key,buffer,sizeof buffer,&length), ==, TC_OK);
    munit_assert_size(length, ==, i ? 0 : sizeof plaintext - 1);
    munit_assert_memory_equal(length,buffer,plaintext);
    munit_assert_memory_equal(sizeof buffer - length,buffer + length,zeros);
    munit_assert_int(TC_TWIC_object_encrypt(&key,buffer,length,sizeof buffer,&length), ==, TC_OK);
    munit_assert_size(length, ==, sizeof buffer);
    munit_assert_memory_equal(length,buffer,ciphertext[i]);
  }
  union { size_t length; TC_TWIC_tpk key; uint8_t bytes[TC_AES_BLOCKLEN]; } alias;
  memcpy(alias.bytes,ciphertext[0],sizeof alias.bytes);
  munit_assert_int(TC_TWIC_object_decrypt(&key,alias.bytes,sizeof alias.bytes,&alias.length), ==, TC_ERROR);
  munit_assert_memory_equal(sizeof alias.bytes,alias.bytes,ciphertext[0]);
  size_t length = SIZE_MAX;
  munit_assert_int(TC_TWIC_object_decrypt(&alias.key,alias.bytes,sizeof alias.bytes,&length), ==, TC_ERROR);
  munit_assert_size(length, ==, SIZE_MAX);
  munit_assert_memory_equal(sizeof alias.bytes,alias.bytes,ciphertext[0]);
  munit_assert_int(TC_TWIC_object_decrypt(NULL,buffer,sizeof buffer,&length), ==, TC_ERROR);
  munit_assert_int(TC_TWIC_object_decrypt(&key,NULL,sizeof buffer,&length), ==, TC_ERROR);
  munit_assert_int(TC_TWIC_object_decrypt(&key,buffer,0,&length), ==, TC_ERROR);
  munit_assert_int(TC_TWIC_object_decrypt(&key,buffer,sizeof buffer,NULL), ==, TC_ERROR);
  (void)params; (void)context;
  return MUNIT_OK;
}

static MunitResult encrypt(const MunitParameter params[], void* context)
{
  TC_TWIC_tpk key = {{0}};
  uint8_t buffer[TC_AES_BLOCKLEN * 4], original[sizeof buffer];
  memset(original,0x5a,sizeof original);
  for (size_t input = 0; input <= TC_AES_BLOCKLEN * 2; ++input) {
    size_t padded = input + TC_AES_BLOCKLEN - input % TC_AES_BLOCKLEN;
    size_t length = SIZE_MAX;
    memcpy(buffer,original,sizeof buffer);
    munit_assert_int(TC_TWIC_object_encrypt(&key,buffer,input,padded - 1,&length), ==, TC_ERROR);
    munit_assert_size(length, ==, SIZE_MAX);
    munit_assert_memory_equal(sizeof buffer,buffer,original);
    munit_assert_int(TC_TWIC_object_encrypt(&key,buffer,input,sizeof buffer,&length), ==, TC_OK);
    munit_assert_size(length, ==, padded);
    munit_assert_memory_equal(sizeof buffer - padded,buffer + padded,original + padded);
    munit_assert_int(TC_TWIC_object_decrypt(&key,buffer,length,&length), ==, TC_OK);
    munit_assert_size(length, ==, input);
    munit_assert_memory_equal(input,buffer,original);
  }
  size_t length = SIZE_MAX;
  memcpy(buffer,original,sizeof buffer);
  munit_assert_int(TC_TWIC_object_encrypt(&key,buffer,SIZE_MAX,SIZE_MAX,&length), ==, TC_ERROR);
  munit_assert_int(TC_TWIC_object_encrypt(NULL,buffer,0,sizeof buffer,&length), ==, TC_ERROR);
  munit_assert_int(TC_TWIC_object_encrypt(&key,NULL,0,sizeof buffer,&length), ==, TC_ERROR);
  munit_assert_int(TC_TWIC_object_encrypt(&key,buffer,0,sizeof buffer,NULL), ==, TC_ERROR);
  munit_assert_size(length, ==, SIZE_MAX);
  munit_assert_memory_equal(sizeof buffer,buffer,original);
  union { size_t length; TC_TWIC_tpk key; uint8_t bytes[TC_AES_BLOCKLEN * 2]; } alias;
  memset(alias.bytes,0x5a,sizeof alias.bytes);
  munit_assert_int(TC_TWIC_object_encrypt(&key,alias.bytes,0,sizeof alias.bytes,&alias.length), ==, TC_ERROR);
  munit_assert_int(TC_TWIC_object_encrypt(&alias.key,alias.bytes,0,sizeof alias.bytes,&length), ==, TC_ERROR);
  munit_assert_memory_equal(sizeof alias.bytes,alias.bytes,original);
  (void)params; (void)context;
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
#if TC_AES_SBOX_MODE == TC_AES_SBOX_MODE_RUNTIME
  /* Initialization failures have the same wiping contract as cipher failures. */
  TC_TWIC_tpk key = {{0}};
  uint8_t buffer[TC_AES_BLOCKLEN * 2], zeros[sizeof buffer] = {0};
  size_t length = SIZE_MAX;
  memset(buffer,0x5a,sizeof buffer);
  munit_assert_int(TC_TWIC_object_encrypt(&key,buffer,0,sizeof buffer,&length), ==, TC_ERROR);
  munit_assert_size(length, ==, SIZE_MAX);
  munit_assert_memory_equal(TC_AES_BLOCKLEN,buffer,zeros);
  for (size_t i = TC_AES_BLOCKLEN; i < sizeof buffer; ++i)
    munit_assert_uint(buffer[i], ==, 0x5a);
  memset(buffer,0x5a,sizeof buffer);
  munit_assert_int(TC_TWIC_object_decrypt(&key,buffer,sizeof buffer,&length), ==, TC_ERROR);
  munit_assert_size(length, ==, SIZE_MAX);
  munit_assert_memory_equal(sizeof buffer,buffer,zeros);
  TC_AES_init_sbox();
#endif
  MunitTest tests[] = {{"/decrypt",decrypt,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/known-answers",known_answers,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/encrypt",encrypt,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}};
  MunitSuite suite = {"/twic/cipher",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
