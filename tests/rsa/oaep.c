/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../src/rsa_oaep_internal.h"
#include "munit.h"

enum { MAX_BYTES = 384, MAX_DIGEST = 64, WORK_BUDGET = 100000 };

static MunitResult known_answer(const MunitParameter params[], void* user)
{
  /* Independently calculated with Python hashlib, SHA-256 for both hashes. */
  static const uint8_t expected[] =
    "\x00\x02\x5b\xd0\x50\xc2\x08\xbb\x41\x53\xc4\xd8\xc7\x8f\xb5\xbb"
    "\xe8\xc7\x1d\xd7\x09\xfe\x88\xad\x9c\x58\xc6\xde\x59\x56\x31\xb5"
    "\x9c\xda\x85\x68\xc9\xef\x97\x08\x9c\xc8\x0c\xe2\xb4\xc9\x57\x6c"
    "\xce\x87\xd0\xab\xdf\x0c\xf7\x40\x0a\x23\xa5\x41\x88\x07\x66\x1e"
    "\xaf\x04\xa6\x95\x0a\x06\xd3\xe3\x30\x8a\xd7\xd3\x60\x6e\xf8\x10"
    "\xeb\x12\x4e\x39\x43\x40\x4c\xa7\x46\xa1\x2c\x51\xc7\xbf\x77\x68"
    "\x39\x0f\x8d\x84\x2a\xc9\xcb\x62\x34\x97\x79\xa7\x53\x7a\x78\x32"
    "\x7d\x54\x5a\xae\xb3\x3b\x2d\x42\xc6\xbc\xb9\x45\xf3\xc5\xd5\x53";
  uint8_t encoded[sizeof expected - 1], seed[32], block[MAX_DIGEST];
  const TC_bytes label = {(const uint8_t*)"piv",3}, input = {(const uint8_t*)"message",7};
  const TC_bytes sentinel = {expected,sizeof expected};
  TC_bytes message = sentinel;
  tc_hash_workspace workspace;
  size_t work = WORK_BUDGET;
  (void)params; (void)user;
  for (size_t i = 0; i < sizeof seed; ++i) seed[i] = (uint8_t)i;
  munit_assert_int(tc_rsa_oaep_encode(encoded,sizeof encoded,TC_HASH_SHA256,TC_HASH_SHA256,
      label,input,(TC_bytes){seed,sizeof seed},block,&workspace,&work), ==, TC_RSA_OK);
  munit_assert_memory_equal(sizeof encoded,encoded,expected);
  const size_t encode_work = WORK_BUDGET - work;
  work = WORK_BUDGET;
  munit_assert_int(tc_rsa_oaep_decode(encoded,sizeof encoded,TC_HASH_SHA256,TC_HASH_SHA256,
      label,block,&workspace,&work,&message), ==, TC_RSA_OK);
  munit_assert_size(message.length, ==, input.length);
  munit_assert_ptr_equal(message.data,encoded + sizeof encoded - input.length);
  munit_assert_memory_equal(message.length,message.data,input.data);
  const size_t decode_work = WORK_BUDGET - work;
  for (size_t i = 0; i < sizeof encoded; ++i) {
    memcpy(encoded,expected,sizeof encoded); encoded[i] ^= 1;
    work = WORK_BUDGET; message = sentinel;
    munit_assert_int(tc_rsa_oaep_decode(encoded,sizeof encoded,TC_HASH_SHA256,TC_HASH_SHA256,
        label,block,&workspace,&work,&message), ==, TC_RSA_INVALID);
    munit_assert_size(WORK_BUDGET - work, ==, decode_work);
    munit_assert_ptr_equal(message.data,sentinel.data);
    munit_assert_size(message.length, ==, sentinel.length);
  }
  for (size_t budget = 0; budget <= encode_work; ++budget) {
    work = budget;
    munit_assert_int(tc_rsa_oaep_encode(encoded,sizeof encoded,TC_HASH_SHA256,TC_HASH_SHA256,
        label,input,(TC_bytes){seed,sizeof seed},block,&workspace,&work), ==,
        budget == encode_work ? TC_RSA_OK : TC_RSA_LIMIT);
  }
  for (size_t budget = 0; budget <= decode_work; ++budget) {
    memcpy(encoded,expected,sizeof encoded); work = budget; message = sentinel;
    munit_assert_int(tc_rsa_oaep_decode(encoded,sizeof encoded,TC_HASH_SHA256,TC_HASH_SHA256,
        label,block,&workspace,&work,&message), ==, budget == decode_work ? TC_RSA_OK : TC_RSA_LIMIT);
    if (budget != decode_work) {
      munit_assert_ptr_equal(message.data,sentinel.data);
      munit_assert_size(message.length, ==, sentinel.length);
    }
  }
  return MUNIT_OK;
}

static MunitResult boundaries(const MunitParameter params[], void* user)
{
  const TC_hash_algorithm hashes[] = {TC_HASH_SHA1,TC_HASH_SHA224,TC_HASH_SHA256,TC_HASH_SHA384,TC_HASH_SHA512};
  const size_t lengths[] = {128,256,384};
  uint8_t encoded[MAX_BYTES], input[MAX_BYTES], seed[MAX_DIGEST], block[MAX_DIGEST];
  tc_hash_workspace workspace;
  const TC_bytes empty = {NULL,0};
  (void)params; (void)user;
  memset(seed,0xa5,sizeof seed);
  for (size_t i = 0; i < sizeof input; ++i) input[i] = (uint8_t)i;
  for (size_t h = 0; h < sizeof hashes / sizeof *hashes; ++h) {
    tc_hash_info info;
    munit_assert_true(tc_hash_info_get(hashes[h],&info));
    for (size_t k = 0; k < sizeof lengths / sizeof *lengths; ++k) {
      const size_t length = lengths[k];
      size_t work = WORK_BUDGET;
      if (length < 2 * info.digest_length + 2) {
        munit_assert_int(tc_rsa_oaep_encode(encoded,length,hashes[h],TC_HASH_SHA256,empty,
            empty,(TC_bytes){seed,info.digest_length},block,&workspace,&work), ==, TC_RSA_INVALID);
        continue;
      }
      const size_t maximum = length - 2 * info.digest_length - 2;
      for (size_t n = 0; n <= maximum; ++n) {
        const TC_bytes input_view = {input,n};
        TC_bytes decoded = {NULL,0};
        work = WORK_BUDGET;
        munit_assert_int(tc_rsa_oaep_encode(encoded,length,hashes[h],TC_HASH_SHA256,empty,
            input_view,(TC_bytes){seed,info.digest_length},block,&workspace,&work), ==, TC_RSA_OK);
        work = WORK_BUDGET;
        munit_assert_int(tc_rsa_oaep_decode(encoded,length,hashes[h],TC_HASH_SHA256,empty,
            block,&workspace,&work,&decoded), ==, TC_RSA_OK);
        munit_assert_size(decoded.length, ==, n);
        munit_assert_memory_equal(n,decoded.data,input);
      }
      work = WORK_BUDGET;
      munit_assert_int(tc_rsa_oaep_encode(encoded,length,hashes[h],TC_HASH_SHA256,empty,
          (TC_bytes){input,maximum + 1},(TC_bytes){seed,info.digest_length},block,&workspace,&work), ==, TC_RSA_INVALID);
    }
  }
  return MUNIT_OK;
}

static MunitResult padding(const MunitParameter params[], void* user)
{
  enum { WIDTH = 128, HASH_BYTES = 32, DB_LENGTH = WIDTH - HASH_BYTES - 1 };
  enum { BAD_PREFIX, BAD_HASH, BAD_PADDING, NO_DELIMITER, CASE_COUNT };
  uint8_t encoded[WIDTH], seed[HASH_BYTES] = {0}, block[MAX_DIGEST];
  tc_hash_workspace workspace;
  const TC_bytes empty = {NULL,0}, input = {(const uint8_t*)"test",4};
  (void)params; (void)user;
  for (unsigned scenario = 0; scenario < CASE_COUNT; ++scenario) {
    size_t work = WORK_BUDGET;
    TC_bytes decoded = empty;
    munit_assert_int(tc_rsa_oaep_encode(encoded,sizeof encoded,TC_HASH_SHA256,TC_HASH_SHA256,
        empty,input,(TC_bytes){seed,sizeof seed},block,&workspace,&work), ==, TC_RSA_OK);
    work = WORK_BUDGET;
    munit_assert_int(tc_rsa_oaep_decode(encoded,sizeof encoded,TC_HASH_SHA256,TC_HASH_SHA256,
        empty,block,&workspace,&work,&decoded), ==, TC_RSA_OK);
    const size_t required = WORK_BUDGET - work;
    uint8_t* db = encoded + HASH_BYTES + 1;
    if (scenario == BAD_PREFIX) encoded[0] = 1;
    if (scenario == BAD_HASH) db[0] ^= 1;
    if (scenario == BAD_PADDING) db[HASH_BYTES] = 2;
    if (scenario == NO_DELIMITER) db[DB_LENGTH - input.length - 1] = 0;
    /* Remask a specific malformed DB so its other fields remain valid. */
    work = WORK_BUDGET;
    munit_assert_int(tc_rsa_mgf1_xor(TC_HASH_SHA256,(TC_bytes){encoded + 1,HASH_BYTES},
        db,DB_LENGTH,block,&workspace,&work), ==, TC_RSA_OK);
    munit_assert_int(tc_rsa_mgf1_xor(TC_HASH_SHA256,(TC_bytes){db,DB_LENGTH},
        encoded + 1,HASH_BYTES,block,&workspace,&work), ==, TC_RSA_OK);
    work = WORK_BUDGET; decoded = empty;
    munit_assert_int(tc_rsa_oaep_decode(encoded,sizeof encoded,TC_HASH_SHA256,TC_HASH_SHA256,
        empty,block,&workspace,&work,&decoded), ==, TC_RSA_INVALID);
    munit_assert_size(WORK_BUDGET - work, ==, required);
    munit_assert_null(decoded.data); munit_assert_size(decoded.length, ==, 0);
  }
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/known-answer",known_answer,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/boundaries",boundaries,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/padding",padding,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/rsa/oaep",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
