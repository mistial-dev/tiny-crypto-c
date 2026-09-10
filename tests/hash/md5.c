/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/md5.h>
#include "munit.h"
#include "test_util.h"
#include <string.h>

static void check(const uint8_t* data, size_t length, const char* answer)
{
  uint8_t expected[TC_MD5_DIGESTLEN], digest[TC_MD5_DIGESTLEN];
  munit_assert_size(tc_test_decode_hex(answer,expected,sizeof expected), ==, sizeof expected);
  munit_assert_int(TC_MD5_digest(data,length,digest), ==, TC_OK);
  munit_assert_memory_equal(sizeof digest,digest,expected);
  for (size_t split = 0; split <= length; ++split) {
    struct TC_MD5_ctx ctx;
    munit_assert_int(TC_MD5_init(&ctx), ==, TC_OK);
    munit_assert_int(TC_MD5_update(&ctx,data,split), ==, TC_OK);
    munit_assert_int(TC_MD5_update(&ctx,NULL,0), ==, TC_OK);
    munit_assert_int(TC_MD5_update(&ctx,data + split,length - split), ==, TC_OK);
    munit_assert_int(TC_MD5_final(&ctx,digest), ==, TC_OK);
    munit_assert_memory_equal(sizeof digest,digest,expected);
#if TC_ZEROIZE
    munit_assert(tc_test_all_zero(&ctx,sizeof ctx));
#endif
    TC_MD5_ctx_clear(&ctx);
    munit_assert(tc_test_all_zero(&ctx,sizeof ctx));
  }
}

static MunitResult test_known(const MunitParameter params[], void* user)
{
  /* RFC 1321 known answers. */
  static const char* messages[] = {"", "a", "abc", "message digest",
    "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890"};
  static const char* answers[] = {"d41d8cd98f00b204e9800998ecf8427e", "0cc175b9c0f1b6a831c399e269772661",
    "900150983cd24fb0d6963f7d28e17f72", "f96b697d7cb7938d525a2f31aaf161d0",
    "c3fcd3d76192e4007dfb496cca67e13b", "d174ab98d277d9f5a5611c2c9f419d9f",
    "57edf4a22be3c955ac49da2e2107b67a"};
  (void)params; (void)user;
  for (size_t i = 0; i < sizeof messages / sizeof messages[0]; ++i)
    check((const uint8_t*)messages[i],strlen(messages[i]),answers[i]);
  return MUNIT_OK;
}

static MunitResult test_boundaries(const MunitParameter params[], void* user)
{
  static const size_t lengths[] = {55,56,63,64,65,119,120,127,128,129,255,256};
  /* Independent hashlib answers for the byte sequence 00,01,...,FF. */
  static const char* answers[] = {"6912ee65fff2d9f9ce2508cddf8bcda0", "51fdd1acda72405dfdfa03fcb85896d7",
    "48a6295221902e8e0938f773a7185e72", "b2d3f56bc197fd985d5965079b5e7148",
    "8bd7053801c768420faf816fadba971c", "1c772251899a7ff007400b888d6b2042",
    "b7ba1efc6022e9ed272f00b8831e26e6", "8402b21e7bc7906493bae0dac017f1f9",
    "37eff01866ba3f538421b30b7cbefcac", "46f986692847558fc38b0cece591c20f",
    "11b7aaa64c413d2f0fccf893881c46a2", "e2c865db4162bed963bfaa9ef6ac18f0"};
  uint8_t data[256];
  (void)params; (void)user;
  tc_test_fill_incrementing(data,sizeof data);
  for (size_t i = 0; i < sizeof lengths / sizeof lengths[0]; ++i) check(data,lengths[i],answers[i]);
  return MUNIT_OK;
}

static MunitResult test_long(const MunitParameter params[], void* user)
{
  struct TC_MD5_ctx ctx;
  uint8_t data[1000], digest[TC_MD5_DIGESTLEN], expected[TC_MD5_DIGESTLEN];
  (void)params; (void)user;
  memset(data,'a',sizeof data);
  tc_test_decode_hex("7707d6ae4e027c70eea2a935c2296f21",expected,sizeof expected);
  munit_assert_int(TC_MD5_init(&ctx), ==, TC_OK);
  for (size_t i = 0; i < 1000; ++i)
    munit_assert_int(TC_MD5_update(&ctx,data,sizeof data), ==, TC_OK);
  munit_assert_int(TC_MD5_final(&ctx,digest), ==, TC_OK);
  munit_assert_memory_equal(sizeof digest,digest,expected);
  return MUNIT_OK;
}

static MunitResult test_arguments(const MunitParameter params[], void* user)
{
  struct TC_MD5_ctx ctx, saved;
  uint8_t output[TC_MD5_DIGESTLEN], data[32] = {0};
  (void)params; (void)user;
  memset(output,0xa5,sizeof output);
  munit_assert_int(TC_MD5_init(&ctx), ==, TC_OK);
  saved = ctx;
  munit_assert_int(TC_MD5_update(&ctx,NULL,1), ==, TC_ERROR);
  munit_assert_int(TC_MD5_update(&ctx,ctx.Buf,1), ==, TC_ERROR);
  munit_assert_int(TC_MD5_final(&ctx,ctx.Buf), ==, TC_ERROR);
  munit_assert_int(TC_MD5_final(&ctx,NULL), ==, TC_ERROR);
  munit_assert_memory_equal(sizeof ctx,&ctx,&saved);
  ctx.BufLen = TC_MD5_BLOCKLEN;
  saved = ctx;
  munit_assert_int(TC_MD5_update(&ctx,data,1), ==, TC_ERROR);
  munit_assert_int(TC_MD5_final(&ctx,output), ==, TC_ERROR);
  munit_assert_memory_equal(sizeof ctx,&ctx,&saved);
  munit_assert_int(TC_MD5_digest(NULL,1,output), ==, TC_ERROR);
  for (size_t i = 0; i < sizeof output; ++i) munit_assert_uint(output[i], ==, 0xa5);
  munit_assert_int(TC_MD5_init(NULL), ==, TC_ERROR);
  munit_assert_int(TC_MD5_update(NULL,data,1), ==, TC_ERROR);
  munit_assert_int(TC_MD5_final(NULL,output), ==, TC_ERROR);
  munit_assert_int(TC_MD5_digest(data,1,NULL), ==, TC_ERROR);
  TC_MD5_ctx_clear(NULL);
  munit_assert_int(TC_MD5_digest(data,sizeof data,output), ==, TC_OK);
  munit_assert_int(TC_MD5_digest(data,sizeof data,data), ==, TC_OK);
  munit_assert_memory_equal(sizeof output,output,data);
  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/known",test_known,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {"/boundaries",test_boundaries,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {"/long",test_long,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {"/arguments",test_arguments,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
};
static const MunitSuite suite = {"/md5",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{ return munit_suite_main(&suite,NULL,argc,argv); }
