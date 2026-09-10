/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/tiny_crypto.h>
#include <tiny_crypto/x509_crypto.h>
#include "munit.h"
#include "test_util.h"
#include "rsa_vectors.h"
#include <string.h>

#if !TC_ENABLE_AES || !TC_AES_ENABLE_CBC || !TC_AES_ENABLE_ECB || \
    !TC_ENABLE_SHA1 || !TC_ENABLE_SHA256 || !TC_ENABLE_SHA384 || !TC_ENABLE_KMAC256 || \
    !TC_ENABLE_TLV || !TC_ENABLE_DER || !TC_ENABLE_X509 || !TC_ENABLE_PIV_CHUID || !TC_ENABLE_GZIP || \
    !TC_TLV_ENABLE_BER || !TC_ENABLE_RSA || !TC_ENABLE_EC || !TC_EC_ENABLE_P256 || !TC_EC_ENABLE_P384
#error "Missing shared PIV capability"
#endif
#if TC_ENABLE_PIV_SM != EXPECT_PD || TC_ENABLE_SSKDF != EXPECT_PD || \
    TC_ENABLE_PIV_CVC != EXPECT_PD || TC_AES_ENABLE_DYNAMIC != EXPECT_PD || \
    TC_PIV_SM_ENABLE_CS2 != EXPECT_PD || \
    TC_PIV_SM_ENABLE_CS7 != EXPECT_PD
#error "Card Secure Messaging must follow the PD role"
#endif
#if TC_ENABLE_DES || TC_ENABLE_SHA224 || TC_ENABLE_SHA512 || \
    TC_ENABLE_HMAC || TC_ENABLE_KDF || TC_ENABLE_EAC_CVC || \
    TC_AES_ENABLE_CTR || TC_AES_ENABLE_GCM || TC_AES_ENABLE_CCM || TC_AES_ENABLE_CMAC || \
    TC_AES_ENABLE_OFB || TC_AES_ENABLE_EAX || TC_AES_ENABLE_EAX_PRIME || TC_AES_ENABLE_SIV || \
    TC_TLV_ENABLE_STREAM
#error "Unrelated algorithm enabled in a PIV role"
#endif

static MunitResult legacy_hash(const MunitParameter params[], void* context)
{
  const uint8_t message[] = {'a','b','c'};
  const uint8_t expected[] = {
    0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,
    0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d
  };
  uint8_t digest[TC_SHA1_DIGESTLEN];
  munit_assert_int(TC_SHA1_digest(message,sizeof message,digest), ==, TC_OK);
  munit_assert_memory_equal(sizeof digest,digest,expected);
  (void)params; (void)context; return MUNIT_OK;
}

static MunitResult gzip_member(const MunitParameter params[], void* context)
{
  uint8_t encoded[] = {0x1f,0x8b,8,0,0,0,0,0,2,0xff,3,0,0,0,0,0,0,0,0,0};
  TC_GZIP_workspace workspace;
  size_t work = 4096, length = SIZE_MAX;
  munit_assert_int(TC_GZIP_decode(encoded,sizeof encoded,NULL,0,&workspace,&work,&length), ==, TC_GZIP_OK);
  munit_assert_size(length, ==, 0);
  encoded[sizeof encoded - 8] ^= 1;
  work = 4096; length = SIZE_MAX;
  munit_assert_int(TC_GZIP_decode(encoded,sizeof encoded,NULL,0,&workspace,&work,&length), ==, TC_GZIP_INVALID);
  munit_assert_size(length, ==, SIZE_MAX);
  (void)params; (void)context; return MUNIT_OK;
}

static MunitResult native_signature(const MunitParameter params[], void* context)
{
  enum { MAX_SCALAR_BYTES = 48, MAX_SPKI_BYTES = 120, WORK_LIMIT = 100000 };
  static const uint8_t p256_prefix[] = {
    0x30,89,0x30,19,6,7,0x2a,0x86,0x48,0xce,0x3d,2,1,
    6,8,0x2a,0x86,0x48,0xce,0x3d,3,1,7,3,66,0
  };
  static const uint8_t p384_prefix[] = {
    0x30,118,0x30,16,6,7,0x2a,0x86,0x48,0xce,0x3d,2,1,
    6,5,0x2b,0x81,4,0,0x22,3,98,0
  };
  const int p384 = !strcmp(munit_parameters_get(params,"curve"),"p384");
  const size_t scalar_bytes = p384 ? 48 : 32;
  const size_t point_offset = p384 ? sizeof p384_prefix : sizeof p256_prefix;
  const size_t point_bytes = 1 + 2 * scalar_bytes, spki_bytes = point_offset + point_bytes;
  const TC_hash_algorithm hash = p384 ? TC_HASH_SHA384 : TC_HASH_SHA256;
  uint8_t spki[MAX_SPKI_BYTES], scalar[MAX_SCALAR_BYTES] = {0}, digest[MAX_SCALAR_BYTES] = {0};
  uint8_t signature[2 * MAX_SCALAR_BYTES + 8] = {0};
  memcpy(spki,p384 ? p384_prefix : p256_prefix,point_offset);
  TC_EC_workspace ec;
  TC_ECDSA_workspace verification;
  TC_X509_public_key key;
  scalar[scalar_bytes - 1] = 1;
  munit_assert_int(TC_EC_public_key(p384 ? TC_EC_P384 : TC_EC_P256,scalar,scalar_bytes,
      spki + point_offset,point_bytes,&ec), ==, TC_OK);
  munit_assert_int(TC_X509_subject_public_key(spki,spki_bytes,&key), ==, TC_TLV_OK);
  /* For d=k=1 and z=0, ECDSA has r=s=G.x. DER keeps these integers positive. */
  const size_t padding = (spki[point_offset + 1] & 0x80) ? 1 : 0;
  const size_t component_bytes = scalar_bytes + padding, signature_bytes = 6 + 2 * component_bytes;
  signature[0] = 0x30; signature[1] = (uint8_t)(signature_bytes - 2);
  signature[2] = 2; signature[3] = (uint8_t)component_bytes;
  memcpy(signature + 4 + padding,spki + point_offset + 1,scalar_bytes);
  signature[component_bytes + 4] = 2; signature[component_bytes + 5] = (uint8_t)component_bytes;
  memcpy(signature + component_bytes + 6,signature + 4,component_bytes);
  const TC_signature_algorithm algorithm = {TC_SIGNATURE_ECDSA,hash,hash,0};
  const TC_X509_native_workspace workspace = {&verification,NULL,TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  const TC_X509_signature_provider provider = TC_X509_native_provider(&workspace);
  for (unsigned variant = 0; variant < 3; ++variant) {
    size_t work = variant == 2 ? 0 : WORK_LIMIT;
    digest[0] = variant == 1 ? 1 : 0;
    munit_assert_int(TC_X509_signature_verify_digest((TC_bytes){digest,scalar_bytes},
        &algorithm,(TC_bytes){signature,signature_bytes},&key,&provider,&work), ==,
        variant == 2 ? TC_X509_SIGNATURE_LIMIT :
        variant == 1 ? TC_X509_SIGNATURE_INVALID : TC_X509_SIGNATURE_VALID);
  }
  (void)params; (void)context; return MUNIT_OK;
}

static MunitResult rsa_signature(const MunitParameter params[], void* context)
{
  enum { MAX_BITS = 3072, MAX_SIGNATURE = MAX_BITS / 8, MAX_SPKI = 512, WORK_LIMIT = 100000 };
  uint8_t spki[MAX_SPKI], signature[MAX_SIGNATURE], digest[TC_SHA256_DIGESTLEN];
  TC_RSA_word words[TC_RSA_VERIFY_WORKSPACE_WORDS(MAX_BITS)];
  const TC_RSA_workspace rsa = {words,sizeof words / sizeof *words};
  const TC_X509_native_workspace workspace = {NULL,&rsa,TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  const TC_X509_signature_provider provider = TC_X509_native_provider(&workspace);
  const int pss = !strcmp(munit_parameters_get(params,"scheme"),"pss");
  const TC_signature_algorithm algorithm = {
    pss ? TC_SIGNATURE_RSA_PSS : TC_SIGNATURE_RSA_V15,TC_HASH_SHA256,TC_HASH_SHA256,TC_SHA256_DIGESTLEN
  };
  for (size_t i = 0; i < sizeof rsa_vectors / sizeof *rsa_vectors; ++i) {
    TC_X509_public_key key;
    size_t spki_length = tc_test_decode_hex(rsa_vectors[i].spki,spki,sizeof spki);
    size_t signature_length = tc_test_decode_hex(pss ? rsa_vectors[i].pss : rsa_vectors[i].v15,
        signature,sizeof signature);
    munit_assert_size(spki_length, >, 0);
    munit_assert_size(signature_length, ==, rsa_vectors[i].bits / 8);
    munit_assert_size(tc_test_decode_hex(rsa_digest,digest,sizeof digest), ==, sizeof digest);
    munit_assert_int(TC_X509_subject_public_key(spki,spki_length,&key), ==, TC_TLV_OK);
    munit_assert_uint(key.bits, ==, rsa_vectors[i].bits);
    for (unsigned variant = 0; variant < 3; ++variant) {
      size_t work = variant == 2 ? 0 : WORK_LIMIT;
      if (variant == 1) digest[0] ^= 1;
      munit_assert_int(TC_X509_signature_verify_digest((TC_bytes){digest,sizeof digest},
          &algorithm,(TC_bytes){signature,signature_length},&key,&provider,&work), ==,
          variant == 2 ? TC_X509_SIGNATURE_LIMIT :
          variant == 1 ? TC_X509_SIGNATURE_INVALID : TC_X509_SIGNATURE_VALID);
      if (variant == 1) digest[0] ^= 1;
    }
  }
  (void)context; return MUNIT_OK;
}

int main(int argc, char** argv)
{
  static char* curves[] = {"p256","p384",NULL};
  static MunitParameterEnum curve_params[] = {{"curve",curves},{NULL,NULL}};
  static char* schemes[] = {"v15","pss",NULL};
  static MunitParameterEnum rsa_params[] = {{"scheme",schemes},{NULL,NULL}};
  MunitTest tests[] = {
    {"/legacy-hash",legacy_hash,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/gzip",gzip_member,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/native-signature",native_signature,NULL,NULL,MUNIT_TEST_OPTION_NONE,curve_params},
    {"/rsa-signature",rsa_signature,NULL,NULL,MUNIT_TEST_OPTION_NONE,rsa_params},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/role",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
