/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Behaviour and contents of each TINY_CRYPTO_TARGET. */
#include <tiny_crypto/tiny_crypto.h>
#include <tiny_crypto/x509_crypto.h>
#include "munit.h"
#include "test_util.h"
#include "cavp.h"
#include <string.h>

/* EXPECT_<TARGET> is 1 for the configured TINY_CRYPTO_TARGET. full, piv and
 * twic share the PIV checks. */
#define EXPECT_PIV_FAMILY (EXPECT_FULL || EXPECT_PIV || EXPECT_TWIC)

#if EXPECT_PIV_FAMILY
#include "rsa_vectors.h"
#endif

#if EXPECT_PIV_FAMILY
#if !TC_ENABLE_SHA256 || !TC_ENABLE_SHA384 || !TC_ENABLE_AES || !TC_AES_ENABLE_DYNAMIC ||          \
    !TC_AES_ENABLE_ECB || !TC_AES_ENABLE_CBC || !TC_AES_ENABLE_CMAC || !TC_ENABLE_SSKDF ||         \
    !TC_ENABLE_EC || !TC_EC_ENABLE_P256 || !TC_EC_ENABLE_P384 || !TC_ENABLE_RSA ||                 \
    !TC_RSA_ENABLE_2048 || !TC_RSA_ENABLE_3072 || !TC_RSA_ENABLE_4096 || !TC_ENABLE_GZIP ||        \
    !TC_TLV_ENABLE_BER || !TC_ENABLE_X509_PATH || !TC_ENABLE_X509_REVOCATION ||                    \
    !TC_ENABLE_CMS_VALIDATION || !TC_ENABLE_PIV_SM || !TC_PIV_SM_ENABLE_CS2 ||                     \
    !TC_PIV_SM_ENABLE_CS7 || !TC_ENABLE_PIV_VCI || !TC_ENABLE_PIV_KEY_PROOF ||                     \
    !TC_ENABLE_PIV_CARD_CHECK
#error "Missing SP 800-73-5 capability"
#endif
#endif

#if EXPECT_TWIC || EXPECT_FULL
#if !TC_ENABLE_TWIC || !TC_ENABLE_TWIC_UUID || !TC_ENABLE_SHA1 || !TC_RSA_ENABLE_1024 ||           \
    !TC_ENABLE_AAMVA || !TC_ENABLE_TWIC_TPK || !TC_ENABLE_TWIC_CCL ||                              \
    !TC_ENABLE_TWIC_OBJECT_CRYPTO
#error "Missing TWIC capability"
#endif
#endif

#if EXPECT_PIV || EXPECT_TWIC
#if TC_ENABLE_SHA224 || TC_ENABLE_SHA512 || TC_ENABLE_MD5 || TC_ENABLE_HMAC ||                     \
    TC_ENABLE_KMAC256 || TC_ENABLE_DES || TC_ENABLE_KDF || TC_ENABLE_HKDF || TC_ENABLE_DRBG ||     \
    TC_EC_ENABLE_P192 || TC_ENABLE_X509_OCSP || TC_ENABLE_EAC_CVC ||                               \
    TC_ENABLE_TRUST_ANCHOR_FORMAT || TC_AES_ENABLE_CTR || TC_AES_ENABLE_OFB ||                     \
    TC_AES_ENABLE_GCM || TC_AES_ENABLE_CCM || TC_AES_ENABLE_EAX || TC_AES_ENABLE_EAX_PRIME ||      \
    TC_AES_ENABLE_SIV || TC_AES_ENABLE_KW || TC_TLV_ENABLE_STREAM
#error "Algorithm outside the PIV or TWIC target enabled"
#endif
#endif
#if EXPECT_PIV &&                                                                                  \
    (TC_ENABLE_TWIC || TC_ENABLE_TWIC_UUID || TC_ENABLE_SHA1 || TC_RSA_ENABLE_1024 ||              \
     TC_ENABLE_AAMVA || TC_ENABLE_TWIC_TPK || TC_ENABLE_TWIC_CCL || TC_ENABLE_TWIC_OBJECT_CRYPTO)
#error "TWIC capability enabled in the PIV target"
#endif

#if EXPECT_DESFIRE || EXPECT_FULL
#if !TC_ENABLE_AES || !TC_AES_ENABLE_CBC || !TC_ENABLE_DES || !TC_DES_ENABLE_ECB ||                \
    !TC_DES_ENABLE_CBC || !TC_DES_ENABLE_TDES
#error "Missing DESFire primitive"
#endif
#endif
#if EXPECT_DESFIRE &&                                                                              \
    (TC_ENABLE_SHA1 || TC_ENABLE_SHA256 || TC_ENABLE_SHA384 || TC_ENABLE_SHA512 ||                 \
     TC_ENABLE_HMAC || TC_ENABLE_KDF || TC_ENABLE_TLV || TC_ENABLE_RSA || TC_ENABLE_EC ||          \
     TC_AES_ENABLE_DYNAMIC || TC_AES_ENABLE_ECB || TC_AES_ENABLE_CTR || TC_AES_ENABLE_CMAC ||      \
     TC_DES_ENABLE_CTR || TC_DES_ENABLE_CMAC || TC_DES_ENABLE_ISO9797)
#error "Primitive outside the DESFire target enabled"
#endif

#if EXPECT_FULL &&                                                                                 \
    (!TC_ENABLE_MD5 || !TC_ENABLE_SHA512 || !TC_ENABLE_HMAC || !TC_ENABLE_KMAC256 ||               \
     !TC_ENABLE_KDF || !TC_ENABLE_HKDF || !TC_ENABLE_DRBG || !TC_EC_ENABLE_P192 ||                 \
     !TC_DES_ENABLE_CMAC || !TC_ENABLE_X509_OCSP || !TC_ENABLE_EAC_CVC ||                          \
     !TC_ENABLE_TRUST_ANCHOR_FORMAT || !TC_AES_ENABLE_GCM || !TC_AES_ENABLE_KW)
#error "The full target omits a capability"
#endif

#if TC_ENABLE_AES && TC_AES_ENABLE_CBC
/* SP 800-38A F.2.1 CBC-AES128.Encrypt, first block, called as dfc-core does. */
TC_TEST(aes128_cbc)
{
  uint8_t key[16], iv[16], block[16], plain[16], cipher[16];
  munit_assert_size(tc_test_hex("2b7e151628aed2a6abf7158809cf4f3c", key, sizeof key), ==, 16);
  munit_assert_size(tc_test_hex("000102030405060708090a0b0c0d0e0f", iv, sizeof iv), ==, 16);
  munit_assert_size(tc_test_hex("6bc1bee22e409f96e93d7e117393172a", plain, sizeof plain), ==, 16);
  munit_assert_size(tc_test_hex("7649abac8119b246cee98e9b12e9197d", cipher, sizeof cipher), ==, 16);
  struct TC_AES_ctx ctx;
  memcpy(block, plain, sizeof block);
  munit_assert_int(TC_AES_init(&ctx, (TC_bytes){key, sizeof key}), ==, TC_OK);
  munit_assert_int(TC_AES_set_iv(&ctx, (TC_bytes){iv, sizeof iv}), ==, TC_OK);
  munit_assert_int(TC_AES_CBC_encrypt(&ctx, (TC_buffer){block, sizeof block}), ==, TC_OK);
  munit_assert_memory_equal(sizeof block, block, cipher);
  munit_assert_int(TC_AES_set_iv(&ctx, (TC_bytes){iv, sizeof iv}), ==, TC_OK);
  munit_assert_int(TC_AES_CBC_decrypt(&ctx, (TC_buffer){block, sizeof block}), ==, TC_OK);
  munit_assert_memory_equal(sizeof block, block, plain);
  TC_AES_ctx_clear(&ctx);
  return MUNIT_OK;
}
#endif

#if TC_ENABLE_DES && TC_DES_ENABLE_ECB && TC_DES_ENABLE_CBC && TC_DES_ENABLE_TDES
/* DES with 8-, 16- and 24-byte keys, as DESFire uses it. A TDEA bundle whose
 * components all equal K1 matches single DES under K1. The single-DES answer
 * is the FIPS 81 example: "Now is t" under 0123456789ABCDEF. */
TC_TEST(des_key_lengths)
{
  uint8_t keys[24], expected[8], block[8], iv[8] = {0};
  static const uint8_t plain[8] = {'N', 'o', 'w', ' ', 'i', 's', ' ', 't'};
  munit_assert_size(
      tc_test_hex("0123456789abcdef0123456789abcdef0123456789abcdef", keys, sizeof keys), ==, 24);
  munit_assert_size(tc_test_hex("3fa40e8a984d4815", expected, sizeof expected), ==, 8);
  struct TC_DES_ctx ctx;
  for (size_t length = 8; length <= 24; length += 8) {
    memcpy(block, plain, sizeof block);
    munit_assert_int(TC_DES_init(&ctx, (TC_bytes){keys, length}), ==, TC_OK);
    munit_assert_int(TC_DES_ECB_encrypt(&ctx, (TC_buffer){block, sizeof block}), ==, TC_OK);
    munit_assert_memory_equal(sizeof block, block, expected);
    munit_assert_int(TC_DES_ECB_decrypt(&ctx, (TC_buffer){block, sizeof block}), ==, TC_OK);
    munit_assert_memory_equal(sizeof block, block, plain);
    /* One CBC block under a zero IV matches ECB. */
    munit_assert_int(TC_DES_set_iv(&ctx, (TC_bytes){iv, sizeof iv}), ==, TC_OK);
    munit_assert_int(TC_DES_CBC_encrypt(&ctx, (TC_buffer){block, sizeof block}), ==, TC_OK);
    munit_assert_memory_equal(sizeof block, block, expected);
    munit_assert_int(TC_DES_set_iv(&ctx, (TC_bytes){iv, sizeof iv}), ==, TC_OK);
    munit_assert_int(TC_DES_CBC_decrypt(&ctx, (TC_buffer){block, sizeof block}), ==, TC_OK);
    munit_assert_memory_equal(sizeof block, block, plain);
    TC_DES_ctx_clear(&ctx);
  }
  return MUNIT_OK;
}
#endif

#if TC_ENABLE_SHA1
TC_TEST(sha1_hash)
{
  const uint8_t message[] = {'a', 'b', 'c'};
  const uint8_t expected[] = {0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
                              0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d};
  uint8_t digest[TC_SHA1_DIGESTLEN];
  munit_assert_int(TC_SHA1_digest((TC_bytes){message, sizeof message}, digest), ==, TC_OK);
  munit_assert_memory_equal(sizeof digest, digest, expected);
  return MUNIT_OK;
}
#endif

#if EXPECT_PIV_FAMILY
TC_TEST(gzip_member)
{
  uint8_t encoded[] = {0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 2, 0xff, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  TC_GZIP_workspace workspace;
  size_t work = 4096, length = SIZE_MAX;
  munit_assert_int(TC_GZIP_decode((TC_bytes){encoded, sizeof encoded}, &workspace, &work,
                                  (TC_buffer){NULL, 0}, &length),
                   ==, TC_GZIP_OK);
  munit_assert_size(length, ==, 0);
  encoded[sizeof encoded - 8] ^= 1;
  work = 4096;
  length = SIZE_MAX;
  munit_assert_int(TC_GZIP_decode((TC_bytes){encoded, sizeof encoded}, &workspace, &work,
                                  (TC_buffer){NULL, 0}, &length),
                   ==, TC_GZIP_INVALID);
  munit_assert_size(length, ==, SIZE_MAX);
  return MUNIT_OK;
}

static MunitResult native_signature(const MunitParameter params[], void* context)
{
  enum { MAX_SCALAR_BYTES = 48, MAX_SPKI_BYTES = 120, WORK_LIMIT = 100000 };
  static const uint8_t p256_prefix[] = {0x30, 89,   0x30, 19, 6, 7, 0x2a, 0x86, 0x48,
                                        0xce, 0x3d, 2,    1,  6, 8, 0x2a, 0x86, 0x48,
                                        0xce, 0x3d, 3,    1,  7, 3, 66,   0};
  static const uint8_t p384_prefix[] = {0x30, 118,  0x30, 16,   6, 7,  0x2a, 0x86,
                                        0x48, 0xce, 0x3d, 2,    1, 6,  5,    0x2b,
                                        0x81, 4,    0,    0x22, 3, 98, 0};
  const int p384 = !strcmp(munit_parameters_get(params, "curve"), "p384");
  const size_t scalar_bytes = p384 ? 48 : 32;
  const size_t point_offset = p384 ? sizeof p384_prefix : sizeof p256_prefix;
  const size_t point_bytes = 1 + 2 * scalar_bytes, spki_bytes = point_offset + point_bytes;
  const TC_hash_algorithm hash = p384 ? TC_HASH_SHA384 : TC_HASH_SHA256;
  uint8_t spki[MAX_SPKI_BYTES], scalar[MAX_SCALAR_BYTES] = {0}, digest[MAX_SCALAR_BYTES] = {0};
  uint8_t signature[2 * MAX_SCALAR_BYTES + 8] = {0};
  memcpy(spki, p384 ? p384_prefix : p256_prefix, point_offset);
  TC_EC_workspace ec;
  TC_ECDSA_workspace verification;
  TC_X509_public_key key;
  scalar[scalar_bytes - 1] = 1;
  TC_work_budget work = {UINT32_MAX};
  munit_assert_int(TC_EC_public_key(p384 ? TC_EC_P384 : TC_EC_P256,
                                    (TC_bytes){scalar, scalar_bytes},
                                    (TC_buffer){spki + point_offset, point_bytes}, &ec, &work),
                   ==, TC_EC_OK);
  munit_assert_int(TC_X509_subject_public_key((TC_bytes){spki, spki_bytes}, &key), ==, TC_TLV_OK);
  /* For d=k=1 and z=0, ECDSA has r=s=G.x. DER keeps these integers positive. */
  const size_t padding = (spki[point_offset + 1] & 0x80) ? 1 : 0;
  const size_t component_bytes = scalar_bytes + padding, signature_bytes = 6 + 2 * component_bytes;
  signature[0] = 0x30;
  signature[1] = (uint8_t)(signature_bytes - 2);
  signature[2] = 2;
  signature[3] = (uint8_t)component_bytes;
  memcpy(signature + 4 + padding, spki + point_offset + 1, scalar_bytes);
  signature[component_bytes + 4] = 2;
  signature[component_bytes + 5] = (uint8_t)component_bytes;
  memcpy(signature + component_bytes + 6, signature + 4, component_bytes);
  const TC_signature_algorithm algorithm = {TC_SIGNATURE_ECDSA, hash, hash, 0};
  const TC_X509_native_workspace workspace = {&verification, NULL,
                                              TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  const TC_X509_signature_provider provider = TC_X509_native_provider(&workspace);
  for (unsigned variant = 0; variant < 3; ++variant) {
    size_t work = variant == 2 ? 0 : WORK_LIMIT;
    digest[0] = variant == 1 ? 1 : 0;
    munit_assert_int(TC_X509_signature_verify_digest((TC_bytes){digest, scalar_bytes}, &algorithm,
                                                     (TC_bytes){signature, signature_bytes}, &key,
                                                     &provider, &work),
                     ==,
                     variant == 2   ? TC_X509_SIGNATURE_LIMIT
                     : variant == 1 ? TC_X509_SIGNATURE_INVALID
                                    : TC_X509_SIGNATURE_VALID);
  }
  (void)context;
  return MUNIT_OK;
}

static MunitResult rsa_signature(const MunitParameter params[], void* context)
{
  enum { MAX_BITS = 3072, MAX_SIGNATURE = MAX_BITS / 8, MAX_SPKI = 512, WORK_LIMIT = 100000 };
  uint8_t spki[MAX_SPKI], signature[MAX_SIGNATURE], digest[TC_SHA256_DIGESTLEN];
  TC_RSA_word words[TC_RSA_VERIFY_WORKSPACE_WORDS(MAX_BITS)];
  const TC_RSA_workspace rsa = {words, sizeof words / sizeof *words};
  const TC_X509_native_workspace workspace = {NULL, &rsa, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  const TC_X509_signature_provider provider = TC_X509_native_provider(&workspace);
  const int pss = !strcmp(munit_parameters_get(params, "scheme"), "pss");
  const TC_signature_algorithm algorithm = {pss ? TC_SIGNATURE_RSA_PSS : TC_SIGNATURE_RSA_V15,
                                            TC_HASH_SHA256, TC_HASH_SHA256, TC_SHA256_DIGESTLEN};
  for (size_t i = 0; i < sizeof rsa_vectors / sizeof *rsa_vectors; ++i) {
#if !TC_RSA_ENABLE_1024
    if (rsa_vectors[i].bits == 1024)
      continue;
#endif
    TC_X509_public_key key;
    size_t spki_length = tc_test_hex(rsa_vectors[i].spki, spki, sizeof spki);
    size_t signature_length =
        tc_test_hex(pss ? rsa_vectors[i].pss : rsa_vectors[i].v15, signature, sizeof signature);
    munit_assert_size(spki_length, >, 0);
    munit_assert_size(signature_length, ==, rsa_vectors[i].bits / 8);
    munit_assert_size(tc_test_hex(rsa_digest, digest, sizeof digest), ==, sizeof digest);
    munit_assert_int(TC_X509_subject_public_key((TC_bytes){spki, spki_length}, &key), ==,
                     TC_TLV_OK);
    munit_assert_uint(key.bits, ==, rsa_vectors[i].bits);
    for (unsigned variant = 0; variant < 3; ++variant) {
      size_t work = variant == 2 ? 0 : WORK_LIMIT;
      if (variant == 1)
        digest[0] ^= 1;
      munit_assert_int(TC_X509_signature_verify_digest(
                           (TC_bytes){digest, sizeof digest}, &algorithm,
                           (TC_bytes){signature, signature_length}, &key, &provider, &work),
                       ==,
                       variant == 2   ? TC_X509_SIGNATURE_LIMIT
                       : variant == 1 ? TC_X509_SIGNATURE_INVALID
                                      : TC_X509_SIGNATURE_VALID);
      if (variant == 1)
        digest[0] ^= 1;
    }
  }
  (void)context;
  return MUNIT_OK;
}
#endif

int main(int argc, char** argv)
{
#if EXPECT_PIV_FAMILY
  static char* curves[] = {"p256", "p384", NULL};
  static MunitParameterEnum curve_params[] = {{"curve", curves}, {NULL, NULL}};
  static char* schemes[] = {"v15", "pss", NULL};
  static MunitParameterEnum rsa_params[] = {{"scheme", schemes}, {NULL, NULL}};
#endif
  MunitTest tests[] = {
#if TC_ENABLE_AES && TC_AES_ENABLE_CBC
      {"/aes128-cbc", aes128_cbc, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
#if TC_ENABLE_DES && TC_DES_ENABLE_ECB && TC_DES_ENABLE_CBC && TC_DES_ENABLE_TDES
      {"/des-key-lengths", des_key_lengths, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
#if TC_ENABLE_SHA1
      {"/sha1-hash", sha1_hash, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
#if EXPECT_PIV_FAMILY
      {"/gzip", gzip_member, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/native-signature", native_signature, NULL, NULL, MUNIT_TEST_OPTION_NONE, curve_params},
      {"/rsa-signature", rsa_signature, NULL, NULL, MUNIT_TEST_OPTION_NONE, rsa_params},
#endif
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/target", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
