/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Mistial Dev
 *
 * Unit tests for tiny-crypto-c using munit: https://nemequ.github.io/munit/
 */

#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#include <tiny_crypto/aes.h>
#include "cavp.h"
#include "munit.h"
#include "test_vectors.h"
#if defined(TC_AES_ENABLE_GCM) && (TC_AES_ENABLE_GCM == 1)
#include "gcm_test_vectors.h"
#endif

#if TC_AES_KEY_BITS == 256
#define TEST_KEY aes256_key
#define TEST_ECB_CIPHERTEXT aes256_ecb_ciphertext
#define TEST_CBC_CIPHERTEXT aes256_cbc_ciphertext
#define TEST_CTR_CIPHERTEXT aes256_ctr_ciphertext
#define TEST_OFB_CIPHERTEXT aes256_ofb_ciphertext
#elif TC_AES_KEY_BITS == 192
#define TEST_KEY aes192_key
#define TEST_ECB_CIPHERTEXT aes192_ecb_ciphertext
#define TEST_CBC_CIPHERTEXT aes192_cbc_ciphertext
#define TEST_CTR_CIPHERTEXT aes192_ctr_ciphertext
#define TEST_OFB_CIPHERTEXT aes192_ofb_ciphertext
#else
#define TEST_KEY aes128_key
#define TEST_ECB_CIPHERTEXT aes128_ecb_ciphertext
#define TEST_CBC_CIPHERTEXT aes128_cbc_ciphertext
#define TEST_CTR_CIPHERTEXT aes128_ctr_ciphertext
#define TEST_OFB_CIPHERTEXT aes128_ofb_ciphertext
#endif

#ifndef CAVP_VECTOR_DIR
#define CAVP_VECTOR_DIR "tests/vectors/aes/cavp"
#endif

#if TC_AES_SBOX_MODE == TC_AES_SBOX_MODE_RUNTIME
static void test_initialize_sbox(void)
{
  TC_AES_init_sbox();
}
#else
static void test_initialize_sbox(void)
{
}
#endif

#if defined(TC_AES_CAVP) && (TC_AES_CAVP == 1)
MunitResult test_cavp(const MunitParameter params[], void* data);
#endif
#if defined(TC_AES_ENABLE_EAX) && (TC_AES_ENABLE_EAX == 1)
MunitResult test_eax(const MunitParameter params[], void* data);
#endif
#if defined(TC_AES_ENABLE_EAX_PRIME) && (TC_AES_ENABLE_EAX_PRIME == 1)
MunitResult test_eax_prime(const MunitParameter params[], void* data);
#endif
#if defined(TC_AES_ENABLE_SIV) && (TC_AES_ENABLE_SIV == 1)
MunitResult test_siv(const MunitParameter params[], void* data);
#endif
#if defined(TC_AES_ENABLE_CMAC) && (TC_AES_ENABLE_CMAC == 1)
MunitResult test_cmac(const MunitParameter params[], void* data);
#endif

static MunitResult test_key_schedule(const MunitParameter params[], void* data)
{
  static const char expected[] =
#if TC_AES_KEY_BITS == 128
    "2b7e151628aed2a6abf7158809cf4f3c"
    "a0fafe1788542cb123a339392a6c7605"
    "f2c295f27a96b9435935807a7359f67f"
    "3d80477d4716fe3e1e237e446d7a883b"
    "ef44a541a8525b7fb671253bdb0bad00"
    "d4d1c6f87c839d87caf2b8bc11f915bc"
    "6d88a37a110b3efddbf98641ca0093fd"
    "4e54f70e5f5fc9f384a64fb24ea6dc4f"
    "ead27321b58dbad2312bf5607f8d292f"
    "ac7766f319fadc2128d12941575c006e"
    "d014f9a8c9ee2589e13f0cc8b6630ca6";
#elif TC_AES_KEY_BITS == 192
    "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
    "fe0c91f72402f5a5ec12068e6c827f6b0e7a95b95c56fec2"
    "4db7b4bd69b5411885a74796e92538fde75fad44bb095386"
    "485af05721efb14fa448f6d94d6dce24aa326360113b30e6"
    "a25e7ed583b1cf9a27f939436a94f767c0a69407d19da4e1"
    "ec1786eb6fa64971485f703222cb8755e26d135233f0b7b3"
    "40beeb282f18a2596747d26b458c553ea7e1466c9411f1df"
    "821f750aad07d753ca4005388fcc5006282d166abc3ce7b5"
    "e98ba06f448c773c8ecc720401002202";
#else
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    "9ba354118e6925afa51a8b5f2067fcdea8b09c1a93d194cdbe49846eb75d5b9a"
    "d59aecb85bf3c917fee94248de8ebe96b5a9328a2678a647983122292f6c79b3"
    "812c81addadf48ba24360af2fab8b46498c5bfc9bebd198e268c3ba709e04214"
    "68007bacb2df331696e939e46c518d80c814e20476a9fb8a5025c02d59c58239"
    "de1369676ccc5a71fa2563959674ee155886ca5d2e2f31d77e0af1fa27cf73c3"
    "749c47ab18501ddae2757e4f7401905acafaaae3e4d59b349adf6acebd10190d"
    "fe4890d1e6188d0b046df344706c631e";
#endif
  struct TC_AES_key_ctx ctx;
  size_t i;

  (void) params;
  (void) data;
  test_initialize_sbox();
  munit_assert_size(sizeof(expected) - 1u, ==, 2u * TC_AES_KEY_EXP_SIZE);
  munit_assert_int(TC_AES_key_init(&ctx, TEST_KEY), ==, TC_OK);
  for (i = 0; i < TC_AES_KEY_EXP_SIZE; ++i)
  {
    const uint8_t value = (uint8_t)((tc_cavp_hex_nibble(expected[2u * i]) << 4) |
                                    tc_cavp_hex_nibble(expected[2u * i + 1u]));
    munit_assert_uint8(ctx.round_key[i], ==, value);
  }
  return MUNIT_OK;
}

static MunitResult test_secure_zero_and_clear(const MunitParameter params[],
                                              void* data)
{
  struct TC_AES_ctx ctx;
  uint8_t buffer[32];
  size_t i;

  (void) params;
  (void) data;

  test_initialize_sbox();
  for (i = 0; i < sizeof(buffer); ++i)
    buffer[i] = (uint8_t)(0xa5u ^ (uint8_t)i);
  TC_secure_zero(buffer, sizeof(buffer));
  for (i = 0; i < sizeof(buffer); ++i)
    munit_assert_uint8(buffer[i], ==, 0);

  TC_AES_init_ctx(&ctx, TEST_KEY);
  TC_AES_ctx_clear(&ctx);
  for (i = 0; i < sizeof(ctx); ++i)
    munit_assert_uint8(((const uint8_t*)&ctx)[i], ==, 0);

  return MUNIT_OK;
}

#if defined(TC_AES_ENABLE_GCM) && (TC_AES_ENABLE_GCM == 1)
#if TC_AES_KEY_BITS == 256
#define TEST_GCM_VECTOR gcm_test_vectors[2]
#elif TC_AES_KEY_BITS == 192
#define TEST_GCM_VECTOR gcm_test_vectors[1]
#else
#define TEST_GCM_VECTOR gcm_test_vectors[0]
#endif
#endif

#if defined(TC_AES_ENABLE_ECB) && (TC_AES_ENABLE_ECB == 1)
static MunitResult test_ecb(const MunitParameter params[], void* data)
{
  struct TC_AES_ctx ctx;
  uint8_t buffer[TC_AES_BLOCKLEN];

  (void) params;
  (void) data;

  test_initialize_sbox();
  TC_AES_init_ctx(&ctx, TEST_KEY);
  memcpy(buffer, nist_plaintext, TC_AES_BLOCKLEN);
  munit_assert_int(TC_AES_ECB_encrypt(&ctx.key, buffer), ==, TC_OK);
  munit_assert_memory_equal(TC_AES_BLOCKLEN, buffer, TEST_ECB_CIPHERTEXT);

  munit_assert_int(TC_AES_ECB_decrypt(&ctx.key, buffer), ==, TC_OK);
  munit_assert_memory_equal(TC_AES_BLOCKLEN, buffer, nist_plaintext);

  return MUNIT_OK;
}
#endif

#if defined(TC_AES_ENABLE_CBC) && (TC_AES_ENABLE_CBC == 1)
static MunitResult test_cbc(const MunitParameter params[], void* data)
{
  struct TC_AES_ctx ctx;
  uint8_t buffer[sizeof(nist_plaintext)];

  (void) params;
  (void) data;

  test_initialize_sbox();
  TC_AES_init_ctx_iv(&ctx, TEST_KEY, nist_iv);
  memcpy(buffer, nist_plaintext, sizeof(buffer));
  munit_assert_int(TC_AES_CBC_encrypt(&ctx, buffer, sizeof(buffer)), ==, TC_OK);
  munit_assert_memory_equal(sizeof(buffer), buffer, TEST_CBC_CIPHERTEXT);

  TC_AES_ctx_set_iv(&ctx, nist_iv);
  munit_assert_int(TC_AES_CBC_decrypt(&ctx, buffer, sizeof(buffer)), ==, TC_OK);
  munit_assert_memory_equal(sizeof(buffer), buffer, nist_plaintext);

  return MUNIT_OK;
}

static MunitResult test_cbc_alignment(const MunitParameter params[], void* data)
{
  struct TC_AES_ctx ctx;
  uint8_t buffer[TC_AES_BLOCKLEN + 1];

  (void) params;
  (void) data;

  test_initialize_sbox();
  TC_AES_init_ctx_iv(&ctx, TEST_KEY, nist_iv);
  memset(buffer, 0x5a, sizeof(buffer));
  munit_assert_int(TC_AES_CBC_encrypt(&ctx, buffer, TC_AES_BLOCKLEN + 1), ==, TC_ERROR);
  munit_assert_int(TC_AES_CBC_decrypt(&ctx, buffer, 1), ==, TC_ERROR);
  munit_assert_int(TC_AES_CBC_encrypt(&ctx, buffer, 0), ==, TC_OK);

  return MUNIT_OK;
}
#endif

#if defined(TC_AES_ENABLE_CTR) && (TC_AES_ENABLE_CTR == 1)
static MunitResult test_ctr(const MunitParameter params[], void* data)
{
  struct TC_AES_ctx ctx;
  uint8_t buffer[sizeof(nist_plaintext)];

  (void) params;
  (void) data;

  test_initialize_sbox();
  TC_AES_init_ctx_iv(&ctx, TEST_KEY, nist_ctr_iv);
  memcpy(buffer, nist_plaintext, sizeof(buffer));
  munit_assert_int(TC_AES_CTR_crypt(&ctx, buffer, sizeof(buffer)), ==, TC_OK);
  munit_assert_memory_equal(sizeof(buffer), buffer, TEST_CTR_CIPHERTEXT);

  TC_AES_ctx_set_iv(&ctx, nist_ctr_iv);
  munit_assert_int(TC_AES_CTR_crypt(&ctx, buffer, sizeof(buffer)), ==, TC_OK);
  munit_assert_memory_equal(sizeof(buffer), buffer, nist_plaintext);

  return MUNIT_OK;
}

static MunitResult test_ctr_unaligned(const MunitParameter params[], void* data)
{
  struct TC_AES_ctx ctx;
  uint8_t storage[sizeof(nist_plaintext) + 1];
  uint8_t* buffer = storage + 1;

  (void) params;
  (void) data;

  test_initialize_sbox();
  TC_AES_init_ctx_iv(&ctx, TEST_KEY, nist_ctr_iv);
  memcpy(buffer, nist_plaintext, sizeof(nist_plaintext));
  munit_assert_int(TC_AES_CTR_crypt(&ctx, buffer, 5), ==, TC_OK);
  munit_assert_int(TC_AES_CTR_crypt(&ctx, buffer + 5,
                                   sizeof(nist_plaintext) - 5), ==, TC_OK);
  munit_assert_memory_equal(sizeof(nist_plaintext), buffer,
                            TEST_CTR_CIPHERTEXT);

  TC_AES_ctx_set_iv(&ctx, nist_ctr_iv);
  munit_assert_int(TC_AES_CTR_crypt(&ctx, buffer, 7), ==, TC_OK);
  munit_assert_int(TC_AES_CTR_crypt(&ctx, buffer + 7,
                                   sizeof(nist_plaintext) - 7), ==, TC_OK);
  munit_assert_memory_equal(sizeof(nist_plaintext), buffer, nist_plaintext);

  return MUNIT_OK;
}

static MunitResult test_ctr_wrap(const MunitParameter params[], void* data)
{
  struct TC_AES_ctx ctx;
  uint8_t iv[TC_AES_BLOCKLEN];
  uint8_t saved_iv[TC_AES_BLOCKLEN];
  uint8_t buffer[TC_AES_BLOCKLEN * 2];
  uint8_t saved_buffer[TC_AES_BLOCKLEN * 2];
  uint8_t i;

  (void) params;
  (void) data;

  test_initialize_sbox();
  memset(iv, 0xff, sizeof(iv));
  memset(buffer, 0x11, sizeof(buffer));
  memcpy(saved_buffer, buffer, sizeof(buffer));
  TC_AES_init_ctx_iv(&ctx, TEST_KEY, iv);
  memcpy(saved_iv, ctx.iv, sizeof(saved_iv));

  /* Two blocks from an all-0xff counter would wrap past 2^128. */
  munit_assert_int(TC_AES_CTR_crypt(&ctx, buffer, sizeof(buffer)), ==, TC_ERROR);
  munit_assert_memory_equal(sizeof(buffer), buffer, saved_buffer);
  munit_assert_memory_equal(sizeof(saved_iv), ctx.iv, saved_iv);

  /* A single block at max counter is allowed; IV then wraps to zero. */
  munit_assert_int(TC_AES_CTR_crypt(&ctx, buffer, TC_AES_BLOCKLEN), ==, TC_OK);
  for (i = 0; i < TC_AES_BLOCKLEN; ++i)
    munit_assert_uint8(ctx.iv[i], ==, 0);

  return MUNIT_OK;
}
#endif

#if defined(TC_AES_ENABLE_OFB) && (TC_AES_ENABLE_OFB == 1)
static MunitResult test_ofb(const MunitParameter params[], void* data)
{
  static const size_t encrypt_chunks[] = { 1, 15, 17, 31 };
  static const size_t decrypt_chunks[] = { 7, 9, 16, 32 };
  struct TC_AES_ctx ctx;
  uint8_t buffer[sizeof(nist_plaintext)];
  uint8_t storage[sizeof(nist_plaintext) + 1];
  uint8_t* unaligned = storage + 1;
  size_t offset;
  size_t i;

  (void) params;
  (void) data;

  test_initialize_sbox();

  TC_AES_init_ctx_iv(&ctx, TEST_KEY, nist_iv);
  memcpy(buffer, nist_plaintext, sizeof(buffer));
  munit_assert_int(TC_AES_OFB_crypt(&ctx, buffer, 0), ==, TC_OK);
  munit_assert_memory_equal(sizeof(buffer), buffer, nist_plaintext);
  munit_assert_int(TC_AES_OFB_crypt(&ctx, buffer, sizeof(buffer)), ==, TC_OK);
  munit_assert_memory_equal(sizeof(buffer), buffer, TEST_OFB_CIPHERTEXT);

  TC_AES_ctx_set_iv(&ctx, nist_iv);
  munit_assert_int(TC_AES_OFB_crypt(&ctx, buffer, sizeof(buffer)), ==, TC_OK);
  munit_assert_memory_equal(sizeof(buffer), buffer, nist_plaintext);

  TC_AES_ctx_set_iv(&ctx, nist_iv);
  memcpy(buffer, nist_plaintext, sizeof(buffer));
  offset = 0;
  for (i = 0; i < sizeof(encrypt_chunks) / sizeof(encrypt_chunks[0]); ++i)
  {
    munit_assert_int(TC_AES_OFB_crypt(&ctx, buffer + offset, encrypt_chunks[i]),
                     ==, TC_OK);
    offset += encrypt_chunks[i];
  }
  munit_assert_memory_equal(sizeof(buffer), buffer, TEST_OFB_CIPHERTEXT);

  TC_AES_ctx_set_iv(&ctx, nist_iv);
  offset = 0;
  for (i = 0; i < sizeof(decrypt_chunks) / sizeof(decrypt_chunks[0]); ++i)
  {
    munit_assert_int(TC_AES_OFB_crypt(&ctx, buffer + offset, decrypt_chunks[i]),
                     ==, TC_OK);
    offset += decrypt_chunks[i];
  }
  munit_assert_memory_equal(sizeof(buffer), buffer, nist_plaintext);

  TC_AES_ctx_set_iv(&ctx, nist_iv);
  memcpy(unaligned, nist_plaintext, sizeof(nist_plaintext));
  munit_assert_int(TC_AES_OFB_crypt(&ctx, unaligned, 37), ==, TC_OK);
  munit_assert_memory_equal(37, unaligned, TEST_OFB_CIPHERTEXT);

  TC_AES_ctx_set_iv(&ctx, nist_iv);
  munit_assert_int(TC_AES_OFB_crypt(&ctx, unaligned, 37), ==, TC_OK);
  munit_assert_memory_equal(37, unaligned, nist_plaintext);

  return MUNIT_OK;
}
#endif

#if defined(TC_AES_ENABLE_CCM) && (TC_AES_ENABLE_CCM == 1)
#if TC_AES_KEY_BITS == 128
static void test_ccm_vector(const uint8_t* key, const uint8_t* nonce,
                            size_t nonce_len, const uint8_t* aad,
                            size_t aad_len, const uint8_t* plaintext,
                            size_t plaintext_len, const uint8_t* ciphertext,
                            const uint8_t* tag, size_t tag_len)
{
  uint8_t buffer[64] = { 0 };
  uint8_t output[64] = { 0 };
  uint8_t generated_tag[16] = { 0 };

  memcpy(buffer, plaintext, plaintext_len);
  munit_assert_int(TC_AES_CCM_encrypt(key, nonce, nonce_len, aad, aad_len,
                                   buffer, plaintext_len, output,
                                   generated_tag, tag_len), ==,
                   TC_OK);
  munit_assert_memory_equal(plaintext_len, output, ciphertext);
  munit_assert_memory_equal(tag_len, generated_tag, tag);

  memset(buffer, 0, sizeof(buffer));
  munit_assert_int(TC_AES_CCM_decrypt(key, nonce, nonce_len, aad, aad_len,
                                   output, plaintext_len, tag, tag_len,
                                   buffer), ==, TC_OK);
  munit_assert_memory_equal(plaintext_len, buffer, plaintext);

  generated_tag[0] ^= 1;
  memset(buffer, 0xa5, sizeof(buffer));
  munit_assert_int(TC_AES_CCM_decrypt(key, nonce, nonce_len, aad, aad_len,
                                   output, plaintext_len, generated_tag,
                                   tag_len, buffer), ==, TC_MISMATCH);
  for (size_t i = 0; i < sizeof(buffer); ++i)
    munit_assert_uint8(buffer[i], ==, 0xa5);
}

static MunitResult test_ccm(const MunitParameter params[], void* data)
{
  static uint8_t nist_aad4[65536];
  size_t i;

  (void) params;
  (void) data;

  test_initialize_sbox();
  for (i = 0; i < sizeof(nist_aad4); ++i)
    nist_aad4[i] = (uint8_t)i;
  test_ccm_vector(ccm_nist_key, ccm_nist_nonce1, sizeof(ccm_nist_nonce1),
                  ccm_nist_aad1, sizeof(ccm_nist_aad1), ccm_nist_plaintext1,
                  sizeof(ccm_nist_plaintext1), ccm_nist_ciphertext1,
                  ccm_nist_tag1, sizeof(ccm_nist_tag1));
  test_ccm_vector(ccm_nist_key, ccm_nist_nonce2, sizeof(ccm_nist_nonce2),
                  ccm_nist_aad2, sizeof(ccm_nist_aad2), ccm_nist_plaintext2,
                  sizeof(ccm_nist_plaintext2), ccm_nist_ciphertext2,
                  ccm_nist_tag2, sizeof(ccm_nist_tag2));
  test_ccm_vector(ccm_nist_key, ccm_nist_nonce4, sizeof(ccm_nist_nonce4),
                  nist_aad4, sizeof(nist_aad4), ccm_nist_plaintext4,
                  sizeof(ccm_nist_plaintext4), ccm_nist_ciphertext4,
                  ccm_nist_tag4, sizeof(ccm_nist_tag4));
  test_ccm_vector(ccm_rfc_key, ccm_rfc_nonce, sizeof(ccm_rfc_nonce),
                  ccm_rfc_aad, sizeof(ccm_rfc_aad), ccm_rfc_plaintext,
                  sizeof(ccm_rfc_plaintext), ccm_rfc_ciphertext, ccm_rfc_tag,
                  sizeof(ccm_rfc_tag));
  return MUNIT_OK;
}

static MunitResult test_ccm_api(const MunitParameter params[], void* data)
{
  static uint8_t large_aad[65280];
  static uint8_t max_plaintext[65535];
  static uint8_t max_ciphertext[65535];
  static uint8_t max_plaintext_copy[65535];
  static const uint8_t nonce13[13] = { 0 };
  uint8_t buffer[64] = { 0 };
  uint8_t ciphertext[64] = { 0 };
  uint8_t tag[16] = { 0 };
  uint8_t bad_aad[sizeof(ccm_nist_aad1)];
  uint8_t bad_nonce[sizeof(ccm_nist_nonce1)];
  uint8_t bad_tag[sizeof(ccm_nist_tag1)];
  uint8_t one = 0;
  size_t i;

  (void) params;
  (void) data;

  test_initialize_sbox();
  memcpy(bad_aad, ccm_nist_aad1, sizeof(bad_aad));
  memcpy(bad_nonce, ccm_nist_nonce1, sizeof(bad_nonce));
  memcpy(bad_tag, ccm_nist_tag1, sizeof(bad_tag));

  munit_assert_int(TC_AES_CCM_encrypt(ccm_nist_key, ccm_nist_nonce1, 6,
                                   ccm_nist_aad1, sizeof(ccm_nist_aad1),
                                   ccm_nist_plaintext1,
                                   sizeof(ccm_nist_plaintext1), ciphertext,
                                   tag, sizeof(ccm_nist_tag1)), ==, TC_ERROR);
  munit_assert_int(TC_AES_CCM_encrypt(ccm_nist_key, ccm_nist_nonce1, 14,
                                   ccm_nist_aad1, sizeof(ccm_nist_aad1),
                                   ccm_nist_plaintext1,
                                   sizeof(ccm_nist_plaintext1), ciphertext,
                                   tag, sizeof(ccm_nist_tag1)), ==, TC_ERROR);
  for (i = 0; i <= 18; ++i)
  {
    if (i == 4 || i == 6 || i == 8 || i == 10 || i == 12 || i == 14 || i == 16)
      continue;
    munit_assert_int(TC_AES_CCM_encrypt(ccm_nist_key, ccm_nist_nonce1,
                                     sizeof(ccm_nist_nonce1), ccm_nist_aad1,
                                     sizeof(ccm_nist_aad1), ccm_nist_plaintext1,
                                     sizeof(ccm_nist_plaintext1), ciphertext,
                                     tag, i), ==, TC_ERROR);
  }

  munit_assert_int(TC_AES_CCM_encrypt(NULL, ccm_nist_nonce1,
                                   sizeof(ccm_nist_nonce1), NULL, 0, NULL, 0,
                                   NULL, tag, sizeof(tag)), ==, TC_ERROR);
  munit_assert_int(TC_AES_CCM_encrypt(ccm_nist_key, NULL,
                                   sizeof(ccm_nist_nonce1), NULL, 0, NULL, 0,
                                   NULL, tag, sizeof(tag)), ==, TC_ERROR);
  munit_assert_int(TC_AES_CCM_encrypt(ccm_nist_key, ccm_nist_nonce1,
                                   sizeof(ccm_nist_nonce1), ccm_nist_aad1, 1,
                                   NULL, 0, NULL, tag, sizeof(tag)), ==, TC_OK);
  munit_assert_int(TC_AES_CCM_encrypt(ccm_nist_key, ccm_nist_nonce1,
                                   sizeof(ccm_nist_nonce1), NULL, 1, NULL, 0,
                                   NULL, tag, sizeof(tag)), ==, TC_ERROR);
  munit_assert_int(TC_AES_CCM_encrypt(ccm_nist_key, ccm_nist_nonce1,
                                   sizeof(ccm_nist_nonce1), NULL, 0, &one, 1,
                                   NULL, tag, sizeof(tag)), ==, TC_ERROR);
  munit_assert_int(TC_AES_CCM_encrypt(ccm_nist_key, ccm_nist_nonce1,
                                   sizeof(ccm_nist_nonce1), NULL, 0, &one, 1,
                                   ciphertext, NULL, sizeof(tag)), ==, TC_ERROR);

  memcpy(buffer, ccm_nist_plaintext1, sizeof(ccm_nist_plaintext1));
  munit_assert_int(TC_AES_CCM_encrypt(ccm_nist_key, ccm_nist_nonce1,
                                   sizeof(ccm_nist_nonce1), ccm_nist_aad1,
                                   sizeof(ccm_nist_aad1), buffer,
                                   sizeof(ccm_nist_plaintext1), buffer, tag,
                                   sizeof(ccm_nist_tag1)), ==, TC_OK);
  munit_assert_memory_equal(sizeof(ccm_nist_ciphertext1), buffer,
                            ccm_nist_ciphertext1);
  munit_assert_memory_equal(sizeof(ccm_nist_tag1), tag, ccm_nist_tag1);
  munit_assert_int(TC_AES_CCM_decrypt(ccm_nist_key, ccm_nist_nonce1,
                                   sizeof(ccm_nist_nonce1), ccm_nist_aad1,
                                   sizeof(ccm_nist_aad1), buffer,
                                   sizeof(ccm_nist_plaintext1), tag,
                                   sizeof(ccm_nist_tag1), buffer), ==,
                   TC_OK);
  munit_assert_memory_equal(sizeof(ccm_nist_plaintext1), buffer,
                            ccm_nist_plaintext1);

  memcpy(ciphertext, ccm_nist_ciphertext1, sizeof(ccm_nist_ciphertext1));
  ciphertext[0] ^= 1;
  memset(buffer, 0xa5, sizeof(buffer));
  munit_assert_int(TC_AES_CCM_decrypt(ccm_nist_key, ccm_nist_nonce1,
                                   sizeof(ccm_nist_nonce1), ccm_nist_aad1,
                                   sizeof(ccm_nist_aad1), ciphertext,
                                   sizeof(ccm_nist_ciphertext1),
                                   ccm_nist_tag1, sizeof(ccm_nist_tag1),
                                   buffer), ==, TC_MISMATCH);
  for (i = 0; i < sizeof(buffer); ++i)
    munit_assert_uint8(buffer[i], ==, 0xa5);

  bad_tag[0] ^= 1;
  memset(buffer, 0xa5, sizeof(buffer));
  munit_assert_int(TC_AES_CCM_decrypt(ccm_nist_key, ccm_nist_nonce1,
                                   sizeof(ccm_nist_nonce1), ccm_nist_aad1,
                                   sizeof(ccm_nist_aad1),
                                   ccm_nist_ciphertext1,
                                   sizeof(ccm_nist_ciphertext1), bad_tag,
                                   sizeof(bad_tag), buffer), ==, TC_MISMATCH);
  bad_aad[0] ^= 1;
  munit_assert_int(TC_AES_CCM_decrypt(ccm_nist_key, ccm_nist_nonce1,
                                   sizeof(ccm_nist_nonce1), bad_aad,
                                   sizeof(bad_aad), ccm_nist_ciphertext1,
                                   sizeof(ccm_nist_ciphertext1), ccm_nist_tag1,
                                   sizeof(ccm_nist_tag1), buffer), ==,
                   TC_MISMATCH);
  bad_nonce[0] ^= 1;
  munit_assert_int(TC_AES_CCM_decrypt(ccm_nist_key, bad_nonce, sizeof(bad_nonce),
                                   ccm_nist_aad1, sizeof(ccm_nist_aad1),
                                   ccm_nist_ciphertext1,
                                   sizeof(ccm_nist_ciphertext1), ccm_nist_tag1,
                                   sizeof(ccm_nist_tag1), buffer), ==,
                   TC_MISMATCH);

  for (i = 0; i < sizeof(large_aad); ++i)
    large_aad[i] = (uint8_t)i;
  for (i = 0; i < 2; ++i)
  {
    const size_t aad_len = i == 0 ? 65279u : 65280u;
    munit_assert_int(TC_AES_CCM_encrypt(ccm_nist_key, ccm_nist_nonce1,
                                     sizeof(ccm_nist_nonce1), large_aad,
                                     aad_len, ccm_nist_plaintext1,
                                     sizeof(ccm_nist_plaintext1), ciphertext,
                                     tag, sizeof(ccm_nist_tag1)), ==,
                     TC_OK);
    munit_assert_int(TC_AES_CCM_decrypt(ccm_nist_key, ccm_nist_nonce1,
                                     sizeof(ccm_nist_nonce1), large_aad,
                                     aad_len, ciphertext,
                                     sizeof(ccm_nist_plaintext1), tag,
                                     sizeof(ccm_nist_tag1), buffer), ==,
                     TC_OK);
    munit_assert_memory_equal(sizeof(ccm_nist_plaintext1), buffer,
                              ccm_nist_plaintext1);
  }

  memset(max_plaintext, 0x5a, sizeof(max_plaintext));
  memcpy(max_plaintext_copy, max_plaintext, sizeof(max_plaintext));
  munit_assert_int(TC_AES_CCM_encrypt(ccm_nist_key, nonce13, sizeof(nonce13),
                                   NULL, 0, max_plaintext,
                                   sizeof(max_plaintext), max_ciphertext, tag,
                                   sizeof(ccm_nist_tag1)), ==, TC_OK);
  munit_assert_int(TC_AES_CCM_decrypt(ccm_nist_key, nonce13, sizeof(nonce13),
                                   NULL, 0, max_ciphertext,
                                   sizeof(max_ciphertext), tag,
                                   sizeof(ccm_nist_tag1), max_plaintext), ==,
                   TC_OK);
  munit_assert_memory_equal(sizeof(max_plaintext), max_plaintext,
                            max_plaintext_copy);
  munit_assert_int(TC_AES_CCM_encrypt(ccm_nist_key, nonce13, sizeof(nonce13),
                                   NULL, 0, &one, sizeof(max_plaintext) + 1,
                                   max_ciphertext, tag,
                                   sizeof(ccm_nist_tag1)), ==, TC_ERROR);
  for (i = 7; i <= 13; ++i)
  {
    const unsigned q = (unsigned)(15 - i);
    const uint64_t maximum = q == sizeof(uint64_t) ? UINT64_MAX :
                             ((UINT64_C(1) << (8u * q)) - 1u);
    if (maximum < (uint64_t)SIZE_MAX)
    {
      const size_t over = (size_t)(maximum + 1u);
      munit_assert_int(TC_AES_CCM_encrypt(ccm_nist_key, nonce13, i, NULL, 0,
                                       &one, over, ciphertext, tag,
                                       sizeof(ccm_nist_tag1)), ==,
                       TC_ERROR);
    }
  }

  return MUNIT_OK;
}

#endif

#endif

#if defined(TC_AES_ENABLE_GCM) && (TC_AES_ENABLE_GCM == 1)
static MunitResult test_gcm(const MunitParameter params[], void* data)
{
  const struct gcm_test_vector* vector = &TEST_GCM_VECTOR;
  struct TC_AES_GCM_ctx ctx;
  uint8_t buffer[16];
  uint8_t tag[16];
  uint8_t short_tag[4];
  uint8_t bad_tag[16];

  (void) params;
  (void) data;

  test_initialize_sbox();
  memcpy(buffer, vector->plaintext, vector->length);
  munit_assert_int(TC_AES_GCM_init(&ctx, vector->key, vector->iv, vector->iv_len,
                                vector->tag_len), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_aad_update(&ctx, vector->aad, 5), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_aad_update(&ctx, vector->aad + 5, vector->aad_len - 5), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_encrypt_update(&ctx, buffer, 3), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_encrypt_update(&ctx, buffer + 3, vector->length - 3), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_encrypt_finish(&ctx, tag), ==, TC_OK);
  munit_assert_memory_equal(vector->length, buffer, vector->ciphertext);
  munit_assert_memory_equal(vector->tag_len, tag, vector->tag);

  /* Fixed t=4 for this key/context; MSBt of the 128-bit tag. */
  munit_assert_int(TC_AES_GCM_init(&ctx, vector->key, vector->iv, vector->iv_len, 4),
                   ==, TC_OK);
  munit_assert_int(TC_AES_GCM_aad_update(&ctx, vector->aad, vector->aad_len), ==, TC_OK);
  memcpy(buffer, vector->plaintext, vector->length);
  munit_assert_int(TC_AES_GCM_encrypt_update(&ctx, buffer, vector->length), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_encrypt_finish(&ctx, short_tag), ==, TC_OK);
  munit_assert_memory_equal(sizeof(short_tag), short_tag, vector->tag);

  munit_assert_int(TC_AES_GCM_init(&ctx, vector->key, vector->iv, vector->iv_len,
                                vector->tag_len), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_aad_update(&ctx, vector->aad, vector->aad_len), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_decrypt_update(&ctx, buffer, vector->length), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_decrypt_finish(&ctx, tag), ==, TC_OK);
  munit_assert_memory_equal(vector->length, buffer, vector->plaintext);

  memcpy(buffer, vector->ciphertext, vector->length);
  memcpy(bad_tag, tag, sizeof(bad_tag));
  bad_tag[0] ^= 1;
  munit_assert_int(TC_AES_GCM_init(&ctx, vector->key, vector->iv, vector->iv_len,
                                vector->tag_len), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_aad_update(&ctx, vector->aad, vector->aad_len), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_decrypt_update(&ctx, buffer, vector->length), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_decrypt_finish(&ctx, bad_tag), ==, TC_MISMATCH);
  munit_assert_int(TC_AES_GCM_aad_update(&ctx, vector->aad, 1), ==, TC_ERROR);

  /* Reject invalid tag lengths at init (SP 800-38D). */
  munit_assert_int(TC_AES_GCM_init(&ctx, vector->key, vector->iv, vector->iv_len, 0),
                   ==, TC_ERROR);
  munit_assert_int(TC_AES_GCM_init(&ctx, vector->key, vector->iv, vector->iv_len, 5),
                   ==, TC_ERROR);
  munit_assert_int(TC_AES_GCM_init(&ctx, vector->key, vector->iv, vector->iv_len, 17),
                   ==, TC_ERROR);

  return MUNIT_OK;
}

static MunitResult test_gcm_direction(const MunitParameter params[], void* data)
{
  const struct gcm_test_vector* vector = &TEST_GCM_VECTOR;
  struct TC_AES_GCM_ctx ctx;
  uint8_t buffer[16];
  uint8_t before[16];
  uint8_t generated_tag[16];

  (void) params;
  (void) data;

  test_initialize_sbox();
  memcpy(buffer, vector->plaintext, vector->length);
  munit_assert_int(TC_AES_GCM_init(&ctx, vector->key, vector->iv, vector->iv_len,
                                vector->tag_len), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_encrypt_update(&ctx, buffer, 1), ==, TC_OK);
  memcpy(before, buffer, sizeof(before));
  munit_assert_int(TC_AES_GCM_decrypt_update(&ctx, buffer, 1), ==, TC_ERROR);
  munit_assert_int(TC_AES_GCM_decrypt_finish(&ctx, vector->tag), ==, TC_ERROR);
  munit_assert_int(TC_AES_GCM_encrypt_finish(&ctx, generated_tag), ==, TC_OK);
  munit_assert_memory_equal(sizeof(before), buffer, before);

  memcpy(buffer, vector->ciphertext, vector->length);
  munit_assert_int(TC_AES_GCM_init(&ctx, vector->key, vector->iv, vector->iv_len,
                                vector->tag_len), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_decrypt_update(&ctx, buffer, 1), ==, TC_OK);
  memcpy(before, buffer, sizeof(before));
  munit_assert_int(TC_AES_GCM_encrypt_update(&ctx, buffer, 1), ==, TC_ERROR);
  munit_assert_int(TC_AES_GCM_encrypt_finish(&ctx, generated_tag), ==, TC_ERROR);
  munit_assert_int(TC_AES_GCM_decrypt_finish(&ctx, vector->tag), ==, TC_MISMATCH);
  munit_assert_memory_equal(sizeof(before), buffer, before);

  memcpy(buffer, vector->ciphertext, vector->length);
  munit_assert_int(TC_AES_GCM_init(&ctx, vector->key, vector->iv, vector->iv_len,
                                vector->tag_len), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_aad_update(&ctx, vector->aad, vector->aad_len), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_decrypt_update(&ctx, buffer, vector->length), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_decrypt_finish(&ctx, (const uint8_t*)vector->tag),
                   ==, TC_OK);
  munit_assert_memory_equal(vector->length, buffer, vector->plaintext);

  return MUNIT_OK;
}

#if TC_AES_KEY_BITS == 128
static MunitResult test_gcm_non96_iv(const MunitParameter params[], void* data)
{
  const struct gcm_test_vector* vector = &gcm_non96_test_vector;
  struct TC_AES_GCM_ctx ctx;
  uint8_t buffer[16];
  uint8_t tag[16];

  (void) params;
  (void) data;

  test_initialize_sbox();
  memcpy(buffer, vector->plaintext, vector->length);
  munit_assert_int(TC_AES_GCM_init(&ctx, vector->key, vector->iv, vector->iv_len,
                                vector->tag_len), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_aad_update(&ctx, vector->aad, vector->aad_len), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_encrypt_update(&ctx, buffer, vector->length), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_encrypt_finish(&ctx, tag), ==, TC_OK);
  munit_assert_memory_equal(vector->length, buffer, vector->ciphertext);
  munit_assert_memory_equal(vector->tag_len, tag, vector->tag);

  return MUNIT_OK;
}
#endif

static MunitResult test_gcm_oneshot(const MunitParameter params[], void* data)
{
  const struct gcm_test_vector* vector = &TEST_GCM_VECTOR;
  uint8_t ciphertext[64];
  uint8_t plaintext[64];
  uint8_t tag[16];
  uint8_t bad_tag[16];
  uint8_t poison[64];
  uint8_t overlap[64];
  size_t i;

  (void) params;
  (void) data;

  test_initialize_sbox();
  munit_assert_size(vector->length, <=, sizeof(ciphertext));

  munit_assert_int(TC_AES_GCM_encrypt(vector->key, vector->iv, vector->iv_len,
                                   vector->aad, vector->aad_len,
                                   vector->plaintext, vector->length,
                                   ciphertext, tag, vector->tag_len), ==,
                   TC_OK);
  munit_assert_memory_equal(vector->length, ciphertext, vector->ciphertext);
  munit_assert_memory_equal(vector->tag_len, tag, vector->tag);

  memset(plaintext, 0xa5, sizeof(plaintext));
  munit_assert_int(TC_AES_GCM_decrypt(vector->key, vector->iv, vector->iv_len,
                                   vector->aad, vector->aad_len,
                                   ciphertext, vector->length, tag,
                                   vector->tag_len, plaintext), ==, TC_OK);
  munit_assert_memory_equal(vector->length, plaintext, vector->plaintext);

  /* Bad tag must not write plaintext (non-aliasing buffers). */
  memcpy(bad_tag, tag, vector->tag_len);
  bad_tag[0] ^= 1u;
  memset(poison, 0x3c, sizeof(poison));
  munit_assert_int(TC_AES_GCM_decrypt(vector->key, vector->iv, vector->iv_len,
                                   vector->aad, vector->aad_len,
                                   ciphertext, vector->length, bad_tag,
                                   vector->tag_len, poison), ==, TC_MISMATCH);
  for (i = 0; i < vector->length; ++i)
    munit_assert_uint8(poison[i], ==, 0x3c);

  /* In-place decrypt with bad tag zeros the shared buffer. */
  memcpy(ciphertext, vector->ciphertext, vector->length);
  munit_assert_int(TC_AES_GCM_decrypt(vector->key, vector->iv, vector->iv_len,
                                   vector->aad, vector->aad_len,
                                   ciphertext, vector->length, bad_tag,
                                   vector->tag_len, ciphertext), ==, TC_MISMATCH);
  for (i = 0; i < vector->length; ++i)
    munit_assert_uint8(ciphertext[i], ==, 0);

  /* Partial overlap is rejected before any write. */
  memcpy(overlap, vector->plaintext, vector->length);
  munit_assert_int(TC_AES_GCM_encrypt(vector->key, vector->iv, vector->iv_len,
                                   vector->aad, vector->aad_len,
                                   overlap, vector->length,
                                   overlap + 1, tag, vector->tag_len), ==,
                   TC_ERROR);
  munit_assert_memory_equal(vector->length, overlap, vector->plaintext);

  return MUNIT_OK;
}

#if TC_AES_KEY_BITS == 128
/* Two contexts, two keys: both must work independently (per-context state). */
static MunitResult test_gcm_multi_key(const MunitParameter params[], void* data)
{
  static const uint8_t key_b[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  };
  const struct gcm_test_vector* va = &TEST_GCM_VECTOR;
  struct TC_AES_GCM_ctx ctx_a;
  struct TC_AES_GCM_ctx ctx_b;
  uint8_t buf_a[32];
  uint8_t buf_b[32];
  uint8_t tag_a[16];
  uint8_t tag_b[16];
  uint8_t expect_b[32];

  (void) params;
  (void) data;

  test_initialize_sbox();
  munit_assert_size(va->length, <=, sizeof(buf_a));

  memcpy(buf_a, va->plaintext, va->length);
  munit_assert_int(TC_AES_GCM_init(&ctx_a, va->key, va->iv, va->iv_len,
                                va->tag_len), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_aad_update(&ctx_a, va->aad, va->aad_len), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_encrypt_update(&ctx_a, buf_a, va->length), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_encrypt_finish(&ctx_a, tag_a), ==, TC_OK);

  memcpy(buf_b, va->plaintext, va->length);
  munit_assert_int(TC_AES_GCM_init(&ctx_b, key_b, va->iv, va->iv_len,
                                va->tag_len), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_aad_update(&ctx_b, va->aad, va->aad_len), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_encrypt_update(&ctx_b, buf_b, va->length), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_encrypt_finish(&ctx_b, tag_b), ==, TC_OK);

  /* Different keys must not produce the same ciphertext/tag as the vector. */
  munit_assert_memory_equal(va->length, buf_a, va->ciphertext);
  munit_assert_memory_equal(va->tag_len, tag_a, va->tag);
  munit_assert_memory_not_equal(va->length, buf_b, va->ciphertext);

  /* Context A remains valid after B was initialized with another key. */
  memcpy(expect_b, buf_b, va->length);
  munit_assert_int(TC_AES_GCM_init(&ctx_a, va->key, va->iv, va->iv_len,
                                va->tag_len), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_aad_update(&ctx_a, va->aad, va->aad_len), ==, TC_OK);
  memcpy(buf_a, va->ciphertext, va->length);
  munit_assert_int(TC_AES_GCM_decrypt_update(&ctx_a, buf_a, va->length), ==, TC_OK);
  munit_assert_int(TC_AES_GCM_decrypt_finish(&ctx_a, tag_a), ==, TC_OK);
  munit_assert_memory_equal(va->length, buf_a, va->plaintext);
  munit_assert_memory_equal(va->length, buf_b, expect_b);

  TC_AES_GCM_clear(&ctx_a);
  TC_AES_GCM_clear(&ctx_b);
  return MUNIT_OK;
}
#endif
#endif

static MunitTest test_suite_tests[] = {
  /*
   * Mode suites that require TC_AES_init_sbox() (runtime profile) are listed
   * before /key-schedule. munit does not fork on Windows (MUNIT_NO_FORK), so
   * an earlier test that initializes the process-global S-box would mask a
   * missing TC_AES_init_sbox() in a later test. On Unix, each test is forked and
   * gets a fresh BSS, so the same bug fails there immediately.
   */
#if defined(TC_AES_ENABLE_SIV) && (TC_AES_ENABLE_SIV == 1)
  { "/siv", test_siv, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if defined(TC_AES_ENABLE_CMAC) && (TC_AES_ENABLE_CMAC == 1)
  { "/cmac", test_cmac, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if defined(TC_AES_ENABLE_EAX) && (TC_AES_ENABLE_EAX == 1)
  { "/eax", test_eax, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if defined(TC_AES_ENABLE_EAX_PRIME) && (TC_AES_ENABLE_EAX_PRIME == 1)
  { "/eax-prime", test_eax_prime, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
  { "/secure-zero-clear", test_secure_zero_and_clear, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/key-schedule", test_key_schedule, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#if defined(TC_AES_ENABLE_ECB) && (TC_AES_ENABLE_ECB == 1)
  { "/ecb", test_ecb, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if defined(TC_AES_ENABLE_CBC) && (TC_AES_ENABLE_CBC == 1)
  { "/cbc", test_cbc, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/cbc-alignment", test_cbc_alignment, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if defined(TC_AES_ENABLE_CTR) && (TC_AES_ENABLE_CTR == 1)
  { "/ctr", test_ctr, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/ctr-unaligned", test_ctr_unaligned, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/ctr-wrap", test_ctr_wrap, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if defined(TC_AES_ENABLE_OFB) && (TC_AES_ENABLE_OFB == 1)
  { "/ofb", test_ofb, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if defined(TC_AES_CAVP) && (TC_AES_CAVP == 1) && \
    ((defined(TC_AES_ENABLE_ECB) && (TC_AES_ENABLE_ECB == 1)) || (defined(TC_AES_ENABLE_CBC) && (TC_AES_ENABLE_CBC == 1)) || \
     (defined(TC_AES_ENABLE_OFB) && (TC_AES_ENABLE_OFB == 1)) || (defined(TC_AES_ENABLE_GCM) && (TC_AES_ENABLE_GCM == 1)) || \
     (defined(TC_AES_ENABLE_CCM) && (TC_AES_ENABLE_CCM == 1)))
  { "/cavp", test_cavp, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if defined(TC_AES_ENABLE_CCM) && (TC_AES_ENABLE_CCM == 1)
#if TC_AES_KEY_BITS == 128
  { "/ccm", test_ccm, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/ccm-api", test_ccm_api, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#endif
#if defined(TC_AES_ENABLE_GCM) && (TC_AES_ENABLE_GCM == 1)
  { "/gcm", test_gcm, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/gcm-direction", test_gcm_direction, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/gcm-oneshot", test_gcm_oneshot, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#if TC_AES_KEY_BITS == 128
  { "/gcm-non96-iv", test_gcm_non96_iv, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if TC_AES_KEY_BITS == 128
  { "/gcm-multi-key", test_gcm_multi_key, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#endif
  { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

static const MunitSuite test_suite = {
  "/tiny-aes-c",
  test_suite_tests,
  NULL,
  1,
  MUNIT_SUITE_OPTION_NONE
};

int main(int argc, char* argv[])
{
  return munit_suite_main(&test_suite, NULL, argc, argv);
}
