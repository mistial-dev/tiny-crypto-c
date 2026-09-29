/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Unit tests for tiny-crypto-c using µunit (munit)
 * https://nemequ.github.io/munit/
 */

#include <stdio.h>
#include <string.h>
#include "munit.h"
#include "test_util.h"
#include <tiny_crypto/des.h>
#include "test_vectors.h"

MunitResult test_edge_vectors_suite(const MunitParameter params[], void* data);

/* ========================================================================= */
/* Matrix 1: Single DES                                                      */
/* ========================================================================= */

/* 1A. Single DES ECB (KAT Encrypt, KAT Decrypt, & Round-Trip) */
#if TC_DES_ENABLE_ECB
static MunitResult test_des_ecb(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;

  struct TC_DES_ctx ctx;
  uint8_t buffer[8];

  TC_DES_init_ctx(&ctx, des_test_key, TC_DES_KEYLEN);

  /* KAT Encrypt */
  memcpy(buffer, des_test_pt, 8);
  TC_DES_ECB_encrypt(&ctx, buffer);
  munit_assert_memory_equal(8, buffer, des_test_ct);

  /* KAT Decrypt */
  memcpy(buffer, des_test_ct, 8);
  TC_DES_ECB_decrypt(&ctx, buffer);
  munit_assert_memory_equal(8, buffer, des_test_pt);

  /* Round-Trip */
  TC_DES_ECB_encrypt(&ctx, buffer);
  munit_assert_memory_equal(8, buffer, des_test_ct);
  TC_DES_ECB_decrypt(&ctx, buffer);
  munit_assert_memory_equal(8, buffer, des_test_pt);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_ECB */

/* 1B. Single DES CBC (KAT Encrypt, KAT Decrypt, & Round-Trip) */
#if TC_DES_ENABLE_CBC
static MunitResult test_des_cbc(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;

  struct TC_DES_ctx ctx;
  uint8_t buffer[8];

  /* KAT Encrypt */
  TC_DES_init_ctx_iv(&ctx, des_test_key, TC_DES_KEYLEN, des_cbc_iv);
  memcpy(buffer, des_test_pt, 8);
  TC_DES_CBC_encrypt(&ctx, buffer, 8);
  munit_assert_memory_equal(8, buffer, des_cbc_ct);

  /* KAT Decrypt */
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  memcpy(buffer, des_cbc_ct, 8);
  TC_DES_CBC_decrypt(&ctx, buffer, 8);
  munit_assert_memory_equal(8, buffer, des_test_pt);

  /* Round-Trip */
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_CBC_encrypt(&ctx, buffer, 8);
  munit_assert_memory_equal(8, buffer, des_cbc_ct);
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_CBC_decrypt(&ctx, buffer, 8);
  munit_assert_memory_equal(8, buffer, des_test_pt);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_CBC */

/* 1C. Single DES CTR Stream Mode */
#if TC_DES_ENABLE_CTR
/* A counter that wraps past 2^64 is exhausted until a new IV is set. */
static MunitResult test_des_ctr_exhaustion(const MunitParameter params[], void* data)
{
  uint8_t iv[TC_DES_BLOCKLEN], buffer[2 * TC_DES_BLOCKLEN], saved[sizeof buffer];
  struct TC_DES_ctx ctx;
  (void)params;
  (void)data;
  memset(iv, 0xff, sizeof iv);
  memset(buffer, 0x11, sizeof buffer);
  munit_assert_int(TC_DES_init_ctx_iv(&ctx, des_test_key, TC_DES_KEYLEN, iv), ==, TC_OK);
  munit_assert_int(TC_DES_CTR_crypt(&ctx, buffer, sizeof buffer), ==, TC_ERROR);
  munit_assert_int(TC_DES_CTR_crypt(&ctx, buffer, 4), ==, TC_OK);
  munit_assert_int(TC_DES_CTR_crypt(&ctx, buffer + 4, 4), ==, TC_OK);
  memcpy(saved, buffer, sizeof saved);
  munit_assert_int(TC_DES_CTR_crypt(&ctx, buffer, 1), ==, TC_ERROR);
  munit_assert_memory_equal(sizeof buffer, buffer, saved);
  memset(iv, 0, sizeof iv);
  munit_assert_int(TC_DES_ctx_set_iv(&ctx, iv), ==, TC_OK);
  munit_assert_int(TC_DES_CTR_crypt(&ctx, buffer, sizeof buffer), ==, TC_OK);
  TC_DES_ctx_clear(&ctx);
#if TC_DES_ENABLE_TDES
  {
    struct TC_DES_ctx ctx3;
    uint8_t key3[24];
    memset(key3, 0x5a, sizeof key3);
    key3[8] = 0xa5;
    key3[16] = 0x3c;
    memset(iv, 0xff, sizeof iv);
    munit_assert_int(TC_DES_init_ctx_iv(&ctx3, key3, sizeof key3, iv), ==, TC_OK);
    munit_assert_int(TC_DES_CTR_crypt(&ctx3, buffer, TC_DES_BLOCKLEN), ==, TC_OK);
    munit_assert_int(TC_DES_CTR_crypt(&ctx3, buffer, 1), ==, TC_ERROR);
    TC_DES_ctx_clear(&ctx3);
  }
#endif
  return MUNIT_OK;
}

static MunitResult test_des_ctr(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;

  struct TC_DES_ctx ctx;
  uint8_t original[20] = "Hello DES CTR Mode!";
  uint8_t buffer[20];
  uint8_t known[sizeof(des_ctr_pt)];

  memcpy(known, des_ctr_pt, sizeof(known));
  munit_assert_int(TC_DES_init_ctx_iv(&ctx, des_test_key, TC_DES_KEYLEN, des_ctr_iv), ==, TC_OK);
  munit_assert_int(TC_DES_CTR_crypt(&ctx, known, 5), ==, TC_OK);
  munit_assert_int(TC_DES_CTR_crypt(&ctx, known + 5, sizeof(known) - 5), ==, TC_OK);
  munit_assert_memory_equal(sizeof(known), known, des_ctr_ct);

  memcpy(buffer, original, 20);

  /* Encrypt */
  TC_DES_init_ctx_iv(&ctx, des_test_key, TC_DES_KEYLEN, des_ctr_iv);
  munit_assert_int(TC_DES_CTR_crypt(&ctx, buffer, 5), ==, TC_OK);
  munit_assert_int(TC_DES_CTR_crypt(&ctx, buffer + 5, 15), ==, TC_OK);
  munit_assert_memory_not_equal(20, buffer, original);

  /* Decrypt */
  TC_DES_ctx_set_iv(&ctx, des_ctr_iv);
  munit_assert_int(TC_DES_CTR_crypt(&ctx, buffer, 7), ==, TC_OK);
  munit_assert_int(TC_DES_CTR_crypt(&ctx, buffer + 7, 13), ==, TC_OK);
  munit_assert_memory_equal(20, buffer, original);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_CTR */

/* ========================================================================= */
/* Matrix 2: 2-Key 3DES (Triple DES)                                         */
/* ========================================================================= */

/* 2A. 2-Key 3DES ECB (KAT Encrypt, KAT Decrypt, & Round-Trip) */
#if TC_DES_ENABLE_TDES && TC_DES_ENABLE_ECB
static MunitResult test_tdes2_ecb(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;

  struct TC_DES_ctx ctx;
  uint8_t buffer[16];

  TC_DES_init_ctx(&ctx, tdes2_key, 16);

  /* KAT Encrypt (2 blocks) */
  memcpy(buffer, tdes2_pt, 16);
  TC_DES_ECB_encrypt(&ctx, buffer);
  TC_DES_ECB_encrypt(&ctx, buffer + 8);
  munit_assert_memory_equal(16, buffer, tdes2_ecb_ct);

  /* KAT Decrypt (2 blocks) */
  memcpy(buffer, tdes2_ecb_ct, 16);
  TC_DES_ECB_decrypt(&ctx, buffer);
  TC_DES_ECB_decrypt(&ctx, buffer + 8);
  munit_assert_memory_equal(16, buffer, tdes2_pt);

  /* Round-Trip */
  TC_DES_ECB_encrypt(&ctx, buffer);
  TC_DES_ECB_encrypt(&ctx, buffer + 8);
  munit_assert_memory_equal(16, buffer, tdes2_ecb_ct);
  TC_DES_ECB_decrypt(&ctx, buffer);
  TC_DES_ECB_decrypt(&ctx, buffer + 8);
  munit_assert_memory_equal(16, buffer, tdes2_pt);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_TDES && TC_DES_ENABLE_ECB */

/* 2B. 2-Key 3DES CBC (KAT Encrypt, KAT Decrypt, & Round-Trip) */
#if TC_DES_ENABLE_TDES && TC_DES_ENABLE_CBC
static MunitResult test_tdes2_cbc(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;

  struct TC_DES_ctx ctx;
  uint8_t buffer[16];

  /* KAT Encrypt */
  TC_DES_init_ctx_iv(&ctx, tdes2_key, 16, des_cbc_iv);
  memcpy(buffer, tdes2_pt, 16);
  TC_DES_CBC_encrypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes2_cbc_ct);

  /* KAT Decrypt */
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  memcpy(buffer, tdes2_cbc_ct, 16);
  TC_DES_CBC_decrypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes2_pt);

  /* Round-Trip */
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_CBC_encrypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes2_cbc_ct);
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_CBC_decrypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes2_pt);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_TDES && TC_DES_ENABLE_CBC */

/* 2C. 2-Key 3DES CTR Stream Mode */
#if TC_DES_ENABLE_TDES && TC_DES_ENABLE_CTR
static MunitResult test_tdes2_ctr(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;

  struct TC_DES_ctx ctx;
  uint8_t original[24] = "Stream 2-Key 3DES Test!";
  uint8_t buffer[24];

  memcpy(buffer, original, 24);

  TC_DES_init_ctx_iv(&ctx, tdes2_key, 16, des_ctr_iv);
  munit_assert_int(TC_DES_CTR_crypt(&ctx, buffer, 5), ==, TC_OK);
  munit_assert_int(TC_DES_CTR_crypt(&ctx, buffer + 5, 19), ==, TC_OK);
  munit_assert_memory_not_equal(24, buffer, original);

  TC_DES_ctx_set_iv(&ctx, des_ctr_iv);
  munit_assert_int(TC_DES_CTR_crypt(&ctx, buffer, 7), ==, TC_OK);
  munit_assert_int(TC_DES_CTR_crypt(&ctx, buffer + 7, 17), ==, TC_OK);
  munit_assert_memory_equal(24, buffer, original);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_TDES && TC_DES_ENABLE_CTR */

/* ========================================================================= */
/* Matrix 3: 3-Key 3DES (Triple DES)                                         */
/* ========================================================================= */

/* 3A. 3-Key 3DES ECB (KAT Encrypt, KAT Decrypt, & Round-Trip) */
#if TC_DES_ENABLE_TDES && TC_DES_ENABLE_ECB
static MunitResult test_tdes3_ecb(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;

  struct TC_DES_ctx ctx;
  uint8_t buffer[16];

  TC_DES_init_ctx(&ctx, tdes3_key, 24);

  /* KAT Encrypt (2 blocks) */
  memcpy(buffer, tdes3_pt, 16);
  TC_DES_ECB_encrypt(&ctx, buffer);
  TC_DES_ECB_encrypt(&ctx, buffer + 8);
  munit_assert_memory_equal(16, buffer, tdes3_ecb_ct);

  /* KAT Decrypt (2 blocks) */
  memcpy(buffer, tdes3_ecb_ct, 16);
  TC_DES_ECB_decrypt(&ctx, buffer);
  TC_DES_ECB_decrypt(&ctx, buffer + 8);
  munit_assert_memory_equal(16, buffer, tdes3_pt);

  /* Round-Trip */
  TC_DES_ECB_encrypt(&ctx, buffer);
  TC_DES_ECB_encrypt(&ctx, buffer + 8);
  munit_assert_memory_equal(16, buffer, tdes3_ecb_ct);
  TC_DES_ECB_decrypt(&ctx, buffer);
  TC_DES_ECB_decrypt(&ctx, buffer + 8);
  munit_assert_memory_equal(16, buffer, tdes3_pt);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_TDES && TC_DES_ENABLE_ECB */

/* 3B. 3-Key 3DES CBC (KAT Encrypt, KAT Decrypt, & Round-Trip) */
#if TC_DES_ENABLE_TDES && TC_DES_ENABLE_CBC
static MunitResult test_tdes3_cbc(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;

  struct TC_DES_ctx ctx;
  uint8_t buffer[16];

  /* KAT Encrypt */
  TC_DES_init_ctx_iv(&ctx, tdes3_key, 24, des_cbc_iv);
  memcpy(buffer, tdes3_pt, 16);
  TC_DES_CBC_encrypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_cbc_ct);

  /* KAT Decrypt */
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  memcpy(buffer, tdes3_cbc_ct, 16);
  TC_DES_CBC_decrypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_pt);

  /* Round-Trip */
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_CBC_encrypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_cbc_ct);
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_CBC_decrypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_pt);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_TDES && TC_DES_ENABLE_CBC */

/* 3C. 3-Key 3DES CTR Stream Mode */
#if TC_DES_ENABLE_TDES && TC_DES_ENABLE_CTR
static MunitResult test_tdes3_ctr(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;

  struct TC_DES_ctx ctx;
  uint8_t original[32] = "Stream 3-Key Triple-DES Test!12";
  uint8_t buffer[32];
  uint8_t known[sizeof(des_ctr_pt)];

  memcpy(known, des_ctr_pt, sizeof(known));
  munit_assert_int(TC_DES_init_ctx_iv(&ctx, tdes3_key, sizeof(tdes3_key), des_ctr_iv), ==, TC_OK);
  munit_assert_int(TC_DES_CTR_crypt(&ctx, known, sizeof(known)), ==, TC_OK);
  munit_assert_memory_equal(sizeof(known), known, tdes3_ctr_ct);

  memcpy(buffer, original, 32);

  TC_DES_init_ctx_iv(&ctx, tdes3_key, 24, des_ctr_iv);
  munit_assert_int(TC_DES_CTR_crypt(&ctx, buffer, 5), ==, TC_OK);
  munit_assert_int(TC_DES_CTR_crypt(&ctx, buffer + 5, 27), ==, TC_OK);
  munit_assert_memory_not_equal(32, buffer, original);

  TC_DES_ctx_set_iv(&ctx, des_ctr_iv);
  munit_assert_int(TC_DES_CTR_crypt(&ctx, buffer, 7), ==, TC_OK);
  munit_assert_int(TC_DES_CTR_crypt(&ctx, buffer + 7, 25), ==, TC_OK);
  munit_assert_memory_equal(32, buffer, original);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_TDES && TC_DES_ENABLE_CTR */

/* ========================================================================= */
/* Matrix 4: CFB / OFB Feedback Modes                                        */
/* ========================================================================= */

/* 4A. Single DES OFB (KAT, Decrypt symmetry, Cross-call chaining) */
#if TC_DES_ENABLE_OFB
static MunitResult test_des_ofb(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;

  struct TC_DES_ctx ctx;
  uint8_t buffer[8];

  /* KAT Encrypt */
  TC_DES_init_ctx_iv(&ctx, des_test_key, TC_DES_KEYLEN, des_cbc_iv);
  memcpy(buffer, des_test_pt, 8);
  munit_assert_int(TC_DES_OFB_crypt(&ctx, buffer, 3), ==, TC_OK);
  munit_assert_int(TC_DES_OFB_crypt(&ctx, buffer + 3, 5), ==, TC_OK);
  munit_assert_memory_equal(8, buffer, des_ofb_ct);

  /* Decrypt is the same operation */
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  munit_assert_int(TC_DES_OFB_crypt(&ctx, buffer, 5), ==, TC_OK);
  munit_assert_int(TC_DES_OFB_crypt(&ctx, buffer + 5, 3), ==, TC_OK);
  munit_assert_memory_equal(8, buffer, des_test_pt);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_OFB */

/* 4B. Single DES CFB64 (KAT Encrypt, KAT Decrypt) */
#if TC_DES_ENABLE_CFB64
static MunitResult test_des_cfb64(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;

  struct TC_DES_ctx ctx;
  uint8_t buffer[8];

  TC_DES_init_ctx_iv(&ctx, des_test_key, TC_DES_KEYLEN, des_cbc_iv);
  memcpy(buffer, des_test_pt, 8);
  TC_DES_CFB64_encrypt(&ctx, buffer, 8);
  munit_assert_memory_equal(8, buffer, des_cfb64_ct);

  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_CFB64_decrypt(&ctx, buffer, 8);
  munit_assert_memory_equal(8, buffer, des_test_pt);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_CFB64 */

#if TC_DES_ENABLE_CFB64
/* SP 800-38A section 5.2: CFB64 messages are whole 8-byte segments. A short
 * segment ends the message until a new IV is set. Splitting at multiples of 8
 * matches one call, for single DES and TDEA. */
static MunitResult test_des_cfb64_short_segment(const MunitParameter params[], void* data)
{
  const uint8_t* keys[3] = {des_test_key, tdes2_key, tdes3_key};
  const size_t keylens[3] = {TC_DES_KEYLEN, TC_DES_KEYLEN_2KEY, TC_DES_KEYLEN_3KEY};
  const size_t key_count = TC_DES_ENABLE_TDES ? 3 : 1;
  size_t k;
  (void)params;
  (void)data;

  for (k = 0; k < key_count; ++k) {
    struct TC_DES_ctx ctx;
    uint8_t oneshot[19];
    uint8_t split[19];
    uint8_t saved[19];
    uint8_t saved_iv[TC_DES_BLOCKLEN];
    size_t i;
    for (i = 0; i < sizeof oneshot; ++i)
      oneshot[i] = split[i] = (uint8_t)(0x30u + i);

    munit_assert_int(TC_DES_init_ctx_iv(&ctx, keys[k], keylens[k], des_cbc_iv), ==, TC_OK);
    munit_assert_int(TC_DES_CFB64_encrypt(&ctx, oneshot, sizeof oneshot), ==, TC_OK);
    munit_assert_uint8(ctx.cfb64_finished, ==, 1);

    /* Aligned splits followed by a short final segment match one call. */
    munit_assert_int(TC_DES_ctx_set_iv(&ctx, des_cbc_iv), ==, TC_OK);
    munit_assert_uint8(ctx.cfb64_finished, ==, 0);
    munit_assert_int(TC_DES_CFB64_encrypt(&ctx, split, 8), ==, TC_OK);
    munit_assert_int(TC_DES_CFB64_encrypt(&ctx, split + 8, 8), ==, TC_OK);
    munit_assert_int(TC_DES_CFB64_encrypt(&ctx, split + 16, 3), ==, TC_OK);
    munit_assert_memory_equal(sizeof split, split, oneshot);

    /* After a short segment every CFB64 call fails and changes nothing. */
    memcpy(saved, split, sizeof saved);
    memcpy(saved_iv, ctx.Iv, sizeof saved_iv);
    munit_assert_int(TC_DES_CFB64_encrypt(&ctx, split, 8), ==, TC_ERROR);
    munit_assert_int(TC_DES_CFB64_decrypt(&ctx, split, 8), ==, TC_ERROR);
    munit_assert_int(TC_DES_CFB64_encrypt(&ctx, split, 0), ==, TC_ERROR);
    munit_assert_memory_equal(sizeof split, split, saved);
    munit_assert_memory_equal(sizeof saved_iv, ctx.Iv, saved_iv);

    /* A non-aligned split (3 + 5) is rejected at the second call. */
    munit_assert_int(TC_DES_ctx_set_iv(&ctx, des_cbc_iv), ==, TC_OK);
    munit_assert_int(TC_DES_CFB64_encrypt(&ctx, split, 3), ==, TC_OK);
    munit_assert_int(TC_DES_CFB64_encrypt(&ctx, split + 3, 5), ==, TC_ERROR);

    /* Decryption follows the same rule and inverts the one-call ciphertext. */
    munit_assert_int(TC_DES_ctx_set_iv(&ctx, des_cbc_iv), ==, TC_OK);
    munit_assert_int(TC_DES_CFB64_decrypt(&ctx, oneshot, 16), ==, TC_OK);
    munit_assert_int(TC_DES_CFB64_decrypt(&ctx, oneshot + 16, 3), ==, TC_OK);
    munit_assert_int(TC_DES_CFB64_decrypt(&ctx, oneshot, 1), ==, TC_ERROR);
    for (i = 0; i < sizeof oneshot; ++i)
      munit_assert_uint8(oneshot[i], ==, (uint8_t)(0x30u + i));

    /* A fresh init also starts a new message. */
    munit_assert_int(TC_DES_init_ctx_iv(&ctx, keys[k], keylens[k], des_cbc_iv), ==, TC_OK);
    munit_assert_int(TC_DES_CFB64_encrypt(&ctx, split, 8), ==, TC_OK);
    TC_DES_ctx_clear(&ctx);
  }
  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_CFB64 */

/* 4C. Single DES CFB8 (KAT Encrypt, KAT Decrypt) */
#if TC_DES_ENABLE_CFB8
static MunitResult test_des_cfb8(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;

  struct TC_DES_ctx ctx;
  uint8_t buffer[8];

  TC_DES_init_ctx_iv(&ctx, des_test_key, TC_DES_KEYLEN, des_cbc_iv);
  memcpy(buffer, des_test_pt, 8);
  TC_DES_CFB8_encrypt(&ctx, buffer, 8);
  munit_assert_memory_equal(8, buffer, des_cfb8_ct);

  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_CFB8_decrypt(&ctx, buffer, 8);
  munit_assert_memory_equal(8, buffer, des_test_pt);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_CFB8 */

/* 4D. Single DES CFB1: NIST CAVP TCFB1vartext.rsp single-bit cases + roundtrip */
#if TC_DES_ENABLE_CFB1
static MunitResult test_des_cfb1(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;

  struct TC_DES_ctx ctx;

  /* TCFB1vartext.rsp COUNT 0: KEYs=0101010101010101 IV=8000000000000000 PT=0 -> CT=1 */
  const uint8_t weak_key[8] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
  const uint8_t iv0[8] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  const uint8_t iv2[8] = {0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  uint8_t bits[1];

  bits[0] = 0x00;
  TC_DES_init_ctx_iv(&ctx, weak_key, TC_DES_KEYLEN, iv0);
  TC_DES_CFB1_encrypt(&ctx, bits, 1);
  munit_assert_uint8(bits[0] >> 7, ==, 1);

  /* COUNT 2: IV=2000000000000000 PT=0 -> CT=0 */
  bits[0] = 0x00;
  TC_DES_ctx_set_iv(&ctx, iv2);
  TC_DES_CFB1_encrypt(&ctx, bits, 1);
  munit_assert_uint8(bits[0] >> 7, ==, 0);

  /* Multi-bit roundtrip with an arbitrary key */
  uint8_t stream[3] = {0xa5, 0x3c, 0x80};
  uint8_t original[3];
  memcpy(original, stream, 3);
  TC_DES_init_ctx_iv(&ctx, des_test_key, TC_DES_KEYLEN, des_cbc_iv);
  TC_DES_CFB1_encrypt(&ctx, stream, 17);
  munit_assert_memory_not_equal(3, stream, original);
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_CFB1_decrypt(&ctx, stream, 17);
  munit_assert_memory_equal(3, stream, original);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_CFB1 */

/* 4E. 3-Key 3DES OFB / CFB64 / CFB8 (KAT + Decrypt) */
#if TC_DES_ENABLE_TDES &&                                                                          \
    (TC_DES_ENABLE_OFB || TC_DES_ENABLE_CFB64 || TC_DES_ENABLE_CFB8 || TC_DES_ENABLE_CFB1)
static MunitResult test_tdes3_feedback_modes(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;

  struct TC_DES_ctx ctx;
  uint8_t buffer[16];

  /* OFB */
  TC_DES_init_ctx_iv(&ctx, tdes3_key, 24, des_cbc_iv);
  memcpy(buffer, tdes3_pt, 16);
  TC_DES_OFB_crypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_ofb_ct);
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_OFB_crypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_pt);

  /* CFB64 */
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_CFB64_encrypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_cfb64_ct);
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_CFB64_decrypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_pt);

  /* CFB8 */
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_CFB8_encrypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_cfb8_ct);
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_CFB8_decrypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_pt);

  /* CFB1 roundtrip. The CAVP files cover the CFB1 KAT. */
  uint8_t stream[2] = {0x5a, 0xc0};
  uint8_t original[2];
  memcpy(original, stream, 2);
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_CFB1_encrypt(&ctx, stream, 10);
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_CFB1_decrypt(&ctx, stream, 10);
  munit_assert_memory_equal(2, stream, original);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_TDES && (TC_DES_ENABLE_OFB || TC_DES_ENABLE_CFB64 || TC_DES_ENABLE_CFB8 || TC_DES_ENABLE_CFB1) */

/* 4F. Cross-call chaining: split calls must equal one-shot output */
#if TC_DES_ENABLE_TDES &&                                                                          \
    (TC_DES_ENABLE_OFB || TC_DES_ENABLE_CFB64 || TC_DES_ENABLE_CFB8 || TC_DES_ENABLE_CFB1)
static MunitResult test_feedback_mode_chaining(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;

  struct TC_DES_ctx ctx;
  uint8_t oneshot[16];
  uint8_t split[16];

  /* CFB64 */
  memcpy(oneshot, tdes3_pt, 16);
  memcpy(split, tdes3_pt, 16);
  TC_DES_init_ctx_iv(&ctx, tdes3_key, 24, des_cbc_iv);
  TC_DES_CFB64_encrypt(&ctx, oneshot, 16);
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_CFB64_encrypt(&ctx, split, 8);
  TC_DES_CFB64_encrypt(&ctx, split + 8, 8);
  munit_assert_memory_equal(16, split, oneshot);

  /* CFB8 */
  memcpy(oneshot, tdes3_pt, 16);
  memcpy(split, tdes3_pt, 16);
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_CFB8_encrypt(&ctx, oneshot, 16);
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_CFB8_encrypt(&ctx, split, 5);
  TC_DES_CFB8_encrypt(&ctx, split + 5, 11);
  munit_assert_memory_equal(16, split, oneshot);

  /* OFB */
  memcpy(oneshot, tdes3_pt, 16);
  memcpy(split, tdes3_pt, 16);
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_OFB_crypt(&ctx, oneshot, 16);
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_OFB_crypt(&ctx, split, 3);
  TC_DES_OFB_crypt(&ctx, split + 3, 13);
  munit_assert_memory_equal(16, split, oneshot);

  /* CFB1: 16 bits one-shot vs two 8-bit calls (split only on byte boundaries) */
  uint8_t bits_oneshot[2] = {0x96, 0x3d};
  uint8_t bits_split[2] = {0x96, 0x3d};
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_CFB1_encrypt(&ctx, bits_oneshot, 16);
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_CFB1_encrypt(&ctx, bits_split, 8);
  TC_DES_CFB1_encrypt(&ctx, bits_split + 1, 8);
  munit_assert_memory_equal(2, bits_split, bits_oneshot);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_TDES && (TC_DES_ENABLE_OFB || TC_DES_ENABLE_CFB64 || TC_DES_ENABLE_CFB8 || TC_DES_ENABLE_CFB1) */

/* ========================================================================= */
/* Additional Cryptographic & Protocol Tests                                 */
/* ========================================================================= */

/* Equivalence Test: 3DES with K1=K2=K3 equals Single DES */
#if TC_DES_ENABLE_TDES && TC_DES_ENABLE_ECB
static MunitResult test_tdes_single_des_equivalence(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;

  struct TC_DES_ctx single_ctx;
  struct TC_DES_ctx tdes_ctx;

  uint8_t key3[24];
  memcpy(key3, des_test_key, 8);
  memcpy(key3 + 8, des_test_key, 8);
  memcpy(key3 + 16, des_test_key, 8);

  TC_DES_init_ctx(&single_ctx, des_test_key, TC_DES_KEYLEN);
  TC_DES_init_ctx(&tdes_ctx, key3, 24);

  uint8_t buf_single[8];
  uint8_t buf_tdes[8];

  memcpy(buf_single, des_test_pt, 8);
  memcpy(buf_tdes, des_test_pt, 8);

  TC_DES_ECB_encrypt(&single_ctx, buf_single);
  TC_DES_ECB_encrypt(&tdes_ctx, buf_tdes);

  munit_assert_memory_equal(8, buf_single, buf_tdes);
  munit_assert_memory_equal(8, buf_single, des_test_ct);

  /* Decryption Equivalence */
  TC_DES_ECB_decrypt(&single_ctx, buf_single);
  TC_DES_ECB_decrypt(&tdes_ctx, buf_tdes);
  munit_assert_memory_equal(8, buf_single, buf_tdes);
  munit_assert_memory_equal(8, buf_single, des_test_pt);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_TDES && TC_DES_ENABLE_ECB */

#if TC_DES_ENABLE_CMAC
/* OpenSSL-cross-checked KATs (legacy des-cbc / des-ede-cbc / des-ede3-cbc). */
/* Keep this exact message paired with the checked-in known-answer tag. */
static const uint8_t cmac_kat_msg[] = "tiny-DES-c CMAC Test!";
static const uint8_t cmac_kat_des[8] = {0x0a, 0xa5, 0xf5, 0xff, 0x35, 0xe8, 0x9f, 0x6a};
static const uint8_t cmac_kat_tdes2[8] = {0x3c, 0xc1, 0x01, 0x09, 0xae, 0x58, 0xa5, 0xa6};
static const uint8_t cmac_kat_tdes3[8] = {0xea, 0x5e, 0x07, 0x9a, 0xac, 0x25, 0x18, 0xe9};
static const uint8_t cmac_kat_des_empty[8] = {0x86, 0xf7, 0x9c, 0x13, 0xfd, 0x30, 0x6e, 0x67};
static const uint8_t cmac_kat_tdes2_empty[8] = {0x79, 0xce, 0x52, 0xa7, 0xf7, 0x86, 0xa9, 0x60};
static const uint8_t cmac_kat_tdes3_empty[8] = {0x7d, 0xb0, 0xd3, 0x7d, 0xf9, 0x36, 0xc5, 0x50};

/* CMAC Tests (NIST SP 800-38B) */
static MunitResult test_des_cmac(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;

  uint8_t cmac1[8], cmac2[8], cmac3[8], cmac_empty[8], bad[8];
  size_t msglen = sizeof(cmac_kat_msg) - 1;

  munit_assert_int(TC_OK, ==, TC_DES_CMAC(des_test_key, 8, cmac_kat_msg, msglen, cmac1, 8));
  munit_assert_int(TC_OK, ==, TC_DES_CMAC(tdes2_key, 16, cmac_kat_msg, msglen, cmac2, 8));
  munit_assert_int(TC_OK, ==, TC_DES_CMAC(tdes3_key, 24, cmac_kat_msg, msglen, cmac3, 8));
  munit_assert_memory_equal(8, cmac1, cmac_kat_des);
  munit_assert_memory_equal(8, cmac2, cmac_kat_tdes2);
  munit_assert_memory_equal(8, cmac3, cmac_kat_tdes3);

  munit_assert_int(TC_OK, ==, TC_DES_CMAC(des_test_key, 8, NULL, 0, cmac_empty, 8));
  munit_assert_memory_equal(8, cmac_empty, cmac_kat_des_empty);
  munit_assert_int(TC_OK, ==, TC_DES_CMAC(tdes2_key, 16, NULL, 0, cmac_empty, 8));
  munit_assert_memory_equal(8, cmac_empty, cmac_kat_tdes2_empty);
  munit_assert_int(TC_OK, ==, TC_DES_CMAC(tdes3_key, 24, NULL, 0, cmac_empty, 8));
  munit_assert_memory_equal(8, cmac_empty, cmac_kat_tdes3_empty);

  munit_assert_int(TC_OK, ==, TC_DES_CMAC_verify(tdes2_key, 16, cmac_kat_msg, msglen, cmac2, 8));
  memcpy(bad, cmac2, 8);
  bad[0] ^= 0x01U;
  munit_assert_int(TC_MISMATCH, ==,
                   TC_DES_CMAC_verify(tdes2_key, 16, cmac_kat_msg, msglen, bad, 8));

  munit_assert_int(TC_ERROR, ==, TC_DES_CMAC(des_test_key, 10, cmac_kat_msg, msglen, cmac1, 8));
  munit_assert_int(TC_ERROR, ==, TC_DES_CMAC(des_test_key, 8, cmac_kat_msg, msglen, cmac1, 0));

  return MUNIT_OK;
}

/* The default entry points take TC_MIN_TAG_LEN..8 bytes and the _short_tag
 * forms take 1..TC_MIN_TAG_LEN - 1 (SP 800-38B Appendix A.2). A rejected
 * length leaves the tag buffer unchanged. */
static MunitResult test_des_cmac_tag_policy(const MunitParameter params[], void* data)
{
  const size_t msglen = sizeof(cmac_kat_msg) - 1;
  const size_t below = TC_MIN_TAG_LEN - 1u;
  uint8_t tag[8], bad[8];

  (void)params;
  (void)data;

  /* Default entry: min - 1 is rejected, min is accepted. */
  memset(tag, 0xa5, sizeof(tag));
  munit_assert_int(TC_ERROR, ==, TC_DES_CMAC(tdes2_key, 16, cmac_kat_msg, msglen, tag, below));
  munit_assert_true(tc_test_all_value(tag, sizeof(tag), 0xa5));
  munit_assert_int(TC_ERROR, ==,
                   TC_DES_CMAC_verify(tdes2_key, 16, cmac_kat_msg, msglen, cmac_kat_tdes2, below));
  munit_assert_int(TC_OK, ==,
                   TC_DES_CMAC(tdes2_key, 16, cmac_kat_msg, msglen, tag, TC_MIN_TAG_LEN));
  munit_assert_memory_equal(TC_MIN_TAG_LEN, tag, cmac_kat_tdes2);
  munit_assert_int(
      TC_OK, ==,
      TC_DES_CMAC_verify(tdes2_key, 16, cmac_kat_msg, msglen, cmac_kat_tdes2, TC_MIN_TAG_LEN));

  /* Short-tag entry: 0 and min are rejected with the tag unchanged. */
  memset(tag, 0xa5, sizeof(tag));
  munit_assert_int(TC_ERROR, ==,
                   TC_DES_CMAC_short_tag(tdes2_key, 16, cmac_kat_msg, msglen, tag, 0));
  munit_assert_int(TC_ERROR, ==,
                   TC_DES_CMAC_short_tag(tdes2_key, 16, cmac_kat_msg, msglen, tag, TC_MIN_TAG_LEN));
  munit_assert_int(TC_ERROR, ==,
                   TC_DES_CMAC_short_tag(tdes2_key, 10, cmac_kat_msg, msglen, tag, below));
  munit_assert_int(TC_ERROR, ==, TC_DES_CMAC_short_tag(NULL, 16, cmac_kat_msg, msglen, tag, below));
  munit_assert_true(tc_test_all_value(tag, sizeof(tag), 0xa5));

  /* Short-tag entry: 1 and min - 1 give the leading bytes of the full tag. */
  munit_assert_int(TC_OK, ==, TC_DES_CMAC_short_tag(tdes2_key, 16, cmac_kat_msg, msglen, tag, 1));
  munit_assert_uint8(tag[0], ==, cmac_kat_tdes2[0]);
  munit_assert_int(TC_OK, ==,
                   TC_DES_CMAC_short_tag(tdes2_key, 16, cmac_kat_msg, msglen, tag, below));
  munit_assert_memory_equal(below, tag, cmac_kat_tdes2);
  munit_assert_true(tc_test_all_value(tag + below, sizeof(tag) - below, 0xa5));

  munit_assert_int(
      TC_OK, ==,
      TC_DES_CMAC_verify_short_tag(tdes2_key, 16, cmac_kat_msg, msglen, cmac_kat_tdes2, below));
  munit_assert_int(TC_ERROR, ==,
                   TC_DES_CMAC_verify_short_tag(tdes2_key, 16, cmac_kat_msg, msglen, cmac_kat_tdes2,
                                                TC_MIN_TAG_LEN));
  munit_assert_int(TC_ERROR, ==,
                   TC_DES_CMAC_verify_short_tag(tdes2_key, 16, cmac_kat_msg, msglen, NULL, below));
  memcpy(bad, cmac_kat_tdes2, sizeof(bad));
  bad[below - 1u] ^= 0x01u;
  munit_assert_int(TC_MISMATCH, ==,
                   TC_DES_CMAC_verify_short_tag(tdes2_key, 16, cmac_kat_msg, msglen, bad, below));
  return MUNIT_OK;
}

/* Streaming context must match the one-shot for every split pattern and
   key length, including an empty message and block-aligned messages. */
static MunitResult test_des_cmac_streaming(const MunitParameter params[], void* data)
{
  static const size_t lengths[] = {0, 1, 7, 8, 9, 16, 21, 24, 50};
  static const size_t splits[] = {1, 7, 8, 9, 20};
  const uint8_t* keys[3];
  size_t keylens[3];
  uint8_t msg[50];
  uint8_t expected[8], tag[8];
  struct TC_DES_CMAC_ctx ctx;
  size_t ki, li, si, i;

  (void)params;
  (void)data;

  keys[0] = des_test_key;
  keylens[0] = 8;
  keys[1] = tdes2_key;
  keylens[1] = 16;
  keys[2] = tdes3_key;
  keylens[2] = 24;
  for (i = 0; i < sizeof(msg); ++i)
    msg[i] = (uint8_t)(i * 13u + 5u);

  for (ki = 0; ki < 3; ++ki) {
    for (li = 0; li < sizeof(lengths) / sizeof(lengths[0]); ++li) {
      const size_t len = lengths[li];
      munit_assert_int(TC_OK, ==, TC_DES_CMAC(keys[ki], keylens[ki], msg, len, expected, 8));

      munit_assert_int(TC_OK, ==, TC_DES_CMAC_init(&ctx, keys[ki], keylens[ki]));
      munit_assert_int(TC_OK, ==, TC_DES_CMAC_update(&ctx, msg, len));
      munit_assert_int(TC_OK, ==, TC_DES_CMAC_final(&ctx, tag));
      munit_assert_memory_equal(8, tag, expected);

      for (si = 0; si < sizeof(splits) / sizeof(splits[0]); ++si) {
        size_t pos = 0;
        munit_assert_int(TC_OK, ==, TC_DES_CMAC_init(&ctx, keys[ki], keylens[ki]));
        while (pos < len) {
          const size_t take = (len - pos) < splits[si] ? (len - pos) : splits[si];
          munit_assert_int(TC_OK, ==, TC_DES_CMAC_update(&ctx, msg + pos, take));
          pos += take;
        }
        munit_assert_int(TC_OK, ==, TC_DES_CMAC_update(&ctx, NULL, 0));
        munit_assert_int(TC_OK, ==, TC_DES_CMAC_final(&ctx, tag));
        munit_assert_memory_equal(8, tag, expected);
      }
    }
  }

  munit_assert_int(TC_ERROR, ==, TC_DES_CMAC_init(NULL, des_test_key, 8));
  munit_assert_int(TC_ERROR, ==, TC_DES_CMAC_init(&ctx, NULL, 8));
  munit_assert_int(TC_ERROR, ==, TC_DES_CMAC_init(&ctx, des_test_key, 12));
  memset(&ctx, 0, sizeof ctx);
  munit_assert_int(TC_DES_CMAC_update(&ctx, msg, 1), ==, TC_ERROR);
  munit_assert_int(TC_DES_CMAC_final(&ctx, tag), ==, TC_ERROR);
  munit_assert_int(TC_DES_CMAC_init(&ctx, des_test_key, 8), ==, TC_OK);
  munit_assert_int(TC_DES_CMAC_final(&ctx, tag), ==, TC_OK);
  munit_assert_int(TC_DES_CMAC_final(&ctx, tag), ==, TC_ERROR);
  TC_DES_CMAC_ctx_clear(&ctx);
  munit_assert_int(TC_DES_CMAC_update(&ctx, msg, 1), ==, TC_ERROR);
  TC_DES_CMAC_ctx_clear(NULL);

  return MUNIT_OK;
}

/* Degenerate Single-DES key (8 bytes) == 2-Key 3DES key with K1=K2 */
static MunitResult test_des_cmac_single_des_matches_2k3des_degenerate(const MunitParameter params[],
                                                                      void* data)
{
  (void)params;
  (void)data;

  uint8_t key8[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
  uint8_t key16[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                       0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
  uint8_t message[8] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33};
  static const uint8_t expected[8] = {0x25, 0xf8, 0xaf, 0xb2, 0x45, 0xd1, 0x53, 0x88};

  uint8_t mac8[8], mac16[8];
  munit_assert_int(TC_OK, ==, TC_DES_CMAC(key8, sizeof(key8), message, sizeof(message), mac8, 8));
  munit_assert_int(TC_OK, ==,
                   TC_DES_CMAC(key16, sizeof(key16), message, sizeof(message), mac16, 8));
  munit_assert_memory_equal(8, mac8, mac16);
  munit_assert_memory_equal(8, mac8, expected);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_CMAC */

/* Negative classical API cases */
static MunitResult test_des_api_errors(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;

  {
    struct TC_DES_ctx ctx = {0};
    uint8_t block[TC_DES_BLOCKLEN] = {1};
    uint8_t saved[TC_DES_BLOCKLEN];
    memcpy(saved, block, sizeof block);
#if TC_DES_ENABLE_ECB
    munit_assert_int(TC_DES_ECB_encrypt(&ctx, block), ==, TC_ERROR);
#endif
#if TC_DES_ENABLE_CBC
    munit_assert_int(TC_DES_CBC_encrypt(&ctx, block, sizeof block), ==, TC_ERROR);
#endif
#if TC_DES_ENABLE_CTR
    munit_assert_int(TC_DES_CTR_crypt(&ctx, block, sizeof block), ==, TC_ERROR);
#endif
#if TC_DES_ENABLE_OFB
    munit_assert_int(TC_DES_OFB_crypt(&ctx, block, sizeof block), ==, TC_ERROR);
#endif
    munit_assert_memory_equal(sizeof block, block, saved);
    munit_assert_int(TC_DES_init_ctx(&ctx, des_test_key, TC_DES_KEYLEN), ==, TC_OK);
    TC_DES_ctx_clear(&ctx);
#if TC_DES_ENABLE_ECB
    munit_assert_int(TC_DES_ECB_encrypt(&ctx, block), ==, TC_ERROR);
#endif
    munit_assert_int(TC_DES_init_ctx(&ctx, NULL, TC_DES_KEYLEN), ==, TC_ERROR);
  }

#if TC_DES_ENABLE_CBC
  {
    struct TC_DES_ctx ctx;
    uint8_t buf[16] = {0};
    TC_DES_init_ctx_iv(&ctx, des_test_key, TC_DES_KEYLEN, des_cbc_iv);
    munit_assert_int(TC_ERROR, ==, TC_DES_CBC_encrypt(&ctx, buf, 7));
    munit_assert_int(TC_ERROR, ==, TC_DES_CBC_decrypt(&ctx, buf, 1));
    munit_assert_int(TC_OK, ==, TC_DES_CBC_encrypt(&ctx, buf, 0));
  }
#endif

#if TC_DES_ENABLE_CTR
  {
    struct TC_DES_ctx ctx;
    uint8_t buf[16];
    uint8_t iv_max[8] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t iv_saved[8];
    memset(buf, 0x5a, sizeof(buf));
    TC_DES_init_ctx_iv(&ctx, des_test_key, TC_DES_KEYLEN, iv_max);
    memcpy(iv_saved, ctx.Iv, 8);
    /* One block from all-ones wraps the counter after the block; one block OK. */
    munit_assert_int(TC_OK, ==, TC_DES_CTR_crypt(&ctx, buf, 8));
    /* Restore max IV and request two blocks: wrap mid-request. */
    TC_DES_ctx_set_iv(&ctx, iv_max);
    munit_assert_int(TC_ERROR, ==, TC_DES_CTR_crypt(&ctx, buf, 16));
    munit_assert_memory_equal(8, ctx.Iv, iv_max);
  }
#endif

  {
    /* The key length selects the cipher. A failed re-init wipes the old key. */
    static const size_t bad_lengths[] = {0, 7, 9, 12, 15, 17, 23, 25, 32};
    struct TC_DES_ctx ctx;
    uint8_t junk[32] = {0};
    size_t i;
    for (i = 0; i < sizeof bad_lengths / sizeof bad_lengths[0]; ++i) {
      munit_assert_int(TC_OK, ==, TC_DES_init_ctx(&ctx, des_test_key, TC_DES_KEYLEN));
      munit_assert_int(TC_ERROR, ==, TC_DES_init_ctx(&ctx, junk, bad_lengths[i]));
      munit_assert_uint8(ctx.active, ==, 0);
    }
#if TC_DES_ENABLE_TDES
    munit_assert_int(TC_OK, ==, TC_DES_init_ctx(&ctx, tdes2_key, TC_DES_KEYLEN_2KEY));
    munit_assert_uint8(ctx.triple, ==, 1);
    munit_assert_int(TC_OK, ==, TC_DES_init_ctx(&ctx, tdes3_key, TC_DES_KEYLEN_3KEY));
    munit_assert_uint8(ctx.triple, ==, 1);
#else
    munit_assert_int(TC_ERROR, ==, TC_DES_init_ctx(&ctx, tdes2_key, TC_DES_KEYLEN_2KEY));
    munit_assert_int(TC_ERROR, ==, TC_DES_init_ctx(&ctx, tdes3_key, TC_DES_KEYLEN_3KEY));
#endif
    munit_assert_int(TC_OK, ==, TC_DES_init_ctx(&ctx, des_test_key, TC_DES_KEYLEN));
    munit_assert_uint8(ctx.triple, ==, 0);
    munit_assert_int(TC_ERROR, ==, TC_DES_init_ctx(NULL, des_test_key, TC_DES_KEYLEN));
#if TC_DES_NEEDS_IV
    munit_assert_int(TC_ERROR, ==, TC_DES_init_ctx_iv(&ctx, des_test_key, TC_DES_KEYLEN, NULL));
    munit_assert_uint8(ctx.active, ==, 0);
    munit_assert_int(TC_ERROR, ==, TC_DES_ctx_set_iv(&ctx, des_cbc_iv));
#endif
    TC_DES_ctx_clear(&ctx);
  }

  return MUNIT_OK;
}

/* Every mode entry rejects a NULL buffer with a nonzero length and leaves the
 * context unchanged. A NULL buffer with length 0 is an empty request. */
#if TC_DES_ENABLE_CBC || TC_DES_ENABLE_CTR || TC_DES_ENABLE_OFB || TC_DES_ENABLE_CFB1 ||           \
    TC_DES_ENABLE_CFB8 || TC_DES_ENABLE_CFB64
/* Compare every context field. */
static void assert_des_ctx_equal(const struct TC_DES_ctx* a, const struct TC_DES_ctx* b)
{
  munit_assert_memory_equal(sizeof a->schedule, a->schedule, b->schedule);
  munit_assert_uint8(a->triple, ==, b->triple);
  munit_assert_uint8(a->active, ==, b->active);
  munit_assert_memory_equal(sizeof a->Iv, a->Iv, b->Iv);
#if TC_DES_ENABLE_CTR
  munit_assert_memory_equal(sizeof a->ctr_stream, a->ctr_stream, b->ctr_stream);
  munit_assert_uint8(a->ctr_pos, ==, b->ctr_pos);
  munit_assert_uint8(a->ctr_exhausted, ==, b->ctr_exhausted);
#endif
#if TC_DES_ENABLE_OFB
  munit_assert_uint8(a->ofb_pos, ==, b->ofb_pos);
#endif
#if TC_DES_ENABLE_CFB64
  munit_assert_uint8(a->cfb64_finished, ==, b->cfb64_finished);
#endif
}

static MunitResult test_des_null_buffers(const MunitParameter params[], void* data)
{
  static const uint8_t iv[TC_DES_BLOCKLEN] = {1, 2, 3, 4, 5, 6, 7, 8};
  const uint8_t* keys[3] = {des_test_key, tdes2_key, tdes3_key};
  const size_t keylens[3] = {TC_DES_KEYLEN, TC_DES_KEYLEN_2KEY, TC_DES_KEYLEN_3KEY};
  const size_t key_count = TC_DES_ENABLE_TDES ? 3 : 1;
  size_t k;
  (void)params;
  (void)data;

  for (k = 0; k < key_count; ++k) {
    struct TC_DES_ctx ctx;
    struct TC_DES_ctx saved;
    munit_assert_int(TC_OK, ==, TC_DES_init_ctx_iv(&ctx, keys[k], keylens[k], iv));
    memcpy(&saved, &ctx, sizeof ctx);
#if TC_DES_ENABLE_CBC
    munit_assert_int(TC_ERROR, ==, TC_DES_CBC_encrypt(&ctx, NULL, 8));
    munit_assert_int(TC_ERROR, ==, TC_DES_CBC_decrypt(&ctx, NULL, 8));
    munit_assert_int(TC_OK, ==, TC_DES_CBC_encrypt(&ctx, NULL, 0));
#endif
#if TC_DES_ENABLE_CTR
    munit_assert_int(TC_ERROR, ==, TC_DES_CTR_crypt(&ctx, NULL, 1));
    munit_assert_int(TC_OK, ==, TC_DES_CTR_crypt(&ctx, NULL, 0));
#endif
#if TC_DES_ENABLE_CFB64
    munit_assert_int(TC_ERROR, ==, TC_DES_CFB64_encrypt(&ctx, NULL, 8));
    munit_assert_int(TC_ERROR, ==, TC_DES_CFB64_decrypt(&ctx, NULL, 3));
    munit_assert_int(TC_OK, ==, TC_DES_CFB64_encrypt(&ctx, NULL, 0));
#endif
#if TC_DES_ENABLE_CFB8
    munit_assert_int(TC_ERROR, ==, TC_DES_CFB8_encrypt(&ctx, NULL, 1));
    munit_assert_int(TC_ERROR, ==, TC_DES_CFB8_decrypt(&ctx, NULL, 1));
    munit_assert_int(TC_OK, ==, TC_DES_CFB8_decrypt(&ctx, NULL, 0));
#endif
#if TC_DES_ENABLE_CFB1
    munit_assert_int(TC_ERROR, ==, TC_DES_CFB1_encrypt(&ctx, NULL, 1));
    munit_assert_int(TC_ERROR, ==, TC_DES_CFB1_decrypt(&ctx, NULL, 1));
    munit_assert_int(TC_OK, ==, TC_DES_CFB1_encrypt(&ctx, NULL, 0));
#endif
#if TC_DES_ENABLE_OFB
    munit_assert_int(TC_ERROR, ==, TC_DES_OFB_crypt(&ctx, NULL, 1));
    munit_assert_int(TC_OK, ==, TC_DES_OFB_crypt(&ctx, NULL, 0));
#endif
    assert_des_ctx_equal(&ctx, &saved);
    TC_DES_ctx_clear(&ctx);
  }
  return MUNIT_OK;
}

typedef TC_status (*des_mode_fn)(struct TC_DES_ctx* ctx, uint8_t* buf, size_t length);

/* A buffer that overlaps the context would overwrite the subkeys or the
 * feedback register while the mode reads them. Each mode rejects it and
 * leaves the context and the neighbouring bytes unchanged. length is in the
 * mode's unit and touches bytes bytes, at most TC_DES_BLOCKLEN. */
static void check_des_mode_overlap(des_mode_fn mode, size_t length, size_t bytes)
{
  static const uint8_t iv[TC_DES_BLOCKLEN] = {1, 2, 3, 4, 5, 6, 7, 8};
  struct {
    uint8_t before[TC_DES_BLOCKLEN];
    struct TC_DES_ctx ctx;
  } frame;
  struct TC_DES_ctx saved;
  uint8_t before[TC_DES_BLOCKLEN];
  /* The last span ends on the first context byte. */
  uint8_t* const inside[] = {frame.ctx.Iv, frame.ctx.schedule[0],
                             frame.before + sizeof frame.before + 1 - bytes};
  size_t i;

  munit_assert_int(TC_OK, ==, TC_DES_init_ctx_iv(&frame.ctx, des_test_key, TC_DES_KEYLEN, iv));
  memset(frame.before, 0x5a, sizeof frame.before);
  memcpy(before, frame.before, sizeof before);
  memcpy(&saved, &frame.ctx, sizeof saved);
  for (i = 0; i < sizeof inside / sizeof inside[0]; ++i) {
    munit_assert_int(TC_ERROR, ==, mode(&frame.ctx, inside[i], length));
    assert_des_ctx_equal(&frame.ctx, &saved);
    munit_assert_memory_equal(sizeof before, frame.before, before);
  }
  TC_DES_ctx_clear(&frame.ctx);
}

static MunitResult test_des_mode_overlap(const MunitParameter params[], void* data)
{
  static const uint8_t iv[TC_DES_BLOCKLEN] = {8, 7, 6, 5, 4, 3, 2, 1};
  struct TC_DES_ctx ctx;
  struct TC_DES_ctx saved;
  (void)params;
  (void)data;
#if TC_DES_ENABLE_CBC
  check_des_mode_overlap(TC_DES_CBC_encrypt, TC_DES_BLOCKLEN, TC_DES_BLOCKLEN);
  check_des_mode_overlap(TC_DES_CBC_decrypt, TC_DES_BLOCKLEN, TC_DES_BLOCKLEN);
#endif
#if TC_DES_ENABLE_CTR
  check_des_mode_overlap(TC_DES_CTR_crypt, 1, 1);
  check_des_mode_overlap(TC_DES_CTR_crypt, TC_DES_BLOCKLEN, TC_DES_BLOCKLEN);
#endif
#if TC_DES_ENABLE_CFB64
  check_des_mode_overlap(TC_DES_CFB64_encrypt, TC_DES_BLOCKLEN, TC_DES_BLOCKLEN);
  check_des_mode_overlap(TC_DES_CFB64_decrypt, 3, 3);
#endif
#if TC_DES_ENABLE_CFB8
  check_des_mode_overlap(TC_DES_CFB8_encrypt, 1, 1);
  check_des_mode_overlap(TC_DES_CFB8_decrypt, TC_DES_BLOCKLEN, TC_DES_BLOCKLEN);
#endif
#if TC_DES_ENABLE_CFB1
  /* CFB1 lengths count bits. 57 bits touch 8 bytes. */
  check_des_mode_overlap(TC_DES_CFB1_encrypt, 1, 1);
  check_des_mode_overlap(TC_DES_CFB1_decrypt, 57, 8);
#endif
#if TC_DES_ENABLE_OFB
  check_des_mode_overlap(TC_DES_OFB_crypt, 1, 1);
  check_des_mode_overlap(TC_DES_OFB_crypt, TC_DES_BLOCKLEN, TC_DES_BLOCKLEN);
#endif

  /* set_iv copies into ctx->Iv. A source inside the context would be an
   * overlapping memcpy or would copy subkey bytes into the IV. */
  munit_assert_int(TC_OK, ==, TC_DES_init_ctx_iv(&ctx, des_test_key, TC_DES_KEYLEN, iv));
  memcpy(&saved, &ctx, sizeof saved);
  munit_assert_int(TC_ERROR, ==, TC_DES_ctx_set_iv(&ctx, ctx.Iv));
  munit_assert_int(TC_ERROR, ==, TC_DES_ctx_set_iv(&ctx, ctx.Iv + 1));
  munit_assert_int(TC_ERROR, ==, TC_DES_ctx_set_iv(&ctx, ctx.schedule[0]));
#if TC_DES_ENABLE_ECB
  munit_assert_int(TC_ERROR, ==, TC_DES_ECB_encrypt(&ctx, ctx.schedule[1]));
  munit_assert_int(TC_ERROR, ==, TC_DES_ECB_decrypt(&ctx, ctx.Iv));
#endif
  assert_des_ctx_equal(&ctx, &saved);
  TC_DES_ctx_clear(&ctx);
  return MUNIT_OK;
}
#endif

#if TC_DES_ENABLE_CMAC
/* Message or tag bytes inside a MAC context change while the MAC runs, and a
 * tag inside it is wiped when final clears the context. */
static MunitResult test_des_cmac_overlap(const MunitParameter params[], void* data)
{
  /* after gives a tag that straddles the context end its storage. */
  struct {
    struct TC_DES_CMAC_ctx ctx;
    uint8_t after[TC_DES_CMAC_TAG_MAX];
  } frame;
  struct TC_DES_CMAC_ctx* const ctx = &frame.ctx;
  uint8_t tag[TC_DES_CMAC_TAG_MAX];
  uint8_t saved_mac[TC_DES_BLOCKLEN];
  uint8_t saved_buf[TC_DES_BLOCKLEN];
  (void)params;
  (void)data;
  munit_assert_int(TC_OK, ==, TC_DES_CMAC_init(ctx, des_test_key, TC_DES_KEYLEN));
  munit_assert_int(TC_OK, ==, TC_DES_CMAC_update(ctx, cmac_kat_msg, 3));
  memcpy(saved_mac, ctx->mac, sizeof saved_mac);
  memcpy(saved_buf, ctx->buf, sizeof saved_buf);
  munit_assert_int(TC_ERROR, ==, TC_DES_CMAC_update(ctx, ctx->buf, 1));
  munit_assert_int(TC_ERROR, ==, TC_DES_CMAC_update(ctx, ctx->k1, sizeof ctx->k1));
  munit_assert_int(TC_ERROR, ==, TC_DES_CMAC_final(ctx, ctx->mac));
  munit_assert_int(TC_ERROR, ==, TC_DES_CMAC_final(ctx, (uint8_t*)&frame + sizeof frame.ctx - 1));
  munit_assert_memory_equal(sizeof saved_mac, ctx->mac, saved_mac);
  munit_assert_memory_equal(sizeof saved_buf, ctx->buf, saved_buf);
  munit_assert_uint8(ctx->buf_len, ==, 3);
  munit_assert_uint8(ctx->active, ==, 1);
  munit_assert_int(TC_OK, ==, TC_DES_CMAC_final(ctx, tag));
  return MUNIT_OK;
}
#endif

#if TC_DES_ENABLE_ISO9797
static MunitResult test_des_iso9797_overlap(const MunitParameter params[], void* data)
{
  static const uint8_t message[] = "Now is the time for all ";
  /* after gives a tag that straddles the context end its storage. */
  struct {
    struct TC_DES_ISO9797_ctx ctx;
    uint8_t after[TC_DES_BLOCKLEN];
  } frame;
  struct TC_DES_ISO9797_ctx* const ctx = &frame.ctx;
  uint8_t tag[TC_DES_BLOCKLEN];
  uint8_t saved_mac[TC_DES_BLOCKLEN];
  uint8_t saved_buf[TC_DES_BLOCKLEN];
  (void)params;
  (void)data;
  munit_assert_int(TC_OK, ==,
                   TC_DES_ISO9797_init(ctx, TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, tdes2_key,
                                       TC_DES_KEYLEN_2KEY));
  munit_assert_int(TC_OK, ==, TC_DES_ISO9797_update(ctx, message, 3));
  memcpy(saved_mac, ctx->mac, sizeof saved_mac);
  memcpy(saved_buf, ctx->buf, sizeof saved_buf);
  munit_assert_int(TC_ERROR, ==, TC_DES_ISO9797_update(ctx, ctx->buf, 1));
  munit_assert_int(TC_ERROR, ==, TC_DES_ISO9797_update(ctx, ctx->keys.schedule[0], 6));
  munit_assert_int(TC_ERROR, ==, TC_DES_ISO9797_final(ctx, ctx->mac));
  munit_assert_int(TC_ERROR, ==,
                   TC_DES_ISO9797_final(ctx, (uint8_t*)&frame + sizeof frame.ctx - 1));
  munit_assert_memory_equal(sizeof saved_mac, ctx->mac, saved_mac);
  munit_assert_memory_equal(sizeof saved_buf, ctx->buf, saved_buf);
  munit_assert_uint8(ctx->used, ==, 3);
  munit_assert_uint8(ctx->active, ==, 1);
  munit_assert_int(TC_OK, ==, TC_DES_ISO9797_final(ctx, tag));
  return MUNIT_OK;
}
#endif

/* Secure wipe / context clear tests */
static MunitResult test_des_secure_zero_and_clear(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;

  uint8_t buf[16];
  struct TC_DES_ctx ctx;
  size_t i;

  for (i = 0; i < sizeof(buf); ++i)
    buf[i] = (uint8_t)(0xA5U + (uint8_t)i);

  TC_secure_zero(buf, sizeof(buf));
  for (i = 0; i < sizeof(buf); ++i)
    munit_assert_uint8(buf[i], ==, 0);

  TC_DES_init_ctx(&ctx, des_test_key, TC_DES_KEYLEN);
  /* Subkey material should be non-zero after init for this KAT key. */
  munit_assert_int(ctx.schedule[0][0] != 0 || ctx.schedule[0][1] != 0, ==, 1);

  TC_DES_ctx_clear(&ctx);
  {
    const uint8_t* p = (const uint8_t*)&ctx;
    for (i = 0; i < sizeof(ctx); ++i)
      munit_assert_uint8(p[i], ==, 0);
  }

  TC_DES_ctx_clear(NULL); /* NULL is a no-op */

#if TC_DES_ENABLE_TDES
  {
    struct TC_DES_ctx tctx;
    TC_DES_init_ctx(&tctx, tdes3_key, 24);
    TC_DES_ctx_clear(&tctx);
    {
      const uint8_t* p = (const uint8_t*)&tctx;
      for (i = 0; i < sizeof(tctx); ++i)
        munit_assert_uint8(p[i], ==, 0);
    }
  }
#endif

  munit_assert_int(TC_OK, ==, 0);
  munit_assert_int(TC_ERROR, ==, -1);

  return MUNIT_OK;
}

/* --- Test Suite Setup --- */

#if TC_DES_ENABLE_CBC && TC_DES_ENABLE_ISO9797
#include "../vectors/des/iso9797/annex_b_algorithm1.h"
static MunitResult test_iso9797_annex_b_algorithm1(const MunitParameter params[], void* data)
{
  static const uint8_t key[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
  static const uint8_t zero_iv[8] = {0};
  (void)params;
  (void)data;
  for (size_t i = 0; i < sizeof iso9797_annex_b_alg1 / sizeof iso9797_annex_b_alg1[0]; ++i) {
    uint8_t blocks[32] = {0};
    struct TC_DES_ctx ctx;
    size_t offset = iso9797_annex_b_alg1[i].padding == 3 ? 8 : 0;
    size_t length =
        iso9797_annex_b_alg1[i].padding == 3 || (iso9797_annex_b_alg1[i].padding == 2 &&
                                                 iso9797_annex_b_alg1[i].message_length == 24)
            ? 32
            : 24;
    if (offset)
      blocks[7] = (uint8_t)(iso9797_annex_b_alg1[i].message_length * 8);
    memcpy(blocks + offset, iso9797_annex_b_alg1[i].message,
           iso9797_annex_b_alg1[i].message_length);
    if (iso9797_annex_b_alg1[i].padding == 2)
      blocks[offset + iso9797_annex_b_alg1[i].message_length] = 0x80;
    munit_assert_int(TC_DES_init_ctx_iv(&ctx, key, TC_DES_KEYLEN, zero_iv), ==, TC_OK);
    munit_assert_int(TC_DES_CBC_encrypt(&ctx, blocks, length), ==, TC_OK);
    munit_assert_memory_equal(8, blocks + length - 8, iso9797_annex_b_alg1[i].chaining_value);
    TC_DES_ctx_clear(&ctx);
  }
  return MUNIT_OK;
}
#endif

#if TC_DES_ENABLE_ISO9797
static const uint8_t iso9797_key3[24] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                         0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
                                         0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
/* ISO/IEC 9797-1 has no three-key examples. test_iso9797_three_key_reference
 * rederives both tags from DES-CBC and DES-ECB. */
static const uint8_t alg1_3key_pad1[8] = {0x44, 0x07, 0xa0, 0x1f, 0xa8, 0x7c, 0x18, 0xe2};
static const uint8_t alg3_3key_pad2[8] = {0x5c, 0xcd, 0x8f, 0x7a, 0x05, 0xc8, 0x05, 0x22};
#endif

#if TC_DES_ENABLE_ISO9797 && TC_DES_ENABLE_CBC && TC_DES_ENABLE_ECB
/* Reference MAC from the mode API: pad, run CBC with a zero IV under the TDEA
 * bundle (Algorithm 1) or K1 (Algorithm 3), then apply D(K2) and E(K3 or K1)
 * for Algorithm 3. msg_len is at most 32 bytes. */
static void iso9797_reference_mac(TC_DES_ISO9797_algorithm algorithm,
                                  TC_DES_ISO9797_padding padding, const uint8_t* key, size_t keylen,
                                  const uint8_t* msg, size_t msg_len, uint8_t out[TC_DES_BLOCKLEN])
{
  static const uint8_t zero_iv[TC_DES_BLOCKLEN] = {0};
  uint8_t blocks[40] = {0};
  size_t padded = msg_len;
  struct TC_DES_ctx ctx;

  munit_assert_size(msg_len, <=, 32);
  if (msg_len != 0)
    memcpy(blocks, msg, msg_len);
  if (padding == TC_DES_ISO9797_PAD2)
    blocks[padded++] = 0x80;
  padded = padded == 0 ? TC_DES_BLOCKLEN : (padded + 7u) / 8u * 8u;

  munit_assert_int(TC_DES_init_ctx_iv(&ctx, key,
                                      algorithm == TC_DES_ISO9797_ALG1 ? keylen : TC_DES_KEYLEN,
                                      zero_iv),
                   ==, TC_OK);
  munit_assert_int(TC_DES_CBC_encrypt(&ctx, blocks, padded), ==, TC_OK);
  memcpy(out, blocks + padded - TC_DES_BLOCKLEN, TC_DES_BLOCKLEN);
  if (algorithm == TC_DES_ISO9797_ALG3) {
    munit_assert_int(TC_DES_init_ctx(&ctx, key + TC_DES_KEYLEN, TC_DES_KEYLEN), ==, TC_OK);
    munit_assert_int(TC_DES_ECB_decrypt(&ctx, out), ==, TC_OK);
    munit_assert_int(TC_DES_init_ctx(&ctx,
                                     keylen == TC_DES_KEYLEN_3KEY ? key + TC_DES_KEYLEN_2KEY : key,
                                     TC_DES_KEYLEN),
                     ==, TC_OK);
    munit_assert_int(TC_DES_ECB_encrypt(&ctx, out), ==, TC_OK);
  }
  TC_DES_ctx_clear(&ctx);
}

static MunitResult test_iso9797_three_key_reference(const MunitParameter params[], void* data)
{
  static const uint8_t msg[] = "Now is the time for all ";
  static const TC_DES_ISO9797_padding paddings[] = {TC_DES_ISO9797_PAD1, TC_DES_ISO9797_PAD2};
  static const size_t lengths[] = {0, 1, 7, 8, 15, 22, 24};
  uint8_t expected[8], tag[8];
  size_t p, l, a;
  (void)params;
  (void)data;

  iso9797_reference_mac(TC_DES_ISO9797_ALG1, TC_DES_ISO9797_PAD1, iso9797_key3, sizeof iso9797_key3,
                        msg, sizeof msg - 2, expected);
  munit_assert_memory_equal(8, expected, alg1_3key_pad1);
  iso9797_reference_mac(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, iso9797_key3, sizeof iso9797_key3,
                        msg, sizeof msg - 2, expected);
  munit_assert_memory_equal(8, expected, alg3_3key_pad2);

  for (a = 0; a < 2; ++a) {
    const TC_DES_ISO9797_algorithm algorithm = a ? TC_DES_ISO9797_ALG3 : TC_DES_ISO9797_ALG1;
    for (p = 0; p < 2; ++p) {
      for (l = 0; l < sizeof lengths / sizeof lengths[0]; ++l) {
        iso9797_reference_mac(algorithm, paddings[p], iso9797_key3, sizeof iso9797_key3, msg,
                              lengths[l], expected);
        munit_assert_int(TC_DES_ISO9797_MAC(algorithm, paddings[p], iso9797_key3,
                                            sizeof iso9797_key3, msg, lengths[l], tag, sizeof tag),
                         ==, TC_OK);
        munit_assert_memory_equal(8, tag, expected);
      }
    }
  }
  return MUNIT_OK;
}
#endif

#if TC_DES_ENABLE_ISO9797
/* Three-key Algorithm 3: streaming equals one-shot, verify and argument
 * failures, and the two-key special case K3 = K1. */
static MunitResult test_iso9797_three_key_api(const MunitParameter params[], void* data)
{
  static const uint8_t msg[] = "Now is the time for all ";
  static const TC_DES_ISO9797_padding paddings[] = {TC_DES_ISO9797_PAD_NONE, TC_DES_ISO9797_PAD1,
                                                    TC_DES_ISO9797_PAD2};
  struct TC_DES_ISO9797_ctx ctx;
  uint8_t key_k3_is_k1[24];
  uint8_t oneshot[8], streamed[8], two_key[8], guard[8];
  size_t p, i;
  (void)params;
  (void)data;

  for (p = 0; p < 3; ++p) {
    const size_t len = paddings[p] == TC_DES_ISO9797_PAD_NONE ? 24 : 22;
    munit_assert_int(TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG3, paddings[p], iso9797_key3,
                                        sizeof iso9797_key3, msg, len, oneshot, sizeof oneshot),
                     ==, TC_OK);
    munit_assert_int(TC_DES_ISO9797_init(&ctx, TC_DES_ISO9797_ALG3, paddings[p], iso9797_key3,
                                         sizeof iso9797_key3),
                     ==, TC_OK);
    for (i = 0; i < len; ++i)
      munit_assert_int(TC_DES_ISO9797_update(&ctx, msg + i, 1), ==, TC_OK);
    munit_assert_int(TC_DES_ISO9797_final(&ctx, streamed), ==, TC_OK);
    munit_assert_memory_equal(8, streamed, oneshot);
    munit_assert_uint8(ctx.active, ==, 0);

    munit_assert_int(TC_DES_ISO9797_verify(TC_DES_ISO9797_ALG3, paddings[p], iso9797_key3,
                                           sizeof iso9797_key3, msg, len, oneshot, 8),
                     ==, TC_OK);
    streamed[7] ^= 0x01u;
    munit_assert_int(TC_DES_ISO9797_verify(TC_DES_ISO9797_ALG3, paddings[p], iso9797_key3,
                                           sizeof iso9797_key3, msg, len, streamed, 8),
                     ==, TC_MISMATCH);
    munit_assert_int(TC_DES_ISO9797_verify_short_tag(TC_DES_ISO9797_ALG3, paddings[p], iso9797_key3,
                                                     sizeof iso9797_key3, msg, len, oneshot, 4),
                     ==, TC_OK);
  }

  /* With K3 = K1 the three-key form equals the two-key Algorithm 3. */
  memcpy(key_k3_is_k1, iso9797_key3, 16);
  memcpy(key_k3_is_k1 + 16, iso9797_key3, 8);
  munit_assert_int(TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, key_k3_is_k1,
                                      sizeof key_k3_is_k1, msg, 22, oneshot, sizeof oneshot),
                   ==, TC_OK);
  munit_assert_int(TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, iso9797_key3, 16,
                                      msg, 22, two_key, sizeof two_key),
                   ==, TC_OK);
  munit_assert_memory_equal(8, oneshot, two_key);

  /* Argument errors return TC_ERROR and leave the tag untouched. */
  memset(guard, 0xa5, sizeof guard);
  munit_assert_int(TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, NULL, 24, msg, 22,
                                      guard, sizeof guard),
                   ==, TC_ERROR);
  munit_assert_int(TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG3, (TC_DES_ISO9797_padding)3, iso9797_key3,
                                      sizeof iso9797_key3, msg, 22, guard, sizeof guard),
                   ==, TC_ERROR);
  munit_assert_int(TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, iso9797_key3, 23,
                                      msg, 22, guard, sizeof guard),
                   ==, TC_ERROR);
  munit_assert_int(TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, iso9797_key3,
                                      sizeof iso9797_key3, msg, 22, guard, 7),
                   ==, TC_ERROR);
  munit_assert_int(TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, iso9797_key3,
                                      sizeof iso9797_key3, msg, 22, guard, 9),
                   ==, TC_ERROR);
  for (i = 0; i < sizeof guard; ++i)
    munit_assert_uint8(guard[i], ==, 0xa5);
  munit_assert_int(TC_DES_ISO9797_verify(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, iso9797_key3,
                                         sizeof iso9797_key3, msg, 22, oneshot, 7),
                   ==, TC_ERROR);
  munit_assert_int(TC_DES_ISO9797_verify(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, iso9797_key3,
                                         sizeof iso9797_key3, msg, 22, oneshot, 9),
                   ==, TC_ERROR);
  munit_assert_int(TC_DES_ISO9797_verify(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, NULL, 24, msg,
                                         22, oneshot, 8),
                   ==, TC_ERROR);
  /* A failed re-init of a keyed context wipes the earlier key schedule. */
  munit_assert_int(TC_DES_ISO9797_init(&ctx, TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, iso9797_key3,
                                       sizeof iso9797_key3),
                   ==, TC_OK);
  munit_assert_int(TC_DES_ISO9797_update(&ctx, msg, 8), ==, TC_OK);
  munit_assert_int(TC_DES_ISO9797_init(&ctx, TC_DES_ISO9797_ALG3, (TC_DES_ISO9797_padding)3,
                                       iso9797_key3, sizeof iso9797_key3),
                   ==, TC_ERROR);
  munit_assert_uint8(ctx.active, ==, 0);
  for (i = 0; i < sizeof ctx.keys.schedule; ++i)
    munit_assert_uint8(((const uint8_t*)ctx.keys.schedule)[i], ==, 0);
  for (i = 0; i < sizeof ctx.mac; ++i)
    munit_assert_uint8(ctx.mac[i], ==, 0);
  munit_assert_int(TC_DES_ISO9797_update(&ctx, msg, 8), ==, TC_ERROR);
  munit_assert_int(TC_DES_ISO9797_final(&ctx, guard), ==, TC_ERROR);
  munit_assert_int(TC_DES_ISO9797_init(NULL, TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, iso9797_key3,
                                       sizeof iso9797_key3),
                   ==, TC_ERROR);
  return MUNIT_OK;
}
#endif

#if TC_DES_ENABLE_ISO9797
static MunitResult test_des_iso9797(const MunitParameter params[], void* data)
{
  static const uint8_t key2[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                   0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
  static const uint8_t msg[] = "Now is the time for all ";
  static const uint8_t msg2[] = "Now is the time for it";
  static const uint8_t retail_none[8] = {0xa1, 0xc7, 0x2e, 0x74, 0xea, 0x3f, 0xa9, 0xb6};
  static const uint8_t retail_pad2[8] = {0xe9, 0x08, 0x62, 0x30, 0xca, 0x3b, 0xe7, 0x96};
  static const uint8_t annex_b_msg2_pad1[8] = {0x2e, 0x2b, 0x14, 0x28, 0xcc, 0x78, 0x25, 0x4f};
  static const uint8_t annex_b_msg2_pad2[8] = {0x5a, 0x69, 0x2c, 0xe6, 0x4f, 0x40, 0x41, 0x45};
  struct TC_DES_ISO9797_ctx ctx;
  uint8_t tag[8];
  uint8_t guard[8];
  size_t i;
  (void)params;
  (void)data;

  /* ISO/IEC 9797-1:2011 Annex B.4 gives these Algorithm 3 tags. */
  munit_assert_int(TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD_NONE, key2,
                                      sizeof key2, msg, sizeof msg - 1, tag, sizeof tag),
                   ==, TC_OK);
  munit_assert_memory_equal(8, tag, retail_none);
  munit_assert_int(TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, key2, sizeof key2,
                                      msg, sizeof msg - 1, tag, sizeof tag),
                   ==, TC_OK);
  munit_assert_memory_equal(8, tag, retail_pad2);
  munit_assert_int(TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD1, key2, sizeof key2,
                                      msg2, sizeof msg2 - 1, tag, sizeof tag),
                   ==, TC_OK);
  munit_assert_memory_equal(8, tag, annex_b_msg2_pad1);
  munit_assert_int(TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, key2, sizeof key2,
                                      msg2, sizeof msg2 - 1, tag, sizeof tag),
                   ==, TC_OK);
  munit_assert_memory_equal(8, tag, annex_b_msg2_pad2);
  munit_assert_int(TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG1, TC_DES_ISO9797_PAD1, iso9797_key3,
                                      sizeof iso9797_key3, msg, sizeof msg - 2, tag, sizeof tag),
                   ==, TC_OK);
  munit_assert_memory_equal(8, tag, alg1_3key_pad1);
  munit_assert_int(TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, iso9797_key3,
                                      sizeof iso9797_key3, msg, sizeof msg - 2, tag, sizeof tag),
                   ==, TC_OK);
  munit_assert_memory_equal(8, tag, alg3_3key_pad2);

  munit_assert_int(
      TC_DES_ISO9797_init(&ctx, TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, key2, sizeof key2), ==,
      TC_OK);
  for (i = 0; i < sizeof msg - 1; ++i)
    munit_assert_int(TC_DES_ISO9797_update(&ctx, msg + i, 1), ==, TC_OK);
  munit_assert_int(TC_DES_ISO9797_update(&ctx, NULL, 0), ==, TC_OK);
  munit_assert_int(TC_DES_ISO9797_final(&ctx, tag), ==, TC_OK);
  munit_assert_memory_equal(8, tag, retail_pad2);
  munit_assert_int(TC_DES_ISO9797_update(&ctx, msg, 1), ==, TC_ERROR);
  munit_assert_int(TC_DES_ISO9797_final(&ctx, tag), ==, TC_ERROR);

  memset(guard, 0xa5, sizeof guard);
  munit_assert_int(TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD_NONE, key2,
                                      sizeof key2, msg, 3, guard, sizeof guard),
                   ==, TC_ERROR);
  for (i = 0; i < sizeof guard; ++i)
    munit_assert_uint8(guard[i], ==, 0xa5);
  munit_assert_int(
      TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, key2, 8, msg, 8, guard, 8), ==,
      TC_ERROR);
  munit_assert_int(TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG1, TC_DES_ISO9797_PAD2, key2, sizeof key2,
                                      NULL, 1, guard, 8),
                   ==, TC_ERROR);
  munit_assert_int(TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, key2, sizeof key2,
                                      msg, 8, guard, 3),
                   ==, TC_ERROR);
  munit_assert_int(TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG1, TC_DES_ISO9797_PAD_NONE, key2,
                                      sizeof key2, NULL, 0, guard, 8),
                   ==, TC_ERROR);
  munit_assert_int(TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD1, key2, sizeof key2,
                                      NULL, 0, guard, 8),
                   ==, TC_OK);
  munit_assert_int(TC_DES_ISO9797_verify(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD1, key2,
                                         sizeof key2, NULL, 0, guard, 8),
                   ==, TC_OK);
  munit_assert_int(
      TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG1, TC_DES_ISO9797_PAD2, key2, 8, msg, 8, guard, 8), ==,
      TC_ERROR);
  munit_assert_int(TC_DES_ISO9797_init(&ctx, (TC_DES_ISO9797_algorithm)2, TC_DES_ISO9797_PAD2, key2,
                                       sizeof key2),
                   ==, TC_ERROR);
  munit_assert_int(
      TC_DES_ISO9797_init(&ctx, TC_DES_ISO9797_ALG3, (TC_DES_ISO9797_padding)3, key2, sizeof key2),
      ==, TC_ERROR);
  munit_assert_int(
      TC_DES_ISO9797_init(&ctx, TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, key2, sizeof key2), ==,
      TC_OK);
  munit_assert_int(TC_DES_ISO9797_update(&ctx, NULL, 1), ==, TC_ERROR);
  TC_DES_ISO9797_clear(&ctx);
  munit_assert_int(TC_DES_ISO9797_verify(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD_NONE, key2,
                                         sizeof key2, msg, sizeof msg - 1, retail_none, 4),
                   ==, TC_ERROR);
  munit_assert_int(TC_DES_ISO9797_verify_short_tag(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD_NONE,
                                                   key2, sizeof key2, msg, sizeof msg - 1,
                                                   retail_none, 4),
                   ==, TC_OK);
  munit_assert_int(TC_DES_ISO9797_MAC(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD_NONE, key2,
                                      sizeof key2, msg, sizeof msg - 1, tag, 4),
                   ==, TC_ERROR);
  munit_assert_int(TC_DES_ISO9797_MAC_short_tag(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD_NONE, key2,
                                                sizeof key2, msg, sizeof msg - 1, tag, 4),
                   ==, TC_OK);
  munit_assert_memory_equal(4, tag, retail_none);
  tag[0] = (uint8_t)(retail_none[0] ^ 1);
  memcpy(tag + 1, retail_none + 1, 7);
  munit_assert_int(TC_DES_ISO9797_verify(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD_NONE, key2,
                                         sizeof key2, msg, sizeof msg - 1, tag, 8),
                   ==, TC_MISMATCH);
  return MUNIT_OK;
}
#endif

static MunitTest test_suite_tests[] = {
#if TC_DES_ENABLE_ECB
    {"/des_ecb", test_des_ecb, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
#if TC_DES_ENABLE_CBC
    {"/des_cbc", test_des_cbc, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
#if TC_DES_ENABLE_CTR
    {"/des_ctr", test_des_ctr, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/des_ctr_exhaustion", test_des_ctr_exhaustion, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
#if TC_DES_ENABLE_TDES && TC_DES_ENABLE_ECB
    {"/tdes2_ecb", test_tdes2_ecb, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/tdes3_ecb", test_tdes3_ecb, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
#if TC_DES_ENABLE_TDES && TC_DES_ENABLE_CBC
    {"/tdes2_cbc", test_tdes2_cbc, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/tdes3_cbc", test_tdes3_cbc, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
#if TC_DES_ENABLE_TDES && TC_DES_ENABLE_CTR
    {"/tdes2_ctr", test_tdes2_ctr, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/tdes3_ctr", test_tdes3_ctr, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
#if TC_DES_ENABLE_OFB
    {"/des_ofb", test_des_ofb, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
#if TC_DES_ENABLE_CFB64
    {"/des_cfb64", test_des_cfb64, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/des_cfb64_short_segment", test_des_cfb64_short_segment, NULL, NULL, MUNIT_TEST_OPTION_NONE,
     NULL},
#endif
#if TC_DES_ENABLE_CFB8
    {"/des_cfb8", test_des_cfb8, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
#if TC_DES_ENABLE_CFB1
    {"/des_cfb1", test_des_cfb1, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
#if TC_DES_ENABLE_TDES &&                                                                          \
    (TC_DES_ENABLE_OFB || TC_DES_ENABLE_CFB64 || TC_DES_ENABLE_CFB8 || TC_DES_ENABLE_CFB1)
    {"/tdes3_feedback_modes", test_tdes3_feedback_modes, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/feedback_mode_chaining", test_feedback_mode_chaining, NULL, NULL, MUNIT_TEST_OPTION_NONE,
     NULL},
#endif
#if TC_DES_ENABLE_TDES && TC_DES_ENABLE_ECB
    {"/tdes_single_des_equiv", test_tdes_single_des_equivalence, NULL, NULL, MUNIT_TEST_OPTION_NONE,
     NULL},
#endif
#if TC_DES_ENABLE_CMAC
    {"/des_cmac", test_des_cmac, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/des_cmac_tag_policy", test_des_cmac_tag_policy, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/des_cmac_streaming", test_des_cmac_streaming, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/des_cmac_single_des_degenerate", test_des_cmac_single_des_matches_2k3des_degenerate, NULL,
     NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
#if TC_DES_ENABLE_ISO9797
    {"/des_iso9797", test_des_iso9797, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/des_iso9797_three_key", test_iso9797_three_key_api, NULL, NULL, MUNIT_TEST_OPTION_NONE,
     NULL},
#endif
#if TC_DES_ENABLE_ISO9797 && TC_DES_ENABLE_CBC && TC_DES_ENABLE_ECB
    {"/des_iso9797_three_key_reference", test_iso9797_three_key_reference, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
#endif
#if TC_DES_ENABLE_CBC && TC_DES_ENABLE_ISO9797
    {"/iso9797_annex_b_algorithm1", test_iso9797_annex_b_algorithm1, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
#endif
    {"/des_api_errors", test_des_api_errors, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#if TC_DES_ENABLE_CBC || TC_DES_ENABLE_CTR || TC_DES_ENABLE_OFB || TC_DES_ENABLE_CFB1 ||           \
    TC_DES_ENABLE_CFB8 || TC_DES_ENABLE_CFB64
    {"/des_null_buffers", test_des_null_buffers, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/des_mode_overlap", test_des_mode_overlap, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
#if TC_DES_ENABLE_CMAC
    {"/des_cmac_overlap", test_des_cmac_overlap, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
#if TC_DES_ENABLE_ISO9797
    {"/des_iso9797_overlap", test_des_iso9797_overlap, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
    {"/des_secure_zero_and_clear", test_des_secure_zero_and_clear, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
#if TC_DES_ENABLE_ECB && TC_DES_ENABLE_CBC && TC_DES_ENABLE_CFB1 && TC_DES_ENABLE_CFB8 &&          \
    TC_DES_ENABLE_CFB64 && TC_DES_ENABLE_OFB && TC_DES_ENABLE_TDES
    {"/edge_vectors", test_edge_vectors_suite, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
#endif
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};

static const MunitSuite test_suite = {"/tiny-des-c", test_suite_tests, NULL, 1,
                                      MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[])
{
  return munit_suite_main(&test_suite, NULL, argc, argv);
}
