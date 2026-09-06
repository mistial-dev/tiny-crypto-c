/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Unit tests for tiny-crypto-c using µunit (munit)
 * https://nemequ.github.io/munit/
 */

#include <stdio.h>
#include <string.h>
#include "munit.h"
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
  (void) params;
  (void) data;

  struct TC_DES_ctx ctx;
  uint8_t buffer[8];

  TC_DES_init_ctx(&ctx, des_test_key);

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
  (void) params;
  (void) data;

  struct TC_DES_ctx ctx;
  uint8_t buffer[8];

  /* KAT Encrypt */
  TC_DES_init_ctx_iv(&ctx, des_test_key, des_cbc_iv);
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
static MunitResult test_des_ctr(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  struct TC_DES_ctx ctx;
  uint8_t original[20] = "Hello DES CTR Mode!";
  uint8_t buffer[20];
  uint8_t known[sizeof(des_ctr_pt)];

  memcpy(known, des_ctr_pt, sizeof(known));
  munit_assert_int(TC_DES_init_ctx_iv(&ctx, des_test_key, des_ctr_iv), ==, TC_OK);
  munit_assert_int(TC_DES_CTR_crypt(&ctx, known, 5), ==, TC_OK);
  munit_assert_int(TC_DES_CTR_crypt(&ctx, known + 5, sizeof(known) - 5), ==, TC_OK);
  munit_assert_memory_equal(sizeof(known), known, des_ctr_ct);

  memcpy(buffer, original, 20);

  /* Encrypt */
  TC_DES_init_ctx_iv(&ctx, des_test_key, des_ctr_iv);
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
  (void) params;
  (void) data;

  struct TC_DES3_ctx ctx;
  uint8_t buffer[16];

  TC_DES3_init_ctx(&ctx, tdes2_key, 16);

  /* KAT Encrypt (2 blocks) */
  memcpy(buffer, tdes2_pt, 16);
  TC_DES3_ECB_encrypt(&ctx, buffer);
  TC_DES3_ECB_encrypt(&ctx, buffer + 8);
  munit_assert_memory_equal(16, buffer, tdes2_ecb_ct);

  /* KAT Decrypt (2 blocks) */
  memcpy(buffer, tdes2_ecb_ct, 16);
  TC_DES3_ECB_decrypt(&ctx, buffer);
  TC_DES3_ECB_decrypt(&ctx, buffer + 8);
  munit_assert_memory_equal(16, buffer, tdes2_pt);

  /* Round-Trip */
  TC_DES3_ECB_encrypt(&ctx, buffer);
  TC_DES3_ECB_encrypt(&ctx, buffer + 8);
  munit_assert_memory_equal(16, buffer, tdes2_ecb_ct);
  TC_DES3_ECB_decrypt(&ctx, buffer);
  TC_DES3_ECB_decrypt(&ctx, buffer + 8);
  munit_assert_memory_equal(16, buffer, tdes2_pt);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_TDES && TC_DES_ENABLE_ECB */

/* 2B. 2-Key 3DES CBC (KAT Encrypt, KAT Decrypt, & Round-Trip) */
#if TC_DES_ENABLE_TDES && TC_DES_ENABLE_CBC
static MunitResult test_tdes2_cbc(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  struct TC_DES3_ctx ctx;
  uint8_t buffer[16];

  /* KAT Encrypt */
  TC_DES3_init_ctx_iv(&ctx, tdes2_key, 16, des_cbc_iv);
  memcpy(buffer, tdes2_pt, 16);
  TC_DES3_CBC_encrypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes2_cbc_ct);

  /* KAT Decrypt */
  TC_DES3_ctx_set_iv(&ctx, des_cbc_iv);
  memcpy(buffer, tdes2_cbc_ct, 16);
  TC_DES3_CBC_decrypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes2_pt);

  /* Round-Trip */
  TC_DES3_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES3_CBC_encrypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes2_cbc_ct);
  TC_DES3_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES3_CBC_decrypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes2_pt);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_TDES && TC_DES_ENABLE_CBC */

/* 2C. 2-Key 3DES CTR Stream Mode */
#if TC_DES_ENABLE_TDES && TC_DES_ENABLE_CTR
static MunitResult test_tdes2_ctr(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  struct TC_DES3_ctx ctx;
  uint8_t original[24] = "Stream 2-Key 3DES Test!";
  uint8_t buffer[24];

  memcpy(buffer, original, 24);

  TC_DES3_init_ctx_iv(&ctx, tdes2_key, 16, des_ctr_iv);
  munit_assert_int(TC_DES3_CTR_crypt(&ctx, buffer, 5), ==, TC_OK);
  munit_assert_int(TC_DES3_CTR_crypt(&ctx, buffer + 5, 19), ==, TC_OK);
  munit_assert_memory_not_equal(24, buffer, original);

  TC_DES3_ctx_set_iv(&ctx, des_ctr_iv);
  munit_assert_int(TC_DES3_CTR_crypt(&ctx, buffer, 7), ==, TC_OK);
  munit_assert_int(TC_DES3_CTR_crypt(&ctx, buffer + 7, 17), ==, TC_OK);
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
  (void) params;
  (void) data;

  struct TC_DES3_ctx ctx;
  uint8_t buffer[16];

  TC_DES3_init_ctx(&ctx, tdes3_key, 24);

  /* KAT Encrypt (2 blocks) */
  memcpy(buffer, tdes3_pt, 16);
  TC_DES3_ECB_encrypt(&ctx, buffer);
  TC_DES3_ECB_encrypt(&ctx, buffer + 8);
  munit_assert_memory_equal(16, buffer, tdes3_ecb_ct);

  /* KAT Decrypt (2 blocks) */
  memcpy(buffer, tdes3_ecb_ct, 16);
  TC_DES3_ECB_decrypt(&ctx, buffer);
  TC_DES3_ECB_decrypt(&ctx, buffer + 8);
  munit_assert_memory_equal(16, buffer, tdes3_pt);

  /* Round-Trip */
  TC_DES3_ECB_encrypt(&ctx, buffer);
  TC_DES3_ECB_encrypt(&ctx, buffer + 8);
  munit_assert_memory_equal(16, buffer, tdes3_ecb_ct);
  TC_DES3_ECB_decrypt(&ctx, buffer);
  TC_DES3_ECB_decrypt(&ctx, buffer + 8);
  munit_assert_memory_equal(16, buffer, tdes3_pt);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_TDES && TC_DES_ENABLE_ECB */

/* 3B. 3-Key 3DES CBC (KAT Encrypt, KAT Decrypt, & Round-Trip) */
#if TC_DES_ENABLE_TDES && TC_DES_ENABLE_CBC
static MunitResult test_tdes3_cbc(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  struct TC_DES3_ctx ctx;
  uint8_t buffer[16];

  /* KAT Encrypt */
  TC_DES3_init_ctx_iv(&ctx, tdes3_key, 24, des_cbc_iv);
  memcpy(buffer, tdes3_pt, 16);
  TC_DES3_CBC_encrypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_cbc_ct);

  /* KAT Decrypt */
  TC_DES3_ctx_set_iv(&ctx, des_cbc_iv);
  memcpy(buffer, tdes3_cbc_ct, 16);
  TC_DES3_CBC_decrypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_pt);

  /* Round-Trip */
  TC_DES3_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES3_CBC_encrypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_cbc_ct);
  TC_DES3_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES3_CBC_decrypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_pt);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_TDES && TC_DES_ENABLE_CBC */

/* 3C. 3-Key 3DES CTR Stream Mode */
#if TC_DES_ENABLE_TDES && TC_DES_ENABLE_CTR
static MunitResult test_tdes3_ctr(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  struct TC_DES3_ctx ctx;
  uint8_t original[32] = "Stream 3-Key Triple-DES Test!12";
  uint8_t buffer[32];
  uint8_t known[sizeof(des_ctr_pt)];

  memcpy(known, des_ctr_pt, sizeof(known));
  munit_assert_int(TC_DES3_init_ctx_iv(&ctx, tdes3_key, sizeof(tdes3_key),
                                      des_ctr_iv), ==, TC_OK);
  munit_assert_int(TC_DES3_CTR_crypt(&ctx, known, sizeof(known)), ==, TC_OK);
  munit_assert_memory_equal(sizeof(known), known, tdes3_ctr_ct);

  memcpy(buffer, original, 32);

  TC_DES3_init_ctx_iv(&ctx, tdes3_key, 24, des_ctr_iv);
  munit_assert_int(TC_DES3_CTR_crypt(&ctx, buffer, 5), ==, TC_OK);
  munit_assert_int(TC_DES3_CTR_crypt(&ctx, buffer + 5, 27), ==, TC_OK);
  munit_assert_memory_not_equal(32, buffer, original);

  TC_DES3_ctx_set_iv(&ctx, des_ctr_iv);
  munit_assert_int(TC_DES3_CTR_crypt(&ctx, buffer, 7), ==, TC_OK);
  munit_assert_int(TC_DES3_CTR_crypt(&ctx, buffer + 7, 25), ==, TC_OK);
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
  (void) params;
  (void) data;

  struct TC_DES_ctx ctx;
  uint8_t buffer[8];

  /* KAT Encrypt */
  TC_DES_init_ctx_iv(&ctx, des_test_key, des_cbc_iv);
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
  (void) params;
  (void) data;

  struct TC_DES_ctx ctx;
  uint8_t buffer[8];

  TC_DES_init_ctx_iv(&ctx, des_test_key, des_cbc_iv);
  memcpy(buffer, des_test_pt, 8);
  TC_DES_CFB64_encrypt(&ctx, buffer, 8);
  munit_assert_memory_equal(8, buffer, des_cfb64_ct);

  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_CFB64_decrypt(&ctx, buffer, 8);
  munit_assert_memory_equal(8, buffer, des_test_pt);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_CFB64 */

/* 4C. Single DES CFB8 (KAT Encrypt, KAT Decrypt) */
#if TC_DES_ENABLE_CFB8
static MunitResult test_des_cfb8(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  struct TC_DES_ctx ctx;
  uint8_t buffer[8];

  TC_DES_init_ctx_iv(&ctx, des_test_key, des_cbc_iv);
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
  (void) params;
  (void) data;

  struct TC_DES_ctx ctx;

  /* TCFB1vartext.rsp COUNT 0: KEYs=0101010101010101 IV=8000000000000000 PT=0 -> CT=1 */
  const uint8_t weak_key[8] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
  const uint8_t iv0[8] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  const uint8_t iv2[8] = {0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  uint8_t bits[1];

  bits[0] = 0x00;
  TC_DES_init_ctx_iv(&ctx, weak_key, iv0);
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
  TC_DES_init_ctx_iv(&ctx, des_test_key, des_cbc_iv);
  TC_DES_CFB1_encrypt(&ctx, stream, 17);
  munit_assert_memory_not_equal(3, stream, original);
  TC_DES_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES_CFB1_decrypt(&ctx, stream, 17);
  munit_assert_memory_equal(3, stream, original);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_CFB1 */

/* 4E. 3-Key 3DES OFB / CFB64 / CFB8 (KAT + Decrypt) */
#if TC_DES_ENABLE_TDES && (TC_DES_ENABLE_OFB || TC_DES_ENABLE_CFB64 || TC_DES_ENABLE_CFB8 || TC_DES_ENABLE_CFB1)
static MunitResult test_tdes3_feedback_modes(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  struct TC_DES3_ctx ctx;
  uint8_t buffer[16];

  /* OFB */
  TC_DES3_init_ctx_iv(&ctx, tdes3_key, 24, des_cbc_iv);
  memcpy(buffer, tdes3_pt, 16);
  TC_DES3_OFB_crypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_ofb_ct);
  TC_DES3_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES3_OFB_crypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_pt);

  /* CFB64 */
  TC_DES3_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES3_CFB64_encrypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_cfb64_ct);
  TC_DES3_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES3_CFB64_decrypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_pt);

  /* CFB8 */
  TC_DES3_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES3_CFB8_encrypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_cfb8_ct);
  TC_DES3_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES3_CFB8_decrypt(&ctx, buffer, 16);
  munit_assert_memory_equal(16, buffer, tdes3_pt);

  /* CFB1 roundtrip (no host-generated KAT available; CAVP files cover KAT) */
  uint8_t stream[2] = {0x5a, 0xc0};
  uint8_t original[2];
  memcpy(original, stream, 2);
  TC_DES3_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES3_CFB1_encrypt(&ctx, stream, 10);
  TC_DES3_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES3_CFB1_decrypt(&ctx, stream, 10);
  munit_assert_memory_equal(2, stream, original);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_TDES && (TC_DES_ENABLE_OFB || TC_DES_ENABLE_CFB64 || TC_DES_ENABLE_CFB8 || TC_DES_ENABLE_CFB1) */

/* 4F. Cross-call chaining: split calls must equal one-shot output */
#if TC_DES_ENABLE_TDES && (TC_DES_ENABLE_OFB || TC_DES_ENABLE_CFB64 || TC_DES_ENABLE_CFB8 || TC_DES_ENABLE_CFB1)
static MunitResult test_feedback_mode_chaining(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  struct TC_DES3_ctx ctx;
  uint8_t oneshot[16];
  uint8_t split[16];

  /* CFB64 */
  memcpy(oneshot, tdes3_pt, 16);
  memcpy(split, tdes3_pt, 16);
  TC_DES3_init_ctx_iv(&ctx, tdes3_key, 24, des_cbc_iv);
  TC_DES3_CFB64_encrypt(&ctx, oneshot, 16);
  TC_DES3_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES3_CFB64_encrypt(&ctx, split, 8);
  TC_DES3_CFB64_encrypt(&ctx, split + 8, 8);
  munit_assert_memory_equal(16, split, oneshot);

  /* CFB8 */
  memcpy(oneshot, tdes3_pt, 16);
  memcpy(split, tdes3_pt, 16);
  TC_DES3_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES3_CFB8_encrypt(&ctx, oneshot, 16);
  TC_DES3_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES3_CFB8_encrypt(&ctx, split, 5);
  TC_DES3_CFB8_encrypt(&ctx, split + 5, 11);
  munit_assert_memory_equal(16, split, oneshot);

  /* OFB */
  memcpy(oneshot, tdes3_pt, 16);
  memcpy(split, tdes3_pt, 16);
  TC_DES3_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES3_OFB_crypt(&ctx, oneshot, 16);
  TC_DES3_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES3_OFB_crypt(&ctx, split, 3);
  TC_DES3_OFB_crypt(&ctx, split + 3, 13);
  munit_assert_memory_equal(16, split, oneshot);

  /* CFB1: 16 bits one-shot vs two 8-bit calls (split only on byte boundaries) */
  uint8_t bits_oneshot[2] = {0x96, 0x3d};
  uint8_t bits_split[2] = {0x96, 0x3d};
  TC_DES3_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES3_CFB1_encrypt(&ctx, bits_oneshot, 16);
  TC_DES3_ctx_set_iv(&ctx, des_cbc_iv);
  TC_DES3_CFB1_encrypt(&ctx, bits_split, 8);
  TC_DES3_CFB1_encrypt(&ctx, bits_split + 1, 8);
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
  (void) params;
  (void) data;

  struct TC_DES_ctx single_ctx;
  struct TC_DES3_ctx tdes_ctx;

  uint8_t key3[24];
  memcpy(key3, des_test_key, 8);
  memcpy(key3 + 8, des_test_key, 8);
  memcpy(key3 + 16, des_test_key, 8);

  TC_DES_init_ctx(&single_ctx, des_test_key);
  TC_DES3_init_ctx(&tdes_ctx, key3, 24);

  uint8_t buf_single[8];
  uint8_t buf_tdes[8];

  memcpy(buf_single, des_test_pt, 8);
  memcpy(buf_tdes, des_test_pt, 8);

  TC_DES_ECB_encrypt(&single_ctx, buf_single);
  TC_DES3_ECB_encrypt(&tdes_ctx, buf_tdes);

  munit_assert_memory_equal(8, buf_single, buf_tdes);
  munit_assert_memory_equal(8, buf_single, des_test_ct);

  /* Decryption Equivalence */
  TC_DES_ECB_decrypt(&single_ctx, buf_single);
  TC_DES3_ECB_decrypt(&tdes_ctx, buf_tdes);
  munit_assert_memory_equal(8, buf_single, buf_tdes);
  munit_assert_memory_equal(8, buf_single, des_test_pt);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_TDES && TC_DES_ENABLE_ECB */

#if TC_DES_ENABLE_CMAC
/* OpenSSL-cross-checked KATs (legacy des-cbc / des-ede-cbc / des-ede3-cbc). */
/* Keep this exact message paired with the checked-in known-answer tag. */
static const uint8_t cmac_kat_msg[] = "tiny-DES-c CMAC Test!";
static const uint8_t cmac_kat_des[8]   = {0x0a,0xa5,0xf5,0xff,0x35,0xe8,0x9f,0x6a};
static const uint8_t cmac_kat_tdes2[8] = {0x3c,0xc1,0x01,0x09,0xae,0x58,0xa5,0xa6};
static const uint8_t cmac_kat_tdes3[8] = {0xea,0x5e,0x07,0x9a,0xac,0x25,0x18,0xe9};
static const uint8_t cmac_kat_des_empty[8]   = {0x86,0xf7,0x9c,0x13,0xfd,0x30,0x6e,0x67};
static const uint8_t cmac_kat_tdes2_empty[8] = {0x79,0xce,0x52,0xa7,0xf7,0x86,0xa9,0x60};
static const uint8_t cmac_kat_tdes3_empty[8] = {0x7d,0xb0,0xd3,0x7d,0xf9,0x36,0xc5,0x50};

/* CMAC Tests (NIST SP 800-38B) */
static MunitResult test_des_cmac(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

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
  munit_assert_int(TC_MISMATCH, ==, TC_DES_CMAC_verify(tdes2_key, 16, cmac_kat_msg, msglen, bad, 8));

  munit_assert_int(TC_ERROR, ==, TC_DES_CMAC(des_test_key, 10, cmac_kat_msg, msglen, cmac1, 8));
  munit_assert_int(TC_ERROR, ==, TC_DES_CMAC(des_test_key, 8, cmac_kat_msg, msglen, cmac1, 0));

  return MUNIT_OK;
}

/* Streaming context must match the one-shot for every split pattern and
   key length, including an empty message and block-aligned messages. */
static MunitResult test_des_cmac_streaming(const MunitParameter params[], void* data)
{
  static const size_t lengths[] = { 0, 1, 7, 8, 9, 16, 21, 24, 50 };
  static const size_t splits[] = { 1, 7, 8, 9, 20 };
  const uint8_t* keys[3];
  size_t keylens[3];
  uint8_t msg[50];
  uint8_t expected[8], tag[8];
  struct TC_DES_CMAC_ctx ctx;
  size_t ki, li, si, i;

  (void) params;
  (void) data;

  keys[0] = des_test_key; keylens[0] = 8;
  keys[1] = tdes2_key;    keylens[1] = 16;
  keys[2] = tdes3_key;    keylens[2] = 24;
  for (i = 0; i < sizeof(msg); ++i)
    msg[i] = (uint8_t)(i * 13u + 5u);

  for (ki = 0; ki < 3; ++ki)
  {
    for (li = 0; li < sizeof(lengths) / sizeof(lengths[0]); ++li)
    {
      const size_t len = lengths[li];
      munit_assert_int(TC_OK, ==, TC_DES_CMAC(keys[ki], keylens[ki], msg, len, expected, 8));

      munit_assert_int(TC_OK, ==, TC_DES_CMAC_init(&ctx, keys[ki], keylens[ki]));
      munit_assert_int(TC_OK, ==, TC_DES_CMAC_update(&ctx, msg, len));
      munit_assert_int(TC_OK, ==, TC_DES_CMAC_final(&ctx, tag));
      munit_assert_memory_equal(8, tag, expected);

      for (si = 0; si < sizeof(splits) / sizeof(splits[0]); ++si)
      {
        size_t pos = 0;
        munit_assert_int(TC_OK, ==, TC_DES_CMAC_init(&ctx, keys[ki], keylens[ki]));
        while (pos < len)
        {
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
  TC_DES_CMAC_ctx_clear(NULL);

  return MUNIT_OK;
}

/* Degenerate Single-DES key (8 bytes) == 2-Key 3DES key with K1=K2 */
static MunitResult test_des_cmac_single_des_matches_2k3des_degenerate(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  uint8_t key8[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
  uint8_t key16[16] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
  };
  uint8_t message[8] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33};
  static const uint8_t expected[8] = {0x25,0xf8,0xaf,0xb2,0x45,0xd1,0x53,0x88};

  uint8_t mac8[8], mac16[8];
  munit_assert_int(TC_OK, ==, TC_DES_CMAC(key8, sizeof(key8), message, sizeof(message), mac8, 8));
  munit_assert_int(TC_OK, ==, TC_DES_CMAC(key16, sizeof(key16), message, sizeof(message), mac16, 8));
  munit_assert_memory_equal(8, mac8, mac16);
  munit_assert_memory_equal(8, mac8, expected);

  return MUNIT_OK;
}
#endif /* TC_DES_ENABLE_CMAC */

/* Negative classical API cases */
static MunitResult test_des_api_errors(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

#if TC_DES_ENABLE_CBC
  {
    struct TC_DES_ctx ctx;
    uint8_t buf[16] = {0};
    TC_DES_init_ctx_iv(&ctx, des_test_key, des_cbc_iv);
    munit_assert_int(TC_ERROR, ==, TC_DES_CBC_encrypt(&ctx, buf, 7));
    munit_assert_int(TC_ERROR, ==, TC_DES_CBC_decrypt(&ctx, buf, 1));
    munit_assert_int(TC_OK, ==, TC_DES_CBC_encrypt(&ctx, buf, 0));
  }
#endif

#if TC_DES_ENABLE_CTR
  {
    struct TC_DES_ctx ctx;
    uint8_t buf[16];
    uint8_t iv_max[8] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
    uint8_t iv_saved[8];
    memset(buf, 0x5a, sizeof(buf));
    TC_DES_init_ctx_iv(&ctx, des_test_key, iv_max);
    memcpy(iv_saved, ctx.Iv, 8);
    /* One block from all-ones wraps the counter after the block; one block OK. */
    munit_assert_int(TC_OK, ==, TC_DES_CTR_crypt(&ctx, buf, 8));
    /* Restore max IV and request two blocks: wrap mid-request. */
    TC_DES_ctx_set_iv(&ctx, iv_max);
    munit_assert_int(TC_ERROR, ==, TC_DES_CTR_crypt(&ctx, buf, 16));
    munit_assert_memory_equal(8, ctx.Iv, iv_max);
  }
#endif

#if TC_DES_ENABLE_TDES
  {
    struct TC_DES3_ctx ctx;
    uint8_t junk[24] = {0};
    munit_assert_int(TC_ERROR, ==, TC_DES3_init_ctx(&ctx, junk, 10));
    munit_assert_int(TC_ERROR, ==, TC_DES3_init_ctx(&ctx, junk, 0));
    munit_assert_int(TC_OK, ==, TC_DES3_init_ctx(&ctx, tdes2_key, 16));
    munit_assert_int(TC_OK, ==, TC_DES3_init_ctx(&ctx, tdes3_key, 24));
  }
#endif

  return MUNIT_OK;
}


/* Secure wipe / context clear tests */
static MunitResult test_des_secure_zero_and_clear(const MunitParameter params[], void* data)
{
  (void) params;
  (void) data;

  uint8_t buf[16];
  struct TC_DES_ctx ctx;
  size_t i;

  for (i = 0; i < sizeof(buf); ++i)
    buf[i] = (uint8_t)(0xA5U + (uint8_t)i);

  TC_secure_zero(buf, sizeof(buf));
  for (i = 0; i < sizeof(buf); ++i)
    munit_assert_uint8(buf[i], ==, 0);

  TC_DES_init_ctx(&ctx, des_test_key);
  /* Subkey material should be non-zero after init for this KAT key. */
  munit_assert_int(ctx.Sk[0][0] != 0 || ctx.Sk[0][1] != 0, ==, 1);

  TC_DES_ctx_clear(&ctx);
  {
    const uint8_t* p = (const uint8_t*)&ctx;
    for (i = 0; i < sizeof(ctx); ++i)
      munit_assert_uint8(p[i], ==, 0);
  }

  TC_DES_ctx_clear(NULL); /* must not crash */

#if TC_DES_ENABLE_TDES
  {
    struct TC_DES3_ctx tctx;
    TC_DES3_init_ctx(&tctx, tdes3_key, 24);
    TC_DES3_ctx_clear(&tctx);
    {
      const uint8_t* p = (const uint8_t*)&tctx;
      for (i = 0; i < sizeof(tctx); ++i)
        munit_assert_uint8(p[i], ==, 0);
    }
    TC_DES3_ctx_clear(NULL);
  }
#endif

  munit_assert_int(TC_OK, ==, 0);
  munit_assert_int(TC_ERROR, ==, -1);

  return MUNIT_OK;
}


/* --- Test Suite Setup --- */

static MunitTest test_suite_tests[] = {
#if TC_DES_ENABLE_ECB
  { "/des_ecb",                           test_des_ecb,                           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if TC_DES_ENABLE_CBC
  { "/des_cbc",                           test_des_cbc,                           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if TC_DES_ENABLE_CTR
  { "/des_ctr",                           test_des_ctr,                           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if TC_DES_ENABLE_TDES && TC_DES_ENABLE_ECB
  { "/tdes2_ecb",                         test_tdes2_ecb,                         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/tdes3_ecb",                         test_tdes3_ecb,                         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if TC_DES_ENABLE_TDES && TC_DES_ENABLE_CBC
  { "/tdes2_cbc",                         test_tdes2_cbc,                         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/tdes3_cbc",                         test_tdes3_cbc,                         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if TC_DES_ENABLE_TDES && TC_DES_ENABLE_CTR
  { "/tdes2_ctr",                         test_tdes2_ctr,                         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/tdes3_ctr",                         test_tdes3_ctr,                         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if TC_DES_ENABLE_OFB
  { "/des_ofb",                           test_des_ofb,                           NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if TC_DES_ENABLE_CFB64
  { "/des_cfb64",                         test_des_cfb64,                         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if TC_DES_ENABLE_CFB8
  { "/des_cfb8",                          test_des_cfb8,                          NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if TC_DES_ENABLE_CFB1
  { "/des_cfb1",                          test_des_cfb1,                          NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if TC_DES_ENABLE_TDES && (TC_DES_ENABLE_OFB || TC_DES_ENABLE_CFB64 || TC_DES_ENABLE_CFB8 || TC_DES_ENABLE_CFB1)
  { "/tdes3_feedback_modes",              test_tdes3_feedback_modes,              NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/feedback_mode_chaining",            test_feedback_mode_chaining,            NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if TC_DES_ENABLE_TDES && TC_DES_ENABLE_ECB
  { "/tdes_single_des_equiv",            test_tdes_single_des_equivalence,        NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
#if TC_DES_ENABLE_CMAC
  { "/des_cmac",                          test_des_cmac,                          NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/des_cmac_streaming",                test_des_cmac_streaming,             NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/des_cmac_single_des_degenerate",    test_des_cmac_single_des_matches_2k3des_degenerate, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
  { "/des_api_errors",                    test_des_api_errors,                    NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
  { "/des_secure_zero_and_clear",         test_des_secure_zero_and_clear,         NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#if TC_DES_ENABLE_ECB && TC_DES_ENABLE_CBC && TC_DES_ENABLE_CFB1 && TC_DES_ENABLE_CFB8 && \
    TC_DES_ENABLE_CFB64 && TC_DES_ENABLE_OFB && TC_DES_ENABLE_TDES
  { "/edge_vectors",                      test_edge_vectors_suite,                NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL },
#endif
  { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

static const MunitSuite test_suite = {
  "/tiny-des-c",
  test_suite_tests,
  NULL,
  1,
  MUNIT_SUITE_OPTION_NONE
};

int main(int argc, char* argv[])
{
  return munit_suite_main(&test_suite, NULL, argc, argv);
}
