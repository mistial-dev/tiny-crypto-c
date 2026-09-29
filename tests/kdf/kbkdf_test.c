/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Mistial Dev
 *
 * SP 800-108 KBKDF tests: Kdf108 cross-check vector, counter encodings pinned
 * against hand-composed HMAC / CMAC calls, a generated CAVP subset, and API
 * edge cases. Test-only translation unit.
 */

#include <tiny_crypto/kdf.h>
#include "munit.h"
#include "test_util.h"
#include "test_vectors.h"

#include <string.h>

#if TC_ENABLE_KDF

/* ------------------------------------------------------------------------- */
/* PRF family table shared by the sub-tests                                  */
/* ------------------------------------------------------------------------- */

typedef TC_status (*kdf_counter_fn)(TC_bytes, const struct TC_KBKDF_params*, TC_bytes, TC_bytes,
                                    TC_buffer);
typedef TC_status (*kdf_feedback_fn)(TC_bytes, const struct TC_KBKDF_params*, TC_bytes, TC_bytes,
                                     TC_buffer);
typedef TC_status (*kdf_pipeline_fn)(TC_bytes, const struct TC_KBKDF_params*, TC_bytes, TC_buffer);

struct kdf_family {
  const char* name;
  int prf_id;     /* KBKDF_PRF_* from test_vectors.h */
  size_t h;       /* PRF output length */
  size_t key_len; /* a valid KDK length for this family */
  kdf_counter_fn counter;
  kdf_feedback_fn feedback;
  kdf_pipeline_fn pipeline;
};

#if TC_AES_KEY_BITS == 128
#define KDF_AES_PRF_ID KBKDF_PRF_CMAC_AES128
#elif TC_AES_KEY_BITS == 192
#define KDF_AES_PRF_ID KBKDF_PRF_CMAC_AES192
#else
#define KDF_AES_PRF_ID KBKDF_PRF_CMAC_AES256
#endif

static const struct kdf_family kdf_families[] = {
#if TC_KBKDF_HAVE_HMAC_SHA1
    {"HMAC-SHA-1", KBKDF_PRF_HMAC_SHA1, TC_SHA1_DIGESTLEN, 32, TC_KBKDF_HMAC_SHA1_counter,
     TC_KBKDF_HMAC_SHA1_feedback, TC_KBKDF_HMAC_SHA1_pipeline},
#endif
#if TC_KBKDF_HAVE_HMAC_SHA224
    {"HMAC-SHA-224", KBKDF_PRF_HMAC_SHA224, TC_SHA224_DIGESTLEN, 32, TC_KBKDF_HMAC_SHA224_counter,
     TC_KBKDF_HMAC_SHA224_feedback, TC_KBKDF_HMAC_SHA224_pipeline},
#endif
#if TC_KBKDF_HAVE_HMAC_SHA256
    {"HMAC-SHA-256", KBKDF_PRF_HMAC_SHA256, TC_SHA256_DIGESTLEN, 32, TC_KBKDF_HMAC_SHA256_counter,
     TC_KBKDF_HMAC_SHA256_feedback, TC_KBKDF_HMAC_SHA256_pipeline},
#endif
#if TC_KBKDF_HAVE_HMAC_SHA384
    {"HMAC-SHA-384", KBKDF_PRF_HMAC_SHA384, TC_SHA384_DIGESTLEN, 32, TC_KBKDF_HMAC_SHA384_counter,
     TC_KBKDF_HMAC_SHA384_feedback, TC_KBKDF_HMAC_SHA384_pipeline},
#endif
#if TC_KBKDF_HAVE_HMAC_SHA512
    {"HMAC-SHA-512", KBKDF_PRF_HMAC_SHA512, TC_SHA512_DIGESTLEN, 32, TC_KBKDF_HMAC_SHA512_counter,
     TC_KBKDF_HMAC_SHA512_feedback, TC_KBKDF_HMAC_SHA512_pipeline},
#endif
#if TC_KBKDF_HAVE_AES_CMAC
    {"AES-CMAC", KDF_AES_PRF_ID, TC_AES_CMAC_TAG_MAX, TC_AES_KEYLEN, TC_KBKDF_AES_CMAC_counter,
     TC_KBKDF_AES_CMAC_feedback, TC_KBKDF_AES_CMAC_pipeline},
#endif
#if TC_KBKDF_HAVE_DES_CMAC
    {"TDEA-CMAC", KBKDF_PRF_CMAC_TDES3, TC_DES_CMAC_TAG_MAX, 24, TC_KBKDF_DES_CMAC_counter,
     TC_KBKDF_DES_CMAC_feedback, TC_KBKDF_DES_CMAC_pipeline},
#endif
};
#define KDF_FAMILY_COUNT (sizeof(kdf_families) / sizeof(kdf_families[0]))

/* ------------------------------------------------------------------------- */
/* Kdf108 cross-check vector                                                 */
/* ------------------------------------------------------------------------- */

MunitResult test_kbkdf_known(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;
#if TC_KBKDF_HAVE_HMAC_SHA256
  {
    const struct TC_KBKDF_params p = {TC_KBKDF_COUNTER_32, 0, 0};
    uint8_t fixed[TC_KBKDF_FIXED_INPUT_LEN(sizeof(kbkdf_known_label), sizeof(kbkdf_known_context))];
    uint8_t out[32];
    uint8_t out2[32];

    munit_assert_size(sizeof(fixed), ==, sizeof(kbkdf_known_fixed));
    munit_assert_int(
        TC_KBKDF_fixed_input((TC_bytes){kbkdf_known_label, sizeof(kbkdf_known_label)},
                             (TC_bytes){kbkdf_known_context, sizeof(kbkdf_known_context)},
                             sizeof(out), (TC_buffer){fixed, sizeof(fixed)}),
        ==, TC_OK);
    munit_assert_memory_equal(sizeof(fixed), fixed, kbkdf_known_fixed);

    /* Label || 0x00 || Context || [256]_32: the encoded length ends 00 00 01 00. */
    munit_assert_uint8(fixed[sizeof(fixed) - 2], ==, 0x01);
    munit_assert_uint8(fixed[sizeof(fixed) - 1], ==, 0x00);

    munit_assert_int(
        TC_KBKDF_HMAC_SHA256_counter((TC_bytes){kbkdf_known_key, sizeof(kbkdf_known_key)}, &p,
                                     (TC_bytes){NULL, 0}, (TC_bytes){fixed, sizeof(fixed)},
                                     (TC_buffer){out, sizeof(out)}),
        ==, TC_OK);
    munit_assert_memory_equal(sizeof(out), out, kbkdf_known_out);

    /* An explicit empty before-buffer is the same BEFORE_FIXED layout. */
    munit_assert_int(
        TC_KBKDF_HMAC_SHA256_counter((TC_bytes){kbkdf_known_key, sizeof(kbkdf_known_key)}, &p,
                                     (TC_bytes){out2, 0}, (TC_bytes){fixed, sizeof(fixed)},
                                     (TC_buffer){out2, sizeof(out2)}),
        ==, TC_OK);
    munit_assert_memory_equal(sizeof(out), out2, kbkdf_known_out);

    /* MIDDLE with an empty after-part is byte-identical to AFTER_FIXED. */
    munit_assert_int(
        TC_KBKDF_HMAC_SHA256_counter((TC_bytes){kbkdf_known_key, sizeof(kbkdf_known_key)}, &p,
                                     (TC_bytes){fixed, sizeof(fixed)}, (TC_bytes){NULL, 0},
                                     (TC_buffer){out, sizeof(out)}),
        ==, TC_OK);
    munit_assert_int(
        TC_KBKDF_HMAC_SHA256_counter((TC_bytes){kbkdf_known_key, sizeof(kbkdf_known_key)}, &p,
                                     (TC_bytes){fixed, sizeof(fixed)}, (TC_bytes){fixed, 0},
                                     (TC_buffer){out2, sizeof(out2)}),
        ==, TC_OK);
    munit_assert_memory_equal(sizeof(out), out, out2);
    munit_assert_false(memcmp(out, kbkdf_known_out, sizeof(out)) == 0);
  }
  return MUNIT_OK;
#else
  return MUNIT_SKIP;
#endif
}

/* ------------------------------------------------------------------------- */
/* Counter encodings and segment order, pinned by hand-composed HMACs         */
/* ------------------------------------------------------------------------- */

#if TC_KBKDF_HAVE_HMAC_SHA256

/* HMAC-SHA-256 over up to four concatenated segments. */
/* HMAC-SHA-256 over the concatenation a || b || c || d. */
static void hmac256_cat(TC_bytes key, TC_bytes a, TC_bytes b, TC_bytes c, TC_bytes d, uint8_t* tag)
{
  const TC_bytes parts[] = {a, b, c, d};
  struct TC_HMAC_SHA256_ctx ctx;
  munit_assert_int(TC_HMAC_SHA256_init(&ctx, key.data, key.length), ==, TC_OK);
  for (size_t i = 0; i < sizeof parts / sizeof *parts; ++i)
    munit_assert_int(TC_HMAC_SHA256_update(&ctx, parts[i].data, parts[i].length), ==, TC_OK);
  munit_assert_int(TC_HMAC_SHA256_final(&ctx, tag), ==, TC_OK);
}

MunitResult test_kbkdf_counter_encoding(const MunitParameter params[], void* data)
{
  static const uint8_t ctr1[4][4] = {
      {0x01}, {0x00, 0x01}, {0x00, 0x00, 0x01}, {0x00, 0x00, 0x00, 0x01}};
  static const uint8_t ctr2[4][4] = {
      {0x02}, {0x00, 0x02}, {0x00, 0x00, 0x02}, {0x00, 0x00, 0x00, 0x02}};
  uint8_t key[32];
  uint8_t fixed[23];
  uint8_t iv[9];
  uint8_t out[2 * TC_SHA256_DIGESTLEN];
  uint8_t k1[TC_SHA256_DIGESTLEN];
  uint8_t k2[TC_SHA256_DIGESTLEN];
  uint8_t a1[TC_SHA256_DIGESTLEN];
  struct TC_KBKDF_params p;
  unsigned r;
  (void)params;
  (void)data;

  tc_test_fill_stride3(key, sizeof(key), 0x10);
  tc_test_fill_stride3(fixed, sizeof(fixed), 0x40);
  tc_test_fill_stride3(iv, sizeof(iv), 0x70);

  for (r = 0; r < 4; ++r) {
    const size_t ctr_len = r + 1;
    p.counter_bits = (uint8_t)(8u * ctr_len);
    p.counter_location = 0;
    p.use_counter = 1;

    /* Counter mode, BEFORE_FIXED: K(i) = HMAC(K, [i]_r || F). */
    munit_assert_int(TC_KBKDF_HMAC_SHA256_counter(
                         (TC_bytes){key, sizeof(key)}, &p, (TC_bytes){NULL, 0},
                         (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, sizeof(out)}),
                     ==, TC_OK);
    hmac256_cat((TC_bytes){key, sizeof(key)}, (TC_bytes){ctr1[r], ctr_len},
                (TC_bytes){fixed, sizeof(fixed)}, (TC_bytes){NULL, 0}, (TC_bytes){NULL, 0}, k1);
    hmac256_cat((TC_bytes){key, sizeof(key)}, (TC_bytes){ctr2[r], ctr_len},
                (TC_bytes){fixed, sizeof(fixed)}, (TC_bytes){NULL, 0}, (TC_bytes){NULL, 0}, k2);
    munit_assert_memory_equal(TC_SHA256_DIGESTLEN, out, k1);
    munit_assert_memory_equal(TC_SHA256_DIGESTLEN, out + TC_SHA256_DIGESTLEN, k2);

    /* Counter mode, AFTER_FIXED: K(i) = HMAC(K, F || [i]_r). */
    munit_assert_int(TC_KBKDF_HMAC_SHA256_counter(
                         (TC_bytes){key, sizeof(key)}, &p, (TC_bytes){fixed, sizeof(fixed)},
                         (TC_bytes){NULL, 0}, (TC_buffer){out, sizeof(out)}),
                     ==, TC_OK);
    hmac256_cat((TC_bytes){key, sizeof(key)}, (TC_bytes){fixed, sizeof(fixed)},
                (TC_bytes){ctr1[r], ctr_len}, (TC_bytes){NULL, 0}, (TC_bytes){NULL, 0}, k1);
    hmac256_cat((TC_bytes){key, sizeof(key)}, (TC_bytes){fixed, sizeof(fixed)},
                (TC_bytes){ctr2[r], ctr_len}, (TC_bytes){NULL, 0}, (TC_bytes){NULL, 0}, k2);
    munit_assert_memory_equal(TC_SHA256_DIGESTLEN, out, k1);
    munit_assert_memory_equal(TC_SHA256_DIGESTLEN, out + TC_SHA256_DIGESTLEN, k2);

    /* Counter mode, MIDDLE_FIXED: K(i) = HMAC(K, F[0..10] || [i]_r || F[10..]). */
    munit_assert_int(TC_KBKDF_HMAC_SHA256_counter(
                         (TC_bytes){key, sizeof(key)}, &p, (TC_bytes){fixed, 10},
                         (TC_bytes){fixed + 10, sizeof(fixed) - 10}, (TC_buffer){out, sizeof(out)}),
                     ==, TC_OK);
    hmac256_cat((TC_bytes){key, sizeof(key)}, (TC_bytes){fixed, 10}, (TC_bytes){ctr1[r], ctr_len},
                (TC_bytes){fixed + 10, sizeof(fixed) - 10}, (TC_bytes){NULL, 0}, k1);
    hmac256_cat((TC_bytes){key, sizeof(key)}, (TC_bytes){fixed, 10}, (TC_bytes){ctr2[r], ctr_len},
                (TC_bytes){fixed + 10, sizeof(fixed) - 10}, (TC_bytes){NULL, 0}, k2);
    munit_assert_memory_equal(TC_SHA256_DIGESTLEN, out, k1);
    munit_assert_memory_equal(TC_SHA256_DIGESTLEN, out + TC_SHA256_DIGESTLEN, k2);

    /* Feedback, BEFORE_ITER: K(1) = HMAC([1] || IV || F), K(2) = HMAC([2] || K(1) || F). */
    p.counter_location = TC_KBKDF_CTR_BEFORE_ITER;
    munit_assert_int(TC_KBKDF_HMAC_SHA256_feedback(
                         (TC_bytes){key, sizeof(key)}, &p, (TC_bytes){iv, sizeof(iv)},
                         (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, sizeof(out)}),
                     ==, TC_OK);
    hmac256_cat((TC_bytes){key, sizeof(key)}, (TC_bytes){ctr1[r], ctr_len},
                (TC_bytes){iv, sizeof(iv)}, (TC_bytes){fixed, sizeof(fixed)}, (TC_bytes){NULL, 0},
                k1);
    hmac256_cat((TC_bytes){key, sizeof(key)}, (TC_bytes){ctr2[r], ctr_len},
                (TC_bytes){k1, sizeof(k1)}, (TC_bytes){fixed, sizeof(fixed)}, (TC_bytes){NULL, 0},
                k2);
    munit_assert_memory_equal(TC_SHA256_DIGESTLEN, out, k1);
    munit_assert_memory_equal(TC_SHA256_DIGESTLEN, out + TC_SHA256_DIGESTLEN, k2);

    /* Feedback, AFTER_ITER, empty IV: K(1) = HMAC([1] || F), K(2) = HMAC(K(1) || [2] || F). */
    p.counter_location = TC_KBKDF_CTR_AFTER_ITER;
    munit_assert_int(TC_KBKDF_HMAC_SHA256_feedback(
                         (TC_bytes){key, sizeof(key)}, &p, (TC_bytes){NULL, 0},
                         (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, sizeof(out)}),
                     ==, TC_OK);
    hmac256_cat((TC_bytes){key, sizeof(key)}, (TC_bytes){ctr1[r], ctr_len},
                (TC_bytes){fixed, sizeof(fixed)}, (TC_bytes){NULL, 0}, (TC_bytes){NULL, 0}, k1);
    hmac256_cat((TC_bytes){key, sizeof(key)}, (TC_bytes){k1, sizeof(k1)},
                (TC_bytes){ctr2[r], ctr_len}, (TC_bytes){fixed, sizeof(fixed)}, (TC_bytes){NULL, 0},
                k2);
    munit_assert_memory_equal(TC_SHA256_DIGESTLEN, out, k1);
    munit_assert_memory_equal(TC_SHA256_DIGESTLEN, out + TC_SHA256_DIGESTLEN, k2);

    /* Feedback, AFTER_FIXED: K(1) = HMAC(IV || F || [1]), K(2) = HMAC(K(1) || F || [2]). */
    p.counter_location = TC_KBKDF_CTR_AFTER_FIXED;
    munit_assert_int(TC_KBKDF_HMAC_SHA256_feedback(
                         (TC_bytes){key, sizeof(key)}, &p, (TC_bytes){iv, sizeof(iv)},
                         (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, sizeof(out)}),
                     ==, TC_OK);
    hmac256_cat((TC_bytes){key, sizeof(key)}, (TC_bytes){iv, sizeof(iv)},
                (TC_bytes){fixed, sizeof(fixed)}, (TC_bytes){ctr1[r], ctr_len}, (TC_bytes){NULL, 0},
                k1);
    hmac256_cat((TC_bytes){key, sizeof(key)}, (TC_bytes){k1, sizeof(k1)},
                (TC_bytes){fixed, sizeof(fixed)}, (TC_bytes){ctr2[r], ctr_len}, (TC_bytes){NULL, 0},
                k2);
    munit_assert_memory_equal(TC_SHA256_DIGESTLEN, out, k1);
    munit_assert_memory_equal(TC_SHA256_DIGESTLEN, out + TC_SHA256_DIGESTLEN, k2);

    /* Pipeline, BEFORE_ITER: A(1) = HMAC(F), K(1) = HMAC([1] || A(1) || F). */
    p.counter_location = TC_KBKDF_CTR_BEFORE_ITER;
    munit_assert_int(TC_KBKDF_HMAC_SHA256_pipeline((TC_bytes){key, sizeof(key)}, &p,
                                                   (TC_bytes){fixed, sizeof(fixed)},
                                                   (TC_buffer){out, TC_SHA256_DIGESTLEN}),
                     ==, TC_OK);
    hmac256_cat((TC_bytes){key, sizeof(key)}, (TC_bytes){fixed, sizeof(fixed)}, (TC_bytes){NULL, 0},
                (TC_bytes){NULL, 0}, (TC_bytes){NULL, 0}, a1);
    hmac256_cat((TC_bytes){key, sizeof(key)}, (TC_bytes){ctr1[r], ctr_len},
                (TC_bytes){a1, sizeof(a1)}, (TC_bytes){fixed, sizeof(fixed)}, (TC_bytes){NULL, 0},
                k1);
    munit_assert_memory_equal(TC_SHA256_DIGESTLEN, out, k1);
  }

  /* Feedback without counter: K(1) = HMAC(IV || F), K(2) = HMAC(K(1) || F).
     counter_bits and counter_location are ignored. */
  p.counter_bits = 7;
  p.counter_location = 9;
  p.use_counter = 0;
  munit_assert_int(TC_KBKDF_HMAC_SHA256_feedback(
                       (TC_bytes){key, sizeof(key)}, &p, (TC_bytes){iv, sizeof(iv)},
                       (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, sizeof(out)}),
                   ==, TC_OK);
  hmac256_cat((TC_bytes){key, sizeof(key)}, (TC_bytes){iv, sizeof(iv)},
              (TC_bytes){fixed, sizeof(fixed)}, (TC_bytes){NULL, 0}, (TC_bytes){NULL, 0}, k1);
  hmac256_cat((TC_bytes){key, sizeof(key)}, (TC_bytes){k1, sizeof(k1)},
              (TC_bytes){fixed, sizeof(fixed)}, (TC_bytes){NULL, 0}, (TC_bytes){NULL, 0}, k2);
  munit_assert_memory_equal(TC_SHA256_DIGESTLEN, out, k1);
  munit_assert_memory_equal(TC_SHA256_DIGESTLEN, out + TC_SHA256_DIGESTLEN, k2);

  /* Pipeline without counter: A(1) = HMAC(F), A(2) = HMAC(A(1)),
     K(1) = HMAC(A(1) || F), K(2) = HMAC(A(2) || F). */
  munit_assert_int(TC_KBKDF_HMAC_SHA256_pipeline((TC_bytes){key, sizeof(key)}, &p,
                                                 (TC_bytes){fixed, sizeof(fixed)},
                                                 (TC_buffer){out, sizeof(out)}),
                   ==, TC_OK);
  hmac256_cat((TC_bytes){key, sizeof(key)}, (TC_bytes){fixed, sizeof(fixed)}, (TC_bytes){NULL, 0},
              (TC_bytes){NULL, 0}, (TC_bytes){NULL, 0}, a1);
  hmac256_cat((TC_bytes){key, sizeof(key)}, (TC_bytes){a1, sizeof(a1)},
              (TC_bytes){fixed, sizeof(fixed)}, (TC_bytes){NULL, 0}, (TC_bytes){NULL, 0}, k1);
  munit_assert_memory_equal(TC_SHA256_DIGESTLEN, out, k1);
  hmac256_cat((TC_bytes){key, sizeof(key)}, (TC_bytes){a1, sizeof(a1)}, (TC_bytes){NULL, 0},
              (TC_bytes){NULL, 0}, (TC_bytes){NULL, 0}, k2); /* A(2) */
  hmac256_cat((TC_bytes){key, sizeof(key)}, (TC_bytes){k2, sizeof(k2)},
              (TC_bytes){fixed, sizeof(fixed)}, (TC_bytes){NULL, 0}, (TC_bytes){NULL, 0}, k1);
  munit_assert_memory_equal(TC_SHA256_DIGESTLEN, out + TC_SHA256_DIGESTLEN, k1);

  return MUNIT_OK;
}

#else /* !TC_KBKDF_HAVE_HMAC_SHA256 */

MunitResult test_kbkdf_counter_encoding(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;
  return MUNIT_SKIP;
}

#endif

/* ------------------------------------------------------------------------- */
/* CMAC PRFs: first block equals the one-shot CMAC over 0x01 || F            */
/* ------------------------------------------------------------------------- */

MunitResult test_kbkdf_cmac_first_block(const MunitParameter params[], void* data)
{
  const struct TC_KBKDF_params p = {TC_KBKDF_COUNTER_8, 0, 0};
  uint8_t fixed[1 + 37];
  uint8_t key[32];
  int ran = 0;
  (void)params;
  (void)data;

  tc_test_fill_stride3(key, sizeof(key), 0x21);
  fixed[0] = 0x01;
  tc_test_fill_stride3(fixed + 1, sizeof(fixed) - 1, 0x55);

#if TC_KBKDF_HAVE_AES_CMAC
  {
    uint8_t out[TC_AES_CMAC_TAG_MAX];
    uint8_t tag[TC_AES_CMAC_TAG_MAX];
    munit_assert_int(TC_KBKDF_AES_CMAC_counter(
                         (TC_bytes){key, TC_AES_KEYLEN}, &p, (TC_bytes){NULL, 0},
                         (TC_bytes){fixed + 1, sizeof(fixed) - 1}, (TC_buffer){out, sizeof(out)}),
                     ==, TC_OK);
    munit_assert_int(TC_AES_CMAC(key, fixed, sizeof(fixed), tag, sizeof(tag)), ==, TC_OK);
    munit_assert_memory_equal(sizeof(out), out, tag);
    ran = 1;
  }
#endif
#if TC_KBKDF_HAVE_DES_CMAC
  {
    static const size_t key_lens[] = {8, 16, 24};
    size_t k;
    for (k = 0; k < 3; ++k) {
      uint8_t out[TC_DES_CMAC_TAG_MAX];
      uint8_t tag[TC_DES_CMAC_TAG_MAX];
      munit_assert_int(TC_KBKDF_DES_CMAC_counter(
                           (TC_bytes){key, key_lens[k]}, &p, (TC_bytes){NULL, 0},
                           (TC_bytes){fixed + 1, sizeof(fixed) - 1}, (TC_buffer){out, sizeof(out)}),
                       ==, TC_OK);
      munit_assert_int(TC_DES_CMAC(key, key_lens[k], fixed, sizeof(fixed), tag, sizeof(tag)), ==,
                       TC_OK);
      munit_assert_memory_equal(sizeof(out), out, tag);
    }
    ran = 1;
  }
#endif
  return ran ? MUNIT_OK : MUNIT_SKIP;
}

/* ------------------------------------------------------------------------- */
/* Generated CAVP subset                                                     */
/* ------------------------------------------------------------------------- */

static const struct kdf_family* kdf_family_for(int prf_id)
{
  size_t i;
  for (i = 0; i < KDF_FAMILY_COUNT; ++i) {
    if (kdf_families[i].prf_id == prf_id)
      return &kdf_families[i];
#if TC_KBKDF_HAVE_DES_CMAC
    /* Both TDEA sizes share one family; the vector's key length selects. */
    if (prf_id == KBKDF_PRF_CMAC_TDES2 && kdf_families[i].prf_id == KBKDF_PRF_CMAC_TDES3)
      return &kdf_families[i];
#endif
  }
  return NULL;
}

MunitResult test_kbkdf_generated(const MunitParameter params[], void* data)
{
  static uint8_t out[512];
  size_t i;
  unsigned ran = 0;
  (void)params;
  (void)data;

  for (i = 0; i < KBKDF_VECTOR_COUNT; ++i) {
    const struct kbkdf_vector* v = &kbkdf_vectors[i];
    const struct kdf_family* f = kdf_family_for(v->prf);
    struct TC_KBKDF_params p;
    TC_status rc;

    if (f == NULL)
      continue;
    munit_assert_size(v->out_len, <=, sizeof(out));
    p.counter_bits = v->counter_bits;
    p.counter_location = v->location;
    p.use_counter = v->use_counter;

    switch (v->mode) {
    case KBKDF_MODE_COUNTER:
      rc = f->counter((TC_bytes){v->key, v->key_len}, &p, (TC_bytes){v->in1, v->in1_len},
                      (TC_bytes){v->in2, v->in2_len}, (TC_buffer){out, v->out_len});
      break;
    case KBKDF_MODE_FEEDBACK:
      rc = f->feedback((TC_bytes){v->key, v->key_len}, &p, (TC_bytes){v->iv, v->iv_len},
                       (TC_bytes){v->in2, v->in2_len}, (TC_buffer){out, v->out_len});
      break;
    default:
      rc = f->pipeline((TC_bytes){v->key, v->key_len}, &p, (TC_bytes){v->in2, v->in2_len},
                       (TC_buffer){out, v->out_len});
      break;
    }
    if (rc != TC_OK)
      munit_errorf("%s: derivation failed", v->source);
    if (memcmp(out, v->out, v->out_len) != 0)
      munit_errorf("%s: output mismatch", v->source);
    ran++;
  }
  munit_assert_uint(ran, >, 0);
  return MUNIT_OK;
}

/* ------------------------------------------------------------------------- */
/* Fixed-input builder                                                       */
/* ------------------------------------------------------------------------- */

MunitResult test_kbkdf_fixed_input(const MunitParameter params[], void* data)
{
  static const uint8_t label[] = {'k', 'e', 'y'};
  static const uint8_t bad_label[] = {'k', 0x00, 'y'};
  static const uint8_t context[] = {0xde, 0xad};
  uint8_t buf[TC_KBKDF_FIXED_INPUT_LEN(sizeof(label), sizeof(context)) + 4];
  (void)params;
  (void)data;

  munit_assert_size(TC_KBKDF_FIXED_INPUT_LEN(3, 2), ==, 10);

  munit_assert_int(
      TC_KBKDF_fixed_input((TC_bytes){label, 3}, (TC_bytes){context, 2}, 32, (TC_buffer){buf, 10}),
      ==, TC_OK);
  munit_assert_memory_equal(3, buf, label);
  munit_assert_uint8(buf[3], ==, 0x00);
  munit_assert_memory_equal(2, buf + 4, context);
  munit_assert_uint8(buf[6], ==, 0x00);
  munit_assert_uint8(buf[7], ==, 0x00);
  munit_assert_uint8(buf[8], ==, 0x01); /* 32 bytes = 256 bits = 0x00000100 */
  munit_assert_uint8(buf[9], ==, 0x00);

  /* A larger buffer is accepted. The builder writes the exact encoded length. */
  memset(buf, 0xA5, sizeof(buf));
  munit_assert_int(TC_KBKDF_fixed_input((TC_bytes){label, 3}, (TC_bytes){context, 2}, 1,
                                        (TC_buffer){buf, sizeof(buf)}),
                   ==, TC_OK);
  munit_assert_uint8(buf[9], ==, 0x08);
  munit_assert_uint8(buf[10], ==, 0xA5);

  /* Empty label and empty context are valid: 0x00 || [L]. */
  munit_assert_int(TC_KBKDF_fixed_input((TC_bytes){NULL, 0}, (TC_bytes){NULL, 0}, 0x1FFFFFFFu,
                                        (TC_buffer){buf, 5}),
                   ==, TC_OK);
  munit_assert_uint8(buf[0], ==, 0x00);
  munit_assert_uint8(buf[1], ==, 0xFF);
  munit_assert_uint8(buf[4], ==, 0xF8);

  munit_assert_int(
      TC_KBKDF_fixed_input((TC_bytes){label, 3}, (TC_bytes){context, 2}, 32, (TC_buffer){buf, 9}),
      ==, TC_ERROR);
  munit_assert_int(
      TC_KBKDF_fixed_input((TC_bytes){label, 3}, (TC_bytes){context, 2}, 32, (TC_buffer){NULL, 10}),
      ==, TC_ERROR);
  munit_assert_int(
      TC_KBKDF_fixed_input((TC_bytes){NULL, 3}, (TC_bytes){context, 2}, 32, (TC_buffer){buf, 10}),
      ==, TC_ERROR);
  munit_assert_int(
      TC_KBKDF_fixed_input((TC_bytes){label, 3}, (TC_bytes){NULL, 2}, 32, (TC_buffer){buf, 10}), ==,
      TC_ERROR);
  munit_assert_int(
      TC_KBKDF_fixed_input((TC_bytes){label, 3}, (TC_bytes){context, 2}, 0, (TC_buffer){buf, 10}),
      ==, TC_ERROR);
  munit_assert_int(TC_KBKDF_fixed_input((TC_bytes){label, 3}, (TC_bytes){context, 2}, 0x20000000u,
                                        (TC_buffer){buf, 10}),
                   ==, TC_ERROR);
  munit_assert_int(TC_KBKDF_fixed_input((TC_bytes){bad_label, 3}, (TC_bytes){context, 2}, 32,
                                        (TC_buffer){buf, 10}),
                   ==, TC_ERROR);
  /* buf overlapping an input */
  memcpy(buf, label, 3);
  munit_assert_int(
      TC_KBKDF_fixed_input((TC_bytes){buf, 3}, (TC_bytes){context, 2}, 32, (TC_buffer){buf, 10}),
      ==, TC_ERROR);
  munit_assert_int(
      TC_KBKDF_fixed_input((TC_bytes){label, 3}, (TC_bytes){buf + 5, 2}, 32, (TC_buffer){buf, 10}),
      ==, TC_ERROR);

  return MUNIT_OK;
}

/* ------------------------------------------------------------------------- */
/* Argument validation across every compiled family                          */
/* ------------------------------------------------------------------------- */

static int all_bytes(const uint8_t* p, size_t len, uint8_t value)
{
  size_t i;
  for (i = 0; i < len; ++i)
    if (p[i] != value)
      return 0;
  return 1;
}

MunitResult test_kbkdf_api(const MunitParameter params[], void* data)
{
  uint8_t key[32];
  uint8_t fixed[40];
  uint8_t iv[16];
  uint8_t out[64];
  uint8_t out2[64];
  uint8_t scratch[128];
  size_t fi;
  (void)params;
  (void)data;

  tc_test_fill_stride3(key, sizeof(key), 0x01);
  tc_test_fill_stride3(fixed, sizeof(fixed), 0x80);
  tc_test_fill_stride3(iv, sizeof(iv), 0xC0);

  for (fi = 0; fi < KDF_FAMILY_COUNT; ++fi) {
    const struct kdf_family* f = &kdf_families[fi];
    const size_t klen = f->key_len;
    struct TC_KBKDF_params p;

    p.counter_bits = TC_KBKDF_COUNTER_32;
    p.counter_location = TC_KBKDF_CTR_BEFORE_ITER;
    p.use_counter = 1;

    /* Baseline success for all three modes. */
    munit_assert_int(f->counter((TC_bytes){key, klen}, &p, (TC_bytes){NULL, 0},
                                (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, 33}),
                     ==, TC_OK);
    munit_assert_int(f->feedback((TC_bytes){key, klen}, &p, (TC_bytes){iv, sizeof(iv)},
                                 (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, 33}),
                     ==, TC_OK);
    munit_assert_int(f->pipeline((TC_bytes){key, klen}, &p, (TC_bytes){fixed, sizeof(fixed)},
                                 (TC_buffer){out, 33}),
                     ==, TC_OK);

    /* Argument errors leave the output untouched. */
    memset(out, 0xA5, sizeof(out));
    munit_assert_int(f->counter((TC_bytes){NULL, klen}, &p, (TC_bytes){NULL, 0},
                                (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, 32}),
                     ==, TC_ERROR);
    munit_assert_int(f->counter((TC_bytes){key, 0}, &p, (TC_bytes){NULL, 0},
                                (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, 32}),
                     ==, TC_ERROR);
    munit_assert_int(f->counter((TC_bytes){key, klen}, NULL, (TC_bytes){NULL, 0},
                                (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, 32}),
                     ==, TC_ERROR);
    munit_assert_int(f->counter((TC_bytes){key, klen}, &p, (TC_bytes){NULL, 0},
                                (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){NULL, 32}),
                     ==, TC_ERROR);
    munit_assert_int(f->counter((TC_bytes){key, klen}, &p, (TC_bytes){NULL, 0},
                                (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, 0}),
                     ==, TC_ERROR);
    munit_assert_int(f->counter((TC_bytes){key, klen}, &p, (TC_bytes){NULL, 1},
                                (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, 32}),
                     ==, TC_ERROR);
    munit_assert_int(f->counter((TC_bytes){key, klen}, &p, (TC_bytes){NULL, 0}, (TC_bytes){NULL, 1},
                                (TC_buffer){out, 32}),
                     ==, TC_ERROR);
    munit_assert_int(f->feedback((TC_bytes){key, klen}, &p, (TC_bytes){NULL, 1},
                                 (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, 32}),
                     ==, TC_ERROR);
    munit_assert_int(f->feedback((TC_bytes){key, klen}, &p, (TC_bytes){iv, sizeof(iv)},
                                 (TC_bytes){NULL, 1}, (TC_buffer){out, 32}),
                     ==, TC_ERROR);
    munit_assert_int(
        f->pipeline((TC_bytes){key, klen}, &p, (TC_bytes){NULL, 1}, (TC_buffer){out, 32}), ==,
        TC_ERROR);
    munit_assert_int(f->pipeline((TC_bytes){NULL, klen}, &p, (TC_bytes){fixed, sizeof(fixed)},
                                 (TC_buffer){out, 32}),
                     ==, TC_ERROR);

    /* Counter width must be 8/16/24/32 whenever a counter is used. */
    {
      static const uint8_t bad_bits[] = {0, 7, 12, 64, 255};
      size_t b;
      for (b = 0; b < sizeof(bad_bits); ++b) {
        p.counter_bits = bad_bits[b];
        munit_assert_int(f->counter((TC_bytes){key, klen}, &p, (TC_bytes){NULL, 0},
                                    (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, 32}),
                         ==, TC_ERROR);
        munit_assert_int(f->feedback((TC_bytes){key, klen}, &p, (TC_bytes){iv, sizeof(iv)},
                                     (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, 32}),
                         ==, TC_ERROR);
        munit_assert_int(f->pipeline((TC_bytes){key, klen}, &p, (TC_bytes){fixed, sizeof(fixed)},
                                     (TC_buffer){out, 32}),
                         ==, TC_ERROR);
      }
      p.counter_bits = TC_KBKDF_COUNTER_32;
    }
    /* Counter location must be 1..3 for feedback / pipeline with a counter. */
    p.counter_location = 0;
    munit_assert_int(f->feedback((TC_bytes){key, klen}, &p, (TC_bytes){iv, sizeof(iv)},
                                 (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, 32}),
                     ==, TC_ERROR);
    munit_assert_int(f->pipeline((TC_bytes){key, klen}, &p, (TC_bytes){fixed, sizeof(fixed)},
                                 (TC_buffer){out, 32}),
                     ==, TC_ERROR);
    p.counter_location = 4;
    munit_assert_int(f->feedback((TC_bytes){key, klen}, &p, (TC_bytes){iv, sizeof(iv)},
                                 (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, 32}),
                     ==, TC_ERROR);
    munit_assert_int(f->pipeline((TC_bytes){key, klen}, &p, (TC_bytes){fixed, sizeof(fixed)},
                                 (TC_buffer){out, 32}),
                     ==, TC_ERROR);
    /* ... but counter mode ignores the location field entirely. */
    munit_assert_int(f->counter((TC_bytes){key, klen}, &p, (TC_bytes){NULL, 0},
                                (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out2, 32}),
                     ==, TC_OK);
    munit_assert_true(all_bytes(out, sizeof(out), 0xA5));

    /* Aliasing between out and any input is rejected. */
    memcpy(scratch, fixed, sizeof(fixed));
    munit_assert_int(f->counter((TC_bytes){scratch, klen}, &p, (TC_bytes){NULL, 0},
                                (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){scratch, 32}),
                     ==, TC_ERROR);
    munit_assert_int(f->counter((TC_bytes){key, klen}, &p, (TC_bytes){NULL, 0},
                                (TC_bytes){scratch, sizeof(fixed)},
                                (TC_buffer){scratch + sizeof(fixed) - 1, 32}),
                     ==, TC_ERROR);
    munit_assert_int(f->counter((TC_bytes){key, klen}, &p, (TC_bytes){scratch, 8},
                                (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){scratch, 32}),
                     ==, TC_ERROR);
    munit_assert_int(f->feedback((TC_bytes){key, klen}, &p, (TC_bytes){scratch, 8},
                                 (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){scratch, 32}),
                     ==, TC_ERROR);
    munit_assert_int(f->pipeline((TC_bytes){key, klen}, &p, (TC_bytes){scratch, 8},
                                 (TC_buffer){scratch + 8, 32}),
                     ==, TC_ERROR);
    /* Adjacent, non-overlapping buffers are fine. */
    munit_assert_int(f->counter((TC_bytes){key, klen}, &p, (TC_bytes){scratch, 8},
                                (TC_bytes){scratch + 8, 8}, (TC_buffer){scratch + 16, 32}),
                     ==, TC_OK);

    /* Without a counter the width and location are ignored, and an empty IV
       or empty fixed input is valid in every mode. */
    p.use_counter = 0;
    p.counter_bits = 7;
    p.counter_location = 9;
    munit_assert_int(f->feedback((TC_bytes){key, klen}, &p, (TC_bytes){NULL, 0},
                                 (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, 32}),
                     ==, TC_OK);
    munit_assert_int(f->feedback((TC_bytes){key, klen}, &p, (TC_bytes){iv, 0},
                                 (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out2, 32}),
                     ==, TC_OK);
    munit_assert_memory_equal(32, out, out2);
    munit_assert_int(f->feedback((TC_bytes){key, klen}, &p, (TC_bytes){iv, sizeof(iv)},
                                 (TC_bytes){NULL, 0}, (TC_buffer){out, 32}),
                     ==, TC_OK);
    munit_assert_int(
        f->pipeline((TC_bytes){key, klen}, &p, (TC_bytes){NULL, 0}, (TC_buffer){out, 32}), ==,
        TC_OK);
    p.counter_bits = TC_KBKDF_COUNTER_16;
    munit_assert_int(f->counter((TC_bytes){key, klen}, &p, (TC_bytes){NULL, 0}, (TC_bytes){NULL, 0},
                                (TC_buffer){out, 32}),
                     ==, TC_OK);
    munit_assert_int(f->counter((TC_bytes){key, klen}, &p, (TC_bytes){fixed, 0},
                                (TC_bytes){fixed, 0}, (TC_buffer){out2, 32}),
                     ==, TC_OK);
    munit_assert_memory_equal(32, out, out2);
  }

#if TC_KBKDF_HAVE_AES_CMAC
  {
    const struct TC_KBKDF_params p = {TC_KBKDF_COUNTER_32, 0, 0};
    munit_assert_int(TC_KBKDF_AES_CMAC_counter((TC_bytes){key, TC_AES_KEYLEN + 1}, &p,
                                               (TC_bytes){NULL, 0}, (TC_bytes){fixed, 8},
                                               (TC_buffer){out, 16}),
                     ==, TC_ERROR);
    munit_assert_int(TC_KBKDF_AES_CMAC_counter((TC_bytes){key, TC_AES_KEYLEN - 1}, &p,
                                               (TC_bytes){NULL, 0}, (TC_bytes){fixed, 8},
                                               (TC_buffer){out, 16}),
                     ==, TC_ERROR);
    munit_assert_int(TC_KBKDF_AES_CMAC_counter((TC_bytes){key, TC_AES_KEYLEN}, &p,
                                               (TC_bytes){NULL, 0}, (TC_bytes){fixed, 8},
                                               (TC_buffer){out, 16}),
                     ==, TC_OK);
  }
#endif
#if TC_KBKDF_HAVE_DES_CMAC
  {
    const struct TC_KBKDF_params p = {TC_KBKDF_COUNTER_32, 0, 0};
    static const size_t bad[] = {7, 9, 15, 17, 32};
    static const size_t good[] = {8, 16, 24};
    size_t i;
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
      munit_assert_int(TC_KBKDF_DES_CMAC_counter((TC_bytes){key, bad[i]}, &p, (TC_bytes){NULL, 0},
                                                 (TC_bytes){fixed, 8}, (TC_buffer){out, 8}),
                       ==, TC_ERROR);
    for (i = 0; i < sizeof(good) / sizeof(good[0]); ++i)
      munit_assert_int(TC_KBKDF_DES_CMAC_counter((TC_bytes){key, good[i]}, &p, (TC_bytes){NULL, 0},
                                                 (TC_bytes){fixed, 8}, (TC_buffer){out, 8}),
                       ==, TC_OK);
  }
#endif
  return MUNIT_OK;
}

/* ------------------------------------------------------------------------- */
/* Counter-limit enforcement: n <= 2^r - 1                                   */
/* ------------------------------------------------------------------------- */

MunitResult test_kbkdf_limits(const MunitParameter params[], void* data)
{
  static uint8_t out[256 * TC_KBKDF_PRF_MAX];
  uint8_t key[32];
  uint8_t fixed[16];
  size_t fi;
  (void)params;
  (void)data;

  tc_test_fill_stride3(key, sizeof(key), 0x33);
  tc_test_fill_stride3(fixed, sizeof(fixed), 0x99);

  for (fi = 0; fi < KDF_FAMILY_COUNT; ++fi) {
    const struct kdf_family* f = &kdf_families[fi];
    const size_t h = f->h;
    struct TC_KBKDF_params p;

    p.counter_location = TC_KBKDF_CTR_AFTER_FIXED;
    p.use_counter = 1;

    /* r = 8: 255 blocks fit, 256 do not (in every mode that uses the counter). */
    p.counter_bits = TC_KBKDF_COUNTER_8;
    munit_assert_size(256 * h, <=, sizeof(out));
    munit_assert_int(f->counter((TC_bytes){key, f->key_len}, &p, (TC_bytes){NULL, 0},
                                (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, 255 * h}),
                     ==, TC_OK);
    munit_assert_int(f->counter((TC_bytes){key, f->key_len}, &p, (TC_bytes){NULL, 0},
                                (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, 255 * h + 1}),
                     ==, TC_ERROR);
    munit_assert_int(f->counter((TC_bytes){key, f->key_len}, &p, (TC_bytes){NULL, 0},
                                (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, 256 * h}),
                     ==, TC_ERROR);
    munit_assert_int(f->feedback((TC_bytes){key, f->key_len}, &p, (TC_bytes){NULL, 0},
                                 (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, 256 * h}),
                     ==, TC_ERROR);
    munit_assert_int(f->pipeline((TC_bytes){key, f->key_len}, &p, (TC_bytes){fixed, sizeof(fixed)},
                                 (TC_buffer){out, 256 * h}),
                     ==, TC_ERROR);

    /* r = 16 lifts the limit for the same request. */
    p.counter_bits = TC_KBKDF_COUNTER_16;
    munit_assert_int(f->counter((TC_bytes){key, f->key_len}, &p, (TC_bytes){NULL, 0},
                                (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, 256 * h}),
                     ==, TC_OK);
    munit_assert_int(f->feedback((TC_bytes){key, f->key_len}, &p, (TC_bytes){NULL, 0},
                                 (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, 256 * h}),
                     ==, TC_OK);
    munit_assert_int(f->pipeline((TC_bytes){key, f->key_len}, &p, (TC_bytes){fixed, sizeof(fixed)},
                                 (TC_buffer){out, 256 * h}),
                     ==, TC_OK);

    /* No counter: no 2^r bound applies. */
    p.use_counter = 0;
    p.counter_bits = TC_KBKDF_COUNTER_8;
    munit_assert_int(f->feedback((TC_bytes){key, f->key_len}, &p, (TC_bytes){NULL, 0},
                                 (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){out, 256 * h}),
                     ==, TC_OK);
    munit_assert_int(f->pipeline((TC_bytes){key, f->key_len}, &p, (TC_bytes){fixed, sizeof(fixed)},
                                 (TC_buffer){out, 256 * h}),
                     ==, TC_OK);
  }
  return MUNIT_OK;
}

/* ------------------------------------------------------------------------- */
/* Truncation: shorter outputs are prefixes of longer ones                   */
/* ------------------------------------------------------------------------- */

MunitResult test_kbkdf_truncation(const MunitParameter params[], void* data)
{
  uint8_t key[32];
  uint8_t fixed[20];
  uint8_t iv[4];
  uint8_t full[3 * TC_KBKDF_PRF_MAX];
  uint8_t part[3 * TC_KBKDF_PRF_MAX];
  size_t fi;
  (void)params;
  (void)data;

  tc_test_fill_stride3(key, sizeof(key), 0x44);
  tc_test_fill_stride3(fixed, sizeof(fixed), 0x88);
  tc_test_fill_stride3(iv, sizeof(iv), 0xCC);

  for (fi = 0; fi < KDF_FAMILY_COUNT; ++fi) {
    const struct kdf_family* f = &kdf_families[fi];
    const size_t full_len = 3 * f->h;
    static const size_t fractions[] = {1, 2, 3}; /* h + 1, 2h - 1, and 1 byte */
    struct TC_KBKDF_params p;
    size_t k;

    p.counter_bits = TC_KBKDF_COUNTER_24;
    p.counter_location = TC_KBKDF_CTR_AFTER_ITER;
    p.use_counter = 1;

    for (k = 0; k < 3; ++k) {
      size_t part_len = (k == 0) ? f->h + 1 : (k == 1) ? 2 * f->h - 1 : 1;

      munit_assert_int(f->counter((TC_bytes){key, f->key_len}, &p, (TC_bytes){NULL, 0},
                                  (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){full, full_len}),
                       ==, TC_OK);
      munit_assert_int(f->counter((TC_bytes){key, f->key_len}, &p, (TC_bytes){NULL, 0},
                                  (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){part, part_len}),
                       ==, TC_OK);
      munit_assert_memory_equal(part_len, part, full);

      munit_assert_int(f->feedback((TC_bytes){key, f->key_len}, &p, (TC_bytes){iv, sizeof(iv)},
                                   (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){full, full_len}),
                       ==, TC_OK);
      munit_assert_int(f->feedback((TC_bytes){key, f->key_len}, &p, (TC_bytes){iv, sizeof(iv)},
                                   (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){part, part_len}),
                       ==, TC_OK);
      munit_assert_memory_equal(part_len, part, full);

      munit_assert_int(f->pipeline((TC_bytes){key, f->key_len}, &p,
                                   (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){full, full_len}),
                       ==, TC_OK);
      munit_assert_int(f->pipeline((TC_bytes){key, f->key_len}, &p,
                                   (TC_bytes){fixed, sizeof(fixed)}, (TC_buffer){part, part_len}),
                       ==, TC_OK);
      munit_assert_memory_equal(part_len, part, full);
      (void)fractions;
    }
  }
  return MUNIT_OK;
}

#else /* !TC_ENABLE_KDF */

MunitResult test_kbkdf_known(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;
  return MUNIT_SKIP;
}
MunitResult test_kbkdf_counter_encoding(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;
  return MUNIT_SKIP;
}
MunitResult test_kbkdf_cmac_first_block(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;
  return MUNIT_SKIP;
}
MunitResult test_kbkdf_generated(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;
  return MUNIT_SKIP;
}
MunitResult test_kbkdf_fixed_input(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;
  return MUNIT_SKIP;
}
MunitResult test_kbkdf_api(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;
  return MUNIT_SKIP;
}
MunitResult test_kbkdf_limits(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;
  return MUNIT_SKIP;
}
MunitResult test_kbkdf_truncation(const MunitParameter params[], void* data)
{
  (void)params;
  (void)data;
  return MUNIT_SKIP;
}

#endif /* TC_ENABLE_KDF */
