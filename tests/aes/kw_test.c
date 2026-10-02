/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Mistial Dev
 *
 * AES key wrap tests: RFC 3394 and RFC 5649 examples, the SP 800-38F
 * argument, limit, integrity, length-indicator and padding rules, overlap,
 * and the NIST CAVP KWVS corpus in full runs. Test-only translation unit.
 */

#include <tiny_crypto/aes_kw.h>
#if TC_AES_ENABLE_DYNAMIC
#include <tiny_crypto/aes_dynamic.h>
#endif
#include "munit.h"
#include "cavp.h"
#include "test_util.h"

#include <stdint.h>
#include <string.h>

#ifndef KW_CAVP_DIR
#define KW_CAVP_DIR "tests/vectors/aes/kw"
#endif

MunitResult test_kw(const MunitParameter params[], void* data);

#if TC_AES_ENABLE_KW

/* Wrapped sizes of the largest key data equal the largest wrapped inputs, so
 * the wrap and unwrap domains correspond (SP 800-38F section 5.3.2). */
typedef char kw_limits_correspond
    [TC_AES_KW_WRAPPED_BYTES(TC_AES_KW_MAX_KEY_DATA_BYTES) == TC_AES_KW_MAX_WRAPPED_BYTES ? 1 : -1];
typedef char kwp_limits_correspond[TC_AES_KWP_WRAPPED_BYTES(TC_AES_KWP_MAX_KEY_DATA_BYTES) ==
                                           TC_AES_KWP_MAX_WRAPPED_BYTES
                                       ? 1
                                       : -1];

enum { KW_SENTINEL = 0xa5, KW_BUFFER = 96 };

typedef struct {
  const char* kek;
  const char* key_data;
  const char* wrapped;
} kw_vector;

/* RFC 3394 section 4.1 to 4.6. */
static const kw_vector rfc3394_vectors[] = {
    {"000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF",
     "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"},
    {"000102030405060708090A0B0C0D0E0F1011121314151617", "00112233445566778899AABBCCDDEEFF",
     "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"},
    {"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
     "00112233445566778899AABBCCDDEEFF", "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"},
    {"000102030405060708090A0B0C0D0E0F1011121314151617",
     "00112233445566778899AABBCCDDEEFF0001020304050607",
     "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2"},
    {"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
     "00112233445566778899AABBCCDDEEFF0001020304050607",
     "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"},
    {"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
     "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
     "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"},
};

/* RFC 5649 section 6: the W path (20 bytes) and the single-block path (7). */
static const kw_vector rfc5649_vectors[] = {
    {"5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8", "c37b7e6492584340bed12207808941155068f738",
     "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a"},
    {"5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8", "466f7250617369",
     "afbeb0f07dfbf5419200f2ccb50bb24f"},
};

#if TC_AES_SBOX_MODE == TC_AES_SBOX_MODE_RUNTIME
static void kw_initialize_sbox(void)
{
  TC_AES_init_sbox();
}
#else
static void kw_initialize_sbox(void)
{}
#endif

static TC_bytes span(const uint8_t* data, size_t length)
{
  return (TC_bytes){data, length};
}

static TC_buffer buffer(uint8_t* data, size_t capacity)
{
  return (TC_buffer){data, capacity};
}

/* A KEK of TC_AES_KEYLEN bytes, accepted by every build. */
static void kw_test_kek(uint8_t kek[TC_AES_KEYLEN])
{
  tc_test_fill_bytes(kek, TC_AES_KEYLEN, 0x40, 7);
}

static TC_status kw_wrap(int padded, TC_bytes kek, TC_bytes key_data, TC_buffer wrapped)
{
  return padded ? TC_AES_KWP_wrap(kek, key_data, wrapped) : TC_AES_KW_wrap(kek, key_data, wrapped);
}

/* One unwrap entry for both modes. *length receives the KW length on
 * success, so callers compare one value. */
static TC_status kw_unwrap(int padded, TC_bytes kek, TC_bytes wrapped, TC_buffer key_data,
                           size_t* length)
{
  if (padded)
    return TC_AES_KWP_unwrap(kek, wrapped, key_data, length);
  const TC_status status = TC_AES_KW_unwrap(kek, wrapped, key_data);
  if (status == TC_OK)
    *length = wrapped.length - 8u;
  return status;
}

/* Run one RFC example through the out-of-place, in-place and aliased calls,
 * or check that a build without its KEK size rejects it with outputs
 * unchanged. */
static void kw_run_vector(int padded, const kw_vector* vector)
{
  uint8_t kek[32], key_data[64], wrapped[72], out[KW_BUFFER], work[KW_BUFFER];
  size_t kek_length = tc_test_hex(vector->kek, kek, sizeof kek);
  size_t key_length = tc_test_hex(vector->key_data, key_data, sizeof key_data);
  size_t wrapped_length = tc_test_hex(vector->wrapped, wrapped, sizeof wrapped);
  size_t length = SIZE_MAX;
  const TC_bytes k = span(kek, kek_length);

  memset(out, KW_SENTINEL, sizeof out);
  if (!TC_AES_KW_KEK_LENGTH_SUPPORTED(kek_length)) {
    munit_assert_int(kw_wrap(padded, k, span(key_data, key_length), buffer(out, sizeof out)), ==,
                     TC_ERROR);
    munit_assert_true(tc_test_all_value(out, sizeof out, KW_SENTINEL));
    munit_assert_int(
        kw_unwrap(padded, k, span(wrapped, wrapped_length), buffer(out, sizeof out), &length), ==,
        TC_ERROR);
    munit_assert_true(tc_test_all_value(out, sizeof out, KW_SENTINEL));
    munit_assert_size(length, ==, SIZE_MAX);
    return;
  }

  munit_assert_int(kw_wrap(padded, k, span(key_data, key_length), buffer(out, sizeof out)), ==,
                   TC_OK);
  munit_assert_memory_equal(wrapped_length, out, wrapped);
  munit_assert_true(
      tc_test_all_value(out + wrapped_length, sizeof out - wrapped_length, KW_SENTINEL));

  memset(out, KW_SENTINEL, sizeof out);
  munit_assert_int(
      kw_unwrap(padded, k, span(wrapped, wrapped_length), buffer(out, sizeof out), &length), ==,
      TC_OK);
  munit_assert_size(length, ==, key_length);
  munit_assert_memory_equal(key_length, out, key_data);
  /* KWP padding is zero, and bytes past the working area stay untouched. */
  munit_assert_true(tc_test_all_zero(out + key_length, wrapped_length - 8u - key_length));
  munit_assert_true(tc_test_all_value(out + wrapped_length - 8u, sizeof out - (wrapped_length - 8u),
                                      KW_SENTINEL));

  /* RFC 3394 layout: key data at wrapped + 8, wrapped in place. */
  memset(work, KW_SENTINEL, sizeof work);
  memcpy(work + 8, key_data, key_length);
  munit_assert_int(kw_wrap(padded, k, span(work + 8, key_length), buffer(work, wrapped_length)), ==,
                   TC_OK);
  munit_assert_memory_equal(wrapped_length, work, wrapped);

  /* Exact alias in both directions. */
  memset(work, KW_SENTINEL, sizeof work);
  memcpy(work, key_data, key_length);
  munit_assert_int(kw_wrap(padded, k, span(work, key_length), buffer(work, wrapped_length)), ==,
                   TC_OK);
  munit_assert_memory_equal(wrapped_length, work, wrapped);
  length = 0;
  munit_assert_int(
      kw_unwrap(padded, k, span(work, wrapped_length), buffer(work, wrapped_length), &length), ==,
      TC_OK);
  munit_assert_size(length, ==, key_length);
  munit_assert_memory_equal(key_length, work, key_data);

  /* Unwrap from wrapped into wrapped + 8. */
  memcpy(work, wrapped, wrapped_length);
  length = 0;
  munit_assert_int(kw_unwrap(padded, k, span(work, wrapped_length),
                             buffer(work + 8, wrapped_length - 8u), &length),
                   ==, TC_OK);
  munit_assert_size(length, ==, key_length);
  munit_assert_memory_equal(key_length, work + 8, key_data);
}

TC_TEST(kw_rfc_examples)
{
  size_t i;
  for (i = 0; i < sizeof rfc3394_vectors / sizeof rfc3394_vectors[0]; ++i)
    kw_run_vector(0, &rfc3394_vectors[i]);
  for (i = 0; i < sizeof rfc5649_vectors / sizeof rfc5649_vectors[0]; ++i)
    kw_run_vector(1, &rfc5649_vectors[i]);
  return MUNIT_OK;
}

/* A wrap argument error leaves the output unchanged. */
static void kw_assert_wrap_rejected(int padded, TC_bytes kek, TC_bytes key_data, TC_buffer out,
                                    const uint8_t* check, size_t check_length)
{
  munit_assert_int(kw_wrap(padded, kek, key_data, out), ==, TC_ERROR);
  munit_assert_true(tc_test_all_value(check, check_length, KW_SENTINEL));
}

/* An unwrap argument error leaves the output and the length unchanged. */
static void kw_assert_unwrap_rejected(int padded, TC_bytes kek, TC_bytes wrapped, TC_buffer out,
                                      const uint8_t* check, size_t check_length)
{
  size_t length = SIZE_MAX;
  munit_assert_int(kw_unwrap(padded, kek, wrapped, out, &length), ==, TC_ERROR);
  munit_assert_true(tc_test_all_value(check, check_length, KW_SENTINEL));
  munit_assert_size(length, ==, SIZE_MAX);
}

TC_TEST(kw_arguments)
{
  uint8_t kek[40], data[KW_BUFFER], out[KW_BUFFER];
  const TC_bytes k = span(kek, TC_AES_KEYLEN);
  size_t kek_length;
  int padded;

  kw_initialize_sbox();
  memset(kek, 0x11, sizeof kek);
  memset(data, 0x22, sizeof data);
  memset(out, KW_SENTINEL, sizeof out);

  for (padded = 0; padded <= 1; ++padded) {
    const size_t key_length = 16;
    const size_t wrapped_length = 24;
    /* Every KEK length the build rejects, and a NULL KEK. */
    for (kek_length = 0; kek_length <= sizeof kek; ++kek_length) {
      if (TC_AES_KW_KEK_LENGTH_SUPPORTED(kek_length))
        continue;
      kw_assert_wrap_rejected(padded, span(kek, kek_length), span(data, key_length),
                              buffer(out, sizeof out), out, sizeof out);
      kw_assert_unwrap_rejected(padded, span(kek, kek_length), span(data, wrapped_length),
                                buffer(out, sizeof out), out, sizeof out);
    }
    kw_assert_wrap_rejected(padded, span(NULL, TC_AES_KEYLEN), span(data, key_length),
                            buffer(out, sizeof out), out, sizeof out);
    kw_assert_unwrap_rejected(padded, span(NULL, TC_AES_KEYLEN), span(data, wrapped_length),
                              buffer(out, sizeof out), out, sizeof out);
    /* NULL spans and buffers with a nonzero length or capacity. */
    kw_assert_wrap_rejected(padded, k, span(NULL, key_length), buffer(out, sizeof out), out,
                            sizeof out);
    kw_assert_wrap_rejected(padded, k, span(data, key_length), buffer(NULL, sizeof out), out,
                            sizeof out);
    kw_assert_unwrap_rejected(padded, k, span(NULL, wrapped_length), buffer(out, sizeof out), out,
                              sizeof out);
    kw_assert_unwrap_rejected(padded, k, span(data, wrapped_length), buffer(NULL, sizeof out), out,
                              sizeof out);
    /* One byte of capacity short. */
    kw_assert_wrap_rejected(padded, k, span(data, key_length), buffer(out, wrapped_length - 1u),
                            out, sizeof out);
    kw_assert_unwrap_rejected(padded, k, span(data, wrapped_length),
                              buffer(out, wrapped_length - 9u), out, sizeof out);
  }

  /* KW key data lengths outside 16.. multiples of 8. */
  {
    static const size_t bad_key[] = {0, 8, 15, 17, 23};
    static const size_t bad_wrapped[] = {0, 8, 16, 23, 25, 31};
    size_t i;
    for (i = 0; i < sizeof bad_key / sizeof bad_key[0]; ++i)
      kw_assert_wrap_rejected(0, k, span(data, bad_key[i]), buffer(out, sizeof out), out,
                              sizeof out);
    for (i = 0; i < sizeof bad_wrapped / sizeof bad_wrapped[0]; ++i)
      kw_assert_unwrap_rejected(0, k, span(data, bad_wrapped[i]), buffer(out, sizeof out), out,
                                sizeof out);
  }
  /* KWP accepts any nonempty key data and wrapped input of 16.. multiples of 8. */
  {
    static const size_t bad_wrapped[] = {0, 8, 15, 17, 23};
    size_t i;
    kw_assert_wrap_rejected(1, k, span(data, 0), buffer(out, sizeof out), out, sizeof out);
    kw_assert_wrap_rejected(1, k, span(NULL, 0), buffer(out, sizeof out), out, sizeof out);
    for (i = 0; i < sizeof bad_wrapped / sizeof bad_wrapped[0]; ++i)
      kw_assert_unwrap_rejected(1, k, span(data, bad_wrapped[i]), buffer(out, sizeof out), out,
                                sizeof out);
    /* KWP capacity follows the padded size. */
    kw_assert_wrap_rejected(1, k, span(data, 17), buffer(out, 31), out, sizeof out);
  }

  /* KWP unwrap needs a length output outside its working area. */
  {
    uint8_t wrapped[32];
    size_t aligned[8];
    uint8_t* area = (uint8_t*)aligned;
    kw_test_kek(kek);
    munit_assert_int(TC_AES_KWP_wrap(k, span(data, 20), buffer(wrapped, sizeof wrapped)), ==,
                     TC_OK);
    munit_assert_int(TC_AES_KWP_unwrap(k, span(wrapped, sizeof wrapped), buffer(out, 24), NULL), ==,
                     TC_ERROR);
    munit_assert_true(tc_test_all_value(out, sizeof out, KW_SENTINEL));
    memset(aligned, KW_SENTINEL, sizeof aligned);
    munit_assert_int(
        TC_AES_KWP_unwrap(k, span(wrapped, sizeof wrapped), buffer(area, 24), &aligned[1]), ==,
        TC_ERROR);
    munit_assert_true(tc_test_all_value(aligned, sizeof aligned, KW_SENTINEL));
    /* The length may sit right after the working area. */
    munit_assert_int(TC_AES_KWP_unwrap(k, span(wrapped, sizeof wrapped), buffer(area, 24),
                                       &aligned[24 / sizeof(size_t)]),
                     ==, TC_OK);
    munit_assert_size(aligned[24 / sizeof(size_t)], ==, 20);
    munit_assert_memory_equal(20, area, data);
  }
  return MUNIT_OK;
}

TC_TEST(kw_limits)
{
  uint8_t kek[TC_AES_KEYLEN], data[32], out[32];
  const TC_bytes k = span(kek, sizeof kek);
  kw_initialize_sbox();
  kw_test_kek(kek);
  memset(data, 0x33, sizeof data);
  memset(out, KW_SENTINEL, sizeof out);
  /* The length checks run before any read, so the spans below describe more
   * memory than the small buffers hold. */
#if SIZE_MAX > UINT32_MAX
  kw_assert_wrap_rejected(1, k, span(data, (size_t)TC_AES_KWP_MAX_KEY_DATA_BYTES + 1u),
                          buffer(out, SIZE_MAX), out, sizeof out);
  kw_assert_wrap_rejected(1, k, span(data, (size_t)TC_AES_KWP_MAX_KEY_DATA_BYTES + 8u),
                          buffer(out, SIZE_MAX), out, sizeof out);
  kw_assert_wrap_rejected(0, k, span(data, (size_t)TC_AES_KW_MAX_KEY_DATA_BYTES + 8u),
                          buffer(out, SIZE_MAX), out, sizeof out);
  kw_assert_unwrap_rejected(1, k, span(data, (size_t)TC_AES_KWP_MAX_WRAPPED_BYTES + 8u),
                            buffer(out, SIZE_MAX), out, sizeof out);
  kw_assert_unwrap_rejected(0, k, span(data, (size_t)TC_AES_KW_MAX_WRAPPED_BYTES + 8u),
                            buffer(out, SIZE_MAX), out, sizeof out);
#endif
  /* Output sizes above SIZE_MAX. */
  kw_assert_wrap_rejected(0, k, span(data, SIZE_MAX - 7u), buffer(out, SIZE_MAX), out, sizeof out);
  kw_assert_wrap_rejected(1, k, span(data, SIZE_MAX - 14u), buffer(out, SIZE_MAX), out, sizeof out);
  return MUNIT_OK;
}

/* Wrap length bytes of pattern data under the test KEK into wrapped. */
static size_t kw_make_wrapped(int padded, size_t length, uint8_t* key_data, uint8_t* wrapped)
{
  uint8_t kek[TC_AES_KEYLEN];
  const size_t wrapped_length =
      padded ? TC_AES_KWP_WRAPPED_BYTES(length) : TC_AES_KW_WRAPPED_BYTES(length);
  kw_test_kek(kek);
  tc_test_fill_bytes(key_data, length, 0x5c, 3);
  munit_assert_int(kw_wrap(padded, span(kek, sizeof kek), span(key_data, length),
                           buffer(wrapped, wrapped_length)),
                   ==, TC_OK);
  return wrapped_length;
}

TC_TEST(kw_integrity)
{
  static const struct {
    int padded;
    size_t length;
  } cases[] = {{0, 16}, {0, 24}, {1, 7}, {1, 20}};
  uint8_t kek[TC_AES_KEYLEN], key_data[32], wrapped[40], out[48];
  size_t c;
  kw_initialize_sbox();
  kw_test_kek(kek);
  for (c = 0; c < sizeof cases / sizeof cases[0]; ++c) {
    const int padded = cases[c].padded;
    const size_t wrapped_length = kw_make_wrapped(padded, cases[c].length, key_data, wrapped);
    const size_t area = wrapped_length - 8u;
    size_t byte;
    for (byte = 0; byte < wrapped_length; ++byte) {
      unsigned bit;
      for (bit = 0; bit < 8; ++bit) {
        size_t length = SIZE_MAX;
        wrapped[byte] ^= (uint8_t)(1u << bit);
        memset(out, KW_SENTINEL, sizeof out);
        munit_assert_int(kw_unwrap(padded, span(kek, sizeof kek), span(wrapped, wrapped_length),
                                   buffer(out, sizeof out), &length),
                         ==, TC_MISMATCH);
        munit_assert_true(tc_test_all_zero(out, area));
        munit_assert_true(tc_test_all_value(out + area, sizeof out - area, KW_SENTINEL));
        munit_assert_size(length, ==, SIZE_MAX);
        wrapped[byte] ^= (uint8_t)(1u << bit);
      }
    }
    /* The unmodified input still unwraps. */
    {
      size_t length = 0;
      munit_assert_int(kw_unwrap(padded, span(kek, sizeof kek), span(wrapped, wrapped_length),
                                 buffer(out, sizeof out), &length),
                       ==, TC_OK);
      munit_assert_size(length, ==, cases[c].length);
      munit_assert_memory_equal(length, out, key_data);
    }
  }
  return MUNIT_OK;
}

/* Test-only reference cipher for the chosen-S cases below. */
#if TC_AES_ENABLE_DYNAMIC
#define KW_HAVE_REFERENCE 1
static void kw_reference_encrypt(const uint8_t* kek, uint8_t block[16])
{
  TC_AES_dynamic_key schedule;
  munit_assert_int(TC_AES_dynamic_key_init(&schedule, (TC_bytes){kek, TC_AES_KEYLEN}), ==, TC_OK);
  munit_assert_int(TC_AES_dynamic_encrypt(&schedule, (TC_buffer){block, TC_AES_BLOCKLEN}), ==,
                   TC_OK);
  TC_AES_dynamic_key_clear(&schedule);
}
#elif TC_AES_ENABLE_ECB
#define KW_HAVE_REFERENCE 1
static void kw_reference_encrypt(const uint8_t* kek, uint8_t block[16])
{
  struct TC_AES_key_ctx schedule;
  munit_assert_int(TC_AES_key_init(&schedule, (TC_bytes){kek, TC_AES_KEYLEN}), ==, TC_OK);
  munit_assert_int(TC_AES_ECB_encrypt(&schedule, (TC_buffer){block, TC_AES_BLOCKLEN}), ==, TC_OK);
  TC_AES_key_ctx_clear(&schedule);
}
#else
#define KW_HAVE_REFERENCE 0
#endif

#if KW_HAVE_REFERENCE
/* Reference W (SP 800-38F section 6.1 Algorithm 1) over s, or one block
 * encryption for two semiblocks (section 6.3 Algorithm 5 step 5). */
static void kw_reference_wrap(const uint8_t* kek, uint8_t* s, size_t length)
{
  const size_t n = length / 8u - 1u;
  uint8_t block[16];
  uint64_t t = 1;
  unsigned j;
  size_t i;
  if (length == 16) {
    kw_reference_encrypt(kek, s);
    return;
  }
  for (j = 0; j < 6; ++j) {
    for (i = 1; i <= n; ++i, ++t) {
      unsigned k;
      memcpy(block, s, 8);
      memcpy(block + 8, s + 8 * i, 8);
      kw_reference_encrypt(kek, block);
      for (k = 0; k < 8; ++k)
        s[k] = block[k] ^ (uint8_t)(t >> (8u * (7u - k)));
      memcpy(s + 8 * i, block + 8, 8);
    }
  }
}

/* Build S = ICV2 || [mli]32 || padded data from the chosen fields, wrap it
 * and unwrap the result. */
static TC_status kwp_unwrap_chosen(const uint8_t icv[4], uint32_t mli, const uint8_t* padded,
                                   size_t padded_length, uint8_t* out, size_t* length)
{
  uint8_t kek[TC_AES_KEYLEN], s[40];
  kw_test_kek(kek);
  memcpy(s, icv, 4);
  s[4] = (uint8_t)(mli >> 24);
  s[5] = (uint8_t)(mli >> 16);
  s[6] = (uint8_t)(mli >> 8);
  s[7] = (uint8_t)mli;
  memcpy(s + 8, padded, padded_length);
  kw_reference_wrap(kek, s, padded_length + 8u);
  memset(out, KW_SENTINEL, 40);
  return TC_AES_KWP_unwrap(span(kek, sizeof kek), span(s, padded_length + 8u),
                           buffer(out, padded_length), length);
}

static void kwp_assert_chosen_rejected(const uint8_t icv[4], uint32_t mli, const uint8_t* padded,
                                       size_t padded_length)
{
  uint8_t out[40];
  size_t length = SIZE_MAX;
  munit_assert_int(kwp_unwrap_chosen(icv, mli, padded, padded_length, out, &length), ==,
                   TC_MISMATCH);
  munit_assert_true(tc_test_all_zero(out, padded_length));
  munit_assert_true(
      tc_test_all_value(out + padded_length, sizeof out - padded_length, KW_SENTINEL));
  munit_assert_size(length, ==, SIZE_MAX);
}
#endif

/* SP 800-38F section 6.3 Algorithm 6 steps 4 to 8: the ICV2 check, the
 * length indicator range 8(n-2) < MLI <= 8(n-1) and zero padding. */
TC_TEST(kwp_length_and_padding)
{
#if KW_HAVE_REFERENCE
  static const uint8_t icv2[4] = {0xa6, 0x59, 0x59, 0xa6};
  size_t n;
  kw_initialize_sbox();
  for (n = 2; n <= 4; ++n) {
    const size_t padded_length = 8u * (n - 1u);
    const uint32_t top = (uint32_t)padded_length;
    uint8_t padded[24], out[40];
    uint32_t mli;
    unsigned k;
    tc_test_fill_bytes(padded, padded_length, 0x71, 5);
    kwp_assert_chosen_rejected(icv2, 0, padded, padded_length);
    kwp_assert_chosen_rejected(icv2, top - 8u, padded, padded_length);
    kwp_assert_chosen_rejected(icv2, top + 1u, padded, padded_length);
    kwp_assert_chosen_rejected(icv2, 0xffffffffu, padded, padded_length);
    for (k = 0; k < 4; ++k) {
      uint8_t icv[4];
      memcpy(icv, icv2, sizeof icv);
      icv[k] ^= 0x01;
      kwp_assert_chosen_rejected(icv, top, padded, padded_length);
    }
    for (mli = top - 7u; mli <= top; ++mli) {
      size_t length = SIZE_MAX, position;
      memset(padded + mli, 0, padded_length - mli);
      munit_assert_int(kwp_unwrap_chosen(icv2, mli, padded, padded_length, out, &length), ==,
                       TC_OK);
      munit_assert_size(length, ==, mli);
      munit_assert_memory_equal(padded_length, out, padded);
      /* One nonzero byte at each padding position. */
      for (position = mli; position < padded_length; ++position) {
        padded[position] = 0x01;
        kwp_assert_chosen_rejected(icv2, mli, padded, padded_length);
        padded[position] = 0;
      }
      tc_test_fill_bytes(padded, padded_length, 0x71, 5);
    }
  }
  return MUNIT_OK;
#else
  return MUNIT_SKIP;
#endif
}

TC_TEST(kw_overlap)
{
  static const size_t offsets[] = {1, 3, 5, 8, 11};
  uint8_t kek[TC_AES_KEYLEN], key_data[24], expected[32], big[80];
  const TC_bytes k = span(kek, sizeof kek);
  int padded;
  kw_initialize_sbox();
  kw_test_kek(kek);
  for (padded = 0; padded <= 1; ++padded) {
    const size_t key_length = padded ? 20u : 24u;
    const size_t wrapped_length = kw_make_wrapped(padded, key_length, key_data, expected);
    size_t i;
    for (i = 0; i < sizeof offsets / sizeof offsets[0]; ++i) {
      const size_t shift = offsets[i];
      size_t length = 0;
      /* Input after the output start, then before it. */
      memcpy(big + shift, key_data, key_length);
      munit_assert_int(
          kw_wrap(padded, k, span(big + shift, key_length), buffer(big, wrapped_length)), ==,
          TC_OK);
      munit_assert_memory_equal(wrapped_length, big, expected);
      memcpy(big, key_data, key_length);
      munit_assert_int(
          kw_wrap(padded, k, span(big, key_length), buffer(big + shift, wrapped_length)), ==,
          TC_OK);
      munit_assert_memory_equal(wrapped_length, big + shift, expected);

      memcpy(big + shift, expected, wrapped_length);
      munit_assert_int(kw_unwrap(padded, k, span(big + shift, wrapped_length),
                                 buffer(big, wrapped_length - 8u), &length),
                       ==, TC_OK);
      munit_assert_size(length, ==, key_length);
      munit_assert_memory_equal(key_length, big, key_data);
      memcpy(big, expected, wrapped_length);
      munit_assert_int(kw_unwrap(padded, k, span(big, wrapped_length),
                                 buffer(big + shift, wrapped_length - 8u), &length),
                       ==, TC_OK);
      munit_assert_memory_equal(key_length, big + shift, key_data);
    }
    /* A KEK inside the output region is read before the first write. */
    memcpy(big + 40, key_data, key_length);
    memcpy(big + 8, kek, sizeof kek);
    munit_assert_int(kw_wrap(padded, span(big + 8, sizeof kek), span(big + 40, key_length),
                             buffer(big, wrapped_length)),
                     ==, TC_OK);
    munit_assert_memory_equal(wrapped_length, big, expected);
    memcpy(big + 40, expected, wrapped_length);
    memcpy(big + 4, kek, sizeof kek);
    {
      size_t length = 0;
      munit_assert_int(kw_unwrap(padded, span(big + 4, sizeof kek), span(big + 40, wrapped_length),
                                 buffer(big, wrapped_length - 8u), &length),
                       ==, TC_OK);
      munit_assert_memory_equal(key_length, big, key_data);
    }
  }
  return MUNIT_OK;
}

#if TC_AES_CAVP
enum { KW_CAVP_LINE = 2048, KW_CAVP_FIELD = 1024 };

/* One KWVS file (CAVS 17.4 KW, CAVS 21.4 KWP): 5 plaintext lengths with 100
 * records each. AD files mark 20 records per length FAIL. */
static void kw_run_cavp_file(int padded, int decrypt, unsigned bits)
{
  static char line[KW_CAVP_LINE];
  static uint8_t kek[32], plain[KW_CAVP_FIELD], cipher[KW_CAVP_FIELD], out[KW_CAVP_FIELD];
  char name[32];
  tc_cavp_reader reader;
  tc_cavp_event event;
  size_t kek_length = 0, plain_length = 0, cipher_length = 0;
  unsigned records = 0, sections = 0, failures = 0;
  int have_plain = 0, expect_fail = 0;

  snprintf(name, sizeof name, "%s_%s_%u.txt", padded ? "KWP" : "KW", decrypt ? "AD" : "AE", bits);
  munit_assert_true(tc_cavp_open(&reader, KW_CAVP_DIR, name, line, sizeof line));
  while ((event = tc_cavp_next(&reader)) != TC_CAVP_END) {
    munit_assert_int(event, !=, TC_CAVP_FAILURE);
    if (event == TC_CAVP_HEADER) {
      ++sections;
    } else if (event == TC_CAVP_FIELD) {
      if (tc_cavp_is(&reader, "K"))
        munit_assert_true(
            tc_test_hex_decode(reader.value, TC_TEST_HEX_FIELD, kek, sizeof kek, &kek_length));
      else if (tc_cavp_is(&reader, "P")) {
        munit_assert_true(tc_test_hex_decode(reader.value, TC_TEST_HEX_FIELD, plain, sizeof plain,
                                             &plain_length));
        have_plain = 1;
      } else if (tc_cavp_is(&reader, "C"))
        munit_assert_true(tc_test_hex_decode(reader.value, TC_TEST_HEX_FIELD, cipher, sizeof cipher,
                                             &cipher_length));
      else if (tc_cavp_is(&reader, "FAIL"))
        expect_fail = 1;
    } else if (event == TC_CAVP_RECORD_END) {
      size_t length = SIZE_MAX;
      munit_assert_size(kek_length * 8u, ==, bits);
      memset(out, KW_SENTINEL, sizeof out);
      if (!decrypt) {
        munit_assert_true(have_plain);
        munit_assert_int(kw_wrap(padded, span(kek, kek_length), span(plain, plain_length),
                                 buffer(out, sizeof out)),
                         ==, TC_OK);
        munit_assert_memory_equal(cipher_length, out, cipher);
      } else if (expect_fail) {
        munit_assert_int(kw_unwrap(padded, span(kek, kek_length), span(cipher, cipher_length),
                                   buffer(out, sizeof out), &length),
                         ==, TC_MISMATCH);
        munit_assert_true(tc_test_all_zero(out, cipher_length - 8u));
        munit_assert_size(length, ==, SIZE_MAX);
        ++failures;
      } else {
        munit_assert_true(have_plain);
        munit_assert_int(kw_unwrap(padded, span(kek, kek_length), span(cipher, cipher_length),
                                   buffer(out, sizeof out), &length),
                         ==, TC_OK);
        munit_assert_size(length, ==, plain_length);
        munit_assert_memory_equal(plain_length, out, plain);
      }
      ++records;
      have_plain = 0;
      expect_fail = 0;
      kek_length = plain_length = cipher_length = 0;
    }
  }
  tc_cavp_close(&reader);
  munit_assert_uint(records, ==, 500);
  munit_assert_uint(sections, ==, 5);
  munit_assert_uint(failures, ==, decrypt ? 100u : 0u);
}

/* Each library runs the files for the KEK sizes it accepts. */
TC_TEST(kw_cavp)
{
  static const unsigned sizes[] = {128, 192, 256};
  size_t i;
  unsigned ran = 0;
  kw_initialize_sbox();
  for (i = 0; i < sizeof sizes / sizeof sizes[0]; ++i) {
    int padded, decrypt;
    if (!TC_AES_KW_KEK_LENGTH_SUPPORTED(sizes[i] / 8u))
      continue;
    for (padded = 0; padded <= 1; ++padded)
      for (decrypt = 0; decrypt <= 1; ++decrypt)
        kw_run_cavp_file(padded, decrypt, sizes[i]);
    ++ran;
  }
  munit_assert_uint(ran, >, 0);
  return MUNIT_OK;
}
#endif

TC_TEST_SHARED(test_kw)
{
  kw_initialize_sbox();
  if (kw_rfc_examples(NULL, NULL) != MUNIT_OK || kw_arguments(NULL, NULL) != MUNIT_OK ||
      kw_limits(NULL, NULL) != MUNIT_OK || kw_integrity(NULL, NULL) != MUNIT_OK ||
      kw_overlap(NULL, NULL) != MUNIT_OK)
    return MUNIT_FAIL;
  {
    const MunitResult result = kwp_length_and_padding(NULL, NULL);
    if (result != MUNIT_OK && result != MUNIT_SKIP)
      return MUNIT_FAIL;
  }
#if TC_AES_CAVP
  if (kw_cavp(NULL, NULL) != MUNIT_OK)
    return MUNIT_FAIL;
#endif
  return MUNIT_OK;
}

#else

TC_TEST_SHARED(test_kw)
{
  return MUNIT_SKIP;
}

#endif
