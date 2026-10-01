/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-FileCopyrightText: Mistial Dev
 *
 * AES-CMAC tests: SP 800-38B Appendix D, NIST CAVP Gen/Ver, Wycheproof.
 * Test-only translation unit.
 */

#include <stddef.h>
#include <tiny_crypto/aes.h>
#include "munit.h"
#include "cavp.h"
#include "test_io.h"
#include "test_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef CMAC_WYCHEPROOF_FILE
#define CMAC_WYCHEPROOF_FILE "tests/vectors/wycheproof/testvectors_v1/aes_cmac_test.json"
#endif

#ifndef CMAC_CAVP_DIR
#define CMAC_CAVP_DIR "tests/vectors/aes/cmac"
#endif

#if TC_AES_ENABLE_CMAC

#if TC_AES_SBOX_MODE == TC_AES_SBOX_MODE_RUNTIME
static void cmac_initialize_sbox(void)
{
  TC_AES_init_sbox();
}
#else
static void cmac_initialize_sbox(void)
{}
#endif

/* NIST SP 800-38B Appendix D — full 16-byte tags. */
TC_TEST(test_cmac_sp800_38b)
{
  uint8_t tag[TC_AES_CMAC_TAG_MAX];

#if TC_AES_KEY_BITS == 128
  {
    static const uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    static const uint8_t m1[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                   0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    static const uint8_t m2[40] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
                                   0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57,
                                   0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
                                   0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11};
    static const uint8_t m3[64] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
                                   0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
                                   0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
                                   0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
                                   0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
                                   0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
    static const uint8_t t0[16] = {0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
                                   0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46};
    static const uint8_t t1[16] = {0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
                                   0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c};
    static const uint8_t t2[16] = {0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
                                   0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27};
    static const uint8_t t3[16] = {0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
                                   0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe};

    munit_assert_int(
        TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){NULL, 0}, (TC_buffer){tag, 16}), ==,
        TC_OK);
    munit_assert_memory_equal(16, tag, t0);
    munit_assert_int(
        TC_AES_CMAC_verify((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){NULL, 0}, (TC_bytes){t0, 16}),
        ==, TC_OK);

    munit_assert_int(TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){m1, sizeof(m1)},
                                 (TC_buffer){tag, 16}),
                     ==, TC_OK);
    munit_assert_memory_equal(16, tag, t1);

    munit_assert_int(TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){m2, sizeof(m2)},
                                 (TC_buffer){tag, 16}),
                     ==, TC_OK);
    munit_assert_memory_equal(16, tag, t2);

    munit_assert_int(TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){m3, sizeof(m3)},
                                 (TC_buffer){tag, 16}),
                     ==, TC_OK);
    munit_assert_memory_equal(16, tag, t3);

    /* Truncation: leading octets of T */
    munit_assert_int(TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){m1, sizeof(m1)},
                                 (TC_buffer){tag, 8}),
                     ==, TC_OK);
    munit_assert_memory_equal(8, tag, t1);
    munit_assert_int(TC_AES_CMAC_verify((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){m1, sizeof(m1)},
                                        (TC_bytes){t1, 8}),
                     ==, TC_OK);
  }
#elif TC_AES_KEY_BITS == 192
  {
    static const uint8_t key[24] = {0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                                    0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                                    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
    static const uint8_t m1[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                   0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    static const uint8_t m2[40] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
                                   0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57,
                                   0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
                                   0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11};
    static const uint8_t m3[64] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
                                   0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
                                   0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
                                   0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
                                   0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
                                   0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
    static const uint8_t t0[16] = {0xd1, 0x7d, 0xdf, 0x46, 0xad, 0xaa, 0xcd, 0xe5,
                                   0x31, 0xca, 0xc4, 0x83, 0xde, 0x7a, 0x93, 0x67};
    static const uint8_t t1[16] = {0x9e, 0x99, 0xa7, 0xbf, 0x31, 0xe7, 0x10, 0x90,
                                   0x06, 0x62, 0xf6, 0x5e, 0x61, 0x7c, 0x51, 0x84};
    static const uint8_t t2[16] = {0x8a, 0x1d, 0xe5, 0xbe, 0x2e, 0xb3, 0x1a, 0xad,
                                   0x08, 0x9a, 0x82, 0xe6, 0xee, 0x90, 0x8b, 0x0e};
    static const uint8_t t3[16] = {0xa1, 0xd5, 0xdf, 0x0e, 0xed, 0x79, 0x0f, 0x79,
                                   0x4d, 0x77, 0x58, 0x96, 0x59, 0xf3, 0x9a, 0x11};

    munit_assert_int(
        TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){NULL, 0}, (TC_buffer){tag, 16}), ==,
        TC_OK);
    munit_assert_memory_equal(16, tag, t0);
    munit_assert_int(TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){m1, sizeof(m1)},
                                 (TC_buffer){tag, 16}),
                     ==, TC_OK);
    munit_assert_memory_equal(16, tag, t1);
    munit_assert_int(TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){m2, sizeof(m2)},
                                 (TC_buffer){tag, 16}),
                     ==, TC_OK);
    munit_assert_memory_equal(16, tag, t2);
    munit_assert_int(TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){m3, sizeof(m3)},
                                 (TC_buffer){tag, 16}),
                     ==, TC_OK);
    munit_assert_memory_equal(16, tag, t3);
  }
#else /* TC_AES_KEY_BITS == 256 */
  {
    static const uint8_t key[32] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                                    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                                    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                                    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
    static const uint8_t m1[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                   0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    static const uint8_t m2[40] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
                                   0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57,
                                   0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
                                   0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11};
    static const uint8_t m3[64] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
                                   0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
                                   0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
                                   0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
                                   0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
                                   0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
    static const uint8_t t0[16] = {0x02, 0x89, 0x62, 0xf6, 0x1b, 0x7b, 0xf8, 0x9e,
                                   0xfc, 0x6b, 0x55, 0x1f, 0x46, 0x67, 0xd9, 0x83};
    static const uint8_t t1[16] = {0x28, 0xa7, 0x02, 0x3f, 0x45, 0x2e, 0x8f, 0x82,
                                   0xbd, 0x4b, 0xf2, 0x8d, 0x8c, 0x37, 0xc3, 0x5c};
    static const uint8_t t2[16] = {0xaa, 0xf3, 0xd8, 0xf1, 0xde, 0x56, 0x40, 0xc2,
                                   0x32, 0xf5, 0xb1, 0x69, 0xb9, 0xc9, 0x11, 0xe6};
    static const uint8_t t3[16] = {0xe1, 0x99, 0x21, 0x90, 0x54, 0x9f, 0x6e, 0xd5,
                                   0x69, 0x6a, 0x2c, 0x05, 0x6c, 0x31, 0x54, 0x10};

    munit_assert_int(
        TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){NULL, 0}, (TC_buffer){tag, 16}), ==,
        TC_OK);
    munit_assert_memory_equal(16, tag, t0);
    munit_assert_int(TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){m1, sizeof(m1)},
                                 (TC_buffer){tag, 16}),
                     ==, TC_OK);
    munit_assert_memory_equal(16, tag, t1);
    munit_assert_int(TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){m2, sizeof(m2)},
                                 (TC_buffer){tag, 16}),
                     ==, TC_OK);
    munit_assert_memory_equal(16, tag, t2);
    munit_assert_int(TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){m3, sizeof(m3)},
                                 (TC_buffer){tag, 16}),
                     ==, TC_OK);
    munit_assert_memory_equal(16, tag, t3);
  }
#endif

  return MUNIT_OK;
}

TC_TEST(test_cmac_api)
{
  uint8_t key[TC_AES_KEYLEN];
  uint8_t msg[16];
  uint8_t tag[TC_AES_CMAC_TAG_MAX];

  memset(key, 0x11, sizeof(key));
  memset(msg, 0x22, sizeof(msg));

  munit_assert_int(TC_AES_CMAC((TC_bytes){NULL, TC_AES_KEYLEN}, (TC_bytes){msg, sizeof(msg)},
                               (TC_buffer){tag, 16}),
                   ==, TC_ERROR);
  munit_assert_int(TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){msg, sizeof(msg)},
                               (TC_buffer){NULL, 16}),
                   ==, TC_ERROR);
  munit_assert_int(TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){msg, sizeof(msg)},
                               (TC_buffer){tag, 0}),
                   ==, TC_ERROR);
  munit_assert_int(TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){msg, sizeof(msg)},
                               (TC_buffer){tag, 17}),
                   ==, TC_ERROR);
  munit_assert_int(
      TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){NULL, 1}, (TC_buffer){tag, 16}), ==,
      TC_ERROR);
  munit_assert_int(TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){msg, sizeof(msg)},
                               (TC_buffer){tag, 16}),
                   ==, TC_OK);
  munit_assert_int(TC_AES_CMAC_verify((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){msg, sizeof(msg)},
                                      (TC_bytes){tag, 16}),
                   ==, TC_OK);

  tag[0] ^= 1u;
  munit_assert_int(TC_AES_CMAC_verify((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){msg, sizeof(msg)},
                                      (TC_bytes){tag, 16}),
                   ==, TC_MISMATCH);
  tag[0] ^= 1u;

  munit_assert_int(TC_AES_CMAC_verify((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){msg, sizeof(msg)},
                                      (TC_bytes){NULL, 16}),
                   ==, TC_ERROR);
  munit_assert_int(TC_AES_CMAC_verify((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){msg, sizeof(msg)},
                                      (TC_bytes){tag, 0}),
                   ==, TC_ERROR);

  return MUNIT_OK;
}

/* The default entry points take TC_MIN_TAG_LEN..16 bytes and the _short_tag
 * forms take 1..TC_MIN_TAG_LEN - 1 (SP 800-38B Appendix A.2). A rejected
 * length leaves the tag buffer unchanged. */
TC_TEST(test_cmac_tag_policy)
{
  uint8_t key[TC_AES_KEYLEN];
  uint8_t msg[20];
  uint8_t full[TC_AES_CMAC_TAG_MAX];
  uint8_t tag[TC_AES_CMAC_TAG_MAX];
  const size_t below = TC_MIN_TAG_LEN - 1u;

  memset(key, 0x3c, sizeof(key));
  memset(msg, 0x5a, sizeof(msg));
  munit_assert_int(TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){msg, sizeof(msg)},
                               (TC_buffer){full, sizeof(full)}),
                   ==, TC_OK);

  /* Default entry: min - 1 is rejected, min is accepted. */
  memset(tag, 0xa5, sizeof(tag));
  munit_assert_int(TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){msg, sizeof(msg)},
                               (TC_buffer){tag, below}),
                   ==, TC_ERROR);
  munit_assert_true(tc_test_all_value(tag, sizeof(tag), 0xa5));
  munit_assert_int(TC_AES_CMAC_verify((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){msg, sizeof(msg)},
                                      (TC_bytes){full, below}),
                   ==, TC_ERROR);
  munit_assert_int(TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){msg, sizeof(msg)},
                               (TC_buffer){tag, TC_MIN_TAG_LEN}),
                   ==, TC_OK);
  munit_assert_memory_equal(TC_MIN_TAG_LEN, tag, full);
  munit_assert_int(TC_AES_CMAC_verify((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){msg, sizeof(msg)},
                                      (TC_bytes){full, TC_MIN_TAG_LEN}),
                   ==, TC_OK);

  /* Short-tag entry: 1..min - 1 are accepted, 0 and min are rejected. */
  memset(tag, 0xa5, sizeof(tag));
  munit_assert_int(TC_AES_CMAC_short_tag((TC_bytes){key, TC_AES_KEYLEN},
                                         (TC_bytes){msg, sizeof(msg)}, (TC_buffer){tag, 0}),
                   ==, TC_ERROR);
  munit_assert_int(TC_AES_CMAC_short_tag((TC_bytes){key, TC_AES_KEYLEN},
                                         (TC_bytes){msg, sizeof(msg)},
                                         (TC_buffer){tag, TC_MIN_TAG_LEN}),
                   ==, TC_ERROR);
  munit_assert_int(TC_AES_CMAC_short_tag((TC_bytes){NULL, TC_AES_KEYLEN},
                                         (TC_bytes){msg, sizeof(msg)}, (TC_buffer){tag, below}),
                   ==, TC_ERROR);
  munit_assert_int(TC_AES_CMAC_short_tag((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){NULL, 1},
                                         (TC_buffer){tag, below}),
                   ==, TC_ERROR);
  munit_assert_true(tc_test_all_value(tag, sizeof(tag), 0xa5));
  munit_assert_int(TC_AES_CMAC_short_tag((TC_bytes){key, TC_AES_KEYLEN},
                                         (TC_bytes){msg, sizeof(msg)}, (TC_buffer){NULL, below}),
                   ==, TC_ERROR);
  munit_assert_int(TC_AES_CMAC_short_tag((TC_bytes){key, TC_AES_KEYLEN},
                                         (TC_bytes){msg, sizeof(msg)}, (TC_buffer){tag, 1}),
                   ==, TC_OK);
  munit_assert_uint8(tag[0], ==, full[0]);
  munit_assert_int(TC_AES_CMAC_short_tag((TC_bytes){key, TC_AES_KEYLEN},
                                         (TC_bytes){msg, sizeof(msg)}, (TC_buffer){tag, below}),
                   ==, TC_OK);
  munit_assert_memory_equal(below, tag, full);
  munit_assert_true(tc_test_all_value(tag + below, sizeof(tag) - below, 0xa5));

  munit_assert_int(TC_AES_CMAC_verify_short_tag((TC_bytes){key, TC_AES_KEYLEN},
                                                (TC_bytes){msg, sizeof(msg)}, (TC_bytes){full, 1}),
                   ==, TC_OK);
  munit_assert_int(TC_AES_CMAC_verify_short_tag((TC_bytes){key, TC_AES_KEYLEN},
                                                (TC_bytes){msg, sizeof(msg)},
                                                (TC_bytes){full, below}),
                   ==, TC_OK);
  munit_assert_int(TC_AES_CMAC_verify_short_tag((TC_bytes){key, TC_AES_KEYLEN},
                                                (TC_bytes){msg, sizeof(msg)}, (TC_bytes){full, 0}),
                   ==, TC_ERROR);
  munit_assert_int(TC_AES_CMAC_verify_short_tag((TC_bytes){key, TC_AES_KEYLEN},
                                                (TC_bytes){msg, sizeof(msg)},
                                                (TC_bytes){full, TC_MIN_TAG_LEN}),
                   ==, TC_ERROR);
  munit_assert_int(TC_AES_CMAC_verify_short_tag((TC_bytes){key, TC_AES_KEYLEN},
                                                (TC_bytes){msg, sizeof(msg)},
                                                (TC_bytes){NULL, below}),
                   ==, TC_ERROR);
  full[below - 1u] ^= 0x01u;
  munit_assert_int(TC_AES_CMAC_verify_short_tag((TC_bytes){key, TC_AES_KEYLEN},
                                                (TC_bytes){msg, sizeof(msg)},
                                                (TC_bytes){full, below}),
                   ==, TC_MISMATCH);
  return MUNIT_OK;
}

/* Streaming context must match the one-shot for every split pattern,
 * including an empty message and a message ending on a block boundary. */
TC_TEST(test_cmac_streaming)
{
  static const size_t lengths[] = {0, 1, 15, 16, 17, 32, 40, 64, 100};
  static const size_t splits[] = {1, 15, 16, 17, 40};
  uint8_t key[TC_AES_KEYLEN];
  uint8_t msg[100];
  uint8_t expected[TC_AES_CMAC_TAG_MAX];
  uint8_t tag[TC_AES_CMAC_TAG_MAX];
  struct TC_AES_CMAC_ctx ctx;
  size_t li, si, i;

  for (i = 0; i < sizeof(key); ++i)
    key[i] = (uint8_t)(0xA0u + i);
  for (i = 0; i < sizeof(msg); ++i)
    msg[i] = (uint8_t)(i * 7u + 3u);

  for (li = 0; li < sizeof(lengths) / sizeof(lengths[0]); ++li) {
    const size_t len = lengths[li];
    munit_assert_int(TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){msg, len},
                                 (TC_buffer){expected, 16}),
                     ==, TC_OK);

    /* Single update. */
    munit_assert_int(TC_AES_CMAC_init(&ctx, (TC_bytes){key, TC_AES_KEYLEN}), ==, TC_OK);
    munit_assert_int(TC_AES_CMAC_update(&ctx, (TC_bytes){msg, len}), ==, TC_OK);
    munit_assert_int(TC_AES_CMAC_final(&ctx, (TC_buffer){tag, TC_AES_CMAC_TAG_MAX}), ==, TC_OK);
    munit_assert_memory_equal(16, tag, expected);

    /* Fixed-size chunks of every split size. */
    for (si = 0; si < sizeof(splits) / sizeof(splits[0]); ++si) {
      size_t pos = 0;
      munit_assert_int(TC_AES_CMAC_init(&ctx, (TC_bytes){key, TC_AES_KEYLEN}), ==, TC_OK);
      while (pos < len) {
        const size_t take = (len - pos) < splits[si] ? (len - pos) : splits[si];
        munit_assert_int(TC_AES_CMAC_update(&ctx, (TC_bytes){msg + pos, take}), ==, TC_OK);
        pos += take;
      }
      /* Zero-length updates must be no-ops anywhere in the stream. */
      munit_assert_int(TC_AES_CMAC_update(&ctx, (TC_bytes){NULL, 0}), ==, TC_OK);
      munit_assert_int(TC_AES_CMAC_final(&ctx, (TC_buffer){tag, TC_AES_CMAC_TAG_MAX}), ==, TC_OK);
      munit_assert_memory_equal(16, tag, expected);
    }
  }

  munit_assert_int(TC_AES_CMAC_init(NULL, (TC_bytes){key, TC_AES_KEYLEN}), ==, TC_ERROR);
  munit_assert_int(TC_AES_CMAC_init(&ctx, (TC_bytes){NULL, TC_AES_KEYLEN}), ==, TC_ERROR);
  memset(&ctx, 0, sizeof ctx);
  munit_assert_int(TC_AES_CMAC_update(&ctx, (TC_bytes){msg, 1}), ==, TC_ERROR);
  munit_assert_int(TC_AES_CMAC_final(&ctx, (TC_buffer){tag, TC_AES_CMAC_TAG_MAX}), ==, TC_ERROR);
  munit_assert_int(TC_AES_CMAC_init(&ctx, (TC_bytes){key, TC_AES_KEYLEN}), ==, TC_OK);
  munit_assert_int(TC_AES_CMAC_final(&ctx, (TC_buffer){tag, TC_AES_CMAC_TAG_MAX}), ==, TC_OK);
  munit_assert_int(TC_AES_CMAC_update(&ctx, (TC_bytes){msg, 1}), ==, TC_ERROR);
  munit_assert_int(TC_AES_CMAC_final(&ctx, (TC_buffer){tag, TC_AES_CMAC_TAG_MAX}), ==, TC_ERROR);
  TC_AES_CMAC_ctx_clear(&ctx);
  munit_assert_int(TC_AES_CMAC_final(&ctx, (TC_buffer){tag, TC_AES_CMAC_TAG_MAX}), ==, TC_ERROR);
  munit_assert_int(TC_AES_CMAC_init(&ctx, (TC_bytes){key, TC_AES_KEYLEN}), ==, TC_OK);
  munit_assert_int(TC_AES_CMAC_update(&ctx, (TC_bytes){NULL, 1}), ==, TC_ERROR);
  munit_assert_int(TC_AES_CMAC_final(&ctx, (TC_buffer){NULL, TC_AES_CMAC_TAG_MAX}), ==, TC_ERROR);
  TC_AES_CMAC_ctx_clear(&ctx);
  TC_AES_CMAC_ctx_clear(NULL);

  /* A key stored anywhere inside the context overlaps it. Init must reject
   * it before clearing the context, so it never MACs with a wiped key. */
  {
    uint8_t* const staged_k1 = (uint8_t*)&ctx + offsetof(struct TC_AES_CMAC_ctx, k1);
    uint8_t* const staged_mac = (uint8_t*)&ctx + offsetof(struct TC_AES_CMAC_ctx, mac);

    memcpy(staged_k1, key, sizeof key);
    munit_assert_int(TC_AES_CMAC_init(&ctx, (TC_bytes){staged_k1, TC_AES_KEYLEN}), ==, TC_ERROR);
    munit_assert_int(ctx.active, ==, 0);
    munit_assert_int(TC_AES_CMAC_update(&ctx, (TC_bytes){msg, 1}), ==, TC_ERROR);
    memcpy(staged_mac, key, sizeof key);
    munit_assert_int(TC_AES_CMAC_init(&ctx, (TC_bytes){staged_mac, TC_AES_KEYLEN}), ==, TC_ERROR);
    munit_assert_int(TC_AES_CMAC_final(&ctx, (TC_buffer){tag, TC_AES_CMAC_TAG_MAX}), ==, TC_ERROR);
  }

  /* Message bytes inside the context change while the MAC reads them, and a
   * tag inside the context is wiped when final clears it. Both return
   * TC_ERROR and leave the context usable. */
  {
    /* after gives a tag that straddles the context end its storage. */
    struct {
      struct TC_AES_CMAC_ctx cmac;
      uint8_t after[TC_AES_CMAC_TAG_MAX];
    } frame;
    struct TC_AES_CMAC_ctx saved;
    munit_assert_int(TC_AES_CMAC_init(&ctx, (TC_bytes){key, TC_AES_KEYLEN}), ==, TC_OK);
    munit_assert_int(TC_AES_CMAC_update(&ctx, (TC_bytes){msg, 3}), ==, TC_OK);
    memcpy(&saved, &ctx, sizeof saved);
    munit_assert_int(TC_AES_CMAC_update(&ctx, (TC_bytes){ctx.buf, 1}), ==, TC_ERROR);
    munit_assert_int(TC_AES_CMAC_update(&ctx, (TC_bytes){ctx.k1, sizeof ctx.k1}), ==, TC_ERROR);
    munit_assert_int(TC_AES_CMAC_final(&ctx, (TC_buffer){ctx.mac, TC_AES_CMAC_TAG_MAX}), ==,
                     TC_ERROR);
    memcpy(&frame.cmac, &ctx, sizeof ctx);
    munit_assert_int(
        TC_AES_CMAC_final(&frame.cmac, (TC_buffer){(uint8_t*)&frame + sizeof frame.cmac - 1, 1}),
        ==, TC_ERROR);
    munit_assert_uint8(frame.cmac.active, ==, 1);
    TC_AES_CMAC_ctx_clear(&frame.cmac);
    munit_assert_memory_equal(sizeof ctx.mac, ctx.mac, saved.mac);
    munit_assert_memory_equal(sizeof ctx.buf, ctx.buf, saved.buf);
    munit_assert_uint8(ctx.buf_len, ==, saved.buf_len);
    munit_assert_uint8(ctx.active, ==, 1);
    munit_assert_int(TC_AES_CMAC_final(&ctx, (TC_buffer){tag, TC_AES_CMAC_TAG_MAX}), ==, TC_OK);
  }

  return MUNIT_OK;
}

/*
 * Full Wycheproof AES-CMAC corpus (311 cases).
 * Per key-size build: matching keySize groups (102) plus InvalidKeySize (5).
 * Matching: valid → generate+verify; invalid ModifiedTag → verify fails.
 * Wrong key length: API is fixed TC_AES_KEYLEN; result must be invalid.
 */
TC_TEST(test_cmac_wycheproof)
{
  FILE* file;
  char line[1024];
  char key_hex[128];
  char msg_hex[256];
  char tag_hex[64];
  char result[16];
  int key_size_bits = 0;
  int in_group = 0;
  int have = 0;
  unsigned ran = 0;
  unsigned ran_valid = 0;
  unsigned ran_invalid = 0;
  unsigned failed = 0;
  /* 102 matching this TC_AES_KEYLEN + 5 InvalidKeySize shared across builds. */
  const unsigned expect_total = 107u;
  const unsigned expect_valid = 21u;
  const unsigned expect_invalid = 86u;
  const int want_bits = (int)(TC_AES_KEYLEN * 8);

  key_hex[0] = msg_hex[0] = tag_hex[0] = result[0] = '\0';

  file = tc_test_fopen(CMAC_WYCHEPROOF_FILE, "rb");
  munit_assert_not_null(file);

  while (fgets(line, (int)sizeof(line), file) != NULL) {
    char* p = line;
    while (*p == ' ' || *p == '\t')
      ++p;

    if (strncmp(p, "\"keySize\"", 9) == 0) {
      char* colon = strchr(p, ':');
      if (colon != NULL)
        key_size_bits = (int)strtol(colon + 1, NULL, 10);
      /* Run matching key size and all InvalidKeySize groups. */
      in_group = (key_size_bits == want_bits ||
                  (key_size_bits != 128 && key_size_bits != 192 && key_size_bits != 256));
      continue;
    }

    if (!in_group)
      continue;

    if (strncmp(p, "\"key\":", 6) == 0 || strncmp(p, "\"msg\":", 6) == 0 ||
        strncmp(p, "\"tag\":", 6) == 0 || strncmp(p, "\"result\":", 9) == 0) {
      char* q1 = strchr(p, ':');
      char* q2;
      char* q3;
      char* dest = NULL;
      size_t dest_sz = 0;
      if (q1 == NULL)
        continue;
      q2 = strchr(q1, '"');
      if (q2 == NULL)
        continue;
      ++q2;
      q3 = strchr(q2, '"');
      if (q3 == NULL)
        continue;
      if (strncmp(p, "\"key\":", 6) == 0) {
        dest = key_hex;
        dest_sz = sizeof(key_hex);
      } else if (strncmp(p, "\"msg\":", 6) == 0) {
        dest = msg_hex;
        dest_sz = sizeof(msg_hex);
      } else if (strncmp(p, "\"tag\":", 6) == 0) {
        dest = tag_hex;
        dest_sz = sizeof(tag_hex);
      } else {
        dest = result;
        dest_sz = sizeof(result);
      }
      {
        size_t n = (size_t)(q3 - q2);
        if (n >= dest_sz)
          n = dest_sz - 1;
        memcpy(dest, q2, n);
        dest[n] = '\0';
      }
      have |= 1;
      if (strncmp(p, "\"result\"", 8) == 0 && have) {
        uint8_t key[40];
        uint8_t msg[64];
        uint8_t tag[TC_AES_CMAC_TAG_MAX];
        uint8_t out[TC_AES_CMAC_TAG_MAX];
        size_t key_len = 0, msg_len = 0, tag_len = 0;
        int expect_ok = (strcmp(result, "valid") == 0);
        int key_decoded =
            tc_test_hex_decode(key_hex, TC_TEST_HEX_SEPARATED, key, sizeof(key), &key_len);
        int msg_decoded =
            tc_test_hex_decode(msg_hex, TC_TEST_HEX_SEPARATED, msg, sizeof(msg), &msg_len);
        int tag_decoded =
            tc_test_hex_decode(tag_hex, TC_TEST_HEX_SEPARATED, tag, sizeof(tag), &tag_len);

        if (!key_decoded || !msg_decoded || (!tag_decoded && expect_ok)) {
          ++failed;
          have = 0;
          continue;
        }

        ++ran;
        if (expect_ok)
          ++ran_valid;
        else
          ++ran_invalid;

        if (key_len != TC_AES_KEYLEN) {
          /* Fixed key-size API cannot accept this key; must be invalid. */
          if (expect_ok)
            ++failed;
        } else if (!tag_decoded || tag_len != TC_AES_CMAC_TAG_MAX) {
          ++failed;
        } else if (expect_ok) {
          if (TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){msg_len ? msg : NULL, msg_len},
                          (TC_buffer){out, tag_len}) != TC_OK ||
              memcmp(out, tag, tag_len) != 0 ||
              TC_AES_CMAC_verify((TC_bytes){key, TC_AES_KEYLEN},
                                 (TC_bytes){msg_len ? msg : NULL, msg_len},
                                 (TC_bytes){tag, tag_len}) != TC_OK)
            ++failed;
        } else {
          if (TC_AES_CMAC_verify((TC_bytes){key, TC_AES_KEYLEN},
                                 (TC_bytes){msg_len ? msg : NULL, msg_len},
                                 (TC_bytes){tag, tag_len}) != TC_MISMATCH)
            ++failed;
        }
        have = 0;
        key_hex[0] = '\0';
      }
    }
  }

  fclose(file);
  munit_assert_uint(ran, ==, expect_total);
  munit_assert_uint(ran_valid, ==, expect_valid);
  munit_assert_uint(ran_invalid, ==, expect_invalid);
  munit_assert_uint(failed, ==, 0);
  return MUNIT_OK;
}

#if TC_AES_CAVP
/* CAVP CMAC max message is 65536 bytes (hex line ~131 KiB). Host-test BSS only. */
#define CMAC_CAVP_MSG_MAX 65536u
#define CMAC_CAVP_LINE_MAX (CMAC_CAVP_MSG_MAX * 2u + 64u)

/* CAVP rows use Tlen 4..16. Rows below TC_MIN_TAG_LEN go through the
 * explicit short-tag entry points. */
static TC_status cmac_cavp_generate(const uint8_t* key, const uint8_t* msg, size_t msg_len,
                                    uint8_t* tag, size_t tag_len)
{
  return tag_len < TC_MIN_TAG_LEN
             ? TC_AES_CMAC_short_tag((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){msg, msg_len},
                                     (TC_buffer){tag, tag_len})
             : TC_AES_CMAC((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){msg, msg_len},
                           (TC_buffer){tag, tag_len});
}

static TC_status cmac_cavp_verify(const uint8_t* key, const uint8_t* msg, size_t msg_len,
                                  const uint8_t* tag, size_t tag_len)
{
  return tag_len < TC_MIN_TAG_LEN
             ? TC_AES_CMAC_verify_short_tag((TC_bytes){key, TC_AES_KEYLEN},
                                            (TC_bytes){msg, msg_len}, (TC_bytes){tag, tag_len})
             : TC_AES_CMAC_verify((TC_bytes){key, TC_AES_KEYLEN}, (TC_bytes){msg, msg_len},
                                  (TC_bytes){tag, tag_len});
}

/* Parse one full CAVP .rsp for the active TC_AES_KEYLEN. Mlen=0 → empty message. */
static MunitResult cmac_run_cavp_file(const char* name, int is_verify, unsigned* ran_out)
{
  tc_cavp_reader reader;
  tc_cavp_event event;
  static char line[CMAC_CAVP_LINE_MAX];
  static uint8_t msg[CMAC_CAVP_MSG_MAX];
  uint8_t key[32];
  uint8_t mac[TC_AES_CMAC_TAG_MAX];
  uint8_t out[TC_AES_CMAC_TAG_MAX];
  size_t key_len = 0;
  size_t msg_len = 0;
  size_t mac_len = 0;
  size_t mlen = 0;
  size_t tlen = 0;
  int have_key = 0, have_msg = 0, have_mac = 0, have_result = 0;
  int result_pass = 0;
  unsigned ran = 0;
  unsigned failed = 0;

  if (!tc_cavp_open(&reader, CMAC_CAVP_DIR, name, line, sizeof line))
    return MUNIT_ERROR;

  while ((event = tc_cavp_next(&reader)) != TC_CAVP_END) {
    const char* value = reader.value;
    if (event == TC_CAVP_FAILURE) {
      tc_cavp_close(&reader);
      return MUNIT_ERROR;
    }
    if (event != TC_CAVP_FIELD)
      continue;

    if (tc_cavp_is(&reader, "Count")) {
      have_key = have_msg = have_mac = have_result = 0;
      key_len = msg_len = mac_len = mlen = tlen = 0;
    } else if (tc_cavp_is(&reader, "Mlen"))
      mlen = (size_t)strtoul(value, NULL, 10);
    else if (tc_cavp_is(&reader, "Tlen"))
      tlen = (size_t)strtoul(value, NULL, 10);
    else if (tc_cavp_is(&reader, "Key")) {
      have_key = tc_test_hex_decode(value, TC_TEST_HEX_SEPARATED, key, sizeof(key), &key_len);
    } else if (tc_cavp_is(&reader, "Msg")) {
      if (mlen == 0) {
        msg_len = 0;
        have_msg = 1;
      } else if (mlen > CMAC_CAVP_MSG_MAX)
        have_msg = 0;
      else {
        have_msg =
            tc_test_hex_decode(value, TC_TEST_HEX_SEPARATED, msg, CMAC_CAVP_MSG_MAX, &msg_len) &&
            msg_len == mlen;
      }
    } else if (tc_cavp_is(&reader, "Mac")) {
      have_mac = tc_test_hex_decode(value, TC_TEST_HEX_SEPARATED, mac, sizeof(mac), &mac_len) &&
                 tlen != 0 && mac_len == tlen;
      if (!is_verify && have_key && have_msg && have_mac && key_len == TC_AES_KEYLEN) {
        ++ran;
        if (cmac_cavp_generate(key, msg_len ? msg : NULL, msg_len, out, tlen) != TC_OK ||
            memcmp(out, mac, tlen) != 0)
          ++failed;
        have_key = have_msg = have_mac = 0;
      }
    } else if (tc_cavp_is(&reader, "Result")) {
      result_pass = (*value == 'P' || *value == 'p');
      have_result = 1;
      if (is_verify && have_key && have_msg && have_mac && have_result &&
          key_len == TC_AES_KEYLEN) {
        int vr;
        ++ran;
        vr = cmac_cavp_verify(key, msg_len ? msg : NULL, msg_len, mac, tlen);
        if (result_pass) {
          if (vr != TC_OK)
            ++failed;
        } else if (vr != TC_MISMATCH)
          ++failed;
        have_key = have_msg = have_mac = have_result = 0;
      }
    }
  }

  tc_cavp_close(&reader);
  if (ran_out != NULL)
    *ran_out = ran;
  munit_assert_uint(failed, ==, 0);
  munit_assert_uint(ran, >, 0);
  return MUNIT_OK;
}

TC_TEST(test_cmac_cavp_gen)
{
  const char* name;
  unsigned ran = 0;
  MunitResult r;

#if TC_AES_KEY_BITS == 128
  name = "CMACGenAES128.rsp";
#elif TC_AES_KEY_BITS == 192
  name = "CMACGenAES192.rsp";
#else
  name = "CMACGenAES256.rsp";
#endif
  r = cmac_run_cavp_file(name, 0, &ran);
  if (r != MUNIT_OK)
    return r;
  /* Full NIST CAVS 11.0 CMAC Gen AES counts. */
#if TC_AES_KEY_BITS == 128
  munit_assert_uint(ran, ==, 96u);
#elif TC_AES_KEY_BITS == 192
  munit_assert_uint(ran, ==, 144u);
#else
  munit_assert_uint(ran, ==, 96u);
#endif
  return MUNIT_OK;
}

TC_TEST(test_cmac_cavp_ver)
{
  const char* name;
  unsigned ran = 0;
  MunitResult r;

#if TC_AES_KEY_BITS == 128
  name = "CMACVerAES128.rsp";
#elif TC_AES_KEY_BITS == 192
  name = "CMACVerAES192.rsp";
#else
  name = "CMACVerAES256.rsp";
#endif
  r = cmac_run_cavp_file(name, 1, &ran);
  if (r != MUNIT_OK)
    return r;
  /* Full NIST CAVS 11.0 CMAC Ver AES counts. */
#if TC_AES_KEY_BITS == 128
  munit_assert_uint(ran, ==, 240u);
#elif TC_AES_KEY_BITS == 192
  munit_assert_uint(ran, ==, 360u);
#else
  munit_assert_uint(ran, ==, 240u);
#endif
  return MUNIT_OK;
}
#endif

MunitResult test_cmac(const MunitParameter params[], void* data)
{

  cmac_initialize_sbox();

  if (test_cmac_sp800_38b(params, data) != MUNIT_OK)
    return MUNIT_FAIL;
  if (test_cmac_api(params, data) != MUNIT_OK)
    return MUNIT_FAIL;
  if (test_cmac_tag_policy(params, data) != MUNIT_OK)
    return MUNIT_FAIL;
  if (test_cmac_streaming(params, data) != MUNIT_OK)
    return MUNIT_FAIL;
  if (test_cmac_wycheproof(params, data) != MUNIT_OK)
    return MUNIT_FAIL;
#if TC_AES_CAVP
  if (test_cmac_cavp_gen(params, data) != MUNIT_OK || test_cmac_cavp_ver(params, data) != MUNIT_OK)
    return MUNIT_FAIL;
#endif
  return MUNIT_OK;
}

#else /* !CMAC */

TC_TEST_SHARED(test_cmac)
{
  return MUNIT_SKIP;
}

#endif
