/*
 * SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <string.h>

#include <tiny_crypto/des.h>
#include "munit.h"
#include "test_util.h"

#if TC_DES_ENABLE_ECB && TC_DES_ENABLE_CBC && TC_DES_ENABLE_CFB1 && TC_DES_ENABLE_CFB8 &&          \
    TC_DES_ENABLE_CFB64 && TC_DES_ENABLE_OFB && TC_DES_ENABLE_TDES

#include "edge_vectors.h"

TC_TEST(test_edge_vectors)
{
  for (size_t i = 0; i < EDGE_VECTOR_COUNT; ++i) {
    const struct edge_vector* vector = &edge_vectors[i];
    uint8_t buffer[32];
    munit_assert(vector->len <= sizeof(buffer));
    memcpy(buffer, vector->msg, vector->len);

    struct TC_DES_ctx ctx;
    munit_assert_int(TC_DES_init(&ctx, (TC_bytes){vector->key, vector->key_len}), ==, TC_OK);
    munit_assert_int(TC_DES_set_iv(&ctx, (TC_bytes){vector->iv, TC_DES_BLOCKLEN}), ==, TC_OK);

    if (strcmp(vector->mode, "ECB") == 0)
      munit_assert_int(TC_DES_ECB_encrypt(&ctx, (TC_buffer){buffer, TC_DES_BLOCKLEN}), ==, TC_OK);
    else if (strcmp(vector->mode, "CBC") == 0)
      munit_assert_int(TC_DES_CBC_encrypt(&ctx, (TC_buffer){buffer, vector->len}), ==, TC_OK);
    else if (strcmp(vector->mode, "CFB1") == 0)
      munit_assert_int(TC_DES_CFB1_encrypt(&ctx,
                                           (TC_buffer){buffer, ((vector->bit_length) / 8u +
                                                                ((vector->bit_length) % 8u != 0))},
                                           vector->bit_length),
                       ==, TC_OK);
    else if (strcmp(vector->mode, "CFB8") == 0)
      munit_assert_int(TC_DES_CFB8_encrypt(&ctx, (TC_buffer){buffer, vector->len}), ==, TC_OK);
    else if (strcmp(vector->mode, "CFB64") == 0)
      munit_assert_int(TC_DES_CFB64_encrypt(&ctx, (TC_buffer){buffer, vector->len}), ==, TC_OK);
    else if (strcmp(vector->mode, "OFB") == 0)
      munit_assert_int(TC_DES_OFB_crypt(&ctx, (TC_buffer){buffer, vector->len}), ==, TC_OK);
    else
      munit_errorf("unknown DES edge-vector mode: %s", vector->mode);
    TC_DES_ctx_clear(&ctx);

    size_t compare_len = vector->bit_length ? (vector->bit_length + 7) / 8 : vector->len;
    if (memcmp(buffer, vector->ct, compare_len) != 0)
      munit_errorf("edge vector %zu (%s) mismatch", i, vector->mode);
  }

  return MUNIT_OK;
}

MunitResult test_edge_vectors_suite(const MunitParameter params[], void* data)
{
  return test_edge_vectors(params, data);
}

#else

TC_TEST_SHARED(test_edge_vectors_suite)
{
  return MUNIT_SKIP;
}

#endif
