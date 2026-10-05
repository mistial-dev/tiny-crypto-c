/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "munit.h"
#include "test_util.h"
#include <tiny_crypto/kmac.h>
#include "cavp.h"
#include "mac_vectors.h"
#include <stdio.h>
#include <string.h>

/* Compare fields because struct padding is indeterminate after assignment. */
static int kmac_ctx_equal(const struct TC_KMAC256_ctx* a, const struct TC_KMAC256_ctx* b)
{
  return memcmp(a->state, b->state, sizeof a->state) == 0 && a->position == b->position &&
         a->active == b->active;
}

TC_TEST(test_profile)
{
  /* NIST SP 800-185 KMAC_samples.pdf, samples 4, 5, 6.
   * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf */
  static const char* expected[] = {
      "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6"
      "f5951f0103f33f4f24871024d9c27773a8dd",
      "75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691589d27cf5e15369cbbff8b9a4c2e"
      "b17800855d0235ff635da82533ec6b759b69",
      "b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d970fbacfde50033aea585f1a27085"
      "10c32d07880801bd182898fe476876fc8965"};
  static const uint8_t custom[] = "My Tagged Application";
  uint8_t key[300], data[300], out[300], want[300], stream[300];
  struct TC_KMAC256_ctx ctx = {{0}, 0, 0}, saved;
  size_t i, n, k;
  for (i = 0; i < sizeof(key); ++i) {
    key[i] = (uint8_t)(i + 0x40);
    data[i] = (uint8_t)i;
  }
  for (i = 0; i < 3; ++i) {
    tc_test_hex(expected[i], want, sizeof want);
    munit_assert(TC_KMAC256_digest((TC_bytes){key, 32}, (TC_bytes){data, i ? 200 : 4},
                                   (TC_bytes){custom, i == 1 ? 0 : sizeof(custom) - 1},
                                   (TC_buffer){out, 64}) == TC_OK);
    munit_assert(memcmp(out, want, 64) == 0);
  }
  /* Try every padding position, especially a suffix in the last rate byte.
   * Long keys, customization strings, and outputs also cross block boundaries. */
  for (n = 0; n <= 300; ++n) {
    size_t output_len = n % 3 == 0 ? 32 : n % 3 == 1 ? 48 : 300;
    munit_assert(TC_KMAC256_digest((TC_bytes){key, n}, (TC_bytes){data, n},
                                   (TC_bytes){custom, sizeof(custom) - 1},
                                   (TC_buffer){out, output_len}) == TC_OK);
    munit_assert(
        TC_KMAC256_init(&ctx, (TC_bytes){key, n}, (TC_bytes){custom, sizeof(custom) - 1}) == TC_OK);
    for (k = 0; k < n; ++k)
      munit_assert(TC_KMAC256_update(&ctx, (TC_bytes){data + k, 1}) == TC_OK);
    munit_assert(TC_KMAC256_update(&ctx, (TC_bytes){NULL, 0}) == TC_OK);
    munit_assert(TC_KMAC256_final(&ctx, (TC_buffer){stream, output_len}) == TC_OK);
    munit_assert(memcmp(out, stream, output_len) == 0);
    /* Final consumes the context and wipes its key-dependent state. */
    memset(&saved, 0, sizeof(saved));
    munit_assert(memcmp(&ctx, &saved, sizeof(ctx)) == 0);
    munit_assert(TC_KMAC256_update(&ctx, (TC_bytes){NULL, 0}) == TC_ERROR);
    munit_assert(TC_KMAC256_final(&ctx, (TC_buffer){stream, 32}) == TC_ERROR);
    munit_assert(TC_KMAC256_digest((TC_bytes){key, 32}, (TC_bytes){data, n}, (TC_bytes){data, n},
                                   (TC_buffer){out, 48}) == TC_OK);
  }
  munit_assert(TC_KMAC256_digest((TC_bytes){NULL, 0}, (TC_bytes){NULL, 0}, (TC_bytes){NULL, 0},
                                 (TC_buffer){out, 32}) == TC_OK);
  munit_assert(TC_KMAC256_digest((TC_bytes){NULL, 0}, (TC_bytes){NULL, 0}, (TC_bytes){NULL, 0},
                                 (TC_buffer){stream, 48}) == TC_OK);
  munit_assert(memcmp(out, stream, 32) != 0);
  munit_assert(TC_KMAC256_digest((TC_bytes){key, 32}, (TC_bytes){data, 4}, (TC_bytes){NULL, 0},
                                 (TC_buffer){out, TC_MIN_TAG_LEN}) == TC_OK);
  munit_assert(TC_KMAC256_verify((TC_bytes){key, 32}, (TC_bytes){data, 4}, (TC_bytes){NULL, 0},
                                 (TC_bytes){out, TC_MIN_TAG_LEN}) == TC_OK);
  out[TC_MIN_TAG_LEN - 1] ^= 1;
  munit_assert(TC_KMAC256_verify((TC_bytes){key, 32}, (TC_bytes){data, 4}, (TC_bytes){NULL, 0},
                                 (TC_bytes){out, TC_MIN_TAG_LEN}) == TC_MISMATCH);
  /* Default verification squeezes long tags across rate blocks. A difference
   * in the first or last byte is a mismatch, and bad spans are errors. */
  munit_assert(TC_KMAC256_digest((TC_bytes){key, 32}, (TC_bytes){data, 4}, (TC_bytes){NULL, 0},
                                 (TC_buffer){want, sizeof want}) == TC_OK);
  munit_assert(TC_KMAC256_verify((TC_bytes){key, 32}, (TC_bytes){data, 4}, (TC_bytes){NULL, 0},
                                 (TC_bytes){want, sizeof want}) == TC_OK);
  for (i = 0; i < sizeof want; i += sizeof want - 1) {
    want[i] ^= 0x80;
    munit_assert(TC_KMAC256_verify((TC_bytes){key, 32}, (TC_bytes){data, 4}, (TC_bytes){NULL, 0},
                                   (TC_bytes){want, sizeof want}) == TC_MISMATCH);
    want[i] ^= 0x80;
  }
  munit_assert(TC_KMAC256_verify((TC_bytes){key, 32}, (TC_bytes){data, 4}, (TC_bytes){NULL, 0},
                                 (TC_bytes){NULL, TC_MIN_TAG_LEN}) == TC_ERROR);
  munit_assert(TC_KMAC256_verify((TC_bytes){NULL, 32}, (TC_bytes){data, 4}, (TC_bytes){NULL, 0},
                                 (TC_bytes){want, TC_MIN_TAG_LEN}) == TC_ERROR);
  munit_assert(TC_KMAC256_verify((TC_bytes){key, 32}, (TC_bytes){NULL, 4}, (TC_bytes){NULL, 0},
                                 (TC_bytes){want, TC_MIN_TAG_LEN}) == TC_ERROR);
  munit_assert(TC_KMAC256_verify((TC_bytes){key, 32}, (TC_bytes){data, 4}, (TC_bytes){NULL, 1},
                                 (TC_bytes){want, TC_MIN_TAG_LEN}) == TC_ERROR);
  munit_assert(TC_KMAC256_digest((TC_bytes){key, 32}, (TC_bytes){data, 4}, (TC_bytes){NULL, 0},
                                 (TC_buffer){out, TC_MIN_TAG_LEN - 1}) == TC_ERROR);
  munit_assert(TC_KMAC256_digest_short_tag((TC_bytes){key, 32}, (TC_bytes){data, 4},
                                           (TC_bytes){NULL, 0},
                                           (TC_buffer){out, TC_MIN_TAG_LEN - 1}) == TC_OK);
  munit_assert(TC_KMAC256_verify_short_tag((TC_bytes){key, 32}, (TC_bytes){data, 4},
                                           (TC_bytes){NULL, 0},
                                           (TC_bytes){out, TC_MIN_TAG_LEN - 1}) == TC_OK);
  munit_assert(TC_KMAC256_digest_short_tag((TC_bytes){key, 32}, (TC_bytes){data, 4},
                                           (TC_bytes){NULL, 0},
                                           (TC_buffer){out, TC_MIN_TAG_LEN}) == TC_ERROR);
  /* A customization string is part of the MAC input for every entry point,
   * and the streaming short-tag final agrees with the one-shot call. */
  munit_assert(TC_KMAC256_digest((TC_bytes){key, 32}, (TC_bytes){data, 4},
                                 (TC_bytes){custom, sizeof(custom) - 1},
                                 (TC_buffer){want, TC_MIN_TAG_LEN}) == TC_OK);
  munit_assert(TC_KMAC256_verify((TC_bytes){key, 32}, (TC_bytes){data, 4},
                                 (TC_bytes){custom, sizeof(custom) - 1},
                                 (TC_bytes){want, TC_MIN_TAG_LEN}) == TC_OK);
  munit_assert(TC_KMAC256_digest_short_tag((TC_bytes){key, 32}, (TC_bytes){data, 4},
                                           (TC_bytes){custom, sizeof(custom) - 1},
                                           (TC_buffer){want, TC_MIN_TAG_LEN - 1}) == TC_OK);
  munit_assert(TC_KMAC256_verify_short_tag((TC_bytes){key, 32}, (TC_bytes){data, 4},
                                           (TC_bytes){custom, sizeof(custom) - 1},
                                           (TC_bytes){want, TC_MIN_TAG_LEN - 1}) == TC_OK);
  munit_assert(TC_KMAC256_init(&ctx, (TC_bytes){key, 32}, (TC_bytes){custom, sizeof(custom) - 1}) ==
               TC_OK);
  munit_assert(TC_KMAC256_update(&ctx, (TC_bytes){data, 4}) == TC_OK);
  munit_assert(TC_KMAC256_final_short_tag(&ctx, (TC_buffer){stream, TC_MIN_TAG_LEN - 1}) == TC_OK);
  munit_assert(memcmp(stream, want, TC_MIN_TAG_LEN - 1) == 0);
  /* SP 800-185 section 8.4.2: a KMAC tag holds at least 32 bits. */
  munit_assert(
      TC_KMAC256_digest_short_tag((TC_bytes){key, 32}, (TC_bytes){data, 4}, (TC_bytes){NULL, 0},
                                  (TC_buffer){out, TC_HASH_MAC_MIN_TAG_LEN - 1}) == TC_ERROR);
  munit_assert(
      TC_KMAC256_verify_short_tag((TC_bytes){key, 32}, (TC_bytes){data, 4}, (TC_bytes){NULL, 0},
                                  (TC_bytes){out, TC_HASH_MAC_MIN_TAG_LEN - 1}) == TC_ERROR);
  munit_assert(TC_KMAC256_digest_short_tag((TC_bytes){key, 32}, (TC_bytes){data, 4},
                                           (TC_bytes){NULL, 0},
                                           (TC_buffer){out, TC_HASH_MAC_MIN_TAG_LEN}) == TC_OK);
  munit_assert(TC_KMAC256_digest((TC_bytes){key, 32}, (TC_bytes){data, 32}, (TC_bytes){NULL, 0},
                                 (TC_buffer){want, 32}) == TC_OK);
  memcpy(out, data, 32);
  munit_assert(TC_KMAC256_digest((TC_bytes){key, 32}, (TC_bytes){out, 32}, (TC_bytes){NULL, 0},
                                 (TC_buffer){out, 32}) == TC_OK);
  munit_assert(memcmp(out, want, 32) == 0);
  munit_assert(TC_KMAC256_init(&ctx, (TC_bytes){key, 32}, (TC_bytes){NULL, 0}) == TC_OK);
  saved = ctx;
  memset(out, 0xa5, sizeof(out));
  memcpy(want, out, sizeof(out));
  munit_assert(TC_KMAC256_update(&ctx, (TC_bytes){(const uint8_t*)&ctx, 1}) == TC_ERROR);
  munit_assert(TC_KMAC256_final(&ctx, (TC_buffer){(uint8_t*)&ctx, 32}) == TC_ERROR);
  munit_assert(TC_KMAC256_final(&ctx, (TC_buffer){out, 0}) == TC_ERROR);
  munit_assert(TC_KMAC256_init(&ctx, (TC_bytes){(const uint8_t*)&ctx, 32}, (TC_bytes){NULL, 0}) ==
               TC_ERROR);
  memset(&saved, 0, sizeof(saved));
  munit_assert(kmac_ctx_equal(&saved, &ctx));
  munit_assert(memcmp(want, out, sizeof(out)) == 0);
  /* NULL pointers with nonzero lengths are argument errors that leave the
   * context and output unchanged. */
  munit_assert(TC_KMAC256_init(NULL, (TC_bytes){key, 32}, (TC_bytes){NULL, 0}) == TC_ERROR);
  munit_assert(TC_KMAC256_update(NULL, (TC_bytes){data, 1}) == TC_ERROR);
  munit_assert(TC_KMAC256_final(NULL, (TC_buffer){out, 32}) == TC_ERROR);
  munit_assert(TC_KMAC256_update(&ctx, (TC_bytes){NULL, 1}) == TC_ERROR);
  munit_assert(TC_KMAC256_final(&ctx, (TC_buffer){NULL, 32}) == TC_ERROR);
  munit_assert(kmac_ctx_equal(&saved, &ctx));
  munit_assert(TC_KMAC256_init(&ctx, (TC_bytes){NULL, 32}, (TC_bytes){NULL, 0}) == TC_ERROR);
  munit_assert(TC_KMAC256_init(&ctx, (TC_bytes){key, 32}, (TC_bytes){NULL, 1}) == TC_ERROR);
  munit_assert(kmac_ctx_equal(&saved, &ctx));
  munit_assert(memcmp(want, out, sizeof(out)) == 0);
  munit_assert(TC_KMAC256_digest((TC_bytes){NULL, 1}, (TC_bytes){data, 1}, (TC_bytes){NULL, 0},
                                 (TC_buffer){out, 32}) == TC_ERROR);
  munit_assert(TC_KMAC256_digest((TC_bytes){key, 32}, (TC_bytes){NULL, 1}, (TC_bytes){NULL, 0},
                                 (TC_buffer){out, 32}) == TC_ERROR);
  munit_assert(TC_KMAC256_digest((TC_bytes){key, 32}, (TC_bytes){data, 1}, (TC_bytes){NULL, 1},
                                 (TC_buffer){out, 32}) == TC_ERROR);
  munit_assert(TC_KMAC256_digest((TC_bytes){key, 32}, (TC_bytes){data, 1}, (TC_bytes){NULL, 0},
                                 (TC_buffer){NULL, 32}) == TC_ERROR);
#if SIZE_MAX > UINT64_MAX / 8
  munit_assert(TC_KMAC256_init(&ctx, (TC_bytes){key, SIZE_MAX}, (TC_bytes){NULL, 0}) == TC_ERROR);
  munit_assert(TC_KMAC256_init(&ctx, (TC_bytes){key, 32}, (TC_bytes){key, SIZE_MAX}) == TC_ERROR);
  munit_assert(TC_KMAC256_final(&ctx, (TC_buffer){out, SIZE_MAX}) == TC_ERROR);
#endif
  TC_KMAC256_ctx_clear(&ctx);
  memset(&saved, 0, sizeof(saved));
  munit_assert(kmac_ctx_equal(&saved, &ctx));

  /* From the kdf section of osdp-piv-latex's PIV Auto test report.
   * The fixture holds test session keys only. */
  n = tc_test_hex(
      "00112233445566778899AABBCCDDEEFF102132435465768798A9BACBDCEDFE0FFFEEDDCCBBAA99887"
      "766554433221100",
      key, sizeof key);
  munit_assert(TC_KMAC256_digest((TC_bytes){key, n}, (TC_bytes){NULL, 0},
                                 (TC_bytes){(const uint8_t*)"OSDP-PIV-AUTO-KDK-v1", 20},
                                 (TC_buffer){out, 32}) == TC_OK);
  tc_test_hex("10FFA4469E902660BA4BEF8C917696848570B20531723D67ECD934A23BA4C89D", want,
              sizeof want);
  munit_assert(memcmp(out, want, 32) == 0);
  n = tc_test_hex("4F5344502D5049562D4155544F01070000002A000000D13810D828AB6C10C339E5A1685A08C92ADE"
                  "0A6184E739C3E709D49C7EFDD0432EACEA268AE905274C9E0700112233445566778899AABBCCDDEE"
                  "FF102132435465768798A9BACBDCEDFE0F",
                  data, sizeof data);
  munit_assert(TC_KMAC256_digest((TC_bytes){out, 32}, (TC_bytes){data, n},
                                 (TC_bytes){(const uint8_t*)"OSDP-PIV-AUTO-CHALLENGE-v1", 26},
                                 (TC_buffer){stream, 32}) == TC_OK);
  tc_test_hex("0864C776F2374124D3E63F0B0B29FC1C5F0E8FF8BB1FA80E2723293B86A0158E", want,
              sizeof want);
  munit_assert(memcmp(stream, want, 32) == 0);
  /* Same fixture, Card Authentication P-384 profile (algorithm 0x14). */
  data[n - 33] = 0x14;
  munit_assert(TC_KMAC256_digest((TC_bytes){out, 32}, (TC_bytes){data, n},
                                 (TC_bytes){(const uint8_t*)"OSDP-PIV-AUTO-CHALLENGE-v1", 26},
                                 (TC_buffer){stream, 48}) == TC_OK);
  tc_test_hex("F3480C6C1DAD008D3E14D0C815D381F01420E9D3402A175BED097C6949E4BA447FA0A11745CE4D054A95"
              "B10A9D5CC689",
              want, sizeof want);
  munit_assert(memcmp(stream, want, 48) == 0);
  return MUNIT_OK;
}

static const char* vector_path;
static TC_status vector_kmac(const uint8_t* key, size_t key_length, const uint8_t* message,
                             size_t message_length, uint8_t* output, size_t tag_length)
{
  return TC_KMAC256_digest((TC_bytes){key, key_length}, (TC_bytes){message, message_length},
                           (TC_bytes){NULL, 0}, (TC_buffer){output, tag_length});
}
TC_TEST(test_wycheproof)
{
  return tc_test_mac_vectors(vector_path, vector_kmac);
}

static MunitTest tests[] = {
    {"/wycheproof", test_wycheproof, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/profile", test_profile, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
static const MunitSuite suite = {"/kmac", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{
  if (argc == 3 && strcmp(argv[1], "--vectors") == 0) {
    char* args[] = {argv[0], (char*)"/kmac/wycheproof"};
    vector_path = argv[2];
    return munit_suite_main(&suite, NULL, 2, args);
  }
  return munit_suite_main(&suite, NULL, argc, argv);
}
