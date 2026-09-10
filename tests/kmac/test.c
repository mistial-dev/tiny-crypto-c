/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "munit.h"
#include <tiny_crypto/kmac.h>
#include "mac_vectors.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>


static size_t unhex(uint8_t* out, const char* hex)
{
  static const char digits[] = "0123456789abcdef";
  size_t n = 0;
  while (*hex) {
    const char *high, *low;
    if (!hex[1]) return 0;
    high = strchr(digits, tolower((unsigned char)hex[0]));
    low = strchr(digits, tolower((unsigned char)hex[1]));
    if (!high || !low) return 0;
    out[n++] = (uint8_t)((high - digits) * 16 + (low - digits));
    hex += 2;
  }
  return n;
}

static MunitResult test_profile(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  /* NIST SP 800-185 KMAC_samples.pdf, samples 4, 5, 6.
   * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf */
  static const char* expected[] = {
    "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd",
    "75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69",
    "b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d970fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965"
  };
  static const uint8_t custom[] = "My Tagged Application";
  uint8_t key[300], data[300], out[300], want[300], stream[300];
  struct TC_KMAC256_ctx ctx = { {0}, 0, 0 }, saved;
  size_t i, n, k;
  for (i = 0; i < sizeof(key); ++i) { key[i] = (uint8_t)(i+0x40); data[i] = (uint8_t)i; }
  for (i = 0; i < 3; ++i) {
    unhex(want, expected[i]);
    munit_assert(TC_KMAC256_digest(key, 32, data, i ? 200 : 4,
          custom, i == 1 ? 0 : sizeof(custom)-1, out, 64) == TC_OK);
    munit_assert(memcmp(out, want, 64) == 0);
  }
  /* Try every padding position, especially a suffix in the last rate byte.
   * Long keys, customization strings, and outputs also cross block boundaries. */
  for (n = 0; n <= 300; ++n) {
    size_t output_len = n % 3 == 0 ? 32 : n % 3 == 1 ? 48 : 300;
    munit_assert(TC_KMAC256_digest(key, n, data, n, custom, sizeof(custom)-1,
                            out, output_len) == TC_OK);
    munit_assert(TC_KMAC256_init(&ctx, key, n, custom, sizeof(custom)-1) == TC_OK);
    for (k = 0; k < n; ++k) munit_assert(TC_KMAC256_update(&ctx, data+k, 1) == TC_OK);
    munit_assert(TC_KMAC256_update(&ctx, NULL, 0) == TC_OK);
    munit_assert(TC_KMAC256_final(&ctx, stream, output_len) == TC_OK);
    munit_assert(memcmp(out, stream, output_len) == 0);
#if TC_ZEROIZE
    memset(&saved, 0, sizeof(saved));
    munit_assert(memcmp(&ctx, &saved, sizeof(ctx)) == 0);
#endif
    munit_assert(TC_KMAC256_update(&ctx, NULL, 0) == TC_ERROR);
    munit_assert(TC_KMAC256_final(&ctx, stream, 32) == TC_ERROR);
    munit_assert(TC_KMAC256_digest(key, 32, data, n, data, n, out, 48) == TC_OK);
  }
  munit_assert(TC_KMAC256_digest(NULL, 0, NULL, 0, NULL, 0, out, 32) == TC_OK);
  munit_assert(TC_KMAC256_digest(NULL, 0, NULL, 0, NULL, 0, stream, 48) == TC_OK);
  munit_assert(memcmp(out, stream, 32) != 0);
  munit_assert(TC_KMAC256_digest(key, 32, data, 32, NULL, 0, want, 32) == TC_OK);
  memcpy(out, data, 32);
  munit_assert(TC_KMAC256_digest(key, 32, out, 32, NULL, 0, out, 32) == TC_OK);
  munit_assert(memcmp(out, want, 32) == 0);
  munit_assert(TC_KMAC256_init(&ctx, key, 32, NULL, 0) == TC_OK);
  saved = ctx;
  memset(out, 0xa5, sizeof(out));
  memcpy(want, out, sizeof(out));
  munit_assert(TC_KMAC256_update(&ctx, (const uint8_t*)&ctx, 1) == TC_ERROR);
  munit_assert(TC_KMAC256_final(&ctx, (uint8_t*)&ctx, 32) == TC_ERROR);
  munit_assert(TC_KMAC256_final(&ctx, out, 0) == TC_ERROR);
  munit_assert(TC_KMAC256_init(&ctx, (const uint8_t*)&ctx, 32, NULL, 0) == TC_ERROR);
  munit_assert(memcmp(&saved, &ctx, sizeof(ctx)) == 0);
  munit_assert(memcmp(want, out, sizeof(out)) == 0);
#if TC_STRICT
  munit_assert(TC_KMAC256_init(NULL, key, 32, NULL, 0) == TC_ERROR);
  munit_assert(TC_KMAC256_init(&ctx, NULL, 32, NULL, 0) == TC_ERROR);
  munit_assert(TC_KMAC256_update(&ctx, NULL, 1) == TC_ERROR);
  munit_assert(TC_KMAC256_final(&ctx, NULL, 32) == TC_ERROR);
#endif
  munit_assert(TC_KMAC256_digest(NULL, 1, data, 1, NULL, 0, out, 32) == TC_ERROR);
  munit_assert(TC_KMAC256_digest(key, 32, NULL, 1, NULL, 0, out, 32) == TC_ERROR);
  munit_assert(TC_KMAC256_digest(key, 32, data, 1, NULL, 1, out, 32) == TC_ERROR);
  munit_assert(TC_KMAC256_digest(key, 32, data, 1, NULL, 0, NULL, 32) == TC_ERROR);
#if SIZE_MAX > UINT64_MAX / 8
  munit_assert(TC_KMAC256_init(&ctx, key, SIZE_MAX, NULL, 0) == TC_ERROR);
  munit_assert(TC_KMAC256_init(&ctx, key, 32, key, SIZE_MAX) == TC_ERROR);
  munit_assert(TC_KMAC256_final(&ctx, out, SIZE_MAX) == TC_ERROR);
#endif
  TC_KMAC256_ctx_clear(&ctx);
  memset(&saved, 0, sizeof(saved));
  munit_assert(memcmp(&saved, &ctx, sizeof(ctx)) == 0);

  /* From the kdf section of osdp-piv-latex's PIV Auto test report.
   * These are test session keys, not card private keys. */
  n = unhex(key, "00112233445566778899AABBCCDDEEFF102132435465768798A9BACBDCEDFE0FFFEEDDCCBBAA99887766554433221100");
  munit_assert(TC_KMAC256_digest(key, n, NULL, 0,
      (const uint8_t*)"OSDP-PIV-AUTO-KDK-v1", 20, out, 32) == TC_OK);
  unhex(want, "10FFA4469E902660BA4BEF8C917696848570B20531723D67ECD934A23BA4C89D");
  munit_assert(memcmp(out, want, 32) == 0);
  n = unhex(data, "4F5344502D5049562D4155544F01070000002A000000D13810D828AB6C10C339E5A1685A08C92ADE0A6184E739C3E709D49C7EFDD0432EACEA268AE905274C9E0700112233445566778899AABBCCDDEEFF102132435465768798A9BACBDCEDFE0F");
  munit_assert(TC_KMAC256_digest(out, 32, data, n,
      (const uint8_t*)"OSDP-PIV-AUTO-CHALLENGE-v1", 26, stream, 32) == TC_OK);
  unhex(want, "0864C776F2374124D3E63F0B0B29FC1C5F0E8FF8BB1FA80E2723293B86A0158E");
  munit_assert(memcmp(stream, want, 32) == 0);
  /* Same fixture, Card Authentication P-384 profile (algorithm 0x14). */
  data[n-33] = 0x14;
  munit_assert(TC_KMAC256_digest(out, 32, data, n,
      (const uint8_t*)"OSDP-PIV-AUTO-CHALLENGE-v1", 26, stream, 48) == TC_OK);
  unhex(want, "F3480C6C1DAD008D3E14D0C815D381F01420E9D3402A175BED097C6949E4BA447FA0A11745CE4D054A95B10A9D5CC689");
  munit_assert(memcmp(stream, want, 48) == 0);
  return MUNIT_OK;
}

static const char* vector_path;
static TC_status vector_kmac(const uint8_t* key, size_t key_length,
                              const uint8_t* message, size_t message_length,
                              uint8_t* output, size_t tag_length)
{
  return TC_KMAC256_digest(key, key_length, message, message_length, NULL, 0, output, tag_length);
}
static MunitResult test_wycheproof(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  return tc_test_mac_vectors(vector_path, vector_kmac);
}

static MunitTest tests[] = {
  {"/wycheproof", test_wycheproof, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/profile", test_profile, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};
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
