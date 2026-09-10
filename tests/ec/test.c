/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/ec.h>
#if TC_ENABLE_X509
#include <tiny_crypto/x509.h>
#endif
#include "munit.h"
#include "test_util.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const struct {
  TC_EC_curve curve;
  size_t bytes;
  const char *generator, *twice, *order, *minus_one, *negative;
} vectors[] = {
#if TC_EC_ENABLE_P256
  {TC_EC_P256, 32,
   "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
   "047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1",
   "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
   "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
   "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a"},
#endif
#if TC_EC_ENABLE_P384
  {TC_EC_P384, 48,
   "04AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB73617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
   "0408d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df618e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875bc6cc43e904e505f256ab4255ffd43e94d39e22d61501e700a940e80",
   "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
   "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972",
   "04AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7c9e821b569d9d390a26167406d6d23d6070be242d765eb831625ceec4a0f473ef59f4e30e2817e6285bce2846f15f1a0"},
#endif
};
static char** capture;
static const char* vector_path;

static MunitResult wycheproof(const MunitParameter params[], void* user)
{
  static char line[32768];
  uint8_t scalar[80], public_key[4096], expected[48], output[48], unchanged[48];
  TC_EC_workspace workspace;
  FILE* file;
  size_t count = 0;
  (void)params; (void)user;
  if (!vector_path) return MUNIT_SKIP;
  file = fopen(vector_path, "r");
  munit_assert_not_null(file);
  memset(unchanged, 0xa5, sizeof unchanged);
  while (fgets(line, sizeof line, file)) {
    char* fields[7];
    char* token = strtok(line, " \t\r\n");
    size_t columns = 0, scalar_length, public_length, expected_length, width;
    TC_EC_curve curve;
    TC_status status = TC_ERROR;
    while (token) {
      munit_assert_size(columns, <, 7);
      fields[columns++] = token;
      token = strtok(NULL, " \t\r\n");
    }
    munit_assert_size(columns, ==, 7);
    munit_assert_true(strcmp(fields[0], "256") == 0 || strcmp(fields[0], "384") == 0);
    curve = strcmp(fields[0], "256") == 0 ? TC_EC_P256 : TC_EC_P384;
    width = curve == TC_EC_P256 ? 32 : 48;
    scalar_length = tc_test_decode_hex(fields[2], scalar, sizeof scalar);
    public_length = strcmp(fields[3], "-") ? tc_test_decode_hex(fields[3], public_key, sizeof public_key) : 0;
    expected_length = strcmp(fields[4], "-") ? tc_test_decode_hex(fields[4], expected, sizeof expected) : 0;
    munit_assert_size(scalar_length, ==, strlen(fields[2]) / 2);
    munit_assert_true(strcmp(fields[5], "accept") == 0 || strcmp(fields[5], "reject") == 0);
    memset(&workspace, 0, sizeof workspace); memcpy(output, unchanged, sizeof output);
    if (strcmp(fields[1], "ecpoint") == 0) {
      status = TC_ECDH(curve, scalar, scalar_length, public_key, public_length,
                       output, width, &workspace);
    }
#if TC_ENABLE_X509
    else if (strcmp(fields[1], "asn") == 0) {
      TC_X509_public_key key;
      if (TC_X509_subject_public_key(public_key, public_length, &key) == TC_TLV_OK &&
          key.type == TC_KEY_EC && key.curve == curve)
        status = TC_ECDH(curve, scalar, scalar_length, key.key.data, key.key.length,
                         output, width, &workspace);
    }
#endif
    else munit_errorf("Unsupported encoding %s", fields[1]);
    if (strcmp(fields[5], "accept") == 0) {
      if (status != TC_OK) munit_errorf("Wycheproof %s: rejected valid input", fields[6]);
      munit_assert_size(expected_length, ==, width);
      munit_assert_memory_equal(width, output, expected);
      munit_assert_memory_equal(sizeof output - width, output + width, unchanged + width);
    } else {
      if (status != TC_ERROR) munit_errorf("Wycheproof %s: accepted rejected input", fields[6]);
      munit_assert_memory_equal(sizeof output, output, unchanged);
    }
    munit_assert_true(tc_test_all_zero(&workspace, sizeof workspace));
    ++count;
  }
  munit_assert_int(ferror(file), ==, 0);
  fclose(file);
  munit_assert_size(count, >, 0);
  return MUNIT_OK;
}

static MunitResult signature_answers(const MunitParameter params[], void* user)
{
  TC_ECDSA_workspace workspace;
  uint8_t point[97], signature[96], order[48], complement[48], digest[48];
  (void)params; (void)user;
  for (size_t v = 0; v < sizeof vectors / sizeof vectors[0]; ++v) {
    size_t n = vectors[v].bytes;
    unsigned borrow = 0;
    munit_assert_size(tc_test_decode_hex(vectors[v].generator, point, sizeof point), ==, 1 + 2 * n);
    munit_assert_size(tc_test_decode_hex(vectors[v].order, order, sizeof order), ==, n);
    /* d = k = 1 and z = 0 gives Q = G and r = s = Gx for these curves. */
    memcpy(signature, point + 1, n);
    memcpy(signature + n, point + 1, n);
    memset(digest, 0, sizeof digest);
    munit_assert_int(TC_ECDSA_verify_digest(vectors[v].curve, point, 1 + 2 * n,
        digest, n, signature, 2 * n, &workspace), ==, TC_OK);
    munit_assert_true(tc_test_all_zero(&workspace, sizeof workspace));
    for (size_t i = n; i > 0; --i) {
      unsigned subtrahend = signature[i - 1] + borrow;
      complement[i - 1] = (uint8_t)(order[i - 1] - subtrahend);
      borrow = order[i - 1] < subtrahend;
    }
    munit_assert_uint(borrow, ==, 0);
    /* Replacing s with n-s preserves an ECDSA signature. */
    memcpy(signature + n, complement, n);
    munit_assert_int(TC_ECDSA_verify_digest(vectors[v].curve, point, 1 + 2 * n,
        digest, n, signature, 2 * n, &workspace), ==, TC_OK);
    memcpy(signature + n, signature, n);
    /* z = n-r makes u1*G + u2*Q the point at infinity. */
    munit_assert_int(TC_ECDSA_verify_digest(vectors[v].curve, point, 1 + 2 * n,
        complement, n, signature, 2 * n, &workspace), ==, TC_MISMATCH);
    memcpy(signature + n, order, n);
    munit_assert_int(TC_ECDSA_verify_digest(vectors[v].curve, point, 1 + 2 * n,
        digest, n, signature, 2 * n, &workspace), ==, TC_MISMATCH);
    memcpy(signature + n, signature, n);
    memcpy(signature, order, n);
    munit_assert_int(TC_ECDSA_verify_digest(vectors[v].curve, point, 1 + 2 * n,
        digest, n, signature, 2 * n, &workspace), ==, TC_MISMATCH);
    munit_assert_true(tc_test_all_zero(&workspace, sizeof workspace));
  }
  return MUNIT_OK;
}

static MunitResult known_answers(const MunitParameter params[], void* user)
{
  TC_EC_workspace w;
  uint8_t scalar[48] = {0}, point[97], expected[97], generator[97], shared[48];
  size_t i, n;
  (void)params; (void)user;
  for (i = 0; i < sizeof vectors / sizeof vectors[0]; ++i) {
    n = vectors[i].bytes;
    memset(scalar, 0, sizeof scalar); scalar[n - 1] = 1;
    munit_assert_size(tc_test_decode_hex(vectors[i].generator, generator, sizeof generator), ==, 1 + 2 * n);
    munit_assert_int(TC_EC_public_key(vectors[i].curve, scalar, n, point, 1 + 2 * n, &w), ==, TC_OK);
    munit_assert_memory_equal(1 + 2 * n, point, generator);
    munit_assert_true(tc_test_all_zero(&w, sizeof w));
    scalar[n - 1] = 2;
    munit_assert_size(tc_test_decode_hex(vectors[i].twice, expected, sizeof expected), ==, 1 + 2 * n);
    munit_assert_int(TC_EC_public_key(vectors[i].curve, scalar, n, point, 1 + 2 * n, &w), ==, TC_OK);
    munit_assert_memory_equal(1 + 2 * n, point, expected);
    munit_assert_int(TC_ECDH(vectors[i].curve, scalar, n, generator, 1 + 2 * n, shared, n, &w), ==, TC_OK);
    munit_assert_memory_equal(n, shared, expected + 1);
    munit_assert_true(tc_test_all_zero(&w, sizeof w));
    munit_assert_size(tc_test_decode_hex(vectors[i].minus_one, scalar, sizeof scalar), ==, n);
    munit_assert_size(tc_test_decode_hex(vectors[i].negative, expected, sizeof expected), ==, 1 + 2 * n);
    munit_assert_int(TC_EC_public_key(vectors[i].curve, scalar, n, point, 1 + 2 * n, &w), ==, TC_OK);
    munit_assert_memory_equal(1 + 2 * n, point, expected);
    munit_assert_int(TC_EC_validate_public_key(vectors[i].curve, point, 1 + 2 * n, &w), ==, TC_OK);
  }
  return MUNIT_OK;
}

static MunitResult rejected_inputs(const MunitParameter params[], void* user)
{
  TC_EC_workspace w;
  uint8_t scalar[48] = {0}, point[97], output[97], saved[97];
  size_t i, n, length;
  (void)params; (void)user;
  memset(output, 0xa5, sizeof output); memcpy(saved, output, sizeof saved);
#if !TC_EC_ENABLE_P256
  munit_assert_int(TC_EC_public_key(TC_EC_P256, scalar, 32, output, 65, &w), ==, TC_ERROR);
#endif
#if !TC_EC_ENABLE_P384
  munit_assert_int(TC_EC_public_key(TC_EC_P384, scalar, 48, output, 97, &w), ==, TC_ERROR);
#endif
  for (i = 0; i < sizeof vectors / sizeof vectors[0]; ++i) {
    n = vectors[i].bytes;
    memset(scalar, 0, sizeof scalar);
    munit_assert_int(TC_EC_public_key(vectors[i].curve, scalar, n, output, 1 + 2 * n, &w), ==, TC_ERROR);
    munit_assert_true(tc_test_all_zero(&w, sizeof w));
    munit_assert_size(tc_test_decode_hex(vectors[i].order, scalar, sizeof scalar), ==, n);
    munit_assert_int(TC_EC_public_key(vectors[i].curve, scalar, n, output, 1 + 2 * n, &w), ==, TC_ERROR);
    memset(scalar, 0xff, sizeof scalar);
    munit_assert_int(TC_EC_public_key(vectors[i].curve, scalar, n, output, 1 + 2 * n, &w), ==, TC_ERROR);
    memset(scalar, 0, sizeof scalar); scalar[n - 1] = 1;
    munit_assert_size(tc_test_decode_hex(vectors[i].generator, point, sizeof point), ==, 1 + 2 * n);
    for (length = 0; length < 1 + 2 * n; ++length)
      munit_assert_int(TC_EC_validate_public_key(vectors[i].curve, point, length, &w), ==, TC_ERROR);
    point[0] = 2;
    munit_assert_int(TC_ECDH(vectors[i].curve, scalar, n, point, 1 + 2 * n, output, n, &w), ==, TC_ERROR);
    point[0] = 4; point[n] ^= 1;
    munit_assert_int(TC_ECDH(vectors[i].curve, scalar, n, point, 1 + 2 * n, output, n, &w), ==, TC_ERROR);
    memset(point + 1, 0xff, n);
    munit_assert_int(TC_ECDH(vectors[i].curve, scalar, n, point, 1 + 2 * n, output, n, &w), ==, TC_ERROR);
    memset(point + 1, 0, 2 * n);
    munit_assert_int(TC_EC_validate_public_key(vectors[i].curve, point, 1 + 2 * n, &w), ==, TC_ERROR);
    munit_assert_int(TC_EC_public_key(vectors[i].curve, scalar, n, scalar, n, &w), ==, TC_ERROR);
    munit_assert_int(TC_EC_public_key(vectors[i].curve, scalar, n, (uint8_t*)&w, 1 + 2 * n, &w), ==, TC_ERROR);
    munit_assert_int(TC_EC_public_key(vectors[i].curve, scalar, n, output, 1 + 2 * n, NULL), ==, TC_ERROR);
    munit_assert_int(TC_EC_public_key((TC_EC_curve)0, scalar, n, output, 1 + 2 * n, &w), ==, TC_ERROR);
    munit_assert_memory_equal(sizeof output, output, saved);
  }
  return MUNIT_OK;
}

static MunitResult captured_answer(const MunitParameter params[], void* user)
{
  TC_EC_workspace w;
  uint8_t scalar[48], peer[97], expected[97], point[97], z[48], shared[48];
  size_t n;
  TC_EC_curve curve;
  (void)params; (void)user;
  if (!capture) return MUNIT_SKIP;
  munit_assert_true(strcmp(capture[0], "256") == 0 || strcmp(capture[0], "384") == 0);
  curve = strcmp(capture[0], "256") == 0 ? TC_EC_P256 : TC_EC_P384;
  n = curve == TC_EC_P256 ? 32 : 48;
  munit_assert_size(tc_test_decode_hex(capture[1], scalar, sizeof scalar), ==, n);
  munit_assert_size(tc_test_decode_hex(capture[2], expected, sizeof expected), ==, 1 + 2 * n);
  munit_assert_size(tc_test_decode_hex(capture[3], peer, sizeof peer), ==, 1 + 2 * n);
  munit_assert_size(tc_test_decode_hex(capture[4], z, sizeof z), ==, n);
  munit_assert_int(TC_EC_public_key(curve, scalar, n, point, 1 + 2 * n, &w), ==, TC_OK);
  munit_assert_memory_equal(1 + 2 * n, point, expected);
  munit_assert_int(TC_ECDH(curve, scalar, n, peer, 1 + 2 * n, shared, n, &w), ==, TC_OK);
  munit_assert_memory_equal(n, shared, z);
  munit_assert_true(tc_test_all_zero(&w, sizeof w));
  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/wycheproof", wycheproof, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/known-answers", known_answers, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/signature-answers", signature_answers, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/rejected-inputs", rejected_inputs, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/captured-answer", captured_answer, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};
static const MunitSuite suite = {"/ec", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{
  if (argc == 3 && strcmp(argv[1], "--vectors") == 0) {
    char* args[] = {argv[0], (char*)"/ec/wycheproof", NULL};
    vector_path = argv[2];
    return munit_suite_main(&suite, NULL, 2, args);
  }
  if (argc == 7 && strcmp(argv[1], "--capture") == 0) {
    char* args[] = {argv[0], (char*)"/ec/captured-answer", NULL};
    capture = argv + 2;
    return munit_suite_main(&suite, NULL, 2, args);
  }
  return munit_suite_main(&suite, NULL, argc, argv);
}
