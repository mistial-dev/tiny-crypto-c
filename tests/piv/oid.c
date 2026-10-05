/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/piv_oid.h>
#include "../../src/piv_oid_internal.h"
#include "../../src/twic_oid_internal.h"
#include "munit.h"
#include "test_util.h"
#include <string.h>

TC_TEST(identifiers)
{
  static const struct {
    uint8_t suffix[4];
    size_t length;
    TC_PIV_oid kind;
    int piv, twic;
  } cases[] = {{{2, 1, 3, 5}, 4, TC_PIV_OID_POLICY_DIGITAL_SIGNATURE, 0, 1},
               {{2, 1, 3, 6}, 4, TC_PIV_OID_POLICY_COMMON, 1, 1},
               {{2, 1, 3, 8}, 4, TC_PIV_OID_POLICY_DEVICES, 1, 1},
               {{2, 1, 3, 13}, 4, TC_PIV_OID_POLICY_AUTHENTICATION, 1, 1},
               {{2, 1, 3, 17}, 4, TC_PIV_OID_POLICY_CARD_AUTHENTICATION, 1, 1},
               {{2, 1, 3, 39}, 4, TC_PIV_OID_POLICY_CONTENT_SIGNING, 1, 0},
               {{6, 1}, 2, TC_PIV_OID_CHUID_CONTENT, 1, 0},
               {{6, 2}, 2, TC_PIV_OID_BIOMETRIC_CONTENT, 1, 0},
               {{6, 5}, 2, TC_PIV_OID_SIGNER_NAME, 1, 0},
               {{6, 6}, 2, TC_PIV_OID_FASCN, 1, 1},
               {{6, 7}, 2, TC_PIV_OID_CONTENT_SIGNING, 1, 1},
               {{6, 8}, 2, TC_PIV_OID_CARD_AUTHENTICATION, 1, 1},
               {{6, 9, 1}, 3, TC_PIV_OID_BACKGROUND_CHECK, 1, 1}};
  static const uint8_t roots[][8] = {{0x60, 0x86, 0x48, 1, 0x65, 3},
                                     {0x2b, 6, 1, 4, 1, 0x81, 0xe3, 0x52}};
  static const size_t root_lengths[] = {6, 8};
  uint8_t encoded[16];
  for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
    for (unsigned twic = 0; twic < 2; ++twic) {
      const size_t root = root_lengths[twic], length = root + cases[i].length;
      memcpy(encoded, roots[twic], root);
      memcpy(encoded + root, cases[i].suffix, cases[i].length);
      const TC_bytes oid = {encoded, length};
      munit_assert_int(TC_PIV_oid_identify(oid, TC_PIV_OIDS_ONLY), ==,
                       !twic && cases[i].piv ? cases[i].kind : TC_PIV_OID_UNKNOWN);
      munit_assert_int(TC_PIV_oid_identify(oid, TC_PIV_OIDS_TWIC_COMPATIBLE), ==,
                       (twic ? cases[i].twic : cases[i].piv) ? cases[i].kind : TC_PIV_OID_UNKNOWN);
      for (size_t prefix = 0; prefix < length; ++prefix)
        munit_assert_int(
            TC_PIV_oid_identify((TC_bytes){encoded, prefix}, TC_PIV_OIDS_TWIC_COMPATIBLE), ==,
            TC_PIV_OID_UNKNOWN);
      encoded[length] = 0;
      munit_assert_int(
          TC_PIV_oid_identify((TC_bytes){encoded, length + 1}, TC_PIV_OIDS_TWIC_COMPATIBLE), ==,
          TC_PIV_OID_UNKNOWN);
      for (size_t byte = 0; byte < root; ++byte) {
        encoded[byte] ^= 1;
        munit_assert_int(TC_PIV_oid_identify(oid, TC_PIV_OIDS_TWIC_COMPATIBLE), ==,
                         TC_PIV_OID_UNKNOWN);
        encoded[byte] ^= 1;
      }
      encoded[length - 1] |= 0x80; /* Unfinished base-128 arc. */
      munit_assert_int(TC_PIV_oid_identify(oid, TC_PIV_OIDS_TWIC_COMPATIBLE), ==,
                       TC_PIV_OID_UNKNOWN);
    }
  }
  munit_assert_int(TC_PIV_oid_identify((TC_bytes){NULL, 8}, TC_PIV_OIDS_TWIC_COMPATIBLE), ==,
                   TC_PIV_OID_UNKNOWN);
  munit_assert_int(TC_PIV_oid_identify((TC_bytes){encoded, 8}, (TC_PIV_oid_profile)99), ==,
                   TC_PIV_OID_UNKNOWN);
  return MUNIT_OK;
}

/* Every identifier maps to the exact contents that identify it, in the
 * namespaces TWIC Part 2 v5 section 6 lists for it. */
TC_TEST(contents)
{
  static const uint8_t common_policy[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 2, 1, 3, 6};
  static const uint8_t twic_key_management[] = {0x2b, 6, 1, 4, 1, 0x81, 0xe3, 0x52, 2, 1, 3, 6};
  static const uint8_t content_signing_policy[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 2, 1, 3, 39};
  const TC_bytes* oid = tc_piv_oid_contents(TC_PIV_OID_POLICY_COMMON);
  munit_assert_not_null(oid);
  munit_assert_size(oid->length, ==, sizeof common_policy);
  munit_assert_memory_equal(sizeof common_policy, oid->data, common_policy);
  oid = tc_twic_oid_contents(TC_PIV_OID_POLICY_COMMON);
  munit_assert_not_null(oid);
  munit_assert_size(oid->length, ==, sizeof twic_key_management);
  munit_assert_memory_equal(sizeof twic_key_management, oid->data, twic_key_management);
  oid = tc_piv_oid_contents(TC_PIV_OID_POLICY_CONTENT_SIGNING);
  munit_assert_not_null(oid);
  munit_assert_size(oid->length, ==, sizeof content_signing_policy);
  munit_assert_memory_equal(sizeof content_signing_policy, oid->data, content_signing_policy);

  static const struct {
    TC_PIV_oid kind;
    int piv, twic;
  } namespaces[] = {{TC_PIV_OID_POLICY_DIGITAL_SIGNATURE, 0, 1},
                    {TC_PIV_OID_POLICY_COMMON, 1, 1},
                    {TC_PIV_OID_POLICY_DEVICES, 1, 1},
                    {TC_PIV_OID_POLICY_AUTHENTICATION, 1, 1},
                    {TC_PIV_OID_POLICY_CARD_AUTHENTICATION, 1, 1},
                    {TC_PIV_OID_POLICY_CONTENT_SIGNING, 1, 0},
                    {TC_PIV_OID_CHUID_CONTENT, 1, 0},
                    {TC_PIV_OID_BIOMETRIC_CONTENT, 1, 0},
                    {TC_PIV_OID_SIGNER_NAME, 1, 0},
                    {TC_PIV_OID_FASCN, 1, 1},
                    {TC_PIV_OID_CONTENT_SIGNING, 1, 1},
                    {TC_PIV_OID_CARD_AUTHENTICATION, 1, 1},
                    {TC_PIV_OID_BACKGROUND_CHECK, 1, 1}};
  for (size_t i = 0; i < sizeof namespaces / sizeof *namespaces; ++i) {
    const TC_bytes* piv = tc_piv_oid_contents(namespaces[i].kind);
    const TC_bytes* twic = tc_twic_oid_contents(namespaces[i].kind);
    munit_assert_int(piv != NULL, ==, namespaces[i].piv);
    munit_assert_int(twic != NULL, ==, namespaces[i].twic);
    if (piv) {
      munit_assert_int(TC_PIV_oid_identify(*piv, TC_PIV_OIDS_ONLY), ==, namespaces[i].kind);
      munit_assert_int(TC_PIV_oid_identify(*piv, TC_PIV_OIDS_TWIC_COMPATIBLE), ==,
                       namespaces[i].kind);
    }
    if (twic) {
      munit_assert_int(TC_PIV_oid_identify(*twic, TC_PIV_OIDS_ONLY), ==, TC_PIV_OID_UNKNOWN);
      munit_assert_int(TC_PIV_oid_identify(*twic, TC_PIV_OIDS_TWIC_COMPATIBLE), ==,
                       namespaces[i].kind);
    }
  }
  munit_assert_null(tc_piv_oid_contents(TC_PIV_OID_UNKNOWN));
  munit_assert_null(tc_twic_oid_contents(TC_PIV_OID_UNKNOWN));
  munit_assert_null(tc_piv_oid_contents((TC_PIV_oid)99));
  munit_assert_null(tc_twic_oid_contents((TC_PIV_oid)99));
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {{"/identifiers", identifiers, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {"/contents", contents, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
                       {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/piv/oid", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
