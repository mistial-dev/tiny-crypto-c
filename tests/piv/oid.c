/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/piv_oid.h>
#include "munit.h"
#include <string.h>

static MunitResult identifiers(const MunitParameter params[], void* user)
{
  static const struct {
    uint8_t suffix[4];
    size_t length;
    TC_PIV_oid kind;
    int piv, twic;
  } cases[] = {
    {{2,1,3,5},4,TC_PIV_OID_POLICY_DIGITAL_SIGNATURE,0,1},
    {{2,1,3,6},4,TC_PIV_OID_POLICY_KEY_MANAGEMENT,1,1},
    {{2,1,3,8},4,TC_PIV_OID_POLICY_DEVICES,1,1},
    {{2,1,3,13},4,TC_PIV_OID_POLICY_AUTHENTICATION,1,1},
    {{2,1,3,17},4,TC_PIV_OID_POLICY_CARD_AUTHENTICATION,1,1},
    {{2,1,3,39},4,TC_PIV_OID_POLICY_CONTENT_SIGNING,1,0},
    {{6,1},2,TC_PIV_OID_CHUID_CONTENT,1,0},
    {{6,2},2,TC_PIV_OID_BIOMETRIC_CONTENT,1,0},
    {{6,5},2,TC_PIV_OID_SIGNER_NAME,1,0},
    {{6,6},2,TC_PIV_OID_FASCN,1,1},
    {{6,7},2,TC_PIV_OID_CONTENT_SIGNING,1,1},
    {{6,8},2,TC_PIV_OID_CARD_AUTHENTICATION,1,1},
    {{6,9,1},3,TC_PIV_OID_BACKGROUND_CHECK,1,1}
  };
  static const uint8_t roots[][8] = {
    {0x60,0x86,0x48,1,0x65,3}, {0x2b,6,1,4,1,0x81,0xe3,0x52}
  };
  static const size_t root_lengths[] = {6,8};
  uint8_t encoded[16];
  for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
    for (unsigned twic = 0; twic < 2; ++twic) {
      const size_t root = root_lengths[twic], length = root + cases[i].length;
      memcpy(encoded,roots[twic],root);
      memcpy(encoded + root,cases[i].suffix,cases[i].length);
      const TC_bytes oid = {encoded,length};
      munit_assert_int(TC_PIV_oid_identify(oid,TC_PIV_OIDS_ONLY), ==,
          !twic && cases[i].piv ? cases[i].kind : TC_PIV_OID_UNKNOWN);
      munit_assert_int(TC_PIV_oid_identify(oid,TC_PIV_OIDS_TWIC_COMPATIBLE), ==,
          (twic ? cases[i].twic : cases[i].piv) ? cases[i].kind : TC_PIV_OID_UNKNOWN);
      for (size_t prefix = 0; prefix < length; ++prefix)
        munit_assert_int(TC_PIV_oid_identify((TC_bytes){encoded,prefix},
            TC_PIV_OIDS_TWIC_COMPATIBLE), ==, TC_PIV_OID_UNKNOWN);
      encoded[length] = 0;
      munit_assert_int(TC_PIV_oid_identify((TC_bytes){encoded,length + 1},
          TC_PIV_OIDS_TWIC_COMPATIBLE), ==, TC_PIV_OID_UNKNOWN);
      for (size_t byte = 0; byte < root; ++byte) {
        encoded[byte] ^= 1;
        munit_assert_int(TC_PIV_oid_identify(oid,TC_PIV_OIDS_TWIC_COMPATIBLE), ==, TC_PIV_OID_UNKNOWN);
        encoded[byte] ^= 1;
      }
      encoded[length - 1] |= 0x80; /* Unfinished base-128 arc. */
      munit_assert_int(TC_PIV_oid_identify(oid,TC_PIV_OIDS_TWIC_COMPATIBLE), ==, TC_PIV_OID_UNKNOWN);
    }
  }
  munit_assert_int(TC_PIV_oid_identify((TC_bytes){NULL,8},TC_PIV_OIDS_TWIC_COMPATIBLE),
      ==, TC_PIV_OID_UNKNOWN);
  munit_assert_int(TC_PIV_oid_identify((TC_bytes){encoded,8},(TC_PIV_oid_profile)99),
      ==, TC_PIV_OID_UNKNOWN);
  (void)params; (void)user;
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/identifiers",identifiers,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/piv/oid",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
