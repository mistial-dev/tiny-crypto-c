/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * PIV object identifiers from TWIC Part 2 v5 section 6, FIPS 201-3 Tables
 * B-1 and B-2 and the Federal PKI Common Policy section 1.2. twic_oid.c holds
 * their TWIC pairs. */
#include "piv_oid_internal.h"
#include "twic_oid_internal.h"
#if TC_ENABLE_PIV_OIDS
#include <string.h>

#define PIV_ROOT 0x60, 0x86, 0x48, 1, 0x65, 3 /* 2.16.840.1.101.3 */
#define OID_SPAN(contents) {contents, sizeof contents}
#define OID_NONE {NULL, 0}

/* Certificate policies. */
static const uint8_t fpki_common_policy[] = {PIV_ROOT, 2, 1, 3, 6};
static const uint8_t fpki_common_devices[] = {PIV_ROOT, 2, 1, 3, 8};
static const uint8_t fpki_common_authentication[] = {PIV_ROOT, 2, 1, 3, 13};
static const uint8_t fpki_common_card_auth[] = {PIV_ROOT, 2, 1, 3, 17};
static const uint8_t fpki_common_content_signing[] = {PIV_ROOT, 2, 1, 3, 39};
/* CMS content types and attributes. */
static const uint8_t piv_chuid_content[] = {PIV_ROOT, 6, 1};
static const uint8_t piv_biometric_content[] = {PIV_ROOT, 6, 2};
static const uint8_t piv_signer_name[] = {PIV_ROOT, 6, 5};
static const uint8_t piv_fascn[] = {PIV_ROOT, 6, 6};
/* Extended key usages. */
static const uint8_t piv_content_signing[] = {PIV_ROOT, 6, 7};
static const uint8_t piv_card_auth[] = {PIV_ROOT, 6, 8};
/* Certificate extensions. */
static const uint8_t piv_naci[] = {PIV_ROOT, 6, 9, 1};

/* One row per identifier with a PIV OID. */
static const struct {
  TC_PIV_oid id;
  TC_bytes piv;
} piv_oids[] = {
    {TC_PIV_OID_POLICY_COMMON, OID_SPAN(fpki_common_policy)},
    {TC_PIV_OID_POLICY_DEVICES, OID_SPAN(fpki_common_devices)},
    {TC_PIV_OID_POLICY_AUTHENTICATION, OID_SPAN(fpki_common_authentication)},
    {TC_PIV_OID_POLICY_CARD_AUTHENTICATION, OID_SPAN(fpki_common_card_auth)},
    {TC_PIV_OID_POLICY_CONTENT_SIGNING, OID_SPAN(fpki_common_content_signing)},
    {TC_PIV_OID_CHUID_CONTENT, OID_SPAN(piv_chuid_content)},
    {TC_PIV_OID_BIOMETRIC_CONTENT, OID_SPAN(piv_biometric_content)},
    {TC_PIV_OID_SIGNER_NAME, OID_SPAN(piv_signer_name)},
    {TC_PIV_OID_FASCN, OID_SPAN(piv_fascn)},
    {TC_PIV_OID_CONTENT_SIGNING, OID_SPAN(piv_content_signing)},
    {TC_PIV_OID_CARD_AUTHENTICATION, OID_SPAN(piv_card_auth)},
    {TC_PIV_OID_BACKGROUND_CHECK, OID_SPAN(piv_naci)},
};

static int profile_known(TC_PIV_oid_profile profile)
{
#if TC_ENABLE_TWIC
  if (profile == TC_PIV_OIDS_TWIC_COMPATIBLE)
    return 1;
#endif
  return profile == TC_PIV_OIDS_ONLY;
}

TC_PIV_oid TC_PIV_oid_identify(TC_bytes oid, TC_PIV_oid_profile profile)
{
  if (!oid.data || !profile_known(profile))
    return TC_PIV_OID_UNKNOWN;
  for (size_t i = 0; i < sizeof piv_oids / sizeof *piv_oids; ++i)
    if (oid.length == piv_oids[i].piv.length && !memcmp(oid.data, piv_oids[i].piv.data, oid.length))
      return piv_oids[i].id;
#if TC_ENABLE_TWIC
  /* TWIC Part 2 v5 section 6: TWIC readers accept either namespace. */
  if (profile == TC_PIV_OIDS_TWIC_COMPATIBLE)
    return tc_twic_oid_identify(oid);
#endif
  return TC_PIV_OID_UNKNOWN;
}

const TC_bytes* tc_piv_oid_contents(TC_PIV_oid id)
{
  for (size_t i = 0; i < sizeof piv_oids / sizeof *piv_oids; ++i)
    if (piv_oids[i].id == id)
      return &piv_oids[i].piv;
  return NULL;
}
#endif
