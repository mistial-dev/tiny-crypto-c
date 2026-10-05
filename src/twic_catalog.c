/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* TWIC data object catalogs (TWIC Part 2 v5 4.5 to 4.7). */
#include <tiny_crypto/piv_catalog.h>
#if TC_ENABLE_TWIC && TC_ENABLE_PIV_CATALOG
#include "piv_catalog_internal.h"

/* TWIC card application, TWIC Part 2 v5 4.5 table order. The capacities
 * are the 4.6 and 4.7 maximum values plus their structure bytes. */
#define TWIC_CHUID {PIV_TAG(0x02), TC_PIV_KIND_CHUID, ALWAYS, ALWAYS, M, 0, 0, 0x3000, 2469}
#define TWIC_UNSIGNED_CHUID                                                                        \
  {PIV_TAG(0x04), TC_PIV_KIND_UNSIGNED_CHUID, ALWAYS, ALWAYS, M, 0, 0, 0x3002, 57}
/* The TWIC Privacy Key reads on contact only (4.5, 4.6.2). */
#define TWIC_PRIVACY_KEY                                                                           \
  {TAG3(0xdf, 0xc1, 0x01), TC_PIV_KIND_TWIC_PRIVACY_KEY, ALWAYS, NEVER, M, 0, SECRET, 0x2001, 40}
#define TWIC_FINGERPRINTS                                                                          \
  {TAG3(0xdf, 0xc1, 0x03), TC_PIV_KIND_FINGERPRINTS, ALWAYS, ALWAYS, M, 0, 0, 0x2003, 2504}
#define TWIC_SECURITY                                                                              \
  {TAG3(0xdf, 0xc1, 0x0f), TC_PIV_KIND_SECURITY, ALWAYS, ALWAYS, M, 0, 0, 0x9000, 920}

static const TC_PIV_object_info legacy_catalog[] = {
    TWIC_CHUID, TWIC_UNSIGNED_CHUID, TWIC_PRIVACY_KEY, TWIC_FINGERPRINTS, TWIC_SECURITY,
};

/* NEXGEN adds the card authentication certificate, the Discovery Object
 * (4.7.5, ISO form) and the TPK-encrypted objects of 4.7. */
static const TC_PIV_object_info nexgen_catalog[] = {
    {PIV_TAG(0x01), TC_PIV_KIND_CERTIFICATE, ALWAYS, ALWAYS, M, 0x9e, 0, 0x0500, 1863},
    TWIC_CHUID,
    TWIC_UNSIGNED_CHUID,
    {{0x7e}, 1, TC_PIV_KIND_DISCOVERY, ALWAYS, ALWAYS, M, 0, 0, 0x6050, 20},
    {TAG3(0xdf, 0xc0, 0x01), TC_PIV_KIND_TWIC_PERSONAL, ALWAYS, ALWAYS, O, 0, 0, 0x6011, 4100},
    {TAG3(0xdf, 0xc0, 0x02), TC_PIV_KIND_TWIC_SIGNATURE_IMAGE, ALWAYS, ALWAYS, O, 0, 0, 0x6012,
     8132},
    TWIC_PRIVACY_KEY,
    TWIC_FINGERPRINTS,
    {TAG3(0xdf, 0xc1, 0x08), TC_PIV_KIND_FACE, ALWAYS, ALWAYS, M, 0, 0, 0x6030, 16714},
    {TAG3(0xdf, 0xc1, 0x09), TC_PIV_KIND_PRINTED, ALWAYS, ALWAYS, M, 0, 0, 0x3001, 203},
    TWIC_SECURITY,
    {TAG3(0xdf, 0xc1, 0x21), TC_PIV_KIND_IRIS, ALWAYS, ALWAYS, O, 0, 0, 0x1015, 7104},
};

const TC_PIV_object_info* tc_twic_catalog(TC_PIV_card_profile profile, size_t* count)
{
  if (profile == TC_TWIC_LEGACY_CARD) {
    *count = sizeof legacy_catalog / sizeof *legacy_catalog;
    return legacy_catalog;
  }
  if (profile == TC_TWIC_NEXGEN_CARD) {
    *count = sizeof nexgen_catalog / sizeof *nexgen_catalog;
    return nexgen_catalog;
  }
  *count = 0;
  return NULL;
}
#endif
