/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Entry notation shared by the PIV and TWIC data object catalogs. */
#ifndef TC_PIV_CATALOG_INTERNAL_H_
#define TC_PIV_CATALOG_INTERNAL_H_
#include <tiny_crypto/piv_catalog.h>

#if TC_ENABLE_PIV_CATALOG
enum {
  ALWAYS = TC_PIV_ACCESS_ALWAYS,
  PIN = TC_PIV_ACCESS_PIN,
  PIN_OR_OCC = TC_PIV_ACCESS_PIN_OR_OCC,
  VCI = TC_PIV_ACCESS_VCI,
  VCI_PIN = TC_PIV_ACCESS_VCI_PIN,
  VCI_PIN_OR_OCC = TC_PIV_ACCESS_VCI_PIN_OR_OCC,
  NEVER = TC_PIV_ACCESS_NEVER,
  M = TC_PIV_MANDATORY,
  C = TC_PIV_CONDITIONAL,
  O = TC_PIV_OPTIONAL,
  SECRET = TC_PIV_OBJECT_SECRET
};

/* A 3-byte tag, such as 5F C1 xx for PIV or DF C0 xx and DF C1 xx for TWIC. */
#define TAG3(a, b, c) {a, b, c}, 3
#define PIV_TAG(last) TAG3(0x5f, 0xc1, last)
#if TC_ENABLE_TWIC
/* The TWIC application catalog of profile and its entry count, or NULL
 * with count 0 for another profile. */
const TC_PIV_object_info* tc_twic_catalog(TC_PIV_card_profile profile, size_t* count);
#endif
#endif
#endif
