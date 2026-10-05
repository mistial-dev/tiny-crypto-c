/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * TWIC object identifiers from TWIC Part 2 v5 section 6. Each one has the
 * meaning of its PIV pair in piv_oid.c and uses the same arcs beneath the
 * TWIC root. */
#include "twic_oid_internal.h"
#if TC_ENABLE_TWIC && TC_ENABLE_PIV_OIDS
#include <string.h>

#define TWIC_ROOT 0x2b, 6, 1, 4, 1, 0x81, 0xe3, 0x52 /* 1.3.6.1.4.1.29138 */
#define OID_SPAN(contents) {contents, sizeof contents}

static const uint8_t digital_signature[] = {TWIC_ROOT, 2, 1, 3, 5};
static const uint8_t key_management[] = {TWIC_ROOT, 2, 1, 3, 6};
static const uint8_t devices[] = {TWIC_ROOT, 2, 1, 3, 8};
static const uint8_t authentication[] = {TWIC_ROOT, 2, 1, 3, 13};
static const uint8_t card_auth_policy[] = {TWIC_ROOT, 2, 1, 3, 17};
static const uint8_t fascn[] = {TWIC_ROOT, 6, 6};
static const uint8_t content_signing[] = {TWIC_ROOT, 6, 7};
static const uint8_t card_auth[] = {TWIC_ROOT, 6, 8};
static const uint8_t interim[] = {TWIC_ROOT, 6, 9, 1};

static const struct {
  TC_PIV_oid id;
  TC_bytes twic;
} twic_oids[] = {
    {TC_PIV_OID_POLICY_DIGITAL_SIGNATURE, OID_SPAN(digital_signature)},
    {TC_PIV_OID_POLICY_COMMON, OID_SPAN(key_management)},
    {TC_PIV_OID_POLICY_DEVICES, OID_SPAN(devices)},
    {TC_PIV_OID_POLICY_AUTHENTICATION, OID_SPAN(authentication)},
    {TC_PIV_OID_POLICY_CARD_AUTHENTICATION, OID_SPAN(card_auth_policy)},
    {TC_PIV_OID_FASCN, OID_SPAN(fascn)},
    {TC_PIV_OID_CONTENT_SIGNING, OID_SPAN(content_signing)},
    {TC_PIV_OID_CARD_AUTHENTICATION, OID_SPAN(card_auth)},
    {TC_PIV_OID_BACKGROUND_CHECK, OID_SPAN(interim)},
};

TC_PIV_oid tc_twic_oid_identify(TC_bytes oid)
{
  for (size_t i = 0; i < sizeof twic_oids / sizeof *twic_oids; ++i)
    if (oid.length == twic_oids[i].twic.length &&
        !memcmp(oid.data, twic_oids[i].twic.data, oid.length))
      return twic_oids[i].id;
  return TC_PIV_OID_UNKNOWN;
}

const TC_bytes* tc_twic_oid_contents(TC_PIV_oid id)
{
  for (size_t i = 0; i < sizeof twic_oids / sizeof *twic_oids; ++i)
    if (twic_oids[i].id == id)
      return &twic_oids[i].twic;
  return NULL;
}
#endif
