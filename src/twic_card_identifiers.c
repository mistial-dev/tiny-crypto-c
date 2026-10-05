/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* TWIC card identifiers in certificate subjectAltNames. */
#include <tiny_crypto/piv_card.h>
#if TC_ENABLE_TWIC && TC_ENABLE_PIV_OBJECTS
#include <tiny_crypto/twic_uuid.h>
#include "twic_card_identifiers_internal.h"
#include <string.h>

enum { UUID_BYTES = 16 };

/* TWIC Legacy cards hold the nil UUID. */
static int legacy_uuid(const uint8_t uuid[UUID_BYTES])
{
  static const uint8_t nil[UUID_BYTES] = {0};
  return !memcmp(uuid, nil, sizeof nil);
}

/* TWIC NEXGEN card UUIDs encode the FASC-N (TWIC Part 2 v5 Appendix D). */
static int nexgen_uuid(const uint8_t uuid[UUID_BYTES])
{
  uint64_t number;
  return TC_TWIC_uuid_read((TC_bytes){uuid, UUID_BYTES}, &number) == TC_TLV_OK;
}

static TC_TLV_result nexgen_fascn(const uint8_t uuid[UUID_BYTES], const TC_FASCN* fascn,
                                  int* matched)
{
  return TC_TWIC_uuid_match((TC_bytes){uuid, UUID_BYTES}, fascn, matched);
}

int tc_twic_identifier_rules(TC_PIV_card_profile profile, int reader_policy,
                             tc_piv_identifier_rules* out)
{
  static const tc_piv_identifier_rules legacy = {TC_PIV_OIDS_TWIC_COMPATIBLE, 0, 1, legacy_uuid,
                                                 NULL};
  static const tc_piv_identifier_rules nexgen = {TC_PIV_OIDS_TWIC_COMPATIBLE, 0, 0, nexgen_uuid,
                                                 nexgen_fascn};
  if (profile == TC_TWIC_LEGACY_CARD)
    *out = legacy;
  else if (profile == TC_TWIC_NEXGEN_CARD) {
    *out = nexgen;
    out->uuid_optional = (uint8_t)(reader_policy != 0);
  } else
    return 0;
  return 1;
}

TC_TLV_result TC_TWIC_card_identifiers_read(TC_bytes encoded, TC_PIV_card_profile profile,
                                            const TC_TLV_limits* limits, TC_TLV_frames frames,
                                            size_t* work, TC_PIV_card_identifiers* out)
{
  tc_piv_identifier_rules rules;
  if (!tc_twic_identifier_rules(profile, 1, &rules))
    return TC_TLV_ARGUMENT;
  return tc_piv_identifiers_read(encoded, &rules, NULL, limits, frames, work, out);
}

TC_TLV_result TC_TWIC_authentication_identifiers_read(TC_bytes encoded, TC_bytes card_guid,
                                                      const TC_TLV_limits* limits,
                                                      TC_TLV_frames frames, size_t* work,
                                                      TC_PIV_card_identifiers* out)
{
  static const tc_piv_identifier_rules rules = {TC_PIV_OIDS_TWIC_COMPATIBLE, 1, 1,
                                                tc_piv_card_uuid_valid, NULL};
  if (!card_guid.data || card_guid.length != UUID_BYTES)
    return TC_TLV_ARGUMENT;
  uint8_t expected[UUID_BYTES];
  memcpy(expected, card_guid.data, sizeof expected);
  return tc_piv_identifiers_read(encoded, &rules, expected, limits, frames, work, out);
}

TC_TLV_result TC_TWIC_card_identifiers_match(const TC_PIV_card_identifiers* identifiers,
                                             TC_bytes fascn, TC_bytes guid, size_t* work,
                                             int* matched)
{
  return tc_piv_identifiers_match(identifiers, fascn, guid, 1, work, matched);
}
#endif
