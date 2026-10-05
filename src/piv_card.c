/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/piv_card.h>
#if TC_ENABLE_PIV_OBJECTS
#include "piv_identifiers_internal.h"
#include "twic_card_identifiers_internal.h"
#include "credential_text_internal.h"
#include "string_internal.h"
#include "pki_reader_internal.h"
#include "pki_tree_internal.h"
#include "piv_uuid_internal.h"

enum {
  FASCN_BYTES = 25,
  UUID_BYTES = 16,
  UUID_URN_BYTES = 45,
  UUID_PREFIX_BYTES = 9,
  GENERAL_NAME_OTHER = 0,
  GENERAL_NAME_URI = 6
};

static int uuid_prefix(TC_bytes text)
{
  static const uint8_t prefix[] = "urn:uuid:";
  if (text.length < UUID_PREFIX_BYTES)
    return 0;
  for (size_t i = 0; i < UUID_PREFIX_BYTES; ++i)
    if (tc_ascii_fold(text.data[i]) != prefix[i])
      return 0;
  return 1;
}

static TC_TLV_result uuid_read(TC_bytes text, uint8_t uuid[UUID_BYTES])
{
  if (!text.data || text.length != UUID_URN_BYTES || !uuid_prefix(text))
    return TC_TLV_INVALID;
  /* RFC 4122 section 3: five hyphen-separated groups of 4, 2, 2, 2 and 6
   * octets. */
  static const uint8_t groups[] = {4, 2, 2, 2, 6};
  size_t position = UUID_PREFIX_BYTES, offset = 0;
  for (size_t group = 0; group < sizeof groups; ++group) {
    if (group && text.data[position++] != '-')
      return TC_TLV_INVALID;
    if (!tc_credential_hex_decode(text.data + position, groups[group], uuid + offset))
      return TC_TLV_INVALID;
    position += 2u * groups[group];
    offset += groups[group];
  }
  return TC_TLV_OK;
}

int tc_piv_card_uuid_valid(const uint8_t uuid[UUID_BYTES])
{
  return tc_piv_uuid_valid(uuid, TC_PIV_CARD_UUID_VERSIONS);
}

static TC_TLV_result read_fascn(const TC_X509_general_name* name, TC_PIV_oid_profile profile,
                                const TC_TLV_limits* limits, const tc_pki_tree_workspace* tree,
                                TC_PIV_card_identifiers* identifiers)
{
  tc_pki_oid_value other;
  TC_TLV_reader value;
  TC_TLV_element octets;
  TC_TLV_result result =
      tc_pki_tree_oid_value(name->encoded, 0xa0, TC_TLV_DER, limits, tree, &other);
  if (result != TC_TLV_OK)
    return result;
  /* Recognize every namespace the build knows before applying the selected
   * acceptance policy, so a TWIC FASC-N under the PIV profile is INVALID. */
#if TC_ENABLE_TWIC
  const TC_PIV_oid_profile recognized = TC_PIV_OIDS_TWIC_COMPATIBLE;
#else
  const TC_PIV_oid_profile recognized = TC_PIV_OIDS_ONLY;
#endif
  if (tc_pki_work_charge(tree->work, other.oid.length) != TC_TLV_OK)
    return TC_TLV_LIMIT;
  if (TC_PIV_oid_identify(other.oid, recognized) != TC_PIV_OID_FASCN)
    return TC_TLV_OK;
  if (tc_pki_work_charge(tree->work, other.oid.length) != TC_TLV_OK)
    return TC_TLV_LIMIT;
  if (identifiers->fascn.data || TC_PIV_oid_identify(other.oid, profile) != TC_PIV_OID_FASCN)
    return TC_TLV_INVALID;
  result = tc_pki_tree_open(other.value, 0xa0, TC_TLV_DER, limits, tree, &value);
  if (result != TC_TLV_OK)
    return result;
  result = tc_pki_tree_field(&value, 4, tree, &octets);
  if (result != TC_TLV_OK)
    return result;
  if (!tc_pki_end(&value) || octets.value.length != FASCN_BYTES)
    return TC_TLV_INVALID;
  identifiers->fascn = octets.value;
  identifiers->fascn_oid = other.oid;
  return TC_TLV_OK;
}

TC_TLV_result tc_piv_identifiers_read(TC_bytes encoded, const tc_piv_identifier_rules* rules,
                                      const uint8_t* card_guid, const TC_TLV_limits* limits,
                                      TC_TLV_frames frames, size_t* work,
                                      TC_PIV_card_identifiers* out)
{
  TC_TLV_result result = tc_pki_reader_storage(encoded, limits, frames, work, out, sizeof *out);
  if (result != TC_TLV_OK)
    return result;
  TC_PIV_card_identifiers identifiers = {0};
  TC_bytes uuid_urns[2] = {0};
  uint8_t uuids[2][UUID_BYTES] = {{0}};
  size_t uuid_count = 0;
  const tc_pki_tree_workspace tree = {frames.data, frames.capacity, work};
  const int authentication = rules->authentication;
  TC_TLV_reader reader;
  /* One full framing scan, then bounded schema scans through every name. */
  result = tc_pki_tree_open(encoded, 0x30, TC_TLV_DER, limits, &tree, &reader);
  if (result != TC_TLV_OK)
    return result == TC_TLV_MORE ? TC_TLV_INVALID : result;
  if (tc_pki_end(&reader))
    return TC_TLV_INVALID;
  TC_X509_general_names_reader names = {reader, frames};
  while (!tc_pki_end(&names.reader)) {
    TC_X509_general_name name;
    TC_TLV_reader next = names.reader;
    TC_TLV_element element;
    result = TC_TLV_next(&next, &element);
    if (result != TC_TLV_OK)
      return result;
    /* next_tree and GeneralName schema checks each scan the name's bytes. */
    for (unsigned scan = 0; scan < 2; ++scan)
      if (tc_pki_work_charge(work, element.encoded.length) != TC_TLV_OK)
        return TC_TLV_LIMIT;
    result = TC_X509_general_name_next(&names, &name);
    if (result != TC_TLV_OK)
      return result;
    if (name.type == GENERAL_NAME_OTHER) {
      result = read_fascn(&name, rules->oids, limits, &tree, &identifiers);
      if (result != TC_TLV_OK)
        return result;
    } else if (name.type == GENERAL_NAME_URI) {
      const size_t prefix_bytes =
          name.value.length < UUID_PREFIX_BYTES ? name.value.length : UUID_PREFIX_BYTES;
      if (tc_pki_work_charge(work, prefix_bytes) != TC_TLV_OK)
        return TC_TLV_LIMIT;
      if (!uuid_prefix(name.value))
        continue;
      const size_t uuid_capacity = authentication ? 2 : 1;
      if (uuid_count == uuid_capacity)
        return TC_TLV_INVALID;
      if (tc_pki_work_charge(work, name.value.length) != TC_TLV_OK)
        return TC_TLV_LIMIT;
      result = uuid_read(name.value, uuids[uuid_count]);
      if (result != TC_TLV_OK || !rules->uuid_valid(uuids[uuid_count]))
        return TC_TLV_INVALID;
      uuid_urns[uuid_count++] = name.value;
    }
  }
  if (!identifiers.fascn.data || (!rules->uuid_optional && uuid_count == 0))
    return TC_TLV_INVALID;
  /* Index of the card UUID. Authentication certificates may also carry a
   * cardholder UUID, in either order. */
  size_t card_index = 0;
  if (authentication && uuid_count) {
    unsigned matches = 0;
    for (size_t i = 0; i < uuid_count; ++i)
      if (!memcmp(uuids[i], card_guid, UUID_BYTES)) {
        card_index = i;
        ++matches;
      }
    if (matches != 1)
      return TC_TLV_INVALID;
    identifiers.uuid_urn = uuid_urns[card_index];
    if (uuid_count == 2) {
      const size_t cardholder_index = card_index ^ 1u;
      if (!tc_piv_uuid_valid(uuids[cardholder_index], TC_PIV_CARDHOLDER_UUID_VERSIONS))
        return TC_TLV_INVALID;
      identifiers.cardholder_uuid_urn = uuid_urns[cardholder_index];
    }
  } else if (uuid_count) {
    identifiers.uuid_urn = uuid_urns[card_index];
  }
  if (tc_pki_work_charge(work, FASCN_BYTES) != TC_TLV_OK)
    return TC_TLV_LIMIT;
  TC_FASCN decoded;
  result = TC_FASCN_read(identifiers.fascn, &decoded);
  if (result != TC_TLV_OK)
    return result;
  if (rules->uuid_fascn_check && identifiers.uuid_urn.data) {
    if (tc_pki_work_charge(work, UUID_BYTES) != TC_TLV_OK)
      return TC_TLV_LIMIT;
    int matched;
    result = rules->uuid_fascn_check(uuids[card_index], &decoded, &matched);
    if (result != TC_TLV_OK)
      return result;
    if (!matched)
      return TC_TLV_INVALID;
  }
  *out = identifiers;
  return TC_TLV_OK;
}

TC_TLV_result TC_PIV_card_identifiers_read(TC_bytes encoded, TC_PIV_card_profile profile,
                                           const TC_TLV_limits* limits, TC_TLV_frames frames,
                                           size_t* work, TC_PIV_card_identifiers* out)
{
  static const tc_piv_identifier_rules piv = {TC_PIV_OIDS_ONLY, 0, 0, tc_piv_card_uuid_valid, NULL};
  tc_piv_identifier_rules rules = piv;
#if TC_ENABLE_TWIC
  if (profile != TC_PIV_CARD && !tc_twic_identifier_rules(profile, 0, &rules))
    return TC_TLV_ARGUMENT;
#else
  if (profile != TC_PIV_CARD)
    return TC_TLV_ARGUMENT;
#endif
  return tc_piv_identifiers_read(encoded, &rules, NULL, limits, frames, work, out);
}

TC_TLV_result TC_PIV_authentication_identifiers_read(TC_bytes encoded, TC_bytes card_guid,
                                                     const TC_TLV_limits* limits,
                                                     TC_TLV_frames frames, size_t* work,
                                                     TC_PIV_card_identifiers* out)
{
  static const tc_piv_identifier_rules rules = {TC_PIV_OIDS_ONLY, 1, 0, tc_piv_card_uuid_valid,
                                                NULL};
  if (!card_guid.data || card_guid.length != UUID_BYTES)
    return TC_TLV_ARGUMENT;
  uint8_t expected[UUID_BYTES];
  memcpy(expected, card_guid.data, sizeof expected);
  return tc_piv_identifiers_read(encoded, &rules, expected, limits, frames, work, out);
}

TC_TLV_result tc_piv_identifiers_match(const TC_PIV_card_identifiers* identifiers, TC_bytes fascn,
                                       TC_bytes guid, int uuid_optional, size_t* work, int* matched)
{
  TC_bytes writes[2];
  tc_pki_storage_plan plan;
  if (!identifiers || !work || !matched || !fascn.data || fascn.length != FASCN_BYTES ||
      !guid.data || guid.length != UUID_BYTES)
    return TC_TLV_ARGUMENT;
  const TC_bytes fields[] = {identifiers->fascn,
                             identifiers->fascn_oid,
                             identifiers->uuid_urn,
                             identifiers->cardholder_uuid_urn,
                             fascn,
                             guid};
  tc_pki_storage_plan_begin(&plan, writes, 2, SIZE_MAX);
  TC_PKI_PLAN_WRITE(&plan, work, 1);
  TC_PKI_PLAN_WRITE(&plan, matched, 1);
  tc_pki_storage_plan_seal(&plan);
  TC_PKI_PLAN_INPUT(&plan, identifiers, 1);
  tc_pki_storage_plan_input_spans(&plan, fields, sizeof fields / sizeof *fields);
  TC_TLV_result result = tc_pki_storage_plan_finish(&plan, NULL);
  if (result != TC_TLV_OK)
    return result;
  if (!identifiers->fascn.data || identifiers->fascn.length != FASCN_BYTES)
    return TC_TLV_INVALID;
  result = tc_pki_work_charge(work, tc_pki_storage_plan_used(&plan) + FASCN_BYTES + UUID_BYTES);
  if (result != TC_TLV_OK)
    return result;
  uint8_t uuid[UUID_BYTES] = {0};
  if (identifiers->uuid_urn.data || identifiers->uuid_urn.length) {
    result = tc_pki_work_charge(work, identifiers->uuid_urn.length);
    if (result != TC_TLV_OK)
      return result;
    result = uuid_read(identifiers->uuid_urn, uuid);
    if (result != TC_TLV_OK)
      return result;
  }
  const int fascn_matches = !memcmp(identifiers->fascn.data, fascn.data, FASCN_BYTES);
  const int uuid_matches =
      (uuid_optional && !identifiers->uuid_urn.length) || !memcmp(uuid, guid.data, UUID_BYTES);
  *matched = fascn_matches && uuid_matches;
  return TC_TLV_OK;
}

TC_TLV_result TC_PIV_card_identifiers_match(const TC_PIV_card_identifiers* identifiers,
                                            TC_bytes fascn, TC_bytes guid, size_t* work,
                                            int* matched)
{
  return tc_piv_identifiers_match(identifiers, fascn, guid, 0, work, matched);
}
#endif
