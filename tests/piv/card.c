/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "fascn_fixture.h"
#include "munit.h"
#include <string.h>
#include <tiny_crypto/piv_card.h>

enum { CAPACITY = 512, FRAMES = 8, WORK = 32768 };
static const TC_TLV_limits limits = {CAPACITY, CAPACITY, 64, FRAMES};
static const uint8_t piv_oid[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 6, 6};
static const uint8_t twic_oid[] = {0x2b, 6, 1, 4, 1, 0x81, 0xe3, 0x52, 6, 6};
static const char piv_uuid[] = "urn:uuid:00112233-4455-4677-8899-aabbccddeeff";
static const char twic_uuid[] = "urn:uuid:91be2094-f6dc-5349-8000-4090e49e505c";
static const char nil_uuid[] = "urn:uuid:00000000-0000-0000-0000-000000000000";
static const uint8_t guid[] = {0,    0x11, 0x22, 0x33, 0x44, 0x55, 0x46, 0x77,
                               0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
static const uint8_t twic_guid[] = {0x91, 0xbe, 0x20, 0x94, 0xf6, 0xdc,
                                    0x53, 0x49, 0x80, 0x00, 0x40, 0x90,
                                    0xe4, 0x9e, 0x50, 0x5c};

static size_t wrap(uint8_t tag, const uint8_t *value, size_t length,
                   uint8_t *output) {
  munit_assert_size(length, <, CAPACITY - 4);
  size_t used = 0;
  output[used++] = tag;
  if (length < 128)
    output[used++] = (uint8_t)length;
  else if (length <= 255) {
    output[used++] = 0x81;
    output[used++] = (uint8_t)length;
  } else {
    output[used++] = 0x82;
    output[used++] = (uint8_t)(length >> 8);
    output[used++] = (uint8_t)length;
  }
  if (length)
    memcpy(output + used, value, length);
  return used + length;
}

static size_t names_values(const uint8_t *oid, size_t oid_length,
                           const char *uuid, const char *second_uuid,
                           unsigned fascn_count, unsigned uuid_count,
                           uint8_t *output) {
  uint8_t contents[CAPACITY], other[64], octets[32], explicit_value[40],
      fascn[25];
  memcpy(fascn, test_card_fascn, sizeof fascn);
  const size_t octet_length = wrap(4, fascn, sizeof fascn, octets);
  const size_t explicit_length =
      wrap(0xa0, octets, octet_length, explicit_value);
  const size_t oid_bytes = wrap(6, oid, oid_length, other);
  memcpy(other + oid_bytes, explicit_value, explicit_length);
  size_t length = 0;
  for (unsigned i = 0; i < fascn_count; ++i)
    length += wrap(0xa0, other, oid_bytes + explicit_length, contents + length);
  for (unsigned i = 0; i < uuid_count; ++i)
    length +=
        wrap(0x86, (const uint8_t *)uuid, strlen(uuid), contents + length);
  if (second_uuid)
    length += wrap(0x86, (const uint8_t *)second_uuid, strlen(second_uuid),
                   contents + length);
  return wrap(0x30, contents, length, output);
}

static size_t names(const uint8_t *oid, size_t oid_length, const char *uuid,
                    unsigned fascn_count, unsigned uuid_count,
                    uint8_t *output) {
  return names_values(oid, oid_length, uuid, NULL, fascn_count, uuid_count,
                      output);
}

static MunitResult profiles(const MunitParameter params[], void *context) {
  const struct {
    TC_PIV_card_profile profile;
    const char *uuid;
    unsigned copies;
  } cases[] = {
      {TC_PIV_CARD, piv_uuid, 1},
      {TC_TWIC_NEXGEN_CARD, twic_uuid, 1},
      {TC_PIV_CARD, "urn:uuid:00112233-4455-1677-8899-aabbccddeeff", 1},
      {TC_PIV_CARD, "urn:uuid:00112233-4455-5677-8899-aabbccddeeff", 1},
      {TC_TWIC_LEGACY_CARD, nil_uuid, 1},
      {TC_TWIC_LEGACY_CARD, nil_uuid, 0}};
  uint8_t encoded[CAPACITY], fascn[25];
  TC_TLV_frame frames[FRAMES];
  memcpy(fascn, test_card_fascn, sizeof fascn);
  for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
    for (unsigned twic = 0; twic < 2; ++twic) {
      const uint8_t *oid = twic ? twic_oid : piv_oid;
      const size_t oid_length = twic ? sizeof twic_oid : sizeof piv_oid;
      const size_t length =
          names(oid, oid_length, cases[i].uuid, 1, cases[i].copies, encoded);
      TC_PIV_card_identifiers out, saved;
      memset(&out, 0xa5, sizeof out);
      memcpy(&saved, &out, sizeof saved);
      size_t work = WORK;
      const TC_TLV_result result = TC_PIV_card_identifiers_read(
          (TC_bytes){encoded, length}, cases[i].profile, &limits, frames,
          FRAMES, &work, &out);
      if (twic && cases[i].profile == TC_PIV_CARD) {
        munit_assert_int(result, ==, TC_TLV_INVALID);
        munit_assert_memory_equal(sizeof out, &out, &saved);
      } else {
        munit_assert_int(result, ==, TC_TLV_OK);
        munit_assert_memory_equal(sizeof fascn, out.fascn.data, fascn);
        munit_assert_size(out.fascn.length, ==, sizeof fascn);
        munit_assert_memory_equal(oid_length, out.fascn_oid.data, oid);
        munit_assert_true(out.fascn.data >= encoded &&
                          out.fascn.data + out.fascn.length <=
                              encoded + length);
        munit_assert_size(out.uuid_urn.length, ==,
                          cases[i].copies ? strlen(cases[i].uuid) : 0);
      }
    }
  }
  (void)params;
  (void)context;
  return MUNIT_OK;
}

static MunitResult malformed(const MunitParameter params[], void *context) {
  const struct {
    const char *uuid;
    unsigned fascn_count, uuid_count;
    TC_PIV_card_profile profile;
  } cases[] = {
      {piv_uuid, 0, 1, TC_PIV_CARD},
      {piv_uuid, 1, 0, TC_PIV_CARD},
      {piv_uuid, 2, 1, TC_PIV_CARD},
      {piv_uuid, 1, 2, TC_PIV_CARD},
      {nil_uuid, 1, 1, TC_PIV_CARD},
      {piv_uuid, 1, 1, TC_TWIC_NEXGEN_CARD},
      {twic_uuid, 1, 1, TC_TWIC_LEGACY_CARD},
      {"urn:uuid:91be2094-f6dc-5349-8000-ffffffffffff", 1, 1,
       TC_TWIC_NEXGEN_CARD},
      {"urn:uuid:91be2094-f6dc-5349-8000-4090e49e505d", 1, 1,
       TC_TWIC_NEXGEN_CARD},
      {"urn:uuid:00112233-4455-3677-8899-aabbccddeeff", 1, 1, TC_PIV_CARD},
      {"urn:uuid:00112233-4455-4677-c899-aabbccddeeff", 1, 1, TC_PIV_CARD},
      {"urn:uuid:00112233-4455-4677-8899-aabbccddeefg", 1, 1, TC_PIV_CARD},
      {"urn:uuid:00112233_4455-4677-8899-aabbccddeeff", 1, 1, TC_PIV_CARD},
      {"urn:uuid:00112233-4455-4677-8899-aabbccddeef", 1, 1, TC_PIV_CARD},
      {"urn:uuid:00112233-4455-4677-8899-aabbccddeeff0", 1, 1, TC_PIV_CARD}};
  uint8_t encoded[CAPACITY];
  TC_TLV_frame frames[FRAMES];
  TC_PIV_card_identifiers out, saved;
  memset(&saved, 0xa5, sizeof saved);
  for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
    size_t length = names(piv_oid, sizeof piv_oid, cases[i].uuid,
                          cases[i].fascn_count, cases[i].uuid_count, encoded);
    size_t work = WORK;
    memcpy(&out, &saved, sizeof out);
    munit_assert_int(TC_PIV_card_identifiers_read((TC_bytes){encoded, length},
                                                  cases[i].profile, &limits,
                                                  frames, FRAMES, &work, &out),
                     ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof out, &out, &saved);
  }
  size_t length = names(piv_oid, sizeof piv_oid, piv_uuid, 1, 1, encoded);
  size_t parse_work = WORK;
  munit_assert_int(TC_PIV_card_identifiers_read((TC_bytes){encoded, length},
                                                TC_PIV_CARD, &limits, frames,
                                                FRAMES, &parse_work, &out),
                   ==, TC_TLV_OK);
  const size_t fascn_offset = (size_t)(out.fascn.data - encoded);
  for (size_t bit = 0; bit < sizeof test_card_fascn * 8; ++bit) {
    encoded[fascn_offset + bit / 8] ^= (uint8_t)(1u << (bit % 8));
    size_t work = WORK;
    memcpy(&out, &saved, sizeof out);
    munit_assert_int(TC_PIV_card_identifiers_read((TC_bytes){encoded, length},
                                                  TC_PIV_CARD, &limits, frames,
                                                  FRAMES, &work, &out),
                     ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof out, &out, &saved);
    encoded[fascn_offset + bit / 8] ^= (uint8_t)(1u << (bit % 8));
  }
  for (size_t truncated = 0; truncated < length; ++truncated) {
    size_t work = WORK;
    memcpy(&out, &saved, sizeof out);
    munit_assert_int(TC_PIV_card_identifiers_read(
                         (TC_bytes){encoded, truncated}, TC_PIV_CARD, &limits,
                         frames, FRAMES, &work, &out),
                     !=, TC_TLV_OK);
    munit_assert_memory_equal(sizeof out, &out, &saved);
  }
  /* Both registered namespaces describe the same FASC-N field. */
  length = names(piv_oid, sizeof piv_oid, nil_uuid, 1, 1, encoded);
  uint8_t other[CAPACITY], merged[CAPACITY];
  const size_t other_length =
      names(twic_oid, sizeof twic_oid, piv_uuid, 1, 0, other);
  memcpy(merged, encoded + 2, length - 2);
  memcpy(merged + length - 2, other + 2, other_length - 2);
  length = wrap(0x30, merged, length + other_length - 4, encoded);
  size_t work = WORK;
  munit_assert_int(TC_PIV_card_identifiers_read((TC_bytes){encoded, length},
                                                TC_TWIC_LEGACY_CARD, &limits,
                                                frames, FRAMES, &work, &out),
                   ==, TC_TLV_INVALID);
  (void)params;
  (void)context;
  return MUNIT_OK;
}

static MunitResult binding(const MunitParameter params[], void *context) {
  uint8_t encoded[CAPACITY], fascn[25], expected_guid[16];
  TC_TLV_frame frames[FRAMES];
  TC_PIV_card_identifiers identifiers;
  memcpy(fascn, test_card_fascn, sizeof fascn);
  memcpy(expected_guid, guid, sizeof guid);
  const size_t length =
      names(piv_oid, sizeof piv_oid,
            "URN:UUID:00112233-4455-4677-8899-AABBCCDDEEFF", 1, 1, encoded);
  size_t work = WORK;
  munit_assert_int(TC_PIV_card_identifiers_read((TC_bytes){encoded, length},
                                                TC_PIV_CARD, &limits, frames,
                                                FRAMES, &work, &identifiers),
                   ==, TC_TLV_OK);
  for (unsigned mismatch = 0; mismatch < 3; ++mismatch) {
    if (mismatch == 1)
      fascn[0] ^= 1;
    if (mismatch == 2)
      expected_guid[15] ^= 1;
    int matched = -1;
    work = WORK;
    munit_assert_int(TC_PIV_card_identifiers_match(
                         &identifiers, (TC_bytes){fascn, sizeof fascn},
                         (TC_bytes){expected_guid, sizeof expected_guid}, &work,
                         &matched),
                     ==, TC_TLV_OK);
    munit_assert_int(matched, ==, mismatch == 0);
    if (mismatch == 1)
      fascn[0] ^= 1;
    if (mismatch == 2)
      expected_guid[15] ^= 1;
  }
  int matched = -1;
  work = 0;
  munit_assert_int(TC_PIV_card_identifiers_match(
                       &identifiers, (TC_bytes){fascn, sizeof fascn},
                       (TC_bytes){expected_guid, sizeof expected_guid}, &work,
                       &matched),
                   ==, TC_TLV_LIMIT);
  munit_assert_int(matched, ==, -1);
  work = WORK;
  size_t saved_work = work;
  munit_assert_int(TC_PIV_card_identifiers_match(
                       &identifiers, (TC_bytes){fascn, sizeof fascn},
                       (TC_bytes){expected_guid, sizeof expected_guid}, &work,
                       (int *)&work),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, saved_work);
  /* Legacy certificates can omit the UUID; their CHUID GUID remains nil. */
  const size_t legacy_length =
      names(twic_oid, sizeof twic_oid, nil_uuid, 1, 0, encoded);
  work = WORK;
  munit_assert_int(TC_PIV_card_identifiers_read(
                       (TC_bytes){encoded, legacy_length}, TC_TWIC_LEGACY_CARD,
                       &limits, frames, FRAMES, &work, &identifiers),
                   ==, TC_TLV_OK);
  memset(expected_guid, 0, sizeof expected_guid);
  for (unsigned mismatch = 0; mismatch < 2; ++mismatch) {
    expected_guid[15] = (uint8_t)mismatch;
    work = WORK;
    matched = -1;
    munit_assert_int(TC_PIV_card_identifiers_match(
                         &identifiers, (TC_bytes){fascn, sizeof fascn},
                         (TC_bytes){expected_guid, sizeof expected_guid}, &work,
                         &matched),
                     ==, TC_TLV_OK);
    munit_assert_int(matched, ==, !mismatch);
  }
  (void)params;
  (void)context;
  return MUNIT_OK;
}

static MunitResult boundaries(const MunitParameter params[], void *context) {
  uint8_t encoded[CAPACITY];
  const size_t length = names(piv_oid, sizeof piv_oid, piv_uuid, 1, 1, encoded);
  TC_TLV_frame frames[FRAMES];
  TC_PIV_card_identifiers out, saved;
  size_t work = WORK;
  munit_assert_int(TC_PIV_card_identifiers_read((TC_bytes){encoded, length},
                                                TC_PIV_CARD, &limits, frames,
                                                FRAMES, &work, &out),
                   ==, TC_TLV_OK);
  const size_t required = WORK - work;
  memset(&saved, 0xa5, sizeof saved);
  for (size_t budget = 0; budget < required; ++budget) {
    work = budget;
    memcpy(&out, &saved, sizeof out);
    munit_assert_int(TC_PIV_card_identifiers_read((TC_bytes){encoded, length},
                                                  TC_PIV_CARD, &limits, frames,
                                                  FRAMES, &work, &out),
                     ==, TC_TLV_LIMIT);
    munit_assert_memory_equal(sizeof out, &out, &saved);
    munit_assert_size(work, <=, budget);
  }
  union {
    TC_PIV_card_identifiers identifiers;
    uint8_t bytes[CAPACITY];
  } aliased;
  memcpy(aliased.bytes, encoded, length);
  work = WORK;
  munit_assert_int(TC_PIV_card_identifiers_read(
                       (TC_bytes){aliased.bytes, length}, TC_PIV_CARD, &limits,
                       frames, FRAMES, &work, &aliased.identifiers),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, WORK);
  munit_assert_memory_equal(length, aliased.bytes, encoded);
  for (size_t capacity = 0; capacity < 3; ++capacity) {
    work = WORK;
    memcpy(&out, &saved, sizeof out);
    munit_assert_int(TC_PIV_card_identifiers_read((TC_bytes){encoded, length},
                                                  TC_PIV_CARD, &limits, frames,
                                                  capacity, &work, &out),
                     ==, TC_TLV_LIMIT);
    munit_assert_memory_equal(sizeof out, &out, &saved);
  }
  (void)params;
  (void)context;
  return MUNIT_OK;
}

static MunitResult reader_policy(const MunitParameter params[], void *context) {
  uint8_t encoded[CAPACITY], fascn[25];
  TC_TLV_frame frames[FRAMES];
  TC_PIV_card_identifiers identifiers;
  memcpy(fascn, test_card_fascn, sizeof fascn);
  size_t length = names(twic_oid, sizeof twic_oid, twic_uuid, 1, 0, encoded);
  size_t work = WORK;
  munit_assert_int(TC_TWIC_card_identifiers_read(
                       (TC_bytes){encoded, length}, TC_TWIC_NEXGEN_CARD,
                       &limits, frames, FRAMES, &work, &identifiers),
                   ==, TC_TLV_OK);
  munit_assert_size(identifiers.uuid_urn.length, ==, 0);
  const size_t read_required = WORK - work;
  const TC_PIV_card_identifiers saved = identifiers;
  for (size_t budget = 0; budget < read_required; ++budget) {
    TC_PIV_card_identifiers limited = saved;
    work = budget;
    munit_assert_int(TC_TWIC_card_identifiers_read(
                         (TC_bytes){encoded, length}, TC_TWIC_NEXGEN_CARD,
                         &limits, frames, FRAMES, &work, &limited),
                     ==, TC_TLV_LIMIT);
    munit_assert_memory_equal(sizeof limited, &limited, &saved);
  }
  int matched = 0;
  work = WORK;
  munit_assert_int(TC_TWIC_card_identifiers_match(
                       &identifiers, (TC_bytes){fascn, sizeof fascn},
                       (TC_bytes){guid, sizeof guid}, &work, &matched),
                   ==, TC_TLV_OK);
  munit_assert_int(matched, ==, 1);
  fascn[0] ^= 1;
  work = WORK;
  munit_assert_int(TC_TWIC_card_identifiers_match(
                       &identifiers, (TC_bytes){fascn, sizeof fascn},
                       (TC_bytes){guid, sizeof guid}, &work, &matched),
                   ==, TC_TLV_OK);
  munit_assert_int(matched, ==, 0);
  fascn[0] ^= 1;
  work = WORK;
  munit_assert_int(TC_PIV_card_identifiers_read(
                       (TC_bytes){encoded, length}, TC_TWIC_NEXGEN_CARD,
                       &limits, frames, FRAMES, &work, &identifiers),
                   ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof saved, &saved, &identifiers);
  length = names(twic_oid, sizeof twic_oid, twic_uuid, 1, 1, encoded);
  work = WORK;
  munit_assert_int(TC_TWIC_card_identifiers_read(
                       (TC_bytes){encoded, length}, TC_TWIC_NEXGEN_CARD,
                       &limits, frames, FRAMES, &work, &identifiers),
                   ==, TC_TLV_OK);
  work = WORK;
  munit_assert_int(TC_TWIC_card_identifiers_match(
                       &identifiers, (TC_bytes){fascn, sizeof fascn},
                       (TC_bytes){twic_guid, sizeof twic_guid}, &work,
                       &matched),
                   ==, TC_TLV_OK);
  munit_assert_int(matched, ==, 1);
  const size_t match_required = WORK - work;
  for (size_t budget = 0; budget < match_required; ++budget) {
    matched = -1;
    work = budget;
    munit_assert_int(TC_TWIC_card_identifiers_match(
                         &identifiers, (TC_bytes){fascn, sizeof fascn},
                         (TC_bytes){twic_guid, sizeof twic_guid}, &work,
                         &matched),
                     ==, TC_TLV_LIMIT);
    munit_assert_int(matched, ==, -1);
  }
  work = WORK;
  munit_assert_int(TC_TWIC_card_identifiers_match(
                       &identifiers, (TC_bytes){fascn, sizeof fascn},
                       (TC_bytes){guid, sizeof guid}, &work, &matched),
                   ==, TC_TLV_OK);
  munit_assert_int(matched, ==, 0);
  length = names(twic_oid, sizeof twic_oid, twic_uuid, 2, 0, encoded);
  work = WORK;
  munit_assert_int(TC_TWIC_card_identifiers_read(
                       (TC_bytes){encoded, length}, TC_TWIC_NEXGEN_CARD,
                       &limits, frames, FRAMES, &work, &identifiers),
                   ==, TC_TLV_INVALID);
  (void)params;
  (void)context;
  return MUNIT_OK;
}

static MunitResult authentication_policy(const MunitParameter params[],
                                         void *context) {
  static const char cardholder_uuid[] =
      "urn:uuid:10213243-5465-4768-899a-abbccddeeff0";
  static const char version_one_uuid[] =
      "urn:uuid:10213243-5465-1768-899a-abbccddeeff0";
  uint8_t encoded[CAPACITY];
  TC_TLV_frame frames[FRAMES];
  TC_PIV_card_identifiers identifiers;

  for (unsigned reversed = 0; reversed < 2; ++reversed) {
    const char *first = reversed ? cardholder_uuid : piv_uuid;
    const char *second = reversed ? piv_uuid : cardholder_uuid;
    const size_t length =
        names_values(piv_oid, sizeof piv_oid, first, second, 1, 1, encoded);
    size_t work = WORK;
    munit_assert_int(TC_PIV_authentication_identifiers_read(
                         (TC_bytes){encoded, length},
                         (TC_bytes){guid, sizeof guid}, &limits, frames, FRAMES,
                         &work, &identifiers),
                     ==, TC_TLV_OK);
    munit_assert_memory_equal(strlen(piv_uuid), identifiers.uuid_urn.data,
                              piv_uuid);
    munit_assert_memory_equal(strlen(cardholder_uuid),
                              identifiers.cardholder_uuid_urn.data,
                              cardholder_uuid);

    const size_t required = WORK - work;
    TC_PIV_card_identifiers saved;
    memset(&saved, 0xa5, sizeof saved);
    for (size_t budget = 0; budget < required; ++budget) {
      identifiers = saved;
      work = budget;
      munit_assert_int(TC_PIV_authentication_identifiers_read(
                           (TC_bytes){encoded, length},
                           (TC_bytes){guid, sizeof guid}, &limits, frames,
                           FRAMES, &work, &identifiers),
                       ==, TC_TLV_LIMIT);
      munit_assert_memory_equal(sizeof identifiers, &identifiers, &saved);
    }
  }

  size_t length = names_values(twic_oid, sizeof twic_oid, piv_uuid,
                               cardholder_uuid, 1, 1, encoded);
  size_t work = WORK;
  munit_assert_int(TC_TWIC_authentication_identifiers_read(
                       (TC_bytes){encoded, length},
                       (TC_bytes){guid, sizeof guid}, &limits, frames, FRAMES,
                       &work, &identifiers),
                   ==, TC_TLV_OK);
  munit_assert_memory_equal(strlen(piv_uuid), identifiers.uuid_urn.data,
                            piv_uuid);
  munit_assert_memory_equal(strlen(cardholder_uuid),
                            identifiers.cardholder_uuid_urn.data,
                            cardholder_uuid);

  work = WORK;
  munit_assert_int(TC_PIV_authentication_identifiers_read(
                       (TC_bytes){encoded, length},
                       (TC_bytes){guid, sizeof guid}, &limits, frames, FRAMES,
                       &work, &identifiers),
                   ==, TC_TLV_INVALID);

  length = names(twic_oid, sizeof twic_oid, piv_uuid, 1, 0, encoded);
  work = WORK;
  munit_assert_int(TC_TWIC_authentication_identifiers_read(
                       (TC_bytes){encoded, length},
                       (TC_bytes){guid, sizeof guid}, &limits, frames, FRAMES,
                       &work, &identifiers),
                   ==, TC_TLV_OK);
  munit_assert_size(identifiers.uuid_urn.length, ==, 0);
  munit_assert_size(identifiers.cardholder_uuid_urn.length, ==, 0);

  static const uint8_t unknown_oid[] = {0x2a, 3, 4};
  length = names(unknown_oid, sizeof unknown_oid, piv_uuid, 1, 0, encoded);
  work = WORK;
  munit_assert_int(TC_TWIC_authentication_identifiers_read(
                       (TC_bytes){encoded, length},
                       (TC_bytes){guid, sizeof guid}, &limits, frames, FRAMES,
                       &work, &identifiers),
                   ==, TC_TLV_INVALID);

  length = names(piv_oid, sizeof piv_oid, piv_uuid, 1, 1, encoded);
  work = WORK;
  munit_assert_int(TC_PIV_authentication_identifiers_read(
                       (TC_bytes){encoded, length},
                       (TC_bytes){guid, sizeof guid}, &limits, frames, FRAMES,
                       &work, &identifiers),
                   ==, TC_TLV_OK);
  munit_assert_size(identifiers.cardholder_uuid_urn.length, ==, 0);

  const struct {
    const char *first;
    const char *second;
    unsigned copies;
  } invalid[] = {{cardholder_uuid, NULL, 1},
                 {piv_uuid, NULL, 2},
                 {piv_uuid, version_one_uuid, 1},
                 {piv_uuid, cardholder_uuid, 2}};
  TC_PIV_card_identifiers saved;
  memset(&saved, 0xa5, sizeof saved);
  for (size_t i = 0; i < sizeof invalid / sizeof *invalid; ++i) {
    length = names_values(piv_oid, sizeof piv_oid, invalid[i].first,
                          invalid[i].second, 1, invalid[i].copies, encoded);
    identifiers = saved;
    work = WORK;
    munit_assert_int(TC_PIV_authentication_identifiers_read(
                         (TC_bytes){encoded, length},
                         (TC_bytes){guid, sizeof guid}, &limits, frames, FRAMES,
                         &work, &identifiers),
                     ==, TC_TLV_INVALID);
    munit_assert_memory_equal(sizeof identifiers, &identifiers, &saved);
  }

  work = WORK;
  munit_assert_int(TC_PIV_authentication_identifiers_read(
                       (TC_bytes){encoded, length}, (TC_bytes){guid, 15},
                       &limits, frames, FRAMES, &work, &identifiers),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_size(work, ==, WORK);
  (void)params;
  (void)context;
  return MUNIT_OK;
}

int main(int argc, char **argv) {
  MunitTest tests[] = {
      {"/profiles", profiles, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/reader-policy", reader_policy, NULL, NULL, MUNIT_TEST_OPTION_NONE,
       NULL},
      {"/authentication-policy", authentication_policy, NULL, NULL,
       MUNIT_TEST_OPTION_NONE, NULL},
      {"/malformed", malformed, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/binding", binding, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/boundaries", boundaries, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/piv/card", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
