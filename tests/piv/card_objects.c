/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Discovery, CCC, Key History, BIT group, Pairing Code and certificate
 * decode readers. Recorded bytes come from NIST SD 33 card 2 and the GSA
 * ICAM test cards in tests/vectors/piv. */
#include "munit.h"
#include "test_util.h"
#include <stdio.h>
#include <string.h>
#include <tiny_crypto/piv_card_objects.h>
#include <tiny_crypto/piv_certificate.h>
#include <tiny_crypto/piv_discovery.h>

#ifndef TC_PIV_VECTOR_DIR
#error "TC_PIV_VECTOR_DIR must name tests/vectors/piv"
#endif

enum { OBJECT_BYTES = 4096, CERTIFICATE_BYTES = 2048 };

typedef struct {
  uint8_t bytes[OBJECT_BYTES];
  size_t length;
} object;

static size_t vector_read(const char* name, uint8_t* bytes, size_t capacity)
{
  char path[512];
  const int written = snprintf(path, sizeof path, "%s/%s", TC_PIV_VECTOR_DIR, name);
  munit_assert_int(written, >, 0);
  munit_assert_size((size_t)written, <, sizeof path);
  FILE* file = fopen(path, "rb");
  munit_assert_not_null(file);
  const size_t length = fread(bytes, 1, capacity, file);
  munit_assert_int(ferror(file), ==, 0);
  munit_assert_int(fgetc(file), ==, EOF);
  munit_assert_int(fclose(file), ==, 0);
  return length;
}

static void append(object* value, const void* bytes, size_t length)
{
  munit_assert_size(value->length + length, <=, sizeof value->bytes);
  if (length)
    memcpy(value->bytes + value->length, bytes, length);
  value->length += length;
}

static void append_byte(object* value, uint8_t byte)
{
  append(value, &byte, 1);
}

/* Append tag, a short or 81/82 length, and value. */
static void append_tlv(object* value, unsigned tag, const void* bytes, size_t length)
{
  if (tag > 0xff)
    append_byte(value, (uint8_t)(tag >> 8));
  append_byte(value, (uint8_t)tag);
  if (length > 0xff) {
    append_byte(value, 0x82);
    append_byte(value, (uint8_t)(length >> 8));
  } else if (length > 0x7f)
    append_byte(value, 0x81);
  append_byte(value, (uint8_t)length);
  append(value, bytes, length);
}

static object wrap(unsigned tag, const object* contents)
{
  object value = {{0}, 0};
  append_tlv(&value, tag, contents->bytes, contents->length);
  return value;
}

static TC_bytes span(const object* value)
{
  return (TC_bytes){value->bytes, value->length};
}

static void discovery_same(const TC_PIV_discovery* a, const TC_PIV_discovery* b)
{
  munit_assert_ptr_equal(a->aid.data, b->aid.data);
  munit_assert_size(a->aid.length, ==, b->aid.length);
  munit_assert_uint8(a->policy, ==, b->policy);
  munit_assert_uint8(a->preference, ==, b->preference);
  munit_assert_uint8(a->profile, ==, b->profile);
  munit_assert_uint8(a->secured, ==, b->secured);
}

static void ccc_same(const TC_PIV_CCC* a, const TC_PIV_CCC* b)
{
  munit_assert_ptr_equal(a->card_identifier.data, b->card_identifier.data);
  munit_assert_size(a->card_identifier.length, ==, b->card_identifier.length);
  munit_assert_ptr_equal(a->card_url.data, b->card_url.data);
  munit_assert_size(a->card_url.length, ==, b->card_url.length);
  munit_assert_ptr_equal(a->access_control_rules.data, b->access_control_rules.data);
  munit_assert_size(a->access_control_rules.length, ==, b->access_control_rules.length);
  munit_assert_int(a->container_version, ==, b->container_version);
  munit_assert_int(a->grammar_version, ==, b->grammar_version);
  munit_assert_int(a->pkcs15, ==, b->pkcs15);
  munit_assert_uint8(a->data_model, ==, b->data_model);
}

static void key_history_same(const TC_PIV_key_history* a, const TC_PIV_key_history* b)
{
  munit_assert_uint8(a->on_card, ==, b->on_card);
  munit_assert_uint8(a->off_card, ==, b->off_card);
  munit_assert_ptr_equal(a->url.data, b->url.data);
  munit_assert_size(a->url.length, ==, b->url.length);
}

static void bit_group_same(const TC_PIV_bit_group* a, const TC_PIV_bit_group* b)
{
  munit_assert_uint(a->fingers, ==, b->fingers);
  for (size_t i = 0; i < 2; ++i) {
    munit_assert_ptr_equal(a->templates[i].data, b->templates[i].data);
    munit_assert_size(a->templates[i].length, ==, b->templates[i].length);
  }
}

static void certificate_same(const TC_PIV_certificate* a, const TC_PIV_certificate* b)
{
  munit_assert_ptr_equal(a->certificate.data, b->certificate.data);
  munit_assert_size(a->certificate.length, ==, b->certificate.length);
  munit_assert_ptr_equal(a->intermediate_cvc.data, b->intermediate_cvc.data);
  munit_assert_size(a->intermediate_cvc.length, ==, b->intermediate_cvc.length);
  munit_assert_ptr_equal(a->mscuid.data, b->mscuid.data);
  munit_assert_size(a->mscuid.length, ==, b->mscuid.length);
  munit_assert_int(a->compression, ==, b->compression);
}

/* Discovery Object */

static const uint8_t card2_discovery[] = {0x7e, 0x12, 0x4f, 0x0b, 0xa0, 0x00, 0x00,
                                          0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01,
                                          0x00, 0x5f, 0x2f, 0x02, 0x48, 0x00};
static const uint8_t twic_aid[] = {0xa0, 0x00, 0x00, 0x03, 0x67, 0x20,
                                   0x00, 0x00, 0x01, 0x01, 0x03};

static object discovery(const uint8_t* aid, uint8_t policy, uint8_t preference)
{
  object value = {{0}, 0};
  append(&value, card2_discovery, sizeof card2_discovery);
  if (aid)
    memcpy(value.bytes + 4, aid, 11);
  value.bytes[18] = policy;
  value.bytes[19] = preference;
  return value;
}

static TC_TLV_result discovery_read(const object* value, TC_PIV_discovery_profile profile,
                                    TC_PIV_discovery* out)
{
  return TC_PIV_discovery_read(span(value), profile, out);
}

TC_TEST(discovery_recorded)
{
  TC_PIV_discovery parsed;
  memset(&parsed, 0xa5, sizeof parsed);
  munit_assert_int(TC_PIV_discovery_read((TC_bytes){card2_discovery, sizeof card2_discovery},
                                         TC_PIV_DISCOVERY_PIV, &parsed),
                   ==, TC_TLV_OK);
  munit_assert_ptr_equal(parsed.aid.data, card2_discovery + 4);
  munit_assert_size(parsed.aid.length, ==, 11);
  munit_assert_uint8(parsed.policy, ==, TC_PIV_POLICY_PIV_PIN | TC_PIV_POLICY_VCI);
  munit_assert_uint8(parsed.preference, ==, 0);
  munit_assert_uint8(parsed.profile, ==, TC_PIV_DISCOVERY_PIV);
  munit_assert_uint8(parsed.secured, ==, 0);
  munit_assert_uint8(TC_PIV_discovery_pin_reference(&parsed), ==, 0x80);

  /* ICAM cards: 40 00, 60 10 and 60 20. */
  static const char* const icam[] = {"icam_cards/26_Disco_Object_Present_App_PIN_Only/"
                                     "1_Discovery_Object.bin",
                                     "icam_cards/27_Disco_Object_Present_App_PIN_Primary/"
                                     "1_Discovery_Object.bin",
                                     "icam_cards/28_Disco_Object_Present_Global_PIN_Primary/"
                                     "1_Discovery_Object.bin"};
  static const uint8_t references[] = {0x80, 0x80, 0x00};
  for (size_t i = 0; i < sizeof icam / sizeof *icam; ++i) {
    object value = {{0}, 0};
    value.length = vector_read(icam[i], value.bytes, sizeof value.bytes);
    munit_assert_int(discovery_read(&value, TC_PIV_DISCOVERY_PIV, &parsed), ==, TC_TLV_OK);
    munit_assert_uint8(TC_PIV_discovery_pin_reference(&parsed), ==, references[i]);
  }
  return MUNIT_OK;
}

TC_TEST(discovery_policy)
{
  /* SP 800-73-5 Part 1 Table 1. */
  static const uint8_t accepted[] = {0x40, 0x48, 0x4c, 0x50, 0x58, 0x5c,
                                     0x60, 0x68, 0x6c, 0x70, 0x78, 0x7c};
  TC_PIV_discovery parsed;
  for (unsigned first = 0; first < 256; ++first) {
    int listed = 0;
    for (size_t i = 0; i < sizeof accepted; ++i)
      listed |= accepted[i] == first;
    const uint8_t preference = (first & TC_PIV_POLICY_GLOBAL_PIN) ? 0x10 : 0x00;
    object value = discovery(NULL, (uint8_t)first, preference);
    munit_assert_int(discovery_read(&value, TC_PIV_DISCOVERY_PIV, &parsed), ==,
                     listed ? TC_TLV_OK : TC_TLV_INVALID);
  }
  object value = discovery(NULL, 0x68, 0x20);
  munit_assert_int(discovery_read(&value, TC_PIV_DISCOVERY_PIV, &parsed), ==, TC_TLV_OK);
  munit_assert_uint8(TC_PIV_discovery_pin_reference(&parsed), ==, 0x00);
  /* The second byte is RFU without bit 6 and 10 or 20 with it. */
  static const uint8_t wrong[][2] = {
      {0x40, 0x10}, {0x48, 0x20}, {0x60, 0x00}, {0x60, 0x30}, {0x68, 0x01}};
  for (size_t i = 0; i < sizeof wrong / sizeof *wrong; ++i) {
    value = discovery(NULL, wrong[i][0], wrong[i][1]);
    munit_assert_int(discovery_read(&value, TC_PIV_DISCOVERY_PIV, &parsed), ==, TC_TLV_INVALID);
  }
  /* The PIV profile takes only the PIV AID. */
  value = discovery(twic_aid, 0x40, 0x00);
  munit_assert_int(discovery_read(&value, TC_PIV_DISCOVERY_PIV, &parsed), ==, TC_TLV_INVALID);
  munit_assert_uint8(TC_PIV_discovery_pin_reference(NULL), ==, 0x80);
  return MUNIT_OK;
}

TC_TEST(discovery_twic)
{
  TC_PIV_discovery parsed;
  /* TWIC Part 2 v5 sections 4.2 and 4.7.5. */
  object value = discovery(NULL, 0x04, 0x00);
  munit_assert_int(discovery_read(&value, TC_PIV_DISCOVERY_TWIC, &parsed), ==, TC_TLV_OK);
  munit_assert_uint8(parsed.profile, ==, TC_PIV_DISCOVERY_TWIC);
  munit_assert_uint8(TC_PIV_discovery_pin_reference(&parsed), ==, 0x80);
  munit_assert_int(discovery_read(&value, TC_PIV_DISCOVERY_PIV, &parsed), ==, TC_TLV_INVALID);
  value = discovery(NULL, 0x40, 0x00);
  munit_assert_int(discovery_read(&value, TC_PIV_DISCOVERY_TWIC, &parsed), ==, TC_TLV_OK);
  value = discovery(twic_aid, 0x00, 0x00);
  munit_assert_int(discovery_read(&value, TC_PIV_DISCOVERY_TWIC, &parsed), ==, TC_TLV_OK);
  munit_assert_memory_equal(sizeof twic_aid, parsed.aid.data, twic_aid);
  munit_assert_int(discovery_read(&value, TC_PIV_DISCOVERY_PIV, &parsed), ==, TC_TLV_INVALID);
  /* The Legacy sub-version is a listed TWIC AID. Others are not. */
  uint8_t aid[sizeof twic_aid];
  memcpy(aid, twic_aid, sizeof aid);
  aid[10] = 0x01;
  value = discovery(aid, 0x00, 0x00);
  munit_assert_int(discovery_read(&value, TC_PIV_DISCOVERY_TWIC, &parsed), ==, TC_TLV_OK);
  aid[10] = 0x02;
  value = discovery(aid, 0x00, 0x00);
  munit_assert_int(discovery_read(&value, TC_PIV_DISCOVERY_TWIC, &parsed), ==, TC_TLV_INVALID);
  aid[10] = 0x03;
  aid[9] = 0x02;
  value = discovery(aid, 0x00, 0x00);
  munit_assert_int(discovery_read(&value, TC_PIV_DISCOVERY_TWIC, &parsed), ==, TC_TLV_INVALID);
  /* Only the three listed TWIC policies. */
  static const uint8_t wrong[][2] = {{0x48, 0x00}, {0x04, 0x10}, {0x00, 0x10}, {0x60, 0x10}};
  for (size_t i = 0; i < sizeof wrong / sizeof *wrong; ++i) {
    value = discovery(NULL, wrong[i][0], wrong[i][1]);
    munit_assert_int(discovery_read(&value, TC_PIV_DISCOVERY_TWIC, &parsed), ==, TC_TLV_INVALID);
  }
  return MUNIT_OK;
}

TC_TEST(discovery_framing)
{
  TC_PIV_discovery parsed;
  memset(&parsed, 0xa5, sizeof parsed);
  TC_PIV_discovery before = parsed;
  object value = discovery(NULL, 0x40, 0x00);
  /* Truncation inside 7E is MORE. */
  for (size_t length = 1; length < value.length; ++length)
    munit_assert_int(
        TC_PIV_discovery_read((TC_bytes){value.bytes, length}, TC_PIV_DISCOVERY_PIV, &parsed), ==,
        TC_TLV_MORE);
  munit_assert_int(TC_PIV_discovery_read((TC_bytes){value.bytes, 0}, TC_PIV_DISCOVERY_PIV, &parsed),
                   ==, TC_TLV_INVALID);
  /* Trailing bytes, the empty 7E 00 of ICAM card 25, another tag and a
   * long-form length. */
  append_byte(&value, 0x00);
  munit_assert_int(discovery_read(&value, TC_PIV_DISCOVERY_PIV, &parsed), ==, TC_TLV_INVALID);
  static const uint8_t empty[] = {0x7e, 0x00};
  munit_assert_int(
      TC_PIV_discovery_read((TC_bytes){empty, sizeof empty}, TC_PIV_DISCOVERY_PIV, &parsed), ==,
      TC_TLV_INVALID);
  value = discovery(NULL, 0x40, 0x00);
  value.bytes[0] = 0x53;
  munit_assert_int(discovery_read(&value, TC_PIV_DISCOVERY_PIV, &parsed), ==, TC_TLV_INVALID);
  object contents = {{0}, 0};
  append(&contents, card2_discovery + 2, sizeof card2_discovery - 2);
  object long_form = {{0}, 0};
  append_byte(&long_form, 0x7e);
  append_byte(&long_form, 0x81);
  append_byte(&long_form, 0x12);
  append(&long_form, contents.bytes, contents.length);
  munit_assert_int(discovery_read(&long_form, TC_PIV_DISCOVERY_PIV, &parsed), ==, TC_TLV_INVALID);
  /* Swapped elements and a wrong inner length. */
  object swapped = {{0}, 0};
  append_byte(&swapped, 0x7e);
  append_byte(&swapped, 0x12);
  append(&swapped, card2_discovery + 15, 5);
  append(&swapped, card2_discovery + 2, 13);
  munit_assert_int(discovery_read(&swapped, TC_PIV_DISCOVERY_PIV, &parsed), ==, TC_TLV_INVALID);
  value = discovery(NULL, 0x40, 0x00);
  value.bytes[17] = 0x01;
  munit_assert_int(discovery_read(&value, TC_PIV_DISCOVERY_PIV, &parsed), ==, TC_TLV_INVALID);
  discovery_same(&parsed, &before);
  return MUNIT_OK;
}

TC_TEST(discovery_arguments)
{
  object value = discovery(NULL, 0x40, 0x00);
  TC_PIV_discovery parsed;
  memset(&parsed, 0xa5, sizeof parsed);
  TC_PIV_discovery before = parsed;
  munit_assert_int(discovery_read(&value, TC_PIV_DISCOVERY_PIV, NULL), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_discovery_read((TC_bytes){NULL, 1}, TC_PIV_DISCOVERY_PIV, &parsed), ==,
                   TC_TLV_ARGUMENT);
  munit_assert_int(discovery_read(&value, (TC_PIV_discovery_profile)2, &parsed), ==,
                   TC_TLV_ARGUMENT);
  TC_PIV_discovery* inside = (TC_PIV_discovery*)(void*)value.bytes;
  munit_assert_int(
      TC_PIV_discovery_read((TC_bytes){value.bytes, sizeof *inside}, TC_PIV_DISCOVERY_PIV, inside),
      ==, TC_TLV_ARGUMENT);
  discovery_same(&parsed, &before);
  return MUNIT_OK;
}

/* Card Capability Container */

static const uint8_t card2_ccc[] = {0x53, 0x1b, 0xf0, 0x00, 0xf1, 0x00, 0xf2, 0x00, 0xf3, 0x00,
                                    0xf4, 0x00, 0xf5, 0x01, 0x10, 0xf6, 0x00, 0xf7, 0x00, 0xfa,
                                    0x00, 0xfb, 0x00, 0xfc, 0x00, 0xfd, 0x00, 0xfe, 0x00};

/* The SD 33 card 2 CCC contents with element tag replaced by value. */
static object ccc_contents(void)
{
  object value = {{0}, 0};
  append(&value, card2_ccc + 2, sizeof card2_ccc - 2);
  return value;
}

TC_TEST(ccc_recorded)
{
  TC_PIV_CCC parsed;
  memset(&parsed, 0xa5, sizeof parsed);
  munit_assert_int(
      TC_PIV_CCC_read((TC_bytes){card2_ccc, sizeof card2_ccc}, TC_PIV_CONTAINER, &parsed), ==,
      TC_TLV_OK);
  munit_assert_size(parsed.card_identifier.length, ==, 0);
  munit_assert_size(parsed.card_url.length, ==, 0);
  munit_assert_size(parsed.access_control_rules.length, ==, 0);
  munit_assert_int(parsed.container_version, ==, -1);
  munit_assert_int(parsed.grammar_version, ==, -1);
  munit_assert_int(parsed.pkcs15, ==, -1);
  munit_assert_uint8(parsed.data_model, ==, 0x10);

  object icam = {{0}, 0};
  icam.length = vector_read("icam_cards/01_Golden_PIV/7_CCC.bin", icam.bytes, sizeof icam.bytes);
  munit_assert_int(TC_PIV_CCC_read(span(&icam), TC_PIV_CONTENTS, &parsed), ==, TC_TLV_OK);
  munit_assert_size(parsed.card_identifier.length, ==, 21);
  munit_assert_ptr_equal(parsed.card_identifier.data, icam.bytes + 2);
  munit_assert_int(parsed.container_version, ==, 0x21);
  munit_assert_int(parsed.grammar_version, ==, 0x21);
  munit_assert_int(parsed.pkcs15, ==, 0x11);
  munit_assert_size(parsed.access_control_rules.length, ==, 17);
  munit_assert_uint8(parsed.data_model, ==, 0x10);
  /* The encodings are distinct. */
  munit_assert_int(TC_PIV_CCC_read(span(&icam), TC_PIV_CONTAINER, &parsed), ==, TC_TLV_INVALID);
  munit_assert_int(
      TC_PIV_CCC_read((TC_bytes){card2_ccc, sizeof card2_ccc}, TC_PIV_CONTENTS, &parsed), ==,
      TC_TLV_INVALID);
  return MUNIT_OK;
}

TC_TEST(ccc_optional_elements)
{
  /* SP 800-73-4 Part 1 Table 8: optional E3 and B4 before FE. */
  uint8_t filler[49];
  memset(filler, 0x20, sizeof filler);
  TC_PIV_CCC parsed;
  for (unsigned variant = 0; variant < 5; ++variant) {
    object value = {{0}, 0};
    append(&value, card2_ccc + 2, sizeof card2_ccc - 4);
    if (variant == 0 || variant == 1)
      append_tlv(&value, 0xe3, filler, 48);
    if (variant == 0 || variant == 2)
      append_tlv(&value, 0xb4, filler, 48);
    if (variant == 3) {
      append_tlv(&value, 0xb4, filler, 1);
      append_tlv(&value, 0xe3, filler, 1);
    }
    if (variant == 4)
      append_tlv(&value, 0xe3, filler, 49);
    append_tlv(&value, 0xfe, NULL, 0);
    munit_assert_int(TC_PIV_CCC_read(span(&value), TC_PIV_CONTENTS, &parsed), ==,
                     variant < 3 ? TC_TLV_OK : TC_TLV_INVALID);
  }
  return MUNIT_OK;
}

/* Replace the value of the element at offset in the card 2 contents. */
static object ccc_with(uint8_t tag, size_t length)
{
  const object base = ccc_contents();
  object value = {{0}, 0};
  uint8_t filler[130];
  memset(filler, 0x31, sizeof filler);
  munit_assert_size(length, <=, sizeof filler);
  for (size_t offset = 0; offset < base.length; offset += 2 + base.bytes[offset + 1]) {
    if (base.bytes[offset] == tag)
      append_tlv(&value, tag, filler, length);
    else
      append(&value, base.bytes + offset, 2u + base.bytes[offset + 1]);
  }
  return value;
}

TC_TEST(ccc_lengths)
{
  /* Table 9 lengths: F0 0 or 21, F1 F2 F4 0 or 1, F3 up to 128, F5 1, F6 0 or
   * 17 and the rest empty. */
  static const struct {
    uint8_t tag;
    size_t length;
    TC_TLV_result result;
  } cases[] = {{0xf0, 21, TC_TLV_OK},      {0xf0, 20, TC_TLV_INVALID},  {0xf0, 22, TC_TLV_INVALID},
               {0xf1, 1, TC_TLV_OK},       {0xf1, 2, TC_TLV_INVALID},   {0xf2, 2, TC_TLV_INVALID},
               {0xf3, 128, TC_TLV_OK},     {0xf3, 129, TC_TLV_INVALID}, {0xf4, 2, TC_TLV_INVALID},
               {0xf5, 0, TC_TLV_INVALID},  {0xf5, 2, TC_TLV_INVALID},   {0xf6, 17, TC_TLV_OK},
               {0xf6, 16, TC_TLV_INVALID}, {0xf7, 1, TC_TLV_INVALID},   {0xfa, 1, TC_TLV_INVALID},
               {0xfd, 1, TC_TLV_INVALID},  {0xfe, 1, TC_TLV_INVALID}};
  TC_PIV_CCC parsed;
  for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
    object value = ccc_with(cases[i].tag, cases[i].length);
    munit_assert_int(TC_PIV_CCC_read(span(&value), TC_PIV_CONTENTS, &parsed), ==, cases[i].result);
  }
  object value = ccc_with(0xf3, 128);
  munit_assert_int(TC_PIV_CCC_read(span(&value), TC_PIV_CONTENTS, &parsed), ==, TC_TLV_OK);
  munit_assert_size(parsed.card_url.length, ==, 128);
  object container = wrap(0x53, &value);
  munit_assert_int(TC_PIV_CCC_read(span(&container), TC_PIV_CONTAINER, &parsed), ==, TC_TLV_OK);
  return MUNIT_OK;
}

TC_TEST(ccc_structure)
{
  TC_PIV_CCC parsed;
  memset(&parsed, 0xa5, sizeof parsed);
  TC_PIV_CCC before = parsed;
  const object base = ccc_contents();
  /* Drop each element in turn. */
  for (size_t skip = 0; skip < base.length; skip += 2 + base.bytes[skip + 1]) {
    object value = {{0}, 0};
    for (size_t offset = 0; offset < base.length; offset += 2 + base.bytes[offset + 1])
      if (offset != skip)
        append(&value, base.bytes + offset, 2u + base.bytes[offset + 1]);
    munit_assert_int(TC_PIV_CCC_read(span(&value), TC_PIV_CONTENTS, &parsed), ==, TC_TLV_INVALID);
  }
  /* Swap F1 and F2, repeat F7, add a trailing element. */
  object value = base;
  value.bytes[2] = 0xf2;
  value.bytes[4] = 0xf1;
  munit_assert_int(TC_PIV_CCC_read(span(&value), TC_PIV_CONTENTS, &parsed), ==, TC_TLV_INVALID);
  value = (object){{0}, 0};
  append(&value, base.bytes, 17);
  append(&value, base.bytes + 15, base.length - 15);
  munit_assert_int(TC_PIV_CCC_read(span(&value), TC_PIV_CONTENTS, &parsed), ==, TC_TLV_INVALID);
  value = base;
  append_tlv(&value, 0xf0, NULL, 0);
  munit_assert_int(TC_PIV_CCC_read(span(&value), TC_PIV_CONTENTS, &parsed), ==, TC_TLV_INVALID);
  /* A truncated container is MORE. Trailing bytes after it are INVALID. */
  munit_assert_int(
      TC_PIV_CCC_read((TC_bytes){card2_ccc, sizeof card2_ccc - 1}, TC_PIV_CONTAINER, &parsed), ==,
      TC_TLV_MORE);
  object container = {{0}, 0};
  append(&container, card2_ccc, sizeof card2_ccc);
  append_byte(&container, 0x00);
  munit_assert_int(TC_PIV_CCC_read(span(&container), TC_PIV_CONTAINER, &parsed), ==,
                   TC_TLV_INVALID);
  /* Truncated contents are INVALID. */
  munit_assert_int(
      TC_PIV_CCC_read((TC_bytes){base.bytes, base.length - 1}, TC_PIV_CONTENTS, &parsed), ==,
      TC_TLV_INVALID);
  ccc_same(&parsed, &before);
  /* Arguments. */
  munit_assert_int(TC_PIV_CCC_read(span(&base), TC_PIV_CONTENTS, NULL), ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_CCC_read((TC_bytes){NULL, 1}, TC_PIV_CONTENTS, &parsed), ==,
                   TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_CCC_read(span(&base), (TC_PIV_container_encoding)2, &parsed), ==,
                   TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_CCC_read(span(&value), TC_PIV_CONTENTS, (TC_PIV_CCC*)(void*)value.bytes),
                   ==, TC_TLV_ARGUMENT);
  ccc_same(&parsed, &before);
  return MUNIT_OK;
}

/* Key History */

static object key_history(uint8_t on_card, uint8_t off_card, const char* url)
{
  object contents = {{0}, 0};
  append_tlv(&contents, 0xc1, &on_card, 1);
  append_tlv(&contents, 0xc2, &off_card, 1);
  if (url)
    append_tlv(&contents, 0xf3, url, strlen(url));
  append_tlv(&contents, 0xfe, NULL, 0);
  return contents;
}

/* "http://" host "/" and 64 hexadecimal digits. */
static void url_make(char* out, size_t capacity, const char* host, char digit)
{
  char hash[65];
  memset(hash, digit, 64);
  hash[64] = 0;
  const int written = snprintf(out, capacity, "http://%s/%s", host, hash);
  munit_assert_int(written, >, 0);
  munit_assert_size((size_t)written, <, capacity);
}

TC_TEST(key_history_recorded)
{
  static const uint8_t card2[] = {0x53, 0x08, 0xc1, 0x01, 0x01, 0xc2, 0x01, 0x00, 0xfe, 0x00};
  TC_PIV_key_history parsed;
  memset(&parsed, 0xa5, sizeof parsed);
  munit_assert_int(
      TC_PIV_key_history_read((TC_bytes){card2, sizeof card2}, TC_PIV_CONTAINER, &parsed), ==,
      TC_TLV_OK);
  munit_assert_uint8(parsed.on_card, ==, 1);
  munit_assert_uint8(parsed.off_card, ==, 0);
  munit_assert_null(parsed.url.data);
  munit_assert_size(parsed.url.length, ==, 0);

  object card3 = {{0}, 0};
  card3.length = vector_read("sd33/card03/key_history_5FC10C.bin", card3.bytes, sizeof card3.bytes);
  munit_assert_int(TC_PIV_key_history_read(span(&card3), TC_PIV_CONTAINER, &parsed), ==, TC_TLV_OK);
  munit_assert_uint8(parsed.on_card, ==, 7);
  munit_assert_uint8(parsed.off_card, ==, 2);
  munit_assert_size(parsed.url.length, ==, 87);
  munit_assert_memory_equal(24, parsed.url.data, "http://smime2.nist.gov/8");
  munit_assert_int(TC_PIV_key_history_read(span(&card3), TC_PIV_CONTENTS, &parsed), ==,
                   TC_TLV_INVALID);
  return MUNIT_OK;
}

TC_TEST(key_history_rules)
{
  char url[160];
  url_make(url, sizeof url, "example.gov", 'A');
  static const struct {
    uint8_t on_card, off_card;
    int url;
    TC_TLV_result result;
  } cases[] = {{0, 0, 0, TC_TLV_OK},       {0, 0, 1, TC_TLV_INVALID},  {1, 0, 0, TC_TLV_OK},
               {1, 0, 1, TC_TLV_OK},       {0, 1, 0, TC_TLV_INVALID},  {0, 1, 1, TC_TLV_OK},
               {20, 0, 1, TC_TLV_OK},      {10, 10, 1, TC_TLV_OK},     {10, 11, 1, TC_TLV_INVALID},
               {21, 0, 0, TC_TLV_INVALID}, {0, 255, 1, TC_TLV_INVALID}};
  TC_PIV_key_history parsed;
  for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
    object value = key_history(cases[i].on_card, cases[i].off_card, cases[i].url ? url : NULL);
    munit_assert_int(TC_PIV_key_history_read(span(&value), TC_PIV_CONTENTS, &parsed), ==,
                     cases[i].result);
  }
  /* A two-byte count, a nonempty FE, a missing FE, trailing bytes. */
  object value = {{0}, 0};
  append_tlv(&value, 0xc1, "\x00\x01", 2);
  append_tlv(&value, 0xc2, "\x00", 1);
  append_tlv(&value, 0xfe, NULL, 0);
  munit_assert_int(TC_PIV_key_history_read(span(&value), TC_PIV_CONTENTS, &parsed), ==,
                   TC_TLV_INVALID);
  value = key_history(1, 0, NULL);
  value.bytes[value.length - 1] = 0x01;
  append_byte(&value, 0x00);
  munit_assert_int(TC_PIV_key_history_read(span(&value), TC_PIV_CONTENTS, &parsed), ==,
                   TC_TLV_INVALID);
  value = key_history(1, 0, NULL);
  value.length -= 2;
  munit_assert_int(TC_PIV_key_history_read(span(&value), TC_PIV_CONTENTS, &parsed), ==,
                   TC_TLV_INVALID);
  value = key_history(1, 0, NULL);
  append_tlv(&value, 0xfe, NULL, 0);
  munit_assert_int(TC_PIV_key_history_read(span(&value), TC_PIV_CONTENTS, &parsed), ==,
                   TC_TLV_INVALID);
  return MUNIT_OK;
}

TC_TEST(key_history_url)
{
  char url[200];
  TC_PIV_key_history parsed;
  /* 46 host bytes give the 118-byte maximum. One more is too long. */
  static const char host46[] = "a23456789.b23456789.c23456789.d23456789.e2345.";
  char host[64];
  memcpy(host, host46, 45);
  host[45] = 'f';
  host[46] = 0;
  url_make(url, sizeof url, host, 'f');
  munit_assert_size(strlen(url), ==, TC_PIV_KEY_HISTORY_URL_MAX_BYTES);
  object value = key_history(0, 1, url);
  munit_assert_int(TC_PIV_key_history_read(span(&value), TC_PIV_CONTENTS, &parsed), ==, TC_TLV_OK);
  munit_assert_size(parsed.url.length, ==, 118);
  host[46] = 'g';
  host[47] = 0;
  url_make(url, sizeof url, host, 'f');
  value = key_history(0, 1, url);
  munit_assert_int(TC_PIV_key_history_read(span(&value), TC_PIV_CONTENTS, &parsed), ==,
                   TC_TLV_INVALID);
  static const char* const hosts[] = {"",       ".gov",    "a..gov", "a.gov.", "-a.gov",
                                      "a-.gov", "a_b.gov", "a b",    "a/b"};
  for (size_t i = 0; i < sizeof hosts / sizeof *hosts; ++i) {
    url_make(url, sizeof url, hosts[i], '0');
    value = key_history(0, 1, url);
    munit_assert_int(TC_PIV_key_history_read(span(&value), TC_PIV_CONTENTS, &parsed), ==,
                     TC_TLV_INVALID);
  }
  url_make(url, sizeof url, "a-b.9.gov", '9');
  value = key_history(0, 1, url);
  munit_assert_int(TC_PIV_key_history_read(span(&value), TC_PIV_CONTENTS, &parsed), ==, TC_TLV_OK);
  /* The scheme, the hash length and the hash digits. */
  url_make(url, sizeof url, "example.gov", 'a');
  static const struct {
    size_t offset;
    char value;
  } edits[] = {{0, 'H'}, {4, 's'}, {6, 'x'}, {30, 'g'}, {82, ' '}};
  for (size_t i = 0; i < sizeof edits / sizeof *edits; ++i) {
    char edited[200];
    memcpy(edited, url, sizeof edited);
    edited[edits[i].offset] = edits[i].value;
    value = key_history(0, 1, edited);
    munit_assert_int(TC_PIV_key_history_read(span(&value), TC_PIV_CONTENTS, &parsed), ==,
                     TC_TLV_INVALID);
  }
  char shorter[200];
  memcpy(shorter, url, sizeof shorter);
  shorter[strlen(shorter) - 1] = 0;
  value = key_history(0, 1, shorter);
  munit_assert_int(TC_PIV_key_history_read(span(&value), TC_PIV_CONTENTS, &parsed), ==,
                   TC_TLV_INVALID);
  strcat(url, "a");
  value = key_history(0, 1, url);
  munit_assert_int(TC_PIV_key_history_read(span(&value), TC_PIV_CONTENTS, &parsed), ==,
                   TC_TLV_INVALID);
  return MUNIT_OK;
}

TC_TEST(key_history_arguments)
{
  object value = key_history(1, 0, NULL);
  TC_PIV_key_history parsed;
  memset(&parsed, 0xa5, sizeof parsed);
  TC_PIV_key_history before = parsed;
  munit_assert_int(TC_PIV_key_history_read(span(&value), TC_PIV_CONTENTS, NULL), ==,
                   TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_key_history_read((TC_bytes){NULL, 3}, TC_PIV_CONTENTS, &parsed), ==,
                   TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_key_history_read(span(&value), (TC_PIV_container_encoding)2, &parsed), ==,
                   TC_TLV_ARGUMENT);
  object container = wrap(0x53, &value);
  munit_assert_int(TC_PIV_key_history_read((TC_bytes){container.bytes, container.length - 1},
                                           TC_PIV_CONTAINER, &parsed),
                   ==, TC_TLV_MORE);
  key_history_same(&parsed, &before);
  return MUNIT_OK;
}

/* BIT group template */

static object bit_group(unsigned count, unsigned templates, size_t length)
{
  uint8_t bit[40];
  memset(bit, 0x83, sizeof bit);
  munit_assert_size(length, <=, sizeof bit);
  object contents = {{0}, 0};
  const uint8_t number = (uint8_t)count;
  append_tlv(&contents, 0x02, &number, 1);
  for (unsigned i = 0; i < templates; ++i)
    append_tlv(&contents, 0x7f60, bit, length);
  return wrap(0x7f61, &contents);
}

TC_TEST(bit_group_forms)
{
  static const uint8_t empty[] = {0x7f, 0x61, 0x03, 0x02, 0x01, 0x00};
  TC_PIV_bit_group parsed;
  memset(&parsed, 0xa5, sizeof parsed);
  munit_assert_int(TC_PIV_bit_group_read((TC_bytes){empty, sizeof empty}, &parsed), ==, TC_TLV_OK);
  munit_assert_uint(parsed.fingers, ==, 0);
  munit_assert_null(parsed.templates[0].data);
  munit_assert_null(parsed.templates[1].data);
  for (unsigned fingers = 1; fingers <= 2; ++fingers) {
    object value = bit_group(fingers, fingers, TC_PIV_BIT_MAX_BYTES);
    munit_assert_int(TC_PIV_bit_group_read(span(&value), &parsed), ==, TC_TLV_OK);
    munit_assert_uint(parsed.fingers, ==, fingers);
    munit_assert_ptr_equal(parsed.templates[0].data, value.bytes + 3 + 3 + 3);
    munit_assert_size(parsed.templates[0].length, ==, TC_PIV_BIT_MAX_BYTES);
    if (fingers == 1)
      munit_assert_null(parsed.templates[1].data);
    else
      munit_assert_size(parsed.templates[1].length, ==, TC_PIV_BIT_MAX_BYTES);
  }
  memset(&parsed, 0xa5, sizeof parsed);
  TC_PIV_bit_group before = parsed;
  static const struct {
    unsigned count, templates;
    size_t length;
  } wrong[] = {{3, 3, 4}, {1, 0, 4}, {1, 2, 4}, {2, 1, 4}, {0, 1, 4}, {1, 1, 29}, {1, 1, 0}};
  for (size_t i = 0; i < sizeof wrong / sizeof *wrong; ++i) {
    object value = bit_group(wrong[i].count, wrong[i].templates, wrong[i].length);
    munit_assert_int(TC_PIV_bit_group_read(span(&value), &parsed), ==, TC_TLV_INVALID);
  }
  /* A two-byte count, another element, another outer tag, trailing bytes. */
  object contents = {{0}, 0};
  append_tlv(&contents, 0x02, "\x00\x01", 2);
  object value = wrap(0x7f61, &contents);
  munit_assert_int(TC_PIV_bit_group_read(span(&value), &parsed), ==, TC_TLV_INVALID);
  contents = (object){{0}, 0};
  append_tlv(&contents, 0x02, "\x01", 1);
  append_tlv(&contents, 0x7f2e, "\x01", 1);
  value = wrap(0x7f61, &contents);
  munit_assert_int(TC_PIV_bit_group_read(span(&value), &parsed), ==, TC_TLV_INVALID);
  contents = (object){{0}, 0};
  append_tlv(&contents, 0x02, "\x00", 1);
  value = wrap(0x53, &contents);
  munit_assert_int(TC_PIV_bit_group_read(span(&value), &parsed), ==, TC_TLV_INVALID);
  value = (object){{0}, 0};
  append(&value, empty, sizeof empty);
  append_byte(&value, 0x00);
  munit_assert_int(TC_PIV_bit_group_read(span(&value), &parsed), ==, TC_TLV_INVALID);
  munit_assert_int(TC_PIV_bit_group_read((TC_bytes){empty, sizeof empty - 1}, &parsed), ==,
                   TC_TLV_MORE);
  munit_assert_int(TC_PIV_bit_group_read((TC_bytes){empty, sizeof empty}, NULL), ==,
                   TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_bit_group_read((TC_bytes){NULL, 1}, &parsed), ==, TC_TLV_ARGUMENT);
  bit_group_same(&parsed, &before);
  return MUNIT_OK;
}

/* Pairing Code container. The code is synthetic test material. */

static const uint8_t pairing[] = {0x53, 0x0c, 0x99, 0x08, 0x31, 0x34, 0x31,
                                  0x35, 0x39, 0x32, 0x36, 0x35, 0xfe, 0x00};

TC_TEST(pairing_code)
{
  TC_bytes code = {NULL, 0};
  munit_assert_int(
      TC_PIV_pairing_code_read((TC_bytes){pairing, sizeof pairing}, TC_PIV_CONTAINER, &code), ==,
      TC_TLV_OK);
  munit_assert_ptr_equal(code.data, pairing + 4);
  munit_assert_size(code.length, ==, TC_PIV_PAIRING_CODE_BYTES);
  munit_assert_int(
      TC_PIV_pairing_code_read((TC_bytes){pairing + 2, sizeof pairing - 2}, TC_PIV_CONTENTS, &code),
      ==, TC_TLV_OK);
  munit_assert_ptr_equal(code.data, pairing + 4);

  const TC_bytes before = code;
  object value = {{0}, 0};
  append(&value, pairing + 2, sizeof pairing - 2);
  static const size_t digits[] = {2, 5, 9};
  static const uint8_t replacements[] = {0x2f, 0x3a, 0x41};
  for (size_t i = 0; i < sizeof digits / sizeof *digits; ++i)
    for (size_t j = 0; j < sizeof replacements; ++j) {
      object edited = value;
      edited.bytes[digits[i]] = replacements[j];
      munit_assert_int(TC_PIV_pairing_code_read(span(&edited), TC_PIV_CONTENTS, &code), ==,
                       TC_TLV_INVALID);
    }
  static const uint8_t* const wrong[] = {
      (const uint8_t*)"\x99\x07\x31\x32\x33\x34\x35\x36\x37\xfe\x00",
      (const uint8_t*)"\x99\x09\x31\x32\x33\x34\x35\x36\x37\x38\x39\xfe\x00",
      (const uint8_t*)"\x99\x08\x31\x32\x33\x34\x35\x36\x37\x38\xfe\x01\x00",
      (const uint8_t*)"\x99\x08\x31\x32\x33\x34\x35\x36\x37\x38",
      (const uint8_t*)"\x98\x08\x31\x32\x33\x34\x35\x36\x37\x38\xfe\x00",
      (const uint8_t*)"\x99\x08\x31\x32\x33\x34\x35\x36\x37\x38\xfe\x00\xfe\x00"};
  static const size_t lengths[] = {11, 13, 13, 10, 12, 14};
  for (size_t i = 0; i < sizeof lengths / sizeof *lengths; ++i)
    munit_assert_int(
        TC_PIV_pairing_code_read((TC_bytes){wrong[i], lengths[i]}, TC_PIV_CONTENTS, &code), ==,
        TC_TLV_INVALID);
  munit_assert_int(
      TC_PIV_pairing_code_read((TC_bytes){pairing, sizeof pairing - 1}, TC_PIV_CONTAINER, &code),
      ==, TC_TLV_MORE);
  munit_assert_int(
      TC_PIV_pairing_code_read((TC_bytes){pairing, sizeof pairing}, TC_PIV_CONTENTS, &code), ==,
      TC_TLV_INVALID);
  munit_assert_int(
      TC_PIV_pairing_code_read((TC_bytes){pairing, sizeof pairing}, TC_PIV_CONTAINER, NULL), ==,
      TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_pairing_code_read((TC_bytes){NULL, 2}, TC_PIV_CONTAINER, &code), ==,
                   TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_pairing_code_read((TC_bytes){pairing, sizeof pairing},
                                            (TC_PIV_container_encoding)2, &code),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_ptr_equal(code.data, before.data);
  munit_assert_size(code.length, ==, before.length);
  return MUNIT_OK;
}

/* Framing beyond ISO/IEC 7816-4 BER-TLV: a four-byte tag and a length with
 * five length octets. Each reader reports INVALID, since no caller limit
 * applies. */
TC_TEST(framing_bounds)
{
  static const uint8_t long_length[] = {0xf0, 0x85, 0x00, 0x00, 0x00, 0x01, 0x00};
  static const uint8_t long_tag[] = {0x1f, 0x81, 0x81, 0x01, 0x00};
  static const uint8_t long_container[] = {0x53, 0x85, 0x00, 0x00, 0x00, 0x01, 0x00};
  static const uint8_t long_group[] = {0x7f, 0x61, 0x85, 0x00, 0x00, 0x00, 0x01, 0x00};
  static const uint8_t long_discovery[] = {0x7e, 0x85, 0x00, 0x00, 0x00, 0x01, 0x00};
  const TC_bytes contents[] = {{long_length, sizeof long_length}, {long_tag, sizeof long_tag}};
  const TC_bytes container = {long_container, sizeof long_container};
  TC_PIV_CCC ccc;
  TC_PIV_key_history history;
  TC_bytes code;
  TC_PIV_bit_group group;
  TC_PIV_discovery discovery;
  for (size_t i = 0; i < sizeof contents / sizeof *contents; ++i) {
    munit_assert_int(TC_PIV_CCC_read(contents[i], TC_PIV_CONTENTS, &ccc), ==, TC_TLV_INVALID);
    munit_assert_int(TC_PIV_key_history_read(contents[i], TC_PIV_CONTENTS, &history), ==,
                     TC_TLV_INVALID);
    munit_assert_int(TC_PIV_pairing_code_read(contents[i], TC_PIV_CONTENTS, &code), ==,
                     TC_TLV_INVALID);
  }
  munit_assert_int(TC_PIV_CCC_read(container, TC_PIV_CONTAINER, &ccc), ==, TC_TLV_INVALID);
  munit_assert_int(TC_PIV_key_history_read(container, TC_PIV_CONTAINER, &history), ==,
                   TC_TLV_INVALID);
  munit_assert_int(TC_PIV_pairing_code_read(container, TC_PIV_CONTAINER, &code), ==,
                   TC_TLV_INVALID);
  munit_assert_int(TC_PIV_bit_group_read((TC_bytes){long_group, sizeof long_group}, &group), ==,
                   TC_TLV_INVALID);
  munit_assert_int(TC_PIV_discovery_read((TC_bytes){long_discovery, sizeof long_discovery},
                                         TC_PIV_DISCOVERY_PIV, &discovery),
                   ==, TC_TLV_INVALID);
  /* Inside a BIT group, a nested element with a five-octet length. */
  static const uint8_t nested[] = {0x7f, 0x61, 0x0b, 0x02, 0x01, 0x01, 0x7f,
                                   0x60, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00};
  munit_assert_int(TC_PIV_bit_group_read((TC_bytes){nested, sizeof nested}, &group), ==,
                   TC_TLV_INVALID);
  return MUNIT_OK;
}

/* Certificate decode */

static TC_GZIP_workspace gzip_workspace;

TC_TEST(certificate_decode_gzip)
{
  object smcs = {{0}, 0};
  smcs.length =
      vector_read("vci_trust_anchors/card-2-direct/smcs-5fc122.bin", smcs.bytes, sizeof smcs.bytes);
  object expected = {{0}, 0};
  expected.length = vector_read("vci_trust_anchors/card-2-direct/content-signing-certificate.der",
                                expected.bytes, sizeof expected.bytes);
  uint8_t der[CERTIFICATE_BYTES];
  size_t work = 1000000;
  TC_PIV_certificate parsed;
  memset(&parsed, 0xa5, sizeof parsed);
  munit_assert_int(TC_PIV_certificate_decode(span(&smcs), TC_PIV_CERTIFICATE_SM_SIGNER,
                                             TC_PIV_CERTIFICATE_RECOMMENDED_BYTES, &gzip_workspace,
                                             &work, (TC_buffer){der, sizeof der}, &parsed),
                   ==, TC_TLV_OK);
  munit_assert_int(parsed.compression, ==, TC_PIV_CERTIFICATE_GZIP);
  munit_assert_ptr_equal(parsed.certificate.data, der);
  munit_assert_size(parsed.certificate.length, ==, expected.length);
  munit_assert_memory_equal(expected.length, der, expected.bytes);
  munit_assert_null(parsed.intermediate_cvc.data);
  munit_assert_size(work, <, 1000000);

  /* Output too small, work too small and a damaged checksum wipe der. */
  memset(&parsed, 0xa5, sizeof parsed);
  const TC_PIV_certificate before = parsed;
  memset(der, 0x5a, sizeof der);
  work = 1000000;
  munit_assert_int(TC_PIV_certificate_decode(span(&smcs), TC_PIV_CERTIFICATE_SM_SIGNER,
                                             TC_PIV_CERTIFICATE_RECOMMENDED_BYTES, &gzip_workspace,
                                             &work, (TC_buffer){der, expected.length - 1}, &parsed),
                   ==, TC_TLV_LIMIT);
  munit_assert_true(tc_test_all_zero(der, expected.length - 1));
  munit_assert_uint8(der[expected.length - 1], ==, 0x5a);
  work = 100;
  munit_assert_int(TC_PIV_certificate_decode(span(&smcs), TC_PIV_CERTIFICATE_SM_SIGNER,
                                             TC_PIV_CERTIFICATE_RECOMMENDED_BYTES, &gzip_workspace,
                                             &work, (TC_buffer){der, sizeof der}, &parsed),
                   ==, TC_TLV_LIMIT);
  object damaged = smcs;
  /* The CRC32 sits eight bytes before the end of the 70 value. */
  damaged.bytes[damaged.length - 5 - 8] ^= 0x01;
  memset(der, 0x5a, sizeof der);
  work = 1000000;
  munit_assert_int(TC_PIV_certificate_decode(span(&damaged), TC_PIV_CERTIFICATE_SM_SIGNER,
                                             TC_PIV_CERTIFICATE_RECOMMENDED_BYTES, &gzip_workspace,
                                             &work, (TC_buffer){der, sizeof der}, &parsed),
                   ==, TC_TLV_INVALID);
  munit_assert_true(tc_test_all_zero(der, sizeof der));
  /* A container failure wipes der as well. */
  memset(der, 0x5a, sizeof der);
  munit_assert_int(TC_PIV_certificate_decode((TC_bytes){smcs.bytes, smcs.length - 1},
                                             TC_PIV_CERTIFICATE_SM_SIGNER,
                                             TC_PIV_CERTIFICATE_RECOMMENDED_BYTES, &gzip_workspace,
                                             &work, (TC_buffer){der, sizeof der}, &parsed),
                   ==, TC_TLV_INVALID);
  munit_assert_true(tc_test_all_zero(der, sizeof der));
  certificate_same(&parsed, &before);
  return MUNIT_OK;
}

/* A container with one 70 value and CertInfo. */
static object certificate_container(const uint8_t* value, size_t length, uint8_t compression)
{
  object contents = {{0}, 0};
  append_tlv(&contents, 0x70, value, length);
  append_tlv(&contents, 0x71, &compression, 1);
  append_tlv(&contents, 0xfe, NULL, 0);
  return wrap(0x53, &contents);
}

TC_TEST(certificate_decode_forms)
{
  static const uint8_t sequence[] = {0x30, 0x03, 0x02, 0x01, 0x05};
  /* gzip of 30 03 02 01 05, of 04 03 02 01 05 and of 30 03 02 01 05 00. */
  static const uint8_t gzip_sequence[] = {0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                                          0xff, 0x33, 0x60, 0x66, 0x62, 0x64, 0x05, 0x00, 0xd5,
                                          0xf1, 0x43, 0x1f, 0x05, 0x00, 0x00, 0x00};
  static const uint8_t gzip_octets[] = {0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                                        0xff, 0x63, 0x61, 0x66, 0x62, 0x64, 0x05, 0x00, 0x93,
                                        0xef, 0xe2, 0x4b, 0x05, 0x00, 0x00, 0x00};
  static const uint8_t gzip_trailing[] = {0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                                          0xff, 0x33, 0x60, 0x66, 0x62, 0x64, 0x65, 0x00, 0x00,
                                          0x27, 0x8a, 0xa4, 0x24, 0x06, 0x00, 0x00, 0x00};
  uint8_t der[64];
  size_t work = 100000;
  TC_PIV_certificate parsed;

  /* PLAIN borrows the container and leaves der unused. */
  object plain = certificate_container(sequence, sizeof sequence, 0);
  memset(der, 0x5a, sizeof der);
  munit_assert_int(TC_PIV_certificate_decode(span(&plain), TC_PIV_CERTIFICATE_SLOT, 1856,
                                             &gzip_workspace, &work, (TC_buffer){der, sizeof der},
                                             &parsed),
                   ==, TC_TLV_OK);
  munit_assert_int(parsed.compression, ==, TC_PIV_CERTIFICATE_PLAIN);
  munit_assert_ptr_equal(parsed.certificate.data, plain.bytes + 4);
  munit_assert_size(parsed.certificate.length, ==, sizeof sequence);
  munit_assert_true(tc_test_all_value(der, sizeof der, 0x5a));
  munit_assert_size(work, ==, 100000);
  munit_assert_int(TC_PIV_certificate_decode(span(&plain), TC_PIV_CERTIFICATE_SLOT, 1856,
                                             &gzip_workspace, &work, (TC_buffer){NULL, 0}, &parsed),
                   ==, TC_TLV_OK);

  object compressed = certificate_container(gzip_sequence, sizeof gzip_sequence, 1);
  munit_assert_int(TC_PIV_certificate_decode(span(&compressed), TC_PIV_CERTIFICATE_SLOT, 1856,
                                             &gzip_workspace, &work, (TC_buffer){der, sizeof der},
                                             &parsed),
                   ==, TC_TLV_OK);
  munit_assert_ptr_equal(parsed.certificate.data, der);
  munit_assert_memory_equal(sizeof sequence, der, sequence);

  /* The certificate must be one complete DER SEQUENCE. */
  static const uint8_t octets[] = {0x04, 0x03, 0x02, 0x01, 0x05};
  static const uint8_t trailing[] = {0x30, 0x03, 0x02, 0x01, 0x05, 0x00};
  const object wrong[] = {certificate_container(octets, sizeof octets, 0),
                          certificate_container(trailing, sizeof trailing, 0),
                          certificate_container(gzip_octets, sizeof gzip_octets, 1),
                          certificate_container(gzip_trailing, sizeof gzip_trailing, 1)};
  for (size_t i = 0; i < sizeof wrong / sizeof *wrong; ++i) {
    memset(der, 0x5a, sizeof der);
    munit_assert_int(TC_PIV_certificate_decode(span(&wrong[i]), TC_PIV_CERTIFICATE_SLOT, 1856,
                                               &gzip_workspace, &work, (TC_buffer){der, sizeof der},
                                               &parsed),
                     ==, TC_TLV_INVALID);
    munit_assert_true(tc_test_all_zero(der, sizeof der));
  }
  /* A compression method other than deflate (RFC 1952 section 2.3.1). */
  uint8_t method[sizeof gzip_sequence];
  memcpy(method, gzip_sequence, sizeof method);
  method[2] = 0x07;
  const object other_method = certificate_container(method, sizeof method, 1);
  memset(der, 0x5a, sizeof der);
  munit_assert_int(TC_PIV_certificate_decode(span(&other_method), TC_PIV_CERTIFICATE_SLOT, 1856,
                                             &gzip_workspace, &work, (TC_buffer){der, sizeof der},
                                             &parsed),
                   ==, TC_TLV_UNSUPPORTED);
  munit_assert_true(tc_test_all_zero(der, sizeof der));
  /* The encoded bound applies before decompression. */
  munit_assert_int(TC_PIV_certificate_decode(span(&compressed), TC_PIV_CERTIFICATE_SLOT,
                                             sizeof gzip_sequence - 1, &gzip_workspace, &work,
                                             (TC_buffer){der, sizeof der}, &parsed),
                   ==, TC_TLV_LIMIT);
  return MUNIT_OK;
}

TC_TEST(certificate_decode_arguments)
{
  static const uint8_t sequence[] = {0x30, 0x03, 0x02, 0x01, 0x05};
  object plain = certificate_container(sequence, sizeof sequence, 0);
  uint8_t der[64];
  memset(der, 0x5a, sizeof der);
  size_t work = 100;
  TC_PIV_certificate parsed;
  memset(&parsed, 0xa5, sizeof parsed);
  const TC_PIV_certificate before = parsed;
  const TC_buffer output = {der, sizeof der};
  const TC_bytes input = span(&plain);
  munit_assert_int(
      TC_PIV_certificate_decode(input, TC_PIV_CERTIFICATE_SLOT, 1856, NULL, &work, output, &parsed),
      ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_certificate_decode(input, TC_PIV_CERTIFICATE_SLOT, 1856, &gzip_workspace,
                                             NULL, output, &parsed),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_certificate_decode(input, TC_PIV_CERTIFICATE_SLOT, 1856, &gzip_workspace,
                                             &work, output, NULL),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_certificate_decode((TC_bytes){NULL, 1}, TC_PIV_CERTIFICATE_SLOT, 1856,
                                             &gzip_workspace, &work, output, &parsed),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_certificate_decode(input, TC_PIV_CERTIFICATE_SLOT, 1856, &gzip_workspace,
                                             &work, (TC_buffer){NULL, 4}, &parsed),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_certificate_decode(input, TC_PIV_CERTIFICATE_SLOT, 0, &gzip_workspace,
                                             &work, output, &parsed),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_certificate_decode(input, (TC_PIV_certificate_profile)3, 1856,
                                             &gzip_workspace, &work, output, &parsed),
                   ==, TC_TLV_ARGUMENT);
  /* Overlaps: der with the container, der with out, der with the workspace. */
  munit_assert_int(TC_PIV_certificate_decode(input, TC_PIV_CERTIFICATE_SLOT, 1856, &gzip_workspace,
                                             &work, (TC_buffer){plain.bytes + 2, 8}, &parsed),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_certificate_decode(input, TC_PIV_CERTIFICATE_SLOT, 1856, &gzip_workspace,
                                             &work, (TC_buffer){(uint8_t*)&parsed, sizeof parsed},
                                             &parsed),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_int(TC_PIV_certificate_decode(
                       input, TC_PIV_CERTIFICATE_SLOT, 1856, &gzip_workspace, &work,
                       (TC_buffer){(uint8_t*)&gzip_workspace, sizeof gzip_workspace}, &parsed),
                   ==, TC_TLV_ARGUMENT);
  size_t words[4] = {100, 0, 0, 0};
  munit_assert_int(TC_PIV_certificate_decode(input, TC_PIV_CERTIFICATE_SLOT, 1856, &gzip_workspace,
                                             words, (TC_buffer){(uint8_t*)words, sizeof words},
                                             &parsed),
                   ==, TC_TLV_ARGUMENT);
  munit_assert_size(words[0], ==, 100);
  certificate_same(&parsed, &before);
  munit_assert_true(tc_test_all_value(der, sizeof der, 0x5a));
  munit_assert_size(work, ==, 100);
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/discovery/recorded", discovery_recorded, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/discovery/policy", discovery_policy, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/discovery/twic", discovery_twic, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/discovery/framing", discovery_framing, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/discovery/arguments", discovery_arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/ccc/recorded", ccc_recorded, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/ccc/optional-elements", ccc_optional_elements, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/ccc/lengths", ccc_lengths, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/ccc/structure", ccc_structure, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/key-history/recorded", key_history_recorded, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/key-history/rules", key_history_rules, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/key-history/url", key_history_url, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/key-history/arguments", key_history_arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/bit-group", bit_group_forms, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/pairing-code", pairing_code, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/framing-bounds", framing_bounds, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/certificate-decode/gzip", certificate_decode_gzip, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/certificate-decode/forms", certificate_decode_forms, NULL, NULL, MUNIT_TEST_OPTION_NONE,
     NULL},
    {"/certificate-decode/arguments", certificate_decode_arguments, NULL, NULL,
     MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};

int main(int argc, char** argv)
{
  MunitSuite suite = {"/piv/card-objects", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
