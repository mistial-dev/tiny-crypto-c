/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* PIV and TWIC catalogs (SP 800-73-5 Part 1 Tables 2, 3 and 8, TWIC Part 2
 * v5 4.5) and the inventory over the SD 33 card 2 simulator on both
 * interfaces, plain and under secure messaging, and over scripted TWIC
 * answers. The PIN and pairing code come from the fixture. */
#include <tiny_crypto/piv_catalog.h>
#include <tiny_crypto/piv_cvc.h>
#include <tiny_crypto/piv_sm_apdu.h>
#include <tiny_crypto/piv_vci.h>
#include "card_simulator.h"
#include "munit.h"
#include "scripted_transport.h"
#include "test_util.h"
#include <stdio.h>
#include <string.h>

#define STEP(command, response) {command, response, {0}, {0}, TC_OK, 0}

enum {
  POOL_BYTES = TC_PIV_INVENTORY_POOL_BYTES,
  RESPONSE_BYTES = 1024,
  SM_SCRATCH_BYTES = 1024,
  EXCHANGES = 4096,
  CATALOG = TC_PIV_CATALOG_PIV_OBJECTS
};

static tc_card_fixture fixture;
static tc_card_simulator card;
static tc_script script;
static uint8_t scratch[TC_APDU_SHORT_COMMAND_MAX_BYTES];
static uint8_t sm_scratch[SM_SCRATCH_BYTES];
static uint8_t response_bytes[RESPONSE_BYTES];
static uint8_t pool[POOL_BYTES];
static TC_PIV_object objects[CATALOG];
static TC_PIV_SM session;
static TC_PIV_SM_workspace workspace;
static const tc_card_session* recorded;

static const uint8_t tag_pairing_code[] = {0x5f, 0xc1, 0x23};

static uint32_t tag_value(const TC_PIV_object_info* info)
{
  uint32_t value = 0;
  for (size_t i = 0; i < info->tag_length; ++i)
    value = value << 8 | info->tag[i];
  return value;
}

static void load(void)
{
  char path[512];
  snprintf(path, sizeof path, "%s/sd33_card2.txt", TC_CARD_FIXTURE_DIR);
  munit_assert_long(tc_card_fixture_load(&fixture, path), ==, 0);
}

static TC_buffer response_buffer(void)
{
  return (TC_buffer){response_bytes, sizeof response_bytes};
}

static TC_buffer pool_buffer(void)
{
  memset(pool, 0xee, sizeof pool);
  return (TC_buffer){pool, sizeof pool};
}

static TC_PIV_inventory inventory_start(void)
{
  TC_PIV_inventory inventory;
  memset(&inventory, 0, sizeof inventory);
  memset(objects, 0xa5, sizeof objects);
  inventory.objects = objects;
  inventory.capacity = CATALOG;
  return inventory;
}

static TC_PIV_link_info link_info(const TC_PIV_link* link)
{
  TC_PIV_link_info info;
  TC_PIV_link_info_get(link, &info);
  return info;
}

static void link_open_with(TC_PIV_link* link, const TC_PIV_link_options* options)
{
  TC_PIV_application application;
  tc_card_simulator_init(&card, &fixture, options->interface);
  munit_assert_int(TC_PIV_link_init(link, tc_card_simulator_transport(&card), options,
                                    (TC_buffer){scratch, sizeof scratch}),
                   ==, TC_PIV_OK);
  munit_assert_int(TC_PIV_select(link, TC_PIV_APPLICATION_PIV, 0, response_buffer(), &application),
                   ==, TC_PIV_OK);
}

static void link_open(TC_PIV_link* link, TC_PIV_interface interface, size_t exchanges)
{
  const TC_PIV_link_options options = {{TC_APDU_SHORT, 0, exchanges, 0, 0}, interface, 0};
  link_open_with(link, &options);
}

/* The PIN or pairing code of reference as ASCII digits. */
static TC_bytes secret(uint8_t reference, uint8_t out[8])
{
  const tc_card_reference* data = tc_card_fixture_reference(&fixture, reference);
  munit_assert_not_null(data);
  size_t length = 0;
  while (length < 8 && data->value[length] != 0xff)
    ++length;
  memcpy(out, data->value, length);
  return (TC_bytes){out, length};
}

static void pin_verify(TC_PIV_link* link)
{
  uint8_t pin[8];
  TC_PIV_reference_status status;
  munit_assert_int(TC_PIV_pin_verify(link, 0x80, secret(0x80, pin), 3, &status), ==, TC_PIV_OK);
}

static TC_status recorded_scalar(void* context, uint8_t* output, size_t length)
{
  (void)context;
  munit_assert_size(length, ==, recorded->scalar.length);
  memcpy(output, recorded->scalar.data, length);
  return TC_OK;
}

/* Secure the contactless link with a recorded key establishment, then
 * establish the VCI with the pairing code. */
static void link_secure_vci(TC_PIV_link* link)
{
  TC_PIV_SM_peer peer;
  TC_PIV_CVC cvc;
  TC_PIV_discovery discovery;
  TC_PIV_vci_mode mode;
  uint8_t pairing[8];
  recorded = &fixture.sessions[0];
  memset(&session, 0, sizeof session);
  munit_assert_int(TC_PIV_SM_key_request(link, &session, (TC_PIV_SM_suite)recorded->suite,
                                         recorded->host_id.data,
                                         (TC_random_source){recorded_scalar, NULL},
                                         response_buffer(), &peer, &workspace),
                   ==, TC_PIV_OK);
  munit_assert_int(TC_PIV_CVC_read(peer.certificate, &cvc), ==, TC_TLV_OK);
  munit_assert_int(TC_PIV_SM_finish(&session, &peer, cvc.public_key, &workspace), ==, TC_OK);
  munit_assert_int(TC_PIV_link_secure(link, &workspace, (TC_buffer){sm_scratch, sizeof sm_scratch}),
                   ==, TC_PIV_OK);
  munit_assert_int(TC_PIV_discovery_get(link, TC_PIV_DISCOVERY_PIV, response_buffer(), &discovery),
                   ==, TC_PIV_OK);
  munit_assert_int(TC_PIV_vci_establish(link, &discovery, secret(0x98, pairing), &mode), ==,
                   TC_PIV_OK);
}

/* 1 when rule is met by info, with OCC never available. */
static int rule_met(uint8_t rule, const TC_PIV_link_info* info)
{
  switch (rule) {
  case TC_PIV_ACCESS_ALWAYS:
    return 1;
  case TC_PIV_ACCESS_PIN:
  case TC_PIV_ACCESS_PIN_OR_OCC:
    return info->pin_verified;
  case TC_PIV_ACCESS_VCI:
    return info->vci;
  case TC_PIV_ACCESS_VCI_PIN:
  case TC_PIV_ACCESS_VCI_PIN_OR_OCC:
    return info->vci && info->pin_verified;
  default:
    return 0;
  }
}

/* Every entry follows the catalog, carries the fixture bytes when read and
 * reached the card exactly when its rule allowed it. */
static void assert_inventory(const TC_PIV_inventory* inventory, const TC_PIV_link_info* info,
                             unsigned flags)
{
  munit_assert_size(inventory->count, ==, CATALOG);
  munit_assert_ptr_equal(inventory->pool, pool);
  munit_assert_int(inventory->link.interface, ==, info->interface);
  munit_assert_uint8(inventory->link.secured, ==, info->secured);
  size_t end = 0;
  for (size_t i = 0; i < inventory->count; ++i) {
    const TC_PIV_object* object = &inventory->objects[i];
    const TC_PIV_object_info* entry = TC_PIV_catalog_at(TC_PIV_APPLICATION_PIV, TC_PIV_CARD, i);
    munit_assert_ptr_equal(object->info, entry);
    const uint8_t rule = info->interface == TC_PIV_CONTACT ? entry->contact : entry->contactless;
    const tc_card_object* expected = tc_card_fixture_object(&fixture, tag_value(entry));
    munit_assert_not_null(expected);
    const size_t sent = tc_card_simulator_sent(&card, 0xcb, tag_value(entry));
    if (entry->kind == TC_PIV_KIND_PAIRING_CODE && !(flags & TC_PIV_INVENTORY_PAIRING_CODE)) {
      munit_assert_int(object->state, ==, TC_PIV_OBJECT_SKIPPED);
      munit_assert_size(sent, ==, 0);
      continue;
    }
    if (!rule_met(rule, info)) {
      munit_assert_int(object->state, ==, TC_PIV_OBJECT_RESTRICTED);
      munit_assert_uint16(object->status, ==, 0);
      munit_assert_size(object->encoded.length, ==, 0);
      munit_assert_size(sent, ==, 0);
      continue;
    }
    munit_assert_size(sent, ==, 1);
    const int empty = expected->data.length == 2;
    munit_assert_int(object->state, ==, empty ? TC_PIV_OBJECT_EMPTY : TC_PIV_OBJECT_PRESENT);
    munit_assert_uint16(object->status, ==, 0x9000);
    munit_assert_uint8(object->secured, ==, info->secured);
    munit_assert_size(object->encoded.length, ==, expected->data.length);
    munit_assert_memory_equal(expected->data.length, object->encoded.data, expected->data.data);
    if (empty)
      munit_assert_size(object->value.length, ==, 0);
    else
      munit_assert_size(object->value.length, >, 0);
    munit_assert_ptr(object->encoded.data, >=, pool);
    end = (size_t)(object->encoded.data + object->encoded.length - pool);
    munit_assert_size(end, <=, inventory->pool_used);
  }
  munit_assert_size(end, ==, inventory->pool_used);
  munit_assert_true(tc_test_all_zero(pool + inventory->pool_used, 512));
  munit_assert_size(card.violations, ==, 0);
}

/* Part 1 Table 3 order, Table 2 rules and Table 8 IDs and key references. */
TC_TEST(catalog_piv)
{
  static const uint16_t containers[CATALOG] = {
      0xdb00, 0x3000, 0x0101, 0x6010, 0x9000, 0x6030, 0x0500, 0x0100, 0x0102,
      0x3001, 0x6050, 0x6060, 0x1001, 0x1002, 0x1003, 0x1004, 0x1005, 0x1006,
      0x1007, 0x1008, 0x1009, 0x100a, 0x100b, 0x100c, 0x100d, 0x100e, 0x100f,
      0x1010, 0x1011, 0x1012, 0x1013, 0x1014, 0x1015, 0x1016, 0x1017, 0x1018};
  static const uint8_t mandatory[] = {0, 1, 2, 3, 4, 5, 6};
  size_t pool_bytes = 0;
  munit_assert_size(TC_PIV_catalog_count(TC_PIV_APPLICATION_PIV, TC_PIV_CARD), ==, CATALOG);
  for (size_t i = 0; i < CATALOG; ++i) {
    const TC_PIV_object_info* entry = TC_PIV_catalog_at(TC_PIV_APPLICATION_PIV, TC_PIV_CARD, i);
    munit_assert_not_null(entry);
    munit_assert_uint16(entry->container, ==, containers[i]);
    munit_assert_ptr_equal(TC_PIV_catalog_find(TC_PIV_APPLICATION_PIV, TC_PIV_CARD,
                                               (TC_bytes){entry->tag, entry->tag_length}),
                           entry);
    const int required = memchr(mandatory, (int)i, sizeof mandatory) != NULL;
    const int conditional = i == 7 || i == 8;
    munit_assert_int(entry->requirement, ==,
                     required      ? TC_PIV_MANDATORY
                     : conditional ? TC_PIV_CONDITIONAL
                                   : TC_PIV_OPTIONAL);
    if (i >= 12 && i < 32) {
      munit_assert_uint8(entry->key_reference, ==, (uint8_t)(0x82 + (i - 12)));
      munit_assert_uint8(entry->tag[2], ==, (uint8_t)(0x0d + (i - 12)));
    }
    munit_assert_uint8(entry->flags, ==, entry->kind == TC_PIV_KIND_PAIRING_CODE ? 1 : 0);
    pool_bytes += TC_PIV_RESPONSE_BYTES(entry->minimum_capacity + 5u);
  }
  munit_assert_size(pool_bytes, ==, TC_PIV_INVENTORY_POOL_BYTES);
  const TC_PIV_object_info* pairing = TC_PIV_catalog_find(
      TC_PIV_APPLICATION_PIV, TC_PIV_CARD, (TC_bytes){tag_pairing_code, sizeof tag_pairing_code});
  munit_assert_not_null(pairing);
  munit_assert_int(pairing->contact, ==, TC_PIV_ACCESS_PIN_OR_OCC);
  munit_assert_int(pairing->contactless, ==, TC_PIV_ACCESS_VCI_PIN_OR_OCC);
  munit_assert_uint8(pairing->flags, ==, TC_PIV_OBJECT_SECRET);
  static const uint8_t keys[][2] = {{0x05, 0x9a}, {0x0a, 0x9c}, {0x0b, 0x9d}, {0x01, 0x9e}};
  for (size_t i = 0; i < sizeof keys / sizeof *keys; ++i) {
    const uint8_t tag[] = {0x5f, 0xc1, keys[i][0]};
    const TC_PIV_object_info* entry =
        TC_PIV_catalog_find(TC_PIV_APPLICATION_PIV, TC_PIV_CARD, (TC_bytes){tag, sizeof tag});
    munit_assert_uint8(entry->key_reference, ==, keys[i][1]);
    munit_assert_int(entry->kind, ==, TC_PIV_KIND_CERTIFICATE);
  }
  static const uint8_t unsigned_chuid[] = {0x5f, 0xc1, 0x04}, bit_group[] = {0x7f, 0x61};
  munit_assert_null(TC_PIV_catalog_find(TC_PIV_APPLICATION_PIV, TC_PIV_CARD,
                                        (TC_bytes){unsigned_chuid, sizeof unsigned_chuid}));
  munit_assert_null(
      TC_PIV_catalog_find(TC_PIV_APPLICATION_PIV, TC_PIV_CARD, (TC_bytes){bit_group, 1}));
  munit_assert_not_null(TC_PIV_catalog_find(TC_PIV_APPLICATION_PIV, TC_PIV_CARD,
                                            (TC_bytes){bit_group, sizeof bit_group}));
  munit_assert_null(TC_PIV_catalog_find(TC_PIV_APPLICATION_PIV, TC_PIV_CARD, (TC_bytes){NULL, 0}));
  munit_assert_null(TC_PIV_catalog_at(TC_PIV_APPLICATION_PIV, TC_PIV_CARD, CATALOG));
  munit_assert_size(TC_PIV_catalog_count(TC_PIV_APPLICATION_PIV, TC_TWIC_NEXGEN_CARD), ==, 0);
  munit_assert_size(TC_PIV_catalog_count(TC_PIV_APPLICATION_TWIC, TC_PIV_CARD), ==, 0);
  munit_assert_size(TC_PIV_catalog_count(TC_PIV_APPLICATION_NONE, TC_PIV_CARD), ==, 0);
  munit_assert_null(TC_PIV_catalog_at(TC_PIV_APPLICATION_NONE, TC_PIV_CARD, 0));
  return MUNIT_OK;
}

/* TWIC Part 2 v5 4.5: Legacy and NEXGEN columns, DFC101 on contact only. */
TC_TEST(catalog_twic)
{
  static const uint32_t legacy[] = {0x5fc102, 0x5fc104, 0xdfc101, 0xdfc103, 0xdfc10f};
  static const uint32_t nexgen[] = {0x5fc101, 0x5fc102, 0x5fc104, 0x7e,     0xdfc001, 0xdfc002,
                                    0xdfc101, 0xdfc103, 0xdfc108, 0xdfc109, 0xdfc10f, 0xdfc121};
  munit_assert_size(TC_PIV_catalog_count(TC_PIV_APPLICATION_TWIC, TC_TWIC_LEGACY_CARD), ==,
                    sizeof legacy / sizeof *legacy);
  munit_assert_size(TC_PIV_catalog_count(TC_PIV_APPLICATION_TWIC, TC_TWIC_NEXGEN_CARD), ==,
                    sizeof nexgen / sizeof *nexgen);
  for (size_t i = 0; i < sizeof legacy / sizeof *legacy; ++i) {
    const TC_PIV_object_info* entry =
        TC_PIV_catalog_at(TC_PIV_APPLICATION_TWIC, TC_TWIC_LEGACY_CARD, i);
    munit_assert_uint32(tag_value(entry), ==, legacy[i]);
    munit_assert_int(entry->requirement, ==, TC_PIV_MANDATORY);
  }
  for (size_t i = 0; i < sizeof nexgen / sizeof *nexgen; ++i) {
    const TC_PIV_object_info* entry =
        TC_PIV_catalog_at(TC_PIV_APPLICATION_TWIC, TC_TWIC_NEXGEN_CARD, i);
    munit_assert_uint32(tag_value(entry), ==, nexgen[i]);
    const int optional = nexgen[i] == 0xdfc001 || nexgen[i] == 0xdfc002 || nexgen[i] == 0xdfc121;
    munit_assert_int(entry->requirement, ==, optional ? TC_PIV_OPTIONAL : TC_PIV_MANDATORY);
    const int privacy_key = nexgen[i] == 0xdfc101;
    munit_assert_int(entry->contact, ==, TC_PIV_ACCESS_ALWAYS);
    munit_assert_int(entry->contactless, ==,
                     privacy_key ? TC_PIV_ACCESS_NEVER : TC_PIV_ACCESS_ALWAYS);
    munit_assert_uint8(entry->flags, ==, privacy_key ? TC_PIV_OBJECT_SECRET : 0);
    for (size_t j = 0; j < i; ++j)
      munit_assert_uint16(
          entry->container, !=,
          TC_PIV_catalog_at(TC_PIV_APPLICATION_TWIC, TC_TWIC_NEXGEN_CARD, j)->container);
  }
  static const uint8_t privacy_key[] = {0xdf, 0xc1, 0x01};
  munit_assert_int(TC_PIV_catalog_find(TC_PIV_APPLICATION_TWIC, TC_TWIC_LEGACY_CARD,
                                       (TC_bytes){privacy_key, sizeof privacy_key})
                       ->kind,
                   ==, TC_PIV_KIND_TWIC_PRIVACY_KEY);
  return MUNIT_OK;
}

/* Contact: Always objects first, PIN objects after the PIN, the pairing
 * code only with the plan flag. Empty containers are EMPTY. */
TC_TEST(inventory_contact)
{
  TC_PIV_link link;
  TC_PIV_inventory inventory = inventory_start();
  const TC_PIV_inventory_plan pairing = {TC_PIV_INVENTORY_PAIRING_CODE, 0};
  size_t work = 1000000;
  load();
  link_open(&link, TC_PIV_CONTACT, EXCHANGES);
  TC_PIV_link_info info = link_info(&link);
  munit_assert_int(TC_PIV_inventory_read(&link, NULL, pool_buffer(), &work, &inventory), ==,
                   TC_PIV_OK);
  assert_inventory(&inventory, &info, 0);
  munit_assert_size(work, ==, 1000000 - CATALOG - inventory.pool_used);
  munit_assert_int(TC_PIV_inventory_find(&inventory, 0x6030)->state, ==, TC_PIV_OBJECT_RESTRICTED);
  munit_assert_int(TC_PIV_inventory_find(&inventory, 0x1016)->state, ==, TC_PIV_OBJECT_PRESENT);
  munit_assert_null(TC_PIV_inventory_find(&inventory, 0x3002));
  munit_assert_null(TC_PIV_inventory_find(NULL, 0x3000));
  TC_PIV_inventory_clear(&inventory);

  pin_verify(&link);
  card.log_count = 0;
  info = link_info(&link);
  munit_assert_int(TC_PIV_inventory_read(&link, NULL, pool_buffer(), &work, &inventory), ==,
                   TC_PIV_OK);
  assert_inventory(&inventory, &info, 0);
  munit_assert_int(TC_PIV_inventory_find(&inventory, 0x6030)->state, ==, TC_PIV_OBJECT_PRESENT);
  TC_PIV_inventory_clear(&inventory);

  card.log_count = 0;
  munit_assert_int(TC_PIV_inventory_read(&link, &pairing, pool_buffer(), &work, &inventory), ==,
                   TC_PIV_OK);
  assert_inventory(&inventory, &info, TC_PIV_INVENTORY_PAIRING_CODE);
  const TC_PIV_object* code = TC_PIV_inventory_find(&inventory, 0x1018);
  munit_assert_int(code->state, ==, TC_PIV_OBJECT_PRESENT);
  munit_assert_uint8(code->info->flags, ==, TC_PIV_OBJECT_SECRET);
  TC_PIV_inventory_clear(&inventory);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* Contactless: only Always objects plain. Under secure messaging with the
 * VCI and the PIN every object reads protected, and the decrypted values
 * stay in the pool. */
TC_TEST(inventory_contactless)
{
  TC_PIV_link link;
  TC_PIV_inventory inventory = inventory_start();
  const TC_PIV_inventory_plan pairing = {TC_PIV_INVENTORY_PAIRING_CODE, 0};
  size_t work = 1000000;
  load();
  link_open(&link, TC_PIV_CONTACTLESS, EXCHANGES);
  TC_PIV_link_info info = link_info(&link);
  munit_assert_int(TC_PIV_inventory_read(&link, &pairing, pool_buffer(), &work, &inventory), ==,
                   TC_PIV_OK);
  assert_inventory(&inventory, &info, TC_PIV_INVENTORY_PAIRING_CODE);
  munit_assert_int(TC_PIV_inventory_find(&inventory, 0x0101)->state, ==, TC_PIV_OBJECT_RESTRICTED);
  munit_assert_int(TC_PIV_inventory_find(&inventory, 0x0500)->state, ==, TC_PIV_OBJECT_PRESENT);
  TC_PIV_inventory_clear(&inventory);

  link_secure_vci(&link);
  pin_verify(&link);
  card.log_count = 0;
  info = link_info(&link);
  munit_assert_true(info.secured && info.vci && info.pin_verified);
  munit_assert_int(TC_PIV_inventory_read(&link, &pairing, pool_buffer(), &work, &inventory), ==,
                   TC_PIV_OK);
  assert_inventory(&inventory, &info, TC_PIV_INVENTORY_PAIRING_CODE);
  for (size_t i = 0; i < card.log_count; ++i)
    munit_assert_uint8(card.log[i].secured, ==, 1);
  munit_assert_true(link_info(&link).secured);
  TC_PIV_inventory_clear(&inventory);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* 6A82 is ABSENT, 6982 and 6A81 are DENIED, and another status aborts with
 * the pool and the objects wiped. */
TC_TEST(inventory_card_status)
{
  TC_PIV_link link;
  TC_PIV_inventory inventory = inventory_start();
  size_t work = 1000000;
  load();
  link_open(&link, TC_PIV_CONTACT, EXCHANGES);
  munit_assert_true(tc_card_simulator_override(&card, 0x5fc10c, 0x6a82, (TC_bytes){NULL, 0}));
  munit_assert_true(tc_card_simulator_override(&card, 0x5fc106, 0x6982, (TC_bytes){NULL, 0}));
  munit_assert_true(tc_card_simulator_override(&card, 0x5fc10a, 0x6a81, (TC_bytes){NULL, 0}));
  munit_assert_int(TC_PIV_inventory_read(&link, NULL, pool_buffer(), &work, &inventory), ==,
                   TC_PIV_OK);
  const TC_PIV_object* absent = TC_PIV_inventory_find(&inventory, 0x6060);
  munit_assert_int(absent->state, ==, TC_PIV_OBJECT_ABSENT);
  munit_assert_uint16(absent->status, ==, 0x6a82);
  munit_assert_size(absent->encoded.length, ==, 0);
  munit_assert_int(TC_PIV_inventory_find(&inventory, 0x9000)->state, ==, TC_PIV_OBJECT_DENIED);
  munit_assert_uint16(TC_PIV_inventory_find(&inventory, 0x9000)->status, ==, 0x6982);
  munit_assert_int(TC_PIV_inventory_find(&inventory, 0x0100)->state, ==, TC_PIV_OBJECT_DENIED);
  munit_assert_int(TC_PIV_inventory_find(&inventory, 0x0101)->state, ==, TC_PIV_OBJECT_PRESENT);
  TC_PIV_inventory_clear(&inventory);

  munit_assert_true(tc_card_simulator_override(&card, 0x5fc10b, 0x6a80, (TC_bytes){NULL, 0}));
  inventory = inventory_start();
  const TC_PIV_inventory before = inventory;
  munit_assert_int(TC_PIV_inventory_read(&link, NULL, pool_buffer(), &work, &inventory), ==,
                   TC_PIV_CARD_STATUS);
  munit_assert_uint16(TC_PIV_link_status(&link), ==, 0x6a80);
  munit_assert_ptr_equal(inventory.objects, before.objects);
  munit_assert_size(inventory.count, ==, 0);
  munit_assert_size(inventory.pool_used, ==, 0);
  munit_assert_null(inventory.pool);
  munit_assert_true(tc_test_all_zero(objects, sizeof objects));
  /* Everything received before the abort is wiped. */
  munit_assert_true(tc_test_all_zero(pool, 8192));
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* A plain link keeps reading after an answer that does not fit. Under
 * secure messaging the same limit ends the session and aborts. */
TC_TEST(inventory_oversized)
{
  TC_PIV_link link;
  TC_PIV_inventory inventory = inventory_start();
  const TC_PIV_inventory_plan capped = {0, 2000};
  size_t work = 1000000;
  load();
  link_open(&link, TC_PIV_CONTACT, EXCHANGES);
  pin_verify(&link);
  munit_assert_int(TC_PIV_inventory_read(&link, &capped, pool_buffer(), &work, &inventory), ==,
                   TC_PIV_OK);
  for (size_t i = 0; i < inventory.count; ++i) {
    const TC_PIV_object* object = &inventory.objects[i];
    const tc_card_object* expected = tc_card_fixture_object(&fixture, tag_value(object->info));
    if (expected->data.length > 2000) {
      munit_assert_int(object->state, ==, TC_PIV_OBJECT_OVERSIZED);
      munit_assert_uint16(object->status, ==, 0);
    } else if (object->info->kind != TC_PIV_KIND_PAIRING_CODE) {
      munit_assert_int(object->state, !=, TC_PIV_OBJECT_OVERSIZED);
      munit_assert_int(object->state, !=, TC_PIV_OBJECT_RESTRICTED);
    }
  }
  munit_assert_int(TC_PIV_inventory_find(&inventory, 0x6030)->state, ==, TC_PIV_OBJECT_OVERSIZED);
  munit_assert_int(TC_PIV_inventory_find(&inventory, 0x3000)->state, ==, TC_PIV_OBJECT_OVERSIZED);
  munit_assert_int(TC_PIV_inventory_find(&inventory, 0x1017)->state, ==, TC_PIV_OBJECT_PRESENT);
  munit_assert_size(card.violations, ==, 0);
  TC_PIV_inventory_clear(&inventory);

  /* A pool too small for any answer marks every read OVERSIZED unsent. */
  inventory = inventory_start();
  card.log_count = 0;
  munit_assert_int(TC_PIV_inventory_read(&link, NULL, (TC_buffer){pool, 100}, &work, &inventory),
                   ==, TC_PIV_OK);
  munit_assert_int(TC_PIV_inventory_find(&inventory, 0x6050)->state, ==, TC_PIV_OBJECT_OVERSIZED);
  munit_assert_size(tc_card_simulator_sent(&card, 0xcb, 0), ==, 0);
  TC_PIV_inventory_clear(&inventory);
  TC_PIV_link_clear(&link);

  link_open(&link, TC_PIV_CONTACTLESS, EXCHANGES);
  link_secure_vci(&link);
  pin_verify(&link);
  inventory = inventory_start();
  munit_assert_int(TC_PIV_inventory_read(&link, &capped, pool_buffer(), &work, &inventory), ==,
                   TC_PIV_LIMIT);
  const TC_PIV_link_info info = link_info(&link);
  munit_assert_true(info.sm_lost);
  munit_assert_false(info.secured);
  munit_assert_size(inventory.count, ==, 0);
  /* The CCC and the CHUID region were offered to the card and are wiped.
   * The pool after them was never offered. */
  const size_t offered = 29 + 5 + TC_PIV_RESPONSE_BYTES(2000);
  munit_assert_true(tc_test_all_zero(pool, offered - 64));
  munit_assert_true(tc_test_all_value(pool + offered + 64, 1024, 0xee));
  munit_assert_true(tc_test_all_zero(objects, sizeof objects));
  /* A link without its session refuses the next inventory before sending. */
  inventory = inventory_start();
  const size_t transmits = card.transmits;
  munit_assert_int(TC_PIV_inventory_read(&link, NULL, pool_buffer(), &work, &inventory), ==,
                   TC_PIV_REFUSED);
  munit_assert_size(card.transmits, ==, transmits);
  munit_assert_true(tc_test_all_value(pool, sizeof pool, 0xee));
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* An EXTENDED link asks for the whole object in one answer. The card's DO
 * 7F66 response limit (32767 bytes on SD 33 card 2) bounds that answer, so
 * a region of that size is enough, and every object reads PRESENT. */
TC_TEST(inventory_extended)
{
  const TC_PIV_link_options options = {
      {TC_APDU_EXTENDED, 0, EXCHANGES, 0, 0}, TC_PIV_CONTACT, TC_APDU_MAX_NE};
  TC_PIV_link link;
  TC_PIV_inventory inventory = inventory_start();
  size_t work = 1000000;
  load();
  link_open_with(&link, &options);
  pin_verify(&link);
  card.log_count = 0;
  const TC_PIV_link_info info = link_info(&link);
  munit_assert_int(TC_PIV_inventory_read(&link, NULL, pool_buffer(), &work, &inventory), ==,
                   TC_PIV_OK);
  assert_inventory(&inventory, &info, 0);
  TC_PIV_inventory_clear(&inventory);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* The object array, the work budget and the exchange budget bound the
 * read. */
TC_TEST(inventory_limits)
{
  TC_PIV_link link;
  TC_PIV_inventory inventory = inventory_start();
  size_t work = 1000000;
  load();
  link_open(&link, TC_PIV_CONTACT, EXCHANGES);
  inventory.capacity = CATALOG - 1;
  const TC_PIV_inventory before = inventory;
  const size_t transmits = card.transmits;
  munit_assert_int(TC_PIV_inventory_read(&link, NULL, pool_buffer(), &work, &inventory), ==,
                   TC_PIV_LIMIT);
  munit_assert_size(card.transmits, ==, transmits);
  munit_assert_size(work, ==, 1000000);
  munit_assert_size(inventory.capacity, ==, before.capacity);
  munit_assert_true(tc_test_all_value(pool, sizeof pool, 0xee));
  munit_assert_true(tc_test_all_value(objects, sizeof objects, 0xa5));

  /* One unit per entry and per kept byte: the CCC and CHUID fit, the PIV
   * Authentication certificate does not. */
  inventory = inventory_start();
  work = 1 + 29 + 1 + 2880 + 1;
  munit_assert_int(TC_PIV_inventory_read(&link, NULL, pool_buffer(), &work, &inventory), ==,
                   TC_PIV_LIMIT);
  munit_assert_size(work, ==, 0);
  munit_assert_size(inventory.count, ==, 0);
  munit_assert_true(tc_test_all_zero(pool, 8192));
  TC_PIV_link_clear(&link);

  /* An exhausted exchange budget aborts instead of reporting OVERSIZED. */
  link_open(&link, TC_PIV_CONTACT, 20);
  inventory = inventory_start();
  work = 1000000;
  munit_assert_int(TC_PIV_inventory_read(&link, NULL, pool_buffer(), &work, &inventory), ==,
                   TC_PIV_LIMIT);
  munit_assert_size(TC_APDU_channel_exchanges_left(&link.channel), ==, 0);
  munit_assert_true(tc_test_all_zero(pool, 8192));
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* Argument errors and refusals change nothing and send nothing. */
TC_TEST(inventory_arguments)
{
  TC_PIV_link link;
  TC_PIV_inventory inventory = inventory_start();
  const TC_PIV_inventory_plan unknown = {1u << 1, 0};
  size_t work = 1000000;
  load();
  tc_card_simulator_init(&card, &fixture, TC_PIV_CONTACT);
  const TC_PIV_link_options options = {{TC_APDU_SHORT, 0, EXCHANGES, 0, 0}, TC_PIV_CONTACT, 0};
  munit_assert_int(TC_PIV_link_init(&link, tc_card_simulator_transport(&card), &options,
                                    (TC_buffer){scratch, sizeof scratch}),
                   ==, TC_PIV_OK);
  const TC_PIV_inventory before = inventory;
  TC_buffer buffer = pool_buffer();
  munit_assert_int(TC_PIV_inventory_read(&link, NULL, buffer, &work, &inventory), ==,
                   TC_PIV_REFUSED);
  TC_PIV_application application;
  munit_assert_int(TC_PIV_select(&link, TC_PIV_APPLICATION_PIV, 0, response_buffer(), &application),
                   ==, TC_PIV_OK);
  munit_assert_int(TC_PIV_inventory_read(NULL, NULL, buffer, &work, &inventory), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_inventory_read(&link, NULL, buffer, NULL, &inventory), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_inventory_read(&link, NULL, buffer, &work, NULL), ==, TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_inventory_read(&link, &unknown, buffer, &work, &inventory), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_inventory_read(&link, NULL, (TC_buffer){NULL, 10}, &work, &inventory), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(
      TC_PIV_inventory_read(&link, NULL, (TC_buffer){scratch, sizeof scratch}, &work, &inventory),
      ==, TC_PIV_ARGUMENT);
  munit_assert_int(
      TC_PIV_inventory_read(&link, NULL, (TC_buffer){(uint8_t*)objects, 64}, &work, &inventory), ==,
      TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_inventory_read(&link, NULL, (TC_buffer){(uint8_t*)&work, sizeof work},
                                         &work, &inventory),
                   ==, TC_PIV_ARGUMENT);
  /* The work counter changes during the read, so it may not alias the
   * inventory or the link. */
  munit_assert_int(TC_PIV_inventory_read(&link, NULL, buffer, &inventory.count, &inventory), ==,
                   TC_PIV_ARGUMENT);
  munit_assert_int(
      TC_PIV_inventory_read(&link, NULL, buffer, (size_t*)(void*)&link.response_ne, &inventory), ==,
      TC_PIV_ARGUMENT);
  munit_assert_int(TC_PIV_inventory_read(&link, NULL, buffer, &work, (TC_PIV_inventory*)&link), ==,
                   TC_PIV_ARGUMENT);
  inventory.objects = NULL;
  munit_assert_int(TC_PIV_inventory_read(&link, NULL, buffer, &work, &inventory), ==,
                   TC_PIV_ARGUMENT);
  inventory = before;
  munit_assert_size(work, ==, 1000000);
  munit_assert_size(tc_card_simulator_sent(&card, 0xcb, 0), ==, 0);
  munit_assert_true(tc_test_all_value(pool, sizeof pool, 0xee));
  munit_assert_true(tc_test_all_value(objects, sizeof objects, 0xa5));
  TC_PIV_link_clear(&link);
  munit_assert_int(TC_PIV_inventory_read(&link, NULL, buffer, &work, &inventory), ==,
                   TC_PIV_ARGUMENT);
  return MUNIT_OK;
}

/* Clear wipes the objects and the pool bytes they use and keeps the array
 * for another read. */
TC_TEST(inventory_clear)
{
  TC_PIV_link link;
  TC_PIV_inventory inventory = inventory_start();
  size_t work = 1000000;
  load();
  link_open(&link, TC_PIV_CONTACT, EXCHANGES);
  munit_assert_int(TC_PIV_inventory_read(&link, NULL, pool_buffer(), &work, &inventory), ==,
                   TC_PIV_OK);
  const size_t used = inventory.pool_used;
  munit_assert_size(used, >, 10000);
  TC_PIV_inventory_clear(&inventory);
  munit_assert_true(tc_test_all_zero(pool, used));
  munit_assert_true(tc_test_all_zero(objects, sizeof objects));
  munit_assert_ptr_equal(inventory.objects, objects);
  munit_assert_size(inventory.capacity, ==, CATALOG);
  munit_assert_size(inventory.count, ==, 0);
  munit_assert_size(inventory.pool_used, ==, 0);
  munit_assert_null(inventory.pool);
  munit_assert_null(TC_PIV_inventory_find(&inventory, 0x3000));
  TC_PIV_inventory_clear(NULL);
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

/* Synthetic TWIC NEXGEN answers (TWIC Part 2 v5 4.5 and 5.2): a 9000
 * without data is EMPTY for an optional object, 6A88 is ABSENT, and the TWIC
 * Privacy Key is RESTRICTED on contactless. */
#define TWIC_SELECT "00A4040009A0000003672000000100"
#define TWIC_APT                                                                                   \
  "61144F0BA0000003672000000101037905" /**/                                                        \
  "4F03A000007F66080202040002020800"
#define GET_DATA(tag) "00CB3FFF055C03" tag "00"

static void twic_start(TC_PIV_link* link, const tc_script_step* steps, size_t count,
                       TC_PIV_interface interface)
{
  const TC_PIV_link_options options = {{TC_APDU_SHORT, 0, 64, 0, 0}, interface, 0};
  TC_PIV_application application;
  tc_script_init(&script, steps, count);
  munit_assert_int(TC_PIV_link_init(link, tc_script_transport(&script), &options,
                                    (TC_buffer){scratch, sizeof scratch}),
                   ==, TC_PIV_OK);
  munit_assert_int(TC_PIV_select(link, TC_PIV_APPLICATION_TWIC, 0, response_buffer(), &application),
                   ==, TC_PIV_OK);
  munit_assert_int(application.profile, ==, TC_TWIC_NEXGEN_CARD);
}

TC_TEST(inventory_twic)
{
  const tc_script_step steps[] = {
      STEP(TWIC_SELECT, TWIC_APT "9000"),
      STEP(GET_DATA("5FC101"), "5303700100"
                               "9000"),
      STEP(GET_DATA("5FC102"), "53023000"
                               "9000"),
      STEP(GET_DATA("5FC104"), "53023000"
                               "9000"),
      STEP("00CB3FFF035C017E00", "7E00"
                                 "9000"),
      STEP(GET_DATA("DFC001"), "9000"),
      STEP(GET_DATA("DFC002"), "6A88"),
      STEP(GET_DATA("DFC103"), "5302BC00"
                               "9000"),
      STEP(GET_DATA("DFC108"), "5302BC00"
                               "9000"),
      STEP(GET_DATA("DFC109"), "5302BC00"
                               "9000"),
      STEP(GET_DATA("DFC10F"), "5302BA00"
                               "9000"),
      STEP(GET_DATA("DFC121"), "5300"
                               "9000"),
  };
  TC_PIV_link link;
  TC_PIV_inventory inventory = inventory_start();
  size_t work = 100000;
  twic_start(&link, steps, sizeof steps / sizeof *steps, TC_PIV_CONTACTLESS);
  munit_assert_int(TC_PIV_inventory_read(&link, NULL, pool_buffer(), &work, &inventory), ==,
                   TC_PIV_OK);
  munit_assert_size(script.mismatch, ==, 0);
  munit_assert_size(script.next, ==, script.count);
  munit_assert_size(inventory.count, ==, 12);
  munit_assert_int(inventory.link.application, ==, TC_PIV_APPLICATION_TWIC);
  munit_assert_int(inventory.link.profile, ==, TC_TWIC_NEXGEN_CARD);
  munit_assert_int(TC_PIV_inventory_find(&inventory, 0x0500)->state, ==, TC_PIV_OBJECT_PRESENT);
  munit_assert_int(TC_PIV_inventory_find(&inventory, 0x6050)->state, ==, TC_PIV_OBJECT_EMPTY);
  const TC_PIV_object* personal = TC_PIV_inventory_find(&inventory, 0x6011);
  munit_assert_int(personal->state, ==, TC_PIV_OBJECT_EMPTY);
  munit_assert_size(personal->encoded.length, ==, 0);
  munit_assert_uint16(personal->status, ==, 0x9000);
  munit_assert_int(TC_PIV_inventory_find(&inventory, 0x6012)->state, ==, TC_PIV_OBJECT_ABSENT);
  munit_assert_uint16(TC_PIV_inventory_find(&inventory, 0x6012)->status, ==, 0x6a88);
  munit_assert_int(TC_PIV_inventory_find(&inventory, 0x2001)->state, ==, TC_PIV_OBJECT_RESTRICTED);
  munit_assert_int(TC_PIV_inventory_find(&inventory, 0x1015)->state, ==, TC_PIV_OBJECT_EMPTY);
  TC_PIV_inventory_clear(&inventory);
  TC_PIV_link_clear(&link);

  /* A mandatory object answering 9000 without data aborts. */
  const tc_script_step bare[] = {
      STEP(TWIC_SELECT, TWIC_APT "9000"),
      STEP(GET_DATA("5FC101"), "9000"),
  };
  inventory = inventory_start();
  twic_start(&link, bare, sizeof bare / sizeof *bare, TC_PIV_CONTACT);
  munit_assert_int(TC_PIV_inventory_read(&link, NULL, pool_buffer(), &work, &inventory), ==,
                   TC_PIV_INVALID);
  munit_assert_size(inventory.count, ==, 0);
  munit_assert_true(tc_test_all_zero(objects, sizeof objects));
  TC_PIV_link_clear(&link);
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/catalog/piv", catalog_piv, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/catalog/twic", catalog_twic, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/inventory/contact", inventory_contact, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/inventory/contactless", inventory_contactless, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/inventory/card-status", inventory_card_status, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/inventory/oversized", inventory_oversized, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/inventory/extended", inventory_extended, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/inventory/limits", inventory_limits, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/inventory/arguments", inventory_arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/inventory/clear", inventory_clear, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/inventory/twic", inventory_twic, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
static const MunitSuite suite = {"/piv-catalog", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char* argv[])
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
