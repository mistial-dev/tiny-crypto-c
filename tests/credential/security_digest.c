/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Security Object authentication and per-container digest checks
 * (SP 800-73-5 Part 1 section 3.1.7) on the SD 33 card 2 capture fixture.
 * The SD 33 issuing CA is pinned as the anchor because the SD 33 root is
 * unavailable. No CRLs are indexed, so the card runs use
 * TC_VALIDATION_REVOCATION_WHEN_AVAILABLE unless a case checks REQUIRED. */
#include "validation_fixture.h"
#include "card_fixture.h"
#include "test_util.h"

#ifndef TC_CARD_FIXTURE_DIR
#error "TC_CARD_FIXTURE_DIR must name the capture fixture directory"
#endif
#ifndef TC_VECTOR_DIR
#error "TC_VECTOR_DIR must name tests/vectors"
#endif

static validation_fixture fixture;
static tc_card_fixture card;
static uint8_t anchor_bytes[FIXTURE_FILE_BYTES];
static uint8_t certificate_bytes[FIXTURE_FILE_BYTES];
static uint8_t lds_content[4096];
static uint8_t tampered[FIXTURE_FILE_BYTES];

static const TC_X509_time at = {2026, 9, 29, 18, 0, 0};

/* An accepted card: its authentication certificate, identifiers and CHUID. */
typedef struct {
  TC_X509_validation_report certificate;
  TC_PIV_card_identifiers identifiers;
  TC_PIV_CHUID_report chuid;
} accepted_card;
static accepted_card accepted;

static TC_bytes vector(const char* name, uint8_t bytes[FIXTURE_FILE_BYTES])
{
  char path[512];
  munit_assert_int(snprintf(path, sizeof path, "%s/%s", TC_VECTOR_DIR, name), >, 0);
  return fixture_read(path, bytes);
}

/* The hashed bytes of a GET DATA answer: the value of its 53 container, or
 * of 7E for the Discovery Object, which has no 53 container (SP 800-73-5
 * Part 1 section 3.3.2). The card 2 Security Object signs these values. */
static TC_bytes container_value(TC_bytes object)
{
  munit_assert_size(object.length, >=, 2);
  if (object.data[0] != 0x7e)
    munit_assert_uint8(object.data[0], ==, 0x53);
  size_t header = 2, length = object.data[1];
  if (length == 0x81 || length == 0x82) {
    const size_t octets = length & 0x7fu;
    length = 0;
    for (size_t i = 0; i < octets; ++i)
      length = length << 8 | object.data[2 + i];
    header += octets;
  }
  munit_assert_size(header + length, ==, object.length);
  return (TC_bytes){object.data + header, length};
}

static TC_bytes card_object(uint32_t tag)
{
  const tc_card_object* object = tc_card_fixture_object(&card, tag);
  munit_assert_not_null(object);
  return object->data;
}

/* Validate the card authentication certificate, read its identifiers and
 * validate the CHUID under the fixture context. */
static TC_credential_status accept_card(TC_bytes certificate, TC_bytes chuid,
                                        TC_PIV_CHUID_encoding encoding)
{
  size_t work = FIXTURE_WORK;
  munit_assert_int(TC_X509_validate(certificate, &fixture.context, &work, &accepted.certificate),
                   ==, TC_CREDENTIAL_VALID);
  fixture_card_identifiers(&fixture, &accepted.certificate.certificate, &accepted.identifiers);
  const TC_PIV_CHUID_validation_request request = {chuid,
                                                   encoding,
                                                   TC_PIV_CARD,
                                                   TC_CHUID_PROFILE_PIV,
                                                   0,
                                                   &accepted.identifiers,
                                                   &accepted.certificate.certificate.not_after};
  work = FIXTURE_WORK;
  return TC_PIV_CHUID_validate(&request, &fixture.context, &work, &accepted.chuid);
}

static void card2_init(TC_validation_revocation policy)
{
  char path[512];
  munit_assert_int(snprintf(path, sizeof path, "%s/sd33_card2.txt", TC_CARD_FIXTURE_DIR), >, 0);
  munit_assert_long(tc_card_fixture_load(&card, path), ==, 0);
  const TC_bytes anchor = vector("x509/ocsp/sd33/card01_issuer.der", anchor_bytes);
  validation_fixture_init(&fixture, anchor, NULL, 0, NULL, 0, at, policy);
}

/* Accept SD 33 card 2 under WHEN_AVAILABLE. The pinned issuing CA signs the
 * card certificates and the CHUID signer. */
static void card2_accept(void)
{
  card2_init(TC_VALIDATION_REVOCATION_WHEN_AVAILABLE);
  const TC_bytes certificate = vector("x509/piv/sd33/card01_card_auth_cert.der", certificate_bytes);
  munit_assert_int(accept_card(certificate, card_object(0x5fc102), TC_PIV_CHUID_CONTAINER), ==,
                   TC_CREDENTIAL_VALID);
  munit_assert_uint8(accepted.certificate.revocation_checked, ==, 0);
  munit_assert_uint8(accepted.chuid.revocation_checked, ==, 0);
}

static TC_PIV_security_signature_request card2_signature(void)
{
  const TC_PIV_security_signature_request request = {
      card_object(0x5fc106), TC_PIV_SECURITY_CONTAINER, TC_PIV_CARD, &accepted.chuid,
      &accepted.certificate.certificate.not_after};
  return request;
}

static const TC_PIV_security_validation_workspace lds_workspace = {lds_content, sizeof lds_content};

/* Card 2 containers named by its Security Object and the GET DATA tags that
 * hold them (SP 800-73-5 Part 1 Table 3). */
static const struct {
  uint16_t container;
  uint32_t tag;
} card2_mapped[] = {{0xdb00, 0x5fc107}, {0x3000, 0x5fc102}, {0x6010, 0x5fc103}, {0x3001, 0x5fc109},
                    {0x6030, 0x5fc108}, {0x6050, 0x7e},     {0x6060, 0x5fc10c}};
enum { CARD2_MAPPED = sizeof card2_mapped / sizeof *card2_mapped };
static TC_bytes card2_parts[CARD2_MAPPED];
static TC_PIV_security_data card2_inventory[CARD2_MAPPED + 1];

static void card2_inventory_init(void)
{
  for (size_t i = 0; i < CARD2_MAPPED; ++i) {
    card2_parts[i] = container_value(card_object(card2_mapped[i].tag));
    card2_inventory[i] = (TC_PIV_security_data){card2_mapped[i].container, &card2_parts[i], 1};
  }
}

/* Authentication decodes the map and LDS digests. It follows the context's
 * evidence policy: without CRLs, REQUIRED is UNAVAILABLE for the CHUID, the
 * card certificate and the Security Object alike. */
TC_TEST(authenticate)
{
  card2_accept();
  const TC_PIV_security_signature_request request = card2_signature();
  TC_PIV_security_map map;
  size_t work = FIXTURE_WORK;
  munit_assert_int(
      TC_PIV_security_authenticate(&request, &fixture.context, &lds_workspace, &work, &map), ==,
      TC_CREDENTIAL_VALID);
  munit_assert_uint16(map.object.groups, ==, map.lds.groups);
  munit_assert_uint16(map.object.groups, ==, 0x0c6b);
  munit_assert_uint8(map.revocation_checked, ==, 0);
  munit_assert_int(map.profile, ==, TC_PIV_CARD);
  munit_assert_ptr_equal(map.signer.data, accepted.chuid.signer.data);
  munit_assert_ptr(map.object.cms.data, >=, request.encoded.data);
  munit_assert_ptr(map.object.cms.data, <, request.encoded.data + request.encoded.length);

  /* REQUIRED under the same trust: the signer has no CRL evidence. */
  fixture.options.revocation = TC_VALIDATION_REVOCATION_REQUIRED;
  TC_PIV_security_map unchanged;
  memset(&unchanged, 0xa5, sizeof unchanged);
  work = FIXTURE_WORK;
  munit_assert_int(
      TC_PIV_security_authenticate(&request, &fixture.context, &lds_workspace, &work, &unchanged),
      ==, TC_CREDENTIAL_UNAVAILABLE);
  munit_assert_true(tc_test_all_value(&unchanged, sizeof unchanged, 0xa5));
  TC_X509_validation_report certificate;
  work = FIXTURE_WORK;
  munit_assert_int(TC_X509_validate(accepted.certificate.certificate.encoded, &fixture.context,
                                    &work, &certificate),
                   ==, TC_CREDENTIAL_UNAVAILABLE);
  const TC_PIV_CHUID_validation_request chuid = {card_object(0x5fc102),
                                                 TC_PIV_CHUID_CONTAINER,
                                                 TC_PIV_CARD,
                                                 TC_CHUID_PROFILE_PIV,
                                                 0,
                                                 &accepted.identifiers,
                                                 &accepted.certificate.certificate.not_after};
  TC_PIV_CHUID_report chuid_result;
  work = FIXTURE_WORK;
  munit_assert_int(TC_PIV_CHUID_validate(&chuid, &fixture.context, &work, &chuid_result), ==,
                   TC_CREDENTIAL_UNAVAILABLE);
  return MUNIT_OK;
}

/* A changed signature byte and a container map whose groups differ from the
 * signed LDS groups are INVALID with out unchanged. */
TC_TEST(authenticate_invalid)
{
  card2_accept();
  const TC_bytes encoded = card_object(0x5fc106);
  TC_PIV_security_signature_request request = card2_signature();
  request.encoded = (TC_bytes){tampered, encoded.length};
  TC_PIV_security_map map;
  memset(&map, 0xa5, sizeof map);
  /* 53 82 04 4A, BA 15, then DG 01 for container DB00. */
  munit_assert_memory_equal(7, encoded.data, "\x53\x82\x04\x4a\xba\x15\x01");
  const size_t offsets[] = {encoded.length - 10, 6};
  for (size_t i = 0; i < sizeof offsets / sizeof *offsets; ++i) {
    memcpy(tampered, encoded.data, encoded.length);
    tampered[offsets[i]] = i ? 0x0f : (uint8_t)(tampered[offsets[i]] ^ 1);
    size_t work = FIXTURE_WORK;
    munit_assert_int(
        TC_PIV_security_authenticate(&request, &fixture.context, &lds_workspace, &work, &map), ==,
        TC_CREDENTIAL_INVALID);
    munit_assert_true(tc_test_all_value(&map, sizeof map, 0xa5));
  }
  return MUNIT_OK;
}

/* Argument errors return ERROR with work and out unchanged. */
TC_TEST(authenticate_arguments)
{
  card2_accept();
  TC_PIV_security_signature_request request = card2_signature();
  TC_PIV_security_map map;
  memset(&map, 0xa5, sizeof map);
  size_t work = FIXTURE_WORK;
  munit_assert_int(
      TC_PIV_security_authenticate(NULL, &fixture.context, &lds_workspace, &work, &map), ==,
      TC_CREDENTIAL_ERROR);
  munit_assert_int(TC_PIV_security_authenticate(&request, &fixture.context, NULL, &work, &map), ==,
                   TC_CREDENTIAL_ERROR);
  munit_assert_int(
      TC_PIV_security_authenticate(&request, &fixture.context, &lds_workspace, NULL, &map), ==,
      TC_CREDENTIAL_ERROR);
  request.encoding = (TC_PIV_security_encoding)2;
  munit_assert_int(
      TC_PIV_security_authenticate(&request, &fixture.context, &lds_workspace, &work, &map), ==,
      TC_CREDENTIAL_ERROR);
  request = card2_signature();
  request.profile = TC_TWIC_NEXGEN_CARD;
  munit_assert_int(
      TC_PIV_security_authenticate(&request, &fixture.context, &lds_workspace, &work, &map), ==,
      TC_CREDENTIAL_ERROR);
  /* LDS scratch inside the encoded Security Object. */
  request = card2_signature();
  const TC_PIV_security_validation_workspace inside = {(uint8_t*)request.encoded.data, 64};
  munit_assert_int(TC_PIV_security_authenticate(&request, &fixture.context, &inside, &work, &map),
                   ==, TC_CREDENTIAL_ERROR);
  munit_assert_size(work, ==, FIXTURE_WORK);
  munit_assert_true(tc_test_all_value(&map, sizeof map, 0xa5));
  return MUNIT_OK;
}

/* Every mapped container matches its signed digest. Containers outside the
 * map are UNAVAILABLE. A changed byte fails only that container. */
TC_TEST(digests)
{
  card2_accept();
  card2_inventory_init();
  const TC_PIV_security_signature_request request = card2_signature();
  TC_PIV_security_map map;
  size_t work = FIXTURE_WORK;
  munit_assert_int(
      TC_PIV_security_authenticate(&request, &fixture.context, &lds_workspace, &work, &map), ==,
      TC_CREDENTIAL_VALID);
  /* The map survives reuse of the validation workspace. */
  memset(fixture.arena, 0, sizeof fixture.arena);
  for (size_t i = 0; i < CARD2_MAPPED; ++i) {
    work = FIXTURE_WORK;
    munit_assert_int(TC_PIV_security_digest_check(&map, &card2_inventory[i], &work), ==,
                     TC_CREDENTIAL_VALID);
    munit_assert_size(work, <, FIXTURE_WORK);
  }
  const uint32_t unmapped[][2] = {{0x0101, 0x5fc105}, {0x0500, 0x5fc101}};
  for (size_t i = 0; i < 2; ++i) {
    const TC_bytes part = container_value(card_object(unmapped[i][1]));
    const TC_PIV_security_data object = {(uint16_t)unmapped[i][0], &part, 1};
    work = FIXTURE_WORK;
    munit_assert_int(TC_PIV_security_digest_check(&map, &object, &work), ==,
                     TC_CREDENTIAL_UNAVAILABLE);
  }
  const TC_bytes fingerprints = card2_parts[2];
  memcpy(tampered, fingerprints.data, fingerprints.length);
  tampered[fingerprints.length - 1] ^= 1;
  const TC_bytes changed = {tampered, fingerprints.length};
  const TC_PIV_security_data object = {0x6010, &changed, 1};
  work = FIXTURE_WORK;
  munit_assert_int(TC_PIV_security_digest_check(&map, &object, &work), ==, TC_CREDENTIAL_INVALID);
  work = FIXTURE_WORK;
  munit_assert_int(TC_PIV_security_digest_check(&map, &card2_inventory[4], &work), ==,
                   TC_CREDENTIAL_VALID);
  /* The same bytes split across parts hash identically. */
  const TC_bytes split[] = {{fingerprints.data, 10},
                            {fingerprints.data + 10, fingerprints.length - 10}};
  const TC_PIV_security_data parts = {0x6010, split, 2};
  work = FIXTURE_WORK;
  munit_assert_int(TC_PIV_security_digest_check(&map, &parts, &work), ==, TC_CREDENTIAL_VALID);
  return MUNIT_OK;
}

/* Argument errors return ERROR with work unchanged. Exhausted work is
 * LIMIT. */
TC_TEST(digest_arguments)
{
  card2_accept();
  card2_inventory_init();
  const TC_PIV_security_signature_request request = card2_signature();
  TC_PIV_security_map map;
  size_t work = FIXTURE_WORK;
  munit_assert_int(
      TC_PIV_security_authenticate(&request, &fixture.context, &lds_workspace, &work, &map), ==,
      TC_CREDENTIAL_VALID);
  const TC_PIV_security_data* object = &card2_inventory[0];
  work = FIXTURE_WORK;
  munit_assert_int(TC_PIV_security_digest_check(NULL, object, &work), ==, TC_CREDENTIAL_ERROR);
  munit_assert_int(TC_PIV_security_digest_check(&map, NULL, &work), ==, TC_CREDENTIAL_ERROR);
  munit_assert_int(TC_PIV_security_digest_check(&map, object, NULL), ==, TC_CREDENTIAL_ERROR);
  const TC_PIV_security_data no_parts = {object->container, NULL, 1};
  munit_assert_int(TC_PIV_security_digest_check(&map, &no_parts, &work), ==, TC_CREDENTIAL_ERROR);
  const TC_PIV_security_data empty = {object->container, object->parts, 0};
  munit_assert_int(TC_PIV_security_digest_check(&map, &empty, &work), ==, TC_CREDENTIAL_ERROR);
  TC_PIV_security_map changed = map;
  changed.lds.groups ^= 1u << 15;
  munit_assert_int(TC_PIV_security_digest_check(&changed, object, &work), ==, TC_CREDENTIAL_ERROR);
  munit_assert_size(work, ==, FIXTURE_WORK);
  /* The work counter may not alias the map. */
  changed = map;
  size_t* inside = (size_t*)(void*)&changed.limits.max_input;
  const size_t max_input = *inside;
  munit_assert_int(TC_PIV_security_digest_check(&changed, object, inside), ==, TC_CREDENTIAL_ERROR);
  munit_assert_size(*inside, ==, max_input);
  size_t small = 16;
  munit_assert_int(TC_PIV_security_digest_check(&map, object, &small), ==, TC_CREDENTIAL_LIMIT);
  return MUNIT_OK;
}

/* TC_PIV_security_validate keeps its complete-inventory contract on top of
 * the per-container checks. */
TC_TEST(validate_inventory)
{
  card2_accept();
  card2_inventory_init();
  TC_PIV_security_validation_request request = {card_object(0x5fc106),
                                                TC_PIV_SECURITY_CONTAINER,
                                                TC_PIV_CARD,
                                                &accepted.chuid,
                                                &accepted.certificate.certificate.not_after,
                                                card2_inventory,
                                                CARD2_MAPPED};
  TC_PIV_security_report result;
  size_t work = FIXTURE_WORK;
  munit_assert_int(
      TC_PIV_security_validate(&request, &fixture.context, &lds_workspace, &work, &result), ==,
      TC_CREDENTIAL_VALID);
  munit_assert_ptr_equal(result.objects, card2_inventory);
  munit_assert_size(result.count, ==, CARD2_MAPPED);
  munit_assert_uint8(result.revocation_checked, ==, 0);

  TC_PIV_security_report unchanged;
  memset(&unchanged, 0xa5, sizeof unchanged);
  /* One changed container fails the complete inventory. */
  const TC_bytes fingerprints = card2_parts[2];
  memcpy(tampered, fingerprints.data, fingerprints.length);
  tampered[0] ^= 1;
  const TC_bytes changed = {tampered, fingerprints.length};
  card2_inventory[2].parts = &changed;
  work = FIXTURE_WORK;
  munit_assert_int(
      TC_PIV_security_validate(&request, &fixture.context, &lds_workspace, &work, &unchanged), ==,
      TC_CREDENTIAL_INVALID);
  card2_inventory[2].parts = &card2_parts[2];
  /* A missing signed container. */
  request.count = CARD2_MAPPED - 1;
  work = FIXTURE_WORK;
  munit_assert_int(
      TC_PIV_security_validate(&request, &fixture.context, &lds_workspace, &work, &unchanged), ==,
      TC_CREDENTIAL_INVALID);
  /* An unsigned container in place of a signed one. */
  const TC_bytes piv_authentication = container_value(card_object(0x5fc105));
  card2_inventory[CARD2_MAPPED - 1] = (TC_PIV_security_data){0x0101, &piv_authentication, 1};
  request.count = CARD2_MAPPED;
  work = FIXTURE_WORK;
  munit_assert_int(
      TC_PIV_security_validate(&request, &fixture.context, &lds_workspace, &work, &unchanged), ==,
      TC_CREDENTIAL_INVALID);
  /* A duplicate container fails before any work. */
  card2_inventory[CARD2_MAPPED - 1] = card2_inventory[0];
  work = FIXTURE_WORK;
  munit_assert_int(
      TC_PIV_security_validate(&request, &fixture.context, &lds_workspace, &work, &unchanged), ==,
      TC_CREDENTIAL_INVALID);
  munit_assert_size(work, ==, FIXTURE_WORK);
  request.count = 1;
  munit_assert_int(
      TC_PIV_security_validate(&request, &fixture.context, &lds_workspace, &work, &unchanged), ==,
      TC_CREDENTIAL_INVALID);
  request.count = TC_LDS_MAX_GROUPS + 1;
  munit_assert_int(
      TC_PIV_security_validate(&request, &fixture.context, &lds_workspace, &work, &unchanged), ==,
      TC_CREDENTIAL_LIMIT);
  card2_inventory_init();
  card2_inventory[1].parts = NULL;
  request.count = CARD2_MAPPED;
  munit_assert_int(
      TC_PIV_security_validate(&request, &fixture.context, &lds_workspace, &work, &unchanged), ==,
      TC_CREDENTIAL_ERROR);
  munit_assert_size(work, ==, FIXTURE_WORK);
  munit_assert_true(tc_test_all_value(&unchanged, sizeof unchanged, 0xa5));
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
      {"/authenticate", authenticate, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/authenticate-invalid", authenticate_invalid, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/authenticate-arguments", authenticate_arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/digests", digests, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/digest-arguments", digest_arguments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {"/validate-inventory", validate_inventory, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
      {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/credential/security-digest", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
