/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/credential.h>
#include <tiny_crypto/x509_crypto.h>
#include <tiny_crypto/x509_crl.h>
#include <tiny_crypto/x509_trust_anchor.h>
#include <tiny_crypto/twic_tpk.h>
#include "munit.h"
#include <stdio.h>
#include <string.h>

#ifndef TC_TWIC_SYNTHETIC_ROOT
#error "TC_TWIC_SYNTHETIC_ROOT must name the vendored fixture directory"
#endif

enum { LIMIT = 20000, WORK = 2000000 };
typedef struct {
  uint8_t root[LIMIT], issuer[LIMIT], card[LIMIT];
  uint8_t root_crl[LIMIT], issuer_crl[LIMIT];
  uint8_t trust_list[LIMIT];
  uint8_t trust_certificate[LIMIT], trust_bad_keyid[LIMIT], trust_bad_name[LIMIT],
      trust_bad_key[LIMIT], trust_bad_certsign[LIMIT];
  uint8_t signed_chuid[LIMIT], unsigned_chuid[LIMIT], security[LIMIT];
  uint8_t fingerprint[LIMIT], face[LIMIT], printed[LIMIT];
  uint8_t tpk[LIMIT], fingerprint_plain[LIMIT], face_plain[LIMIT], printed_plain[LIMIT], lds[2048];
  uint8_t piv_chuid[LIMIT], piv_security[LIMIT], piv_fingerprint[LIMIT], piv_face[LIMIT],
      piv_printed[LIMIT], piv_discovery[LIMIT];
  size_t root_length, issuer_length, card_length;
  size_t trust_list_length;
  size_t trust_certificate_length, trust_bad_keyid_length, trust_bad_name_length,
      trust_bad_key_length, trust_bad_certsign_length;
  size_t signed_length, unsigned_length, security_length;
  size_t fingerprint_length, face_length, printed_length;
  size_t tpk_length, fingerprint_plain_length, face_plain_length, printed_plain_length;
  size_t piv_chuid_length, piv_security_length, piv_fingerprint_length, piv_face_length,
      piv_printed_length, piv_discovery_length;
  TC_bytes crls[2];
  TC_X509_crl_record crl_records[2];
  TC_X509_crl_index crl_index;
  TC_X509_store_anchor anchor;
  TC_bytes candidates[2];
  TC_X509_store_array source_array;
  TC_X509_store_source source;
  TC_X509_store store;
  TC_X509_store_snapshot slot, *held;
  TC_validation_trust trust;
  TC_validation_options options;
  TC_validation_context context;
  TC_validation_workspace workspace;
  TC_X509_native_workspace native;
  TC_RSA_word rsa_words[TC_RSA_VERIFY_WORKSPACE_WORDS(3072)];
  TC_RSA_workspace rsa;
  TC_ECDSA_workspace ec;
  TC_validation_storage arena[40000];
  TC_TLV_frame parse_frames[32];
  TC_bytes parse_oids[32];
  TC_PIV_card_identifiers identifiers;
  TC_X509_time card_expiration;
} Fixture;

static Fixture fixture;

static size_t read_file(const char* profile, const char* name, uint8_t out[LIMIT])
{
  char path[512];
  munit_assert_int(snprintf(path, sizeof path, "%s/%s/%s", TC_TWIC_SYNTHETIC_ROOT, profile, name),
                   >, 0);
  FILE* file = fopen(path, "rb");
  munit_assert_not_null(file);
  size_t length = fread(out, 1, LIMIT, file);
  munit_assert_int(ferror(file), ==, 0);
  munit_assert_int(fgetc(file), ==, EOF);
  munit_assert_int(fclose(file), ==, 0);
  munit_assert_size(length, >, 0);
  return length;
}

static TC_bytes value(TC_bytes encoded, uint8_t tag)
{
  const TC_TLV_limits limits = {LIMIT, LIMIT, 256, 16};
  TC_TLV_element element;
  munit_assert_int(TC_TLV_read(encoded.data, encoded.length, TC_TLV_ISO7816, &limits, &element), ==,
                   TC_TLV_OK);
  munit_assert_size(element.encoded.length, ==, encoded.length);
  munit_assert_uint(element.encoded.data[0], ==, tag);
  return element.value;
}

static TC_bytes first_value(TC_bytes encoded, uint8_t tag)
{
  const TC_TLV_limits limits = {LIMIT, LIMIT, 256, 16};
  TC_TLV_element element;
  munit_assert_int(TC_TLV_read(encoded.data, encoded.length, TC_TLV_ISO7816, &limits, &element), ==,
                   TC_TLV_OK);
  munit_assert_uint(element.encoded.data[0], ==, tag);
  return element.value;
}

static void prepare(const char* profile)
{
  Fixture* state = &fixture;
  memset(state, 0, sizeof *state);
  const TC_TLV_limits limits = {LIMIT, LIMIT, 512, 16};
  state->root_length = read_file(profile, "root.der", state->root);
  state->issuer_length = read_file(profile, "issuer.der", state->issuer);
  state->card_length = read_file(profile, "card.der", state->card);
  state->trust_list_length = read_file(profile, "trust-anchors.der", state->trust_list);
  state->trust_certificate_length =
      read_file(profile, "trust-anchor-certificate.der", state->trust_certificate);
  state->trust_bad_keyid_length =
      read_file(profile, "trust-anchor-bad-keyid.der", state->trust_bad_keyid);
  state->trust_bad_name_length =
      read_file(profile, "trust-anchor-bad-name.der", state->trust_bad_name);
  state->trust_bad_key_length =
      read_file(profile, "trust-anchor-bad-key.der", state->trust_bad_key);
  state->trust_bad_certsign_length =
      read_file(profile, "trust-anchor-bad-certsign.der", state->trust_bad_certsign);
  size_t root_crl_length = read_file(profile, "root-crl.der", state->root_crl);
  size_t issuer_crl_length = read_file(profile, "issuer-crl.der", state->issuer_crl);
  state->signed_length = read_file(profile, "signed-chuid.bin", state->signed_chuid);
  state->unsigned_length = read_file(profile, "unsigned-chuid.bin", state->unsigned_chuid);
  state->security_length = read_file(profile, "security.bin", state->security);
  state->fingerprint_length = read_file(profile, "fingerprint.bin", state->fingerprint);
  state->tpk_length = read_file(profile, "tpk.bin", state->tpk);
  state->piv_chuid_length = read_file(profile, "piv-signed-chuid.bin", state->piv_chuid);
  state->piv_security_length = read_file(profile, "piv-security.bin", state->piv_security);
  state->piv_fingerprint_length = read_file(profile, "piv-fingerprint.bin", state->piv_fingerprint);
  state->piv_face_length = read_file(profile, "piv-face.bin", state->piv_face);
  state->piv_printed_length = read_file(profile, "piv-printed.bin", state->piv_printed);
  state->piv_discovery_length = read_file(profile, "piv-discovery.bin", state->piv_discovery);
  if (!strcmp(profile, "nexgen")) {
    state->face_length = read_file(profile, "face.bin", state->face);
    state->printed_length = read_file(profile, "printed.bin", state->printed);
  }
  TC_TWIC_tpk key;
  munit_assert_int(TC_TWIC_tpk_read(value((TC_bytes){state->tpk, state->tpk_length}, 0x53),
                                    TC_TWIC_TPK_CONTENTS, &key),
                   ==, TC_TLV_OK);
  TC_bytes ciphertext =
      value(value((TC_bytes){state->fingerprint, state->fingerprint_length}, 0x53), 0xbc);
  memcpy(state->fingerprint_plain, ciphertext.data, ciphertext.length);
  munit_assert_int(TC_TWIC_object_decrypt(&key, state->fingerprint_plain, ciphertext.length,
                                          &state->fingerprint_plain_length),
                   ==, TC_OK);
  if (!strcmp(profile, "nexgen")) {
    ciphertext = value(value((TC_bytes){state->face, state->face_length}, 0x53), 0xbc);
    memcpy(state->face_plain, ciphertext.data, ciphertext.length);
    munit_assert_int(TC_TWIC_object_decrypt(&key, state->face_plain, ciphertext.length,
                                            &state->face_plain_length),
                     ==, TC_OK);
    ciphertext = value(value((TC_bytes){state->printed, state->printed_length}, 0x53), 0xbc);
    memcpy(state->printed_plain, ciphertext.data, ciphertext.length);
    munit_assert_int(TC_TWIC_object_decrypt(&key, state->printed_plain, ciphertext.length,
                                            &state->printed_plain_length),
                     ==, TC_OK);
  }
  TC_secure_zero(&key, sizeof key);
  TC_X509_workspace parser = {state->parse_frames, 32, state->parse_oids, 32};
  TC_X509_certificate card;
  TC_TLV_reader trust_reader;
  munit_assert_int(TC_X509_trust_anchor_list_init(&trust_reader, state->trust_list,
                                                  state->trust_list_length, &limits, &parser),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_trust_anchor_next(&trust_reader, &limits, &parser, &state->anchor), ==,
                   TC_TLV_OK);
  munit_assert_int(state->anchor.x509_unusable, ==, 0);
  TC_X509_store_anchor ignored;
  munit_assert_int(TC_X509_trust_anchor_next(&trust_reader, &limits, &parser, &ignored), ==,
                   TC_TLV_END);
  munit_assert_int(TC_X509_trust_anchor_list_init(&trust_reader, state->trust_certificate,
                                                  state->trust_certificate_length, &limits,
                                                  &parser),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_trust_anchor_next(&trust_reader, &limits, &parser, &ignored), ==,
                   TC_TLV_OK);
  munit_assert_size(ignored.trust.name.length, ==, state->anchor.trust.name.length);
  munit_assert_memory_equal(ignored.trust.name.length, ignored.trust.name.data,
                            state->anchor.trust.name.data);
  munit_assert_int(TC_X509_trust_anchor_list_init(&trust_reader, state->trust_bad_keyid,
                                                  state->trust_bad_keyid_length, &limits, &parser),
                   ==, TC_TLV_OK);
  munit_assert_int(TC_X509_trust_anchor_next(&trust_reader, &limits, &parser, &ignored), ==,
                   TC_TLV_INVALID);
  const TC_bytes invalid_lists[] = {{state->trust_bad_name, state->trust_bad_name_length},
                                    {state->trust_bad_key, state->trust_bad_key_length},
                                    {state->trust_bad_certsign, state->trust_bad_certsign_length}};
  for (size_t i = 0; i < sizeof invalid_lists / sizeof *invalid_lists; ++i) {
    munit_assert_int(TC_X509_trust_anchor_list_init(&trust_reader, invalid_lists[i].data,
                                                    invalid_lists[i].length, &limits, &parser),
                     ==, TC_TLV_OK);
    munit_assert_int(TC_X509_trust_anchor_next(&trust_reader, &limits, &parser, &ignored), ==,
                     TC_TLV_INVALID);
  }
  /* Fixture authorization is the pinned synthetic root certificate. */
  TC_X509_certificate root;
  munit_assert_int(TC_X509_read(state->root, state->root_length, &limits, &parser, &root), ==,
                   TC_TLV_OK);
  munit_assert_size(state->anchor.trust.name.length, ==, root.subject.length);
  munit_assert_memory_equal(root.subject.length, state->anchor.trust.name.data, root.subject.data);
  munit_assert_size(state->anchor.trust.public_key.key.length, ==, root.public_key.key.length);
  munit_assert_memory_equal(root.public_key.key.length, state->anchor.trust.public_key.key.data,
                            root.public_key.key.data);
  munit_assert_int(TC_X509_read(state->card, state->card_length, &limits, &parser, &card), ==,
                   TC_TLV_OK);
  state->card_expiration = card.not_after;
  TC_TLV_reader extensions;
  munit_assert_int(
      TC_X509_extensions_init(&extensions, card.extensions.data, card.extensions.length, &limits),
      ==, TC_TLV_OK);
  TC_X509_extension extension;
  static const uint8_t san_oid[] = {0x55, 0x1d, 0x11};
  TC_bytes san = {NULL, 0};
  while (TC_X509_extension_next(&extensions, &extension) == TC_TLV_OK) {
    if (extension.oid.length == sizeof san_oid &&
        !memcmp(extension.oid.data, san_oid, sizeof san_oid))
      san = extension.value;
  }
  munit_assert_not_null(san.data);
  size_t work = WORK;
  TC_PIV_card_profile card_profile =
      !strcmp(profile, "legacy") ? TC_TWIC_LEGACY_CARD : TC_TWIC_NEXGEN_CARD;
  munit_assert_int(TC_TWIC_card_identifiers_read(san, card_profile, &limits,
                                                 (TC_TLV_frames){state->parse_frames, 32}, &work,
                                                 &state->identifiers),
                   ==, TC_TLV_OK);
  state->candidates[0] = (TC_bytes){state->issuer, state->issuer_length};
  state->candidates[1] = (TC_bytes){state->root, state->root_length};
  state->source_array = (TC_X509_store_array){state->candidates, 2, &state->anchor, 1};
  munit_assert_int(TC_X509_store_array_source(&state->source_array, &state->source), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_store_prepare(&state->slot, &state->source), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_store_publish(&state->store, 0, &state->slot), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_store_acquire(&state->store, &state->held), ==, TC_TLV_OK);
  state->source = state->held->source;
  state->crls[0] = (TC_bytes){state->root_crl, root_crl_length};
  state->crls[1] = (TC_bytes){state->issuer_crl, issuer_crl_length};
  work = WORK;
  munit_assert_int(TC_X509_crl_index_init(state->crls, 2, &limits, &parser, &work,
                                          state->crl_records, 2, &state->crl_index),
                   ==, TC_TLV_OK);
  state->rsa =
      (TC_RSA_workspace){state->rsa_words, sizeof state->rsa_words / sizeof *state->rsa_words};
  state->native =
      (TC_X509_native_workspace){&state->ec, &state->rsa, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  state->options.signatures = TC_X509_native_provider(&state->native);
  TC_validation_capacity capacities;
  size_t bytes = 0;
  munit_assert_int(TC_validation_capacity_init(TC_VALIDATION_DESKTOP, &capacities), ==,
                   TC_RESULT_OK);
  munit_assert_int(TC_validation_workspace_size(&capacities, &bytes), ==, TC_RESULT_OK);
  munit_assert_size(bytes, <=, sizeof state->arena);
  munit_assert_int(
      TC_validation_workspace_init(
          &capacities, (TC_buffer){(uint8_t*)state->arena, sizeof state->arena}, &state->workspace),
      ==, TC_RESULT_OK);
  static const uint8_t content_signing[] = {0x60, 0x86, 0x48, 1, 0x65, 3, 6, 7};
  state->options.at = (TC_X509_time){2026, 1, 1, 0, 0, 0};
  state->options.parsing = limits;
  state->options.max_certificates = 4;
  state->options.max_input = LIMIT;
  state->options.max_candidates = 8;
  state->options.max_candidate_bytes = LIMIT;
  state->options.certificate.purpose = (TC_bytes){content_signing, sizeof content_signing};
  state->options.certificate.key_usage = TC_KEY_USAGE_DIGITAL_SIGNATURE;
  state->options.certificate.flags = TC_X509_PATH_REQUIRE_KEY_USAGE |
                                     TC_X509_PATH_REQUIRE_EXTENDED_KEY_USAGE |
                                     TC_X509_PATH_INHIBIT_ANY_PURPOSE;
  state->options.crl_signer.key_usage = TC_KEY_USAGE_CRL_SIGN;
  state->options.attributes = TC_CMS_ATTRIBUTES_DER;
  state->options.delta_policy = TC_X509_CRL_COMPLETE_ONLY;
  state->options.order_policy = TC_X509_CRL_ORDER_NUMBER;
  state->trust = (TC_validation_trust){&state->source, &state->crl_index};
  munit_assert_int(TC_validation_context_init(&state->trust, &state->options,
                                              &state->workspace.credential, &state->context),
                   ==, TC_RESULT_OK);
}

static MunitResult validate(const MunitParameter params[], void* user_data)
{
  const char* profile = munit_parameters_get(params, "profile");
  prepare(profile);
  Fixture* state = &fixture;
  TC_PIV_card_profile card_profile =
      !strcmp(profile, "legacy") ? TC_TWIC_LEGACY_CARD : TC_TWIC_NEXGEN_CARD;
  TC_PIV_CHUID_validation_request request = {{state->signed_chuid, state->signed_length},
                                             TC_PIV_CHUID_CONTAINER,
                                             card_profile,
                                             TC_CHUID_PROFILE_TWIC_SIGNED,
                                             0,
                                             &state->identifiers,
                                             &state->card_expiration};
  TC_PIV_CHUID_result chuid;
  size_t work = WORK;
  munit_assert_int(TC_PIV_CHUID_validate(&request, &state->context, &work, &chuid), ==,
                   TC_CREDENTIAL_VALID);
  TC_PIV_biometric_validation_request fingerprint = {
      {state->fingerprint_plain, state->fingerprint_plain_length},
      card_profile,
      chuid.object.fascn,
      chuid.object.card_uuid,
      chuid.signer,
      &state->card_expiration,
      TC_PIV_CMS_BIOMETRIC,
      TC_PIV_CBEFF_FINGERPRINT_TEMPLATE,
      0};
  work = WORK;
  munit_assert_int(TC_PIV_biometric_validate(&fingerprint, &state->context, &work), ==,
                   TC_CREDENTIAL_VALID);

  TC_bytes parts[5];
  TC_PIV_security_data objects[5];
  static const uint16_t legacy_containers[] = {0x3002, 0x3000, 0x2003};
  static const uint16_t nexgen_containers[] = {0x3002, 0x3000, 0x6030, 0x3001, 0x2003};
  const int nexgen = !strcmp(profile, "nexgen");
  const size_t count = nexgen ? 5u : 3u;
  parts[0] = value((TC_bytes){state->unsigned_chuid, state->unsigned_length}, 0x53);
  parts[1] = value((TC_bytes){state->signed_chuid, state->signed_length}, 0x53);
  if (nexgen) {
    parts[2] = value((TC_bytes){state->face, state->face_length}, 0x53);
    parts[3] = (TC_bytes){state->printed_plain, state->printed_plain_length};
    parts[4] = value((TC_bytes){state->fingerprint, state->fingerprint_length}, 0x53);
  } else {
    parts[2] = value((TC_bytes){state->fingerprint, state->fingerprint_length}, 0x53);
  }
  for (size_t i = 0; i < count; ++i) {
    objects[i] =
        (TC_PIV_security_data){(nexgen ? nexgen_containers : legacy_containers)[i], &parts[i], 1};
  }
  TC_PIV_security_validation_request security_request = {{state->security, state->security_length},
                                                         TC_PIV_SECURITY_CONTAINER,
                                                         card_profile,
                                                         chuid.signer,
                                                         &state->card_expiration,
                                                         objects,
                                                         count};
  TC_PIV_security_validation_workspace security_workspace = {state->lds, sizeof state->lds};
  TC_PIV_security_result security;
  work = WORK;
  munit_assert_int(TC_PIV_security_validate(&security_request, &state->context, &security_workspace,
                                            &work, &security),
                   ==, TC_CREDENTIAL_VALID);
  TC_TWIC_unsigned_CHUID_validation_request unsigned_request = {parts[0], TC_PIV_CHUID_CONTENTS,
                                                                card_profile, &state->identifiers};
  work = WORK;
  munit_assert_int(
      TC_TWIC_unsigned_CHUID_validate(&unsigned_request, &security, &state->context, &work), ==,
      TC_CREDENTIAL_VALID);

  TC_bytes piv_fingerprint = first_value(
      value((TC_bytes){state->piv_fingerprint, state->piv_fingerprint_length}, 0x53), 0xbc);
  TC_bytes piv_face =
      first_value(value((TC_bytes){state->piv_face, state->piv_face_length}, 0x53), 0xbc);
  munit_assert_size(piv_fingerprint.length, ==, state->fingerprint_plain_length);
  munit_assert_memory_equal(piv_fingerprint.length, piv_fingerprint.data, state->fingerprint_plain);
  TC_PIV_biometric_validation_request face_request = fingerprint;
  face_request.encoded = piv_face;
  face_request.format = TC_PIV_CBEFF_FACE_IMAGE;
  work = WORK;
  munit_assert_int(TC_PIV_biometric_validate(&face_request, &state->context, &work), ==,
                   TC_CREDENTIAL_VALID);
  static const uint16_t piv_containers[] = {0x3000, 0x6010, 0xdb00, 0x6030, 0x3001};
  TC_bytes piv_parts[5] = {
      value((TC_bytes){state->piv_chuid, state->piv_chuid_length}, 0x53),
      value((TC_bytes){state->piv_fingerprint, state->piv_fingerprint_length}, 0x53),
      value((TC_bytes){state->piv_discovery, state->piv_discovery_length}, 0x53),
      value((TC_bytes){state->piv_face, state->piv_face_length}, 0x53),
      value((TC_bytes){state->piv_printed, state->piv_printed_length}, 0x53)};
  TC_PIV_security_data piv_objects[5];
  for (size_t i = 0; i < 5; ++i)
    piv_objects[i] = (TC_PIV_security_data){piv_containers[i], &piv_parts[i], 1};
  TC_PIV_security_validation_request piv_security = {
      {state->piv_security, state->piv_security_length},
      TC_PIV_SECURITY_CONTAINER,
      card_profile,
      chuid.signer,
      &state->card_expiration,
      piv_objects,
      5};
  work = WORK;
  munit_assert_int(TC_PIV_security_validate(&piv_security, &state->context, &security_workspace,
                                            &work, &security),
                   ==, TC_CREDENTIAL_VALID);

  state->fingerprint_plain[100] ^= 1;
  work = WORK;
  munit_assert_int(TC_PIV_biometric_validate(&fingerprint, &state->context, &work), !=,
                   TC_CREDENTIAL_VALID);
  state->fingerprint_plain[100] ^= 1;
  state->fingerprint[10] ^= 1;
  work = WORK;
  munit_assert_int(TC_PIV_security_validate(&security_request, &state->context, &security_workspace,
                                            &work, &security),
                   !=, TC_CREDENTIAL_VALID);
  state->fingerprint[10] ^= 1;
  state->signed_chuid[40] ^= 1;
  work = WORK;
  munit_assert_int(TC_PIV_CHUID_validate(&request, &state->context, &work, &chuid), !=,
                   TC_CREDENTIAL_VALID);
  state->signed_chuid[40] ^= 1;
  munit_assert_int(TC_X509_store_release(state->held), ==, TC_TLV_OK);
  (void)user_data;
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  static char* profiles[] = {"legacy", "nexgen", NULL};
  MunitParameterEnum parameters[] = {{"profile", profiles}, {NULL, NULL}};
  MunitTest tests[] = {{"/validate", validate, NULL, NULL, MUNIT_TEST_OPTION_NONE, parameters},
                       {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};
  MunitSuite suite = {"/twic/synthetic", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite, NULL, argc, argv);
}
