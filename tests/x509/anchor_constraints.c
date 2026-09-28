/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/validation.h>
#include <tiny_crypto/x509_crypto.h>
#include <tiny_crypto/x509_trust_anchor.h>
#include "munit.h"
#include <stdio.h>
#include <string.h>

#ifndef TC_TWIC_SYNTHETIC_ROOT
#error "TC_TWIC_SYNTHETIC_ROOT must name the vendored fixture directory"
#endif

enum { FILE_CAPACITY = 20000 };
static uint8_t issuer_der[FILE_CAPACITY], card_der[FILE_CAPACITY], anchors_der[FILE_CAPACITY];
static uint8_t piv_der[FILE_CAPACITY];
static TC_validation_storage arena[40000];
static TC_RSA_word rsa_words[TC_RSA_VERIFY_WORKSPACE_WORDS(3072)];
static TC_ECDSA_workspace ec;

static TC_bytes fixture(const char* profile, const char* name, uint8_t* buffer)
{
  char path[512];
  FILE* file;
  size_t length;
  munit_assert_int(snprintf(path, sizeof path, "%s/%s/%s", TC_TWIC_SYNTHETIC_ROOT, profile, name),
                   >, 0);
  file = fopen(path, "rb");
  munit_assert_not_null(file);
  length = fread(buffer, 1, FILE_CAPACITY, file);
  munit_assert_int(ferror(file), ==, 0);
  munit_assert_int(fgetc(file), ==, EOF);
  munit_assert_int(fclose(file), ==, 0);
  munit_assert_size(length, >, 0);
  return (TC_bytes){buffer, length};
}

static void check_profile(const char* profile)
{
  const TC_TLV_limits limits = {FILE_CAPACITY, FILE_CAPACITY, 512, 16};
  TC_bytes issuer = fixture(profile, "issuer.der", issuer_der);
  TC_bytes card = fixture(profile, "card.der", card_der);
  TC_bytes encoded = fixture(profile, "trust-anchors.der", anchors_der);
  TC_bytes chain[] = {issuer, card};
  TC_bytes candidates[] = {issuer};
  TC_TLV_frame parse_frames[32];
  TC_bytes parse_oids[32];
  TC_X509_workspace parser = {parse_frames, 32, parse_oids, 32};
  TC_TLV_reader list;
  TC_X509_store_anchor anchor, options_anchor[2];
  TC_X509_native_workspace native;
  TC_RSA_workspace rsa = {rsa_words, sizeof rsa_words / sizeof *rsa_words};
  TC_validation_capacity capacity;
  TC_validation_workspace storage;
  TC_X509_path_options options = {0};
  TC_X509_path_result result;
  TC_X509_search_result found;
  TC_X509_search_frame frames[3];
  TC_X509_search_workspace search;
  TC_X509_store_array array;
  TC_X509_store_source source;
  TC_bytes discovered[3];
  size_t bytes;
  static const uint8_t unknown_critical[] = {0x30, 12, 6, 3, 0x2a, 3, 99, 1, 1, 0xff, 4, 2, 5, 0};
  munit_assert_int(
      TC_X509_trust_anchor_list_init(&list, encoded.data, encoded.length, &limits, &parser), ==,
      TC_TLV_OK);
  munit_assert_int(TC_X509_trust_anchor_next(&list, &limits, &parser, &anchor), ==, TC_TLV_OK);
  munit_assert_int(anchor.x509_unusable, ==, 0);
  munit_assert_int(TC_validation_capacity_init(TC_VALIDATION_DESKTOP, &capacity), ==, TC_RESULT_OK);
  munit_assert_int(TC_validation_workspace_size(&capacity, &bytes), ==, TC_RESULT_OK);
  munit_assert_size(bytes, <=, sizeof arena);
  munit_assert_int(
      TC_validation_workspace_init(&capacity, (TC_buffer){(uint8_t*)arena, sizeof arena}, &storage),
      ==, TC_RESULT_OK);
  native = (TC_X509_native_workspace){&ec, &rsa, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  options.at = (TC_X509_time){2026, 1, 1, 0, 0, 0};
  options.parsing = limits;
  options.max_certificates = 4;
  options.max_input = FILE_CAPACITY;
  options.max_work = 2000000;
  options.signatures = TC_X509_native_provider(&native);
  munit_assert_int(TC_X509_path_validate_with_anchor(chain, 2, &anchor, &options,
                                                     &storage.path.validation, &result),
                   ==, TC_X509_PATH_VALID);
  options_anchor[0] = anchor;
  options_anchor[0].has_path_len = 1;
  options_anchor[0].path_len = 0;
  munit_assert_int(TC_X509_path_validate_with_anchor(chain, 2, options_anchor, &options,
                                                     &storage.path.validation, &result),
                   ==, TC_X509_PATH_INVALID);
  /* The card's PIV Authentication certificate chains to the same constrained
   * anchor, and the anchor's path length applies to it too. */
  {
    const TC_bytes piv_chain[] = {issuer, fixture(profile, "piv-auth.der", piv_der)};
    munit_assert_int(TC_X509_path_validate_with_anchor(piv_chain, 2, &anchor, &options,
                                                       &storage.path.validation, &result),
                     ==, TC_X509_PATH_VALID);
    munit_assert_int(TC_X509_path_validate_with_anchor(piv_chain, 2, options_anchor, &options,
                                                       &storage.path.validation, &result),
                     ==, TC_X509_PATH_INVALID);
  }
  options_anchor[0] = anchor;
  options_anchor[0].extensions = (TC_bytes){unknown_critical, sizeof unknown_critical};
  munit_assert_int(TC_X509_path_validate_with_anchor(chain, 2, options_anchor, &options,
                                                     &storage.path.validation, &result),
                   ==, TC_X509_PATH_UNSUPPORTED);
  options_anchor[0] = anchor;
  options_anchor[0].certificate_extensions = (TC_bytes){unknown_critical, sizeof unknown_critical};
  munit_assert_int(TC_X509_path_validate_with_anchor(chain, 2, options_anchor, &options,
                                                     &storage.path.validation, &result),
                   ==, TC_X509_PATH_UNSUPPORTED);
  options_anchor[0] = anchor;
  options_anchor[0].has_path_len = 1;
  options_anchor[0].path_len = 0;
  options_anchor[1] = anchor;
  array = (TC_X509_store_array){candidates, 1, options_anchor, 2};
  munit_assert_int(TC_X509_store_array_source(&array, &source), ==, TC_TLV_OK);
  search = (TC_X509_search_workspace){discovered, frames, 3};
  munit_assert_int(
      TC_X509_path_build(card, &source, &options, &storage.path.validation, &search, &found), ==,
      TC_X509_PATH_VALID);
  munit_assert_size(found.anchor_index, ==, 1);
  options_anchor[1].path_len = 0;
  munit_assert_int(
      TC_X509_path_build(card, &source, &options, &storage.path.validation, &search, &found), ==,
      TC_X509_PATH_INVALID);
}

static MunitResult anchor_constraints(const MunitParameter params[], void* user)
{
  (void)params;
  (void)user;
  check_profile("legacy");
  check_profile("nexgen");
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/x509/anchor/constraints", anchor_constraints, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, 0, NULL}};
static const MunitSuite suite = {"", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
