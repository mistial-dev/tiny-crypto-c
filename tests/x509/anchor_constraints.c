/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/validation.h>
#include <tiny_crypto/x509_crypto.h>
#include <tiny_crypto/x509_trust_anchor.h>
#include "munit.h"
#include "test_util.h"
#include <stdio.h>
#include <string.h>

#ifndef TC_TWIC_SYNTHETIC_ROOT
#error "TC_TWIC_SYNTHETIC_ROOT must name the vendored fixture directory"
#endif

enum { FILE_CAPACITY = 20000 };
static uint8_t issuer_der[FILE_CAPACITY], card_der[FILE_CAPACITY], anchors_der[FILE_CAPACITY];
static uint8_t piv_der[FILE_CAPACITY], root_der[FILE_CAPACITY];
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

/* DER tag and length followed by value into capacity bytes at out. out may
 * alias value. */
static size_t der(uint8_t* out, size_t capacity, unsigned tag, const uint8_t* value, size_t length)
{
  const size_t header = length < 128 ? 2 : length < 256 ? 3 : 4;
  munit_assert_size(length, <, 65536);
  munit_assert_size(capacity, >=, header + length);
  memmove(out + header, value, length);
  out[0] = (uint8_t)tag;
  if (header == 2) {
    out[1] = (uint8_t)length;
  } else if (header == 3) {
    out[1] = 0x81;
    out[2] = (uint8_t)length;
  } else {
    out[1] = 0x82;
    out[2] = (uint8_t)(length >> 8);
    out[3] = (uint8_t)length;
  }
  return header + length;
}

/* One critical Extension for id-ce id (2.5.29.id) with the given value. */
static size_t critical_extension(uint8_t* out, size_t capacity, unsigned id, const uint8_t* value,
                                 size_t length)
{
  uint8_t body[FILE_CAPACITY];
  const uint8_t prefix[] = {6, 3, 0x55, 0x1d, (uint8_t)id, 1, 1, 0xff};
  size_t n = sizeof prefix;
  memcpy(body, prefix, n);
  n += der(body + n, sizeof body - n, 0x04, value, length);
  return der(out, capacity, 0x30, body, n);
}

/* nameConstraints excluding directoryName subtrees under name. */
static size_t excluding_name(uint8_t* out, size_t capacity, TC_bytes name)
{
  uint8_t value[FILE_CAPACITY];
  size_t n = der(value, sizeof value, 0xa4, name.data, name.length);
  n = der(value, sizeof value, 0x30, value, n);
  n = der(value, sizeof value, 0xa1, value, n);
  n = der(value, sizeof value, 0x30, value, n);
  return critical_extension(out, capacity, 30, value, n);
}

/* A caller-built anchor carries its certificate's path controls only through
 * the normalized record fields. certificate_extensions holding a control
 * whose field is empty fails closed. TC_X509_store_anchor_from_certificate
 * fills those fields, so the same constraint then rejects the path. */
static void check_certificate_controls(const char* profile, const TC_bytes* chain,
                                       const TC_X509_store_anchor* anchor,
                                       const TC_X509_path_options* options,
                                       const TC_X509_path_workspace* workspace)
{
  static const uint8_t policies[] = {0x30, 8, 0x30, 6, 6, 4, 0x55, 0x1d, 0x20, 0};
  static const uint8_t explicit_policy[] = {0x30, 3, 0x80, 1, 0};
  static const uint8_t inhibit_any[] = {2, 1, 0};
  static const uint8_t path_zero[] = {0x30, 6, 1, 1, 0xff, 2, 1, 0};
  const TC_TLV_limits limits = options->parsing;
  TC_TLV_frame frames[32];
  TC_bytes oids[32];
  TC_X509_workspace parser = {{frames, 32}, oids, 32};
  TC_X509_certificate issuer, root;
  TC_X509_store_anchor bare = {0}, built;
  TC_X509_path_report result;
  uint8_t extension[FILE_CAPACITY], list[FILE_CAPACITY];
  size_t length;
  const TC_bytes encoded_root = fixture(profile, "root.der", root_der);
  munit_assert_int(TC_X509_read(chain[0], &limits, &parser, &issuer), ==, TC_TLV_OK);
  bare.trust = anchor->trust;
  munit_assert_int(TC_X509_path_validate_with_anchor(chain, 2, &bare, options, workspace, &result),
                   ==, TC_X509_PATH_VALID);
  length = excluding_name(extension, sizeof extension, issuer.subject);
  bare.certificate_extensions = (TC_bytes){extension, length};
  munit_assert_int(TC_X509_path_validate_with_anchor(chain, 2, &bare, options, workspace, &result),
                   ==, TC_X509_PATH_UNSUPPORTED);
  {
    const struct {
      unsigned id;
      const uint8_t* value;
      size_t length;
    } controls[] = {{32, policies, sizeof policies},
                    {36, explicit_policy, sizeof explicit_policy},
                    {54, inhibit_any, sizeof inhibit_any},
                    {19, path_zero, sizeof path_zero}};
    for (size_t i = 0; i < sizeof controls / sizeof *controls; ++i) {
      TC_bytes control;
      control.length = critical_extension(extension, sizeof extension, controls[i].id,
                                          controls[i].value, controls[i].length);
      control.data = extension;
      bare.certificate_extensions = control;
      munit_assert_int(
          TC_X509_path_validate_with_anchor(chain, 2, &bare, options, workspace, &result), ==,
          TC_X509_PATH_UNSUPPORTED);
    }
  }
  /* A TrustAnchorInfo exts basicConstraints pathLen can only lower path_len
   * (RFC 5914 section 2.5). A record whose path_len misses it fails closed. */
  {
    /* Extension { basicConstraints, OCTET STRING { cA TRUE, pathLen n } } */
    uint8_t basic[] = {0x30, 15, 6, 3, 0x55, 0x1d, 19, 4, 8, 0x30, 6, 1, 1, 0xff, 2, 1, 1};
    const struct {
      uint8_t exts_path_len, has_path_len;
      size_t path_len;
      TC_X509_path_status expected;
    } cases[] = {{1, 0, 0, TC_X509_PATH_UNSUPPORTED},
                 {1, 1, 2, TC_X509_PATH_UNSUPPORTED},
                 {1, 1, 1, TC_X509_PATH_VALID},
                 {5, 1, 1, TC_X509_PATH_VALID},
                 {0, 1, 0, TC_X509_PATH_INVALID}};
    bare.certificate_extensions = (TC_bytes){NULL, 0};
    bare.extensions = (TC_bytes){basic, sizeof basic};
    for (size_t i = 0; i < sizeof cases / sizeof *cases; ++i) {
      basic[sizeof basic - 1] = cases[i].exts_path_len;
      bare.has_path_len = cases[i].has_path_len;
      bare.path_len = cases[i].path_len;
      munit_assert_int(
          TC_X509_path_validate_with_anchor(chain, 2, &bare, options, workspace, &result), ==,
          cases[i].expected);
    }
    bare.extensions = (TC_bytes){NULL, 0};
    bare.has_path_len = 0;
    bare.path_len = 0;
  }
  /* The builder normalizes the anchor certificate itself. */
  munit_assert_int(TC_X509_read(encoded_root, &limits, &parser, &root), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_store_anchor_from_certificate(&root, &limits, &parser, &built), ==,
                   TC_TLV_OK);
  munit_assert_int(TC_X509_path_validate_with_anchor(chain, 2, &built, options, workspace, &result),
                   ==, TC_X509_PATH_VALID);
  length = excluding_name(list, sizeof list, issuer.subject);
  root.extensions = (TC_bytes){list, der(list, sizeof list, 0x30, list, length)};
  munit_assert_int(TC_X509_store_anchor_from_certificate(&root, &limits, &parser, &built), ==,
                   TC_TLV_OK);
  munit_assert_size(built.names.excluded.length, >, 0);
  munit_assert_int(TC_X509_path_validate_with_anchor(chain, 2, &built, options, workspace, &result),
                   ==, TC_X509_PATH_INVALID);
}

/* Append value to out at *length. */
static void append(uint8_t* out, size_t* length, TC_bytes value)
{
  munit_assert_size(value.length, <=, FILE_CAPACITY - *length);
  memcpy(out + *length, value.data, value.length);
  *length += value.length;
}

/* TrustAnchorList with one TrustAnchorInfo for root (RFC 5914 section 2).
 * CertPathControls embeds root with extension appended to its extensions,
 * followed by the encoded fields in controls. The embedded signature no
 * longer matches, and the reader does not verify it. */
static TC_bytes anchor_list_with(uint8_t* out, const TC_X509_certificate* root, TC_bytes key_id,
                                 TC_bytes extension, TC_bytes controls, const TC_TLV_limits* limits)
{
  static uint8_t body[FILE_CAPACITY], part[FILE_CAPACITY];
  TC_TLV_element certificate, tbs, extensions, child;
  TC_TLV_reader fields;
  size_t length = 0, part_length = 0;
  munit_assert_int(TC_TLV_read(root->encoded, TC_TLV_DER, limits, &certificate), ==, TC_TLV_OK);
  munit_assert_int(TC_TLV_read(root->tbs, TC_TLV_DER, limits, &tbs), ==, TC_TLV_OK);
  munit_assert_int(TC_TLV_read(root->extensions, TC_TLV_DER, limits, &extensions), ==, TC_TLV_OK);
  /* TBSCertificate fields before extensions [3], then the extended list. */
  munit_assert_int(TC_TLV_reader_init(&fields, tbs.value, TC_TLV_DER, limits), ==, TC_TLV_OK);
  while (TC_TLV_next(&fields, &child) == TC_TLV_OK && child.header.tag[0] != 0xa3)
    append(body, &length, child.encoded);
  append(part, &part_length, extensions.value);
  append(part, &part_length, extension);
  part_length = der(part, sizeof part, 0x30, part, part_length);
  part_length = der(part, sizeof part, 0xa3, part, part_length);
  append(body, &length, (TC_bytes){part, part_length});
  length = der(body, sizeof body, 0x30, body, length);
  /* signatureAlgorithm and signatureValue follow the TBSCertificate. */
  append(body, &length,
         (TC_bytes){root->tbs.data + root->tbs.length,
                    (size_t)(certificate.value.data + certificate.value.length -
                             (root->tbs.data + root->tbs.length))});
  length = der(body, sizeof body, 0xa0, body, length);
  part_length = 0;
  append(part, &part_length, root->subject);
  append(part, &part_length, (TC_bytes){body, length});
  append(part, &part_length, controls);
  part_length = der(part, sizeof part, 0x30, part, part_length);
  length = 0;
  append(body, &length, root->spki);
  length += der(body + length, sizeof body - length, 0x04, key_id.data, key_id.length);
  append(body, &length, (TC_bytes){part, part_length});
  length = der(body, sizeof body, 0x30, body, length);
  length = der(body, sizeof body, 0xa2, body, length);
  length = der(body, sizeof body, 0x30, body, length);
  memcpy(out, body, length);
  return (TC_bytes){out, length};
}

/* RFC 5914 section 2.5: CertPathControls policyFlags replace the embedded
 * certificate's policyConstraints and inhibitAnyPolicy, even when they clear
 * a flag the certificate sets. The record marks the replacement, so the
 * certificate control is neither enforced nor reported as dropped. */
static void check_replaced_controls(const TC_bytes* chain, const TC_bytes encoded_root,
                                    const TC_X509_path_options* options,
                                    const TC_X509_path_workspace* workspace)
{
  static const uint8_t explicit_policy[] = {0x30, 3, 0x80, 1, 0};
  static const uint8_t inhibit_any[] = {2, 1, 0};
  static const uint8_t cleared_flags[] = {0x82, 1, 0};
  static uint8_t list[FILE_CAPACITY];
  const TC_TLV_limits limits = options->parsing;
  TC_TLV_frame frames[32];
  TC_bytes oids[32];
  TC_X509_workspace parser = {{frames, 32}, oids, 32};
  TC_X509_certificate root;
  TC_X509_store_anchor built, anchor;
  TC_X509_path_report result;
  TC_X509_trust_anchor_reader reader;
  uint8_t extension[64];
  munit_assert_int(TC_X509_read(encoded_root, &limits, &parser, &root), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_store_anchor_from_certificate(&root, &limits, &parser, &built), ==,
                   TC_TLV_OK);
  const struct {
    unsigned id;
    const uint8_t* value;
    size_t length;
    unsigned flag;
  } controls[] = {
      {36, explicit_policy, sizeof explicit_policy, TC_X509_PATH_REQUIRE_EXPLICIT_POLICY},
      {54, inhibit_any, sizeof inhibit_any, TC_X509_PATH_INHIBIT_ANY_POLICY}};
  for (size_t i = 0; i < sizeof controls / sizeof *controls; ++i) {
    const TC_bytes control = {extension,
                              critical_extension(extension, sizeof extension, controls[i].id,
                                                 controls[i].value, controls[i].length)};
    for (int replaced = 0; replaced < 2; ++replaced) {
      const TC_bytes fields =
          replaced ? (TC_bytes){cleared_flags, sizeof cleared_flags} : (TC_bytes){NULL, 0};
      const TC_bytes encoded =
          anchor_list_with(list, &root, built.key_id, control, fields, &limits);
      munit_assert_int(TC_X509_trust_anchor_list_init(&reader, encoded, &limits, &parser), ==,
                       TC_TLV_OK);
      munit_assert_int(TC_X509_trust_anchor_next(&reader, &anchor), ==, TC_TLV_OK);
      if (replaced) {
        munit_assert_uint(anchor.policy_flags, ==, 0);
        munit_assert_uint(anchor.replaced_controls, ==, TC_X509_ANCHOR_REPLACED_POLICY_FLAGS);
        munit_assert_int(
            TC_X509_path_validate_with_anchor(chain, 2, &anchor, options, workspace, &result), ==,
            TC_X509_PATH_VALID);
        /* A caller-built record without the marker keeps the certificate
         * control unenforced, so it fails closed. */
        anchor.replaced_controls = 0;
        munit_assert_int(
            TC_X509_path_validate_with_anchor(chain, 2, &anchor, options, workspace, &result), ==,
            TC_X509_PATH_UNSUPPORTED);
        anchor.replaced_controls = 1u << 4;
        munit_assert_int(
            TC_X509_path_validate_with_anchor(chain, 2, &anchor, options, workspace, &result), ==,
            TC_X509_PATH_ERROR);
      } else {
        munit_assert_uint(anchor.policy_flags, ==, controls[i].flag);
        munit_assert_uint(anchor.replaced_controls, ==, 0);
      }
    }
  }
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
  TC_X509_workspace parser = {{parse_frames, 32}, parse_oids, 32};
  TC_X509_trust_anchor_reader list;
  TC_X509_store_anchor anchor, options_anchor[2];
  TC_X509_native_workspace native;
  TC_RSA_workspace rsa = {rsa_words, sizeof rsa_words / sizeof *rsa_words};
  TC_validation_capacity capacity;
  TC_validation_workspace storage;
  TC_X509_path_options options = {0};
  TC_X509_path_report result;
  TC_X509_search_report found;
  TC_X509_search_frame frames[3];
  TC_X509_search_workspace search;
  TC_X509_store_array array;
  TC_X509_store_source source;
  TC_bytes discovered[3];
  size_t bytes;
  static const uint8_t unknown_critical[] = {0x30, 12, 6, 3, 0x2a, 3, 99, 1, 1, 0xff, 4, 2, 5, 0};
  munit_assert_int(TC_X509_trust_anchor_list_init(&list, encoded, &limits, &parser), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_trust_anchor_next(&list, &anchor), ==, TC_TLV_OK);
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
  /* RFC 5914 section 2.6: nameConstraints, certificatePolicies,
   * policyConstraints and inhibitAnyPolicy must not appear in
   * TrustAnchorInfo exts. A caller-built anchor carrying one is rejected, so
   * a constraint is never silently dropped. */
  {
    static const uint8_t ids[] = {30, 32, 36, 54};
    for (size_t i = 0; i < sizeof ids; ++i)
      for (int critical = 0; critical < 2; ++critical) {
        uint8_t forbidden[] = {0x30, 12, 6, 3, 0x55, 0x1d, 0, 1, 1, 0xff, 4, 2, 0x30, 0};
        size_t length = sizeof forbidden;
        forbidden[6] = ids[i];
        if (!critical) {
          memmove(forbidden + 7, forbidden + 10, 4);
          forbidden[1] = 9;
          length -= 3;
        }
        options_anchor[0] = anchor;
        options_anchor[0].extensions = (TC_bytes){forbidden, length};
        munit_assert_int(TC_X509_path_validate_with_anchor(chain, 2, options_anchor, &options,
                                                           &storage.path.validation, &result),
                         ==, TC_X509_PATH_INVALID);
      }
  }
  /* RFC 5280 section 4.2.1.10 requires minimum zero and no maximum. The
   * validator does not implement distances, so a subtree that sets one is
   * UNSUPPORTED wherever it comes from, even when its name form does not
   * occur in the path. */
  {
    static const uint8_t distant[] = {0x30, 6, 0x82, 1, 'x', 0x80, 1, 1};
    const TC_X509_name_constraints distance = {{NULL, 0}, {distant, sizeof distant}};
    options.anchor_names = distance;
    munit_assert_int(TC_X509_path_validate_with_anchor(chain, 2, &anchor, &options,
                                                       &storage.path.validation, &result),
                     ==, TC_X509_PATH_UNSUPPORTED);
    memset(&options.anchor_names, 0, sizeof options.anchor_names);
    options_anchor[0] = anchor;
    options_anchor[0].names = distance;
    munit_assert_int(TC_X509_path_validate_with_anchor(chain, 2, options_anchor, &options,
                                                       &storage.path.validation, &result),
                     ==, TC_X509_PATH_UNSUPPORTED);
  }
  options_anchor[0] = anchor;
  options_anchor[0].certificate_extensions = (TC_bytes){unknown_critical, sizeof unknown_critical};
  munit_assert_int(TC_X509_path_validate_with_anchor(chain, 2, options_anchor, &options,
                                                     &storage.path.validation, &result),
                   ==, TC_X509_PATH_UNSUPPORTED);
  check_certificate_controls(profile, chain, &anchor, &options, &storage.path.validation);
  check_replaced_controls(chain, fixture(profile, "root.der", root_der), &options,
                          &storage.path.validation);
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
  /* A returned policy may borrow the anchor's policy_set, so that span must
   * stay separate from the search result. */
  memset(&found, 0, sizeof found);
  options_anchor[1] = anchor;
  options_anchor[1].policy_set = (TC_bytes){(const uint8_t*)&found, sizeof found};
  munit_assert_int(
      TC_X509_path_build(card, &source, &options, &storage.path.validation, &search, &found), ==,
      TC_X509_PATH_ERROR);
}

TC_TEST(anchor_constraints)
{
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
