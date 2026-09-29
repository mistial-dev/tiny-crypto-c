/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * RFC 5914 trust-anchor controls applied through RFC 5937 path
 * initialization, checked against NIST PKITS paths from the vendored corpus.
 * The anchor is the PKITS Trust Anchor. Its policy set, policy flags, name
 * constraints and path length constrain each path, both as a store record
 * and as a TrustAnchorInfo decoded from DER. */
#include <tiny_crypto/validation.h>
#include <tiny_crypto/x509_crypto.h>
#include <tiny_crypto/x509_trust_anchor.h>
#include "../../src/x509_path_internal.h"
#include "munit.h"
#include <stdio.h>
#include <string.h>

#ifndef TC_PKITS_DIR
#error "TC_PKITS_DIR must name the vendored PKITS certificate directory"
#endif

enum { FILE_CAPACITY = 4096, CHAIN = 2 };

static const TC_TLV_limits limits = {FILE_CAPACITY, FILE_CAPACITY, 512, 16};
static uint8_t anchor_der[FILE_CAPACITY], chain_der[CHAIN][FILE_CAPACITY];
static TC_validation_storage arena[40000];
static TC_validation_workspace storage;
static TC_RSA_word rsa_words[TC_RSA_VERIFY_WORKSPACE_WORDS(2048)];
static TC_ECDSA_workspace ec;
static TC_X509_native_workspace native;
static TC_TLV_frame parse_frames[32];
static TC_bytes parse_oids[32];
static TC_X509_workspace parser = {{parse_frames, 32}, parse_oids, 32};

/* NIST-test-policy-1 and -2 (2.16.840.1.101.3.2.1.48.1, .2) and anyPolicy. */
static const uint8_t policy1[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x02, 0x01, 0x30, 0x01};
static const uint8_t policy2[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x02, 0x01, 0x30, 0x02};
static const uint8_t any_policy[] = {0x55, 0x1d, 0x20, 0x00};

/* The first two RDNs of every PKITS name: C=US, O=Test Certificates 2011. */
static const uint8_t pkits_rdns[] = {
    0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x1f, 0x30,
    0x1d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x16, 'T',  'e',  's',  't',  ' ',  'C',  'e',  'r',
    't',  'i',  'f',  'i',  'c',  'a',  't',  'e',  's',  ' ',  '2',  '0',  '1',  '1'};
/* C=US, O=Other Certificates. */
static const uint8_t other_rdns[] = {
    0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
    0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x12, 'O',  't',  'h',  'e',
    'r',  ' ',  'C',  'e',  'r',  't',  'i',  'f',  'i',  'c',  'a',  't',  'e',  's'};

static TC_bytes load(const char* name, uint8_t* buffer)
{
  char path[512];
  FILE* file;
  size_t length;
  munit_assert_int(snprintf(path, sizeof path, "%s/%s", TC_PKITS_DIR, name), >, 0);
  file = fopen(path, "rb");
  munit_assert_not_null(file);
  length = fread(buffer, 1, FILE_CAPACITY, file);
  munit_assert_int(ferror(file), ==, 0);
  munit_assert_int(fgetc(file), ==, EOF);
  munit_assert_int(fclose(file), ==, 0);
  return (TC_bytes){buffer, length};
}

/* DER tag and length, with one or two length bytes, followed by value. */
static size_t der(TC_buffer output, unsigned tag, const uint8_t* value, size_t length)
{
  uint8_t* out = output.data;
  size_t header = 2;
  munit_assert_size(length, <, 65536);
  munit_assert_size(output.capacity, >=, (length < 128 ? 2 : length < 256 ? 3 : 4) + length);
  out[0] = (uint8_t)tag;
  if (length < 128) {
    out[1] = (uint8_t)length;
  } else if (length < 256) {
    out[1] = 0x81;
    out[2] = (uint8_t)length;
    header = 3;
  } else {
    out[1] = 0x82;
    out[2] = (uint8_t)(length >> 8);
    out[3] = (uint8_t)length;
    header = 4;
  }
  memmove(out + header, value, length);
  return header + length;
}

/* One GeneralSubtree whose base is directoryName(Name of rdns). */
static size_t directory_subtree(TC_buffer out, const uint8_t* rdns, size_t length)
{
  uint8_t name[128], base[132];
  const size_t name_length = der((TC_buffer){name, sizeof name}, 0x30, rdns, length);
  const size_t base_length = der((TC_buffer){base, sizeof base}, 0xa4, name, name_length);
  return der(out, 0x30, base, base_length);
}

static TC_X509_path_options path_options(unsigned flags)
{
  TC_X509_path_options options = {0};
  options.at = (TC_X509_time){2020, 1, 1, 0, 0, 0};
  options.parsing = limits;
  options.max_certificates = 4;
  options.max_input = 2 * FILE_CAPACITY;
  options.max_work = 4000000;
  options.flags = flags;
  options.signatures = TC_X509_native_provider(&native);
  return options;
}

/* The PKITS Trust Anchor as an unconstrained store record. */
static TC_X509_store_anchor pkits_anchor(void)
{
  TC_X509_certificate certificate;
  TC_X509_store_anchor anchor = {0};
  const TC_bytes encoded = load("TrustAnchorRootCertificate.crt", anchor_der);
  munit_assert_int(TC_X509_read(encoded, &limits, &parser, &certificate), ==, TC_TLV_OK);
  anchor.trust.name = certificate.subject;
  anchor.trust.public_key = certificate.public_key;
  return anchor;
}

static TC_X509_path_status validate(const char* ca, const char* ee,
                                    const TC_X509_store_anchor* anchor,
                                    const TC_X509_path_options* options,
                                    TC_X509_path_result* result)
{
  const TC_bytes chain[CHAIN] = {load(ca, chain_der[0]), load(ee, chain_der[1])};
  return TC_X509_path_validate_with_anchor(chain, CHAIN, anchor, options, &storage.path.validation,
                                           result);
}

static void setup_workspace(void)
{
  static TC_RSA_workspace rsa;
  TC_validation_capacity capacity;
  size_t bytes;
  rsa = (TC_RSA_workspace){rsa_words, sizeof rsa_words / sizeof *rsa_words};
  native = (TC_X509_native_workspace){&ec, &rsa, TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  munit_assert_int(TC_validation_capacity_init(TC_VALIDATION_DESKTOP, &capacity), ==, TC_RESULT_OK);
  munit_assert_int(TC_validation_workspace_size(&capacity, &bytes), ==, TC_RESULT_OK);
  munit_assert_size(bytes, <=, sizeof arena);
  munit_assert_int(
      TC_validation_workspace_init(&capacity, (TC_buffer){(uint8_t*)arena, sizeof arena}, &storage),
      ==, TC_RESULT_OK);
}

/* CertificatePolicies contents with one PolicyInformation for oid. This is
 * the form of TC_X509_store_anchor.policy_set and of the IMPLICIT
 * CertPathControls.policySet value. */
static size_t policy_set(TC_buffer out, const uint8_t* oid, size_t length)
{
  uint8_t element[32];
  const size_t element_length = der((TC_buffer){element, sizeof element}, 0x06, oid, length);
  return der(out, 0x30, element, element_length);
}

static MunitResult policies(const MunitParameter params[], void* user)
{
  static uint8_t set1[64], set2[64], set_any[64];
  const TC_bytes initial1[] = {{policy1, sizeof policy1}};
  TC_X509_store_anchor anchor = pkits_anchor();
  TC_X509_path_options options = path_options(0);
  TC_X509_path_result result;
  (void)params;
  (void)user;
  setup_workspace();

  /* 4.1.1: the unconstrained anchor accepts the path. With no initial
   * policies the user-initial-policy-set is {anyPolicy} (RFC 5280 section
   * 6.1.1 (c)), so the path's policy is selected and an explicit policy
   * requirement is met. */
  munit_assert_int(
      validate("GoodCACert.crt", "ValidCertificatePathTest1EE.crt", &anchor, &options, &result), ==,
      TC_X509_PATH_VALID);
  munit_assert_size(result.policy_count, ==, 1);
  munit_assert_memory_equal(sizeof policy1, result.policies[0].data, policy1);
  options.flags = TC_X509_PATH_REQUIRE_EXPLICIT_POLICY;
  munit_assert_int(
      validate("GoodCACert.crt", "ValidCertificatePathTest1EE.crt", &anchor, &options, &result), ==,
      TC_X509_PATH_VALID);
  munit_assert_size(result.policy_count, ==, 1);
  options = path_options(0);

  /* The anchor's policy set limits the acceptable policies. */
  anchor.policy_flags = TC_X509_PATH_REQUIRE_EXPLICIT_POLICY;
  anchor.policy_set =
      (TC_bytes){set1, policy_set((TC_buffer){set1, sizeof set1}, policy1, sizeof policy1)};
  munit_assert_int(
      validate("GoodCACert.crt", "ValidCertificatePathTest1EE.crt", &anchor, &options, &result), ==,
      TC_X509_PATH_VALID);
  munit_assert_size(result.policy_count, ==, 1);
  munit_assert_memory_equal(sizeof policy1, result.policies[0].data, policy1);
  anchor.policy_set =
      (TC_bytes){set2, policy_set((TC_buffer){set2, sizeof set2}, policy2, sizeof policy2)};
  munit_assert_int(
      validate("GoodCACert.crt", "ValidCertificatePathTest1EE.crt", &anchor, &options, &result), ==,
      TC_X509_PATH_INVALID);
  anchor.policy_set = (TC_bytes){
      set_any, policy_set((TC_buffer){set_any, sizeof set_any}, any_policy, sizeof any_policy)};
  munit_assert_int(
      validate("GoodCACert.crt", "ValidCertificatePathTest1EE.crt", &anchor, &options, &result), ==,
      TC_X509_PATH_VALID);

  /* The anchor set intersects the application's initial set. */
  anchor.policy_set =
      (TC_bytes){set2, policy_set((TC_buffer){set2, sizeof set2}, policy2, sizeof policy2)};
  anchor.policy_flags = 0;
  options.initial_policies = initial1;
  options.initial_policy_count = 1;
  munit_assert_int(
      validate("GoodCACert.crt", "ValidCertificatePathTest1EE.crt", &anchor, &options, &result), ==,
      TC_X509_PATH_VALID);
  munit_assert_size(result.policy_count, ==, 0);
  options.flags = TC_X509_PATH_REQUIRE_EXPLICIT_POLICY;
  munit_assert_int(
      validate("GoodCACert.crt", "ValidCertificatePathTest1EE.crt", &anchor, &options, &result), ==,
      TC_X509_PATH_INVALID);
  options = path_options(0);

  /* 4.10.1: the path relies on mapping policy1 to policy2, which the
   * anchor's inhibitPolicyMapping flag forbids. */
  anchor.policy_set =
      (TC_bytes){set1, policy_set((TC_buffer){set1, sizeof set1}, policy1, sizeof policy1)};
  anchor.policy_flags = TC_X509_PATH_REQUIRE_EXPLICIT_POLICY;
  munit_assert_int(validate("Mapping1to2CACert.crt", "ValidPolicyMappingTest1EE.crt", &anchor,
                            &options, &result),
                   ==, TC_X509_PATH_VALID);
  anchor.policy_flags |= TC_X509_PATH_INHIBIT_MAPPING;
  munit_assert_int(validate("Mapping1to2CACert.crt", "ValidPolicyMappingTest1EE.crt", &anchor,
                            &options, &result),
                   ==, TC_X509_PATH_INVALID);

  /* 4.8.14: the CA asserts only anyPolicy and requires an explicit policy.
   * With initial-policy-set = {policy1} the path validates, and the anchor's
   * inhibitAnyPolicy flag leaves no valid policy. */
  anchor.policy_set = (TC_bytes){NULL, 0};
  anchor.policy_flags = 0;
  options.initial_policies = initial1;
  options.initial_policy_count = 1;
  munit_assert_int(
      validate("anyPolicyCACert.crt", "AnyPolicyTest14EE.crt", &anchor, &options, &result), ==,
      TC_X509_PATH_VALID);
  anchor.policy_flags = TC_X509_PATH_INHIBIT_ANY_POLICY;
  munit_assert_int(
      validate("anyPolicyCACert.crt", "AnyPolicyTest14EE.crt", &anchor, &options, &result), ==,
      TC_X509_PATH_INVALID);
  return MUNIT_OK;
}

static MunitResult names(const MunitParameter params[], void* user)
{
  static uint8_t pkits[80], other[80];
  const TC_bytes pkits_subtree = {
      pkits, directory_subtree((TC_buffer){pkits, sizeof pkits}, pkits_rdns, sizeof pkits_rdns)};
  const TC_bytes other_subtree = {
      other, directory_subtree((TC_buffer){other, sizeof other}, other_rdns, sizeof other_rdns)};
  TC_X509_store_anchor anchor = pkits_anchor();
  TC_X509_path_options options = path_options(0);
  TC_X509_path_result result;
  (void)params;
  (void)user;
  setup_workspace();

  /* Permitted and excluded subtrees from the anchor apply to every
   * certificate in the path. */
  anchor.names.permitted = pkits_subtree;
  munit_assert_int(
      validate("GoodCACert.crt", "ValidCertificatePathTest1EE.crt", &anchor, &options, &result), ==,
      TC_X509_PATH_VALID);
  anchor.names.permitted = other_subtree;
  munit_assert_int(
      validate("GoodCACert.crt", "ValidCertificatePathTest1EE.crt", &anchor, &options, &result), ==,
      TC_X509_PATH_INVALID);
  anchor.names.permitted = (TC_bytes){NULL, 0};
  anchor.names.excluded = pkits_subtree;
  munit_assert_int(
      validate("GoodCACert.crt", "ValidCertificatePathTest1EE.crt", &anchor, &options, &result), ==,
      TC_X509_PATH_INVALID);

  /* Anchor and application constraints both apply. */
  anchor.names.excluded = (TC_bytes){NULL, 0};
  anchor.names.permitted = pkits_subtree;
  options.anchor_names.permitted = other_subtree;
  munit_assert_int(
      validate("GoodCACert.crt", "ValidCertificatePathTest1EE.crt", &anchor, &options, &result), ==,
      TC_X509_PATH_INVALID);
  options.anchor_names.permitted = pkits_subtree;
  munit_assert_int(
      validate("GoodCACert.crt", "ValidCertificatePathTest1EE.crt", &anchor, &options, &result), ==,
      TC_X509_PATH_VALID);
  return MUNIT_OK;
}

/* A TrustAnchorList holding one TrustAnchorInfo for the PKITS Trust Anchor,
 * with CertPathControls built from the given fields. */
/* NULL data omits a control. A negative path_length omits pathLenConstraint. */
static size_t trust_anchor_info(TC_buffer out, const TC_X509_certificate* root, TC_bytes policy,
                                TC_bytes flags, TC_bytes subtree, int path_length)
{
  static const uint8_t key_id[] = {0x04, 0x04, 1, 2, 3, 4};
  static uint8_t controls[1024], info[2048], work[2048];
  size_t n = 0, m = 0, length;
  memcpy(controls, root->subject.data, root->subject.length);
  n = root->subject.length;
  if (policy.data) {
    uint8_t set[64];
    const size_t set_length = policy_set((TC_buffer){set, sizeof set}, policy.data, policy.length);
    n += der((TC_buffer){controls + n, sizeof controls - n}, 0xa1, set, set_length);
  }
  if (flags.data)
    n += der((TC_buffer){controls + n, sizeof controls - n}, 0x82, flags.data, flags.length);
  if (subtree.data) {
    uint8_t permitted[128];
    if (subtree.length > sizeof permitted - 4u)
      return 0;
    const size_t permitted_length =
        der((TC_buffer){permitted, sizeof permitted}, 0xa0, subtree.data, subtree.length);
    n += der((TC_buffer){controls + n, sizeof controls - n}, 0xa3, permitted, permitted_length);
  }
  if (path_length >= 0) {
    const uint8_t value = (uint8_t)path_length;
    n += der((TC_buffer){controls + n, sizeof controls - n}, 0x84, &value, 1);
  }
  memcpy(info, root->spki.data, root->spki.length);
  m = root->spki.length;
  memcpy(info + m, key_id, sizeof key_id);
  m += sizeof key_id;
  m += der((TC_buffer){info + m, sizeof info - m}, 0x30, controls, n);
  length = der((TC_buffer){work, sizeof work}, 0x30, info, m);
  length = der((TC_buffer){info, sizeof info}, 0xa2, work, length);
  return der(out, 0x30, info, length);
}

static MunitResult parsed_info(const MunitParameter params[], void* user)
{
  static const uint8_t explicit_policy[] = {0x06, 0x40};
  static uint8_t list[4096], subtree[80];
  const size_t subtree_length =
      directory_subtree((TC_buffer){subtree, sizeof subtree}, pkits_rdns, sizeof pkits_rdns);
  TC_X509_certificate root;
  TC_X509_store_anchor anchor;
  TC_X509_trust_anchor_reader reader;
  TC_X509_path_options options = path_options(0);
  TC_X509_path_result result;
  const TC_bytes encoded = load("TrustAnchorRootCertificate.crt", anchor_der);
  size_t length;
  (void)params;
  (void)user;
  setup_workspace();
  munit_assert_int(TC_X509_read(encoded, &limits, &parser, &root), ==, TC_TLV_OK);

  /* Decoded controls: policy1 required explicitly, PKITS names permitted and
   * one intermediate allowed. */
  length = trust_anchor_info(
      (TC_buffer){list, sizeof list}, &root, (TC_bytes){policy1, sizeof policy1},
      (TC_bytes){explicit_policy, sizeof explicit_policy}, (TC_bytes){subtree, subtree_length}, 1);
  munit_assert_int(
      TC_X509_trust_anchor_list_init(&reader, (TC_bytes){list, length}, &limits, &parser), ==,
      TC_TLV_OK);
  munit_assert_int(TC_X509_trust_anchor_next(&reader, &anchor), ==, TC_TLV_OK);
  munit_assert_int(anchor.x509_unusable, ==, 0);
  munit_assert_uint(anchor.policy_flags, ==, TC_X509_PATH_REQUIRE_EXPLICIT_POLICY);
  munit_assert_int(anchor.has_path_len, ==, 1);
  munit_assert_not_null(anchor.names.permitted.data);
  munit_assert_int(
      validate("GoodCACert.crt", "ValidCertificatePathTest1EE.crt", &anchor, &options, &result), ==,
      TC_X509_PATH_VALID);

  /* A policy set the path lacks. */
  length = trust_anchor_info(
      (TC_buffer){list, sizeof list}, &root, (TC_bytes){policy2, sizeof policy2},
      (TC_bytes){explicit_policy, sizeof explicit_policy}, (TC_bytes){NULL, 0}, -1);
  munit_assert_int(
      TC_X509_trust_anchor_list_init(&reader, (TC_bytes){list, length}, &limits, &parser), ==,
      TC_TLV_OK);
  munit_assert_int(TC_X509_trust_anchor_next(&reader, &anchor), ==, TC_TLV_OK);
  munit_assert_int(
      validate("GoodCACert.crt", "ValidCertificatePathTest1EE.crt", &anchor, &options, &result), ==,
      TC_X509_PATH_INVALID);

  /* pathLenConstraint 0 forbids the intermediate CA. */
  length = trust_anchor_info((TC_buffer){list, sizeof list}, &root, (TC_bytes){NULL, 0},
                             (TC_bytes){NULL, 0}, (TC_bytes){NULL, 0}, 0);
  munit_assert_int(
      TC_X509_trust_anchor_list_init(&reader, (TC_bytes){list, length}, &limits, &parser), ==,
      TC_TLV_OK);
  munit_assert_int(TC_X509_trust_anchor_next(&reader, &anchor), ==, TC_TLV_OK);
  munit_assert_int(
      validate("GoodCACert.crt", "ValidCertificatePathTest1EE.crt", &anchor, &options, &result), ==,
      TC_X509_PATH_INVALID);

  /* requireExplicitPolicy without a policySet is malformed (RFC 5914). */
  length = trust_anchor_info((TC_buffer){list, sizeof list}, &root, (TC_bytes){NULL, 0},
                             (TC_bytes){explicit_policy, sizeof explicit_policy},
                             (TC_bytes){NULL, 0}, -1);
  munit_assert_int(
      TC_X509_trust_anchor_list_init(&reader, (TC_bytes){list, length}, &limits, &parser), ==,
      TC_TLV_OK);
  munit_assert_int(TC_X509_trust_anchor_next(&reader, &anchor), ==, TC_TLV_INVALID);
  return MUNIT_OK;
}

static MunitResult workspace_limits(const MunitParameter params[], void* user)
{
  static uint8_t list[4096];
  TC_TLV_frame frames[2];
  TC_bytes oids[1];
  TC_X509_workspace small_frames = {{frames, 2}, parse_oids, 32};
  TC_X509_workspace small_oids = {{parse_frames, 32}, oids, 1};
  TC_X509_trust_anchor_reader reader;
  TC_X509_store_anchor anchor;
  const TC_bytes encoded = load("TrustAnchorRootCertificate.crt", anchor_der);
  size_t length;
  (void)params;
  (void)user;

  /* A certificate choice: the list wraps the PKITS root certificate. */
  length = der((TC_buffer){list, sizeof list}, 0x30, encoded.data, encoded.length);
  munit_assert_int(
      TC_X509_trust_anchor_list_init(&reader, (TC_bytes){list, length}, &limits, &small_frames), ==,
      TC_TLV_LIMIT);
  munit_assert_int(
      TC_X509_trust_anchor_list_init(&reader, (TC_bytes){list, length}, &limits, &small_oids), ==,
      TC_TLV_OK);
  munit_assert_int(TC_X509_trust_anchor_next(&reader, &anchor), ==, TC_TLV_LIMIT);
  munit_assert_int(
      TC_X509_trust_anchor_list_init(&reader, (TC_bytes){list, length}, &limits, &parser), ==,
      TC_TLV_OK);
  munit_assert_int(TC_X509_trust_anchor_next(&reader, &anchor), ==, TC_TLV_OK);
  munit_assert_int(TC_X509_trust_anchor_next(&reader, &anchor), ==, TC_TLV_END);

  /* Path validation needs one extension summary per certificate. */
  setup_workspace();
  anchor = pkits_anchor();
  const TC_X509_path_options options = path_options(0);
  TC_X509_path_result result;
  TC_X509_path_workspace* validation = &storage.path.validation;
  TC_X509_extension_summary* summaries = validation->summaries;
  munit_assert_int(
      validate("GoodCACert.crt", "ValidCertificatePathTest1EE.crt", &anchor, &options, &result), ==,
      TC_X509_PATH_VALID);
  validation->summary_capacity = CHAIN - 1;
  munit_assert_int(
      validate("GoodCACert.crt", "ValidCertificatePathTest1EE.crt", &anchor, &options, &result), ==,
      TC_X509_PATH_LIMIT);
  validation->summaries = NULL;
  validation->summary_capacity = CHAIN;
  munit_assert_int(
      validate("GoodCACert.crt", "ValidCertificatePathTest1EE.crt", &anchor, &options, &result), ==,
      TC_X509_PATH_LIMIT);
  validation->summaries = summaries;
  return MUNIT_OK;
}

/* The basic pass parses each path certificate once. A cache-filling pass
 * therefore costs exactly the DER bytes of every certificate more than the
 * same pass over already-parsed views. PKITS 4.5.1 gives three certificates. */
static MunitResult basic_pass_work(const MunitParameter params[], void* user)
{
  static uint8_t der_files[3][FILE_CAPACITY];
  static const char* const files[] = {"BasicSelfIssuedNewKeyCACert.crt",
                                      "BasicSelfIssuedNewKeyOldWithNewCACert.crt",
                                      "ValidBasicSelfIssuedOldWithNewTest1EE.crt"};
  TC_X509_path_workspace* validation = &storage.path.validation;
  TC_bytes chain[3];
  tc_x509_path_input input;
  size_t i, bytes = 0, cached_work, parsed_work;
  int accepted = 0;
  (void)params;
  (void)user;
  setup_workspace();
  const TC_X509_store_anchor anchor = pkits_anchor();
  const TC_X509_path_options options = path_options(0);
  TC_X509_workspace chain_parser = {validation->frames, validation->oids, validation->oid_capacity};
  for (i = 0; i < 3; ++i) {
    chain[i] = load(files[i], der_files[i]);
    bytes += chain[i].length;
  }
  memset(&input, 0, sizeof input);
  input.count = 3;
  input.max_certificates = options.max_certificates;
  input.max_input = options.max_input;
  input.anchor = &anchor.trust;
  input.at = &options.at;
  input.signatures = &options.signatures;
  input.limits = &options.parsing;
  input.encoded = chain;
  input.parser = &chain_parser;
  input.cache = validation->certificates;
  input.summaries = validation->summaries;
  memset(input.summaries, 0, 3 * sizeof *input.summaries);
  cached_work = options.max_work;
  munit_assert_int(tc_x509_path_basic(&input, &validation->names, &cached_work, &accepted), ==,
                   TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  /* The same pass over the views the first pass left in the cache. */
  input.certificates = validation->certificates;
  memset(input.summaries, 0, 3 * sizeof *input.summaries);
  parsed_work = options.max_work;
  accepted = 0;
  munit_assert_int(tc_x509_path_basic(&input, &validation->names, &parsed_work, &accepted), ==,
                   TC_TLV_OK);
  munit_assert_int(accepted, ==, 1);
  munit_assert_size(parsed_work - cached_work, ==, bytes);
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/basic-pass-work", basic_pass_work, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/policies", policies, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/names", names, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/parsed-info", parsed_info, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/workspace-limits", workspace_limits, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, 0, NULL}};
static const MunitSuite suite = {"/x509-anchor-controls", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{
  return munit_suite_main(&suite, NULL, argc, argv);
}
