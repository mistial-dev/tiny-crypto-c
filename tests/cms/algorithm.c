/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../src/cms_signature_internal.h"
#include "munit.h"

static const uint8_t rsa_oid[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1};
static const uint8_t null_parameters[] = {5,0};

static void digest_algorithm(tc_cms_signer_info* signer, TC_hash_algorithm hash)
{
  tc_hash_info info;
  munit_assert_true(tc_hash_info_get(hash,&info));
  signer->digest_algorithm = (TC_DER_algorithm){info.oid,{NULL,0}};
}

static MunitResult rsa_selection(const MunitParameter params[], void* user)
{
  static const uint8_t invalid_parameters[] = {4,0};
  tc_cms_signer_info signer = {0};
  TC_X509_public_key key = {0};
  tc_cms_signature_algorithm parsed, saved;
  (void)params; (void)user;
  signer.signature_algorithm = (TC_DER_algorithm){{rsa_oid,sizeof rsa_oid},
    {null_parameters,sizeof null_parameters}};
  key.type = TC_KEY_RSA;
  for (unsigned id = TC_HASH_SHA1; id <= TC_HASH_SHA512; ++id) {
    digest_algorithm(&signer,(TC_hash_algorithm)id);
    munit_assert_int(tc_cms_signature_resolve(&signer,&key,&parsed), ==, TC_TLV_OK);
    munit_assert_int(parsed.content_hash, ==, (TC_hash_algorithm)id);
    munit_assert_int(parsed.signature.hash, ==, (TC_hash_algorithm)id);
    munit_assert_int(parsed.signature.scheme, ==, TC_SIGNATURE_RSA_V15);
    signer.digest_algorithm.parameters = (TC_bytes){null_parameters,sizeof null_parameters};
    munit_assert_int(tc_cms_signature_resolve(&signer,&key,&parsed), ==, TC_TLV_OK);
  }
  memset(&parsed,0xa5,sizeof parsed); memcpy(&saved,&parsed,sizeof saved);
  key.type = TC_KEY_RSA_PSS;
  munit_assert_int(tc_cms_signature_resolve(&signer,&key,&parsed), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  key.type = TC_KEY_EC;
  munit_assert_int(tc_cms_signature_resolve(&signer,&key,&parsed), ==, TC_TLV_INVALID);
  key.type = TC_KEY_RSA;
  signer.signature_algorithm.parameters = (TC_bytes){NULL,0};
  munit_assert_int(tc_cms_signature_resolve(&signer,&key,&parsed), ==, TC_TLV_INVALID);
  signer.signature_algorithm.parameters = (TC_bytes){invalid_parameters,sizeof invalid_parameters};
  munit_assert_int(tc_cms_signature_resolve(&signer,&key,&parsed), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  return MUNIT_OK;
}

static MunitResult rsa_parameter_policy(const MunitParameter params[], void* user)
{
  enum { FRAME_COUNT = 4, WORK = 4096 };
  static const uint8_t encodings[][4] = {{5,0},{5,0x81,0},{4,0},{5,1,0},{5,0x80,0,0},{0x25,0}};
  static const size_t lengths[] = {2,3,2,3,4,2};
  const TC_TLV_limits limits = {WORK,WORK,32,FRAME_COUNT};
  TC_TLV_frame frames[FRAME_COUNT];
  tc_cms_signer_info signer = {0};
  TC_X509_public_key key = {0};
  tc_cms_signature_algorithm parsed, saved;
  (void)params; (void)user;
  digest_algorithm(&signer,TC_HASH_SHA256);
  signer.signature_algorithm.oid = (TC_bytes){rsa_oid,sizeof rsa_oid};
  key.type = TC_KEY_RSA;
  for (unsigned profile = 0; profile < 2; ++profile) {
    const TC_TLV_profile framing = profile ? TC_TLV_BER : TC_TLV_DER;
    for (unsigned policy = 0; policy < 3; ++policy) {
      for (size_t variant = 0; variant <= sizeof lengths / sizeof *lengths; ++variant) {
        size_t work = WORK;
        const tc_pki_tree_workspace tree = {frames,FRAME_COUNT,&work};
        signer.signature_algorithm.parameters = variant == 0 ? (TC_bytes){NULL,0} :
            (TC_bytes){encodings[variant - 1],lengths[variant - 1]};
        memset(&saved,0xa5,sizeof saved); memcpy(&parsed,&saved,sizeof parsed);
        TC_TLV_result expected = TC_TLV_INVALID;
        if (policy > TC_CMS_RSA_PARAMETERS_ALLOW_ABSENT) expected = TC_TLV_ARGUMENT;
        else if (variant == 1 || (variant == 2 && profile) || (variant == 0 && policy))
          expected = TC_TLV_OK;
        munit_assert_int(tc_cms_signature_resolve_policy(&signer,&key,framing,&limits,
            &tree,(TC_CMS_rsa_parameters)policy,&parsed), ==, expected);
        if (expected != TC_TLV_OK) munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
        else {
          munit_assert_int(parsed.signature.scheme, ==, TC_SIGNATURE_RSA_V15);
          munit_assert_int(parsed.signature.hash, ==, TC_HASH_SHA256);
        }
      }
    }
  }
  signer.signature_algorithm.parameters = (TC_bytes){NULL,0};
  const TC_key_type wrong_keys[] = {TC_KEY_EC,TC_KEY_RSA_PSS};
  for (size_t i = 0; i < sizeof wrong_keys / sizeof *wrong_keys; ++i) {
    key.type = wrong_keys[i];
    munit_assert_int(tc_cms_signature_resolve_policy(&signer,&key,TC_TLV_DER,&limits,
        NULL,TC_CMS_RSA_PARAMETERS_ALLOW_ABSENT,&parsed), ==, TC_TLV_INVALID);
  }
  return MUNIT_OK;
}

static MunitResult hash_selection(const MunitParameter params[], void* user)
{
  static const uint8_t ecdsa[] = {0x2a,0x86,0x48,0xce,0x3d,4,3,2};
  static const uint8_t rsa_sha256[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,11};
  static const uint8_t pss_oid[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,10};
  static const uint8_t defaults[] = {0x30,0};
  static const uint8_t sha256_parameters[] = {0x30,17,0xa0,15,0x30,13,6,9,
    0x60,0x86,0x48,1,0x65,3,4,2,1,5,0};
  tc_cms_signer_info signer = {0};
  TC_X509_public_key key = {0};
  tc_cms_signature_algorithm parsed, saved;
  (void)params; (void)user;
  digest_algorithm(&signer,TC_HASH_SHA256);
  key.type = TC_KEY_EC;
  signer.signature_algorithm = (TC_DER_algorithm){{ecdsa,sizeof ecdsa},{NULL,0}};
  munit_assert_int(tc_cms_signature_resolve(&signer,&key,&parsed), ==, TC_TLV_OK);
  munit_assert_int(parsed.signature.scheme, ==, TC_SIGNATURE_ECDSA);
  memset(&parsed,0xa5,sizeof parsed); memcpy(&saved,&parsed,sizeof saved);
  digest_algorithm(&signer,TC_HASH_SHA384);
  munit_assert_int(tc_cms_signature_resolve(&signer,&key,&parsed), ==, TC_TLV_INVALID);
  /* Attribute framing is checked separately; this stage uses presence only. */
  signer.signed_attributes = (TC_bytes){defaults,sizeof defaults};
  munit_assert_int(tc_cms_signature_resolve(&signer,&key,&parsed), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  key.type = TC_KEY_RSA;
  signer.signature_algorithm = (TC_DER_algorithm){{rsa_sha256,sizeof rsa_sha256},{NULL,0}};
  munit_assert_int(tc_cms_signature_resolve(&signer,&key,&parsed), ==, TC_TLV_INVALID);
  digest_algorithm(&signer,TC_HASH_SHA256);
  munit_assert_int(tc_cms_signature_resolve(&signer,&key,&parsed), ==, TC_TLV_OK);
  munit_assert_int(parsed.signature.scheme, ==, TC_SIGNATURE_RSA_V15);
  signer.signature_algorithm = (TC_DER_algorithm){{pss_oid,sizeof pss_oid},{defaults,sizeof defaults}};
  munit_assert_int(tc_cms_signature_resolve(&signer,&key,&parsed), ==, TC_TLV_OK);
  munit_assert_int(parsed.content_hash, ==, TC_HASH_SHA256);
  munit_assert_int(parsed.signature.hash, ==, TC_HASH_SHA1);
  munit_assert_int(parsed.signature.scheme, ==, TC_SIGNATURE_RSA_PSS);
  memset(&parsed,0xa5,sizeof parsed); memcpy(&saved,&parsed,sizeof saved);
  signer.signed_attributes = (TC_bytes){NULL,0};
  munit_assert_int(tc_cms_signature_resolve(&signer,&key,&parsed), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  digest_algorithm(&signer,TC_HASH_SHA1);
  munit_assert_int(tc_cms_signature_resolve(&signer,&key,&parsed), ==, TC_TLV_OK);
  key.type = TC_KEY_RSA_PSS;
  key.algorithm.parameters = (TC_bytes){sha256_parameters,sizeof sha256_parameters};
  memset(&parsed,0xa5,sizeof parsed); memcpy(&saved,&parsed,sizeof saved);
  munit_assert_int(tc_cms_signature_resolve(&signer,&key,&parsed), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  key.algorithm.parameters = (TC_bytes){defaults,sizeof defaults};
  munit_assert_int(tc_cms_signature_resolve(&signer,&key,&parsed), ==, TC_TLV_OK);
  signer.signature_algorithm.parameters = (TC_bytes){NULL,0};
  munit_assert_int(tc_cms_signature_resolve(&signer,&key,&parsed), !=, TC_TLV_OK);
  return MUNIT_OK;
}

static MunitResult ber_parameters(const MunitParameter params[], void* user)
{
  enum { FRAME_CAPACITY = 8, WORK_BUDGET = 16384, TRAILER_VALUE_FROM_END = 5 };
  static const uint8_t ber_null[] = {5,0x82,0,0};
  static const uint8_t pss_oid[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,10};
  static const uint8_t defaults[] = {0x30,0};
  uint8_t pss[] = {
    0x30,0x80,
    0xa0,0x80,0x30,0x80,6,9,0x60,0x86,0x48,1,0x65,3,4,2,1,5,0x81,0,0,0,0,0,
    0xa1,0x80,0x30,0x80,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,8,
      0x30,0x80,6,9,0x60,0x86,0x48,1,0x65,3,4,2,2,5,0x82,0,0,0,0,0,0,0,0,
    0xa2,0x80,2,0x81,1,32,0,0,
    0xa3,0x80,2,1,1,0,0,0,0
  };
  const TC_TLV_limits limits = {WORK_BUDGET,WORK_BUDGET,64,FRAME_CAPACITY};
  TC_TLV_frame frames[FRAME_CAPACITY];
  size_t work = WORK_BUDGET;
  const tc_pki_tree_workspace tree = {frames,FRAME_CAPACITY,&work};
  tc_cms_signer_info signer = {0};
  TC_X509_public_key key = {0};
  tc_cms_signature_algorithm parsed, saved;
  (void)params; (void)user;
  digest_algorithm(&signer,TC_HASH_SHA256);
  signer.digest_algorithm.parameters = (TC_bytes){ber_null,sizeof ber_null};
  signer.signature_algorithm = (TC_DER_algorithm){{rsa_oid,sizeof rsa_oid},{ber_null,sizeof ber_null}};
  key.type = TC_KEY_RSA;
  munit_assert_int(tc_cms_signature_resolve_profile(&signer,&key,TC_TLV_BER,&limits,&tree,&parsed),
      ==, TC_TLV_OK);
  munit_assert_int(parsed.signature.scheme, ==, TC_SIGNATURE_RSA_V15);
  memset(&parsed,0xa5,sizeof parsed); memcpy(&saved,&parsed,sizeof saved);
  munit_assert_int(tc_cms_signature_resolve(&signer,&key,&parsed), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  {
    static const uint8_t invalid_nulls[][4] = {{0x25,0},{5,1,0},{5,0x80,0,0},{5,0x81,0,0}};
    static const size_t lengths[] = {2,3,4,4};
    for (size_t i = 0; i < sizeof lengths / sizeof lengths[0]; ++i) {
      signer.signature_algorithm.parameters = (TC_bytes){invalid_nulls[i],lengths[i]};
      work = WORK_BUDGET;
      munit_assert_int(tc_cms_signature_resolve_profile(&signer,&key,TC_TLV_BER,&limits,&tree,&parsed),
          ==, TC_TLV_INVALID);
      munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
    }
  }
  signer.signature_algorithm = (TC_DER_algorithm){{pss_oid,sizeof pss_oid},{pss,sizeof pss}};
  work = WORK_BUDGET;
  munit_assert_int(tc_cms_signature_resolve_profile(&signer,&key,TC_TLV_BER,&limits,&tree,&parsed),
      ==, TC_TLV_OK);
  munit_assert_int(parsed.signature.scheme, ==, TC_SIGNATURE_RSA_PSS);
  munit_assert_int(parsed.signature.hash, ==, TC_HASH_SHA256);
  munit_assert_int(parsed.signature.mgf_hash, ==, TC_HASH_SHA384);
  munit_assert_uint(parsed.signature.salt_length, ==, 32);
  const size_t required = WORK_BUDGET - work;
  memset(&parsed,0xa5,sizeof parsed); memcpy(&saved,&parsed,sizeof saved);
  for (size_t budget = 0; budget < required; ++budget) {
    work = budget;
    munit_assert_int(tc_cms_signature_resolve_profile(&signer,&key,TC_TLV_BER,&limits,&tree,&parsed),
        ==, TC_TLV_LIMIT);
    munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  }
  for (size_t prefix = 0; prefix < sizeof pss; ++prefix) {
    signer.signature_algorithm.parameters.length = prefix; work = WORK_BUDGET;
    munit_assert_int(tc_cms_signature_resolve_profile(&signer,&key,TC_TLV_BER,&limits,&tree,&parsed),
        !=, TC_TLV_OK);
    munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  }
  signer.signature_algorithm.parameters.length = sizeof pss; work = required;
  munit_assert_int(tc_cms_signature_resolve_profile(&signer,&key,TC_TLV_BER,&limits,&tree,&parsed),
      ==, TC_TLV_OK);
  munit_assert_size(work, ==, 0);
  memset(&parsed,0xa5,sizeof parsed); memcpy(&saved,&parsed,sizeof saved);
  {
    TC_TLV_limits shallow = limits;
    shallow.max_depth = 2; work = WORK_BUDGET;
    munit_assert_int(tc_cms_signature_resolve_profile(&signer,&key,TC_TLV_BER,&shallow,&tree,&parsed),
        ==, TC_TLV_LIMIT);
    munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
    shallow = limits; shallow.max_elements = 2; work = WORK_BUDGET;
    munit_assert_int(tc_cms_signature_resolve_profile(&signer,&key,TC_TLV_BER,&shallow,&tree,&parsed),
        ==, TC_TLV_LIMIT);
    munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  }
  key.type = TC_KEY_RSA_PSS; key.algorithm.parameters = (TC_bytes){defaults,sizeof defaults};
  work = WORK_BUDGET;
  munit_assert_int(tc_cms_signature_resolve_profile(&signer,&key,TC_TLV_BER,&limits,&tree,&parsed),
      ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  key.type = TC_KEY_RSA;
  pss[sizeof pss - TRAILER_VALUE_FROM_END] = 2; work = WORK_BUDGET;
  munit_assert_int(tc_cms_signature_resolve_profile(&signer,&key,TC_TLV_BER,&limits,&tree,&parsed),
      ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  return MUNIT_OK;
}

static MunitResult digest_sets(const MunitParameter params[], void* user)
{
  enum { FRAME_COUNT = 8, WORK_BUDGET = 4096, OID_BYTES = 9 };
  static const uint8_t oid[] = {0x60,0x86,0x48,1,0x65,3,4,2,1};
  static const uint8_t empty[] = {0x31,0};
  uint8_t encoded[] = {0x31,15,0x30,13,6,OID_BYTES,0x60,0x86,0x48,1,0x65,3,4,2,1,5,0};
  TC_DER_algorithm selected = {{oid,sizeof oid},{NULL,0}};
  TC_TLV_frame frames[FRAME_COUNT];
  const TC_TLV_limits limits = {WORK_BUDGET,WORK_BUDGET,64,FRAME_COUNT};
  size_t work = WORK_BUDGET;
  const tc_pki_tree_workspace tree = {frames,FRAME_COUNT,&work};
  TC_hash_algorithm hash = TC_HASH_UNKNOWN;
  const TC_bytes input = {encoded,sizeof encoded};
  munit_assert_int(tc_cms_digest_algorithms(input,&selected,&limits,&tree,&hash), ==, TC_TLV_OK);
  munit_assert_int(hash, ==, TC_HASH_SHA256);
  const size_t required = WORK_BUDGET - work;
  for (size_t budget = 0; budget <= required; ++budget) {
    work = budget; hash = TC_HASH_UNKNOWN;
    munit_assert_int(tc_cms_digest_algorithms(input,&selected,&limits,&tree,&hash), ==,
        budget == required ? TC_TLV_OK : TC_TLV_LIMIT);
    munit_assert_int(hash, ==, budget == required ? TC_HASH_SHA256 : TC_HASH_UNKNOWN);
  }
  /* Digest parameters permit both absent and NULL encodings. */
  selected.parameters = (TC_bytes){null_parameters,sizeof null_parameters};
  work = WORK_BUDGET;
  munit_assert_int(tc_cms_digest_algorithms(input,&selected,&limits,&tree,&hash), ==, TC_TLV_OK);
  encoded[1] -= sizeof null_parameters; encoded[3] -= sizeof null_parameters;
  work = WORK_BUDGET;
  munit_assert_int(tc_cms_digest_algorithms((TC_bytes){encoded,sizeof encoded - sizeof null_parameters},
      &selected,&limits,&tree,&hash), ==, TC_TLV_OK);
  munit_assert_int(hash, ==, TC_HASH_SHA256);
  encoded[1] += sizeof null_parameters; encoded[3] += sizeof null_parameters;
  for (size_t prefix = 0; prefix < sizeof encoded; ++prefix) {
    work = WORK_BUDGET; hash = TC_HASH_UNKNOWN;
    munit_assert_int(tc_cms_digest_algorithms((TC_bytes){encoded,prefix},&selected,
        &limits,&tree,&hash), !=, TC_TLV_OK);
    munit_assert_int(hash, ==, TC_HASH_UNKNOWN);
  }
  work = WORK_BUDGET; hash = TC_HASH_UNKNOWN;
  munit_assert_int(tc_cms_digest_algorithms((TC_bytes){empty,sizeof empty},&selected,
      &limits,&tree,&hash), ==, TC_TLV_INVALID);
  munit_assert_int(hash, ==, TC_HASH_UNKNOWN);
  encoded[sizeof encoded - 2] = 4;
  work = WORK_BUDGET;
  munit_assert_int(tc_cms_digest_algorithms(input,&selected,&limits,&tree,&hash), ==, TC_TLV_INVALID);
  munit_assert_int(hash, ==, TC_HASH_UNKNOWN);
  encoded[sizeof encoded - 2] = 5;
  encoded[6 + OID_BYTES - 1] = 0x7f;
  work = WORK_BUDGET;
  munit_assert_int(tc_cms_digest_algorithms(input,&selected,&limits,&tree,&hash), ==, TC_TLV_INVALID);
  munit_assert_int(hash, ==, TC_HASH_UNKNOWN);
  work = WORK_BUDGET;
  munit_assert_int(tc_cms_digest_algorithms(input,NULL,&limits,&tree,NULL), ==, TC_TLV_OK);
  selected.oid = (TC_bytes){encoded + 6,OID_BYTES};
  work = WORK_BUDGET;
  munit_assert_int(tc_cms_digest_algorithms(input,&selected,&limits,&tree,&hash), ==, TC_TLV_UNSUPPORTED);
  munit_assert_int(hash, ==, TC_HASH_UNKNOWN);
  (void)params; (void)user;
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/rsa",rsa_selection,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/rsa-parameter-policy",rsa_parameter_policy,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/hashes",hash_selection,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/digest-sets",digest_sets,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/ber-parameters",ber_parameters,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/cms/algorithm",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
