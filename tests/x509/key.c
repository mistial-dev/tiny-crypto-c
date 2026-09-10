/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/x509.h>
#include <tiny_crypto/key_challenge.h>
#include "../../src/pki_hash_internal.h"
#include "../../src/pki_key_internal.h"
#include "../../src/pki_signature_internal.h"
#include <stdio.h>
#include <string.h>

#include "munit.h"

static TC_status fixed_random(void* context, uint8_t* output, size_t length)
{
  const int fail = *(const int*)context;
  memset(output,0x5a,length);
  return fail ? TC_ERROR : TC_OK;
}

static TC_X509_signature_result proof_result(void* context, TC_bytes digest,
    const TC_signature_algorithm* algorithm, TC_bytes signature,
    const TC_X509_public_key* key, size_t* work)
{
  (void)digest; (void)algorithm; (void)signature; (void)key;
  if (!*work) return TC_X509_SIGNATURE_LIMIT;
  --*work;
  return *(const TC_X509_signature_result*)context;
}

static MunitResult key_challenge(const MunitParameter params[], void* user)
{
  uint8_t oid = 1, point = 4, proof = 1;
  TC_X509_public_key key = {0};
  key.type = TC_KEY_EC;
  key.curve = TC_EC_P256;
  key.bits = 256;
  key.algorithm.oid = (TC_bytes){&oid,1};
  key.key = (TC_bytes){&point,1};
  const TC_key_challenge_options options = {
    {TC_SIGNATURE_ECDSA,TC_HASH_SHA256,TC_HASH_UNKNOWN,0}};
  TC_key_challenge_workspace workspace, saved;
  TC_bytes challenge = {(const uint8_t*)1,7}, unchanged = challenge;
  TC_work_budget work = {31};
  int fail = 0;
  (void)params; (void)user;
  memset(&workspace,0xa5,sizeof workspace);
  saved = workspace;
  munit_assert_int(TC_key_challenge_prepare(&key,&options,
      (TC_random_source){fixed_random,&fail},&workspace,&work,&challenge), ==,
      TC_KEY_CHALLENGE_LIMIT);
  munit_assert_uint(work.remaining, ==, 31);
  munit_assert_memory_equal(sizeof workspace,&workspace,&saved);
  munit_assert_memory_equal(sizeof challenge,&challenge,&unchanged);

  work.remaining = 32;
  munit_assert_int(TC_key_challenge_prepare(&key,&options,
      (TC_random_source){fixed_random,&fail},&workspace,&work,&challenge), ==,
      TC_KEY_CHALLENGE_OK);
  munit_assert_uint(work.remaining, ==, 0);
  munit_assert_ptr_equal(challenge.data,workspace.digest);
  munit_assert_size(challenge.length, ==, 32);
  TC_X509_signature_result proof_outcome = TC_X509_SIGNATURE_VALID;
  const TC_X509_signature_provider provider = {NULL,&proof_outcome,proof_result};
  work.remaining = 100;
  munit_assert_int(TC_key_challenge_verify(&key,(TC_bytes){&proof,1},&provider,
      &workspace,&work), ==, TC_KEY_CHALLENGE_OK);
  munit_assert_uint(work.remaining, <, 100);

  work.remaining = 32;
  munit_assert_int(TC_key_challenge_prepare(&key,&options,
      (TC_random_source){fixed_random,&fail},&workspace,&work,&challenge), ==,
      TC_KEY_CHALLENGE_OK);
  proof_outcome = TC_X509_SIGNATURE_INVALID;
  work.remaining = 100;
  munit_assert_int(TC_key_challenge_verify(&key,(TC_bytes){&proof,1},&provider,
      &workspace,&work), ==, TC_KEY_CHALLENGE_INVALID);
  munit_assert_uint(work.remaining, <, 100);

  work.remaining = 32;
  munit_assert_int(TC_key_challenge_prepare(&key,&options,
      (TC_random_source){fixed_random,&fail},&workspace,&work,&challenge), ==,
      TC_KEY_CHALLENGE_OK);
  work.remaining = 0;
  munit_assert_int(TC_key_challenge_verify(&key,(TC_bytes){&proof,1},&provider,
      &workspace,&work), ==, TC_KEY_CHALLENGE_LIMIT);

  fail = 1;
  challenge = unchanged;
  work.remaining = 32;
  munit_assert_int(TC_key_challenge_prepare(&key,&options,
      (TC_random_source){fixed_random,&fail},&workspace,&work,&challenge), ==,
      TC_KEY_CHALLENGE_ERROR);
  munit_assert_uint(work.remaining, ==, 0);
  const uint8_t zero[sizeof workspace] = {0};
  munit_assert_memory_equal(sizeof workspace,&workspace,zero);
  munit_assert_memory_equal(sizeof challenge,&challenge,&unchanged);
  return MUNIT_OK;
}

static MunitResult test_key_encodings(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  uint8_t rsa[] = {0x30,27,0x30,13,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1,5,0,
                   3,10,0,0x30,7,2,2,0x0c,0xa1,2,1,17};
  uint8_t ec[91] = {0x30,89,0x30,19,6,7,0x2a,0x86,0x48,0xce,0x3d,2,1,
                    6,8,0x2a,0x86,0x48,0xce,0x3d,3,1,7,3,66,0,4};
  uint8_t ed25519[44] = {0x30,42,0x30,5,6,3,0x2b,0x65,112,3,33,0};
  TC_X509_public_key key, saved;
  size_t i;
  munit_assert(TC_X509_subject_public_key(rsa, sizeof rsa, &key) == TC_TLV_OK);
  munit_assert(key.type == TC_KEY_RSA && key.bits == 12 && key.modulus.length == 2);
  munit_assert(key.exponent.length == 1 && key.exponent.data[0] == 17);
  saved = key;
  for (i = 0; i < sizeof rsa; ++i) {
    munit_assert(TC_X509_subject_public_key(rsa, i, &key) == TC_TLV_MORE);
    munit_assert(memcmp(&key, &saved, sizeof key) == 0);
  }
  rsa[25] = 0xa0;
  munit_assert(TC_X509_subject_public_key(rsa, sizeof rsa, &key) == TC_TLV_INVALID);
  rsa[25] = 0xa1; rsa[28] = 2;
  munit_assert(TC_X509_subject_public_key(rsa, sizeof rsa, &key) == TC_TLV_INVALID);
  rsa[28] = 1;
  munit_assert(TC_X509_subject_public_key(rsa, sizeof rsa, &key) == TC_TLV_INVALID);
  rsa[28] = 17; rsa[15] = 4;
  munit_assert(TC_X509_subject_public_key(rsa, sizeof rsa, &key) == TC_TLV_INVALID);
  munit_assert(memcmp(&key, &saved, sizeof key) == 0);
  memset(ec + 27, 1, 64);
  munit_assert(TC_X509_subject_public_key(ec, sizeof ec, &key) == TC_TLV_OK);
  munit_assert(key.type == TC_KEY_EC && key.bits == 256 && key.curve == TC_EC_P256);
  ec[26] = 6;
  munit_assert(TC_X509_subject_public_key(ec, sizeof ec, &key) == TC_TLV_INVALID);
  ec[26] = 2;
  munit_assert(TC_X509_subject_public_key(ec, sizeof ec, &key) == TC_TLV_INVALID);
  ec[1] = 57; ec[24] = 34;
  munit_assert(TC_X509_subject_public_key(ec, 59, &key) == TC_TLV_OK);
  munit_assert(key.bits == 256 && key.key.length == 33);
  munit_assert(TC_X509_subject_public_key(ed25519, sizeof ed25519, &key) == TC_TLV_OK);
  munit_assert(key.type == TC_KEY_ED25519 && key.bits == 255);
  ed25519[11] = 1;
  munit_assert(TC_X509_subject_public_key(ed25519, sizeof ed25519, &key) == TC_TLV_INVALID);
  munit_assert(TC_X509_subject_public_key(NULL, 1, &key) == TC_TLV_ARGUMENT);
  return MUNIT_OK;
}


static MunitResult rsa_algorithm(const MunitParameter params[], void* user)
{
  uint8_t oid[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,1};
  const uint8_t null[] = {5,0}, defaults[] = {0x30,0};
  TC_DER_algorithm algorithm = {{oid,sizeof oid},{null,sizeof null}};
  TC_key_type type = TC_KEY_UNKNOWN;
  (void)params; (void)user;
  munit_assert_int(tc_pki_rsa_key_algorithm(&algorithm,&type), ==, TC_TLV_OK);
  munit_assert_int(type, ==, TC_KEY_RSA);
  algorithm.parameters = (TC_bytes){NULL,0};
  munit_assert_int(tc_pki_rsa_key_algorithm(&algorithm,&type), ==, TC_TLV_INVALID);
  munit_assert_int(type, ==, TC_KEY_RSA);
  oid[8] = 10;
  munit_assert_int(tc_pki_rsa_key_algorithm(&algorithm,&type), ==, TC_TLV_OK);
  munit_assert_int(type, ==, TC_KEY_RSA_PSS);
  algorithm.parameters = (TC_bytes){null,sizeof null};
  munit_assert_int(tc_pki_rsa_key_algorithm(&algorithm,&type), ==, TC_TLV_INVALID);
  munit_assert_int(type, ==, TC_KEY_RSA_PSS);
  algorithm.parameters = (TC_bytes){defaults,sizeof defaults};
  munit_assert_int(tc_pki_rsa_key_algorithm(&algorithm,&type), ==, TC_TLV_OK);
  munit_assert_int(type, ==, TC_KEY_RSA_PSS);
  oid[8] = 99;
  munit_assert_int(tc_pki_rsa_key_algorithm(&algorithm,&type), ==, TC_TLV_OK);
  munit_assert_int(type, ==, TC_KEY_UNKNOWN);
  munit_assert_int(tc_pki_rsa_key_algorithm(NULL,&type), ==, TC_TLV_ARGUMENT);
  munit_assert_int(tc_pki_rsa_key_algorithm(&algorithm,NULL), ==, TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

static MunitResult pss_parameters(const MunitParameter params[], void* user)
{
  static const uint8_t defaults[] = {0x30,0};
  uint8_t encoded[] = {
    0x30,52,
    0xa0,15,0x30,13,6,9,0x60,0x86,0x48,1,0x65,3,4,2,1,5,0,
    0xa1,28,0x30,26,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,8,
    0x30,13,6,9,0x60,0x86,0x48,1,0x65,3,4,2,2,5,0,
    0xa2,3,2,1,32
  };
  tc_pki_pss_parameters parsed, saved;
  TC_hash_algorithm hash = TC_HASH_UNKNOWN;
  (void)params; (void)user;
  munit_assert_int(tc_pki_pss_read((TC_bytes){defaults,sizeof defaults},&parsed), ==, TC_TLV_OK);
  munit_assert_int(tc_pki_hash_algorithm(&parsed.hash,&hash), ==, TC_TLV_OK);
  munit_assert_int(hash, ==, TC_HASH_SHA1);
  munit_assert_int(tc_pki_hash_algorithm(&parsed.mgf_hash,&hash), ==, TC_TLV_OK);
  munit_assert_int(hash, ==, TC_HASH_SHA1);
  munit_assert_uint(parsed.salt_length.data[0], ==, 20);
  munit_assert_int(tc_pki_pss_read((TC_bytes){encoded,sizeof encoded},&parsed), ==, TC_TLV_OK);
  munit_assert_int(tc_pki_hash_algorithm(&parsed.hash,&hash), ==, TC_TLV_OK);
  munit_assert_int(hash, ==, TC_HASH_SHA256);
  munit_assert_int(tc_pki_hash_algorithm(&parsed.mgf_hash,&hash), ==, TC_TLV_OK);
  munit_assert_int(hash, ==, TC_HASH_SHA384);
  munit_assert_ptr_equal(parsed.salt_length.data,encoded + sizeof encoded - 1);
  munit_assert_uint(parsed.salt_length.data[0], ==, 32);
  memset(&parsed,0xa5,sizeof parsed); memcpy(&saved,&parsed,sizeof saved);
  for (size_t length = 0; length < sizeof encoded; ++length) {
    munit_assert_int(tc_pki_pss_read((TC_bytes){encoded,length},&parsed), !=, TC_TLV_OK);
    munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  }
  encoded[sizeof encoded - 1] = 0xff;
  munit_assert_int(tc_pki_pss_read((TC_bytes){encoded,sizeof encoded},&parsed), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  munit_assert_int(tc_pki_pss_read((TC_bytes){defaults,sizeof defaults},NULL), ==, TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

static MunitResult signature_restrictions(const MunitParameter params[], void* user)
{
  uint8_t oid[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,10};
  static const uint8_t defaults[] = {0x30,0};
  uint8_t salt[] = {0x30,5,0xa2,3,2,1,21};
  static const uint8_t sha256[] = {0x30,17,0xa0,15,0x30,13,6,9,
    0x60,0x86,0x48,1,0x65,3,4,2,1,5,0};
  static const uint8_t ecdsa[] = {0x2a,0x86,0x48,0xce,0x3d,4,3,3};
  TC_DER_algorithm algorithm = {{oid,sizeof oid},{salt,sizeof salt}};
  TC_X509_public_key key = {0};
  TC_signature_algorithm parsed, saved;
  (void)params; (void)user;
  key.type = TC_KEY_RSA_PSS;
  key.algorithm.parameters = (TC_bytes){defaults,sizeof defaults};
  munit_assert_int(tc_pki_signature_resolve(&algorithm,&key,&parsed), ==, TC_TLV_OK);
  munit_assert_int(parsed.scheme, ==, TC_SIGNATURE_RSA_PSS);
  munit_assert_uint(parsed.salt_length, ==, 21);
  salt[6] = 20;
  munit_assert_int(tc_pki_signature_resolve(&algorithm,&key,&parsed), ==, TC_TLV_OK);
  memset(&parsed,0xa5,sizeof parsed); memcpy(&saved,&parsed,sizeof saved);
  salt[6] = 19;
  munit_assert_int(tc_pki_signature_resolve(&algorithm,&key,&parsed), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  salt[6] = 21;
  key.algorithm.parameters = (TC_bytes){sha256,sizeof sha256};
  munit_assert_int(tc_pki_signature_resolve(&algorithm,&key,&parsed), ==, TC_TLV_INVALID);
  munit_assert_memory_equal(sizeof parsed,&parsed,&saved);
  key.algorithm.parameters = (TC_bytes){NULL,0};
  munit_assert_int(tc_pki_signature_resolve(&algorithm,&key,&parsed), ==, TC_TLV_OK);
  oid[8] = 11; algorithm.parameters = (TC_bytes){NULL,0};
  munit_assert_int(tc_pki_signature_resolve(&algorithm,&key,&parsed), ==, TC_TLV_INVALID);
  key.type = TC_KEY_RSA;
  munit_assert_int(tc_pki_signature_resolve(&algorithm,&key,&parsed), ==, TC_TLV_OK);
  munit_assert_int(parsed.scheme, ==, TC_SIGNATURE_RSA_V15);
  munit_assert_int(parsed.hash, ==, TC_HASH_SHA256);
  key.type = TC_KEY_EC;
  munit_assert_int(tc_pki_signature_resolve(&algorithm,&key,&parsed), ==, TC_TLV_INVALID);
  algorithm.oid = (TC_bytes){ecdsa,sizeof ecdsa};
  munit_assert_int(tc_pki_signature_resolve(&algorithm,&key,&parsed), ==, TC_TLV_OK);
  munit_assert_int(parsed.scheme, ==, TC_SIGNATURE_ECDSA);
  munit_assert_int(parsed.hash, ==, TC_HASH_SHA384);
  algorithm.parameters = (TC_bytes){defaults,sizeof defaults};
  munit_assert_int(tc_pki_signature_resolve(&algorithm,&key,&parsed), ==, TC_TLV_INVALID);
  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/key-challenge", key_challenge, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/rsa-algorithm", rsa_algorithm, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/signature-restrictions", signature_restrictions, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/pss-parameters", pss_parameters, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/key-encodings", test_key_encodings, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};
static const MunitSuite suite = {"/x509-key", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[])
{ return munit_suite_main(&suite, NULL, argc, argv); }
