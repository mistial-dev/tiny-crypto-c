/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/x509.h>
#include "munit.h"
#include <string.h>

enum { SHA256_DIGEST_BYTES = 32 };

typedef struct {
  const TC_X509_certificate* certificate;
  const TC_X509_public_key* key;
  TC_X509_signature_result result;
  unsigned calls;
  int increase;
} ProviderState;

static TC_X509_signature_result verify(void* context, const TC_bytes* message, size_t count,
    const TC_DER_algorithm* algorithm, TC_bytes signature,
    const TC_X509_public_key* key, size_t* work)
{
  ProviderState* state = (ProviderState*)context;
  size_t offset = 0;
  ++state->calls;
  for (size_t i = 0; i < count; ++i) {
    munit_assert_size(message[i].length, <=, state->certificate->tbs.length - offset);
    if (message[i].length)
      munit_assert_memory_equal(message[i].length,message[i].data,state->certificate->tbs.data + offset);
    offset += message[i].length;
  }
  munit_assert_size(offset, ==, state->certificate->tbs.length);
  if (count == 1) munit_assert_ptr_equal(message[0].data,state->certificate->tbs.data);
  munit_assert_ptr_equal(algorithm, &state->certificate->signature_algorithm);
  munit_assert_ptr_equal(signature.data, state->certificate->signature.data);
  munit_assert_size(signature.length, ==, state->certificate->signature.length);
  munit_assert_ptr_equal(key, state->key);
  if (state->increase) { ++*work; return TC_X509_SIGNATURE_VALID; }
  if (!*work) return TC_X509_SIGNATURE_LIMIT;
  --*work;
  return state->result;
}

static void fixture(TC_X509_certificate* certificate, TC_X509_public_key* key)
{
  static const uint8_t tbs[] = {0x30,0};
  static const uint8_t oid[] = {0x2a,3};
  static const uint8_t signature[] = {1,2,3};
  static const uint8_t public_key[] = {4,5,6};
  static const uint8_t parameters[] = {5,0};
  memset(certificate, 0, sizeof(*certificate)); memset(key, 0, sizeof(*key));
  certificate->tbs.data = tbs; certificate->tbs.length = sizeof tbs;
  certificate->signature.data = signature; certificate->signature.length = sizeof signature;
  certificate->signature_algorithm.oid.data = oid; certificate->signature_algorithm.oid.length = sizeof oid;
  certificate->signature_algorithm.parameters.data = parameters;
  certificate->signature_algorithm.parameters.length = sizeof parameters;
  key->algorithm = certificate->signature_algorithm;
  key->key.data = public_key; key->key.length = sizeof public_key;
}

static MunitResult dispatch(const MunitParameter params[], void* user)
{
  TC_X509_certificate certificate;
  TC_X509_public_key key;
  ProviderState state = {&certificate,&key,TC_X509_SIGNATURE_VALID,0,0};
  TC_X509_signature_provider provider = {verify,&state,NULL};
  size_t work;
  unsigned result;
  (void)params; (void)user;
  fixture(&certificate, &key);
  for (result = TC_X509_SIGNATURE_VALID; result <= TC_X509_SIGNATURE_LIMIT; ++result) {
    state.result = (TC_X509_signature_result)result; state.calls = 0; work = 100;
    munit_assert_int(TC_X509_signature_verify(&certificate, &key, &provider, &work), ==, result);
    munit_assert_uint(state.calls, ==, 1);
    munit_assert_size(work, <, 100);
  }
  state.result = (TC_X509_signature_result)99; work = 100;
  munit_assert_int(TC_X509_signature_verify(&certificate, &key, &provider, &work), ==, TC_X509_SIGNATURE_ERROR);
  state.increase = 1; work = 100;
  munit_assert_int(TC_X509_signature_verify(&certificate, &key, &provider, &work), ==, TC_X509_SIGNATURE_ERROR);
  munit_assert_size(work, ==, 0);
  return MUNIT_OK;
}

static MunitResult limits(const MunitParameter params[], void* user)
{
  TC_X509_certificate certificate;
  TC_X509_public_key key;
  ProviderState state = {&certificate,&key,TC_X509_SIGNATURE_VALID,0,0};
  TC_X509_signature_provider provider = {verify,&state,NULL};
  size_t work = 100, required, i;
  (void)params; (void)user;
  fixture(&certificate, &key);
  munit_assert_int(TC_X509_signature_verify(&certificate, &key, &provider, &work), ==, TC_X509_SIGNATURE_VALID);
  required = 100 - work;
  for (i = 0; i < required; ++i) {
    state.calls = 0; work = i;
    munit_assert_int(TC_X509_signature_verify(&certificate, &key, &provider, &work), ==, TC_X509_SIGNATURE_LIMIT);
    munit_assert_uint(state.calls, ==, i == required - 1 ? 1 : 0);
  }
  state.calls = 0; work = 100;
  munit_assert_int(TC_X509_signature_verify(&certificate, &key, NULL, &work), ==, TC_X509_SIGNATURE_UNSUPPORTED);
  provider.verify = NULL;
  munit_assert_int(TC_X509_signature_verify(&certificate, &key, &provider, &work), ==, TC_X509_SIGNATURE_UNSUPPORTED);
  munit_assert_uint(state.calls, ==, 0);
  munit_assert_size(work, ==, 100);
  provider.verify = verify;
  certificate.tbs.data = NULL;
  munit_assert_int(TC_X509_signature_verify(&certificate, &key, &provider, &work), ==, TC_X509_SIGNATURE_ERROR);
  fixture(&certificate, &key);
  certificate.tbs.data = (const uint8_t*)&work; certificate.tbs.length = sizeof work;
  munit_assert_int(TC_X509_signature_verify(&certificate, &key, &provider, &work), ==, TC_X509_SIGNATURE_ERROR);
  munit_assert_uint(state.calls, ==, 0);
  munit_assert_size(work, ==, 100);
  return MUNIT_OK;
}

static MunitResult segments(const MunitParameter params[], void* user)
{
  TC_X509_certificate certificate;
  TC_X509_public_key key;
  ProviderState state = {&certificate,&key,TC_X509_SIGNATURE_VALID,0,0};
  TC_X509_signature_provider provider = {verify,&state,NULL};
  TC_bytes message[3];
  size_t work = 100, required;
  (void)params; (void)user;
  fixture(&certificate,&key);
  message[0] = (TC_bytes){certificate.tbs.data,1};
  message[1] = (TC_bytes){NULL,0};
  message[2] = (TC_bytes){certificate.tbs.data + 1,1};
  munit_assert_int(TC_X509_signature_verify_message(message,3,&certificate.signature_algorithm,
      certificate.signature,&key,&provider,&work), ==, TC_X509_SIGNATURE_VALID);
  required = 100 - work;
  for (size_t budget = 0; budget < required; ++budget) {
    work = budget;
    munit_assert_int(TC_X509_signature_verify_message(message,3,&certificate.signature_algorithm,
        certificate.signature,&key,&provider,&work), ==, TC_X509_SIGNATURE_LIMIT);
  }
  work = 100; state.calls = 0;
  message[2] = (TC_bytes){(const uint8_t*)&work,sizeof work};
  munit_assert_int(TC_X509_signature_verify_message(message,3,&certificate.signature_algorithm,
      certificate.signature,&key,&provider,&work), ==, TC_X509_SIGNATURE_ERROR);
  munit_assert_size(work, ==, 100);
  message[2] = (TC_bytes){NULL,1};
  munit_assert_int(TC_X509_signature_verify_message(message,3,&certificate.signature_algorithm,
      certificate.signature,&key,&provider,&work), ==, TC_X509_SIGNATURE_ERROR);
  munit_assert_size(work, ==, 100);
  munit_assert_int(TC_X509_signature_verify_message(message,SIZE_MAX,&certificate.signature_algorithm,
      certificate.signature,&key,&provider,&work), ==, TC_X509_SIGNATURE_ERROR);
  munit_assert_uint(state.calls, ==, 0);
  certificate.tbs.length = 0;
  munit_assert_int(TC_X509_signature_verify_message(NULL,0,&certificate.signature_algorithm,
      certificate.signature,&key,&provider,&work), ==, TC_X509_SIGNATURE_VALID);
  munit_assert_uint(state.calls, ==, 1);
  return MUNIT_OK;
}

static TC_X509_signature_result verify_digest(void* context, TC_bytes digest,
    const TC_signature_algorithm* algorithm, TC_bytes signature,
    const TC_X509_public_key* key, size_t* work)
{
  ProviderState* state = context;
  munit_assert_size(digest.length, ==, SHA256_DIGEST_BYTES);
  munit_assert_int(algorithm->hash, ==, TC_HASH_SHA256);
  munit_assert_ptr_equal(signature.data,state->certificate->signature.data);
  munit_assert_ptr_equal(key,state->key);
  ++state->calls;
  if (state->increase) { ++*work; return TC_X509_SIGNATURE_VALID; }
  if (!*work) return TC_X509_SIGNATURE_LIMIT;
  --*work;
  return state->result;
}

static MunitResult digests(const MunitParameter params[], void* user)
{
  enum { DIGEST_BYTES = SHA256_DIGEST_BYTES, WORK_BUDGET = 1024 };
  uint8_t bytes[DIGEST_BYTES] = {0};
  const TC_bytes digest = {bytes,sizeof bytes};
  TC_signature_algorithm algorithm = {TC_SIGNATURE_ECDSA,TC_HASH_SHA256,TC_HASH_UNKNOWN,0};
  TC_X509_certificate certificate;
  TC_X509_public_key key;
  ProviderState state = {&certificate,&key,TC_X509_SIGNATURE_VALID,0,0};
  TC_X509_signature_provider provider = {NULL,&state,verify_digest};
  size_t work = WORK_BUDGET;
  (void)params; (void)user;
  fixture(&certificate,&key);
  munit_assert_int(TC_X509_signature_verify_digest(digest,&algorithm,certificate.signature,
      &key,&provider,&work), ==, TC_X509_SIGNATURE_VALID);
  const size_t required = WORK_BUDGET - work;
  for (size_t budget = 0; budget < required; ++budget) {
    work = budget; state.calls = 0;
    munit_assert_int(TC_X509_signature_verify_digest(digest,&algorithm,certificate.signature,
        &key,&provider,&work), ==, TC_X509_SIGNATURE_LIMIT);
    munit_assert_uint(state.calls, ==, budget == required - 1 ? 1 : 0);
  }
  work = required;
  munit_assert_int(TC_X509_signature_verify_digest(digest,&algorithm,certificate.signature,
      &key,&provider,&work), ==, TC_X509_SIGNATURE_VALID);
  munit_assert_size(work, ==, 0);
  for (unsigned result = TC_X509_SIGNATURE_VALID; result <= TC_X509_SIGNATURE_LIMIT; ++result) {
    state.result = (TC_X509_signature_result)result; work = WORK_BUDGET;
    munit_assert_int(TC_X509_signature_verify_digest(digest,&algorithm,certificate.signature,
        &key,&provider,&work), ==, result);
  }
  state.result = (TC_X509_signature_result)99; work = WORK_BUDGET;
  munit_assert_int(TC_X509_signature_verify_digest(digest,&algorithm,certificate.signature,
      &key,&provider,&work), ==, TC_X509_SIGNATURE_ERROR);
  state.increase = 1; work = WORK_BUDGET;
  munit_assert_int(TC_X509_signature_verify_digest(digest,&algorithm,certificate.signature,
      &key,&provider,&work), ==, TC_X509_SIGNATURE_ERROR);
  munit_assert_size(work, ==, 0);
  state.increase = 0; state.calls = 0; work = WORK_BUDGET;
  munit_assert_int(TC_X509_signature_verify_digest((TC_bytes){(const uint8_t*)&work,DIGEST_BYTES},
      &algorithm,certificate.signature,&key,&provider,&work), ==, TC_X509_SIGNATURE_ERROR);
  munit_assert_size(work, ==, WORK_BUDGET);
  munit_assert_int(TC_X509_signature_verify_digest((TC_bytes){bytes,DIGEST_BYTES - 1},
      &algorithm,certificate.signature,&key,&provider,&work), ==, TC_X509_SIGNATURE_ERROR);
  munit_assert_uint(state.calls, ==, 0);
  provider.verify_digest = NULL;
  munit_assert_int(TC_X509_signature_verify_digest(digest,&algorithm,certificate.signature,
      &key,&provider,&work), ==, TC_X509_SIGNATURE_UNSUPPORTED);
  munit_assert_uint(state.calls, ==, 0);
  return MUNIT_OK;
}

static MunitResult issuer(const MunitParameter params[], void* user)
{
  static const uint8_t name[] = {0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A'};
  uint8_t other[sizeof name];
  uint32_t left[16], right[16];
  uint8_t used[2];
  TC_X509_name_workspace workspace = {left,right,16,used,2};
  const TC_TLV_limits bounds = {1024,1024,32,8};
  TC_X509_certificate certificate;
  TC_X509_trust_anchor anchor;
  ProviderState state = {&certificate,&anchor.public_key,TC_X509_SIGNATURE_VALID,0,0};
  TC_X509_signature_provider provider = {verify,&state,NULL};
  size_t work = 10000, required, i;
  (void)params; (void)user;
  fixture(&certificate, &anchor.public_key);
  certificate.issuer.data = name; certificate.issuer.length = sizeof name;
  memcpy(other, name, sizeof other); other[sizeof other - 1] = 'a';
  anchor.name.data = other; anchor.name.length = sizeof other;
  munit_assert_int(TC_X509_issuer_check(&certificate, anchor.name, &anchor.public_key, &provider, &bounds, &workspace, &work), ==, TC_X509_SIGNATURE_VALID);
  munit_assert_uint(state.calls, ==, 1);
  required = 10000 - work;
  for (i = 0; i < required; ++i) {
    state.calls = 0; work = i;
    munit_assert_int(TC_X509_issuer_check(&certificate, anchor.name, &anchor.public_key, &provider, &bounds, &workspace, &work), ==, TC_X509_SIGNATURE_LIMIT);
    munit_assert_uint(state.calls, <=, 1);
  }
  other[sizeof other - 1] = 'B'; work = 10000; state.calls = 0;
  munit_assert_int(TC_X509_issuer_check(&certificate, anchor.name, &anchor.public_key, &provider, &bounds, &workspace, &work), ==, TC_X509_SIGNATURE_INVALID);
  munit_assert_uint(state.calls, ==, 0);
  other[0] = 0x31; work = 10000;
  munit_assert_int(TC_X509_issuer_check(&certificate, anchor.name, &anchor.public_key, &provider, &bounds, &workspace, &work), ==, TC_X509_SIGNATURE_INVALID);
  munit_assert_uint(state.calls, ==, 0);
  memcpy(other, name, sizeof other); other[11] = 0x14; work = 10000;
  munit_assert_int(TC_X509_issuer_check(&certificate, anchor.name, &anchor.public_key, &provider, &bounds, &workspace, &work), ==, TC_X509_SIGNATURE_UNSUPPORTED);
  munit_assert_uint(state.calls, ==, 0);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/dispatch",dispatch,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/limits",limits,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/segments",segments,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/digests",digests,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/issuer",issuer,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/x509/signature",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
