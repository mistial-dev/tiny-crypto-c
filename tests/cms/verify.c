/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/cms.h>
#include "munit.h"
#include <string.h>
#if TC_ENABLE_SHA256
#include <tiny_crypto/hash.h>
#endif

enum { FRAME_CAPACITY = 8, WORK_BUDGET = 4096, DIGEST_BYTES = 32 };
static const uint8_t record[] = {
  0x30,36,2,1,3,0x80,1,0xaa,
  0x30,13,6,9,0x60,0x86,0x48,1,0x65,3,4,2,1,5,0,
  0x30,10,6,8,0x2a,0x86,0x48,0xce,0x3d,4,3,2,4,1,1
};
static const uint8_t data_type[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,1};
static const uint8_t ec_type[] = {0x2a,0x86,0x48,0xce,0x3d,2,1};
static const uint8_t key_bytes[] = {4,1};
static const uint8_t digest_bytes[DIGEST_BYTES] = {0};
static const TC_TLV_limits limits = {256,256,64,FRAME_CAPACITY};

typedef struct { unsigned calls; int increase; const uint8_t* digest; } ProviderState;
static TC_X509_signature_result verify(void* context, TC_bytes digest,
    const TC_signature_algorithm* algorithm, TC_bytes signature,
    const TC_X509_public_key* key, size_t* work)
{
  ProviderState* state = context;
  munit_assert_int(algorithm->scheme, ==, TC_SIGNATURE_ECDSA);
  munit_assert_int(algorithm->hash, ==, TC_HASH_SHA256);
  munit_assert_size(digest.length, ==, DIGEST_BYTES);
  munit_assert_memory_equal(digest.length,digest.data,state->digest ? state->digest : digest_bytes);
  munit_assert_size(signature.length, ==, 1);
  munit_assert_uint(signature.data[0], ==, 1);
  munit_assert_int(key->type, ==, TC_KEY_EC);
  ++state->calls;
  if (state->increase) { ++*work; return TC_X509_SIGNATURE_VALID; }
  if (!*work) return TC_X509_SIGNATURE_LIMIT;
  --*work;
  return TC_X509_SIGNATURE_VALID;
}

static TC_X509_public_key public_key(void)
{
  TC_X509_public_key key = {0};
  key.type = TC_KEY_EC;
  key.algorithm.oid = (TC_bytes){ec_type,sizeof ec_type};
  key.key = (TC_bytes){key_bytes,sizeof key_bytes};
  return key;
}

static MunitResult verification(const MunitParameter params[], void* user)
{
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_CMS_signature_workspace workspace = {frames,FRAME_CAPACITY,NULL,0};
  TC_CMS_signer_info signer;
  TC_X509_public_key key = public_key();
  ProviderState state = {0};
  TC_X509_signature_provider provider = {NULL,&state,verify};
  const TC_bytes type = {data_type,sizeof data_type};
  const TC_bytes digest = {digest_bytes,sizeof digest_bytes};
  size_t work = WORK_BUDGET;
  (void)params; (void)user;
  munit_assert_int(TC_CMS_signer_info_read((TC_bytes){record,sizeof record},TC_TLV_BER,
      &limits,frames,FRAME_CAPACITY,&work,&signer), ==, TC_TLV_OK);
  work = WORK_BUDGET;
  munit_assert_int(TC_CMS_signer_verify_digest(&signer,type,digest,TC_CMS_ATTRIBUTES_DER,
      &key,&provider,&limits,&workspace,&work), ==, TC_X509_SIGNATURE_VALID);
  const size_t required = WORK_BUDGET - work;
  for (size_t budget = 0; budget < required; ++budget) {
    work = budget; state.calls = 0;
    munit_assert_int(TC_CMS_signer_verify_digest(&signer,type,digest,TC_CMS_ATTRIBUTES_DER,
        &key,&provider,&limits,&workspace,&work), ==, TC_X509_SIGNATURE_LIMIT);
    munit_assert_uint(state.calls, ==, budget == required - 1 ? 1 : 0);
  }
  work = required;
  munit_assert_int(TC_CMS_signer_verify_digest(&signer,type,digest,TC_CMS_ATTRIBUTES_DER,
      &key,&provider,&limits,&workspace,&work), ==, TC_X509_SIGNATURE_VALID);
  munit_assert_size(work, ==, 0);
  work = WORK_BUDGET; state.calls = 0;
  munit_assert_int(TC_CMS_signer_verify_digest(&signer,(TC_bytes){data_type,1},digest,
      TC_CMS_ATTRIBUTES_DER,&key,&provider,&limits,&workspace,&work), ==, TC_X509_SIGNATURE_INVALID);
  munit_assert_uint(state.calls, ==, 0);
  work = WORK_BUDGET;
  munit_assert_int(TC_CMS_signer_verify_digest(&signer,type,(TC_bytes){digest_bytes,DIGEST_BYTES - 1},
      TC_CMS_ATTRIBUTES_DER,&key,&provider,&limits,&workspace,&work), ==, TC_X509_SIGNATURE_ERROR);
  munit_assert_uint(state.calls, ==, 0);
  work = WORK_BUDGET;
  munit_assert_int(TC_CMS_signer_verify_digest(&signer,type,digest,(TC_CMS_attribute_encoding)99,
      &key,&provider,&limits,&workspace,&work), ==, TC_X509_SIGNATURE_ERROR);
  munit_assert_size(work, ==, WORK_BUDGET);
  state.increase = 1; work = WORK_BUDGET;
  munit_assert_int(TC_CMS_signer_verify_digest(&signer,type,digest,TC_CMS_ATTRIBUTES_DER,
      &key,&provider,&limits,&workspace,&work), ==, TC_X509_SIGNATURE_ERROR);
  munit_assert_size(work, ==, 0);
  provider.verify_digest = NULL; work = WORK_BUDGET;
  munit_assert_int(TC_CMS_signer_verify_digest(&signer,type,digest,TC_CMS_ATTRIBUTES_DER,
      &key,&provider,&limits,&workspace,&work), ==, TC_X509_SIGNATURE_UNSUPPORTED);
  return MUNIT_OK;
}

static MunitResult storage(const MunitParameter params[], void* user)
{
  enum { SIGNER, KEY, PROVIDER, LIMITS, WORKSPACE, INPUT, FRAMES, BUFFER, WORK, COUNT };
  union slot {
    TC_CMS_signer_info signer;
    TC_X509_public_key key;
    TC_X509_signature_provider provider;
    TC_TLV_limits limits;
    TC_CMS_signature_workspace workspace;
    TC_TLV_frame frames[FRAME_CAPACITY];
    uint8_t bytes[256];
    size_t work;
  } slots[COUNT];
  uint8_t saved[sizeof slots];
  ProviderState state = {0};
  (void)params; (void)user;
  for (unsigned operation = 0; operation < 3; ++operation)
  for (unsigned output = FRAMES; output < COUNT; ++output)
    for (unsigned input = 0; input < output; ++input) {
      void* pointers[COUNT];
      memset(slots,0,sizeof slots);
      for (unsigned i = 0; i < COUNT; ++i) pointers[i] = &slots[i];
      pointers[output] = pointers[input];
      *(size_t*)pointers[WORK] = WORK_BUDGET;
      TC_CMS_signer_info* signer = pointers[SIGNER];
      signer->encoded = (TC_bytes){pointers[INPUT],sizeof record};
      *(TC_X509_public_key*)pointers[KEY] = public_key();
      *(TC_X509_signature_provider*)pointers[PROVIDER] = (TC_X509_signature_provider){NULL,&state,verify};
      *(TC_TLV_limits*)pointers[LIMITS] = limits;
      *(TC_CMS_signature_workspace*)pointers[WORKSPACE] =
          (TC_CMS_signature_workspace){pointers[FRAMES],FRAME_CAPACITY,pointers[BUFFER],256};
      memcpy(saved,slots,sizeof slots);
      TC_X509_signature_result result;
      if (operation == 0) result = TC_CMS_signer_verify_digest(signer,
          (TC_bytes){data_type,sizeof data_type},(TC_bytes){digest_bytes,sizeof digest_bytes},
          TC_CMS_ATTRIBUTES_DER,pointers[KEY],pointers[PROVIDER],pointers[LIMITS],
          pointers[WORKSPACE],pointers[WORK]);
      else result = TC_CMS_signer_verify_content(signer,
          (TC_bytes){data_type,sizeof data_type},(TC_bytes){digest_bytes,sizeof digest_bytes},
          operation == 1 ? TC_CMS_CONTENT_RAW : TC_CMS_CONTENT_BER_OCTETS,
          TC_CMS_ATTRIBUTES_DER,pointers[KEY],pointers[PROVIDER],pointers[LIMITS],
          pointers[WORKSPACE],pointers[WORK]);
      munit_assert_int(result, ==, TC_X509_SIGNATURE_ERROR);
      munit_assert_memory_equal(sizeof slots,slots,saved);
    }
  munit_assert_uint(state.calls, ==, 0);
  return MUNIT_OK;
}

static MunitResult content(const MunitParameter params[], void* user)
{
  static const uint8_t message[] = {'a','b','c'};
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_CMS_signature_workspace workspace = {frames,FRAME_CAPACITY,NULL,0};
  TC_CMS_signer_info signer;
  TC_X509_public_key key = public_key();
  ProviderState state = {0};
  TC_X509_signature_provider provider = {NULL,&state,verify};
  const TC_bytes type = {data_type,sizeof data_type};
  size_t work = WORK_BUDGET;
  (void)params; (void)user;
  munit_assert_int(TC_CMS_signer_info_read((TC_bytes){record,sizeof record},TC_TLV_BER,
      &limits,frames,FRAME_CAPACITY,&work,&signer), ==, TC_TLV_OK);
#if TC_ENABLE_SHA256
  static const uint8_t primitive[] = {4,3,'a','b','c'};
  static const uint8_t definite[] = {0x24,7,4,1,'a',4,2,'b','c'};
  static const uint8_t indefinite[] = {0x24,0x80,4,1,'a',0x24,0x80,4,2,'b','c',0,0,0,0};
  static const uint8_t empty[] = {4,0};
  static const uint8_t wrong[] = {0x24,3,2,1,0};
  const TC_bytes inputs[] = {{message,sizeof message},{primitive,sizeof primitive},
    {definite,sizeof definite},{indefinite,sizeof indefinite},{NULL,0},{empty,sizeof empty},
    {wrong,sizeof wrong}};
  uint8_t expected[DIGEST_BYTES];
  for (size_t i = 0; i < sizeof inputs / sizeof *inputs; ++i) {
    const int raw = i == 0 || i == 4 || i == 6;
    const TC_CMS_content_encoding format = raw ? TC_CMS_CONTENT_RAW : TC_CMS_CONTENT_BER_OCTETS;
    TC_bytes bytes = raw ? inputs[i] : i == 5 ? (TC_bytes){NULL,0} :
        (TC_bytes){message,sizeof message};
    munit_assert_int(TC_SHA256_digest(bytes.data,bytes.length,expected), ==, TC_OK);
    state.digest = expected; work = WORK_BUDGET;
    munit_assert_int(TC_CMS_signer_verify_content(&signer,type,inputs[i],format,TC_CMS_ATTRIBUTES_DER,
        &key,&provider,&limits,&workspace,&work), ==, TC_X509_SIGNATURE_VALID);
    const size_t required = WORK_BUDGET - work;
    for (size_t budget = 0; budget < required; ++budget) {
      work = budget;
      munit_assert_int(TC_CMS_signer_verify_content(&signer,type,inputs[i],format,TC_CMS_ATTRIBUTES_DER,
          &key,&provider,&limits,&workspace,&work), ==, TC_X509_SIGNATURE_LIMIT);
    }
    work = required;
    munit_assert_int(TC_CMS_signer_verify_content(&signer,type,inputs[i],format,TC_CMS_ATTRIBUTES_DER,
        &key,&provider,&limits,&workspace,&work), ==, TC_X509_SIGNATURE_VALID);
    munit_assert_size(work, ==, 0);
    if (!raw) for (size_t length = 0; length < inputs[i].length; ++length) {
      work = WORK_BUDGET; state.calls = 0;
      munit_assert_int(TC_CMS_signer_verify_content(&signer,type,(TC_bytes){inputs[i].data,length},
          format,TC_CMS_ATTRIBUTES_DER,&key,&provider,&limits,&workspace,&work),
          ==, TC_X509_SIGNATURE_INVALID);
      munit_assert_uint(state.calls, ==, 0);
    }
  }
  work = WORK_BUDGET; state.calls = 0;
  munit_assert_int(TC_CMS_signer_verify_content(&signer,type,(TC_bytes){wrong,sizeof wrong},
      TC_CMS_CONTENT_BER_OCTETS,TC_CMS_ATTRIBUTES_DER,&key,&provider,&limits,&workspace,&work),
      ==, TC_X509_SIGNATURE_INVALID);
  munit_assert_uint(state.calls, ==, 0);
  TC_TLV_limits bounded = limits;
  for (unsigned bound = 0; bound < 2; ++bound) {
    bounded = limits;
    if (bound) bounded.max_value = sizeof message - 1;
    else bounded.max_input = sizeof message - 1;
    work = WORK_BUDGET;
    munit_assert_int(TC_CMS_signer_verify_content(&signer,type,(TC_bytes){message,sizeof message},
        TC_CMS_CONTENT_RAW,TC_CMS_ATTRIBUTES_DER,&key,&provider,&bounded,&workspace,&work),
        ==, TC_X509_SIGNATURE_LIMIT);
  }
#else
  work = WORK_BUDGET;
  munit_assert_int(TC_CMS_signer_verify_content(&signer,type,(TC_bytes){message,sizeof message},
      TC_CMS_CONTENT_RAW,TC_CMS_ATTRIBUTES_DER,&key,&provider,&limits,&workspace,&work),
      ==, TC_X509_SIGNATURE_UNSUPPORTED);
  munit_assert_uint(state.calls, ==, 0);
#endif
  work = WORK_BUDGET;
  munit_assert_int(TC_CMS_signer_verify_content(&signer,type,(TC_bytes){message,sizeof message},
      (TC_CMS_content_encoding)99,TC_CMS_ATTRIBUTES_DER,&key,&provider,&limits,&workspace,&work),
      ==, TC_X509_SIGNATURE_ERROR);
  munit_assert_size(work, ==, WORK_BUDGET);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {
    {"/digest",verification,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/storage",storage,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/content",content,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/cms/verify",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
