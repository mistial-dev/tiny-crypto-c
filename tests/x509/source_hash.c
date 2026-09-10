/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../src/source_hash_internal.h"
#include "../../src/x509_crl_source_internal.h"
#include "../../src/pki_signature_internal.h"
#include <tiny_crypto/x509_crypto.h>
#include <tiny_crypto/x509_crl_source.h>
#include "munit.h"
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

static TC_status failed_read(void* context, uint64_t offset, uint8_t* output, size_t length)
{
  (void)context; (void)offset;
  memset(output,0xa5,length);
  return TC_ERROR;
}

static MunitResult hashing(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  static const uint8_t expected[] = {
    0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
    0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
  TC_bytes bytes = {(const uint8_t*)"!abc?",5};
  TC_source source = {tc_source_memory_read,&bytes,bytes.length};
  for (size_t window_size = 1; window_size <= 8; ++window_size) {
    uint8_t window[8], digest[32];
    tc_source_reader reader;
    tc_source_hash state;
    int complete = 0;
    munit_assert_int(tc_source_reader_init(&reader,&source,
      (TC_buffer){window,window_size},16,16),==,TC_RESULT_OK);
    munit_assert_int(tc_source_hash_init(&state,&reader,TC_HASH_SHA256,1,3),==,TC_RESULT_OK);
    munit_assert_int(tc_source_hash_final(&state,(TC_buffer){digest,sizeof digest}),==,TC_RESULT_ARGUMENT);
    for (size_t step = 0; step < 3; ++step) {
      munit_assert_int(tc_source_hash_step(&state,1,&complete),==,TC_RESULT_OK);
      munit_assert_int(complete,==,step == 2);
    }
    munit_assert_int(tc_source_hash_final(&state,(TC_buffer){digest,1}),==,TC_RESULT_LIMIT);
    munit_assert_int(tc_source_hash_final(&state,(TC_buffer){digest,sizeof digest}),==,TC_RESULT_OK);
    munit_assert_memory_equal(sizeof expected,digest,expected);
    munit_assert_int(tc_source_hash_step(&state,1,&complete),==,TC_RESULT_ARGUMENT);
  }
  uint8_t window[1], digest[32];
  tc_source_reader reader;
  tc_source_hash state;
  int complete = 7;
  munit_assert_int(tc_source_reader_init(&reader,&source,(TC_buffer){window,1},1,1),==,TC_RESULT_OK);
  munit_assert_int(tc_source_hash_init(&state,&reader,TC_HASH_SHA256,1,3),==,TC_RESULT_OK);
  munit_assert_int(tc_source_hash_step(&state,3,&complete),==,TC_RESULT_LIMIT);
  munit_assert_int(complete,==,7);
  munit_assert_false(state.active);
  memset(digest,0xa5,sizeof digest);
  munit_assert_int(tc_source_hash_final(&state,(TC_buffer){digest,sizeof digest}),==,TC_RESULT_ARGUMENT);
  for (size_t i = 0; i < sizeof digest; ++i) munit_assert_uint8(digest[i],==,0xa5);
  source.read = failed_read;
  munit_assert_int(tc_source_reader_init(&reader,&source,(TC_buffer){window,1},8,8),==,TC_RESULT_OK);
  munit_assert_int(tc_source_hash_init(&state,&reader,TC_HASH_SHA256,1,3),==,TC_RESULT_OK);
  munit_assert_int(tc_source_hash_step(&state,3,&complete),==,TC_RESULT_ERROR);
  munit_assert_int(complete,==,7);
  munit_assert_false(state.active);
  const uint8_t* cleared = (const uint8_t*)&state.hash;
  for (size_t i = 0; i < sizeof state.hash; ++i) munit_assert_uint8(cleared[i],==,0);
  munit_assert_int(tc_source_hash_init(&state,&reader,TC_HASH_SHA256,UINT64_MAX,1),==,TC_RESULT_ARGUMENT);
  munit_assert_int(tc_source_hash_init(&state,&reader,TC_HASH_UNKNOWN,0,0),==,TC_RESULT_UNSUPPORTED);
  static const uint8_t empty_digest[] = {
    0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
    0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55};
  munit_assert_int(tc_source_hash_init(&state,&reader,TC_HASH_SHA256,source.length,0),==,TC_RESULT_OK);
  munit_assert_int(tc_source_hash_step(&state,1,&complete),==,TC_RESULT_OK);
  munit_assert_true(complete);
  munit_assert_int(tc_source_hash_final(&state,(TC_buffer){digest,sizeof digest}),==,TC_RESULT_OK);
  munit_assert_memory_equal(sizeof digest,digest,empty_digest);
  return MUNIT_OK;
}

typedef struct { FILE* file; uint64_t flip; int corrupt; } file_source;

static MunitResult preparation(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  static const uint8_t encoded[] = {
    0x30,0x44,0x30,0x2f,2,1,1,
    0x30,13,6,9,0x2a,0x86,0x48,0x86,0xf7,13,1,1,11,5,0,
    0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A',
    0x17,13,'2','6','0','1','0','1','0','0','0','0','0','0','Z',
    0x30,13,6,9,0x2a,0x86,0x48,0x86,0xf7,13,1,1,11,5,0,3,2,0,1};
  TC_bytes bytes = {encoded,sizeof encoded};
  TC_source source = {tc_source_memory_read,&bytes,bytes.length};
  TC_X509_crl_storage state[256];
  uint8_t window[16], metadata[256], scratch[256], issuer[64];
  TC_TLV_frame frames[16]; TC_bytes oids[8];
  uint32_t left[32], right[32]; uint8_t names[8];
  TC_X509_crl_prepare_workspace workspace = {
    {(uint8_t*)state,sizeof state},{window,sizeof window},{metadata,sizeof metadata},
    {scratch,sizeof scratch},{issuer,sizeof issuer},{frames,16,oids,8},{left,right,32,names,8},NULL,0};
  TC_X509_crl_prepare_options options = {{256,256,128,16},sizeof encoded,4096,4096,0};
  TC_X509_crl_job* job = NULL;
  size_t work = 60000;
  TC_X509_crl_prepare_workspace bad = workspace;
  bad.window = bad.metadata;
  munit_assert_int(TC_X509_crl_prepare_begin(&source,NULL,0,&options,&bad,&work,&job),==,TC_TLV_ARGUMENT);
  munit_assert_null(job);
  options.max_input--;
  munit_assert_int(TC_X509_crl_prepare_begin(&source,NULL,0,&options,&workspace,&work,&job),==,TC_TLV_LIMIT);
  munit_assert_null(job); options.max_input++;
  munit_assert_int(TC_X509_crl_prepare_begin(&source,NULL,0,&options,&workspace,&work,&job),==,TC_TLV_OK);
  const size_t untouched_work = work;
  munit_assert_int(TC_X509_crl_prepare_step(job,1,1,&work,(int*)&work),==,TC_TLV_ARGUMENT);
  munit_assert_size(work,==,untouched_work);
  TC_X509_crl_record record;
  munit_assert_int(TC_X509_crl_prepare_finish(job,&record),==,TC_TLV_ARGUMENT);
  int complete = 0;
  while (!complete) {
    work = 60000;
    munit_assert_int(TC_X509_crl_prepare_step(job,1,1,&work,&complete),==,TC_TLV_OK);
  }
  munit_assert_int(TC_X509_crl_prepare_finish(job,(TC_X509_crl_record*)job),==,TC_TLV_ARGUMENT);
  munit_assert_int(TC_X509_crl_prepare_finish(job,&record),==,TC_TLV_OK);
  const TC_bytes tbs = {encoded + 2,49};
  uint8_t expected[32]; tc_hash_workspace hash;
  munit_assert_int(tc_hash_digest_parts(TC_HASH_SHA256,&tbs,1,expected,&hash),==,TC_OK);
  munit_assert_memory_equal(sizeof expected,expected,record.crl.prepared->digest.data);
  TC_X509_crl_prepare_clear(job);
  munit_assert_int(TC_X509_crl_prepare_step(job,1,1,&work,&complete),==,TC_TLV_ARGUMENT);
  return MUNIT_OK;
}

static TC_status file_read(void* context, uint64_t offset, uint8_t* output, size_t length)
{
  file_source* source = (file_source*)context;
  if (offset > LONG_MAX || fseek(source->file,(long)offset,SEEK_SET) ||
      fread(output,1,length,source->file) != length) return TC_ERROR;
  if (source->corrupt && source->flip >= offset && source->flip - offset < length)
    output[(size_t)(source->flip - offset)] ^= 1;
  return TC_OK;
}

static MunitResult public_crl(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  const char* crl_path = getenv("TC_CRL_FILE");
  const char* issuer_path = getenv("TC_CRL_ISSUER");
  if (!crl_path || !issuer_path) return MUNIT_SKIP;
  enum { METADATA_BYTES = 4096, CERTIFICATE_BYTES = 8192, READ_BYTES = 1024,
    FRAME_COUNT = 32, OID_COUNT = 32, STEP_BYTES = 8192, RSA_BITS = 4096 };
  uint8_t metadata[METADATA_BYTES], certificate[CERTIFICATE_BYTES], window[READ_BYTES], digest[64];
  FILE* issuer_file = fopen(issuer_path,"rb");
  munit_assert_not_null(issuer_file);
  const size_t certificate_length = fread(certificate,1,sizeof certificate,issuer_file);
  munit_assert_size(certificate_length,>,0);
  munit_assert_int(fgetc(issuer_file),==,EOF);
  munit_assert_false(ferror(issuer_file));
  munit_assert_int(fclose(issuer_file),==,0);
  TC_TLV_frame frames[FRAME_COUNT];
  TC_bytes oids[OID_COUNT];
  TC_X509_workspace workspace = {frames,FRAME_COUNT,oids,OID_COUNT};
  const TC_TLV_limits limits = {CERTIFICATE_BYTES,CERTIFICATE_BYTES,4096,FRAME_COUNT};
  TC_X509_certificate issuer;
  munit_assert_int(TC_X509_read(certificate,certificate_length,&limits,&workspace,&issuer),==,TC_TLV_OK);
  file_source file = {fopen(crl_path,"rb"),0,0};
  munit_assert_not_null(file.file);
  munit_assert_int(fseek(file.file,0,SEEK_END),==,0);
  const long length = ftell(file.file);
  munit_assert_true(length > 0 && (uint64_t)length <= UINT64_C(1024) * 1024 * 1024);
  TC_source source = {file_read,&file,(uint64_t)length};
  tc_source_reader reader;
  munit_assert_int(tc_source_reader_init(&reader,&source,(TC_buffer){window,sizeof window},
    UINT64_MAX,UINT64_MAX),==,TC_RESULT_OK);
  tc_x509_crl_layout layout;
  tc_x509_crl crl;
  size_t work = 1000000;
  const tc_pki_tree_workspace tree = {frames,FRAME_COUNT,&work};
  munit_assert_int(tc_x509_crl_source_layout(&reader,&layout),==,TC_TLV_OK);
  munit_assert_int(tc_x509_crl_source_metadata(&reader,&layout,
    (TC_buffer){metadata,sizeof metadata},&limits,&tree,&crl),==,TC_TLV_OK);
  tc_x509_crl_extension_info extensions;
  munit_assert_int(tc_x509_crl_extension_info_read(crl.extensions,&limits,&tree,
    oids,OID_COUNT,&extensions),==,TC_TLV_OK);
  munit_assert_int(tc_x509_crl_extension_policy(&extensions),==,TC_TLV_OK);
  tc_x509_crl_source_revoked entries;
  uint8_t entry_scratch[METADATA_BYTES], issuer_storage[METADATA_BYTES];
  munit_assert_int(tc_x509_crl_source_revoked_init(&reader,layout.revoked,&crl,&extensions,
    source.length / 2 + 1,(TC_buffer){issuer_storage,sizeof issuer_storage},&entries),==,TC_TLV_OK);
  tc_x509_crl_source_scan scan;
  munit_assert_int(tc_x509_crl_source_scan_init(&reader,&entries,NULL,0,NULL,0,&scan),==,TC_TLV_OK);
  int scan_complete = 0;
  while (!scan_complete) {
    work = 60000;
    munit_assert_int(tc_x509_crl_source_scan_step(&scan,1,
      (TC_buffer){entry_scratch,sizeof entry_scratch},&limits,&tree,NULL,oids,OID_COUNT,&scan_complete),==,TC_TLV_OK);
  }
  munit_assert_int(tc_x509_crl_source_scan_finish(&scan,NULL,0),==,TC_TLV_OK);
  TC_signature_algorithm algorithm;
  munit_assert_int(tc_pki_signature_algorithm_read(&crl.signature_algorithm,TC_TLV_DER,
    &limits,&tree,&algorithm),==,TC_TLV_OK);
  tc_hash_info info;
  munit_assert_true(tc_hash_info_get(algorithm.hash,&info));
  TC_RSA_word words[TC_RSA_VERIFY_WORKSPACE_WORDS(RSA_BITS)];
  TC_RSA_workspace rsa = {words,sizeof words / sizeof *words};
  const TC_X509_native_workspace native = {NULL,&rsa,TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  const TC_X509_signature_provider provider = TC_X509_native_provider(&native);
  uint32_t left[128], right[128]; uint8_t matched_names[32];
  const TC_X509_name_workspace names = {left,right,128,matched_names,32};
  for (int corrupt = 0; corrupt <= 1; ++corrupt) {
    file.corrupt = corrupt;
    file.flip = layout.tbs.offset + layout.tbs.length / 2;
    munit_assert_int(tc_source_reader_init(&reader,&source,(TC_buffer){window,sizeof window},
      source.length + sizeof window,source.length),==,TC_RESULT_OK);
    tc_source_hash hash;
    munit_assert_int(tc_source_hash_init(&hash,&reader,algorithm.hash,layout.tbs.offset,layout.tbs.length),==,TC_RESULT_OK);
    int complete = 0;
    size_t steps = 0;
    while (!complete) {
      munit_assert_int(tc_source_hash_step(&hash,STEP_BYTES,&complete),==,TC_RESULT_OK);
      steps++;
    }
    munit_assert_true(steps == (layout.tbs.length + STEP_BYTES - 1) / STEP_BYTES);
    munit_assert_int(tc_source_hash_final(&hash,(TC_buffer){digest,sizeof digest}),==,TC_RESULT_OK);
    work = 1000000;
    munit_assert_int(TC_X509_signature_verify_digest((TC_bytes){digest,info.digest_length},
      &algorithm,crl.signature,&issuer.public_key,&provider,&work),==,
      corrupt ? TC_X509_SIGNATURE_INVALID : TC_X509_SIGNATURE_VALID);
    work = 1000000;
    munit_assert_int(tc_x509_crl_signer_digest_check(&crl,algorithm.hash,
      (TC_bytes){digest,info.digest_length},&issuer,&provider,&limits,&names,&work),==,
      corrupt ? TC_X509_SIGNATURE_INVALID : TC_X509_SIGNATURE_VALID);
    const TC_X509_crl_prepared prepared = {NULL,NULL,0,{digest,info.digest_length},algorithm.hash};
    crl.prepared = &prepared;
    work = 1000000;
    munit_assert_int(tc_x509_crl_signer_check(&crl,&issuer,&provider,&limits,&names,&work),==,
      corrupt ? TC_X509_SIGNATURE_INVALID : TC_X509_SIGNATURE_VALID);
    TC_X509_trust_anchor anchor = {0};
    anchor.name = issuer.subject; anchor.public_key = issuer.public_key;
    TC_X509_signature_provider digest_only = provider;
    digest_only.verify = NULL;
    work = 1000000;
    munit_assert_int(tc_x509_crl_anchor_check(&crl,&anchor,&digest_only,&limits,&names,&work),==,
      corrupt ? TC_X509_SIGNATURE_INVALID : TC_X509_SIGNATURE_VALID);
    crl.prepared = NULL;
    if (!corrupt) {
      work = 1000000;
      const TC_hash_algorithm wrong_hash = algorithm.hash == TC_HASH_SHA256 ? TC_HASH_SHA384 : TC_HASH_SHA256;
      munit_assert_int(tc_x509_crl_signer_digest_check(&crl,wrong_hash,
        (TC_bytes){digest,info.digest_length},&issuer,&provider,&limits,&names,&work),==,TC_X509_SIGNATURE_INVALID);
      const uint8_t wrong_name[] = {0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'Z'};
      TC_X509_certificate wrong_issuer = issuer;
      wrong_issuer.subject = (TC_bytes){wrong_name,sizeof wrong_name};
      work = 1000000;
      munit_assert_int(tc_x509_crl_signer_digest_check(&crl,algorithm.hash,
        (TC_bytes){digest,info.digest_length},&wrong_issuer,&provider,&limits,&names,&work),==,TC_X509_SIGNATURE_INVALID);
    }
  }
  file.corrupt = 0;
  TC_X509_crl_storage state_storage[256];
  munit_assert_size(sizeof state_storage,>=,TC_X509_crl_prepare_size());
  const TC_X509_crl_prepare_options options = {limits,source.length,
    source.length * 3 + METADATA_BYTES * 2,source.length + 4096,source.length / 2 + 1};
  const TC_X509_crl_prepare_workspace preparation = {
    {(uint8_t*)state_storage,sizeof state_storage},{window,sizeof window},
    {metadata,sizeof metadata},{entry_scratch,sizeof entry_scratch},{issuer_storage,sizeof issuer_storage},
    workspace,names,NULL,0};
  TC_X509_crl_job* job = NULL;
  work = 60000;
  munit_assert_int(TC_X509_crl_prepare_begin(&source,NULL,0,&options,&preparation,&work,&job),==,TC_TLV_OK);
  TC_X509_crl_record prepared_record, saved_record;
  memset(&prepared_record,0xa5,sizeof prepared_record); memcpy(&saved_record,&prepared_record,sizeof saved_record);
  munit_assert_int(TC_X509_crl_prepare_finish(job,&prepared_record),==,TC_TLV_ARGUMENT);
  munit_assert_memory_equal(sizeof prepared_record,&prepared_record,&saved_record);
  int complete = 0;
  while (!complete) {
    work = 60000;
    munit_assert_int(TC_X509_crl_prepare_step(job,16,STEP_BYTES,&work,&complete),==,TC_TLV_OK);
  }
  munit_assert_int(TC_X509_crl_prepare_finish(job,&prepared_record),==,TC_TLV_OK);
  munit_assert_not_null(prepared_record.crl.prepared);
  work = 1000000;
  munit_assert_int(tc_x509_crl_signer_check(&prepared_record.crl,&issuer,&provider,
    &limits,&names,&work),==,TC_X509_SIGNATURE_VALID);
  TC_X509_crl_prepare_clear(job);
  munit_assert_int(TC_X509_crl_prepare_finish(job,&prepared_record),==,TC_TLV_ARGUMENT);
  munit_assert_int(fclose(file.file),==,0);
  return MUNIT_OK;
}

static MunitResult content_comparison(const MunitParameter params[], void* user)
{
  (void)params; (void)user;
  const TC_bytes bytes = {(const uint8_t*)"abc",3};
  uint8_t digest[TC_SHA256_DIGESTLEN], different[TC_SHA256_DIGESTLEN];
  tc_hash_workspace hash;
  munit_assert_int(tc_hash_digest_parts(TC_HASH_SHA256,&bytes,1,digest,&hash),==,TC_OK);
  memcpy(different,digest,sizeof digest); different[0] ^= 1;
  TC_X509_crl_prepared a = {NULL,NULL,0,{digest,sizeof digest},TC_HASH_SHA256};
  TC_X509_crl_prepared b = {NULL,NULL,0,{different,sizeof different},TC_HASH_SHA256};
  TC_X509_crl left = {0}, right = {0};
  left.prepared = &a; right.prepared = &b;
  size_t work = 10000; int equal = 7;
  munit_assert_int(tc_x509_crl_content_equal(&left,&right,&work,&equal),==,TC_TLV_OK);
  munit_assert_false(equal);
  b.digest = a.digest;
  munit_assert_int(tc_x509_crl_content_equal(&left,&right,&work,&equal),==,TC_TLV_OK);
  munit_assert_true(equal);
  b.hash = TC_HASH_SHA384; equal = 7;
  munit_assert_int(tc_x509_crl_content_equal(&left,&right,&work,&equal),==,TC_TLV_UNSUPPORTED);
  munit_assert_int(equal,==,7);
  right.prepared = NULL; right.tbs = bytes;
  munit_assert_int(tc_x509_crl_content_equal(&left,&right,&work,&equal),==,TC_TLV_OK);
  munit_assert_true(equal);
  munit_assert_int(tc_x509_crl_content_equal(&right,&left,&work,&equal),==,TC_TLV_OK);
  munit_assert_true(equal);
  right.tbs = (TC_bytes){(const uint8_t*)"abd",3};
  munit_assert_int(tc_x509_crl_content_equal(&left,&right,&work,&equal),==,TC_TLV_OK);
  munit_assert_false(equal);
  work = 0; equal = 7;
  munit_assert_int(tc_x509_crl_content_equal(&left,&right,&work,&equal),==,TC_TLV_LIMIT);
  munit_assert_int(equal,==,7);
  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/content-comparison",content_comparison,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {"/hashing",hashing,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {"/preparation",preparation,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {"/public-crl",public_crl,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
  {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
};
static const MunitSuite suite = {"/source-hash",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
int main(int argc, char* argv[]) { return munit_suite_main(&suite,NULL,argc,argv); }
