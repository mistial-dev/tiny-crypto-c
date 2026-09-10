/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/x509_crypto.h>
#include "munit.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include "openssl_fixture.h"
#include "../../examples/x509_client.h"

static MunitResult signatures(const MunitParameter params[], void* user)
{
  static const uint8_t ec_oid[] = {0x2a,0x86,0x48,0xce,0x3d,4,3,2};
  uint8_t rsa_oid[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,11};
  static const uint8_t pss[] = {0x30,52,
    0xa0,15,0x30,13,6,9,0x60,0x86,0x48,1,0x65,3,4,2,1,5,0,
    0xa1,28,0x30,26,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,8,
    0x30,13,6,9,0x60,0x86,0x48,1,0x65,3,4,2,1,5,0,0xa2,3,2,1,32};
  uint8_t message[] = {'a','b','c'}, spki[512], signature[384];
  TC_ECDSA_workspace ec;
  TC_RSA_word words[TC_RSA_VERIFY_WORKSPACE_WORDS(3072)];
  TC_RSA_workspace rsa = {words,sizeof words / sizeof *words};
  TC_X509_native_workspace scratch = {&ec,&rsa,TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  TC_X509_signature_provider provider = TC_X509_native_provider(&scratch);
  (void)params; (void)user;
  for (unsigned kind = 0; kind < 3; ++kind) {
    EVP_PKEY* generated = kind == 0 ? EVP_EC_gen("prime256v1") : EVP_RSA_gen(2048);
    EVP_MD_CTX* signer = EVP_MD_CTX_new();
    EVP_PKEY_CTX* signing_key = NULL;
    unsigned char* cursor = spki;
    size_t signature_length = sizeof signature;
    int spki_length;
    TC_X509_public_key key;
    TC_DER_algorithm algorithm = {kind == 0 ? (TC_bytes){ec_oid,sizeof ec_oid} :
      (TC_bytes){rsa_oid,sizeof rsa_oid},{NULL,0}};
    munit_assert_not_null(generated); munit_assert_not_null(signer);
    spki_length = i2d_PUBKEY(generated,NULL);
    munit_assert_int(spki_length, >, 0); munit_assert_size((size_t)spki_length, <=, sizeof spki);
    munit_assert_int(i2d_PUBKEY(generated,&cursor), ==, spki_length);
    munit_assert_int(TC_X509_subject_public_key(spki,(size_t)spki_length,&key), ==, TC_TLV_OK);
    munit_assert_int(EVP_DigestSignInit(signer,&signing_key,EVP_sha256(),NULL,generated), ==, 1);
    if (kind == 2) {
      rsa_oid[8] = 10; algorithm.parameters = (TC_bytes){pss,sizeof pss};
      munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(signing_key,RSA_PKCS1_PSS_PADDING), ==, 1);
      munit_assert_int(EVP_PKEY_CTX_set_rsa_pss_saltlen(signing_key,32), ==, 1);
    }
    munit_assert_int(EVP_DigestSign(signer,signature,&signature_length,message,sizeof message), ==, 1);
    {
      enum { DIGEST_BYTES = 32, WORK_BUDGET = 100000 };
      uint8_t digest[DIGEST_BYTES];
      unsigned digest_length = 0;
      TC_signature_algorithm resolved = {kind == 0 ? TC_SIGNATURE_ECDSA :
        kind == 1 ? TC_SIGNATURE_RSA_V15 : TC_SIGNATURE_RSA_PSS,
        TC_HASH_SHA256,TC_HASH_SHA256,DIGEST_BYTES};
      munit_assert_int(EVP_Digest(message,sizeof message,digest,&digest_length,EVP_sha256(),NULL), ==, 1);
      munit_assert_uint(digest_length, ==, DIGEST_BYTES);
      const TC_bytes computed = {digest,sizeof digest};
      const TC_bytes signed_value = {signature,signature_length};
      size_t work = WORK_BUDGET;
      munit_assert_int(TC_X509_signature_verify_digest(computed,&resolved,signed_value,
          &key,&provider,&work), ==, TC_X509_SIGNATURE_VALID);
      const size_t required = WORK_BUDGET - work;
      work = required;
      munit_assert_int(TC_X509_signature_verify_digest(computed,&resolved,signed_value,
          &key,&provider,&work), ==, TC_X509_SIGNATURE_VALID);
      munit_assert_size(work, ==, 0);
      work = required - 1;
      munit_assert_int(TC_X509_signature_verify_digest(computed,&resolved,signed_value,
          &key,&provider,&work), ==, TC_X509_SIGNATURE_LIMIT);
      digest[0] ^= 1; work = WORK_BUDGET;
      munit_assert_int(TC_X509_signature_verify_digest(computed,&resolved,signed_value,
          &key,&provider,&work), ==, TC_X509_SIGNATURE_INVALID);
      digest[0] ^= 1; signature[signature_length - 1] ^= 1; work = WORK_BUDGET;
      munit_assert_int(TC_X509_signature_verify_digest(computed,&resolved,signed_value,
          &key,&provider,&work), ==, TC_X509_SIGNATURE_INVALID);
      signature[signature_length - 1] ^= 1; work = WORK_BUDGET;
      munit_assert_int(TC_X509_signature_verify_digest((TC_bytes){(const uint8_t*)&ec,DIGEST_BYTES},
          &resolved,signed_value,&key,&provider,&work), ==, TC_X509_SIGNATURE_ERROR);
      if (kind == 2) {
        ++resolved.salt_length; work = WORK_BUDGET;
        munit_assert_int(TC_X509_signature_verify_digest(computed,&resolved,signed_value,
            &key,&provider,&work), ==, TC_X509_SIGNATURE_INVALID);
      }
    }
    for (size_t split = 0; split <= sizeof message; ++split) {
      TC_bytes parts[] = {{message,split},{NULL,0},{message + split,sizeof message - split}};
      size_t work = 100000;
      munit_assert_int(TC_X509_signature_verify_message(parts,3,&algorithm,
          (TC_bytes){signature,signature_length},&key,&provider,&work), ==, TC_X509_SIGNATURE_VALID);
      size_t required = 100000 - work;
      work = required;
      munit_assert_int(TC_X509_signature_verify_message(parts,3,&algorithm,
          (TC_bytes){signature,signature_length},&key,&provider,&work), ==, TC_X509_SIGNATURE_VALID);
      munit_assert_size(work, ==, 0);
      work = required - 1;
      munit_assert_int(TC_X509_signature_verify_message(parts,3,&algorithm,
          (TC_bytes){signature,signature_length},&key,&provider,&work), ==, TC_X509_SIGNATURE_LIMIT);
      size_t saved_reservation = scratch.signature_work;
      scratch.signature_work = 0; work = 100000;
      munit_assert_int(TC_X509_signature_verify_message(parts,3,&algorithm,
          (TC_bytes){signature,signature_length},&key,&provider,&work), ==, TC_X509_SIGNATURE_LIMIT);
      scratch.signature_work = saved_reservation;
      if (kind == 0) scratch.ec = NULL;
      else scratch.rsa = NULL;
      work = 100000;
      munit_assert_int(TC_X509_signature_verify_message(parts,3,&algorithm,
          (TC_bytes){signature,signature_length},&key,&provider,&work), ==, TC_X509_SIGNATURE_ERROR);
      scratch.ec = &ec; scratch.rsa = &rsa;
      message[0] ^= 1; work = 100000;
      munit_assert_int(TC_X509_signature_verify_message(parts,3,&algorithm,
          (TC_bytes){signature,signature_length},&key,&provider,&work), ==, TC_X509_SIGNATURE_INVALID);
      message[0] ^= 1; work = 0;
      munit_assert_int(TC_X509_signature_verify_message(parts,3,&algorithm,
          (TC_bytes){signature,signature_length},&key,&provider,&work), ==, TC_X509_SIGNATURE_LIMIT);
      work = 100000; parts[0] = (TC_bytes){(const uint8_t*)&ec,1};
      munit_assert_int(TC_X509_signature_verify_message(parts,3,&algorithm,
          (TC_bytes){signature,signature_length},&key,&provider,&work), ==, TC_X509_SIGNATURE_ERROR);
    }
    EVP_MD_CTX_free(signer); EVP_PKEY_free(generated);
  }
  return MUNIT_OK;
}
typedef struct {
  TC_bytes candidate;
  TC_X509_store_anchor anchor;
} certificate_source;

static TC_TLV_result source_candidate(void* context, size_t index, size_t* work, TC_bytes* out)
{
  if (index) return TC_TLV_END;
  if (!*work) return TC_TLV_LIMIT;
  --*work; *out = ((certificate_source*)context)->candidate;
  return TC_TLV_OK;
}

static TC_TLV_result source_anchor(void* context, size_t index, size_t* work, TC_X509_store_anchor* out)
{
  if (index) return TC_TLV_END;
  if (!*work) return TC_TLV_LIMIT;
  --*work; *out = ((certificate_source*)context)->anchor;
  return TC_TLV_OK;
}

static MunitResult paths(const MunitParameter params[], void* user)
{
  TC_ECDSA_workspace ec;
  TC_RSA_word words[TC_RSA_VERIFY_WORKSPACE_WORDS(3072)];
  TC_RSA_workspace rsa = {words,sizeof words / sizeof *words};
  TC_X509_native_workspace scratch = {&ec,&rsa,TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  TC_X509_signature_provider provider = TC_X509_native_provider(&scratch);
  ExampleX509Workspace storage;
  TC_TLV_frame frames[16];
  TC_bytes oids[16];
  TC_X509_workspace parser = {frames,16,oids,16};
  TC_TLV_limits limits = {2048,2048,256,16};
  TC_X509_time at = {2026,1,1,0,0,0};
  uint8_t root_der[2048], leaf_der[2048];
  (void)params; (void)user;
  for (unsigned kind = 0; kind < 2; ++kind) {
    EVP_PKEY* root_key = kind ? EVP_RSA_gen(2048) : EVP_EC_gen("prime256v1");
    EVP_PKEY* leaf_key = EVP_EC_gen("prime256v1");
    X509* root = make_certificate(root_key,"Root",NULL);
    X509* leaf = make_certificate(leaf_key,"Leaf",root);
    size_t root_length = encode_certificate(root,root_key,EVP_sha256(),root_der,sizeof root_der);
    size_t leaf_length = encode_certificate(leaf,root_key,EVP_sha256(),leaf_der,sizeof leaf_der);
    TC_X509_certificate parsed_root, parsed_leaf;
    TC_X509_path_result result;
    munit_assert_int(TC_X509_read(root_der,root_length,&limits,&parser,&parsed_root), ==, TC_TLV_OK);
    munit_assert_int(TC_X509_read(leaf_der,leaf_length,&limits,&parser,&parsed_leaf), ==, TC_TLV_OK);
    TC_X509_trust_anchor anchor = {parsed_root.subject,parsed_root.public_key};
    TC_bytes chain = {leaf_der,leaf_length};
    size_t work = 100000;
    munit_assert_int(TC_X509_signature_verify(&parsed_leaf,&anchor.public_key,&provider,&work), ==, TC_X509_SIGNATURE_VALID);
    munit_assert_int(example_check_client_certificate(&chain,1,&anchor,&at,&provider,
        1000000,&storage,&result), ==, TC_X509_PATH_VALID);
    munit_assert_ptr_equal(result.public_key.key.data,parsed_leaf.public_key.key.data);
    at.year = 2029;
    munit_assert_int(example_check_client_certificate(&chain,1,&anchor,&at,&provider,
        1000000,&storage,&result), ==, TC_X509_PATH_INVALID);
    at.year = 2026;
    leaf_der[leaf_length - 1] ^= 1;
    munit_assert_int(example_check_client_certificate(&chain,1,&anchor,&at,&provider,
        1000000,&storage,&result), ==, TC_X509_PATH_INVALID);
    leaf_der[leaf_length - 1] ^= 1;
    anchor.public_key = parsed_leaf.public_key;
    munit_assert_int(example_check_client_certificate(&chain,1,&anchor,&at,&provider,
        1000000,&storage,&result), ==, TC_X509_PATH_INVALID);
    {
      uint8_t intermediate_der[2048];
      EVP_PKEY* intermediate_key = EVP_EC_gen("prime256v1");
      X509* intermediate = make_certificate(intermediate_key,"Intermediate",root);
      ExampleX509SearchWorkspace search;
      TC_X509_search_result found;
      certificate_source records = {0};
      TC_X509_store_source source = {&records,1,1,source_candidate,source_anchor};
      add_extension(intermediate,NID_basic_constraints,"critical,CA:TRUE,pathlen:0");
      add_extension(intermediate,NID_key_usage,"critical,keyCertSign");
      size_t intermediate_length = encode_certificate(intermediate,root_key,EVP_sha256(),
          intermediate_der,sizeof intermediate_der);
      munit_assert_int(X509_set_issuer_name(leaf,X509_get_subject_name(intermediate)), ==, 1);
      leaf_length = encode_certificate(leaf,intermediate_key,EVP_sha256(),leaf_der,sizeof leaf_der);
      records.candidate = (TC_bytes){intermediate_der,intermediate_length};
      records.anchor.trust = (TC_X509_trust_anchor){parsed_root.subject,parsed_root.public_key};
      chain = (TC_bytes){leaf_der,leaf_length};
      munit_assert_int(example_find_client_path(chain,&source,&at,&provider,1000000,
          &search,&found), ==, TC_X509_PATH_VALID);
      munit_assert_size(found.count, ==, 2);
      munit_assert_size(found.anchor_index, ==, 0);
      munit_assert_ptr_equal(found.path[0].data,intermediate_der);
      munit_assert_ptr_equal(found.path[1].data,leaf_der);
      intermediate_der[intermediate_length - 1] ^= 1;
      munit_assert_int(example_find_client_path(chain,&source,&at,&provider,1000000,
          &search,&found), ==, TC_X509_PATH_INVALID);
      X509_free(intermediate); EVP_PKEY_free(intermediate_key);
    }
    X509_free(leaf); X509_free(root); EVP_PKEY_free(leaf_key); EVP_PKEY_free(root_key);
  }
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {{"/signatures",signatures,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {"/paths",paths,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}};
  MunitSuite suite = {"/x509/native",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
