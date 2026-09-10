/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/rsa.h>
#include "../../src/pki_verify_internal.h"
#include "munit.h"
#include "test_util.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <string.h>
#include <stdlib.h>
#include "openssl_hash.h"
#include "openssl_key.h"

typedef struct { unsigned calls, fail_at; } random_source;

static TC_status random_bytes(void* context, uint8_t* output, size_t length)
{
  random_source* source = context;
  ++source->calls;
  memset(output,0,length);
  if (length) output[length - 1] = 2;
  return source->calls == source->fail_at ? TC_ERROR : TC_OK;
}

static TC_RSA_result verify_pss(const TC_RSA_public_key* key,
    TC_hash_algorithm hash, TC_hash_algorithm mgf_hash, size_t salt_length,
    TC_bytes digest, TC_bytes signature, const TC_RSA_workspace* workspace,
    size_t work)
{
  const TC_RSA_pss_options options = {hash,mgf_hash,salt_length};
  TC_work_budget budget = {work > UINT32_MAX ? UINT32_MAX : (uint32_t)work};
  return TC_RSA_verify_pss_digest(key,&options,digest,signature,workspace,&budget);
}

static TC_RSA_result sign_pss(const TC_RSA_private_key* key,
    TC_hash_algorithm hash, TC_hash_algorithm mgf_hash, size_t salt_length,
    TC_bytes digest, uint8_t* signature, size_t signature_length,
    TC_random_fn random, void* context, size_t attempts,
    const TC_RSA_workspace* workspace, size_t work)
{
  const TC_RSA_pss_options options = {hash,mgf_hash,salt_length};
  TC_RSA_execution execution = {{random,context},attempts,
    {work > UINT32_MAX ? UINT32_MAX : (uint32_t)work}};
  return TC_RSA_sign_pss_digest(key,&options,digest,workspace,
      (TC_buffer){signature,signature_length},&execution);
}

static MunitResult signatures(const MunitParameter params[], void *user)
{
  const char* hash_name = munit_parameters_get(params,"hash");
  const char* mgf_name = munit_parameters_get(params,"mgf");
  const tc_test_openssl_hash* message_hash = tc_test_openssl_hash_get(hash_name);
  const tc_test_openssl_hash* mask_hash = tc_test_openssl_hash_get(mgf_name);
  const TC_hash_algorithm hash = message_hash->algorithm, mgf_hash = mask_hash->algorithm;
  const EVP_MD* method = message_hash->method();
  const EVP_MD* mgf_method = mask_hash->method();
  const size_t digest_length = (size_t)EVP_MD_get_size(method);
  const size_t mgf_length = (size_t)EVP_MD_get_size(mgf_method);
  const unsigned bits = (unsigned)strtoul(munit_parameters_get(params,"bits"),NULL,10);
  const int full_failure_coverage = !strcmp(hash_name,"SHA256") &&
      !strcmp(mgf_name,"SHA256");
  (void)user;
#if TC_RSA_SMALL
  if (bits > 1024 && !full_failure_coverage) return MUNIT_SKIP;
#endif
  {
    EVP_PKEY *generated = EVP_RSA_gen(bits);
    uint8_t components[5][TC_TEST_RSA_MAX_BYTES], signature[TC_TEST_RSA_MAX_BYTES], digest[64] = {0};
    TC_RSA_word scratch[TC_RSA_SIGN_WORKSPACE_WORDS(3072)];
    TC_RSA_workspace workspace = {scratch,sizeof scratch / sizeof scratch[0]};
    TC_RSA_public_key key;
    const int salts[] = {0,1,32,(int)(bits / 8 - digest_length - 2)};
    size_t i;
    munit_assert_not_null(generated);
    const size_t exponent_length = tc_test_rsa_export(generated,components,bits / 8);
    munit_assert_size(exponent_length, >, 0);
    key.modulus = (TC_bytes){components[0],bits / 8};
    key.exponent = (TC_bytes){components[1],exponent_length};
    TC_RSA_private_key private_key = {key,{components[2],key.modulus.length},
      {components[3],key.modulus.length},{components[4],key.modulus.length},NULL};
    for (i = 0; i < sizeof salts / sizeof salts[0]; ++i) {
      EVP_PKEY_CTX *signer = EVP_PKEY_CTX_new(generated,NULL);
      size_t length = sizeof signature;
      munit_assert_not_null(signer);
      munit_assert_int(EVP_PKEY_sign_init(signer), ==, 1);
      munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(signer,RSA_PKCS1_PSS_PADDING), ==, 1);
      munit_assert_int(EVP_PKEY_CTX_set_signature_md(signer,method), ==, 1);
      munit_assert_int(EVP_PKEY_CTX_set_rsa_mgf1_md(signer,mgf_method), ==, 1);
      munit_assert_int(EVP_PKEY_CTX_set_rsa_pss_saltlen(signer,salts[i]), ==, 1);
      munit_assert_int(EVP_PKEY_sign(signer,signature,&length,digest,digest_length), ==, 1);
      munit_assert_int(verify_pss(&key,hash,mgf_hash,
        (size_t)salts[i],(TC_bytes){digest,digest_length},(TC_bytes){signature,length},&workspace,SIZE_MAX), ==, TC_RSA_OK);
      munit_assert_true(tc_test_all_zero(scratch,TC_RSA_verify_workspace_words(bits) * sizeof scratch[0]));
      munit_assert_int(verify_pss(&key,hash,mgf_hash,
        (size_t)salts[i] + 1,(TC_bytes){digest,digest_length},(TC_bytes){signature,length},&workspace,SIZE_MAX), ==, TC_RSA_INVALID);
      digest[0] ^= 1;
      munit_assert_int(verify_pss(&key,hash,mgf_hash,
        (size_t)salts[i],(TC_bytes){digest,digest_length},(TC_bytes){signature,length},&workspace,SIZE_MAX), ==, TC_RSA_INVALID);
      digest[0] ^= 1;
      munit_assert_int(verify_pss(&key,hash,mgf_hash,
        (size_t)salts[i],(TC_bytes){digest,digest_length},(TC_bytes){signature,length},&workspace,0), ==, TC_RSA_LIMIT);
      {
        TC_X509_public_key issuer = {0};
        TC_signature_algorithm algorithm = {TC_SIGNATURE_RSA_PSS,hash,mgf_hash,(uint32_t)salts[i]};
        issuer.type = TC_KEY_RSA;
        issuer.modulus = key.modulus; issuer.exponent = key.exponent;
        munit_assert_int(tc_pki_verify_digest(&algorithm,&issuer,
            (TC_bytes){digest,digest_length},(TC_bytes){signature,length},
            NULL,&workspace,32768), ==, TC_X509_SIGNATURE_VALID);
        munit_assert_int(tc_pki_verify_digest(&algorithm,&issuer,
            (TC_bytes){digest,digest_length},(TC_bytes){signature,length},
            NULL,&workspace,0), ==, TC_X509_SIGNATURE_LIMIT);
        ++algorithm.salt_length;
        munit_assert_int(tc_pki_verify_digest(&algorithm,&issuer,
            (TC_bytes){digest,digest_length},(TC_bytes){signature,length},
            NULL,&workspace,32768), ==, TC_X509_SIGNATURE_INVALID);
        --algorithm.salt_length;
        signature[length - 1] ^= 1;
        munit_assert_int(tc_pki_verify_digest(&algorithm,&issuer,
            (TC_bytes){digest,digest_length},(TC_bytes){signature,length},
            NULL,&workspace,32768), ==, TC_X509_SIGNATURE_INVALID);
        signature[length - 1] ^= 1;
        if (i == 0) {
          munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(signer,RSA_PKCS1_PADDING), ==, 1);
          length = sizeof signature;
          munit_assert_int(EVP_PKEY_sign(signer,signature,&length,digest,digest_length), ==, 1);
          algorithm.scheme = TC_SIGNATURE_RSA_V15;
          munit_assert_int(tc_pki_verify_digest(&algorithm,&issuer,
              (TC_bytes){digest,digest_length},(TC_bytes){signature,length},
              NULL,&workspace,32768), ==, TC_X509_SIGNATURE_VALID);
          digest[0] ^= 1;
          munit_assert_int(tc_pki_verify_digest(&algorithm,&issuer,
              (TC_bytes){digest,digest_length},(TC_bytes){signature,length},
              NULL,&workspace,32768), ==, TC_X509_SIGNATURE_INVALID);
          digest[0] ^= 1;
          munit_assert_int(tc_pki_verify_digest(&algorithm,&issuer,
              (TC_bytes){digest,digest_length - 1},(TC_bytes){signature,length},
              NULL,&workspace,32768), ==, TC_X509_SIGNATURE_ERROR);
          munit_assert_int(tc_pki_verify_digest(&algorithm,&issuer,
              (TC_bytes){digest,digest_length},(TC_bytes){signature,length},
              NULL,NULL,32768), ==, TC_X509_SIGNATURE_ERROR);
        }
      }
      EVP_PKEY_CTX_free(signer);
      random_source random = {0,0};
      munit_assert_int(sign_pss(&private_key,hash,mgf_hash,
          (size_t)salts[i],(TC_bytes){digest,digest_length},signature,key.modulus.length,
          random_bytes,&random,1,&workspace,SIZE_MAX), ==, TC_RSA_OK);
      munit_assert_uint(random.calls, ==, salts[i] ? 2 : 1);
      munit_assert_true(tc_test_all_zero(scratch,TC_RSA_sign_workspace_words(bits) * sizeof *scratch));
      EVP_PKEY_CTX* verifier = EVP_PKEY_CTX_new(generated,NULL);
      munit_assert_not_null(verifier);
      munit_assert_int(EVP_PKEY_verify_init(verifier), ==, 1);
      munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(verifier,RSA_PKCS1_PSS_PADDING), ==, 1);
      munit_assert_int(EVP_PKEY_CTX_set_signature_md(verifier,method), ==, 1);
      munit_assert_int(EVP_PKEY_CTX_set_rsa_mgf1_md(verifier,mgf_method), ==, 1);
      munit_assert_int(EVP_PKEY_CTX_set_rsa_pss_saltlen(verifier,salts[i]), ==, 1);
      munit_assert_int(EVP_PKEY_verify(verifier,signature,key.modulus.length,digest,digest_length), ==, 1);
      EVP_PKEY_CTX_free(verifier);
      if (!full_failure_coverage) continue;
      for (unsigned fail_at = 1; fail_at <= (salts[i] ? 2u : 1u); ++fail_at) {
        random = (random_source){0,fail_at};
        memset(signature,0xa5,sizeof signature); memset(scratch,0xa5,sizeof scratch);
        munit_assert_int(sign_pss(&private_key,hash,mgf_hash,
            (size_t)salts[i],(TC_bytes){digest,digest_length},signature,key.modulus.length,
            random_bytes,&random,1,&workspace,SIZE_MAX), ==, TC_RSA_ERROR);
        munit_assert_uint(random.calls, ==, fail_at);
        for (size_t j = 0; j < sizeof signature; ++j)
          munit_assert_uint(signature[j], ==, 0xa5);
        const size_t used = TC_RSA_sign_workspace_words(bits) * sizeof *scratch;
        munit_assert_true(tc_test_all_zero(scratch,used));
        for (size_t j = used; j < sizeof scratch; ++j)
          munit_assert_uint(((uint8_t*)scratch)[j], ==, 0xa5);
      }
      random = (random_source){0,0};
      memset(signature,0xa5,sizeof signature); memset(scratch,0xa5,sizeof scratch);
      munit_assert_int(sign_pss(&private_key,hash,mgf_hash,
          (size_t)salts[i],(TC_bytes){digest,digest_length},signature,key.modulus.length,
          random_bytes,&random,1,&workspace,0), ==, TC_RSA_LIMIT);
      munit_assert_uint(random.calls, ==, 0);
      for (size_t j = 0; j < sizeof signature; ++j)
        munit_assert_uint(signature[j], ==, 0xa5);
      for (size_t j = 0; j < sizeof scratch; ++j)
        munit_assert_uint(((uint8_t*)scratch)[j], ==, 0xa5);
      const size_t oversized_salts[] = {key.modulus.length - digest_length - 1,SIZE_MAX};
      for (size_t j = 0; j < sizeof oversized_salts / sizeof *oversized_salts; ++j) {
        munit_assert_int(sign_pss(&private_key,hash,mgf_hash,
            oversized_salts[j],(TC_bytes){digest,digest_length},signature,key.modulus.length,
            random_bytes,&random,1,&workspace,SIZE_MAX), ==, TC_RSA_INVALID);
        munit_assert_uint(random.calls, ==, 0);
        for (size_t k = 0; k < sizeof signature; ++k)
          munit_assert_uint(signature[k], ==, 0xa5);
        for (size_t k = 0; k < sizeof scratch; ++k)
          munit_assert_uint(((uint8_t*)scratch)[k], ==, 0xa5);
      }
      const size_t db_length = key.modulus.length - digest_length - 1;
      const size_t mask_blocks = db_length / mgf_length + (db_length % mgf_length != 0);
      const size_t encoding_work = key.modulus.length + digest_length + (size_t)salts[i] + 9 +
          db_length + mask_blocks * (digest_length + 5);
      const size_t private_work = 48 * key.modulus.length + 32 * key.exponent.length + 9;
      const size_t exact_work = encoding_work + private_work + (salts[i] != 0);
      for (unsigned short_work = 0; short_work < 2; ++short_work) {
        random = (random_source){0,0};
        memset(signature,0xa5,sizeof signature); memset(scratch,0xa5,sizeof scratch);
        munit_assert_int(sign_pss(&private_key,hash,mgf_hash,
            (size_t)salts[i],(TC_bytes){digest,digest_length},signature,key.modulus.length,
            random_bytes,&random,1,&workspace,exact_work - short_work), ==,
            short_work ? TC_RSA_LIMIT : TC_RSA_OK);
        munit_assert_uint(random.calls, ==, (salts[i] != 0) + !short_work);
        munit_assert_true(tc_test_all_zero(scratch,TC_RSA_sign_workspace_words(bits) * sizeof *scratch));
        if (short_work) {
          for (size_t j = 0; j < sizeof signature; ++j)
            munit_assert_uint(signature[j], ==, 0xa5);
        } else {
          munit_assert_int(verify_pss(&key,hash,mgf_hash,
              (size_t)salts[i],(TC_bytes){digest,digest_length},
              (TC_bytes){signature,key.modulus.length},&workspace,SIZE_MAX), ==, TC_RSA_OK);
        }
      }
    }
    EVP_PKEY_free(generated);
  }
  return MUNIT_OK;
}
static char* sizes[] = {"1024","2048","3072",NULL};
static char* hash_names[] = {"SHA1","SHA224","SHA256","SHA384","SHA512",NULL};
static MunitParameterEnum parameters[] = {
  {"bits",sizes},{"hash",hash_names},{"mgf",hash_names},{NULL,NULL}
};
static MunitTest tests[] = {
  {"/signatures",signatures,NULL,NULL,MUNIT_TEST_OPTION_NONE,parameters},
  {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
};
int main(int argc, char **argv)
{
  MunitSuite suite = {"/rsa-pss",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
