/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "../../src/rsa_oaep_internal.h"
#include "munit.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <stdlib.h>
#include "openssl_key.h"
#include "../../examples/rsa_encrypt.h"

enum { MAX_BYTES = 384, MAX_DIGEST = 64, WORK_BUDGET = 100000 };

static TC_status fixed_seed(void* context, uint8_t* output, size_t length)
{
  memcpy(output,context,length);
  return TC_OK;
}

static TC_status failed_seed(void* context, uint8_t* output, size_t length)
{
  ++*(size_t*)context;
  memset(output,0x3c,length);
  return TC_ERROR;
}

static EVP_PKEY_CTX* operation(EVP_PKEY* key, int encrypt, const EVP_MD* hash,
    const EVP_MD* mgf_hash, TC_bytes label)
{
  EVP_PKEY_CTX* context = EVP_PKEY_CTX_new(key,NULL);
  munit_assert_not_null(context);
  munit_assert_int(encrypt ? EVP_PKEY_encrypt_init(context) : EVP_PKEY_decrypt_init(context), ==, 1);
  munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(context,hash ? RSA_PKCS1_OAEP_PADDING : RSA_NO_PADDING), ==, 1);
  if (hash) {
    munit_assert_int(EVP_PKEY_CTX_set_rsa_oaep_md(context,hash), ==, 1);
    munit_assert_int(EVP_PKEY_CTX_set_rsa_mgf1_md(context,mgf_hash), ==, 1);
    if (label.length) {
      void* copy = OPENSSL_memdup(label.data,label.length);
      munit_assert_not_null(copy);
      /* The context owns this label after set0 succeeds. */
      munit_assert_int(EVP_PKEY_CTX_set0_rsa_oaep_label(context,copy,(int)label.length), ==, 1);
    }
  }
  return context;
}

static MunitResult interoperability(const MunitParameter params[], void* user)
{
  const unsigned bits = (unsigned)strtoul(munit_parameters_get(params,"bits"),NULL,10);
  const size_t width = bits / 8;
  const struct { TC_hash_algorithm algorithm; const EVP_MD* (*digest)(void); } hashes[] = {
    {TC_HASH_SHA1,EVP_sha1},{TC_HASH_SHA224,EVP_sha224},{TC_HASH_SHA256,EVP_sha256},
    {TC_HASH_SHA384,EVP_sha384},{TC_HASH_SHA512,EVP_sha512}
  };
  static const uint8_t label_bytes[] = {0,0xff,'p','i','v'};
  const TC_bytes labels[] = {{NULL,0},{label_bytes,sizeof label_bytes}};
  uint8_t encoded[MAX_BYTES], ciphertext[MAX_BYTES], plaintext[MAX_BYTES];
  uint8_t input[MAX_BYTES], seed[MAX_DIGEST], block[MAX_DIGEST], saved[MAX_BYTES];
  tc_hash_workspace workspace;
  munit_assert_true(bits == 1024 || bits == 2048 || bits == 3072);
  EVP_PKEY* key = EVP_RSA_gen(bits);
  (void)user;
  munit_assert_not_null(key);
  uint8_t modulus[MAX_BYTES], exponent[MAX_BYTES];
  const size_t modulus_length = tc_test_rsa_component(key,OSSL_PKEY_PARAM_RSA_N,
      modulus,sizeof modulus,0);
  const size_t exponent_length = tc_test_rsa_component(key,OSSL_PKEY_PARAM_RSA_E,
      exponent,sizeof exponent,0);
  const TC_RSA_public_key public_key = {{modulus,modulus_length},{exponent,exponent_length}};
  TC_RSA_word words[TC_RSA_ENCRYPT_WORKSPACE_WORDS(3072) + 1];
  const size_t required = TC_RSA_encrypt_workspace_words(bits);
  const TC_RSA_workspace arithmetic = {words,required};
  munit_assert_size(required, ==, TC_RSA_ENCRYPT_WORKSPACE_WORDS(bits));
  munit_assert_size(width, <=, MAX_BYTES);
  EVP_PKEY_CTX* raw_encrypt = operation(key,1,NULL,NULL,labels[0]);
  EVP_PKEY_CTX* raw_decrypt = operation(key,0,NULL,NULL,labels[0]);
  for (size_t i = 0; i < sizeof input; ++i) input[i] = (uint8_t)i;
  for (size_t i = 0; i < sizeof seed; ++i) seed[i] = (uint8_t)(i + 1);
  enum { RNG_FAILURE, NO_WORK, SHORT_SCRATCH, LONG_MESSAGE, SHORT_OUTPUT, OVERLAP, FAILURE_COUNT };
  for (unsigned failure = 0; failure < FAILURE_COUNT; ++failure) {
    TC_RSA_workspace limited = arithmetic;
    TC_bytes message = {input,1};
    size_t budget = WORK_BUDGET, output_length = width, calls = 0;
    TC_RSA_result expected = TC_RSA_ERROR;
    if (failure == NO_WORK) { budget = 0; expected = TC_RSA_LIMIT; }
    if (failure == SHORT_SCRATCH) { --limited.capacity; expected = TC_RSA_LIMIT; }
    if (failure == LONG_MESSAGE) { message.length = width; expected = TC_RSA_INVALID; }
    if (failure == SHORT_OUTPUT) { --output_length; expected = TC_RSA_INVALID; }
    if (failure == OVERLAP) { message.data = ciphertext; expected = TC_RSA_ARGUMENT; }
    memset(words,0xa5,sizeof words);
    memset(ciphertext,0xa5,sizeof ciphertext);
    const TC_RSA_oaep_options options = {TC_HASH_SHA256,TC_HASH_SHA256,labels[0]};
    TC_RSA_execution execution = {{failed_seed,&calls},0,{(uint32_t)budget}};
    munit_assert_int(TC_RSA_encrypt_oaep(&public_key,&options,message,&limited,
        (TC_buffer){ciphertext,output_length},&execution), ==, expected);
    munit_assert_size(calls, ==, failure == RNG_FAILURE ? 1 : 0);
    for (size_t i = 0; i < sizeof ciphertext; ++i)
      munit_assert_uint(ciphertext[i], ==, 0xa5);
    const uint8_t* scratch_bytes = (const uint8_t*)words;
    for (size_t i = 0; i < sizeof words; ++i)
      munit_assert_uint(scratch_bytes[i], ==,
          failure == RNG_FAILURE && i < required * sizeof *words ? 0 : 0xa5);
  }
  size_t example_calls = 0;
  munit_assert_int(example_encrypt_rsa_oaep_sha256(NULL,labels[0],labels[0],
      ciphertext,width,failed_seed,&example_calls,words,required), ==, TC_RSA_ARGUMENT);
  TC_RSA_public_key oversized_key = public_key;
  oversized_key.modulus.length = SIZE_MAX;
  munit_assert_int(example_encrypt_rsa_oaep_sha256(&oversized_key,labels[0],labels[0],
      ciphertext,width,failed_seed,&example_calls,words,required), ==, TC_RSA_INVALID);
  munit_assert_int(example_encrypt_rsa_oaep_sha256(&public_key,(TC_bytes){input,SIZE_MAX},
      labels[0],ciphertext,width,failed_seed,&example_calls,words,required), ==, TC_RSA_LIMIT);
  munit_assert_size(example_calls, ==, 0);
  for (size_t h = 0; h < sizeof hashes / sizeof *hashes; ++h) {
    tc_hash_info info;
    munit_assert_true(tc_hash_info_get(hashes[h].algorithm,&info));
    if (width < 2 * info.digest_length + 2) continue;
    const size_t lengths[] = {0,1,width - 2 * info.digest_length - 2};
    for (size_t mgf = 0; mgf < sizeof hashes / sizeof *hashes; ++mgf) {
      tc_hash_info mgf_info;
      munit_assert_true(tc_hash_info_get(hashes[mgf].algorithm,&mgf_info));
      const size_t hlen = info.digest_length, glen = mgf_info.digest_length;
      const size_t db_length = width - hlen - 1;
      const size_t db_mask_work = db_length + ((db_length + glen - 1) / glen) * (hlen + 5);
      const size_t seed_mask_work = hlen + ((hlen + glen - 1) / glen) * (db_length + 5);
      for (size_t l = 0; l < sizeof labels / sizeof *labels; ++l) {
        const size_t prepared_work = 1 + width + labels[l].length + 1;
        const size_t total_work = prepared_work + db_mask_work + seed_mask_work +
            16 * width + 16 * exponent_length + 4;
        const size_t budgets[] = {prepared_work,prepared_work + db_mask_work,total_work - 1,total_work};
        EVP_PKEY_CTX* encrypt = operation(key,1,hashes[h].digest(),hashes[mgf].digest(),labels[l]);
        EVP_PKEY_CTX* decrypt = operation(key,0,hashes[h].digest(),hashes[mgf].digest(),labels[l]);
        for (size_t m = 0; m < sizeof lengths / sizeof *lengths; ++m) {
          const TC_bytes message = {input,lengths[m]};
          size_t work = WORK_BUDGET, size = sizeof ciphertext, recovered = sizeof plaintext;
          munit_assert_int(tc_rsa_oaep_encode(encoded,width,hashes[h].algorithm,hashes[mgf].algorithm,
              labels[l],message,(TC_bytes){seed,info.digest_length},block,&workspace,&work), ==, TC_RSA_OK);
          /* OpenSSL supplies only the RSA transform for our encoded block. */
          munit_assert_int(EVP_PKEY_encrypt(raw_encrypt,ciphertext,&size,encoded,width), ==, 1);
          memcpy(saved,ciphertext,width);
          /* Exhaust work at each masking stage and just before exponentiation. */
          for (size_t b = 0; b < sizeof budgets / sizeof *budgets; ++b) {
            memset(words,0xa5,sizeof words);
            memset(ciphertext,0xa5,sizeof ciphertext);
            const int complete = budgets[b] == total_work;
            const TC_RSA_oaep_options options = {
              hashes[h].algorithm,hashes[mgf].algorithm,labels[l]
            };
            TC_RSA_execution execution = {
              {fixed_seed,seed},0,{(uint32_t)budgets[b]}
            };
            munit_assert_int(TC_RSA_encrypt_oaep(&public_key,&options,message,
                &arithmetic,(TC_buffer){ciphertext,width},&execution), ==,
                complete ? TC_RSA_OK : TC_RSA_LIMIT);
            if (!complete)
              for (size_t j = 0; j < sizeof ciphertext; ++j)
                munit_assert_uint(ciphertext[j], ==, 0xa5);
            const uint8_t* scratch_bytes = (const uint8_t*)words;
            for (size_t j = 0; j < sizeof words; ++j)
              munit_assert_uint(scratch_bytes[j], ==, j < required * sizeof *words ? 0 : 0xa5);
          }
          munit_assert_memory_equal(width,ciphertext,saved);
          if (hashes[h].algorithm == TC_HASH_SHA256 && hashes[mgf].algorithm == TC_HASH_SHA256) {
            memset(ciphertext,0xa5,sizeof ciphertext);
            munit_assert_int(example_encrypt_rsa_oaep_sha256(&public_key,labels[l],message,
                ciphertext,width,fixed_seed,seed,words,required), ==, TC_RSA_OK);
            munit_assert_memory_equal(width,ciphertext,saved);
          }
          munit_assert_int(EVP_PKEY_decrypt(decrypt,plaintext,&recovered,ciphertext,size), ==, 1);
          munit_assert_size(recovered, ==, message.length);
          munit_assert_memory_equal(recovered,plaintext,message.data);

          size = sizeof ciphertext; recovered = sizeof encoded;
          munit_assert_int(EVP_PKEY_encrypt(encrypt,ciphertext,&size,message.data,message.length), ==, 1);
          munit_assert_int(EVP_PKEY_decrypt(raw_decrypt,encoded,&recovered,ciphertext,size), ==, 1);
          munit_assert_size(recovered, ==, width);
          memcpy(saved,encoded,width);
          TC_bytes decoded = {NULL,0};
          work = WORK_BUDGET;
          munit_assert_int(tc_rsa_oaep_decode(encoded,width,hashes[h].algorithm,hashes[mgf].algorithm,
              labels[l],block,&workspace,&work,&decoded), ==, TC_RSA_OK);
          munit_assert_size(decoded.length, ==, message.length);
          munit_assert_memory_equal(decoded.length,decoded.data,message.data);
          memcpy(encoded,saved,width); decoded = (TC_bytes){NULL,0}; work = WORK_BUDGET;
          munit_assert_int(tc_rsa_oaep_decode(encoded,width,hashes[h].algorithm,hashes[mgf].algorithm,
              labels[l ^ 1u],block,&workspace,&work,&decoded), ==, TC_RSA_INVALID);
          munit_assert_null(decoded.data); munit_assert_size(decoded.length, ==, 0);
        }
        EVP_PKEY_CTX_free(encrypt); EVP_PKEY_CTX_free(decrypt);
      }
    }
  }
  EVP_PKEY_CTX_free(raw_encrypt); EVP_PKEY_CTX_free(raw_decrypt); EVP_PKEY_free(key);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  static char* sizes[] = {"1024","2048","3072",NULL};
  static MunitParameterEnum parameters[] = {{"bits",sizes},{NULL,NULL}};
  MunitTest tests[] = {
    {"/interoperability",interoperability,NULL,NULL,MUNIT_TEST_OPTION_NONE,parameters},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}
  };
  MunitSuite suite = {"/rsa/oaep",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
