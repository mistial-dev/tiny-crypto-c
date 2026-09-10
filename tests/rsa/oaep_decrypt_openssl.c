/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/rsa.h>
#include "munit.h"
#include "openssl_hash.h"
#include "openssl_key.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <stdlib.h>
#include <string.h>

typedef struct { unsigned calls; TC_status status; } random_source;

typedef enum {
  DECRYPT_OK, WRONG_LABEL, SHORT_OUTPUT, RNG_FAILURE, ZERO_WORK,
  SHORT_WORK, EXACT_WORK, ZERO_CIPHERTEXT, MODULUS_CIPHERTEXT, SCENARIO_COUNT
} decrypt_scenario;

static TC_status random_bytes(void* context, uint8_t* output, size_t length)
{
  random_source* source = context;
  ++source->calls;
  memset(output,0,length); output[length - 1] = 2;
  return source->status;
}

static MunitResult decrypt(const MunitParameter params[], void* user)
{
  enum { MAX_BYTES = TC_TEST_RSA_MAX_BYTES, MGF_COUNTER_BYTES = 4 };
  const char* hash_name = munit_parameters_get(params,"hash");
  const char* mgf_name = munit_parameters_get(params,"mgf");
  const tc_test_openssl_hash* hash = tc_test_openssl_hash_get(hash_name);
  const tc_test_openssl_hash* mgf = tc_test_openssl_hash_get(mgf_name);
  const size_t hash_length = (size_t)EVP_MD_get_size(hash->method());
  const size_t mgf_length = (size_t)EVP_MD_get_size(mgf->method());
  const unsigned bits = (unsigned)strtoul(munit_parameters_get(params,"bits"),NULL,10);
  const size_t width = bits / 8;
  const size_t label_length = (size_t)strtoul(munit_parameters_get(params,"label"),NULL,10);
  const int representative = !strcmp(hash_name,"SHA256") &&
      !strcmp(mgf_name,"SHA256") && label_length == 1;
#if TC_RSA_SMALL
  /* Native limbs cover the full 2048/3072 parameter matrix. The byte-limb
   * build exercises those sizes with a representative OAEP configuration. */
  if (bits > 1024 && !representative) return MUNIT_SKIP;
#endif
  uint8_t label_bytes[256], wrong_label[256];
  munit_assert_size(label_length, <=, sizeof label_bytes);
  for (size_t i = 0; i < sizeof label_bytes; ++i) label_bytes[i] = (uint8_t)i;
  memcpy(wrong_label,label_bytes,sizeof wrong_label);
  wrong_label[label_length ? label_length - 1 : 0] ^= 1;
  uint8_t components[5][MAX_BYTES], input[MAX_BYTES], ciphertext[MAX_BYTES], output[MAX_BYTES];
  TC_RSA_word words[TC_RSA_DECRYPT_WORKSPACE_WORDS(3072)];
  TC_RSA_workspace workspace = {words,TC_RSA_decrypt_workspace_words(bits)};
  EVP_PKEY* generated = EVP_RSA_gen(bits);
  (void)user;
  munit_assert_not_null(generated);
  size_t exponent_length = tc_test_rsa_export(generated,components,width);
  munit_assert_size(exponent_length, >, 0);
  TC_RSA_private_key key = {{{components[0],width},{components[1],exponent_length}},
    {components[2],width},{components[3],width},{components[4],width},NULL};
  if (width < 2 * hash_length + 2) {
    size_t recovered = SIZE_MAX;
    random_source random = {0,TC_OK};
    memset(output,0xa5,sizeof output); memset(words,0xa5,sizeof words);
    memset(ciphertext,0,sizeof ciphertext);
    const TC_RSA_oaep_options options = {hash->algorithm,mgf->algorithm,
      {label_bytes,label_length}};
    TC_RSA_execution execution = {{random_bytes,&random},1,{UINT32_MAX}};
    munit_assert_int(TC_RSA_decrypt_oaep(&key,&options,
        (TC_bytes){ciphertext,width},&workspace,(TC_buffer){output,sizeof output},
        &recovered,&execution), ==, TC_RSA_INVALID);
    munit_assert_size(recovered, ==, SIZE_MAX);
    munit_assert_uint(random.calls, ==, 0);
    for (size_t i = 0; i < sizeof output; ++i) munit_assert_uint(output[i], ==, 0xa5);
    for (size_t i = 0; i < sizeof words; ++i)
      munit_assert_uint(((uint8_t*)words)[i], ==, 0xa5);
    EVP_PKEY_free(generated);
    return MUNIT_OK;
  }
  EVP_PKEY_CTX* encrypt = EVP_PKEY_CTX_new(generated,NULL);
  munit_assert_not_null(encrypt);
  munit_assert_int(EVP_PKEY_encrypt_init(encrypt), ==, 1);
  munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(encrypt,RSA_PKCS1_OAEP_PADDING), ==, 1);
  munit_assert_int(EVP_PKEY_CTX_set_rsa_oaep_md(encrypt,hash->method()), ==, 1);
  munit_assert_int(EVP_PKEY_CTX_set_rsa_mgf1_md(encrypt,mgf->method()), ==, 1);
  if (label_length) {
    unsigned char* owned_label = OPENSSL_memdup(label_bytes,label_length);
    munit_assert_not_null(owned_label);
    /* OpenSSL takes ownership after a successful set0 call. */
    munit_assert_int(EVP_PKEY_CTX_set0_rsa_oaep_label(encrypt,owned_label,
        (int)label_length), ==, 1);
  }
  for (size_t i = 0; i < sizeof input; ++i) input[i] = (uint8_t)i;
  const size_t lengths[] = {0,1,width - 2 * hash_length - 2};
  const size_t db_length = width - hash_length - 1;
  const size_t db_blocks = db_length / mgf_length + (db_length % mgf_length != 0);
  const size_t seed_blocks = hash_length / mgf_length + (hash_length % mgf_length != 0);
  const size_t decode_work = width + label_length + 1 + hash_length +
      seed_blocks * (db_length + MGF_COUNTER_BYTES + 1) +
      db_length + db_blocks * (hash_length + MGF_COUNTER_BYTES + 1);
  const size_t exact_work = 48 * width + 32 * exponent_length + 9 + decode_work;
  for (size_t i = 0; i < sizeof lengths / sizeof *lengths; ++i) {
    size_t encrypted = sizeof ciphertext;
    munit_assert_int(EVP_PKEY_encrypt(encrypt,ciphertext,&encrypted,input,lengths[i]), ==, 1);
    for (unsigned scenario = 0; scenario < SCENARIO_COUNT; ++scenario) {
      const int boundary = i + 1 == sizeof lengths / sizeof *lengths;
      if (scenario != DECRYPT_OK && !boundary) continue;
      if ((scenario == RNG_FAILURE || scenario == ZERO_WORK ||
           scenario == ZERO_CIPHERTEXT || scenario == MODULUS_CIPHERTEXT) &&
          !representative) continue;
      const TC_bytes label = scenario == WRONG_LABEL ?
          (TC_bytes){wrong_label,label_length ? label_length : 1} :
          (TC_bytes){label_bytes,label_length};
      const size_t capacity = scenario == SHORT_OUTPUT && lengths[i] ? lengths[i] - 1 : lengths[i];
      random_source random = {0,scenario == RNG_FAILURE ? TC_ERROR : TC_OK};
      const size_t work = scenario == ZERO_WORK ? 0 : scenario == SHORT_WORK ? exact_work - 1 :
          scenario == EXACT_WORK ? exact_work : SIZE_MAX;
      uint8_t zero_ciphertext[MAX_BYTES] = {0};
      const TC_bytes candidate = scenario == ZERO_CIPHERTEXT ?
          (TC_bytes){zero_ciphertext,width} : scenario == MODULUS_CIPHERTEXT ?
          key.public_key.modulus : (TC_bytes){ciphertext,encrypted};
      size_t recovered = SIZE_MAX;
      memset(output,0xa5,sizeof output); memset(words,0xa5,sizeof words);
      const TC_RSA_result expected = scenario == RNG_FAILURE ? TC_RSA_ERROR :
          scenario == ZERO_WORK || scenario == SHORT_WORK ? TC_RSA_LIMIT :
          scenario == WRONG_LABEL || scenario == ZERO_CIPHERTEXT ||
          scenario == MODULUS_CIPHERTEXT ? TC_RSA_INVALID :
          scenario == SHORT_OUTPUT && lengths[i] ? TC_RSA_LIMIT : TC_RSA_OK;
      const TC_RSA_oaep_options options = {hash->algorithm,mgf->algorithm,label};
      TC_RSA_execution execution = {{random_bytes,&random},1,{(uint32_t)work}};
      munit_assert_int(TC_RSA_decrypt_oaep(&key,&options,candidate,&workspace,
          (TC_buffer){output,capacity},&recovered,&execution), ==, expected);
      munit_assert_uint(random.calls, ==,
          scenario == ZERO_WORK || scenario == MODULUS_CIPHERTEXT ? 0 : 1);
      const size_t used = workspace.capacity * sizeof *words;
      for (size_t j = 0; j < sizeof words; ++j)
        munit_assert_uint(((uint8_t*)words)[j], ==, scenario == ZERO_WORK || j >= used ? 0xa5 : 0);
      if (expected == TC_RSA_OK) {
        munit_assert_size(recovered, ==, lengths[i]);
        munit_assert_memory_equal(recovered,output,input);
      } else munit_assert_size(recovered, ==, SIZE_MAX);
      for (size_t j = expected == TC_RSA_OK ? recovered : 0; j < sizeof output; ++j)
        munit_assert_uint(output[j], ==, 0xa5);
    }
  }
  if (representative) {
    uint8_t dp[MAX_BYTES / 2], dq[MAX_BYTES / 2], inverse[MAX_BYTES / 2];
    munit_assert_size(tc_test_rsa_component(generated,OSSL_PKEY_PARAM_RSA_EXPONENT1,
        dp,sizeof dp,width / 2), ==, width / 2);
    munit_assert_size(tc_test_rsa_component(generated,OSSL_PKEY_PARAM_RSA_EXPONENT2,
        dq,sizeof dq,width / 2), ==, width / 2);
    munit_assert_size(tc_test_rsa_component(generated,OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
        inverse,sizeof inverse,width / 2), ==, width / 2);
    TC_RSA_crt crt = {{dp,width / 2},{dq,width / 2},{inverse,width / 2}};
    key.crt = &crt;
    random_source random = {0,TC_OK};
    size_t recovered = SIZE_MAX;
    memset(output,0xa5,sizeof output);
    const TC_RSA_oaep_options options = {hash->algorithm,mgf->algorithm,
      {label_bytes,label_length}};
    TC_RSA_execution execution = {{random_bytes,&random},1,{UINT32_MAX}};
    munit_assert_int(TC_RSA_decrypt_oaep(&key,&options,
        (TC_bytes){ciphertext,width},&workspace,(TC_buffer){output,lengths[2]},
        &recovered,&execution), ==, TC_RSA_OK);
    munit_assert_size(recovered, ==, lengths[2]);
    munit_assert_memory_equal(recovered,output,input);
  }
  EVP_PKEY_CTX_free(encrypt); EVP_PKEY_free(generated);
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  char* sizes[] = {"1024","2048","3072",NULL};
  char* labels[] = {"0","1","256",NULL};
  char* hashes[] = {"SHA1","SHA224","SHA256","SHA384","SHA512",NULL};
  MunitParameterEnum parameters[] = {{"bits",sizes},{"label",labels},
    {"hash",hashes},{"mgf",hashes},{NULL,NULL}};
  MunitTest tests[] = {{"/decrypt",decrypt,NULL,NULL,MUNIT_TEST_OPTION_NONE,parameters},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}};
  MunitSuite suite = {"/rsa/oaep",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
