/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/x509_crypto.h>
#include <tiny_crypto/cms.h>
#include <tiny_crypto/cms_validation.h>
#include "../../examples/x509_workspace.h"
#include "../x509/openssl_fixture.h"
#include "envelope.h"
#include "munit.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <string.h>

enum { MAX_RSA_BITS = 3072, ENCODED_CAPACITY = 1024, FRAME_CAPACITY = 16,
  WORK_BUDGET = 100000, CONTENT_DIGEST_BYTES = 32,
  PSS_HASH_OFFSET = 16, PSS_MGF_HASH_OFFSET = 46, PSS_SALT_OFFSET = 53 };
static const uint8_t data_type[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,1};
static const uint8_t message[] = {'a','b','c'};
static const uint8_t pss_parameters[] = {
  0x30,52,0xa0,15,0x30,13,6,9,0x60,0x86,0x48,1,0x65,3,4,2,2,5,0,
  0xa1,28,0x30,26,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,8,
  0x30,13,6,9,0x60,0x86,0x48,1,0x65,3,4,2,1,5,0,0xa2,3,2,1,48
};

typedef struct {
  TC_bytes certificate;
  TC_X509_store_anchor anchor;
} PssSource;

static TC_TLV_result pss_candidate(void* context, size_t index, size_t* work, TC_bytes* out)
{
  if (index) return TC_TLV_ARGUMENT;
  if (!*work) return TC_TLV_LIMIT;
  --*work;
  *out = ((const PssSource*)context)->certificate;
  return TC_TLV_OK;
}

static TC_TLV_result pss_anchor(void* context, size_t index, size_t* work, TC_X509_store_anchor* out)
{
  if (index) return TC_TLV_ARGUMENT;
  if (!*work) return TC_TLV_LIMIT;
  --*work;
  *out = ((const PssSource*)context)->anchor;
  return TC_TLV_OK;
}

static void check_envelope_path(TC_bytes signer, EVP_PKEY* key, TC_RSA_workspace* rsa)
{
  enum { CERT_CAPACITY = 2 * ENCODED_CAPACITY, PATH_WORK = 10 * WORK_BUDGET };
  static const uint8_t algorithms[] = {0x31,13,0x30,11,6,9,0x60,0x86,0x48,1,0x65,3,4,2,1};
  static const uint8_t content[] = {4,3,'a','b','c'};
  uint8_t root_der[CERT_CAPACITY], leaf_der[CERT_CAPACITY], encoded[CERT_CAPACITY];
  uint8_t signers[ENCODED_CAPACITY + 4];
  ExampleX509SearchWorkspace storage;
  TC_bytes index[1];
  TC_ECDSA_workspace ec;
  TC_X509_native_workspace native = {&ec,rsa,TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  TC_CMS_path_workspace workspace = {example_x509_workspace(&storage.validation),
    example_x509_search_workspace(&storage),index,1,NULL,0};
  TC_X509_workspace parser = {workspace.validation.frames,workspace.validation.frame_capacity,
    workspace.validation.oids,workspace.validation.oid_capacity};
  TC_CMS_path_options options = {0};
  TC_X509_certificate parsed_root;
  TC_X509_search_result found, saved;
  TC_CMS_signed_data data = {0};
  EVP_PKEY* root_key = EVP_EC_gen("prime256v1");
  munit_assert_not_null(root_key);
  X509* root = make_certificate(root_key,"Root",NULL);
  X509* leaf = make_certificate(key,"PSS signer",root);
  /* encode_signer uses this one-byte subject key identifier. */
  add_extension(leaf,NID_subject_key_identifier,"AA");
  add_extension(leaf,NID_key_usage,"critical,digitalSignature");
  const size_t root_length = encode_certificate(root,root_key,EVP_sha256(),root_der,sizeof root_der);
  const size_t leaf_length = encode_certificate(leaf,root_key,EVP_sha256(),leaf_der,sizeof leaf_der);
  options.path.parsing = (TC_TLV_limits){CERT_CAPACITY,CERT_CAPACITY,256,FRAME_CAPACITY};
  options.path.at = (TC_X509_time){2026,1,1,0,0,0};
  options.path.max_certificates = 1; options.path.max_input = CERT_CAPACITY;
  options.path.signatures = TC_X509_native_provider(&native);
  options.max_candidates = 1; options.max_candidate_bytes = CERT_CAPACITY;
  munit_assert_int(TC_X509_read(root_der,root_length,&options.path.parsing,&parser,&parsed_root), ==, TC_TLV_OK);
  PssSource records = {{leaf_der,leaf_length},
    {{parsed_root.subject,parsed_root.public_key},{{NULL,0},{NULL,0}}}};
  const TC_X509_store_source source = {&records,1,1,pss_candidate,pss_anchor};
  signers[0] = 0x31; signers[1] = 0x80;
  munit_assert_size(signer.length, <=, sizeof signers - 4);
  memcpy(signers + 2,signer.data,signer.length); memset(signers + 2 + signer.length,0,2);
  data.version = 3; data.has_content = 1;
  data.content_type = (TC_bytes){data_type,sizeof data_type};
  data.content = (TC_bytes){content,sizeof content};
  const size_t length = test_cms_encode_envelope(&data,(TC_bytes){algorithms,sizeof algorithms},
      (TC_bytes){signers,signer.length + 4},encoded,sizeof encoded);
  size_t work = PATH_WORK;
  munit_assert_int(TC_CMS_signed_data_path_build((TC_bytes){encoded,length},0,data.content_type,
      (TC_bytes){NULL,0},&source,&options,&workspace,&work,&found), ==, TC_X509_PATH_VALID);
  munit_assert_size(found.count, ==, 1);
  munit_assert_ptr_equal(found.path[0].data,leaf_der);
  const size_t required = PATH_WORK - work;
  munit_assert_size(found.validation.work_used, ==, required);
  work = required;
  munit_assert_int(TC_CMS_signed_data_path_build((TC_bytes){encoded,length},0,data.content_type,
      (TC_bytes){NULL,0},&source,&options,&workspace,&work,&found), ==, TC_X509_PATH_VALID);
  munit_assert_size(work, ==, 0);
  memset(&found,0xa5,sizeof found); memcpy(&saved,&found,sizeof saved); work = required - 1;
  munit_assert_int(TC_CMS_signed_data_path_build((TC_bytes){encoded,length},0,data.content_type,
      (TC_bytes){NULL,0},&source,&options,&workspace,&work,&found), ==, TC_X509_PATH_LIMIT);
  munit_assert_memory_equal(sizeof found,&found,&saved);
  X509_free(leaf); X509_free(root); EVP_PKEY_free(root_key);
}

static void append(uint8_t* buffer, size_t* length, TC_bytes part)
{
  munit_assert_size(*length, <=, ENCODED_CAPACITY);
  munit_assert_size(part.length, <=, ENCODED_CAPACITY - *length);
  memcpy(buffer + *length,part.data,part.length);
  *length += part.length;
}

static size_t encode_signer(uint8_t* encoded, TC_bytes attributes,
    TC_bytes parameters, TC_bytes signature)
{
  static const uint8_t prefix[] = {
    0x30,0x82,0,0,2,1,3,0x80,1,0xaa,
    0x30,13,6,9,0x60,0x86,0x48,1,0x65,3,4,2,1,5,0
  };
  static const uint8_t signature_algorithm[] = {
    0x30,65,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,1,10
  };
  uint8_t signature_header[] = {4,0x82,(uint8_t)(signature.length >> 8),(uint8_t)signature.length};
  size_t length = 0;
  append(encoded,&length,(TC_bytes){prefix,sizeof prefix});
  if (attributes.length) {
    const size_t start = length;
    append(encoded,&length,attributes);
    encoded[start] = 0xa0;
  }
  append(encoded,&length,(TC_bytes){signature_algorithm,sizeof signature_algorithm});
  append(encoded,&length,parameters);
  append(encoded,&length,(TC_bytes){signature_header,sizeof signature_header});
  append(encoded,&length,signature);
  /* Root length uses BER so RSA sizes share one header layout. */
  encoded[2] = (uint8_t)((length - 4) >> 8);
  encoded[3] = (uint8_t)(length - 4);
  return length;
}

static MunitResult pss_signers(const MunitParameter params[], void* user)
{
  static const unsigned key_sizes[] = {1024,2048,MAX_RSA_BITS};
  static const struct { int attributes, distinct_hash; } cases[] = {{1,1},{1,0},{0,0}};
  static const uint8_t attribute_prefix[] = {
    0x31,75,
    0x30,24,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,9,3,
    0x31,11,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,7,1,
    0x30,47,6,9,0x2a,0x86,0x48,0x86,0xf7,0x0d,1,9,4,0x31,34,4,CONTENT_DIGEST_BYTES
  };
  uint8_t encoded[ENCODED_CAPACITY], spki[ENCODED_CAPACITY], signature[MAX_RSA_BITS / 8];
  uint8_t digest[CONTENT_DIGEST_BYTES], attributes[sizeof attribute_prefix + CONTENT_DIGEST_BYTES];
  uint8_t parameters[sizeof pss_parameters];
  TC_TLV_frame frames[FRAME_CAPACITY];
  TC_RSA_word words[TC_RSA_VERIFY_WORKSPACE_WORDS(MAX_RSA_BITS)];
  TC_RSA_workspace rsa = {words,sizeof words / sizeof *words};
  const TC_X509_native_workspace native = {NULL,&rsa,TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  const TC_X509_signature_provider provider = TC_X509_native_provider(&native);
  const TC_CMS_signature_workspace workspace = {frames,FRAME_CAPACITY,NULL,0};
  const TC_TLV_limits limits = {ENCODED_CAPACITY,ENCODED_CAPACITY,128,FRAME_CAPACITY};
  const TC_bytes type = {data_type,sizeof data_type};
  const TC_bytes computed = {digest,sizeof digest};
  unsigned digest_length = 0;
  (void)params; (void)user;
  munit_assert_int(EVP_Digest(message,sizeof message,digest,&digest_length,EVP_sha256(),NULL), ==, 1);
  munit_assert_uint(digest_length, ==, sizeof digest);
  memcpy(attributes,attribute_prefix,sizeof attribute_prefix);
  memcpy(attributes + sizeof attribute_prefix,digest,sizeof digest);
  for (unsigned restricted = 0; restricted < 2; ++restricted)
  for (size_t size = 0; size < sizeof key_sizes / sizeof *key_sizes; ++size) {
    EVP_PKEY* generated = NULL;
    if (restricted) {
      EVP_PKEY_CTX* generation = EVP_PKEY_CTX_new_from_name(NULL,"RSA-PSS",NULL);
      munit_assert_not_null(generation);
      munit_assert_int(EVP_PKEY_keygen_init(generation), ==, 1);
      munit_assert_int(EVP_PKEY_CTX_set_rsa_keygen_bits(generation,(int)key_sizes[size]), ==, 1);
      munit_assert_int(EVP_PKEY_CTX_set_rsa_pss_keygen_md(generation,EVP_sha384()), ==, 1);
      munit_assert_int(EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(generation,EVP_sha256()), ==, 1);
      munit_assert_int(EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(generation,CONTENT_DIGEST_BYTES), ==, 1);
      munit_assert_int(EVP_PKEY_generate(generation,&generated), ==, 1);
      EVP_PKEY_CTX_free(generation);
    } else generated = EVP_RSA_gen(key_sizes[size]);
    unsigned char* cursor = spki;
    TC_X509_public_key key;
    int spki_length;
    munit_assert_not_null(generated);
    spki_length = i2d_PUBKEY(generated,NULL);
    munit_assert_int(spki_length, >, 0);
    munit_assert_size((size_t)spki_length, <=, sizeof spki);
    munit_assert_int(i2d_PUBKEY(generated,&cursor), ==, spki_length);
    munit_assert_int(TC_X509_subject_public_key(spki,(size_t)spki_length,&key), ==, TC_TLV_OK);
    munit_assert_int(key.type, ==, restricted ? TC_KEY_RSA_PSS : TC_KEY_RSA);
    for (size_t variant = 0; variant < sizeof cases / sizeof *cases; ++variant) {
      if (restricted && !cases[variant].distinct_hash) continue;
      EVP_MD_CTX* signing = EVP_MD_CTX_new();
      EVP_PKEY_CTX* signing_key = NULL;
      TC_CMS_signer_info signer;
      const EVP_MD* signature_hash = cases[variant].distinct_hash ? EVP_sha384() : EVP_sha256();
      const size_t salt_length = (size_t)EVP_MD_get_size(signature_hash);
      const TC_bytes attrs = {attributes,cases[variant].attributes ? sizeof attributes : 0};
      const TC_bytes signed_message = cases[variant].attributes ? attrs :
          (TC_bytes){message,sizeof message};
      size_t signature_length = sizeof signature, work = WORK_BUDGET;
      munit_assert_not_null(signing);
      memcpy(parameters,pss_parameters,sizeof parameters);
      parameters[PSS_HASH_OFFSET] = cases[variant].distinct_hash ? 2 : 1;
      parameters[PSS_SALT_OFFSET] = (uint8_t)salt_length;
      munit_assert_int(EVP_DigestSignInit(signing,&signing_key,signature_hash,NULL,generated), ==, 1);
      munit_assert_int(EVP_PKEY_CTX_set_rsa_padding(signing_key,RSA_PKCS1_PSS_PADDING), ==, 1);
      munit_assert_int(EVP_PKEY_CTX_set_rsa_mgf1_md(signing_key,EVP_sha256()), ==, 1);
      munit_assert_int(EVP_PKEY_CTX_set_rsa_pss_saltlen(signing_key,(int)salt_length), ==, 1);
      munit_assert_int(EVP_DigestSign(signing,signature,&signature_length,
          signed_message.data,signed_message.length), ==, 1);
      size_t length = encode_signer(encoded,attrs,(TC_bytes){parameters,sizeof parameters},
          (TC_bytes){signature,signature_length});
      munit_assert_int(TC_CMS_signer_info_read((TC_bytes){encoded,length},TC_TLV_BER,
          &limits,frames,FRAME_CAPACITY,&work,&signer), ==, TC_TLV_OK);
      work = WORK_BUDGET;
      munit_assert_int(TC_CMS_signer_verify_digest(&signer,type,computed,TC_CMS_ATTRIBUTES_DER,
          &key,&provider,&limits,&workspace,&work), ==, TC_X509_SIGNATURE_VALID);
      check_envelope_path((TC_bytes){encoded,length},generated,&rsa);
      {
        static const uint8_t chunked[] = {0x24,0x80,4,1,'a',4,2,'b','c',0,0};
        uint8_t changed_message[] = {'a','b','d'};
        const TC_bytes inputs[] = {{message,sizeof message},{chunked,sizeof chunked}};
        for (unsigned form = 0; form < 2; ++form) {
          size_t content_work = WORK_BUDGET;
          const TC_CMS_content_encoding format = form ? TC_CMS_CONTENT_BER_OCTETS : TC_CMS_CONTENT_RAW;
          munit_assert_int(TC_CMS_signer_verify_content(&signer,type,inputs[form],format,
              TC_CMS_ATTRIBUTES_DER,&key,&provider,&limits,&workspace,&content_work),
              ==, TC_X509_SIGNATURE_VALID);
          const size_t content_required = WORK_BUDGET - content_work;
          content_work = content_required;
          munit_assert_int(TC_CMS_signer_verify_content(&signer,type,inputs[form],format,
              TC_CMS_ATTRIBUTES_DER,&key,&provider,&limits,&workspace,&content_work),
              ==, TC_X509_SIGNATURE_VALID);
          munit_assert_size(content_work, ==, 0);
          content_work = content_required - 1;
          munit_assert_int(TC_CMS_signer_verify_content(&signer,type,inputs[form],format,
              TC_CMS_ATTRIBUTES_DER,&key,&provider,&limits,&workspace,&content_work),
              ==, TC_X509_SIGNATURE_LIMIT);
        }
        size_t content_work = WORK_BUDGET;
        munit_assert_int(TC_CMS_signer_verify_content(&signer,type,
            (TC_bytes){changed_message,sizeof changed_message},TC_CMS_CONTENT_RAW,
            TC_CMS_ATTRIBUTES_DER,&key,&provider,&limits,&workspace,&content_work),
            ==, TC_X509_SIGNATURE_INVALID);
      }
      const size_t required = WORK_BUDGET - work;
      work = required;
      munit_assert_int(TC_CMS_signer_verify_digest(&signer,type,computed,TC_CMS_ATTRIBUTES_DER,
          &key,&provider,&limits,&workspace,&work), ==, TC_X509_SIGNATURE_VALID);
      munit_assert_size(work, ==, 0);
      work = required - 1;
      munit_assert_int(TC_CMS_signer_verify_digest(&signer,type,computed,TC_CMS_ATTRIBUTES_DER,
          &key,&provider,&limits,&workspace,&work), ==, TC_X509_SIGNATURE_LIMIT);
      digest[0] ^= 1; work = WORK_BUDGET;
      munit_assert_int(TC_CMS_signer_verify_digest(&signer,type,computed,TC_CMS_ATTRIBUTES_DER,
          &key,&provider,&limits,&workspace,&work), ==, TC_X509_SIGNATURE_INVALID);
      digest[0] ^= 1;
      /* Change each parameter in the encoded SignerInfo, then parse it again. */
      const size_t parameter_start = (size_t)(signer.signature_algorithm.parameters.data - encoded);
      const size_t changed_offsets[] = {parameter_start + PSS_HASH_OFFSET,
        parameter_start + PSS_MGF_HASH_OFFSET,parameter_start + PSS_SALT_OFFSET,length - 1};
      for (size_t change = 0; change < sizeof changed_offsets / sizeof *changed_offsets; ++change) {
        const size_t offset = changed_offsets[change];
        const uint8_t saved = encoded[offset];
        encoded[offset] = change < 2 ? (saved == 1 ? 2 : 1) :
          change == 2 && restricted ? CONTENT_DIGEST_BYTES - 1 : (uint8_t)(saved ^ 1);
        work = WORK_BUDGET;
        munit_assert_int(TC_CMS_signer_info_read((TC_bytes){encoded,length},TC_TLV_BER,
            &limits,frames,FRAME_CAPACITY,&work,&signer), ==, TC_TLV_OK);
        munit_assert_int(TC_CMS_signer_verify_digest(&signer,type,computed,TC_CMS_ATTRIBUTES_DER,
            &key,&provider,&limits,&workspace,&work), ==, TC_X509_SIGNATURE_INVALID);
        encoded[offset] = saved;
      }
      EVP_MD_CTX_free(signing);
    }
    EVP_PKEY_free(generated);
  }
  return MUNIT_OK;
}

int main(int argc, char** argv)
{
  MunitTest tests[] = {{"/signers",pss_signers,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL},
    {NULL,NULL,NULL,NULL,MUNIT_TEST_OPTION_NONE,NULL}};
  MunitSuite suite = {"/cms/pss",tests,NULL,1,MUNIT_SUITE_OPTION_NONE};
  return munit_suite_main(&suite,NULL,argc,argv);
}
