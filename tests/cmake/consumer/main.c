/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/tiny_crypto.h>
#include <string.h>
int main(void)
{
  if (!TC_RSA_verify_workspace_words(3072) ||
      !TC_RSA_keygen_workspace_words(3072)) return 1;
  {
    static TC_RSA_word words[TC_RSA_KEYGEN_WORKSPACE_WORDS(1024)];
    static uint8_t modulus[128], exponent[3], d[128], p[64], q[64];
    TC_RSA_workspace workspace = {words,sizeof words / sizeof *words};
    TC_RSA_keygen_output output = {
      {modulus,sizeof modulus},{exponent,sizeof exponent},{d,sizeof d},
      {p,sizeof p},{q,sizeof q}
    };
    TC_RSA_keygen_state state = {0};
    if (TC_RSA_keygen_init(&state,1024,&output,
        (TC_RSA_keygen_limits){1,1},&workspace) != TC_RSA_OK) return 1;
    TC_RSA_keygen_clear(&state);
    {
      TC_RSA_private_key key = {0};
      TC_RSA_crt crt = {0};
      TC_RSA_crt_output crt_output = {0};
      uint8_t signature[128];
      size_t plaintext_length = 0;
      TC_work_budget work = {UINT32_MAX};
      TC_RSA_execution execution = {{NULL,NULL},1,{UINT32_MAX}};
      const TC_RSA_v15_options v15 = {TC_HASH_SHA256};
      const TC_RSA_pss_options pss = {TC_HASH_SHA256,TC_HASH_SHA256,32};
      const TC_RSA_oaep_options oaep = {TC_HASH_SHA256,TC_HASH_SHA256,{NULL,0}};
      key.crt = &crt;
      if (TC_RSA_derive_crt(&key,&crt_output,&workspace,&work) == TC_RSA_OK ||
          TC_RSA_sign_v15_digest(&key,&v15,(TC_bytes){signature,32},&workspace,
            (TC_buffer){signature,sizeof signature},&execution) == TC_RSA_OK ||
          TC_RSA_sign_pss_digest(&key,&pss,(TC_bytes){signature,32},&workspace,
            (TC_buffer){signature,sizeof signature},&execution) == TC_RSA_OK ||
          TC_RSA_decrypt_oaep(&key,&oaep,(TC_bytes){signature,sizeof signature},
            &workspace,(TC_buffer){signature,sizeof signature},&plaintext_length,
            &execution) == TC_RSA_OK) return 1;
    }
  }
  {
    TC_X509_native_workspace scratch = {NULL,NULL,TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
    TC_X509_signature_provider provider = TC_X509_native_provider(&scratch);
    if (!provider.verify || !provider.verify_digest || provider.context != &scratch) return 1;
  }
  {
    TC_bytes empty = {NULL,0};
    TC_TLV_limits cms_limits = {1024,1024,64,8};
    TC_TLV_frame frames[8];
    static const uint8_t encoded_tree[] = {0x30,0x80,0,0};
    TC_TLV_element tree;
    if (TC_TLV_read_tree(encoded_tree,sizeof encoded_tree,TC_TLV_BER,&cms_limits,
        frames,sizeof frames / sizeof *frames,&tree) != TC_TLV_OK || tree.value.length) return 1;
    TC_CMS_signed_attributes attributes;
    size_t work = 4096;
    if (TC_CMS_signed_attributes_read(empty,TC_CMS_ATTRIBUTES_DER,
        &cms_limits,frames,8,&work,&attributes) != TC_TLV_MORE) return 1;
    if (TC_CMS_signed_attributes_read(empty,TC_CMS_ATTRIBUTES_BER_DEFINITE_ORDER,
        &cms_limits,frames,8,&work,&attributes) != TC_TLV_MORE) return 1;
  }
  TC_X509_store store = {0};
  TC_X509_store_snapshot snapshot = {0}, *reader = NULL;
  TC_X509_store_source source = {0};
  static const uint8_t expected[TC_SHA256_DIGESTLEN] = {
    0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
    0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
  };
  uint8_t result[TC_SHA256_DIGESTLEN];
  uint8_t key[32] = {0};
  static const uint8_t integer[] = {2, 1, 42};
  uint32_t number;
  TC_PIV_CVC cvc;
  TC_PIV_CHUID chuid;
  TC_X509_public_key public_key;
  TC_X509_policy_reader policies;
  TC_X509_policy policy;
  TC_bytes policy_oids[1];
  TC_EAC_CVC_public_key eac_key;
  TC_PIV_SM session = {0};
  TC_EC_workspace workspace;
  uint8_t point[65];
  TC_TLV_limits limits = {64,64,4,1};
  static const uint8_t policy_extension[] = {0x30,5,0x30,3,6,1,42};
  static const uint8_t eac[] = {0x7f,0x49,19,6,10,4,0,0x7f,0,7,2,2,2,1,1,
                               0x81,2,0x0c,0xa1,0x82,1,17};
  static const uint8_t spki[] = {
    0x30,0x1b,0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,
    0x05,0x00,0x03,0x0a,0x00,0x30,0x07,0x02,0x02,0x0c,0xa1,0x02,0x01,0x11
  };
  if (TC_X509_store_prepare(&snapshot,&source) != TC_TLV_OK ||
      TC_X509_store_publish(&store,0,&snapshot) != TC_TLV_OK ||
      TC_X509_store_acquire(&store,&reader) != TC_TLV_OK ||
      reader != &snapshot || TC_X509_store_release(reader) != TC_TLV_OK) return 1;
  {
    TC_X509_path_options options = {0};
    TC_X509_path_workspace validation = {0};
    TC_bytes path[1];
    TC_X509_search_frame frames[1];
    TC_X509_search_workspace search = {path,frames,1};
    TC_X509_search_result found;
    TC_bytes target = {spki,sizeof spki};
    options.max_work = 10000;
    options.max_certificates = 1;
    if (TC_X509_path_build(target,&source,&options,&validation,&search,&found)
        != TC_X509_PATH_INVALID) return 1;
  }
  if (TC_X509_subject_public_key(spki, sizeof spki, &public_key) != TC_TLV_OK ||
      public_key.bits != 12) return 1;
  {
    const uint8_t name[] = {0x30,12,0x31,10,0x30,8,6,3,0x55,4,3,0x0c,1,'A'};
    TC_bytes encoded = {name,sizeof name};
    TC_TLV_limits name_limits = {64,64,8,3};
    uint32_t left[8], right[8];
    uint8_t used[1];
    TC_X509_name_workspace names = {left,right,8,used,1};
    size_t work = 1000;
    int equal = 0;
    if (TC_X509_name_equal(encoded, encoded, &name_limits, &names, &work, &equal) != TC_TLV_OK
        || !equal) return 1;
  }
  if (TC_X509_policies_init(&policies, policy_extension, sizeof policy_extension,
                            &limits, policy_oids, 1) != TC_TLV_OK ||
      TC_X509_policy_next(&policies, &policy) != TC_TLV_OK ||
      policy.oid.length != 1 || policy.oid.data[0] != 42 ||
      TC_X509_policy_next(&policies, &policy) != TC_TLV_END) return 1;
  if (TC_EAC_CVC_public_key_read(eac, sizeof eac, &limits, &eac_key) != TC_TLV_OK ||
      eac_key.modulus.length != 2) return 1;
  if (TC_PIV_CVC_read(NULL, 0, &cvc) != TC_TLV_MORE) return 1;
  if (TC_PIV_CHUID_read(NULL, 0, TC_PIV_CHUID_CONTAINER, &chuid) != TC_TLV_MORE) return 1;
  if (TC_DER_uint32(integer, sizeof integer, &number) != TC_TLV_OK || number != 42) return 1;
  if (TC_KMAC256_digest(key, sizeof(key), NULL, 0, NULL, 0,
                       result, sizeof(result)) != TC_OK) return 1;
  if (TC_SSKDF_SHA256(key, sizeof key, NULL, 0, result, sizeof result) != TC_OK) return 1;
  key[31] = 1;
  if (TC_EC_public_key(TC_EC_P256, key, sizeof key,
                       point, sizeof point, &workspace) != TC_OK) return 1;
  if (TC_EC_validate_public_key(TC_EC_P256, point, sizeof point,
                                &workspace) != TC_OK) return 1;
  TC_PIV_SM_clear(&session);
  return TC_SHA256_digest((const uint8_t*)"abc", 3, result) != TC_OK ||
         memcmp(result, expected, sizeof(result)) != 0;
}
