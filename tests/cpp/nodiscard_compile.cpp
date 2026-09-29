/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */

/* tests/cmake/cpp_nodiscard.cmake compiles this file with -Wunused-result.
 * Every line marked DISCARDED must produce an unused-result warning and no
 * other line may. The file is never linked or run. */

#define TC_ENABLE_AES 1
#define TC_AES_ENABLE_CBC 1
#define TC_AES_ENABLE_ECB 1
#define TC_AES_ENABLE_CTR 1
#define TC_AES_ENABLE_OFB 1
#define TC_AES_ENABLE_GCM 1
#define TC_AES_ENABLE_CCM 1
#define TC_AES_ENABLE_EAX 1
#define TC_AES_ENABLE_EAX_PRIME 1
#define TC_AES_ENABLE_SIV 1
#define TC_AES_ENABLE_CMAC 1
#define TC_AES_ENABLE_DYNAMIC 1
#define TC_ENABLE_DES 1
#define TC_DES_ENABLE_ECB 1
#define TC_DES_ENABLE_CBC 1
#define TC_DES_ENABLE_CTR 1
#define TC_DES_ENABLE_OFB 1
#define TC_DES_ENABLE_CFB1 1
#define TC_DES_ENABLE_CFB8 1
#define TC_DES_ENABLE_CFB64 1
#define TC_DES_ENABLE_TDES 1
#define TC_DES_ENABLE_CMAC 1
#define TC_ENABLE_SHA256 1
#define TC_ENABLE_HMAC 1
#define TC_ENABLE_KMAC256 1
#define TC_ENABLE_RSA 1
#define TC_ENABLE_GZIP 1
#define TC_ENABLE_TLV 1

#include <tiny_crypto/aes.hpp>
#include <tiny_crypto/aes_dynamic.hpp>
#include <tiny_crypto/des.hpp>
#include <tiny_crypto/gzip.hpp>
#include <tiny_crypto/hash.hpp>
#include <tiny_crypto/kmac.hpp>
#include <tiny_crypto/rsa.hpp>
#include <tiny_crypto/tlv.hpp>

void tiny_crypto_nodiscard_compile(uint8_t* data, size_t length)
{
  using namespace tiny_crypto;
  const bytes in = {data, length};
  const buffer out = {data, length};
  uint8_t block[16] = {0};
  uint8_t eax_prime_tag[TC_AES_EAX_PRIME_TAG_LEN] = {0};
  uint8_t synthetic_iv[TC_AES_SIV_V_LEN] = {0};

  /* Authentication and verification results. */
  GCM gcm;
  gcm.decrypt_finish(data, length);                              /* DISCARDED */
  HMAC_SHA256::verify(data, length, data, length, data, length); /* DISCARDED */
  ct_equal(data, data, length);                                  /* DISCARDED */
  ccm_decrypt(in, in, in, in, in, out);                          /* DISCARDED */
  eax_decrypt(in, in, in, in, in, out);                          /* DISCARDED */
  eax_prime_decrypt(in, in, in, eax_prime_tag, out);             /* DISCARDED */
  siv_decrypt(in, &in, 1, synthetic_iv, in, out);                /* DISCARDED */

  rsa_public_key public_key = {};
  rsa_private_key private_key = {};
  rsa_prepared_public_key prepared = {};
  rsa_v15_options v15 = {};
  rsa_pss_options pss = {};
  rsa_oaep_options oaep = {};
  rsa_workspace workspace = {};
  rsa_execution execution = {};
  TC_work_budget work = {};
  size_t plain_length = 0;
  rsa_verify_v15_digest(public_key, v15, in, in, workspace, work);                  /* DISCARDED */
  rsa_verify_v15_prepared(prepared, v15, in, in, workspace, work);                  /* DISCARDED */
  rsa_verify_pss_digest(public_key, pss, in, in, workspace, work);                  /* DISCARDED */
  rsa_verify_pss_prepared(prepared, pss, in, in, workspace, work);                  /* DISCARDED */
  rsa_decrypt_oaep(private_key, oaep, in, workspace, out, plain_length, execution); /* DISCARDED */
  rsa_sign_pss_digest(private_key, pss, in, workspace, out, execution);             /* DISCARDED */

  /* Cipher, hash and MAC status results. */
  AES aes;
  aes.xcrypt_ctr(data, length);                       /* DISCARDED */
  aes.decrypt_cbc(data, length);                      /* DISCARDED */
  aes.set_iv(block);                                  /* DISCARDED */
  gcm.encrypt_finish(data, length);                   /* DISCARDED */
  gcm.aad_update(data, length);                       /* DISCARDED */
  aes_cmac(data, length, data, length, data, length); /* DISCARDED */
  ccm_encrypt(in, in, in, in, out, out);              /* DISCARDED */

  DES des;
  des.init(data, length);                             /* DISCARDED */
  des.encrypt_ecb(block);                             /* DISCARDED */
  des.xcrypt_ctr(data, length);                       /* DISCARDED */
  des.set_iv(data, length);                           /* DISCARDED */
  des_cmac(data, length, data, length, data, length); /* DISCARDED */

  SHA256 hash;
  hash.update(data, length);                  /* DISCARDED */
  hash.finish(data, length);                  /* DISCARDED */
  SHA256::digest(data, length, data, length); /* DISCARDED */
  HMAC_SHA256 hmac;
  hmac.update(data, length);                                  /* DISCARDED */
  hmac.finish(data, length);                                  /* DISCARDED */
  HMAC_SHA256::mac(data, length, data, length, data, length); /* DISCARDED */

  KMAC256 kmac;
  kmac.update(data, length); /* DISCARDED */
  kmac.final(data, length);  /* DISCARDED */

  AES_dynamic dynamic;
  dynamic.encrypt(block); /* DISCARDED */
  AES_dynamic_CMAC dynamic_cmac;
  dynamic_cmac.final(block); /* DISCARDED */

  /* Decoder and parser results. */
  GZIPDecoder gzip;
  size_t gzip_work = 0;
  size_t gzip_length = 0;
  gzip.decode(data, length, data, length, gzip_work, gzip_length); /* DISCARDED */
  TLVReader reader;
  TC_TLV_limits limits = {};
  TC_TLV_element element = {};
  reader.init(data, length, TC_TLV_DER, limits); /* DISCARDED */
  reader.next(element);                          /* DISCARDED */

  /* Clearing stays unmarked. */
  aes.clear();
  des.clear();
  kmac.clear();
  dynamic.clear();
}
