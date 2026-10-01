/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/tiny_crypto.hpp>
#include <tiny_crypto/rsa.h>
#include <tiny_crypto/cms.h>
#include <tiny_crypto/x509_crypto.h>

int main()
{
  const uint8_t prefix[] = {1, 2};
  if (tiny_crypto::ct_equal({prefix, sizeof prefix}, {prefix, 1}) != TC_MISMATCH)
    return 1;
  if (!tiny_crypto::rsa_workspace_words(TC_RSA_OPERATION_VERIFY, 3072) ||
      !tiny_crypto::rsa_modulus_supported(3072))
    return 1;
  TC_X509_native_workspace native_scratch = {nullptr, nullptr,
                                             TC_X509_NATIVE_DEFAULT_SIGNATURE_WORK};
  auto native_provider = TC_X509_native_provider(&native_scratch);
  if (!native_provider.verify || !native_provider.verify_digest ||
      native_provider.context != &native_scratch)
    return 1;
  TC_TLV_limits cms_limits = {1024, 1024, 64, 8};
  TC_TLV_frame frames[8];
  const uint8_t encoded_tree[] = {0x30, 0x80, 0, 0};
  TC_TLV_element tree;
  if (TC_TLV_read_tree(TC_bytes{encoded_tree, sizeof encoded_tree}, TC_TLV_BER, &cms_limits,
                       TC_TLV_frames{frames, sizeof frames / sizeof *frames}, &tree) != TC_TLV_OK ||
      tree.value.length)
    return 1;
  TC_CMS_signed_attributes attributes;
  const TC_CMS_verification_policy cms_policy{};
  size_t work = 4096;
  if (TC_CMS_signed_attributes_read({nullptr, 0}, &cms_policy, &cms_limits,
                                    TC_TLV_frames{frames, 8}, &work, &attributes) != TC_TLV_MORE)
    return 1;
  TC_RSA_word rsa_words[TC_RSA_VERIFY_WORKSPACE_WORDS(2048)];
  auto rsa_workspace = tiny_crypto::rsa_workspace_for(rsa_words);
  tiny_crypto::rsa_public_key rsa_key = {};
  uint8_t ciphertext[256] = {};
  tiny_crypto::rsa_oaep_options oaep = {TC_HASH_SHA256, TC_HASH_SHA256, {nullptr, 0}};
  tiny_crypto::rsa_execution execution = {{nullptr, nullptr}, 0, {0}};
  if (tiny_crypto::rsa_encrypt_oaep(rsa_key, oaep, {nullptr, 0}, rsa_workspace,
                                    {ciphertext, sizeof ciphertext}, execution) != TC_RSA_ARGUMENT)
    return 1;
  tiny_crypto::rsa_v15_options v15 = {TC_HASH_SHA256};
  TC_work_budget rsa_work = {0};
  const tiny_crypto::rsa_pss_options pss = {TC_HASH_SHA256, TC_HASH_SHA256, 32};
  const uint8_t digest[32] = {}, salt[32] = {};
  uint8_t representative[256];
  rsa_work.remaining = UINT32_MAX;
  if (tiny_crypto::rsa_encode_pss_digest(pss, {digest, sizeof digest}, {salt, sizeof salt},
                                         representative, rsa_work) != TC_RSA_OK)
    return 1;
  rsa_work.remaining = UINT32_MAX;
  if (tiny_crypto::rsa_encode_pss_digest(pss, {digest, sizeof digest}, {salt, sizeof salt},
                                         {ciphertext, sizeof ciphertext}, rsa_work) != TC_RSA_OK)
    return 1;
  for (size_t i = 0; i < sizeof representative; ++i)
    if (representative[i] != ciphertext[i])
      return 1;
  rsa_work.remaining = 0;
  if (tiny_crypto::rsa_verify_v15_digest(rsa_key, v15, {nullptr, 0}, {nullptr, 0}, rsa_workspace,
                                         rsa_work) != TC_RSA_ARGUMENT)
    return 1;
  uint8_t raw_output[256];
  rsa_work.remaining = UINT32_MAX;
  if (tiny_crypto::rsa_raw_public(rsa_key, {nullptr, 0}, rsa_workspace, raw_output, rsa_work) !=
      TC_RSA_ARGUMENT)
    return 1;

  /* Symmetric wrappers take key, IV and message spans. */
  const uint8_t aes_key[TC_AES_KEYLEN] = {1}, aes_iv[TC_AES_BLOCKLEN] = {2};
  uint8_t block[TC_AES_BLOCKLEN] = {3}, original[TC_AES_BLOCKLEN] = {3};
  tiny_crypto::AES aes;
  if (aes.init({aes_key, sizeof aes_key}, {aes_iv, sizeof aes_iv}) != TC_OK ||
      aes.xcrypt_ctr(block) != TC_OK || aes.set_iv(aes_iv) != TC_OK ||
      aes.xcrypt_ctr(block) != TC_OK)
    return 1;
  for (size_t i = 0; i < sizeof block; ++i)
    if (block[i] != original[i])
      return 1;
  if (aes.init({aes_key, sizeof aes_key - 1}) != TC_ERROR || aes.xcrypt_ctr(block) != TC_ERROR)
    return 1;
  tiny_crypto::AES_dynamic_CMAC cmac;
  uint8_t cmac_tag[16];
  if (cmac.init({aes_key, sizeof aes_key}) != TC_OK || cmac.update(original) != TC_OK ||
      cmac.finish(cmac_tag) != TC_OK)
    return 1;
  uint8_t hmac_tag[TC_HMAC_MIN_TAG_LEN];
  if (tiny_crypto::HMAC_SHA256::mac({aes_key, sizeof aes_key}, {original, sizeof original},
                                    {hmac_tag, sizeof hmac_tag}) != TC_OK ||
      tiny_crypto::HMAC_SHA256::verify({aes_key, sizeof aes_key}, {original, sizeof original},
                                       {hmac_tag, sizeof hmac_tag}) != TC_OK)
    return 1;

  uint8_t scalar[32] = {};
  uint8_t point[65];
  uint8_t derived[32];
  tiny_crypto::ec_workspace workspace;
  tiny_crypto::piv_sm session;
  scalar[31] = 1;
  TC_work_budget ec_work = {UINT32_MAX};
  if (tiny_crypto::ec_public_key(TC_EC_P256, {scalar, sizeof scalar}, point, workspace, ec_work) !=
      TC_EC_OK)
    return 1;
  if (tiny_crypto::ec_validate_public_key(TC_EC_P256, {point, sizeof point}, workspace, ec_work) !=
      TC_EC_OK)
    return 1;
  if (tiny_crypto::sskdf_sha256({scalar, sizeof scalar}, nullptr, 0, {derived, sizeof derived}) !=
      TC_OK)
    return 1;
  if (tiny_crypto::hkdf_sha256_derive(
          tiny_crypto::bytes{nullptr, 0}, tiny_crypto::bytes{scalar, sizeof scalar},
          tiny_crypto::bytes{nullptr, 0}, {derived, sizeof derived}) != TC_OK)
    return 1;
  session.clear();
  return session.state() != TC_PIV_SM_IDLE;
}
