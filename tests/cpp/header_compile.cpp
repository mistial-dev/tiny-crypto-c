/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */

#include <tiny_crypto/tiny_crypto.hpp>
#if TC_ENABLE_MD5
#include <tiny_crypto/hash.hpp>
#endif

template <typename Left, typename Right> struct same_type {
  enum { value = 0 };
};
template <typename Type> struct same_type<Type, Type> {
  enum { value = 1 };
};
static_assert(same_type<TC_result, TC_status>::value, "TC_status must be the shared result");
static_assert(same_type<TC_result, TC_EC_result>::value, "EC must use the shared result");
static_assert(same_type<TC_result, TC_RSA_result>::value, "RSA must use the shared result");
static_assert(same_type<TC_result, TC_TLV_result>::value, "TLV must use the shared result");
static_assert(same_type<tiny_crypto::result, tiny_crypto::status>::value,
              "C++ result aliases must be identical");
static_assert(TC_TLV_INVALID < TC_TLV_OK && TC_TLV_END > TC_TLV_OK,
              "TLV error and flow-control signs are public parser behavior");
static_assert(TC_DRBG_ENTROPY != TC_DRBG_ERROR, "entropy failure must remain distinguishable");
static_assert(TC_CREDENTIAL_REVOKED != TC_CREDENTIAL_INVALID,
              "revocation must remain distinguishable from invalid input");
static_assert(TC_PIV_CARD_STATUS != TC_PIV_REFUSED,
              "card status must remain distinguishable from a local refusal");
#if TC_ENABLE_X509
#include <tiny_crypto/key_challenge.h>
#include <tiny_crypto/x509_path.h>
#include <tiny_crypto/x509_crl.h>
#include <tiny_crypto/x509_revocation.h>
#include <tiny_crypto/x509_store.h>
#include <tiny_crypto/rsa.h>
#include <tiny_crypto/rsa.hpp>
#endif

/* Explicit instantiation compiles every member of the hash and HMAC
 * templates, including members a test does not call. */
#if TC_ENABLE_MD5
template class tiny_crypto::basic_hash<tiny_crypto::detail::tc_md5_traits>;
#endif
#if TC_ENABLE_SHA1
template class tiny_crypto::basic_hash<tiny_crypto::detail::tc_sha1_traits>;
#endif
#if TC_ENABLE_SHA224
template class tiny_crypto::basic_hash<tiny_crypto::detail::tc_sha224_traits>;
#endif
#if TC_ENABLE_SHA256
template class tiny_crypto::basic_hash<tiny_crypto::detail::tc_sha256_traits>;
#endif
#if TC_ENABLE_SHA384
template class tiny_crypto::basic_hash<tiny_crypto::detail::tc_sha384_traits>;
#endif
#if TC_ENABLE_SHA512
template class tiny_crypto::basic_hash<tiny_crypto::detail::tc_sha512_traits>;
#endif
#if TC_ENABLE_HMAC && TC_ENABLE_SHA1
template class tiny_crypto::basic_hmac<tiny_crypto::detail::tc_hmac_sha1_traits>;
#endif
#if TC_ENABLE_HMAC && TC_ENABLE_SHA224
template class tiny_crypto::basic_hmac<tiny_crypto::detail::tc_hmac_sha224_traits>;
#endif
#if TC_ENABLE_HMAC && TC_ENABLE_SHA256
template class tiny_crypto::basic_hmac<tiny_crypto::detail::tc_hmac_sha256_traits>;
#endif
#if TC_ENABLE_HMAC && TC_ENABLE_SHA384
template class tiny_crypto::basic_hmac<tiny_crypto::detail::tc_hmac_sha384_traits>;
#endif
#if TC_ENABLE_HMAC && TC_ENABLE_SHA512
template class tiny_crypto::basic_hmac<tiny_crypto::detail::tc_hmac_sha512_traits>;
#endif

/* Array-deduced function templates that the function below does not call. */
#if TC_ENABLE_SHA256
template TC_status tiny_crypto::SHA256::digest<16>(const uint8_t (&)[16],
                                                   uint8_t (&)[TC_SHA256_DIGESTLEN]) noexcept;
#if TC_ENABLE_HMAC
template TC_status tiny_crypto::HMAC_SHA256::init<16>(const uint8_t (&)[16]) noexcept;
#endif
#endif
#if TC_ENABLE_AES && TC_AES_ENABLE_CBC
template TC_status tiny_crypto::AES::decrypt_cbc<16>(uint8_t (&)[16]) noexcept;
#endif
#if TC_ENABLE_DES && TC_DES_ENABLE_CFB1
template TC_status tiny_crypto::DES::decrypt_cfb1<8>(uint8_t (&)[8], size_t) noexcept;
#endif
#if TC_ENABLE_RSA
template tiny_crypto::rsa_result
tiny_crypto::rsa_raw_private<128>(const tiny_crypto::rsa_public_key&, tiny_crypto::bytes,
                                  tiny_crypto::bytes, const tiny_crypto::rsa_workspace&,
                                  uint8_t (&)[128], tiny_crypto::rsa_execution&) noexcept;
template tiny_crypto::rsa_result
tiny_crypto::rsa_encode_v15_digest<128>(const tiny_crypto::rsa_v15_options&, tiny_crypto::bytes,
                                        uint8_t (&)[128], TC_work_budget&) noexcept;
template tiny_crypto::rsa_result
tiny_crypto::rsa_encode_pss_digest<128>(const tiny_crypto::rsa_pss_options&, tiny_crypto::bytes,
                                        tiny_crypto::bytes, uint8_t (&)[128],
                                        TC_work_budget&) noexcept;
#endif
#if TC_ENABLE_EC
template tiny_crypto::ec_result tiny_crypto::ec_public_key<65>(tiny_crypto::ec_curve,
                                                               tiny_crypto::bytes, uint8_t (&)[65],
                                                               tiny_crypto::ec_workspace&,
                                                               TC_work_budget&) noexcept;
template tiny_crypto::ec_result
tiny_crypto::ec_generate_key_pair<32, 65>(tiny_crypto::ec_curve, uint8_t (&)[32], uint8_t (&)[65],
                                          tiny_crypto::ec_workspace&,
                                          tiny_crypto::ec_execution&) noexcept;
template tiny_crypto::ec_result tiny_crypto::ecdh<32>(tiny_crypto::ec_curve, tiny_crypto::bytes,
                                                      tiny_crypto::bytes, uint8_t (&)[32],
                                                      tiny_crypto::ec_workspace&,
                                                      TC_work_budget&) noexcept;
template tiny_crypto::ec_result tiny_crypto::ecdsa_sign_digest<64>(
    tiny_crypto::ec_curve, tiny_crypto::bytes, tiny_crypto::bytes, tiny_crypto::bytes,
    uint8_t (&)[64], tiny_crypto::ecdsa_workspace&, tiny_crypto::ec_execution&) noexcept;
#endif

/* Instantiate every wrapper class and the array-deduced member templates.
 * The object is compiled and never run, so each result is only returned. */
int tiny_crypto_cpp_header_compile(uint8_t* data, size_t length)
{
  const tiny_crypto::bytes in = {data, length};
  const tiny_crypto::buffer out = {data, length};
  uint8_t block[16] = {0};
  int failures = 0;
  (void)in;
  (void)out;
  (void)block;
#if TC_ENABLE_AES
  tiny_crypto::AES aes;
  failures += aes.init(block) != TC_OK;
#if TC_AES_ENABLE_CBC || TC_AES_ENABLE_CTR || TC_AES_ENABLE_OFB
  failures += aes.init(in, in) != TC_OK;
  failures += aes.init(block, block) != TC_OK;
  failures += aes.set_iv(block) != TC_OK;
#endif
#if TC_AES_ENABLE_CBC
  failures += aes.encrypt_cbc(block) != TC_OK;
#endif
#if TC_AES_ENABLE_CTR
  failures += aes.xcrypt_ctr(block) != TC_OK;
#endif
#if TC_AES_ENABLE_OFB
  failures += aes.xcrypt_ofb(block) != TC_OK;
#endif
#if TC_AES_ENABLE_GCM
  tiny_crypto::GCM gcm;
  failures += gcm.init(in, in) != TC_OK;
  failures += gcm.init(block, in) != TC_OK;
  failures += gcm.init_short_tag(block, in, 8) != TC_OK;
  failures += gcm.encrypt_update(block) != TC_OK;
  failures += gcm.encrypt_finish(block) != TC_OK;
  gcm.clear();
#endif
#if TC_AES_ENABLE_CMAC
  tiny_crypto::AES_CMAC aes_cmac;
  failures += aes_cmac.init(block) != TC_OK;
  failures += aes_cmac.update(block) != TC_OK;
  failures += aes_cmac.finish(block) != TC_OK;
  failures += tiny_crypto::aes_cmac_verify(in, in, in) != TC_OK;
#endif
#if TC_AES_ENABLE_DYNAMIC
  tiny_crypto::AES_dynamic dynamic;
  failures += dynamic.init(block) != TC_OK;
  tiny_crypto::AES_dynamic_CMAC dynamic_cmac;
  failures += dynamic_cmac.init(block) != TC_OK;
  failures += dynamic_cmac.update(block) != TC_OK;
#endif
#if TC_AES_ENABLE_KW
  size_t kw_length = 0;
  failures += tiny_crypto::aes_kw_wrap(in, in, {block, sizeof block}) != TC_OK;
  failures += tiny_crypto::aes_kw_unwrap(in, in, {block, sizeof block}) != TC_OK;
  failures += tiny_crypto::aes_kwp_wrap(in, in, {block, sizeof block}) != TC_OK;
  failures += tiny_crypto::aes_kwp_unwrap(in, in, {block, sizeof block}, kw_length) != TC_OK;
#endif
#endif
#if TC_ENABLE_DES
  uint8_t des_block[8] = {0};
  tiny_crypto::DES des;
  failures += des.init(des_block) != TC_OK;
#if TC_DES_NEEDS_IV
  failures += des.init(in, in) != TC_OK;
  failures += des.init(des_block, des_block) != TC_OK;
  failures += des.set_iv(des_block) != TC_OK;
#endif
#if TC_DES_ENABLE_CFB1
  failures += des.encrypt_cfb1(des_block, 8) != TC_OK;
#endif
#if TC_DES_ENABLE_CMAC
  tiny_crypto::DES_CMAC des_cmac;
  failures += des_cmac.init(des_block) != TC_OK;
  failures += des_cmac.update(des_block) != TC_OK;
  failures += des_cmac.finish(des_block) != TC_OK;
  failures += tiny_crypto::des_cmac_verify(in, in, in) != TC_OK;
#endif
#if TC_DES_ENABLE_ISO9797
  tiny_crypto::DES_ISO9797 iso9797;
  failures += iso9797.init(TC_DES_ISO9797_ALG3, TC_DES_ISO9797_PAD2, block) != TC_OK;
  failures += iso9797.update(des_block) != TC_OK;
  failures += iso9797.finish(des_block) != TC_OK;
  failures += tiny_crypto::des_iso9797_verify(TC_DES_ISO9797_ALG1, TC_DES_ISO9797_PAD1, in, in,
                                              in) != TC_OK;
#endif
#endif
#if TC_ENABLE_SHA256
  tiny_crypto::SHA256 hash;
  failures += hash.update(block) != TC_OK;
#if TC_ENABLE_HMAC
  tiny_crypto::HMAC_SHA256 hmac(block);
  failures += hmac.update(block) != TC_OK;
#endif
#endif
#if TC_ENABLE_MD5
  tiny_crypto::MD5 md5;
  failures += md5.update(block) != TC_OK;
#endif
#if TC_ENABLE_KMAC256
  tiny_crypto::KMAC256 kmac;
  failures += kmac.init(in) != TC_OK;
#endif
#if TC_ENABLE_GZIP
  tiny_crypto::GZIPDecoder gzip;
  (void)gzip;
#endif
#if TC_ENABLE_DRBG
  tiny_crypto::drbg generator;
  failures += generator.generate(tiny_crypto::buffer{block, sizeof block}) != TC_DRBG_ARGUMENT;
#endif
#if TC_ENABLE_RSA
  TC_RSA_word rsa_words[4];
  const tiny_crypto::rsa_workspace rsa_workspace = tiny_crypto::rsa_workspace_for(rsa_words);
  const tiny_crypto::rsa_public_key rsa_key = {in, in};
  TC_work_budget rsa_work = {0};
  failures += tiny_crypto::rsa_raw_public(rsa_key, in, rsa_workspace, block, rsa_work) != TC_RSA_OK;
  failures += tiny_crypto::rsa_workspace_words(TC_RSA_OPERATION_RAW_PUBLIC, 1024) == 0;
#endif
#if TC_ENABLE_PIV_SM
  tiny_crypto::piv_sm session;
  tiny_crypto::piv_sm_workspace sm_workspace{};
  const tiny_crypto::piv_sm_unprotect_request sm_response{};
  size_t sm_length = 0;
  failures += session.unprotect(sm_response, tiny_crypto::buffer{block, sizeof block}, sm_length,
                                sm_workspace) != TC_ERROR;
#endif
#if TC_ENABLE_X509
  TC_RSA_result (*validate)(const TC_RSA_private_key*, TC_RSA_exponent_policy,
                            const TC_RSA_workspace*, TC_RSA_execution*) =
      TC_RSA_validate_private_key;
  tiny_crypto::rsa_result (*validate_cpp)(
      const tiny_crypto::rsa_private_key&, const tiny_crypto::rsa_workspace&,
      tiny_crypto::rsa_execution&, TC_RSA_exponent_policy) = tiny_crypto::rsa_validate_private_key;
  (void)validate;
  (void)validate_cpp;
#if defined(__AVR__)
  static_assert(sizeof(size_t) == 2, "AVR size_t must be 16-bit");
  static_assert(sizeof(uint32_t) == 4, "RSA validation work must be 32-bit");
#endif
  TC_X509_public_key key = {};
  (void)key;
  TC_key_challenge_options challenge_options = {};
  TC_key_challenge_workspace challenge_workspace = {};
  (void)challenge_options;
  (void)challenge_workspace;
  TC_TLV_frame frames[4];
  TC_bytes oids[4], policies[4];
  uint32_t left[8], right[6];
  uint8_t matched[2];
  TC_X509_policy_node nodes[4];
  TC_X509_policy_edge edges[4];
  TC_X509_policy_expected expected[4];
  TC_X509_policy_mapping mappings[4];
  TC_X509_certificate certificates[4];
  TC_X509_extension_summary summaries[4];
  TC_X509_path_workspace workspace =
      TC_X509_PATH_WORKSPACE_INIT(frames, oids, left, right, matched, nodes, edges, expected,
                                  mappings, policies, certificates, summaries);
  (void)workspace;
#if TC_ENABLE_X509_PATH
  static TC_X509_path_storage path_arena[256];
  const TC_X509_path_capacity path_capacity = {4, 4, 8, 2, 4, 4, 4, 4, 4, 4};
  const TC_buffer path_buffer = {reinterpret_cast<uint8_t*>(path_arena), sizeof path_arena};
  TC_X509_path_workspace arena_workspace = {};
  size_t path_bytes = 0;
  if (TC_X509_path_workspace_size(&path_capacity, &path_bytes) != TC_RESULT_OK ||
      path_bytes > sizeof path_arena ||
      TC_X509_path_workspace_init(&path_capacity, path_buffer, &arena_workspace) != TC_RESULT_OK)
    ++failures;
#endif
#endif
#if TC_ENABLE_TLV
  tiny_crypto::TLVReader reader;
  (void)reader;
#endif
#if TC_ENABLE_APDU
  {
    static const uint8_t answer[] = {0x90, 0x00};
    const tiny_crypto::apdu_command command = {{answer, 0}, 0, 0x00, 0xa4, 0x04, 0x00};
    uint8_t encoded[TC_APDU_HEADER_BYTES];
    size_t written = 0;
    tiny_crypto::apdu_response response = {};
    tiny_crypto::apdu_channel channel;
    if (tiny_crypto::apdu_command_encode(command, TC_APDU_SHORT, encoded, written) != TC_APDU_OK ||
        tiny_crypto::apdu_response_read({answer, sizeof answer}, response) != TC_APDU_OK ||
        tiny_crypto::apdu_status_classify(response.sw) != TC_APDU_SW_SUCCESS ||
        channel.exchanges_left() != 0 || channel.native() == nullptr)
      ++failures;
  }
#endif
#if TC_ENABLE_PIV_COMMAND
  {
    tiny_crypto::piv_link link;
    if (link.status() != 0 || link.info().application != TC_PIV_APPLICATION_NONE ||
        tiny_crypto::piv_status_classify(0x6a82, TC_PIV_COMMAND_GET_DATA, TC_PIV_APPLICATION_PIV) !=
            TC_PIV_SW_NOT_FOUND)
      ++failures;
  }
#endif
#if TC_ENABLE_PIV_SM_APDU
  {
    // The session outlives the link that borrows it.
    tiny_crypto::piv_sm link_session;
    tiny_crypto::piv_link link;
    tiny_crypto::piv_sm_workspace link_workspace{};
    if (link_session.native() == nullptr ||
        tiny_crypto::piv_link_secure(link, link_workspace, tiny_crypto::buffer{data, length}) !=
            TC_PIV_ARGUMENT)
      ++failures;
    tiny_crypto::piv_link_unsecure(link);
  }
#endif
#if TC_ENABLE_PIV_VCI
  {
    tiny_crypto::piv_link link;
    tiny_crypto::piv_discovery discovery{};
    tiny_crypto::piv_vci_mode mode = TC_PIV_VCI_PAIRED;
    if (tiny_crypto::piv_discovery_get(link, TC_PIV_DISCOVERY_PIV,
                                       tiny_crypto::buffer{data, length},
                                       discovery) != TC_PIV_ARGUMENT ||
        tiny_crypto::piv_vci_establish(link, discovery, tiny_crypto::bytes{nullptr, 0}, mode) !=
            TC_PIV_ARGUMENT)
      ++failures;
  }
#endif
#if TC_ENABLE_PIV_CATALOG
  {
    tiny_crypto::piv_link link;
    tiny_crypto::piv_object objects[TC_PIV_CATALOG_PIV_OBJECTS];
    tiny_crypto::piv_inventory inventory(objects);
    size_t work = 0;
    if (inventory.read(link, nullptr, tiny_crypto::buffer{data, length}, work) != TC_PIV_ARGUMENT ||
        tiny_crypto::piv_catalog_count(TC_PIV_APPLICATION_PIV, TC_PIV_CARD) !=
            TC_PIV_CATALOG_PIV_OBJECTS)
      ++failures;
  }
#endif
#if TC_ENABLE_PIV_KEY_PROOF
  {
    tiny_crypto::piv_link link;
    const tiny_crypto::piv_key_proof_request request{};
    const TC_X509_signature_provider provider{};
    static tiny_crypto::piv_key_proof_workspace proof_workspace;
    TC_work_budget work{0};
    if (tiny_crypto::piv_key_prove(link, request, TC_random_source{nullptr, nullptr}, provider,
                                   proof_workspace, work) != TC_PIV_ARGUMENT)
      ++failures;
  }
#endif
#if TC_ENABLE_PIV_CARD_CHECK
  {
    static tiny_crypto::piv_card_report report;
    static tiny_crypto::piv_card_check_workspace workspace;
    const tiny_crypto::piv_card_check_request request{};
    const tiny_crypto::piv_check_requirement required[] = {{TC_PIV_CHECK_CHUID, 0, 0}};
    size_t work = 0;
    if (tiny_crypto::piv_card_check(request, workspace, work, report) != TC_PIV_ARGUMENT ||
        tiny_crypto::piv_card_report_accepts(report, required))
      ++failures;
  }
#endif
  return failures;
}
