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
#define TC_AES_ENABLE_KW 1
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
#define TC_DES_ENABLE_ISO9797 1
#define TC_ENABLE_SHA256 1
#define TC_ENABLE_HMAC 1
#define TC_ENABLE_KMAC256 1
#define TC_ENABLE_RSA 1
#define TC_ENABLE_GZIP 1
#define TC_ENABLE_TLV 1
#define TC_ENABLE_APDU 1
#define TC_ENABLE_PIV_COMMAND 1
#define TC_ENABLE_DER 1
#define TC_ENABLE_PIV_CVC 1
#define TC_ENABLE_PIV_SM_APDU 1
#define TC_TLV_ENABLE_BER 1
#define TC_ENABLE_X509 1
#define TC_ENABLE_PIV_OIDS 1
#define TC_ENABLE_CMS 1
#define TC_ENABLE_FASCN 1
#define TC_ENABLE_TWIC_UUID 1
#define TC_ENABLE_PIV_OBJECTS 1
#define TC_ENABLE_PIV_VCI 1
#define TC_ENABLE_PIV_CATALOG 1
#define TC_ENABLE_KEY_CHALLENGE 1
#define TC_ENABLE_PIV_KEY_PROOF 1
#define TC_ENABLE_X509_PATH 1
#define TC_ENABLE_X509_REVOCATION 1
#define TC_ENABLE_CMS_VALIDATION 1
#define TC_ENABLE_PIV_CHUID 1
#define TC_ENABLE_CREDENTIAL 1
#define TC_ENABLE_PIV_CARD_CHECK 1
#define TC_ENABLE_DRBG 1
#define TC_DRBG_ENABLE_HASH 1
#define TC_DRBG_ENABLE_HMAC 1
#define TC_DRBG_ENABLE_CTR 1
#define TC_ENABLE_SSKDF 1
#define TC_ENABLE_EC 1
#define TC_EC_ENABLE_P256 1
#define TC_ENABLE_PIV_SM 1
#define TC_PIV_SM_ENABLE_CS2 1
#define TC_PIV_SM_ENABLE_CS7 0

#include <tiny_crypto/aes.hpp>
#include <tiny_crypto/apdu.hpp>
#include <tiny_crypto/aes_dynamic.hpp>
#include <tiny_crypto/aes_kw.hpp>
#include <tiny_crypto/des.hpp>
#include <tiny_crypto/drbg.hpp>
#include <tiny_crypto/gzip.hpp>
#include <tiny_crypto/hash.hpp>
#include <tiny_crypto/kmac.hpp>
#include <tiny_crypto/piv_card_check.hpp>
#include <tiny_crypto/piv_catalog.hpp>
#include <tiny_crypto/piv_command.hpp>
#include <tiny_crypto/piv_key_proof.hpp>
#include <tiny_crypto/piv_sm.hpp>
#include <tiny_crypto/piv_sm_apdu.hpp>
#include <tiny_crypto/piv_vci.hpp>
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
  gcm_decrypt(in, in, in, in, in, out);              /* DISCARDED */
  HMAC_SHA256::verify(in, in, in);                   /* DISCARDED */
  ct_equal(in, in);                                  /* DISCARDED */
  ccm_decrypt(in, in, in, in, in, out);              /* DISCARDED */
  eax_decrypt(in, in, in, in, in, out);              /* DISCARDED */
  ccm_decrypt_short_tag(in, in, in, in, in, out);    /* DISCARDED */
  eax_decrypt_short_tag(in, in, in, in, in, out);    /* DISCARDED */
  eax_prime_decrypt(in, in, in, eax_prime_tag, out); /* DISCARDED */
  siv_decrypt(in, &in, 1, synthetic_iv, in, out);    /* DISCARDED */

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
  rsa_raw_public(public_key, in, workspace, out, work);                             /* DISCARDED */
  rsa_raw_private(public_key, in, in, workspace, out, execution);                   /* DISCARDED */
  rsa_workspace_words(TC_RSA_OPERATION_VERIFY, 2048);                               /* DISCARDED */
  rsa_modulus_supported(2048);                                                      /* DISCARDED */
  rsa_exponent_in_fips_range(in);                                                   /* DISCARDED */
  rsa_public_work(public_key);                                                      /* DISCARDED */
  rsa_private_work(private_key, 1);                                                 /* DISCARDED */

  /* Cipher, hash and MAC status results. */
  AES aes;
  aes.init(in);                  /* DISCARDED */
  aes.init(in, in);              /* DISCARDED */
  aes.xcrypt_ctr(data, length);  /* DISCARDED */
  aes.decrypt_cbc(data, length); /* DISCARDED */
  aes.set_iv(block);             /* DISCARDED */
  aes.set_iv(in);                /* DISCARDED */
  aes.init(block, block);        /* DISCARDED */
  GCM gcm;
  gcm.init(in, in);                                /* DISCARDED */
  gcm.init(block, in);                             /* DISCARDED */
  gcm.init_short_tag(block, in, 8);                /* DISCARDED */
  gcm.init_short_tag(in, in, 8);                   /* DISCARDED */
  gcm.encrypt_update(data, length);                /* DISCARDED */
  gcm_encrypt(in, in, in, in, out, out);           /* DISCARDED */
  gcm.encrypt_finish(out);                         /* DISCARDED */
  gcm.encrypt_finish(block);                       /* DISCARDED */
  gcm.aad_update(in);                              /* DISCARDED */
  aes_cmac(in, in, out);                           /* DISCARDED */
  aes_cmac_verify(in, in, in);                     /* DISCARDED */
  aes_cmac_short_tag(in, in, out);                 /* DISCARDED */
  aes_cmac_verify_short_tag(in, in, in);           /* DISCARDED */
  ccm_encrypt(in, in, in, in, out, out);           /* DISCARDED */
  ccm_encrypt_short_tag(in, in, in, in, out, out); /* DISCARDED */
  eax_encrypt_short_tag(in, in, in, in, out, out); /* DISCARDED */
  AES_CMAC aes_mac;
  aes_mac.init(in);      /* DISCARDED */
  aes_mac.update(in);    /* DISCARDED */
  aes_mac.finish(block); /* DISCARDED */

  DES des;
  uint8_t des_block[TC_DES_BLOCKLEN] = {0};
  des.init(in);                          /* DISCARDED */
  des.init(in, in);                      /* DISCARDED */
  des.init(des_block, des_block);        /* DISCARDED */
  des.encrypt_ecb(block);                /* DISCARDED */
  des.xcrypt_ctr(data, length);          /* DISCARDED */
  des.set_iv(in);                        /* DISCARDED */
  des_cmac(in, in, out);                 /* DISCARDED */
  des_cmac_verify(in, in, in);           /* DISCARDED */
  des_cmac_short_tag(in, in, out);       /* DISCARDED */
  des_cmac_verify_short_tag(in, in, in); /* DISCARDED */
  DES_CMAC des_mac;
  des_mac.init(in);          /* DISCARDED */
  des_mac.update(in);        /* DISCARDED */
  des_mac.finish(des_block); /* DISCARDED */
  const TC_DES_ISO9797_algorithm alg3 = TC_DES_ISO9797_ALG3;
  const TC_DES_ISO9797_padding pad2 = TC_DES_ISO9797_PAD2;
  des_iso9797_mac(alg3, pad2, in, in, out);             /* DISCARDED */
  des_iso9797_verify(alg3, pad2, in, in, in);           /* DISCARDED */
  des_iso9797_mac_short_tag(alg3, pad2, in, in, out);   /* DISCARDED */
  des_iso9797_verify_short_tag(alg3, pad2, in, in, in); /* DISCARDED */
  DES_ISO9797 iso9797;
  iso9797.init(TC_DES_ISO9797_ALG1, TC_DES_ISO9797_PAD1, in); /* DISCARDED */
  iso9797.update(in);                                         /* DISCARDED */
  iso9797.finish(des_block);                                  /* DISCARDED */

  SHA256 hash;
  hash.update(in);         /* DISCARDED */
  hash.finish(out);        /* DISCARDED */
  SHA256::digest(in, out); /* DISCARDED */
  HMAC_SHA256 hmac;
  hmac.update(in);               /* DISCARDED */
  hmac.finish(out);              /* DISCARDED */
  HMAC_SHA256::mac(in, in, out); /* DISCARDED */
  uint8_t hmac_tag[HMAC_SHA256::tag_size] = {0};
  HMAC_SHA256::mac(in, in, hmac_tag); /* DISCARDED */

  KMAC256 kmac;
  kmac.update(in);                  /* DISCARDED */
  kmac.final(out);                  /* DISCARDED */
  KMAC256::digest(in, in, in, out); /* DISCARDED */

  AES_dynamic dynamic;
  dynamic.init(in);       /* DISCARDED */
  dynamic.encrypt(block); /* DISCARDED */
  AES_dynamic_CMAC dynamic_cmac;
  dynamic_cmac.init(in);     /* DISCARDED */
  dynamic_cmac.update(in);   /* DISCARDED */
  dynamic_cmac.final(block); /* DISCARDED */
  size_t kw_length = 0;
  aes_kw_wrap(in, in, out);               /* DISCARDED */
  aes_kw_unwrap(in, in, out);             /* DISCARDED */
  aes_kwp_wrap(in, in, out);              /* DISCARDED */
  aes_kwp_unwrap(in, in, out, kw_length); /* DISCARDED */

  /* Generator and secure messaging results. */
  drbg generator;
  generator.generate(out);       /* DISCARDED */
  generator.generate(out, true); /* DISCARDED */
  piv_sm session;
  piv_sm_workspace sm_workspace = {};
  const piv_sm_unprotect_request sm_response = {};
  size_t sm_length = 0;
  session.unprotect(sm_response, out, sm_length, sm_workspace); /* DISCARDED */

  /* Decoder and parser results. */
  GZIPDecoder gzip;
  size_t gzip_work = 0;
  size_t gzip_length = 0;
  const TC_bytes gzip_input = {data, length};
  const TC_buffer gzip_output = {data, length};
  gzip.decode(gzip_input, gzip_work, gzip_output, gzip_length); /* DISCARDED */
  TLVReader reader;
  TC_TLV_limits limits = {};
  TC_TLV_element element = {};
  reader.init(TC_bytes{data, length}, TC_TLV_DER, limits); /* DISCARDED */
  reader.next(element);                                    /* DISCARDED */
  apdu_command command = {in, 0, 0, 0, 0, 0};
  apdu_response response = {};
  size_t apdu_size = 0;
  apdu_command_size(command, TC_APDU_SHORT, apdu_size);        /* DISCARDED */
  apdu_command_encode(command, TC_APDU_SHORT, out, apdu_size); /* DISCARDED */
  apdu_response_read(in, response);                            /* DISCARDED */
  apdu_status_classify(0x9000);                                /* DISCARDED */
  piv_link link;
  piv_application application = {};
  piv_data_object object = {};
  piv_reference_status reference = {};
  const piv_link_options link_options = {};
  link.init(apdu_transport{}, link_options, out);                             /* DISCARDED */
  link.select(TC_PIV_APPLICATION_PIV, 0, out, application);                   /* DISCARDED */
  link.get_data(in, out, object);                                             /* DISCARDED */
  link.verify_status(0x80, reference);                                        /* DISCARDED */
  link.pin_verify(0x80, in, 3, reference);                                    /* DISCARDED */
  link.status();                                                              /* DISCARDED */
  link.info();                                                                /* DISCARDED */
  link.native();                                                              /* DISCARDED */
  piv_application_read(in, TC_PIV_APPLICATION_PIV, 0, application);           /* DISCARDED */
  piv_status_classify(0x9000, TC_PIV_COMMAND_SELECT, TC_PIV_APPLICATION_PIV); /* DISCARDED */
  const uint8_t id[8] = {};
  const TC_random_source rng = {};
  piv_sm_peer peer = {};
  session.native(); /* DISCARDED */
  piv_sm_workspace& w = sm_workspace;
  piv_sm_key_request(link, session, TC_PIV_SM_CS2, id, rng, out, peer, w); /* DISCARDED */
  piv_link_secure(link, sm_workspace, out);                                /* DISCARDED */
  piv_discovery discovery = {};
  piv_vci_mode mode = TC_PIV_VCI_PAIRED;
  piv_discovery_get(link, TC_PIV_DISCOVERY_PIV, out, discovery); /* DISCARDED */
  piv_vci_establish(link, discovery, in, mode);                  /* DISCARDED */
  piv_object objects[1];
  piv_inventory inventory(objects);
  size_t inventory_work = 0;
  inventory.read(link, nullptr, out, inventory_work);        /* DISCARDED */
  inventory.find(0x3000);                                    /* DISCARDED */
  piv_catalog_count(TC_PIV_APPLICATION_PIV, TC_PIV_CARD);    /* DISCARDED */
  piv_catalog_at(TC_PIV_APPLICATION_PIV, TC_PIV_CARD, 0);    /* DISCARDED */
  piv_catalog_find(TC_PIV_APPLICATION_PIV, TC_PIV_CARD, in); /* DISCARDED */
  const TC_X509_certificate certificate = {};
  const TC_X509_signature_provider provider = {};
  piv_key_parameters parameters = {};
  piv_key_proof_request proof = {};
  static piv_key_proof_workspace proof_workspace;
  TC_work_budget proof_work = {0};
  piv_key_parameters_select(certificate, proof.policy, parameters);       /* DISCARDED */
  piv_key_prove(link, proof, rng, provider, proof_workspace, proof_work); /* DISCARDED */
  static piv_card_report report;
  static piv_card_check_workspace check_workspace;
  const piv_card_check_request check = {};
  const piv_check_requirement required[] = {{TC_PIV_CHECK_CHUID, 0, 0}};
  const piv_card_proof_request keys = {};
  size_t check_work = 0;
  piv_card_check(check, check_workspace, check_work, report);           /* DISCARDED */
  piv_card_report_find(report, required[0]);                            /* DISCARDED */
  piv_card_report_accepts(report, required);                            /* DISCARDED */
  piv_card_prove_keys(link, keys, proof_workspace, proof_work, report); /* DISCARDED */

  /* Clearing stays unmarked. */
  aes.clear();
  gcm.clear();
  aes_mac.clear();
  des.clear();
  des_mac.clear();
  iso9797.clear();
  kmac.clear();
  dynamic.clear();
  generator.uninstantiate();
  session.clear();
  piv_link_unsecure(link);
  link.clear();
}
