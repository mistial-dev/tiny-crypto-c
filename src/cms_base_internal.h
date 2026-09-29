/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_CMS_BASE_INTERNAL_H_
#define TC_CMS_BASE_INTERNAL_H_
#include <tiny_crypto/cms.h>
#include "hash_dispatch_internal.h"
#include "pki_tree_internal.h"

typedef enum {
  TC_CMS_CERT_X509,
  TC_CMS_CERT_EXTENDED,
  TC_CMS_CERT_ATTRIBUTE_V1,
  TC_CMS_CERT_ATTRIBUTE_V2,
  TC_CMS_CERT_OTHER
} tc_cms_certificate_kind;
enum { TC_CMS_SIGNER_SPAN_COUNT = 11 };

TC_TLV_result tc_cms_digest_algorithms(TC_bytes encoded, const TC_DER_algorithm* required,
                                       const TC_TLV_limits* limits,
                                       const tc_pki_tree_workspace* tree, TC_hash_algorithm* out);
TC_TLV_result tc_cms_signed_data_read(TC_bytes encoded, const TC_TLV_limits* limits,
                                      TC_TLV_frames frames, size_t* work, TC_CMS_signed_data* out);
TC_TLV_result tc_cms_signed_data_version_check(const TC_CMS_signed_data* input,
                                               const TC_TLV_limits* limits,
                                               const tc_pki_tree_workspace* tree);
TC_TLV_result tc_cms_signer_info_read(TC_bytes encoded, TC_TLV_profile profile,
                                      const TC_TLV_limits* limits, TC_TLV_frames frames,
                                      size_t* work, TC_CMS_signer_info* out);

typedef enum { TC_CMS_VERIFY_DIGEST, TC_CMS_VERIFY_RAW, TC_CMS_VERIFY_BER } tc_cms_verify_input;

/* Valid only during one signer search; signer_name borrows the signed input. */
typedef struct {
  uint8_t* digest;
  size_t capacity;
  size_t digest_length;
  TC_hash_algorithm hash;
  TC_bytes signer_name;
  int valid;
} tc_cms_signed_attrs_cache;

/* Shared with the optional path and revocation layer. */
void tc_cms_signer_spans(const TC_CMS_signer_info* signer, TC_bytes* spans);
TC_TLV_result tc_cms_hash_content(TC_bytes input, TC_CMS_content_encoding encoding,
                                  TC_hash_algorithm algorithm, const TC_TLV_limits* limits,
                                  const tc_pki_tree_workspace* tree, TC_hash_context* scratch,
                                  uint8_t* digest);
TC_X509_signature_result
tc_cms_signer_verify(const TC_CMS_signer_info* signer, TC_bytes content_type, TC_bytes input,
                     tc_cms_verify_input input_kind, TC_CMS_verification_policy policy,
                     const TC_X509_public_key* key, const TC_X509_signature_provider* provider,
                     const TC_TLV_limits* limits, const TC_CMS_signature_workspace* workspace,
                     size_t* work, TC_bytes* signer_name);
TC_X509_signature_result
tc_cms_signer_verify_cached(const TC_CMS_signer_info* signer, TC_bytes content_type, TC_bytes input,
                            tc_cms_verify_input input_kind, TC_CMS_verification_policy policy,
                            const TC_X509_public_key* key,
                            const TC_X509_signature_provider* provider, const TC_TLV_limits* limits,
                            const TC_CMS_signature_workspace* workspace, size_t* work,
                            TC_bytes* signer_name, tc_cms_signed_attrs_cache* cache);
TC_TLV_result tc_cms_signed_data_check(const TC_CMS_signed_data* input, const TC_TLV_limits* limits,
                                       const tc_pki_tree_workspace* tree, size_t signer_index,
                                       TC_CMS_signer_info* selected);
TC_TLV_result tc_cms_classify_certificate(const TC_TLV_element* element,
                                          tc_cms_certificate_kind* out);

#endif
