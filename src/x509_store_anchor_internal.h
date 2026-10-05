/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_X509_STORE_ANCHOR_INTERNAL_H_
#define TC_X509_STORE_ANCHOR_INTERNAL_H_
#include <tiny_crypto/x509_store.h>
#include "pki_extensions_internal.h"

/* Anchor record decoding shared by TC_X509_store_anchor_from_certificate and
 * the RFC 5914 TrustAnchorList reader. Every span borrows the input DER.
 * The extension OID scratch and frames come from workspace. */

/* The CertPathControls field (TC_X509_ANCHOR_REPLACED_*) that replaces the
 * certificate extension with 2.5.29 arc id, or 0 (RFC 5914 section 2.5). */
static inline unsigned tc_x509_anchor_path_control(unsigned id)
{
  switch (id) {
  case TC_PKI_EXT_CERTIFICATE_POLICIES:
    return TC_X509_ANCHOR_REPLACED_POLICY_SET;
  case TC_PKI_EXT_POLICY_CONSTRAINTS:
  case TC_PKI_EXT_INHIBIT_ANY_POLICY:
    return TC_X509_ANCHOR_REPLACED_POLICY_FLAGS;
  case TC_PKI_EXT_NAME_CONSTRAINTS:
    return TC_X509_ANCHOR_REPLACED_NAMES;
  case TC_PKI_EXT_BASIC_CONSTRAINTS:
    return TC_X509_ANCHOR_REPLACED_PATH_LEN;
  default:
    return 0;
  }
}

/* RFC 5914 section 2.6: TrustAnchorInfo exts duplicates of the policy and
 * name controls are ignored. A basicConstraints pathLen there still bounds
 * path_len. */
static inline int tc_x509_anchor_exts_ignored(unsigned id)
{
  const unsigned control = tc_x509_anchor_path_control(id);
  return control && control != TC_X509_ANCHOR_REPLACED_PATH_LEN;
}

/* CertificatePolicies contents with unique identifiers. RFC 5914 section 2.5
 * forbids policyQualifiers in a TrustAnchorInfo policySet. An anchor
 * certificate's extension may carry them. */
TC_TLV_result tc_x509_anchor_policy_set(TC_bytes contents, const TC_TLV_limits* limits,
                                        const TC_X509_workspace* workspace, int qualifiers_allowed);
/* Walk every GeneralSubtree of both lists. A NULL list is absent. */
TC_TLV_result tc_x509_anchor_subtrees(const TC_X509_name_constraints* names,
                                      const TC_TLV_limits* limits,
                                      const TC_X509_workspace* workspace);
/* Decode an Extensions SEQUENCE into out's path-control fields. With
 * trust_anchor_info set, the list is TrustAnchorInfo exts, where RFC 5914
 * section 2.6 ignores the CertPathControls duplicates. */
TC_TLV_result tc_x509_anchor_extensions(TC_bytes encoded, const TC_TLV_limits* limits,
                                        const TC_X509_workspace* workspace, int trust_anchor_info,
                                        TC_X509_store_anchor* out);
/* Anchor fields from a parsed Certificate or TBSCertificate, without the
 * argument and storage checks of the public builder. out is partly written
 * on failure. */
TC_TLV_result tc_x509_anchor_certificate(const TC_X509_certificate* certificate,
                                         const TC_TLV_limits* limits,
                                         const TC_X509_workspace* workspace,
                                         TC_X509_store_anchor* out);
#endif
