/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_X509_OCSP_INTERNAL_H_
#define TC_X509_OCSP_INTERNAL_H_
#include <tiny_crypto/x509_ocsp.h>
#include <tiny_crypto/x509_store.h>

/* The validated certification path above an OCSP issuer: the selected anchor
 * with its CertPathControls and the certificates from the anchor-issued one
 * down to the issuer, anchor-issued first. count is zero when the anchor is
 * the issuer. path is scratch for count + 1 spans, disjoint from the
 * validation workspace and the inputs. */
typedef struct {
  const TC_X509_store_anchor* anchor;
  const TC_bytes* issuers;
  size_t count;
  TC_bytes* path;
  size_t path_capacity;
} tc_x509_ocsp_issuer_path;

#if TC_ENABLE_X509_OCSP
/* TC_X509_ocsp_response_verify with each delegate validated as issuers
 * followed by the delegate under anchor, so the anchor's path controls and
 * the upstream constraints apply (RFC 5937 section 3.1, RFC 5914 section
 * 2.5). request->issuer holds the name and key of the last issuer. A path
 * scratch below count + 1 spans makes a delegate check return LIMIT. */
TC_TLV_result tc_x509_ocsp_response_verify_path(const TC_X509_ocsp_verify_request* request,
                                                const tc_x509_ocsp_issuer_path* above,
                                                const TC_X509_path_workspace* workspace,
                                                size_t* work, TC_X509_ocsp_report* out);
#endif
#endif
