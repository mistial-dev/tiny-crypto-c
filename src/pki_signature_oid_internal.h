/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_PKI_SIGNATURE_OID_INTERNAL_H_
#define TC_PKI_SIGNATURE_OID_INTERNAL_H_
#include <tiny_crypto/x509.h>

typedef enum {
  TC_PKI_SIGNATURE_UNKNOWN,
  TC_PKI_SIGNATURE_RSA_V15,
  TC_PKI_SIGNATURE_RSA_PSS,
  TC_PKI_SIGNATURE_ECDSA,
  TC_PKI_SIGNATURE_DSA,
  TC_PKI_SIGNATURE_ED25519,
  TC_PKI_SIGNATURE_ED448
} tc_pki_signature_kind;

typedef struct {
  tc_pki_signature_kind kind;
  TC_hash_algorithm hash;
} tc_pki_signature_oid_info;

/* Unknown OIDs remain available to external signature providers. */
tc_pki_signature_oid_info tc_pki_signature_oid_classify(TC_bytes oid);
#endif
