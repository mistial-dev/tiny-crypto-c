/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_CREDENTIAL_STATUS_INTERNAL_H_
#define TC_CREDENTIAL_STATUS_INTERNAL_H_

#include <tiny_crypto/x509.h>

typedef struct {
  TC_credential_status on_ok;
  TC_credential_status on_unmapped;
} tc_credential_tlv_policy;

/* Validation accepts OK. CMS calls this mapper only for errors. */
static const tc_credential_tlv_policy tc_credential_tlv_validation = {TC_CREDENTIAL_VALID,
                                                                      TC_CREDENTIAL_INVALID};
static const tc_credential_tlv_policy tc_credential_tlv_cms = {TC_CREDENTIAL_ERROR,
                                                               TC_CREDENTIAL_ERROR};

static inline TC_credential_status tc_credential_tlv_status(TC_TLV_result result,
                                                            const tc_credential_tlv_policy* policy)
{
  switch (result) {
  case TC_TLV_OK:
    return policy->on_ok;
  case TC_TLV_INVALID:
    return TC_CREDENTIAL_INVALID;
  case TC_TLV_LIMIT:
    return TC_CREDENTIAL_LIMIT;
  case TC_TLV_UNSUPPORTED:
    return TC_CREDENTIAL_UNSUPPORTED;
  case TC_TLV_ARGUMENT:
    return TC_CREDENTIAL_ERROR;
  default:
    return policy->on_unmapped;
  }
}

static inline TC_credential_status tc_credential_signature_status(TC_X509_signature_result result)
{
  switch (result) {
  case TC_X509_SIGNATURE_VALID:
    return TC_CREDENTIAL_VALID;
  case TC_X509_SIGNATURE_INVALID:
    return TC_CREDENTIAL_INVALID;
  case TC_X509_SIGNATURE_LIMIT:
    return TC_CREDENTIAL_LIMIT;
  case TC_X509_SIGNATURE_UNSUPPORTED:
    return TC_CREDENTIAL_UNSUPPORTED;
  default:
    return TC_CREDENTIAL_ERROR;
  }
}

#endif
