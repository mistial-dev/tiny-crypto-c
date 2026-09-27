/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_PKI_BUDGET_INTERNAL_H_
#define TC_PKI_BUDGET_INTERNAL_H_

#include <tiny_crypto/tlv.h>

static inline TC_TLV_result tc_pki_work_charge(size_t* work, size_t amount)
{
  if (amount > *work) {
    *work = 0;
    return TC_TLV_LIMIT;
  }
  *work -= amount;
  return TC_TLV_OK;
}

#endif
