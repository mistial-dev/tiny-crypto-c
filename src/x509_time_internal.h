/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_X509_TIME_INTERNAL_H_
#define TC_X509_TIME_INTERNAL_H_
#include <tiny_crypto/x509.h>
/* A framed UTC/GeneralizedTime element. Calendar output changes only on OK. */
TC_TLV_result tc_x509_time_value(const TC_TLV_element* element, TC_X509_time* out);
/* within receives 1 when not_before - skew <= at <= not_after + skew. Every
 * time must be valid and not_before must not follow not_after, otherwise the
 * result is INVALID. within changes only on OK. */
TC_TLV_result tc_x509_time_window(const TC_X509_time* at, uint32_t skew_seconds,
                                  const TC_X509_time* not_before, const TC_X509_time* not_after,
                                  int* within);
#endif
