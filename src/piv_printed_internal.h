/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Field rules of a printed-information profile for TC_PIV_printed_read. */
#ifndef TC_PIV_PRINTED_INTERNAL_H_
#define TC_PIV_PRINTED_INTERNAL_H_
#include <tiny_crypto/piv_printed.h>

#if TC_ENABLE_PIV_OBJECTS
/* contents_max     largest object contents, or SIZE_MAX. Larger is LIMIT.
 * date             reads the 9-byte expiration text.
 * serial, issuer   accept the card serial number and issuer identification.
 * organizations    1 when both organization affiliation lines are present.
 * error_detection  1 when an empty FE ends the object. */
typedef struct {
  size_t contents_max;
  int (*date)(TC_bytes value, TC_X509_time* out);
  int (*serial)(TC_bytes value);
  int (*issuer)(TC_bytes value);
  uint8_t organizations;
  uint8_t error_detection;
} tc_piv_printed_rules;

/* 1 when every byte is printable ASCII, the value holds at most maximum
 * bytes, and empty values are allowed when empty is 1. */
int tc_piv_printed_text(TC_bytes value, size_t maximum, int empty);
#endif
#endif
