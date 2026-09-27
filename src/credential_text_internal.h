/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_CREDENTIAL_TEXT_INTERNAL_H_
#define TC_CREDENTIAL_TEXT_INTERNAL_H_

#include <stdint.h>
#include <stddef.h>

int tc_credential_hex_digit(uint8_t value);

/* title_case selects Jan rather than JAN. Both formats require exact case. */
unsigned tc_credential_month3(const uint8_t value[3], int title_case);

/* Parse a full Gregorian YYYYMMDD date. Output pointers may be null. */
int tc_credential_yyyymmdd(const uint8_t* value, size_t length,
    unsigned* year, unsigned* month, unsigned* day);

#endif
