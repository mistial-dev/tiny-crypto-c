/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* TWIC printed information rules (TWIC Part 2 v5 section 4.7.2). */
#include <tiny_crypto/common.h>
#if TC_ENABLE_TWIC && TC_ENABLE_PIV_OBJECTS
#include "twic_card_objects_internal.h"
#include "credential_text_internal.h"
#include <string.h>

enum { PRINTED_SERIAL_LENGTH = 8, PRINTED_ISSUER_LENGTH = 8, PRINTED_CONTENTS_MAX = 200 };

static int printed_date(TC_bytes value, TC_X509_time* out)
{
  return tc_credential_day_month_year(value.data, 0, out);
}

static int printed_serial(TC_bytes value)
{
  return value.length == PRINTED_SERIAL_LENGTH && tc_credential_digits(value.data, value.length);
}

static int printed_issuer(TC_bytes value)
{
  static const uint8_t prefix[] = {'7', '0', '9', '9'};
  return value.length == PRINTED_ISSUER_LENGTH && tc_credential_digits(value.data, value.length) &&
         !memcmp(value.data, prefix, sizeof prefix);
}

const tc_piv_printed_rules tc_twic_printed_rules = {
    PRINTED_CONTENTS_MAX, printed_date, printed_serial, printed_issuer, 1, 0};
#endif
