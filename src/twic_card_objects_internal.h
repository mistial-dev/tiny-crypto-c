/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* TWIC rules for the PIV object readers (TWIC Part 2 v5). */
#ifndef TC_TWIC_CARD_OBJECTS_INTERNAL_H_
#define TC_TWIC_CARD_OBJECTS_INTERNAL_H_
#include <tiny_crypto/common.h>
#include "piv_printed_internal.h"

#if TC_ENABLE_TWIC && TC_ENABLE_PIV_OBJECTS
/* 1 when a Discovery Object on a TWIC card names the PIV or TWIC AID and
 * carries a TWIC PIN usage policy: 40 00 (section 4.2), or 04 00 in the PIV
 * application and 00 00 in the TWIC application (section 4.7.5). */
int tc_twic_discovery_accept(TC_bytes aid, uint8_t policy, uint8_t preference);

/* TWIC printed information (section 4.7.2): DDMMMYYYY expiration, an
 * 8-digit serial number, an 8-digit issuer starting 7099, both organization
 * lines, no FE, and at most 200 content bytes. */
extern const tc_piv_printed_rules tc_twic_printed_rules;
#endif
#endif
