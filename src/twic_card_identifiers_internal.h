/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* TWIC card identifier rules (TWIC Part 2 v5 section 6, Part 3 4.4.4). */
#ifndef TC_TWIC_CARD_IDENTIFIERS_INTERNAL_H_
#define TC_TWIC_CARD_IDENTIFIERS_INTERNAL_H_
#include "piv_identifiers_internal.h"

#if TC_ENABLE_TWIC && TC_ENABLE_PIV_OBJECTS
/* Card Authentication rules of a TWIC profile. Legacy requires the nil UUID,
 * which may be absent. NEXGEN requires a UUID that encodes the FASC-N, and
 * reader_policy allows it to be absent. Returns 0 for another profile. */
int tc_twic_identifier_rules(TC_PIV_card_profile profile, int reader_policy,
                             tc_piv_identifier_rules* out);
#endif
#endif
