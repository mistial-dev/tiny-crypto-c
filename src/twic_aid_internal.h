/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* The TWIC card application identifier (TWIC Part 2 v5 section 4.1 and
 * Appendix C) for SELECT and the Discovery Object reader. */
#ifndef TC_TWIC_AID_INTERNAL_H_
#define TC_TWIC_AID_INTERNAL_H_
#include "piv_aid_internal.h"

#if TC_ENABLE_TWIC
/* The 9-byte TWIC AID prefix. tests/twic/apdu_replay.py and the capture
 * tools mirror it. */
extern const uint8_t tc_twic_aid_prefix[TC_PIV_AID_PREFIX_BYTES];

/* 1 when aid is a complete TWIC AID with version 01 and the Legacy or NEXGEN
 * sub-version. */
int tc_twic_aid_known(TC_bytes aid);

#if TC_ENABLE_PIV_COMMAND
#include <tiny_crypto/piv_command.h>
#include <tiny_crypto/tlv.h>
/* Card profile from the second version byte: 03 is NEXGEN and 01 is Legacy.
 * TC_PIV_SELECT_TWIC_SUBVERSION_COMPATIBLE in flags reads any other
 * sub-version as Legacy (TWIC Part 3 v4 Appendix D.3). Otherwise it is
 * UNSUPPORTED. */
TC_TLV_result tc_twic_aid_profile(uint8_t subversion, unsigned flags, TC_PIV_card_profile* out);
#endif
#endif
#endif
