/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* The TWIC card profiles (TWIC Part 2 v5 section 4.1). */
#ifndef TC_TWIC_PROFILE_INTERNAL_H_
#define TC_TWIC_PROFILE_INTERNAL_H_
#include <tiny_crypto/piv_card.h>

#if TC_ENABLE_TWIC
/* 1 for the TWIC Legacy and NEXGEN card profiles. */
static inline int tc_twic_card_profile(TC_PIV_card_profile profile)
{
  return profile == TC_TWIC_LEGACY_CARD || profile == TC_TWIC_NEXGEN_CARD;
}
#endif
#endif
