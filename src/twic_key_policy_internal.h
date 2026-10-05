/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* TWIC key rules for the key proofs (TWIC Part 2 v5 4.5, 5.3 and Appendix H). */
#ifndef TC_TWIC_KEY_POLICY_INTERNAL_H_
#define TC_TWIC_KEY_POLICY_INTERNAL_H_
#include "piv_key_proof_internal.h"
#include "piv_link_internal.h"

#if TC_ENABLE_TWIC && TC_ENABLE_PIV_KEY_PROOF
/* Key rules of a TWIC profile, or NULL for another profile. */
const tc_piv_key_profile_rules* tc_twic_key_profile_rules(TC_PIV_card_profile profile);

/* Proof rules of the TWIC application: key 9E only, under the profile of its
 * SELECT (ARGUMENT otherwise), and on NEXGEN cards only (UNSUPPORTED). */
TC_PIV_result tc_twic_proof_allowed(const TC_PIV_link* link, uint8_t key_reference,
                                    TC_PIV_card_profile profile);
#endif
#endif
