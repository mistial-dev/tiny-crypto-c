/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* TWIC key rules for the key proofs. */
#include <tiny_crypto/piv_key_proof.h>
#if TC_ENABLE_TWIC && TC_ENABLE_PIV_KEY_PROOF
#include "twic_key_policy_internal.h"

const tc_piv_key_profile_rules* tc_twic_key_profile_rules(TC_PIV_card_profile profile)
{
  /* Legacy readers may accept RSA-1024 by explicit policy (Appendix H). The
   * NEXGEN card authentication key is 9E07 (4.5 and 5.3). Neither profile
   * has the SP 800-78-5 RSA-2048 end date. */
  static const tc_piv_key_profile_rules legacy = {1, 0, 0},
                                        nexgen = {0, 0, TC_PIV_ALGORITHM_RSA_2048};
  if (profile == TC_TWIC_LEGACY_CARD)
    return &legacy;
  if (profile == TC_TWIC_NEXGEN_CARD)
    return &nexgen;
  return NULL;
}

TC_PIV_result tc_twic_proof_allowed(const TC_PIV_link* link, uint8_t key_reference,
                                    TC_PIV_card_profile profile)
{
  /* The TWIC application offers 9E only (5.3 syntax table, TWIC Part 3 v4
   * 4.4.4) and proves under the profile of its SELECT. */
  if (key_reference != TC_PIV_KEY_CARD_AUTHENTICATION || profile != link->profile)
    return TC_PIV_ARGUMENT;
  /* GENERAL AUTHENTICATE is a NEXGEN command of the TWIC application. A
   * Legacy card proves 9E on its PIV application. */
  return link->profile == TC_TWIC_NEXGEN_CARD ? TC_PIV_OK : TC_PIV_UNSUPPORTED;
}
#endif
