/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* TWIC rules of the composed card check (TWIC Part 2 v5). */
#ifndef TC_TWIC_CARD_CHECK_INTERNAL_H_
#define TC_TWIC_CARD_CHECK_INTERNAL_H_
#include <tiny_crypto/piv_card_check.h>

/* 1 for the TWIC card application, and 0 in builds without TWIC support, so
 * TWIC application rules compile out of PIV-only builds. */
static inline int tc_twic_application(unsigned application)
{
#if TC_ENABLE_TWIC
  return application == TC_PIV_APPLICATION_TWIC;
#else
  (void)application;
  return 0;
#endif
}

#if TC_ENABLE_TWIC && TC_ENABLE_PIV_CARD_CHECK
/* A TWIC credential profile fits the inventory: the TWIC application keeps
 * its SELECT profile, and the PIV application of a TWIC card takes either
 * TWIC profile. 0 for another profile. */
int tc_twic_check_profile_fits(TC_PIV_card_profile profile, const TC_PIV_inventory* inventory);

/* TC_PIV_card_chuid_profile for a TWIC profile: the SP 800-73-4 form on the
 * PIV application, which keeps the SP 800-73-2 key map, and the signed TWIC
 * form on the TWIC application. ARGUMENT otherwise. */
TC_TLV_result tc_twic_card_chuid_profile(TC_PIV_application_id application,
                                         TC_PIV_card_profile profile, TC_PIV_CHUID_profile* out);

/* Certificate identifiers under the TWIC reader policy: the PIV
 * Authentication certificate of a TWIC card, or a TWIC Card Authentication
 * certificate. Arguments as TC_PIV_card_certificate_validate checks them. */
TC_TLV_result tc_twic_certificate_identifiers_read(TC_bytes subject_alt_name,
                                                   const TC_PIV_card_certificate_request* request,
                                                   const TC_TLV_limits* limits,
                                                   TC_TLV_frames frames, size_t* work,
                                                   TC_PIV_card_identifiers* out);
#endif
#endif
