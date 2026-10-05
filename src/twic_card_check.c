/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* TWIC rules of the composed card check. */
#include <tiny_crypto/piv_card_check.h>
#if TC_ENABLE_TWIC && TC_ENABLE_PIV_CARD_CHECK
#include "twic_card_check_internal.h"
#include "twic_profile_internal.h"

int tc_twic_check_profile_fits(TC_PIV_card_profile profile, const TC_PIV_inventory* inventory)
{
  if (!tc_twic_card_profile(profile))
    return 0;
  if (inventory->link.application == TC_PIV_APPLICATION_TWIC)
    return profile == inventory->link.profile;
  return inventory->link.application == TC_PIV_APPLICATION_PIV;
}

TC_TLV_result tc_twic_card_chuid_profile(TC_PIV_application_id application,
                                         TC_PIV_card_profile profile, TC_PIV_CHUID_profile* out)
{
  if (!tc_twic_card_profile(profile))
    return TC_TLV_ARGUMENT;
  if (application == TC_PIV_APPLICATION_PIV)
    *out = TC_CHUID_PROFILE_PIV_SP800_73_4;
  else if (application == TC_PIV_APPLICATION_TWIC)
    *out = TC_CHUID_PROFILE_TWIC_SIGNED;
  else
    return TC_TLV_ARGUMENT;
  return TC_TLV_OK;
}

TC_TLV_result tc_twic_certificate_identifiers_read(TC_bytes subject_alt_name,
                                                   const TC_PIV_card_certificate_request* request,
                                                   const TC_TLV_limits* limits,
                                                   TC_TLV_frames frames, size_t* work,
                                                   TC_PIV_card_identifiers* out)
{
  if (request->key_reference == TC_PIV_KEY_PIV_AUTHENTICATION)
    return TC_TWIC_authentication_identifiers_read(subject_alt_name, request->card_guid, limits,
                                                   frames, work, out);
  return TC_TWIC_card_identifiers_read(subject_alt_name, request->profile, limits, frames, work,
                                       out);
}
#endif
