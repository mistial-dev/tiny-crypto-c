/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* TWIC Discovery Object PIN policies. */
#include <tiny_crypto/piv_discovery.h>
#if TC_ENABLE_TWIC && TC_ENABLE_PIV_OBJECTS
#include "twic_card_objects_internal.h"
#include "twic_aid_internal.h"
#include <string.h>

int tc_twic_discovery_accept(TC_bytes aid, uint8_t policy, uint8_t preference)
{
  const int piv = aid.length == TC_PIV_AID_BYTES && !memcmp(aid.data, tc_piv_aid, TC_PIV_AID_BYTES);
  return (piv || tc_twic_aid_known(aid)) && preference == 0 &&
         (policy == TC_PIV_POLICY_PIV_PIN || policy == TC_PIV_POLICY_VCI_WITHOUT_PAIRING ||
          policy == 0);
}
#endif
