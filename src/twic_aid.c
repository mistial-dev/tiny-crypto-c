/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* The TWIC card application identifier. */
#include <tiny_crypto/common.h>
#if TC_ENABLE_TWIC && (TC_ENABLE_PIV_COMMAND || TC_ENABLE_PIV_OBJECTS)
#include "twic_aid_internal.h"
#include <string.h>

enum { SUBVERSION_LEGACY = 0x01, SUBVERSION_NEXGEN = 0x03 };

const uint8_t tc_twic_aid_prefix[TC_PIV_AID_PREFIX_BYTES] = {0xa0, 0x00, 0x00, 0x03, 0x67,
                                                             0x20, 0x00, 0x00, 0x01};

int tc_twic_aid_known(TC_bytes aid)
{
  if (aid.length != TC_PIV_AID_BYTES ||
      memcmp(aid.data, tc_twic_aid_prefix, TC_PIV_AID_PREFIX_BYTES) != 0)
    return 0;
  const uint8_t* version = aid.data + TC_PIV_AID_PREFIX_BYTES;
  return version[0] == TC_PIV_AID_VERSION &&
         (version[1] == SUBVERSION_LEGACY || version[1] == SUBVERSION_NEXGEN);
}

#if TC_ENABLE_PIV_COMMAND
TC_TLV_result tc_twic_aid_profile(uint8_t subversion, unsigned flags, TC_PIV_card_profile* out)
{
  if (subversion == SUBVERSION_NEXGEN)
    *out = TC_TWIC_NEXGEN_CARD;
  else if (subversion == SUBVERSION_LEGACY || (flags & TC_PIV_SELECT_TWIC_SUBVERSION_COMPATIBLE))
    *out = TC_TWIC_LEGACY_CARD;
  else
    return TC_TLV_UNSUPPORTED;
  return TC_TLV_OK;
}
#endif
#endif
