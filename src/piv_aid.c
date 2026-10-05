/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* The PIV application identifier. */
#include <tiny_crypto/common.h>
#if TC_ENABLE_PIV_COMMAND || TC_ENABLE_PIV_OBJECTS
#include "piv_aid_internal.h"

const uint8_t tc_piv_aid[TC_PIV_AID_BYTES] = {0xa0, 0x00, 0x00, 0x03, 0x08, 0x00,
                                              0x00, 0x10, 0x00, 0x01, 0x00};
#endif
