/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* TWIC facial image and certificate container rules. */
#include <tiny_crypto/common.h>
#if TC_ENABLE_TWIC && TC_ENABLE_PIV_OBJECTS
#include "twic_card_objects_internal.h"

/* TWIC credentials carry Basic face records: any expression or image type
 * up to the PIV values, and any nonzero width. */
const tc_piv_face_rules tc_twic_face_rules = {0, 0, 1};

/* TWIC Part 2 v5 4.7.1 lists 70 and 71 and calls the structure similar to
 * the PIV one without the MSCUID. NEXGEN cards end it with the empty FE of
 * the PIV form. */
const tc_piv_certificate_rules tc_twic_certificate_rules = {0, 0, 1};
#endif
