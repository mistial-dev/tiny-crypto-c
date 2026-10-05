/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_PIV_DISCOVERY_INTERNAL_H_
#define TC_PIV_DISCOVERY_INTERNAL_H_
#include <tiny_crypto/piv_discovery.h>

#if TC_ENABLE_PIV_OBJECTS
/* 1 for the PIV Discovery profile, and for the TWIC one in builds with TWIC
 * support. */
int tc_piv_discovery_profile_known(TC_PIV_discovery_profile profile);
#endif
#endif
