/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* The PIV application identifier shared by SELECT, the application property
 * template reader and the Discovery Object reader. */
#ifndef TC_PIV_AID_INTERNAL_H_
#define TC_PIV_AID_INTERNAL_H_
#include <tiny_crypto/common.h>

/* A complete AID is the 9-byte prefix followed by two version bytes. */
#define TC_PIV_AID_PREFIX_BYTES 9u
#define TC_PIV_AID_BYTES (TC_PIV_AID_PREFIX_BYTES + 2u)

/* First version byte of the PIV (01 00) and TWIC (01 xx) AIDs. */
enum { TC_PIV_AID_VERSION = 0x01 };

/* The complete PIV AID with version 01 00 (SP 800-73-5 Part 1 section 2.2).
 * Its first TC_PIV_AID_PREFIX_BYTES bytes are the PIV AID prefix. */
extern const uint8_t tc_piv_aid[TC_PIV_AID_BYTES];
#endif
