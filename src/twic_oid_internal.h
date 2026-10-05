/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* TWIC identifiers paired with PIV identifiers (TWIC Part 2 v5 section 6). */
#ifndef TC_TWIC_OID_INTERNAL_H_
#define TC_TWIC_OID_INTERNAL_H_
#include <tiny_crypto/piv_oid.h>

#if TC_ENABLE_TWIC && TC_ENABLE_PIV_OIDS
/* The PIV identifier whose TWIC pair is oid, or TC_PIV_OID_UNKNOWN. */
TC_PIV_oid tc_twic_oid_identify(TC_bytes oid);
/* Borrow the encoded TWIC OID contents paired with id, excluding the ASN.1
 * tag and length. The span has static storage. NULL when section 6 gives id
 * no TWIC identifier. */
const TC_bytes* tc_twic_oid_contents(TC_PIV_oid id);
#endif
#endif
