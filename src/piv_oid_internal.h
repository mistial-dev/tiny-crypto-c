/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TC_PIV_OID_INTERNAL_H_
#define TC_PIV_OID_INTERNAL_H_
#include <tiny_crypto/piv_oid.h>

/* Borrow the encoded PIV OID contents for id, excluding the ASN.1 tag and
 * length. The span has static storage, so callers may keep the pointer, for
 * example as a one-element initial policy set. Returns NULL for UNKNOWN, an
 * unlisted id, or an id without a PIV identifier. tc_twic_oid_contents in
 * twic_oid_internal.h gives the TWIC pair. */
const TC_bytes* tc_piv_oid_contents(TC_PIV_oid id);

#endif
