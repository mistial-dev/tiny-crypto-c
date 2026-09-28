/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TINY_CRYPTO_X509_TRUST_ANCHOR_H_
#define TINY_CRYPTO_X509_TRUST_ANCHOR_H_
#include <tiny_crypto/x509_store.h>
#ifdef __cplusplus
extern "C" {
#endif

/* RFC 5914 TrustAnchorList. The reader and decoded records borrow the DER.
 * Keep it unchanged through validation. Frames and extension OID scratch are
 * caller-owned via workspace.
 * Disabled CHOICE variants return UNSUPPORTED from next. */
TC_TLV_result TC_X509_trust_anchor_list_init(TC_TLV_reader* reader, const uint8_t* data,
                                             size_t length, const TC_TLV_limits* limits,
                                             TC_X509_workspace* workspace);
/* One choice at a time. A TrustAnchorInfo lacking certPath is returned with
 * x509_unusable=1. Its public key remains available for non-path purposes.
 * On END or error, reader and out remain unchanged. */
TC_TLV_result TC_X509_trust_anchor_next(TC_TLV_reader* reader, const TC_TLV_limits* limits,
                                        TC_X509_workspace* workspace, TC_X509_store_anchor* out);

#ifdef __cplusplus
}
#endif
#endif
