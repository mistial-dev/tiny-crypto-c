/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* RFC 5914 TrustAnchorList reader.
 * Standards: RFC 5914, RFC 5937.
 * Configuration: TC_ENABLE_TRUST_ANCHOR_FORMAT and the TC_TAF_ENABLE_*
 * choices.
 * Contracts: docs/api.md. Guide: docs/x509-trust-anchors.md. */
#ifndef TINY_CRYPTO_X509_TRUST_ANCHOR_H_
#define TINY_CRYPTO_X509_TRUST_ANCHOR_H_
#include <tiny_crypto/x509_store.h>
#ifdef __cplusplus
extern "C" {
#endif

/* RFC 5914 TrustAnchorList reader. init binds the list, limits and workspace.
 * Treat members as private after init. The reader and decoded records borrow
 * the DER. Keep it unchanged through validation. The caller owns the
 * workspace frames and extension OID scratch. Keep them alive and exclusive
 * to this reader until the last next call. */
typedef struct {
  TC_TLV_reader reader;
  TC_X509_workspace* workspace;
} TC_X509_trust_anchor_reader;

/* init walks the complete list under limits, so every anchor fits them.
 * limits also apply to each anchor that next decodes. frames need one entry
 * per constructed nesting level of the list. The reader, the frames and the
 * extension OID array are written, so they must be pairwise disjoint and lie
 * outside encoded and the workspace struct.
 * Returns ARGUMENT for NULL arguments, a workspace array that is NULL with a
 * capacity, or overlap, INVALID for a malformed or empty list, and LIMIT when
 * limits or frames are exhausted. reader changes only on OK. */
TC_TLV_result TC_X509_trust_anchor_list_init(TC_X509_trust_anchor_reader* reader, TC_bytes encoded,
                                             const TC_TLV_limits* limits,
                                             TC_X509_workspace* workspace);
/* One choice at a time. A TrustAnchorInfo lacking certPath is returned with
 * x509_unusable=1. Its public key remains available for non-path purposes.
 * Disabled CHOICE variants and unsupported versions return UNSUPPORTED.
 * out must lie outside the list, the reader, the workspace struct and both
 * workspace arrays. Returns ARGUMENT for a NULL argument or overlap.
 * Workspace scratch may change on failure. On END or error, reader and out
 * remain unchanged. */
TC_TLV_result TC_X509_trust_anchor_next(TC_X509_trust_anchor_reader* reader,
                                        TC_X509_store_anchor* out);

#ifdef __cplusplus
}
#endif
#endif
