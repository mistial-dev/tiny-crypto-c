/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Card Holder Unique Identifier reader for the PIV, signed and unsigned TWIC,
 * and SP 800-73-4 profiles.
 * Standards: SP 800-73-5 Part 1 Table 10 and sections 3.4.1 and 3.4.2,
 * SP 800-73-4 Part 1 Table 9, SP 800-73-2 Part 1 Table 8, TWIC Part 2 v5,
 * RFC 4122 section 4.1.
 * Configuration: TC_ENABLE_PIV_CHUID.
 * Limitations: parsing only. credential.h authenticates the signature.
 * Contracts: docs/api.md. */
#ifndef TINY_CRYPTO_PIV_CHUID_H_
#define TINY_CRYPTO_PIV_CHUID_H_
#include <tiny_crypto/tlv.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef enum { TC_PIV_CHUID_CONTENTS, TC_PIV_CHUID_CONTAINER } TC_PIV_CHUID_encoding;
typedef enum {
  TC_CHUID_PROFILE_PIV,
  TC_CHUID_PROFILE_TWIC_SIGNED,
  TC_CHUID_PROFILE_TWIC_UNSIGNED,
  TC_CHUID_PROFILE_PIV_SP800_73_4
} TC_PIV_CHUID_profile;
typedef struct {
  TC_bytes fascn, card_uuid, cardholder_uuid, expiration, signature;
  /* Optional 3D value, covered by signed_content. NULL means absent. */
  TC_bytes authentication_key_map;
  /* Hash these spans in order for CMS detached content. Both are empty for
   * unsigned TWIC. Encodings include the trailing FE field. */
  TC_bytes signed_content[2];
} TC_PIV_CHUID;

#if TC_ENABLE_PIV_CHUID
/* Read a CHUID. CONTAINER includes the outer 53 object. CONTENTS starts with
 * its first field. Select the profile from the application's card-object
 * policy. Field order and sizes follow the profile:
 * - PIV: SP 800-73-5 Part 1 Table 10. The GUID (34) must be an RFC 4122
 *   UUID of version 1, 4 or 5, and the optional Cardholder UUID (36) one of
 *   version 4 (sections 3.4.1 and 3.4.2). Buffer Length (EE), Organizational
 *   Identifier (32) and DUNS (33) are rejected.
 * - TWIC_SIGNED and TWIC_UNSIGNED: TWIC Part 2 v5 sections 4.6.3 and 4.6.1.
 *   Unsigned TWIC has neither a signature nor a cardholder UUID. EE, 32 and 33
 *   are rejected. The GUID is opaque, since Legacy TWIC cards hold zeros.
 * - PIV_SP800_73_4: SP 800-73-4 Part 1 Table 9 with an optional Authentication
 *   Key Map (3D, 0..512 bytes) immediately before the signature, following
 *   SP 800-73-2 Part 1 Table 8. Buffer Length (EE, 2 bytes), Organizational
 *   Identifier (32, 4 bytes) and DUNS (33, 9 bytes) are optional and checked
 *   for length. UUID versions are unchecked. signed_content includes the
 *   exact encoded map TLV. Authenticate the signature before using the map.
 *   The PIV application of a TWIC card uses it, and a PIV card whose CHUID
 *   follows SP 800-73-4 selects it explicitly.
 * signed_content excludes a Buffer Length element (SP 800-73-4 Part 1
 * section 3.1.2). Spans borrow encoded, which must stay unchanged while they
 * are used. An absent optional field has a NULL pointer. The caller verifies
 * the CMS signature, or uses TC_PIV_CHUID_validate. Charges no work.
 * Returns OK, MORE when input ends inside the outer 53 object or a CONTENTS
 * field, INVALID for malformed or out-of-profile fields, and ARGUMENT for a
 * NULL out, NULL data with a length, an unknown encoding or profile, or out
 * overlapping encoded.
 * out changes only on OK. */
TC_TLV_result TC_PIV_CHUID_read(TC_bytes encoded, TC_PIV_CHUID_encoding encoding,
                                TC_PIV_CHUID_profile profile, TC_PIV_CHUID* out);
#endif

#ifdef __cplusplus
}
#endif
#endif
