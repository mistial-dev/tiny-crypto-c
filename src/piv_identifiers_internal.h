/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* The subjectAltName identifier reader shared by the PIV and TWIC card
 * profiles. */
#ifndef TC_PIV_IDENTIFIERS_INTERNAL_H_
#define TC_PIV_IDENTIFIERS_INTERNAL_H_
#include <tiny_crypto/piv_card.h>
#include <tiny_crypto/fascn.h>

#if TC_ENABLE_PIV_OBJECTS
/* Acceptance rules of one card profile and certificate.
 * oids             the FASC-N OIDs accepted.
 * authentication   a PIV Authentication certificate: card_guid selects the
 *                  card UUID, and a version 4 cardholder UUID may follow.
 * uuid_optional    the card UUID may be absent.
 * uuid_valid       the form a present card UUID must have.
 * uuid_fascn_check compares a present card UUID with the decoded FASC-N,
 *                  after a 16-unit work charge. NULL skips the check. */
typedef struct {
  TC_PIV_oid_profile oids;
  uint8_t authentication;
  uint8_t uuid_optional;
  int (*uuid_valid)(const uint8_t uuid[16]);
  TC_TLV_result (*uuid_fascn_check)(const uint8_t uuid[16], const TC_FASCN* fascn, int* matched);
} tc_piv_identifier_rules;

/* 1 for a version 1, 4 or 5 RFC 4122 card UUID (SP 800-73-5 Part 1 3.4.1). */
int tc_piv_card_uuid_valid(const uint8_t uuid[16]);

/* TC_PIV_card_identifiers_read under rules. card_guid holds 16 bytes for an
 * authentication read and is NULL otherwise. Work, statuses and failure
 * behavior match TC_PIV_card_identifiers_read. */
TC_TLV_result tc_piv_identifiers_read(TC_bytes encoded, const tc_piv_identifier_rules* rules,
                                      const uint8_t* card_guid, const TC_TLV_limits* limits,
                                      TC_TLV_frames frames, size_t* work,
                                      TC_PIV_card_identifiers* out);

/* TC_PIV_card_identifiers_match. With uuid_optional, an absent card UUID
 * matches any GUID. */
TC_TLV_result tc_piv_identifiers_match(const TC_PIV_card_identifiers* identifiers, TC_bytes fascn,
                                       TC_bytes guid, int uuid_optional, size_t* work,
                                       int* matched);
#endif
#endif
