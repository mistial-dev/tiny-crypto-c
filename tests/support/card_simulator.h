/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* A PIV card for tests, driven by a tests/support/card_fixture.h fixture
 * and used as a TC_APDU_transport. It implements the card side of:
 *
 * - SELECT of the PIV AID, full or right-truncated (SP 800-73-5 Part 2
 *   3.1.1). Reselecting PIV keeps the security status. Another AID answers
 *   6A82 and keeps the selection.
 * - GET DATA with the Part 1 Table 2 read rules for the contact and
 *   contactless interfaces: 6982 when a rule is unmet, 6A82 for a container
 *   the fixture lacks (Part 2 3.1.2).
 * - VERIFY for 80, 00 and 98 with retry counters, the data-less query and
 *   P1 FF (Part 2 3.2.1). On contactless, 80 and 00 need the VCI and 98
 *   needs secure messaging (Part 1 Table 4).
 * - GENERAL AUTHENTICATE with the recorded key establishment sessions and
 *   GENERAL AUTHENTICATE pairs. 9E is Always, 9A, 9D and retired keys need
 *   the PIN, 9C needs a PIN submission as the preceding command (PIN
 *   Always), and on contactless all but 9E need the VCI (Part 1 Table 5).
 * - Secure messaging (Part 2 4.2): the C-MAC of every protected command is
 *   checked by tests/support/sm_card_session.c, 1C chains are collected,
 *   answers go out in 256-byte chunks with 61XX and plain GET RESPONSE
 *   (4.2.6). A bad C-MAC answers 6988. Every SM error status ends the
 *   session, and so does every key establishment request, recorded or not
 *   (4.3). A protected command without a session answers 6982 (footnote 24).
 * - The VCI condition of Part 1 5.5: the command is protected, the Discovery
 *   Object policy has bit 4 set, and the pairing code was verified in this
 *   session or policy bit 3 is set. The policy and the verifiable references
 *   come from the Discovery Object the card answers, overrides included.
 *
 * Plain answers follow ISO/IEC 7816-4 5.3.4: Le 00 gets 256-byte chunks with
 * 61XX. An extended Le gets the complete answer, as SD 33 card 2 answered
 * 264 bytes to Ne 256. A short Le below the answer size gets the first Le
 * bytes with the final status, as SD 33 card 2 does
 * (vci_contactless_card01.json exchange 1). Commands other than SELECT
 * answer 6985 before a SELECT, and any command other than GET RESPONSE ends
 * a pending answer. An answer that exceeds the offered capacity is a
 * transport ERROR, as with a reader buffer that is too small.
 *
 * Host behaviour that the library never produces counts in violations with
 * a reason: an unknown CLA, a malformed APDU, a bad C-MAC, extended length
 * secure messaging, a protected command without the outer Le 00, GET
 * RESPONSE without pending data or with a CLA other than 00, a broken chain,
 * and plaintext reference data on the contactless interface. A command that
 * finds the log full also counts, so log queries never miss a command. */
#ifndef TC_TEST_CARD_SIMULATOR_H
#define TC_TEST_CARD_SIMULATOR_H

#include <tiny_crypto/apdu.h>
#include "card_fixture.h"
#include "sm_card_session.h"

#define TC_CARD_SIMULATOR_MAX_ANSWER (16384u + TC_SM_CARD_ANSWER_OVERHEAD)
#define TC_CARD_SIMULATOR_MAX_COMMAND 4096u
#define TC_CARD_SIMULATOR_LOG 256u
#define TC_CARD_SIMULATOR_OVERRIDES 8u

/* One completed command after chaining and secure messaging. */
typedef struct {
  uint8_t ins, p1, p2;
  uint8_t secured;   /* sent under secure messaging */
  uint32_t tag;      /* GET DATA tag, or 0 */
  size_t data_bytes; /* plain command data length */
  uint16_t sw;       /* card status, inside 99 when secured */
} tc_card_command;

/* A test's change to one container: sw 9000 answers data, any other sw
 * answers that status alone. */
typedef struct {
  uint32_t tag;
  uint16_t sw;
  TC_bytes data;
} tc_card_override;

typedef struct {
  const tc_card_fixture* fixture;
  TC_PIV_interface interface;
  /* Card state. verified and retries follow fixture->references. pin_always
   * is set by a PIN submission and lasts for the next command. */
  uint8_t selected, session_active, pairing_verified, pin_always;
  uint8_t verified[TC_CARD_FIXTURE_MAX_REFERENCES];
  uint8_t retries[TC_CARD_FIXTURE_MAX_REFERENCES];
  tc_sm_card_session session;
  tc_card_override overrides[TC_CARD_SIMULATOR_OVERRIDES];
  size_t override_count;
  /* Observations. transmits counts every APDU, fragments the chained ones
   * (CLA b5 set), protected_commands the final 0C commands, and the
   * submissions every VERIFY with data for 80 or 00 and for 98. */
  size_t transmits, fragments, get_responses, protected_commands;
  size_t pin_submissions, pairing_submissions, violations;
  const char* violation; /* the first violation */
  tc_card_command log[TC_CARD_SIMULATOR_LOG];
  size_t log_count;
  /* Internal state. */
  uint8_t chain_header[4];
  uint8_t chain_secured, chaining;
  uint8_t chain[TC_CARD_SIMULATOR_MAX_COMMAND], plain[TC_CARD_SIMULATOR_MAX_COMMAND];
  size_t chain_length;
  uint8_t pending[TC_CARD_SIMULATOR_MAX_ANSWER];
  size_t pending_length, pending_offset;
  uint16_t pending_sw;
} tc_card_simulator;

/* Power up the card from fixture on interface. fixture must outlive card. */
void tc_card_simulator_init(tc_card_simulator* card, const tc_card_fixture* fixture,
                            TC_PIV_interface interface);

/* Card reset: ends the session, clears the selection and every security
 * status. Retry counters, overrides and observations stay. */
void tc_card_simulator_reset(tc_card_simulator* card);

/* Replace the answer to GET DATA of tag. data must outlive card. Returns 0
 * when the override table is full. */
int tc_card_simulator_override(tc_card_simulator* card, uint32_t tag, uint16_t sw, TC_bytes data);

/* Number of logged commands with ins, and with tag unless tag is 0. The log
 * holds commands that reached the command rules. APDUs refused for their
 * CLA, length or secure messaging count only in transmits. */
size_t tc_card_simulator_sent(const tc_card_simulator* card, uint8_t ins, uint32_t tag);

TC_APDU_transport tc_card_simulator_transport(tc_card_simulator* card);

#endif
