/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Transmit guard of the PIV hardware tests. It sees every command APDU
 * before the reader sends it and every answer after, and it refuses any
 * command outside this list:
 *
 * - SELECT 00 A4 04 00 with the complete PIV AID, the 9-byte PIV AID prefix
 *   or the 9-byte TWIC AID prefix (SP 800-73-5 Part 2 3.1.1, TWIC Part 2 v5
 *   5.1).
 * - GET DATA 00 or 0C CB 3F FF (Part 2 3.1.2).
 * - GET RESPONSE 00 C0 00 00 with Le, only after an answer of 61XX (ISO/IEC
 *   7816-4 5.3.4, Part 2 4.2.6).
 * - VERIFY 00 or 0C 20 00 with P2 80, 00 or 98 (Part 2 3.2.1).
 * - GENERAL AUTHENTICATE 00 or 10 87 with P1 27 or 2E and P2 04 (key
 *   establishment, Part 2 4.1), and 00, 10, 0C or 1C 87 with P1 05, 06, 07,
 *   11 or 14 and P2 9A, 9C or 9E (Part 2 3.2.4, SP 800-78-5 Table 9).
 *   Chained fragments (CLA b5) continue one GENERAL AUTHENTICATE with the
 *   same header.
 *
 * Everything else is refused, such as CHANGE REFERENCE DATA (24), RESET
 * RETRY COUNTER (2C), PUT DATA (DB), GENERATE ASYMMETRIC KEY PAIR (47),
 * VERIFY P1 FF, key references 9B and 9D, retired keys, logical channels
 * and proprietary classes.
 *
 * Reference data rules:
 * - A VERIFY with data is a submission. Under secure messaging (CLA 0C) the
 *   data field is the SM field, and a submission carries DO 87 (Part 2
 *   4.2.1, 4.2.4). An SM field with a DO outside 87, 97 and 8E is refused. A plain
 *   submission is refused on contactless.
 * - A PIN submission (80 or 00) needs the identity binding below, a
 *   data-less query of that reference answered 63CX with X at least
 *   minimum_retries since the last submission or SELECT, budget left in
 *   pin_submissions, and no earlier submission that failed. Any answer
 *   other than 9000, or a missing answer, counts as failed.
 * - A pairing code submission (98) needs the identity binding, budget left
 *   in pairing_submissions and no earlier pairing failure.
 * - GENERAL AUTHENTICATE of 9C needs the identity binding, budget left in
 *   signatures and a successful PIN submission as the preceding command
 *   (PIN Always, SP 800-73-5 Part 1 Table 5).
 *
 * Identity binding: a plain GET DATA of 5FC102 (CHUID) or 5FC101 (Card
 * Authentication certificate), with its GET RESPONSE steps, whose complete
 * answer data equals the expected bytes. Any watched answer that differs
 * blocks the binding for the life of the guard.
 *
 * The guard starts on contactless rules and learns the interface from
 * tc_piv_guard_connected. One guard serves one card connection. */
#ifndef TC_TEST_PIV_HARDWARE_GUARD_H
#define TC_TEST_PIV_HARDWARE_GUARD_H

#include <tiny_crypto/piv_command.h>

/* Largest identity answer the guard collects. The SD 33 CHUID is 2884
 * bytes. */
#define TC_PIV_GUARD_CAPTURE_BYTES 4096u
#define TC_PIV_GUARD_MAX_PIN_SUBMISSIONS 2u

enum { TC_PIV_GUARD_CHUID, TC_PIV_GUARD_CARD_CERTIFICATE, TC_PIV_GUARD_IDENTITIES };

/* identity         expected GET DATA answer data of 5FC102 and 5FC101
 *                  (the complete 53 container). Empty entries are never
 *                  matched. The spans stay borrowed and unchanged.
 * minimum_retries  2 to 15.
 * pin_submissions  0 to TC_PIV_GUARD_MAX_PIN_SUBMISSIONS.
 * pairing_submissions, signatures
 *                  0 or 1. */
typedef struct {
  TC_bytes identity[TC_PIV_GUARD_IDENTITIES];
  unsigned minimum_retries;
  unsigned pin_submissions, pairing_submissions, signatures;
} tc_piv_guard_policy;

/* Observations for assertions. exchanges counts the commands the guard
 * passed, fragments the chained ones and protected_commands those with an
 * SM CLA. get_response_le_mismatches counts GET RESPONSE steps whose Le
 * differs from the SW2 of the preceding 61XX. refusal names the first
 * refused command. */
typedef struct {
  size_t exchanges, get_responses, get_response_le_mismatches, fragments, protected_commands;
  size_t max_command_bytes, max_answer_bytes;
  size_t pin_queries, pin_submissions, pairing_submissions, signatures;
  size_t refusals;
  const char* refusal;
} tc_piv_guard_counts;

/* Members after counts are private. */
typedef struct {
  tc_piv_guard_policy policy;
  tc_piv_guard_counts counts;
  TC_PIV_interface interface;
  uint8_t identity_bound, identity_conflict;
  uint8_t query_ready[2]; /* 80 and 00 */
  uint8_t pin_outcome_pending, pin_failed, pairing_outcome_pending, pairing_failed;
  uint8_t pin_just_verified, answer_pending, last_sw2;
  uint8_t chain_open, chain_header[3], chain_secured;
  uint8_t pending_kind, pending_reference, pending_secured, pending_chained;
  uint8_t pending_header[3];
  int capture_index; /* identity being collected, or -1 */
  size_t capture_length;
  uint8_t capture[TC_PIV_GUARD_CAPTURE_BYTES];
} tc_piv_guard;

/* Start a guard. Returns 0 for a NULL pointer or a policy outside the
 * ranges above. */
int tc_piv_guard_init(tc_piv_guard* guard, const tc_piv_guard_policy* policy);

/* The interface the reader connected over. context is the guard. */
void tc_piv_guard_connected(void* context, TC_PIV_interface interface);

/* 1 to send command, 0 to refuse it. context is the guard. */
int tc_piv_guard_check(void* context, TC_bytes command);

/* The answer, with SW1 SW2, to the command the guard passed last. context
 * is the guard. */
void tc_piv_guard_observe(void* context, TC_bytes command, TC_bytes answer);

/* 1 once an identity answer matched and none differed. */
int tc_piv_guard_identity_bound(const tc_piv_guard* guard);

/* A TC_APDU_transport that runs the guard around inner. A refused command
 * or a failed transfer wipes the response and stops the transport. */
typedef struct {
  tc_piv_guard* guard;
  TC_APDU_transport inner;
  int stopped;
} tc_piv_guarded_transport;

TC_APDU_transport tc_piv_guarded_transport_init(tc_piv_guarded_transport* wrapper,
                                                tc_piv_guard* guard, TC_APDU_transport inner);

#endif
