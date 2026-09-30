/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Card side of PIV secure messaging for tests (SP 800-73-5 Part 2 4.2). The
 * model answers SELECT and key establishment from fixed bytes, checks the
 * C-MAC of every protected command, decrypts it, and builds the protected
 * answer that the test configured. It verifies the chaining and GET RESPONSE
 * rules of 4.2.4 and 4.2.6 and can inject one fault per command. The
 * session cryptography is tests/support/sm_card_session.c. */
#ifndef TC_TEST_SM_CARD_H
#define TC_TEST_SM_CARD_H

#include <tiny_crypto/apdu.h>
#include <tiny_crypto/piv_sm.h>
#include "sm_card_session.h"

#define TC_SM_CARD_MAX_BYTES 4096u

typedef struct {
  /* Session keys and state, set by tc_sm_card_keys. */
  tc_sm_card_session session;
  /* Plain answers with SW1 SW2. key_command, when set, must match the key
   * establishment command byte for byte. */
  TC_bytes select_answer, key_command, key_answer;
  /* The next protected answer. */
  uint8_t answer[TC_SM_CARD_MAX_BYTES];
  size_t answer_length;
  uint16_t inner_sw, outer_sw;
  tc_sm_card_fault fault;
  /* Observations. plain holds the decrypted data of the last protected
   * command, header its INS P1 P2. */
  uint8_t plain[TC_SM_CARD_MAX_BYTES], header[3];
  size_t plain_length;
  int plain_le, mac_valid, broken;
  size_t transmits, protected_commands, fragments, get_responses, plain_commands;
  uint8_t last_fragment[TC_APDU_SHORT_COMMAND_MAX_BYTES];
  size_t last_fragment_length;
  /* The first protected command as sent, header to Le. */
  uint8_t first_command[TC_APDU_SHORT_COMMAND_MAX_BYTES];
  size_t first_command_length;
  /* Internal state. */
  uint8_t field[TC_SM_CARD_MAX_BYTES], pending[TC_SM_CARD_MAX_BYTES + TC_SM_CARD_ANSWER_OVERHEAD],
      previous[TC_SM_CARD_MAX_BYTES + TC_SM_CARD_ANSWER_OVERHEAD];
  size_t field_length, pending_length, pending_offset, previous_length;
  uint16_t pending_sw;
} tc_sm_card;

void tc_sm_card_init(tc_sm_card* card);
/* Load the session keys from the SP 800-73-5 key material SK_CFRM || SK_MAC
 * || SK_ENC || SK_RMAC and reset the counter to 1 and both MCVs to zero. */
void tc_sm_card_keys(tc_sm_card* card, TC_bytes material);
TC_APDU_transport tc_sm_card_transport(tc_sm_card* card);

#endif
