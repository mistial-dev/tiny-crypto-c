/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Card side of PIV secure messaging for tests (SP 800-73-5 Part 2 4.2). The
 * model answers SELECT and key establishment from fixed bytes, checks the
 * C-MAC of every protected command, decrypts it, and builds the protected
 * answer that the test configured. It verifies the chaining and GET RESPONSE
 * rules of 4.2.4 and 4.2.6 and can inject one fault per command. It shares
 * only AES and CMAC with the library. */
#ifndef TC_TEST_SM_CARD_H
#define TC_TEST_SM_CARD_H

#include <tiny_crypto/apdu.h>
#include <tiny_crypto/piv_sm.h>

#define TC_SM_CARD_MAX_BYTES 4096u

typedef enum {
  TC_SM_CARD_ANSWER,           /* a protected answer with answer and inner_sw */
  TC_SM_CARD_OUTER_STATUS,     /* outer_sw alone, as a card SM error */
  TC_SM_CARD_CHAIN_STATUS,     /* the first 1C fragment answered with outer_sw */
  TC_SM_CARD_STALE,            /* the previous protected answer again */
  TC_SM_CARD_BAD_INDICATOR,    /* 87 with padding indicator 02 */
  TC_SM_CARD_PARTIAL_BLOCK,    /* 87 ciphertext of 17 bytes */
  TC_SM_CARD_BAD_PADDING,      /* plaintext padding without the 80 marker */
  TC_SM_CARD_MAC_LENGTH,       /* 8E 07 */
  TC_SM_CARD_NO_STATUS,        /* no 99 */
  TC_SM_CARD_NO_MAC,           /* no 8E */
  TC_SM_CARD_TRAILING,         /* one byte after 8E */
  TC_SM_CARD_BAD_MAC,          /* one flipped MAC bit */
  TC_SM_CARD_CRYPTOGRAM_ALWAYS /* 87 even when the answer is empty */
} tc_sm_card_fault;

typedef struct {
  /* Session keys and state, set by tc_sm_card_keys. */
  size_t key_bytes;
  uint8_t mac_key[32], enc_key[32], rmac_key[32];
  uint8_t counter[16], command_mcv[16], response_mcv[16];
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
  uint8_t field[TC_SM_CARD_MAX_BYTES], pending[TC_SM_CARD_MAX_BYTES + 64],
      previous[TC_SM_CARD_MAX_BYTES + 64];
  size_t field_length, pending_length, pending_offset, previous_length;
  uint16_t pending_sw;
} tc_sm_card;

void tc_sm_card_init(tc_sm_card* card);
/* Load the session keys from the SP 800-73-5 key material SK_CFRM || SK_MAC
 * || SK_ENC || SK_RMAC and reset the counter to 1 and both MCVs to zero. */
void tc_sm_card_keys(tc_sm_card* card, TC_bytes material);
TC_APDU_transport tc_sm_card_transport(tc_sm_card* card);

#endif
