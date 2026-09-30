/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Card side of one PIV secure messaging session for tests (SP 800-73-5
 * Part 2 4.2): the C-MAC check and decryption of a protected command and the
 * protected answer. The card models tests/support/sm_card.c and
 * tests/support/card_simulator.c share it. It uses only AES and CMAC from
 * the library, so the host framing in src/piv_sm_apdu.c and
 * src/piv_sm_message.c is checked against separate code. */
#ifndef TC_TEST_SM_CARD_SESSION_H
#define TC_TEST_SM_CARD_SESSION_H

#include <tiny_crypto/common.h>

/* Bytes an answer adds around its plaintext: 87 82 LL LL 01, one padding
 * block, 99 02 SW, 8E 08 MAC and one fault byte. */
#define TC_SM_CARD_ANSWER_OVERHEAD 64u

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
  size_t key_bytes;
  uint8_t mac_key[32], enc_key[32], rmac_key[32];
  /* The counter of the next command and both MAC chaining values (4.2.2). */
  uint8_t counter[16], command_mcv[16], response_mcv[16];
} tc_sm_card_session;

/* The SM data field of one protected command after decryption. */
typedef struct {
  uint8_t* data;   /* caller storage for the plaintext */
  size_t capacity; /* bytes at data */
  size_t length;   /* plaintext bytes after a successful open */
  int has_le;      /* 97 01 00 was present */
  int mac_valid;   /* the C-MAC matched */
} tc_sm_card_plain;

/* Load SK_CFRM || SK_MAC || SK_ENC || SK_RMAC and reset the counter to 1 and
 * both MCVs to zero (4.1.6, 4.2.2). */
void tc_sm_card_session_keys(tc_sm_card_session* session, TC_bytes material);

/* Check [87 L 01 ciphertext] [97 01 00] 8E 08 MAC for the command header
 * INS P1 P2 (4.2.3), update the command MCV and decrypt the 87 value into
 * plain. Returns 1 for a well-formed field with a valid MAC and padding. */
int tc_sm_card_session_open(tc_sm_card_session* session, const uint8_t header[3], TC_bytes field,
                            tc_sm_card_plain* plain);

/* Write [87 L 01 ciphertext] 99 02 inner_sw 8E 08 MAC for answer (4.2.5,
 * 4.2.6) with the fault given, update the response MCV and return the
 * length. out holds answer.length + TC_SM_CARD_ANSWER_OVERHEAD bytes. The
 * counter stays for tc_sm_card_session_next. */
size_t tc_sm_card_session_answer(tc_sm_card_session* session, TC_bytes answer, uint16_t inner_sw,
                                 tc_sm_card_fault fault, uint8_t* out);

/* Advance the counter after a protected answer (4.2.2). */
void tc_sm_card_session_next(tc_sm_card_session* session);

#endif
