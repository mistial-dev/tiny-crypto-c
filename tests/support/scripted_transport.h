/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Scripted TC_APDU_transport for tests. Each transmit checks the next
 * expected command and delivers the scripted response. Hex text uses
 * TC_TEST_HEX_SEPARATED, so "00 A4 04 00" and "00a40400" both work. */
#ifndef TC_TEST_SCRIPTED_TRANSPORT_H
#define TC_TEST_SCRIPTED_TRANSPORT_H

#include <tiny_crypto/apdu.h>

#define TC_SCRIPT_MAX_STEPS 32u
#define TC_SCRIPT_MAX_BYTES 1024u

typedef struct {
  /* Expected command as hex, or NULL to use command_bytes. When both are
   * empty, any command is accepted. */
  const char* command;
  /* Response data and SW1 SW2 as hex, or NULL to use response_bytes. */
  const char* response;
  TC_bytes command_bytes, response_bytes;
  /* TC_ERROR returns a transport failure and delivers nothing. */
  TC_status status;
  /* Nonzero overrides the reported *length after the bytes are written. */
  size_t reported_length;
} tc_script_step;

typedef struct {
  const tc_script_step* steps;
  size_t count, next;
  /* Index + 1 of the first step whose command differed, or 0. A mismatch,
   * an extra call or a response above the offered capacity returns TC_ERROR. */
  size_t mismatch;
  size_t offered[TC_SCRIPT_MAX_STEPS];
  /* Copy of each command sent, for fragment and GET RESPONSE checks. */
  uint8_t sent[TC_SCRIPT_MAX_STEPS][TC_SCRIPT_MAX_BYTES];
  size_t sent_length[TC_SCRIPT_MAX_STEPS];
  /* Set scratch to the channel scratch buffer to check the wipe after each
   * transmit: every call records scratch_dirty when a byte after the current
   * command is nonzero. */
  const uint8_t* scratch;
  size_t scratch_length;
  int scratch_dirty;
} tc_script;

void tc_script_init(tc_script* script, const tc_script_step* steps, size_t count);
TC_status tc_script_transmit(void* context, TC_bytes command, TC_buffer response, size_t* length);
TC_APDU_transport tc_script_transport(tc_script* script);

#endif
