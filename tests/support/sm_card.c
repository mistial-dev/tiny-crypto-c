/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "sm_card.h"
#include <string.h>

enum { CHUNK = 256, SW_SUCCESS = 0x9000, SW_SM_INCORRECT = 0x6988 };

void tc_sm_card_init(tc_sm_card* card)
{
  memset(card, 0, sizeof *card);
  card->inner_sw = SW_SUCCESS;
}

void tc_sm_card_keys(tc_sm_card* card, TC_bytes material)
{
  tc_sm_card_session_keys(&card->session, material);
}

static void status_write(uint8_t* out, uint16_t sw)
{
  out[0] = (uint8_t)(sw >> 8);
  out[1] = (uint8_t)sw;
}

static TC_status deliver(tc_sm_card* card, size_t le, TC_buffer response, size_t* length)
{
  const size_t remaining = card->pending_length - card->pending_offset;
  const size_t count = remaining < le ? remaining : le;
  const size_t after = remaining - count;
  if (count + 2 > response.capacity)
    return TC_ERROR;
  memcpy(response.data, card->pending + card->pending_offset, count);
  card->pending_offset += count;
  status_write(response.data + count,
               after ? (uint16_t)(0x6100 | (after >= CHUNK ? 0 : after)) : card->pending_sw);
  *length = count + 2;
  if (!after)
    card->pending_length = card->pending_offset = 0;
  return TC_OK;
}

static TC_status deliver_status(uint16_t sw, TC_buffer response, size_t* length)
{
  if (response.capacity < 2)
    return TC_ERROR;
  status_write(response.data, sw);
  *length = 2;
  return TC_OK;
}

static TC_status deliver_plain(TC_bytes answer, TC_buffer response, size_t* length)
{
  if (answer.length > response.capacity)
    return TC_ERROR;
  memcpy(response.data, answer.data, answer.length);
  *length = answer.length;
  return TC_OK;
}

/* Check the C-MAC and decrypt the collected SM data field (4.2.3). Returns
 * 0 for a malformed field or MAC. */
static int command_open(tc_sm_card* card)
{
  tc_sm_card_plain plain = {card->plain, sizeof card->plain, 0, 0, 0};
  const int opened = tc_sm_card_session_open(&card->session, card->header,
                                             (TC_bytes){card->field, card->field_length}, &plain);
  card->plain_length = plain.length;
  card->plain_le = plain.has_le;
  card->mac_valid = plain.mac_valid;
  return opened;
}

static TC_status protected_command(tc_sm_card* card, TC_buffer response, size_t* length)
{
  ++card->protected_commands;
  if (card->fault == TC_SM_CARD_OUTER_STATUS)
    return deliver_status(card->outer_sw, response, length);
  if (!command_open(card)) {
    card->broken = 1;
    return deliver_status(SW_SM_INCORRECT, response, length);
  }
  if (card->fault == TC_SM_CARD_STALE) {
    memcpy(card->pending, card->previous, card->previous_length);
    card->pending_length = card->previous_length;
  } else {
    card->pending_length =
        tc_sm_card_session_answer(&card->session, (TC_bytes){card->answer, card->answer_length},
                                  card->inner_sw, card->fault, card->pending);
    memcpy(card->previous, card->pending, card->pending_length);
    card->previous_length = card->pending_length;
  }
  tc_sm_card_session_next(&card->session);
  card->pending_offset = 0;
  card->pending_sw = SW_SUCCESS;
  return deliver(card, CHUNK, response, length);
}

/* One short fragment of a protected command: 1C without Le, or 0C with
 * Le 00 (4.2.4, footnote 22). */
static TC_status fragment(tc_sm_card* card, TC_bytes command, TC_buffer response, size_t* length)
{
  const uint8_t* c = command.data;
  const size_t lc = command.length > 4 ? c[4] : 0;
  const int last = c[0] == 0x0c;
  const size_t expected = 5 + lc + (last ? 1 : 0);
  memcpy(card->last_fragment, c, command.length);
  card->last_fragment_length = command.length;
  ++card->fragments;
  if (!lc || command.length != expected || (last && c[expected - 1] != 0) ||
      card->field_length + lc > sizeof card->field ||
      (card->field_length && memcmp(card->header, c + 1, 3))) {
    card->broken = 1;
    card->field_length = 0;
    return deliver_status(SW_SM_INCORRECT, response, length);
  }
  memcpy(card->header, c + 1, 3);
  memcpy(card->field + card->field_length, c + 5, lc);
  card->field_length += lc;
  if (!last) {
    if (card->fault == TC_SM_CARD_CHAIN_STATUS) {
      card->field_length = 0;
      ++card->protected_commands;
      return deliver_status(card->outer_sw, response, length);
    }
    return deliver_status(SW_SUCCESS, response, length);
  }
  if (!card->first_command_length && card->fragments == 1) {
    memcpy(card->first_command, c, command.length);
    card->first_command_length = command.length;
  }
  const TC_status status = protected_command(card, response, length);
  card->field_length = 0;
  return status;
}

static TC_status transmit(void* context, TC_bytes command, TC_buffer response, size_t* length)
{
  tc_sm_card* card = context;
  const uint8_t* c = command.data;
  ++card->transmits;
  if (command.length < 4)
    return TC_ERROR;
  if (c[1] == 0xa4)
    return deliver_plain(card->select_answer, response, length);
  if (c[1] == 0xc0) {
    /* GET RESPONSE is plain and leaves the counter (4.2.2, 4.2.6). */
    ++card->get_responses;
    if (c[0] != 0x00 || command.length != 5 || !card->pending_length)
      card->broken = 1;
    return deliver(card, c[4] ? c[4] : CHUNK, response, length);
  }
  if (c[0] == 0x00 && c[1] == 0x87 && c[3] == 0x04) {
    if (card->key_command.data && (command.length != card->key_command.length ||
                                   memcmp(command.data, card->key_command.data, command.length)))
      card->broken = 1;
    return deliver_plain(card->key_answer, response, length);
  }
  if (c[0] == 0x1c || c[0] == 0x0c)
    return fragment(card, command, response, length);
  ++card->plain_commands;
  return deliver_status(0x6982, response, length);
}

TC_APDU_transport tc_sm_card_transport(tc_sm_card* card)
{
  TC_APDU_transport transport = {transmit, card};
  return transport;
}
