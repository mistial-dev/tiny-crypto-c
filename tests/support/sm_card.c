/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "sm_card.h"
#include <tiny_crypto/aes_dynamic.h>
#include <string.h>

enum { BLOCK = 16, CHUNK = 256, SW_SUCCESS = 0x9000, SW_SM_INCORRECT = 0x6988 };

void tc_sm_card_init(tc_sm_card* card)
{
  memset(card, 0, sizeof *card);
  card->inner_sw = SW_SUCCESS;
}

void tc_sm_card_keys(tc_sm_card* card, TC_bytes material)
{
  card->key_bytes = material.length / 4;
  memcpy(card->mac_key, material.data + card->key_bytes, card->key_bytes);
  memcpy(card->enc_key, material.data + 2 * card->key_bytes, card->key_bytes);
  memcpy(card->rmac_key, material.data + 3 * card->key_bytes, card->key_bytes);
  memset(card->counter, 0, sizeof card->counter);
  card->counter[15] = 1;
  memset(card->command_mcv, 0, sizeof card->command_mcv);
  memset(card->response_mcv, 0, sizeof card->response_mcv);
}

static void mac_compute(const uint8_t* key, size_t key_bytes, const TC_bytes* parts, size_t count,
                        uint8_t out[BLOCK])
{
  TC_AES_dynamic_CMAC mac;
  TC_AES_dynamic_CMAC_init(&mac, key, key_bytes);
  for (size_t i = 0; i < count; ++i)
    TC_AES_dynamic_CMAC_update(&mac, parts[i].data, parts[i].length);
  TC_AES_dynamic_CMAC_final(&mac, out);
  TC_AES_dynamic_CMAC_clear(&mac);
}

/* CBC in the direction given, with the IV derived from the command counter
 * (4.2.2). Responses replace the first counter byte with 80. */
static void cipher(const tc_sm_card* card, int response, int decrypt, uint8_t* data, size_t length)
{
  TC_AES_dynamic_key key;
  uint8_t iv[BLOCK];
  memcpy(iv, card->counter, BLOCK);
  if (response)
    iv[0] = 0x80;
  TC_AES_dynamic_key_init(&key, card->enc_key, card->key_bytes);
  TC_AES_dynamic_encrypt(&key, iv);
  if (length) {
    if (decrypt)
      TC_AES_dynamic_CBC_decrypt(&key, iv, data, length);
    else
      TC_AES_dynamic_CBC_encrypt(&key, iv, data, length);
  }
  TC_AES_dynamic_key_clear(&key);
}

static size_t length_write(uint8_t* out, size_t length)
{
  if (length < 0x80) {
    out[0] = (uint8_t)length;
    return 1;
  }
  if (length < 0x100) {
    out[0] = 0x81;
    out[1] = (uint8_t)length;
    return 2;
  }
  out[0] = 0x82;
  out[1] = (uint8_t)(length >> 8);
  out[2] = (uint8_t)length;
  return 3;
}

/* Read a BER length of 1 to 3 octets at field[*at]. */
static int length_read(const uint8_t* field, size_t end, size_t* at, size_t* length)
{
  if (*at >= end)
    return 0;
  const uint8_t first = field[(*at)++];
  if (first < 0x80) {
    *length = first;
  } else if (first == 0x81 && *at + 1 <= end) {
    *length = field[*at];
    *at += 1;
  } else if (first == 0x82 && *at + 2 <= end) {
    *length = (size_t)field[*at] << 8 | field[*at + 1];
    *at += 2;
  } else {
    return 0;
  }
  return *length <= end - *at;
}

static void increment(uint8_t counter[BLOCK])
{
  for (size_t i = BLOCK; i > 0; --i)
    if (++counter[i - 1])
      break;
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

/* Check the C-MAC over MCV, the header block and the 87 and 97 DOs (4.2.3),
 * then decrypt the 87 value. Returns 0 for a malformed field or MAC. */
static int command_open(tc_sm_card* card)
{
  const uint8_t* field = card->field;
  const size_t end = card->field_length;
  size_t at = 0, value = 0, ciphertext_at = 0, ciphertext_length = 0;
  if (at < end && field[at] == 0x87) {
    ++at;
    if (!length_read(field, end, &at, &value) || value < 1 + BLOCK || field[at] != 1 ||
        (value - 1) % BLOCK)
      return 0;
    ciphertext_at = at + 1;
    ciphertext_length = value - 1;
    at += value;
  }
  card->plain_le = 0;
  if (at + 3 <= end && field[at] == 0x97) {
    if (field[at + 1] != 1 || field[at + 2] != 0)
      return 0;
    card->plain_le = 1;
    at += 3;
  }
  const size_t authenticated = at;
  if (at + 10 != end || field[at] != 0x8e || field[at + 1] != 8)
    return 0;
  uint8_t header[BLOCK] = {0x0c, card->header[0], card->header[1], card->header[2], 0x80};
  const TC_bytes parts[] = {{card->command_mcv, BLOCK}, {header, BLOCK}, {field, authenticated}};
  uint8_t full[BLOCK];
  mac_compute(card->mac_key, card->key_bytes, parts, 3, full);
  memcpy(card->command_mcv, full, BLOCK);
  card->mac_valid = memcmp(full, field + at + 2, 8) == 0;
  if (!card->mac_valid)
    return 0;
  memcpy(card->plain, field + ciphertext_at, ciphertext_length);
  cipher(card, 0, 1, card->plain, ciphertext_length);
  card->plain_length = ciphertext_length;
  while (card->plain_length && card->plain[card->plain_length - 1] == 0)
    --card->plain_length;
  if (ciphertext_length && (!card->plain_length || card->plain[card->plain_length - 1] != 0x80))
    return 0;
  if (ciphertext_length)
    --card->plain_length;
  return 1;
}

/* Build [87 L 01 ciphertext] 99 02 SW 8E 08 MAC (4.2.5, 4.2.6) with the
 * configured fault. */
static size_t answer_build(tc_sm_card* card, uint8_t* out)
{
  size_t at = 0;
  if (card->answer_length || card->fault == TC_SM_CARD_CRYPTOGRAM_ALWAYS) {
    const size_t padded = (card->answer_length / BLOCK + 1) * BLOCK;
    uint8_t block[TC_SM_CARD_MAX_BYTES + BLOCK];
    memcpy(block, card->answer, card->answer_length);
    memset(block + card->answer_length, 0, padded - card->answer_length);
    if (card->fault != TC_SM_CARD_BAD_PADDING)
      block[card->answer_length] = 0x80;
    cipher(card, 1, 0, block, padded);
    const size_t value = 1 + padded + (card->fault == TC_SM_CARD_PARTIAL_BLOCK);
    out[at++] = 0x87;
    at += length_write(out + at, value);
    out[at++] = card->fault == TC_SM_CARD_BAD_INDICATOR ? 0x02 : 0x01;
    memcpy(out + at, block, padded);
    at += padded;
    if (card->fault == TC_SM_CARD_PARTIAL_BLOCK)
      out[at++] = 0;
  }
  if (card->fault != TC_SM_CARD_NO_STATUS) {
    out[at++] = 0x99;
    out[at++] = 2;
    status_write(out + at, card->inner_sw);
    at += 2;
  }
  const TC_bytes parts[] = {{card->response_mcv, BLOCK}, {out, at}};
  uint8_t full[BLOCK];
  mac_compute(card->rmac_key, card->key_bytes, parts, 2, full);
  memcpy(card->response_mcv, full, BLOCK);
  if (card->fault == TC_SM_CARD_BAD_MAC)
    full[0] ^= 1;
  if (card->fault != TC_SM_CARD_NO_MAC) {
    const size_t mac = card->fault == TC_SM_CARD_MAC_LENGTH ? 7 : 8;
    out[at++] = 0x8e;
    out[at++] = (uint8_t)mac;
    memcpy(out + at, full, mac);
    at += mac;
  }
  if (card->fault == TC_SM_CARD_TRAILING)
    out[at++] = 0;
  return at;
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
    card->pending_length = answer_build(card, card->pending);
    memcpy(card->previous, card->pending, card->pending_length);
    card->previous_length = card->pending_length;
  }
  increment(card->counter);
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
