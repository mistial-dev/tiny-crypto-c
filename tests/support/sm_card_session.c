/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "sm_card_session.h"
#include <tiny_crypto/aes_dynamic.h>
#include <string.h>

enum { BLOCK = 16 };

void tc_sm_card_session_keys(tc_sm_card_session* session, TC_bytes material)
{
  session->key_bytes = material.length / 4;
  memcpy(session->mac_key, material.data + session->key_bytes, session->key_bytes);
  memcpy(session->enc_key, material.data + 2 * session->key_bytes, session->key_bytes);
  memcpy(session->rmac_key, material.data + 3 * session->key_bytes, session->key_bytes);
  memset(session->counter, 0, sizeof session->counter);
  session->counter[15] = 1;
  memset(session->command_mcv, 0, sizeof session->command_mcv);
  memset(session->response_mcv, 0, sizeof session->response_mcv);
}

static void mac_compute(const uint8_t* key, size_t key_bytes, const TC_bytes* parts, size_t count,
                        uint8_t out[BLOCK])
{
  TC_AES_dynamic_CMAC mac;
  TC_AES_dynamic_CMAC_init(&mac, (TC_bytes){key, key_bytes});
  for (size_t i = 0; i < count; ++i)
    TC_AES_dynamic_CMAC_update(&mac, (TC_bytes){parts[i].data, parts[i].length});
  TC_AES_dynamic_CMAC_final(&mac, (TC_buffer){out, TC_AES_BLOCKLEN});
  TC_AES_dynamic_CMAC_clear(&mac);
}

/* CBC in the direction given, with the IV derived from the command counter
 * (4.2.2). Responses replace the first counter byte with 80. */
static void cipher(const tc_sm_card_session* session, int response, int decrypt, uint8_t* data,
                   size_t length)
{
  TC_AES_dynamic_key key;
  uint8_t iv[BLOCK];
  memcpy(iv, session->counter, BLOCK);
  if (response)
    iv[0] = 0x80;
  TC_AES_dynamic_key_init(&key, (TC_bytes){session->enc_key, session->key_bytes});
  TC_AES_dynamic_encrypt(&key, (TC_buffer){iv, TC_AES_BLOCKLEN});
  if (length) {
    if (decrypt)
      TC_AES_dynamic_CBC_decrypt(&key, (TC_buffer){iv, TC_AES_BLOCKLEN}, (TC_buffer){data, length});
    else
      TC_AES_dynamic_CBC_encrypt(&key, (TC_buffer){iv, TC_AES_BLOCKLEN}, (TC_buffer){data, length});
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

void tc_sm_card_session_next(tc_sm_card_session* session)
{
  for (size_t i = BLOCK; i > 0; --i)
    if (++session->counter[i - 1])
      break;
}

int tc_sm_card_session_open(tc_sm_card_session* session, const uint8_t header[3], TC_bytes field,
                            tc_sm_card_plain* plain)
{
  const uint8_t* bytes = field.data;
  const size_t end = field.length;
  size_t at = 0, value = 0, ciphertext_at = 0, ciphertext_length = 0;
  plain->has_le = 0;
  plain->mac_valid = 0;
  plain->length = 0;
  if (at < end && bytes[at] == 0x87) {
    ++at;
    if (!length_read(bytes, end, &at, &value) || value < 1 + BLOCK || bytes[at] != 1 ||
        (value - 1) % BLOCK || value - 1 > plain->capacity)
      return 0;
    ciphertext_at = at + 1;
    ciphertext_length = value - 1;
    at += value;
  }
  if (at + 3 <= end && bytes[at] == 0x97) {
    if (bytes[at + 1] != 1 || bytes[at + 2] != 0)
      return 0;
    plain->has_le = 1;
    at += 3;
  }
  const size_t authenticated = at;
  if (at + 10 != end || bytes[at] != 0x8e || bytes[at + 1] != 8)
    return 0;
  uint8_t block[BLOCK] = {0x0c, header[0], header[1], header[2], 0x80};
  const TC_bytes parts[] = {{session->command_mcv, BLOCK}, {block, BLOCK}, {bytes, authenticated}};
  uint8_t full[BLOCK];
  mac_compute(session->mac_key, session->key_bytes, parts, 3, full);
  memcpy(session->command_mcv, full, BLOCK);
  plain->mac_valid = memcmp(full, bytes + at + 2, 8) == 0;
  if (!plain->mac_valid)
    return 0;
  memcpy(plain->data, bytes + ciphertext_at, ciphertext_length);
  cipher(session, 0, 1, plain->data, ciphertext_length);
  size_t length = ciphertext_length;
  while (length && plain->data[length - 1] == 0)
    --length;
  if (ciphertext_length && (!length || plain->data[length - 1] != 0x80))
    return 0;
  plain->length = ciphertext_length ? length - 1 : 0;
  return 1;
}

size_t tc_sm_card_session_answer(tc_sm_card_session* session, TC_bytes answer, uint16_t inner_sw,
                                 tc_sm_card_fault fault, uint8_t* out)
{
  size_t at = 0;
  if (answer.length || fault == TC_SM_CARD_CRYPTOGRAM_ALWAYS) {
    const size_t padded = (answer.length / BLOCK + 1) * BLOCK;
    const size_t value = 1 + padded + (fault == TC_SM_CARD_PARTIAL_BLOCK);
    out[at++] = 0x87;
    at += length_write(out + at, value);
    out[at++] = fault == TC_SM_CARD_BAD_INDICATOR ? 0x02 : 0x01;
    uint8_t* block = out + at;
    memmove(block, answer.data, answer.length);
    memset(block + answer.length, 0, padded - answer.length);
    if (fault != TC_SM_CARD_BAD_PADDING)
      block[answer.length] = 0x80;
    cipher(session, 1, 0, block, padded);
    at += padded;
    if (fault == TC_SM_CARD_PARTIAL_BLOCK)
      out[at++] = 0;
  }
  if (fault != TC_SM_CARD_NO_STATUS) {
    out[at++] = 0x99;
    out[at++] = 2;
    out[at++] = (uint8_t)(inner_sw >> 8);
    out[at++] = (uint8_t)inner_sw;
  }
  const TC_bytes parts[] = {{session->response_mcv, BLOCK}, {out, at}};
  uint8_t full[BLOCK];
  mac_compute(session->rmac_key, session->key_bytes, parts, 2, full);
  memcpy(session->response_mcv, full, BLOCK);
  if (fault == TC_SM_CARD_BAD_MAC)
    full[0] ^= 1;
  if (fault != TC_SM_CARD_NO_MAC) {
    const size_t mac = fault == TC_SM_CARD_MAC_LENGTH ? 7 : 8;
    out[at++] = 0x8e;
    out[at++] = (uint8_t)mac;
    memcpy(out + at, full, mac);
    at += mac;
  }
  if (fault == TC_SM_CARD_TRAILING)
    out[at++] = 0;
  return at;
}
