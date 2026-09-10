/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/piv_sm.h>
#include "../../examples/piv_sm_wire.h"
#include <stdlib.h>
#include <string.h>

static int all_zero(const void* pointer, size_t length)
{
  const uint8_t* bytes = (const uint8_t*)pointer;
  size_t i;
  for (i = 0; i < length; ++i) if (bytes[i]) return 0;
  return 1;
}

/* Build authenticated responses so mutations also exercise CBC padding and
 * output-capacity handling, which random tags almost never reach. */
static void authenticated_response(TC_PIV_SM_suite suite, const uint8_t* data, size_t length,
                                   int bad_padding)
{
  TC_PIV_SM session = {0}, saved_session;
  TC_PIV_SM_workspace workspace;
  TC_AES_dynamic_key aes;
  TC_AES_dynamic_CMAC cmac;
  ExamplePIVSMResult result, saved_result;
  uint8_t wire[1060], output[1024], key[32] = {0}, iv[16] = {0}, mac[16];
  size_t padded, position = 0, cipher_start, capacity, key_length;
  int short_buffer;
  TC_status status;
  if (length > sizeof output) return;
  padded = (length / 16 + 1) * 16;
  wire[position++] = 0x87;
  if (padded + 1 < 128) wire[position++] = (uint8_t)(padded + 1);
  else if (padded + 1 < 256) {
    wire[position++] = 0x81; wire[position++] = (uint8_t)(padded + 1);
  } else {
    wire[position++] = 0x82; wire[position++] = (uint8_t)((padded + 1) >> 8);
    wire[position++] = (uint8_t)(padded + 1);
  }
  wire[position++] = 1;
  cipher_start = position;
  memcpy(wire + position, data, length);
  wire[position + length] = 0x80;
  memset(wire + position + length + 1, 0, padded - length - 1);
  if (bad_padding) wire[position + padded - 1] = 1;
  key_length = suite == TC_PIV_SM_CS2 ? 16 : 32;
  iv[0] = 0x80; iv[15] = 1;
  if (TC_AES_dynamic_key_init(&aes, key, key_length) != TC_OK ||
      TC_AES_dynamic_encrypt(&aes, iv) != TC_OK ||
      TC_AES_dynamic_CBC_encrypt(&aes, iv, wire + cipher_start, padded) != TC_OK) abort();
  TC_AES_dynamic_key_clear(&aes);
  position += padded;
  wire[position++] = 0x99; wire[position++] = 2;
  wire[position++] = 0x90; wire[position++] = 0;
  if (TC_AES_dynamic_CMAC_init(&cmac, key, key_length) != TC_OK ||
      TC_AES_dynamic_CMAC_update(&cmac, key, 16) != TC_OK ||
      TC_AES_dynamic_CMAC_update(&cmac, wire, position) != TC_OK ||
      TC_AES_dynamic_CMAC_final(&cmac, mac) != TC_OK) abort();
  wire[position++] = 0x8e; wire[position++] = 8;
  memcpy(wire + position, mac, 8); position += 8;
  session.suite = (uint8_t)suite;
  session.state = TC_PIV_SM_PENDING;
  session.data.traffic.counter[15] = 2;
  memcpy(&saved_session, &session, sizeof session);
  memset(&saved_result, 0xa5, sizeof saved_result);
  short_buffer = length && (data[0] & 1);
  capacity = short_buffer ? length - 1 : sizeof output;
  for (;;) {
    memset(output, 0xa5, sizeof output);
    memcpy(&result, &saved_result, sizeof result);
    memset(&workspace, 0xa5, sizeof workspace);
    status = example_piv_sm_unprotect(&session,(TC_bytes){wire,position},0x9000,output,
                              capacity, &result, &workspace);
    if (!all_zero(&workspace, sizeof workspace)) abort();
    if (bad_padding) {
      size_t i;
      if (status != TC_ERROR || !all_zero(&session, sizeof session) ||
          memcmp(&result, &saved_result, sizeof result)) abort();
      for (i = 0; i < sizeof output; ++i) if (output[i] != 0xa5) abort();
      break;
    } else if (short_buffer) {
      size_t i;
      if (status != TC_ERROR || memcmp(&session, &saved_session, sizeof session) ||
          memcmp(&result, &saved_result, sizeof result)) abort();
      for (i = 0; i < sizeof output; ++i) if (output[i] != 0xa5) abort();
      short_buffer = 0; capacity = sizeof output;
    } else {
      size_t i;
      if (status != TC_OK || result.length != length || result.status != 0x9000 ||
          memcmp(output, data, length) || session.state != TC_PIV_SM_READY ||
          memcmp(session.data.traffic.response_mcv, mac, 16)) abort();
      for (i = length; i < sizeof output; ++i) if (output[i] != 0xa5) abort();
      break;
    }
  }
  TC_PIV_SM_clear(&session);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t length)
{
  const TC_PIV_SM_suite suites[] = {TC_PIV_SM_CS2, TC_PIV_SM_CS7};
  TC_PIV_SM session;
  TC_PIV_SM_workspace workspace;
  ExamplePIVSMResponse response, saved_response;
  ExamplePIVSMResult result, saved_result;
  uint8_t output[8192], saved_output[8192];
  size_t i;
  if (length > sizeof output) return 0;
  memset(saved_output, 0xa5, sizeof saved_output);
  memset(&saved_response, 0xa5, sizeof saved_response);
  memset(&saved_result, 0xa5, sizeof saved_result);
  for (i = 0; i < sizeof suites / sizeof suites[0]; ++i) {
    TC_status status;
    authenticated_response(suites[i], data, length, 0);
    authenticated_response(suites[i], data, length, 1);
    memcpy(&response, &saved_response, sizeof response);
    status = example_piv_sm_response_read(suites[i],(TC_bytes){data,length},&response);
    if (status != TC_OK && memcmp(&response, &saved_response, sizeof response)) abort();

    memset(&session, 0, sizeof session);
    session.suite = (uint8_t)suites[i];
    session.state = TC_PIV_SM_PENDING;
    session.data.traffic.counter[15] = 2;
    memcpy(&result, &saved_result, sizeof result);
    memcpy(output, saved_output, sizeof output);
    memset(&workspace, 0xa5, sizeof workspace);
    status = example_piv_sm_unprotect(&session,(TC_bytes){data,length},0x9000,output,
                              sizeof output, &result, &workspace);
    if (status == TC_OK) {
      if (session.state != TC_PIV_SM_READY || result.length > length) abort();
      if (memcmp(output + result.length, saved_output + result.length,
                 sizeof output - result.length)) abort();
    } else {
      if (!all_zero(&session, sizeof session) ||
          memcmp(&result, &saved_result, sizeof result) ||
          memcmp(output, saved_output, sizeof output)) abort();
    }
    if (!all_zero(&workspace, sizeof workspace)) abort();
    TC_PIV_SM_clear(&session);
  }
  return 0;
}
