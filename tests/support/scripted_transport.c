/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "scripted_transport.h"
#include "cavp.h"
#include <string.h>

void tc_script_init(tc_script* script, const tc_script_step* steps, size_t count)
{
  memset(script, 0, sizeof *script);
  script->steps = steps;
  script->count = count;
}

TC_APDU_transport tc_script_transport(tc_script* script)
{
  TC_APDU_transport transport = {tc_script_transmit, script};
  return transport;
}

static int decode(const char* hex, TC_bytes bytes, uint8_t* output, size_t capacity, size_t* length)
{
  if (hex)
    return tc_test_hex_decode(hex, TC_TEST_HEX_SEPARATED, output, capacity, length);
  if (bytes.length > capacity)
    return 0;
  if (bytes.length)
    memcpy(output, bytes.data, bytes.length);
  *length = bytes.length;
  return 1;
}

static void record(tc_script* script, size_t index, TC_bytes command, TC_buffer response)
{
  if (index >= TC_SCRIPT_MAX_STEPS)
    return;
  script->offered[index] = response.capacity;
  script->sent_length[index] = command.length;
  memcpy(script->sent[index], command.data,
         command.length < TC_SCRIPT_MAX_BYTES ? command.length : TC_SCRIPT_MAX_BYTES);
  for (size_t i = command.length; i < script->scratch_length; ++i)
    if (script->scratch && script->scratch[i])
      script->scratch_dirty = 1;
}

TC_status tc_script_transmit(void* context, TC_bytes command, TC_buffer response, size_t* length)
{
  static uint8_t expected[TC_APDU_SHORT_COMMAND_MAX_BYTES * 4];
  tc_script* script = context;
  const size_t index = script->next++;
  record(script, index, command, response);
  if (index >= script->count) {
    if (!script->mismatch)
      script->mismatch = index + 1;
    return TC_ERROR;
  }
  const tc_script_step* step = &script->steps[index];
  const int any = !step->command && !step->command_bytes.data;
  size_t expected_length = 0;
  if (!any &&
      (!decode(step->command, step->command_bytes, expected, sizeof expected, &expected_length) ||
       expected_length != command.length || memcmp(expected, command.data, expected_length) != 0)) {
    if (!script->mismatch)
      script->mismatch = index + 1;
    return TC_ERROR;
  }
  if (step->status != TC_OK)
    return step->status;
  size_t written = 0;
  if (!decode(step->response, step->response_bytes, response.data, response.capacity, &written)) {
    if (!script->mismatch)
      script->mismatch = index + 1;
    return TC_ERROR;
  }
  *length = step->reported_length ? step->reported_length : written;
  return TC_OK;
}
