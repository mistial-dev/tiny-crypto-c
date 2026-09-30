/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include "credential_pcsc.h"
#include <string.h>

int example_card_pcsc_close(ExampleCardPCSC* state)
{
  int ok = 1;
  if (!state)
    return 0;
  if (state->transaction && SCardEndTransaction(state->card, SCARD_LEAVE_CARD) != SCARD_S_SUCCESS)
    ok = 0;
  if (state->connected && SCardDisconnect(state->card, SCARD_LEAVE_CARD) != SCARD_S_SUCCESS)
    ok = 0;
  if (state->established && SCardReleaseContext(state->context) != SCARD_S_SUCCESS)
    ok = 0;
  memset(state, 0, sizeof *state);
  return ok;
}

int example_card_pcsc_open(ExampleCardPCSC* state, const char* reader)
{
  if (!state || !reader || !*reader || state->established || state->connected || state->transaction)
    return 0;
  if (SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &state->context) != SCARD_S_SUCCESS)
    goto failed;
  state->established = 1;
#if defined(_WIN32)
  if (SCardConnectA(state->context, reader, SCARD_SHARE_EXCLUSIVE,
#else
  if (SCardConnect(state->context, reader, SCARD_SHARE_EXCLUSIVE,
#endif
                    SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &state->card,
                    &state->protocol) != SCARD_S_SUCCESS)
    goto failed;
  state->connected = 1;
  if (state->protocol != SCARD_PROTOCOL_T0 && state->protocol != SCARD_PROTOCOL_T1)
    goto failed;
  if (SCardBeginTransaction(state->card) != SCARD_S_SUCCESS)
    goto failed;
  state->transaction = 1;
  state->failed = 0;
  return 1;
failed:
  (void)example_card_pcsc_close(state);
  return 0;
}

TC_status example_card_pcsc_transmit(void* context, TC_bytes command, TC_buffer response,
                                     size_t* length)
{
  ExampleCardPCSC* state = context;
  const size_t max_transfer = (ExamplePCSCSize)-1;
  if (!state || !state->transaction || state->failed || !command.data || !command.length ||
      !response.data || !length || response.capacity < TC_APDU_STATUS_BYTES ||
      command.length > max_transfer || response.capacity > max_transfer)
    return TC_ERROR;
  ExamplePCSCSize received = (ExamplePCSCSize)response.capacity;
  const SCARD_IO_REQUEST* protocol =
      state->protocol == SCARD_PROTOCOL_T0 ? SCARD_PCI_T0 : SCARD_PCI_T1;
  if (SCardTransmit(state->card, protocol, command.data, (ExamplePCSCSize)command.length, NULL,
                    response.data, &received) != SCARD_S_SUCCESS ||
      received < TC_APDU_STATUS_BYTES || received > response.capacity) {
    state->failed = 1;
    TC_secure_zero(response.data, response.capacity);
    return TC_ERROR;
  }
  *length = received;
  return TC_OK;
}
