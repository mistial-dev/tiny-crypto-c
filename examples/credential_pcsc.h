/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef EXAMPLE_CREDENTIAL_PCSC_H_
#define EXAMPLE_CREDENTIAL_PCSC_H_
#include <tiny_crypto/apdu.h>
#if defined(__APPLE__)
#include <PCSC/winscard.h>
typedef uint32_t ExamplePCSCSize;
#else
#include <winscard.h>
typedef DWORD ExamplePCSCSize;
#endif

typedef struct {
  SCARDCONTEXT context;
  SCARDHANDLE card;
  ExamplePCSCSize protocol;
  int established, connected, transaction, failed;
} ExampleCardPCSC;

/* Zero-initialize state. Open the named reader exclusively and hold a transaction
 * until close. A failed open releases acquired resources. Reader names use the
 * platform's narrow PC/SC encoding. Concurrent access requires caller locking. */
int example_card_pcsc_open(ExampleCardPCSC* state, const char* reader);
/* Release every acquired resource, leaving card contents and PIN unchanged.
 * Returns zero if any release failed. State is cleared on every close. */
int example_card_pcsc_close(ExampleCardPCSC* state);
/* A TC_APDU_transmit with state as its context. A failed transfer wipes the
 * response buffer and disables further transfers on this connection. No
 * reconnect is attempted. */
TC_status example_card_pcsc_transmit(void* context, TC_bytes command, TC_buffer response,
                                     size_t* length);
#endif
