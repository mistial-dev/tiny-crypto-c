/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* The card behind tests/piv/hardware/piv_card.c. backend_pcsc.c reaches the
 * reader through examples/credential_pcsc.c with the guard installed.
 * backend_simulated.c puts the same guard in front of the SD 33 card
 * simulator, so the scenarios also run without hardware. */
#ifndef TC_TEST_PIV_HARDWARE_CARD_BACKEND_H
#define TC_TEST_PIV_HARDWARE_CARD_BACKEND_H

#include "card_config.h"
#include "guard.h"
#include <tiny_crypto/x509.h>

/* An open card. signature_proofs is 1 when a 9C proof can succeed. The
 * simulator holds no recorded card 2 proof of 9C. */
typedef struct {
  TC_APDU_transport transport;
  TC_PIV_interface interface;
  TC_random_source random;
  uint8_t host_id[8];
  TC_X509_time at;
  uint8_t signature_proofs;
} tc_piv_card_backend;

/* Why the backend cannot run, such as an unset TC_PIV_CARD_READER, or
 * NULL. */
const char* tc_piv_card_backend_skip(const tc_piv_card_config* config);

/* Open the card with guard in front of it. guard is initialized and stays
 * in place until close. Returns NULL, or why the open failed. */
const char* tc_piv_card_backend_open(tc_piv_card_backend* backend, const tc_piv_card_config* config,
                                     tc_piv_guard* guard);

/* The keys of the next proofs, in order, for a random source that replays
 * recorded challenges. The reader backend ignores them. */
void tc_piv_card_backend_proofs(tc_piv_card_backend* backend, const uint8_t* keys, size_t count);

/* Close the card. The reader backend resets it, which clears the PIN
 * status. Returns 0 when the release failed. */
int tc_piv_card_backend_close(tc_piv_card_backend* backend);

#endif
