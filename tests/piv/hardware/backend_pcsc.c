/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* The PC/SC reader behind the hardware scenarios. The reader filter,
 * the Yubico refusal before connect and the ATR interface check are those
 * of examples/credential_pcsc.c. */
#include "../../../examples/credential_pcsc.h"
#include "../../../examples/credential_system.h"
#include "card_backend.h"
#include <string.h>

static ExampleCardPCSC connection;
static ExampleCardPCSCGuard hook;

const char* tc_piv_card_backend_skip(const tc_piv_card_config* config)
{
  return config->reader && *config->reader ? NULL : "TC_PIV_CARD_READER is unset";
}

const char* tc_piv_card_backend_open(tc_piv_card_backend* backend, const tc_piv_card_config* config,
                                     tc_piv_guard* guard)
{
  static const ExampleCardPCSCInterface interfaces[] = {EXAMPLE_PCSC_DETECT, EXAMPLE_PCSC_CONTACT,
                                                        EXAMPLE_PCSC_CONTACTLESS};
  memset(backend, 0, sizeof *backend);
  hook = (ExampleCardPCSCGuard){tc_piv_guard_check, tc_piv_guard_observe, guard,
                                tc_piv_guard_connected};
  const ExampleCardPCSCOptions options = {config->reader, interfaces[config->interface], &hook};
  memset(&connection, 0, sizeof connection);
  switch (example_card_pcsc_open(&connection, &options)) {
  case EXAMPLE_PCSC_OPENED:
    break;
  case EXAMPLE_PCSC_NO_READER:
    return "no reader name contains TC_PIV_CARD_READER";
  case EXAMPLE_PCSC_AMBIGUOUS:
    return "several reader names contain TC_PIV_CARD_READER";
  case EXAMPLE_PCSC_REFUSED:
    return "refused a Yubico reader or YubiKey";
  case EXAMPLE_PCSC_NO_CARD:
    return "the reader holds no card";
  case EXAMPLE_PCSC_INTERFACE:
    return "the ATR shows a contactless card";
  default:
    return "unable to acquire the reader";
  }
  /* The reset on close clears the PIN status the run leaves. */
  example_card_pcsc_reset_on_close(&connection);
  backend->transport = (TC_APDU_transport){example_card_pcsc_transmit, &connection};
  backend->interface = example_card_pcsc_interface(&connection);
  backend->random = (TC_random_source){example_card_random, NULL};
  backend->signature_proofs = 1;
  if (example_card_random(NULL, backend->host_id, sizeof backend->host_id) != TC_OK ||
      !example_card_now(&backend->at)) {
    (void)example_card_pcsc_close(&connection);
    return "no entropy or clock";
  }
  return NULL;
}

void tc_piv_card_backend_proofs(tc_piv_card_backend* backend, const uint8_t* keys, size_t count)
{
  (void)backend;
  (void)keys;
  (void)count;
}

int tc_piv_card_backend_close(tc_piv_card_backend* backend)
{
  memset(backend, 0, sizeof *backend);
  return example_card_pcsc_close(&connection);
}
