/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* The SD 33 card simulator behind the hardware scenarios, with the guard
 * in front of it. The random source replays the recorded key establishment
 * scalar and the recorded proof challenges, and the evaluation time is the
 * one of the vendored CRLs and OCSP responses. */
#include "card_backend.h"
#include "card_simulator.h"
#include <stdio.h>
#include <string.h>

#ifndef TC_CARD_FIXTURE_DIR
#error "TC_CARD_FIXTURE_DIR must name the capture fixture directory"
#endif

enum { PROOFS = 8 };

static tc_card_fixture fixture;
static tc_card_simulator card;
static tc_piv_guarded_transport guarded;
static struct {
  uint8_t keys[PROOFS];
  size_t count, next;
  int scalar_drawn;
} entropy;

const char* tc_piv_card_backend_skip(const tc_piv_card_config* config)
{
  return config->expect ? NULL : "TC_PIV_CARD_EXPECT is unset";
}

/* The recorded scalar first, then the challenge of each announced key. */
static TC_status replay(void* context, uint8_t* out, size_t length)
{
  (void)context;
  TC_bytes value = {NULL, 0};
  if (!entropy.scalar_drawn) {
    entropy.scalar_drawn = 1;
    value = fixture.sessions[0].scalar;
  } else if (entropy.next < entropy.count) {
    value = tc_card_fixture_challenge(&fixture, entropy.keys[entropy.next++]);
  }
  if (!value.length || value.length != length)
    return TC_ERROR;
  memcpy(out, value.data, length);
  return TC_OK;
}

const char* tc_piv_card_backend_open(tc_piv_card_backend* backend, const tc_piv_card_config* config,
                                     tc_piv_guard* guard)
{
  char path[512];
  memset(backend, 0, sizeof *backend);
  if (!config->expect)
    return "TC_PIV_CARD_EXPECT is unset";
  if (snprintf(path, sizeof path, "%s/%s.txt", TC_CARD_FIXTURE_DIR, config->expect->fixture) <= 0 ||
      tc_card_fixture_load(&fixture, path) || !fixture.session_count)
    return "unable to load the capture fixture";
  const TC_PIV_interface interface =
      config->interface == TC_PIV_CARD_CONTACT ? TC_PIV_CONTACT : TC_PIV_CONTACTLESS;
  tc_card_simulator_init(&card, &fixture, interface);
  tc_piv_guard_connected(guard, interface);
  memset(&entropy, 0, sizeof entropy);
  backend->transport =
      tc_piv_guarded_transport_init(&guarded, guard, tc_card_simulator_transport(&card));
  backend->interface = interface;
  backend->random = (TC_random_source){replay, NULL};
  memcpy(backend->host_id, fixture.sessions[0].host_id.data, sizeof backend->host_id);
  backend->at = (TC_X509_time){2026, 9, 29, 18, 0, 0};
  backend->signature_proofs = tc_card_fixture_challenge(&fixture, 0x9c).length != 0;
  return NULL;
}

void tc_piv_card_backend_proofs(tc_piv_card_backend* backend, const uint8_t* keys, size_t count)
{
  (void)backend;
  for (size_t i = 0; i < count && entropy.count < PROOFS; ++i)
    entropy.keys[entropy.count++] = keys[i];
}

int tc_piv_card_backend_close(tc_piv_card_backend* backend)
{
  memset(backend, 0, sizeof *backend);
  const int clean = !card.violations;
  if (!clean)
    fprintf(stderr, "simulator violation: %s\n", card.violation);
  tc_card_simulator_reset(&card);
  return clean;
}
