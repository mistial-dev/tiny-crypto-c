/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Card fixtures for tests/support/card_simulator.c. tests/piv/capture_fixture.py
 * writes them from the vendored SD 33 captures into
 * tests/vectors/piv/sm_captures/fixtures, and its docstring defines the
 * record format. The loader keeps every byte string in the fixture's own
 * pool, so a loaded fixture needs no other storage. */
#ifndef TC_TEST_CARD_FIXTURE_H
#define TC_TEST_CARD_FIXTURE_H

#include <tiny_crypto/piv_command.h>

#define TC_CARD_FIXTURE_POOL_BYTES (192u * 1024u)
#define TC_CARD_FIXTURE_MAX_OBJECTS 48u
#define TC_CARD_FIXTURE_MAX_REFERENCES 3u
#define TC_CARD_FIXTURE_MAX_AUTHENTICATIONS 16u
#define TC_CARD_FIXTURE_MAX_SESSIONS 4u
#define TC_CARD_FIXTURE_MAX_REPLAYS 4u
#define TC_CARD_FIXTURE_MAX_EXCHANGES 256u
/* Retry count of a reference whose count the capture did not record. */
#define TC_CARD_FIXTURE_DEFAULT_RETRIES 3u

/* GET DATA answer data of one container (answered with 9000). */
typedef struct {
  uint32_t tag; /* up to 3 tag bytes, big-endian */
  TC_bytes data;
} tc_card_object;

/* VERIFY reference data: 80 PIV PIN, 00 Global PIN or 98 pairing code. */
typedef struct {
  uint8_t reference;
  uint8_t value_known; /* 0 when the capture holds no submission */
  uint8_t value[8];    /* padded to 8 bytes with FF (Part 2 2.4.3) */
  uint8_t retries;     /* tries left, also the count restored on success */
} tc_card_reference;

/* One recorded GENERAL AUTHENTICATE: the input DO of the 7C template and
 * the answer data. */
typedef struct {
  uint8_t algorithm, key, tag;
  TC_bytes input, answer;
} tc_card_authentication;

/* One recorded key establishment (Part 2 4.1). */
typedef struct {
  uint8_t suite;
  TC_bytes scalar, host_id, command, answer, material;
} tc_card_session;

/* One wire exchange: a command APDU and its answer with SW1 SW2. */
typedef struct {
  TC_bytes command, answer;
} tc_card_exchange;

/* A recorded session from card reset: exchanges[first, first + count). */
typedef struct {
  char name[64];
  TC_PIV_interface interface;
  size_t first, count;
} tc_card_replay;

typedef struct {
  char name[32];
  TC_bytes select; /* APT answer data */
  tc_card_object objects[TC_CARD_FIXTURE_MAX_OBJECTS];
  tc_card_reference references[TC_CARD_FIXTURE_MAX_REFERENCES];
  tc_card_authentication authentications[TC_CARD_FIXTURE_MAX_AUTHENTICATIONS];
  tc_card_session sessions[TC_CARD_FIXTURE_MAX_SESSIONS];
  tc_card_replay replays[TC_CARD_FIXTURE_MAX_REPLAYS];
  tc_card_exchange exchanges[TC_CARD_FIXTURE_MAX_EXCHANGES];
  size_t object_count, reference_count, authentication_count, session_count, replay_count,
      exchange_count;
  uint8_t pool[TC_CARD_FIXTURE_POOL_BYTES];
  size_t pool_used;
} tc_card_fixture;

/* Load the fixture at path. Returns 0 on success, -1 when the file cannot
 * be read, or the 1-based number of the first line that is malformed, holds
 * an unknown record or exceeds a limit above. */
long tc_card_fixture_load(tc_card_fixture* fixture, const char* path);

/* The container with tag, or NULL. */
const tc_card_object* tc_card_fixture_object(const tc_card_fixture* fixture, uint32_t tag);

/* The reference data for reference, or NULL. */
const tc_card_reference* tc_card_fixture_reference(const tc_card_fixture* fixture,
                                                   uint8_t reference);

/* The replay called name, or NULL. */
const tc_card_replay* tc_card_fixture_replay(const tc_card_fixture* fixture, const char* name);

#endif
