/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* Environment of the PIV hardware tests (docs/testing.md, "PIV card
 * hardware tests"):
 *
 * TC_PIV_CARD_READER       substring of exactly one reader name.
 * TC_PIV_CARD_INTERFACE    contact or contactless. Unset takes the ATR.
 * TC_PIV_PIN               6 to 8 digits, or unset for no PIN.
 * TC_PIV_PAIRING_CODE      8 digits, or unset.
 * TC_PIV_CARD_MIN_RETRIES  PIN tries the card must report before a
 *                          submission, 2 to 15, default 3.
 * TC_PIV_CARD_EXPECT       sd33-card2 or sd33-card4: the card identity.
 *                          Reference data and 9C need it.
 * TC_PIV_CARD_ROOT         an extra DER trust anchor. It needs
 *                          TC_PIV_CARD_ROOT_SHA256, its SHA-256 in hex.
 * TC_PIV_CARD_CRL_DIR      a directory whose *.crl files replace the
 *                          vendored CRLs.
 * TC_PIV_CARD_REVOCATION   required or when-available (default).
 * TC_PIV_CARD_EXTENDED     1 adds the extended-length scenario.
 * TC_PIV_CARD_DUMP_DIR     a directory of mode 0700 for object dumps.
 *
 * The default trust points are the vendored SD 33 issuing CAs with pinned
 * SHA-256 digests, since the SD 33 root is unavailable. */
#ifndef TC_TEST_PIV_HARDWARE_CARD_CONFIG_H
#define TC_TEST_PIV_HARDWARE_CARD_CONFIG_H

#include <tiny_crypto/validation.h>

#define TC_PIV_CARD_TRUST_FILES 4u
#define TC_PIV_CARD_PATH_BYTES 1024u

typedef enum {
  TC_PIV_CARD_DETECT,
  TC_PIV_CARD_CONTACT,
  TC_PIV_CARD_CONTACTLESS
} tc_piv_card_interface;

/* A known card: its capture fixture and the vendored trust inputs, as
 * paths below tests/vectors. */
typedef struct {
  const char* name;
  const char* fixture;
  const char* anchors[2];
  const char* anchor_sha256[2];
  const char* crls[2];
  size_t anchor_count, crl_count;
} tc_piv_card_identity;

/* Trust files. Paths are absolute. anchor_sha256[i] is the pin of
 * anchors[i]. */
typedef struct {
  char anchors[TC_PIV_CARD_TRUST_FILES][TC_PIV_CARD_PATH_BYTES];
  const char* anchor_sha256[TC_PIV_CARD_TRUST_FILES];
  char crls[TC_PIV_CARD_TRUST_FILES][TC_PIV_CARD_PATH_BYTES];
  size_t anchor_count, crl_count;
} tc_piv_card_trust_paths;

/* The parsed environment. Strings borrow the environment. expect is NULL
 * without TC_PIV_CARD_EXPECT. */
typedef struct {
  const char* reader;
  tc_piv_card_interface interface;
  TC_bytes pin, pairing_code;
  unsigned minimum_retries;
  const tc_piv_card_identity* expect;
  TC_validation_revocation revocation;
  int extended;
  const char* dump_dir;
  tc_piv_card_trust_paths trust;
} tc_piv_card_config;

/* Read the environment into out. vector_dir names tests/vectors. Returns
 * NULL on success, or the name of the first malformed variable. */
const char* tc_piv_card_config_read(tc_piv_card_config* out, const char* vector_dir);

/* 1 when path is a directory of mode 0700 owned by the caller. */
int tc_piv_card_private_directory(const char* path);

#endif
