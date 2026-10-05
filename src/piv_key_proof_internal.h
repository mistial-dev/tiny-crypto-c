/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
/* The key policy check and profile rules shared by the key policy and the
 * key proof. */
#ifndef TC_PIV_KEY_PROOF_INTERNAL_H_
#define TC_PIV_KEY_PROOF_INTERNAL_H_
#include <tiny_crypto/piv_key_proof.h>

#if TC_ENABLE_PIV_KEY_PROOF
/* Key rules of a card profile.
 * rsa1024             RSA-1024 (06) is accepted when the policy allows it.
 * rsa2048_sunset      SP 800-78-5 Table 10 ends RSA-2048 (07) after 2030.
 * required_algorithm  0, or the only algorithm identifier accepted. */
typedef struct {
  uint8_t rsa1024;
  uint8_t rsa2048_sunset;
  uint8_t required_algorithm;
} tc_piv_key_profile_rules;

/* Rules of profile, or NULL for an unknown one. */
const tc_piv_key_profile_rules* tc_piv_key_profile_rules_get(TC_PIV_card_profile profile);

/* 1 when policy holds a known profile and padding, allow_rsa1024 of 0 or 1
 * and a valid time. */
int tc_piv_key_policy_valid(const TC_PIV_key_policy* policy);
#endif
#endif
