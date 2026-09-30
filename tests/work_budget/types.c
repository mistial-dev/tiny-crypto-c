/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */

/* RSA, EC and key-challenge work is counted in 32 bits on every target
 * (docs/api.md, Work budgets). This file compiles only while the budget type,
 * the execution descriptors, the cost functions and every public or header
 * helper that takes a budget keep exactly those types. A size_t budget, or a
 * helper that takes size_t* behind a pointer cast, fails the build.
 * tests/cmake/work_budget_width.cmake compiles it and checks that every
 * declaration with a work parameter in the scanned headers appears here. */
#include <tiny_crypto/ec.h>
#include <tiny_crypto/key_challenge.h>
#include <tiny_crypto/rsa.h>
/* The RSA sources select their limb width before the private headers. */
#define TC_MP_WORD_BITS TC_RSA_WORD_BITS
#include "rsa_internal.h"
#include "rsa_padding_internal.h"
#include "rsa_prime_internal.h"
#include "rsa_private_internal.h"
#include "check.h"

void tc_work_budget_types(TC_work_budget* budget, TC_RSA_execution* rsa, TC_EC_execution* ec);

void tc_work_budget_types(TC_work_budget* budget, TC_RSA_execution* rsa, TC_EC_execution* ec)
{
  TC_EXPECT_MEMBER(uint32_t, budget, remaining);
  TC_EXPECT_MEMBER(TC_work_budget, rsa, work);
  TC_EXPECT_MEMBER(TC_work_budget, ec, work);

  /* Cost functions return budget units. */
  TC_EXPECT_FUNCTION(TC_EC_operation_work, uint32_t, (TC_EC_curve, TC_EC_operation));
  TC_EXPECT_FUNCTION(TC_RSA_encode_v15_work, uint32_t, (const TC_RSA_v15_options*, size_t));
  TC_EXPECT_FUNCTION(TC_RSA_encode_pss_work, uint32_t, (const TC_RSA_pss_options*, size_t));
  TC_EXPECT_FUNCTION(TC_RSA_oaep_work, uint32_t, (const TC_RSA_oaep_options*, size_t));
  TC_EXPECT_FUNCTION(TC_RSA_public_work, uint32_t, (const TC_RSA_public_key*));
  TC_EXPECT_FUNCTION(TC_RSA_prepared_public_work, uint32_t, (const TC_RSA_prepared_public_key*));
  TC_EXPECT_FUNCTION(TC_RSA_private_work, uint32_t, (const TC_RSA_private_key*, size_t));

  /* Public entry points. Execution-based operations carry the budget in
   * TC_RSA_execution or TC_EC_execution, checked above. */
  TC_EXPECT_FUNCTION(TC_EC_public_key, TC_EC_result,
                     (TC_EC_curve, TC_bytes, TC_buffer, TC_EC_workspace*, TC_work_budget*));
  TC_EXPECT_FUNCTION(TC_EC_validate_public_key, TC_EC_result,
                     (TC_EC_curve, TC_bytes, TC_EC_workspace*, TC_work_budget*));
  TC_EXPECT_FUNCTION(
      TC_ECDH, TC_EC_result,
      (TC_EC_curve, TC_bytes, TC_bytes, TC_buffer, TC_EC_workspace*, TC_work_budget*));
  TC_EXPECT_FUNCTION(
      TC_ECDSA_verify_digest, TC_EC_result,
      (TC_EC_curve, TC_bytes, TC_bytes, TC_bytes, TC_ECDSA_workspace*, TC_work_budget*));
  TC_EXPECT_FUNCTION(TC_key_challenge_prepare, TC_key_challenge_result,
                     (const TC_X509_public_key*, const TC_key_challenge_options*, TC_random_source,
                      TC_key_challenge_workspace*, TC_work_budget*, TC_bytes*));
  TC_EXPECT_FUNCTION(TC_key_challenge_verify, TC_key_challenge_result,
                     (const TC_X509_public_key*, TC_bytes, const TC_X509_signature_provider*,
                      TC_key_challenge_workspace*, TC_work_budget*));
  TC_EXPECT_FUNCTION(TC_RSA_prepare_public_key, TC_RSA_result,
                     (TC_RSA_prepared_public_key*, const TC_RSA_public_key*,
                      const TC_RSA_workspace*, const TC_RSA_workspace*, TC_work_budget*));
  TC_EXPECT_FUNCTION(
      TC_RSA_keygen_step, TC_RSA_result,
      (TC_RSA_keygen_state*, TC_random_source, TC_RSA_cancel_fn, void*, TC_work_budget*));
  TC_EXPECT_FUNCTION(
      TC_RSA_raw_public, TC_RSA_result,
      (const TC_RSA_public_key*, TC_bytes, const TC_RSA_workspace*, TC_buffer, TC_work_budget*));
  TC_EXPECT_FUNCTION(TC_RSA_encode_v15_digest, TC_RSA_result,
                     (const TC_RSA_v15_options*, TC_bytes, TC_buffer, TC_work_budget*));
  TC_EXPECT_FUNCTION(TC_RSA_encode_pss_digest, TC_RSA_result,
                     (const TC_RSA_pss_options*, TC_bytes, TC_bytes, TC_buffer, TC_work_budget*));
  TC_EXPECT_FUNCTION(
      TC_RSA_validate_crt, TC_RSA_result,
      (const TC_RSA_private_key*, const TC_RSA_crt*, const TC_RSA_workspace*, TC_work_budget*));
  TC_EXPECT_FUNCTION(TC_RSA_derive_crt, TC_RSA_result,
                     (const TC_RSA_private_key*, const TC_RSA_crt_output*, const TC_RSA_workspace*,
                      TC_work_budget*));
  TC_EXPECT_FUNCTION(TC_RSA_verify_v15_digest, TC_RSA_result,
                     (const TC_RSA_public_key*, const TC_RSA_v15_options*, TC_bytes, TC_bytes,
                      const TC_RSA_workspace*, TC_work_budget*));
  TC_EXPECT_FUNCTION(TC_RSA_verify_v15_prepared, TC_RSA_result,
                     (const TC_RSA_prepared_public_key*, const TC_RSA_v15_options*, TC_bytes,
                      TC_bytes, const TC_RSA_workspace*, TC_work_budget*));
  TC_EXPECT_FUNCTION(TC_RSA_verify_pss_digest, TC_RSA_result,
                     (const TC_RSA_public_key*, const TC_RSA_pss_options*, TC_bytes, TC_bytes,
                      const TC_RSA_workspace*, TC_work_budget*));
  TC_EXPECT_FUNCTION(TC_RSA_verify_pss_prepared, TC_RSA_result,
                     (const TC_RSA_prepared_public_key*, const TC_RSA_pss_options*, TC_bytes,
                      TC_bytes, const TC_RSA_workspace*, TC_work_budget*));

  /* Internal RSA helpers pass &budget->remaining as uint32_t*. */
  TC_EXPECT_FUNCTION(tc_rsa_public_operation, TC_RSA_result,
                     (const TC_RSA_public_key*, const uint8_t*, uint8_t*, tc_mp_scratch, uint32_t*,
                      const tc_mp_word*));
  TC_EXPECT_FUNCTION(tc_rsa_probable_prime_magnitude, TC_RSA_result,
                     (TC_bytes, size_t, size_t, const tc_rsa_random*, tc_mp_scratch, uint32_t*));
  TC_EXPECT_FUNCTION(tc_rsa_sample_blinding, TC_RSA_result,
                     (const tc_mp_word*, size_t, tc_mp_word*, tc_mp_word*, tc_mp_word*,
                      const tc_rsa_random*, uint32_t*));
  TC_EXPECT_FUNCTION(
      tc_rsa_private_magnitudes_consistent, TC_RSA_result,
      (const tc_rsa_private_view*, TC_RSA_exponent_policy, tc_mp_scratch, uint32_t*));
  TC_EXPECT_FUNCTION(tc_rsa_private_magnitudes_check, TC_RSA_result,
                     (const tc_rsa_private_view*, TC_RSA_exponent_policy, size_t,
                      const tc_rsa_random*, tc_mp_scratch, uint32_t*));
  TC_EXPECT_FUNCTION(tc_rsa_private_operation_magnitude, TC_RSA_result,
                     (const TC_RSA_public_key*, TC_bytes, const uint8_t*, uint8_t*,
                      const tc_rsa_random*, tc_mp_scratch, uint32_t*));
  TC_EXPECT_FUNCTION(tc_rsa_crt_consistent, TC_RSA_result,
                     (const tc_rsa_private_view*, tc_mp_scratch, uint32_t*));
  TC_EXPECT_FUNCTION(tc_rsa_crt_derive, TC_RSA_result,
                     (const tc_rsa_private_view*, tc_mp_scratch, uint32_t*, tc_mp_word**,
                      tc_mp_word**, tc_mp_word**));
  TC_EXPECT_FUNCTION(tc_rsa_crt_private_operation, TC_RSA_result,
                     (const tc_rsa_private_view*, const uint8_t*, uint8_t*, const tc_rsa_random*,
                      tc_mp_scratch, uint32_t*));
  TC_EXPECT_FUNCTION(tc_rsa_private_apply, TC_RSA_result,
                     (const tc_rsa_private_view*, const uint8_t*, uint8_t*, const tc_rsa_random*,
                      tc_mp_scratch, uint32_t*));
  TC_EXPECT_FUNCTION(
      tc_rsa_mgf1_xor, TC_RSA_result,
      (TC_hash_algorithm, TC_bytes, uint8_t*, size_t, uint8_t*, TC_hash_context*, uint32_t*));
  TC_EXPECT_FUNCTION(tc_rsa_pss_prepare, TC_RSA_result,
                     (size_t, size_t, TC_hash_algorithm, TC_hash_algorithm, size_t, size_t,
                      uint32_t*, tc_hash_info*));
  TC_EXPECT_FUNCTION(tc_rsa_pss_encode, TC_RSA_result,
                     (const TC_RSA_pss_options*, TC_buffer, size_t, TC_bytes, TC_bytes,
                      tc_rsa_hash_scratch, uint32_t*));
  TC_EXPECT_FUNCTION(
      tc_rsa_pss_check, TC_RSA_result,
      (const TC_RSA_pss_options*, TC_buffer, size_t, TC_bytes, tc_rsa_hash_scratch, uint32_t*));
  TC_EXPECT_FUNCTION(
      tc_rsa_oaep_prepare, TC_RSA_result,
      (size_t, TC_hash_algorithm, TC_hash_algorithm, TC_bytes, uint32_t*, tc_hash_info*));
  TC_EXPECT_FUNCTION(
      tc_rsa_oaep_encode, TC_RSA_result,
      (const TC_RSA_oaep_options*, TC_buffer, TC_bytes, TC_bytes, tc_rsa_hash_scratch, uint32_t*));
  TC_EXPECT_FUNCTION(
      tc_rsa_oaep_decode, TC_RSA_result,
      (const TC_RSA_oaep_options*, TC_buffer, tc_rsa_hash_scratch, uint32_t*, TC_bytes*));
}
