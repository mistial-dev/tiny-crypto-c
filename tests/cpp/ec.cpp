/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/tiny_crypto.hpp>
#include <doctest.h>
#include <cstring>

namespace {
TC_status counter_random(void* context, uint8_t* output, size_t length)
{
  unsigned* counter = static_cast<unsigned*>(context);
  std::memset(output, 0, length);
  output[length - 1] = static_cast<uint8_t>(++*counter);
  return TC_OK;
}

TC_status failing_random(void* context, uint8_t*, size_t)
{
  ++*static_cast<unsigned*>(context);
  return TC_ERROR;
}

bool all_equal(const uint8_t* data, size_t length, uint8_t value)
{
  for (size_t i = 0; i < length; ++i)
    if (data[i] != value)
      return false;
  return true;
}
} // namespace

TEST_CASE("EC wrappers")
{
  tiny_crypto::ec_workspace workspace;
  uint8_t scalar[32] = {}, public_key[65], shared[32];
  scalar[31] = 1;
  TC_work_budget work = {100000};
  REQUIRE(tiny_crypto::ec_public_key(TC_EC_P256, {scalar, sizeof scalar}, public_key, workspace,
                                     work) == TC_EC_OK);
  REQUIRE(tiny_crypto::ec_validate_public_key(TC_EC_P256, {public_key, sizeof public_key},
                                              workspace, work) == TC_EC_OK);
  REQUIRE(tiny_crypto::ecdh(TC_EC_P256, {scalar, sizeof scalar}, {public_key, sizeof public_key},
                            shared, workspace, work) == TC_EC_OK);
  CHECK(std::memcmp(shared, public_key + 1, sizeof shared) == 0);
  tiny_crypto::ecdsa_workspace signature_workspace;
  uint8_t digest[32] = {}, signature[64];
  // With d = k = 1 and a zero digest, r = s = Gx.
  std::memcpy(signature, public_key + 1, 32);
  std::memcpy(signature + 32, public_key + 1, 32);
  CHECK(tiny_crypto::ecdsa_verify_digest(TC_EC_P256, {public_key, sizeof public_key},
                                         {digest, sizeof digest}, {signature, sizeof signature},
                                         signature_workspace, work) == TC_EC_OK);
  digest[0] = 1;
  CHECK(tiny_crypto::ecdsa_verify_digest(TC_EC_P256, {public_key, sizeof public_key},
                                         {digest, sizeof digest}, {signature, sizeof signature},
                                         signature_workspace, work) == TC_EC_INVALID);
  CHECK(tiny_crypto::ecdsa_verify_digest(TC_EC_P256, {public_key, sizeof public_key}, {nullptr, 0},
                                         {signature, sizeof signature}, signature_workspace,
                                         work) == TC_EC_ARGUMENT);
  CHECK(tiny_crypto::ec_public_key(TC_EC_P256, {nullptr, 0}, public_key, workspace, work) ==
        TC_EC_ARGUMENT);

  unsigned counter = 0;
  uint8_t private_key[32], generated[65], produced[64];
  tiny_crypto::ec_execution execution = {{counter_random, &counter}, 4, {100000}};
  REQUIRE(tiny_crypto::ec_generate_key_pair(TC_EC_P256, private_key, generated, workspace,
                                            execution) == TC_EC_OK);
  const tiny_crypto::ecdsa_sign_options sign_options = {TC_HASH_SHA256, 4};
  TC_work_budget sign_work = {100000};
  CHECK(tiny_crypto::ecdsa_sign_digest(TC_EC_P256, {scalar, sizeof scalar},
                                       {public_key, sizeof public_key}, {digest, sizeof digest},
                                       produced, signature_workspace, sign_options,
                                       sign_work) == TC_EC_OK);
  CHECK(tiny_crypto::ecdsa_verify_digest(TC_EC_P256, {public_key, sizeof public_key},
                                         {digest, sizeof digest}, {produced, sizeof produced},
                                         signature_workspace, sign_work) == TC_EC_OK);
  CHECK(tiny_crypto::ec_operation_work(TC_EC_P256, TC_EC_OPERATION_VALIDATE) == 1);
}

TEST_CASE("EC wrappers reject short arrays, bad lengths and exhausted randomness")
{
  CHECK(tiny_crypto::ec_coordinate_bytes(TC_EC_P256) == 32);
  CHECK(tiny_crypto::ec_coordinate_bytes(static_cast<tiny_crypto::ec_curve>(0)) == 0);

  tiny_crypto::ec_workspace workspace;
  tiny_crypto::ecdsa_workspace signature_workspace;
  uint8_t scalar[32] = {}, public_key[65];
  scalar[31] = 1;
  TC_work_budget work = {100000};
  REQUIRE(tiny_crypto::ec_public_key(TC_EC_P256, {scalar, sizeof scalar}, public_key, workspace,
                                     work) == TC_EC_OK);
  const uint32_t remaining = work.remaining;

  uint8_t short_point[64];
  std::memset(short_point, 0xa5, sizeof short_point);
  CHECK(tiny_crypto::ec_public_key(TC_EC_P256, {scalar, sizeof scalar}, short_point, workspace,
                                   work) == TC_EC_LIMIT);
  CHECK(all_equal(short_point, sizeof short_point, 0xa5));
  uint8_t short_secret[31];
  CHECK(tiny_crypto::ecdh(TC_EC_P256, {scalar, sizeof scalar}, {public_key, sizeof public_key},
                          short_secret, workspace, work) == TC_EC_LIMIT);
  CHECK(tiny_crypto::ec_public_key(TC_EC_P256, {scalar, 31}, public_key, workspace, work) ==
        TC_EC_INVALID);
  CHECK(tiny_crypto::ec_validate_public_key(TC_EC_P256, {public_key, 64}, workspace, work) ==
        TC_EC_INVALID);
  CHECK(work.remaining == remaining);

  unsigned calls = 0;
  uint8_t digest[32] = {1}, private_key[32], generated[65], signature[64];
  uint8_t short_private[31], short_signature[63];
  std::memset(short_signature, 0xa5, sizeof short_signature);
  tiny_crypto::ec_execution execution = {{counter_random, &calls}, 4, {100000}};
  CHECK(tiny_crypto::ec_generate_key_pair(TC_EC_P256, short_private, generated, workspace,
                                          execution) == TC_EC_LIMIT);
  CHECK(tiny_crypto::ec_generate_key_pair(TC_EC_P256, private_key, short_point, workspace,
                                          execution) == TC_EC_LIMIT);
  const tiny_crypto::ecdsa_sign_options sign_options = {TC_HASH_SHA256, 4};
  TC_work_budget sign_work = {100000};
  CHECK(tiny_crypto::ecdsa_sign_digest(TC_EC_P256, {scalar, sizeof scalar},
                                       {public_key, sizeof public_key}, {digest, sizeof digest},
                                       short_signature, signature_workspace, sign_options,
                                       sign_work) == TC_EC_LIMIT);
  CHECK(all_equal(short_signature, sizeof short_signature, 0xa5));
  CHECK(calls == 0);
  CHECK(execution.work.remaining == 100000);

  // No attempts left: LIMIT without an RNG request.
  execution.random_attempts = 0;
  std::memset(signature, 0xa5, sizeof signature);
  CHECK(tiny_crypto::ecdsa_sign_digest_external_random(
            TC_EC_P256, {scalar, sizeof scalar}, {public_key, sizeof public_key},
            {digest, sizeof digest}, signature, signature_workspace, execution) == TC_EC_LIMIT);
  CHECK(tiny_crypto::ec_generate_key_pair(TC_EC_P256, private_key, generated, workspace,
                                          execution) == TC_EC_LIMIT);
  CHECK(calls == 0);
  CHECK(all_equal(signature, sizeof signature, 0xa5));

  // A failing RNG returns ERROR and leaves outputs unchanged.
  unsigned failures = 0;
  tiny_crypto::ec_execution failing = {{failing_random, &failures}, 4, {100000}};
  std::memset(private_key, 0xa5, sizeof private_key);
  CHECK(tiny_crypto::ec_generate_key_pair(TC_EC_P256, private_key, generated, workspace, failing) ==
        TC_EC_ERROR);
  CHECK(all_equal(private_key, sizeof private_key, 0xa5));
  CHECK(tiny_crypto::ecdsa_sign_digest_external_random(
            TC_EC_P256, {scalar, sizeof scalar}, {public_key, sizeof public_key},
            {digest, sizeof digest}, signature, signature_workspace, failing) == TC_EC_ERROR);
  CHECK(all_equal(signature, sizeof signature, 0xa5));
  CHECK(failures == 2);

  // An exhausted work budget returns LIMIT with the budget unchanged.
  TC_work_budget short_work = {tiny_crypto::ec_operation_work(TC_EC_P256, TC_EC_OPERATION_VERIFY) -
                               1};
  CHECK(tiny_crypto::ecdsa_verify_digest(TC_EC_P256, {public_key, sizeof public_key},
                                         {digest, sizeof digest}, {signature, sizeof signature},
                                         signature_workspace, short_work) == TC_EC_LIMIT);
  CHECK(short_work.remaining ==
        tiny_crypto::ec_operation_work(TC_EC_P256, TC_EC_OPERATION_VERIFY) - 1);
}
