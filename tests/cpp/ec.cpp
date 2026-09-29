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
  CHECK(tiny_crypto::ecdsa_sign_digest(TC_EC_P256, {private_key, sizeof private_key},
                                       {generated, sizeof generated}, {digest, sizeof digest},
                                       produced, signature_workspace, execution) == TC_EC_OK);
  CHECK(tiny_crypto::ecdsa_verify_digest(TC_EC_P256, {generated, sizeof generated},
                                         {digest, sizeof digest}, {produced, sizeof produced},
                                         signature_workspace, work) == TC_EC_OK);
  CHECK(tiny_crypto::ec_operation_work(TC_EC_P256, TC_EC_OPERATION_VALIDATE) == 1);
}
