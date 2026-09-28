/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/tiny_crypto.hpp>
#include <doctest.h>
#include <cstdio>
#include <cstring>
#include <type_traits>

namespace {
// Serves one fixed entropy input, as the DRBGVS test harness does.
struct fixed_entropy {
  const uint8_t* data;
  size_t length;
  bool used;
};

TC_status fill(void* user, uint8_t* output, size_t length)
{
  fixed_entropy* source = static_cast<fixed_entropy*>(user);
  if (source->used || length != source->length)
    return TC_ERROR;
  std::memcpy(output, source->data, length);
  source->used = true;
  return TC_OK;
}

void unhex(const char* text, uint8_t* out)
{
  for (size_t i = 0; text[2 * i]; ++i) {
    unsigned value = 0;
    std::sscanf(text + 2 * i, "%2x", &value);
    out[i] = static_cast<uint8_t>(value);
  }
}
} // namespace

TEST_CASE("HMAC_DRBG SHA-256 CAVP answer and lifecycle")
{
  // tests/vectors/drbg/cavp/no_reseed/HMAC_DRBG.rsp, [SHA-256], COUNT = 0.
  uint8_t entropy[32], nonce[16], expected[128], out[128];
  unhex("ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488", entropy);
  unhex("659ba96c601dc69fc902940805ec0ca8", nonce);
  unhex("e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89"
        "d54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc1"
        "07694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668"
        "961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8",
        expected);

  CHECK_FALSE(std::is_copy_constructible<tiny_crypto::drbg>::value);
  CHECK_FALSE(std::is_move_constructible<tiny_crypto::drbg>::value);

  fixed_entropy source = {entropy, sizeof(entropy), false};
  tiny_crypto::drbg_config config = {};
  config.mechanism = TC_DRBG_HMAC;
  config.hash = TC_HASH_SHA256;
  tiny_crypto::drbg generator;
  CHECK(generator.generate(out, sizeof(out)) == TC_DRBG_ARGUMENT);
  REQUIRE(generator.instantiate(config, TC_random_source{fill, &source},
                                tiny_crypto::bytes{nonce, sizeof(nonce)},
                                tiny_crypto::bytes{nullptr, 0}) == TC_DRBG_OK);
  REQUIRE(generator.generate(out, sizeof(out)) == TC_DRBG_OK);
  REQUIRE(generator.generate(out, sizeof(out)) == TC_DRBG_OK);
  CHECK(std::memcmp(out, expected, sizeof(out)) == 0);

  // The C random source adapter draws from the same generator.
  TC_random_source random = generator.random_source();
  CHECK(random.fill(random.context, out, 16) == TC_OK);
  // Reseeding needs fresh entropy, and this source is spent.
  CHECK(generator.reseed() == TC_DRBG_ENTROPY);
  generator.uninstantiate();
  CHECK(generator.generate(out, 16) == TC_DRBG_ARGUMENT);
}
