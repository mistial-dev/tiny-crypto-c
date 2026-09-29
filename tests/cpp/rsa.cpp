/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <tiny_crypto/rsa.hpp>
#include <doctest.h>
#include <cstring>

TEST_CASE("RSA signature representative encoding")
{
  uint8_t digest[32] = {}, encoded[256], expected[256];
  tiny_crypto::rsa_v15_options options = {TC_HASH_SHA256};
  TC_work_budget work = {sizeof encoded};
  CHECK(tiny_crypto::rsa_encode_v15_digest(options, {digest, sizeof digest}, encoded, work) ==
        TC_RSA_OK);
  work.remaining = sizeof expected;
  CHECK(TC_RSA_encode_v15_digest(&options, {digest, sizeof digest}, {expected, sizeof expected},
                                 &work) == TC_RSA_OK);
  CHECK(std::memcmp(encoded, expected, sizeof encoded) == 0);
  work.remaining = sizeof encoded - 1;
  CHECK(tiny_crypto::rsa_encode_v15_digest(options, {digest, sizeof digest}, encoded, work) ==
        TC_RSA_LIMIT);
  CHECK(std::memcmp(encoded, expected, sizeof encoded) == 0);
  work.remaining = sizeof encoded;
  CHECK(tiny_crypto::rsa_encode_v15_digest(options, {encoded, sizeof digest}, encoded, work) ==
        TC_RSA_ARGUMENT);
  CHECK(std::memcmp(encoded, expected, sizeof encoded) == 0);
}

TEST_CASE("RSA PSS representative wrappers preserve C results")
{
  uint8_t digest[32] = {}, salt[32] = {}, encoded[256], expected[256];
  std::memset(encoded, 0x5a, sizeof encoded);
  std::memset(expected, 0x5a, sizeof expected);
  tiny_crypto::rsa_pss_options options = {TC_HASH_SHA256, TC_HASH_SHA256, sizeof salt};
  TC_work_budget work = {100000}, reference_work = work;
  const TC_RSA_result reference =
      TC_RSA_encode_pss_digest(&options, {digest, sizeof digest}, {salt, sizeof salt},
                               {expected, sizeof expected}, &reference_work);
  CHECK(tiny_crypto::rsa_encode_pss_digest(options, {digest, sizeof digest}, {salt, sizeof salt},
                                           encoded, work) == reference);
  CHECK(work.remaining == reference_work.remaining);
  CHECK(std::memcmp(encoded, expected, sizeof encoded) == 0);
  work.remaining = 100000;
  tiny_crypto::buffer output = {encoded, sizeof encoded};
  CHECK(tiny_crypto::rsa_encode_pss_digest(options, {digest, sizeof digest}, {salt, sizeof salt},
                                           output, work) == reference);
  CHECK(std::memcmp(encoded, expected, sizeof encoded) == 0);
  CHECK(tiny_crypto::rsa_encode_pss_digest(options, {digest, sizeof digest},
                                           {salt, sizeof salt - 1}, output,
                                           work) == TC_RSA_ARGUMENT);
  CHECK(std::memcmp(encoded, expected, sizeof encoded) == 0);
}

TEST_CASE("RSA key generation state wrappers")
{
  TC_RSA_word words[TC_RSA_KEYGEN_WORKSPACE_WORDS(1024)] = {};
  uint8_t modulus[128], exponent[3], d[128], p[64], q[64];
  tiny_crypto::rsa_keygen_output output = {{modulus, sizeof modulus},
                                           {exponent, sizeof exponent},
                                           {d, sizeof d},
                                           {p, sizeof p},
                                           {q, sizeof q}};
  tiny_crypto::rsa_keygen_state state = {};
  auto workspace = tiny_crypto::rsa_workspace_for(words);
  CHECK(tiny_crypto::rsa_keygen_init(state, 1024, output, {1, 1}, workspace) == TC_RSA_OK);
  tiny_crypto::rsa_keygen_clear(state);
  CHECK(state.marker == 0);
}

TEST_CASE("RSA workspace view and verification")
{
  TC_RSA_word words[9 * 1024 / TC_RSA_WORD_BITS + 2];
  auto workspace = tiny_crypto::rsa_workspace_for(words);
  CHECK(workspace.words == words);
  CHECK(workspace.capacity == tiny_crypto::rsa_workspace_words(TC_RSA_OPERATION_VERIFY, 1024));
  uint8_t modulus[128], exponent[] = {3}, digest[32] = {}, signature[128] = {};
  std::memset(modulus, 0xff, sizeof modulus);
  tiny_crypto::rsa_public_key key = {{modulus, sizeof modulus}, {exponent, sizeof exponent}};
  tiny_crypto::rsa_v15_options v15 = {TC_HASH_SHA256};
  tiny_crypto::rsa_pss_options pss = {TC_HASH_SHA256, TC_HASH_SHA256, sizeof digest};
  TC_work_budget work = {10000};
  CHECK(tiny_crypto::rsa_verify_v15_digest(key, v15, {digest, sizeof digest},
                                           {signature, sizeof signature}, workspace,
                                           work) == TC_RSA_INVALID);
  work.remaining = 0;
  CHECK(tiny_crypto::rsa_verify_v15_digest(key, v15, {digest, sizeof digest},
                                           {signature, sizeof signature}, workspace,
                                           work) == TC_RSA_LIMIT);
  work.remaining = 10000;
  CHECK(tiny_crypto::rsa_verify_v15_digest(key, v15, {nullptr, sizeof digest},
                                           {signature, sizeof signature}, workspace,
                                           work) == TC_RSA_ARGUMENT);
  CHECK(tiny_crypto::rsa_verify_pss_digest(key, pss, {nullptr, sizeof digest},
                                           {signature, sizeof signature}, workspace,
                                           work) == TC_RSA_ARGUMENT);
  TC_RSA_word cache_words[1024 / TC_RSA_WORD_BITS];
  auto cache = tiny_crypto::rsa_workspace_for(cache_words);
  tiny_crypto::rsa_prepared_public_key prepared = {};
  work.remaining = 16 * sizeof modulus + 1;
  CHECK(tiny_crypto::rsa_prepare_public_key(prepared, key, cache, workspace, work) == TC_RSA_OK);
  work.remaining = 10000;
  CHECK(tiny_crypto::rsa_verify_v15_prepared(prepared, v15, {digest, sizeof digest},
                                             {signature, sizeof signature}, workspace,
                                             work) == TC_RSA_INVALID);
  tiny_crypto::rsa_prepared_public_key_clear(prepared);
  CHECK(prepared.marker == 0);
  for (TC_RSA_word word : cache_words)
    CHECK(word == 0);
}

static TC_status unavailable_random(void* context, uint8_t*, size_t)
{
  ++*static_cast<unsigned*>(context);
  return TC_ERROR;
}

TEST_CASE("RSA CRT wrapper argument checks")
{
  TC_RSA_word words[TC_RSA_CRT_WORKSPACE_WORDS(1024)];
  auto workspace = tiny_crypto::rsa_workspace_for(words);
  tiny_crypto::rsa_private_key key = {};
  tiny_crypto::rsa_crt crt = {};
  tiny_crypto::rsa_crt_output output = {};
  CHECK(workspace.capacity == tiny_crypto::rsa_workspace_words(TC_RSA_OPERATION_CRT, 1024));
  TC_work_budget work = {0};
  /* NULL key and output spans are argument errors, reported before any key
   * check. */
  CHECK(tiny_crypto::rsa_validate_crt(key, crt, workspace, work) == TC_RSA_ARGUMENT);
  CHECK(tiny_crypto::rsa_derive_crt(key, output, workspace, work) == TC_RSA_ARGUMENT);
  workspace.words = nullptr;
  CHECK(tiny_crypto::rsa_validate_crt(key, crt, workspace, work) == TC_RSA_ARGUMENT);
}

TEST_CASE("RSA encryption wrapper argument checks")
{
  TC_RSA_word words[TC_RSA_ENCRYPT_WORKSPACE_WORDS(1024)];
  auto workspace = tiny_crypto::rsa_workspace_for(words);
  tiny_crypto::rsa_public_key key = {};
  uint8_t ciphertext[128] = {};
  unsigned calls = 0;
  CHECK(workspace.capacity == tiny_crypto::rsa_workspace_words(TC_RSA_OPERATION_ENCRYPT, 1024));
  CHECK(tiny_crypto::rsa_workspace_words(TC_RSA_OPERATION_ENCRYPT, 1536) == 0);
  tiny_crypto::rsa_oaep_options options = {TC_HASH_SHA256, TC_HASH_SHA256, {nullptr, 0}};
  tiny_crypto::rsa_execution execution = {{nullptr, &calls}, 0, {10000}};
  CHECK(tiny_crypto::rsa_encrypt_oaep(key, options, {nullptr, 0}, workspace,
                                      {ciphertext, sizeof ciphertext},
                                      execution) == TC_RSA_ARGUMENT);
  execution = {{unavailable_random, &calls}, 0, {10000}};
  CHECK(tiny_crypto::rsa_encrypt_oaep(key, options, {nullptr, 0}, workspace,
                                      {ciphertext, sizeof ciphertext},
                                      execution) == TC_RSA_ARGUMENT);
  CHECK(calls == 0);
}

TEST_CASE("RSA private validation wrapper")
{
  TC_RSA_word words[TC_RSA_VALIDATE_WORKSPACE_WORDS(1024)];
  auto workspace = tiny_crypto::rsa_workspace_for(words);
  CHECK(workspace.capacity == tiny_crypto::rsa_workspace_words(TC_RSA_OPERATION_VALIDATE, 1024));
  uint8_t modulus[128], exponent[] = {3}, d[128] = {}, p[128] = {}, q[128] = {};
  std::memset(modulus, 0xff, sizeof modulus);
  d[sizeof d - 1] = 3;
  tiny_crypto::rsa_private_key key = {{{modulus, sizeof modulus}, {exponent, sizeof exponent}},
                                      {d, sizeof d},
                                      {p, sizeof p},
                                      {q, sizeof q},
                                      nullptr};
  unsigned calls = 0;
  tiny_crypto::rsa_execution execution = {
      {unavailable_random, &calls}, TC_RSA_VALIDATION_ROUNDS, {0}};
  CHECK(tiny_crypto::rsa_validate_private_key(key, workspace, execution) == TC_RSA_LIMIT);
  execution = {{nullptr, &calls}, TC_RSA_VALIDATION_ROUNDS, {10000}};
  CHECK(tiny_crypto::rsa_validate_private_key(key, workspace, execution) == TC_RSA_ARGUMENT);
  std::memset(words, 0xa5, sizeof words);
  execution = {{unavailable_random, &calls},
               TC_RSA_VALIDATION_ROUNDS,
               {TC_RSA_VALIDATE_WORK(1024u, TC_RSA_VALIDATION_ROUNDS)}};
  CHECK(tiny_crypto::rsa_validate_private_key(key, workspace, execution) == TC_RSA_INVALID);
  CHECK(calls == 0);
  for (auto word : words)
    CHECK(word == 0);
  uint8_t digest[32] = {}, signature[128];
  std::memset(signature, 0xa5, sizeof signature);
  CHECK(tiny_crypto::rsa_workspace_words(TC_RSA_OPERATION_SIGN, 1024) ==
        TC_RSA_SIGN_WORKSPACE_WORDS(1024));
  tiny_crypto::rsa_v15_options v15 = {TC_HASH_SHA256};
  execution = {{unavailable_random, &calls}, 1, {10000}};
  CHECK(tiny_crypto::rsa_sign_v15_digest(key, v15, {digest, sizeof digest}, workspace,
                                         {signature, sizeof signature}, execution) == TC_RSA_LIMIT);
  execution.work.remaining = 10000;
  CHECK(tiny_crypto::rsa_sign_v15_digest(key, v15, {digest, sizeof digest}, workspace,
                                         {modulus, sizeof modulus}, execution) == TC_RSA_ARGUMENT);
  CHECK(calls == 0);
  for (auto byte : signature)
    CHECK(byte == 0xa5);
  tiny_crypto::rsa_pss_options pss = {TC_HASH_SHA256, TC_HASH_SHA256, sizeof digest};
  execution.work.remaining = 10000;
  CHECK(tiny_crypto::rsa_sign_pss_digest(key, pss, {digest, sizeof digest}, workspace,
                                         {modulus, sizeof modulus}, execution) == TC_RSA_ARGUMENT);
  size_t plaintext_length = SIZE_MAX;
  tiny_crypto::rsa_oaep_options oaep = {TC_HASH_SHA256, TC_HASH_SHA256, {nullptr, 0}};
  execution = {{nullptr, &calls}, 1, {10000}};
  CHECK(tiny_crypto::rsa_decrypt_oaep(key, oaep, {modulus, sizeof modulus}, workspace,
                                      {signature, sizeof signature}, plaintext_length,
                                      execution) == TC_RSA_ARGUMENT);
  execution = {{unavailable_random, &calls}, 1, {10000}};
  CHECK(tiny_crypto::rsa_decrypt_oaep(key, oaep, {modulus, sizeof modulus}, workspace,
                                      {modulus, sizeof modulus}, plaintext_length,
                                      execution) == TC_RSA_ARGUMENT);
  CHECK(plaintext_length == SIZE_MAX);
  CHECK(calls == 0);
  for (auto byte : signature)
    CHECK(byte == 0xa5);
}

namespace {
TC_status xorshift_random(void* context, uint8_t* output, size_t length)
{
  uint32_t* state = static_cast<uint32_t*>(context);
  for (size_t i = 0; i < length; ++i) {
    uint32_t value = *state;
    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    *state = value;
    output[i] = static_cast<uint8_t>(value);
  }
  return TC_OK;
}

/* A deterministic RSA-1024 key generated through the C++ wrappers. */
struct generated_key {
  uint8_t modulus[128], exponent[3], d[128], p[64], q[64];
  tiny_crypto::rsa_private_key key;
};

const generated_key& key_fixture()
{
  static generated_key fixture;
  static bool ready = false;
  if (ready)
    return fixture;
  static TC_RSA_word words[TC_RSA_KEYGEN_WORKSPACE_WORDS(1024)];
  const tiny_crypto::rsa_keygen_output output = {{fixture.modulus, sizeof fixture.modulus},
                                                 {fixture.exponent, sizeof fixture.exponent},
                                                 {fixture.d, sizeof fixture.d},
                                                 {fixture.p, sizeof fixture.p},
                                                 {fixture.q, sizeof fixture.q}};
  tiny_crypto::rsa_keygen_state state = {};
  uint32_t rng = UINT32_C(0x2545f491);
  REQUIRE(tiny_crypto::rsa_keygen_init(state, 1024, output, {4096, 16384},
                                       tiny_crypto::rsa_workspace_for(words)) == TC_RSA_OK);
  tiny_crypto::rsa_result status;
  do {
    TC_work_budget budget = {50000};
    status = tiny_crypto::rsa_keygen_step(state, {xorshift_random, &rng}, nullptr, nullptr, budget);
  } while (status == TC_RSA_IN_PROGRESS);
  REQUIRE(status == TC_RSA_OK);
  tiny_crypto::rsa_keygen_clear(state);
  fixture.key = {
      {{fixture.modulus, sizeof fixture.modulus}, {fixture.exponent, sizeof fixture.exponent}},
      {fixture.d, sizeof fixture.d},
      {fixture.p, sizeof fixture.p},
      {fixture.q, sizeof fixture.q},
      nullptr};
  ready = true;
  return fixture;
}
} // namespace

TEST_CASE("RSA sizing and preflight wrappers match the C API")
{
  CHECK(tiny_crypto::rsa_workspace_words(TC_RSA_OPERATION_RAW_PUBLIC, 1024) ==
        TC_RSA_RAW_PUBLIC_WORKSPACE_WORDS(1024));
  CHECK(tiny_crypto::rsa_workspace_words(TC_RSA_OPERATION_RAW_PRIVATE, 2048) ==
        TC_RSA_RAW_PRIVATE_WORKSPACE_WORDS(2048));
  CHECK(tiny_crypto::rsa_workspace_words(TC_RSA_OPERATION_VERIFY, 1000) == 0);
  CHECK(tiny_crypto::rsa_modulus_supported(2048));
  CHECK_FALSE(tiny_crypto::rsa_modulus_supported(1000));
  CHECK_FALSE(tiny_crypto::rsa_modulus_supported(TC_RSA_MAX_MODULUS_BITS + 1024));

  const uint8_t f4[] = {0x00, 0x01, 0x00, 0x01};
  const uint8_t three[] = {3};
  const uint8_t even[] = {0x01, 0x00, 0x02};
  CHECK(tiny_crypto::rsa_exponent_in_fips_range({f4, sizeof f4}));
  CHECK_FALSE(tiny_crypto::rsa_exponent_in_fips_range({three, sizeof three}));
  CHECK_FALSE(tiny_crypto::rsa_exponent_in_fips_range({even, sizeof even}));

  const tiny_crypto::rsa_v15_options v15 = {TC_HASH_SHA256};
  const tiny_crypto::rsa_pss_options pss = {TC_HASH_SHA256, TC_HASH_SHA256, 32};
  const tiny_crypto::rsa_oaep_options oaep = {TC_HASH_SHA256, TC_HASH_SHA256, {nullptr, 0}};
  CHECK(tiny_crypto::rsa_encode_v15_work(v15, 256) == TC_RSA_encode_v15_work(&v15, 256));
  CHECK(tiny_crypto::rsa_encode_v15_work(v15, 256) != 0);
  /* The PSS and OAEP costs are 0 when this library build omits SHA-256. */
  CHECK(tiny_crypto::rsa_encode_pss_work(pss, 256) == TC_RSA_encode_pss_work(&pss, 256));
  CHECK(tiny_crypto::rsa_oaep_work(oaep, 256) == TC_RSA_oaep_work(&oaep, 256));
  const tiny_crypto::rsa_v15_options unknown = {TC_HASH_UNKNOWN};
  CHECK(tiny_crypto::rsa_encode_v15_work(unknown, 256) == 0);

  uint8_t modulus[128], exponent[] = {1, 0, 1};
  std::memset(modulus, 0xff, sizeof modulus);
  const tiny_crypto::rsa_public_key key = {{modulus, sizeof modulus}, {exponent, sizeof exponent}};
  /* 16*modulus_bytes + 16*exponent_bytes + 4 (rsa.h). */
  CHECK(tiny_crypto::rsa_public_work(key) == 16u * 128u + 16u * 3u + 4u);
  const tiny_crypto::rsa_private_key private_key = {
      key, {nullptr, 0}, {nullptr, 0}, {nullptr, 0}, nullptr};
  CHECK(tiny_crypto::rsa_private_work(private_key, 1) == TC_RSA_private_work(&private_key, 1));
  CHECK(tiny_crypto::rsa_private_work(private_key, 1) != 0);
  const tiny_crypto::rsa_prepared_public_key unprepared = {};
  CHECK(tiny_crypto::rsa_prepared_public_work(unprepared) == 0);
  CHECK(noexcept(tiny_crypto::rsa_workspace_words(TC_RSA_OPERATION_SIGN, 1024)));
}

TEST_CASE("RSA raw operation wrappers round trip")
{
  const generated_key& fixture = key_fixture();
  const tiny_crypto::rsa_public_key& key = fixture.key.public_key;
  TC_RSA_word public_words[TC_RSA_RAW_PUBLIC_WORKSPACE_WORDS(1024)];
  TC_RSA_word private_words[TC_RSA_RAW_PRIVATE_WORKSPACE_WORDS(1024)];
  const tiny_crypto::rsa_workspace public_workspace = tiny_crypto::rsa_workspace_for(public_words);
  const tiny_crypto::rsa_workspace private_workspace =
      tiny_crypto::rsa_workspace_for(private_words);
  CHECK(public_workspace.capacity ==
        tiny_crypto::rsa_workspace_words(TC_RSA_OPERATION_RAW_PUBLIC, 1024));
  CHECK(private_workspace.capacity ==
        tiny_crypto::rsa_workspace_words(TC_RSA_OPERATION_RAW_PRIVATE, 1024));

  uint8_t message[128];
  for (size_t i = 0; i < sizeof message; ++i)
    message[i] = static_cast<uint8_t>(i + 1);
  message[0] = 0;

  /* Private then public operation returns the representative. */
  uint8_t signature[128], recovered[128];
  uint32_t rng = UINT32_C(0x9e3779b9);
  const uint32_t private_work = tiny_crypto::rsa_private_work(fixture.key, 1);
  tiny_crypto::rsa_execution execution = {{xorshift_random, &rng}, 1, {private_work}};
  REQUIRE(tiny_crypto::rsa_raw_private(key, {fixture.d, sizeof fixture.d},
                                       {message, sizeof message}, private_workspace, signature,
                                       execution) == TC_RSA_OK);
  CHECK(std::memcmp(signature, message, sizeof message) != 0);
  TC_work_budget work = {tiny_crypto::rsa_public_work(key)};
  REQUIRE(tiny_crypto::rsa_raw_public(key, {signature, sizeof signature}, public_workspace,
                                      recovered, work) == TC_RSA_OK);
  CHECK(std::memcmp(recovered, message, sizeof message) == 0);
  CHECK(work.remaining == 0);

  /* The buffer overloads match the array overloads. */
  uint8_t second[128];
  work.remaining = tiny_crypto::rsa_public_work(key);
  CHECK(tiny_crypto::rsa_raw_public(key, {signature, sizeof signature}, public_workspace,
                                    tiny_crypto::buffer{second, sizeof second}, work) == TC_RSA_OK);
  CHECK(std::memcmp(second, message, sizeof message) == 0);

  /* A short output returns LIMIT and leaves the output unchanged. */
  uint8_t short_output[127];
  std::memset(short_output, 0x5a, sizeof short_output);
  work.remaining = tiny_crypto::rsa_public_work(key);
  CHECK(tiny_crypto::rsa_raw_public(key, {signature, sizeof signature}, public_workspace,
                                    short_output, work) == TC_RSA_LIMIT);
  execution.work.remaining = private_work;
  CHECK(tiny_crypto::rsa_raw_private(key, {fixture.d, sizeof fixture.d}, {message, sizeof message},
                                     private_workspace, short_output, execution) == TC_RSA_LIMIT);
  for (uint8_t byte : short_output)
    CHECK(byte == 0x5a);

  /* An input at or above the modulus is invalid. */
  std::memset(recovered, 0x5a, sizeof recovered);
  work.remaining = tiny_crypto::rsa_public_work(key);
  CHECK(tiny_crypto::rsa_raw_public(key, {fixture.modulus, sizeof fixture.modulus},
                                    public_workspace, recovered, work) == TC_RSA_INVALID);
  execution.work.remaining = private_work;
  CHECK(tiny_crypto::rsa_raw_private(key, {fixture.d, sizeof fixture.d},
                                     {fixture.modulus, sizeof fixture.modulus}, private_workspace,
                                     recovered, execution) == TC_RSA_INVALID);
  for (uint8_t byte : recovered)
    CHECK(byte == 0x5a);

  /* An exhausted budget is a limit, and a NULL input is an argument error. */
  work.remaining = tiny_crypto::rsa_public_work(key) - 1;
  CHECK(tiny_crypto::rsa_raw_public(key, {signature, sizeof signature}, public_workspace, recovered,
                                    work) == TC_RSA_LIMIT);
  work.remaining = tiny_crypto::rsa_public_work(key);
  CHECK(tiny_crypto::rsa_raw_public(key, {nullptr, sizeof signature}, public_workspace, recovered,
                                    work) == TC_RSA_ARGUMENT);
  for (uint8_t byte : recovered)
    CHECK(byte == 0x5a);
}
