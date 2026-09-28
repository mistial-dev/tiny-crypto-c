/* SPDX-FileCopyrightText: Mistial Dev
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * RSA public-key operations: raw public, prepared keys and PKCS #1 v1.5
 * and PSS signature verification. */
#include <tiny_crypto/rsa.h>
#if TC_ENABLE_RSA
#define TC_MP_WORD_BITS TC_RSA_WORD_BITS
#include "rsa_pss_internal.h"
#include "rsa_keygen_internal.h"
#include "rsa_inputs_internal.h"

TC_RSA_result TC_RSA_raw_public(const TC_RSA_public_key* key, TC_bytes input,
                                const TC_RSA_workspace* workspace, TC_buffer output,
                                TC_work_budget* work)
{
  if (!key || !workspace || !work)
    return TC_RSA_ARGUMENT;
  TC_RSA_result result =
      tc_rsa_workspace_inputs(workspace, &(TC_bytes){(const uint8_t*)work, sizeof *work}, 1);
  if (result != TC_RSA_OK)
    return result;
  result = tc_rsa_public_inputs(key, input, (TC_bytes){(const uint8_t*)work, sizeof *work},
                                (TC_bytes){output.data, output.capacity}, workspace);
  if (result != TC_RSA_OK)
    return result;
  const size_t length = key->modulus.length;
  if (input.length != length)
    return TC_RSA_INVALID;
  if (output.capacity < length ||
      workspace->capacity < TC_RSA_raw_public_workspace_words(length * 8))
    return TC_RSA_LIMIT;
  return tc_rsa_public_operation(key->modulus.data, length, key->exponent.data,
                                 key->exponent.length, input.data, output.data, workspace->words,
                                 workspace->capacity, &work->remaining, NULL);
}

enum { TC_RSA_PUBLIC_SETUP_MARKER = 0x52533250u };

TC_RSA_result TC_RSA_prepare_public_key(TC_RSA_prepared_public_key* setup,
                                        const TC_RSA_public_key* key, const TC_RSA_workspace* cache,
                                        const TC_RSA_workspace* workspace, TC_work_budget* work)
{
  if (!setup || !key || !cache || !workspace || !work)
    return TC_RSA_ARGUMENT;
  TC_RSA_result status = tc_rsa_public_key_check(key->modulus.data, key->modulus.length,
                                                 key->exponent.data, key->exponent.length);
  if (status != TC_RSA_OK)
    return status;
  const size_t length = key->modulus.length;
  const size_t n = length / sizeof(TC_RSA_word);
  const TC_bytes inputs[] = {{(const uint8_t*)setup, sizeof *setup},
                             {(const uint8_t*)key, sizeof *key},
                             {(const uint8_t*)work, sizeof *work},
                             {(const uint8_t*)cache, sizeof *cache},
                             key->modulus,
                             key->exponent};
  status = tc_rsa_workspace_inputs(workspace, inputs, sizeof inputs / sizeof *inputs);
  if (status != TC_RSA_OK)
    return status;
  for (size_t i = 1; i < sizeof inputs / sizeof *inputs; ++i)
    if (!tc_internal_ranges_disjoint(setup, sizeof *setup, inputs[i].data, inputs[i].length))
      return TC_RSA_ARGUMENT;
  if (!tc_internal_ranges_disjoint(setup, sizeof *setup, workspace, sizeof *workspace))
    return TC_RSA_ARGUMENT;
  status = tc_rsa_workspace_inputs(cache, inputs, sizeof inputs / sizeof *inputs);
  if (status != TC_RSA_OK)
    return status;
  if (!tc_internal_ranges_disjoint(cache->words, cache->capacity * sizeof *cache->words,
                                   workspace->words,
                                   workspace->capacity * sizeof *workspace->words) ||
      !tc_internal_ranges_disjoint(cache->words, cache->capacity * sizeof *cache->words, workspace,
                                   sizeof *workspace))
    return TC_RSA_ARGUMENT;
  if (cache->capacity < n || workspace->capacity < 2 * n || work->remaining < 16 * length + 1)
    return TC_RSA_LIMIT;
  work->remaining -= (uint32_t)(16 * length + 1);
  tc_mp_word* modulus_words = workspace->words;
  tc_mp_from_be(modulus_words, key->modulus.data, length);
  tc_mp_montgomery_r2(cache->words, modulus_words, n, workspace->words + n);
  setup->key = *key;
  setup->r2 = *cache;
  setup->marker = TC_RSA_PUBLIC_SETUP_MARKER;
  TC_secure_zero(workspace->words, 2 * length);
  return TC_RSA_OK;
}

void TC_RSA_prepared_public_key_clear(TC_RSA_prepared_public_key* setup)
{
  if (!setup)
    return;
  if (setup->marker == TC_RSA_PUBLIC_SETUP_MARKER && setup->r2.words &&
      setup->key.modulus.length <= TC_RSA_MAX_MODULUS_BYTES)
    TC_secure_zero(setup->r2.words, setup->key.modulus.length);
  TC_secure_zero(setup, sizeof *setup);
}

static TC_RSA_result tc_rsa_prepared_inputs(const TC_RSA_prepared_public_key* setup,
                                            const void* options, size_t options_size,
                                            TC_bytes digest, TC_bytes signature,
                                            const TC_RSA_workspace* workspace,
                                            const TC_work_budget* work)
{
  if (!setup || setup->marker != TC_RSA_PUBLIC_SETUP_MARKER || !workspace || !work)
    return TC_RSA_ARGUMENT;
  const TC_bytes inputs[] = {{(const uint8_t*)options, options_size},
                             digest,
                             signature,
                             {(const uint8_t*)workspace, sizeof *workspace},
                             {(const uint8_t*)work, sizeof *work},
                             setup->key.modulus,
                             setup->key.exponent};
  if (!setup->r2.words || setup->r2.capacity < setup->key.modulus.length / sizeof(TC_RSA_word))
    return TC_RSA_ARGUMENT;
  /* The setup and its cached R^2 stay unchanged while the operation runs. */
  TC_bytes protected_ranges[3];
  tc_pki_storage_plan plan;
  tc_pki_storage_plan_begin(&plan, protected_ranges, 3, SIZE_MAX);
  TC_PKI_PLAN_WRITE(&plan, setup, 1);
  TC_PKI_PLAN_WRITE(&plan, setup->r2.words, setup->r2.capacity);
  TC_PKI_PLAN_WRITE(&plan, workspace->words, workspace->capacity);
  tc_pki_storage_plan_seal(&plan);
  tc_pki_storage_plan_input_spans(&plan, inputs, sizeof inputs / sizeof *inputs);
  return tc_rsa_storage_status(&plan);
}

static TC_RSA_result tc_rsa_verify_v15_digest_impl(const TC_RSA_public_key* key,
                                                   const TC_RSA_v15_options* options,
                                                   TC_bytes digest, TC_bytes signature,
                                                   const TC_RSA_workspace* workspace,
                                                   TC_work_budget* work,
                                                   const tc_mp_word* prepared_r2)
{
  if (!options || !work)
    return TC_RSA_ARGUMENT;
  TC_RSA_result result = tc_rsa_control_inputs(workspace, (TC_bytes){NULL, 0}, options,
                                               sizeof *options, work, sizeof *work);
  if (result != TC_RSA_OK)
    return result;
  result = tc_rsa_public_inputs(key, digest, signature, (TC_bytes){NULL, 0}, workspace);
  if (result != TC_RSA_OK)
    return result;
  return tc_rsa_verify_v15(key->modulus.data, key->modulus.length, key->exponent.data,
                           key->exponent.length, signature.data, signature.length, options->hash,
                           digest.data, digest.length, workspace->words, workspace->capacity,
                           &work->remaining, prepared_r2);
}

TC_RSA_result TC_RSA_verify_v15_digest(const TC_RSA_public_key* key,
                                       const TC_RSA_v15_options* options, TC_bytes digest,
                                       TC_bytes signature, const TC_RSA_workspace* workspace,
                                       TC_work_budget* work)
{
  return tc_rsa_verify_v15_digest_impl(key, options, digest, signature, workspace, work, NULL);
}

TC_RSA_result TC_RSA_verify_v15_prepared(const TC_RSA_prepared_public_key* setup,
                                         const TC_RSA_v15_options* options, TC_bytes digest,
                                         TC_bytes signature, const TC_RSA_workspace* workspace,
                                         TC_work_budget* work)
{
  TC_RSA_result status =
      tc_rsa_prepared_inputs(setup, options, sizeof *options, digest, signature, workspace, work);
  if (status != TC_RSA_OK)
    return status;
  return tc_rsa_verify_v15_digest_impl(&setup->key, options, digest, signature, workspace, work,
                                       setup->r2.words);
}

static TC_RSA_result tc_rsa_verify_pss_digest_impl(const TC_RSA_public_key* key,
                                                   const TC_RSA_pss_options* options,
                                                   TC_bytes digest, TC_bytes signature,
                                                   const TC_RSA_workspace* workspace,
                                                   TC_work_budget* work,
                                                   const tc_mp_word* prepared_r2)
{
  TC_hash_context hash_workspace;
  uint8_t block[64];
  uint8_t* encoded;
  size_t length, words, needed;
  uint32_t validation_work = UINT32_MAX;
  tc_hash_info info;
  if (!options || !work)
    return TC_RSA_ARGUMENT;
  TC_RSA_result result = tc_rsa_control_inputs(workspace, (TC_bytes){NULL, 0}, options,
                                               sizeof *options, work, sizeof *work);
  if (result != TC_RSA_OK)
    return result;
  result = tc_rsa_public_inputs(key, digest, signature, (TC_bytes){NULL, 0}, workspace);
  if (result != TC_RSA_OK)
    return result;
  length = key->modulus.length;
  if (!tc_rsa_supported_modulus_size(length))
    return TC_RSA_INVALID;
  if (signature.length != length)
    return TC_RSA_INVALID;
  if (!digest.data)
    return TC_RSA_ARGUMENT;
  result = tc_rsa_pss_prepare(length, length * 8 - 1, options->hash, options->mgf_hash,
                              digest.length, options->salt_length, &validation_work, &info);
  if (result != TC_RSA_OK)
    return result;
  words = length / sizeof(TC_RSA_word);
  needed = 9 * words + 2;
  if (workspace->capacity < needed)
    return TC_RSA_LIMIT;
  encoded = (uint8_t*)(workspace->words + 8 * words + 2);
  result = tc_rsa_public_operation(key->modulus.data, length, key->exponent.data,
                                   key->exponent.length, signature.data, encoded, workspace->words,
                                   8 * words + 2, &work->remaining, prepared_r2);
  if (result == TC_RSA_OK)
    result = tc_rsa_pss_check(encoded, length, length * 8 - 1, options->hash, options->mgf_hash,
                              digest, options->salt_length, block, &hash_workspace,
                              &work->remaining);
  TC_secure_zero(workspace->words, needed * sizeof(TC_RSA_word));
  TC_secure_zero(block, sizeof block);
  TC_secure_zero(&hash_workspace, sizeof hash_workspace);
  return result;
}

TC_RSA_result TC_RSA_verify_pss_digest(const TC_RSA_public_key* key,
                                       const TC_RSA_pss_options* options, TC_bytes digest,
                                       TC_bytes signature, const TC_RSA_workspace* workspace,
                                       TC_work_budget* work)
{
  return tc_rsa_verify_pss_digest_impl(key, options, digest, signature, workspace, work, NULL);
}

TC_RSA_result TC_RSA_verify_pss_prepared(const TC_RSA_prepared_public_key* setup,
                                         const TC_RSA_pss_options* options, TC_bytes digest,
                                         TC_bytes signature, const TC_RSA_workspace* workspace,
                                         TC_work_budget* work)
{
  TC_RSA_result status =
      tc_rsa_prepared_inputs(setup, options, sizeof *options, digest, signature, workspace, work);
  if (status != TC_RSA_OK)
    return status;
  return tc_rsa_verify_pss_digest_impl(&setup->key, options, digest, signature, workspace, work,
                                       setup->r2.words);
}
#endif
